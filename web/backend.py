"""
Copyright 2026 NXP
SPDX-License-Identifier: BSD-3-Clause

FastAPI backend for BACnet Security Monitoring Web GUI.
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import asyncio
import json
from pathlib import Path
import sys
import yaml
from datetime import datetime
from contextlib import asynccontextmanager

# Import agent components
from google.adk.agents import Agent
from google.adk.models.lite_llm import LiteLlm
from google.adk.sessions import InMemorySessionService
from google.adk.runners import Runner
from google.genai import types
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StreamableHTTPConnectionParams
from google.adk.agents.run_config import RunConfig, StreamingMode

# Import MCP Client
from fastmcp import Client
from mcp.types import GetTaskResult

# Add parent directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from bacnet.anomaly_storage import AnomalyStorage
from bacnet.pcap_monitor import PCAPMonitor

# Config path
AGENT_CONFIG_PATH = Path(__file__).parent / "config" / "agent.yaml"

# Global instances
storage = AnomalyStorage()
pcap_monitor = None
anomaly_event = None
websocket_clients = []
agent_lock = asyncio.Lock()
mcp_client = None
mcp_tasks = []

# Agent service (will be initialized if available)
agent_service = None
# Create session service
session_service = InMemorySessionService()


def load_agent_config(config_path: Path = AGENT_CONFIG_PATH) -> dict:
    """Load agent configuration from YAML file."""
    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
        if config is None:
            config = {}
        print(f"[✓] Agent config loaded from {config_path}")
        return config
    except FileNotFoundError:
        print(f"[!] Config file not found: {config_path}. Using defaults.")
        return {}
    except yaml.YAMLError as e:
        print(f"[!] Error parsing config file: {e}. Using defaults.")
        return {}


import re

# Markdown images the model invents (it has no tool that returns images),
# e.g. ![](https://example.com/image.png)
_IMAGE_RE = re.compile(r'!\[[^\]\n]*\]\([^)\n]*\)')
# The start of such an image at the end of streamed text: hold it back until
# it is complete (and removed) or turns out to be an ordinary "!"
_PARTIAL_IMAGE_RE = re.compile(r'!(\[[^\]\n]*(\](\([^)\n]*)?)?)?$')
# Tool-call markup the connector sometimes passes through as text when the model
# writes it mid-chunk; the call itself is handled separately, so never show it
_TOOL_CALL_RE = re.compile(r'<tool_call>.*?(</tool_call>|$)', re.S)
# An unfinished "<tool_call" tag at the end of streamed text
_PARTIAL_TOOL_RE = re.compile(r'<(t(o(o(l(_(c(a(l(l)?)?)?)?)?)?)?)?)?$')
# A reply that opens with an invented image often continues with a fragment about
# it ("![](...) seems inappropriate here."): drop the image and that fragment
_IMG = r'!\[[^\]\n]*\]\([^)\n]*\)'
_LEAD_FRAGMENT_RE = re.compile(r'^\s*(?:' + _IMG + r'\s*)+[a-z][^.!?\n]*[.!?]?[ \t]*')
_LEAD_FRAGMENT_OPEN_RE = re.compile(r'^\s*(?:' + _IMG + r'\s*)+(?:[a-z][^.!?\n]*)?$')
# The model sometimes goes on to invent the next chat turn ("\nuser\nCan you ...")
_FAKE_TURN_RE = re.compile(r'\n[ \t]*(?:user|assistant|system)[ \t]*\n')
_PARTIAL_FAKE_TURN_RE = re.compile(
    r'\n[ \t]*(?:u(?:s(?:e(?:r)?)?)?|a(?:s(?:s(?:i(?:s(?:t(?:a(?:n(?:t)?)?)?)?)?)?)?)?|'
    r's(?:y(?:s(?:t(?:e(?:m)?)?)?)?)?)?[ \t]*$')


def clean_model_text(text: str) -> str:
    """Remove invented image links, tool-call markup, invented chat turns and a stray leading "!"."""
    text = _TOOL_CALL_RE.sub('', text)
    text = _FAKE_TURN_RE.split(text, 1)[0]
    text = _LEAD_FRAGMENT_RE.sub('', text, count=1)
    text = _IMAGE_RE.sub('', text).lstrip()
    text = re.sub(r'^!+\s*', '', text)
    text = re.sub(r'(?m)^!+(?=[A-Z])', '', text)     # stray "!" opening a later line
    return re.sub(r'\n{3,}', '\n\n', text)


class TurnCleaner:
    """Cleans one model turn while it streams, returning only new clean text."""

    def __init__(self):
        self.raw = ""
        self.sent = 0

    def _emit(self, text: str) -> str:
        cleaned = clean_model_text(text)
        out = cleaned[self.sent:]
        self.sent = max(self.sent, len(cleaned))
        return out

    def feed(self, chunk: str) -> str:
        self.raw += chunk
        stable = self.raw
        for pattern in (_PARTIAL_TOOL_RE, _PARTIAL_IMAGE_RE, _PARTIAL_FAKE_TURN_RE):
            held = pattern.search(stable)
            if held:
                stable = stable[:held.start()]
        # An open <tool_call> block is held until its closing tag arrives
        open_tag = stable.rfind('<tool_call>')
        if open_tag != -1 and '</tool_call>' not in stable[open_tag:]:
            stable = stable[:open_tag]
        # A leading image is held with the fragment after it until the sentence ends
        if _LEAD_FRAGMENT_OPEN_RE.match(_TOOL_CALL_RE.sub('', stable)):
            stable = ""
        return self._emit(stable)

    def finish(self) -> str:
        return self._emit(self.raw)


# ---------------------------------------------------------------------------
# Safeguards for the small on-device model. It sometimes (1) runs away writing
# junk such as a base64 "image", (2) writes a tool call as text, e.g.
# ![](get_device_details{"instance_number": 201}), or (3) answers a data
# question without calling any tool. The backend detects these, runs the right
# tool itself and asks the model for the answer without offering tools.
# ---------------------------------------------------------------------------
LLM_API_BASE = "http://127.0.0.1:8000/v1"
LLM_MODEL = "Qwen2.5-7B-Instruct"
AGENT_TOOLS = ("get_bacnet_anomalies", "get_network_statistics", "get_device_details")
MAX_TURN_CHARS = 4000
_RUNAWAY_RE = re.compile(r'data:image|base64,|\S{150,}')
_TOOL_TEXT_RE = re.compile(r'(' + '|'.join(AGENT_TOOLS) + r')\s*([({][^\n]{0,80})?')
_TOOL_JSON_RE = re.compile(r'"name"\s*:\s*"(' + '|'.join(AGENT_TOOLS) +
                           r')"\s*,\s*"arguments"\s*:\s*(\{[^{}]*\})')

ANSWER_PROMPT = (
    "You are a BACnet network security assistant on an edge gateway. Answer the "
    "operator's question using only the data provided. Copy names, numbers, addresses "
    "and timestamps exactly. For each anomaly start with its anomaly_type in bold, then "
    "its severity, a short description and its \"action\" as the recommended action; "
    "if anomalies were omitted, say how many more exist. Keep the answer short and use "
    "Markdown lists. Never output images, links or tool calls."
)


def looks_runaway(text: str) -> bool:
    """True when a model turn has turned into junk that will not end usefully."""
    return len(text) > MAX_TURN_CHARS or bool(_RUNAWAY_RE.search(text))


def find_tool_in_text(text: str):
    """A tool call the model wrote as text instead of calling it, as (name, args)."""
    # JSON form, e.g. <tool_call>{"name": "get_device_details", "arguments": {...}}
    j = _TOOL_JSON_RE.search(text or "")
    if j:
        try:
            args = json.loads(j.group(2))
            if j.group(1) != "get_device_details" or "instance_number" in args:
                return j.group(1), args
        except ValueError:
            pass
    m = _TOOL_TEXT_RE.search(text or "")
    if not m:
        return None
    name, nums = m.group(1), re.findall(r'\d+', m.group(2) or "")
    if name == "get_device_details":
        return (name, {"instance_number": int(nums[0])}) if nums else None
    if name == "get_bacnet_anomalies":
        return name, {"limit": int(nums[0]) if nums else 5}
    return name, {}


def route_question(question: str):
    """The tool a data question needs, from its words, as (name, args) or None."""
    q = question.lower()
    m = re.search(r'\b(?:device|instance|controller)\s*#?\s*(\d+)', q)
    if m:
        return "get_device_details", {"instance_number": int(m.group(1))}
    if re.search(r'anomal|alert|alarm|issue|problem|wrong|secur|attack|threat|'
                 r'password|unauthori|intrus|error|conflict', q):
        return "get_bacnet_anomalies", {"limit": 5}
    if re.search(r'network|health|statistic|stats|overview|how many|devices|packet|traffic', q):
        return "get_network_statistics", {}
    return None


# The model misquotes numbers and addresses now and then, so tool data is shown
# to the operator exactly as stored; the model only adds a short comment.
SUMMARY_PROMPT = (
    "You are a BACnet network security assistant on an edge gateway. The data below has "
    "already been shown to the operator in full. Reply with at most two short sentences: "
    "what matters most and what to do first. Do not repeat the list, and do not quote "
    "numbers, addresses or device names. Never output images, links or tool calls."
)
_SEVERITY_LABEL = {"critical": "**CRITICAL**", "high": "**HIGH**", "medium": "Medium", "low": "Low"}


def _md(text) -> str:
    """Plain value for Markdown: no line breaks, no table pipes."""
    return str(text).replace("\n", " ").replace("|", "/").strip()


def _when(ts) -> str:
    return _md(ts)[:19].replace("T", " ") if ts else "-"


def render_tool_result(tool: str, result) -> Optional[str]:
    """Markdown for a tool result, or None when it is not in a known shape."""
    if not isinstance(result, dict) or result.get("status") not in (None, "success", "error"):
        return None
    if tool == "get_bacnet_anomalies" and isinstance(result.get("anomalies"), list):
        items = result["anomalies"]
        if not items:
            return "No anomalies have been detected."
        total = result.get("total") or len(items)
        head = (f"**{len(items)} anomalies, most severe first:**" if total <= len(items)
                else f"**{len(items)} of {total} anomalies, most severe first:**")
        lines = [head, ""]
        for n, a in enumerate(items, 1):
            sev = _SEVERITY_LABEL.get(str(a.get("severity", "")).lower(), _md(a.get("severity", "")))
            lines.append(f"{n}. `{_md(a.get('anomaly_type', '?'))}` - {sev}  ")
            lines.append(f"   {_md(a.get('description', ''))}  ")
            if a.get("action"):
                lines.append(f"   *Action:* {_md(a['action'])}")
        if result.get("omitted"):
            lines += ["", f"_{result['omitted']} more not shown._"]
        return "\n".join(lines)
    if tool == "get_network_statistics" and isinstance(result.get("statistics"), dict):
        st = result["statistics"]
        lines = ["**Network statistics:**", "",
                 f"- Devices: {st.get('total_devices', 0)}",
                 f"- Packets analyzed: {st.get('total_packets', 0):,}" if isinstance(st.get('total_packets'), int)
                 else f"- Packets analyzed: {_md(st.get('total_packets', 0))}",
                 f"- Anomalies: {st.get('total_anomalies', 0)} "
                 f"({st.get('unresolved_anomalies', 0)} unresolved)"]
        sev = st.get("severity_counts") or {}
        order = ["critical", "high", "medium", "low"]
        parts = [f"{k}: {sev[k]}" for k in order if sev.get(k)] + \
                [f"{_md(k)}: {v}" for k, v in sev.items() if k not in order and v]
        if parts:
            lines.append("- By severity: " + ", ".join(parts))
        types = st.get("type_counts") or {}
        if types:
            lines.append("- By type: " + ", ".join(f"`{_md(k)}` {v}" for k, v in
                                                   sorted(types.items(), key=lambda kv: -kv[1])))
        if st.get("last_updated"):
            lines.append(f"- Last updated: {_when(st['last_updated'])}")
        return "\n".join(lines)
    if tool == "get_device_details" and ("device" in result or "error_message" in result):
        d = result.get("device")
        if not d:
            return _md(result.get("error_message") or "Device not found.")
        lines = [f"**Device {d.get('instance_number')}:**", ""]
        for label, key in (("IP addresses", "ip_addresses"), ("MAC addresses", "mac_addresses"),
                           ("Routed / MS/TP addresses", "mstp_addresses")):
            if d.get(key):
                lines.append(f"- {label}: " + ", ".join(f"`{_md(v)}`" for v in d[key]))
        lines.append(f"- First seen: {_when(d.get('first_seen'))}")
        lines.append(f"- Last seen: {_when(d.get('last_seen'))}")
        lines.append(f"- Packets: {d.get('packet_count', 0)}")
        return "\n".join(lines)
    return None


async def stream_answer(question: str, tool: str, args: dict, result, prompt: str = ANSWER_PROMPT):
    """Ask the model to answer from a tool result (no tools offered), yielding clean text."""
    import httpx
    data = json.dumps(result, default=str)
    body = {"model": LLM_MODEL, "stream": True, "messages": [
        {"role": "system", "content": prompt},
        {"role": "user", "content": f"{question}\n\nData from {tool}({json.dumps(args)}):\n{data}"},
    ]}
    cleaner, raw = TurnCleaner(), ""
    async with httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=10.0)) as client:
        async with client.stream("POST", f"{LLM_API_BASE}/chat/completions", json=body) as resp:
            async for line in resp.aiter_lines():
                if not line.startswith("data: ") or line.strip() == "data: [DONE]":
                    continue
                try:
                    delta = json.loads(line[6:])["choices"][0]["delta"].get("content") or ""
                except (ValueError, KeyError, IndexError, TypeError):
                    continue
                raw += delta
                if looks_runaway(raw):
                    print(f"[guard] Runaway answer stopped after {len(raw)} characters")
                    return
                out = cleaner.feed(delta)
                if out:
                    yield out
    out = cleaner.finish()
    if out:
        yield out


class QueryRequest(BaseModel):
    query: str


class QueryResponse(BaseModel):
    response: str
    timestamp: str


# Create agent service wrapper
class AgentService:
    def __init__(self, runner):
        self.runner = runner

    async def process_query(self, query: str, session_id: str = "chat_session"):
        """Process a user query (non-streaming, used internally for anomaly handling)."""
        content = types.Content(role='user', parts=[types.Part(text=query)])

        final_response_text = "I apologize, but I couldn't process your request."
        tool_was_called = False

        async for event in self.runner.run_async(
            user_id="web_user",
            session_id=session_id,
            new_message=content
        ):
            # Detect MCP tool calls in event parts
            if event.content and event.content.parts:
                for part in event.content.parts:
                    if getattr(part, "function_call", None):
                        tool_was_called = True

            if event.is_final_response():
                if event.content and event.content.parts and event.content.parts[0].text:
                    final_response_text = clean_model_text(event.content.parts[0].text)
                break

        # Clean history to avoid large system prompts after tool calls
        if tool_was_called:
            print(f"[*] MCP tool call detected in session '{session_id}', cleaning history...")
            await session_service.delete_session(
                app_name="bacnet_security_app",
                user_id="web_user",
                session_id=session_id
            )
            await session_service.create_session(
                app_name="bacnet_security_app",
                user_id="web_user",
                session_id=session_id
            )

        return final_response_text

    async def process_query_stream(self, query: str, session_id: str = "chat_session"):
        """Process a user query and yield SSE events for tool calls, text chunks, and final response."""
        content = types.Content(role='user', parts=[types.Part(text=query)])

        accumulated_text = ""
        tool_was_called = False
        # With SSE streaming, ADK sends each model turn as partial chunks and then
        # once more as one complete (non-partial) event. Stream the chunks only,
        # cleaned per turn, so nothing is shown twice.
        turn = TurnCleaner()
        turn_streamed = False   # this turn arrived as partial chunks
        turn_emitted = False    # text of this turn was already sent
        last_turn_raw = ""      # raw text of the last finished model turn
        pending_call = None     # (name, args) of the tool call in progress
        last_tool = None        # (name, args, result) of the last tool the agent ran
        runaway = False
        got_data = False        # a tool returned data the backend renders itself

        def emit(text: str):
            nonlocal accumulated_text, turn_emitted
            if not text:
                return None
            if not turn_emitted and accumulated_text:
                text = "\n\n" + text   # keep separate turns (explanation, answer) apart
            turn_emitted = True
            accumulated_text += text
            return f"data: {json.dumps({'type': 'text_chunk', 'text': text})}\n\n"

        events = self.runner.run_async(
            user_id="web_user",
            session_id=session_id,
            new_message=content,
            run_config=RunConfig(
                streaming_mode=StreamingMode.SSE,
            )
        )
        try:
            async for event in events:
                if event.content and event.content.parts:
                    for part in event.content.parts:
                        # Detect and stream tool calls
                        if getattr(part, "function_call", None):
                            tool_was_called = True
                            fc = part.function_call
                            try:
                                tool_args = dict(fc.args) if fc.args else {}
                            except Exception:
                                tool_args = {}
                            pending_call = (fc.name, tool_args)
                            yield f"data: {json.dumps({'type': 'tool_call', 'tool_name': fc.name, 'tool_args': tool_args}, default=str)}\n\n"

                        # Detect and stream tool responses
                        elif getattr(part, "function_response", None):
                            fr = part.function_response
                            resp = fr.response if isinstance(fr.response, dict) else {}
                            args = pending_call[1] if pending_call and pending_call[0] == fr.name else {}
                            last_tool = (fr.name, args, resp.get("structuredContent", resp))
                            yield f"data: {json.dumps({'type': 'tool_response', 'tool_name': fr.name})}\n\n"
                            # The backend shows the data itself (see below), so the
                            # model's own retelling of it is not needed
                            if render_tool_result(fr.name, last_tool[2]) is not None:
                                got_data = True
                                break

                        # Stream text chunks as they arrive; skip the complete copy
                        # of a turn that was already streamed
                        elif getattr(part, "text", None):
                            if event.partial or not turn_streamed:
                                turn_streamed = turn_streamed or bool(event.partial)
                                if looks_runaway(turn.raw + part.text):
                                    print(f"[guard] Runaway model output stopped after "
                                          f"{len(turn.raw)} characters")
                                    runaway = True
                                    break
                                out = emit(turn.feed(part.text))
                                if out:
                                    yield out
                    if runaway or got_data:
                        break

                if not event.partial:
                    # End of one model turn: flush any held-back text, start the next
                    last_turn_raw = turn.raw
                    out = emit(turn.finish())
                    if out:
                        yield out
                    turn, turn_streamed, turn_emitted = TurnCleaner(), False, False

                if event.is_final_response():
                    break
        finally:
            await events.aclose()

        # Safeguards: if the model did not get the data it needed, get it here
        data_tool = last_tool if (tool_was_called and last_tool) else None
        if not data_tool:
            final_clean = "" if runaway else clean_model_text(last_turn_raw).strip()
            needs_data = route_question(query)
            if runaway or not final_clean or (not tool_was_called and needs_data):
                intended = find_tool_in_text(last_turn_raw) or needs_data
                if intended:
                    name, args = intended
                    print(f"[guard] Model did not call a tool; calling {name}({args}) for it")
                    yield f"data: {json.dumps({'type': 'tool_call', 'tool_name': name, 'tool_args': args})}\n\n"
                    result = None
                    try:
                        r = await mcp_client.call_tool(name, args)
                        result = r.structured_content or {
                            "text": "".join(getattr(c, "text", "") for c in r.content)}
                    except Exception as e:
                        print(f"[guard] Tool {name} failed: {e}")
                    yield f"data: {json.dumps({'type': 'tool_response', 'tool_name': name})}\n\n"
                    tool_was_called = True
                    if result is not None:
                        data_tool = (name, args, result)

        if data_tool:
            name, args, result = data_tool
            rendered = render_tool_result(name, result)
            turn_emitted = False
            if rendered:
                # Exact data from the tool, then a short comment from the model
                out = emit(rendered)
                if out:
                    yield out
                turn_emitted = False
                try:
                    async for piece in stream_answer(query, name, args, result, SUMMARY_PROMPT):
                        out = emit(piece)
                        if out:
                            yield out
                except Exception as e:
                    print(f"[guard] Summary request failed: {e}")
            elif runaway or not clean_model_text(last_turn_raw).strip() or got_data:
                # Unknown result shape: let the model write the whole answer
                try:
                    async for piece in stream_answer(query, name, args, result):
                        out = emit(piece)
                        if out:
                            yield out
                except Exception as e:
                    print(f"[guard] Answer request failed: {e}")
                if not turn_emitted:
                    out = emit("I could not get a usable answer from the model this time. "
                               "Please try again or rephrase the question.")
                    if out:
                        yield out
        elif runaway or not accumulated_text.strip():
            out = emit("I could not get a usable answer from the model this time. "
                       "Please try again or rephrase the question.")
            if out:
                yield out

        # Clean history to avoid large system prompts after tool calls (and after
        # an interrupted run, which can leave a half-finished turn in the session)
        if tool_was_called or runaway:
            print(f"[*] MCP tool call detected in session '{session_id}', cleaning history...")
            await session_service.delete_session(
                app_name="bacnet_security_app",
                user_id="web_user",
                session_id=session_id
            )
            await session_service.create_session(
                app_name="bacnet_security_app",
                user_id="web_user",
                session_id=session_id
            )

        final_response_text = accumulated_text or "I apologize, but I couldn't process your request."
        yield f"data: {json.dumps({'type': 'final_response', 'response': final_response_text})}\n\n"

async def on_status_change_cb(status: GetTaskResult) -> None:
    """Callback for MCP task status changes (triggered by anomaly detection)."""
    if status.statusMessage:
        print(f"[*] Task status update: {status.statusMessage}")
        
        # Parse the anomaly data from status message
        anomaly_data = {
            "anomaly_type": "MCP_DETECTED",
            "severity": "medium",
            "description": status.statusMessage,
            "timestamp": datetime.now().isoformat()
        }
        
        # Get agent analysis if available
        message = None
        if agent_service:
            try:
                async with agent_lock:
                    query = f"A task status update was received: {status}. Please report this anomaly politely to the user"
                    analysis_text = await agent_service.process_query(query, session_id="anomaly_session")
                    
                    message = {
                        "type": "anomaly",
                        "data": {
                            "anomaly": anomaly_data,
                            "analysis": analysis_text
                        }
                    }
            except Exception as e:
                print(f"[!] Error getting agent analysis: {e}")
                message = {
                    "type": "anomaly",
                    "data": {"anomaly": anomaly_data}
                }
        else:
            message = {
                "type": "anomaly",
                "data": {"anomaly": anomaly_data}
            }
        
        # Broadcast to all connected WebSocket clients
        if message:
            disconnected = []
            for client in websocket_clients:
                try:
                    await client.send_json(message)
                except:
                    disconnected.append(client)
            
            # Remove disconnected clients
            for client in disconnected:
                websocket_clients.remove(client)

    # Define after_tool_callback to remove content field
async def after_tool_callback(tool: str, args: dict, tool_context: str, tool_response: dict) -> dict:
    """
    Callback to process tool results before sending to LLM.
    Removes the 'content' field to reduce payload size.
    """
    if isinstance(tool_response, dict) and "content" in tool_response:
        # Create a copy without the content field
        filtered_result = {k: v for k, v in tool_response.items() if k != "content"}
        print(f"[*] Removed 'content' field from {tool} result (reduced payload)")
        return filtered_result
    return tool_response

async def initialize_agent():
    """Initialize the AI agent service with MCP Client."""
    global agent_service, mcp_client, mcp_tasks
    
    # Load agent configuration from YAML
    agent_config = load_agent_config()
    system_prompt = agent_config.get("system_prompt", "")

    if not system_prompt:
        print("[!] No system_prompt found in config. Using default instruction.")
        system_prompt = (
            "You are a BACnet network security expert. "
            "Monitor the network for anomalies, analyze device behavior, "
            "and provide security recommendations. "
            "Use the available tools to query devices, anomalies, and statistics. "
            "Present information clearly and highlight critical security issues."
        )
    else:
        print(f"[✓] Loaded system_prompt from config ({len(system_prompt)} chars)")

    try:
        print("[*] Connecting to MCP Server...")
        mcp_client = Client("http://localhost:8081/mcp")
        await mcp_client.__aenter__()
        
        # List and filter tools
        tools = await mcp_client.list_tools()
        trigger_tools = []
        allowed_tools = []
        
        for tool in tools:
            if "trigger" in tool.meta.get("fastmcp", {}).get("tags", []):
                trigger_tools.append(tool.name)
            else:
                allowed_tools.append(tool.name)
        
        print(f"[*] Available tools: {[tool.name for tool in tools]}")
        print(f"[*] Trigger tools: {trigger_tools}")
        print(f"[*] Allowed tools: {allowed_tools}")
        
        # Launch trigger tools as tasks
        for tool_name in trigger_tools:
            task = await mcp_client.call_tool(tool_name, task=True)
            task.on_status_change(on_status_change_cb)
            mcp_tasks.append(task)
            print(f"[*] Started trigger task: {task.task_id}")
        
        # Create agent with system_prompt from config and after_tool_callback
        agent = Agent(
            name="bacnet_security_agent",
            model=LiteLlm(
                model="openai/Qwen2.5-7B-Instruct",
                api_base="http://0.0.0.0:8000/v1",
                api_key="sk-no-required"
            ),
            description="BACnet anomaly detection assistant.",
            instruction=system_prompt,
            tools=[
                McpToolset(
                    connection_params=StreamableHTTPConnectionParams(url="http://localhost:8081/mcp"),
                    tool_filter=allowed_tools,  # Only use allowed tools, not trigger tools
                )
            ],
            after_tool_callback=after_tool_callback  # Add callback to filter results
        )

        await session_service.create_session(
            app_name="bacnet_security_app",
            user_id="web_user",
            session_id="chat_session"
        )
        await session_service.create_session(
            app_name="bacnet_security_app",
            user_id="web_user",
            session_id="anomaly_session"
        )
        
        # Create runner
        runner = Runner(
            agent=agent,
            app_name="bacnet_security_app",
            session_service=session_service
        )
        
        agent_service = AgentService(runner)
        
        # Run first query as set up 
        async with agent_lock:
            await agent_service.process_query("Hi",session_id="chat_session")
            
        print("[✓] AI Agent initialized successfully")
        return True
        
    except Exception as e:
        print(f"[!] Could not initialize AI Agent: {e}")
        print("[*] Agent features will be disabled")
        import traceback
        traceback.print_exc()
        return False

async def broadcast_anomalies():
    """Continuously broadcast anomaly notifications from PCAP monitor to WebSocket clients."""
    while True:
        try:
            anomaly = await anomaly_event.wait_for_anomaly()
            
            """
            # Get agent analysis if available
            if agent_service:
                try:
                    async with agent_lock:
                        analysis = await agent_service.handle_anomaly_notification(anomaly)
                        message = {
                            "type": "anomaly",
                            "data": analysis
                        }
                except Exception as e:
                    print(f"[!] Error getting agent analysis: {e}")
                    message = {
                        "type": "anomaly",
                        "data": {"anomaly": anomaly}
                    }
            else:
                message = {
                    "type": "anomaly",
                    "data": {"anomaly": anomaly}
                }
            """
            message = {
                "type": "anomaly",
                "data": {"anomaly": anomaly}
            }
            
            # Broadcast to all connected clients
            disconnected = []
            for client in websocket_clients:
                try:
                    await client.send_json(message)
                except:
                    disconnected.append(client)
            
            # Remove disconnected clients
            for client in disconnected:
                websocket_clients.remove(client)
        
        except Exception as e:
            print(f"[!] Error broadcasting anomaly: {e}")
            await asyncio.sleep(1)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler for startup and shutdown."""
    global pcap_monitor, anomaly_event
    
    # Startup
    print("=" * 60)
    print("BACnet Security Monitor - Backend Starting")
    print("=" * 60)
    print()
    
    # Create directories
    Path("pcap_files").mkdir(exist_ok=True)
    Path("web/static").mkdir(exist_ok=True)

    # Start every run with an empty database: anomalies, devices and statistics
    # from earlier runs are removed, and the parse records with them, so every
    # capture in pcap_files is analyzed again.
    storage.clear_all_data()
    print("[*] Cleared anomaly database from previous runs")

    # Initialize AI agent with MCP Client
    print("[1/3] Initializing AI Agent with MCP Client...")
    await initialize_agent()
    # Start PCAP monitor with shared anomaly event from MCP server
    print("[2/3] Starting PCAP Monitor...")
    
    pcap_monitor = PCAPMonitor(pcap_directory="./pcap_files", poll_interval=60)
    anomaly_event = pcap_monitor.anomaly_event   # Share the same event instance
    
    asyncio.create_task(pcap_monitor.start())
    
    # Start anomaly notification broadcaster
    print("[3/3] Starting WebSocket Broadcaster...")
    # Broadcast will be handle by Agent callback 
    asyncio.create_task(broadcast_anomalies())
    
    yield
    
    # Shutdown
    if pcap_monitor:
        pcap_monitor.stop()
    
    if mcp_client:
        await mcp_client.__aexit__(None, None, None)



app = FastAPI(
    title="NXP Agentic AI Network Monitoring System",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates."""
    await websocket.accept()
    websocket_clients.append(websocket)
    print(f"[*] WebSocket client connected. Total clients: {len(websocket_clients)}")
    
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    
    except WebSocketDisconnect:
        websocket_clients.remove(websocket)
        print(f"[*] WebSocket client disconnected. Total clients: {len(websocket_clients)}")


@app.get("/api/devices")
async def get_devices():
    """Get all discovered BACnet devices."""
    devices = storage.get_all_devices()
    return {"status": "success", "devices": devices}


@app.get("/api/anomalies")
async def get_anomalies(limit: int = 50, anomaly_type: Optional[str] = None):
    """Get recent anomalies."""
    anomalies = storage.get_recent_anomalies(limit=limit, anomaly_type=anomaly_type)
    return {"status": "success", "anomalies": anomalies}


@app.get("/api/statistics")
async def get_statistics():
    """Get network statistics."""
    stats = storage.get_statistics()
    return {"status": "success", "statistics": stats}


@app.get("/api/device/{instance_number}")
async def get_device(instance_number: int):
    """Get specific device information."""
    device = storage.get_device_info(instance_number)
    
    if device:
        return {"status": "success", "device": device}
    else:
        raise HTTPException(status_code=404, detail="Device not found")


@app.post("/api/query")
async def process_query(request: QueryRequest):
    """Process a user query through the agent with streaming tool-call feedback."""
    if not agent_service:
        raise HTTPException(
            status_code=503, 
            detail="AI Agent service is not available. Please ensure the MCP server is running and the agent is properly configured."
        )

    async def event_generator():
        try:
            async with agent_lock:
                async for event in agent_service.process_query_stream(
                    request.query, session_id="chat_session"
                ):
                    yield event
        except Exception as e:
            print(f"[!] Error processing query: {e}")
            import traceback
            traceback.print_exc()
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/")
async def get_index():
    """Serve the main HTML page."""
    html_file = Path("web/static/index.html")
    if html_file.exists():
        return FileResponse(html_file)
    else:
        return HTMLResponse(content="<h1>BACnet Security Monitor</h1><p>Frontend not found. Please create web/static/index.html</p>")


# Mount static files
static_dir = Path("web/static")
static_dir.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
