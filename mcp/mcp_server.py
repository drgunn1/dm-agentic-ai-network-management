"""
Copyright 2026 NXP
SPDX-License-Identifier: BSD-3-Clause
"""

import asyncio
import inspect
import sys
from fastmcp import FastMCP
from fastmcp.dependencies import Progress
from fastmcp.utilities.logging import get_logger
from pathlib import Path
from pydantic import BaseModel, Field
from typing import Optional

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from bacnet.anomaly_storage import AnomalyStorage
from bacnet.pcap_monitor import PCAPMonitor

logger = get_logger(__name__)


class DeviceInfo(BaseModel):
    instance_number: int
    ip_addresses: list[str] = Field(default_factory=list)
    mac_addresses: list[str] = Field(default_factory=list)
    mstp_addresses: list[str] = Field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    packet_count: int = 0

class DevicesResponse(BaseModel):
    status: str
    count: int
    devices: list[DeviceInfo]

class AnomalyInfo(BaseModel):
    # Compact on purpose: the whole LLM prompt (system prompt, tool definitions,
    # question and this result) must fit in the connector's 2047-token window.
    anomaly_type: str
    severity: str
    description: str
    action: Optional[str] = None
    timestamp: str

class AnomaliesResponse(BaseModel):
    status: str
    count: int
    total: int = 0
    omitted: int = 0
    anomalies: list[AnomalyInfo]

# Character budget for the anomalies returned (about 900 tokens; IPs and JSON
# punctuation tokenize at ~2.6 characters per token). The web backend shows this
# result itself and only sends it to the model in a short prompt asking for a
# comment (about 1,100 tokens in all), well inside the 2047-token window.
ANOMALY_RESULT_BUDGET = 2400
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _clip(text: str, n: int) -> str:
    return text if len(text) <= n else text[:n - 3].rstrip() + "..."


def _compact_anomaly(a: dict) -> AnomalyInfo:
    action = (a.get("details") or {}).get("recommended_action")
    return AnomalyInfo(
        anomaly_type=a["anomaly_type"],
        severity=a["severity"],
        description=_clip(a["description"], 160),
        action=_clip(action, 120) if action else None,
        timestamp=a["timestamp"][:19].replace("T", " "),
    )

class StatisticsInfo(BaseModel):
    total_devices: int = 0
    total_anomalies: int = 0
    unresolved_anomalies: int = 0
    total_packets: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)
    type_counts: dict[str, int] = Field(default_factory=dict)
    last_updated: str = ""

class StatisticsResponse(BaseModel):
    status: str
    statistics: StatisticsInfo

class DeviceDetailResponse(BaseModel):
    status: str
    device: Optional[DeviceInfo] = None
    error_message: Optional[str] = None

class ResolveAnomalyResponse(BaseModel):
    status: str
    anomaly_id: int
    message: str

# Initialize the server
mcp = FastMCP("BACnet Security MCP Server")

# Initialize storage
storage = AnomalyStorage()

@mcp.tool()
def get_bacnet_anomalies(limit: int = 5) -> AnomaliesResponse:
    """Retrieves the most severe BACnet network anomalies, most severe first.

    Args:
        limit: Maximum number of anomalies to return (default: 5). Only as many as
            fit in the model's context are returned; "omitted" counts the rest.

    Returns:
        AnomaliesResponse: Anomalies with type, severity, description,
        recommended action and timestamp.
    """
    logger.info(f"Tool: get_bacnet_anomalies called with limit={limit}")
    # Rank the latest 200 (the database is cleared at every start) by severity,
    # so a critical anomaly is never hidden behind newer low ones.
    recent = storage.get_recent_anomalies(limit=200)
    recent.sort(key=lambda a: (SEVERITY_RANK.get(a["severity"], 9), -a["id"]))

    selected, used = [], 0
    for a in recent:
        item = _compact_anomaly(a)
        size = len(item.model_dump_json())
        if len(selected) >= max(1, limit) or (selected and used + size > ANOMALY_RESULT_BUDGET):
            break
        selected.append(item)
        used += size
    return AnomaliesResponse(
        status="success",
        anomalies=selected,
        count=len(selected),
        total=len(recent),
        omitted=len(recent) - len(selected),
    )


@mcp.tool()
def get_network_statistics() -> StatisticsResponse:
    """Retrieves BACnet network statistics and health metrics.

    Returns:
        StatisticsResponse: Network statistics and metrics.
    """
    logger.info("Tool: get_network_statistics called")
    stats = storage.get_statistics()
    return StatisticsResponse(status="success", statistics=stats)


@mcp.tool()
def get_device_details(instance_number: int) -> DeviceDetailResponse:
    """Retrieves detailed information about a specific BACnet device.

    Args:
        instance_number: The BACnet device instance number.

    Returns:
        DeviceDetailResponse: Device details or error message.
    """
    logger.info(f"Tool: get_device_details called for instance {instance_number}")
    device = storage.get_device_info(instance_number)

    if device:
        return DeviceDetailResponse(
            status="success",
            device=DeviceInfo(**device),
        )
    else:
        return DeviceDetailResponse(
            status="error",
            error_message=f"Device instance {instance_number} not found",
        )


# Run the server
if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=8081)
