#!/bin/sh
# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
# Start the Agentic Network Management demo once the eIQ AAF Connector has
# finished loading its model onto the Ara240:
#   1. wait until the connector's /v1/models reports every model ready
#   2. start the MCP server and wait until it accepts connections
#   3. run the web backend in the foreground (Ctrl+C stops both)
#
# With --wait-connector it only does step 1 and exits (0 = ready).
#
# Environment overrides:
#   CONNECTOR_URL      connector base URL     (default http://127.0.0.1:8000)
#   CONNECTOR_TIMEOUT  seconds to wait for it (default 600)
#   MCP_PORT           MCP server port        (default 8081)

set -u
cd "$(dirname "$0")" || exit 1

CONNECTOR_URL=${CONNECTOR_URL:-http://127.0.0.1:8000}
CONNECTOR_TIMEOUT=${CONNECTOR_TIMEOUT:-600}
MCP_PORT=${MCP_PORT:-8081}

# A manual run would fight the systemd services over ports 8080/8081.
if [ "${1:-}" != "--wait-connector" ] && [ -z "${INVOCATION_ID:-}" ]; then
    for svc in bacnet-backend bacnet-mcp; do
        state=$(systemctl is-active "$svc" 2>/dev/null)
        if [ "$state" = "active" ] || [ "$state" = "activating" ]; then
            echo "[!] The demo is already running as the $svc service."
            echo "    Watch its console output:  journalctl -fu bacnet-backend"
            echo "    Or stop it to run here:    systemctl stop bacnet-backend bacnet-mcp"
            exit 1
        fi
    done
fi

# True when the connector answers and no model is still loading.
connector_ready() {
    body=$(curl -sf --max-time 5 "$CONNECTOR_URL/v1/models") || return 1
    case $body in
        *'"ready":true'*) case $body in *'"ready":false'*) return 1 ;; esac; return 0 ;;
    esac
    return 1
}

echo "[*] Waiting for the eIQ AAF Connector at $CONNECTOR_URL to finish loading the model..."
start=$(date +%s)
until connector_ready; do
    waited=$(( $(date +%s) - start ))
    if [ "$waited" -ge "$CONNECTOR_TIMEOUT" ]; then
        echo "[!] Connector not ready after ${waited}s."
        echo "    Check it with: systemctl status eiq-aaf-connector; journalctl -u eiq-aaf-connector -b"
        exit 1
    fi
    state=$(systemctl is-active eiq-aaf-connector 2>/dev/null || true)
    if [ -t 1 ]; then
        printf '\r    %4ds elapsed (service: %s)   ' "$waited" "${state:-not a service}"
    elif [ $((waited % 10)) -lt 2 ]; then
        echo "    ${waited}s elapsed (service: ${state:-not a service})"
    fi
    sleep 2
done
printf '\r[✓] Connector ready after %ss                              \n' "$(( $(date +%s) - start ))"

# --wait-connector: only wait (used by the bacnet-backend systemd service)
[ "${1:-}" = "--wait-connector" ] && exit 0

echo "[*] Starting MCP server on port $MCP_PORT..."
uv run mcp/mcp_server.py &
mcp_pid=$!
trap 'kill $mcp_pid 2>/dev/null; wait $mcp_pid 2>/dev/null' EXIT
trap 'exit 130' INT TERM

# curl exits with 7 while nothing is listening; any HTTP answer means it is up.
i=0
while curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$MCP_PORT/mcp"; [ $? -eq 7 ]; do
    if ! kill -0 "$mcp_pid" 2>/dev/null; then
        echo "[!] MCP server exited during start-up."
        exit 1
    fi
    i=$((i + 1))
    if [ "$i" -ge 60 ]; then
        echo "[!] MCP server not listening on port $MCP_PORT after 60s."
        exit 1
    fi
    sleep 1
done
echo "[✓] MCP server is up"

echo "[*] Starting web backend (dashboard on port 8080)..."
uv run web/backend.py
