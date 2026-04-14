#!/usr/bin/env bash
# CTF-MCP Server Manager
# Usage:
#   ./manage.sh start [category|all] [--transport sse|streamable]
#   ./manage.sh stop  [category|all]
#   ./manage.sh restart [category|all] [--transport sse|streamable]
#   ./manage.sh status
#   ./manage.sh logs <category>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load .env if present (allows overriding VENV_PYTHON and other vars)
if [[ -f "$SCRIPT_DIR/.env" ]]; then
    set -o allexport
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/.env"
    set +o allexport
fi

# Default to system python3 if VENV_PYTHON not set
VENV_PYTHON="${VENV_PYTHON:-python3}"
PID_DIR="$SCRIPT_DIR/.pids"
LOG_DIR="$SCRIPT_DIR/.logs"

mkdir -p "$PID_DIR" "$LOG_DIR"

# Parse --transport flag from remaining args (can appear anywhere)
TRANSPORT="sse"
FILTERED_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --transport)
            TRANSPORT="$2"
            shift 2
            ;;
        *)
            FILTERED_ARGS+=("$1")
            shift
            ;;
    esac
done
set -- "${FILTERED_ARGS[@]+"${FILTERED_ARGS[@]}"}"

if [[ "$TRANSPORT" != "sse" && "$TRANSPORT" != "streamable" ]]; then
    echo "Invalid transport '$TRANSPORT'. Choose: sse, streamable"
    exit 1
fi

# Endpoint path differs by transport
endpoint_path() {
    [[ "$TRANSPORT" == "streamable" ]] && echo "/mcp" || echo "/sse"
}

# Category → port mapping
declare -A PORTS=(
    [full]=8000
    [crypto]=8001
    [web]=8002
    [pwn]=8003
    [reverse]=8004
    [forensics]=8005
)

ALL_CATEGORIES=(full crypto web pwn reverse forensics)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

pid_file()  { echo "$PID_DIR/$1.pid"; }
log_file()  { echo "$LOG_DIR/$1.log"; }

is_running() {
    local category="$1"
    local pf; pf=$(pid_file "$category")
    [[ -f "$pf" ]] && kill -0 "$(cat "$pf")" 2>/dev/null
}

start_one() {
    local category="$1"
    local port="${PORTS[$category]}"
    local ep; ep=$(endpoint_path)

    if is_running "$category"; then
        echo "  [already running] $category → http://localhost:$port$ep (pid $(cat "$(pid_file "$category")"))"
        return
    fi

    nohup "$VENV_PYTHON" "$SCRIPT_DIR/sse_server.py" "$category" "$port" --transport "$TRANSPORT" \
        > "$(log_file "$category")" 2>&1 &

    local pid=$!
    echo "$pid" > "$(pid_file "$category")"
    sleep 0.4

    if is_running "$category"; then
        echo "  [started] $category → http://localhost:$port$ep (pid $pid) [$TRANSPORT]"
    else
        echo "  [FAILED]  $category — check $(log_file "$category")"
        rm -f "$(pid_file "$category")"
    fi
}

stop_one() {
    local category="$1"
    local pf; pf=$(pid_file "$category")

    if ! is_running "$category"; then
        echo "  [not running] $category"
        rm -f "$pf"
        return
    fi

    local pid; pid=$(cat "$pf")
    kill "$pid" 2>/dev/null && echo "  [stopped] $category (pid $pid)" || echo "  [error]   $category"
    rm -f "$pf"
}

status_all() {
    local ep; ep=$(endpoint_path)
    echo "CTF-MCP Server Status  [transport: $TRANSPORT]"
    echo "---------------------"
    for cat in "${ALL_CATEGORIES[@]}"; do
        local port="${PORTS[$cat]}"
        if is_running "$cat"; then
            local pid; pid=$(cat "$(pid_file "$cat")")
            echo "  RUNNING  $cat → http://localhost:$port$ep  (pid $pid)"
        else
            echo "  STOPPED  $cat → port $port"
        fi
    done
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

CMD="${1:-status}"
TARGET="${2:-}"

case "$CMD" in
    start)
        if [[ "$TARGET" == "all" || -z "$TARGET" ]]; then
            echo "Starting all CTF-MCP servers..."
            for cat in "${ALL_CATEGORIES[@]}"; do start_one "$cat"; done
        elif [[ -v "PORTS[$TARGET]" ]]; then
            start_one "$TARGET"
        else
            echo "Unknown category: $TARGET"
            echo "Valid: ${!PORTS[*]}"
            exit 1
        fi
        ;;

    stop)
        if [[ "$TARGET" == "all" || -z "$TARGET" ]]; then
            echo "Stopping all CTF-MCP servers..."
            for cat in "${ALL_CATEGORIES[@]}"; do stop_one "$cat"; done
        elif [[ -v "PORTS[$TARGET]" ]]; then
            stop_one "$TARGET"
        else
            echo "Unknown category: $TARGET"
            exit 1
        fi
        ;;

    restart)
        TARGET="${TARGET:-all}"
        bash "$0" stop  "$TARGET"
        sleep 0.5
        bash "$0" start "$TARGET"
        ;;

    status)
        status_all
        ;;

    logs)
        if [[ -z "$TARGET" ]]; then
            echo "Usage: $0 logs <category>"
            exit 1
        fi
        tail -f "$(log_file "$TARGET")"
        ;;

    *)
        echo "Usage: $0 {start|stop|restart|status|logs} [category|all] [--transport sse|streamable]"
        echo ""
        echo "Categories:  ${ALL_CATEGORIES[*]}"
        echo "Ports:       full=8000 crypto=8001 web=8002 pwn=8003 reverse=8004 forensics=8005"
        echo "Transports:  sse (default, GET /sse + POST /messages)"
        echo "             streamable (POST /mcp — current MCP spec)"
        exit 1
        ;;
esac
