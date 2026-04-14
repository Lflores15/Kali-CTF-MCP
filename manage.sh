#!/usr/bin/env bash
# CTF-MCP Server Manager
# Usage:
#   ./manage.sh start [category|all]   # start one or all servers
#   ./manage.sh stop  [category|all]   # stop one or all servers
#   ./manage.sh restart [category|all] # restart one or all servers
#   ./manage.sh status                 # show running servers

set -euo pipefail

VENV_PYTHON="/Users/louisflores/Documents/Code/Kali-venv/Kali-venv/bin/python"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_DIR="$SCRIPT_DIR/.pids"
LOG_DIR="$SCRIPT_DIR/.logs"

mkdir -p "$PID_DIR" "$LOG_DIR"

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

    if is_running "$category"; then
        echo "  [already running] $category → http://localhost:$port/sse (pid $(cat "$(pid_file "$category")"))"
        return
    fi

    nohup "$VENV_PYTHON" "$SCRIPT_DIR/sse_server.py" "$category" "$port" \
        > "$(log_file "$category")" 2>&1 &

    local pid=$!
    echo "$pid" > "$(pid_file "$category")"
    sleep 0.4

    if is_running "$category"; then
        echo "  [started] $category → http://localhost:$port/sse (pid $pid)"
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
    echo "CTF-MCP Server Status"
    echo "---------------------"
    for cat in "${ALL_CATEGORIES[@]}"; do
        local port="${PORTS[$cat]}"
        if is_running "$cat"; then
            local pid; pid=$(cat "$(pid_file "$cat")")
            echo "  RUNNING  $cat → http://localhost:$port/sse  (pid $pid)"
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
        echo "Usage: $0 {start|stop|restart|status|logs} [category|all]"
        echo ""
        echo "Categories: ${ALL_CATEGORIES[*]}"
        echo "Ports:      full=8000 crypto=8001 web=8002 pwn=8003 reverse=8004 forensics=8005"
        exit 1
        ;;
esac
