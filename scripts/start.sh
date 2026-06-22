#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="${CHATDOME_CONFIG:-/etc/chatdome/config.yaml}"
DATA_DIR="${CHATDOME_DATA_DIR:-/var/lib/chatdome}"
LOG_DIR="${CHATDOME_LOG_DIR:-/var/log/chatdome}"
LOG_FILE="${CHATDOME_LOG_FILE:-$LOG_DIR/chatdome.log}"
PID_FILE="$DATA_DIR/chatdome.pid"
ACTION="${1:-start}"

export CHATDOME_CONFIG="$CONFIG_FILE"
export CHATDOME_DATA_DIR="$DATA_DIR"
export CHATDOME_LOG_DIR="$LOG_DIR"
export CHATDOME_LOG_FILE="$LOG_FILE"

if [[ -x "$ROOT_DIR/venv/bin/chatdome-server" ]]; then
  SERVER_BIN="$ROOT_DIR/venv/bin/chatdome-server"
elif command -v chatdome-server >/dev/null 2>&1; then
  SERVER_BIN="$(command -v chatdome-server)"
else
  SERVER_BIN="python3 -m chatdome.main"
fi

is_running() {
  [[ -f "$PID_FILE" ]] || return 1
  local pid
  pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  [[ -n "$pid" ]] || return 1
  kill -0 "$pid" >/dev/null 2>&1
}

start_service() {
  mkdir -p "$DATA_DIR" "$LOG_DIR"
  if is_running; then
    echo "ChatDome already running (pid=$(cat "$PID_FILE"))."
    return
  fi
  cd "$DATA_DIR"
  nohup $SERVER_BIN --config "$CONFIG_FILE" >/dev/null 2>>"$LOG_FILE" &
  local pid=$!
  echo "$pid" >"$PID_FILE"
  sleep 1
  if ! kill -0 "$pid" >/dev/null 2>&1; then
    rm -f "$PID_FILE"
    echo "ChatDome failed to start. Check $LOG_FILE." >&2
    return 1
  fi
  echo "ChatDome started (pid=$pid)."
}

stop_service() {
  if ! is_running; then
    echo "ChatDome is not running."
    return
  fi
  local pid
  pid="$(cat "$PID_FILE")"
  kill "$pid" >/dev/null 2>&1 || true
  for _ in $(seq 1 20); do
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      rm -f "$PID_FILE"
      echo "ChatDome stopped."
      return
    fi
    sleep 0.5
  done
  kill -9 "$pid" >/dev/null 2>&1 || true
  rm -f "$PID_FILE"
  echo "ChatDome force stopped."
}

case "$ACTION" in
  start) start_service ;;
  stop) stop_service ;;
  restart)
    stop_service
    start_service
    ;;
  status)
    if is_running; then
      echo "ChatDome running (pid=$(cat "$PID_FILE"))."
    else
      echo "ChatDome not running."
      exit 1
    fi
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|status}" >&2
    exit 2
    ;;
esac
