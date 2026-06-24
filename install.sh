#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="chatdome"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
MENU_LINK="/usr/local/bin/chatdome"
CONFIG_DIR="${CHATDOME_CONFIG_DIR:-/etc/chatdome}"
CONFIG_FILE="${CHATDOME_CONFIG:-$CONFIG_DIR/config.yaml}"
DATA_DIR="${CHATDOME_DATA_DIR:-/var/lib/chatdome}"
LOG_DIR="${CHATDOME_LOG_DIR:-/var/log/chatdome}"
LOG_FILE="${CHATDOME_LOG_FILE:-$LOG_DIR/chatdome.log}"
VENV_ROOT="${CHATDOME_VENV_ROOT:-$DATA_DIR/venvs}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash $ROOT_DIR/install.sh" >&2
  exit 1
fi

cd "$ROOT_DIR"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required." >&2
  exit 1
fi

install -d -m 0750 "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"

if [[ ! -f "$CONFIG_FILE" ]]; then
  if [[ -f "$ROOT_DIR/config.yaml" ]]; then
    cp -p "$ROOT_DIR/config.yaml" "$CONFIG_FILE"
  else
    cp "$ROOT_DIR/config.example.yaml" "$CONFIG_FILE"
  fi
fi
chmod 600 "$CONFIG_FILE"

if [[ -d "$ROOT_DIR/chat_data" && ! -L "$ROOT_DIR/chat_data" ]]; then
  cp -a "$ROOT_DIR/chat_data/." "$DATA_DIR/"
  rm -rf "$ROOT_DIR/chat_data"
fi
if [[ -f "$DATA_DIR/chatdome.log" ]]; then
  if [[ ! -f "$LOG_FILE" ]]; then
    mv "$DATA_DIR/chatdome.log" "$LOG_FILE"
  else
    rm -f "$DATA_DIR/chatdome.log"
  fi
fi
rm -f "$ROOT_DIR/config.yaml"
touch "$LOG_FILE"
chmod 0640 "$LOG_FILE"

VERSION_ID="${CHATDOME_VERSION_ID:-$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || date -u +install-%Y%m%d%H%M%S)}"
VENV_PATH="$VENV_ROOT/$VERSION_ID"

if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
  systemctl stop "$SERVICE_NAME"
fi
install -d -m 0750 "$VENV_ROOT"
rm -rf "$VENV_PATH"
python3 -m venv "$VENV_PATH"
"$VENV_PATH/bin/python" -m pip install --no-cache-dir --upgrade pip
"$VENV_PATH/bin/python" -m pip install --no-cache-dir -e "$ROOT_DIR/controlplane"
rm -rf "$ROOT_DIR/venv"
ln -s "$VENV_PATH" "$ROOT_DIR/venv"

cat >"$SERVICE_PATH" <<UNIT
[Unit]
Description=ChatDome AI Host Security Assistant
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$DATA_DIR
ExecStart=$VENV_PATH/bin/python -m chatdome.main --config $CONFIG_FILE
Restart=on-failure
RestartSec=5
User=root
Group=root
Environment=PYTHONUNBUFFERED=1
Environment=CHATDOME_CONFIG=$CONFIG_FILE
Environment=CHATDOME_DATA_DIR=$DATA_DIR
Environment=CHATDOME_LOG_DIR=$LOG_DIR
Environment=CHATDOME_LOG_FILE=$LOG_FILE

[Install]
WantedBy=multi-user.target
UNIT

chmod +x "$ROOT_DIR/chatdome" "$ROOT_DIR/chatdome-cli.py" "$ROOT_DIR/scripts/start.sh"
ln -sf "$ROOT_DIR/chatdome" "$MENU_LINK"

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

cat <<DONE
ChatDome installed.

Next steps:
  1. Run: chatdome
  2. Configure Telegram Bot Token and allowed Chat IDs.
  3. Start the service from the menu.

Config: $CONFIG_FILE
Data: $DATA_DIR
Log: $LOG_FILE
Service: $SERVICE_PATH
DONE
