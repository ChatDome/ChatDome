#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="chatdome"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
MENU_LINK="/usr/local/bin/chatdome"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run as root so the installer can create the systemd unit and menu symlink." >&2
  exit 1
fi

cd "$ROOT_DIR"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required." >&2
  exit 1
fi

python3 -m venv "$ROOT_DIR/venv"
"$ROOT_DIR/venv/bin/python" -m pip install --no-cache-dir --upgrade pip
"$ROOT_DIR/venv/bin/python" -m pip install --no-cache-dir -e "$ROOT_DIR/controlplane"

if [[ ! -f "$ROOT_DIR/config.yaml" ]]; then
  cp "$ROOT_DIR/config.example.yaml" "$ROOT_DIR/config.yaml"
fi
chmod 600 "$ROOT_DIR/config.yaml" || true
mkdir -p "$ROOT_DIR/chat_data"

cat >"$SERVICE_PATH" <<UNIT
[Unit]
Description=ChatDome AI Host Security Assistant
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$ROOT_DIR
ExecStart=$ROOT_DIR/venv/bin/chatdome-server --config $ROOT_DIR/config.yaml
Restart=on-failure
RestartSec=5
User=root
Group=root
Environment=PYTHONUNBUFFERED=1

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

Config: $ROOT_DIR/config.yaml
Service: $SERVICE_PATH
DONE
