#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="chatdome"
REPO_URL="${CHATDOME_REPO_URL:-https://github.com/ChatDome/ChatDome.git}"
REMOTE_INSTALL_DIR="${CHATDOME_INSTALL_DIR:-/opt/chatdome}"
CHATDOME_REF="${CHATDOME_REF:-main}"
SERVICE_PATH="${CHATDOME_SERVICE_PATH:-/etc/systemd/system/${SERVICE_NAME}.service}"
MENU_LINK="${CHATDOME_COMMAND_PATH:-/usr/local/bin/chatdome}"
CONFIG_DIR="${CHATDOME_CONFIG_DIR:-/etc/chatdome}"
CONFIG_FILE="${CHATDOME_CONFIG:-$CONFIG_DIR/config.yaml}"
if [[ -n "${CHATDOME_CONFIG:-}" && -z "${CHATDOME_CONFIG_DIR:-}" ]]; then
  CONFIG_DIR="$(dirname "$CONFIG_FILE")"
fi
DATA_DIR="${CHATDOME_DATA_DIR:-/var/lib/chatdome}"
LOG_DIR="${CHATDOME_LOG_DIR:-/var/log/chatdome}"
LOG_FILE="${CHATDOME_LOG_FILE:-$LOG_DIR/chatdome.log}"
VENV_ROOT="${CHATDOME_VENV_ROOT:-$DATA_DIR/venvs}"

DRY_RUN=0
START_AFTER_INSTALL=0
ORIGINAL_ARGS=("$@")
TMP_DIR=""
CANDIDATE_VENV=""

cleanup_tmp() {
  if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
    rm -rf "$TMP_DIR"
  fi
  if [[ -n "$CANDIDATE_VENV" && -d "$CANDIDATE_VENV" ]]; then
    rm -rf "$CANDIDATE_VENV"
  fi
}
trap cleanup_tmp EXIT

fail() {
  echo "$1" >&2
  exit "${2:-1}"
}

usage() {
  cat <<'USAGE'
Usage:
  sudo bash install.sh [--start]
  bash install.sh --dry-run
  bash install.sh --help

Remote install:
  curl -fsSL https://raw.githubusercontent.com/ChatDome/ChatDome/main/install.sh -o /tmp/chatdome-install.sh && sudo bash /tmp/chatdome-install.sh

Options:
  --dry-run    Print planned actions.
  --start      Start chatdome.service after installation.
  --help       Show this help.

Environment:
  CHATDOME_INSTALL_DIR   Program directory for remote install. Default: /opt/chatdome
  CHATDOME_REF           Git branch, tag, or commit. Default: main
  CHATDOME_CONFIG_DIR    Config directory. Default: /etc/chatdome
  CHATDOME_CONFIG        Config file. Default: /etc/chatdome/config.yaml
  CHATDOME_DATA_DIR      Data directory. Default: /var/lib/chatdome
  CHATDOME_LOG_DIR       Log directory. Default: /var/log/chatdome
  CHATDOME_LOG_FILE      Log file. Default: /var/log/chatdome/chatdome.log
  CHATDOME_VENV_ROOT     Python environment directory. Default: /var/lib/chatdome/venvs
USAGE
}

parse_args() {
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --dry-run)
        DRY_RUN=1
        ;;
      --start)
        START_AFTER_INSTALL=1
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        fail "Unknown option: $1"
        ;;
    esac
    shift
  done
}

script_dir() {
  local source="${BASH_SOURCE[0]:-$0}"
  if [[ -f "$source" ]]; then
    cd -P "$(dirname "$source")" >/dev/null 2>&1
    pwd
    return
  fi

  if [[ "$source" == */* && -f "$source" ]]; then
    cd -P "$(dirname "$source")" >/dev/null 2>&1
    pwd
    return
  fi

  printf '\n'
}

source_tree_complete() {
  local dir="$1"
  [[ -n "$dir" ]] || return 1
  [[ -f "$dir/install.sh" ]] || return 1
  [[ -x "$dir/chatdome" || -f "$dir/chatdome" ]] || return 1
  [[ -f "$dir/config.example.yaml" ]] || return 1
  [[ -f "$dir/controlplane/pyproject.toml" || -f "$dir/controlplane/setup.py" ]] || return 1
  [[ -d "$dir/controlplane/src/chatdome" ]] || return 1
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    fail "Run as root: sudo bash install.sh"
  fi
}

require_absolute_path() {
  local name="$1" path="$2"
  [[ "$path" == /* ]] || fail "$name must be an absolute path: $path"
  [[ "$path" != "/" ]] || fail "$name cannot be /"
}

validate_paths() {
  require_absolute_path "CHATDOME_INSTALL_DIR" "$REMOTE_INSTALL_DIR"
  require_absolute_path "CHATDOME_CONFIG_DIR" "$CONFIG_DIR"
  require_absolute_path "CHATDOME_CONFIG" "$CONFIG_FILE"
  require_absolute_path "CHATDOME_DATA_DIR" "$DATA_DIR"
  require_absolute_path "CHATDOME_LOG_DIR" "$LOG_DIR"
  require_absolute_path "CHATDOME_LOG_FILE" "$LOG_FILE"
  require_absolute_path "CHATDOME_VENV_ROOT" "$VENV_ROOT"
  require_absolute_path "CHATDOME_SERVICE_PATH" "$SERVICE_PATH"
  require_absolute_path "CHATDOME_COMMAND_PATH" "$MENU_LINK"
}

missing_dependencies() {
  local missing=()

  command -v git >/dev/null 2>&1 || missing+=("git")
  command -v python3 >/dev/null 2>&1 || missing+=("python3")
  command -v systemctl >/dev/null 2>&1 || missing+=("systemctl")

  if command -v python3 >/dev/null 2>&1; then
    python3 -m venv --help >/dev/null 2>&1 || missing+=("python3-venv")
  fi

  if [[ "${#missing[@]}" -gt 0 ]]; then
    printf '%s\n' "${missing[@]}"
  fi
}

dependency_install_command() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "apt-get update && apt-get install -y git python3 python3-venv systemd"
  elif command -v dnf >/dev/null 2>&1; then
    echo "dnf install -y git python3 systemd"
  elif command -v yum >/dev/null 2>&1; then
    echo "yum install -y git python3 systemd"
  elif command -v pacman >/dev/null 2>&1; then
    echo "pacman -Sy --needed --noconfirm git python python-virtualenv systemd"
  elif command -v zypper >/dev/null 2>&1; then
    echo "zypper --non-interactive install git python3 systemd"
  else
    return 1
  fi
}

confirm_dependency_install() {
  local answer
  if [[ ! -r /dev/tty || ! -w /dev/tty ]]; then
    return 1
  fi

  printf 'Install now? [y/N]: ' >/dev/tty
  read -r answer </dev/tty || return 1
  case "$answer" in
    y|Y|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

dependencies_ok() {
  local install_cmd missing_text
  local -a missing
  mapfile -t missing < <(missing_dependencies)

  if [[ "${#missing[@]}" -eq 0 ]]; then
    return 0
  fi

  missing_text="${missing[*]}"
  echo "Missing dependencies: $missing_text" >&2

  if install_cmd="$(dependency_install_command)"; then
    echo "Install command: $install_cmd" >&2
    if confirm_dependency_install; then
      bash -c "$install_cmd"
      mapfile -t missing < <(missing_dependencies)
      if [[ "${#missing[@]}" -eq 0 ]]; then
        return 0
      fi
      echo "Missing dependencies: ${missing[*]}" >&2
    fi
  fi

  echo "Install dependencies and rerun: git python3 python3-venv systemd" >&2
  return 1
}

dependency_status() {
  if command -v git >/dev/null 2>&1; then
    echo "[dry-run] Dependency git: ok"
  else
    echo "[dry-run] Dependency git: missing"
  fi

  if command -v python3 >/dev/null 2>&1; then
    echo "[dry-run] Dependency python3: ok"
    if python3 -m venv --help >/dev/null 2>&1; then
      echo "[dry-run] Dependency python3-venv: ok"
    else
      echo "[dry-run] Dependency python3-venv: missing"
    fi
  else
    echo "[dry-run] Dependency python3: missing"
    echo "[dry-run] Dependency python3-venv: missing"
  fi

  if command -v systemctl >/dev/null 2>&1; then
    echo "[dry-run] Dependency systemctl: ok"
  else
    echo "[dry-run] Dependency systemctl: missing"
  fi
}

git_clean_enough() {
  local dir="$1"
  git -C "$dir" diff --quiet &&
    git -C "$dir" diff --cached --quiet
}

fetch_ref() {
  local dir="$1" ref="$2"

  git -C "$dir" fetch --depth 1 origin "$ref" >/dev/null 2>&1 ||
    git -C "$dir" fetch --depth 1 origin "refs/heads/$ref" >/dev/null 2>&1 ||
    git -C "$dir" fetch --depth 1 origin "refs/tags/$ref" >/dev/null 2>&1
}

checkout_ref() {
  local dir="$1" ref="$2"
  git_clean_enough "$dir" || fail "Install dir has local changes: $dir"
  if git -C "$dir" rev-parse --verify --quiet "$ref^{commit}" >/dev/null; then
    git -C "$dir" checkout --detach "$ref" >/dev/null 2>&1 ||
      fail "Failed: git checkout $ref. Check $dir."
    return
  fi
  fetch_ref "$dir" "$ref" || fail "Failed: git fetch $ref. Check network and retry."
  git -C "$dir" checkout --detach FETCH_HEAD >/dev/null 2>&1 ||
    fail "Failed: git checkout $ref. Check $dir."
}

prepare_remote_source() {
  local parent
  parent="$(dirname "$REMOTE_INSTALL_DIR")"
  install -d -m 0755 "$parent"

  if [[ -d "$REMOTE_INSTALL_DIR/.git" ]]; then
    checkout_ref "$REMOTE_INSTALL_DIR" "$CHATDOME_REF"
    return
  fi

  if [[ -e "$REMOTE_INSTALL_DIR" ]]; then
    fail "Install dir exists and is not a Git repository: $REMOTE_INSTALL_DIR"
  fi

  TMP_DIR="$(mktemp -d)"
  if ! git clone --depth 1 --branch "$CHATDOME_REF" "$REPO_URL" "$TMP_DIR" >/dev/null 2>&1; then
    rm -rf "$TMP_DIR"
    TMP_DIR="$(mktemp -d)"
    git clone "$REPO_URL" "$TMP_DIR" >/dev/null 2>&1 ||
      fail "Failed: git clone $REPO_URL. Check network and retry."
    checkout_ref "$TMP_DIR" "$CHATDOME_REF"
  fi

  mv "$TMP_DIR" "$REMOTE_INSTALL_DIR"
  TMP_DIR=""
}

dry_run_summary() {
  local mode="$1" root_dir="$2" version_label
  if [[ "$mode" == "local" && -d "$root_dir/.git" ]]; then
    version_label="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || true)"
  else
    version_label="$CHATDOME_REF"
  fi
  [[ -n "$version_label" ]] || version_label="install"

  echo "[dry-run] Mode:             $mode"
  if [[ "$mode" == "remote" ]]; then
    echo "[dry-run] Would clone:      $REPO_URL"
    echo "[dry-run] Would checkout:   $CHATDOME_REF"
  fi
  echo "[dry-run] Would install to: $root_dir"
  echo "[dry-run] Would use config: $CONFIG_FILE"
  echo "[dry-run] Would use data:   $DATA_DIR"
  echo "[dry-run] Would use logs:   $LOG_FILE"
  echo "[dry-run] Would create venv: $VENV_ROOT/$version_label"
  echo "[dry-run] Would create service: $SERVICE_PATH"
  echo "[dry-run] Would link command:   $MENU_LINK"
  if [[ "$START_AFTER_INSTALL" -eq 1 ]]; then
    echo "[dry-run] Would start service: yes"
  else
    echo "[dry-run] Would start service: no"
  fi
  dependency_status
}

version_id_for() {
  local root_dir="$1" raw
  raw="${CHATDOME_VERSION_ID:-}"
  if [[ -z "$raw" ]]; then
    raw="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || date -u +install-%Y%m%d%H%M%S)"
  fi
  raw="${raw//[^A-Za-z0-9._-]/_}"
  [[ -n "$raw" ]] || raw="install"
  printf '%s\n' "$raw"
}

install_config_and_data() {
  local root_dir="$1"

  install -d -m 0750 "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"

  if [[ ! -f "$CONFIG_FILE" ]]; then
    if [[ -f "$root_dir/config.yaml" ]]; then
      cp -p "$root_dir/config.yaml" "$CONFIG_FILE"
    else
      [[ -f "$root_dir/config.example.yaml" ]] ||
        fail "Missing file: $root_dir/config.example.yaml"
      cp "$root_dir/config.example.yaml" "$CONFIG_FILE"
    fi
  fi
  chmod 600 "$CONFIG_FILE"

  if [[ -d "$root_dir/chat_data" && ! -L "$root_dir/chat_data" ]]; then
    cp -a "$root_dir/chat_data/." "$DATA_DIR/"
    rm -rf "$root_dir/chat_data"
  fi

  if [[ -f "$DATA_DIR/chatdome.log" ]]; then
    if [[ ! -f "$LOG_FILE" ]]; then
      mv "$DATA_DIR/chatdome.log" "$LOG_FILE"
    else
      rm -f "$DATA_DIR/chatdome.log"
    fi
  fi

  rm -f "$root_dir/config.yaml"
  touch "$LOG_FILE"
  chmod 0640 "$LOG_FILE"
}

build_venv() {
  local root_dir="$1" venv_path="$2" install_log="$3"

  install -d -m 0750 "$VENV_ROOT"
  CANDIDATE_VENV="$venv_path.tmp.$$"
  rm -rf "$CANDIDATE_VENV"

  python3 -m venv "$CANDIDATE_VENV" ||
    fail "Failed: python3 -m venv $CANDIDATE_VENV"

  {
    "$CANDIDATE_VENV/bin/python" -m pip install --no-cache-dir --upgrade pip setuptools wheel
    "$CANDIDATE_VENV/bin/python" -m pip install --no-cache-dir -e "$root_dir/controlplane"
  } >>"$install_log" 2>&1 || fail "Failed: pip install. Check $install_log."
}

install_service_unit() {
  local root_dir="$1" venv_path="$2"
  VENV_PATH="$venv_path"

  install -d -m 0755 "$(dirname "$SERVICE_PATH")"
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

  chmod +x "$root_dir/chatdome" "$root_dir/chatdome-cli.py" "$root_dir/scripts/start.sh"
  install -d -m 0755 "$(dirname "$MENU_LINK")"
  ln -sf "$root_dir/chatdome" "$MENU_LINK"
  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME" >/dev/null
}

install_local() {
  local root_dir="$1"
  local install_log service_was_active version_id

  cd "$root_dir"
  install_config_and_data "$root_dir"

  install_log="$LOG_DIR/install.log"
  touch "$install_log"
  chmod 0640 "$install_log"

  version_id="$(version_id_for "$root_dir")"
  VERSION_ID="$version_id"
  VENV_PATH="$VENV_ROOT/$VERSION_ID"
  build_venv "$root_dir" "$VENV_PATH" "$install_log"

  service_was_active=0
  if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    service_was_active=1
    systemctl stop "$SERVICE_NAME"
  fi

  rm -rf "$VENV_PATH"
  mv "$CANDIDATE_VENV" "$VENV_PATH"
  CANDIDATE_VENV=""
  rm -rf "$root_dir/venv"
  ln -s "$VENV_PATH" "$root_dir/venv"

  install_service_unit "$root_dir" "$VENV_PATH"

  if [[ "$START_AFTER_INSTALL" -eq 1 || "$service_was_active" -eq 1 ]]; then
    systemctl start "$SERVICE_NAME" ||
      fail "Failed: systemctl start $SERVICE_NAME. Check systemctl status $SERVICE_NAME."
  fi

  cat <<DONE
ChatDome installed.

Next:
  1. Run: chatdome
  2. Configure Telegram Bot Token and allowed Chat IDs.
  3. Start: sudo systemctl start chatdome

Config: $CONFIG_FILE
Data: $DATA_DIR
Log: $LOG_FILE
Service: $SERVICE_PATH
DONE
}

main() {
  local script_root mode root_dir
  parse_args "$@"
  validate_paths

  script_root="$(script_dir)"
  if [[ -n "$script_root" ]] && source_tree_complete "$script_root"; then
    mode="local"
    root_dir="$script_root"
  else
    mode="remote"
    root_dir="$REMOTE_INSTALL_DIR"
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    dry_run_summary "$mode" "$root_dir"
    exit 0
  fi

  require_root
  dependencies_ok || exit 1

  if [[ "$mode" == "remote" ]]; then
    prepare_remote_source
    exec bash "$REMOTE_INSTALL_DIR/install.sh" "${ORIGINAL_ARGS[@]}"
  fi

  install_local "$root_dir"
}

main "$@"
