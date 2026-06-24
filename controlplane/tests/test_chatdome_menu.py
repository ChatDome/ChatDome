import os
import shutil
import signal
import stat
import subprocess
import time
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
MENU_PATH = REPO_ROOT / "chatdome"

pytestmark = pytest.mark.skipif(
    not all(shutil.which(name) for name in ("bash", "git", "flock")),
    reason="requires bash, git, and flock",
)


def _run(command, *, cwd=None, env=None, input_text=None, check=True):
    return subprocess.run(
        [str(part) for part in command],
        cwd=cwd,
        env=env,
        input=input_text,
        text=True,
        capture_output=True,
        check=check,
    )


def _git(repo: Path, *args: str) -> str:
    env = os.environ.copy()
    env.update({"GIT_AUTHOR_NAME": "ChatDome Test", "GIT_AUTHOR_EMAIL": "test@chatdome.invalid", "GIT_COMMITTER_NAME": "ChatDome Test", "GIT_COMMITTER_EMAIL": "test@chatdome.invalid"})
    return _run(["git", "-C", repo, *args], env=env).stdout.strip()


def _write_executable(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _read_pty_until(master_fd: int, needle: str, timeout: float = 5.0) -> str:
    import select

    output = bytearray()
    deadline = time.monotonic() + timeout
    expected = needle.encode()
    while expected not in output:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError(f"Timed out waiting for {needle!r}. Output: {output.decode(errors='replace')}")
        ready, _, _ = select.select([master_fd], [], [], remaining)
        if not ready:
            continue
        try:
            chunk = os.read(master_fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        output.extend(chunk)
    text = output.decode(errors="replace")
    assert needle in text, text
    return text


def _spawn_interactive_menu(deploy: Path, env: dict[str, str]):
    import pty

    master_fd, slave_fd = pty.openpty()
    process = subprocess.Popen(
        ["bash", str(deploy / "chatdome")],
        env=env,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        start_new_session=True,
        close_fds=True,
    )
    os.close(slave_fd)
    return process, master_fd


def _create_fixture(tmp_path: Path):
    origin = tmp_path / "origin.git"
    seed = tmp_path / "seed"
    deploy = tmp_path / "deploy"
    _run(["git", "init", "--bare", origin])
    _run(["git", "init", "-b", "main", seed])

    shutil.copy2(MENU_PATH, seed / "chatdome")
    (seed / "chatdome-cli.py").write_text("# managed by the fake Python executable\n", encoding="utf-8")
    (seed / "config.example.yaml").write_text("chatdome: {}\n", encoding="utf-8")
    (seed / ".gitignore").write_text("venv/\n.venv-update/\n.venv-rollback/\nconfig.yaml\nchat_data/\n", encoding="utf-8")
    (seed / "controlplane").mkdir()
    (seed / "controlplane" / "pyproject.toml").write_text("[project]\nname='fixture'\nversion='1'\n", encoding="utf-8")
    (seed / "version.txt").write_text("v1\n", encoding="utf-8")
    _git(seed, "add", ".")
    _git(seed, "commit", "-m", "v1")
    _git(seed, "remote", "add", "origin", str(origin))
    _git(seed, "push", "-u", "origin", "main")
    _run(["git", "--git-dir", origin, "symbolic-ref", "HEAD", "refs/heads/main"])
    _run(["git", "clone", origin, deploy])

    old_commit = _git(deploy, "rev-parse", "HEAD")
    (seed / "version.txt").write_text("v2\n", encoding="utf-8")
    _git(seed, "add", "version.txt")
    _git(seed, "commit", "-m", "v2")
    _git(seed, "push", "origin", "main")
    target_commit = _git(seed, "rev-parse", "HEAD")

    config_dir = tmp_path / "etc" / "chatdome"
    data_dir = tmp_path / "var" / "lib" / "chatdome"
    log_dir = tmp_path / "var" / "log" / "chatdome"
    lock_file = tmp_path / "chatdome-update.lock"
    fake_bin = tmp_path / "bin"
    command_log = tmp_path / "python.log"
    service_log = tmp_path / "service.log"
    pip_count = tmp_path / "pip-count"
    active_file = tmp_path / "service-active"
    enabled_file = tmp_path / "service-enabled"
    active_file.touch()
    enabled_file.touch()
    command_path = fake_bin / "chatdome"
    _write_executable(command_path, "#!/usr/bin/env bash\nexit 0\n")

    _write_executable(
        deploy / "venv" / "bin" / "python",
        """#!/usr/bin/env bash
set -eu
echo "$*" >>"$FAKE_PYTHON_LOG"
if [[ "${2:-}" == "llm-profile-state" && "${FAKE_PROFILE_EXISTS:-0}" == "1" ]]; then
  echo "exists"
  exit 0
fi
if [[ "${2:-}" == "llm-profile-info" && "${FAKE_PROFILE_EXISTS:-0}" == "1" ]]; then
  case "${5:-}" in
    api-mode) echo "openai_api" ;;
    model) echo "gpt-4o" ;;
    base-url) echo "https://api.openai.com/v1" ;;
    fingerprint) echo "fixture-fingerprint" ;;
    active) echo "false" ;;
    has-api-key) echo "true" ;;
  esac
  exit 0
fi
if [[ "${1:-}" == "-m" && "${2:-}" == "venv" ]]; then
  mkdir -p "$3/bin"
  cp "$0" "$3/bin/python"
  chmod +x "$3/bin/python"
  touch "$3/CANDIDATE"
  exit 0
fi
if [[ "${1:-}" == "-m" && "${2:-}" == "pip" && " $* " == *" -e "* ]]; then
  count=0
  [[ -f "$FAKE_PIP_COUNT" ]] && count="$(cat "$FAKE_PIP_COUNT")"
  count=$((count + 1))
  echo "$count" >"$FAKE_PIP_COUNT"
  if [[ "${FAIL_FIRST_INSTALL:-0}" == "1" && "$count" == "1" ]]; then
    exit 1
  fi
fi
if [[ "${2:-}" == "validate-config" ]]; then
  if [[ "${FAIL_CONFIG:-0}" == "1" ]]; then
    echo "Configuration error: chatdome.active_ai_profile is required." >&2
    exit 1
  fi
  if [[ "${FAIL_CANDIDATE_CONFIG:-0}" == "1" && "$0" == *"/.venv-update/"* ]]; then
    echo "Configuration error: chatdome.new_required_field is required." >&2
    exit 1
  fi
fi
if [[ "${1:-}" == "-m" && "${2:-}" == "chatdome.main" && "${FAIL_ACTIVATED_RUNTIME:-0}" == "1" ]]; then
  echo "fixture activated runtime failure" >&2
  exit 1
fi
if [[ "${2:-}" == "health-check" && "${FAIL_HEALTH:-0}" == "1" ]]; then
  exit 1
fi
exit 0
""",
    )
    (deploy / "venv" / "ORIGINAL").write_text("original\n", encoding="utf-8")
    _write_executable(fake_bin / "systemctl", """#!/usr/bin/env bash
set -eu
echo "$*" >>"$FAKE_SERVICE_LOG"
case "${1:-}" in
  is-active) [[ -f "$FAKE_ACTIVE_FILE" ]] ;;
  is-enabled) [[ -f "$FAKE_ENABLED_FILE" ]] ;;
  start|restart) touch "$FAKE_ACTIVE_FILE" ;;
  stop) rm -f "$FAKE_ACTIVE_FILE" ;;
  enable) touch "$FAKE_ENABLED_FILE" ;;
  disable)
    rm -f "$FAKE_ENABLED_FILE"
    [[ " $* " == *" --now "* ]] && rm -f "$FAKE_ACTIVE_FILE"
    ;;
  daemon-reload) ;;
  *) ;;
esac
""")
    _write_executable(fake_bin / "sleep", "#!/usr/bin/env bash\nexit 0\n")
    _write_executable(fake_bin / "sudo", '#!/usr/bin/env bash\nexec "$@"\n')

    env = os.environ.copy()
    env.update({
        "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
        "CHATDOME_CONFIG": str(config_dir / "config.yaml"),
        "CHATDOME_DATA_DIR": str(data_dir),
        "CHATDOME_LOG_DIR": str(log_dir),
        "CHATDOME_LOG_FILE": str(log_dir / "chatdome.log"),
        "CHATDOME_UPDATE_LOCK_FILE": str(lock_file),
        "CHATDOME_SERVICE_PATH": str(tmp_path / "chatdome.service"),
        "CHATDOME_COMMAND_PATH": str(command_path),
        "CHATDOME_ORIGIN_URL": str(origin),
        "CHATDOME_NO_SUDO": "1",
        "FAKE_PYTHON_LOG": str(command_log),
        "FAKE_SERVICE_LOG": str(service_log),
        "FAKE_PIP_COUNT": str(pip_count),
        "FAKE_ACTIVE_FILE": str(active_file),
        "FAKE_ENABLED_FILE": str(enabled_file),
    })
    return locals()


def test_update_skips_when_origin_main_matches_head(tmp_path):
    fixture = _create_fixture(tmp_path)
    deploy = fixture["deploy"]
    _git(
        deploy,
        "fetch",
        "origin",
        "+refs/heads/main:refs/remotes/origin/main",
    )
    _git(deploy, "reset", "--hard", "origin/main")
    fixture["service_log"].unlink(missing_ok=True)

    result = _run(
        ["bash", deploy / "chatdome", "--update"],
        env=fixture["env"],
        input_text="",
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "ChatDome is already up to date:" in result.stdout
    assert not (deploy / ".venv-update").exists()
    service_calls = (
        fixture["service_log"].read_text(encoding="utf-8")
        if fixture["service_log"].exists()
        else ""
    )
    assert "stop chatdome" not in service_calls
    assert "restart chatdome" not in service_calls


def test_update_replaces_checkout_migrates_runtime_and_checks_health(tmp_path):
    fixture = _create_fixture(tmp_path)
    deploy = fixture["deploy"]
    (deploy / "version.txt").write_text("local change\n", encoding="utf-8")
    (deploy / "scratch.tmp").write_text("remove me\n", encoding="utf-8")
    (deploy / "config.yaml").write_text("legacy config\n", encoding="utf-8")
    (deploy / "chat_data").mkdir()
    (deploy / "chat_data" / "runtime.json").write_text("keep me\n", encoding="utf-8")

    result = _run(["bash", deploy / "chatdome", "--update"], env=fixture["env"], input_text="y\n", check=False)

    assert result.returncode == 0, result.stdout + result.stderr
    assert _git(deploy, "rev-parse", "HEAD") == fixture["target_commit"]
    assert (deploy / "version.txt").read_text(encoding="utf-8") == "v2\n"
    assert not (deploy / "scratch.tmp").exists()
    assert not (deploy / "config.yaml").exists()
    assert not (deploy / "chat_data").exists()
    assert (deploy / "venv" / "CANDIDATE").exists()
    assert not (deploy / "venv" / "ORIGINAL").exists()
    assert (fixture["config_dir"] / "config.yaml").read_text(encoding="utf-8") == "legacy config\n"
    assert (fixture["data_dir"] / "runtime.json").read_text(encoding="utf-8") == "keep me\n"
    assert (fixture["data_dir"] / "previous_commit").read_text(encoding="utf-8").strip() == fixture["old_commit"]

    python_calls = fixture["command_log"].read_text(encoding="utf-8")
    assert "validate-config" in python_calls
    assert "-m ensurepip --upgrade" in python_calls
    assert "-m pip install --no-cache-dir --upgrade pip setuptools wheel" in python_calls
    assert "-m pip install -e" in python_calls
    assert python_calls.index("-m ensurepip --upgrade") < python_calls.index("-m pip install -e")
    assert "-m chatdome.main --help" in python_calls
    assert "health-check" in python_calls
    service_unit = Path(fixture["env"]["CHATDOME_SERVICE_PATH"]).read_text(encoding="utf-8")
    assert "venv/bin/python -m chatdome.main --config" in service_unit
    assert "venv/bin/chatdome-server" not in service_unit
    service_calls = fixture["service_log"].read_text(encoding="utf-8")
    assert "stop chatdome" in service_calls
    assert "restart chatdome" in service_calls
    assert "is-active --quiet chatdome" in service_calls


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX terminal signals")
def test_ctrl_c_cancels_openai_configuration_and_exits_main_menu(tmp_path):
    fixture = _create_fixture(tmp_path)
    process, master_fd = _spawn_interactive_menu(fixture["deploy"], fixture["env"])

    try:
        _read_pty_until(master_fd, "Select: ")
        os.write(master_fd, b"3\n")
        output = _read_pty_until(master_fd, "Select: ")
        assert "LLM Management" in output
        os.write(master_fd, b"2\n")
        _read_pty_until(master_fd, "Profile name [my-openai-profile]: ")
        os.write(master_fd, b"broken-profile\n")
        _read_pty_until(master_fd, "Model [gpt-4o]: ")

        os.killpg(process.pid, signal.SIGINT)
        output = _read_pty_until(master_fd, "Select: ")

        assert "Cancelled." in output
        assert "LLM Management" in output
        assert process.poll() is None
        python_calls = fixture["command_log"].read_text(encoding="utf-8")
        assert "set-openai" not in python_calls

        os.write(master_fd, b"0\n")
        output = _read_pty_until(master_fd, "Select: ")
        assert "1) Start service" in output
        os.killpg(process.pid, signal.SIGINT)

        assert process.wait(timeout=5) == 130
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        os.close(master_fd)


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX terminal signals")
def test_existing_openai_profile_requires_explicit_overwrite(tmp_path):
    fixture = _create_fixture(tmp_path)
    env = fixture["env"].copy()
    env["FAKE_PROFILE_EXISTS"] = "1"
    process, master_fd = _spawn_interactive_menu(fixture["deploy"], env)

    try:
        _read_pty_until(master_fd, "Select: ")
        os.write(master_fd, b"3\n")
        _read_pty_until(master_fd, "Select: ")
        os.write(master_fd, b"2\n")
        _read_pty_until(master_fd, "Profile name [my-openai-profile]: ")
        os.write(master_fd, b"base\n")
        output = _read_pty_until(master_fd, "Overwrite this profile? [y/N] ")
        assert "Profile already exists: base" in output

        os.write(master_fd, b"n\n")
        output = _read_pty_until(master_fd, "Select: ")
        assert "LLM Management" in output
        calls = fixture["command_log"].read_text(encoding="utf-8")
        assert "set-openai" not in calls
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        os.close(master_fd)


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX terminal signals")
def test_confirmed_openai_overwrite_passes_fingerprint(tmp_path):
    fixture = _create_fixture(tmp_path)
    env = fixture["env"].copy()
    env["FAKE_PROFILE_EXISTS"] = "1"
    process, master_fd = _spawn_interactive_menu(fixture["deploy"], env)

    try:
        _read_pty_until(master_fd, "Select: ")
        os.write(master_fd, b"3\n")
        _read_pty_until(master_fd, "Select: ")
        os.write(master_fd, b"2\n")
        _read_pty_until(master_fd, "Profile name [my-openai-profile]: ")
        os.write(master_fd, b"base\n")
        _read_pty_until(master_fd, "Overwrite this profile? [y/N] ")
        os.write(master_fd, b"y\n")
        _read_pty_until(master_fd, "Model [gpt-4o]: ")
        os.write(master_fd, b"\n")
        _read_pty_until(master_fd, "Base URL [https://api.openai.com/v1]: ")
        os.write(master_fd, b"\n")
        _read_pty_until(master_fd, "API Key (blank = keep current): ")
        os.write(master_fd, b"\n")
        _read_pty_until(master_fd, "Update profile 'base'? [y/N] ")
        os.write(master_fd, b"y\n")
        _read_pty_until(master_fd, "Press Enter to continue...")
        os.write(master_fd, b"\n")
        _read_pty_until(master_fd, "Select: ")

        calls = fixture["command_log"].read_text(encoding="utf-8")
        assert "set-openai" in calls
        assert "--overwrite" in calls
        assert "--expected-profile-fingerprint fixture-fingerprint" in calls
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        os.close(master_fd)


def test_update_preserves_existing_standard_config(tmp_path):
    fixture = _create_fixture(tmp_path)
    deploy = fixture["deploy"]
    standard_config = fixture["config_dir"] / "config.yaml"
    standard_config.parent.mkdir(parents=True)
    standard_config.write_text("standard config\n", encoding="utf-8")
    (deploy / "config.yaml").write_text("legacy config\n", encoding="utf-8")

    result = _run(
        ["bash", deploy / "chatdome", "--update"],
        env=fixture["env"],
        input_text="y\n",
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert standard_config.read_text(encoding="utf-8") == "standard config\n"
    assert not (deploy / "config.yaml").exists()


def test_update_rolls_back_when_previously_valid_config_becomes_invalid(tmp_path):
    fixture = _create_fixture(tmp_path)
    deploy = fixture["deploy"]
    before = _git(deploy, "rev-parse", "HEAD")
    failing_env = fixture["env"].copy()
    failing_env["FAIL_CANDIDATE_CONFIG"] = "1"

    result = _run(
        ["bash", deploy / "chatdome", "--update"],
        env=failing_env,
        input_text="y\n",
        check=False,
    )

    assert result.returncode != 0
    assert "configuration validation failed" in result.stdout
    assert "Restored ChatDome" in result.stdout
    assert _git(deploy, "rev-parse", "HEAD") == before
    assert (deploy / "venv" / "ORIGINAL").exists()


def test_update_with_invalid_existing_config_updates_but_stays_stopped(tmp_path):
    fixture = _create_fixture(tmp_path)
    deploy = fixture["deploy"]
    invalid_env = fixture["env"].copy()
    invalid_env["FAIL_CONFIG"] = "1"

    result = _run(
        ["bash", deploy / "chatdome", "--update"],
        env=invalid_env,
        input_text="y\n",
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert _git(deploy, "rev-parse", "HEAD") == fixture["target_commit"]
    assert (deploy / "venv" / "CANDIDATE").exists()
    assert "Fix " in result.stdout
    assert "then start ChatDome from the menu" in result.stdout
    assert not fixture["active_file"].exists()
    service_calls = fixture["service_log"].read_text(encoding="utf-8")
    assert "stop chatdome" in service_calls
    assert "restart chatdome" not in service_calls

def test_update_rolls_back_commit_when_dependency_installation_fails(tmp_path):
    fixture = _create_fixture(tmp_path)
    deploy = fixture["deploy"]
    first = _run(["bash", deploy / "chatdome", "--update"], env=fixture["env"], input_text="y\n", check=False)
    assert first.returncode == 0, first.stdout + first.stderr
    stable_commit = _git(deploy, "rev-parse", "HEAD")

    seed = fixture["seed"]
    (seed / "version.txt").write_text("v3\n", encoding="utf-8")
    _git(seed, "add", "version.txt")
    _git(seed, "commit", "-m", "v3")
    _git(seed, "push", "origin", "main")

    fixture["pip_count"].unlink(missing_ok=True)
    rollback_env = fixture["env"].copy()
    rollback_env["FAIL_FIRST_INSTALL"] = "1"
    result = _run(["bash", deploy / "chatdome", "--update"], env=rollback_env, input_text="y\n", check=False)

    assert result.returncode != 0
    assert "Restored ChatDome" in result.stdout
    assert _git(deploy, "rev-parse", "HEAD") == stable_commit
    assert (deploy / "version.txt").read_text(encoding="utf-8") == "v2\n"
    assert int(fixture["pip_count"].read_text(encoding="utf-8")) == 1
    assert not (deploy / ".venv-rollback").exists()
    assert (deploy / "venv" / "CANDIDATE").exists()
    assert not (deploy / "venv" / "ORIGINAL").exists()


def test_update_rolls_back_when_activated_runtime_cannot_start(tmp_path):
    fixture = _create_fixture(tmp_path)
    deploy = fixture["deploy"]
    before = _git(deploy, "rev-parse", "HEAD")
    failing_env = fixture["env"].copy()
    failing_env["FAIL_ACTIVATED_RUNTIME"] = "1"

    result = _run(
        ["bash", deploy / "chatdome", "--update"],
        env=failing_env,
        input_text="y\n",
        check=False,
    )

    assert result.returncode != 0
    assert "activated Python environment cannot start ChatDome" in result.stdout
    assert "fixture activated runtime failure" in result.stdout
    runtime_log = fixture["data_dir"] / "update-runtime-check.log"
    assert runtime_log.read_text(encoding="utf-8").strip() == "fixture activated runtime failure"
    assert "Restored ChatDome" in result.stdout
    assert _git(deploy, "rev-parse", "HEAD") == before
    assert (deploy / "venv" / "ORIGINAL").exists()
    assert not (deploy / "venv" / "CANDIDATE").exists()


def test_update_rolls_back_code_and_venv_when_health_check_fails(tmp_path):
    fixture = _create_fixture(tmp_path)
    deploy = fixture["deploy"]
    before = _git(deploy, "rev-parse", "HEAD")
    failing_env = fixture["env"].copy()
    failing_env["FAIL_HEALTH"] = "1"

    result = _run(
        ["bash", deploy / "chatdome", "--update"],
        env=failing_env,
        input_text="y\n",
        check=False,
    )

    assert result.returncode != 0
    assert "service health check failed" in result.stdout
    assert "Restored ChatDome" in result.stdout
    assert _git(deploy, "rev-parse", "HEAD") == before
    assert (deploy / "venv" / "ORIGINAL").exists()
    assert not (deploy / "venv" / "CANDIDATE").exists()
    assert not (deploy / ".venv-rollback").exists()


def test_update_rejects_unexpected_origin_without_changing_checkout(tmp_path):
    fixture = _create_fixture(tmp_path)
    deploy = fixture["deploy"]
    before = _git(deploy, "rev-parse", "HEAD")
    bad_env = fixture["env"].copy()
    bad_env["CHATDOME_ORIGIN_URL"] = str(tmp_path / "different-origin.git")

    result = _run(["bash", deploy / "chatdome", "--update"], env=bad_env, input_text="y\n", check=False)

    assert result.returncode != 0
    assert "set origin to" in result.stdout
    assert _git(deploy, "rev-parse", "HEAD") == before


def test_update_lock_rejects_concurrent_update(tmp_path):
    import fcntl

    fixture = _create_fixture(tmp_path)
    lock_path = Path(fixture["env"]["CHATDOME_UPDATE_LOCK_FILE"])
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = _run(
            ["bash", fixture["deploy"] / "chatdome", "--update"],
            env=fixture["env"],
            input_text="y\n",
            check=False,
        )

    assert result.returncode != 0
    assert "Another ChatDome update is running." in result.stdout


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX pseudo terminals")
def test_start_menu_starts_stopped_service(tmp_path):
    fixture = _create_fixture(tmp_path)
    fixture["active_file"].unlink()
    process, master_fd = _spawn_interactive_menu(fixture["deploy"], fixture["env"])

    try:
        _read_pty_until(master_fd, "Select: ")
        os.write(master_fd, b"1\n")
        output = _read_pty_until(master_fd, "Start ChatDome service now? [y/N] ")
        assert "Restart ChatDome service now?" not in output
        os.write(master_fd, b"y\n")
        _read_pty_until(master_fd, "Press Enter to continue...")
        service_calls = fixture["service_log"].read_text(encoding="utf-8")
        assert "start chatdome" in service_calls
        assert "restart chatdome" not in service_calls
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        os.close(master_fd)


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX pseudo terminals")
def test_start_menu_restarts_running_service(tmp_path):
    fixture = _create_fixture(tmp_path)
    process, master_fd = _spawn_interactive_menu(fixture["deploy"], fixture["env"])

    try:
        _read_pty_until(master_fd, "Select: ")
        os.write(master_fd, b"1\n")
        output = _read_pty_until(master_fd, "Restart ChatDome service now? [y/N] ")
        assert "Start ChatDome service now?" not in output
        os.write(master_fd, b"y\n")
        _read_pty_until(master_fd, "Press Enter to continue...")
        service_calls = fixture["service_log"].read_text(encoding="utf-8")
        assert "restart chatdome" in service_calls
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        os.close(master_fd)


def test_stop_reports_success_and_repeated_state(tmp_path):
    fixture = _create_fixture(tmp_path)
    deploy = fixture["deploy"]

    first = _run(["bash", deploy / "chatdome", "--stop"], env=fixture["env"], check=False)
    second = _run(["bash", deploy / "chatdome", "--stop"], env=fixture["env"], check=False)

    assert first.returncode == 0
    assert "ChatDome stopped." in first.stdout
    assert second.returncode == 0
    assert "already stopped" in second.stdout


def test_permanent_removal_requires_exact_confirmation(tmp_path):
    fixture = _create_fixture(tmp_path)
    deploy = fixture["deploy"]

    result = _run(
        ["bash", deploy / "chatdome"],
        env=fixture["env"],
        input_text="7\n2\n2\nNO\n\n0\n0\n",
        check=False,
    )

    assert result.returncode == 0
    output = result.stdout + result.stderr
    assert "Type DELETE to continue" in output
    assert "Cancelled." in output
    assert deploy.exists()
    assert fixture["command_path"].exists()


def test_permanent_removal_deletes_program_config_data_and_service(tmp_path):
    fixture = _create_fixture(tmp_path)
    deploy = fixture["deploy"]
    service_path = Path(fixture["env"]["CHATDOME_SERVICE_PATH"])
    service_path.write_text("unit\n", encoding="utf-8")

    result = _run(
        ["bash", deploy / "chatdome"],
        env=fixture["env"],
        input_text="7\n2\n2\nDELETE\n",
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "ChatDome was permanently removed." in result.stdout
    assert not deploy.exists()
    assert not fixture["config_dir"].exists()
    assert not fixture["data_dir"].exists()
    assert not fixture["log_dir"].exists()
    assert not service_path.exists()
    assert not fixture["command_path"].exists()
    assert not fixture["active_file"].exists()
    assert not fixture["enabled_file"].exists()


def test_disable_reports_success_and_repeated_state(tmp_path):
    fixture = _create_fixture(tmp_path)
    deploy = fixture["deploy"]

    first = _run(
        ["bash", deploy / "chatdome", "--disable-service"],
        env=fixture["env"],
        check=False,
    )
    second = _run(
        ["bash", deploy / "chatdome", "--disable-service"],
        env=fixture["env"],
        check=False,
    )

    assert first.returncode == 0
    assert "stopped and disabled" in first.stdout
    assert "Config and data were retained" in first.stdout
    assert second.returncode == 0
    assert "already stopped and disabled" in second.stdout
