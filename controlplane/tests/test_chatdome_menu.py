import os
import shutil
import stat
import subprocess
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

    _write_executable(
        deploy / "venv" / "bin" / "python",
        """#!/usr/bin/env bash
set -eu
echo "$*" >>"$FAKE_PYTHON_LOG"
if [[ "${1:-}" == "-m" && "${2:-}" == "venv" ]]; then
  mkdir -p "$3/bin"
  cp "$0" "$3/bin/python"
  chmod +x "$3/bin/python"
  touch "$3/CANDIDATE"
  exit 0
fi
if [[ "${1:-}" == "-m" && "${2:-}" == "pip" ]]; then
  count=0
  [[ -f "$FAKE_PIP_COUNT" ]] && count="$(cat "$FAKE_PIP_COUNT")"
  count=$((count + 1))
  echo "$count" >"$FAKE_PIP_COUNT"
  if [[ "${FAIL_FIRST_INSTALL:-0}" == "1" && "$count" == "1" ]]; then
    exit 1
  fi
fi
if [[ "${2:-}" == "health-check" && "${FAIL_HEALTH:-0}" == "1" ]]; then
  exit 1
fi
exit 0
""",
    )
    (deploy / "venv" / "ORIGINAL").write_text("original\n", encoding="utf-8")
    _write_executable(fake_bin / "systemctl", """#!/usr/bin/env bash
echo "$*" >>"$FAKE_SERVICE_LOG"
exit 0
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
        "CHATDOME_ORIGIN_URL": str(origin),
        "CHATDOME_NO_SUDO": "1",
        "FAKE_PYTHON_LOG": str(command_log),
        "FAKE_SERVICE_LOG": str(service_log),
        "FAKE_PIP_COUNT": str(pip_count),
    })
    return locals()


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
    assert "-m pip install -e" in python_calls
    assert "health-check" in python_calls
    service_calls = fixture["service_log"].read_text(encoding="utf-8")
    assert "stop chatdome" in service_calls
    assert "restart chatdome" in service_calls
    assert "is-active --quiet chatdome" in service_calls


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
