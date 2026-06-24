from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_service_templates_use_python_module_entrypoint():
    for relative_path in ("chatdome", "install.sh", "chatdome.service"):
        content = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
        assert "venv/bin/python -m chatdome.main --config" in content
        assert "venv/bin/chatdome-server" not in content

    fallback = (REPO_ROOT / "scripts/start.sh").read_text(encoding="utf-8")
    assert 'SERVER_CMD=("$ROOT_DIR/venv/bin/python" -m chatdome.main)' in fallback
    assert "venv/bin/chatdome-server" not in fallback


def test_update_validates_activated_module_entrypoint():
    content = (REPO_ROOT / "chatdome").read_text(encoding="utf-8")
    assert '"$ROOT_DIR/venv/bin/python" -m chatdome.main --help' in content


def test_start_menu_uses_state_specific_actions():
    content = (REPO_ROOT / "chatdome").read_text(encoding="utf-8")
    assert "Start or restart ChatDome service now?" not in content
    assert "Start ChatDome service now?" in content
    assert "Restart ChatDome service now?" in content
    assert "y|yes) start_service_with_result" in content
    assert "y|yes) restart_service_with_result" in content


def test_disable_menu_states_retention_policy():
    content = (REPO_ROOT / "chatdome").read_text(encoding="utf-8")
    assert "Stop and disable service (keep config and data)" in content
    assert 'echo "1) Stop and disable service"' not in content


def test_permanent_removal_uses_typed_confirmation_and_path_checks():
    content = (REPO_ROOT / "chatdome").read_text(encoding="utf-8")
    assert "Permanently remove ChatDome (delete config and data)" in content
    assert "Type DELETE to continue:" in content
    assert "safe_removal_directory" in content
    assert "Show full removal commands" not in content


def test_update_runtime_failure_is_persisted_and_journaled():
    content = (REPO_ROOT / "chatdome").read_text(encoding="utf-8")
    assert "update-runtime-check.log" in content
    assert "Activated runtime check failed:" in content
    assert "systemd-cat -t chatdome-update" in content
    assert "chatdome.main --help >/dev/null 2>&1" not in content
    assert 'runtime_check_output="$("$ROOT_DIR/venv/bin/python"' in content


def test_update_checks_origin_before_confirmation():
    content = (REPO_ROOT / "chatdome").read_text(encoding="utf-8")
    check_index = content.index("Checking origin/main...")
    compare_index = content.index('if [[ "$old_commit" == "$target_commit" ]]')
    prompt_index = content.index("Tracked local changes and untracked non-ignored files")
    assert check_index < compare_index < prompt_index
    assert "ChatDome is already up to date:" in content
