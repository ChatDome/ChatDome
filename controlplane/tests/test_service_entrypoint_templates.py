from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_service_templates_use_python_module_entrypoint():
    assert not (REPO_ROOT / "chatdome.service").exists()

    installer = (REPO_ROOT / "install.sh").read_text(encoding="utf-8")
    assert "ExecStart=$VENV_PATH/bin/python -m chatdome.main --config" in installer
    assert 'VENV_PATH="$VENV_ROOT/$VERSION_ID"' in installer
    assert 'ln -s "$VENV_PATH" "$root_dir/venv"' in installer
    assert "Environment=CHATDOME_SENTINEL_LOG_FILE=$SENTINEL_LOG_FILE" in installer
    assert "Environment=CHATDOME_RUN_DIR=$RUN_DIR" in installer
    assert "RuntimeDirectory=chatdome" in installer

    updater = (REPO_ROOT / "chatdome").read_text(encoding="utf-8")
    assert "ExecStart=$runtime_python -m chatdome.main --config" in updater
    assert 'install_systemd_unit "$candidate_python"' in updater
    assert "Environment=CHATDOME_SENTINEL_LOG_FILE=$SENTINEL_LOG_FILE" in updater
    assert "Environment=CHATDOME_RUN_DIR=$RUN_DIR" in updater
    assert "RuntimeDirectory=chatdome" in updater

    fallback = (REPO_ROOT / "scripts/start.sh").read_text(encoding="utf-8")
    assert 'SERVER_CMD=("$ROOT_DIR/venv/bin/python" -m chatdome.main)' in fallback
    assert 'CHATDOME_SENTINEL_LOG_FILE="$SENTINEL_LOG_FILE"' in fallback
    assert "venv/bin/chatdome-server" not in fallback


def test_update_validates_candidate_module_entrypoint():
    content = (REPO_ROOT / "chatdome").read_text(encoding="utf-8")
    assert '"$candidate_python" -m chatdome.main --help' in content


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
    assert "Candidate runtime check failed:" in content
    assert "systemd-cat -t chatdome-update" in content
    assert "chatdome.main --help >/dev/null 2>&1" not in content
    assert 'runtime_check_output="$("$candidate_python"' in content


def test_update_checks_origin_before_confirmation():
    content = (REPO_ROOT / "chatdome").read_text(encoding="utf-8")
    check_index = content.index("Checking origin/main...")
    compare_index = content.index('if [[ "$old_commit" == "$target_commit" ]]')
    prompt_index = content.index("Tracked local changes and untracked non-ignored files")
    assert check_index < compare_index < prompt_index
    assert "目前已经是最新版本：" in content


def test_update_uses_fixed_versioned_venv_paths():
    content = (REPO_ROOT / "chatdome").read_text(encoding="utf-8")
    assert 'VENV_ROOT="${CHATDOME_VENV_ROOT:-$DATA_DIR/venvs}"' in content
    assert 'candidate_venv="$VENV_ROOT/$target_commit"' in content
    assert 'ln -s "$candidate_venv" "$ROOT_DIR/venv"' in content
    assert 'mv "$candidate_venv" "$ROOT_DIR/venv"' not in content
    assert 'cleanup_versioned_venvs "$candidate_venv" "$previous_venv"' in content


def test_gitignore_preserves_active_venv_symlink():
    patterns = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "venv" in patterns


def test_installer_prompts_before_dependency_install():
    content = (REPO_ROOT / "install.sh").read_text(encoding="utf-8")
    assert "Missing dependencies:" in content
    assert "Install command:" in content
    assert "Install now? [y/N]:" in content
    assert "apt-get update && apt-get install -y" in content
    assert "dnf install -y" in content
    assert "yum install -y" in content
    assert "pacman -Sy --needed --noconfirm" in content
    assert "zypper --non-interactive install" in content

def test_installer_requires_full_source_tree_markers():
    content = (REPO_ROOT / "install.sh").read_text(encoding="utf-8")
    assert '[[ -f "$dir/install.sh" ]] || return 1' in content
    assert '[[ -x "$dir/chatdome" || -f "$dir/chatdome" ]] || return 1' in content
    assert '[[ -f "$dir/config.example.yaml" ]] || return 1' in content
    assert '[[ -d "$dir/controlplane/src/chatdome" ]] || return 1' in content
    assert 'if [[ -n "$script_root" ]] && source_tree_complete "$script_root"; then' in content

def test_installer_enters_valid_workdir_before_install_actions():
    content = (REPO_ROOT / "install.sh").read_text(encoding="utf-8")
    assert '(cd -P "$dir" >/dev/null 2>&1 && pwd)' in content
    assert 'enter_install_workdir "$mode" "$root_dir"' in content
    assert 'cd / || fail "Cannot access /"' in content
    assert 'cd / && curl -fsSL https://raw.githubusercontent.com/ChatDome/ChatDome/main/install.sh' in content

def test_menu_level_ctrl_c_exits_process():
    content = (REPO_ROOT / "chatdome").read_text(encoding="utf-8")
    assert 'trap \'printf "\\n"; return 130\' INT' not in content
    assert 'trap \'printf "\\n"; exit 130\' INT' in content
    assert 'echo "Cancelled."; return 130' in content
