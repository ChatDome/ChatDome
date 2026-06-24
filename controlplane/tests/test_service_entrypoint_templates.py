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
