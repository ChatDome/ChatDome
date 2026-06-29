from pathlib import Path

from chatdome import runtime_paths


def test_runtime_paths_use_grouped_data_and_run_dirs(monkeypatch, tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    run_dir = tmp_path / "run"
    monkeypatch.setenv("CHATDOME_DATA_DIR", str(data_dir))
    monkeypatch.setenv("CHATDOME_RUN_DIR", str(run_dir))

    assert runtime_paths.memory_file_path(123) == data_dir / "memory" / "123.json"
    assert runtime_paths.compression_log_path(123) == data_dir / "compression" / "123.log"
    assert runtime_paths.engram_store_path() == data_dir / "memory" / "engram.json"
    assert runtime_paths.sentinel_alerts_path() == data_dir / "sentinel" / "alerts.jsonl"
    assert runtime_paths.sentinel_push_state_path() == data_dir / "sentinel" / "push_state.json"
    assert runtime_paths.sentinel_user_context_path() == data_dir / "sentinel" / "user_context.json"
    assert runtime_paths.token_usage_path() == data_dir / "usage" / "token_usage.jsonl"
    assert runtime_paths.environment_profile_path() == data_dir / "environment" / "profile.md"
    assert runtime_paths.run_path("ready.json") == run_dir / "ready.json"
    assert runtime_paths.llm_profile_lock_path() == run_dir / "llm-profile.lock"


def test_runtime_paths_migrate_legacy_memory_file(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CHATDOME_DATA_DIR", str(tmp_path))
    legacy = tmp_path / "42_memory.json"
    legacy.write_text('{"summary":"old"}', encoding="utf-8")

    migrated = runtime_paths.memory_file_path(42)

    assert migrated == tmp_path / "memory" / "42.json"
    assert migrated.read_text(encoding="utf-8") == '{"summary":"old"}'
    assert not legacy.exists()


def test_runtime_paths_migrate_legacy_sentinel_file(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CHATDOME_DATA_DIR", str(tmp_path))
    legacy = tmp_path / "sentinel_alerts.jsonl"
    legacy.write_text('{"event":"old"}\n', encoding="utf-8")

    migrated = runtime_paths.sentinel_alerts_path()

    assert migrated == tmp_path / "sentinel" / "alerts.jsonl"
    assert migrated.read_text(encoding="utf-8") == '{"event":"old"}\n'
    assert not legacy.exists()