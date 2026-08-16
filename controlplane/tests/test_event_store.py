import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from chatdome.agent.event_store import EventStore


def test_event_store_appends_jsonl_with_unique_ids(tmp_path: Path) -> None:
    store = EventStore(tmp_path, retention_days=30)

    first = store.append(
        7,
        "message.user",
        {"content": "检查日志"},
        turn_id=3,
        source="cli",
    )
    second = store.append(
        7,
        "message.assistant",
        {"content": "已检查"},
        turn_id=3,
        source="cli",
    )

    assert first.event_id != second.event_id
    assert [event.type for event in store.read_events(7)] == [
        "message.user",
        "message.assistant",
    ]
    lines = store.path_for(7).read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert all(json.loads(line)["schema_version"] == 1 for line in lines)
    assert first.timestamp.endswith(("+08:00", "+00:00"))


def test_event_store_recursively_redacts_payload(tmp_path: Path) -> None:
    store = EventStore(tmp_path, retention_days=30)

    event = store.append(
        7,
        "tool.call",
        {
            "arguments": {
                "api_key": "sk-1234567890abcdefghijklmnop",
                "nested": ["Authorization: Bearer abcdefghijklmnop"],
            }
        },
    )

    serialized = json.dumps(event.to_dict(), ensure_ascii=False)
    assert "sk-1234567890abcdefghijklmnop" not in serialized
    assert "abcdefghijklmnop" not in serialized
    assert "[REDACTED]" in serialized
    assert event.redaction_applied is True


def test_search_stops_at_latest_clear_unless_explicitly_allowed(tmp_path: Path) -> None:
    store = EventStore(tmp_path, retention_days=30)
    old = store.append(7, "message.user", {"content": "旧任务 nginx"})
    cleared = store.append(7, "session.cleared", {})
    store.append(7, "message.user", {"content": "新任务 ssh"})

    assert store.latest_clear_event_id(7) == cleared.event_id
    assert store.search(7, "nginx").matches == []
    allowed = store.search(7, "nginx", include_cleared=True)
    assert [event.event_id for event in allowed.matches] == [old.event_id]
    assert allowed.clear_boundary_event_id == cleared.event_id


def test_search_only_returns_searchable_types_and_applies_limit(tmp_path: Path) -> None:
    store = EventStore(tmp_path, retention_days=30)
    store.append(7, "context.compaction_completed", {"detail": "needle"})
    first = store.append(7, "message.user", {"content": "needle one"})
    second = store.append(7, "tool.result", {"content": "needle two"})

    result = store.search(7, "NEEDLE", limit=1)

    assert [event.event_id for event in result.matches] == [second.event_id]
    assert result.scanned_events == 2
    assert first.event_id != second.event_id


def test_cleanup_removes_expired_events_and_keeps_recent_events(tmp_path: Path) -> None:
    store = EventStore(tmp_path, retention_days=30)
    now = datetime(2026, 8, 16, 12, 0, tzinfo=timezone.utc)
    old = store.append(7, "message.user", {"content": "old"})
    recent = store.append(7, "message.user", {"content": "recent"})
    records = [old.to_dict(), recent.to_dict()]
    records[0]["timestamp"] = (now - timedelta(days=31)).isoformat(sep=" ", timespec="seconds")
    records[1]["timestamp"] = (now - timedelta(days=2)).isoformat(sep=" ", timespec="seconds")
    store.path_for(7).write_text(
        "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in records),
        encoding="utf-8",
    )

    result = store.cleanup(now=now)

    assert result.scanned_files == 1
    assert result.removed_events == 1
    assert result.kept_events == 1
    assert [event.event_id for event in store.read_events(7)] == [recent.event_id]


def test_cleanup_is_disabled_when_retention_is_zero(tmp_path: Path) -> None:
    store = EventStore(tmp_path, retention_days=0)
    store.append(7, "message.user", {"content": "永久保留"})
    before = store.path_for(7).read_bytes()

    result = store.cleanup(now=datetime(2026, 8, 16, tzinfo=timezone.utc))

    assert result.skipped is True
    assert store.path_for(7).read_bytes() == before
