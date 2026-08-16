import json
from pathlib import Path

from chatdome.agent.context_budget import ContextTokenCounter
from chatdome.agent.event_store import EventStore
from chatdome.agent.memory_vault import MemoryCandidate, MemoryVaultStore


class CharacterEncoder:
    def encode(self, text: str) -> list[int]:
        return list(range(len(text)))


def _counter() -> ContextTokenCounter:
    return ContextTokenCounter(model="test", encoder=CharacterEncoder())


def test_v1_summary_migrates_to_unverified_legacy_entry(tmp_path: Path) -> None:
    path = tmp_path / "memory" / "7.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "summary": "旧摘要",
                "last_updated": "2026-08-14 22:41:24+08:00",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    vault = MemoryVaultStore(tmp_path, token_counter=_counter()).load(7)

    assert vault.version == 2
    assert vault.entries[0].category == "legacy_summary"
    assert vault.entries[0].status == "unverified"
    assert vault.entries[0].source_event_ids == []
    assert vault.entries[0].content == "旧摘要"
    persisted = json.loads(path.read_text(encoding="utf-8"))
    assert persisted["version"] == 2
    assert persisted["entries"][0]["created_at"] == "2026-08-14 22:41:24+08:00"


def test_empty_candidates_leave_vault_unchanged(tmp_path: Path) -> None:
    store = MemoryVaultStore(tmp_path, token_counter=_counter())
    path = store.path_for(7)
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "version": 2,
                "last_updated": "2026-08-14 22:41:24+08:00",
                "token_count": 0,
                "entries": [],
            }
        ),
        encoding="utf-8",
    )
    before = path.read_bytes()

    result = store.accept_candidates(7, [], allowed_event_ids=set())

    assert result.changed is False
    assert path.read_bytes() == before


def test_candidate_requires_allowed_evidence_of_the_right_type(tmp_path: Path) -> None:
    events = EventStore(tmp_path, retention_days=30)
    user_event = events.append(7, "message.user", {"content": "所有改动先审批"})
    assistant_event = events.append(7, "message.assistant", {"content": "用户偏好先审批"})
    store = MemoryVaultStore(tmp_path, token_counter=_counter(), event_store=events)

    result = store.accept_candidates(
        7,
        [
            MemoryCandidate(
                category="user_constraint",
                content="涉及主机改动的命令必须先取得批准",
                source_event_ids=[user_event.event_id],
            ),
            MemoryCandidate(
                category="user_preference",
                content="用户喜欢简洁输出",
                source_event_ids=[assistant_event.event_id],
            ),
            MemoryCandidate(
                category="confirmed_fact",
                content="未经本次压缩验证的事实",
                source_event_ids=["EV-NOT-ALLOWED"],
            ),
        ],
        allowed_event_ids={user_event.event_id, assistant_event.event_id},
    )

    assert result.changed is True
    assert result.accepted == 1
    assert result.rejected == 2
    vault = store.load(7)
    assert [entry.category for entry in vault.entries] == ["user_constraint"]
    assert vault.entries[0].status == "verified"
    assert vault.entries[0].token_count > 0


def test_duplicate_and_temporary_candidates_do_not_change_vault(tmp_path: Path) -> None:
    events = EventStore(tmp_path, retention_days=30)
    user_event = events.append(7, "message.user", {"content": "改动前先审批"})
    store = MemoryVaultStore(tmp_path, token_counter=_counter(), event_store=events)
    candidate = MemoryCandidate(
        category="user_constraint",
        content="改动前先审批",
        source_event_ids=[user_event.event_id],
    )
    first = store.accept_candidates(
        7,
        [candidate],
        allowed_event_ids={user_event.event_id},
    )
    before = store.path_for(7).read_bytes()

    second = store.accept_candidates(
        7,
        [
            candidate,
            MemoryCandidate(
                category="reusable_result",
                content="当前任务临时待办：稍后再检查日志",
                source_event_ids=[user_event.event_id],
            ),
        ],
        allowed_event_ids={user_event.event_id},
    )

    assert first.accepted == 1
    assert second.changed is False
    assert second.rejected == 2
    assert store.path_for(7).read_bytes() == before


def test_render_prompt_prioritizes_verified_entries_and_honors_budget(tmp_path: Path) -> None:
    path = tmp_path / "memory" / "7.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "version": 2,
                "last_updated": "2026-08-14 22:41:24+08:00",
                "token_count": 999,
                "entries": [
                    {
                        "id": "MEM-VERIFIED",
                        "category": "confirmed_fact",
                        "content": "SSH 服务使用 2222 端口",
                        "source_event_ids": ["EV-1"],
                        "created_at": "2026-08-14 22:41:24+08:00",
                        "updated_at": "2026-08-14 22:41:24+08:00",
                        "token_count": 1,
                        "status": "verified",
                    },
                    {
                        "id": "MEM-LEGACY",
                        "category": "legacy_summary",
                        "content": "旧版自由文本摘要" * 100,
                        "source_event_ids": [],
                        "created_at": "2026-08-13 22:41:24+08:00",
                        "updated_at": "2026-08-13 22:41:24+08:00",
                        "token_count": 1,
                        "status": "unverified",
                    },
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    store = MemoryVaultStore(tmp_path, token_counter=_counter())

    prompt = store.render_prompt(7, query="SSH", max_tokens=120)

    assert "SSH 服务使用 2222 端口" in prompt
    assert _counter().count_text(prompt).tokens <= 120
    assert "legacy_unverified" not in prompt


def test_delete_and_clear_manage_memory_independently(tmp_path: Path) -> None:
    events = EventStore(tmp_path, retention_days=30)
    user_event = events.append(7, "message.user", {"content": "回复使用中文"})
    store = MemoryVaultStore(tmp_path, token_counter=_counter(), event_store=events)
    result = store.accept_candidates(
        7,
        [
            MemoryCandidate(
                category="user_preference",
                content="回复使用中文",
                source_event_ids=[user_event.event_id],
            )
        ],
        allowed_event_ids={user_event.event_id},
    )
    entry_id = result.accepted_entry_ids[0]

    assert store.delete(7, entry_id) is True
    assert store.delete(7, entry_id) is False
    assert store.clear(7) is True
    assert not store.path_for(7).exists()
