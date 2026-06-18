from pathlib import Path

from chatdome.main import _InstanceLock


def test_instance_lock_rejects_second_holder(tmp_path: Path) -> None:
    lock_path = tmp_path / "chat_data" / "chatdome.lock"
    first = _InstanceLock(lock_path)
    second = _InstanceLock(lock_path)

    assert first.acquire()
    try:
        assert not second.acquire()
    finally:
        first.release()

    assert second.acquire()
    second.release()
