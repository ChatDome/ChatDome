"""Runtime filesystem locations shared by the server components."""

from __future__ import annotations

import os
from pathlib import Path


def data_dir() -> Path:
    """Return the writable runtime data directory."""
    return Path(os.environ.get("CHATDOME_DATA_DIR", "chat_data")).expanduser()


def data_path(*parts: str) -> Path:
    """Return one path below the writable runtime data directory."""
    return data_dir().joinpath(*parts)


def log_dir() -> Path:
    """Return the writable runtime log directory."""
    return Path(os.environ.get("CHATDOME_LOG_DIR", str(data_dir()))).expanduser()


def log_path(name: str = "chatdome.log") -> Path:
    """Return one path below the writable runtime log directory."""
    return log_dir() / name