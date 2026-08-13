"""Optional runtime capability state and shared service helpers."""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from chatdome.config import ChatDomeConfig


MODEL_SETUP_MESSAGE = "未配置模型。运行 chatdome 后进入 Model Configuration 完成配置，再重启服务。"


@dataclass(frozen=True)
class CapabilityStatus:
    """Health state for one independently configured component."""

    state: str
    detail: str = ""


@dataclass(frozen=True)
class RuntimeCapabilities:
    """Current state of the core and optional components."""

    core: CapabilityStatus
    sentinel: CapabilityStatus
    llm: CapabilityStatus
    telegram: CapabilityStatus

    @classmethod
    def from_config(cls, config: ChatDomeConfig) -> "RuntimeCapabilities":
        return cls(
            core=CapabilityStatus("ready"),
            sentinel=CapabilityStatus(
                "ready" if config.sentinel.enabled else "disabled"
            ),
            llm=CapabilityStatus(
                "ready" if config.llm_configured else "not_configured"
            ),
            telegram=CapabilityStatus(
                "ready" if config.telegram_configured else "not_configured"
            ),
        )

    def with_state(self, component: str, state: str, detail: str = "") -> "RuntimeCapabilities":
        values = {
            "core": self.core,
            "sentinel": self.sentinel,
            "llm": self.llm,
            "telegram": self.telegram,
        }
        if component not in values:
            raise ValueError(f"Unknown runtime component: {component}")
        values[component] = CapabilityStatus(state, detail)
        return RuntimeCapabilities(**values)

    def to_dict(self) -> dict[str, object]:
        return {
            "pid": os.getpid(),
            "ready_at": time.time(),
            "components": {
                name: asdict(getattr(self, name))
                for name in ("core", "sentinel", "llm", "telegram")
            },
        }


def write_runtime_status(path: Path, capabilities: RuntimeCapabilities) -> None:
    """Persist component health for local service tooling."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(capabilities.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


async def discard_platform_delivery(*_args, **_kwargs) -> None:
    """Keep local Sentinel processing active when no platform is configured."""
    return None
