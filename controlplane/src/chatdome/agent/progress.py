"""Platform-neutral labels for Agent progress stages."""

CONTEXT_COMPACTION_PROGRESS_TEXT = "正在进行上下文压缩"


def progress_label(stage: str) -> str:
    if stage == "context_compacting":
        return CONTEXT_COMPACTION_PROGRESS_TEXT
    if stage == "executing":
        return "正在执行操作"
    return "正在处理"
