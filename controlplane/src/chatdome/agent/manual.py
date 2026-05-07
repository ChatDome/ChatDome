"""
Curated ChatDome operating manual access.

The manual is intentionally exposed through a narrow section_id interface so the
LLM can read operational guidance without gaining arbitrary filesystem access.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

MANUAL_DIR = Path(__file__).resolve().parent / "manual"
INDEX_PATH = MANUAL_DIR / "index.yaml"
MAX_SECTION_CHARS = 8000


@dataclass
class ManualSection:
    id: str
    title: str
    summary: str
    file: str
    when_to_read: list[str]
    tools: list[str]


def _as_str_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if value is None:
        return []
    text = str(value).strip()
    return [text] if text else []


def _load_sections() -> list[ManualSection]:
    if not INDEX_PATH.exists():
        return []

    raw = yaml.safe_load(INDEX_PATH.read_text(encoding="utf-8")) or {}
    raw_sections = raw.get("sections", [])
    if not isinstance(raw_sections, list):
        return []

    sections: list[ManualSection] = []
    seen: set[str] = set()
    for item in raw_sections:
        if not isinstance(item, dict):
            continue
        section_id = str(item.get("id", "")).strip()
        file_name = str(item.get("file", "")).strip()
        if not section_id or not file_name or section_id in seen:
            continue
        sections.append(
            ManualSection(
                id=section_id,
                title=str(item.get("title", section_id)).strip() or section_id,
                summary=str(item.get("summary", "")).strip(),
                file=file_name,
                when_to_read=_as_str_list(item.get("when_to_read")),
                tools=_as_str_list(item.get("tools")),
            )
        )
        seen.add(section_id)
    return sections


def list_manual_sections() -> list[ManualSection]:
    """Return the curated manual index."""
    return _load_sections()


def get_manual_section_ids() -> list[str]:
    """Return valid section IDs for the read_chatdome_manual tool schema."""
    return [section.id for section in list_manual_sections()]


def _format_available_sections(sections: list[ManualSection]) -> str:
    if not sections:
        return "No ChatDome manual sections are available."

    lines = ["Available ChatDome manual sections:"]
    for section in sections:
        summary = f" - {section.summary}" if section.summary else ""
        lines.append(f"- {section.id}: {section.title}{summary}")
    return "\n".join(lines)


def build_manual_index_prompt() -> str:
    """Build the compact manual index inserted into the system prompt."""
    sections = list_manual_sections()
    if not sections:
        return (
            "ChatDome 操作手册索引：当前未加载到手册章节。"
            "工具选择或数据来源不确定时，先向用户追问。"
        )

    lines = [
        "ChatDome 操作手册索引：",
        "当工具选择、数据来源或操作流程不确定时，先调用 read_chatdome_manual(section_id) 读取对应章节；不要猜测。",
    ]
    for section in sections:
        when = "；".join(section.when_to_read[:2])
        tools = ", ".join(section.tools[:4])
        detail = section.summary
        if when:
            detail += f" 何时读：{when}。"
        if tools:
            detail += f" 关键工具：{tools}。"
        lines.append(f"- {section.id}: {detail}")
    return "\n".join(lines)


def _resolve_section_path(section: ManualSection) -> Path:
    path = (MANUAL_DIR / section.file).resolve()
    manual_root = MANUAL_DIR.resolve()
    try:
        path.relative_to(manual_root)
    except ValueError as exc:
        raise ValueError(f"Manual section path escapes manual directory: {section.file}") from exc
    return path


def read_manual_section(section_id: str) -> str:
    """Read one curated manual section by section_id."""
    normalized = str(section_id or "").strip()
    sections = list_manual_sections()
    by_id = {section.id: section for section in sections}
    section = by_id.get(normalized)
    if section is None:
        return f"Unknown ChatDome manual section: {normalized}\n\n{_format_available_sections(sections)}"

    path = _resolve_section_path(section)
    if not path.exists():
        return f"ChatDome manual section file is missing: {section.id}"

    content = path.read_text(encoding="utf-8").strip()
    if len(content) > MAX_SECTION_CHARS:
        content = content[:MAX_SECTION_CHARS].rstrip() + "\n\n[section truncated]"

    lines = [
        f"ChatDome manual section: {section.id} - {section.title}",
    ]
    if section.summary:
        lines.append(f"Summary: {section.summary}")
    if section.tools:
        lines.append(f"Relevant tools: {', '.join(section.tools)}")
    lines.extend(["", content])
    return "\n".join(lines)
