"""Template-driven atomic writer for the user configuration file."""

from __future__ import annotations

import os
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

import yaml
from yaml.nodes import MappingNode, Node


def default_config_template_path() -> Path:
    """Return the repository template used by installed and editable runtimes."""
    return Path(__file__).resolve().parents[3] / "config.example.yaml"


class TemplateConfigWriter:
    """Overlay user values onto the current commented configuration template."""

    def __init__(self, config_path: str | Path, template_path: str | Path) -> None:
        self.config_path = Path(config_path).expanduser()
        self.template_path = Path(template_path).expanduser()

    def write(self, document: Mapping[str, Any]) -> None:
        if not isinstance(document, Mapping):
            raise ValueError("Configuration document must be a mapping.")
        template_text, template_document, template_node = self._load_template()
        merged = self._overlay(template_document, dict(document))
        rendered = self._render(template_text, template_node, merged)
        try:
            rendered_document = yaml.safe_load(rendered)
        except yaml.YAMLError as exc:
            raise ValueError(f"Rendered configuration is invalid: {exc}") from exc
        if rendered_document != merged:
            raise ValueError("Rendered configuration does not match the requested values.")
        self._atomic_replace(rendered)

    def restore_text(self, text: str) -> None:
        """Atomically restore previously validated configuration text."""
        self._atomic_replace(text)

    def _load_template(self) -> tuple[str, dict[str, Any], MappingNode]:
        try:
            text = self.template_path.read_text(encoding="utf-8")
            document = yaml.safe_load(text)
            node = yaml.compose(text)
        except (OSError, yaml.YAMLError) as exc:
            raise ValueError(f"Configuration template is invalid: {self.template_path}") from exc
        if not isinstance(document, dict) or not isinstance(node, MappingNode):
            raise ValueError("Configuration template must be a mapping.")
        return text, document, node

    @classmethod
    def _overlay(cls, template: Any, current: Any) -> Any:
        if isinstance(template, dict) and isinstance(current, Mapping):
            if not template:
                return deepcopy(dict(current))
            merged = deepcopy(template)
            for key, value in current.items():
                if key in template:
                    merged[key] = cls._overlay(template[key], value)
                else:
                    merged[key] = deepcopy(value)
            return merged
        return deepcopy(current)

    @classmethod
    def _render(cls, text: str, root: MappingNode, merged: dict[str, Any]) -> str:
        replacements: list[tuple[int, int, str]] = []
        cls._collect_replacements(root, merged, replacements)
        for start, end, value in sorted(replacements, reverse=True):
            text = text[:start] + value + text[end:]
        trailing_newline = "\n" if text.endswith(("\n", "\r")) else ""
        return "\n".join(line.rstrip() for line in text.splitlines()) + trailing_newline

    @classmethod
    def _collect_replacements(
        cls,
        node: MappingNode,
        values: Mapping[str, Any],
        replacements: list[tuple[int, int, str]],
    ) -> None:
        template_keys: set[str] = set()
        for key_node, value_node in node.value:
            key = str(key_node.value)
            template_keys.add(key)
            value = values.get(key)
            if (
                isinstance(value_node, MappingNode)
                and value_node.value
                and isinstance(value, Mapping)
            ):
                cls._collect_replacements(value_node, value, replacements)
                continue
            replacements.append(
                (
                    value_node.start_mark.index,
                    value_node.end_mark.index,
                    cls._serialize_value(value, key_node, value_node),
                )
            )
        extra_keys = [key for key in values if key not in template_keys]
        if extra_keys:
            raise ValueError(
                "Configuration contains fields missing from the template: "
                + ", ".join(str(key) for key in extra_keys)
            )

    @staticmethod
    def _serialize_value(value: Any, key_node: Node, value_node: Node) -> str:
        if isinstance(value, Mapping) and value:
            dumped = yaml.safe_dump(
                dict(value),
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
            ).rstrip("\n")
            indent = " " * (key_node.start_mark.column + 2)
            return "\n" + "\n".join(indent + line for line in dumped.splitlines())
        dumped = yaml.safe_dump(
            value,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=True,
            width=1_000_000,
        ).strip()
        if dumped.endswith("\n..."):
            dumped = dumped[:-4]
        elif dumped.endswith("..."):
            dumped = dumped[:-3].rstrip()
        return dumped

    def _atomic_replace(self, rendered: str) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{self.config_path.name}.",
            suffix=".tmp",
            dir=str(self.config_path.parent),
        )
        temp_path = Path(temp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(rendered)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_path, 0o600)
            os.replace(temp_path, self.config_path)
            self._sync_parent_directory()
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def _sync_parent_directory(self) -> None:
        try:
            directory_fd = os.open(str(self.config_path.parent), os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(directory_fd)
        except OSError:
            pass
        finally:
            os.close(directory_fd)
