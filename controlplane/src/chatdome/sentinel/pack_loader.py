"""
Pack Loader — YAML-based command library with platform auto-detection.

Replaces the hardcoded ``executor/registry.py``.  Provides the same
``render_command()`` / ``list_checks()`` public API so that the agent
and sandbox layers continue to work without changes.
"""

from __future__ import annotations

import logging
import platform
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

_DEBIAN_DISTROS = {
    "debian", "ubuntu", "linuxmint", "kali", "raspbian", "elementary",
    "pop", "popos", "zorin",
}
_RHEL_DISTROS = {
    "rhel", "centos", "rocky", "almalinux", "fedora", "ol", "oracle",
}


def _read_linux_distro_id() -> str:
    """Best-effort Linux distro detection via ``/etc/os-release``."""
    path = Path("/etc/os-release")
    if not path.exists():
        return ""
    try:
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if line.startswith("ID="):
                return line.split("=", 1)[1].strip().strip('"').lower()
    except OSError:
        return ""
    return ""


def _detect_platform() -> list[str]:
    """
    Return platform candidate keys in priority order.

    Linux-first policy (Phase 1):
      - Linux → distro-family key first, then ``linux``, then ``any``
      - Non-Linux → ``any`` only
    """
    os_family = platform.system().lower()

    if os_family != "linux":
        return ["any"]

    distro_id = _read_linux_distro_id()
    keys: list[str] = []
    if distro_id:
        if distro_id in _DEBIAN_DISTROS:
            keys.append("debian")
        elif distro_id in _RHEL_DISTROS:
            keys.append("rhel")
    keys.append("linux")
    keys.append("any")
    return keys


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ResolvedCommand:
    """A command definition resolved from Pack YAML."""

    id: str
    name: str
    command_template: str
    params: dict[str, dict[str, Any]]
    timeout: int
    tags: list[str]
    pack: str
    requires: list[str] = field(default_factory=list)


@dataclass
class RenderedCommand:
    """A command ready for execution — signature-compatible with old registry."""

    check_id: str
    name: str
    command: str
    timeout: int


# ---------------------------------------------------------------------------
# Pack Loader
# ---------------------------------------------------------------------------

class PackLoader:
    """
    Load YAML command packs, resolve platform templates, and render commands.

    Compatible public API:
        - ``render_command(check_id, args)`` → ``RenderedCommand``
        - ``list_checks()`` → ``list[dict]``
    """

    def __init__(
        self,
        builtin_dir: Path,
        custom_dir: Path | None = None,
    ) -> None:
        self._builtin_dir = builtin_dir
        self._custom_dir = custom_dir
        self._commands: dict[str, ResolvedCommand] = {}
        self._platform_keys = _detect_platform()
        logger.info("PackLoader platform candidates: %s", self._platform_keys)

    # -- Loading ----------------------------------------------------------

    def load(self, enabled_packs: list[str] | None = None) -> None:
        """
        Load packs from builtin (and optionally custom) directories.

        Args:
            enabled_packs: If provided, only load packs whose filename stem
                           is in this list.  ``None`` → load all.
        """
        self._commands.clear()

        # Builtin
        self._load_directory(self._builtin_dir, enabled_packs, source="builtin")

        # Custom (user packs override builtins on name collision)
        if self._custom_dir and self._custom_dir.is_dir():
            self._load_directory(self._custom_dir, enabled_packs=None, source="custom")

        logger.info(
            "PackLoader loaded %d commands from %d packs",
            len(self._commands),
            len({c.pack for c in self._commands.values()}),
        )

    def _load_directory(
        self,
        directory: Path,
        enabled_packs: list[str] | None,
        source: str,
    ) -> None:
        if not directory.is_dir():
            logger.warning("Pack directory does not exist: %s", directory)
            return

        for yaml_path in sorted(directory.glob("*.yaml")):
            pack_stem = yaml_path.stem
            if enabled_packs is not None and pack_stem not in enabled_packs:
                logger.debug("Skipping disabled pack: %s", pack_stem)
                continue
            self._load_pack_file(yaml_path, pack_stem, source)

    def _load_pack_file(self, path: Path, pack_stem: str, source: str) -> None:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception:
            logger.exception("Failed to parse pack YAML: %s", path)
            return

        if not isinstance(raw, dict) or "commands" not in raw:
            logger.warning("Invalid pack file (no 'commands' key): %s", path)
            return

        commands_section = raw["commands"]
        if not isinstance(commands_section, dict):
            logger.warning("Invalid 'commands' section in %s", path)
            return

        for cmd_id, cmd_def in commands_section.items():
            try:
                resolved = self._resolve_command(cmd_id, cmd_def, pack_stem)
                if resolved is not None:
                    self._commands[cmd_id] = resolved
            except Exception:
                logger.exception("Failed to resolve command %s in %s", cmd_id, path)

        logger.debug(
            "Loaded pack %s (%s): %d commands",
            pack_stem, source, len(commands_section),
        )

    # -- Template resolution -----------------------------------------------

    def _resolve_command(
        self,
        cmd_id: str,
        cmd_def: dict[str, Any],
        pack_stem: str,
    ) -> ResolvedCommand | None:
        """Resolve best-matching template for current platform."""
        templates = cmd_def.get("templates", [])
        if not isinstance(templates, list) or not templates:
            logger.warning("Command %s has no templates", cmd_id)
            return None

        selected_template = None
        selected_requires: list[str] = []

        for platform_key in self._platform_keys:
            for tpl in templates:
                tpl_platform = tpl.get("platform", "any")
                if tpl_platform != platform_key:
                    continue

                requires = tpl.get("requires", [])
                if self._requirements_met(requires):
                    selected_template = tpl["command"]
                    selected_requires = requires
                    break

            if selected_template:
                break

        if selected_template is None:
            # Fallback: use first template matching any platform key
            for platform_key in self._platform_keys:
                for tpl in templates:
                    if tpl.get("platform", "any") == platform_key:
                        selected_template = tpl["command"]
                        selected_requires = tpl.get("requires", [])
                        logger.warning(
                            "No fully-matched template for %s (requires not met), "
                            "using fallback",
                            cmd_id,
                        )
                        break
                if selected_template:
                    break

        if selected_template is None:
            logger.warning(
                "No template matched for command %s on platforms %s",
                cmd_id, self._platform_keys,
            )
            return None

        return ResolvedCommand(
            id=cmd_id,
            name=cmd_def.get("name", cmd_id),
            command_template=selected_template,
            params=cmd_def.get("params", {}),
            timeout=cmd_def.get("timeout", 10),
            tags=cmd_def.get("tags", []),
            pack=pack_stem,
            requires=selected_requires,
        )

    @staticmethod
    def _requirements_met(requires: list[str]) -> bool:
        """Check whether required binaries are available on host."""
        if not requires:
            return True
        return all(shutil.which(cmd) is not None for cmd in requires)

    # -- Public API (registry-compatible) ----------------------------------

    def render_command(
        self,
        check_id: str,
        args: dict[str, Any] | None = None,
    ) -> RenderedCommand:
        """
        Render a command template with validated parameters.

        Raises ``ValueError`` if *check_id* is unknown or parameters invalid.
        Signature is compatible with the old ``registry.render_command()``.
        """
        resolved = self._commands.get(check_id)
        if resolved is None:
            available = ", ".join(sorted(self._commands.keys()))
            raise ValueError(
                f"Unknown check_id: '{check_id}'. Available: {available}",
            )

        # Merge defaults with user-provided args
        resolved_params: dict[str, Any] = {}
        for param_name, schema in resolved.params.items():
            user_value = (args or {}).get(param_name, schema.get("default"))

            ptype = schema.get("type", "str")
            if ptype == "int":
                try:
                    user_value = int(user_value)
                except (TypeError, ValueError):
                    user_value = schema.get("default", 0)
                pmax = schema.get("max")
                if pmax is not None and user_value > pmax:
                    logger.warning(
                        "Parameter %s=%d exceeds max %d for %s, clamping",
                        param_name, user_value, pmax, check_id,
                    )
                    user_value = pmax
            else:
                user_value = str(user_value) if user_value is not None else ""

            resolved_params[param_name] = user_value

        command = resolved.command_template.format(**resolved_params)

        return RenderedCommand(
            check_id=check_id,
            name=resolved.name,
            command=command,
            timeout=resolved.timeout,
        )

    def list_checks(self) -> list[dict[str, str]]:
        """Return summary of all available checks (registry-compatible)."""
        return [
            {"check_id": cmd.id, "name": cmd.name}
            for cmd in sorted(self._commands.values(), key=lambda c: c.id)
        ]

    def get_command(self, check_id: str) -> ResolvedCommand | None:
        """Look up a resolved command by ID."""
        return self._commands.get(check_id)

    @property
    def command_count(self) -> int:
        return len(self._commands)
