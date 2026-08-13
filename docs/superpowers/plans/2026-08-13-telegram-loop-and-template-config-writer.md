# Telegram Event Loop and Template Config Writer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop Telegram polling task storms caused by cross-loop asyncio primitives and make every menu configuration save regenerate `config.yaml` from the current example template without losing user values.

**Architecture:** Telegram `Application` construction moves inside the coroutine executed by `asyncio.run()`, so python-telegram-bot creates all locks and events on the service loop. A shared round-trip configuration writer loads `config.example.yaml` as the presentation template, recursively overlays validated user data, and atomically replaces the production file while retaining template comments, ordering, defaults, dynamic model profiles, secrets, and file permissions.

**Tech Stack:** Python 3.9+, asyncio, python-telegram-bot, PyYAML syntax nodes, pytest.

## Global Constraints

- `config.example.yaml` is the canonical structure, comments, ordering, and defaults for saved production configuration.
- Existing user values and dynamic `ai_profiles` entries must survive every save.
- Newly added template fields receive their template defaults on the next menu save.
- Configuration writes remain atomic and owner-readable.
- Telegram objects containing asyncio primitives must be constructed inside the one service event loop.
- User-visible errors remain concise and actionable.

---

### Task 1: Telegram event-loop ownership and log-storm containment

**Files:**
- Modify: `controlplane/src/chatdome/main.py`
- Modify: `controlplane/src/chatdome/logger.py`
- Test: `controlplane/tests/test_telegram_lifecycle.py`
- Test: `controlplane/tests/test_logger.py`

**Interfaces:**
- Produces: `build_telegram_application(bot: TelegramBot) -> Awaitable[Application]`
- Produces: file logging that disables the failed handler after `ENOSPC` without emitting repeated logging tracebacks.

- [x] Write a regression test that builds a real Telegram updater inside `asyncio.run()` and waits on its stop event without a cross-loop `RuntimeError`.
- [x] Run the focused test and verify it fails because the loop-bound construction helper does not exist.
- [x] Move `bot.build()` from synchronous startup into `_run_service()` through the new helper.
- [x] Add an `ENOSPC` handler regression test and contain repeated file-handler failures.
- [x] Run Telegram lifecycle and logging tests.

### Task 2: Template-driven atomic configuration writer

**Files:**
- Create: `controlplane/src/chatdome/config_writer.py`
- Modify: `config.example.yaml`
- Modify: `controlplane/src/chatdome/llm/profile_admin.py`
- Modify: `controlplane/src/chatdome/main.py`
- Modify: `chatdome-cli.py`
- Test: `controlplane/tests/test_config_writer.py`
- Test: `controlplane/tests/test_llm_profile_admin.py`
- Test: `controlplane/tests/test_chatdome_cli.py`

**Interfaces:**
- Produces: `TemplateConfigWriter(config_path: Path, template_path: Path)`
- Produces: `TemplateConfigWriter.write(document: Mapping[str, Any]) -> None`
- Consumes: the complete user configuration document after one menu or profile mutation.

- [x] Write regression tests proving comments and field ordering come from the template, current secrets and profiles survive, new defaults are inserted, explicit alert targets survive, and file mode remains owner-only.
- [x] Run the focused tests and verify failure because the writer is absent.
- [x] Implement recursive template overlay and atomic round-trip output.
- [x] Route CLI `_write_yaml`, update migration, and `ProfileConfigStore` through the shared writer.
- [x] Run configuration, profile administration, and CLI tests.

### Task 3: Verification

**Files:**
- Verify: all modified files.

- [x] Run Python compile checks.
- [x] Load the regenerated example configuration with Telegram and LLM empty.
- [x] Run the complete pytest suite.
- [x] Run `git diff --check` and inspect repository status.
