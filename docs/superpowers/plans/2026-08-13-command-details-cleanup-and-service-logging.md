# Command Details, Cleanup, and Service Logging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Analyze shell commands one segment per LLM request, close the session cleanup task deterministically, and keep normal application logs out of duplicated system log files.

**Architecture:** The existing local shell parser remains authoritative for segmentation and ordering. `ToolDispatcher` performs one bounded request per segment, merges validated results, and records static-risk disagreements; `SessionManager` owns an awaitable cleanup lifecycle; generated systemd units discard stdout while retaining stderr in the journal.

**Tech Stack:** Python 3.9+, asyncio, OpenAI-compatible Chat Completions, PyYAML, pytest, systemd.

## Global Constraints

- Do not use `response_format`, JSON Schema, or tool calls for command details.
- Analyze segments strictly in order with no concurrent LLM detail requests.
- Limit each segment, including compact retry, to 20 seconds and the full run to `20 × n` seconds.
- Preserve completed segment results when another segment fails.
- Never lower the local static risk result.
- Redact secrets and escape control characters before logging commands.
- Keep uncaught failures observable through systemd journal.

---

### Task 1: Per-segment command detail analysis

**Files:**
- Modify: `controlplane/src/chatdome/agent/prompts.py`
- Modify: `controlplane/src/chatdome/agent/tools.py`
- Test: `controlplane/tests/test_pending_approval_followups.py`

**Interfaces:**
- Produces: serial one-segment detail requests through `ToolDispatcher.analyze_command_for_approval(...)`.
- Produces: `_COMMAND_DETAIL_SEGMENT_TIMEOUT_SECONDS = 20.0`.

- [x] Add a failing test proving three shell segments produce three ordered LLM requests and no request contains `response_format`.
- [x] Add a failing test proving one timed-out segment does not prevent the next segment from completing.
- [x] Replace batch concurrency and the fixed 30-second timeout with a serial deadline-bound loop.
- [x] Update the standard and compact prompts for an exact one-segment JSON contract.
- [x] Run the focused command-detail tests.

### Task 2: Static-risk disagreement diagnostics

**Files:**
- Modify: `controlplane/src/chatdome/agent/tools.py`
- Test: `controlplane/tests/test_pending_approval_followups.py`

**Interfaces:**
- Produces: one `WARNING` whenever static safety or risk raises the LLM result.

- [x] Add a failing test for full command, segment, index, hash, risk fields, redaction, and escaped control characters.
- [x] Implement bounded safe command rendering and disagreement logging.
- [x] Apply the static floor per segment and retain the final full-command floor.
- [x] Run the focused disagreement tests.

### Task 3: Awaitable session cleanup lifecycle

**Files:**
- Modify: `controlplane/src/chatdome/agent/session.py`
- Modify: `controlplane/src/chatdome/agent/core.py`
- Modify: `controlplane/src/chatdome/main.py`
- Test: `controlplane/tests/test_session_compression.py`

**Interfaces:**
- Produces: `async SessionManager.stop_cleanup_task() -> None`.

- [x] Add a failing test proving stop cancels, awaits, clears the task reference, and is idempotent.
- [x] Implement the awaitable stop method and update `Agent.stop()` to use it.
- [x] Ensure service startup failures enter the same final cleanup block.
- [x] Run session and runtime lifecycle tests.

### Task 4: systemd and file-log failure routing

**Files:**
- Modify: `install.sh`
- Modify: `chatdome`
- Modify: `controlplane/src/chatdome/logger.py`
- Test: `controlplane/tests/test_service_entrypoint_templates.py`
- Test: `controlplane/tests/test_logger.py`

**Interfaces:**
- Produces: generated units with `StandardOutput=null` and `StandardError=journal`.
- Produces: one stderr notification per file handler disabled by `ENOSPC`.

- [x] Add failing tests for generated unit routing and the single stderr notification.
- [x] Update both systemd unit templates.
- [x] Emit one direct stderr diagnostic before disabling a full-disk file handler.
- [x] Run service-template and logging tests.

### Task 5: Verification

**Files:**
- Verify: all modified files.

- [x] Run focused command-detail, session, logging, and service tests.
- [x] Run Python compile checks and load `config.example.yaml`.
- [x] Run the complete pytest suite.
- [x] Run shell syntax checks where the host permits them.
- [x] Run `git diff --check` and inspect repository status.
