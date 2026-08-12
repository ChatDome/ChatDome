# Command Approval and Config Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the two legacy command switches with one required three-mode approval setting, remove the conversational command-pack tool, keep command packs for Sentinel, and reject invalid YAML configuration with aggregated line-aware diagnostics before startup.

**Architecture:** A new `config_validation.py` module validates YAML text and preserves node marks before `config.py` creates dataclasses. `ToolDispatcher` becomes the only approval-policy decision point for AI-generated `run_shell_command` calls, while `CommandSandbox` becomes a policy-free executor. Sentinel retains `PackLoader` and invokes the renamed `execute_sentinel_check()` path directly.

**Tech Stack:** Python 3.11+, PyYAML node API, dataclasses, asyncio, pytest/unittest, YAML command packs.

## Global Constraints

- Work directly on `main`; do not create a worktree.
- `chatdome.agent.command_approval_mode` is required in YAML and accepts only `execute_without_approval`, `require_approval_for_risky_commands`, or `require_approval_for_all_commands`.
- `config.example.yaml` explicitly uses `require_approval_for_risky_commands`.
- Do not implement legacy-field migration or special compatibility branches.
- Unknown or indeterminate command risk requires approval.
- `command_approval_mode` applies only to AI-generated `run_shell_command` calls.
- Sentinel command packs bypass conversational approval.
- Config validation reports all independently detectable errors with YAML line locations before runtime components initialize.
- User-visible text remains concise and actionable.

---

### Task 1: Add line-aware aggregate configuration validation

**Files:**
- Create: `controlplane/src/chatdome/config_validation.py`
- Create: `controlplane/tests/test_config_validation.py`
- Modify: `controlplane/src/chatdome/config.py`
- Modify: `controlplane/tests/test_llm_provider_config.py`
- Modify: `controlplane/tests/test_chatdome_cli.py`

**Interfaces:**
- Produces: `ConfigIssue(path: str, message: str, line: int | None, column: int | None)`.
- Produces: `ConfigValidationError(issues: list[ConfigIssue])`, whose string form contains one heading followed by all sorted issues.
- Produces: `load_and_validate_config_document(path: Path) -> dict[str, Any]`.
- Consumes: built-in pack files under `controlplane/src/chatdome/packs` and a config-relative `custom_packs_dir` when checking Sentinel IDs.

- [ ] **Step 1: Write failing aggregate and line-number tests**

Add tests that write a YAML fixture containing an unknown Agent field on line 8, an invalid approval enum on line 9, and a zero command timeout on line 10, then assert one `ConfigValidationError` contains all three paths and line numbers. Add separate tests for a duplicate key, missing `command_approval_mode` pointing to the `agent` block line, an active profile that does not exist, and an unknown Sentinel `check_id`.

```python
with self.assertRaises(ConfigValidationError) as raised:
    load_config(config_path)

text = str(raised.exception)
self.assertIn("第 8 行：chatdome.agent.unexpected 是未知字段", text)
self.assertIn("第 9 行：chatdome.agent.command_approval_mode 取值无效", text)
self.assertIn("第 10 行：chatdome.agent.command_timeout 必须是大于 0 的整数", text)
```

- [ ] **Step 2: Run the new tests and verify RED**

Run: `python -m pytest -q controlplane/tests/test_config_validation.py controlplane/tests/test_llm_provider_config.py controlplane/tests/test_chatdome_cli.py`

Expected: failure because `ConfigValidationError` and the line-aware loader do not exist, and missing approval mode is still accepted.

- [ ] **Step 3: Implement YAML node indexing and duplicate detection**

Use `yaml.compose()` to walk `MappingNode` and `SequenceNode` values. Record one-based key lines by paths such as `chatdome.agent.command_timeout` and `chatdome.sentinel.checks[0].check_id`. When the same scalar mapping key occurs twice in one mapping, append an issue at the second key's mark. Convert YAML syntax exceptions into one issue using `problem_mark`.

- [ ] **Step 4: Implement the centralized schema checks**

Validate root, `chatdome`, Telegram, AI profiles, Agent, Sentinel, checks, and rules. Reject unknown keys except dynamic AI profile names and command `args`. Validate booleans, strings, numeric bounds, lists, the three approval enum values, non-empty required runtime fields, active-profile references, enabled built-in pack names, and configured Sentinel check IDs. Missing fields use the parent mapping line.

- [ ] **Step 5: Route `load_config()` and `validate-config` through the validator**

Make `load_config()` require a real configuration file, call `load_and_validate_config_document()`, then call `parse_config_document()`. Keep the pure dictionary parser usable by profile-administration code, but ensure file startup/reload validation always uses the strict path. Update CLI tests to assert the aggregate diagnostic is printed without a traceback.

- [ ] **Step 6: Run focused config tests and verify GREEN**

Run: `python -m pytest -q controlplane/tests/test_config_validation.py controlplane/tests/test_llm_provider_config.py controlplane/tests/test_chatdome_cli.py`

Expected: all focused tests pass.

- [ ] **Step 7: Commit**

```bash
git add controlplane/src/chatdome/config.py controlplane/src/chatdome/config_validation.py controlplane/tests/test_config_validation.py controlplane/tests/test_llm_provider_config.py controlplane/tests/test_chatdome_cli.py
git commit -m "feat(config): 增加带行号的聚合配置校验"
```

### Task 2: Implement the single three-mode approval policy

**Files:**
- Modify: `controlplane/src/chatdome/config.py`
- Modify: `controlplane/src/chatdome/agent/core.py`
- Modify: `controlplane/src/chatdome/agent/tools.py`
- Modify: `controlplane/src/chatdome/executor/sandbox.py`
- Modify: `controlplane/src/chatdome/executor/validator.py`
- Modify: `controlplane/tests/test_pending_approval_followups.py`
- Modify: `controlplane/tests/test_executor_validator.py`
- Modify: `controlplane/tests/test_sandbox_logging.py`

**Interfaces:**
- Produces: `AgentConfig.command_approval_mode: str`.
- Produces: `ToolDispatcher(..., command_approval_mode: str = "require_approval_for_risky_commands")` and mutable `command_approval_mode` for runtime reload.
- Produces: a policy-free `CommandSandbox.execute_shell_command(command, reason, chat_id, tool_call_id)`.
- Consumes: the existing `PendingApprovalError`, audit tracker, deterministic validator, and approved-command resume path.

- [ ] **Step 1: Write failing mode-behavior tests**

Add async behavior tests using a sandbox fake that records actually executed commands:

```python
async def test_execute_without_approval_runs_risky_command():
    dispatcher = ToolDispatcher(
        sandbox,
        command_approval_mode="execute_without_approval",
    )
    result = await dispatcher.dispatch(
        "run_shell_command",
        '{"command":"rm /tmp/example","reason":"cleanup"}',
        "call-1",
        7,
    )
    assert sandbox.commands == ["rm /tmp/example"]
    assert "exit_code" in result
```

Also assert risky mode auto-runs an explicitly safe multi-segment read command, requires approval for unknown/write/destructive commands and validator exceptions, and all-command mode always raises `PendingApprovalError` without invoking the risk analyzer.

- [ ] **Step 2: Run focused approval tests and verify RED**

Run: `python -m pytest -q controlplane/tests/test_pending_approval_followups.py controlplane/tests/test_executor_validator.py controlplane/tests/test_sandbox_logging.py`

Expected: failures because the dispatcher has no approval-mode parameter and the sandbox still contains legacy policy branches.

- [ ] **Step 3: Move approval policy into `ToolDispatcher`**

Branch at the start of `_handle_shell_command()` after checking that the command is non-empty. Direct execution mode calls the sandbox immediately. All-command mode creates a pending approval without static analysis. Risky mode analyzes every parsed command segment and auto-executes only if every segment is recognized read-only and no critical, write, delete, parser, or validation signal occurs. Catch risk-analysis exceptions, audit a stable failure reason, and require approval.

- [ ] **Step 4: Remove executor policy state**

Delete `allow_generated_commands` and `allow_unrestricted_commands` constructor arguments and attributes from `CommandSandbox`. Remove its validator/blocking branches so `execute_shell_command()` always performs the requested execution and audit after the dispatcher has decided policy. Preserve timeout, cancellation, output persistence, sensitive-output suppression, and approved-command behavior.

- [ ] **Step 5: Wire Agent construction and reload to the new mode**

Pass `config.command_approval_mode` into `ToolDispatcher`. On Agent config reload, update `agent.tool_dispatcher.command_approval_mode`; do not alter pending approval records. Replace old startup mode logs with the explicit approval-mode value.

- [ ] **Step 6: Run focused approval tests and verify GREEN**

Run: `python -m pytest -q controlplane/tests/test_pending_approval_followups.py controlplane/tests/test_executor_validator.py controlplane/tests/test_sandbox_logging.py controlplane/tests/test_turn_lifecycle.py`

Expected: all focused tests pass.

- [ ] **Step 7: Commit**

```bash
git add controlplane/src/chatdome/config.py controlplane/src/chatdome/agent/core.py controlplane/src/chatdome/agent/tools.py controlplane/src/chatdome/executor/sandbox.py controlplane/src/chatdome/executor/validator.py controlplane/tests/test_pending_approval_followups.py controlplane/tests/test_executor_validator.py controlplane/tests/test_sandbox_logging.py controlplane/tests/test_turn_lifecycle.py
git commit -m "feat(agent): 统一 AI 命令审批模式"
```

### Task 3: Remove the conversational command-pack tool

**Files:**
- Modify: `controlplane/src/chatdome/agent/prompts.py`
- Modify: `controlplane/src/chatdome/agent/tools.py`
- Modify: `controlplane/src/chatdome/agent/core.py`
- Modify: `controlplane/src/chatdome/agent/session.py`
- Modify: `controlplane/src/chatdome/agent/manual/index.yaml`
- Modify: `controlplane/src/chatdome/agent/manual/shell_commands.md`
- Modify: `controlplane/src/chatdome/agent/manual/intent_disambiguation.md`
- Modify: `controlplane/src/chatdome/agent/manual/ssh_session_commands.md`
- Modify: `controlplane/src/chatdome/agent/manual/host_exec_audit.md`
- Modify: `controlplane/src/chatdome/agent/manual/command_audit.md`
- Modify: `controlplane/tests/test_pending_approval_followups.py`

**Interfaces:**
- Produces: `build_tools() -> list[dict]` without PackLoader or check-ID parameters.
- Produces: `build_system_prompt(runtime_environment_context: str = "") -> str` with one command capability policy.
- Removes: `run_security_check` dispatch and `_handle_security_check()`.

- [ ] **Step 1: Write failing public-behavior tests**

Assert the built tool-name set excludes `run_security_check`, the system prompt does not advertise predefined commands or restricted/unrestricted modes, and dispatching the removed name returns the standard unknown-tool response without executing the sandbox.

- [ ] **Step 2: Run the prompt/dispatcher tests and verify RED**

Run: `python -m pytest -q controlplane/tests/test_pending_approval_followups.py`

Expected: failure because the tool is still advertised and dispatched.

- [ ] **Step 3: Remove the tool and PackLoader dependencies from Agent prompts**

Delete fallback check text, dynamic check listing, dual restricted/unrestricted policies, `run_security_check` schema, and related function arguments. Keep a single shell-capability policy that permits commands needed for an explicit user request and states that the runtime may require approval.

- [ ] **Step 4: Remove dispatch, summaries, and Agent wiring**

Delete `_handle_security_check()`, its dispatch branch, session-summary formatting, `valid_check_ids`, and Agent prompt/tool PackLoader parameters. Keep Sentinel injection used by alert-control tools separate from command packs.

- [ ] **Step 5: Update the curated Agent manual**

Replace conversational pack-tool instructions with `run_shell_command` guidance, remove the tool from the manual index, and keep Sentinel-specific check IDs only in Sentinel documentation where they refer to alerts or schedules.

- [ ] **Step 6: Run the focused tests and verify GREEN**

Run: `python -m pytest -q controlplane/tests/test_pending_approval_followups.py controlplane/tests/test_session_compression.py controlplane/tests/test_engram.py`

Expected: all focused tests pass.

- [ ] **Step 7: Commit**

```bash
git add controlplane/src/chatdome/agent controlplane/tests/test_pending_approval_followups.py controlplane/tests/test_session_compression.py controlplane/tests/test_engram.py
git commit -m "refactor(agent): 移除对话命令包工具"
```

### Task 4: Rename the Sentinel-only execution path and audit vocabulary

**Files:**
- Modify: `controlplane/src/chatdome/executor/sandbox.py`
- Modify: `controlplane/src/chatdome/sentinel/scheduler.py`
- Modify: `controlplane/src/chatdome/sentinel/pack_loader.py`
- Modify: `controlplane/src/chatdome/executor/registry.py`
- Modify: `controlplane/tests/test_sentinel_ssh_login.py`
- Modify: `controlplane/tests/test_sentinel_alert_push_controls.py`
- Modify: `controlplane/tests/test_sandbox_logging.py`

**Interfaces:**
- Produces: `CommandSandbox.execute_sentinel_check(check_id: str, args: dict[str, Any] | None = None, chat_id: int = 0, tool_call_id: str = "") -> CommandResult`.
- Consumes: `PackLoader.render_command()` and the existing Sentinel log-origin context.
- Removes: `execute_security_check()`.

- [ ] **Step 1: Write failing Sentinel execution and audit tests**

Rename sandbox fakes to expose only `execute_sentinel_check()`. Assert a scheduled check succeeds through that method and its audit record uses `sentinel_check_executed`, `sentinel_check:<check_id>`, and `execution_mode="sentinel_pack"`.

- [ ] **Step 2: Run focused Sentinel tests and verify RED**

Run: `python -m pytest -q controlplane/tests/test_sentinel_ssh_login.py controlplane/tests/test_sentinel_alert_push_controls.py controlplane/tests/test_sandbox_logging.py`

Expected: failure because the scheduler still calls `execute_security_check()` and audit names are unchanged.

- [ ] **Step 3: Rename the method and all Sentinel call sites**

Rename the sandbox method and scheduler wrapper, then update docstrings and compatibility wording in the pack loader and legacy registry. Change invalid, executed, reason, log-label, and execution-mode values to the `sentinel_check` vocabulary.

- [ ] **Step 4: Run focused Sentinel tests and verify GREEN**

Run: `python -m pytest -q controlplane/tests/test_sentinel_ssh_login.py controlplane/tests/test_sentinel_alert_push_controls.py controlplane/tests/test_sentinel_state_machine.py controlplane/tests/test_sandbox_logging.py`

Expected: all focused tests pass.

- [ ] **Step 5: Commit**

```bash
git add controlplane/src/chatdome/executor controlplane/src/chatdome/sentinel controlplane/tests/test_sentinel_ssh_login.py controlplane/tests/test_sentinel_alert_push_controls.py controlplane/tests/test_sentinel_state_machine.py controlplane/tests/test_sandbox_logging.py
git commit -m "refactor(sentinel): 明确命令包执行入口"
```

### Task 5: Update runtime configuration, examples, and documentation

**Files:**
- Modify: `controlplane/src/chatdome/main.py`
- Modify: `config.example.yaml`
- Modify: `README.md`
- Modify: `README_ZH.md`
- Modify: `SECURITY.md`
- Modify: `CHANGELOG.md`
- Modify: affected tests under `controlplane/tests/`

**Interfaces:**
- Consumes: strict `load_config()` and `AgentConfig.command_approval_mode`.
- Produces: startup and hot-reload behavior with the same validated configuration contract.

- [ ] **Step 1: Add missing approval mode to valid configuration fixtures**

Update every YAML fixture passed through `load_config()` so `chatdome.agent.command_approval_mode` is explicit. Add a runtime-reload test that changes the mode and observes the dispatcher value while an existing pending approval remains intact.

- [ ] **Step 2: Run impacted tests and verify RED**

Run: `python -m pytest -q controlplane/tests/test_llm_provider_config.py controlplane/tests/test_chatdome_cli.py controlplane/tests/test_reload_control.py controlplane/tests/test_chatdome_menu.py`

Expected: reload/config fixture failures until wiring and templates use the new required field.

- [ ] **Step 3: Update startup and hot-reload wiring**

Remove PackLoader data from Agent tool construction, log `Command approval mode: <value>`, pass the new mode into the dispatcher, and reload it for future commands. Ensure strict validation completes before LLM, sandbox, Telegram, or Sentinel initialization.

- [ ] **Step 4: Update public configuration and security documentation**

Replace the two legacy switches and named modes with the three exact enum values. Explain that only AI-generated `run_shell_command` is controlled, unknown risk requires approval in the default mode, and Sentinel command packs are internal scheduled checks. Remove `run_security_check` from public tool tables.

- [ ] **Step 5: Run impacted tests and verify GREEN**

Run: `python -m pytest -q controlplane/tests/test_llm_provider_config.py controlplane/tests/test_chatdome_cli.py controlplane/tests/test_reload_control.py controlplane/tests/test_chatdome_menu.py controlplane/tests/test_service_entrypoint_templates.py`

Expected: all focused tests pass.

- [ ] **Step 6: Commit**

```bash
git add controlplane/src/chatdome/main.py config.example.yaml README.md README_ZH.md SECURITY.md CHANGELOG.md controlplane/tests
git commit -m "docs(config): 更新命令审批配置与哨兵边界"
```

### Task 6: Full regression and stale-concept audit

**Files:**
- Modify only files required by failures found during verification.

**Interfaces:**
- Verifies the complete specification and all earlier task interfaces.

- [ ] **Step 1: Scan for stale public and runtime symbols**

Run:

```bash
rg -n "allow_generated_commands|allow_unrestricted_commands|run_security_check|execute_security_check|security_check_executed|security_check_invalid|ai_command:unrestricted|restricted_default|unrestricted_guardrail" .
```

Expected: no runtime, test, example, or active manual references; historical design documents may retain old names only when describing the replaced state.

- [ ] **Step 2: Validate the example configuration**

Create a temporary filled copy of `config.example.yaml`, insert non-secret placeholder Telegram/model values, and run `python chatdome-cli.py validate-config` with `CHATDOME_CONFIG` pointing to it.

Expected: `config valid: <temporary-path>`.

- [ ] **Step 3: Run the full test suite**

Run: `python -m pytest -q`

Expected: all tests pass with no unhandled task, warning, or collection errors.

- [ ] **Step 4: Review the final diff**

Run: `git diff --check` and `git status --short`. Inspect changes for unrelated edits, leaked credentials, obsolete user-visible terminology, and violations of the approved design.

Expected: no whitespace errors, no secrets, and only in-scope changes.

- [ ] **Step 5: Commit any verification fixes**

```bash
git add <only-files-fixed-during-verification>
git commit -m "fix(agent): 完善统一审批与配置校验回归"
```

Skip this commit when verification requires no additional changes.
