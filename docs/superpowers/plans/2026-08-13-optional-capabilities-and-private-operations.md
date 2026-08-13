# Optional Capabilities and Private Operations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep the ChatDome service and Sentinel operational without Telegram or LLM configuration, enforce private-user Telegram access, move Sentinel checks into one built-in policy, and serialize all interactive entry points through one global turn.

**Architecture:** Configuration parsing exposes independent readiness states for LLM and platform adapters. The core service owns Sentinel and optional components, while a process-safe `GlobalTurnCoordinator` guards interactive turns across Telegram and CLI. Sentinel loads its only check policy from a packaged YAML file and routes alerts through platform-scoped targets.

**Tech Stack:** Python 3.9+, asyncio, PyYAML, python-telegram-bot, POSIX `fcntl`, pytest, Bash updater.

## Global Constraints

- Telegram, LLM, and Sentinel configuration are independent capabilities.
- Telegram accepts private chats only and authorizes `effective_user.id` against `allowed_ids ∪ admin_ids`.
- Empty Telegram allow/admin lists deny every inbound Telegram request.
- All interactive platforms share one active turn; Sentinel background checks do not consume it.
- `config.yaml` does not contain Sentinel checks; the packaged policy is the only source.
- Runtime configuration rejects legacy fields; `chatdome update` performs explicit migration and rollback.
- User-visible text remains concise and actionable.

---

### Task 1: Optional Telegram and LLM configuration

**Files:**
- Modify: `controlplane/src/chatdome/config.py`
- Modify: `controlplane/src/chatdome/config_validation.py`
- Modify: `config.example.yaml`
- Test: `controlplane/tests/test_config_validation.py`
- Test: `controlplane/tests/test_llm_provider_config.py`

**Interfaces:**
- Produces: `ChatDomeConfig.llm_configured: bool`
- Produces: `TelegramConfig.allowed_ids: list[int]`
- Produces: `TelegramConfig.admin_ids: list[int]`
- Produces: `ChatDomeConfig.telegram_configured: bool`

- [ ] **Step 1: Write failing validation tests**

Add tests proving an empty token and empty LLM pool load successfully, partially configured LLM settings fail, and the renamed Telegram lists parse as integers.

```python
def test_optional_telegram_and_llm_can_be_empty(self):
    config = self.load(OPTIONAL_CAPABILITIES_CONFIG)
    self.assertFalse(config.telegram_configured)
    self.assertFalse(config.llm_configured)

def test_nonempty_profiles_require_active_profile(self):
    with self.assertRaisesRegex(ValueError, "active_ai_profile"):
        self.load(CONFIG_WITH_PROFILE_AND_NO_ACTIVE)
```

- [ ] **Step 2: Run tests and verify RED**

Run: `python -m pytest -q controlplane/tests/test_config_validation.py controlplane/tests/test_llm_provider_config.py`

Expected: failures report the current non-empty requirements or missing renamed fields.

- [ ] **Step 3: Implement capability-aware parsing and validation**

Allow Telegram and LLM sections to be structurally valid while empty. Enforce profile references only when either LLM field is populated. Rename Telegram list fields and reject the old names.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run: `python -m pytest -q controlplane/tests/test_config_validation.py controlplane/tests/test_llm_provider_config.py`

- [ ] **Step 5: Commit**

```bash
git add controlplane/src/chatdome/config.py controlplane/src/chatdome/config_validation.py config.example.yaml controlplane/tests/test_config_validation.py controlplane/tests/test_llm_provider_config.py
git commit -m "feat(config): 拆分可选平台与模型能力"
```

### Task 2: Private Telegram authorization and administrator scope

**Files:**
- Modify: `controlplane/src/chatdome/telegram/auth.py`
- Modify: `controlplane/src/chatdome/telegram/bot.py`
- Modify: `chatdome-cli.py`
- Modify: `chatdome`
- Test: `controlplane/tests/test_telegram_lifecycle.py`
- Test: `controlplane/tests/test_telegram_llm_admin.py`
- Test: `controlplane/tests/test_chatdome_cli.py`
- Test: `controlplane/tests/test_chatdome_menu.py`

**Interfaces:**
- Produces: `Authenticator(allowed_ids: list[int], admin_ids: list[int])`
- Produces: `Authenticator.is_authorized(user_id: int) -> bool`
- Produces: `Authenticator.is_admin(user_id: int) -> bool`

- [ ] **Step 1: Write failing private-access tests**

Cover denied empty lists, administrator access inheritance, authorization by `effective_user.id`, group rejection, and the two requested menu labels.

```python
def test_empty_lists_deny_every_user(self):
    self.assertFalse(Authenticator([], []).is_authorized(123))

def test_admin_inherits_allowed_access(self):
    auth = Authenticator([], [123])
    self.assertTrue(auth.is_authorized(123))
    self.assertTrue(auth.is_admin(123))
```

- [ ] **Step 2: Run tests and verify RED**

Run: `python -m pytest -q controlplane/tests/test_telegram_lifecycle.py controlplane/tests/test_telegram_llm_admin.py controlplane/tests/test_chatdome_cli.py controlplane/tests/test_chatdome_menu.py`

- [ ] **Step 3: Implement private-user authorization**

Reject non-private updates before command or message dispatch, authorize on user ID, replace model-only administrator wording, and update CLI configuration commands to write `allowed_ids` and `admin_ids`.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run the command from Step 2.

- [ ] **Step 5: Commit**

```bash
git add controlplane/src/chatdome/telegram chatdome-cli.py chatdome controlplane/tests
git commit -m "feat(telegram): 强制私人用户白名单访问"
```

### Task 3: Built-in Sentinel policy and platform alert targets

**Files:**
- Create: `controlplane/src/chatdome/sentinel/default-checks.yaml`
- Modify: `controlplane/pyproject.toml`
- Modify: `controlplane/src/chatdome/config.py`
- Modify: `controlplane/src/chatdome/config_validation.py`
- Modify: `controlplane/src/chatdome/sentinel/checks.py`
- Modify: `controlplane/src/chatdome/sentinel/scheduler.py`
- Modify: `controlplane/src/chatdome/main.py`
- Modify: `config.example.yaml`
- Test: `controlplane/tests/test_config_validation.py`
- Test: `controlplane/tests/test_sentinel_state_machine.py`
- Test: `controlplane/tests/test_sentinel_alert_push_controls.py`

**Interfaces:**
- Produces: `load_builtin_checks() -> list[CheckDefinition]`
- Produces: `SentinelConfig.alert_targets: dict[str, PlatformAlertTarget]`
- Produces: `resolve_telegram_alert_user_ids(config: ChatDomeConfig) -> list[int]`

- [ ] **Step 1: Write failing policy and target tests**

Prove checks load without config entries, `checks` becomes unknown, omitted Telegram targets fall back to allowed/admin union, explicit empty disables delivery, and unauthorized targets fail validation.

- [ ] **Step 2: Run tests and verify RED**

Run: `python -m pytest -q controlplane/tests/test_config_validation.py controlplane/tests/test_sentinel_state_machine.py controlplane/tests/test_sentinel_alert_push_controls.py`

- [ ] **Step 3: Extract and load the built-in policy**

Move the existing example checks unchanged into the packaged file, validate it on load, and remove check parsing from user configuration.

- [ ] **Step 4: Implement platform-scoped alert targets**

Parse `sentinel.alert_targets.<platform>.user_ids`, distinguish omitted and explicit empty targets, and route the resolved Telegram user IDs into the scheduler.

- [ ] **Step 5: Run focused tests and verify GREEN**

Run the command from Step 2.

- [ ] **Step 6: Commit**

```bash
git add controlplane/src/chatdome/sentinel controlplane/src/chatdome/config.py controlplane/src/chatdome/config_validation.py controlplane/src/chatdome/main.py controlplane/pyproject.toml config.example.yaml controlplane/tests
git commit -m "refactor(sentinel): 内置统一巡检策略"
```

### Task 4: Optional runtime components and degraded health

**Files:**
- Create: `controlplane/src/chatdome/runtime.py`
- Modify: `controlplane/src/chatdome/main.py`
- Modify: `controlplane/src/chatdome/telegram/bot.py`
- Modify: `chatdome-cli.py`
- Test: `controlplane/tests/test_optional_runtime.py`
- Test: `controlplane/tests/test_chatdome_cli.py`
- Test: `controlplane/tests/test_telegram_lifecycle.py`

**Interfaces:**
- Produces: `CapabilityStatus(state: str, detail: str = "")`
- Produces: `RuntimeCapabilities` with `core`, `sentinel`, `llm`, and `telegram` status
- Produces: `run_service(config: ChatDomeConfig) -> None`

- [ ] **Step 1: Write failing four-combination tests**

Test the Telegram/LLM configuration matrix and verify Sentinel starts in all four combinations. Verify LLM-dependent chat returns a model-configuration prompt without creating a turn.

- [ ] **Step 2: Run tests and verify RED**

Run: `python -m pytest -q controlplane/tests/test_optional_runtime.py controlplane/tests/test_chatdome_cli.py controlplane/tests/test_telegram_lifecycle.py`

- [ ] **Step 3: Implement the core lifecycle**

Create Sentinel independently, create LLM Manager and Agent only when configured, start Telegram polling only with a token, and keep the process alive through asyncio signal handling when Telegram is absent.

- [ ] **Step 4: Implement deterministic Telegram mode and health status**

Allow shared deterministic commands without an Agent, return the model setup prompt for ordinary text, and write component states to `ready.json` for `health-check` and status output.

- [ ] **Step 5: Run focused tests and verify GREEN**

Run the command from Step 2.

- [ ] **Step 6: Commit**

```bash
git add controlplane/src/chatdome/runtime.py controlplane/src/chatdome/main.py controlplane/src/chatdome/telegram/bot.py chatdome-cli.py controlplane/tests
git commit -m "feat(core): 支持可选平台与模型运行组件"
```

### Task 5: Process-safe global turn coordinator

**Files:**
- Create: `controlplane/src/chatdome/agent/global_turn.py`
- Modify: `controlplane/src/chatdome/agent/core.py`
- Modify: `chatdome-cli.py`
- Test: `controlplane/tests/test_global_turn.py`
- Test: `controlplane/tests/test_turn_lifecycle.py`
- Test: `controlplane/tests/test_chatdome_cli.py`

**Interfaces:**
- Produces: `GlobalTurnCoordinator.try_acquire(source: str, chat_id: int, user_id: int | None) -> GlobalTurnLease | None`
- Produces: `GlobalTurnLease.update(turn_id: int | None, state: str) -> None`
- Produces: `GlobalTurnLease.release() -> None`

- [ ] **Step 1: Write failing lock lifecycle tests**

Cover contention between independent coordinator instances, ownership through approval wait, release after terminal outcomes, automatic OS release after process exit, and Sentinel exclusion.

- [ ] **Step 2: Run tests and verify RED**

Run: `python -m pytest -q controlplane/tests/test_global_turn.py controlplane/tests/test_turn_lifecycle.py controlplane/tests/test_chatdome_cli.py`

- [ ] **Step 3: Implement process-safe locking**

Use a non-blocking POSIX `flock` on the runtime lock file. Write non-sensitive owner metadata atomically beside the held descriptor and remove it on release when still owned.

- [ ] **Step 4: Integrate with Agent and CLI**

Acquire before a new user turn, retain through approval and user-choice states, release only at terminal outcomes, and return the busy result without mutating sessions when acquisition fails.

- [ ] **Step 5: Run focused tests and verify GREEN**

Run the command from Step 2.

- [ ] **Step 6: Commit**

```bash
git add controlplane/src/chatdome/agent/global_turn.py controlplane/src/chatdome/agent/core.py chatdome-cli.py controlplane/tests
git commit -m "feat(agent): 串行化全部交互入口"
```

### Task 6: Transactional update migration and documentation

**Files:**
- Modify: `chatdome-cli.py`
- Modify: `chatdome`
- Modify: `README.md`
- Modify: `README_ZH.md`
- Modify: `controlplane/src/chatdome/agent/manual/sentinel.md`
- Test: `controlplane/tests/test_chatdome_cli.py`
- Test: `controlplane/tests/test_chatdome_menu.py`

**Interfaces:**
- Produces: CLI command `migrate-config --from-commit <commit>`
- Produces: idempotent config migration with an adjacent backup path printed to stdout

- [ ] **Step 1: Write failing migration and rollback tests**

Test every renamed field, Sentinel check removal, secret preservation, idempotence, validation failure, and updater restoration of the original production config.

- [ ] **Step 2: Run tests and verify RED**

Run: `python -m pytest -q controlplane/tests/test_chatdome_cli.py controlplane/tests/test_chatdome_menu.py`

- [ ] **Step 3: Implement explicit migration**

Add a CLI migration command that makes a permission-preserving backup, transforms known schema changes, validates through the candidate runtime, and restores the backup on failure.

- [ ] **Step 4: Integrate migration into update transaction**

Run migration after candidate installation and before candidate validation. Extend updater rollback to restore the configuration backup along with the previous commit and Python environment.

- [ ] **Step 5: Update public documentation**

Document optional capabilities, private Telegram IDs, built-in Sentinel policy, alert target semantics, status states, and update behavior.

- [ ] **Step 6: Run focused tests and verify GREEN**

Run the command from Step 2.

- [ ] **Step 7: Commit**

```bash
git add chatdome chatdome-cli.py README.md README_ZH.md controlplane/src/chatdome/agent/manual/sentinel.md controlplane/tests
git commit -m "feat(update): 迁移可选能力配置结构"
```

### Task 7: Full verification

**Files:**
- Verify: all modified files

- [ ] **Step 1: Validate Python and shell syntax**

Run:

```bash
python -m compileall -q controlplane/src chatdome-cli.py
bash -n chatdome
bash -n install.sh
bash -n scripts/start.sh
```

- [ ] **Step 2: Validate example and migration fixtures**

Run the candidate CLI against the empty optional-capability example and against a migrated production-style fixture.

- [ ] **Step 3: Run the complete test suite**

Run: `python -m pytest -q`

Expected: all tests pass; only intentional environment skips remain.

- [ ] **Step 4: Review repository state**

Run:

```bash
git diff --check
git status --short
git log --oneline -10
```

- [ ] **Step 5: Commit verification fixes if required**

```bash
git add controlplane chatdome-cli.py chatdome install.sh scripts/start.sh config.example.yaml README.md README_ZH.md
git commit -m "test(core): 补全可选能力集成验证"
```
