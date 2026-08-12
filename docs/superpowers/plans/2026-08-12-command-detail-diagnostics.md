# Command Detail Diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在不改变命令详情分析行为的前提下，为失败响应输出足以定位 JSON、字段、分组或截断问题的安全诊断日志。

**Architecture:** OpenAI 兼容客户端在规范化响应时保留 `finish_reason`。命令详情请求层把响应元数据附加到带稳定原因代码的内部异常，批次调度层只记录异常诊断字段，不记录命令和模型响应正文。

**Tech Stack:** Python 3.11、openai Python SDK、asyncio、unittest/pytest、标准库 logging。

## Global Constraints

- 不改变 `response_format={"type":"json_object"}`、请求次数、token 预算、超时、审批和用户提示。
- 不记录模型原始响应、提示词、完整命令或凭据。
- 兼容缺少 `finish_reason`、usage、model、`temperature` 或 `max_tokens` 参数的 OpenAI 兼容接口及测试替身。
- 所有代码和测试文件使用 UTF-8。

---

### Task 1: 保留 OpenAI 兼容响应的结束原因

**Files:**
- Create: `controlplane/tests/test_llm_client.py`
- Modify: `controlplane/src/chatdome/llm/client.py`

**Interfaces:**
- Consumes: OpenAI 兼容响应的 `choices[0].finish_reason`。
- Produces: `LLMResponse.finish_reason: str = ""`。

- [ ] **Step 1: Write the failing test**

创建一个包含 message、usage 和 `finish_reason="length"` 的完整响应替身，调用 `LLMClient._parse_response`，断言规范化结果的 `finish_reason` 为 `length`；另一个不含结束原因的替身断言为空字符串。

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest -q controlplane/tests/test_llm_client.py`

Expected: FAIL，`LLMResponse` 尚无 `finish_reason`。

- [ ] **Step 3: Write minimal implementation**

在 `LLMResponse` 增加默认空字符串字段，并在 `_parse_response` 使用 `getattr(choice, "finish_reason", "") or ""` 赋值。

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest -q controlplane/tests/test_llm_client.py`

Expected: PASS。

### Task 2: 输出命令详情响应的安全诊断日志

**Files:**
- Modify: `controlplane/tests/test_pending_approval_followups.py`
- Modify: `controlplane/src/chatdome/agent/tools.py`

**Interfaces:**
- Consumes: `LLMResponse.content`、usage、`finish_reason`，以及详情结构校验异常。
- Produces: `_InvalidCommandDetailResponse` 的 `reason_code` 与安全 metadata；两次警告日志均包含 mode、reason、model、requested_max_tokens、response_chars、completion_tokens、finish_reason。

- [ ] **Step 1: Write failing JSON-parse diagnostic test**

使用包含唯一敏感标记的截断 JSON 响应和 `finish_reason="length"`，通过 `assertLogs("chatdome.agent.tools", WARNING)` 执行详情分析。断言普通和紧凑两条日志含 `reason=json_parse_error`、响应长度及结束原因，且不含响应正文标记或命令正文。

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest -q controlplane/tests/test_pending_approval_followups.py -k diagnostic`

Expected: FAIL，现有日志只有通用的 invalid 信息。

- [ ] **Step 3: Write failing schema diagnostic tests**

构造缺少必需字段的合法 JSON，以及 commands 期望 2 项、实际 1 项的合法 JSON。断言日志分别包含 `reason=missing_detail_fields` 和 `reason=incomplete_command_groups expected=2 actual=1`。

- [ ] **Step 4: Implement stable diagnostics**

让 `_validate_command_detail_payload` 抛出稳定下划线原因代码及必要计数；让 `_request_command_detail_batch` 区分 JSON 解析和结构校验，附加 mode、model、requested token、字符数、completion tokens、finish reason；让批次捕获点通过一个统一方法写警告日志。异常及日志不得包含响应或命令正文。

- [ ] **Step 5: Run focused tests**

Run: `python -m pytest -q controlplane/tests/test_llm_client.py controlplane/tests/test_pending_approval_followups.py`

Expected: PASS。

### Task 3: 回归验证与提交

**Files:**
- Verify: all modified files

**Interfaces:**
- Consumes: Task 1 与 Task 2 的实现。
- Produces: 通过完整回归的可提交改动。

- [ ] **Step 1: Run formatting and whitespace checks**

Run: `git diff --check`

Expected: 无输出，退出码 0。

- [ ] **Step 2: Run full test suite**

Run: `python -m pytest -q`

Expected: 全部测试通过，只有仓库已有的 skip。

- [ ] **Step 3: Review diff and commit**

确认 diff 仅涉及响应元数据、诊断异常、日志和对应测试，然后提交：

```text
fix(agent): 增强命令详情分析失败诊断
```
