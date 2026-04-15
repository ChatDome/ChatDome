# ChatDome Sentinel 实施方案

> 基于 `chatdome-sentinel-design-ZH.md` 设计文档，结合现有代码库（18 个源文件，~2670 行），制定从当前 v0.1.0 到 v0.2.0 (Sentinel) 的完整实施路径。

---

## 1. 现有代码资产盘点

### 1.1 文件清单与代码量

| 模块 | 文件 | 行数 | 职责 |
|------|------|------|------|
| 入口 | `main.py` | 98 | 加载配置、初始化组件、启动 Bot |
| 配置 | `config.py` | 170 | YAML + 环境变量配置加载 |
| Agent 核心 | `agent/core.py` | 200 | ReAct 循环驱动 |
| Agent 提示词 | `agent/prompts.py` | 130 | 系统提示词 + Tool 定义 + Reviewer 提示词 |
| Agent 会话 | `agent/session.py` | 328 | 多轮对话管理 + 历史压缩 + Memory Vault |
| Agent 工具 | `agent/tools.py` | 220 | 工具分发（security_check / shell / whois） |
| Agent 追踪 | `agent/tracker.py` | 95 | Token 消耗追踪（JSONL） |
| 命令注册 | `executor/registry.py` | 210 | **15 条硬编码命令** + 模板渲染 |
| 命令沙箱 | `executor/sandbox.py` | 182 | asyncio subprocess 执行 + 超时 + 截断 |
| 命令验证 | `executor/validator.py` | 157 | 正则黑名单 + 只读白名单 |
| LLM 客户端 | `llm/client.py` | 251 | OpenAI 兼容异步客户端 + 重试 + 安全审查 |
| Telegram 认证 | `telegram/auth.py` | 52 | Chat ID 白名单认证 |
| Telegram Bot | `telegram/bot.py` | 422 | 消息路由 + 审批流程 + 长消息分片 |
| **合计** | **18 文件** | **~2670 行** | |

### 1.2 架构依赖图

```
main.py
  ├─ config.py                    ← 配置加载
  ├─ llm/client.py                ← LLM 调用
  ├─ executor/sandbox.py          ← 命令执行
  │   ├─ executor/registry.py     ← 命令定义（将被替换）
  │   └─ executor/validator.py    ← 安全验证
  ├─ agent/core.py                ← ReAct 引擎
  │   ├─ agent/prompts.py         ← 提示词 + Tool schema
  │   ├─ agent/session.py         ← 会话管理
  │   ├─ agent/tools.py           ← 工具分发
  │   └─ agent/tracker.py         ← Token 追踪
  └─ telegram/bot.py              ← Telegram 入口
      └─ telegram/auth.py         ← 认证
```

---

## 2. 组件替换与复用分析

### 2.1 直接替换（删除旧代码）

| 旧组件 | 行数 | 替换为 | 原因 |
|--------|------|--------|------|
| `executor/registry.py` | 210 | `sentinel/pack_loader.py` + 8 个 Pack YAML | 15 条硬编码命令全部迁移到 Pack YAML，PackLoader 提供 `render_command()` 等价接口 |

**影响范围**：
- `executor/sandbox.py` 第 5 行：`from chatdome.executor.registry import render_command` → 改为从 PackLoader 获取
- `agent/prompts.py` 第 50-65 行：SYSTEM_PROMPT 中硬编码的 15 个 check_id 列表 → 改为动态生成
- `agent/prompts.py` 第 98-115 行：TOOLS 中 `run_security_check` 的 description 硬编码 check_id 列表 → 动态注入

### 2.2 需要修改的组件

| 组件 | 修改内容 | 影响程度 |
|------|----------|----------|
| `config.py` | 新增 `SentinelConfig` dataclass + `sentinel:` YAML 段解析 | **中** — 增量修改，不破坏现有 |
| `main.py` | 新增 Sentinel 初始化 + 启动/关闭生命周期 | **中** — 增加 ~30 行 |
| `agent/prompts.py` | SYSTEM_PROMPT 改为动态注入可用命令 + 新增 Sentinel 相关提示词 | **中** — 模板化改造 |
| `agent/tools.py` | `_handle_security_check` 改用 PackLoader；新增 Sentinel 命令分发 | **中** — 接口不变，内部实现替换 |
| `executor/sandbox.py` | `execute_security_check` 接口改用 PackLoader 的 `RenderedCommand` | **低** — 仅改数据源 |
| `telegram/bot.py` | 新增 /sentinel 系列命令处理 + 告警推送方法 | **高** — 新增 ~150 行 |

### 2.3 完全复用（无需修改）

| 组件 | 行数 | 复用方式 |
|------|------|----------|
| `llm/client.py` | 251 | Sentinel alerter/envelope 直接调用 `llm.chat_completion()` |
| `executor/sandbox.py` | 182 | Sentinel scheduler 复用 `sandbox._execute()` 执行检查命令 |
| `executor/validator.py` | 157 | AI 兜底模式生成命令时仍需安全验证 |
| `telegram/auth.py` | 52 | Sentinel 告警推送复用认证机制 |
| `agent/session.py` | 328 | 会话管理不受 Sentinel 影响 |
| `agent/core.py` | 200 | ReAct 循环不受 Sentinel 影响 |
| `agent/tracker.py` | 95 | Sentinel AI 调用复用 Token 追踪 |

### 2.4 替换关系总览

```
┌─────────────────────────────────────────────────────────────┐
│                    现有代码 → Sentinel 映射                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ██ 删除替换                                                 │
│  executor/registry.py (210行)                                │
│       └──▶ sentinel/pack_loader.py + 8× Pack YAML           │
│                                                             │
│  ▤▤ 需要修改                                                 │
│  config.py ──────── +SentinelConfig                          │
│  main.py ─────────── +Sentinel 启动/关闭                      │
│  agent/prompts.py ── 动态命令列表 + Sentinel 提示词            │
│  agent/tools.py ──── PackLoader 接入                          │
│  executor/sandbox.py  PackLoader 接入                         │
│  telegram/bot.py ──── +/sentinel 命令 + 告警推送               │
│                                                             │
│  ░░ 完全复用                                                 │
│  llm/client.py ───── Sentinel AI 分析 + 叙事更新              │
│  executor/validator.py  AI 兜底命令验证                       │
│  telegram/auth.py ── 告警推送认证                              │
│  agent/session.py ── 不受影响                                  │
│  agent/core.py ───── 不受影响                                  │
│  agent/tracker.py ── 复用 Token 追踪                           │
│                                                             │
│  ★★ 全新模块                                                  │
│  sentinel/   （14 个新文件）                                   │
│  packs/      （8 个内置 YAML + 用户自定义目录）                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. 迁移关键路径：registry.py → PackLoader

这是唯一的"删旧建新"操作，需要确保调用链无缝切换。

### 3.1 当前调用链

```
LLM tool_call: run_security_check(check_id="ssh_bruteforce")
  → agent/tools.py: ToolDispatcher._handle_security_check()
    → executor/sandbox.py: CommandSandbox.execute_security_check(check_id, args)
      → executor/registry.py: render_command(check_id, args) → RenderedCommand
      → sandbox._execute(rendered.command, rendered.timeout)
```

### 3.2 迁移后调用链

```
LLM tool_call: run_security_check(check_id="ssh_bruteforce")
  → agent/tools.py: ToolDispatcher._handle_security_check()
    → executor/sandbox.py: CommandSandbox.execute_security_check(check_id, args)
      → sentinel/pack_loader.py: PackLoader.render_command(check_id, args) → RenderedCommand
      → sandbox._execute(rendered.command, rendered.timeout)
```

### 3.3 迁移步骤

1. **创建** `sentinel/pack_loader.py`，实现 `render_command(check_id, args)` 接口，保持返回类型 `RenderedCommand` 与旧 registry 一致
2. **创建** 8 个 Pack YAML 文件，覆盖原 15 条命令（已扩展到 ~40 条）
3. **修改** `executor/sandbox.py`：`from chatdome.executor.registry import render_command` → `from chatdome.sentinel.pack_loader import PackLoader`；`execute_security_check` 改为调用 PackLoader 实例
4. **修改** `agent/prompts.py`：SYSTEM_PROMPT 中的命令列表改为占位符，由启动时动态注入
5. **修改** `agent/tools.py`：Tool 定义中的 description 改为动态生成
6. **验证**：现有 Agent 对话流程不受影响（`run_security_check` 工具签名不变）
7. **删除** `executor/registry.py`

### 3.4 兼容性保证

| 维度 | 保证 |
|------|------|
| Tool 签名 | `run_security_check(check_id, args)` 不变 |
| 返回类型 | `RenderedCommand(check_id, name, command, timeout)` 不变 |
| 已有 check_id | 15 个 check_id 全部保留在 Pack YAML 中，一一对应 |
| 错误处理 | check_id 不存在时仍抛 `ValueError`，消息格式不变 |

---

## 4. 新增模块清单

### 4.1 sentinel/ 模块

| 文件 | 职责 | 依赖 | 预估行数 |
|------|------|------|---------|
| `__init__.py` | 模块入口 | — | 5 |
| `pack_loader.py` | Pack YAML 加载 + 平台检测 + 模板渲染 | `PyYAML`, `platform` | 200 |
| `scheduler.py` | asyncio 定时调度器 | `asyncio` | 150 |
| `checks.py` | CheckDefinition 数据类 + YAML 加载 | `dataclasses` | 100 |
| `evaluator.py` | 规则引擎（line_count / regex_extract / added_count） | `re` | 120 |
| `diff.py` | Differential 差异追踪 | — | 80 |
| `suppressor.py` | 三层告警抑制 | `asyncio` | 150 |
| `envelope.py` | 威胁信封（四态生命周期 + 双层架构） | `collections.Counter`, `datetime` | 350 |
| `whitelist.py` | 交互式白名单 | `LLMClient` | 200 |
| `memory_vault.py` | 哨兵记忆库 | `json`, `sqlite3` | 200 |
| `alerter.py` | 告警格式化 + AI 分析 + Telegram 推送 | `LLMClient`, `telegram.Bot` | 250 |
| `enrichment.py` | 上下文富化 | `CommandSandbox` | 80 |
| `report.py` | 每日巡检报告 | `LLMClient` | 120 |
| `prompts.py` | Sentinel AI Prompt 集合 | — | 100 |
| **合计** | | | **~2100** |

### 4.2 packs/ 内置 YAML

| 文件 | 命令数 | 覆盖原 registry 命令 |
|------|--------|---------------------|
| `ssh_auth.yaml` | 5 | ssh_bruteforce, ssh_success_login, failed_sudo |
| `network.yaml` | 6 | active_connections, open_ports, firewall_rules |
| `system_resources.yaml` | 6 | disk_usage, memory_usage, system_load, last_reboot |
| `users_permissions.yaml` | 5 | — (新增) |
| `file_integrity.yaml` | 5 | large_files + 新增 |
| `processes_services.yaml` | 5 | suspicious_processes, recent_cron_jobs |
| `logs.yaml` | 4 | recent_syslog, kernel_errors |
| `containers.yaml` | 4 | — (新增) |
| **合计** | **~40** | **15/15 全覆盖** |

---

## 5. 分阶段实施计划

### Phase 1：基础巡检 MVP — Pack 迁移 + 调度器

**目标**：替换 registry.py，实现最小可用的定时巡检 + Telegram 告警。

**前置条件**：无，可立即开始。

```
改动文件:
  创建  controlplane/src/chatdome/packs/*.yaml          (8 文件)
  创建  controlplane/src/chatdome/sentinel/__init__.py
  创建  controlplane/src/chatdome/sentinel/pack_loader.py
  创建  controlplane/src/chatdome/sentinel/scheduler.py
  创建  controlplane/src/chatdome/sentinel/checks.py
  创建  controlplane/src/chatdome/sentinel/evaluator.py
  创建  controlplane/src/chatdome/sentinel/alerter.py    (基础版)
  创建  controlplane/src/chatdome/sentinel/suppressor.py (仅 Cooldown)
  修改  controlplane/src/chatdome/config.py              (+SentinelConfig)
  修改  controlplane/src/chatdome/main.py                (+Sentinel 启动)
  修改  controlplane/src/chatdome/executor/sandbox.py    (PackLoader 接入)
  修改  controlplane/src/chatdome/agent/prompts.py       (动态命令列表)
  修改  controlplane/src/chatdome/agent/tools.py         (PackLoader 接入)
  删除  controlplane/src/chatdome/executor/registry.py
```

**任务分解**：

| # | 任务 | 产出 | 依赖 |
|---|------|------|------|
| 1.1 | 编写 8 个 Pack YAML 文件 | `packs/*.yaml` | 无 |
| 1.2 | 实现 PackLoader（加载/平台检测/渲染） | `sentinel/pack_loader.py` | 1.1 |
| 1.3 | 修改 sandbox.py + tools.py 接入 PackLoader | 调用链切换 | 1.2 |
| 1.4 | 修改 prompts.py 动态注入命令列表 | SYSTEM_PROMPT 模板化 | 1.2 |
| 1.5 | **验证点**：现有 Agent 对话功能不受影响 | 手动测试 | 1.3, 1.4 |
| 1.6 | 删除 registry.py | 清理旧代码 | 1.5 |
| 1.7 | 实现 SentinelConfig + config.py 扩展 | 配置解析 | 无 |
| 1.8 | 实现 CheckDefinition + checks.py | 检查策略加载 | 1.7 |
| 1.9 | 实现 Evaluator（规则引擎） | `sentinel/evaluator.py` | 无 |
| 1.10 | 实现 Suppressor（Cooldown 层） | `sentinel/suppressor.py` | 无 |
| 1.11 | 实现 Alerter（基础 Telegram 推送） | `sentinel/alerter.py` | 无 |
| 1.12 | 实现 Scheduler + main.py 启动集成 | 定时调度运行 | 1.8-1.11 |
| 1.13 | **里程碑**：Sentinel 定时巡检 + Telegram 告警可用 | 端到端测试 | 全部 |

**Phase 1 完成标准**：
- [x] `registry.py` 已删除，PackLoader 完全接管
- [x] 8 个 Pack YAML 加载成功，15 个旧 check_id 全部可用
- [x] Agent 对话中 `run_security_check` 正常工作
- [x] `sentinel.enabled: true` 时启动定时巡检
- [x] 检查结果超阈值时 Telegram 推送告警
- [x] 相同告警在 cooldown 期内不重复推送

---

### Phase 2：智能告警 — Diff + AI 分析 + 交互

**前置条件**：Phase 1 完成。

```
改动文件:
  创建  controlplane/src/chatdome/sentinel/diff.py
  创建  controlplane/src/chatdome/sentinel/enrichment.py
  创建  controlplane/src/chatdome/sentinel/prompts.py
  修改  controlplane/src/chatdome/sentinel/suppressor.py   (+Dedup +Aggregation)
  修改  controlplane/src/chatdome/sentinel/alerter.py      (+AI 分析 +交互按钮)
  修改  controlplane/src/chatdome/telegram/bot.py           (+告警交互回调)
```

| # | 任务 | 产出 | 依赖 |
|---|------|------|------|
| 2.1 | 实现 DiffTracker | `sentinel/diff.py` | Phase 1 |
| 2.2 | Evaluator 扩展 `added_count` 规则类型 | 配合 Diff 使用 | 2.1 |
| 2.3 | 实现 Suppressor 全三层（+Dedup +Aggregation） | 告警抑制完善 | Phase 1 |
| 2.4 | 编写 Sentinel AI Prompt | `sentinel/prompts.py` | 无 |
| 2.5 | Alerter 集成 AI 分析（high/critical 调 LLM） | 智能告警 | 2.4 |
| 2.6 | 实现 Enrichment（单条告警上下文富化） | `sentinel/enrichment.py` | Phase 1 |
| 2.7 | Alerter 增加交互按钮（深入分析/忽略/加白） | Telegram InlineKeyboard | 2.5 |
| 2.8 | bot.py 新增告警交互回调处理 | 告警 → Agent 无缝衔接 | 2.7 |
| 2.9 | 用户自定义 Pack 加载 + 同名覆盖 | PackLoader 扩展 | Phase 1 |
| 2.10 | **里程碑**：高级别告警带 AI 分析 + 用户可交互 | 端到端测试 | 全部 |

---

### Phase 3：闭环运营 — 报告 + 持久化 + 命令

**前置条件**：Phase 2 完成。

```
改动文件:
  创建  controlplane/src/chatdome/sentinel/report.py
  修改  controlplane/src/chatdome/sentinel/scheduler.py    (+每日报告调度)
  修改  controlplane/src/chatdome/sentinel/alerter.py      (+持久化)
  修改  controlplane/src/chatdome/telegram/bot.py           (+/sentinel 命令族)
  修改  controlplane/src/chatdome/sentinel/suppressor.py   (+Cooldown 自动升级)
```

| # | 任务 | 产出 | 依赖 |
|---|------|------|------|
| 3.1 | 实现每日报告生成 | `sentinel/report.py` | Phase 2 |
| 3.2 | Scheduler 增加每日报告调度 | 定时 09:00 UTC 推送 | 3.1 |
| 3.3 | 告警事件持久化（JSONL / SQLite） | 历史查询能力 | Phase 2 |
| 3.4 | Cooldown 自动升级（同一告警反复触发 → 翻倍） | 抑制策略增强 | Phase 2 |
| 3.5 | 聚合窗口批量推送（10s 内多条告警合并推送） | 减少消息干扰 | 2.3 |
| 3.6 | AI 兜底模式（goal 字段 → AI 自行生成命令） | Pack 混合模式 | Phase 2 |
| 3.7 | `/sentinel` 命令族（status / trigger / packs / history） | bot.py 扩展 | 3.3 |
| 3.8 | **里程碑**：每日报告 + 历史查询 + 手动操控 | 端到端测试 | 全部 |

---

### Phase 4：威胁态势感知 — 信封 + 白名单 + 记忆

**前置条件**：Phase 3 完成。

```
改动文件:
  创建  controlplane/src/chatdome/sentinel/envelope.py
  创建  controlplane/src/chatdome/sentinel/whitelist.py
  创建  controlplane/src/chatdome/sentinel/memory_vault.py
  修改  controlplane/src/chatdome/sentinel/alerter.py       (+信封集成)
  修改  controlplane/src/chatdome/sentinel/scheduler.py     (+信封生命周期管理)
  修改  controlplane/src/chatdome/sentinel/prompts.py       (+叙事更新 Prompt +白名单解析 Prompt)
  修改  controlplane/src/chatdome/telegram/bot.py            (+态势面板 +白名单命令)
  修改  controlplane/src/chatdome/sentinel/pack_loader.py   (+ATT&CK tags 解析)
```

| # | 任务 | 产出 | 依赖 |
|---|------|------|------|
| 4.1 | Pack YAML 增加 ATT&CK 战术标签 | tags 字段扩展 | Phase 3 |
| 4.2 | 实现 ThreatEnvelope 数据结构 + 四态生命周期 | `sentinel/envelope.py` 核心 | 无 |
| 4.3 | 实现 extract_facets() 特征提取 | 零 token 维度提取 | 4.1 |
| 4.4 | 实现 match_score() + absorb_alert() | Counter 匹配 + 吸收 | 4.2 |
| 4.5 | 实现 IsolatedAlertBuffer + 聚类扫描 | 缓冲区 + ATT&CK 触发 | 4.3 |
| 4.6 | 实现 AI 叙事更新（update_narrative） | NARRATIVE_UPDATE_PROMPT | 4.4 |
| 4.7 | 实现动态 TTL + 休眠态 + 唤醒机制 | 四态完整流转 | 4.2 |
| 4.8 | 信封与告警流程集成（含休眠回退匹配） | alerter.py 重构 | 4.4-4.7 |
| 4.9 | 实现 `/sentinel status` 态势面板 | Telegram 展示 | 4.8 |
| 4.10 | 实现恢复通知 + 叙事归档 | 信封过期处理 | 4.7 |
| 4.11 | 实现 WhitelistManager | `sentinel/whitelist.py` | Phase 3 |
| 4.12 | 白名单自然语言解析 + 确认流程 | LLM 驱动规则生成 | 4.11 |
| 4.13 | 告警交互按钮增加"加白"选项 | 闭环白名单管理 | 4.11, 2.7 |
| 4.14 | 实现 SentinelMemoryVault | `sentinel/memory_vault.py` | Phase 3 |
| 4.15 | 首次启动主动问询 + 主机画像 | 记忆初始化 | 4.14 |
| 4.16 | AI 分析注入记忆上下文 | 降低误报率 | 4.14 |
| 4.17 | 信封过期 → 自动写入记忆库 | 闭环学习 | 4.10, 4.14 |
| 4.18 | **里程碑**：威胁信封 + 白名单 + 记忆 全功能可用 | 端到端测试 | 全部 |

---

## 6. 关键修改详解

### 6.1 config.py — 新增 SentinelConfig

```python
# 新增 dataclass
@dataclass
class SentinelConfig:
    enabled: bool = False
    alert_chat_ids: list[int] = field(default_factory=list)
    builtin_packs: list[str] = field(default_factory=lambda: [
        "ssh_auth", "network", "system_resources", "processes_services", "logs"
    ])
    custom_packs_dir: str = ""
    default_cooldown: int = 300
    max_cooldown: int = 1800
    aggregation_window: int = 10
    daily_report: bool = True
    daily_report_time: str = "09:00"
    ai_analysis_min_severity: str = "high"
    checks: list[dict] = field(default_factory=list)

# 修改 ChatDomeConfig
@dataclass
class ChatDomeConfig:
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    agent: AgentConfig = field(default_factory=AgentConfig)
    sentinel: SentinelConfig = field(default_factory=SentinelConfig)  # 新增
```

### 6.2 main.py — Sentinel 启动集成

```python
# 在 main() 函数中新增:

# 原有组件初始化后...

# Sentinel (可选)
sentinel = None
if config.sentinel.enabled:
    from chatdome.sentinel.pack_loader import PackLoader
    from chatdome.sentinel.scheduler import SentinelScheduler

    pack_loader = PackLoader(
        builtin_dir=Path(__file__).parent / "packs",
        custom_dir=Path(config.sentinel.custom_packs_dir) if config.sentinel.custom_packs_dir else None,
    )

    sentinel = SentinelScheduler(config.sentinel, pack_loader, sandbox, llm, bot)
```

### 6.3 executor/sandbox.py — 切换到 PackLoader

```python
# 旧代码:
from chatdome.executor.registry import render_command

# 新代码:
# render_command 不再从 registry 导入
# 而是通过构造函数注入 PackLoader 实例

class CommandSandbox:
    def __init__(self, ..., pack_loader=None):
        ...
        self._pack_loader = pack_loader  # 新增

    async def execute_security_check(self, check_id, args=None):
        # 旧: rendered = render_command(check_id, args)
        # 新:
        rendered = self._pack_loader.render_command(check_id, args)
        return await self._execute(rendered.command, timeout=rendered.timeout)
```

### 6.4 agent/prompts.py — 动态命令列表

```python
# 旧代码: 硬编码15条命令
SYSTEM_PROMPT = """...
可用的预定义命令 (check_id)：
- ssh_bruteforce: SSH 暴力破解检测
- ssh_success_login: SSH 成功登录记录
...
"""

# 新代码: 占位符 + 工厂函数
SYSTEM_PROMPT_TEMPLATE = """...
可用的预定义命令 (check_id)：
{available_checks}
"""

def build_system_prompt(pack_loader) -> str:
    checks = pack_loader.list_checks()
    lines = [f"- {c['check_id']}: {c['name']}" for c in checks]
    return SYSTEM_PROMPT_TEMPLATE.format(available_checks="\n".join(lines))

def build_tools(pack_loader) -> list[dict]:
    checks = pack_loader.list_checks()
    check_ids = ", ".join(c["check_id"] for c in checks)
    # 动态生成 TOOLS[0] 的 description
    ...
```

### 6.5 telegram/bot.py — 新增命令与推送

```python
# 新增的 Handler 注册:
self._app.add_handler(CommandHandler("sentinel", self._handle_sentinel))

# 新增命令处理:
async def _handle_sentinel(self, update, context):
    # /sentinel status  → 调用 envelope 态势面板
    # /sentinel trigger → 手动触发全量巡检
    # /sentinel packs   → 列出已加载的 Pack
    # /sentinel close <id> → 关闭指定信封
    ...

# Alerter 需要的推送方法:
async def send_alert(self, chat_id: int, text: str, buttons=None):
    """供 Sentinel Alerter 调用，推送告警到 Telegram"""
    ...
```

---

## 7. 文件变更汇总

| 操作 | 文件 | 阶段 |
|------|------|------|
| **删除** | `executor/registry.py` | P1 |
| **创建** | `packs/*.yaml` (8 文件) | P1 |
| **创建** | `sentinel/__init__.py` | P1 |
| **创建** | `sentinel/pack_loader.py` | P1 |
| **创建** | `sentinel/scheduler.py` | P1 |
| **创建** | `sentinel/checks.py` | P1 |
| **创建** | `sentinel/evaluator.py` | P1 |
| **创建** | `sentinel/alerter.py` | P1 (基础) → P2 (AI) → P4 (信封) |
| **创建** | `sentinel/suppressor.py` | P1 (Cooldown) → P2 (全三层) |
| **创建** | `sentinel/diff.py` | P2 |
| **创建** | `sentinel/enrichment.py` | P2 |
| **创建** | `sentinel/prompts.py` | P2 → P4 |
| **创建** | `sentinel/report.py` | P3 |
| **创建** | `sentinel/envelope.py` | P4 |
| **创建** | `sentinel/whitelist.py` | P4 |
| **创建** | `sentinel/memory_vault.py` | P4 |
| **修改** | `config.py` | P1 |
| **修改** | `main.py` | P1 |
| **修改** | `executor/sandbox.py` | P1 |
| **修改** | `agent/prompts.py` | P1 |
| **修改** | `agent/tools.py` | P1 |
| **修改** | `telegram/bot.py` | P2 → P3 → P4 |
| **修改** | `config.example.yaml` | P1 |

**代码量预估**：

| 阶段 | 新增行数 | 修改行数 | 删除行数 |
|------|---------|---------|---------|
| Phase 1 | ~900 | ~150 | ~210 |
| Phase 2 | ~550 | ~100 | 0 |
| Phase 3 | ~400 | ~80 | 0 |
| Phase 4 | ~1000 | ~120 | 0 |
| **合计** | **~2850** | **~450** | **~210** |

---

## 8. 风险与缓解

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| registry.py 删除后 Agent 对话失败 | 核心功能中断 | Phase 1 任务 1.5 设置验证点，确认 Agent 正常后再删除 |
| Pack YAML 格式不兼容 | 命令加载失败 | PackLoader 实现严格 schema 校验 + 详细错误提示 |
| Sentinel 调度器影响 Bot 主循环 | 消息延迟/卡死 | 所有检查命令异步执行，单独 try-except，不阻塞事件循环 |
| 动态 TTL 倍率过大导致信封堆积 | 内存泄漏 | MAX_ACTIVE_ENVELOPES = 10 硬上限 + 休眠态仅 ~200B/个 |
| AI 叙事更新失败 | 信封叙事停滞 | 索引层不依赖 AI，叙事更新失败不影响匹配和吸收 |
| SQLite 并发写入冲突 | 休眠/归档数据丢失 | 单进程架构天然无冲突；使用 WAL 模式兜底 |

---

## 9. 实施起点建议

**推荐从 Phase 1 任务 1.1 开始**：先编写 Pack YAML 文件。

原因：
1. Pack YAML 是无依赖的独立产出，可以并行设计和审查
2. 完成后可立即用于 PackLoader 开发和测试
3. 直观验证 15 个旧命令是否完整迁移
4. 即使后续方案调整，Pack YAML 作为命令定义库不受影响
