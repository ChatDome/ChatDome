<p align="center">
  <h1 align="center">🛡️ ChatDome</h1>
  <p align="center">AI 驱动的主机安全助手，通过 Telegram 交付。</p>
  <p align="center">
    <a href="README.md">English</a> | <strong>中文</strong>
  </p>
  <p align="center">
    <a href="#功能特性">功能特性</a> •
    <a href="#解决什么问题">解决什么问题</a> •
    <a href="#为什么是-sub-agent">为什么是 Sub-Agent</a> •
    <a href="#快速开始">快速开始</a> •
    <a href="#配置">配置</a> •
    <a href="#工作原理">工作原理</a> •
    <a href="#安全模型">安全模型</a> •
    <a href="#路线图">路线图</a>
  </p>
</p>

---

## ChatDome 是什么？

> 你想拥有一个“手机在手，就能随时掌握服务器安全状态”的安全助手吗？  
> ChatDome 的核心应用场景，就是把主机安全巡检、分析和处置建议放进你每天都在用的 Telegram 对话里。

ChatDome 是一个**轻便、快捷、低侵入性**的开源自托管 **AI 智能安全 Agent**，直接运行在你的 Telegram 中。专为个人开发者和小型团队设计，无需部署庞大的监控架构，零侵入式守护你的 Linux 服务器。

你只需用自然语言跟它对话——它会自动判断需要执行什么指令、自主调用内建命令库，或**动态生成 AI 命令并在严格的安全校验与二次交互确认（Human-in-the-loop）机制下执行**，最后分析结果并回复你。

可以把它理解为放在口袋里的轻量级 SOC 分析师，专为管理 Linux 服务器的个人用户和小团队设计——那些没有预算和精力去折腾企业级安全工具的人。

```
你:       "有没有人在爆破我的SSH？"
ChatDome:  已执行 ssh_bruteforce 检查...
           发现 3 个 IP 在过去 24 小时内尝试登录超过 100 次：
           • 45.xx.xx.12  (俄罗斯)  — 847 次
           • 103.xx.xx.5  (越南)    — 312 次
           • 91.xx.xx.88  (中国)    — 156 次
           建议：考虑通过防火墙封禁这些 IP。
```

## 解决什么问题？

以下是个人开发者和小型团队在主机安全实践中最常见的场景，以及 ChatDome 对应提供的能力：

| 典型运维/安全场景 | ChatDome 对应能力 |
|---------|-------------------|
| 缺少专职安全人员，排查路径不清晰 | 使用自然语言提问，Agent 自动规划检查步骤并给出结论 |
| 传统安全工具部署和维护成本较高 | 单 Python 进程，无数据库、无额外 Agent，配置后可直接运行 |
| 需要执行命令但担心误操作影响生产环境 | 审查 + 人工确认 + 沙箱超时/截断，降低高风险误执行概率 |
| 告警噪声较大，难以长期持续巡检 | Sentinel 路线聚焦告警抑制、威胁聚合和长期记忆 |
| 通用 Agent 在安全场景缺乏明确边界 | ChatDome 聚焦主机安全域，强调可控、可审计、可复盘 |

## 为什么是 Sub-Agent？

ChatDome 不打算做“另一个泛化 Main-Agent”，而是定位为 **主机安全 Sub-Agent**：

- **与 Main-Agent 共生**：Main-Agent 负责统一入口与跨域编排，ChatDome 负责安全领域的专业执行与结论
- **专业深度优先**：把能力投入在风险评估、审批流程、证据链、误报抑制，而不是无边界功能堆叠
- **接口开放可集成**：当前可直接 Telegram 使用，后续方向是对任意 Main-Agent 开放标准化调用接口
- **开箱即用**：用户不必先搭一套复杂自动化体系，几步配置就能得到可用的安全能力

## 功能特性

- **LLM 优先风险审查** — 动态命令在执行前会输出结构化风险字段（`safety_status`、`risk_level`、`mutation_detected`、`deletion_detected`），并由静态护栏进行保守升级。
- **运行环境画像** — 启动时自动采集 OS/Shell/命令可用性，写入 `chat_data/environment_profile.md`，并将兼容性上下文注入提示词；可通过 `/env` 快速查看摘要。
- **防篡改命令审计** — 命令审查、审批、执行事件写入哈希链 JSONL 审计日志（`prev_hash` + `event_hash`），默认保留 30 天；可通过 `/audit [N]` 快速查看最近记录。
- **动态命令生成与交互确认机制** — 开启自由模式后，AI 可针对未预设的任意问题动态生成主机指令。这些生成的指令会先经过 AI Reviewer 进行安全与客观的影响评估，并在 Telegram 弹出交互卡片，强制要求你进行最终确认甚至强制放行（`/confirm`），实现最高级别的防破坏隔离。
- **自然语言交互** — 不用记命令，直接描述你想知道的。
- **AI Agent + 工具调用** — 多轮推理：AI 规划、执行主机命令、分析输出，循环迭代直到给出完整答案。
- **内置安全审计命令** — 预置 SSH 爆破检测、登录记录、开放端口、磁盘使用、可疑进程等检查项。
- **沙箱执行** — 所有命令在安全沙箱中执行，强制超时、输出截断、危险命令正则表达式拦截。
- **Telegram 原生** — 随时随地用手机管理服务器。
- **OpenAI 兼容** — 支持任何兼容 OpenAI Function Calling 格式的 LLM API（OpenAI、Claude、通过 LiteLLM 接入的本地模型等）。
- **上下文管理与长线记忆** — 内置轻量级的智能记忆库和上下文压缩引擎，能够记住历史排查重点与对话上下文，无需外挂数据库。
- **零基础设施，低侵入性** — 单个 Python 进程，无数据库，不在目标环境写入 Agent 文件，除 Telegram Bot Token 和 LLM API Key 外无任何外部依赖。
- **Sub-Agent 化方向** — 正在沿“可被 Main-Agent 调用的专业安全能力模块”演进，强调可集成、可编排、可审计。

### 🛡️ Sentinel — 7×24 自主守卫（规划中）

ChatDome 正在从"被动应答式助手"进化为 **7×24 全天候主动安全守卫**。即将推出的 Sentinel 模块引入了区别于传统主机安全产品的核心能力：

- **威胁信封 — 双层态势感知架构** — 一种将攻击链关联与威胁状态建模统一为同一套机制的创新架构。**索引层**（多维 Counter 信封）以零 token 成本做集合交集匹配，判断新告警是否与现有威胁相关；**叙事层**（AI 生成的自然语言）动态演化出“到底发生了什么”的压缩叙事。不依赖预设攻击模式，而是通过 ATT&CK 战术阶段覆盖度来触发 AI 分析。
- **威胁状态即压缩叙事** — 不再在攻击持续期间每隔几分钟发一条重复告警，而是将威胁建模为“活的信封”——持续吸收新证据、在阶段跃迁时自动升级严重度、威胁消退后推送恢复通知。
- **自然语言交互式白名单** — 直接告诉 ChatDome："*10.0.0.5 是我的跳板机，忽略它的 SSH 登录*"，AI 自动理解意图、生成白名单规则、请求确认后持久化生效。不用改配置文件，不用登录控制台。
- **哨兵记忆库** — 独立于会话上下文的持久化记忆系统。Sentinel 首次启动时主动询问服务器用途、已知服务、可信 IP，此后 **永久记住** 这些信息以 **杜绝误报乌龙**。每次告警处置和白名单操作都会被自动学习。

### 🔓 “无限可能性”模式 (Infinite Possibilities Mode)

ChatDome 出厂内置了丰富且安全的内置审计命令库。然而，**当你将配置中的 `allow_generated_commands` 切换为 `true` 时，才算是真正解锁了 ChatDome 的终极形态**。

只要开启大模型的自由生成模式，AI 就不再局限于死板的预设模版。如果你要求：*“列出 /var/log 下最大的三个文件”*，大模型会调动自身庞大的 Linux 操作系统知识，自动想出最完美的组合命令（比如 `find` 结合 `sort` 和 `head`）。

正因为我们打造了**安全隔离与两级人工互交确认（Human-in-the-loop）**这条防线，你才可以放心地赋予 AI 这种“无限的权利”：哪怕是 AI 自己发明的查杀指令，也会在后台接受另外一个独立 AI 审查员的影响评估，然后以卡片的形式推送到你的 Telegram 取决你的最终态度。只有在你确认它是安全的查询指令并点击之后，服务器才会做相应的动作！

## 快速开始

### 前置要求

- Python 3.9+
- 一台 Linux 服务器
- [Telegram Bot Token](https://core.telegram.org/bots/tutorial)
- OpenAI 兼容的 API Key

### 安装

首先，克隆仓库：
```bash
git clone https://github.com/ChatDome/ChatDome.git
cd ChatDome/controlplane
```

请根据需要选择一种安装方式：

#### 方式 A：标准安装（推荐服务器使用）
仅安装运行所需的依赖。
```bash
python3 -m pip install -r requirements.txt
```

#### 方式 B：开发模式安装（Editable Mode）
不仅安装依赖，还会注册全局可用的 `chatdome` 命令行工具。
```bash
python3 -m pip install -e .
```

### 配置

所有敏感参数通过**环境变量**配置，不会存储在本地文件中。

```bash
# == 强烈建议：将以下配置写入 ~/.bashrc 或 ~/.zshrc 以便持久化生效 ==

# 必需
export CHATDOME_BOT_TOKEN="your-telegram-bot-token"
export CHATDOME_AI_API_KEY="your-openai-api-key"

# 可选
export CHATDOME_ALLOWED_CHAT_IDS="123456789"                # Telegram Chat ID 访问控制
export CHATDOME_AI_BASE_URL="https://api.openai.com/v1"     # LLM API 地址
export CHATDOME_AI_MODEL="gpt-4o"                           # LLM 模型名称
export CHATDOME_SENTINEL_ENABLED="true"                     # 开启 7×24 哨兵监控模式
export CHATDOME_ALLOW_GENERATED_COMMANDS="true"             # 允许 AI 自主生成并执行命令
export CHATDOME_ALLOW_UNRESTRICTED_COMMANDS="true"          # 开启完全开放权限模式（God Mode）
```

非敏感的调优参数在 YAML 配置文件中：

```bash
cp config.example.yaml config.yaml
# 可选：编辑 config.yaml 调整非敏感参数
```

### 运行

根据你选择的安装方式，使用以下对应的命令启动：

**如果使用 方式 A（标准安装）：**
```bash
python3 -m chatdome.main
```

**如果使用 方式 B（开发模式安装）：**
```bash
chatdome
```

打开 Telegram，给你的 Bot 发一条消息，搞定。

### 获取你的 Telegram Chat ID

给你的 Bot 发送任意消息，然后访问：
```
https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates
```
在返回结果中找到 `"chat":{"id": 123456789}`。

## 配置

### 环境变量

所有敏感参数通过环境变量配置，不会从配置文件中读取。

**Telegram：**

| 变量名 | 必需 | 说明 |
|--------|------|------|
| `CHATDOME_BOT_TOKEN` | ✅ | Telegram Bot Token |
| `CHATDOME_ALLOWED_CHAT_IDS` | ❌ | 逗号分隔的 Chat ID，用于访问控制 |

**LLM：**

| 变量名 | 必需 | 说明 |
|--------|------|------|
| `CHATDOME_AI_API_KEY` | ✅ | OpenAI 兼容的 API Key |
| `CHATDOME_AI_BASE_URL` | ❌ | API 地址（默认: `https://api.openai.com/v1`） |
| `CHATDOME_AI_MODEL` | ❌ | 模型名称（默认: `gpt-4o`） |

**通用：**

| 变量名 | 必需 | 说明 |
|--------|------|------|
| `CHATDOME_CONFIG` | ❌ | 配置文件路径（默认: `./config.yaml`） |
| `CHATDOME_SENTINEL_ENABLED` | ❌ | 开启 7×24 Sentinel 哨兵主动监控模式 (`true`/`false`) |
| `CHATDOME_ALLOW_GENERATED_COMMANDS` | ❌ | 全局一键开启“动态命令无限可能”模式 (`true`/`false`) |
| `CHATDOME_ALLOW_UNRESTRICTED_COMMANDS` | ❌ | 开启 God Mode（绕过所有命令验证）(`true`/`false`) |

> ⚠️ **安全提醒**：切勿将 Token 或 API Key 提交到版本控制。请使用环境变量、`.env` 文件（并添加到 `.gitignore`）或密钥管理器。

### 🎛️ 核心能力控制开关（进阶）

除了基础的 Token 配置外，ChatDome 提供了三个改变核心运行逻辑的进阶能力开关。在使用进阶功能前，强烈建议你了解它们的作用。它们**默认全为关闭状态**，如需开启，请在环境变量中传递 `"true"`：

#### 1. 哨兵主动监控模式 (`CHATDOME_SENTINEL_ENABLED`)
- **功能说明**：将 ChatDome 从“被动的一问一答助手”升级为“7x24 小时主动巡更的哨兵”。它会在后台静默定期执行系统安全审计，并通过独创的双层态势感知架构对告警进行降噪聚合。
- **推荐场景**：希望完全不需要主动询问，就能在异常发生的第一时间在 Telegram 被动收到精炼警报通知的所有运维人员。

#### 2. 无限可能模式 (`CHATDOME_ALLOW_GENERATED_COMMANDS`)
- **功能说明**：解除“仅允许执行出厂预装官方只读命令”的绝对严格限制！开启后，你用自然语言下达的任何复杂、模糊查阅要求，AI 都会结合自带的 Linux 知识库，为你实时现场推敲编写出全新的 Shell 组合查询命令。
- **内置安全机制**：不用担心 AI 误操，所有的现场动态生成命令依然会受限于“只读读取”规则，任何危险动作都会被沙箱立刻拦截报错。

#### 3. 上帝越狱模式 (`CHATDOME_ALLOW_UNRESTRICTED_COMMANDS`)
- **功能说明**：**【危险！上帝权限】**开启此项后，沙箱的“仅限只读审查”原生封印将被彻底解除。此时，AI 能够针对诸如“帮我清理所有的冗余日志文件”、“直接在防火墙里封禁那个攻击我的恶劣黑客IP”等运维要求，直接下达具备破坏性质的操作指令（允许执行类似 `rm`、`iptables` 等写操作）。
- **内置安全机制**：所有被独立分析模块判定为具备高危风险（包含写入、删除、高风险状态变更）的越狱命令，绝不会擅自执行！而是会在执行的最后一刻暂停，并通过卡片推送到你的 Telegram 进行高亮风险警报（即 **Human-in-the-loop** 防线），只有你亲自端详命令无误，点击同意按钮或发送 `/confirm` 后，大模型才会最终扣动扳机。

### 配置文件（非敏感参数）

`config.yaml` 仅包含非敏感的调优参数：

```yaml
chatdome:
  telegram:
    max_message_length: 4000

  ai:
    model: "gpt-4o"
    temperature: 0.1
    max_tokens: 2000

  agent:
    allow_generated_commands: false           # true = 允许 AI 执行非预定义的只读命令
    allow_unrestricted_commands: false        # true = 绕过所有命令验证（极高风险）
    session_timeout: 600                      # 会话空闲超时（秒）
    max_rounds_per_turn: 10                   # 单次消息最多触发的工具调用轮数
    command_timeout: 10                       # 命令执行超时（秒）
    max_output_chars: 4000                    # 命令输出超过此长度会被截断
```

## 工作原理

```
用户通过 Telegram 发送消息
         │
         ▼
┌─────────────────────┐
│  鉴权 (Chat ID)     │──── 未授权 → 忽略
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│   AI Agent 循环     │
│                     │
│  1. 发送给 LLM      │◄───────────┐
│  2. LLM 响应        │            │
│     ├─ tool_call ───┤            │
│     │  执行命令      │            │
│     │  收集输出 ─────────────────┘
│     │               │  (将结果回传 LLM)
│     └─ 文本 ────────┤
│        最终回答      │
└────────┬────────────┘
         │
         ▼
   发送回复到 Telegram
```

AI 通过 **Function Calling**（工具调用）与主机交互，可用工具：

| 工具 | 描述 |
|------|------|
| `run_security_check` | 按 ID 执行预定义的安全审计命令 |
| `run_shell_command` | 执行 shell 命令（默认只读；`allow_unrestricted_commands=true` 时可执行运维写操作） |
| `whois_lookup` | 查询 IP 地理位置和归属信息 |

### 内置安全检查项

| 检查 ID | 描述 |
|---------|------|
| `ssh_bruteforce` | SSH 新访问来源检测 |
| `ssh_success_login` | SSH 成功登录记录 |
| `failed_sudo` | sudo 失败记录 |
| `active_connections` | 当前活跃连接 |
| `open_ports` | 监听端口 |
| `firewall_rules` | 防火墙规则 |
| `disk_usage` | 磁盘使用 |
| `memory_usage` | 内存使用 |
| `system_load` | 系统负载 |
| `suspicious_processes` | 可疑进程（高 CPU） |
| `recent_cron_jobs` | 最近 cron 执行 |
| `recent_syslog` | 最近系统日志 |
| `kernel_errors` | 内核错误 |
| `large_files` | 大文件检测 |
| `last_reboot` | 重启历史 |

## Telegram 命令

| 命令 | 描述 |
|------|------|
| *(直接发送消息)* | 用自然语言与 AI Agent 对话 |
| `/confirm` | 强制批准并执行当前待确认的高风险命令 |
| `/reject` | 拒绝当前待确认命令 |
| `/clear` | 清除对话上下文，重新开始 |
| `/env` | 查看当前运行环境摘要（来自 `chat_data/environment_profile.md`） |
| `/token` | 查看当前会话 Token 消耗统计 |
| `/cmd_echo` | 切换底层命令回显模式 |
| `/audit [N]` | 查看当前会话最近 N 条命令审计事件（默认 10，最大 30） |
| `/help` | 显示使用帮助和示例问题 |

没有死板的命令格式——直接说话就行。

### 示例问题

- "有没有人在爆破我的 SSH？"
- "磁盘空间还够吗？有没有特别大的文件？"
- "最近有没有异常的登录记录？"
- "服务器上哪些端口在监听？"
- "检查一下系统负载，最近有没有异常进程"
- "我的防火墙配置有没有问题？"

## 安全模型

ChatDome 在你的服务器上执行命令——安全是第一优先级：

1. **Telegram 鉴权** — 仅处理白名单 Chat ID 的消息，其他一律静默忽略。
2. **默认最小权限** — 默认情况下 AI 仅使用预定义审计命令；模板运行时不可篡改。
3. **生成命令审查** — 开启 `allow_generated_commands` 后，命令会经过审查 + 风险确认流程。
4. **Unrestricted 模式强告警** — 开启 `allow_unrestricted_commands` 后会绕过命令验证，高危命令仍会进入人工确认/强制 `/confirm` 流程。
5. **执行沙箱** — 所有命令强制超时、输出截断，降低误操作影响面。

> ⚠️ **建议**：以专用低权限用户运行 ChatDome，该用户对日志文件有读取权限但没有 sudo 权限。

### 安全增强（2026-04）

- 风险审查输出结构化字段：`safety_status`、`risk_level`、`mutation_detected`、`deletion_detected`。
- 即使开启 unrestricted 模式，也仅低风险只读命令可自动执行；涉及修改/删除风险的命令仍需人工确认。
- 命令“审查 → 审批 → 执行”全链路事件写入可校验审计日志。
- 审计日志按天分桶，默认自动保留 30 天。
- 可通过 `/audit [N]` 在 Telegram 直接查看最近审计事件。

## 项目结构

```
ChatDome/
├── README.md
├── README_ZH.md
├── config.example.yaml
└── controlplane/
    ├── pyproject.toml
    └── src/
        └── chatdome/
            ├── main.py              # 入口
            ├── config.py            # 配置加载
            ├── runtime_environment.py # 运行环境采集与兼容上下文
            ├── telegram/
            │   ├── bot.py           # Telegram Bot 初始化 + 消息路由
            │   └── auth.py          # Chat ID 鉴权
            ├── agent/
            │   ├── core.py          # AI Agent ReAct 循环
            │   ├── tools.py         # 工具定义 + 分发
            │   ├── session.py       # 多轮会话管理
            │   ├── audit.py         # 命令审计追踪器（哈希链 + 30天保留）
            │   └── prompts.py       # System Prompt 模板
            ├── executor/
            │   ├── sandbox.py       # 命令执行沙箱
            │   ├── registry.py      # 预定义命令注册表
            │   └── validator.py     # AI 生成命令安全校验
            └── llm/
                └── client.py        # OpenAI 兼容 API 客户端
```

当前代码新增模块（实现对齐）：

- `controlplane/src/chatdome/runtime_environment.py` — 启动时采集运行环境并注入命令兼容上下文
- `controlplane/src/chatdome/agent/audit.py` — 命令审计追踪器（哈希链 + 30 天保留）

## 路线图

- [x] 架构设计
- [ ] **Phase 1 — MVP**：Telegram Bot + AI Agent + 核心安全检查项 + 沙箱
- [ ] **Phase 2 — 可用**：多轮会话、更多检查项、错误处理、whois
- [ ] **Phase 3 — 完善**：定时巡检、自动告警、会话历史
- [ ] **Phase 4 — 可扩展**：自定义命令插件、多服务器管理、数据平面集成
- [ ] **Phase 5 — Sentinel**：7×24 主动监控、威胁信封（双层态势感知）、交互式白名单、AI 记忆库

## 贡献

欢迎贡献！提交 PR 前请先开一个 Issue 讨论。

## 许可证

[Apache-2.0](LICENSE)
