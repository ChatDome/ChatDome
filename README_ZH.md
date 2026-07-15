<p align="center">
  <h1 align="center">🛡️ ChatDome</h1>
  <p align="center">AI 驱动的主机安全助手，通过 Telegram 交付。</p>
  <p align="center">
    <a href="README.md">English</a> | <strong>中文</strong>
  </p>
  <p align="center">
    <a href="https://github.com/ChatDome/ChatDome/actions/workflows/tests.yml"><img alt="Tests" src="https://github.com/ChatDome/ChatDome/actions/workflows/tests.yml/badge.svg"></a>
    <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg"></a>
    <img alt="Python" src="https://img.shields.io/badge/python-3.9%2B-blue.svg">
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
- **运行环境画像** — 启动时自动采集 OS/Shell/命令可用性，写入 `/var/lib/chatdome/environment/profile.md`（systemd 安装），并将兼容性上下文注入提示词；可通过 `/env` 快速查看摘要。
- **防篡改命令审计** — 命令审查、审批、执行事件写入哈希链 JSONL 审计日志（`prev_hash` + `event_hash`），默认保留 30 天；可通过 `/audit [N]` 快速查看最近记录。
- **动态命令生成与交互确认机制** — 开启自由模式后，AI 可针对未预设的任意问题动态生成主机指令。这些生成的指令会先经过 AI Reviewer 进行安全与客观的影响评估，并在 Telegram 弹出交互卡片，强制要求你进行最终确认甚至强制放行（`/confirm`），实现最高级别的防破坏隔离。
- **自然语言交互** — 不用记命令，直接描述你想知道的。
- **AI Agent + 工具调用** — 多轮推理：AI 规划、执行主机命令、分析输出，循环迭代直到给出完整答案。
- **内置安全审计命令** — 预置 SSH 爆破检测、登录记录、开放端口、磁盘使用、可疑进程等检查项。
- **沙箱执行** — 所有命令在安全沙箱中执行，强制超时、输出截断、危险命令正则表达式拦截。
- **Telegram 原生** — 随时随地用手机管理服务器。
- **多 LLM Profile** — 默认支持 Codex OAuth Responses API，也可切换到 OpenAI-compatible API（OpenAI、DeepSeek、LiteLLM 网关等）。
- **上下文管理与长线记忆** — 内置轻量级的智能记忆库和上下文压缩引擎，能够记住历史排查重点与对话上下文，无需外挂数据库。
- **零基础设施，低侵入性** — 单个 Python 进程，无数据库，不在目标环境写入 Agent 文件；Codex 默认通过 `/codex_login` 完成 OAuth，API Key 仅在启用 OpenAI-compatible profile 时需要。
- **Sub-Agent 化方向** — 正在沿“可被 Main-Agent 调用的专业安全能力模块”演进，强调可集成、可编排、可审计。

### 🛡️ Sentinel — 7×24 自主守卫（基础能力已实现，高级能力演进中）

ChatDome 正在从"被动应答式助手"进化为 **7×24 全天候主动安全守卫**。当前版本已包含 Command Pack、定时巡检、规则评估、告警历史、Telegram 推送，以及通过自然语言或 `/sentinel_mute` / `/sentinel_resume` 控制告警静默与恢复的能力；下面这些能力属于 Sentinel 的高级演进方向：

- **威胁信封 — 双层态势感知架构** — 一种将攻击链关联与威胁状态建模统一为同一套机制的创新架构。**索引层**（多维 Counter 信封）以零 token 成本做集合交集匹配，判断新告警是否与现有威胁相关；**叙事层**（AI 生成的自然语言）动态演化出“到底发生了什么”的压缩叙事。不依赖预设攻击模式，而是通过 ATT&CK 战术阶段覆盖度来触发 AI 分析。
- **威胁状态即压缩叙事** — 不再在攻击持续期间每隔几分钟发一条重复告警，而是将威胁建模为“活的信封”——只在新威胁首次出现和威胁升级时主动推送，恢复、观察和归档状态仅写入历史。
- **自然语言交互式白名单** — 直接告诉 ChatDome："*10.0.0.5 是我的跳板机，忽略它的 SSH 登录*"，AI 自动理解意图、生成白名单规则、请求确认后持久化生效。不用改配置文件，不用登录控制台。
- **哨兵记忆库** — 独立于会话上下文的持久化记忆系统。Sentinel 首次启动时主动询问服务器用途、已知服务、可信 IP，此后 **永久记住** 这些信息以 **杜绝误报乌龙**。每次告警处置和白名单操作都会被自动学习。

### 🔓 “无限可能性”模式 (Infinite Possibilities Mode)

ChatDome 出厂内置了丰富且安全的内置审计命令库。在当前默认配置中，`allow_generated_commands` 为 `true`，这让 ChatDome 可以根据你的自然语言问题生成临场查询命令；如果你希望采用最保守模式，可以将它改为 `false`，让 AI 仅使用预定义审计命令。

只要开启大模型的自由生成模式，AI 就不再局限于死板的预设模版。如果你要求：*“列出 /var/log 下最大的三个文件”*，大模型会调动自身庞大的 Linux 操作系统知识，自动想出最完美的组合命令（比如 `find` 结合 `sort` 和 `head`）。

正因为我们打造了**安全隔离与两级人工互交确认（Human-in-the-loop）**这条防线，你才可以放心地赋予 AI 这种“无限的权利”：哪怕是 AI 自己发明的查杀指令，也会在后台接受另外一个独立 AI 审查员的影响评估，然后以卡片的形式推送到你的 Telegram 取决你的最终态度。只有在你确认它是安全的查询指令并点击之后，服务器才会做相应的动作！

## 快速开始

### 前置要求

- Python 3.9+
- 一台 Linux 服务器
- [Telegram Bot Token](https://core.telegram.org/bots/tutorial)
- Codex OAuth 账号（默认 profile）或 OpenAI-compatible API Key（切换到 API-key profile 时）

### 安装

请根据需要选择一种安装方式：

#### 方式 A：一键安装（推荐）
```bash
cd / && curl -fsSL https://raw.githubusercontent.com/ChatDome/ChatDome/main/install.sh \
  -o /tmp/chatdome-install.sh && sudo bash /tmp/chatdome-install.sh
```

使用 wget：
```bash
cd / && wget -qO /tmp/chatdome-install.sh \
  https://raw.githubusercontent.com/ChatDome/ChatDome/main/install.sh && \
  sudo bash /tmp/chatdome-install.sh
```

预览安装动作：
```bash
cd / && curl -fsSL https://raw.githubusercontent.com/ChatDome/ChatDome/main/install.sh \
  -o /tmp/chatdome-install.sh && bash /tmp/chatdome-install.sh --dry-run
```

自定义安装目录：
```bash
sudo env CHATDOME_INSTALL_DIR=/srv/chatdome \
  bash /tmp/chatdome-install.sh
```

默认下载到 `/opt/chatdome`。安装后配置位于 `/etc/chatdome/config.yaml`，日志位于 `/var/log/chatdome`，运行数据位于 `/var/lib/chatdome`，运行状态位于 `/run/chatdome`。详见 `ChatDome-docs/docs/02-system-design/chatdome-runtime-files-zh.md`。
缺少依赖时，安装脚本会根据包管理器生成安装命令并等待确认，支持 `apt-get`、`dnf`、`yum`、`pacman` 和 `zypper`。安装脚本会注册 systemd 服务并设置开机自启；未传入 `--start` 时不会立即启动服务。完成配置后，运行 `chatdome` 并选择 `Start service`，或执行 `sudo systemctl start chatdome`。

#### 方式 B：本地仓库安装
```bash
git clone https://github.com/ChatDome/ChatDome.git
cd ChatDome
sudo bash install.sh
```

#### 方式 C：开发模式安装（Editable Mode）
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ./controlplane
```

开发模式将源码以 editable 方式安装到当前虚拟环境，修改 Python 源码后无需重新安装。它不会注册 systemd 服务，也不会创建 `/etc/chatdome`、`/var/lib/chatdome` 或 `chatdome` 系统命令，适用于本地开发和测试；服务器常驻运行请使用方式 A 或 B。

### 配置

服务器安装将运行配置写入 `/etc/chatdome/config.yaml`；源码开发仍使用本地 `config.yaml`。该文件会包含 Telegram Bot Token 和 API-key profile 凭据，已被 `.gitignore` 忽略；Linux 部署时建议保持 `chmod 600`。新建 Codex OAuth profile 默认使用 `~/.chatdome/codex-auth/` 下的独立 token 文件；旧配置中的空 token 路径仍兼容 `~/.chatdome/auth.json`。

```bash
cp config.example.yaml config.yaml
chmod 600 config.yaml
# 编辑 config.yaml：填写 chatdome.telegram.bot_token、allowed_chat_ids 和需要的 api_key
```

也可以直接运行仓库根目录的交互式菜单：

```bash
./chatdome
```

默认未配置任何大模型（`active_ai_profile` 为空）。可通过本地菜单配置 profile。`System Maintenance` → `Update ChatDome` 会校验官方远端、精确拉取 `main`，commit 相同时直接结束，否则覆盖代码、在固定版本路径构建并校验 Python 环境、不移动 venv、仅保留当前和上一环境，并重启检查应用就绪状态；失败时恢复旧 commit。

### 运行

根据你选择的安装方式，使用以下对应的命令启动：

**如果使用方式 A 或 B：**
```bash
sudo systemctl start chatdome
```

**如果使用方式 C（开发模式安装，并已激活 `.venv`）：**
```bash
chatdome-server --config config.yaml
```

如果使用一键安装脚本，安装后运行 `chatdome` 会进入本地管理菜单，服务由 systemd 使用 `/etc/chatdome/config.yaml` 启动。

打开 Telegram，给你的 Bot 发一条消息，搞定。

### 获取你的 Telegram Chat ID

给你的 Bot 发送任意消息，然后访问：
```
https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates
```
在返回结果中找到 `"chat":{"id": 123456789}`。

## 配置

### config.yaml 单文件配置

ChatDome 采用单文件运行配置。服务器安装使用 `/etc/chatdome/config.yaml`，源码开发默认使用仓库内 `config.yaml`。Telegram Bot Token、允许访问的 Chat IDs、OpenAI-compatible API Key、Sentinel 和 Agent 策略均写入该文件。

默认初始安装时不包含任何 API Key 或预设档案。最简单的起步方式是运行 `./chatdome` → `AI model management` → `Add Codex OAuth LLM`；ChatDome 会触发 OAuth Device Code 登录，并在 token 保存成功后写入 profile。

默认值按 `config.example.yaml` 列出；复制模板后不修改时，对应值会直接作为运行配置生效。

| 配置路径 | 配置要求 | 默认值（模板） | 说明 |
|----------|----------|----------------|------|
| `chatdome.telegram.bot_token` | 必填 | `""`；启动前填写 | Telegram Bot Token |
| `chatdome.telegram.allowed_chat_ids` | 可选 | `[]`；不限制普通访问 | 允许访问的 Chat ID 列表 |
| `chatdome.telegram.admin_chat_ids` | 可选 | `[]`；使用 `allowed_chat_ids` | 允许管理 LLM profile 的私聊管理员；两者均为空时禁用远程 LLM 管理 |
| `chatdome.telegram.proxy_url` | 可选 | `""`；不使用代理 | Telegram Bot API 代理地址 |
| `chatdome.active_ai_profile` | 配置 LLM 后必填 | `""`；未选择 profile | 当前启用的 LLM profile 名称 |
| `chatdome.ai_profiles` | 配置 LLM 后必填 | `{}`；未配置 profile | LLM profile 集合，可通过本地菜单写入 |
| `chatdome.ai_profiles.<name>.api_key` | 取决于 profile | `""`；OpenAI-compatible profile 未认证 | OpenAI-compatible profile 的 API Key，直接写入本地 `config.yaml` |
| `chatdome.sentinel.enabled` | 可选 | `true` | 开启 7×24 Sentinel 哨兵主动监控模式 |
| `chatdome.agent.allow_generated_commands` | 可选 | `true` | 允许 AI 自主生成命令 |
| `chatdome.agent.allow_unrestricted_commands` | 可选 | `true` | 开启 unrestricted 模式 |

> ⚠️ **安全提醒**：切勿将 `config.yaml` 提交到版本控制。远程 LLM 管理仅允许 `admin_chat_ids` 中的私聊管理员使用；`admin_chat_ids` 为空时使用 `allowed_chat_ids`。API Key 消息会在保存配置前删除。

### 🎛️ 核心能力控制开关（进阶）

除了基础的 Token 配置外，ChatDome 提供了三个改变核心运行逻辑的进阶能力开关。在使用进阶功能前，强烈建议你了解它们的作用。当前随仓库提供的默认配置（`config.example.yaml`）中，Sentinel 与动态命令执行默认开启；如需保守部署，请在 `config.yaml` 中显式设置对应选项为 `false`：

#### 1. 哨兵主动监控模式 (`chatdome.sentinel.enabled`)
- **功能说明**：将 ChatDome 从“被动的一问一答助手”升级为“7x24 小时主动巡更的哨兵”。它会在后台静默定期执行系统安全审计，并通过独创的双层态势感知架构对告警进行降噪聚合。
- **推荐场景**：希望完全不需要主动询问，就能在异常发生的第一时间在 Telegram 被动收到精炼警报通知的所有运维人员。

#### 2. 无限可能模式 (`chatdome.agent.allow_generated_commands`)
- **功能说明**：解除“仅允许执行出厂预装官方命令”的严格限制。开启后，你用自然语言下达的复杂、模糊查阅要求，AI 会结合 Linux 知识生成新的 Shell 组合查询命令。
- **内置安全机制**：动态命令会先经过静态审查和审批流程；当 unrestricted 模式关闭时，还会经过只读 allowlist/blocklist 校验。

#### 3. 上帝越狱模式 (`chatdome.agent.allow_unrestricted_commands`)
- **功能说明**：**【危险！上帝权限】**开启此项后，沙箱会绕过确定性的命令校验器，不再使用只读 allowlist/blocklist 作为硬边界。
- **内置安全机制**：ToolDispatcher 仍会做执行前审查；静态安全、无写入/删除信号的命令可能自动执行，高风险、写入或删除命令会进入 Telegram 审批流，需要按钮确认或显式 `/confirm`。这仍是高风险模式，生产环境应谨慎开启。

### 配置文件示例

```yaml
chatdome:
  telegram:
    bot_token: "123456:ABC..."
    allowed_chat_ids: [123456789]
    admin_chat_ids: []
    proxy_url: ""
    max_message_length: 4000

  # 默认安装时这里为空。Codex OAuth 授权成功后会写入下方配置
  active_ai_profile: "codex"

  ai_profiles:
    codex:
      provider: "codex"
      api_mode: "codex_responses"
      model: "gpt-5.5"
      temperature: 0.1
      max_tokens: 2000
      codex_token_file: "~/.chatdome/codex-auth/codex.json"
      codex_base_url: "https://chatgpt.com/backend-api/codex"

    my-openai-profile:
      provider: "openai"
      api_mode: "openai_api"
      base_url: "https://api.openai.com/v1"
      model: "gpt-4o"
      temperature: 0.1
      max_tokens: 2000
      api_key: "sk-..."                    # 直接写入本地 config.yaml

  agent:
    allow_generated_commands: true            # true = 允许 AI 生成临场命令
    allow_unrestricted_commands: true         # true = 绕过确定性命令校验器（极高风险）
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
| `run_shell_command` | 执行 shell 命令（当前默认允许生成命令并开启 unrestricted 模式；高风险/写入/删除命令进入审批流） |
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

## 终端对话

运行：

```bash
chatdome hello
```

`chatdome hello` 启动可编辑的终端会话，支持历史记录、slash 补全和 Agent 输出保护。非 TTY 输入使用普通 stdin/stdout。普通输入提示符默认为 `› `，ChatDome 回复以输出块展示。设置 `CHATDOME_PROMPT` 可替换或隐藏普通输入提示符。使用 `chatdome hello --quiet` 或 `CHATDOME_COMPACT=1` 可启用单行启动页。审批首屏会说明本次命令的目的，不展开完整命令。审批初始提示为 `approve [y/n/d]>`，查看详情后切换为 `approve [y/n]>`，暂停提示为 `continue [y/n]>`。运行中按 `Ctrl+C` 会中止当前任务并保留 CLI；空闲时按 `Ctrl+C` 会退出 CLI。任务中止行为见 `ChatDome-docs/docs/03-module-specs/chatdome-task-control-design-zh.md`。

| 命令 | 描述 |
|------|------|
| `/help` | 查看终端命令 |
| `/clear` | 清除对话上下文 |
| `/stop` | 中止当前任务 |
| `/env` | 查看当前运行环境摘要 |
| `/token` | 查看当前终端会话 Token 消耗统计 |
| `/cmd_echo` | 切换底层命令回显模式 |
| `/audit [N]` | 查看最近的命令审计事件 |
| `/engram [delete <id>]` | 查看或删除持久记忆 |
| `/model [profile]` | 查看或切换 model profile |
| `/model_list` | 查看已配置 model profile 与鉴权状态 |
| `/model_add` | 新增 OpenAI-compatible 或 Codex model profile |
| `/model_delete <profile>` | 删除未启用的 model profile |
| `/model_cancel` | 取消当前 model 操作 |
| `/codex_login [profile]` | 启动 Codex OAuth 设备码认证 |
| `/details [approval_id] [full]` | 查看待审批动作详情 |
| `/confirm [approval_id]` | 批准待审批命令 |
| `/reject [approval_id]` | 拒绝待审批命令或停止暂停任务 |
| `/continue` | 继续暂停中的任务 |
| `/sentinel_status` | 查看 Sentinel 状态 |
| `/sentinel_trigger` | 运行全部 Sentinel 检查 |
| `/sentinel_history` | 查看最近 Sentinel 告警 |
| `/sentinel_packs` | 查看已加载 Sentinel Command Pack |
| `/sentinel_mute [duration]` | 暂停 Sentinel 告警推送 |
| `/sentinel_resume` | 恢复 Sentinel 告警推送 |
| `/exit` | 退出终端会话；`/quit` 为别名 |

CLI 与 Telegram 加载同一命令目录并调用同一业务服务。每个已注册命令都会规范化为 `CommandResult`，转换为统一 `OutboundMessage`，再由平台 Renderer 输出。`/model*`、`/codex_login` 和 `/env` 分别使用共享模型命令服务、OAuth 流程和环境 Facts Builder。`/exit` 与 `/quit` 只用于关闭本地终端进程。
## Telegram 命令

| 命令 | 描述 |
|------|------|
| *(直接发送消息)* | 用自然语言与 AI Agent 对话 |
| `/help` | 显示命令帮助 |
| `/clear` | 清除对话上下文 |
| `/stop` | 中止当前任务 |
| `/env` | 查看当前运行环境摘要 |
| `/token` | 查看当前会话 Token 消耗统计 |
| `/cmd_echo` | 切换底层命令回显模式 |
| `/audit [N]` | 查看最近 N 条命令审计事件 |
| `/engram [delete <id>]` | 查看或删除持久记忆 |
| `/model [profile]` | 查看 profile；管理员可切换当前 model |
| `/model_list` | 查看已配置 model profile 与鉴权状态 |
| `/model_add` | 管理员新增或覆盖 model profile |
| `/model_delete <profile>` | 管理员删除未启用的 model profile |
| `/model_cancel` | 取消当前 model 管理流程 |
| `/codex_login [profile]` | 启动 Codex OAuth 设备码认证 |
| `/details [approval_id] [full]` | 查看待审批命令分析 |
| `/confirm [approval_id]` | 批准待审批命令 |
| `/reject [approval_id]` | 拒绝待审批命令或放弃暂停任务 |
| `/continue` | 继续暂停中的任务 |
| `/sentinel_status` | 查看 Sentinel 状态 |
| `/sentinel_trigger` | 运行全部 Sentinel 检查 |
| `/sentinel_history` | 查看最近 Sentinel 告警 |
| `/sentinel_packs` | 查看已加载 Sentinel Command Pack |
| `/sentinel_mute [duration]` | 暂停 Sentinel 告警推送 |
| `/sentinel_resume` | 恢复 Sentinel 告警推送 |

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
2. **预定义命令优先** — 预定义审计命令模板运行时不可篡改；如需最小权限模式，可关闭 `allow_generated_commands` 与 `allow_unrestricted_commands`。
3. **生成命令审查** — 开启 `allow_generated_commands` 后，命令会经过审查与风险确认流程。
4. **Unrestricted 模式强告警** — 开启 `allow_unrestricted_commands` 后会绕过确定性命令校验器，高危命令仍会进入人工确认/强制 `/confirm` 流程。
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
                ├── client.py          # OpenAI-compatible API 客户端
                ├── codex_auth.py      # Codex OAuth Device Code 登录与 token 生命周期
                ├── codex_responses.py # Codex Responses API 适配器
                └── manager.py         # 多 LLM profile 管理与运行时切换
```

当前代码新增模块（实现对齐）：

- `controlplane/src/chatdome/runtime_environment.py` — 启动时采集运行环境并注入命令兼容上下文
- `controlplane/src/chatdome/agent/audit.py` — 命令审计追踪器（哈希链 + 30 天保留）
- `controlplane/src/chatdome/llm/codex_auth.py` 与 `codex_responses.py` — Codex OAuth 传输与 Responses API 直连
- `controlplane/src/chatdome/llm/codex_oauth_service.py` — 统一 Codex profile 解析、设备授权、令牌交换与持久化
- `controlplane/src/chatdome/model_commands.py` — 统一 `/model*` 业务服务
- `controlplane/src/chatdome/outbound/` — 统一出站消息契约、Builder、Policy 与平台 Renderer

## 路线图

- [x] 架构设计
- [ ] **Phase 1 — MVP**：Telegram Bot + AI Agent + 核心安全检查项 + 沙箱
- [ ] **Phase 2 — 可用**：多轮会话、更多检查项、错误处理、whois
- [ ] **Phase 3 — 完善**：定时巡检、自动告警、会话历史
- [ ] **Phase 4 — 可扩展**：自定义命令插件、多服务器管理、数据平面集成
- [x] **Sentinel 基础能力**：Command Pack、定时巡检、规则评估、告警历史、Telegram 推送、运行时告警静默/恢复
- [ ] **Sentinel 高级能力**：威胁信封（双层态势感知）、交互式白名单、AI 记忆库

## 贡献

提交 PR 前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。安全问题按 [SECURITY.md](SECURITY.md) 报告，不要提交公开 issue。

## 许可证

[Apache-2.0](LICENSE)
