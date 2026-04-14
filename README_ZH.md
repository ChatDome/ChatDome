<p align="center">
  <h1 align="center">🛡️ ChatDome</h1>
  <p align="center">AI 驱动的主机安全助手，通过 Telegram 交付。</p>
  <p align="center">
    <a href="README.md">English</a> | <strong>中文</strong>
  </p>
  <p align="center">
    <a href="#功能特性">功能特性</a> •
    <a href="#快速开始">快速开始</a> •
    <a href="#配置">配置</a> •
    <a href="#工作原理">工作原理</a> •
    <a href="#安全模型">安全模型</a> •
    <a href="#路线图">路线图</a>
  </p>
</p>

---

## ChatDome 是什么？

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

## 功能特性

- **动态命令生成与交互确认机制** — 开启自由模式后，AI 可针对未预设的任意问题动态生成主机指令。这些生成的指令会先经过 AI Reviewer 进行安全与客观的影响评估，并在 Telegram 弹出交互卡片，强制要求你进行最终确认甚至强制放行（`/confirm`），实现最高级别的防破坏隔离。
- **自然语言交互** — 不用记命令，直接描述你想知道的。
- **AI Agent + 工具调用** — 多轮推理：AI 规划、执行主机命令、分析输出，循环迭代直到给出完整答案。
- **内置安全审计命令** — 预置 SSH 爆破检测、登录记录、开放端口、磁盘使用、可疑进程等检查项。
- **沙箱执行** — 所有命令在安全沙箱中执行，强制超时、输出截断、危险命令正则表达式拦截。
- **Telegram 原生** — 随时随地用手机管理服务器。
- **OpenAI 兼容** — 支持任何兼容 OpenAI Function Calling 格式的 LLM API（OpenAI、Claude、通过 LiteLLM 接入的本地模型等）。
- **上下文管理与长线记忆** — 内置轻量级的智能记忆库和上下文压缩引擎，能够记住历史排查重点与对话上下文，无需外挂数据库。
- **零基础设施，低侵入性** — 单个 Python 进程，无数据库，不在目标环境写入 Agent 文件，除 Telegram Bot Token 和 LLM API Key 外无任何外部依赖。

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
# 必需
export CHATDOME_BOT_TOKEN="your-telegram-bot-token"
export CHATDOME_AI_API_KEY="your-openai-api-key"

# 可选
export CHATDOME_ALLOWED_CHAT_IDS="123456789"     # Telegram Chat ID 访问控制
export CHATDOME_AI_BASE_URL="https://api.openai.com/v1"  # LLM API 地址
export CHATDOME_AI_MODEL="gpt-4o"                # LLM 模型名称
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
| `CHATDOME_ALLOW_GENERATED_COMMANDS` | ❌ | 全局一键开启“动态命令无限可能”模式 (`true`/`false`) |

> ⚠️ **安全提醒**：切勿将 Token 或 API Key 提交到版本控制。请使用环境变量、`.env` 文件（并添加到 `.gitignore`）或密钥管理器。

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
| `run_shell_command` | 执行只读 shell 命令（需开启） |
| `whois_lookup` | 查询 IP 地理位置和归属信息 |

### 内置安全检查项

| 检查 ID | 描述 |
|---------|------|
| `ssh_bruteforce` | SSH 暴力破解检测 |
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
| `/clear` | 清除对话上下文，重新开始 |
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
2. **预定义命令** — 默认情况下 AI 只能从预定义的只读审计命令中选择，命令模板运行时不可篡改。
3. **危险命令拦截** — 开启 `allow_generated_commands` 时，正则黑名单会拦截危险模式（`rm`、`dd`、`chmod`、`sudo`、shell 重定向等）。
4. **执行沙箱** — 所有命令强制超时、输出截断、禁止 shell 展开。
5. **禁止写操作** — AI 被指示永远不执行修改系统的命令，沙箱作为第二道防线强制执行。

> ⚠️ **建议**：以专用低权限用户运行 ChatDome，该用户对日志文件有读取权限但没有 sudo 权限。

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
            ├── telegram/
            │   ├── bot.py           # Telegram Bot 初始化 + 消息路由
            │   └── auth.py          # Chat ID 鉴权
            ├── agent/
            │   ├── core.py          # AI Agent ReAct 循环
            │   ├── tools.py         # 工具定义 + 分发
            │   ├── session.py       # 多轮会话管理
            │   └── prompts.py       # System Prompt 模板
            ├── executor/
            │   ├── sandbox.py       # 命令执行沙箱
            │   ├── registry.py      # 预定义命令注册表
            │   └── validator.py     # AI 生成命令安全校验
            └── llm/
                └── client.py        # OpenAI 兼容 API 客户端
```

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
