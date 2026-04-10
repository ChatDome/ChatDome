# ChatDome 控制平面设计

> ⚠️ **开发优先级声明**
>
> 数据平面（Go TCP 代理 + 流量过滤）暂缓开发——实现难度高、短期收益低。
> **当前阶段全力聚焦控制平面**，目标是用最短的时间交付一个可独立运行的、有实际使用价值的产品：
> **Telegram Bot + AI Agent + 主机安全审计**。
>
> 数据平面将在控制平面验证可用性后，作为未来增强模块接入。

---

## 1. 产品定位

一个通过 Telegram 驱动的 AI 主机安全助手。用户用自然语言与 ChatDome 对话，AI 自主决定执行什么主机命令、分析执行结果、并以可读的方式回复。

**一句话描述**：把企业 SOC 的 AI Agent 能力装进一个 Telegram Bot 里，给个人和小团队用。

## 2. 核心能力

| 能力 | 描述 | 优先级 |
|------|------|--------|
| Telegram ChatOps | 通过 Telegram Bot 远程管理服务器 | P0 |
| AI Agent 多轮对话 | 自然语言 → AI 推理 → 执行命令 → 分析结果 → 多轮循环 | P0 |
| 预定义命令库 | 内置安全审计命令集（SSH 爆破检测、登录记录、磁盘/网络状态等） | P0 |
| 主机命令沙箱 | 安全地在主机上执行命令，防止 AI 执行危险操作 | P0 |
| 会话管理 | 多轮对话上下文保持、会话超时、token 控制 | P1 |
| 被动告警 | 定时巡检 + 异常推送 Telegram | P2 |
| 数据平面集成 | 通过 gRPC 对接未来的数据平面 | P3 (暂缓) |

## 3. 架构

### 3.1 整体架构（控制平面独立运行）

```
                     Telegram
                        |
                        v
+-----------------------------------------------+
|            ChatDome Control Plane              |
|                                                |
|  +-----------+    +-----------+                |
|  | Telegram  |--->| Session   |                |
|  | Handler   |    | Manager   |                |
|  +-----+-----+    +-----+-----+               |
|        |                |                      |
|        v                v                      |
|  +---------------------------+                 |
|  |       AI Agent Core       |                 |
|  |  (ReAct Loop + Tool Use)  |                 |
|  +------------+--------------+                 |
|               |                                |
|        +------+------+                         |
|        v             v                         |
|  +-----------+  +-----------+                  |
|  | Command   |  | LLM API   |                  |
|  | Executor  |  | Client    |                  |
|  | (Sandbox) |  | (OpenAI)  |                  |
|  +-----+-----+  +-----------+                  |
|        |                                       |
|        v                                       |
|  [Host OS: auth.log, ss, df, journalctl, ...]  |
+-----------------------------------------------+
```

### 3.2 模块职责

| 模块 | 职责 |
|------|------|
| **Telegram Handler** | 接收用户消息、鉴权（Chat ID 白名单）、消息分发、结果回传 |
| **Session Manager** | 管理多轮对话的上下文状态、超时清理、token 计数 |
| **AI Agent Core** | ReAct 循环：接收用户意图 → 调用 LLM → 解析 tool_calls → 执行 → 将结果回传 LLM → 循环直到 LLM 给出最终回答 |
| **Command Executor** | 安全沙箱，执行预定义命令或受限的 AI 生成命令，强制超时、输出截断 |
| **LLM API Client** | 封装 OpenAI 兼容 API 调用，支持 Function Calling / Tool Use |

## 4. AI Agent 设计

### 4.1 Agent 循环（ReAct Pattern）

```
用户消息
    │
    ▼
┌──────────────────────────────┐
│  构建 messages:              │
│  [system_prompt,             │
│   ...历史消息,               │
│   user_message]              │
│  + tools 定义                │
└──────────────┬───────────────┘
               │
               ▼
         ┌───────────┐
         │  调用 LLM  │◄──────────────────┐
         └─────┬─────┘                    │
               │                          │
          response                        │
               │                          │
        ┌──────┴──────┐                   │
        │ has tool_calls?                 │
        ├──Yes────────┤                   │
        │             │                   │
        │  执行 tool  │                   │
        │  收集结果   ├───────────────────┘
        │             │   (结果加入 messages, 继续循环)
        │             │
        ├──No─────────┤
        │             │
        │  最终回复   │
        │  发送给用户 │
        └─────────────┘
```

### 4.2 Tool 定义

AI 可调用的工具清单，通过 Function Calling 协议传给 LLM：

```python
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "run_security_check",
            "description": "执行预定义的主机安全审计命令。可用的 check_id 包括："
                           "ssh_bruteforce, ssh_success_login, active_connections, "
                           "disk_usage, memory_usage, suspicious_processes, "
                           "open_ports, recent_cron_jobs, failed_sudo, "
                           "large_files, last_reboot, firewall_rules ...",
            "parameters": {
                "type": "object",
                "properties": {
                    "check_id": {
                        "type": "string",
                        "description": "预定义命令的 ID"
                    },
                    "args": {
                        "type": "object",
                        "description": "命令参数，如 limit, time_range 等",
                        "additionalProperties": true
                    }
                },
                "required": ["check_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_shell_command",
            "description": "在主机上执行只读 shell 命令。仅当预定义命令无法满足需求时使用。"
                           "禁止执行写入、删除、修改类操作。",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "要执行的 shell 命令（只读）"
                    },
                    "reason": {
                        "type": "string",
                        "description": "执行此命令的理由"
                    }
                },
                "required": ["command", "reason"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "whois_lookup",
            "description": "查询 IP 地址的归属信息（地理位置、AS、运营商）",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": { "type": "string", "description": "要查询的 IP 地址" }
                },
                "required": ["ip"]
            }
        }
    }
]
```

### 4.3 预定义命令注册表

```python
COMMAND_REGISTRY = {
    # ── SSH / 认证 ──
    "ssh_bruteforce": {
        "name": "SSH 暴力破解检测",
        "template": "awk '/Failed password/ {{print $(NF-3)}}' /var/log/auth.log | sort | uniq -c | sort -nr | head -{limit}",
        "params": {"limit": {"type": "int", "default": 10, "max": 50}},
        "timeout": 10
    },
    "ssh_success_login": {
        "name": "SSH 成功登录记录",
        "template": "awk '/Accepted/ {{print $1, $2, $3, $9, $11}}' /var/log/auth.log | tail -{limit}",
        "params": {"limit": {"type": "int", "default": 20, "max": 100}},
        "timeout": 10
    },
    "failed_sudo": {
        "name": "sudo 失败记录",
        "template": "grep 'sudo:.*COMMAND' /var/log/auth.log | grep 'NOT' | tail -{limit}",
        "params": {"limit": {"type": "int", "default": 20, "max": 100}},
        "timeout": 10
    },

    # ── 网络 ──
    "active_connections": {
        "name": "当前活跃连接",
        "template": "ss -tunapl | head -{limit}",
        "params": {"limit": {"type": "int", "default": 30, "max": 100}},
        "timeout": 10
    },
    "open_ports": {
        "name": "监听端口",
        "template": "ss -tlnp",
        "params": {},
        "timeout": 10
    },
    "firewall_rules": {
        "name": "防火墙规则",
        "template": "iptables -L -n --line-numbers 2>/dev/null || nft list ruleset 2>/dev/null || echo 'No firewall detected'",
        "params": {},
        "timeout": 10
    },

    # ── 系统状态 ──
    "disk_usage": {
        "name": "磁盘使用",
        "template": "df -h",
        "params": {},
        "timeout": 10
    },
    "memory_usage": {
        "name": "内存使用",
        "template": "free -h",
        "params": {},
        "timeout": 10
    },
    "system_load": {
        "name": "系统负载",
        "template": "uptime; echo '---'; top -bn1 | head -20",
        "params": {},
        "timeout": 15
    },
    "last_reboot": {
        "name": "重启历史",
        "template": "last reboot | head -{limit}",
        "params": {"limit": {"type": "int", "default": 10, "max": 30}},
        "timeout": 10
    },

    # ── 进程 / 文件 ──
    "suspicious_processes": {
        "name": "可疑进程检测",
        "template": "ps aux --sort=-%cpu | head -{limit}",
        "params": {"limit": {"type": "int", "default": 20, "max": 50}},
        "timeout": 10
    },
    "recent_cron_jobs": {
        "name": "最近 cron 执行",
        "template": "journalctl -u cron --since '{since}' --no-pager | tail -{limit}",
        "params": {
            "since": {"type": "str", "default": "1 hour ago"},
            "limit": {"type": "int", "default": 30, "max": 100}
        },
        "timeout": 15
    },
    "large_files": {
        "name": "大文件检测",
        "template": "find / -xdev -type f -size +{min_size} 2>/dev/null | head -{limit}",
        "params": {
            "min_size": {"type": "str", "default": "100M"},
            "limit": {"type": "int", "default": 20, "max": 50}
        },
        "timeout": 30
    },

    # ── 日志 ──
    "recent_syslog": {
        "name": "最近系统日志",
        "template": "journalctl --since '{since}' --no-pager --priority={priority} | tail -{limit}",
        "params": {
            "since": {"type": "str", "default": "1 hour ago"},
            "priority": {"type": "str", "default": "warning"},
            "limit": {"type": "int", "default": 50, "max": 200}
        },
        "timeout": 15
    },
    "kernel_errors": {
        "name": "内核错误",
        "template": "dmesg --level=err,warn | tail -{limit}",
        "params": {"limit": {"type": "int", "default": 30, "max": 100}},
        "timeout": 10
    }
}
```

### 4.4 System Prompt

```
你是 ChatDome，一个 AI 驱动的主机安全助手。你通过 Telegram 与用户对话，
帮助用户诊断和分析 Linux 服务器的安全状况。

你的能力：
1. 执行预定义的安全审计命令（run_security_check）
2. 在必要时执行只读的 shell 命令（run_shell_command）
3. 查询 IP 归属信息（whois_lookup）

工作原则：
- 先使用预定义命令，只在预定义命令无法满足时才使用 run_shell_command
- 绝对不执行写入、删除、修改系统的命令
- 分析时给出具体的数据和建议，不要空泛
- 如果发现安全威胁，明确告知严重程度和建议措施
- 回复使用中文，简洁扼要，适合在手机上阅读
- 如果信息不足以判断，主动执行更多命令获取上下文，而不是猜测
```

## 5. 命令执行安全模型

### 5.1 三层防护

```
Layer 1: 预定义命令白名单
  │  AI 优先选择 run_security_check (check_id)
  │  参数通过 schema 验证，命令模板不可篡改
  │
  ▼ 当预定义命令不够用时
Layer 2: AI 生成命令审查 (run_shell_command)
  │  - 正则黑名单拦截危险命令（rm, dd, mkfs, chmod, mv, >, >>, |bash 等）
  │  - 仅允许只读命令（白名单可选：awk, grep, cat, head, tail, sort, uniq,
  │    wc, find, ls, ps, ss, netstat, journalctl, dmesg, df, free, uptime,
  │    last, who, id, uname, hostnamectl, ip, whois, dig, nslookup, curl -I）
  │  - 配置开关：allow_generated_commands (默认 false)
  │
  ▼ 所有命令执行
Layer 3: 沙箱强制约束
    - 超时：最长 30 秒，默认 10 秒
    - 输出截断：最大 4000 字符（Telegram 消息限制）
    - 无 shell 展开：使用 subprocess 的列表模式，不走 shell=True
    - 以当前用户权限执行，不 sudo（除非显式配置）
    - 资源限制：可选 cgroup / ulimit
```

### 5.2 危险命令黑名单

```python
DANGEROUS_PATTERNS = [
    r'\brm\b', r'\bdd\b', r'\bmkfs\b', r'\bformat\b',
    r'\bchmod\b', r'\bchown\b', r'\bchattr\b',
    r'\bmv\b', r'\bcp\b',                          # 写入类
    r'\bkill\b', r'\bkillall\b', r'\bpkill\b',     # 进程操控
    r'\breboot\b', r'\bshutdown\b', r'\bhalt\b',   # 系统控制
    r'\bsudo\b', r'\bsu\b',                         # 提权
    r'\bcurl\b(?!.*-I)', r'\bwget\b',               # 网络下载（curl -I 除外）
    r'\bpython\b', r'\bperl\b', r'\bruby\b', r'\bnode\b',  # 解释器
    r'>\s', r'>>', r'\|.*\bsh\b', r'\|.*\bbash\b',  # 重定向和管道到 shell
    r'\beval\b', r'\bexec\b', r'\bsource\b',        # 代码执行
    r'/etc/shadow', r'/etc/passwd',                  # 敏感文件直接读取
]
```

## 6. 会话管理与长时记忆 (Local Memory Vault)

ChatDome 采用“零基础架构”的轻量方式，在不依赖任何外部数据库的情况下，实现了健壮的上下文管理与断点跨端持久记忆。
class AgentSession:
    chat_id: int                     # Telegram Chat ID
    messages: list[dict]             # OpenAI 格式的消息历史
    created_at: float                # 创建时间戳
    last_active: float               # 最后活跃时间戳
    round_count: int                 # 当前 Agent 循环次数

    MAX_IDLE_SECONDS = 600           # 10 分钟无活动，会话过期
    MAX_ROUNDS_PER_TURN = 10         # 单次用户消息最多触发 10 轮工具调用
    MAX_HISTORY_TOKENS = 16000       # 上下文窗口限制（超出时截断早期消息）
    MAX_OUTPUT_CHARS = 4000          # 单条 Telegram 消息的输出上限
```

```

### 6.1 核心内存回收与压缩策略

1. **会话池与超时销毁（TTL Cleanup）**：
   通过 `SessionManager` 按 `Chat ID` 隔离管理。如果用户对话中断时间超过 `MAX_IDLE_SECONDS`（如 10 分钟），系统将自动从内存中移除该 `AgentSession` 以防内存泄漏。
2. **AI 本地化上下文智能压缩（Context Compression）**：
   对于超长对话，不再采取暴力的 `pop(1)` 抛弃旧对话，而是当 `messages` 容量逐渐逼近 `MAX_HISTORY_TOKENS` 时，系统会自动寻找安全锚点截断前半部分记录，向 LLM 提交一次后台异步提炼请求。最终这部分历史消息会被替换为一句由 AI 凝练的简短背景说明（System Context），既解决了 Token 越界爆炸问题，又保证了重点线索（IP、报错、排查结论）在下文持续有效。

### 6.2 本地长时记忆库 (Local Memory Vault)

为了让 ChatDome 实现“昨天解决过的警报今天依然有印象”，我们将记忆下沉于本地文件树：
- **原始交互流水账 (`chat_data/{chat_id}_raw.log`)**：记录 AI 和用户对话期间每一轮的 User Prompt、Tool Call Args 及 Sandbox Result，提供不可篡改的安全操作审计追踪源文件。
- **持久化精华案卷 (`chat_data/{chat_id}_memory.json`)**：当内存发生上文提到的“上下文压缩”时，生成的总结会被追加合并到本地文件中。
- **跨会话唤醒（RAG-like Injection）**：即使是因为内存闲置导致会话对象被清除，下一次用户重新发言触发实例化 `AgentSession` 时，系统也会读取并把这个 JSON 的精华记录塞入到对大模型的背景设定中，实现零 DB 负担的长线持久记忆。

### 6.3 会话生命周期状态机

```
用户发送任意消息
    │
    ├─ 读取本地 memory.json 注入背景（若有）
    │
    ├─ 已有活跃会话 → 追加消息到会话，继续 Agent 循环
    │
    └─ 无活跃会话 → 创建新会话
                    │
                    ├─ Agent 循环 → 记录 raw.log
                    │
                    ├─ 若达到临界值 → 触发上下文提炼压缩，并更新 memory.json
                    │
                    ├─ 用户 10 分钟未说话 → 内存自动过期销毁
                    │
                    └─ /clear → 手动清除会话与临时上下文
```

## 7. 配置

纯控制平面配置，不再包含数据平面相关字段：

```yaml
chatdome:
  telegram:
    bot_token: "${CHATDOME_BOT_TOKEN}"
    allowed_chat_ids:
      - 123456789
    # 消息限制
    max_message_length: 4000

  ai:
    base_url: "https://api.openai.com/v1"
    api_key: "${CHATDOME_AI_API_KEY}"
    model: "gpt-4o"
    temperature: 0.1
    max_tokens: 2000

  agent:
    # 是否允许 AI 生成非预定义命令
    allow_generated_commands: false
    # 会话配置
    session_timeout: 600
    max_rounds_per_turn: 10
    max_history_tokens: 16000
    # 命令执行
    command_timeout: 10
    max_output_chars: 4000

  # 被动巡检（P2，后续实现）
  patrol:
    enabled: false
    interval: 3600
    checks:
      - ssh_bruteforce
      - disk_usage
      - suspicious_processes
```

## 8. 仓库结构（控制平面优先）

```
ChatDome/
├── config.example.yaml               # 配置模板
├── README.md                          # 项目说明
├── controlplane/                      # 控制平面（Python）
│   ├── pyproject.toml                 # 项目配置 + 依赖
│   ├── src/
│   │   └── chatdome/
│   │       ├── __init__.py
│   │       ├── main.py                # 入口：加载配置，启动 Bot
│   │       ├── config.py              # YAML 配置加载 + 环境变量替换
│   │       ├── telegram/
│   │       │   ├── __init__.py
│   │       │   ├── bot.py             # Telegram Bot 初始化 + 消息路由
│   │       │   └── auth.py            # Chat ID 鉴权
│   │       ├── agent/
│   │       │   ├── __init__.py
│   │       │   ├── core.py            # Agent ReAct 循环
│   │       │   ├── tools.py           # Tool 定义 + 分发
│   │       │   ├── session.py         # 会话状态管理
│   │       │   └── prompts.py         # System Prompt 模板
│   │       ├── executor/
│   │       │   ├── __init__.py
│   │       │   ├── sandbox.py         # 命令沙箱（安全执行层）
│   │       │   ├── registry.py        # 预定义命令注册表
│   │       │   └── validator.py       # AI 生成命令的安全校验
│   │       └── llm/
│   │           ├── __init__.py
│   │           └── client.py          # OpenAI 兼容 API 客户端
│   └── tests/
│       ├── test_config.py
│       ├── test_agent.py
│       ├── test_sandbox.py
│       ├── test_registry.py
│       └── test_validator.py
├── docs/                              # 内部文档（不公开）
└── .gitignore
```

## 9. 技术栈

| 组件 | 选型 | 理由 |
|------|------|------|
| 语言 | Python 3.11+ | AI/Bot 生态最好 |
| Telegram SDK | python-telegram-bot (v20+) | 成熟、async、维护活跃 |
| LLM 调用 | openai (官方 SDK) | 标准 Function Calling 支持 |
| HTTP | httpx | openai SDK 的底层依赖，可复用做 whois 等 |
| 配置 | PyYAML | 简单够用 |
| 命令执行 | asyncio.subprocess | 原生 async，无额外依赖 |
| 打包 | pip / pipx | 轻量安装 |

## 10. Telegram 命令

| 命令 | 描述 |
|------|------|
| (直接发送自然语言) | 进入 AI Agent 对话，AI 自主决定做什么 |
| /clear | 清除当前对话上下文，开始新会话 |
| /help | 显示帮助信息和示例问题 |
| /config | 查看当前配置（脱敏） |

**设计决策**：不再设计 `/status`、`/ban` 等硬编码命令。所有功能通过自然语言驱动，由 AI Agent 决定调用什么工具。这是与传统 ChatOps Bot 的根本区别。

## 11. 实现分期

### Phase 1：能跑 (MVP)

- [ ] 项目脚手架（pyproject.toml, 目录结构）
- [ ] YAML 配置加载 + 环境变量替换
- [ ] Telegram Bot 基本框架（接收消息、鉴权）
- [ ] LLM API Client（OpenAI 兼容，支持 Function Calling）
- [ ] 预定义命令注册表（5 个核心命令）
- [ ] 命令沙箱（subprocess 执行 + 超时 + 输出截断）
- [ ] Agent 核心循环（单轮：用户消息 → LLM → tool_call → 执行 → LLM → 回复）
- [ ] 端到端测试：Telegram 发送"有没有人爆破我的SSH"→ 收到分析报告

### Phase 2：能用

- [ ] 多轮会话管理（上下文保持、超时清理）
- [ ] AI 生成命令的安全校验（可选开启）
- [ ] 扩充预定义命令到 15+ 个
- [ ] 长输出分页（Telegram 4096 字符限制处理）
- [ ] whois 查询工具
- [ ] 错误处理健壮化（API 超时、命令执行异常、Telegram 限流）

### Phase 3：能看

- [ ] 被动巡检 + 定时告警推送
- [ ] 巡检结果 AI 摘要
- [ ] 历史会话简要回顾
- [ ] /help 交互式引导

### Phase 4：能扩展

- [ ] 数据平面 gRPC 集成接口（预留）
- [ ] 插件化命令注册（用户自定义命令模板）
- [ ] 多用户/多服务器管理
