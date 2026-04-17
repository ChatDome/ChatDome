<p align="center">
  <h1 align="center">🛡️ ChatDome</h1>
  <p align="center">AI-powered host security assistant, delivered through Telegram.</p>
  <p align="center">
    <strong>English</strong> | <a href="README_ZH.md">中文</a>
  </p>
  <p align="center">
    <a href="#features">Features</a> •
    <a href="#what-pain-does-it-solve">Pain Points</a> •
    <a href="#why-sub-agent-instead-of-another-main-agent">Why Sub-Agent</a> •
    <a href="#quick-start">Quick Start</a> •
    <a href="#configuration">Configuration</a> •
    <a href="#how-it-works">How It Works</a> •
    <a href="#security">Security</a> •
    <a href="#roadmap">Roadmap</a>
  </p>
</p>

---

## What is ChatDome?

ChatDome is a **lightweight, fast, and low-intrusion** open-source, self-hosted **AI security agent** that lives directly in your Telegram. Designed specifically for individuals and small teams, it provides a zero-intrusion security layer without the need for bloated monitoring architectures.

Talk to it in plain language—it autonomously figures out what commands to run, utilizing either its built-in knowledge or **dynamically generating AI commands subjected to a strict safety validation and dual-confirmation (Human-in-the-loop) mechanism**. It executes these commands safely, analyzes the results, and reports back to you.

Think of it as a lightweight SOC analyst in your pocket, designed to be as friendly as possible for individual developers and small remote teams who manage Linux servers but don't have the budget or time for enterprise security tools.

```
You:     "Has anyone been brute-forcing my SSH?"
ChatDome: Ran ssh_bruteforce check...
          Found 3 IPs with >100 failed attempts in the last 24h:
          • 45.xx.xx.12  (Russia)  — 847 attempts
          • 103.xx.xx.5  (Vietnam) — 312 attempts
          • 91.xx.xx.88  (China)   — 156 attempts
          Recommendation: Consider banning these IPs via firewall.
```

## What Pain Does It Solve?

| Real pain | How ChatDome addresses it |
|-----------|---------------------------|
| No dedicated security engineer; unclear where to start | Ask in natural language, and let the agent choose investigation steps |
| Security tooling is too heavy for small teams | Single Python process, no database, no extra host agent |
| Fear of breaking production with ad-hoc commands | AI review, human confirmation, sandbox timeout and truncation controls |
| Alert fatigue makes continuous monitoring unsustainable | Sentinel roadmap focuses on suppression, aggregation, and long-term context |
| General-purpose AI can overreach in sensitive environments | ChatDome stays focused on host security with auditable, risk-aware workflows |

## Why Sub-Agent Instead of Another Main-Agent?

ChatDome is positioned as a **host-security sub-agent**, not a generic main-agent:

- **Coexists with main-agents**: main-agents orchestrate; ChatDome executes security-specialized workflows
- **Optimized for depth**: effort goes into risk control, approvals, evidence chain, and false-positive reduction
- **Open integration direction**: Telegram-first today, evolving toward standardized interfaces for external agent calls
- **Out-of-the-box value**: users get a usable security capability quickly, without building an entire automation stack first

## Features

- **LLM-First Risk Review** — Before execution, generated commands are classified with structured fields (`safety_status`, `risk_level`, `mutation_detected`, `deletion_detected`) and then escalated conservatively by static guardrails.
- **Runtime Environment Profiling** — At startup, ChatDome automatically collects OS/shell/command availability into `chat_data/environment_profile.md`, injects compatibility context into prompts, and exposes a quick `/env` summary in Telegram.
- **Tamper-Evident Command Audit** — Command review/approval/execution events are written to append-only hash-chained JSONL logs with automatic 30-day retention and Telegram-side inspection via `/audit [N]`.

- **Dynamic Command Generation & Dual-Confirmation** — When unlocked, the AI can dynamically generate commands to answer arbitrary questions. These commands are processed by an AI Reviewer for impact analysis and require explicit interactive confirmation (or a mandatory `/confirm` for high-risk actions) before execution.
- **Natural Language Interface** — No commands to memorize. Just describe what you want to know.
- **AI Agent with Tool Use** — Multi-turn reasoning: the AI plans, executes host commands, analyzes output, and iterates until it has a complete answer.
- **Built-in Security Audit Commands** — Pre-defined checks for SSH brute force, login history, open ports, disk usage, suspicious processes, and more.
- **Sandboxed Execution** — Commands run in a security sandbox with timeouts, output truncation, and dangerous command regex blocking.
- **Long-term Memory & Context Management** — Features an intelligent, automatic AI-compression memory vault. It remembers past alerts and server diagnostics across multiple sessions without blowing up token limits or requiring an external database.
- **Telegram-Native** — Manage your server from your phone, anywhere.
- **OpenAI-Compatible** — Works with any LLM API that supports the OpenAI function calling format (OpenAI, Claude, local models via LiteLLM, etc.).
- **Zero Infrastructure & Low Intrusion** — Single Python process, no database, no agent installation on target filespaces, requiring just a Telegram bot token and an LLM API key.
- **Sub-Agent Direction** — Evolving into a security module that main-agents can call, orchestrate, and audit.

### 🛡️ Sentinel — 7×24 Autonomous Guardian (Planned)

ChatDome is evolving beyond a reactive assistant into an **always-on security guardian**. The upcoming Sentinel module introduces proactive monitoring capabilities that set it apart from traditional host security tools:

- **Threat Envelope — Dual-Layer Situational Awareness** — A novel architecture that unifies attack chain correlation and threat state modeling into a single mechanism. The **index layer** (multi-dimensional Counter) performs zero-token set-intersection matching to determine if a new alert relates to an existing threat. The **narrative layer** (AI-generated natural language) dynamically evolves a compressed story of "what is actually happening." No preset attack patterns—ATT&CK tactical stage coverage triggers AI analysis only when genuinely needed.
- **Threat State as Compressed Narrative** — Instead of firing the same alert every 5 minutes during an ongoing attack, threats are modeled as living envelopes that absorb new evidence, auto-escalate severity on stage transitions, and push recovery notifications when the threat subsides.
- **Interactive Whitelist via Natural Language** — Tell ChatDome *"10.0.0.5 is my jump server, ignore its SSH logins"* in plain language. The AI parses your intent, generates a whitelist rule, asks for confirmation, and persists it. No config files to edit, no consoles to log into.
- **Sentinel Memory Vault** — A persistent, session-independent memory system. Sentinel proactively asks about your server's role, known services, and trusted IPs on first launch—then remembers everything to **prevent false alarms**. Every alert dismissal and whitelist action is learned automatically.

### 🔓 The "Infinite Possibilities" Mode

ChatDome ships with a robust set of predefined safety checks. However, **the true power of ChatDome is unleashed when you set `allow_generated_commands: true` in your config**.

When enabled, the AI is no longer bound by predefined rules. If you ask *"Show me the 3 largest files in `/var/log`"*, the LLM will dynamically generate the correct Linux shell commands (`du`, `sort`, `head`, etc.) from its vast knowledge base. 

Because we use the **Dual-Confirmation Mechanism**, granting the AI this "Infinite Power" remains safe and predictable: every dynamically generated command is individually vetted by a secondary AI Reviewer, providing you with a specific impact analysis and forcing an interactive human approval step in Telegram before anything touches your server's bash shell.

## Quick Start

### Prerequisites

- Python 3.9+
- A Linux server to monitor
- A [Telegram Bot Token](https://core.telegram.org/bots/tutorial)
- An OpenAI-compatible API key

### Install

First, clone the repository:
```bash
git clone https://github.com/your-username/ChatDome.git
cd ChatDome/controlplane
```

Choose one of the following installation methods:

#### Method A: Standard Install (Recommended for Servers)
Simply installs the required dependencies.
```bash
python3 -m pip install -r requirements.txt
```

#### Method B: Development Install (Editable Mode)
Installs dependencies as well as the globally accessible `chatdome` CLI command.
```bash
python3 -m pip install -e .
```

### Configure

All sensitive parameters are configured via **environment variables** — they are never stored in local files.

```bash
# Required
export CHATDOME_BOT_TOKEN="your-telegram-bot-token"
export CHATDOME_AI_API_KEY="your-openai-api-key"

# Optional
export CHATDOME_ALLOWED_CHAT_IDS="123456789"     # Telegram Chat IDs for access control
export CHATDOME_AI_BASE_URL="https://api.openai.com/v1"  # LLM API endpoint
export CHATDOME_AI_MODEL="gpt-4o"                # LLM model name
```

Non-sensitive settings (model, timeout, etc.) are in a YAML config file:

```bash
cp config.example.yaml config.yaml
# Edit config.yaml to tune non-sensitive parameters (optional)
```

### Run

Depending on your installation method, start ChatDome using one of the following commands:

**If you used Method A (Standard Install):**
```bash
python3 -m chatdome.main
```

**If you used Method B (Development Install):**
```bash
chatdome
```

Open Telegram, send your bot a message. Done.

### Find Your Telegram Chat ID

Send any message to your bot, then visit:
```
https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates
```
Look for `"chat":{"id": 123456789}` in the response.

## Configuration

### Environment Variables

All sensitive parameters are configured via environment variables. They are never read from config files.

**Telegram:**

| Variable | Required | Description |
|----------|----------|-------------|
| `CHATDOME_BOT_TOKEN` | ✅ | Telegram Bot token |
| `CHATDOME_ALLOWED_CHAT_IDS` | ❌ | Comma-separated Chat IDs for access control |

**LLM:**

| Variable | Required | Description |
|----------|----------|-------------|
| `CHATDOME_AI_API_KEY` | ✅ | OpenAI-compatible API key |
| `CHATDOME_AI_BASE_URL` | ❌ | API base URL (default: `https://api.openai.com/v1`) |
| `CHATDOME_AI_MODEL` | ❌ | Model name (default: `gpt-4o`) |

**General:**

| Variable | Required | Description |
|----------|----------|-------------|
| `CHATDOME_CONFIG` | ❌ | Path to config.yaml (default: `./config.yaml`) |
| `CHATDOME_ALLOW_GENERATED_COMMANDS` | ❌ | Enable Infinite Possibilities Mode (`true`/`false`) |
| `CHATDOME_ALLOW_UNRESTRICTED_COMMANDS` | ❌ | Enable God Mode (bypass ALL command validation:`true`/`false`) |

> ⚠️ **Security**: Never commit tokens or API keys to version control. Use environment variables, `.env` files (with `.gitignore`), or a secrets manager.

### Config File (Non-Sensitive / Optional)

`config.yaml` contains only non-sensitive tuning parameters:

```yaml
chatdome:
  telegram:
    max_message_length: 4000

  ai:
    model: "gpt-4o"
    temperature: 0.1
    max_tokens: 2000

  agent:
    allow_generated_commands: false           # true = AI can run arbitrary read-only commands
    session_timeout: 600                      # seconds of inactivity before session expires
    max_rounds_per_turn: 10                   # max tool calls per user message
    command_timeout: 10                       # seconds before a command is killed
    max_output_chars: 4000                    # truncate command output beyond this
```

## How It Works

```
User sends message via Telegram
         │
         ▼
┌─────────────────────┐
│   Auth (Chat ID)    │──── Unauthorized → ignore
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│   AI Agent Loop     │
│                     │
│  1. Send to LLM     │◄───────────┐
│  2. LLM responds    │            │
│     ├─ tool_call ───┤            │
│     │  Execute cmd  │            │
│     │  Collect output────────────┘
│     │               │  (feed result back to LLM)
│     └─ text ────────┤
│        Final answer │
└────────┬────────────┘
         │
         ▼
   Send reply to Telegram
```

The AI uses **function calling** (tool use) to interact with the host. It can:

| Tool | Description |
|------|-------------|
| `run_security_check` | Execute a pre-defined security audit command by ID |
| `run_shell_command` | Execute shell commands (read-only by default; maintenance write operations when `allow_unrestricted_commands=true`) |
| `whois_lookup` | Look up IP geolocation and ownership |

### Built-in Security Checks

| Check ID | Description |
|----------|-------------|
| `ssh_bruteforce` | Detect SSH brute force attempts |
| `ssh_success_login` | List successful SSH logins |
| `failed_sudo` | Show failed sudo attempts |
| `active_connections` | Current network connections |
| `open_ports` | Listening ports |
| `firewall_rules` | iptables / nft rules |
| `disk_usage` | Disk space usage |
| `memory_usage` | Memory usage |
| `system_load` | CPU load and top processes |
| `suspicious_processes` | High-CPU processes |
| `recent_cron_jobs` | Recent cron activity |
| `recent_syslog` | Recent system log entries |
| `kernel_errors` | Kernel error messages |
| `large_files` | Find large files |
| `last_reboot` | Reboot history |

## Telegram Commands

| Command | Description |
|---------|-------------|
| *(any message)* | Talk to the AI agent in natural language |
| `/confirm` | Force-approve and execute the current pending high-risk command |
| `/reject` | Reject the current pending command |
| `/clear` | Clear conversation context, start fresh |
| `/env` | Show runtime environment summary from `chat_data/environment_profile.md` |
| `/token` | Show token usage statistics for current chat |
| `/cmd_echo` | Toggle command echo mode in replies |
| `/audit [N]` | Show latest command audit events for current chat (default 10, max 30) |
| `/help` | Show usage guide and example questions |

No rigid command syntax — just talk to it.

### Example Questions

- "有没有人在爆破我的SSH？"
- "Show me the disk usage and any large files"
- "最近有没有异常的登录记录？"
- "What ports are listening on this server?"
- "检查一下系统负载，最近有没有异常进程"
- "Is my firewall configured correctly?"

## Security

ChatDome executes commands on your server — security is taken seriously:

1. **Telegram Auth** — Only messages from whitelisted Chat IDs are processed. All others are silently dropped.
2. **Safe-by-Default Mode** — By default, AI sticks to curated audit commands with immutable templates.
3. **Generated Command Review** — With `allow_generated_commands`, generated commands go through review and confirmation flow.
4. **Unrestricted Mode Warning** — `allow_unrestricted_commands` bypasses command validation; high-risk commands still go through explicit human confirmation and `/confirm` for critical actions.
5. **Execution Sandbox** — Command execution still has timeout and output-bound controls to reduce blast radius.

> ⚠️ **Recommendation**: Run ChatDome under a dedicated low-privilege user account that has read access to log files but no sudo privileges.

### Security Enhancements (2026-04)

- Risk review now outputs structured fields: `safety_status`, `risk_level`, `mutation_detected`, `deletion_detected`.
- Even in unrestricted mode, only clearly low-risk read-only commands auto-execute; mutation/deletion risk still requires human confirmation.
- Command review, approval, rejection, and execution are recorded in tamper-evident hash-chained audit logs.
- Audit logs are automatically rotated by day and retained for 30 days.
- Use `/audit [N]` in Telegram to inspect recent audit events for the current chat.

## Project Structure

```
ChatDome/
├── README.md
├── config.example.yaml
└── controlplane/
    ├── pyproject.toml
    └── src/
        └── chatdome/
            ├── main.py              # Entry point
            ├── config.py            # Configuration loader
            ├── telegram/
            │   ├── bot.py           # Telegram bot setup & message routing
            │   └── auth.py          # Chat ID authentication
            ├── agent/
            │   ├── core.py          # AI agent ReAct loop
            │   ├── tools.py         # Tool definitions & dispatch
            │   ├── session.py       # Multi-turn session management
            │   └── prompts.py       # System prompt templates
            ├── executor/
            │   ├── sandbox.py       # Command execution sandbox
            │   ├── registry.py      # Pre-defined command registry
            │   └── validator.py     # Generated command safety validator
            └── llm/
                └── client.py        # OpenAI-compatible API client
```

Additional implementation modules (current codebase):

- `controlplane/src/chatdome/runtime_environment.py` — startup environment profiling and prompt compatibility context
- `controlplane/src/chatdome/agent/audit.py` — command audit tracker (hash chain + 30-day retention)

## Roadmap

- [x] Architecture design
- [ ] **Phase 1 — MVP**: Telegram bot + AI agent + core security checks + sandbox
- [ ] **Phase 2 — Usable**: Multi-turn sessions, more checks, error handling, whois
- [ ] **Phase 3 — Polished**: Scheduled patrols, auto-alerts, session history
- [ ] **Phase 4 — Extensible**: Custom command plugins, multi-server, data plane integration
- [ ] **Phase 5 — Sentinel**: 7×24 proactive monitoring, threat envelope (dual-layer situational awareness), interactive whitelist, AI memory vault

## Contributing

Contributions are welcome! Please open an issue to discuss before submitting a PR.

## License

[Apache-2.0](LICENSE)
