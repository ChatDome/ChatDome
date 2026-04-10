<p align="center">
  <h1 align="center">🛡️ ChatDome</h1>
  <p align="center">AI-powered host security assistant, delivered through Telegram.</p>
  <p align="center">
    <strong>English</strong> | <a href="README_ZH.md">中文</a>
  </p>
  <p align="center">
    <a href="#features">Features</a> •
    <a href="#quick-start">Quick Start</a> •
    <a href="#configuration">Configuration</a> •
    <a href="#how-it-works">How It Works</a> •
    <a href="#security">Security</a> •
    <a href="#roadmap">Roadmap</a>
  </p>
</p>

---

## What is ChatDome?

ChatDome is an open-source, self-hosted **AI security agent** that lives in your Telegram. Talk to it in plain language — it figures out what commands to run on your server, executes them safely, analyzes the results, and reports back.

Think of it as a lightweight SOC analyst in your pocket, designed for individuals and small teams who manage Linux servers but don't have the budget for enterprise security tools.

```
You:     "Has anyone been brute-forcing my SSH?"
ChatDome: Ran ssh_bruteforce check...
          Found 3 IPs with >100 failed attempts in the last 24h:
          • 45.xx.xx.12  (Russia)  — 847 attempts
          • 103.xx.xx.5  (Vietnam) — 312 attempts
          • 91.xx.xx.88  (China)   — 156 attempts
          Recommendation: Consider banning these IPs via firewall.
```

## Features

- **Natural Language Interface** — No commands to memorize. Just describe what you want to know.
- **AI Agent with Tool Use** — Multi-turn reasoning: the AI plans, executes host commands, analyzes output, and iterates until it has a complete answer.
- **Built-in Security Audit Commands** — Pre-defined checks for SSH brute force, login history, open ports, disk usage, suspicious processes, and more.
- **Sandboxed Execution** — Commands run in a security sandbox with timeouts, output truncation, and dangerous command blocking.
- **Telegram-Native** — Manage your server from your phone, anywhere.
- **OpenAI-Compatible** — Works with any LLM API that supports the OpenAI function calling format (OpenAI, Claude, local models via LiteLLM, etc.).
- **Zero Infrastructure** — Single Python process, no database, no external dependencies beyond a Telegram bot token and an LLM API key.

## Quick Start

### Prerequisites

- Python 3.9+
- A Linux server to monitor
- A [Telegram Bot Token](https://core.telegram.org/bots/tutorial)
- An OpenAI-compatible API key

### Install

```bash
# Clone
git clone https://github.com/your-username/ChatDome.git
cd ChatDome/controlplane

# Install dependencies
python3 -m pip install -r requirements.txt
```
*(Optional for development: `python3 -m pip install -e .` to install the `chatdome` CLI command)*

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

```bash
python3 -m chatdome.main
```
*(If you installed via editable mode, you can simply run `chatdome`)*

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
| `run_shell_command` | Execute a read-only shell command (when enabled) |
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
| `/clear` | Clear conversation context, start fresh |
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
2. **Pre-defined Commands** — By default, AI can only pick from a curated list of read-only audit commands. Templates are not user-modifiable at runtime.
3. **Dangerous Command Blocking** — When `allow_generated_commands` is enabled, a regex blacklist blocks destructive patterns (`rm`, `dd`, `chmod`, `sudo`, shell redirects, etc.).
4. **Execution Sandbox** — All commands run with enforced timeouts, output truncation, and no shell expansion.
5. **No Write Operations** — The AI is instructed to never execute commands that modify the system. The sandbox enforces this as a second layer.

> ⚠️ **Recommendation**: Run ChatDome under a dedicated low-privilege user account that has read access to log files but no sudo privileges.

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

## Roadmap

- [x] Architecture design
- [ ] **Phase 1 — MVP**: Telegram bot + AI agent + core security checks + sandbox
- [ ] **Phase 2 — Usable**: Multi-turn sessions, more checks, error handling, whois
- [ ] **Phase 3 — Polished**: Scheduled patrols, auto-alerts, session history
- [ ] **Phase 4 — Extensible**: Custom command plugins, multi-server, data plane integration

## Contributing

Contributions are welcome! Please open an issue to discuss before submitting a PR.

## License

[Apache-2.0](LICENSE)
