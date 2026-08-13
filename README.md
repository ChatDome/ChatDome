<p align="center">
  <h1 align="center">🛡️ ChatDome</h1>
  <p align="center">AI-powered host security assistant, delivered through Telegram.</p>
  <p align="center">
    <strong>English</strong> | <a href="README_ZH.md">中文</a>
  </p>
  <p align="center">
    <a href="https://github.com/ChatDome/ChatDome/actions/workflows/tests.yml"><img alt="Tests" src="https://github.com/ChatDome/ChatDome/actions/workflows/tests.yml/badge.svg"></a>
    <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg"></a>
    <img alt="Python" src="https://img.shields.io/badge/python-3.9%2B-blue.svg">
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
- **Runtime Environment Profiling** — At startup, ChatDome automatically collects OS/shell/command availability into `/var/lib/chatdome/environment/profile.md` for system installations, injects compatibility context into prompts, and exposes a quick `/env` summary in Telegram.
- **Tamper-Evident Command Audit** — Command review/approval/execution events are written to append-only hash-chained JSONL logs with automatic 30-day retention and Telegram-side inspection via `/audit [N]`.

- **Dynamic Command Generation & Dual-Confirmation** — When unlocked, the AI can dynamically generate commands to answer arbitrary questions. These commands are processed by an AI Reviewer for impact analysis and require explicit interactive confirmation (or a mandatory `/confirm` for high-risk actions) before execution.
- **Natural Language Interface** — No commands to memorize. Just describe what you want to know.
- **AI Agent with Tool Use** — Multi-turn reasoning: the AI plans, executes host commands, analyzes output, and iterates until it has a complete answer.
- **Built-in Security Audit Commands** — Pre-defined checks for SSH brute force, login history, open ports, disk usage, suspicious processes, and more.
- **Sandboxed Execution** — Commands run in a security sandbox with timeouts, output truncation, and dangerous command regex blocking.
- **Long-term Memory & Context Management** — Features an intelligent, automatic AI-compression memory vault. It remembers past alerts and server diagnostics across multiple sessions without blowing up token limits or requiring an external database.
- **Telegram-Native** — Manage your server from your phone, anywhere.
- **Multi-LLM Profiles** — Supports Codex OAuth Responses API by default, with OpenAI-compatible API profiles available for OpenAI, DeepSeek, LiteLLM gateways, and similar endpoints.
- **Zero Infrastructure & Low Intrusion** — Single Python process, no database, no agent installation on target filespaces; Codex uses `/codex_login` OAuth by default, and API keys are only needed for API-key profiles.
- **Sub-Agent Direction** — Evolving into a security module that main-agents can call, orchestrate, and audit.

### 🛡️ Sentinel — 7×24 Autonomous Guardian (Core Implemented, Advanced Capabilities Evolving)

ChatDome is evolving beyond a reactive assistant into an **always-on security guardian**. The current codebase already includes Command Packs, scheduled patrols, rule evaluation, alert history, Telegram push notifications, and runtime alert mute/resume controls via natural language or `/sentinel_mute` / `/sentinel_resume`; the following capabilities describe Sentinel's advanced roadmap:

- **Threat Envelope — Dual-Layer Situational Awareness** — A novel architecture that unifies attack chain correlation and threat state modeling into a single mechanism. The **index layer** (multi-dimensional Counter) performs zero-token set-intersection matching to determine if a new alert relates to an existing threat. The **narrative layer** (AI-generated natural language) dynamically evolves a compressed story of "what is actually happening." No preset attack patterns—ATT&CK tactical stage coverage triggers AI analysis only when genuinely needed.
- **Threat State as Compressed Narrative** — Instead of firing the same alert every 5 minutes during an ongoing attack, threats are modeled as living envelopes that only push first-seen and escalation transitions; recovery, observation, and archival states are recorded in history without Telegram push.
- **Interactive Whitelist via Natural Language** — Tell ChatDome *"10.0.0.5 is my jump server, ignore its SSH logins"* in plain language. The AI parses your intent, generates a whitelist rule, asks for confirmation, and persists it. No config files to edit, no consoles to log into.
- **Sentinel Memory Vault** — A persistent, session-independent memory system. Sentinel proactively asks about your server's role, known services, and trusted IPs on first launch—then remembers everything to **prevent false alarms**. Every alert dismissal and whitelist action is learned automatically.

### 🔐 Command Approval Modes

ChatDome generates shell commands for explicit user requests. The required `chatdome.agent.command_approval_mode` setting controls whether those commands run immediately or wait for approval.

The default `require_approval_for_risky_commands` mode auto-runs only commands that the local deterministic rules clearly identify as low-risk. Risky or indeterminate commands wait for approval. Command-detail analysis is available on demand and does not decide whether approval is required.

## Quick Start

### Prerequisites

- Python 3.9+
- A Linux server to monitor
- Optional: a [Telegram Bot Token](https://core.telegram.org/bots/tutorial) for remote access and alerts
- Optional: a Codex OAuth account or OpenAI-compatible API key for AI chat

The core service and Sentinel can run without Telegram or an LLM. Telegram without an LLM still delivers Sentinel alerts and deterministic management commands. An LLM without Telegram remains available through the local CLI.

### Install

Choose one of the following installation methods:

#### Method A: One-Line Install (Recommended)
```bash
cd / && curl -fsSL https://raw.githubusercontent.com/ChatDome/ChatDome/main/install.sh \
  -o /tmp/chatdome-install.sh && sudo bash /tmp/chatdome-install.sh
```

Or with wget:
```bash
cd / && wget -qO /tmp/chatdome-install.sh \
  https://raw.githubusercontent.com/ChatDome/ChatDome/main/install.sh && \
  sudo bash /tmp/chatdome-install.sh
```

Preview before running:
```bash
cd / && curl -fsSL https://raw.githubusercontent.com/ChatDome/ChatDome/main/install.sh \
  -o /tmp/chatdome-install.sh && bash /tmp/chatdome-install.sh --dry-run
```

Customize installation paths:
```bash
sudo env CHATDOME_INSTALL_DIR=/srv/chatdome \
  bash /tmp/chatdome-install.sh
```

The installer downloads ChatDome to `/opt/chatdome` by default. It uses `/etc/chatdome/config.yaml` for configuration, `/var/log/chatdome` for logs, `/var/lib/chatdome` for runtime data, and `/run/chatdome` for runtime state. See `ChatDome-docs/docs/02-system-design/chatdome-runtime-files-zh.md`.
It prompts before installing missing dependencies with the detected package manager (`apt-get`, `dnf`, `yum`, `pacman`, or `zypper`). It registers the systemd service and enables it at boot, but does not start it unless `--start` is passed. After configuration, run `chatdome` and select `Start service`, or run `sudo systemctl start chatdome`.

#### Method B: Local Repository Install
```bash
git clone https://github.com/ChatDome/ChatDome.git
cd ChatDome
sudo bash install.sh
```

#### Method C: Development Install (Editable Mode)
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ./controlplane
```

Development mode installs the source tree into the active virtual environment in editable mode, so Python source changes do not require reinstallation. It does not register a systemd service, create `/etc/chatdome` or `/var/lib/chatdome`, or install the system-wide `chatdome` command. Use it for local development and testing; use Method A or B for a persistent server deployment.

### Configure

Server installations store runtime settings in `/etc/chatdome/config.yaml`; source development uses local `config.yaml`. This file contains Telegram Bot tokens and API-key profile credentials, is ignored by Git, and should be kept owner-readable only (`chmod 600` on Linux). New Codex OAuth profiles use profile-scoped token files under `~/.chatdome/codex-auth/`; legacy empty token paths still resolve to `~/.chatdome/auth.json`.

```bash
cp config.example.yaml config.yaml
chmod 600 config.yaml
# Edit config.yaml: set optional Telegram user IDs and model profiles as needed
```

You can also use the interactive local menu from the repository root:

```bash
./chatdome
```

By default, no LLM profile is configured (`active_ai_profile` is empty). Use the local menu to configure a profile. `System Maintenance` → `Update ChatDome` backs up and migrates the production configuration, validates the candidate runtime, and restores the previous code, environment, service unit, and configuration if any update step fails.

### Run

Depending on your installation method, start ChatDome using one of the following commands:

**If you used Method A or B:**
```bash
sudo systemctl start chatdome
```

**If you used Method C (Development Install, with `.venv` activated):**
```bash
chatdome-server --config config.yaml
```

When installed with `install.sh`, the `chatdome` command opens the local management menu, and the systemd service runs with `/etc/chatdome/config.yaml`.

Open Telegram, send your bot a message. Done.

### Find Your Telegram User ID

Send any message to your bot, then visit:
```
https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates
```
Look for `"from":{"id": 123456789}` in the private-message update. Store that value in `allowed_ids` or `admin_ids`.

## Configuration

### Single-File `config.yaml`

ChatDome uses one runtime configuration file. Server installations use `/etc/chatdome/config.yaml`; source development defaults to repository-local `config.yaml`. Sentinel check definitions are packaged with ChatDome and are not user configuration.

The default installation comes with no API keys or pre-configured profiles. The easiest way to get started is `./chatdome` → `AI model management` → `Add Codex OAuth LLM`. ChatDome starts the OAuth Device Code login and writes the profile only after the token is saved.

Defaults below come from `config.example.yaml`; if copied unchanged, those values become the runtime configuration.

| Path | Requirement | Default (template) | Description |
|------|-------------|--------------------|-------------|
| `chatdome.telegram.bot_token` | Optional | `""`; Telegram disabled | Telegram Bot token |
| `chatdome.telegram.allowed_ids` | Optional | `[]`; denies all non-admin users | Allowed private Telegram User IDs |
| `chatdome.telegram.admin_ids` | Optional | `[]`; no administrators | Administrator User IDs; administrators inherit ordinary access |
| `chatdome.telegram.proxy_url` | Optional | `""`; no proxy | Telegram Bot API proxy URL |
| `chatdome.active_ai_profile` | Required after LLM setup | `""`; no profile selected | Active LLM profile name |
| `chatdome.ai_profiles` | Required after LLM setup | `{}`; no profiles configured | LLM profile map, usually written by the local menu |
| `chatdome.ai_profiles.<name>.api_key` | Profile-dependent | `""`; OpenAI-compatible profile is not authenticated | OpenAI-compatible profile API key, stored directly in local `config.yaml` |
| `chatdome.sentinel.enabled` | Optional | `true` | Enable 7x24 Sentinel proactive monitoring |
| `chatdome.sentinel.alert_targets.telegram.user_ids` | Optional | omitted; uses `allowed_ids ∪ admin_ids` | Telegram Sentinel recipients; explicit `[]` disables Telegram alert delivery |
| `chatdome.agent.command_approval_mode` | Required | `require_approval_for_risky_commands` | Approval policy for AI-generated `run_shell_command` calls |

> ⚠️ **Security**: Never commit `config.yaml` to version control. Telegram accepts private chats only. Empty `allowed_ids` and `admin_ids` deny every inbound Telegram request.

### 🎛️ Core Capability Controls

Sentinel scheduling and command approval are configured independently:

#### 1. Sentinel Proactive Monitoring Mode (`chatdome.sentinel.enabled`)
- **What it does**: Upgrades ChatDome from a "passive Q&A assistant" to a "7x24 proactive patrolling sentinel". It quietly performs periodic system security audits in the background and employs an innovative dual-layer situational awareness architecture to aggregate and denoise alerts.
- **Recommended for**: Administrators who want to receive refined, proactive alert notifications on Telegram the moment an anomaly occurs, without needing to ask manually.

#### 2. Command Approval Policy (`chatdome.agent.command_approval_mode`)
- `execute_without_approval`: execute every non-empty AI-generated command immediately.
- `require_approval_for_risky_commands`: auto-run only commands that local rules clearly identify as low-risk; require approval for risky or indeterminate commands.
- `require_approval_for_all_commands`: require approval for every non-empty AI-generated command.

Sentinel command packs are internal scheduled checks and do not use the conversational approval policy.

### Config File Example

```yaml
chatdome:
  telegram:
    bot_token: "123456:ABC..."
    allowed_ids: [123456789]
    admin_ids: []
    proxy_url: ""
    max_message_length: 4000

  # Empty by default upon fresh install. Codex setup writes this block after OAuth succeeds.
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
      api_key: "sk-..."                    # stored directly in local config.yaml

  agent:
    command_approval_mode: require_approval_for_risky_commands
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
│   Auth (User ID)    │──── Unauthorized → ignore
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
| `run_shell_command` | Execute shell commands according to `command_approval_mode` |
| `whois_lookup` | Look up IP geolocation and ownership |

### Sentinel Built-in Checks

| Check ID | Description |
|----------|-------------|
| `ssh_bruteforce` | Detect new SSH source access records |
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

## Terminal Chat

Run:

```bash
chatdome hello
```

`chatdome hello` starts an editable terminal session with command history, slash completion, and protected agent output. Non-TTY input uses plain stdin/stdout. The normal prompt defaults to `› ` and ChatDome replies render as output blocks. Set `CHATDOME_PROMPT` to change or hide the normal input prompt. Use `chatdome hello --quiet` or `CHATDOME_COMPACT=1` for a one-line startup. The initial approval card shows the command purpose without expanding the full command. Approval starts at `approve [y/n/d]>`, switches to `approve [y/n]>` after details, and pause uses `continue [y/n]>`. Press `Ctrl+C` during a running task to stop that task and keep the CLI open. Press `Ctrl+C` while idle to exit the CLI. See `ChatDome-docs/docs/03-module-specs/chatdome-task-control-design-zh.md` for task-control behavior.

| Command | Description |
|---------|-------------|
| `/help` | Show terminal commands |
| `/clear` | Clear conversation context |
| `/stop` | Stop the current running, analyzing, or approval-waiting task |
| `/env` | Show the runtime environment summary |
| `/token` | Show token usage for the current terminal session |
| `/cmd_echo` | Toggle command echo mode |
| `/audit [N]` | Show recent command audit events |
| `/model <profile>` | Switch the model profile for this terminal session |
| `/model_list` | Show configured model profiles and auth status |
| `/details` | Show analysis for the current pending command |
| `/confirm` | Execute the current pending command |
| `/reject` | Reject the current pending command and cancel its task |
| `/continue` | Continue a paused task |
| `/engram [delete <id>]` | List or delete persistent memory |
| `/model_add` | Add an OpenAI-compatible or Codex model profile |
| `/model_delete <profile>` | Delete an inactive model profile |
| `/model_cancel` | Cancel the current model operation |
| `/codex_login [profile]` | Start Codex OAuth device-code authentication |
| `/sentinel_status` | Show Sentinel status |
| `/sentinel_trigger` | Run all Sentinel checks as an administrator |
| `/sentinel_history` | Show recent Sentinel alerts |
| `/sentinel_packs` | Show loaded Sentinel command packs |
| `/sentinel_mute [duration]` | Pause Sentinel alert pushes as an administrator |
| `/sentinel_resume` | Resume Sentinel alert pushes as an administrator |
| `/exit` | Exit terminal chat; `/quit` is an alias |

CLI and Telegram load the same command catalog and call the same business services. Every registered command is normalized to `CommandResult`, converted to a unified `OutboundMessage`, and then rendered by the platform-specific renderer. `/model*` uses one model command service, `/codex_login` uses one OAuth workflow, and `/env` uses one environment Facts Builder. `/exit` and `/quit` are CLI-only because they close the local terminal process.

## Telegram Commands

| Command | Description |
|---------|-------------|
| *(any message)* | Talk to the AI agent in natural language |
| `/clear` | Clear conversation context, start fresh |
| `/stop` | Stop the current running, analyzing, or approval-waiting task |
| `/details` | Show analysis for the current pending command |
| `/confirm` | Execute the current pending command |
| `/reject` | Reject the current pending command and cancel its task |
| `/continue` | Continue a paused task |
| `/env` | Show runtime environment summary from `/var/lib/chatdome/environment/profile.md` |
| `/token` | Show token usage statistics for current chat |
| `/cmd_echo` | Toggle command echo mode in replies |
| `/audit [N]` | Show latest command audit events for current chat (default 10, max 30) |
| `/engram [delete <id>]` | List or delete persistent memory |
| `/sentinel_status` | Show Sentinel status |
| `/sentinel_trigger` | Run all Sentinel checks |
| `/sentinel_history` | Show recent Sentinel alerts |
| `/sentinel_packs` | Show loaded Sentinel command packs |
| `/sentinel_mute [duration]` | Pause Sentinel alert pushes |
| `/sentinel_resume` | Resume Sentinel alert pushes |
| `/codex_login [profile]` | Start Codex OAuth device-code login for the current or named Codex profile |
| `/model_list` | Show configured model profiles and auth status |
| `/model [profile]` | Show profiles or switch the active model profile as an administrator |
| `/model_add` | Add or overwrite a model profile as an administrator |
| `/model_delete <profile>` | Delete an inactive model profile as an administrator |
| `/model_cancel` | Cancel the current model management flow |
| `/help` | Show usage guide and example questions |

No rigid command syntax — just talk to it.

Approval buttons bind the current internal approval record; users do not need to view or enter an approval ID. Telegram, CLI, and future interactive platforms share one global active turn. The lease remains occupied while a command waits for approval and is released only after completion, rejection, cancellation, or terminal failure.

### Example Questions

- "有没有人在爆破我的SSH？"
- "Show me the disk usage and any large files"
- "最近有没有异常的登录记录？"
- "What ports are listening on this server?"
- "检查一下系统负载，最近有没有异常进程"
- "Is my firewall configured correctly?"

## Security

ChatDome executes commands on your server — security is taken seriously:

1. **Telegram Auth** — Only private messages from whitelisted User IDs are processed. Empty lists deny all inbound requests.
2. **Explicit Approval Policy** — `command_approval_mode` is required and controls only AI-generated `run_shell_command` calls.
3. **Fail-Closed Risk Review** — The default mode requires approval when deterministic rules cannot establish low risk.
4. **Sentinel Isolation** — Scheduled Sentinel checks use internal command packs and never wait on conversational approval.
5. **Execution Sandbox** — Command execution has timeout and output-bound controls to reduce blast radius.

> ⚠️ **Recommendation**: Run ChatDome under a dedicated low-privilege user account that has read access to log files but no sudo privileges.

### Security Enhancements (2026-04)

- Risk review now outputs structured fields: `safety_status`, `risk_level`, `mutation_detected`, `deletion_detected`.
- The default approval mode auto-executes only clearly low-risk commands; mutation, deletion, parser failure, and unknown commands require human confirmation.
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
            │   └── auth.py          # private User ID authentication
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
                ├── client.py          # OpenAI-compatible API client
                ├── codex_auth.py      # Codex OAuth Device Code login and token lifecycle
                ├── codex_responses.py # Codex Responses API adapter
                └── manager.py         # Multi-profile LLM management and runtime switching
```

Additional implementation modules (current codebase):

- `controlplane/src/chatdome/runtime_environment.py` — startup environment profiling and prompt compatibility context
- `controlplane/src/chatdome/agent/audit.py` — command audit tracker (hash chain + 30-day retention)
- `controlplane/src/chatdome/llm/codex_auth.py` and `codex_responses.py` — Codex OAuth transport and direct Responses API access
- `controlplane/src/chatdome/llm/codex_oauth_service.py` — shared Codex profile resolution, device authorization, token exchange, and persistence
- `controlplane/src/chatdome/model_commands.py` — shared `/model*` business service
- `controlplane/src/chatdome/outbound/` — unified outbound message contracts, builders, policy, and platform renderers

## Roadmap

- [x] Architecture design
- [ ] **Phase 1 — MVP**: Telegram bot + AI agent + core security checks + sandbox
- [ ] **Phase 2 — Usable**: Multi-turn sessions, more checks, error handling, whois
- [ ] **Phase 3 — Polished**: Scheduled patrols, auto-alerts, session history
- [ ] **Phase 4 — Extensible**: Custom command plugins, multi-server, data plane integration
- [x] **Sentinel Core**: Command Packs, scheduled patrols, rule evaluation, alert history, Telegram push, runtime alert mute/resume
- [ ] **Sentinel Advanced**: threat envelope (dual-layer situational awareness), interactive whitelist, AI memory vault

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Report security issues through [SECURITY.md](SECURITY.md), not public issues.

## License

[Apache-2.0](LICENSE)
