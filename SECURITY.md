# Security Policy

ChatDome executes commands on user-managed hosts. Treat security issues as high priority, even when exploitation requires local configuration or administrator access.

## Supported Versions

Security fixes target the `main` branch and the latest published release. Older versions may receive fixes when the issue is severe and the patch is low risk.

## Reporting a Vulnerability

Do not open a public issue with exploit details.

Use GitHub Security Advisories for this repository. If advisories are unavailable, open a public issue that only requests a private maintainer contact channel and does not include secrets, tokens, payloads, logs, or reproduction details.

Include:

- Affected version or commit
- Deployment mode and operating system
- Minimal reproduction steps
- Expected impact
- Relevant logs with secrets removed

## Security Boundaries

AI-generated `run_shell_command` calls are controlled by the required
`chatdome.agent.command_approval_mode` setting:

- `execute_without_approval` executes every non-empty generated command.
- `require_approval_for_risky_commands` requires approval for risky or indeterminate commands.
- `require_approval_for_all_commands` requires approval for every generated command.

Sentinel checks execute internal command packs independently of the conversational
approval flow. ChatDome validates the complete configuration before startup and
reports all detected errors with YAML line numbers.

Report issues involving:

- Command approval bypass
- Sandbox or validator bypass
- Secret exposure in logs, Telegram replies, or runtime files
- Unauthorized Telegram command execution
- Unsafe installer or update behavior
- Prompt/tool behavior that can execute unintended host commands

Do not report issues that require full host compromise before ChatDome is involved unless ChatDome increases the impact.
