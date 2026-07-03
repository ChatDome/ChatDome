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

Report issues involving:

- Command approval bypass
- Sandbox or validator bypass
- Secret exposure in logs, Telegram replies, or runtime files
- Unauthorized Telegram command execution
- Unsafe installer or update behavior
- Prompt/tool behavior that can execute unintended host commands

Do not report issues that require full host compromise before ChatDome is involved unless ChatDome increases the impact.
