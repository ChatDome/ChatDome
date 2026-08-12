# Changelog

All notable changes to ChatDome should be recorded in this file.

This project uses Conventional Commits for commit messages and keeps release notes focused on user-visible behavior, security changes, compatibility notes, and migration steps.

## [Unreleased]

### Added

- Startup configuration validation reports all detected schema, type, enum, range, and reference errors with YAML line numbers.
- Task stop controls are documented for CLI Ctrl+C, CLI /stop, Telegram /stop, and plain stdin/stdout behavior.
- Open-source contribution, security, conduct, issue, and pull request guidance.
- Repository maintenance automation and packaging metadata hardening.

### Changed

- AI-generated shell commands now use the required `command_approval_mode`; risk uncertainty defaults to approval.
- Sentinel retains internal command-pack execution while the conversational `run_security_check` tool is removed.
- Runtime file layout documentation now points to ChatDome-docs, and the duplicate code-repository copy is removed.
- CI coverage and README command references are being aligned with the current public model command surface.
