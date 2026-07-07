# Task Control

ChatDome exposes one visible stop command across interactive surfaces:

```text
/stop
```

`/cancel` and `/abort` are not registered aliases.

## Behavior Matrix

| Surface | Input | Current state | Behavior |
|---------|-------|---------------|----------|
| Interactive CLI | `Ctrl+C` | Task running | Stop the current task and keep the CLI open |
| Interactive CLI | `Ctrl+C` | Idle | Exit the CLI |
| Interactive CLI | `/stop` | Task running | Stop the current task |
| Interactive CLI | `/stop` | Idle | Report that no task is running |
| Telegram | `/stop` | Task running | Stop the current chat task |
| Telegram | `/stop` | Idle | Report that no task is running |
| Plain stdin/stdout | `Ctrl+C` | Any | Use normal process interruption |

## CLI

`chatdome hello` uses the interactive `prompt_toolkit` view when a TTY is available. In this mode, user messages run in a cancellable background task so the input loop can still receive `Ctrl+C` or `/stop`.

When the CLI runs in plain stdin/stdout mode, user messages remain synchronous. `Ctrl+C` keeps the operating system's normal process-interrupt behavior.

## Telegram

Telegram messages run as one cancellable task per chat. While a chat task is running, another regular message is rejected with an instruction to send `/stop`. The `/stop` command cancels the current task for that chat only.

## Command Execution

Cancelling a task propagates into the command sandbox. If a shell command is running, ChatDome terminates the active subprocess. On POSIX systems, the sandbox terminates the process group; on Windows, it terminates the child process.

## SSH Disconnects

`Ctrl+C` and `/stop` are explicit user stop requests. An SSH disconnect is a transport event and does not mean the user requested cancellation. Whether work continues after disconnect depends on the process supervisor, terminal session, and transport behavior.
