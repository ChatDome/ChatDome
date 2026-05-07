# ChatDome 内部命令审计

## 适用场景

用户明确询问 ChatDome、机器人、助手或"你"最近执行过哪些命令，或询问 `/audit`、审批记录、拦截记录、命令审计事件。

## 优先工具

使用 `get_command_audit_events`。

### 参数说明

- `limit`（可选，整数）：返回条数，默认 5，最大 30。
- `scope`（可选，字符串）：
  - `executed`（默认）：只返回实际执行过的命令（`command_executed`、`security_check_executed`）。
  - `all`：同时包含审批、拦截、安全审查等生命周期事件。

### 返回值格式

工具返回纯文本，按时间倒序排列，每条记录包含：

```
序号. 时间戳(ISO) | 事件类型 (check_id=..., mode=..., return_code=..., duration_ms=...)
   实际执行的命令文本
```

事件类型说明：
- `command_executed`：通过 `run_shell_command` 执行的动态命令
- `security_check_executed`：通过 `run_security_check` 执行的预定义检查
- `command_reviewed`：命令经过安全审查但尚未执行
- `command_pending_approval`：命令进入等待用户审批状态
- `command_blocked`：命令被安全策略拦截

## 歧义意图判别

| 用户可能的表述 | 应该使用的手册章节 |
|---|---|
| "你刚才执行了什么命令" / "查看审计日志" | **本章节**（command_audit） |
| "服务器最近执行了哪些命令" / "主机命令历史" | `host_exec_audit` |
| "SSH 登录后执行了什么" / "那个 IP 做了什么" | `ssh_session_commands` |
| "最近执行了哪些命令"（主体不明确） | **必须追问**：是 ChatDome 自身、SSH 用户还是整台主机 |

## 禁止事项

- 不要把这个工具用于"SSH 用户执行过哪些命令"。
- 不要把这个工具用于"整台主机最近执行过哪些命令"。
- 不要把 `last -i -F -n`、`journalctl`、`auditctl`、`ausearch` 等 ChatDome 巡检命令解释成 SSH 用户手动执行的业务命令。
- 不要为了回答 ChatDome 自己执行过什么而查询 shell history 或 auditd。

## 回答要求

说明数据来源是 ChatDome 内部工具审计。若用户其实想查 SSH 会话或整机命令历史，应指出范围差异，并改用对应章节的流程或先追问。
