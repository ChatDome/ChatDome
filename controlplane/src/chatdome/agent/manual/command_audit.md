# ChatDome 内部命令审计

## 适用场景

用户明确询问 ChatDome、机器人、助手或“你”最近执行过哪些命令，或询问 `/audit`、审批记录、拦截记录、命令审计事件。

## 优先工具

使用 `get_command_audit_events`。

常用参数：

- `limit`: 用户要求的条数，默认 5，工具层会限制最大值。
- `scope: executed`: 只看实际执行过的命令。
- `scope: all`: 需要同时查看审批、拦截、审核等事件时使用。

## 禁止事项

- 不要把这个工具用于“SSH 用户执行过哪些命令”。
- 不要把这个工具用于“整台主机最近执行过哪些命令”。
- 不要把 `last -i -F -n`、`journalctl`、`auditctl`、`ausearch` 等 ChatDome 巡检命令解释成 SSH 用户手动执行的业务命令。
- 不要为了回答 ChatDome 自己执行过什么而查询 shell history 或 auditd。

## 回答要求

说明数据来源是 ChatDome 内部工具审计。若用户其实想查 SSH 会话或整机命令历史，应指出范围差异，并改用对应章节的流程或先追问。
