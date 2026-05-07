# SSH 会话命令追踪

## 适用场景

用户询问自己 SSH 登录后执行过哪些命令、某个 SSH 登录会话执行了什么、某个来源 IP 登录后做过什么，或想判断某个 SSH 会话里是否执行了危险命令。

## 优先流程

1. 使用 `run_security_check` 调用 `auditd_status`，确认 auditd 可用且存在 execve 规则。
2. 使用 `ssh_active_sessions` 查看当前活跃 SSH 会话，或使用 `ssh_success_login` 查看近期成功登录记录。
3. 如果拿到了 `sshd_pid`，使用 `ssh_audit_session_for_pid` 映射到 audit session ID。
4. 使用 `ssh_session_commands`，传入 `session_id` 和用户要求的 `limit`，查询该会话内的命令。

## 关键边界

- `last -i -F -n` 只能辅助查看登录记录，不是 SSH 会话内执行命令的来源。
- `ssh_session_commands` 依赖 auditd execve 规则。规则缺失、auditd 未启动或查询权限不足时，不能可靠追溯。
- auditd 通常只能记录规则启用后的命令，不能凭空恢复过去未记录的命令。
- 如果存在多个 SSH 会话，先让用户选择会话，或按时间、用户、来源 IP 明确筛选条件。

## 回答要求

说明结果来自 SSH audit session，并尽量标注 user、source IP、sshd_pid、audit session ID 和时间线。不要混入 ChatDome 自己为了查询而执行的巡检命令。
