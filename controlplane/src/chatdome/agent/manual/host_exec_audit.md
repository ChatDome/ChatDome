# 主机级 execve 审计

## 适用场景

用户明确询问整台服务器、整台主机或 Linux 系统最近执行过哪些命令，或询问 auditd、execve、主机级命令执行历史。

如果用户只说“最近执行过的 N 条命令”，但没有说明主体，先追问：是 ChatDome 自己执行的命令、SSH 用户会话里的命令，还是整台主机的命令历史。

## 优先流程

1. 使用 `run_security_check` 调用 `auditd_status`，确认 auditd 是否可用，以及是否存在 execve 审计规则。
2. 如果 auditd 不可用或缺少 execve 规则，明确说明不能可靠追溯历史命令，尤其不能追溯规则启用前的命令。
3. 如果用户明确需要整机范围，可在安全边界内使用受控只读查询读取 auditd execve 事件。

## 关键边界

- 主机级 execve 记录可能混入系统服务、cron、用户 shell、ChatDome 自己执行的巡检命令和其他自动化任务。
- 主机级结果不是“某个 SSH 用户会话”的纯净命令列表。
- 需要定位某个 SSH 登录会话时，改读 `ssh_session_commands` 章节。

## 回答要求

必须说明数据范围和局限。例如：“以下是主机级 auditd execve 记录，可能包含系统服务和 ChatDome 巡检命令，不等同于某个 SSH 用户手动输入的命令。”
