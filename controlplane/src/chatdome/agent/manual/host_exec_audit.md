# 主机级 execve 审计

## 适用场景

用户明确询问整台服务器、整台主机或 Linux 系统最近执行过哪些命令，或询问 auditd、execve、主机级命令执行历史。

如果用户只说"最近执行过的 N 条命令"，但没有说明主体，**必须先追问**：是 ChatDome 自己执行的命令、SSH 用户会话里的命令，还是整台主机的命令历史。

## 优先流程

1. 使用 `run_security_check` 调用 `auditd_status`，确认 auditd 是否可用，以及是否存在 execve 审计规则。
2. 如果 auditd 不可用或缺少 execve 规则，明确说明不能可靠追溯历史命令，尤其不能追溯规则启用前的命令。
3. 如果用户明确需要整机范围，可在安全边界内使用受控只读查询读取 auditd execve 事件。

## auditd 缺失时的降级响应

当 auditd 不可用或缺少 execve 规则时，**禁止以下降级操作**：
- 不要尝试读取 `~/.bash_history`（安全风险，且只记录当前 shell、不含其他用户）
- 不要用 `last` 替代（last 只记录登录记录，不记录命令）

正确的降级响应模板：
> "当前主机的 auditd 服务未启用 / 缺少 execve 审计规则，因此无法可靠查询主机级命令执行历史。auditd 只能记录规则启用后的命令，不能恢复历史数据。如需启用，可参考命令 `auditctl -a always,exit -F arch=b64 -S execve`（需要 root 权限）。"

## auditd 输出字段解读

ausearch 返回的 execve 记录格式示例：
```
type=EXECVE msg=audit(1714123456.789:1234): argc=3 a0="/usr/bin/ls" a1="-la" a2="/tmp"
```

关键字段说明：
- `msg=audit(时间戳:序列号)`：事件发生的 Unix 时间戳
- `argc`：命令参数个数
- `a0`：可执行文件路径
- `a1`, `a2`, ...：命令参数
- `ses=N`：audit session ID（用于关联 SSH 会话）
- `uid=N` / `auid=N`：执行用户 ID / 审计 UID（原始登录用户）

## 过滤 ChatDome 自身命令

主机级 execve 记录会混入大量 ChatDome 巡检命令。识别特征：
- ChatDome 进程的 PID/PPID 通常指向 `/usr/bin/python3 /usr/local/bin/chatdome`
- 巡检命令通常包含 `ausearch`、`ss -tlnp`、`journalctl` 等模式
- 若 `auid` 字段为 `unset` 或 `4294967295`，通常为系统后台进程

回答时应明确提醒用户："以下结果可能包含系统服务和 ChatDome 巡检命令，并非全部由人工操作产生。"

## 关键边界

- 主机级 execve 记录可能混入系统服务、cron、用户 shell、ChatDome 自己执行的巡检命令和其他自动化任务。
- 主机级结果不是"某个 SSH 用户会话"的纯净命令列表。
- 需要定位某个 SSH 登录会话时，改读 `ssh_session_commands` 章节。

## 回答要求

必须说明数据范围和局限。例如："以下是主机级 auditd execve 记录，可能包含系统服务和 ChatDome 巡检命令，不等同于某个 SSH 用户手动输入的命令。"
