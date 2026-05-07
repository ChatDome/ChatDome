# SSH 会话命令追踪

## 适用场景

用户询问自己 SSH 登录后执行过哪些命令、某个 SSH 登录会话执行了什么、某个来源 IP 登录后做过什么，或想判断某个 SSH 会话里是否执行了危险命令。

## 优先流程

### 步骤 1：确认 auditd 就绪

调用 `run_security_check`，check_id 为 `auditd_status`。

确认以下两点：
- auditd 服务正在运行
- 存在 `execve` 类型的审计规则

如果任一条件不满足，直接告知用户无法追踪会话命令，并给出启用建议。

### 步骤 2：获取目标 SSH 会话信息

根据场景选择：

- **查看当前活跃会话**：调用 `run_security_check`，check_id 为 `ssh_active_sessions`
  - 返回三段信息：Active SSH Sessions（w 命令输出）、sshd Session PIDs（`ps` 输出，包含 `sshd_pid`）、Audit Session Mapping
  - 关键字段：`sshd_pid`（后续步骤需要）

- **查看历史登录记录**：调用 `run_security_check`，check_id 为 `ssh_success_login`
  - 返回格式：`月 日 时间 用户 IP 端口 认证方式 sshd_pid=N`
  - 关键字段：`sshd_pid=N`（从输出末尾提取）

### 步骤 3：映射 Audit Session ID

调用 `run_security_check`，check_id 为 `ssh_audit_session_for_pid`，参数：
- `args.sshd_pid`（字符串）：步骤 2 获取到的 sshd 进程 PID

返回值解读：
- `ses=N`：成功映射到 audit session ID，N 即为后续查询需要的 session_id
- `AUDITD_NOT_AVAILABLE`：ausearch 命令不可用，无法继续
- 空输出：该 PID 无法映射到 session ID（进程可能已退出或 session 不在 auditd 范围内）

### 步骤 4：查询会话内的命令

调用 `run_security_check`，check_id 为 `ssh_session_commands`，参数：
- `args.session_id`（字符串）：步骤 3 获取到的 session ID 数字
- `args.limit`（整数，可选）：返回条数，默认 50，最大 200

返回值：每行一条命令文本（已从 auditd execve 记录中提取）。

## 多会话选择指引

当步骤 2 返回多个 SSH 会话时：
1. 将所有会话以列表形式展示给用户，标注：用户名、来源 IP、登录时间、sshd_pid
2. 询问用户要查看哪个会话
3. 不要猜测用户要查看哪个会话，除非用户之前已明确指定了 IP 或用户名

## 排错决策树

```
步骤 3 映射失败？
├── 输出 "AUDITD_NOT_AVAILABLE"
│   └── 告知：auditd/ausearch 不可用，无法追踪会话命令
├── 输出为空
│   ├── 会话是否仍在活跃？（步骤 2 的 ps 输出中是否有该 PID）
│   │   ├── 是 → 可能是新建会话，尚未产生 execve 事件；建议用户稍后重试
│   │   └── 否 → 该会话已结束，且 auditd 可能未覆盖其创建时期
│   └── 尝试使用 ssh_active_sessions 的 Audit Session Mapping 段寻找对应 ses=
└── 返回了 ses=N
    └── 继续步骤 4
```

## 关键边界

- `last -i -F -n` 只能辅助查看登录记录，不是 SSH 会话内执行命令的来源。
- `ssh_session_commands` 依赖 auditd execve 规则。规则缺失、auditd 未启动或查询权限不足时，不能可靠追溯。
- auditd 通常只能记录规则启用后的命令，不能凭空恢复过去未记录的命令。
- 如果存在多个 SSH 会话，先让用户选择会话，或按时间、用户、来源 IP 明确筛选条件。

## 回答要求

说明结果来自 SSH audit session，并尽量标注 user、source IP、sshd_pid、audit session ID 和时间线。不要混入 ChatDome 自己为了查询而执行的巡检命令。
