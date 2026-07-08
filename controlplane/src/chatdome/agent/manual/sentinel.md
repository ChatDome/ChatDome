# Sentinel 巡检与告警解释

## 适用场景

用户询问哨兵告警是什么意思、为什么持续提醒、某条告警是否误报，或希望 ChatDome 记住某个正常变更背景。

## 告警状态机

Sentinel 对每种威胁类型维护一个独立的状态机，共六种状态：

```
首次命中 → NEW
             │
             ▼ (10分钟内 ≥5次 或 ≥3个不同指纹)
         ESCALATED_L1
             │
             ▼ (20分钟内 ≥12次 或 ≥6个不同指纹)
         ESCALATED_L2
             │
             ▼ (30分钟内 ≥25次 或 ≥10个不同指纹)
         ESCALATED_L3
             │
             ▼ (20分钟无新增)
     RECOVERED_CANDIDATE
       │              │
       ▼ (15分钟无新增) ▼ (有新增)
    RECOVERED      ESCALATED_L1 (回弹)
    (归档)
```

关键规则：
- 同一类型的重复事件不会产生新的 NEW 告警，而是升级现有状态机
- 不同类型的告警（如 ssh_bruteforce 和 open_ports）使用独立的状态机
- 全局速率限制 `global_rate_limit` 作为消息风暴的最后保险阀

## 告警指纹去重

每种告警类型有固定的指纹计算规则，相同指纹在状态机窗口内不会重复计数：

- `ssh_bruteforce`：`来源IP|目标端口|用户名|认证结果`
- `ssh_failed_burst`：`来源IP|分钟级时间桶`（同一 IP 同一分钟内多次失败只算一次）
- `ssh_success_login`：`来源IP|用户名|目标端口`
- `open_ports`：`监听IP|端口|PID|进程名`
- `disk_usage`：`挂载点`

## 标准告警回复结构

回答告警相关问题时，使用以下三段结构：

1. **发现了什么**：客观描述告警证据（来源 IP、命中次数、时间范围等）
2. **为什么重要**：解释该事件的安全含义和潜在风险
3. **建议怎么做**：给出具体可执行的处置建议

示例：
> 发现了什么：过去 10 分钟内，IP 203.0.113.42 对 SSH 端口发起了 47 次登录失败尝试，目标用户包括 root、admin、ubuntu。
> 为什么重要：这是典型的 SSH 暴力破解攻击模式，如果目标用户使用弱密码，攻击者可能获得访问权限。
> 建议怎么做：确认该 IP 是否为已知来源；如非合法，建议使用 fail2ban 封禁或防火墙规则阻断。

## `add_user_context` 工具使用指南

当用户确认某条告警对应的是自己的正常操作时，使用此工具记录背景信息。

### 参数说明

- `check_id`（必填）：触发告警的检查项 ID，必须从告警上下文中提取（如 `open_ports`、`ssh_success_login`）
- `pattern`（可选）：匹配关键词。设置后仅静默包含该词的告警。留空则静默该检查项的全部告警
- `summary`（必填）：一句话客观记录用户的声明

### 使用示例

用户说："刚才是我在重启 nginx"

```
add_user_context(
  check_id="open_ports",
  pattern="nginx",
  summary="用户确认手动重启了 nginx 服务，端口变化属正常操作"
)
```

### 使用约束

- **仅在用户明确声明时调用**，禁止自行推测
- 不要因为告警频繁就自动调用此工具
- 每次调用都会持久化写入记录，后续巡检自动静默匹配的事件
- 用户确认的稳定 IP、VPN 节点、跳板机、端口用途等事实会同步写入 Engram；一次性的重启、部署、测试只写入用户上下文记录

## `set_sentinel_alert_push_policy` 工具使用指南

当用户用自然语言要求暂停、静默、关闭、恢复或查看 Sentinel 主动 Telegram 告警推送时，使用此工具。该工具只控制“主动推送”，不会停止 Sentinel 巡检，也不会停止写入告警历史。

精准命令仍可直接提示用户使用：

- `/sentinel_mute`
- `/sentinel_mute 本周`
- `/sentinel_mute 7d`
- `/sentinel_resume`

### 参数说明

- `action`（必填）：`mute`、`resume` 或 `status`
- `duration`（可选，仅 `mute`）：规范化时长
  - `manual` 或 `until_resume`：静默到用户手动恢复
  - `today`：静默到今天结束
  - `this_week`：静默到本周结束
  - `7d`、`24h`、`30min`、`2weeks`：相对时长
- `until_iso`（可选，仅 `mute`）：明确恢复时间，ISO-8601 格式；提供时优先于 `duration`
- `reason`（可选）：一句话记录用户为什么调整推送策略

### 使用示例

用户说："我不希望收到 Sentinel 的告警了"

```
set_sentinel_alert_push_policy(
  action="mute",
  duration="manual",
  reason="用户要求暂停 Sentinel 主动告警推送，直到手动恢复"
)
```

用户说："本周不希望再收到告警了"

```
set_sentinel_alert_push_policy(
  action="mute",
  duration="this_week",
  reason="用户要求本周静默 Sentinel 主动告警推送"
)
```

用户说："一周不进行告警推送"

```
set_sentinel_alert_push_policy(
  action="mute",
  duration="7d",
  reason="用户要求未来一周静默 Sentinel 主动告警推送"
)
```

用户说："恢复 Sentinel 告警推送"

```
set_sentinel_alert_push_policy(
  action="resume",
  reason="用户要求恢复 Sentinel 主动告警推送"
)
```

### 使用约束

- 不要用 `run_shell_command` 修改 Sentinel 推送策略。
- 不要把“静默推送”解释成停止巡检；必须说明巡检和历史记录仍会继续。
- 如果用户表达模糊，例如“最近别烦我”，先追问是否指 Sentinel 告警推送，以及希望静默多久。
- 长期静默或永久静默前，回复中应提醒用户可以用 `/sentinel_resume` 或自然语言恢复。

## 常见误报判别

| 场景 | 判别方法 | 处理建议 |
|------|------|------|
| 用户重启服务后端口变化告警 | 用户确认是自己操作 | 使用 add_user_context 记录 |
| 管理员从新 IP 登录 SSH | 用户确认是自己的 VPN、跳板机或固定来源 | 使用 add_user_context 记录，稳定来源会同步 Engram |
| cron 定时任务触发异常进程告警 | 检查进程路径是否为已知 cron 任务 | 建议用户确认后记录 |
| Sentinel 巡检命令被 auditd 记录 | 这不是误报，是正常的审计记录 | 向用户解释数据来源差异 |

## 处理原则

- 区分巡检命令、告警事件、用户上下文和静默策略。
- 先解释告警证据，再判断风险，不要仅凭告警标题下结论。
- 对用户确认的正常变更，可使用 `add_user_context` 记录背景，帮助后续降低误报。
- 对用户确认的稳定环境事实，依赖 `add_user_context` 的自动 Engram 同步，不要重复保存同一事实。
- 不应在没有用户确认时自行静默告警。

## 回答要求

尽量用"发现了什么、为什么重要、建议怎么做"的结构回答。涉及静默或忽略时，说明生效范围和潜在风险。
