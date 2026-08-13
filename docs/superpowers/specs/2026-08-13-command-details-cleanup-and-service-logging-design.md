# 命令详情、会话清理与服务日志设计

## 目标

修复命令详情在 OpenAI-compatible Chat Completions 接口上的不稳定行为，确保会话清理任务退出时被完整取消和等待，并避免正常 ChatDome 日志被 systemd 重复转发到系统日志文件。

## 命令详情分析

ChatDome 先使用本地 shell 解析器拆分完整命令，再按原始顺序逐条调用 LLM。每次请求只包含一个子命令、它前后的连接符以及固定 JSON 契约；请求不依赖 `response_format`、JSON Schema 或工具调用等可选接口能力。

LLM 必须返回当前子命令的安全状态、风险级别、修改和删除标记、影响说明以及命令组成信息。ChatDome 严格校验字段、枚举、布尔类型和风险一致性。首次响应无效时，在同一个 20 秒时间预算内使用精简契约重试一次；仍失败或超时则只标记当前子命令不可用，并继续分析下一条。

单条子命令的完整分析最多等待 20 秒。完整详情的截止时间为开始时间加 `20 × n` 秒，其中 `n` 是本地拆分后的子命令数量。分析严格串行，因此不会对同一模型并发发出详情请求。已经完成的结果不会因后续子命令失败而丢失。

ChatDome 在本地按顺序汇总逐条结果，最终风险不得低于本地静态规则。静态规则实际抬高 LLM 的安全状态或风险级别时，在 `chatdome.log` 记录一条 `WARNING`。日志包含完整命令、触发差异的子命令、子命令序号、命令哈希、LLM 判断、本地判断和静态规则原因。命令先使用现有敏感信息规则脱敏，再将控制字符转义为可见形式；完整命令和子命令分别限制为 2000 字符。

## 会话清理任务

`SessionManager` 负责清理任务的完整生命周期。启动方法保持幂等；异步停止方法取消任务、等待任务结束并清空引用。重复停止不报错。`Agent.stop()` 只调用公开的异步停止接口，不读取 `_cleanup_task` 私有字段。

服务退出和启动失败路径都必须进入统一的异步清理流程，避免事件循环关闭时仍存在 `_cleanup_loop()` pending task。

## systemd 日志路由

安装器和更新器生成的 systemd unit 使用：

```ini
StandardOutput=null
StandardError=journal
```

正常 Python logging 继续写入 `/var/log/chatdome/chatdome.log` 和 `/var/log/chatdome/sentinel.log`。控制台标准输出不再由 journald 收集，因此不会再经 rsyslog 重复进入 `syslog` 或 `daemon.log`。未捕获异常、启动崩溃和直接写入 stderr 的文件日志故障仍进入 journal。

文件日志处理器首次遇到 `ENOSPC` 时，直接向 stderr 输出一次可操作的故障提示，然后停用该处理器。后续日志和 flush 不再重复报告相同错误，避免形成新的日志风暴。

非 systemd 的 `scripts/start.sh` 保持现有重定向行为。

## 验证

- 真实逐条请求测试验证一个请求只包含一个子命令且不发送 `response_format`。
- 超时测试验证单条 20 秒预算、失败后继续以及总预算上限。
- 风险抬升日志测试验证命令内容、索引、风险字段、哈希、控制字符转义和凭据脱敏。
- 清理任务测试验证取消、等待、引用清空及重复停止。
- service unit 测试验证 stdout 丢弃和 stderr 进入 journal。
- 文件日志测试验证 `ENOSPC` 只向 stderr 报告一次。

