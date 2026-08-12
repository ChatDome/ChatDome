# 命令审批与配置校验统一设计

## 目标

统一 AI 生成 Shell 命令的审批配置和决策入口，移除对话 Agent 的预定义命令工具，并将命令包明确收归哨兵模式。同时建立带 YAML 行号的统一配置校验器，在服务启动前一次报告全部配置问题。

## 行为边界

对话 Agent 只通过 `run_shell_command` 执行 AI 生成的命令。是否要求人工审批仅由必填配置 `chatdome.agent.command_approval_mode` 决定：

- `execute_without_approval`：所有非空命令直接执行，不运行风险判定；
- `require_approval_for_risky_commands`：仅明确判定为低风险的命令直接执行，风险、写入、删除、危险或无法确定的命令等待审批；
- `require_approval_for_all_commands`：所有非空命令等待审批，不先运行风险判定。

默认示例配置显式填写 `require_approval_for_risky_commands`。字段缺失属于配置错误，不在运行时静默补默认值。

审批模式只约束 AI 生成的 `run_shell_command`。已经进入等待审批状态的命令在运行时重载审批模式后继续原审批流程，新模式只影响之后生成的命令。

## 风险判定

`require_approval_for_risky_commands` 使用本地确定性规则决定是否需要审批，不依赖 LLM 响应。规则覆盖命令拆分、危险操作、写入与删除意图、提权、网络请求、解释器执行和基础命令识别。

只有能明确判定为低风险的命令才自动执行。解析失败、无法识别、规则冲突或判定异常均采用失败关闭策略，进入人工审批并记录判定失败原因。

LLM 命令分析仅在用户请求审批详情时用于解释影响，不参与审批决策。分析超时、返回格式错误或部分成功不妨碍用户批准或拒绝命令。

## 哨兵命令包

删除对话工具 `run_security_check` 及其分发、提示词、手册引用和会话摘要展示。对话 Agent 不再接触哨兵命令包。

保留 `PackLoader` 和现有命令包，作为哨兵模式的受控检查定义。底层 `CommandSandbox.execute_security_check()` 重命名为 `execute_sentinel_check()`，由 `SentinelScheduler` 直接调用：

```text
SentinelScheduler
  → execute_sentinel_check(check_id, args)
  → PackLoader
  → 哨兵命令包
```

哨兵检查不读取 `command_approval_mode`，不会进入对话审批流程。审计事件、原因和执行日志标签从 `security_check_*` 统一调整为 `sentinel_check_*`。

## 组件职责

- `AgentConfig`：删除 `allow_generated_commands` 和 `allow_unrestricted_commands`，保存必填的 `command_approval_mode`；
- `ToolDispatcher`：根据 `command_approval_mode` 作出直接执行或等待审批的唯一决策；
- `CommandSandbox`：执行命令、限制超时与输出并记录审计，不保存 restricted/unrestricted 状态；
- `SentinelScheduler`：通过 `execute_sentinel_check()` 执行命令包；
- 配置校验器：负责配置结构、字段位置和跨字段关系，不为旧字段编写迁移分支。

运行时配置重载同步更新 `command_approval_mode`。启动日志和文档不再使用 restricted、unrestricted、无限可能或 God Mode 等旧概念。

## 统一配置校验

配置读取分为两个阶段：先解析 YAML 节点并保留字段位置，再按集中式配置规则验证；校验通过后才创建运行时配置对象和服务组件。

校验范围包括：

- YAML 语法和重复字段；
- 未知字段；
- 字段类型；
- 必填字段缺失或值为空；
- 枚举值和数值范围；
- 跨字段引用，例如活动模型必须存在于模型集合；
- 哨兵 `check_id` 必须存在于已启用命令包。

校验器一次收集所有能够独立识别的问题，并按行号排序输出。字段值、未知字段和重复字段指向字段所在行；缺失字段指向父配置块所在行；YAML 语法问题使用解析器提供的行号和列号；文件缺失只报告文件路径。

示例：

```text
配置检查失败，共 3 项：
第 26 行：chatdome.agent 缺少必填字段 command_approval_mode
第 42 行：chatdome.agent.command_timeout 必须是大于 0 的整数
第 115 行：chatdome.sentinel.checks[0].check_id 未在已启用的命令包中定义
```

普通启动、`validate-config`、更新前检查和运行时重载共用同一个校验入口。任何错误都会阻止启动或拒绝本次重载；警告仍可在校验成功后单独输出。

## 配置示例

`config.example.yaml` 的 Agent 配置使用以下结构：

```yaml
chatdome:
  agent:
    command_approval_mode: require_approval_for_risky_commands
```

不保留 `allow_generated_commands` 和 `allow_unrestricted_commands`。所有部署配置由用户统一更新，程序不推断旧字段的等价模式。

## 错误处理

- 配置无效时，在服务组件初始化前输出全部问题并退出；
- 风险判断异常时要求审批，并在审计日志记录稳定的失败原因；
- 哨兵命令包加载或渲染失败只终止对应检查项，并记录 `check_id`；
- `execute_without_approval` 下的执行失败按普通命令错误返回；
- `require_approval_for_all_commands` 在建立审批前只验证命令非空。

## 验证

测试覆盖：

- 三种审批模式的直接执行、等待审批和风险判定异常降级；
- 对话 Agent 的工具列表和调用路径不再包含 `run_security_check`；
- 哨兵通过 `execute_sentinel_check()` 继续执行命令包；
- 配置校验的未知字段、缺失字段、错误类型、非法枚举、重复字段、范围错误、跨字段错误和准确行号；
- 启动、`validate-config`、更新前检查和运行时重载的校验结果一致；
- 审批恢复、命令详情分析、Telegram 审批按钮和哨兵巡检的完整回归。
