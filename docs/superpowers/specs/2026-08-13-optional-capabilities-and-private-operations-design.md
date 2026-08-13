# ChatDome 可选能力与私人运维模式设计

## 目标

ChatDome 核心服务不再以 Telegram 或 LLM 配置作为启动条件。systemd 服务始终可以承载 Sentinel 本地巡检；Telegram、LLM 和未来消息平台作为相互独立的可选能力启用。

同时将 Telegram 明确限定为私人运维机器人，按用户白名单授权，并在所有用户入口之间实施全局单活动 turn。

## 能力组合

| Telegram | LLM | 运行结果 |
| --- | --- | --- |
| 未配置 | 未配置 | 核心服务与 Sentinel 正常运行，只记录本地巡检结果 |
| 已配置 | 未配置 | Telegram 接收巡检告警和确定性管理命令；自然语言对话提示配置模型 |
| 未配置 | 已配置 | CLI 可进行 AI 对话；Sentinel 在本地运行 |
| 已配置 | 已配置 | Telegram、CLI、Sentinel 和 AI Agent 全部可用 |

Telegram 和 LLM 的缺失属于能力未就绪，不属于配置文件错误。字段一旦填写，仍必须通过类型、取值和引用关系校验。

## 配置模型

### Telegram

```yaml
chatdome:
  telegram:
    bot_token: ""
    allowed_ids: []
    admin_ids: []
    proxy_url: ""
    max_message_length: 4000
```

- `bot_token` 为空时不启动 Telegram Adapter。
- `allowed_ids` 和 `admin_ids` 保存 Telegram User ID，不保存群组 Chat ID。
- 有效访问集合为 `allowed_ids ∪ admin_ids`。
- 两个列表同时为空时拒绝全部 Telegram 入站消息。
- Telegram 仅处理私聊；群组、超级群组和频道消息不创建 turn，也不执行命令。
- 管理员拥有普通访问权限，并可执行模型、Sentinel 和后续系统级管理操作。

CLI 菜单使用以下文案：

```text
Set allowed IDs
Set admin IDs
```

### LLM

以下配置允许同时为空：

```yaml
chatdome:
  active_ai_profile: ""
  ai_profiles: {}
```

校验规则：

- 两者同时为空表示 LLM 未配置，配置校验和服务启动均通过。
- `ai_profiles` 非空时必须配置 `active_ai_profile`。
- `active_ai_profile` 非空时必须指向 `ai_profiles` 中存在的配置。
- 已定义的 profile 继续执行完整字段校验。
- CLI 进入聊天、Telegram 收到普通文本或命令需要 LLM 时，返回可操作的模型配置提示。
- 不依赖 LLM 的 Telegram 管理命令和 Sentinel 基础巡检不受影响。

### Sentinel 告警目标

告警目标按平台分组，避免混用不同平台的用户标识：

```yaml
chatdome:
  sentinel:
    alert_targets:
      telegram:
        user_ids: []
```

Telegram 目标解析规则：

1. 未配置 `alert_targets.telegram` 时，默认目标为 `telegram.allowed_ids ∪ telegram.admin_ids`。
2. 显式配置 `user_ids: []` 时，关闭 Telegram Sentinel 告警推送。
3. 配置具体 ID 时，只向列出的用户推送。
4. 显式目标必须属于 Telegram 有效访问集合；越权目标在配置校验阶段报错。
5. 未配置 Telegram Token 时不推送 Telegram 告警，但继续巡检和保存记录。

未来平台沿用 `sentinel.alert_targets.<platform>.user_ids`，各平台独立决定默认值与推送状态。

## Sentinel 检查策略

`config.yaml` 不再保存 `sentinel.checks`。所有检查名称、命令编号、执行周期、参数、规则、阈值和严重级别迁移到随程序发布的内置策略文件。

当前阶段的约束：

- 内置策略文件是唯一策略来源。
- 不支持用户策略文件、覆盖或合并。
- 策略随 ChatDome 版本统一更新。
- 内置策略启动时必须验证；损坏或引用不存在的命令包属于程序错误。
- `config.yaml` 只保留 Sentinel 开关、告警目标以及速率、学习、报告等运行参数。
- Sentinel 的基础规则巡检不依赖 LLM；需要 AI 的增强步骤在 LLM 未配置时跳过并记录状态。

## 运行时架构

核心服务统一管理以下可选组件：

```text
ChatDome Core
├── Sentinel Runtime       可独立运行
├── LLM Runtime            配置模型后就绪
├── CLI Adapter            始终可用
├── Telegram Adapter       配置 Token 后启用
└── Future Platform Adapter
```

核心进程不再依赖 Telegram polling 维持生命周期。启动顺序为：

1. 加载并校验结构配置。
2. 加载并校验内置 Sentinel 策略。
3. 创建核心运行时和 Sentinel。
4. 模型配置完整时启用 LLM Runtime。
5. Telegram Token 存在时启用 Telegram Adapter。
6. 等待系统停止信号并按相反顺序关闭已启用组件。

健康状态分别报告核心服务、Sentinel、LLM 和各平台 Adapter，未配置的可选能力显示为 `not_configured`，不导致核心服务不健康。

Telegram 告警通过核心持有的平台投递路由发送。Telegram Adapter 未启用时，该路由跳过 Telegram 目标，不要求 Sentinel 持有 Telegram Bot 实例。配置了可选能力但组件初始化或连接失败时，该组件进入 `degraded` 状态并记录可操作错误；核心服务和 Sentinel 继续运行，用户修正配置后可通过重载或重启恢复组件。

LLM 未配置时不创建 `LLMManager` 和 `Agent`。Telegram 的确定性命令通过独立命令服务处理；只有自然语言、命令分析或其他明确依赖 LLM 的入口才检查 Agent 是否就绪。

## 全局单活动 turn

所有用户入口共享一个 `GlobalTurnCoordinator`：

- Telegram、CLI 和未来平台合计只允许一个活动 turn。
- `running`、`waiting_approval` 和等待用户明确选择均占用全局 turn。
- turn 完成、拒绝、取消或不可恢复失败后释放。
- Sentinel 后台巡检不属于用户 turn，不占用协调器。
- 新请求在协调器被占用时不排队，直接返回当前任务正在执行的提示。
- 协调必须覆盖 systemd 与独立 CLI 进程，使用操作系统级排他锁；进程退出后锁由操作系统自动释放。
- 锁旁保存非敏感元数据，用于说明占用来源和 turn 编号，不保存用户消息或命令正文。

## 更新与配置迁移

运行时继续拒绝未知旧字段，不在普通启动路径中隐式兼容历史配置。`chatdome update` 在候选版本校验前执行显式、可审计的一次性迁移：

- `agent.allow_generated_commands` 和 `agent.allow_unrestricted_commands` 转换为 `agent.command_approval_mode`，无法无歧义映射时使用 `require_approval_for_risky_commands`。
- `telegram.allowed_chat_ids` 转换为 `telegram.allowed_ids`。
- `telegram.admin_chat_ids` 转换为 `telegram.admin_ids`。
- `sentinel.alert_chat_ids` 转换为 `sentinel.alert_targets.telegram.user_ids`。
- 删除迁移到内置策略文件的 `sentinel.checks`。
- 保留 Token、模型 profile、代理和其他用户设置。

更新器在修改前保存配置备份。候选版本或迁移后配置验证失败时，同时恢复程序版本和原配置。不得用 `config.example.yaml` 覆盖生产配置。

## 错误处理

- Telegram 未配置：记录 Adapter 未启用，不作为错误。
- LLM 未配置：聊天入口提示配置模型，不生成 turn。
- Telegram 白名单为空：拒绝入站消息并记录 User ID，不回显主机信息。
- 群组或频道消息：忽略并记录来源类型。
- 内置 Sentinel 策略无效：核心启动失败并指出内置策略文件和具体条目。
- 告警平台未配置：跳过该平台推送，巡检结果仍写入本地历史。
- 全局 turn 被占用：返回当前有任务执行中的提示，不修改现有 turn。

## 测试范围

- 四种 Telegram/LLM 配置组合都能得到预期启动状态。
- 空 Telegram 白名单拒绝全部入站消息；管理员自动获得访问权限。
- 群组与频道消息不能创建 turn。
- 未配置和显式空告警目标具有不同语义。
- 告警目标不能超出有效访问集合。
- 没有 LLM 时确定性 Telegram 命令和 Sentinel 基础巡检可运行。
- Sentinel 从唯一内置策略加载，`config.yaml` 中的 `checks` 被判为未知字段。
- Telegram 与 CLI 并发请求只能有一个获得全局 turn，包括等待审批状态。
- 更新测试覆盖旧字段迁移、生产配置保留、失败回滚和重复运行。
- 完整测试套件通过，示例配置通过结构校验并允许可选能力为空。
