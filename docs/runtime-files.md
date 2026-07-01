# ChatDome 运行文件布局

ChatDome 的运行文件分三类：日志、运行数据、运行状态。

## systemd 默认布局

```text
/var/log/chatdome/chatdome.log
/var/log/chatdome/sentinel.log
/var/log/chatdome/install.log
/var/log/chatdome/update-runtime-check.log

/var/lib/chatdome/sessions/<chat_id>.json
/var/lib/chatdome/memory/<chat_id>.json
/var/lib/chatdome/memory/engram.json
/var/lib/chatdome/compression/<chat_id>.log
/var/lib/chatdome/audit/audit-YYYY-MM-DD.jsonl
/var/lib/chatdome/audit/sentinel-commands-YYYY-MM-DD.jsonl
/var/lib/chatdome/sentinel/alerts.jsonl
/var/lib/chatdome/sentinel/push_state.json
/var/lib/chatdome/sentinel/user_context.json
/var/lib/chatdome/usage/token_usage.jsonl
/var/lib/chatdome/command_outputs/YYYY-MM-DD/*.json
/var/lib/chatdome/environment/profile.md
/var/lib/chatdome/update/previous_commit
/var/lib/chatdome/update/chatdome.service.rollback
/var/lib/chatdome/update/chatdome.service.update
/var/lib/chatdome/venvs/<version>/

/run/chatdome/chatdome.pid
/run/chatdome/chatdome.lock
/run/chatdome/ready.json
/run/chatdome/reload_request.json
/run/chatdome/reload_status.json
/run/chatdome/llm-profile.lock
```

## 分类说明

| 类别 | 目录 | 内容 |
|---|---|---|
| 日志 | `/var/log/chatdome/` | 人工排查和日志系统采集使用的运行记录 |
| 运行数据 | `/var/lib/chatdome/` | 服务重启后仍需要保留的数据 |
| 运行状态 | `/run/chatdome/` | 只对当前进程有效，重启后可丢弃的状态文件 |

## 日志文件

| 文件 | 内容 |
|---|---|
| `/var/log/chatdome/chatdome.log` | 主运行日志：启动停止、配置加载、Telegram、Agent、LLM、审批、用户主动工具调用 |
| `/var/log/chatdome/sentinel.log` | Sentinel 运行日志：Sentinel 调度、周期巡检、巡检命令执行、规则评估、告警推送异常 |
| `/var/log/chatdome/install.log` | 安装脚本运行日志 |
| `/var/log/chatdome/update-runtime-check.log` | 更新候选版本检查失败日志 |

## 运行数据子目录

| 目录 | 内容 |
|---|---|
| `/var/lib/chatdome/sessions/` | 当前可恢复的 Telegram 会话上下文、用户可见结果摘要和待审批状态 |
| `/var/lib/chatdome/memory/` | 脱敏后的上下文压缩摘要和 Engram 长期记忆 |
| `/var/lib/chatdome/compression/` | 脱敏后的上下文压缩事件记录 |
| `/var/lib/chatdome/audit/` | 用户命令审批和敏感操作审计；Sentinel 巡检命令写入独立 `sentinel-commands-*` 文件 |
| `/var/lib/chatdome/sentinel/` | Sentinel 告警历史、推送状态和用户确认的例外上下文 |
| `/var/lib/chatdome/usage/` | LLM token 用量统计 |
| `/var/lib/chatdome/command_outputs/` | 可选命令 stdout/stderr 归档 |
| `/var/lib/chatdome/environment/` | OS、shell、命令可用性画像 |
| `/var/lib/chatdome/update/` | 菜单更新和回滚需要的状态文件 |
| `/var/lib/chatdome/venvs/` | 版本化 Python 虚拟环境 |

## 会话上下文

`/var/lib/chatdome/sessions/<chat_id>.json` 是 Telegram 会话主快照，包含 `session.messages`、待审批状态和轮次限制状态。

用户在 Telegram 中看到的业务结果摘要会写入 `session.messages`，包括 Sentinel 告警推送、告警详情、告警分析、审批详情和手动巡检结果。临时状态消息、按钮清除、内部重试和 debug 日志不写入会话上下文。

`search_session_history` 只检索当前 chat 的 `sessions/<chat_id>.json`，用于用户依赖历史上下文但当前 `messages` 无法唯一确定对象时补充上下文。

## 环境变量

| 环境变量 | systemd 默认值 | 用途 |
|---|---|---|
| `CHATDOME_LOG_DIR` | `/var/log/chatdome` | 日志目录 |
| `CHATDOME_LOG_FILE` | `/var/log/chatdome/chatdome.log` | 主运行日志 |
| `CHATDOME_SENTINEL_LOG_FILE` | `/var/log/chatdome/sentinel.log` | Sentinel 运行日志 |
| `CHATDOME_DATA_DIR` | `/var/lib/chatdome` | 运行数据目录 |
| `CHATDOME_RUN_DIR` | `/run/chatdome` | 运行状态目录 |
| `CHATDOME_UPDATE_RUNTIME_LOG` | `/var/log/chatdome/update-runtime-check.log` | 更新候选版本检查失败日志 |

源码开发时未设置 `CHATDOME_RUN_DIR`，Python 代码默认使用当前工作目录下的运行状态目录；以仓库根目录为 `/path/to/ChatDome` 时，该目录为 `/path/to/ChatDome/chat_data/run/`。

## 路径策略

ChatDome 的标准运行文件路径以本文定义的新布局为准。部分旧版路径会在首次访问时自动迁移到新布局；新代码不得新增旧路径写入点。

无法自动迁移的旧路径历史文件由部署方按需手动归档或删除。
