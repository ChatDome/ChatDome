# ChatDome 运行文件布局

ChatDome 的运行文件分三类：日志、运行数据、运行状态。

## systemd 默认布局

```text
/var/log/chatdome/
  chatdome.log
  install.log
  update-runtime-check.log

/var/lib/chatdome/
  sessions/<chat_id>.json
  memory/<chat_id>.json
  memory/engram.json
  compression/<chat_id>.log
  audit/audit-YYYY-MM-DD.jsonl
  sentinel/alerts.jsonl
  sentinel/push_state.json
  sentinel/user_context.json
  usage/token_usage.jsonl
  command_outputs/YYYY-MM-DD/*.json
  environment/profile.md
  update/previous_commit
  update/chatdome.service.rollback
  update/chatdome.service.update
  venvs/<version>/

/run/chatdome/
  chatdome.pid
  chatdome.lock
  ready.json
  reload_request.json
  reload_status.json
  llm-profile.lock
```

## 分类说明

| 类别 | 目录 | 内容 |
|---|---|---|
| 日志 | `/var/log/chatdome` | 人工排查和日志系统采集使用的运行记录 |
| 运行数据 | `/var/lib/chatdome` | 服务重启后仍需要保留的数据 |
| 运行状态 | `/run/chatdome` | 只对当前进程有效，重启后可丢弃的状态文件 |

## 运行数据子目录

| 子目录 | 内容 |
|---|---|
| `sessions/` | 当前可恢复的 Telegram 会话上下文和待审批状态 |
| `memory/` | 上下文压缩摘要和 Engram 长期记忆 |
| `compression/` | 上下文压缩事件记录 |
| `audit/` | 命令审批、执行、拒绝、配置变更等审计事件 |
| `sentinel/` | Sentinel 告警历史、推送状态和用户确认的例外上下文 |
| `usage/` | LLM token 用量统计 |
| `command_outputs/` | 可选命令 stdout/stderr 归档 |
| `environment/` | OS、shell、命令可用性画像 |
| `update/` | 菜单更新和回滚需要的状态文件 |
| `venvs/` | 版本化 Python 虚拟环境 |

## 环境变量

| 环境变量 | systemd 默认值 | 用途 |
|---|---|---|
| `CHATDOME_LOG_DIR` | `/var/log/chatdome` | 日志目录 |
| `CHATDOME_LOG_FILE` | `/var/log/chatdome/chatdome.log` | 主运行日志 |
| `CHATDOME_DATA_DIR` | `/var/lib/chatdome` | 运行数据目录 |
| `CHATDOME_RUN_DIR` | `/run/chatdome` | 运行状态目录 |
| `CHATDOME_UPDATE_RUNTIME_LOG` | `/var/log/chatdome/update-runtime-check.log` | 更新候选版本检查失败日志 |

源码开发时未设置 `CHATDOME_RUN_DIR`，Python 代码默认使用 `chat_data/run`，避免普通用户写入 `/run` 失败。

## 旧路径兼容

启动后，ChatDome 会在新位置不存在时迁移以下旧文件：

| 旧位置 | 新位置 |
|---|---|
| `/var/lib/chatdome/<chat_id>_memory.json` | `/var/lib/chatdome/memory/<chat_id>.json` |
| `/var/lib/chatdome/<chat_id>_raw.log` | `/var/lib/chatdome/compression/<chat_id>.log` |
| `/var/lib/chatdome/engram.json` | `/var/lib/chatdome/memory/engram.json` |
| `/var/lib/chatdome/sentinel_alerts.jsonl` | `/var/lib/chatdome/sentinel/alerts.jsonl` |
| `/var/lib/chatdome/sentinel_alert_push_state.json` | `/var/lib/chatdome/sentinel/push_state.json` |
| `/var/lib/chatdome/user_context.json` | `/var/lib/chatdome/sentinel/user_context.json` |
| `/var/lib/chatdome/token_usage.jsonl` | `/var/lib/chatdome/usage/token_usage.jsonl` |
| `/var/lib/chatdome/environment_profile.md` | `/var/lib/chatdome/environment/profile.md` |
