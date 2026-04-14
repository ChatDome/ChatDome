# ChatDome Sentinel — 7×24 主动监控与告警系统设计

> **设计目标**
>
> 让 ChatDome 从"被动应答式安全助手"进化为 **7×24 全天候主动守卫**。
> 系统持续巡检主机状态，在异常发生时主动通过 Telegram 推送告警，
> 并由 AI 分析上下文、给出处置建议，用户可直接在对话中执行修复操作。
>
> **核心理念**：检测即配置、告警不轰炸、AI 闭环处置。

---

## 1. 设计原则

| 原则 | 说明 |
|------|------|
| **零外部依赖** | 不引入 Prometheus / Grafana / Alertmanager，全部内建于 ChatDome 单进程中 |
| **声明式检查** | 借鉴 osquery Query Pack，所有检查项以 YAML 声明，不写代码即可扩展 |
| **Pack 目录结构** | 借鉴 osquery pack 分组 + Wazuh 内置/自定义隔离，命令库按主题分文件、内置与用户自定义物理隔离 |
| **多平台自适应** | 同一检查项支持多个平台模板（debian/rhel/systemd），启动时自动检测并选择 |
| **混合命令模型** | 模板命令优先（零 token）+ AI 动态生成兜底（灵活性），兼顾效率与覆盖面 |
| **分级告警** | 借鉴 Wazuh level 体系，告警按严重度分级响应 |
| **告警抑制** | 相同告警在冷却窗口内不重复推送，防止消息风暴 |
| **威胁态势感知** | 双层架构：结构化索引（Counter 多维信封，零 token 匹配）+ AI 自然语言叙事（理解与演化），统一了攻击链关联与威胁状态机 |
| **交互式白名单** | 用户通过自然语言管理白名单（"这个 IP 是跳板机"），AI 自动解析并持久化 |
| **哨兵记忆库** | 独立于会话上下文的持久化记忆，记住主机画像、已知服务、历史处置，避免乌龙误报 |
| **AI 闭环** | 借鉴 CrowdStrike，异常 → AI 分析 → 处置建议 → 用户确认 → 执行修复 |
| **最大复用** | 复用现有 `CommandSandbox`、`LLMClient`、Telegram 推送 |

---

## 2. 整体架构

```
                    ┌───────────────────────────────────────────────────────────┐
                    │                  ChatDome Process                         │
                    │                                                           │
                    │  ┌─────────────────────────────────────────────────────┐  │
                    │  │              Sentinel Engine (新增)                  │  │
                    │  │                                                     │  │
                    │  │  ┌──────────┐   ┌──────────┐   ┌───────────────┐   │  │
                    │  │  │Pack      │   │          │   │               │   │  │
                    │  │  │Loader    │   │Scheduler │   │  Evaluator    │   │  │
                    │  │  │(内置+用户)│──▶│(asyncio) │──▶│  (规则引擎)   │   │  │
                    │  │  └──────────┘   └──────────┘   └───────┬───────┘   │  │
                    │  │                                        │           │  │
                    │  │                          ┌─────────────┼──────┐    │  │
                    │  │                          │ 正常        │ 异常  │    │  │
                    │  │                          ▼             ▼      │    │  │
                    │  │                       (静默)    ┌────────────┐│    │  │
                    │  │                                │ Suppressor ││    │  │
                    │  │                                │ (告警抑制)  ││    │  │
                    │  │                                └──────┬─────┘│    │  │
                    │  │                                       │      │    │  │
                    │  │                              ┌────────┴───┐  │    │  │
                    │  │                              │ 新告警?     │  │    │  │
                    │  │                              ├─ NO → 静默 │  │    │  │
                    │  │                              ├─ YES ↓     │  │    │  │
                    │  │                              └────────────┘  │    │  │
                    │  │                                       │      │    │  │
                    │  └───────────────────────────────────────┼──────┘    │  │
                    │                                          │           │  │
                    │  ┌───── 复用现有组件 ─────────────────────┼────────┐  │  │
                    │  │                                       ▼        │  │  │
                    │  │  ┌──────────┐  ┌──────────┐  ┌─────────────┐  │  │  │
                    │  │  │ Command  │  │   LLM    │  │  Telegram   │  │  │  │
                    │  │  │ Sandbox  │  │  Client  │  │  Bot.send() │  │  │  │
                    │  │  │ (执行)   │  │ (AI分析) │  │  (推送告警) │  │  │  │
                    │  │  └──────────┘  └──────────┘  └─────────────┘  │  │  │
                    │  └───────────────────────────────────────────────┘  │  │
                    └────────────────────────────────────────────────────────┘
                                                           │
                                                           ▼
                                                    ┌─────────────┐
                                                    │  Telegram    │
                                                    │  用户收到     │
                                                    │  告警 + 建议  │
                                                    └─────────────┘
```

---

## 3. Command Pack — 命令库体系

### 3.1 设计思想

**问题**：原有 `registry.py` 将 15 个命令硬编码在 Python 中，存在三个瓶颈——数量少（15 个覆盖面有限）、不可扩展（新增必须改代码部署）、不适配（不同发行版日志路径不同，模板写死了）。

**方案**：借鉴 osquery Pack 分组 + Wazuh 内置/自定义隔离 + CrowdStrike AI 兜底，采用 **Pack 目录结构 + 混合命令模型**：

| 设计来源 | ChatDome 映射 |
|----------|---------------|
| osquery Query Pack 按主题分文件 | Command Pack — 按安全域分 YAML 文件（`ssh_auth.yaml`、`network.yaml`...） |
| osquery `interval` + `snapshot` / `differential` | 检查策略定义于 `config.yaml` 的 `sentinel.checks` 中 |
| Wazuh 内置规则 vs `local_rules.xml` 隔离 | 内置 pack（`src/chatdome/packs/`）vs 用户 pack（`packs/`） |
| CrowdStrike AI 自主分析 | `goal` 字段驱动 AI 动态生成命令，作为模板命令的兜底 |

### 3.2 Pack 目录结构

```
ChatDome/
├── controlplane/src/chatdome/
│   └── packs/                            # ★ 内置命令库（随代码分发，升级可覆盖）
│       ├── ssh_auth.yaml                 #   SSH / 认证 (~6 条)
│       ├── network.yaml                  #   网络 (~6 条)
│       ├── system_resources.yaml         #   系统资源 (~6 条)
│       ├── users_permissions.yaml        #   用户 / 权限 (~5 条)
│       ├── file_integrity.yaml           #   文件完整性 (~5 条)
│       ├── processes_services.yaml       #   进程 / 服务 (~5 条)
│       ├── containers.yaml               #   容器 (~4 条)
│       └── logs.yaml                     #   日志 (~4 条)
│                                         #   合计 ~41 条内置命令
├── packs/                                # ★ 用户自定义命令库（永不被升级覆盖）
│   └── my_app.yaml                       #   用户自己的业务检查
└── config.yaml                           #   主配置（引用 pack + 定义检查策略）
```

**核心规则**：

- **内置 pack 目录** (`src/chatdome/packs/`) — 随代码版本发布，升级时可安全覆盖
- **用户 pack 目录** (`packs/`) — 用户自行维护，ChatDome 永远不会写入或覆盖此目录
- **同名 command** — 如果用户 pack 中定义了与内置 pack 同名的 command_id，用户版覆盖内置版
- **按需加载** — 配置中通过 `builtin_packs` 列表选择性加载，不需要的 pack 不加载

### 3.3 Pack 文件格式

每个 pack 文件是一个独立的 YAML，按安全主题聚合一组相关命令：

```yaml
# packs/ssh_auth.yaml — SSH 与认证安全命令包
pack:
  name: "SSH & Authentication"
  description: "SSH 登录安全与认证审计"
  platform: linux
  version: "1.0"

commands:
  ssh_bruteforce:
    name: "SSH 暴力破解检测"
    templates:
      - platform: debian
        command: "awk '/Failed password/ {print $(NF-3)}' /var/log/auth.log | sort | uniq -c | sort -nr | head -{limit}"
      - platform: rhel
        command: "awk '/Failed password/ {print $(NF-3)}' /var/log/secure | sort | uniq -c | sort -nr | head -{limit}"
      - platform: any                  # 通用 fallback（systemd 日志）
        command: "journalctl _COMM=sshd --since '{since}' --no-pager | grep 'Failed password' | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head -{limit}"
    params:
      limit: { type: int, default: 10, max: 50 }
      since: { type: str, default: "1 hour ago" }
    timeout: 10
    tags: [ssh, bruteforce, credential_access]

  ssh_success_login:
    name: "SSH 成功登录记录"
    templates:
      - platform: debian
        command: "awk '/Accepted/ {print $1, $2, $3, $9, $11}' /var/log/auth.log | tail -{limit}"
      - platform: any
        command: "journalctl _COMM=sshd --since '{since}' --no-pager | grep 'Accepted' | tail -{limit}"
    params:
      limit: { type: int, default: 20, max: 100 }
      since: { type: str, default: "24 hours ago" }
    timeout: 10
    tags: [ssh, login, audit]

  ssh_authorized_keys:
    name: "SSH 公钥变更检测"
    templates:
      - platform: any
        command: "find /home -name authorized_keys -exec md5sum {} \\;"
    params: {}
    timeout: 10
    tags: [ssh, persistence, file_integrity]

  failed_sudo:
    name: "sudo 失败记录"
    templates:
      - platform: debian
        command: "grep 'sudo:.*COMMAND' /var/log/auth.log | grep 'NOT' | tail -{limit}"
      - platform: any
        command: "journalctl _COMM=sudo --since '{since}' --no-pager | grep 'NOT' | tail -{limit}"
    params:
      limit: { type: int, default: 20, max: 100 }
      since: { type: str, default: "24 hours ago" }
    timeout: 10
    tags: [sudo, privilege_escalation]

  sudoers_changes:
    name: "sudoers 文件变更"
    templates:
      - platform: any
        command: "md5sum /etc/sudoers /etc/sudoers.d/* 2>/dev/null"
    params: {}
    timeout: 10
    tags: [sudo, persistence, file_integrity]
```

```yaml
# packs/network.yaml — 网络安全命令包
pack:
  name: "Network Security"
  description: "网络连接、端口与防火墙检查"
  platform: linux
  version: "1.0"

commands:
  active_connections:
    name: "当前活跃连接"
    templates:
      - platform: any
        command: "ss -tunapl | head -{limit}"
    params:
      limit: { type: int, default: 30, max: 100 }
    timeout: 10
    tags: [network, connections]

  open_ports:
    name: "监听端口"
    templates:
      - platform: any
        command: "ss -tlnp"
    params: {}
    timeout: 10
    tags: [network, ports]

  firewall_rules:
    name: "防火墙规则"
    templates:
      - platform: any
        command: "iptables -L -n --line-numbers 2>/dev/null || nft list ruleset 2>/dev/null || echo 'No firewall detected'"
    params: {}
    timeout: 10
    tags: [network, firewall]

  network_interfaces:
    name: "网络接口检测"
    templates:
      - platform: any
        command: "ip -br addr show"
    params: {}
    timeout: 10
    tags: [network, interface, tunnel]

  dns_resolv:
    name: "DNS 配置"
    templates:
      - platform: any
        command: "md5sum /etc/resolv.conf; cat /etc/resolv.conf"
    params: {}
    timeout: 10
    tags: [network, dns, file_integrity]

  established_foreign:
    name: "外部连接统计"
    templates:
      - platform: any
        command: "ss -tn state established | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -{limit}"
    params:
      limit: { type: int, default: 20, max: 50 }
    timeout: 10
    tags: [network, connections, audit]
```

```yaml
# packs/system_resources.yaml — 系统资源命令包
pack:
  name: "System Resources"
  description: "CPU、内存、磁盘、负载监控"
  platform: linux
  version: "1.0"

commands:
  disk_usage:
    name: "磁盘使用"
    templates:
      - platform: any
        command: "df -h"
    params: {}
    timeout: 10
    tags: [system, disk]

  memory_usage:
    name: "内存使用"
    templates:
      - platform: any
        command: "free -h"
    params: {}
    timeout: 10
    tags: [system, memory]

  system_load:
    name: "系统负载"
    templates:
      - platform: any
        command: "uptime; echo '---'; top -bn1 | head -20"
    params: {}
    timeout: 15
    tags: [system, cpu, load]

  last_reboot:
    name: "重启历史"
    templates:
      - platform: any
        command: "last reboot | head -{limit}"
    params:
      limit: { type: int, default: 10, max: 30 }
    timeout: 10
    tags: [system, reboot]

  inode_usage:
    name: "Inode 使用率"
    templates:
      - platform: any
        command: "df -i | grep -v tmpfs"
    params: {}
    timeout: 10
    tags: [system, disk, inode]

  swap_usage:
    name: "Swap 使用详情"
    templates:
      - platform: any
        command: "swapon --show; echo '---'; cat /proc/swaps"
    params: {}
    timeout: 10
    tags: [system, memory, swap]
```

```yaml
# packs/users_permissions.yaml — 用户与权限命令包
pack:
  name: "Users & Permissions"
  description: "用户账户、权限变更、SUID 检测"
  platform: linux
  version: "1.0"

commands:
  passwd_changes:
    name: "系统用户列表"
    templates:
      - platform: any
        command: "awk -F: '$3 >= 1000 || $3 == 0 {print $1, $3, $6, $7}' /etc/passwd"
    params: {}
    timeout: 10
    tags: [users, persistence]

  setuid_binaries:
    name: "SUID 文件检测"
    templates:
      - platform: any
        command: "find / -xdev -perm -4000 -type f 2>/dev/null | sort"
    params: {}
    timeout: 30
    tags: [permissions, suid, privilege_escalation]

  world_writable:
    name: "全局可写目录"
    templates:
      - platform: any
        command: "find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | head -{limit}"
    params:
      limit: { type: int, default: 20, max: 50 }
    timeout: 30
    tags: [permissions, writable]

  login_history:
    name: "最近登录历史"
    templates:
      - platform: any
        command: "last -n {limit} --time-format iso"
    params:
      limit: { type: int, default: 20, max: 100 }
    timeout: 10
    tags: [users, login, audit]

  active_users:
    name: "当前活跃用户"
    templates:
      - platform: any
        command: "who -u"
    params: {}
    timeout: 10
    tags: [users, session]
```

```yaml
# packs/file_integrity.yaml — 文件完整性命令包
pack:
  name: "File Integrity"
  description: "关键配置文件变更、可疑文件检测"
  platform: linux
  version: "1.0"

commands:
  critical_config_hash:
    name: "关键配置文件哈希"
    templates:
      - platform: any
        command: "md5sum /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/ssh/sshd_config /etc/crontab 2>/dev/null"
    params: {}
    timeout: 10
    tags: [file_integrity, config]

  large_files:
    name: "大文件检测"
    templates:
      - platform: any
        command: "find / -xdev -type f -size +{min_size} 2>/dev/null | head -{limit}"
    params:
      min_size: { type: str, default: "100M" }
      limit: { type: int, default: 20, max: 50 }
    timeout: 30
    tags: [file_integrity, disk]

  tmp_suspicious:
    name: "/tmp 可疑文件"
    templates:
      - platform: any
        command: "find /tmp /var/tmp /dev/shm -type f \\( -perm -111 -o -name '*.sh' -o -name '*.py' -o -name '*.pl' \\) 2>/dev/null | head -{limit}"
    params:
      limit: { type: int, default: 30, max: 100 }
    timeout: 15
    tags: [file_integrity, suspicious, persistence]

  recently_modified:
    name: "最近修改的系统文件"
    templates:
      - platform: any
        command: "find /etc /usr/bin /usr/sbin -mtime -{days} -type f 2>/dev/null | head -{limit}"
    params:
      days: { type: int, default: 1, max: 7 }
      limit: { type: int, default: 30, max: 100 }
    timeout: 15
    tags: [file_integrity, recent_changes]

  webshell_scan:
    name: "Web 目录可疑文件"
    templates:
      - platform: any
        command: "find {web_root} -type f \\( -name '*.php' -o -name '*.jsp' -o -name '*.asp' \\) -mtime -{days} 2>/dev/null | head -{limit}"
    params:
      web_root: { type: str, default: "/var/www" }
      days: { type: int, default: 3, max: 30 }
      limit: { type: int, default: 20, max: 50 }
    timeout: 15
    tags: [file_integrity, webshell, web]
```

```yaml
# packs/processes_services.yaml — 进程与服务命令包
pack:
  name: "Processes & Services"
  description: "进程监控、服务状态、定时任务"
  platform: linux
  version: "1.0"

commands:
  suspicious_processes:
    name: "可疑进程检测"
    templates:
      - platform: any
        command: "ps aux --sort=-%cpu | head -{limit}"
    params:
      limit: { type: int, default: 20, max: 50 }
    timeout: 10
    tags: [process, cpu, suspicious]

  recent_cron_jobs:
    name: "最近 cron 执行"
    templates:
      - platform: any
        command: "journalctl -u cron --since '{since}' --no-pager | tail -{limit}"
    params:
      since: { type: str, default: "1 hour ago" }
      limit: { type: int, default: 30, max: 100 }
    timeout: 15
    tags: [process, cron, persistence]

  crontab_list:
    name: "所有用户 Crontab"
    templates:
      - platform: any
        command: "for user in $(cut -f1 -d: /etc/passwd); do crontab -l -u $user 2>/dev/null | grep -v '^#' | while read line; do echo \"$user: $line\"; done; done"
    params: {}
    timeout: 15
    tags: [process, cron, persistence, audit]

  systemd_new_services:
    name: "Systemd 服务列表"
    templates:
      - platform: any
        command: "systemctl list-unit-files --type=service --state=enabled --no-pager"
    params: {}
    timeout: 10
    tags: [process, service, persistence]

  deleted_but_running:
    name: "已删除但仍运行的进程"
    templates:
      - platform: any
        command: "ls -la /proc/*/exe 2>/dev/null | grep '(deleted)' | head -{limit}"
    params:
      limit: { type: int, default: 20, max: 50 }
    timeout: 10
    tags: [process, suspicious, malware]
```

```yaml
# packs/containers.yaml — 容器安全命令包
pack:
  name: "Container Security"
  description: "Docker / Podman 容器状态与安全检查"
  platform: linux
  version: "1.0"

commands:
  docker_containers:
    name: "Docker 容器状态"
    templates:
      - platform: any
        command: "docker ps -a --format 'table {{{{.Names}}}}\\t{{{{.Status}}}}\\t{{{{.Ports}}}}\\t{{{{.Image}}}}' 2>/dev/null || echo 'Docker not available'"
    params: {}
    timeout: 10
    tags: [container, docker, status]

  docker_privileged:
    name: "特权容器检测"
    templates:
      - platform: any
        command: "docker ps -q 2>/dev/null | xargs -I{{}} docker inspect --format '{{{{.Name}}}} Privileged={{{{.HostConfig.Privileged}}}} PidMode={{{{.HostConfig.PidMode}}}}' {{}} 2>/dev/null || echo 'Docker not available'"
    params: {}
    timeout: 15
    tags: [container, docker, privileged, security]

  docker_volumes:
    name: "容器敏感挂载"
    templates:
      - platform: any
        command: "docker ps -q 2>/dev/null | xargs -I{{}} docker inspect --format '{{{{.Name}}}} {{{{range .Mounts}}}}{{{{.Source}}}}:{{{{.Destination}}}} {{{{end}}}}' {{}} 2>/dev/null | grep -E '(/etc|/var|/root|/proc|/sys)' || echo 'No sensitive mounts found'"
    params: {}
    timeout: 15
    tags: [container, docker, mount, security]

  container_network:
    name: "容器网络模式"
    templates:
      - platform: any
        command: "docker ps -q 2>/dev/null | xargs -I{{}} docker inspect --format '{{{{.Name}}}} NetworkMode={{{{.HostConfig.NetworkMode}}}}' {{}} 2>/dev/null || echo 'Docker not available'"
    params: {}
    timeout: 10
    tags: [container, docker, network]
```

```yaml
# packs/logs.yaml — 日志分析命令包
pack:
  name: "Log Analysis"
  description: "系统日志、内核日志、审计日志"
  platform: linux
  version: "1.0"

commands:
  recent_syslog:
    name: "最近系统日志"
    templates:
      - platform: any
        command: "journalctl --since '{since}' --no-pager --priority={priority} | tail -{limit}"
    params:
      since: { type: str, default: "1 hour ago" }
      priority: { type: str, default: "warning" }
      limit: { type: int, default: 50, max: 200 }
    timeout: 15
    tags: [log, syslog]

  kernel_errors:
    name: "内核错误"
    templates:
      - platform: any
        command: "dmesg --level=err,warn | tail -{limit}"
    params:
      limit: { type: int, default: 30, max: 100 }
    timeout: 10
    tags: [log, kernel, error]

  auth_log_summary:
    name: "认证日志摘要"
    templates:
      - platform: debian
        command: "awk '{print $5}' /var/log/auth.log | cut -d'[' -f1 | sort | uniq -c | sort -nr | head -{limit}"
      - platform: any
        command: "journalctl _COMM=sshd _COMM=sudo _COMM=su --since '{since}' --no-pager | wc -l"
    params:
      limit: { type: int, default: 20, max: 50 }
      since: { type: str, default: "24 hours ago" }
    timeout: 10
    tags: [log, auth, summary]

  oom_killer:
    name: "OOM Killer 事件"
    templates:
      - platform: any
        command: "dmesg | grep -i 'out of memory\\|oom-killer\\|killed process' | tail -{limit}"
    params:
      limit: { type: int, default: 10, max: 30 }
    timeout: 10
    tags: [log, kernel, oom, memory]
```

### 3.4 用户自定义 Pack 示例

用户可在 `packs/` 目录下创建自己的 pack 文件，格式与内置 pack 完全一致：

```yaml
# packs/my_app.yaml — 用户自定义：业务应用检查
pack:
  name: "My Application"
  description: "自定义业务应用健康检查"
  platform: linux
  version: "1.0"

commands:
  app_health:
    name: "应用健康检查"
    templates:
      - platform: any
        command: "curl -sf http://localhost:{port}/health"
    params:
      port: { type: int, default: 8080 }
    timeout: 5
    tags: [custom, app, health]

  app_error_log:
    name: "应用错误日志"
    templates:
      - platform: any
        command: "tail -{limit} {log_path} | grep -i 'error\\|exception\\|fatal'"
    params:
      limit: { type: int, default: 100, max: 500 }
      log_path: { type: str, default: "/var/log/app/error.log" }
    timeout: 10
    tags: [custom, app, log]

  redis_status:
    name: "Redis 状态"
    templates:
      - platform: any
        command: "redis-cli info server 2>/dev/null | grep -E 'redis_version|uptime|connected_clients' || echo 'Redis not available'"
    params: {}
    timeout: 5
    tags: [custom, redis, status]
```

### 3.5 Pack 加载器

启动时自动扫描、加载、合并所有 pack，并根据当前平台选择匹配的命令模板：

```python
class PackLoader:
    """Pack 加载与平台自适应"""

    def __init__(self, builtin_dir: Path, custom_dir: Path | None = None):
        self._builtin_dir = builtin_dir
        self._custom_dir = custom_dir
        self._platform = self._detect_platform()
        self._commands: dict[str, ResolvedCommand] = {}

    def load(self, enabled_packs: list[str] | None = None) -> dict[str, ResolvedCommand]:
        """
        加载流程:
        1. 扫描 builtin pack 目录，按 enabled_packs 过滤
        2. 扫描 custom pack 目录（全部加载）
        3. 同名 command → 用户版覆盖内置版
        4. 每个 command 根据当前平台选择 template
        """
        # Step 1: 加载内置 pack
        for pack_file in sorted(self._builtin_dir.glob("*.yaml")):
            pack_name = pack_file.stem
            if enabled_packs and pack_name not in enabled_packs:
                logger.debug(f"跳过未启用的内置 pack: {pack_name}")
                continue
            self._load_pack_file(pack_file, source="builtin")

        # Step 2: 加载用户自定义 pack（覆盖同名命令）
        if self._custom_dir and self._custom_dir.exists():
            for pack_file in sorted(self._custom_dir.glob("*.yaml")):
                self._load_pack_file(pack_file, source="custom")

        logger.info(f"Pack 加载完成: {len(self._commands)} 条命令 "
                    f"(平台: {self._platform})")
        return self._commands

    def _load_pack_file(self, path: Path, source: str):
        """加载单个 pack 文件"""
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        pack_meta = data.get("pack", {})
        commands = data.get("commands", {})

        for cmd_id, cmd_def in commands.items():
            # 平台匹配：选择最佳 template
            template = self._select_template(cmd_def.get("templates", []))
            if template is None:
                logger.warning(f"命令 {cmd_id} 无匹配平台模板，跳过")
                continue

            if cmd_id in self._commands and source == "custom":
                logger.info(f"用户 pack 覆盖内置命令: {cmd_id}")

            self._commands[cmd_id] = ResolvedCommand(
                id=cmd_id,
                name=cmd_def["name"],
                command_template=template,
                params=cmd_def.get("params", {}),
                timeout=cmd_def.get("timeout", 10),
                tags=cmd_def.get("tags", []),
                source=source,
                pack=pack_meta.get("name", path.stem),
            )

    def _select_template(self, templates: list[dict]) -> str | None:
        """根据当前平台选择最佳匹配的命令模板"""
        # 优先精确匹配
        for t in templates:
            if t["platform"] == self._platform:
                return t["command"]
        # fallback 到 any
        for t in templates:
            if t["platform"] == "any":
                return t["command"]
        return None

    @staticmethod
    def _detect_platform() -> str:
        """检测当前 Linux 发行版族"""
        try:
            with open("/etc/os-release") as f:
                content = f.read().lower()
            if "debian" in content or "ubuntu" in content:
                return "debian"
            elif "rhel" in content or "centos" in content or "fedora" in content or "rocky" in content or "alma" in content:
                return "rhel"
            elif "arch" in content:
                return "arch"
            elif "suse" in content:
                return "suse"
        except FileNotFoundError:
            pass
        return "any"


@dataclass
class ResolvedCommand:
    """加载并解析平台后的命令定义"""
    id: str                            # 命令 ID (如 ssh_bruteforce)
    name: str                          # 人类可读名称
    command_template: str              # 已选定平台的命令模板
    params: dict                       # 参数 schema
    timeout: int                       # 超时（秒）
    tags: list[str]                    # 标签
    source: str                        # "builtin" 或 "custom"
    pack: str                          # 所属 pack 名称
```

### 3.6 混合命令模型 — 模板优先、AI 兜底

Sentinel 检查项支持两种命令来源，**模板命令优先，AI 动态生成兜底**：

```
检查请求
    │
    ├─ 有 check_id 字段？
    │   ├─ YES → 从已加载的 Pack 中查找命令模板
    │   │        └─ 找到？ → 渲染模板 + 直接执行（零 LLM 消耗）
    │   │        └─ 未找到？ → 报错并跳过
    │   │
    │   └─ NO → 有 goal 字段？
    │       ├─ YES → 发给 LLM，AI 自主决定执行什么命令
    │       │        └─ 走 CommandValidator 安全审查 → 执行
    │       │        （消耗 tokens，间隔建议 ≥ 30 分钟）
    │       └─ NO → 配置错误，报错
    │
    └─ 执行结果 → Evaluator 规则判定 / AI 判定
```

**检查策略定义（config.yaml）**：

```yaml
sentinel:
  checks:
    # 模式 1: 模板驱动（优先，快速，零 token 消耗）
    - name: "SSH 暴力破解检测"
      check_id: ssh_bruteforce         # → 从 Pack 中查找
      interval: 300
      mode: differential
      severity: high
      rule:
        type: line_count
        operator: ">"
        threshold: 5
      cooldown: 600

    # 模式 2: AI 驱动（灵活，当没有现成模板时使用）
    - name: "Docker 逃逸风险检测"
      goal: "检查 Docker 容器是否存在特权模式运行、敏感目录挂载等容器逃逸风险"
      interval: 3600                   # 间隔大，降低 token 消耗
      severity: critical
      ai_budget: 3                     # 限制 AI 最多执行 3 个命令
```

### 3.7 内置命令库全景

| Pack | 命令数 | 关键命令 |
|------|--------|---------|
| `ssh_auth` | 5 | ssh_bruteforce, ssh_success_login, ssh_authorized_keys, failed_sudo, sudoers_changes |
| `network` | 6 | active_connections, open_ports, firewall_rules, network_interfaces, dns_resolv, established_foreign |
| `system_resources` | 6 | disk_usage, memory_usage, system_load, last_reboot, inode_usage, swap_usage |
| `users_permissions` | 5 | passwd_changes, setuid_binaries, world_writable, login_history, active_users |
| `file_integrity` | 5 | critical_config_hash, large_files, tmp_suspicious, recently_modified, webshell_scan |
| `processes_services` | 5 | suspicious_processes, recent_cron_jobs, crontab_list, systemd_new_services, deleted_but_running |
| `containers` | 4 | docker_containers, docker_privileged, docker_volumes, container_network |
| `logs` | 4 | recent_syslog, kernel_errors, auth_log_summary, oom_killer |
| **合计** | **40** | |

### 3.8 检查策略数据结构

检查策略（`sentinel.checks`）定义"怎么用命令巡检"，与命令定义（Pack）分离：

```python
@dataclass
class CheckDefinition:
    """Sentinel 检查策略，定义于 config.yaml"""
    name: str                          # 人类可读名称
    # 命令来源（二选一）
    check_id: str | None               # 模板模式 → 映射 Pack 中的命令 ID
    goal: str | None                   # AI 模式 → 描述检查目标，由 AI 决定命令
    ai_budget: int                     # AI 模式下最多执行的命令数（默认 3）
    # 策略配置
    interval: int                      # 执行间隔（秒）
    args: dict                         # 命令参数（仅模板模式）
    mode: Literal["snapshot", "differential"]
    severity: Literal["info", "warning", "high", "critical"]
    rule: RuleDefinition | None        # 异常判定规则（模板模式必填，AI 模式可选）
    cooldown: int | None               # 独立冷却期


@dataclass
class RuleDefinition:
    """异常判定规则"""
    type: str                          # line_count / regex_extract / regex_match / added_count / custom_parser
    operator: str                      # > / < / >= / <= / == / !=
    threshold: int | float | str       # 数值阈值 或 "dynamic"
    pattern: str | None = None         # 正则表达式
    aggregation: str | None = None     # first / last / max / min / sum / avg
    threshold_command: str | None = None  # 动态阈值的获取命令
    parser: str | None = None          # 内置解析器名称
```

### 3.4 Differential（差异）模式

这是 Sentinel 的核心能力之一，确保 **只报告变化，不重复推送已知状态**。

```
时间线  命令输出                                 报告
──────────────────────────────────────────────────────────
T1     pid=100 port=22                          (初始基线，不报告)
       pid=200 port=80

T2     pid=100 port=22                          ✚ ADDED: pid=300 port=4444
       pid=200 port=80                          → 触发告警！
       pid=300 port=4444   ← 新增

T3     pid=100 port=22                          ✖ REMOVED: pid=300 port=4444
       pid=200 port=80                          (可选：端口消失通知)

T4     pid=100 port=22                          (无变化，静默)
       pid=200 port=80
```

**实现方式**：

```python
class DiffTracker:
    """跟踪每个检查项的上一次输出，计算差异"""

    def __init__(self):
        self._baselines: dict[str, set[str]] = {}  # check_name → 上次输出行集合

    def compute_diff(self, check_name: str, current_output: str) -> DiffResult:
        current_lines = set(current_output.strip().splitlines())
        previous_lines = self._baselines.get(check_name, None)

        # 首次执行：建立基线，不触发告警
        if previous_lines is None:
            self._baselines[check_name] = current_lines
            return DiffResult(is_first_run=True, added=set(), removed=set())

        added = current_lines - previous_lines
        removed = previous_lines - current_lines

        self._baselines[check_name] = current_lines
        return DiffResult(is_first_run=False, added=added, removed=removed)


@dataclass
class DiffResult:
    is_first_run: bool
    added: set[str]       # 新增的行
    removed: set[str]     # 消失的行
```

---

## 4. 告警分级体系（借鉴 Wazuh）

### 4.1 设计思想

Wazuh 使用 0-15 级告警体系，不同级别触发不同响应动作。ChatDome 简化为 4 级，每级对应不同的响应策略：

### 4.2 告警级别定义

| Level | 名称 | 含义 | 响应策略 |
|-------|------|------|----------|
| `info` | 信息 | 状态变化记录，无安全风险 | 仅写日志，不推送（可选纳入每日报告） |
| `warning` | 警告 | 资源接近阈值，需关注 | 推送 Telegram 简要通知，**不调用 AI 分析** |
| `high` | 严重 | 安全事件或资源临界 | 推送 Telegram + **AI 分析上下文 + 处置建议** |
| `critical` | 紧急 | 严重安全威胁，需立即处理 | 推送 Telegram + **AI 深度分析 + 处置建议 + 交互式操作按钮** |

### 4.3 告警消息模板

**Warning 级别**（直接推送，不调 AI）：

```
⚠️ [WARNING] 磁盘使用率告警

检查项: disk_usage
时间: 2026-04-14 15:30:02 UTC
规则: 最大使用率 > 85%
当前值: 92%

原始数据:
Filesystem  Size  Used Avail Use% Mounted on
/dev/sda1   50G   46G  4.0G  92% /

💡 回复任意消息可进入对话模式，获取 AI 详细分析。
```

**High / Critical 级别**（AI 分析 + 建议）：

```
🚨 [CRITICAL] 新增未知监听端口

检查项: open_ports
时间: 2026-04-14 15:30:02 UTC
规则: 新增端口数 > 0
新增:
  + tcp  0.0.0.0:4444  pid=29381 (nc)

━━━━━━━━━━━━━━━━━━━
🤖 AI 分析:
端口 4444 由 netcat (nc) 进程监听，这是一个常见的反弹 Shell 端口。
进程 PID 29381 需要立即调查。

⚡ 建议操作:
1. 查看进程详情: ps aux | grep 29381
2. 查看进程网络连接: ss -tnp | grep 29381
3. 查看进程打开的文件: ls -la /proc/29381/fd/
4. 如确认恶意，终止进程: kill -9 29381

[🔍 深入分析]  [⚡ 执行建议1]  [⚡ 执行建议2]  [❌ 忽略]
```

### 4.4 告警级别与 AI 调用关系

```
告警触发
    │
    ├─ severity == info
    │  └─ 写入 sentinel.log → 结束
    │
    ├─ severity == warning
    │  └─ 格式化原始数据 → Telegram 推送 → 结束
    │     （不调 LLM，零 token 消耗）
    │
    ├─ severity == high
    │  └─ 调 LLM 分析原始数据 → 生成建议 → Telegram 推送
    │     （约 1-2k tokens / 次）
    │
    └─ severity == critical
       └─ 调 LLM 深度分析 → 生成建议 → 附加交互按钮 → Telegram 推送
          （约 2-3k tokens / 次）
          └─ 用户点击按钮 → 进入 Agent 对话模式 → 可执行修复命令
```

---

## 5. 告警抑制系统

### 5.1 问题

不做抑制的后果：SSH 暴力破解每 5 分钟检测一次，如果攻击持续 24 小时，用户会收到 **288 条告警消息** — 这是不可接受的。

### 5.2 三层抑制策略

```
┌─────────────────────────────────────────────────────┐
│              告警抑制 Pipeline                       │
│                                                     │
│  Layer 1: Cooldown（冷却窗口）                       │
│  │  同一检查项在 cooldown 时间内不重复告警             │
│  │  默认 300 秒，可按检查项独立配置                    │
│  │                                                   │
│  ▼                                                   │
│  Layer 2: Deduplication（内容去重）                   │
│  │  如果告警内容与上次完全相同，跳过                    │
│  │  （例如磁盘使用率连续 3 次都是 92%）                │
│  │                                                   │
│  ▼                                                   │
│  Layer 3: Aggregation（聚合窗口）                     │
│  │  短时间内多个不同检查项同时触发时，                  │
│  │  合并为一条综合告警消息推送                          │
│  │  聚合窗口：10 秒                                   │
│  │                                                   │
│  ▼                                                   │
│  → 通过所有抑制层 → 推送 Telegram                     │
└─────────────────────────────────────────────────────┘
```

### 5.3 Cooldown 机制

```python
class AlertSuppressor:
    """告警抑制器"""

    def __init__(self, default_cooldown: int = 300):
        self._default_cooldown = default_cooldown
        self._last_alert_time: dict[str, float] = {}    # check_name → 上次告警时间
        self._last_alert_content: dict[str, str] = {}   # check_name → 上次告警内容哈希
        self._pending_alerts: list[AlertEvent] = []     # 聚合窗口中的待发告警
        self._aggregation_task: asyncio.Task | None = None

    def should_suppress(self, event: AlertEvent) -> bool:
        now = time.time()

        # Layer 1: Cooldown
        last_time = self._last_alert_time.get(event.check_name)
        cooldown = event.cooldown or self._default_cooldown
        if last_time and (now - last_time) < cooldown:
            return True  # 冷却中，抑制

        # Layer 2: Content Dedup
        content_hash = hashlib.md5(event.raw_output.encode()).hexdigest()
        if self._last_alert_content.get(event.check_name) == content_hash:
            return True  # 内容相同，抑制

        # 通过抑制检查，更新状态
        self._last_alert_time[event.check_name] = now
        self._last_alert_content[event.check_name] = content_hash
        return False

    async def submit(self, event: AlertEvent):
        """提交告警，自动进入聚合窗口"""
        if self.should_suppress(event):
            logger.debug(f"告警已抑制: {event.check_name}")
            return

        self._pending_alerts.append(event)

        # Layer 3: Aggregation — 启动 10 秒聚合窗口
        if self._aggregation_task is None:
            self._aggregation_task = asyncio.create_task(self._flush_after_delay())

    async def _flush_after_delay(self):
        """等待聚合窗口结束后批量发送"""
        await asyncio.sleep(10)  # 聚合窗口
        alerts = self._pending_alerts.copy()
        self._pending_alerts.clear()
        self._aggregation_task = None

        if len(alerts) == 1:
            await self._send_single_alert(alerts[0])
        else:
            await self._send_aggregated_alert(alerts)
```

### 5.4 Cooldown 升级机制

当同一告警在冷却期内持续触发时，说明问题未解决。此时自动提升提醒频率：

```
第 1 次触发 → 立即推送
  │ cooldown = 300s
第 2-5 次触发 → 抑制（冷却中）
  │
第 6 次触发 (300s 后) → 再次推送，附带 "⚠️ 此告警已持续 25 分钟"
  │ cooldown 升级为 600s
  │
第 N 次触发 (600s 后) → 推送 + "⚠️ 此告警已持续 X 小时"
  │ cooldown 升级为 1800s（上限）
  │
用户主动回复 / 问题消失 → 重置 cooldown 到初始值
```

---

## 6. AI 闭环处置（借鉴 CrowdStrike）

### 6.1 设计思想

传统监控系统的告警止步于"通知"。CrowdStrike Falcon 的核心差异是 **检测 → 上下文富化 → AI 判定 → 处置建议 → 自动/半自动响应** 的闭环。

ChatDome 的独特优势在于：**告警之后，用户可以直接在 Telegram 对话中追问、执行修复命令**，将"监控告警"与"交互式运维"无缝衔接。

### 6.2 闭环流程

```
┌──────────────────────────────────────────────────────────────────────┐
│                     AI 闭环处置流程                                   │
│                                                                      │
│  Phase 1: 检测 (Detect)                                              │
│  │  Scheduler 定时执行检查 → Evaluator 判定异常                       │
│  │                                                                   │
│  ▼                                                                   │
│  Phase 2: 上下文富化 (Enrich)                                        │
│  │  自动执行关联检查，收集更多上下文：                                  │
│  │  ├─ 触发检查: open_ports → 发现新端口 4444                        │
│  │  ├─ 自动关联: 查看对应进程 → ps aux | grep <pid>                  │
│  │  ├─ 自动关联: 查看进程网络 → ss -tnp | grep <pid>                 │
│  │  └─ 自动关联: 查看进程时间线 → ls -la /proc/<pid>                 │
│  │                                                                   │
│  ▼                                                                   │
│  Phase 3: AI 分析 (Analyze)                                          │
│  │  将原始数据 + 上下文打包发给 LLM：                                  │
│  │  ├─ 异常是什么？（定性）                                           │
│  │  ├─ 严重程度？（定级）                                             │
│  │  ├─ 可能原因？（推理）                                             │
│  │  └─ 建议操作？（处置方案，按优先级排列）                             │
│  │                                                                   │
│  ▼                                                                   │
│  Phase 4: 推送告警 (Alert)                                            │
│  │  格式化告警消息 + AI 分析结果 → Telegram 推送                       │
│  │  附加交互按钮（critical 级别）                                     │
│  │                                                                   │
│  ▼                                                                   │
│  Phase 5: 交互处置 (Respond)              ← ChatDome 独有优势         │
│  │  用户可选：                                                        │
│  │  ├─ 点击 [🔍 深入分析] → 进入 Agent 对话，AI 自主执行更多命令分析    │
│  │  ├─ 点击 [⚡ 执行建议] → 走 Human-in-Loop 审批流程执行修复命令      │
│  │  ├─ 直接回复消息 → 进入自由对话模式，追问细节                       │
│  │  └─ 点击 [❌ 忽略] → 标记已处理，加入抑制白名单                    │
│  │                                                                   │
│  ▼                                                                   │
│  Phase 6: 闭环记录 (Record)                                          │
│  │  ├─ 告警事件 → sentinel_alerts.jsonl                              │
│  │  ├─ 处置操作 → sentinel_actions.jsonl                             │
│  │  └─ 写入 memory vault → 下次分析时 AI 可参考历史                   │
│  │      "上次 4444 端口告警是测试环境的 nc 调试，已确认安全"            │
│  │                                                                   │
│  ▼                                                                   │
│  → 闭环完成。AI 下次遇到类似告警时会参考历史记录。                      │
└──────────────────────────────────────────────────────────────────────┘
```

### 6.3 AI 分析 Prompt

```python
SENTINEL_ANALYSIS_PROMPT = """你是 ChatDome Sentinel，一个 AI 驱动的主机安全告警分析引擎。

当前告警信息：
- 检查项: {check_name}
- 严重级别: {severity}
- 触发规则: {rule_description}
- 检测时间: {timestamp}

原始命令输出：
```
{raw_output}
```

{enriched_context}

历史记录：
{memory_context}

请分析以上告警并输出 JSON：
{{
    "summary": "一句话描述异常（不超过 50 字）",
    "risk_level": "low|medium|high|critical",
    "analysis": "详细分析（包括可能原因、影响范围）",
    "recommendations": [
        {{
            "priority": 1,
            "action": "建议操作的自然语言描述",
            "command": "可直接执行的命令（若适用，否则为 null）",
            "risk": "该操作的风险等级 safe|caution|dangerous"
        }}
    ],
    "related_checks": ["建议追加执行的 check_id 列表"]
}}
"""
```

### 6.4 上下文富化策略

不同检查项触发告警时，自动关联执行的额外检查：

```python
ENRICHMENT_MAP = {
    "ssh_bruteforce": [
        ("whois_lookup", "对攻击源 IP 进行归属查询"),
        ("ssh_success_login", "检查是否有暴力破解成功的记录"),
        ("active_connections", "查看当前是否有来自攻击 IP 的活跃连接"),
    ],
    "open_ports": [
        ("suspicious_processes", "查看可疑进程"),
        # 动态：根据新增端口的 PID 查看进程详情
    ],
    "suspicious_processes": [
        ("active_connections", "查看可疑进程的网络连接"),
        ("recent_cron_jobs", "检查是否通过 cron 持久化"),
    ],
    "failed_sudo": [
        ("ssh_success_login", "查看最近登录记录，确认操作者"),
    ],
    "disk_usage": [
        ("large_files", "查找大文件"),
    ],
}
```

---

## 7. 威胁态势感知（Threat Situational Awareness）

> 本章将"攻击链关联"与"威胁状态机"两个概念统一为同一套机制。
> 核心产出是 **威胁信封（Threat Envelope）**——一个结构化索引 + 自然语言叙事的双层容器，
> 它既是对历史告警的实时压缩，又是判断新告警关联性的匹配引擎。

### 7.1 设计动机

传统主机安全产品在"告警关联"上有两个极端：

| 方案 | 做法 | 缺陷 |
|------|------|------|
| 预设攻击链模板 | YAML 定义固定步骤序列，按模式匹配 | 攻击者不按剧本走，预设模板覆盖面有限 |
| 逐条 AI 分析 | 每条告警发给 LLM 判断关联性 | token 消耗不可控，延迟大 |

ChatDome Sentinel 选择第三条路：**零成本结构化预判 + 按需 AI 深度分析**。

- **结构化索引**（信封）用于高速判断"新告警跟已有状态有没有关系"——纯集合运算、零 token
- **自然语言叙事**（AI 生成）用于理解"到底发生了什么"——仅在确认关联后调用

这是在 **穷举枚举** 与 **纯自然语言** 之间的折中：

```
穷举枚举                     威胁信封                        纯自然语言
under_ssh_brute_force       结构化索引 + 自然语言叙事         "主机好像在被攻击..."
│                           │                               │
├ 能精确匹配                ├ 能精确匹配（索引层）             ├ 不能精确匹配
├ 不能表达未知场景           ├ 能表达任意场景（叙事层）         ├ 能表达任意场景
├ 不需要 AI                ├ 索引层不需要 AI                 ├ 每次都要 AI
├ 无法演化                  ├ 索引自动增长，叙事 AI 演化       ├ 能演化但成本高
└ 覆盖有限                  └ 覆盖无限                       └ 覆盖无限
```

> **核心理念**：把一个威胁状态拆成两层职责——
> **索引层** 回答"跟我有没有关系"（检索问题，不该浪费推理能力）；
> **叙事层** 回答"到底发生了什么"（理解问题，需要 AI）。
> 每一层只做自己擅长的事，互不越界。

**信封结构化示意**：

```
┌─────────────────────── ThreatEnvelope ───────────────────────┐
│                                                              │
│  ┌─── 元数据 ──────────────────────────────────────────────┐  │
│  │ envelope_id : "env-a3f7"                                │  │
│  │ created_at  : 2026-04-14T14:21:00Z                      │  │
│  │ last_updated: 2026-04-14T15:38:00Z                      │  │
│  │ alert_count : 52                                        │  │
│  │ severity    : critical                                  │  │
│  │ status      : active                                    │  │
│  │ ttl         : 3600 (动态计算, 见 7.9)                    │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌─── 索引层 (dict[str, Counter]) ─── 零 token 匹配 ──────┐  │
│  │                                                         │  │
│  │  ip:       { 45.xx.xx.12: 47,  103.xx.xx.5: 2 }        │  │
│  │  tactic:   { credential_access: 47,                     │  │
│  │              initial_access: 1,  persistence: 1 }       │  │
│  │  user:     { root: 3,  backup_svc: 1 }                 │  │
│  │  check_id: { ssh_bruteforce: 47,                        │  │
│  │              ssh_success_login: 1,                       │  │
│  │              ssh_authorized_keys: 1 }                   │  │
│  │  port:     { 22: 48 }                                   │  │
│  │  file:     { /root/.ssh/authorized_keys: 1 }            │  │
│  │                                                         │  │
│  │  ▲ Counter 值 = 出现次数 → 高频值自动获得高权重          │  │
│  │  ▲ 维度由 extract_facets() 自动提取 + AI 按需扩展        │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌─── 叙事层 (str) ─── AI 生成，仅强关联时更新 ────────────┐  │
│  │                                                         │  │
│  │  "主机正在遭受来自 45.xx.xx.12 (俄罗斯) 的 SSH 暴力      │  │
│  │   破解。14:35 root 从该 IP 登录成功，14:37 新增用户      │  │
│  │   backup_svc，14:38 authorized_keys 被修改。攻击者       │  │
│  │   已完成 SSH 公钥持久化。"                               │  │
│  │                                                         │  │
│  │  ▲ 由 NARRATIVE_UPDATE_PROMPT 驱动更新                   │  │
│  │  ▲ 保持 ≤200 字，时间线连贯                              │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌─── 生命周期 ─── 四态模型 (见 7.9) ─────────────────────┐  │
│  │                                                         │  │
│  │  active ──TTL内无新告警──▶ decaying ──TTL到期──▶         │  │
│  │    ▲  ◀──新告警命中──┘       │                          │  │
│  │    │                         └──新告警命中──▶ active     │  │
│  │    │                                                    │  │
│  │  hibernating ──HIBERNATION_MAX到期──▶ expired            │  │
│  │    ▲  ◀──新告警命中索引──┘              │               │  │
│  │    │                              归档+记忆库+恢复通知    │  │
│  │    └── decaying TTL 到期时转入                            │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### 7.2 威胁信封数据结构

```python
@dataclass
class ThreatEnvelope:
    """
    威胁信封 — 结构化索引 + 自然语言叙事的双层容器。
    
    索引层（Counter dict）: 用于零成本匹配新告警的关联性。
        每个维度是一个 Counter，key 是具体值，value 是出现次数。
        高频值自然获得高权重，无需人工设定。
    
    叙事层（AI 生成的自然语言）: 对"到底发生了什么"的实时压缩描述。
        由 AI 在关联告警被吸收时动态更新和演化。
    """

    # ── 元数据 ──
    envelope_id: str                       # 唯一 ID
    created_at: datetime                   # 创建时间
    last_updated: datetime                 # 最后更新时间
    alert_count: int                       # 已吸收的告警总数
    severity: str                          # 当前严重程度 (info/warning/high/critical)

    # ── 索引层: 多维 Counter 索引 ──
    # 每个维度是一个 Counter[str, int]
    # 维度由代码自动提取 + AI 按需扩展
    envelope: dict[str, Counter]
    # 示例:
    # {
    #     "ip":       Counter({"45.xx.xx.12": 47, "103.xx.xx.5": 2}),
    #     "tactic":   Counter({"credential_access": 47, "initial_access": 1, "persistence": 1}),
    #     "user":     Counter({"root": 3, "backup_svc": 1}),
    #     "check_id": Counter({"ssh_bruteforce": 47, "ssh_success_login": 1}),
    #     "port":     Counter({"22": 48}),
    #     "file":     Counter({"/root/.ssh/authorized_keys": 1}),
    # }

    # ── 叙事层: AI 生成的自然语言 ──
    narrative: str
    # 示例:
    # "主机正在遭受来自 45.xx.xx.12 (俄罗斯) 的 SSH 暴力破解，
    #  已持续 30 分钟，累计 2341 次尝试。14:35 root 从该 IP 登录成功，
    #  14:38 authorized_keys 被修改，攻击者已完成 SSH 公钥持久化。"

    # ── 生命周期（四态模型） ──
    status: str                            # "active" | "decaying" | "hibernating" | "expired"
    base_severity: str                     # 创建时的 severity，用于计算 base_ttl

    # ── 休眠态专用 ──
    hibernated_at: datetime | None = None  # 进入休眠的时间
    compressed_narrative: str = ""         # 休眠时叙事压缩为一行摘要

    # ── 动态 TTL 计算 ──
    @property
    def stage_count(self) -> int:
        """ATT&CK 战术阶段覆盖数 — 从索引层零成本读取"""
        return len(self.envelope.get("tactic", Counter()))

    @property
    def ttl(self) -> int:
        """
        动态 TTL = base_ttl × 阶段覆盖倍率，上限 72h。
        阶段越多 → 攻击链越长 → APT 可能性越大 → 信封存活越久。
        """
        BASE_TTL = {"warning": 900, "high": 1800, "critical": 3600}  # 15m / 30m / 60m
        STAGE_MULTIPLIER = {1: 1, 2: 4, 3: 24}                      # ×1 / ×4 / ×24
        MAX_TTL = 259200  # 72h

        base = BASE_TTL.get(self.severity, 1800)
        multiplier = STAGE_MULTIPLIER.get(self.stage_count, 72)      # 4+ stages → ×72
        return min(base * multiplier, MAX_TTL)

    @property
    def is_expired(self) -> bool:
        if self.status == "hibernating":
            if self.hibernated_at is None:
                return False
            return (datetime.utcnow() - self.hibernated_at).total_seconds() > HIBERNATION_MAX
        return (datetime.utcnow() - self.last_updated).total_seconds() > self.ttl

    @property
    def ttl_remaining(self) -> int:
        if self.status == "hibernating":
            if self.hibernated_at is None:
                return HIBERNATION_MAX
            elapsed = (datetime.utcnow() - self.hibernated_at).total_seconds()
            return max(0, int(HIBERNATION_MAX - elapsed))
        elapsed = (datetime.utcnow() - self.last_updated).total_seconds()
        return max(0, int(self.ttl - elapsed))

    def hibernate(self):
        """TTL 到期 → 转入休眠态：丢弃叙事全文，只保留索引和一行摘要"""
        self.compressed_narrative = self.narrative[:80] + "..."
        self.narrative = ""
        self.status = "hibernating"
        self.hibernated_at = datetime.utcnow()

    def reawaken(self):
        """休眠态被新告警命中 → 恢复为活跃态"""
        self.status = "active"
        self.narrative = self.compressed_narrative  # 临时恢复摘要，等 AI 重新生成
        self.compressed_narrative = ""
        self.hibernated_at = None
        self.last_updated = datetime.utcnow()


HIBERNATION_MAX = 604800  # 7 天 — 休眠态最大存活时间
```

### 7.3 ATT&CK 战术标签体系

每个 Pack 命令的 `tags` 字段中增加 ATT&CK 战术阶段标签，用于零成本判断告警的战术属性：

```yaml
# Pack YAML 中的 tags 扩展示例
ssh_bruteforce:     tags: [ssh, credential_access]       # 凭证获取
ssh_success_login:  tags: [ssh, initial_access]           # 初始访问
passwd_changes:     tags: [user, persistence]              # 持久化
ssh_authorized_keys: tags: [ssh, persistence]              # 持久化
open_ports:         tags: [network, command_and_control]   # 命令控制
suspicious_processes: tags: [process, execution]           # 执行
deleted_but_running: tags: [process, defense_evasion]      # 防御规避
crontab_list:       tags: [process, persistence]           # 持久化
webshell_scan:      tags: [file_integrity, initial_access] # 初始访问
```

**ChatDome 采用的 ATT&CK 战术阶段集**（精简适配主机安全场景）:

```python
ATTCK_TACTICS = {
    "reconnaissance",       # 侦察
    "initial_access",       # 初始访问
    "execution",            # 执行
    "persistence",          # 持久化
    "privilege_escalation", # 提权
    "defense_evasion",      # 防御规避
    "credential_access",    # 凭证获取
    "discovery",            # 发现（内网探测）
    "lateral_movement",     # 横向移动
    "collection",           # 数据收集
    "command_and_control",  # 命令控制
    "exfiltration",         # 数据外传
    "impact",               # 影响（破坏/加密）
}
```

### 7.4 告警特征提取（零 token）

每条告警到达时，自动从已有的结构化字段中提取匹配维度，不需要 AI 参与：

```python
def extract_facets(alert: dict, command_tags: list[str]) -> dict[str, set]:
    """
    从告警的结构化字段中提取匹配维度 — 纯字段映射，零 token。
    返回的 facets 用于与现有信封的索引层做集合匹配。
    """
    facets = {}

    # 从命令 tags 中提取 ATT&CK 战术标签
    tactics = set(command_tags) & ATTCK_TACTICS
    if tactics:
        facets["tactic"] = tactics

    # 从告警上下文中提取实体
    ctx = alert.get("context", {})
    if ctx.get("source_ip"):    facets["ip"] = {ctx["source_ip"]}
    if ctx.get("port"):         facets["port"] = {str(ctx["port"])}
    if ctx.get("user"):         facets["user"] = {ctx["user"]}
    if ctx.get("file"):         facets["file"] = {ctx["file"]}
    if ctx.get("process"):      facets["process"] = {ctx["process"]}
    if ctx.get("pid"):          facets["pid"] = {str(ctx["pid"])}

    # check_id 始终作为一个维度
    facets["check_id"] = {alert["check_id"]}

    return facets
```

### 7.5 信封匹配算法

```python
def match_score(envelope: dict[str, Counter], alert_facets: dict[str, set]) -> float:
    """
    通用匹配：计算新告警与信封索引的关联分数。
    
    逻辑：遍历告警的每个维度，若该维度的值存在于信封的 Counter 中，
    则累加该值的 Counter 计数作为分数。
    
    效果：高频出现的值（如频繁攻击的 IP）自然获得更高权重，
    无需人工设定任何权重参数。
    """
    score = 0.0
    for dim, values in alert_facets.items():
        if dim in envelope:
            for v in values:
                if v in envelope[dim]:
                    score += envelope[dim][v]
    return score
```

**匹配结果决策**：

```python
# 阈值可配置，默认值：
STRONG_MATCH_THRESHOLD = 2      # 匹配分 ≥ 2 → 强关联
WEAK_MATCH_THRESHOLD = 1        # 匹配分 ≥ 1 → 弱关联

score = match_score(envelope.envelope, facets)

if score >= STRONG_MATCH_THRESHOLD:
    # 强关联 → 立即吸收 + 调 AI 更新叙事
    action = "absorb_and_update"
elif score >= WEAK_MATCH_THRESHOLD:
    # 弱关联 → 先吸收索引（计数），暂不调 AI
    # 累计弱关联 ≥ 3 次后触发一次 AI 更新
    action = "absorb_silent"
else:
    # 无关联 → 进入孤立告警缓冲区
    action = "isolate"
```

### 7.6 信封吸收逻辑

```python
def absorb_alert(envelope: ThreatEnvelope, facets: dict[str, set]):
    """
    将告警的 facets 吸收进信封索引层。
    纯 Counter 累加，零 token。
    每次吸收都会重置 TTL 计时器（攻击还在继续 → 信封不过期）。
    """
    for dim, values in facets.items():
        envelope.envelope.setdefault(dim, Counter())
        for v in values:
            envelope.envelope[dim][v] += 1

    envelope.alert_count += 1
    envelope.last_updated = datetime.utcnow()
    # 吸收即续命：只要攻击还在继续，信封就不会过期
```

### 7.7 AI 叙事更新

仅在 **强关联吸收** 或 **弱关联累积触发** 时调用 AI 更新叙事：

```python
NARRATIVE_UPDATE_PROMPT = """你是 ChatDome Sentinel 威胁分析引擎。

当前威胁状态叙事：
```
{current_narrative}
```

信封索引摘要（高频维度 top-5）：
{envelope_summary}

新吸收的告警：
- 检查项: {check_name} ({check_id})
- 严重级别: {severity}
- 时间: {timestamp}
- 原始输出:
```
{raw_output}
```

请完成以下任务：
1. 更新威胁叙事：将新告警融入已有叙事，保持时间线连贯，描述攻击演进
2. 判断 severity 是否需要升级
3. 判断是否存在 ATT&CK 攻击阶段跃迁（如从"凭证获取"进入"持久化"阶段）
4. 指定需要添加到信封索引的新维度和值

输出 JSON：
{{
    "narrative": "更新后的完整叙事（保持简洁，不超过 200 字）",
    "severity": "当前严重级别 (info/warning/high/critical)",
    "stage_transition": true/false,
    "should_notify_user": true/false,
    "notify_reason": "如需推送，简述原因（如：攻击进入持久化阶段）",
    "envelope_add": {{
        "维度名": ["值1", "值2"]
    }},
    "envelope_remove": {{
        "维度名": ["值1"]
    }}
}}
"""


async def update_narrative(envelope: ThreatEnvelope, alert: dict, llm: LLMClient) -> dict:
    """
    调用 AI 更新信封叙事层。
    同时根据 AI 返回的 envelope_add/remove 更新索引层。
    """
    response = await llm.chat_completion(
        messages=[
            {"role": "system", "content": NARRATIVE_UPDATE_PROMPT.format(
                current_narrative=envelope.narrative,
                envelope_summary=format_envelope_summary(envelope.envelope),
                check_name=alert["check_name"],
                check_id=alert["check_id"],
                severity=alert["severity"],
                timestamp=alert["timestamp"],
                raw_output=alert.get("raw_output", ""),
            )}
        ]
    )
    result = json.loads(response.content)

    # 更新叙事层
    envelope.narrative = result["narrative"]
    envelope.severity = result["severity"]

    # 更新索引层（AI 指定的增量）
    for dim, values in result.get("envelope_add", {}).items():
        envelope.envelope.setdefault(dim, Counter())
        for v in values:
            if v not in envelope.envelope[dim]:
                envelope.envelope[dim][v] = 1  # AI 新增的维度初始计数为 1

    for dim, values in result.get("envelope_remove", {}).items():
        if dim in envelope.envelope:
            for v in values:
                envelope.envelope[dim].pop(v, None)

    return result


def format_envelope_summary(envelope: dict[str, Counter]) -> str:
    """将索引层格式化为人类可读摘要，供 AI prompt 使用"""
    lines = []
    for dim, counter in envelope.items():
        top5 = counter.most_common(5)
        values_str = ", ".join(f"{v}({c}次)" for v, c in top5)
        lines.append(f"  {dim}: {values_str}")
    return "\n".join(lines)
```

### 7.8 信封创建：两条路径

```
新告警到达 → 遍历所有活跃信封求匹配分
    │
    ├─ 匹配到现有信封 → 吸收（7.6 + 7.7）
    │
    └─ 所有信封都不匹配 → 进入「孤立告警缓冲区」
                          │
                          ├─ 路径 A：单条重磅告警
                          │   severity = critical
                          │   → 立即调 AI 创建新信封
                          │   → AI 生成初始叙事 + 初始索引维度
                          │   → 推送告警给用户
                          │
                          └─ 路径 B：孤立告警积累
                              定期扫描缓冲区（每 60s），按以下逻辑聚类：
                              │
                              ├─ 聚类维度: 同源 IP / 同目标用户 / 时间窗口内
                              │
                              ├─ 对每个聚类，提取覆盖的 ATT&CK 战术阶段集合
                              │
                              ├─ 触发条件:
                              │   某个聚类覆盖了 ≥2 个不同的 ATT&CK 战术阶段
                              │   AND 包含 ≥1 条 severity ≥ high
                              │
                              ├─ 不触发的情况:
                              │   磁盘满 + 内存高 + CPU 高
                              │   → 全部无战术标签 → 不触发（纯系统问题）
                              │   6 条 SSH 暴力破解
                              │   → 全是 credential_access → 同一个阶段 → 不触发
                              │
                              └─ 触发的情况:
                                  SSH 暴力破解(credential_access) + 登录成功(initial_access)
                                  → 2 个阶段 → 打包调 AI 创建新信封
```

```python
class IsolatedAlertBuffer:
    """孤立告警缓冲区"""

    def __init__(self, window: int = 3600):
        self._buffer: deque[dict] = deque()       # 未归属任何信封的告警
        self._window = window                      # 缓冲窗口（秒）

    def add(self, alert: dict, facets: dict[str, set]):
        self._buffer.append({"alert": alert, "facets": facets, "time": datetime.utcnow()})
        self._evict_expired()

    def scan_for_clusters(self) -> list[list[dict]] | None:
        """
        扫描缓冲区，尝试发现可关联的告警聚类。
        聚类条件：≥2 个不同 ATT&CK 战术阶段 + ≥1 条 high/critical。
        """
        self._evict_expired()

        # Step 1: 按 IP 聚类（同一攻击源的行为更可能关联）
        ip_clusters: dict[str, list[dict]] = {}
        no_ip: list[dict] = []
        for item in self._buffer:
            ips = item["facets"].get("ip", set())
            if ips:
                for ip in ips:
                    ip_clusters.setdefault(ip, []).append(item)
            else:
                no_ip.append(item)

        # Step 2: 对每个聚类检查战术阶段覆盖
        results = []
        for ip, items in ip_clusters.items():
            all_tactics = set()
            has_high = False
            for item in items:
                all_tactics |= item["facets"].get("tactic", set())
                if item["alert"]["severity"] in ("high", "critical"):
                    has_high = True

            if len(all_tactics) >= 2 and has_high:
                results.append(items)
                # 从缓冲区中移除已聚类的告警
                for item in items:
                    if item in self._buffer:
                        self._buffer.remove(item)

        # Step 3: 对无 IP 的告警，按时间密度聚类（5 分钟内）
        # ...（类似逻辑，此处省略）

        return results if results else None

    def _evict_expired(self):
        cutoff = datetime.utcnow() - timedelta(seconds=self._window)
        while self._buffer and self._buffer[0]["time"] < cutoff:
            self._buffer.popleft()
```

### 7.9 信封生命周期（四态模型）

传统安全系统使用固定 TTL，无法应对 APT 长周期攻击（中位驻留 21 天）。ChatDome 采用 **四态生命周期** + **动态 TTL** 双重机制：

#### 7.9.1 四态流转

```
                    ┌────────────────────────────────────────────────────┐
                    │              信封生命周期（四态模型）                │
                    │                                                    │
  创建 ─────────────┤                                                    │
  (AI 生成初始叙事)  │   ┌──────────┐                                     │
                    │   │  活跃期   │ ◄─── 新告警匹配命中                  │
                    │   │ (active)  │      → 吸收: Counter++              │
                    │   │          │      → 若强关联: AI 更新叙事          │
                    │   │          │      → 重置 TTL 计时器               │
                    │   │          │                                      │
                    │   │          │   每次吸收都续命                      │
                    │   │          │   只要攻击还在继续                    │
                    │   │          │   信封就不会过期                      │
                    │   └────┬─────┘                                      │
                    │        │                                            │
                    │        │ 动态 TTL 时间内无新告警命中                  │
                    │        ▼                                            │
                    │   ┌──────────┐                                      │
                    │   │  衰减期   │  最后一次更新后开始倒计时              │
                    │   │(decaying)│  期间仍可被新告警激活                  │
                    │   │          │  → 激活则回到活跃期                   │
                    │   └────┬─────┘                                      │
                    │        │                                            │
                    │        │ 动态 TTL 到期                               │
                    │        ▼                                            │
                    │   ┌──────────┐                                      │
                    │   │  休眠期   │  不立即归档，转入低成本休眠            │
                    │   │(hiberna- │  → 叙事压缩为一行摘要                 │
                    │   │  ting)   │  → 仅保留 Counter 索引（~200B）       │
                    │   │          │  → 持久化到 SQLite                   │
                    │   │          │  → 新告警仍可匹配索引（零 token）      │
                    │   │          │  → 命中则 reawaken → 回到活跃期       │
                    │   │          │  → HIBERNATION_MAX = 7 天             │
                    │   └────┬─────┘                                      │
                    │        │                                            │
                    │        │ 休眠超过 7 天，且未被唤醒                     │
                    │        ▼                                            │
                    │   ┌──────────┐                                      │
                    │   │  过期     │                                      │
                    │   │(expired) │  → 推送恢复通知给用户                  │
                    │   │          │  → 完整叙事写入历史存档                │
                    │   │          │  → 写入哨兵记忆库                     │
                    │   │          │  → 从活跃/休眠列表移除                 │
                    │   └──────────┘                                      │
                    └────────────────────────────────────────────────────┘
```

#### 7.9.2 动态 TTL 策略

固定 TTL 无法兼顾"噪音快过期"和"APT 长追踪"两个需求。动态 TTL 基于 ATT&CK 阶段覆盖度自动升档——阶段越多，说明攻击链越长，APT 可能性越大，信封自动获得更长的存活时间。

```
动态 TTL = min(base_ttl × stage_multiplier, MAX_TTL)

base_ttl（按当前 severity）:
  severity = warning   → 15min  (900s)
  severity = high      → 30min  (1800s)
  severity = critical  → 60min  (3600s)

stage_multiplier（按 ATT&CK 战术覆盖数，零 token，读 Counter 即可）:
  1 stage    → ×1      单阶段噪音，正常过期 (15min-1h)
  2 stages   → ×4      攻击链初现，延长至 (1h-4h)
  3 stages   → ×24     多阶段入侵确认 (6h-24h)
  4+ stages  → ×72     APT 级持久威胁 (1.5d-3d)

MAX_TTL = 72h          绝对上限

被用户主动关闭 /sentinel close <id>  → 立即归档（跳过休眠）
```

**效果示例**：

| 场景 | 阶段 | severity | 动态 TTL |
|------|------|----------|---------|
| 单次 SSH 暴力破解 | credential_access (1) | warning | 15min × 1 = **15min** |
| SSH 爆破 + 登录成功 | credential_access + initial_access (2) | high | 30min × 4 = **2h** |
| 爆破 + 登录 + 植入公钥 | 上 + persistence (3) | critical | 60min × 24 = **24h** |
| 完整 APT 链 | 4+ stages | critical | 60min × 72 = **72h** → 休眠 **7天** |

> **关键特性**：信封在活跃期每吸收一条告警就重置 TTL 计时器。如果一次 APT 攻击持续活跃了 3 天（不断有新告警命中），信封会一直处于活跃态——动态 TTL 只在攻击"暂停"后的沉默期才起作用。

#### 7.9.3 休眠态机制

休眠态是四态模型的核心创新，解决了传统系统"要么占内存，要么丢状态"的两难困境：

| 维度 | 活跃/衰减期 | 休眠期 |
|------|------------|--------|
| 内存占用 | 完整（索引+叙事） | 仅索引 (~200B) |
| 叙事层 | 完整自然语言 | 压缩为 ≤80 字符摘要 |
| 匹配参与 | 优先匹配 | 回退匹配（活跃信封无命中后再查） |
| 最大存续 | 动态 TTL (15min-72h) | HIBERNATION_MAX = 7 天 |
| 存储位置 | 内存（活跃列表） | SQLite（持久化） |

**休眠匹配流程**：

```
新告警 → extract_facets()
    │
    ├─ Step 1: 遍历活跃信封 match_score()
    │   → 命中 → 吸收（正常流程）
    │
    └─ Step 2: 活跃信封全部未命中
        → 遍历休眠信封索引 match_score()  ← 仍是 Counter 交叉，零 token
            │
            ├─ 命中 (score ≥ STRONG_MATCH_THRESHOLD)
            │   → reawaken()：恢复为活跃态
            │   → AI 生成"间隔性叙事更新"
            │      （告知距上次活动已过 N 小时/天）
            │   → 推送通知用户："休眠威胁被重新激活"
            │
            └─ 未命中 → 进入孤立告警缓冲区（正常流程）
```

**唤醒叙事 Prompt**（追加到 NARRATIVE_UPDATE_PROMPT 的上下文中）:

```python
REAWAKEN_CONTEXT = """
⚠️ 这是一个从休眠态被重新激活的信封。
上次活跃时间: {last_updated}
休眠时长: {hibernation_duration}
休眠前的摘要: {compressed_narrative}

请在叙事中体现时间间隔，例如"沉寂 N 小时后，攻击者再次现身"。
这种间隔性活动是 APT 的典型特征。
"""
```

#### 7.9.4 四态生命周期管理代码

```python
async def manage_envelope_lifecycle(envelopes: list[ThreatEnvelope],
                                     hibernating: list[ThreatEnvelope],
                                     db: SQLiteStore,
                                     alerter: TelegramAlerter,
                                     memory_vault: SentinelMemoryVault):
    """
    定期调用（每 60s），管理所有信封的状态流转。
    """
    now = datetime.utcnow()

    # 1. 活跃/衰减 → 休眠
    for env in list(envelopes):
        if env.is_expired and env.status in ("active", "decaying"):
            env.hibernate()
            envelopes.remove(env)
            hibernating.append(env)
            await db.save_hibernating_envelope(env)
            # 不推送通知 — 休眠是静默的，用户不需要知道

    # 2. 休眠 → 过期（真正归档）
    for env in list(hibernating):
        if env.is_expired:
            hibernating.remove(env)
            await db.archive_envelope(env)
            await memory_vault.learn_from_envelope(env)
            await alerter.send_recovery_notification(env)
            await db.delete_hibernating_envelope(env.envelope_id)
```

### 7.10 信封数量的自然收敛

无需人为限制信封数量。匹配机制本身就是收敛力量——攻击链上的所有告警会因为 IP / 用户 / 进程等维度交叉而被吸进同一个信封。

| 场景 | 活跃信封数 |
|------|-----------|
| 平安无事 | 0 |
| 日常噪音（偶发 SSH 爆破） | 0-1 |
| 一次完整入侵（同一攻击源） | 1（所有阶段的告警被同一个信封吸收） |
| 同时被两拨不同源 IP 攻击 | 2（IP 不交叉，各自成信封） |
| 极端情况 | 3-5（硬上限兜底，超出则淘汰最旧的低 severity 信封） |

```python
MAX_ACTIVE_ENVELOPES = 10   # 硬上限，防止资源泄漏
```

### 7.11 与告警流程的集成

```
告警到达
    │
    ├─ Step 1: 特征提取
    │   extract_facets(alert, command_tags) → facets
    │
    ├─ Step 2: 白名单检查（Section 9）
    │   WhitelistManager.is_whitelisted() → 命中则跳过
    │
    ├─ Step 3: 信封匹配
    │   遍历所有活跃信封，计算 match_score
    │   │
    │   ├─ 强关联 (score ≥ 2)
    │   │   → absorb_alert() 吸收索引
    │   │   → AI update_narrative() 更新叙事
    │   │   → AI 返回 should_notify_user?
    │   │       ├─ true (阶段跃迁) → 推送升级告警
    │   │       └─ false → 静默吸收（已在此状态中）
    │   │
    │   ├─ 弱关联 (score ≥ 1)
    │   │   → absorb_alert() 静默吸收
    │   │   → 累计弱关联 ≥ 3 次 → 触发 AI 更新
    │   │
    │   └─ 无关联
    │       → 进入 Step 3.5
    │
    ├─ Step 3.5: 休眠信封匹配（回退）
    │   遍历休眠信封索引，计算 match_score
    │   │
    │   ├─ 强关联 → reawaken() 唤醒信封
    │   │   → AI 生成间隔性叙事（含休眠时长）
    │   │   → 推送 "⚠️ 休眠威胁被重新激活"
    │   │
    │   └─ 无关联
    │       → 进入孤立告警缓冲区
    │       → 单条 critical → 立即创建新信封
    │       → 否则等待缓冲区聚类扫描
    │
    ├─ Step 4: 缓冲区定期扫描 (每 60s)
    │   scan_for_clusters()
    │   → 发现聚类 → 打包调 AI 创建新信封
    │
    └─ Step 5: 信封生命周期管理 (每 60s)
        manage_envelope_lifecycle()
        → 活跃/衰减信封 TTL 到期 → 转入休眠态（静默）
        → 休眠信封超过 7 天 → 推送恢复通知 → 归档 → 写入记忆库

    ※ 常规 Suppressor 抑制仍作为兜底（处理未进入信封的孤立告警）
```

### 7.12 威胁态势面板

用户可通过 `/sentinel status` 查看当前所有活跃信封的状态概览：

```
🛡️ ChatDome Sentinel — 威胁态势

🔴 信封 #1: SSH 暴力破解 → 持久化入侵
   叙事: 45.xx.xx.12 暴力破解 SSH 后成功登入 root，
         已植入 SSH 公钥完成持久化
   持续: 77 分钟 | 吸收告警: 52 条
   战术阶段: credential_access → initial_access → persistence
   关键实体: IP 45.xx.xx.12 (47次), user root (3次)
   状态: 🔴 critical | 动态 TTL: 24h (3阶段×24) | 剩余: 22h43m

🟡 信封 #2: 系统资源异常
   叙事: CPU 持续 90%+ 并伴随可疑高 CPU 进程 python3
   持续: 12 分钟 | 吸收告警: 4 条
   战术阶段: execution
   关键实体: process python3 (4次), pid 2847 (4次)
   状态: 🟡 high | 动态 TTL: 30m (1阶段×1) | 剩余: 18m

💤 休眠信封: 1 个
   #3: 可疑端口扫描 (休眠 2天3小时, 剩余 4天21小时)

🟢 无其他活跃威胁

📊 孤立告警缓冲区: 2 条 (均为 warning，无关联迹象)
```

### 7.13 恢复通知

信封过期时，推送恢复通知并附带完整叙事：

```
✅ 威胁已解除 — SSH 暴力破解 → 持久化入侵

━━ 完整叙事 ━━
14:21  来自 45.xx.xx.12 (俄罗斯) 的 SSH 暴力破解开始
14:35  root 账户从该 IP 登录成功（暴力破解成功）
14:37  新增用户 backup_svc
14:38  /root/.ssh/authorized_keys 被修改，植入 SSH 公钥

━━ 统计 ━━
持续时间: 77 分钟
吸收告警: 52 条
攻击阶段: credential_access → initial_access → persistence
主力攻击源: 45.xx.xx.12 (47 次命中)

此叙事已归档并写入哨兵记忆库。
```

### 7.14 成本分析

| 场景 | AI 调用 | 估算频率 |
|------|---------|---------|
| 低风险告警，无关联 | 不调 | 大部分时间 |
| 新告警与信封强关联 | 更新叙事 ~1k tokens | 攻击期间每条新线索 |
| 孤立告警积累触发新信封 | 创建叙事 ~2k tokens | 偶发 |
| 信封过期恢复 | 不调 | TTL 到期自动清理 |
| 动态 TTL 计算 | 不调（读 Counter 长度） | 每次匹配 |
| 休眠信封索引匹配 | 不调（Counter 交叉） | 活跃信封未命中时 |
| 休眠信封被唤醒 | 间隔性叙事更新 ~1.5k tokens | 极低频（APT 场景） |

**正常日均：0-3 次 AI 调用，~$0.01/天。**

### 7.15 完整示例

```
14:21  告警: ssh_bruteforce (high, ip=45.x.x.12, tactic=credential_access)
       → 无活跃信封 → severity=high，不够 critical → 进入孤立缓冲区

14:35  告警: ssh_success_login (high, ip=45.x.x.12, tactic=initial_access)
       → 孤立缓冲区扫描:
         聚类 {45.x.x.12}: credential_access + initial_access = 2 个战术阶段 ✅
         包含 high 级别 ✅
       → 触发 AI 创建信封 #1
       → AI 生成初始叙事:
         "45.x.x.12 在 14:21 开始 SSH 暴力破解，14:35 root 登录成功"
       → 初始索引: {ip: {45.x.x.12: 2}, tactic: {credential_access: 1, initial_access: 1}, ...}
       → 动态 TTL: 2 stages × high = 30min × 4 = 2h
       → 推送告警给用户

14:37  告警: passwd_changes (warning, user=backup_svc, tactic=persistence)
       → 匹配信封 #1: ip 维度无交集, check_id 无交集
         但时间窗口内同一主机 → score=0 → 弱关联不够
       → 进入孤立缓冲区

14:38  告警: ssh_authorized_keys (high, ip=45.x.x.12, tactic=persistence,
             file=/root/.ssh/authorized_keys)
       → 匹配信封 #1: ip 命中 (Counter=2, score += 2) → 强关联 ✅
       → absorb_alert(): ip[45.x.x.12] → 3, tactic += persistence, ...
       → AI update_narrative():
         叙事更新: "...14:38 authorized_keys 被修改，攻击者已完成 SSH 公钥持久化"
         AI 返回: severity → critical, stage_transition → true, should_notify → true
         AI 返回: envelope_add → {file: ["/root/.ssh/authorized_keys"]}
       → 动态 TTL 自动升档: 3 stages × critical = 60min × 24 = 24h
       → 推送升级告警: "⚠️ 攻击进入新阶段: 持久化"

       → 缓冲区中 14:37 的 passwd_changes 被重新评估:
         信封 #1 现在有 tactic=persistence
         passwd_changes 的 tactic=persistence → tactic 维度命中 (Counter=1, score=1)
         → 弱关联 → 静默吸收

次日 14:38  动态 TTL 24h 到期，期间无新告警
       → 信封 #1 转入休眠态
       → 叙事压缩: "45.x.x.12 SSH爆破→root登录→公钥持久化，52条告警..."
       → Counter 索引持久化到 SQLite（~200B）
       → 不推送通知（休眠是静默的）

次日 20:15  告警: suspicious_outbound (high, ip=45.x.x.12, tactic=command_and_control)
       → 活跃信封: 无匹配
       → 回退查询休眠信封: 信封 #1 索引命中 ip=45.x.x.12 (Counter=3, score=3) → 强关联 ✅
       → reawaken(): 信封 #1 恢复为活跃态
       → AI 间隔性叙事更新:
         "沉寂约 30 小时后，攻击者再次现身。45.x.x.12 发起可疑外联，
          疑似建立 C2 通道。此间隔性行为符合 APT 特征。"
       → 动态 TTL: 4 stages × critical = 60min × 72 = 72h
       → 推送: "⚠️ 休眠威胁被重新激活 — 可能的 APT 行为"

第 8 天  休眠超过 HIBERNATION_MAX = 7 天，最终未被唤醒
       → 推送恢复通知: "✅ 来自 45.x.x.12 的入侵活动已停止"
       → 归档完整叙事到 sentinel_alerts.jsonl
       → 写入记忆库: "45.x.x.12 曾于 2026-04-14 入侵本机并植入 SSH 公钥，
         次日疑似建立 C2 通道，展示 APT 级间隔性行为"
```

---

## 8. 交互式白名单（Interactive Whitelist）

### 8.1 设计思想

传统安全产品的白名单维护是运维人员的噩梦——要么需要登录控制台手动编辑配置文件，要么需要填写复杂的表单。这导致了两个极端：白名单几乎不维护（误报越来越多），或者白名单过度放行（安全漏洞）。

ChatDome 的独特优势在于 **Telegram 对话即管理界面**。用户可以直接用自然语言告诉 ChatDome：

> "这个 IP 是我的跳板机，忽略它的 SSH 登录"
> "8080 端口是我的业务应用，不用报警"
> "/tmp/deploy.sh 是我自己放的部署脚本，标记为安全"

AI 理解用户意图后，自动生成白名单规则并持久化存储，从此相关检查自动跳过或降级。

### 8.2 白名单规则结构

```python
@dataclass
class WhitelistRule:
    """白名单规则"""
    rule_id: str                       # 唯一 ID (自动生成)
    created_at: datetime               # 创建时间
    created_by: int                    # Telegram chat_id（谁创建的）
    source: str                        # 创建来源："natural_language" | "alert_dismiss" | "manual"

    # 匹配条件
    check_ids: list[str]               # 适用的检查项（空 = 全部）
    match_type: str                    # "ip" | "port" | "process" | "file" | "user" | "custom"
    match_pattern: str                 # 匹配模式（IP 地址、端口号、正则等）

    # 动作
    action: str                        # "suppress" (不再告警) | "downgrade" (降级为 info)
    reason: str                        # 用户说明的原因（原始自然语言）
    expires_at: datetime | None        # 过期时间（None = 永久）

    # 审计
    hit_count: int = 0                 # 命中次数
    last_hit: datetime | None = None   # 最后命中时间
```

### 8.3 自然语言白名单解析

```python
WHITELIST_PARSE_PROMPT = """你是 ChatDome 白名单管理助手。

用户通过自然语言描述了一条白名单规则，请解析为结构化的 JSON。

用户原文: "{user_input}"

请输出 JSON:
{{
    "check_ids": ["关联的检查项 ID 列表，如 ssh_bruteforce, open_ports 等"],
    "match_type": "ip|port|process|file|user|custom",
    "match_pattern": "具体的匹配值或正则",
    "action": "suppress|downgrade",
    "reason": "一句话摘要",
    "permanent": true/false,
    "confidence": 0.0-1.0
}}

注意：
- 如果用户说"忽略"/"不用报警"→ action = "suppress"
- 如果用户说"降低级别"/"标记为低风险" → action = "downgrade"
- confidence < 0.7 时应追问确认
"""


class WhitelistManager:
    """交互式白名单管理器"""

    def __init__(self, storage_path: Path, llm: LLMClient):
        self._storage_path = storage_path
        self._llm = llm
        self._rules: list[WhitelistRule] = self._load()

    async def add_from_natural_language(self, user_input: str, chat_id: int) -> dict:
        """
        从自然语言解析并添加白名单规则。
        返回解析结果供用户确认。
        """
        response = await self._llm.chat_completion(
            messages=[
                {"role": "system", "content": WHITELIST_PARSE_PROMPT.format(user_input=user_input)},
            ]
        )
        parsed = json.loads(response.content)

        if parsed["confidence"] < 0.7:
            return {
                "status": "need_clarification",
                "message": f"我理解你想将 {parsed['match_pattern']} 加入白名单，"
                           f"适用于 {', '.join(parsed['check_ids'])} 检查。"
                           f"请确认是否正确？",
                "parsed": parsed,
            }

        rule = WhitelistRule(
            rule_id=self._generate_id(),
            created_at=datetime.utcnow(),
            created_by=chat_id,
            source="natural_language",
            check_ids=parsed["check_ids"],
            match_type=parsed["match_type"],
            match_pattern=parsed["match_pattern"],
            action=parsed["action"],
            reason=parsed["reason"],
            expires_at=None if parsed["permanent"] else datetime.utcnow() + timedelta(days=30),
        )

        return {
            "status": "confirm",
            "message": f"✅ 即将添加白名单规则:\n"
                       f"• 类型: {rule.match_type}\n"
                       f"• 匹配: {rule.match_pattern}\n"
                       f"• 适用: {', '.join(rule.check_ids) or '所有检查'}\n"
                       f"• 动作: {'静默' if rule.action == 'suppress' else '降级'}\n"
                       f"• 原因: {rule.reason}\n"
                       f"• 有效期: {'永久' if not rule.expires_at else rule.expires_at.strftime('%Y-%m-%d')}\n\n"
                       f"回复「确认」以生效。",
            "pending_rule": rule,
        }

    def confirm_rule(self, rule: WhitelistRule):
        """用户确认后正式添加规则"""
        self._rules.append(rule)
        self._save()

    def is_whitelisted(self, check_id: str, context: dict) -> WhitelistRule | None:
        """
        检查本次告警是否命中白名单。
        在 Evaluator 判定异常 → Suppressor 抑制之前调用。
        """
        for rule in self._rules:
            if rule.expires_at and datetime.utcnow() > rule.expires_at:
                continue
            if rule.check_ids and check_id not in rule.check_ids:
                continue
            if self._match(rule, context):
                rule.hit_count += 1
                rule.last_hit = datetime.utcnow()
                self._save()
                return rule
        return None

    def list_rules(self) -> str:
        """格式化输出所有白名单规则（供 /sentinel whitelist 命令使用）"""
        if not self._rules:
            return "📋 白名单为空"
        lines = ["📋 当前白名单规则:\n"]
        for i, rule in enumerate(self._rules, 1):
            status = "🟢" if not rule.expires_at or datetime.utcnow() < rule.expires_at else "⚫"
            lines.append(
                f"{status} {i}. [{rule.match_type}] {rule.match_pattern}\n"
                f"   适用: {', '.join(rule.check_ids) or '全部'} | "
                f"命中: {rule.hit_count} 次 | 原因: {rule.reason}"
            )
        return "\n".join(lines)

    def remove_rule(self, rule_id: str) -> bool:
        """移除规则"""
        self._rules = [r for r in self._rules if r.rule_id != rule_id]
        self._save()
        return True
```

### 8.4 白名单触发场景

除了主动对话添加，白名单还可在以下场景自动触发：

```
┌─────────────────────────────────────────────────┐
│            白名单添加路径                         │
│                                                  │
│  路径 1: 主动对话                                 │
│  用户: "10.0.0.5 是我的跳板机，忽略它"             │
│  → AI 解析 → 确认 → 生效                         │
│                                                  │
│  路径 2: 告警处置                                 │
│  告警推送 → 用户点击 [❌ 忽略]                     │
│  → ChatDome 追问: "是否将此加入白名单？"           │
│  → 用户确认 → 自动生成 suppress 规则              │
│                                                  │
│  路径 3: Memory Vault 联动                        │
│  ChatDome 从记忆库中发现用户曾说过                 │
│  "xx 是正常的" → 主动建议添加白名单               │
│                                                  │
│  路径 4: 首次部署问询                              │
│  Sentinel 首次启动时主动询问:                      │
│  "你的服务器上有哪些已知服务？"                     │
│  → 用户回答 → 批量生成白名单                      │
└─────────────────────────────────────────────────┘
```

### 8.5 与检查流程的集成

```
检查执行 → Evaluator 判定异常
    │
    ├─ WhitelistManager.is_whitelisted()
    │   ├─ 命中 suppress → 跳过告警（仅记录日志）
    │   ├─ 命中 downgrade → 告警降级为 info
    │   └─ 未命中 → 继续正常告警流程
    │
    └─ ThreatStateMachine → Suppressor → Alerter
```

---

## 9. 哨兵记忆库（Sentinel Memory Vault）

### 9.1 设计思想

ChatDome 现有的 Memory Vault 是基于会话上下文的压缩记忆，设计目标是压缩历史对话以节省 token。但 Sentinel 守卫模式对记忆有更强的要求：

1. **独立于上下文**：记忆不应随会话过期而丢失，需要独立持久化
2. **主动获取**：Sentinel 应在首次启动时主动向用户提问，了解主机环境
3. **避免乌龙**：知道"这台服务器是 Web 服务器，8080 是正常业务端口"后，就不会把 8080 当异常端口告警
4. **持续学习**：用户的每次 dismiss、白名单操作、告警处置都应被记忆

> **核心理念**：一个好的安全助手，必须"了解"它所守护的服务器。不了解环境的安全监控，只会制造噪音。

### 9.2 记忆分类

```python
class MemoryCategory(Enum):
    """记忆分类"""
    HOST_PROFILE = "host_profile"          # 主机画像：OS、角色、业务用途
    KNOWN_SERVICES = "known_services"      # 已知服务：端口、进程、定时任务
    USER_PREFERENCES = "user_preferences"  # 用户偏好：告警阈值、关注重点
    THREAT_HISTORY = "threat_history"      # 威胁历史：过去的告警及处置结果
    ENVIRONMENT_FACTS = "environment_facts"# 环境事实：IP 段、网络拓扑、团队成员


@dataclass
class MemoryEntry:
    """记忆条目"""
    entry_id: str
    category: MemoryCategory
    content: str                           # 自然语言描述
    structured_data: dict | None           # 结构化数据（可选）
    source: str                            # "user_told" | "proactive_ask" | "alert_learning" | "auto_discovered"
    created_at: datetime
    confidence: float                      # 置信度
    referenced_count: int = 0              # 被 AI 引用次数
    last_referenced: datetime | None = None
```

### 9.3 主动问询机制

Sentinel 首次启动（或发现记忆库为空时），会主动向用户发起问询：

```python
PROACTIVE_QUESTIONS = [
    {
        "category": "host_profile",
        "question": "🛡️ Sentinel 首次启动！为了更精准的安全监控，请告诉我：\n\n"
                    "1. 这台服务器的主要用途是什么？（如 Web 服务器、数据库、CI/CD、开发机等）\n"
                    "2. 是否有跳板机或固定运维 IP？\n"
                    "3. 有没有其他需要我知道的事情？\n\n"
                    "你可以现在回答，也可以稍后通过对话随时补充。",
        "parse_prompt": "从用户的回答中提取主机画像信息...",
    },
    {
        "category": "known_services",
        "condition": "host_profile exists",  # 仅在首轮问答后触发
        "question": "感谢！还有两个问题有助于减少误报：\n\n"
                    "1. 服务器上运行了哪些业务服务？（端口号、进程名）\n"
                    "2. 有没有定期执行的 cron 任务或脚本？\n\n"
                    "了解这些后，这类活动不会被误报为异常。",
        "parse_prompt": "从用户的回答中提取已知服务信息...",
    },
]


class SentinelMemoryVault:
    """哨兵记忆库 — 独立于会话上下文的持久化记忆"""

    def __init__(self, storage_path: Path, llm: LLMClient):
        self._storage_path = storage_path
        self._llm = llm
        self._entries: list[MemoryEntry] = self._load()

    async def process_user_input(self, user_input: str, chat_id: int) -> list[MemoryEntry]:
        """
        从用户输入中提取可记忆的信息。
        在 Agent 对话和主动问询回答中调用。
        """
        response = await self._llm.chat_completion(
            messages=[
                {"role": "system", "content": MEMORY_EXTRACT_PROMPT},
                {"role": "user", "content": user_input},
            ]
        )
        extracted = json.loads(response.content)
        new_entries = []
        for item in extracted.get("memories", []):
            entry = MemoryEntry(
                entry_id=self._generate_id(),
                category=MemoryCategory(item["category"]),
                content=item["content"],
                structured_data=item.get("structured_data"),
                source="user_told",
                created_at=datetime.utcnow(),
                confidence=item.get("confidence", 0.9),
            )
            new_entries.append(entry)
            self._entries.append(entry)

        if new_entries:
            self._save()
        return new_entries

    def learn_from_alert(self, alert: dict, user_action: str):
        """
        从告警处置中学习。
        用户 dismiss/whitelist 某个告警时自动记忆。
        """
        entry = MemoryEntry(
            entry_id=self._generate_id(),
            category=MemoryCategory.THREAT_HISTORY,
            content=f"用户将 {alert['check_name']} 告警标记为 {user_action}. "
                    f"原因: {alert.get('dismiss_reason', '未说明')}",
            structured_data={
                "check_id": alert["check_id"],
                "action": user_action,
                "context": alert.get("context", {}),
            },
            source="alert_learning",
            created_at=datetime.utcnow(),
            confidence=1.0,
        )
        self._entries.append(entry)
        self._save()

    def get_context_for_analysis(self, check_id: str) -> str:
        """
        为 AI 分析提供记忆上下文。
        根据 check_id 检索相关记忆，避免产生误判。
        """
        relevant = []
        for entry in self._entries:
            # 按关联度筛选
            if entry.category == MemoryCategory.THREAT_HISTORY:
                if entry.structured_data and entry.structured_data.get("check_id") == check_id:
                    relevant.append(entry)
            elif entry.category in (MemoryCategory.KNOWN_SERVICES, MemoryCategory.HOST_PROFILE):
                relevant.append(entry)  # 主机画像和已知服务始终提供

        if not relevant:
            return "（无历史记忆）"

        lines = ["=== 哨兵记忆 ==="]
        for entry in relevant[-10:]:  # 最多取最近 10 条
            entry.referenced_count += 1
            entry.last_referenced = datetime.utcnow()
            lines.append(f"[{entry.category.value}] {entry.content}")

        self._save()
        return "\n".join(lines)

    def get_summary(self) -> str:
        """生成记忆库摘要（用于每日报告或 /sentinel memory 命令）"""
        by_category = {}
        for entry in self._entries:
            by_category.setdefault(entry.category.value, []).append(entry)

        lines = ["🧠 哨兵记忆库摘要:\n"]
        for cat, entries in by_category.items():
            lines.append(f"📁 {cat}: {len(entries)} 条")
            for e in entries[-3:]:  # 每类展示最近 3 条
                lines.append(f"   • {e.content[:60]}...")
        return "\n".join(lines)

    def needs_onboarding(self) -> bool:
        """判断是否需要执行首次问询"""
        return not any(
            e.category == MemoryCategory.HOST_PROFILE for e in self._entries
        )
```

### 9.4 记忆与告警分析的联动

```
告警分析流程（融入记忆）
    │
    ├─ 触发: ssh_bruteforce → source_ip = 10.0.0.5
    │
    ├─ MemoryVault.get_context_for_analysis("ssh_bruteforce")
    │   → [host_profile] "这是一台 Web 服务器"
    │   → [known_services] "10.0.0.5 是运维跳板机"
    │   → [threat_history] "10.0.0.5 上次触发告警后用户标记为白名单"
    │
    ├─ AI 分析时将记忆上下文注入 prompt
    │   → AI: "来源 IP 10.0.0.5 在记忆库中标记为运维跳板机，
    │          且用户曾将其加入白名单。本次为正常运维访问，
    │          建议自动降级为 info。"
    │
    └─ 避免了一次误报（乌龙）
```

### 9.5 持久化存储

```json
// chat_data/sentinel_memory.json
{
    "version": 1,
    "entries": [
        {
            "entry_id": "mem_001",
            "category": "host_profile",
            "content": "这是一台 Ubuntu 22.04 Web 服务器，运行 Nginx + Python Flask 应用",
            "structured_data": {
                "os": "Ubuntu 22.04",
                "role": "web_server",
                "services": ["nginx", "flask"]
            },
            "source": "proactive_ask",
            "created_at": "2026-04-14T10:00:00Z",
            "confidence": 0.95,
            "referenced_count": 23,
            "last_referenced": "2026-04-20T15:30:00Z"
        },
        {
            "entry_id": "mem_002",
            "category": "known_services",
            "content": "8080 端口是 Flask 业务应用，10.0.0.5 是运维跳板机 IP",
            "structured_data": {
                "known_ports": [8080],
                "known_ips": ["10.0.0.5"]
            },
            "source": "user_told",
            "created_at": "2026-04-14T10:05:00Z",
            "confidence": 1.0,
            "referenced_count": 15,
            "last_referenced": "2026-04-20T14:00:00Z"
        }
    ]
}
```

---

## 10. 调度器设计

### 10.1 Scheduler 核心逻辑

```python
class SentinelScheduler:
    """7×24 巡检调度器，基于 asyncio 实现"""

    def __init__(self, checks: list[CheckDefinition], commands: dict[str, ResolvedCommand],
                 sandbox: CommandSandbox, llm: LLMClient, bot: TelegramBot,
                 suppressor: AlertSuppressor):
        self._checks = checks
        self._commands = commands       # Pack 加载后的命令集
        self._sandbox = sandbox
        self._llm = llm
        self._bot = bot
        self._suppressor = suppressor
        self._diff_tracker = DiffTracker()
        self._tasks: list[asyncio.Task] = []
        self._running = False

    async def start(self):
        """启动所有检查项的定时任务"""
        self._running = True
        for check in self._checks:
            task = asyncio.create_task(self._run_check_loop(check))
            self._tasks.append(task)
        logger.info(f"Sentinel 已启动，{len(self._checks)} 个检查项就绪")

    async def stop(self):
        """优雅停止所有任务"""
        self._running = False
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        logger.info("Sentinel 已停止")

    async def _run_check_loop(self, check: CheckDefinition):
        """单个检查项的循环执行"""
        # 启动时随机延迟 0-30 秒，避免所有检查同时执行
        await asyncio.sleep(random.uniform(0, 30))

        while self._running:
            try:
                await self._execute_check(check)
            except Exception as e:
                logger.error(f"检查项 {check.name} 执行异常: {e}")
            await asyncio.sleep(check.interval)

    async def _execute_check(self, check: CheckDefinition):
        """执行单次检查"""
        if check.check_id:
            # 模板模式：从 Pack 命令集中查找并执行
            output = await self._execute_template_check(check)
        elif check.goal:
            # AI 模式：让 LLM 自主决定命令
            output = await self._execute_ai_check(check)
        else:
            logger.error(f"检查项 {check.name} 缺少 check_id 或 goal")
            return

        if output is None:
            return

        # Step 2: Differential 处理（如果是 differential 模式）
        if check.mode == "differential":
            diff = self._diff_tracker.compute_diff(check.name, output)
            if diff.is_first_run:
                logger.info(f"检查项 {check.name} 首次执行，建立基线")
                return
            if not diff.added:
                return  # 无新增内容，静默
            output = "\n".join(diff.added)  # 只用新增内容做规则判定

        # Step 3: 规则判定（模板模式必须有 rule，AI 模式可选）
        if check.rule:
            is_anomaly = self._evaluate_rule(check.rule, output)
            if not is_anomaly:
                return  # 正常，静默

        # Step 4: 构造告警事件
        event = AlertEvent(
            check_name=check.name,
            check_id=check.check_id or "ai_check",
            severity=check.severity,
            rule_description=str(check.rule) if check.rule else "AI 判定",
            raw_output=output,
            cooldown=check.cooldown,
            timestamp=datetime.utcnow(),
        )

        # Step 5: 提交到抑制器
        await self._suppressor.submit(event)

    async def _execute_template_check(self, check: CheckDefinition) -> str | None:
        """模板模式：从 Pack 中查找命令并执行"""
        cmd = self._commands.get(check.check_id)
        if not cmd:
            logger.error(f"检查项 {check.name} 引用的命令 {check.check_id} 未在 Pack 中找到")
            return None

        # 渲染模板参数
        command_str = cmd.command_template.format(**{
            **{k: v.get("default") for k, v in cmd.params.items()},
            **(check.args or {}),
        })

        result = await self._sandbox.execute_raw(command_str, timeout=cmd.timeout)
        if result.return_code != 0:
            logger.warning(f"检查项 {check.name} 命令执行失败: {result.stderr}")
            return None
        return result.stdout

    async def _execute_ai_check(self, check: CheckDefinition) -> str | None:
        """AI 模式：让 LLM 自主决定并执行命令"""
        response = await self._llm.chat_completion(
            messages=[
                {"role": "system", "content": AI_CHECK_PROMPT},
                {"role": "user", "content": f"检查目标: {check.goal}\n预算: 最多执行 {check.ai_budget} 个命令"},
            ],
            tools=SENTINEL_AI_TOOLS,
        )
        # 执行 AI 选择的命令（受 ai_budget 限制），收集输出
        # ... (复用 Agent ReAct 循环的简化版)
        return combined_output
```

### 10.2 规则引擎

```python
class RuleEvaluator:
    """轻量级规则引擎"""

    def evaluate(self, rule: RuleDefinition, output: str) -> bool:
        """返回 True 表示异常"""

        if rule.type == "line_count":
            value = len(output.strip().splitlines()) if output.strip() else 0
            return self._compare(value, rule.operator, rule.threshold)

        elif rule.type == "regex_extract":
            matches = re.findall(rule.pattern, output)
            if not matches:
                return False
            values = [float(m) for m in matches]
            value = self._aggregate(values, rule.aggregation)
            return self._compare(value, rule.operator, rule.threshold)

        elif rule.type == "regex_match":
            matches = re.findall(rule.pattern, output, re.MULTILINE)
            if rule.operator == "count>":
                return len(matches) > rule.threshold
            return len(matches) > 0

        elif rule.type == "added_count":
            # differential 模式下，output 已经是新增行
            count = len(output.strip().splitlines()) if output.strip() else 0
            return self._compare(count, rule.operator, rule.threshold)

        elif rule.type == "custom_parser":
            parser_fn = CUSTOM_PARSERS.get(rule.parser)
            if not parser_fn:
                logger.error(f"未知的自定义解析器: {rule.parser}")
                return False
            value = parser_fn(output)
            return self._compare(value, rule.operator, rule.threshold)

        return False

    @staticmethod
    def _compare(value: float, operator: str, threshold: float) -> bool:
        ops = {">": gt, "<": lt, ">=": ge, "<=": le, "==": eq, "!=": ne}
        return ops[operator](value, threshold)

    @staticmethod
    def _aggregate(values: list[float], method: str) -> float:
        return {"max": max, "min": min, "sum": sum, "avg": lambda v: sum(v)/len(v),
                "first": lambda v: v[0], "last": lambda v: v[-1]}[method](values)


# ── 内置解析器 ──

def _parse_memory_percent(output: str) -> float:
    """从 free -h 输出中计算内存使用百分比"""
    for line in output.splitlines():
        if line.startswith("Mem:"):
            parts = line.split()
            total = _parse_size(parts[1])
            used = _parse_size(parts[2])
            return (used / total) * 100 if total > 0 else 0
    return 0

CUSTOM_PARSERS = {
    "memory_percent": _parse_memory_percent,
}
```

---

## 11. 每日巡检报告

### 11.1 设计

每天定时推送一份汇总报告，让用户知道 Sentinel 在正常工作，同时提供系统健康概览。

### 11.2 报告格式

```
📋 ChatDome Sentinel 每日巡检报告
2026-04-14 09:00 UTC

━━━ 系统健康概览 ━━━
🟢 CPU 负载:    0.42 (4 核)
🟢 内存使用:    62%
🟡 磁盘使用:    78% (/) ← 接近告警阈值 85%
🟢 监听端口:    4 个 (无变化)
🟢 SSH 安全:    无暴力破解
🟢 系统日志:    无内核错误

━━━ 过去 24 小时告警统计 ━━━
🚨 Critical: 0
⚠️ High:     1 (SSH 暴力破解, 已抑制)
⚡ Warning:   2 (磁盘使用率)
ℹ️ Info:      5

━━━ 值得关注 ━━━
• 磁盘使用率持续上升: 72% → 78% (7天趋势)
• 来自 185.220.101.x 的 SSH 暴力破解仍在持续

💡 回复任意消息可进入 AI 对话模式。
```

### 11.3 实现

```python
async def generate_daily_report(self) -> str:
    """生成每日巡检报告"""
    results = {}
    for check in self._checks:
        result = await self._sandbox.execute_security_check(check.check_id, check.args)
        results[check.check_id] = result.stdout

    # 获取过去 24h 告警统计
    alert_stats = self._get_alert_stats(hours=24)

    # AI 汇总（将所有原始数据 + 统计发给 LLM 生成报告）
    report = await self._llm.chat_completion(
        messages=[
            {"role": "system", "content": DAILY_REPORT_PROMPT},
            {"role": "user", "content": json.dumps(results) + "\n\n" + json.dumps(alert_stats)}
        ]
    )
    return report.content
```

---

## 12. 持久化与日志

### 12.1 文件结构

```
chat_data/
├── sentinel_alerts.jsonl        # 告警事件流水（JSONL 格式，可审计）
├── sentinel_actions.jsonl       # 用户处置操作记录
├── sentinel_baselines.json      # Differential 模式的基线快照
├── sentinel_whitelist.json      # ★ 交互式白名单规则
├── sentinel_memory.json         # ★ 哨兵记忆库（独立于会话上下文）
├── sentinel_daily/              # 每日报告归档
│   ├── 2026-04-13.md
│   └── 2026-04-14.md
└── {chat_id}_memory.json        # 现有 memory vault（会话级压缩记忆）
```

### 12.2 告警事件格式

```json
{
    "timestamp": "2026-04-14T15:30:02Z",
    "check_name": "新增监听端口",
    "check_id": "open_ports",
    "severity": "critical",
    "rule": "added_count > 0",
    "raw_output": "tcp 0.0.0.0:4444 pid=29381 (nc)",
    "ai_analysis": "端口 4444 由 netcat 监听，疑似反弹 Shell...",
    "suppressed": false,
    "user_action": "investigate",
    "resolved_at": "2026-04-14T15:35:18Z"
}
```

---

## 13. 模块结构

```
ChatDome/
├── packs/                               # ★ 用户自定义命令库（永不被升级覆盖）
│   └── my_app.yaml                      #   用户业务检查
├── config.yaml                          #   主配置（引用 pack + 定义检查策略）
└── controlplane/src/chatdome/
    ├── packs/                           # ★ 内置命令库（随代码发布，升级可覆盖）
    │   ├── ssh_auth.yaml                #   SSH / 认证 (5 条)
    │   ├── network.yaml                 #   网络 (6 条)
    │   ├── system_resources.yaml        #   系统资源 (6 条)
    │   ├── users_permissions.yaml       #   用户 / 权限 (5 条)
    │   ├── file_integrity.yaml          #   文件完整性 (5 条)
    │   ├── processes_services.yaml      #   进程 / 服务 (5 条)
    │   ├── containers.yaml              #   容器 (4 条)
    │   └── logs.yaml                    #   日志 (4 条)
    │                                    #   合计 ~40 条内置命令
    ├── sentinel/                        # ★ Sentinel 引擎（新增模块）
    │   ├── __init__.py
    │   ├── scheduler.py                 #   定时调度器
    │   ├── pack_loader.py               #   Pack 加载器 + 平台自适应
    │   ├── checks.py                    #   检查策略定义 + YAML 加载
    │   ├── evaluator.py                 #   规则引擎
    │   ├── diff.py                      #   Differential 差异追踪
    │   ├── suppressor.py                #   告警抑制（Cooldown + Dedup + Aggregation）
    │   ├── envelope.py                  #   ★ 威胁信封（双层架构：索引层 + 叙事层）
    │   ├── whitelist.py                 #   ★ 交互式白名单管理
    │   ├── memory_vault.py              #   ★ 哨兵记忆库（独立持久化）
    │   ├── alerter.py                   #   告警消息格式化 + AI 分析 + Telegram 推送
    │   ├── enrichment.py                #   上下文富化（关联检查）
    │   ├── report.py                    #   每日巡检报告
    │   └── prompts.py                   #   Sentinel 专用 AI Prompt
    ├── agent/                           # 现有
    ├── executor/                        # 现有（复用 CommandSandbox）
    ├── llm/                             # 现有（复用 LLMClient）
    └── telegram/                        # 现有（复用 + 扩展推送能力）
```

---

## 14. 配置扩展

在现有 `config.example.yaml` 中追加 `sentinel` 段，**命令定义与检查策略分离**：

```yaml
chatdome:
  # ... 现有 telegram / ai / agent 配置 ...

  sentinel:
    enabled: false                     # 默认关闭，显式开启
    alert_chat_ids: []                 # 告警推送目标（空 = 使用 telegram.allowed_chat_ids）

    # 命令库
    builtin_packs:                     # 启用的内置 pack（省略 = 全部加载）
      - ssh_auth
      - network
      - system_resources
      - processes_services
      - logs
      # - users_permissions            # 按需启用
      # - file_integrity
      # - containers
    custom_packs_dir: "./packs"        # 用户自定义 pack 目录

    # 告警抑制
    default_cooldown: 300              # 默认冷却期（秒）
    max_cooldown: 1800                 # 冷却期上限（秒）
    aggregation_window: 10             # 聚合窗口（秒）

    # 每日报告
    daily_report: true
    daily_report_time: "09:00"         # UTC

    # AI 分析
    ai_analysis_min_severity: "high"   # 最低触发 AI 分析的级别

    # 检查策略列表（引用 Pack 中的命令 ID）
    checks:
      # 模板驱动检查
      - name: "SSH 暴力破解检测"
        check_id: ssh_bruteforce
        interval: 300
        mode: differential
        severity: high
        rule:
          type: line_count
          operator: ">"
          threshold: 5
        cooldown: 600

      - name: "磁盘使用率"
        check_id: disk_usage
        interval: 600
        mode: snapshot
        severity: warning
        rule:
          type: regex_extract
          pattern: '(\d+)%'
          aggregation: max
          operator: ">"
          threshold: 85

      - name: "新增监听端口"
        check_id: open_ports
        interval: 120
        mode: differential
        severity: critical
        rule:
          type: added_count
          operator: ">"
          threshold: 0

      # AI 驱动检查（兆底）
      - name: "Docker 逃逸风险检测"
        goal: "检查 Docker 容器是否存在特权模式运行、敏感目录挂载等容器逃逸风险"
        interval: 3600
        severity: critical
        ai_budget: 3
```

---

## 15. 启动集成

Sentinel 作为 Bot 的子任务启动，与 Telegram polling 共享同一个 asyncio 事件循环：

```python
# main.py 中的变更

async def post_init(application):
    """Bot 启动后初始化 Sentinel"""
    if config.sentinel.enabled:
        # Step 1: 加载 Pack 命令库
        pack_loader = PackLoader(
            builtin_dir=Path(__file__).parent / "packs",
            custom_dir=Path(config.sentinel.custom_packs_dir) if config.sentinel.custom_packs_dir else None,
        )
        commands = pack_loader.load(enabled_packs=config.sentinel.builtin_packs)

        # Step 2: 加载检查策略
        checks = load_checks(config.sentinel.checks)

        # Step 3: 启动 Sentinel
        sentinel = SentinelScheduler(
            checks=checks,
            commands=commands,
            sandbox=sandbox,
            llm=llm_client,
            bot=application.bot,
            suppressor=AlertSuppressor(config.sentinel.default_cooldown),
        )
        application.bot_data["sentinel"] = sentinel
        await sentinel.start()
        logger.info("Sentinel 守卫模式已启动")

async def post_shutdown(application):
    """Bot 关闭时停止 Sentinel"""
    sentinel = application.bot_data.get("sentinel")
    if sentinel:
        await sentinel.stop()

# app.post_init = post_init
# app.post_shutdown = post_shutdown
```

**启动输出更新**：

```
==============================================================
  ChatDome v0.2.0 — AI Host Security Assistant
==============================================================
  Model:    gpt-4o
  Base URL: https://api.openai.com/v1
  Allowed chats: [123456789]
  Generated commands: false
  ── Sentinel ──
  Status:   ✅ ACTIVE
  Platform: debian
  Packs:    5 builtin + 1 custom (34 commands loaded)
  Checks:   9 items (3 critical, 3 high, 3 warning)
  Cooldown: 300s (default) / 1800s (max)
  Daily report: 09:00 UTC → [123456789]
==============================================================
```
```

---

## 16. 成本分析

### 16.1 LLM Token 消耗

| 场景 | 频率 | 每次消耗 | 日均消耗 |
|------|------|----------|----------|
| 正常巡检（无异常） | 持续 | 0 tokens | **0** |
| Warning 告警 | ~5 次/天 | 0 tokens（不调 AI） | **0** |
| High 告警 + AI 分析 | ~2 次/天 | ~1.5k tokens | **~3k tokens** |
| Critical 告警 + 深度分析 | ~0.5 次/天 | ~3k tokens | **~1.5k tokens** |
| 每日报告 | 1 次/天 | ~3k tokens | **~3k tokens** |
| **日均总计** | | | **~7.5k tokens** |

以 GPT-4o 价格估算：约 **$0.02-0.05/天**，几乎可忽略。

### 16.2 系统资源

- **CPU**：每次检查 = 一次 shell 命令执行，消耗极低
- **内存**：Scheduler + DiffTracker + Suppressor 状态，估计 < 10MB
- **磁盘 I/O**：JSONL 日志写入，可忽略
- **网络**：仅异常时调用 LLM API + Telegram API

---

## 17. 实现分期

### Phase 1：基础巡检（MVP）

- [ ] `sentinel/pack_loader.py` — Pack 加载器 + 平台检测 + 模板选择
- [ ] `packs/ssh_auth.yaml` + `packs/system_resources.yaml` + `packs/logs.yaml` — 3 个核心内置 pack
- [ ] `sentinel/scheduler.py` — asyncio 定时调度器
- [ ] `sentinel/checks.py` — 检查策略 YAML 加载 + CheckDefinition
- [ ] `sentinel/evaluator.py` — 规则引擎（line_count + regex_extract）
- [ ] `sentinel/alerter.py` — Telegram 直接推送（不含 AI 分析）
- [ ] `sentinel/suppressor.py` — Cooldown 抑制
- [ ] 配置扩展 + 启动集成
- [ ] 迁移 `registry.py` 硬编码命令到 Pack YAML

### Phase 2：智能告警

- [ ] 剩余 5 个内置 pack（network, users_permissions, file_integrity, processes_services, containers）
- [ ] `sentinel/diff.py` — Differential 差异追踪
- [ ] `sentinel/enrichment.py` — 上下文富化
- [ ] `sentinel/prompts.py` — AI 分析 Prompt
- [ ] alerter 集成 AI 分析（high/critical 级别）
- [ ] 交互式按钮（深入分析 / 执行建议 / 忽略）
- [ ] 告警 → Agent 对话模式无缝衔接
- [ ] 用户自定义 pack 加载 + 同名覆盖逻辑

### Phase 3：闭环运营

- [ ] `sentinel/report.py` — 每日巡检报告
- [ ] 告警事件持久化 + 历史统计
- [ ] Cooldown 自动升级机制
- [ ] 聚合窗口批量推送
- [ ] AI 兜底模式（goal 字段驱动）
- [ ] `/sentinel` 命令（查看状态、手动触发巡检、列出已加载 pack）

### Phase 4：威胁态势感知与记忆（ChatDome 独有）

- [ ] `sentinel/envelope.py` — 威胁信封核心（ThreatEnvelope 双层架构）
- [ ] 告警特征提取（extract_facets）+ ATT&CK 战术标签扩展
- [ ] Counter 多维索引匹配（match_score）+ 信封吸收（absorb_alert）
- [ ] AI 叙事更新（update_narrative）+ 信封索引增量管理
- [ ] 孤立告警缓冲区 + 聚类扫描（ATT&CK 阶段覆盖度触发）
- [ ] 信封生命周期管理（活跃 → 衰减 → 过期 → 归档）
- [ ] 恢复通知推送 + 完整叙事归档
- [ ] `/sentinel status` — 威胁态势面板
- [ ] `sentinel/whitelist.py` — 交互式白名单管理
- [ ] 自然语言白名单规则解析 + 用户确认流程
- [ ] 告警处置时自动建议添加白名单
- [ ] `sentinel/memory_vault.py` — 哨兵记忆库
- [ ] 首次启动主动问询（主机画像 + 已知服务）
- [ ] 从告警处置中自动学习
- [ ] AI 分析时注入记忆上下文（防乌龙误报）
