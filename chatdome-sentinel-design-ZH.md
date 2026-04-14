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

## 7. 调度器设计

### 7.1 Scheduler 核心逻辑

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

### 7.2 规则引擎

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

## 8. 每日巡检报告

### 8.1 设计

每天定时推送一份汇总报告，让用户知道 Sentinel 在正常工作，同时提供系统健康概览。

### 8.2 报告格式

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

### 8.3 实现

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

## 9. 持久化与日志

### 9.1 文件结构

```
chat_data/
├── sentinel_alerts.jsonl        # 告警事件流水（JSONL 格式，可审计）
├── sentinel_actions.jsonl       # 用户处置操作记录
├── sentinel_baselines.json      # Differential 模式的基线快照
├── sentinel_daily/              # 每日报告归档
│   ├── 2026-04-13.md
│   └── 2026-04-14.md
└── {chat_id}_memory.json        # 现有 memory vault，追加 sentinel 上下文
```

### 9.2 告警事件格式

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

## 10. 模块结构

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

## 11. 配置扩展

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

## 12. 启动集成

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

## 13. 成本分析

### 13.1 LLM Token 消耗

| 场景 | 频率 | 每次消耗 | 日均消耗 |
|------|------|----------|----------|
| 正常巡检（无异常） | 持续 | 0 tokens | **0** |
| Warning 告警 | ~5 次/天 | 0 tokens（不调 AI） | **0** |
| High 告警 + AI 分析 | ~2 次/天 | ~1.5k tokens | **~3k tokens** |
| Critical 告警 + 深度分析 | ~0.5 次/天 | ~3k tokens | **~1.5k tokens** |
| 每日报告 | 1 次/天 | ~3k tokens | **~3k tokens** |
| **日均总计** | | | **~7.5k tokens** |

以 GPT-4o 价格估算：约 **$0.02-0.05/天**，几乎可忽略。

### 13.2 系统资源

- **CPU**：每次检查 = 一次 shell 命令执行，消耗极低
- **内存**：Scheduler + DiffTracker + Suppressor 状态，估计 < 10MB
- **磁盘 I/O**：JSONL 日志写入，可忽略
- **网络**：仅异常时调用 LLM API + Telegram API

---

## 14. 实现分期

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
- [ ] Memory Vault 集成（AI 参考历史告警）
- [ ] AI 兆底模式（goal 字段驱动）
- [ ] `/sentinel` 命令（查看状态、手动触发巡检、列出已加载 pack）
