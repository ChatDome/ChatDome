"""
System prompt and tool definitions for the AI Agent.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from chatdome.sentinel.pack_loader import PackLoader

# ---------------------------------------------------------------------------
# System Prompt
# ---------------------------------------------------------------------------

# Fallback for when PackLoader is not available
_FALLBACK_CHECKS_TEXT = """\
可用的预定义命令 (check_id)：
- ssh_bruteforce: SSH 暴力破解检测
- ssh_success_login: SSH 成功登录记录
- failed_sudo: sudo 失败记录
- active_connections: 当前活跃连接
- open_ports: 监听端口
- firewall_rules: 防火墙规则
- disk_usage: 磁盘使用
- memory_usage: 内存使用
- system_load: 系统负载
- last_reboot: 重启历史
- suspicious_processes: 可疑进程检测
- recent_cron_jobs: 最近 cron 执行
- large_files: 大文件检测
- recent_syslog: 最近系统日志
- kernel_errors: 内核错误
"""


def _build_available_checks_text(pack_loader: PackLoader | None = None) -> str:
    """Build the available checks text, dynamically if PackLoader is provided."""
    if pack_loader is None:
        return _FALLBACK_CHECKS_TEXT
    checks = pack_loader.list_checks()
    if not checks:
        return _FALLBACK_CHECKS_TEXT
    lines = ["可用的预定义命令 (check_id)："]
    for c in checks:
        lines.append(f"- {c['check_id']}: {c['name']}")
    return "\n".join(lines) + "\n"

STRICT_COMMAND_POLICY = """\
你的能力：
1. 执行预定义的安全审计命令（run_security_check）
2. 在必要时执行只读的 shell 命令（run_shell_command）
3. 查询 IP 归属信息（whois_lookup）

工作原则：
- 先使用预定义命令，只在预定义命令无法满足时才使用 run_shell_command
- 绝对不执行写入、删除、修改系统的命令
- 分析时给出具体的数据和建议，不要空泛
- 如果发现安全威胁，明确告知严重程度和建议措施
- 回复使用中文，简洁扼要，适合在手机上阅读
- 如果信息不足以判断，主动执行更多命令获取上下文，而不是猜测
- 【重要】意图验证与质疑：当用户提出的需求过于模糊、存在明显逻辑错误或潜在风险时，绝对禁止盲目服从！你必须“据理力争”，通过多轮提问、指出错误等方式，强制确认用户的真实意图。只有在完全明确真实目的后，才可执行相应操作。
"""

UNRESTRICTED_COMMAND_POLICY = """\
你的能力：
1. 执行预定义的安全审计命令（run_security_check）
2. 执行 shell 命令（run_shell_command），包括用户明确要求的运维、修复、安装、重启、删除、封禁、配置修改等操作
3. 查询 IP 归属信息（whois_lookup）

当前实例已启用 unrestricted command 模式。你不再受“只能执行只读命令”的提示词限制；当用户的真实意图明确、任务确实需要时，可以生成会修改系统状态的命令。

工作原则：
- 优先用预定义命令和只读命令收集证据；当用户明确要求执行运维动作时，不要因为“只读限制”而拒绝生成相应命令
- 对写入、删除、重启、提权、安装、卸载、封禁、修改配置等命令，必须在 reason 中清楚说明目标、影响范围和主要风险
- 对不可逆、高风险或意图模糊的操作，先追问确认；用户意图明确后再生成命令
- 不要谎称已经执行命令；动态命令会由 ChatDome 运行层按风险级别执行或要求人工确认
- 分析时给出具体的数据和建议，不要空泛
- 如果发现安全威胁，明确告知严重程度和建议措施
- 回复使用中文，简洁扼要，适合在手机上阅读
- 如果信息不足以判断，主动执行更多命令获取上下文，而不是猜测
- 【重要】意图验证与质疑：当用户提出的需求过于模糊、存在明显逻辑错误或潜在风险时，绝对禁止盲目服从！你必须“据理力争”，通过多轮提问、指出错误等方式，强制确认用户的真实意图。只有在完全明确真实目的后，才可执行相应操作。
"""

SYSTEM_PROMPT_TEMPLATE = """\
你是 ChatDome，一个 AI 驱动的主机安全助手。你通过 Telegram 与用户对话，\
帮助用户诊断和分析 Linux 服务器的安全状况。

{command_policy}

{runtime_environment_block}

{available_checks}
"""


def _build_runtime_environment_block(runtime_environment_context: str = "") -> str:
    """Build runtime environment compatibility block for the system prompt."""
    if not runtime_environment_context.strip():
        return (
            "运行环境信息：未采集到详细环境档案。\n"
            "命令要求：在执行命令前需先确认当前系统类型、命令可用性和兼容性。"
        )

    return (
        "运行环境兼容性约束：\n"
        f"{runtime_environment_context.strip()}\n"
        "执行要求：所有命令必须与当前 OS/发行版/命令可用性兼容；"
        "若命令不兼容，请先切换等价命令或明确说明限制。"
    )


def build_system_prompt(
    allow_unrestricted_commands: bool = False,
    runtime_environment_context: str = "",
    pack_loader: PackLoader | None = None,
) -> str:
    """Build the system prompt for the configured command mode."""
    command_policy = (
        UNRESTRICTED_COMMAND_POLICY
        if allow_unrestricted_commands
        else STRICT_COMMAND_POLICY
    )
    runtime_environment_block = _build_runtime_environment_block(
        runtime_environment_context,
    )
    available_checks = _build_available_checks_text(pack_loader)
    return SYSTEM_PROMPT_TEMPLATE.format(
        command_policy=command_policy.strip(),
        runtime_environment_block=runtime_environment_block.strip(),
        available_checks=available_checks.strip(),
    )


SYSTEM_PROMPT = build_system_prompt()

REVIEWER_SYSTEM_PROMPT = """\
你是一个极度严谨的 Linux 安全分析师。你的任务是分析即将在服务器中执行的 shell 命令。

你必须且只能以 JSON 格式输出，包含以下字段：
1. "safety_status": "SAFE" | "UNSAFE" | "CRITICAL"
   - SAFE: 纯读取/查询，不修改系统状态。
   - UNSAFE: 存在修改、写入、安装、网络下载、服务变更等风险。
   - CRITICAL: 不可逆或高破坏操作（例如删除大量文件、重启/关机、格式化等）。
2. "risk_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
3. "mutation_detected": true/false
   - 是否会修改系统状态（写文件、改配置、启停服务、安装软件等）
4. "deletion_detected": true/false
   - 是否包含删除或清理类行为（rm、truncate、覆盖写入导致内容丢失等）
5. "impact_analysis": 客观、具体地描述执行影响（100 字内）

判定要求：
- 先判断是否存在修改行为，再判断是否存在删除行为，再给出风险等级。
- 若 mutation_detected=true，则 safety_status 不得为 SAFE。
- 若 deletion_detected=true，risk_level 至少为 HIGH；若存在不可逆大范围删除，应为 CRITICAL。
- 禁止输出 JSON 以外的任何文本。
"""

COMPRESSION_PROMPT = """\
请对以下过长的历史聊天记录进行总结提炼。你需要提取：
1. 核心的技术上下文和用户的最终目标
2. 重要命令执行的结果数据（如黑客 IP、关键报错信息、文件路径等核心调查指标）

省略掉所有无关的客套话和分析过渡语。将这些提取出的要素压缩为一段精炼的背景参考资料，作为潜意识（Memory）供后续分析参考使用。你的回复请直接给出总结结果。
"""

# ---------------------------------------------------------------------------
# Tool Definitions (OpenAI Function Calling format)
# ---------------------------------------------------------------------------

def _shell_command_description(allow_unrestricted_commands: bool = False) -> str:
    """Return a mode-aware tool description for shell command execution."""
    if allow_unrestricted_commands:
        return (
            "在主机上执行 shell 命令。当前实例已启用 unrestricted command 模式，"
            "可以根据用户明确意图生成读写、修复、安装、重启、删除、封禁、"
            "配置修改等运维命令。命令会由 ChatDome 运行层按风险级别执行或要求人工确认；"
            "reason 必须说明目的、影响范围和主要风险。"
        )

    return (
        "在主机上执行只读 shell 命令。仅当预定义命令无法满足需求时使用。"
        "禁止执行写入、删除、修改类操作。"
    )


def build_tools(
    allow_unrestricted_commands: bool = False,
    pack_loader: PackLoader | None = None,
    valid_check_ids: list[str] | None = None,
) -> list[dict]:
    """Build OpenAI tool definitions for the configured command mode."""
    # Build dynamic check_id list
    if pack_loader is not None:
        checks = pack_loader.list_checks()
        check_ids = ", ".join(c["check_id"] for c in checks)
    else:
        check_ids = (
            "ssh_bruteforce, ssh_success_login, failed_sudo, "
            "active_connections, open_ports, firewall_rules, "
            "disk_usage, memory_usage, system_load, last_reboot, "
            "suspicious_processes, recent_cron_jobs, large_files, "
            "recent_syslog, kernel_errors"
        )

    return [
        {
            "type": "function",
            "function": {
                "name": "run_security_check",
                "description": (
                    "执行预定义的主机安全审计命令。"
                    "当前仅实现 Linux 命令包（macOS/Windows 后续支持）。"
                    f"可用的 check_id 包括：{check_ids}"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "check_id": {
                            "type": "string",
                            "description": "预定义命令的 ID",
                        },
                        "args": {
                            "type": "object",
                            "description": "命令参数，如 limit, time_range 等",
                            "additionalProperties": True,
                        },
                    },
                    "required": ["check_id"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "run_shell_command",
                "description": _shell_command_description(allow_unrestricted_commands),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "reason": {
                            "type": "string",
                            "description": "为什么要执行这条命令的简短理由；如果命令会修改系统，还要说明影响范围和主要风险。这将展示给审批员看。",
                        },
                        "command": {
                            "type": "string",
                            "description": "要执行的 shell 命令",
                        },
                    },
                    "required": ["reason", "command"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "whois_lookup",
                "description": "查询 IP 地址的归属信息（地理位置、AS、运营商）",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "ip": {
                            "type": "string",
                            "description": "要查询的 IP 地址",
                        },
                    },
                    "required": ["ip"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "add_user_context",
                "description": (
                    "当用户明确告知某个 Sentinel 告警对应的系统变更是其本人操作时使用。"
                    "将用户提供的信息写入上下文记录单，后续巡检将自动静默匹配的告警。"
                    "仅在用户主动确认/声明时调用，禁止自行推测。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "check_id": {
                            "type": "string",
                            "enum": valid_check_ids or [],
                            "description": "被覆盖的检查项 ID，必须从最近告警上下文中提取",
                        },
                        "pattern": {
                            "type": "string",
                            "description": "可选匹配关键词。设置后仅静默输出包含该词的告警。留空则静默该检查项的全部告警",
                        },
                        "summary": {
                            "type": "string",
                            "description": "用一句话客观记录用户的意图，如'用户确认手动停止了 Xray 代理服务'",
                        },
                    },
                    "required": ["check_id", "summary"],
                },
            },
        },
    ]


TOOLS = build_tools()
