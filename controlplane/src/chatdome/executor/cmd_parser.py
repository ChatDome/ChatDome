"""Static shell command breakdown for approval UI."""

from __future__ import annotations

import os
import shlex
from typing import Any


COMMAND_DESCRIPTIONS = {
    # --- 危险/破坏性命令 ---
    "rm": "删除文件或目录",
    "rmdir": "删除空目录",
    "dd": "底层块设备或文件写入",
    "shred": "安全擦除文件内容",
    "wipe": "安全擦除文件内容",
    # --- 文件操作 ---
    "mv": "移动或重命名文件",
    "cp": "复制文件",
    "ln": "创建文件链接",
    "touch": "创建文件或更新时间戳",
    "truncate": "截断文件到指定大小",
    "tee": "将输入写入文件",
    # --- 权限/所有权 ---
    "chmod": "修改文件权限",
    "chown": "修改文件所有者",
    "chgrp": "修改文件所属组",
    # --- 进程 ---
    "kill": "终止进程",
    "pkill": "按名称终止进程",
    "killall": "按名称终止所有匹配进程",
    # --- 服务/系统 ---
    "systemctl": "控制系统服务",
    "service": "控制系统服务（旧式）",
    "shutdown": "关机或重启系统",
    "reboot": "重启系统",
    "init": "切换运行级别",
    # --- 网络 ---
    "wget": "网络下载",
    "curl": "网络请求或下载",
    "iptables": "修改防火墙规则",
    "ip": "网络配置",
    "ifconfig": "网络接口配置",
    "nft": "修改 nftables 防火墙规则",
    "ufw": "管理防火墙规则",
    # --- 账号/认证 ---
    "passwd": "修改用户密码",
    "useradd": "创建用户账号",
    "userdel": "删除用户账号",
    "usermod": "修改用户账号",
    "groupadd": "创建用户组",
    "groupdel": "删除用户组",
    "visudo": "编辑 sudoers 配置",
    # --- 定时任务 ---
    "crontab": "管理定时任务",
    "at": "安排一次性定时任务",
    # --- 只读/查询命令 ---
    "stat": "查询文件或文件系统元信息",
    "ls": "列出目录内容",
    "cat": "显示文件内容",
    "less": "分页查看文件内容",
    "more": "分页查看文件内容",
    "head": "显示文件开头内容",
    "tail": "显示文件末尾内容",
    "grep": "搜索文本内容",
    "find": "搜索文件",
    "du": "统计磁盘占用",
    "df": "查看磁盘空间",
    "ps": "查看进程列表",
    "top": "实时查看系统资源",
    "htop": "实时查看系统资源（交互式）",
    "netstat": "查看网络连接状态",
    "ss": "查看 socket 连接状态",
    "lsof": "列出打开的文件",
    "who": "显示登录用户",
    "w": "显示登录用户及活动",
    "last": "显示登录历史",
    "id": "显示用户身份",
    "uname": "显示系统信息",
    "uptime": "显示系统运行时间",
    "free": "显示内存使用情况",
    "env": "显示或设置环境变量",
    "echo": "输出文本",
    "printf": "格式化输出文本",
    "date": "显示或设置系统时间",
    "which": "查找命令路径",
    "whereis": "查找命令及相关文件",
    "file": "识别文件类型",
    "wc": "统计文件行数/字数/字节数",
    "md5sum": "计算 MD5 校验和",
    "sha256sum": "计算 SHA256 校验和",
    "journalctl": "查看系统日志",
    "dmesg": "查看内核日志",
    "lspci": "列出 PCI 设备",
    "lsblk": "列出块设备",
    "mount": "挂载文件系统",
    "umount": "卸载文件系统",
    # --- 包管理 ---
    "apt": "管理 APT 软件包",
    "apt-get": "管理 APT 软件包",
    "yum": "管理 YUM 软件包",
    "dnf": "管理 DNF 软件包",
    "pip": "管理 Python 软件包",
    "pip3": "管理 Python 3 软件包",
    "npm": "管理 Node.js 软件包",
    # --- 文本处理 ---
    "sed": "流编辑器（可修改文件）",
    "awk": "文本处理工具",
    "sort": "排序文本",
    "uniq": "去重文本行",
    "cut": "截取文本字段",
    "tr": "转换或删除字符",
    # --- 其他 ---
    "bash": "执行 bash 脚本或命令",
    "sh": "执行 sh 脚本或命令",
    "python": "执行 Python 脚本",
    "python3": "执行 Python 3 脚本",
    "ssh": "远程 SSH 连接",
    "scp": "通过 SSH 复制文件",
    "rsync": "远程或本地文件同步",
    "tar": "归档或解压文件",
    "gzip": "压缩或解压文件",
    "gunzip": "解压 gzip 文件",
    "zip": "压缩文件",
    "unzip": "解压 zip 文件",
}

WRAPPER_COMMANDS = {"sudo", "doas", "command"}
COMMON_FLAG_MEANINGS = {
    "-r": "递归处理目录",
    "-R": "递归处理目录",
    "--recursive": "递归处理目录",
    "-f": "强制执行",
    "--force": "强制执行",
    "-i": "执行前逐项确认",
    "--interactive": "执行前逐项确认",
    "--no-preserve-root": "允许操作根目录保护",
}


def parse_shell_command(command: str) -> dict[str, Any]:
    """Return a JSON-safe, best-effort explanation for one shell command."""
    raw_command = str(command or "").strip()
    tokens, parse_error = _split_command(raw_command)
    if not tokens:
        return {
            "base_cmd": "",
            "description": "空命令",
            "tokens": [],
            "targets": [],
            "flags": [],
            "irreversible": False,
            "warnings": [],
            "parse_error": parse_error,
        }

    entries: list[dict[str, str]] = []
    command_tokens = list(tokens)
    wrappers, command_tokens = _strip_wrappers(command_tokens)
    for wrapper in wrappers:
        entries.append(_entry(wrapper, "执行前缀", _wrapper_meaning(wrapper)))

    if not command_tokens:
        return _result(tokens[0], "执行命令", entries, [], [], [], False, parse_error)

    executable = command_tokens[0]
    base_cmd = os.path.basename(executable)
    description = COMMAND_DESCRIPTIONS.get(base_cmd, "执行命令（未识别）")
    entries.append(_entry(executable, "命令", description))

    args = command_tokens[1:]
    flags = _flag_tokens(args)
    entries.extend(_flag_entries(base_cmd, flags))

    if base_cmd in {"rm", "rmdir"}:
        detail_entries, targets, warnings, irreversible = _parse_rm_like(base_cmd, args, flags)
    elif base_cmd == "systemctl":
        detail_entries, targets, warnings, irreversible = _parse_systemctl(args)
    elif base_cmd in {"mv", "cp"}:
        detail_entries, targets, warnings, irreversible = _parse_copy_move(base_cmd, args)
    elif base_cmd == "chmod":
        detail_entries, targets, warnings, irreversible = _parse_chmod(args)
    elif base_cmd == "chown":
        detail_entries, targets, warnings, irreversible = _parse_chown(args)
    elif base_cmd in {"kill", "pkill"}:
        detail_entries, targets, warnings, irreversible = _parse_kill(base_cmd, args)
    elif base_cmd == "dd":
        detail_entries, targets, warnings, irreversible = _parse_dd(args)
    elif base_cmd in {"wget", "curl"}:
        detail_entries, targets, warnings, irreversible = _parse_network_download(base_cmd, args)
    elif base_cmd == "iptables":
        detail_entries, targets, warnings, irreversible = _parse_iptables(args)
    elif base_cmd == "crontab":
        detail_entries, targets, warnings, irreversible = _parse_crontab(args)
    elif base_cmd == "passwd":
        detail_entries, targets, warnings, irreversible = _parse_passwd(args)
    else:
        detail_entries, targets, warnings, irreversible = _parse_unknown(args)

    entries.extend(detail_entries)
    return _result(base_cmd, description, entries, targets, flags, warnings, irreversible, parse_error)


def _split_command(command: str) -> tuple[list[str], str]:
    if not command:
        return [], ""
    try:
        return shlex.split(command, posix=True), ""
    except ValueError as exc:
        return command.split(), str(exc)


def _strip_wrappers(tokens: list[str]) -> tuple[list[str], list[str]]:
    wrappers: list[str] = []
    remaining = list(tokens)
    while remaining and os.path.basename(remaining[0]) in WRAPPER_COMMANDS:
        wrappers.append(remaining.pop(0))
    if remaining and os.path.basename(remaining[0]) == "env":
        wrappers.append(remaining.pop(0))
        while remaining and "=" in remaining[0] and not remaining[0].startswith("-"):
            wrappers.append(remaining.pop(0))
    return wrappers, remaining


def _wrapper_meaning(token: str) -> str:
    base = os.path.basename(token)
    if base in {"sudo", "doas"}:
        return "以提升权限执行后续命令"
    if base == "env":
        return "设置环境后执行后续命令"
    if "=" in token:
        return "环境变量赋值"
    return "执行后续命令"


def _result(
    base_cmd: str,
    description: str,
    entries: list[dict[str, str]],
    targets: list[str],
    flags: list[str],
    warnings: list[str],
    irreversible: bool,
    parse_error: str,
) -> dict[str, Any]:
    result = {
        "base_cmd": base_cmd,
        "description": description,
        "tokens": entries,
        "targets": _dedupe(targets),
        "flags": _dedupe(flags),
        "irreversible": irreversible,
        "warnings": _dedupe(warnings),
    }
    if parse_error:
        result["parse_error"] = parse_error
    return result


def _entry(token: str, role: str, meaning: str) -> dict[str, str]:
    return {"token": str(token), "role": role, "meaning": meaning}


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def _flag_tokens(args: list[str]) -> list[str]:
    return [arg for arg in args if _is_flag(arg)]


def _is_flag(value: str) -> bool:
    return str(value or "").startswith("-") and value != "-"


def _non_flag_args(args: list[str]) -> list[str]:
    return [arg for arg in args if not _is_flag(arg)]


def _flag_entries(base_cmd: str, flags: list[str]) -> list[dict[str, str]]:
    return [_entry(flag, "选项", _flag_meaning(base_cmd, flag)) for flag in flags]


def _flag_meaning(base_cmd: str, flag: str) -> str:
    if base_cmd == "rm" and flag.startswith("-") and not flag.startswith("--") and len(flag) > 2:
        meanings = []
        for char in flag[1:]:
            meanings.append(COMMON_FLAG_MEANINGS.get(f"-{char}", f"短选项 -{char}"))
        return "、".join(meanings)
    return COMMON_FLAG_MEANINGS.get(flag, "命令选项")


def _has_flag(flags: list[str], *names: str) -> bool:
    for flag in flags:
        if flag in names:
            return True
        if flag.startswith("-") and not flag.startswith("--"):
            short = set(flag[1:])
            for name in names:
                if name.startswith("-") and not name.startswith("--") and name[1:] in short:
                    return True
    return False


def _parse_rm_like(base_cmd: str, args: list[str], flags: list[str]) -> tuple[list[dict[str, str]], list[str], list[str], bool]:
    targets = _non_flag_args(args)
    entries = []
    for target in targets:
        role = _target_role(target)
        entries.append(_entry(target, role, f"{role}（将被永久删除）"))
    warnings = []
    if base_cmd == "rm" and not _has_flag(flags, "-i", "--interactive"):
        warnings.append("无 -i 标志，删除时不会提示确认")
    if _has_flag(flags, "-f", "--force"):
        warnings.append("包含强制删除选项，缺失目标或权限提示可能被忽略")
    if _has_flag(flags, "-r", "-R", "--recursive"):
        warnings.append("包含递归删除，目录内文件会一并删除")
    if "--no-preserve-root" in flags:
        warnings.append("允许操作根目录保护，风险极高")
    return entries, targets, warnings, True


def _parse_systemctl(args: list[str]) -> tuple[list[dict[str, str]], list[str], list[str], bool]:
    values = _non_flag_args(args)
    entries = []
    targets: list[str] = []
    warnings: list[str] = []
    if values:
        entries.append(_entry(values[0], "子命令", _systemctl_action_meaning(values[0])))
    for service in values[1:]:
        entries.append(_entry(service, "目标服务", "将被 systemctl 操作的服务单元"))
        targets.append(service)
    if values and values[0] in {"restart", "stop", "disable", "mask", "kill"}:
        warnings.append("会改变服务运行状态")
    return entries, targets, warnings, False


def _systemctl_action_meaning(action: str) -> str:
    meanings = {
        "start": "启动服务",
        "stop": "停止服务",
        "restart": "重启服务",
        "reload": "重新加载服务配置",
        "enable": "设置服务开机自启",
        "disable": "取消服务开机自启",
        "status": "查看服务状态",
    }
    return meanings.get(action, "systemctl 操作")


def _parse_copy_move(base_cmd: str, args: list[str]) -> tuple[list[dict[str, str]], list[str], list[str], bool]:
    values = _non_flag_args(args)
    entries: list[dict[str, str]] = []
    if len(values) >= 2:
        for source in values[:-1]:
            entries.append(_entry(source, "源路径", "将被读取的路径"))
        target_meaning = "移动或重命名到此路径" if base_cmd == "mv" else "复制到此路径"
        entries.append(_entry(values[-1], "目标路径", target_meaning))
    else:
        entries.extend(_entry(value, "路径参数", "命令参数") for value in values)
    return entries, values, [], base_cmd == "mv"


def _parse_chmod(args: list[str]) -> tuple[list[dict[str, str]], list[str], list[str], bool]:
    values = _non_flag_args(args)
    entries: list[dict[str, str]] = []
    if values:
        entries.append(_entry(values[0], "权限模式", "将应用到目标路径的权限设置"))
    for target in values[1:]:
        entries.append(_entry(target, _target_role(target), "权限将被修改的路径"))
    return entries, values[1:], ["会改变文件或目录权限"], False


def _parse_chown(args: list[str]) -> tuple[list[dict[str, str]], list[str], list[str], bool]:
    values = _non_flag_args(args)
    entries: list[dict[str, str]] = []
    if values:
        entries.append(_entry(values[0], "所有者", "新的用户或用户组"))
    for target in values[1:]:
        entries.append(_entry(target, _target_role(target), "所有者将被修改的路径"))
    return entries, values[1:], ["会改变文件或目录所有者"], False


def _parse_kill(base_cmd: str, args: list[str]) -> tuple[list[dict[str, str]], list[str], list[str], bool]:
    values = _non_flag_args(args)
    role = "目标进程" if base_cmd == "kill" else "进程匹配条件"
    entries = [_entry(value, role, "将被终止的进程标识") for value in values]
    return entries, values, ["会终止匹配进程"], True


def _parse_dd(args: list[str]) -> tuple[list[dict[str, str]], list[str], list[str], bool]:
    entries: list[dict[str, str]] = []
    targets: list[str] = []
    for arg in args:
        if arg.startswith("if="):
            entries.append(_entry(arg, "输入源", "dd 将读取的数据来源"))
        elif arg.startswith("of="):
            target = arg[3:]
            entries.append(_entry(arg, "输出目标", "dd 将写入或覆盖的目标"))
            targets.append(target)
        elif not _is_flag(arg):
            entries.append(_entry(arg, "参数", "dd 参数"))
    return entries, targets, ["可能直接覆盖输出目标数据"], True


def _parse_network_download(base_cmd: str, args: list[str]) -> tuple[list[dict[str, str]], list[str], list[str], bool]:
    entries: list[dict[str, str]] = []
    targets: list[str] = []
    for arg in args:
        if _is_flag(arg):
            continue
        if arg.startswith(("http://", "https://")):
            entries.append(_entry(arg, "URL", "网络请求目标"))
            targets.append(arg)
        else:
            entries.append(_entry(arg, "参数", "下载命令参数"))
    warnings = ["会访问外部网络"]
    if base_cmd in {"wget", "curl"} and any(flag in args for flag in {"-O", "-o", "--output"}):
        warnings.append("可能写入本地文件")
    return entries, targets, warnings, False


def _parse_iptables(args: list[str]) -> tuple[list[dict[str, str]], list[str], list[str], bool]:
    entries = [_entry(arg, "规则参数", "防火墙规则参数") for arg in args if not _is_flag(arg)]
    return entries, [], ["会修改防火墙规则"], False


def _parse_crontab(args: list[str]) -> tuple[list[dict[str, str]], list[str], list[str], bool]:
    entries = [_entry(arg, "参数", "crontab 参数") for arg in args]
    warnings = ["会读取或修改定时任务"]
    if "-r" in args:
        warnings.append("-r 会删除当前用户的定时任务")
    return entries, [], warnings, "-r" in args


def _parse_passwd(args: list[str]) -> tuple[list[dict[str, str]], list[str], list[str], bool]:
    values = _non_flag_args(args)
    entries = [_entry(value, "目标用户", "密码或账号状态将被修改的用户") for value in values]
    return entries, values, ["会修改账号认证状态"], False


def _parse_unknown(args: list[str]) -> tuple[list[dict[str, str]], list[str], list[str], bool]:
    # flags 已经在 _flag_entries() 中单独记录，这里只处理非 flag 参数，避免重复
    non_flags = _non_flag_args(args)
    entries = [_entry(arg, "参数", "命令参数") for arg in non_flags]
    return entries, non_flags, [], False


def _target_role(target: str) -> str:
    text = str(target or "")
    if text.endswith("/"):
        return "目标目录"
    name = os.path.basename(text.rstrip("/"))
    if "." in name and not name.startswith("."):
        return "目标文件"
    return "目标路径"
