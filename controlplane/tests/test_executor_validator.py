import logging

import pytest

from chatdome.executor.validator import validate_command


def test_interpreter_name_inside_grep_pattern_is_not_execution():
    command = (
        "grep -a -E 'Jul 18 13:4[0-5]' /var/log/syslog.1 "
        "| grep -avE 'python|UFW BLOCK' | head -30"
    )

    assert validate_command(command).is_safe


def test_interpreter_after_pipeline_still_requires_approval():
    result = validate_command("printf payload | python script.py")

    assert not result.is_safe


def test_unknown_command_after_pipeline_requires_approval():
    result = validate_command(
        "cat /var/log/syslog | custom-inspector --all",
        require_recognized_read_only=True,
    )

    assert not result.is_safe
    assert "custom-inspector" in result.reason


def test_all_readonly_pipeline_commands_are_safe():
    result = validate_command(
        "cat /var/log/syslog | grep ssh | head -20",
        require_recognized_read_only=True,
    )

    assert result.is_safe


def test_unrecognized_command_uses_read_only_recognition_terms(caplog):
    with caplog.at_level(logging.WARNING, logger="chatdome.executor.validator"):
        result = validate_command(
            "du -sh /var/log/journal",
            require_recognized_read_only=True,
        )

    assert not result.is_safe
    assert result.reason == "本地规则未将 'du' 识别为只读命令"
    assert "Command not recognized as read-only" in caplog.text
    assert "Command not in allowlist" not in caplog.text


@pytest.mark.parametrize(
    "command",
    [
        "ip link set eth0 down",
        "find /tmp/x -delete",
        r"find /tmp -exec rm -f {} ;",
        "journalctl --vacuum-time=1s",
        "dmesg -C",
        "ss -K dst 192.0.2.1",
        "date -s 2030-01-01",
        "hostname changed-host",
        "sort -o /tmp/result /tmp/input",
        'awk BEGIN { system("touch /tmp/x") }',
    ],
)
def test_multimode_and_write_commands_not_safe_as_readonly(command):
    result = validate_command(command, require_recognized_read_only=True)
    assert not result.is_safe


@pytest.mark.parametrize(
    "command",
    [
        "ps aux",
        "ls -la /tmp",
        "grep root /etc/group",
        "sha256sum /tmp/input",
    ],
)
def test_pure_readonly_commands_remain_safe(command):
    result = validate_command(command, require_recognized_read_only=True)
    assert result.is_safe


@pytest.mark.parametrize(
    "command",
    [
        "uniq /tmp/input /tmp/output",
        "file -C -m /tmp/custom-magic",
    ],
)
def test_multimode_tools_with_write_modes_not_safe_as_readonly(command):
    result = validate_command(command, require_recognized_read_only=True)
    assert not result.is_safe


@pytest.mark.parametrize(
    "command",
    [
        "cat>/tmp/x",
        "ls>/tmp/listing",
        "cat 2>/tmp/error",
        "cat<>/tmp/x",
    ],
)
def test_compact_redirection_not_safe_as_readonly(command):
    result = validate_command(command, require_recognized_read_only=True)
    assert not result.is_safe
