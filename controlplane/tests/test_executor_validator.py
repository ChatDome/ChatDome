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
    result = validate_command("cat /var/log/syslog | custom-inspector --all", check_allowlist=True)

    assert not result.is_safe
    assert "custom-inspector" in result.reason


def test_all_readonly_pipeline_commands_are_safe():
    result = validate_command("cat /var/log/syslog | grep ssh | head -20", check_allowlist=True)

    assert result.is_safe

