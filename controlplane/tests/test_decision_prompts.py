from chatdome.outbound.decision_prompts import (
    DecisionPromptComposer,
    build_approval_decision_facts,
)


def test_read_only_prompt_requires_deterministic_boundary():
    facts = build_approval_decision_facts(
        reason="检查系统日志",
        static_is_safe=True,
        mutation_detected=False,
        deletion_detected=False,
    )

    assert DecisionPromptComposer.compose(facts) == (
        "ChatDome 请求执行一项操作：检查系统日志。"
        "它会读取相关系统资源中的信息。"
        "本地检查未发现修改或删除操作。"
        "是否允许继续？"
    )


def test_unknown_impact_never_claims_read_only_boundary():
    facts = build_approval_decision_facts(
        reason="检查系统日志",
        static_is_safe=False,
        mutation_detected=False,
        deletion_detected=False,
    )

    text = DecisionPromptComposer.compose(facts)

    assert text == (
        "ChatDome 请求执行一项操作：检查系统日志。"
        "当前还不能确认具体影响，请先查看命令分析。"
        "是否允许继续？"
    )
    assert "未发现修改或删除操作" not in text


def test_delete_prompt_states_irreversible_risk_without_claiming_completion():
    facts = build_approval_decision_facts(
        reason="清理旧日志",
        static_is_safe=False,
        mutation_detected=True,
        deletion_detected=True,
    )

    text = DecisionPromptComposer.compose(facts)

    assert "这可能会删除系统中的内容，删除后可能无法恢复。" in text
    assert "已经删除" not in text
    assert "未发现修改或删除操作" not in text


def test_missing_reason_uses_neutral_command_request():
    facts = build_approval_decision_facts(
        reason="无说明",
        static_is_safe=False,
        mutation_detected=False,
        deletion_detected=False,
    )

    assert DecisionPromptComposer.compose(facts) == (
        "ChatDome 请求执行一项命令。"
        "当前还不能确认具体影响，请先查看命令分析。"
        "是否允许继续？"
    )
