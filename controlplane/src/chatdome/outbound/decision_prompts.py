"""Deterministic composition of user decision prompts."""

from __future__ import annotations

from chatdome.outbound.models import (
    DecisionBoundary,
    DecisionBoundaryKind,
    DecisionEffect,
    DecisionEffectKind,
    DecisionIntentStyle,
    DecisionPromptFacts,
    DecisionQuestion,
    DecisionUncertainty,
)
from chatdome.outbound.policy import has_meaningful_approval_reason, normalize_text


class DecisionPromptComposer:
    """Turn structured business facts into one platform-neutral prompt."""

    _QUESTIONS = {
        DecisionQuestion.APPROVE: "是否允许继续？",
        DecisionQuestion.CONFIRM_DELETE: "是否确认删除？",
        DecisionQuestion.CONTINUE_TASK: "是否让 ChatDome 继续处理？",
        DecisionQuestion.STOP_TASK: "是否停止当前任务？",
        DecisionQuestion.CONFIRM_CHANGE: "是否确认这项调整？",
        DecisionQuestion.CONFIRM: "是否确认继续？",
    }
    _UNCERTAINTIES = {
        DecisionUncertainty.IMPACT_UNKNOWN: (
            "当前还不能确认具体影响，请先查看命令分析。"
        ),
        DecisionUncertainty.ANALYSIS_PARTIAL: (
            "部分操作尚未完成分析，请核对未分析部分。"
        ),
    }

    @classmethod
    def compose(
        cls,
        facts: DecisionPromptFacts,
        *,
        include_question: bool = True,
    ) -> str:
        """Compose facts in intent, effect, boundary, uncertainty order."""

        sentences = [cls._intent_sentence(facts)]
        sentences.extend(cls._effect_sentence(effect) for effect in facts.effects)
        sentences.extend(cls._boundary_sentence(boundary) for boundary in facts.boundaries)
        if facts.uncertainty != DecisionUncertainty.NONE:
            sentences.append(cls._UNCERTAINTIES[facts.uncertainty])
        if include_question:
            sentences.append(cls._QUESTIONS.get(facts.question, cls._QUESTIONS[DecisionQuestion.CONFIRM]))
        return "".join(dict.fromkeys(sentence for sentence in sentences if sentence))

    @staticmethod
    def _intent_sentence(facts: DecisionPromptFacts) -> str:
        intent = normalize_text(facts.intent)
        if not intent:
            return "ChatDome 请求执行一项操作。"
        if facts.intent_style == DecisionIntentStyle.CONTINUE:
            return f"ChatDome 还需要{intent}。"
        if facts.intent_style == DecisionIntentStyle.WILL:
            return f"ChatDome 将{intent}。"
        if facts.intent_style == DecisionIntentStyle.DESCRIBE:
            return f"ChatDome 请求执行一项操作：{intent}。"
        if facts.intent_style == DecisionIntentStyle.REQUEST:
            return f"ChatDome 请求{intent}。"
        return f"ChatDome 想{intent}。"

    @staticmethod
    def _effect_sentence(effect: DecisionEffect) -> str:
        target = normalize_text(effect.target)
        detail = normalize_text(effect.detail)
        if effect.kind == DecisionEffectKind.READ:
            return f"它会读取{target or '相关资源'}中的信息。"
        if effect.kind == DecisionEffectKind.MODIFY:
            return f"这可能会修改{target or '系统状态或文件'}。"
        if effect.kind == DecisionEffectKind.DELETE:
            return f"这可能会删除{target or '系统中的内容'}，删除后可能无法恢复。"
        if effect.kind == DecisionEffectKind.INTERRUPT:
            return f"这会暂时中断{target or '当前服务'}。"
        if effect.kind == DecisionEffectKind.POLICY_CHANGE:
            return f"之后，{detail or target}。" if detail or target else ""
        if effect.kind == DecisionEffectKind.AUTHORIZE:
            return f"这会启动{target or '外部授权流程'}。"
        if effect.kind == DecisionEffectKind.TASK_WINDOW:
            return detail
        return ""

    @staticmethod
    def _boundary_sentence(boundary: DecisionBoundary) -> str:
        target = normalize_text(boundary.target)
        detail = normalize_text(boundary.detail)
        if boundary.kind == DecisionBoundaryKind.NO_MUTATION_OR_DELETION:
            return "本地检查未发现修改或删除操作。"
        if boundary.kind == DecisionBoundaryKind.NO_FILE_CHANGE:
            return f"本次操作不会修改{target or '相关文件'}。"
        if boundary.kind == DecisionBoundaryKind.PATROL_CONTINUES:
            return detail or "Sentinel 巡检和告警记录仍会继续。"
        return ""


def build_approval_decision_facts(
    *,
    reason: str,
    static_is_safe: bool | None,
    mutation_detected: bool | None,
    deletion_detected: bool | None,
) -> DecisionPromptFacts:
    """Map deterministic command checks to approval prompt facts."""

    meaningful_reason = normalize_text(reason)
    if not has_meaningful_approval_reason(meaningful_reason):
        meaningful_reason = ""

    effects = []
    boundaries = []
    uncertainty = DecisionUncertainty.NONE
    if deletion_detected is True:
        effects.append(DecisionEffect(DecisionEffectKind.DELETE, "系统中的内容"))
    elif mutation_detected is True:
        effects.append(DecisionEffect(DecisionEffectKind.MODIFY, "系统状态或文件"))
    elif static_is_safe is True:
        effects.append(DecisionEffect(DecisionEffectKind.READ, "相关系统资源"))
        boundaries.append(
            DecisionBoundary(DecisionBoundaryKind.NO_MUTATION_OR_DELETION)
        )
    else:
        uncertainty = DecisionUncertainty.IMPACT_UNKNOWN

    return DecisionPromptFacts(
        intent=meaningful_reason or "执行一项命令",
        intent_style=(
            DecisionIntentStyle.DESCRIBE
            if meaningful_reason
            else DecisionIntentStyle.REQUEST
        ),
        effects=tuple(effects),
        boundaries=tuple(boundaries),
        uncertainty=uncertainty,
        question=DecisionQuestion.APPROVE,
    )
