"""
Sentinel Rule Evaluator — determines if a check result is anomalous.

Supports multiple rule types:
  - ``line_count``: count non-empty output lines
  - ``regex_extract``: extract numeric values by regex and aggregate
  - ``regex_match``: check if any line matches a pattern
  - ``added_count``: count added lines (Phase 2 — differential mode)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

from chatdome.sentinel.checks import RuleDefinition

logger = logging.getLogger(__name__)


@dataclass
class EvalResult:
    """Result of rule evaluation."""

    triggered: bool                 # Whether the rule threshold was breached
    current_value: float | None     # The computed value (e.g., line count, extracted max)
    description: str = ""           # Human-readable explanation


_OPERATORS = {
    ">": lambda a, b: a > b,
    ">=": lambda a, b: a >= b,
    "<": lambda a, b: a < b,
    "<=": lambda a, b: a <= b,
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
}


def evaluate(rule: RuleDefinition, output: str) -> EvalResult:
    """
    Evaluate a rule against command output.

    Args:
        rule: The rule definition.
        output: Raw command stdout.

    Returns:
        EvalResult with triggered flag and context.
    """
    try:
        if rule.type == "line_count":
            return _eval_line_count(rule, output)
        elif rule.type == "regex_extract":
            return _eval_regex_extract(rule, output)
        elif rule.type == "regex_match":
            return _eval_regex_match(rule, output)
        elif rule.type == "added_count":
            # Phase 2 — for now treat as line_count
            return _eval_added_count(rule, output)
        else:
            logger.warning("Unknown rule type: %s", rule.type)
            return EvalResult(triggered=False, current_value=None, description=f"Unknown rule type: {rule.type}")
    except Exception:
        logger.exception("Rule evaluation failed for type=%s", rule.type)
        return EvalResult(triggered=False, current_value=None, description="Rule evaluation error")


def _compare(value: float, operator: str, threshold: float) -> bool:
    """Apply comparison operator."""
    op_fn = _OPERATORS.get(operator)
    if op_fn is None:
        logger.warning("Unknown operator: %s, defaulting to >", operator)
        return value > threshold
    return op_fn(value, threshold)


def _eval_line_count(rule: RuleDefinition, output: str) -> EvalResult:
    """Count non-empty lines in output."""
    lines = [ln for ln in output.strip().splitlines() if ln.strip()]
    count = len(lines)
    triggered = _compare(count, rule.operator, rule.threshold)
    return EvalResult(
        triggered=triggered,
        current_value=count,
        description=f"匹配行数 {rule.operator} {rule.threshold}",
    )


def _eval_added_count(rule: RuleDefinition, output: str) -> EvalResult:
    """Count non-empty added-delta lines in differential mode."""
    lines = [ln for ln in output.strip().splitlines() if ln.strip()]
    count = len(lines)
    triggered = _compare(count, rule.operator, rule.threshold)
    return EvalResult(
        triggered=triggered,
        current_value=count,
        description=f"added item count {rule.operator} {rule.threshold}",
    )


def _eval_regex_extract(rule: RuleDefinition, output: str) -> EvalResult:
    """Extract numeric values via regex and aggregate."""
    if not rule.pattern:
        return EvalResult(triggered=False, current_value=None, description="No pattern defined")

    pattern = re.compile(rule.pattern)
    values: list[float] = []

    for line in output.splitlines():
        match = pattern.search(line)
        if match:
            try:
                values.append(float(match.group(1)))
            except (ValueError, IndexError):
                continue

    if not values:
        return EvalResult(
            triggered=False,
            current_value=None,
            description="No numeric values extracted",
        )

    # Aggregate
    agg = rule.aggregation
    if agg == "max":
        result = max(values)
    elif agg == "min":
        result = min(values)
    elif agg == "sum":
        result = sum(values)
    elif agg == "avg":
        result = sum(values) / len(values)
    else:
        result = max(values)

    triggered = _compare(result, rule.operator, rule.threshold)
    return EvalResult(
        triggered=triggered,
        current_value=result,
        description=f"{agg}提取值 {rule.operator} {rule.threshold}",
    )


def _eval_regex_match(rule: RuleDefinition, output: str) -> EvalResult:
    """Check if any line matches the regex pattern."""
    if not rule.pattern:
        return EvalResult(triggered=False, current_value=None, description="No pattern defined")

    pattern = re.compile(rule.pattern)
    match_count = 0

    for line in output.splitlines():
        if pattern.search(line):
            match_count += 1

    triggered = _compare(match_count, rule.operator, rule.threshold)
    return EvalResult(
        triggered=triggered,
        current_value=match_count,
        description=f"正则匹配行数 {rule.operator} {rule.threshold}",
    )
