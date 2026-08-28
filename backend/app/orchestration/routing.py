"""Deterministic answer routing and bounded long-form section planning."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from ..types import AnswerRoute, IssuePlan, TaskType

SECTION_WORD_TARGET = 625
MIN_SECTION_WORDS = 500
MAX_SECTION_WORDS = 700
ROUTER_VERSION = "legalbot-answer-router-v3"


@dataclass(frozen=True, slots=True)
class RouteDecision:
    route: AnswerRoute
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SectionTask:
    key: str
    heading: str
    query: str
    word_target: int


_COMPLEXITY_MARKERS = (
    "critically",
    "counterargument",
    "contrary authority",
    "conflicting",
    "multi-authority",
    "time-sensitive",
    "advise the parties",
    "available remedies",
)

_ISSUE_LABELS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Overview and issues", ("advise", "critically", "explain", "analyse")),
    ("Applicable legal framework", ("law", "test", "framework", "statutory")),
    ("Duty and standard", ("duty", "standard of care", "scope of duty")),
    ("Breach and classification", ("breach", "classification", "term")),
    ("Causation and remoteness", ("causation", "remoteness", "loss of a chance")),
    ("Liability and defences", ("liability", "defence", "justification")),
    ("Rights and priorities", ("priority", "registration", "actual occupation")),
    ("Remedies and relief", ("remedy", "remedies", "damages", "relief", "rejection")),
    ("Counterarguments and limits", ("counterargument", "limits", "limitation clause")),
    ("Application and conclusion", ("advise", "application", "conclusion")),
)


def decide_route(question: str, word_target: int, task_type: TaskType) -> RouteDecision:
    lowered = question.casefold()
    complexity = sum(marker in lowered for marker in _COMPLEXITY_MARKERS)
    issue_count = len(
        {marker for _, markers in _ISSUE_LABELS for marker in markers if marker in lowered}
    )
    # A full enquiry is a research/control-loop decision, not simply a synonym
    # for a long answer.  Long problem questions need independent issue packs,
    # while a bounded critical essay can still use the sectioned route.  Every
    # output above 5,000 words is full-enquiry regardless of task type.
    if word_target > 5_000 or (task_type is TaskType.PROBLEM and word_target >= 3_000):
        return RouteDecision(
            AnswerRoute.FULL_ENQUIRY,
            ("long_output_budget", "multi_issue_research")
            if word_target > 5_000
            else ("multi_issue_research",),
        )
    if word_target >= 2_500 and (complexity >= 3 or issue_count >= 8):
        return RouteDecision(AnswerRoute.FULL_ENQUIRY, ("multi_issue_research",))
    # Difficult legal problem and essay requests are always planned in bounded
    # sections even at 1,000 words.  This avoids a single-call direct route for
    # dense short questions such as agency, defamation and housing, while the
    # full-enquiry rules above still control independent multi-issue research.
    if word_target > 1_200 or (
        task_type in {TaskType.ESSAY, TaskType.PROBLEM} and word_target >= 1_000
    ):
        return RouteDecision(AnswerRoute.SECTIONED, ("section_safe_output_budget",))
    return RouteDecision(AnswerRoute.DIRECT, ("bounded_single_generation",))


def build_section_tasks(
    *,
    question: str,
    word_target: int,
    issue_plan: IssuePlan,
) -> tuple[SectionTask, ...]:
    """Create a deterministic, bounded plan without persisting question prose."""

    needed = max(2, math.ceil(word_target / SECTION_WORD_TARGET))
    # Rounding up around the preferred size can make the minimum section size
    # impossible (for example, 1,300 words across three 500-word sections).
    # Reduce the count until the requested total can be distributed exactly.
    while needed > 2 and needed * MIN_SECTION_WORDS > word_target:
        needed -= 1
    lowered = question.casefold()
    headings: list[str] = []
    for heading, markers in _ISSUE_LABELS:
        if any(marker in lowered for marker in markers) and heading not in headings:
            headings.append(heading)
    for key in issue_plan.proposition_keys:
        heading = key.replace("_", " ").title()
        if heading not in headings:
            headings.append(heading)
    while len(headings) < needed:
        headings.append(f"Further analysis {len(headings) + 1}")
    headings = headings[:needed]

    base, remainder = divmod(word_target, len(headings))
    tasks: list[SectionTask] = []
    for index, heading in enumerate(headings):
        target = base + (1 if index < remainder else 0)
        target = min(MAX_SECTION_WORDS, max(MIN_SECTION_WORDS, target))
        focus = re.sub(r"[^A-Za-z0-9 &()'-]", "", heading)[:120]
        suffix = f" Focus issue: {focus}."
        available = max(1, 1_200 - len(suffix))
        compact = " ".join(question.split())
        if len(compact) > available:
            head = (available - 5) // 2
            tail = available - 5 - head
            compact = f"{compact[:head]} […] {compact[-tail:]}"
        tasks.append(
            SectionTask(
                key=f"section-{index + 1:02d}",
                heading=heading,
                query=f"{compact}{suffix}",
                word_target=target,
            )
        )
    return tuple(tasks)
