from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from typing import Any, Protocol

from ..types import (
    EvidenceSpan,
    IssueSpottingNote,
    QualityFinding,
    StructuredDraft,
    TaskType,
    UploadContextSpan,
)


@dataclass(slots=True)
class ModelDraft:
    raw_text: str
    structured: StructuredDraft
    rubric_scores: dict[str, float]
    model_version: str
    metrics: dict[str, Any] | None = None


class EvidenceRetriever(Protocol):
    async def retrieve_issue_spotting_notes(
        self,
        *,
        query: str,
        jurisdiction: str,
        subject: str | None,
        as_of_date: date,
        limit: int = 8,
    ) -> Sequence[IssueSpottingNote]: ...

    async def retrieve(
        self,
        *,
        query: str,
        jurisdiction: str,
        subject: str | None,
        as_of_date: date,
        limit: int = 30,
        cacheable: bool = True,
    ) -> Sequence[EvidenceSpan]: ...

    def active_build_id(self) -> str | None: ...


class AnswerModel(Protocol):
    async def health(self) -> bool: ...

    async def draft(
        self,
        *,
        question: str,
        task_type: TaskType,
        jurisdiction: str,
        as_of_date: date,
        word_target: int,
        evidence: Sequence[EvidenceSpan],
        assessment_rules: Sequence[str],
        upload_context: Sequence[UploadContextSpan] = (),
    ) -> ModelDraft: ...

    async def repair(
        self,
        *,
        question: str,
        prior: StructuredDraft,
        failed_sections: Sequence[str],
        findings: Sequence[QualityFinding],
        evidence: Mapping[str, EvidenceSpan],
        word_target: int,
        upload_context: Sequence[UploadContextSpan] = (),
    ) -> ModelDraft: ...


class OnlineResearcher(Protocol):
    async def research_gap(
        self,
        *,
        proposition: str,
        jurisdiction: str,
        subject: str | None,
        as_of_date: date,
    ) -> tuple[Sequence[EvidenceSpan], list[dict[str, str]], list[str]]: ...
