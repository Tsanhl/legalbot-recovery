"""Rule-based coverage checks that enqueue research work, never sources."""

from __future__ import annotations

from dataclasses import dataclass

from .gap_queue import GapKind, GapQueue


@dataclass(frozen=True, slots=True)
class SubjectCoverage:
    subject: str
    jurisdiction: str
    legislation_count: int = 0
    binding_case_count: int = 0
    procedure_or_regulator_count: int = 0
    doctrinal_scholarship_count: int = 0
    critical_scholarship_count: int = 0
    sources_with_currentness_flags: int = 0
    sources_without_citation_metadata: int = 0


class CoverageGapDetector:
    def __init__(self, queue: GapQueue) -> None:
        self.queue = queue

    def inspect(self, coverage: SubjectCoverage) -> tuple[str, ...]:
        created: list[str] = []
        requirements = (
            (
                coverage.legislation_count < 1,
                GapKind.LEGISLATION,
                "missing_primary_legislation",
                "No reviewed primary legislation is mapped.",
            ),
            (
                coverage.binding_case_count < 1,
                GapKind.CASE_AUTHORITY,
                "missing_binding_authority",
                "No reviewed binding appellate authority is mapped.",
            ),
            (
                coverage.doctrinal_scholarship_count < 1,
                GapKind.SCHOLARSHIP,
                "missing_doctrinal_scholarship",
                "No independently reviewed doctrinal scholarship is mapped.",
            ),
            (
                coverage.critical_scholarship_count < 1,
                GapKind.SCHOLARSHIP,
                "missing_critical_scholarship",
                "No independently reviewed critical scholarship is mapped.",
            ),
            (
                coverage.sources_with_currentness_flags > 0,
                GapKind.COMMENCEMENT_OR_EFFECT,
                "currentness_review_required",
                "One or more sources have unapplied effects, appeal, supersession or update flags.",
            ),
            (
                coverage.sources_without_citation_metadata > 0,
                GapKind.CITATION_METADATA,
                "oscola_metadata_incomplete",
                "One or more sources lack the metadata needed for a verified OSCOLA citation.",
            ),
        )
        for condition, kind, reason, description in requirements:
            if not condition:
                continue
            item = self.queue.enqueue(
                subject=coverage.subject,
                jurisdiction=coverage.jurisdiction,
                kind=kind,
                reason_code=reason,
                description=description,
                priority=90 if kind in {GapKind.LEGISLATION, GapKind.CASE_AUTHORITY} else 60,
            )
            created.append(item.gap_id)
        return tuple(created)
