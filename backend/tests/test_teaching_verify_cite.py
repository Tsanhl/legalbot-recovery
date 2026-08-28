from __future__ import annotations

import asyncio
import json
from collections.abc import Sequence
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from app.config import Settings
from app.orchestration.contracts import ModelDraft
from app.orchestration.issues import build_issue_plan
from app.orchestration.runner import AnswerRunner
from app.orchestration.teaching_verify import (
    render_teaching_notes_view,
    run_teaching_verify_cite_flow,
    teaching_chunks_cannot_satisfy_material_claim,
    teaching_summary_for,
)
from app.quality.evaluator import QualityEvaluator
from app.quality.evidence import is_citable_authority_lane
from app.types import (
    EvidenceSpan,
    IssueSpottingNote,
    MaterialLane,
    QualityReport,
    QuestionRequest,
    ReleaseState,
    StructuredClaimDraft,
    StructuredDraft,
    StructuredSectionDraft,
    TaskType,
    TeachingVerifyStatus,
    UploadContextSpan,
)


def _note(note_id: str, text: str) -> IssueSpottingNote:
    return IssueSpottingNote(
        id=note_id,
        source_version_id=f"source-{note_id}",
        chunk_id=f"chunk-{note_id}",
        text=text,
        jurisdiction="England and Wales",
        subject="tort",
        content_sha256=(note_id.encode().hex() + "0" * 64)[:64],
        index_build_id="build-1",
    )


def _teaching_span(text: str) -> EvidenceSpan:
    return EvidenceSpan(
        id="teaching-evidence-1",
        source_version_id="source-teaching-1",
        chunk_id="chunk-teaching-1",
        text=text,
        locator="slide 4",
        lane=MaterialLane.PRIVATE_TEACHING,
        jurisdiction="England and Wales",
        subject="tort",
        citation_data={},
        canonical_citation=None,
        currentness_status="n/a",
        content_sha256="d" * 64,
        index_build_id="build-1",
        identity_verified=True,
        currentness_verified=True,
    )


def test_teaching_summary_is_taxonomy_bound_not_private_prose() -> None:
    private = "UNIQUE_PRIVATE_LECTURE_PROSE_9912"
    plan = build_issue_plan(
        question="What issues arise?",
        jurisdiction="England and Wales",
        subject="tort",
        notes=[_note("t1", f"Consider duty of care and remoteness. {private}")],
    )
    flow = run_teaching_verify_cite_flow(issue_plan=plan, authority_evidence=[])
    serialized = json.dumps(flow.model_dump(mode="json"), sort_keys=True)
    assert private not in serialized
    assert all(item.status != TeachingVerifyStatus.TEACHING_SUGGESTION for item in flow.items)
    assert any(item.status == TeachingVerifyStatus.NOT_FOUND for item in flow.items)
    summary = teaching_summary_for("duty of care")
    assert summary.startswith("Duty of care is the legal issue")
    assert "teaching suggested" not in summary.casefold()
    assert "private teaching materials suggest" not in summary.casefold()
    notes = render_teaching_notes_view(flow)
    assert notes.startswith("notes\n")
    assert "teaching_suggestion" not in notes
    assert "what:" in notes
    assert "authority:" in notes
    assert "none in current authority set" in notes
    assert "here verified" not in notes
    assert "here not found" not in notes
    assert "??? status" not in notes
    assert "Private teaching" not in notes
    assert "teaching suggested" not in notes.casefold()
    meta = flow.safe_metadata()
    assert "teaching_suggestion" not in meta["status_counts"]
    assert meta["notes_view"] == notes
    # Internal verify statuses remain available in metadata items.
    assert any(item["status"] == "not_found" for item in meta["items"])


def test_verification_statuses_and_authority_only_citations(evidence: EvidenceSpan) -> None:
    supporting = evidence.model_copy(
        update={
            "id": "evidence-duty",
            "text": (
                "A duty of care may arise where the neighbour principle and "
                "reasonably foreseeable harm are established."
            ),
            "subject": "tort",
        }
    )
    teaching_leak = _teaching_span(
        "Duty of care is always owed in every private teaching hypothetical."
    )
    plan = build_issue_plan(
        question="Is a duty of care owed?",
        jurisdiction="England and Wales",
        subject="tort",
        notes=[_note("t2", "Spot duty of care on these facts.")],
    )
    flow = run_teaching_verify_cite_flow(
        issue_plan=plan,
        authority_evidence=[teaching_leak, supporting],
    )
    statuses = {item.status for item in flow.items}
    assert TeachingVerifyStatus.TEACHING_SUGGESTION not in statuses
    assert TeachingVerifyStatus.VERIFIED in statuses or (
        TeachingVerifyStatus.PARTLY_VERIFIED in statuses
    )
    for item in flow.items:
        assert item.status != TeachingVerifyStatus.TEACHING_SUGGESTION
        assert all(evidence_id != teaching_leak.id for evidence_id in item.evidence_ids)
        assert "Example Act 2026" in " ".join(item.citations) or item.status in {
            TeachingVerifyStatus.NOT_FOUND,
            TeachingVerifyStatus.CONTRADICTED,
        }
        assert "teaching-suggested" not in (item.reason or "")
    meta = flow.safe_metadata()
    assert "status_counts" in meta
    assert "teaching_suggestion" not in meta["status_counts"]
    assert meta["item_count"] == len(flow.items)
    notes = meta["notes_view"]
    assert notes.startswith("notes")
    assert "duty of care" in notes.casefold()
    assert "what:" in notes
    assert "authority:" in notes
    assert "Example Act 2026" in notes
    assert "here verified" not in notes
    assert "here partly verified" not in notes
    assert "teaching_suggestion" not in notes
    assert "teaching suggested" not in notes.casefold()
    # Authority excerpt preferred for what when a citable span exists.
    assert "neighbour principle" in notes.casefold() or "duty of care" in notes.casefold()


def test_teaching_chunk_cannot_satisfy_material_legal_claim(evidence: EvidenceSpan) -> None:
    teaching = _teaching_span("The verified statutory proposition appears in the lecture notes.")
    assert not is_citable_authority_lane(teaching)
    assert teaching_chunks_cannot_satisfy_material_claim(
        "The verified statutory proposition is the applicable rule.",
        [teaching],
    )
    report = QualityEvaluator().evaluate(
        answer_version_id="answer-teaching-block",
        draft=StructuredDraft(
            title="Teaching misuse",
            task_type=TaskType.GENERAL,
            jurisdiction="England and Wales",
            as_of_date=date(2026, 8, 13),
            sections=[
                StructuredSectionDraft(
                    id="law",
                    heading="Law",
                    claims=[
                        StructuredClaimDraft(
                            id="claim-1",
                            text="The verified statutory proposition is the applicable rule.",
                            evidence_ids=[teaching.id],
                            material=True,
                        )
                    ],
                )
            ],
        ),
        rendered_text="The verified statutory proposition is the applicable rule.",
        evidence_by_id={teaching.id: teaching},
        word_count=150,
        word_target=150,
    )
    assert not report.evidence_passed
    assert report.release_state == ReleaseState.HELD_FOR_REVIEW
    assert any(finding.code == "non_authority_lane" for finding in report.findings)
    # Authority span still can pass when alone.
    ok = QualityEvaluator().evaluate(
        answer_version_id="answer-authority-ok",
        draft=StructuredDraft(
            title="Authority use",
            task_type=TaskType.GENERAL,
            jurisdiction="England and Wales",
            as_of_date=date(2026, 8, 13),
            sections=[
                StructuredSectionDraft(
                    id="law",
                    heading="Law",
                    claims=[
                        StructuredClaimDraft(
                            id="claim-1",
                            text=(
                                'The source records "The verified statutory proposition" '
                                "as the applicable rule."
                            ),
                            evidence_ids=[evidence.id],
                            material=True,
                        )
                    ],
                )
            ],
        ),
        rendered_text=(
            'The source records "The verified statutory proposition" as the applicable rule.'
        ),
        evidence_by_id={evidence.id: evidence},
        word_count=150,
        word_target=150,
    )
    assert ok.evidence_passed


class _FlowRetriever:
    def __init__(self, evidence: EvidenceSpan) -> None:
        self.evidence = evidence
        self.queries: list[str] = []

    async def retrieve_issue_spotting_notes(
        self,
        *,
        query: str,
        jurisdiction: str,
        subject: str | None,
        as_of_date: date,
        limit: int = 8,
    ) -> list[IssueSpottingNote]:
        del query, subject, as_of_date, limit
        return [
            _note(
                "teaching",
                "Duty of care may be relevant. UNIQUE_PRIVATE_TEACHING_FLOW must stay private.",
            ).model_copy(update={"jurisdiction": jurisdiction})
        ]

    async def retrieve(
        self,
        *,
        query: str,
        jurisdiction: str,
        subject: str | None,
        as_of_date: date,
        limit: int = 30,
        cacheable: bool = True,
    ) -> list[EvidenceSpan]:
        del jurisdiction, subject, as_of_date, limit, cacheable
        self.queries.append(query)
        if "duty of care" in query.casefold():
            return [
                self.evidence.model_copy(
                    update={
                        "text": (
                            "A duty of care arises under the neighbour principle where "
                            "harm is reasonably foreseeable."
                        ),
                        "subject": "tort",
                    }
                )
            ]
        return [self.evidence]

    def active_build_id(self) -> str:
        return "build-1"


class _BoundEvidenceModel:
    async def health(self) -> bool:
        return True

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
    ) -> ModelDraft:
        del question, word_target, assessment_rules, upload_context
        structured = StructuredDraft(
            title="Verified legal answer",
            task_type=task_type,
            jurisdiction=jurisdiction,
            as_of_date=as_of_date,
            sections=[
                StructuredSectionDraft(
                    id="analysis",
                    heading="Analysis",
                    claims=[
                        StructuredClaimDraft(
                            id="claim-1",
                            text=evidence[0].text,
                            evidence_ids=[evidence[0].id],
                        )
                    ],
                )
            ],
        )
        return ModelDraft(
            raw_text=evidence[0].text,
            structured=structured,
            rubric_scores={
                "authority_accuracy": 1.0,
                "analysis": 1.0,
                "organisation": 1.0,
                "precision": 1.0,
            },
            model_version="test-teaching-flow",
        )

    async def repair(self, **kwargs: Any) -> ModelDraft:
        evidence = list(kwargs["evidence"].values())
        prior = kwargs["prior"]
        return ModelDraft(
            raw_text=evidence[0].text,
            structured=prior,
            rubric_scores={
                "authority_accuracy": 1.0,
                "analysis": 1.0,
                "organisation": 1.0,
                "precision": 1.0,
            },
            model_version="test-teaching-flow",
        )


class _PassingEvaluator:
    def evaluate(self, **kwargs: Any) -> QualityReport:
        return QualityReport(
            id="teaching-flow-quality",
            answer_version_id=str(kwargs["answer_version_id"]),
            evidence_passed=True,
            academic_score=75,
            release_state=ReleaseState.VERIFIED_FULL,
        )


def test_runner_emits_teaching_verify_statuses_in_checkpoint(
    tmp_path: Path, database, cipher, evidence: EvidenceSpan
) -> None:
    database.create_job(
        job_id="teaching-flow-job",
        encrypted_question=cipher.encrypt_text("What claims could arise?"),
        question_summary="What claims could arise?",
        request={"task_type": "general", "word_target": 100},
    )
    runner = AnswerRunner(
        settings=Settings(project_root=tmp_path, test_mode=True),
        database=database,
        cipher=cipher,
        retriever=_FlowRetriever(evidence),
        model=_BoundEvidenceModel(),
    )
    runner.evaluator = _PassingEvaluator()  # type: ignore[assignment]
    request = QuestionRequest(
        question="What claims could arise?",
        task_type=TaskType.GENERAL,
        word_target=100,
    )
    with pytest.raises(
        RuntimeError,
        match="normal_live_release_content_certification_missing",
    ):
        asyncio.run(runner._run("teaching-flow-job", request.question, request))
    job = database.job("teaching-flow-job")
    assert job is not None
    assert job["answer_id"] is None
    assert database.fetchall("SELECT id FROM release_outbox WHERE job_id='teaching-flow-job'") == []
    checkpoint = json.loads(job["checkpoint_json"])
    flow = checkpoint["issue_plan"]["teaching_verify_cite"]
    assert flow["item_count"] >= 1
    assert "teaching_suggestion" not in flow["status_counts"]
    statuses = {item["status"] for item in flow["items"]}
    assert "teaching_suggestion" not in statuses
    assert statuses & {"verified", "partly_verified", "not_found", "contradicted"}
    assert "notes_view" in flow
    assert flow["notes_view"].startswith("notes")
    assert "what:" in flow["notes_view"]
    assert "authority:" in flow["notes_view"]
    assert "here verified" not in flow["notes_view"]
    assert "teaching_suggestion" not in flow["notes_view"]
    assert "teaching suggested" not in flow["notes_view"].casefold()
    assert "private teaching materials suggest" not in flow["notes_view"].casefold()
    blob = json.dumps(checkpoint, sort_keys=True)
    assert "UNIQUE_PRIVATE_TEACHING_FLOW" not in blob


def test_notes_view_is_knowledge_card_not_status_jargon(evidence: EvidenceSpan) -> None:
    supporting = evidence.model_copy(
        update={
            "id": "evidence-duty-card",
            "text": (
                "A duty of care may arise where the neighbour principle and "
                "reasonably foreseeable harm are established."
            ),
            "subject": "tort",
        }
    )
    plan = build_issue_plan(
        question="Is a duty of care owed?",
        jurisdiction="England and Wales",
        subject="tort",
        notes=[_note("card", "Spot duty of care on these facts.")],
    )
    flow = run_teaching_verify_cite_flow(
        issue_plan=plan,
        authority_evidence=[supporting],
    )
    notes = render_teaching_notes_view(flow)
    sample_lines = [line for line in notes.splitlines() if line.strip()]
    assert sample_lines[0] == "notes"
    assert any(line.startswith("duty_of_care - ") for line in sample_lines)
    assert any(line.startswith("what: ") for line in sample_lines)
    assert any(line.startswith("authority: ") for line in sample_lines)
    forbidden = (
        "here verified",
        "here partly verified",
        "here contradicted",
        "here not found",
        "teaching suggested",
        "??? status",
        "Private teaching suggests",
    )
    lowered = notes.casefold()
    for phrase in forbidden:
        assert phrase.casefold() not in lowered
    assert "Example Act 2026" in notes
