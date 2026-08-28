from __future__ import annotations

import json
import stat
from datetime import date
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from app.quality.ai_evidence_reviewer import (
    AIEvidenceReviewerCheckpointStore,
    AIEvidenceReviewResult,
    AIEvidenceReviewVersionGateError,
    AIReviewerClaimCheckpoint,
    invoke_ai_evidence_reviewer,
    load_persisted_ai_evidence_review,
    seal_ai_reviewer_invocation_trace,
)
from app.quality.draft_identity import source_draft_sha256
from app.types import (
    EvidenceSpan,
    MaterialLane,
    StructuredClaimDraft,
    StructuredDraft,
    StructuredSectionDraft,
    TaskType,
)

POLICY_SHA256 = "a" * 64


def _evidence(number: int) -> EvidenceSpan:
    return EvidenceSpan(
        id=f"evidence-{number}",
        source_version_id=f"source-version-{number}",
        chunk_id=f"chunk-{number}",
        text=f"Verified statutory proposition {number} applies.",
        locator=f"s {number}",
        lane=MaterialLane.PRIMARY_AUTHORITY,
        jurisdiction="England and Wales",
        subject="contract",
        currentness_status="current",
        content_sha256=f"{number}" * 64,
        index_build_id="candidate-v111",
        identity_verified=True,
        currentness_verified=True,
    )


def _draft() -> StructuredDraft:
    return StructuredDraft(
        title="Private draft",
        task_type=TaskType.ESSAY,
        jurisdiction="England and Wales",
        as_of_date=date(2026, 8, 20),
        sections=[
            StructuredSectionDraft(
                id="section-1",
                heading="Rule",
                claims=[
                    StructuredClaimDraft(
                        id=f"claim-{number}",
                        text=f"The material proposition {number} applies.",
                        evidence_ids=[f"evidence-{number}"],
                    )
                    for number in (1, 2)
                ],
            )
        ],
    )


def _evidence_map() -> dict[str, EvidenceSpan]:
    return {f"evidence-{number}": _evidence(number) for number in (1, 2)}


class _ScriptedReviewer:
    def __init__(self, *, fail_claim_id: str | None = None) -> None:
        self.fail_claim_id = fail_claim_id
        self.calls: list[str] = []

    async def invoke_json(self, **kwargs: Any) -> tuple[Any, ...]:
        payload = kwargs["user_payload"]
        claim = payload["claims"][0]
        claim_id = str(claim["claim_id"])
        self.calls.append(claim_id)
        if claim_id == self.fail_claim_id:
            raise RuntimeError("reviewer_transport_lost")
        evidence_id = str(claim["evidence"][0]["evidence_id"])
        ordinal = int(claim_id.rsplit("-", 1)[1])
        return (
            f"review-invocation-{ordinal:03d}",
            {
                "claims": [
                    {
                        "claim_id": claim_id,
                        "verdict": "supported",
                        "reason_codes": ["entailed_by_frozen_span"],
                        "cited_evidence_ids": [evidence_id],
                    }
                ]
            },
            {
                "duration_ms": ordinal * 7,
                "input_tokens": ordinal * 101,
                "output_tokens": ordinal * 11,
            },
        )


async def _invoke(
    *,
    model: object,
    store: AIEvidenceReviewerCheckpointStore,
    draft: StructuredDraft | None = None,
    policy_sha256: str = POLICY_SHA256,
    model_id: str = "reviewer-model",
) -> AIEvidenceReviewResult:
    return await invoke_ai_evidence_reviewer(
        model=model,
        draft=draft or _draft(),
        evidence_by_id=_evidence_map(),
        model_id=model_id,
        model_version="2026-08-20",
        policy_sha256=policy_sha256,
        checkpoint_store=store,
    )


@pytest.mark.asyncio
async def test_late_failure_resumes_sealed_claim_without_replaying_transport(
    tmp_path: Path,
) -> None:
    checkpoint_directory = tmp_path / "private-review-checkpoints"
    first_store = AIEvidenceReviewerCheckpointStore(checkpoint_directory, resume=False)
    first_model = _ScriptedReviewer(fail_claim_id="claim-2")

    with pytest.raises(RuntimeError, match="reviewer_transport_lost"):
        await _invoke(model=first_model, store=first_store)

    assert first_model.calls == ["claim-1", "claim-2"]
    checkpoint_files = tuple(checkpoint_directory.glob("*.json"))
    assert len(checkpoint_files) == 1
    assert stat.S_IMODE(checkpoint_directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(checkpoint_files[0].stat().st_mode) == 0o600

    checkpoint_text = checkpoint_files[0].read_text(encoding="utf-8")
    assert "The material proposition" not in checkpoint_text
    assert "Verified statutory proposition" not in checkpoint_text
    assert "chain_of_thought" not in checkpoint_text
    assert "/Users/" not in checkpoint_text
    checkpoint = AIReviewerClaimCheckpoint.model_validate_json(checkpoint_text)
    assert checkpoint.source_draft_sha256 == source_draft_sha256(_draft())
    assert checkpoint.claim_identity.claim_id == "claim-1"
    assert checkpoint.decision.claim_id == "claim-1"
    assert checkpoint.invocation_trace.input_token_count == 101
    assert checkpoint.invocation_trace.output_token_count == 11

    resumed_store = AIEvidenceReviewerCheckpointStore(checkpoint_directory, resume=True)
    resumed_model = _ScriptedReviewer()
    review = await _invoke(model=resumed_model, store=resumed_store)

    assert resumed_model.calls == ["claim-2"]
    assert (
        load_persisted_ai_evidence_review(review.model_dump(mode="json", by_alias=True)) == review
    )
    assert review.passed is True
    assert review.invocation_ids == (
        "review-invocation-001",
        "review-invocation-002",
    )
    assert [trace.resumed_from_checkpoint for trace in review.invocation_traces] == [
        True,
        False,
    ]
    assert [trace.duration_ms for trace in review.invocation_traces] == [7, 14]
    assert [trace.input_token_count for trace in review.invocation_traces] == [101, 202]
    assert [trace.output_token_count for trace in review.invocation_traces] == [11, 22]
    assert all(trace.checkpoint_seal_sha256 for trace in review.invocation_traces)
    assert all(trace.seal_sha256 for trace in review.invocation_traces)
    assert len(tuple(checkpoint_directory.glob("*.json"))) == 2
    assert all(
        stat.S_IMODE(path.stat().st_mode) == 0o600 for path in checkpoint_directory.glob("*.json")
    )

    fully_resumed = await _invoke(
        model=object(),
        store=AIEvidenceReviewerCheckpointStore(checkpoint_directory, resume=True),
    )
    assert all(trace.resumed_from_checkpoint for trace in fully_resumed.invocation_traces)
    assert fully_resumed.invocation_ids == review.invocation_ids


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ("source_draft", "binding differs"),
        ("policy", "binding differs"),
        ("model", "binding differs"),
    ],
)
async def test_resume_rejects_changed_exact_provenance_before_transport(
    tmp_path: Path,
    change: str,
    expected: str,
) -> None:
    checkpoint_directory = tmp_path / f"checkpoints-{change}"
    original_model = _ScriptedReviewer()
    await _invoke(
        model=original_model,
        store=AIEvidenceReviewerCheckpointStore(checkpoint_directory, resume=False),
    )
    assert original_model.calls == ["claim-1", "claim-2"]

    changed_draft = _draft()
    if change == "source_draft":
        changed_draft.limitations.append("Non-material source-draft change.")
    policy = "b" * 64 if change == "policy" else POLICY_SHA256
    model_id = "different-reviewer-model" if change == "model" else "reviewer-model"
    no_replay_model = _ScriptedReviewer()
    with pytest.raises(ValueError, match=expected):
        await _invoke(
            model=no_replay_model,
            store=AIEvidenceReviewerCheckpointStore(checkpoint_directory, resume=True),
            draft=changed_draft,
            policy_sha256=policy,
            model_id=model_id,
        )
    assert no_replay_model.calls == []


@pytest.mark.asyncio
async def test_metrics_and_store_contracts_fail_closed(tmp_path: Path) -> None:
    class InvalidMetricsReviewer(_ScriptedReviewer):
        async def invoke_json(self, **kwargs: Any) -> tuple[Any, ...]:
            response = await super().invoke_json(**kwargs)
            return (*response[:2], {"input_tokens": -1})

    checkpoint_directory = tmp_path / "invalid-metrics"
    with pytest.raises(ValueError, match="outside its bounded integer contract"):
        await _invoke(
            model=InvalidMetricsReviewer(),
            store=AIEvidenceReviewerCheckpointStore(checkpoint_directory, resume=False),
        )
    assert tuple(checkpoint_directory.iterdir()) == ()

    with pytest.raises(FileExistsError):
        AIEvidenceReviewerCheckpointStore(checkpoint_directory, resume=False)
    checkpoint_directory.chmod(0o755)
    with pytest.raises(PermissionError, match="0700"):
        AIEvidenceReviewerCheckpointStore(checkpoint_directory, resume=True)

    with pytest.raises(ValidationError, match="greater than or equal to 0"):
        seal_ai_reviewer_invocation_trace(
            claim_id="claim-1",
            invocation_id="review-invocation-001",
            duration_ms=-1,
            timing_source="local_monotonic",
        )


def test_review_trace_is_self_sealed_and_tamper_evident() -> None:
    trace = seal_ai_reviewer_invocation_trace(
        claim_id="claim-1",
        invocation_id="review-invocation-001",
        duration_ms=17,
        input_token_count=100,
        output_token_count=20,
        timing_source="transport",
    )
    payload = json.loads(trace.model_dump_json(by_alias=True))
    payload["duration_ms"] = 18

    with pytest.raises(ValidationError, match="seal"):
        type(trace).model_validate(payload)


@pytest.mark.parametrize(
    "schema",
    (
        "legalbot.ai-evidence-review.v2",
        "legalbot.ai-evidence-review.v3",
        "legalbot.ai-evidence-review.v4",
    ),
)
def test_persisted_legacy_review_is_explicitly_non_releasable(schema: str) -> None:
    with pytest.raises(AIEvidenceReviewVersionGateError, match="fresh v5 review required"):
        load_persisted_ai_evidence_review({"schema": schema, "seal_sha256": "0" * 64})

    with pytest.raises(AIEvidenceReviewVersionGateError, match="unsupported"):
        load_persisted_ai_evidence_review(
            {
                "schema": "legalbot.ai-evidence-review.v999",
                "seal_sha256": "0" * 64,
            }
        )
