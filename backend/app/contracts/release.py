"""VerifiedRelease, committed terminal event and complete AnswerJob builders."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Literal

from .schema_registry import ContractSchemaRegistry, canonical_json_bytes, seal_contract

PublicReleaseState = Literal["verified_full", "verified_concise", "verified_limited"]


def _utc(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def committed_terminal_event_id(
    *, job_id: str, attempt_id: str, lease_generation: int, sequence: int
) -> str:
    identity = hashlib.sha256(
        canonical_json_bytes(
            {
                "schema": "legalbot.committed-terminal-event-identity.v1",
                "job_id": job_id,
                "attempt_id": attempt_id,
                "lease_generation": lease_generation,
                "sequence": sequence,
            }
        )
    ).hexdigest()
    return f"event-{identity[:40]}"


def build_verified_release(
    *,
    job_id: str,
    answer_id: str,
    release_state: PublicReleaseState,
    answer_content_sha256: str,
    request_sha256: str,
    query_plan: Mapping[str, Any],
    query_plan_sha256: str,
    conversation_snapshot: Mapping[str, Any],
    fact_snapshot: Mapping[str, Any],
    retrieval_result: Mapping[str, Any],
    evidence_pack: Mapping[str, Any],
    claim_set: Mapping[str, Any],
    validation_report: Mapping[str, Any],
    validation_report_sha256: str,
    model_sha256: str,
    prompt_sha256: str,
    renderer_sha256: str,
    policy_bundle_sha256: str,
    repair_count: int,
    parent_answer_id: str | None,
    outbox_id: str,
    committed_at: datetime,
    terminal_event_id: str,
    release_reason_codes: Sequence[str],
    registry: ContractSchemaRegistry,
) -> dict[str, Any]:
    """Create a release only when every predecessor digest is exact."""

    for value in (
        query_plan,
        conversation_snapshot,
        fact_snapshot,
        retrieval_result,
        evidence_pack,
        claim_set,
        validation_report,
    ):
        registry.validate_new(value)
    if validation_report["final_disposition"] != release_state:
        raise ValueError("validation disposition does not authorize this release state")
    if any(
        check["material"] and check["result"] == "FAIL" for check in validation_report["checks"]
    ):
        raise ValueError("a material validation failure cannot publish")
    predecessor_checks = (
        (query_plan["request_sha256"], request_sha256, "request"),
        (retrieval_result["query_plan_sha256"], query_plan_sha256, "retrieval plan"),
        (evidence_pack["query_plan_sha256"], query_plan_sha256, "evidence plan"),
        (
            evidence_pack["retrieval_result_sha256"],
            retrieval_result["content_sha256"],
            "evidence retrieval",
        ),
        (claim_set["query_plan_sha256"], query_plan_sha256, "claim plan"),
        (
            claim_set["evidence_pack_sha256"],
            evidence_pack["content_sha256"],
            "claim evidence",
        ),
        (
            validation_report["claim_set_sha256"],
            claim_set["content_sha256"],
            "validation claims",
        ),
        (
            validation_report["evidence_pack_sha256"],
            evidence_pack["content_sha256"],
            "validation evidence",
        ),
        (
            validation_report_sha256,
            hashlib.sha256(canonical_json_bytes(validation_report)).hexdigest(),
            "validation report",
        ),
    )
    for actual, expected, label in predecessor_checks:
        if actual != expected:
            raise ValueError(f"release predecessor differs: {label}")
    if (
        query_plan["conversation_snapshot"]["content_sha256"]
        != conversation_snapshot["content_sha256"]
    ):
        raise ValueError("release conversation snapshot differs")
    if query_plan["fact_snapshot_id"] != fact_snapshot["snapshot_id"]:
        raise ValueError("release fact snapshot differs")
    if evidence_pack["fact_snapshot_sha256"] != fact_snapshot["content_sha256"]:
        raise ValueError("release evidence fact snapshot differs")
    if claim_set["fact_snapshot_sha256"] != fact_snapshot["content_sha256"]:
        raise ValueError("release claim fact snapshot differs")

    release_identity = hashlib.sha256(
        canonical_json_bytes(
            {
                "job_id": job_id,
                "answer_id": answer_id,
                "outbox_id": outbox_id,
                "validation_report_sha256": validation_report_sha256,
                "terminal_event_id": terminal_event_id,
            }
        )
    ).hexdigest()
    release = seal_contract(
        {
            "schema": "legalbot.verified-release.v1",
            "release_id": f"verified-release-{release_identity[:40]}",
            "job_id": job_id,
            "answer_id": answer_id,
            "release_state": release_state,
            "answer_content_sha256": answer_content_sha256,
            "request_sha256": request_sha256,
            "query_plan_sha256": query_plan_sha256,
            "conversation_snapshot_sha256": conversation_snapshot["content_sha256"],
            "fact_snapshot_sha256": fact_snapshot["content_sha256"],
            "evidence_pack_sha256": evidence_pack["content_sha256"],
            "candidate_sha256": retrieval_result["candidate_sha256"],
            "model_sha256": model_sha256,
            "prompt_sha256": prompt_sha256,
            "renderer_sha256": renderer_sha256,
            "policy_bundle_sha256": policy_bundle_sha256,
            "verification_report_sha256": validation_report_sha256,
            "repair_count": repair_count,
            "parent_answer_id": parent_answer_id,
            "outbox_id": outbox_id,
            "committed_at": _utc(committed_at),
            "conversation_revision": conversation_snapshot["revision"],
            "retrieval_result_sha256": retrieval_result["content_sha256"],
            "claim_set_sha256": claim_set["content_sha256"],
            "validation_report_id": validation_report["validation_report_id"],
            "response_disposition": query_plan["response_disposition"],
            "requested_as_of_date": query_plan["requested_as_of_date"],
            "jurisdiction": query_plan["jurisdiction"],
            "terminal_event_id": terminal_event_id,
            "release_reason_codes": list(dict.fromkeys(release_reason_codes)),
            "schema_selection_sha256": registry.manifest_sha256,
        }
    )
    registry.validate_new(release)
    return release


def build_committed_terminal_event(
    *,
    verified_release: Mapping[str, Any],
    attempt_id: str,
    lease_generation: int,
    sequence: int,
    emitted_at: datetime,
    registry: ContractSchemaRegistry,
) -> dict[str, Any]:
    registry.validate_new(verified_release)
    expected_id = committed_terminal_event_id(
        job_id=str(verified_release["job_id"]),
        attempt_id=attempt_id,
        lease_generation=lease_generation,
        sequence=sequence,
    )
    if verified_release["terminal_event_id"] != expected_id:
        raise ValueError("verified release terminal event identity differs")
    event = {
        "schema": "legalbot.job-event.v1",
        "event_id": expected_id,
        "job_id": verified_release["job_id"],
        "sequence": sequence,
        "event": "done",
        "emitted_at": _utc(emitted_at),
        "data": {
            "stage": None,
            "progress": 1.0,
            "message_code": "job.terminal.committed",
            "status": "complete",
            "release_state": verified_release["release_state"],
            "answer_id": verified_release["answer_id"],
            "release_sha256": verified_release["content_sha256"],
            "status_url": f"/api/v1/jobs/{verified_release['job_id']}",
            "release_id": verified_release["release_id"],
            "terminal_kind": "committed",
            "reset_from_sequence": None,
        },
        "attempt_id": attempt_id,
        "lease_generation": lease_generation,
    }
    registry.validate_new(event)
    return event


def build_complete_answer_job(
    *,
    job_id: str,
    request_id: str,
    request_sha256: str,
    idempotency_sha256: str,
    owner_scope_sha256: str,
    attempt_id: str,
    lease_generation: int,
    conversation_snapshot_sha256: str,
    fact_snapshot_sha256: str,
    query_plan_sha256: str,
    retrieval_result_sha256: str,
    evidence_pack_sha256: str,
    claim_set_sha256: str,
    validation_report_sha256: str,
    release_sha256: str,
    created_at: datetime,
    terminal_at: datetime,
    registry: ContractSchemaRegistry,
) -> dict[str, Any]:
    terminal = _utc(terminal_at)
    job = seal_contract(
        {
            "schema": "legalbot.answer-job.v1",
            "job_id": job_id,
            "request_id": request_id,
            "request_sha256": request_sha256,
            "idempotency_sha256": idempotency_sha256,
            "owner_scope_sha256": owner_scope_sha256,
            "attempt_id": attempt_id,
            "lease_generation": lease_generation,
            "state": "complete",
            "stage": "complete",
            "conversation_snapshot_sha256": conversation_snapshot_sha256,
            "fact_snapshot_sha256": fact_snapshot_sha256,
            "query_plan_sha256": query_plan_sha256,
            "retrieval_result_sha256": retrieval_result_sha256,
            "evidence_pack_sha256": evidence_pack_sha256,
            "claim_set_sha256": claim_set_sha256,
            "validation_report_sha256": validation_report_sha256,
            "release_sha256": release_sha256,
            "failure_fingerprint": None,
            "created_at": _utc(created_at),
            "updated_at": terminal,
            "terminal_at": terminal,
        }
    )
    registry.validate_new(job)
    return job


__all__ = [
    "PublicReleaseState",
    "build_committed_terminal_event",
    "build_complete_answer_job",
    "build_verified_release",
    "committed_terminal_event_id",
]
