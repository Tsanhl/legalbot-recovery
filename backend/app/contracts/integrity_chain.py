"""Typed digest closure for one complete request-to-release chain."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .schema_registry import ContractSchemaRegistry, canonical_json_bytes


class IntegrityChainError(ValueError):
    """One object is missing, substituted, out of order or cross-bound."""


@dataclass(frozen=True, slots=True)
class IntegrityChainReceipt:
    job_id: str
    request_id: str
    schema_selection_sha256: str
    object_sha256: Mapping[str, str]
    terminal_event_id: str
    chain_sha256: str


def _require_equal(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        raise IntegrityChainError(f"integrity chain mismatch: {label}")


def _require_unique_ids(values: list[Any], *, field: str) -> None:
    identifiers = [str(value[field]) for value in values]
    if len(identifiers) != len(set(identifiers)):
        raise IntegrityChainError(f"duplicate logical ID: {field}")


class AnswerIntegrityChainVerifier:
    """Verify all selected objects before a committed terminal event may publish."""

    def __init__(self, registry: ContractSchemaRegistry) -> None:
        self.registry = registry

    def verify_complete(
        self,
        *,
        job_id: str,
        request_id: str,
        request_sha256: str,
        conversation_snapshot: Mapping[str, Any],
        fact_snapshot: Mapping[str, Any],
        query_plan: Mapping[str, Any],
        retrieval_result: Mapping[str, Any],
        evidence_pack: Mapping[str, Any],
        claim_set: Mapping[str, Any],
        validation_report: Mapping[str, Any],
        verified_release: Mapping[str, Any],
        terminal_event: Mapping[str, Any],
        answer_job: Mapping[str, Any] | None = None,
    ) -> IntegrityChainReceipt:
        objects = (
            conversation_snapshot,
            fact_snapshot,
            query_plan,
            retrieval_result,
            evidence_pack,
            claim_set,
            validation_report,
            verified_release,
            terminal_event,
        )
        for value in objects:
            self.registry.validate_new(value)
        if answer_job is not None:
            self.registry.validate_new(answer_job)

        digests = {
            str(value["schema"]): str(value["content_sha256"])
            for value in objects
            if "content_sha256" in value
        }
        conversation_digest = str(conversation_snapshot["content_sha256"])
        fact_digest = str(fact_snapshot["content_sha256"])
        plan_digest = str(query_plan.get("content_sha256") or "")
        # QueryPlan v2 deliberately has no self digest field. Freeze the exact
        # validated bytes for downstream predecessor binding.
        if not plan_digest:
            plan_digest = hashlib.sha256(canonical_json_bytes(query_plan)).hexdigest()
            digests[str(query_plan["schema"])] = plan_digest
        retrieval_digest = str(retrieval_result["content_sha256"])
        evidence_digest = str(evidence_pack["content_sha256"])
        claim_digest = str(claim_set["content_sha256"])
        validation_digest = hashlib.sha256(canonical_json_bytes(validation_report)).hexdigest()
        # ValidationReport v1 has no self digest field; its canonical digest is
        # what VerifiedRelease calls verification_report_sha256.
        digests[str(validation_report["schema"])] = validation_digest
        release_digest = str(verified_release["content_sha256"])

        _require_equal(query_plan["request_id"], request_id, "query request ID")
        _require_equal(query_plan["request_sha256"], request_sha256, "query request digest")
        _require_equal(
            query_plan["schema_selection_sha256"],
            self.registry.manifest_sha256,
            "query schema selection",
        )
        conversation_ref = query_plan["conversation_snapshot"]
        _require_equal(
            conversation_ref["conversation_id"],
            conversation_snapshot["conversation_id"],
            "query conversation ID",
        )
        _require_equal(
            conversation_ref["revision"],
            conversation_snapshot["revision"],
            "query conversation revision",
        )
        _require_equal(
            conversation_ref["content_sha256"],
            conversation_digest,
            "query conversation digest",
        )
        _require_equal(query_plan["fact_snapshot_id"], fact_snapshot["snapshot_id"], "fact ID")
        _require_equal(
            fact_snapshot["conversation_id"],
            conversation_snapshot["conversation_id"],
            "fact conversation ID",
        )
        _require_equal(
            fact_snapshot["conversation_revision"],
            conversation_snapshot["revision"],
            "fact conversation revision",
        )

        _require_equal(
            retrieval_result["query_plan_id"], query_plan["query_plan_id"], "retrieval plan ID"
        )
        _require_equal(retrieval_result["query_plan_sha256"], plan_digest, "retrieval plan digest")
        _require_equal(
            retrieval_result["candidate_id"], query_plan["candidate_id"], "retrieval candidate"
        )

        _require_equal(
            evidence_pack["query_plan_id"], query_plan["query_plan_id"], "evidence plan ID"
        )
        _require_equal(evidence_pack["query_plan_sha256"], plan_digest, "evidence plan digest")
        _require_equal(
            evidence_pack["retrieval_result_sha256"], retrieval_digest, "evidence retrieval digest"
        )
        _require_equal(evidence_pack["fact_snapshot_sha256"], fact_digest, "evidence fact digest")

        _require_equal(claim_set["job_id"], job_id, "claim job ID")
        _require_equal(claim_set["query_plan_sha256"], plan_digest, "claim plan digest")
        _require_equal(claim_set["fact_snapshot_sha256"], fact_digest, "claim fact digest")
        _require_equal(claim_set["evidence_pack_sha256"], evidence_digest, "claim evidence digest")
        _require_unique_ids(list(claim_set["claims"]), field="claim_id")

        _require_equal(
            validation_report["claim_set_sha256"], claim_digest, "validation claim digest"
        )
        _require_equal(
            validation_report["evidence_pack_sha256"], evidence_digest, "validation evidence digest"
        )
        _require_equal(
            validation_report["fact_snapshot_sha256"], fact_digest, "validation fact digest"
        )
        _require_unique_ids(list(validation_report["checks"]), field="check_id")

        release_checks = {
            "job_id": job_id,
            "request_sha256": request_sha256,
            "query_plan_sha256": plan_digest,
            "conversation_snapshot_sha256": conversation_digest,
            "fact_snapshot_sha256": fact_digest,
            "retrieval_result_sha256": retrieval_digest,
            "evidence_pack_sha256": evidence_digest,
            "claim_set_sha256": claim_digest,
            "verification_report_sha256": validation_digest,
            "validation_report_id": validation_report["validation_report_id"],
            "schema_selection_sha256": self.registry.manifest_sha256,
            "conversation_revision": conversation_snapshot["revision"],
            "response_disposition": query_plan["response_disposition"],
            "requested_as_of_date": query_plan["requested_as_of_date"],
            "jurisdiction": query_plan["jurisdiction"],
            "candidate_sha256": retrieval_result["candidate_sha256"],
        }
        for field, expected in release_checks.items():
            _require_equal(verified_release[field], expected, f"release {field}")

        _require_equal(terminal_event["job_id"], job_id, "terminal job ID")
        _require_equal(terminal_event["event"], "done", "terminal event kind")
        _require_equal(
            terminal_event["event_id"],
            verified_release["terminal_event_id"],
            "terminal event ID",
        )
        terminal_data = terminal_event["data"]
        _require_equal(terminal_data["terminal_kind"], "committed", "terminal disposition")
        _require_equal(
            terminal_data["release_id"], verified_release["release_id"], "terminal release ID"
        )
        _require_equal(terminal_data["release_sha256"], release_digest, "terminal release digest")

        if answer_job is not None:
            job_checks = {
                "job_id": job_id,
                "request_id": request_id,
                "request_sha256": request_sha256,
                "conversation_snapshot_sha256": conversation_digest,
                "fact_snapshot_sha256": fact_digest,
                "query_plan_sha256": plan_digest,
                "retrieval_result_sha256": retrieval_digest,
                "evidence_pack_sha256": evidence_digest,
                "claim_set_sha256": claim_digest,
                "validation_report_sha256": validation_digest,
                "release_sha256": release_digest,
            }
            for field, expected in job_checks.items():
                _require_equal(answer_job[field], expected, f"answer job {field}")

        object_digests: Mapping[str, str] = dict(sorted(digests.items()))
        receipt_material = {
            "schema": "legalbot.integrity-chain-receipt.v1",
            "job_id": job_id,
            "request_id": request_id,
            "schema_selection_sha256": self.registry.manifest_sha256,
            "object_sha256": object_digests,
            "terminal_event_id": str(terminal_event["event_id"]),
        }
        chain_sha256 = hashlib.sha256(canonical_json_bytes(receipt_material)).hexdigest()
        return IntegrityChainReceipt(
            job_id=job_id,
            request_id=request_id,
            schema_selection_sha256=self.registry.manifest_sha256,
            object_sha256=object_digests,
            terminal_event_id=str(terminal_event["event_id"]),
            chain_sha256=chain_sha256,
        )


__all__ = [
    "AnswerIntegrityChainVerifier",
    "IntegrityChainError",
    "IntegrityChainReceipt",
]
