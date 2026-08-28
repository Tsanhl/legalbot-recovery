"""Typed, exact-case owner-canary projection and final-package reconciliation.

The adapter is the only bridge from an authoritative released-answer artifact
to the readable owner review workspace.  It recomputes the exact UTF-8 bytes,
hash, canonical word count and privacy checks, revalidates every positive gate
artifact, and writes create-only machine projections.  The serial circuit only
marks a case complete after receiving the sealed receipt produced here.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol, Self, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..crypto import LocalCipher
from ..privacy import contains_absolute_private_path, prompt_injection_hits
from ..text_metrics import word_count
from .canary_review_workspace import (
    RELEASE_PROJECTION_SCHEMA,
    CanaryReviewWorkspace,
    ReleasedAnswerProjection,
)
from .live30 import assert_safe_evaluation_payload
from .live_suite import LiveEvaluationBundle, sealed_sha256
from .owner_quality_canary import OwnerQualityCanaryManifest
from .owner_quality_canary_artifacts import (
    OwnerCanaryCaseProjectionReceipt,
    OwnerCanaryDeterministicGateReport,
    OwnerCanaryEvidenceBundle,
    OwnerCanaryReleaseAttestation,
    verify_positive_release_artifacts,
)
from .owner_quality_canary_authorization import OwnerCanaryAuthorization
from .owner_quality_canary_circuit import (
    CaseCallback,
    OwnerCanaryCaseAttemptResult,
    OwnerCanaryCaseCallback,
    OwnerCanaryCircuitResult,
    run_owner_canary_serial,
)
from .owner_quality_owned_model_runtime import (
    VerifiedEndedOwnerCanaryRuntime,
    require_verified_ended_owner_canary_runtime,
)

GAP_INVENTORY_SCHEMA = "legalbot.owner-canary-gap-inventory.v1"
SAFE_METRICS_SCHEMA = "legalbot.owner-canary-safe-case-metrics.v1"
RETRY_PROJECTION_SCHEMA = "legalbot.owner-canary-case-retry-projection.v1"
AI_PROJECTION_SCHEMA = "legalbot.owner-canary-ai-projection.v1"
STANDARDS_PROJECTION_SCHEMA = "legalbot.owner-canary-standards-projection.v1"
FINAL_REVIEW_PACKAGE_SCHEMA = "legalbot.owner-canary-final-review-package.v1"

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_SAFE_CODE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_CASE_ID = re.compile(r"^(?:live30|live60)-q[0-9]{2}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _workspace_file_sha256(workspace: CanaryReviewWorkspace, category: str, filename: str) -> str:
    try:
        data = workspace.read_private_bytes(category, filename)
    except FileNotFoundError as exc:
        raise ValueError("owner-canary workspace projection is missing") from exc
    return hashlib.sha256(data).hexdigest()


def _sealed_projection(schema: str, value: Mapping[str, Any]) -> dict[str, Any]:
    material = {"schema": schema, **dict(value)}
    assert_safe_evaluation_payload(material)
    material["seal_sha256"] = sealed_sha256(material)
    return material


class OwnerCanaryGapDisposition(BaseModel):
    """Safe gap identity; detailed legal content remains in the encrypted store."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    gap_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    issue_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    status: Literal[
        "resolved_in_candidate",
        "owner_decision_required",
        "staged_official_material",
        "not_material",
    ]
    material: bool
    detailed_content_encrypted: Literal[True] = True


class OwnerCanaryGapInventory(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-canary-gap-inventory.v1"] = Field(
        default="legalbot.owner-canary-gap-inventory.v1", alias="schema"
    )
    workspace_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    authorization_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    canary_manifest_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    case_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    candidate_build_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    candidate_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    gap_count: int = Field(ge=0)
    gaps: tuple[OwnerCanaryGapDisposition, ...]
    detailed_content_retained: Literal[False]
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def inventory_is_complete_and_sealed(self) -> Self:
        gap_ids = tuple(item.gap_id for item in self.gaps)
        if self.gap_count != len(self.gaps) or len(gap_ids) != len(set(gap_ids)):
            raise ValueError("owner-canary gap inventory is inconsistent")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("owner-canary gap inventory seal does not match")
        return self


class OwnerCanaryFinalReviewPackage(BaseModel):
    """Exact 30-case projection seal used by the answer-only DOCX exporter."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-canary-final-review-package.v1"] = Field(
        default="legalbot.owner-canary-final-review-package.v1", alias="schema"
    )
    workspace_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    lane: Literal["development", "blind_holdout"]
    authorization_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    canary_manifest_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    circuit_result_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_build_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    candidate_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    case_count: Literal[30]
    case_ids: tuple[str, ...]
    projection_receipts: tuple[OwnerCanaryCaseProjectionReceipt, ...]
    projection_receipt_seal_sha256s: tuple[str, ...]
    answer_sha256s: tuple[str, ...]
    reviewer_invocation_trace_seal_sha256s: tuple[str, ...]
    reviewer_total_duration_ms: int = Field(ge=0)
    reviewer_total_input_tokens: int = Field(ge=0)
    reviewer_total_output_tokens: int = Field(ge=0)
    reviewer_token_counts_complete: bool
    exact_case_projection_reconciled: Literal[True]
    answer_only: Literal[True]
    plaintext_questions_included: Literal[False]
    tuning_input_allowed: bool
    eligible_for_training: Literal[False]
    training_export_allowed: Literal[False]
    create_only: Literal[True]
    owned_runtime_start_attestation_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    owned_runtime_end_attestation_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    owned_runtime_instance_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    owned_runtime_memory_policy_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    owned_runtime_checkpoint_set_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    authoritative_owned_runtime: bool = False
    synthetic_non_authoritative: bool = False
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator(
        "case_ids",
        "projection_receipt_seal_sha256s",
        "reviewer_invocation_trace_seal_sha256s",
    )
    @classmethod
    def ordered_identities_are_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("owner-canary final package contains duplicate identities")
        return values

    @model_validator(mode="after")
    def package_is_exact_and_sealed(self) -> Self:
        if (
            len(self.case_ids) != 30
            or len(self.projection_receipts) != 30
            or len(self.projection_receipt_seal_sha256s) != 30
            or len(self.answer_sha256s) != 30
            or tuple(item.case_id for item in self.projection_receipts) != self.case_ids
            or tuple(item.seal_sha256 for item in self.projection_receipts)
            != self.projection_receipt_seal_sha256s
            or tuple(item.answer_sha256 for item in self.projection_receipts) != self.answer_sha256s
            or self.tuning_input_allowed != (self.lane == "development")
            or self.reviewer_token_counts_complete
            != all(item.reviewer_token_counts_complete for item in self.projection_receipts)
        ):
            raise ValueError("owner-canary final review package is incomplete")
        all_trace_seals = tuple(
            seal
            for receipt in self.projection_receipts
            for seal in receipt.reviewer_invocation_trace_seal_sha256s
        )
        if all_trace_seals != self.reviewer_invocation_trace_seal_sha256s:
            raise ValueError("owner-canary reviewer trace inventory is incomplete")
        runtime_values = (
            self.owned_runtime_start_attestation_sha256,
            self.owned_runtime_end_attestation_sha256,
            self.owned_runtime_instance_sha256,
            self.owned_runtime_memory_policy_sha256,
            self.owned_runtime_checkpoint_set_sha256,
        )
        if self.authoritative_owned_runtime:
            if self.synthetic_non_authoritative or any(value is None for value in runtime_values):
                raise ValueError("owner-canary final package lacks exact owned runtime evidence")
        elif any(value is not None for value in runtime_values):
            raise ValueError("legacy owner-canary package carries partial runtime evidence")
        material = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        current_seal = sealed_sha256(material)
        legacy_material = dict(material)
        if not self.authoritative_owned_runtime and not self.synthetic_non_authoritative:
            legacy_material.pop("authoritative_owned_runtime", None)
            legacy_material.pop("synthetic_non_authoritative", None)
        legacy_seal = sealed_sha256(legacy_material)
        if self.seal_sha256 not in {current_seal, legacy_seal}:
            raise ValueError("owner-canary final review package seal does not match")
        return self


class ReleasedAnswerLoader(Protocol):
    def __call__(self, answer_artifact_id: str) -> bytes: ...


type AnswerLoader = Callable[[str], bytes]


class OwnerCanaryProjectionAdapter:
    """Stateful create-only projector used as the circuit's required callback."""

    def __init__(
        self,
        *,
        workspace: CanaryReviewWorkspace,
        authorization: OwnerCanaryAuthorization,
        manifest: OwnerQualityCanaryManifest,
        answer_loader: ReleasedAnswerLoader | AnswerLoader,
        gap_inventory_by_case: Mapping[
            str, Sequence[OwnerCanaryGapDisposition | Mapping[str, Any]]
        ],
        pre_readable_commit_callback: Callable[[str], Any] | None = None,
    ) -> None:
        expected_ids = authorization.authorized_case_ids
        if (
            workspace.manifest.run_id != authorization.run_id
            or workspace.manifest.runtime_run_manifest_sha256 != authorization.seal_sha256
            or workspace.manifest.canary_manifest_seal_sha256 != manifest.seal_sha256
            or workspace.manifest.expected_case_ids != expected_ids
            or set(gap_inventory_by_case) != set(expected_ids)
        ):
            raise ValueError("owner-canary projection inputs differ from authorization")
        self.workspace = workspace
        self.authorization = authorization
        self.manifest = manifest
        self.answer_loader = answer_loader
        self.gap_inventory_by_case = {
            case_id: tuple(OwnerCanaryGapDisposition.model_validate(item) for item in values)
            for case_id, values in gap_inventory_by_case.items()
        }
        self.pre_readable_commit_callback = pre_readable_commit_callback
        self._receipts: list[OwnerCanaryCaseProjectionReceipt] = []
        # Readable answer bytes are deliberately process-local until the whole
        # serial runtime has ended and its final model/toolchain/integration
        # re-attestation has passed.  The durable source remains encrypted.
        self._pending_answers: dict[str, bytes] = {}

    @property
    def receipts(self) -> tuple[OwnerCanaryCaseProjectionReceipt, ...]:
        return tuple(self._receipts)

    def _gap_inventory(self, result: OwnerCanaryCaseAttemptResult) -> OwnerCanaryGapInventory:
        gaps = self.gap_inventory_by_case[result.case_id]
        if any(item.material and item.status != "resolved_in_candidate" for item in gaps):
            raise ValueError("material owner-canary knowledge gap blocks readable projection")
        material: dict[str, Any] = {
            "schema": GAP_INVENTORY_SCHEMA,
            "workspace_seal_sha256": self.workspace.manifest.seal_sha256,
            "run_id": result.run_id,
            "authorization_seal_sha256": result.authorization_seal_sha256,
            "canary_manifest_seal_sha256": result.canary_manifest_seal_sha256,
            "case_id": result.case_id,
            "candidate_build_id": result.candidate_build_id,
            "candidate_manifest_sha256": result.candidate_manifest_sha256,
            "gap_count": len(gaps),
            "gaps": [item.model_dump(mode="json") for item in gaps],
            "detailed_content_retained": False,
        }
        material["seal_sha256"] = sealed_sha256(material)
        return OwnerCanaryGapInventory.model_validate(material)

    def project(self, result: OwnerCanaryCaseAttemptResult) -> OwnerCanaryCaseProjectionReceipt:
        result = OwnerCanaryCaseAttemptResult.model_validate(
            result.model_dump(mode="json", by_alias=True)
        )
        if result.case_id in {receipt.case_id for receipt in self._receipts}:
            raise FileExistsError("owner-canary case projection is create-only")
        required = (
            result.job_id,
            result.answer_version_id,
            result.answer_artifact_id,
            result.answer_sha256,
            result.word_count,
            result.ai_review,
            result.ai_adjudication,
            result.standards_report,
            result.evidence_bundle,
            result.deterministic_gate_report,
            result.release_attestation,
        )
        if not result.released or any(value is None for value in required):
            raise ValueError("owner-canary projection requires a positive released result")
        if (
            result.run_id != self.authorization.run_id
            or result.authorization_seal_sha256 != self.authorization.seal_sha256
            or result.canary_manifest_seal_sha256 != self.manifest.seal_sha256
            or result.candidate_build_id != self.authorization.candidate_build_id
            or result.candidate_manifest_sha256 != self.authorization.candidate_manifest_sha256
            or result.case_id not in self.authorization.authorized_case_ids
        ):
            raise ValueError("owner-canary result differs from projection authorization")

        ai_review = cast(Any, result.ai_review)
        adjudication = cast(Any, result.ai_adjudication)
        standards = cast(Any, result.standards_report)
        evidence = cast(OwnerCanaryEvidenceBundle, result.evidence_bundle)
        gates = cast(OwnerCanaryDeterministicGateReport, result.deterministic_gate_report)
        release = cast(OwnerCanaryReleaseAttestation, result.release_attestation)
        if not ai_review.passed or not adjudication.passed or not standards.avoidance_passed:
            raise ValueError("owner-canary projection received a failed AI or standards gate")
        verify_positive_release_artifacts(
            run_id=result.run_id,
            authorization_seal_sha256=result.authorization_seal_sha256,
            canary_manifest_seal_sha256=result.canary_manifest_seal_sha256,
            case_id=result.case_id,
            candidate_build_id=result.candidate_build_id,
            candidate_manifest_sha256=result.candidate_manifest_sha256,
            job_id=cast(str, result.job_id),
            answer_version_id=cast(str, result.answer_version_id),
            answer_sha256=cast(str, result.answer_sha256),
            word_count=cast(int, result.word_count),
            ai_review=ai_review,
            evidence_bundle=evidence,
            deterministic_gate_report=gates,
            release_attestation=release,
        )

        raw = self.answer_loader(cast(str, result.answer_artifact_id))
        if not isinstance(raw, bytes) or not raw:
            raise ValueError("authoritative answer loader must return non-empty bytes")
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("authoritative released answer is not UTF-8") from exc
        if content.encode("utf-8") != raw or not content.strip():
            raise ValueError("authoritative released answer bytes are not canonical UTF-8")
        computed_sha = hashlib.sha256(raw).hexdigest()
        computed_words = word_count(content)
        if (
            computed_sha != result.answer_sha256
            or computed_words != result.word_count
            or contains_absolute_private_path(content)
            or prompt_injection_hits(content)
        ):
            raise ValueError("authoritative released answer failed hash, word or privacy checks")

        release_gates = {
            **gates.gates,
            "ai_evidence_review": True,
            "applicable_standards": True,
        }
        release_material: dict[str, Any] = {
            "schema": RELEASE_PROJECTION_SCHEMA,
            "workspace_seal_sha256": self.workspace.manifest.seal_sha256,
            "case_id": result.case_id,
            "lane": self.workspace.manifest.lane,
            "answer_sha256": computed_sha,
            "word_count": computed_words,
            "release_gates": dict(sorted(release_gates.items())),
            "all_required_release_gates_passed": True,
        }
        release_material["seal_sha256"] = sealed_sha256(release_material)
        release_projection = ReleasedAnswerProjection.model_validate(release_material)
        gap_inventory = self._gap_inventory(result)
        # The owned process/listener/memory/DB frontier is re-attested and
        # advanced only after every positive artifact and plaintext byte has
        # been validated, but before any readable answer reaches disk.
        if self.pre_readable_commit_callback is not None:
            self.pre_readable_commit_callback(result.case_id)

        self.workspace.write_safe_json(
            category="evidence-citation-maps",
            filename=f"{result.case_id}.json",
            value=evidence.model_dump(mode="json", by_alias=True),
        )
        ai_value = _sealed_projection(
            AI_PROJECTION_SCHEMA,
            {
                "workspace_seal_sha256": self.workspace.manifest.seal_sha256,
                "case_id": result.case_id,
                "review": ai_review.model_dump(mode="json", by_alias=True),
                "adjudication": adjudication.model_dump(mode="json", by_alias=True),
            },
        )
        self.workspace.write_safe_json(
            category="ai-reviews", filename=f"{result.case_id}.json", value=ai_value
        )
        standards_value = _sealed_projection(
            STANDARDS_PROJECTION_SCHEMA,
            {
                "workspace_seal_sha256": self.workspace.manifest.seal_sha256,
                "case_id": result.case_id,
                "report": standards.model_dump(mode="json", by_alias=True),
            },
        )
        self.workspace.write_safe_json(
            category="standards",
            filename=f"{result.case_id}.json",
            value=standards_value,
        )
        self.workspace.write_safe_json(
            category="gaps",
            filename=f"{result.case_id}.json",
            value=gap_inventory.model_dump(mode="json", by_alias=True),
        )

        traces = tuple(getattr(ai_review, "invocation_traces", ()))
        trace_seals = tuple(str(item.seal_sha256) for item in traces)
        duration_ms = sum(int(getattr(item, "duration_ms", 0)) for item in traces)
        raw_input_tokens = tuple(getattr(item, "input_token_count", None) for item in traces)
        raw_output_tokens = tuple(getattr(item, "output_token_count", None) for item in traces)
        input_tokens = sum(int(value) for value in raw_input_tokens if value is not None)
        output_tokens = sum(int(value) for value in raw_output_tokens if value is not None)
        token_counts_complete = all(
            value is not None for value in (*raw_input_tokens, *raw_output_tokens)
        )
        metrics_value = _sealed_projection(
            SAFE_METRICS_SCHEMA,
            {
                "workspace_seal_sha256": self.workspace.manifest.seal_sha256,
                "case_id": result.case_id,
                "attempt_number": result.attempt_number,
                "answer_byte_count": len(raw),
                "word_count": computed_words,
                "evidence_span_count": len(evidence.evidence_span_ids),
                "material_claim_count": ai_review.material_claim_count,
                "applicable_standard_count": len(standards.scores),
                "reviewer_invocation_count": len(traces),
                "reviewer_invocation_trace_seal_sha256s": list(trace_seals),
                "reviewer_total_duration_ms": duration_ms,
                "reviewer_total_input_tokens": input_tokens,
                "reviewer_total_output_tokens": output_tokens,
                "reviewer_token_counts_complete": token_counts_complete,
            },
        )
        self.workspace.write_safe_json(
            category="safe-metrics",
            filename=f"{result.case_id}-metrics.json",
            value=metrics_value,
        )
        retry_value = _sealed_projection(
            RETRY_PROJECTION_SCHEMA,
            {
                "workspace_seal_sha256": self.workspace.manifest.seal_sha256,
                "case_id": result.case_id,
                "attempt_number": result.attempt_number,
                "input_revision_sha256": result.input_revision_sha256,
                "attempt_result_seal_sha256": result.seal_sha256,
                "failure_reason_codes": list(result.failure_reason_codes),
                "deterministic_hard_failure_codes": list(result.deterministic_hard_failure_codes),
                "worker_hard_failure": result.worker_hard_failure,
                "next_input_revision_sha256": result.next_input_revision_sha256,
            },
        )
        self.workspace.write_safe_json(
            category="retry-trace",
            filename=f"{result.case_id}-projection.json",
            value=retry_value,
        )

        receipt_material: dict[str, Any] = {
            "schema": "legalbot.owner-canary-case-projection-receipt.v1",
            "workspace_seal_sha256": self.workspace.manifest.seal_sha256,
            "run_id": result.run_id,
            "authorization_seal_sha256": result.authorization_seal_sha256,
            "canary_manifest_seal_sha256": result.canary_manifest_seal_sha256,
            "case_id": result.case_id,
            "candidate_build_id": result.candidate_build_id,
            "candidate_manifest_sha256": result.candidate_manifest_sha256,
            "job_id": result.job_id,
            "answer_version_id": result.answer_version_id,
            "answer_artifact_id": result.answer_artifact_id,
            "attempt_result_seal_sha256": result.seal_sha256,
            "answer_sha256": computed_sha,
            "answer_byte_count": len(raw),
            "word_count": computed_words,
            "release_projection_seal_sha256": release_projection.seal_sha256,
            "evidence_projection_sha256": _workspace_file_sha256(
                self.workspace, "evidence-citation-maps", f"{result.case_id}.json"
            ),
            "ai_projection_sha256": _workspace_file_sha256(
                self.workspace, "ai-reviews", f"{result.case_id}.json"
            ),
            "standards_projection_sha256": _workspace_file_sha256(
                self.workspace, "standards", f"{result.case_id}.json"
            ),
            "gap_projection_sha256": _workspace_file_sha256(
                self.workspace, "gaps", f"{result.case_id}.json"
            ),
            "metrics_projection_sha256": _workspace_file_sha256(
                self.workspace, "safe-metrics", f"{result.case_id}-metrics.json"
            ),
            "retry_projection_sha256": _workspace_file_sha256(
                self.workspace, "retry-trace", f"{result.case_id}-projection.json"
            ),
            "evidence_bundle_seal_sha256": evidence.seal_sha256,
            "ai_review_seal_sha256": ai_review.seal_sha256,
            "ai_adjudication_seal_sha256": adjudication.seal_sha256,
            "reviewer_invocation_trace_seal_sha256s": list(trace_seals),
            "reviewer_total_duration_ms": duration_ms,
            "reviewer_total_input_tokens": input_tokens,
            "reviewer_total_output_tokens": output_tokens,
            "reviewer_token_counts_complete": token_counts_complete,
            "standards_report_seal_sha256": standards.seal_sha256,
            "deterministic_gate_report_seal_sha256": gates.seal_sha256,
            "release_attestation_seal_sha256": release.seal_sha256,
            "authoritative_answer_recomputed": True,
            "privacy_passed": True,
            "positive_artifacts_reverified": True,
            "plaintext_question_included": False,
        }
        receipt_material["seal_sha256"] = sealed_sha256(receipt_material)
        receipt = OwnerCanaryCaseProjectionReceipt.model_validate(receipt_material)
        self.workspace.create_private_directory("cases", result.case_id, exist_ok=False)
        self.workspace.write_private_bytes(
            "cases",
            result.case_id,
            "release-attestation.json",
            payload=(
                json.dumps(
                    release_projection.model_dump(mode="json", by_alias=True),
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8"),
        )
        self.workspace.write_safe_json(
            category="safe-metrics",
            filename=f"{result.case_id}-projection-receipt.json",
            value=receipt.model_dump(mode="json", by_alias=True),
        )
        self._receipts.append(receipt)
        self._pending_answers[result.case_id] = raw
        return receipt

    def commit_readable_answers(
        self, *, ended_runtime: VerifiedEndedOwnerCanaryRuntime | None
    ) -> None:
        """Materialize the exact 30 answers only after authoritative runtime end.

        Synthetic/legacy test executions have no owned runtime, but still call
        this method only after their complete serial circuit passes.  An
        authoritative execution must provide the opaque verified-ended
        capability and its exact case sequence must match the receipts.
        """

        ordered_case_ids = tuple(receipt.case_id for receipt in self._receipts)
        if ordered_case_ids != self.authorization.authorized_case_ids:
            raise ValueError("owner-canary readable commit requires exact case completion")
        if set(self._pending_answers) != set(ordered_case_ids):
            raise ValueError("owner-canary readable commit has incomplete staged answers")
        if ended_runtime is not None:
            verified = require_verified_ended_owner_canary_runtime(ended_runtime)
            if (
                verified.start.run_id != self.authorization.run_id
                or verified.start.authorization_seal_sha256 != self.authorization.seal_sha256
                or verified.start.canary_manifest_seal_sha256 != self.manifest.seal_sha256
                or verified.end.case_ids != ordered_case_ids
            ):
                raise ValueError("owner-canary ended runtime differs from readable commit")

        destinations = {
            case_id: self.workspace.root / "cases" / case_id / "released-answer.md"
            for case_id in ordered_case_ids
        }
        if any(path.exists() or path.is_symlink() for path in destinations.values()):
            raise FileExistsError("owner-canary readable answer projection is create-only")

        created: list[Path] = []
        try:
            for case_id in ordered_case_ids:
                path = self.workspace.write_private_bytes(
                    "cases",
                    case_id,
                    "released-answer.md",
                    payload=self._pending_answers[case_id],
                )
                created.append(path)
        except BaseException:
            # These paths were created by this invocation only.  Remove the
            # partial readable set so a failed commit never exposes a prefix.
            for path in reversed(created):
                path.unlink(missing_ok=True)
            raise
        self._pending_answers.clear()


def finalize_owner_canary_review_package(
    *,
    workspace: CanaryReviewWorkspace,
    authorization: OwnerCanaryAuthorization,
    manifest: OwnerQualityCanaryManifest,
    circuit_result: OwnerCanaryCircuitResult,
    receipts: Sequence[OwnerCanaryCaseProjectionReceipt],
    owned_runtime: VerifiedEndedOwnerCanaryRuntime | None = None,
    synthetic_non_authoritative: bool = False,
) -> OwnerCanaryFinalReviewPackage:
    """Re-read all 30 create-only projections and seal their exact completeness."""

    ordered = tuple(
        OwnerCanaryCaseProjectionReceipt.model_validate(item.model_dump(mode="json", by_alias=True))
        for item in receipts
    )
    if (
        circuit_result.status != "passed"
        or circuit_result.completed_case_ids != authorization.authorized_case_ids
        or circuit_result.projection_receipt_seal_sha256s
        != tuple(item.seal_sha256 for item in ordered)
        or tuple(item.case_id for item in ordered) != authorization.authorized_case_ids
        or workspace.manifest.canary_manifest_seal_sha256 != manifest.seal_sha256
    ):
        raise ValueError("owner-canary final package requires an exact passed circuit")

    for receipt in ordered:
        try:
            answer_bytes = workspace.read_private_bytes(
                "cases", receipt.case_id, "released-answer.md"
            )
        except FileNotFoundError as exc:
            raise ValueError(
                "owner-canary readable answer projection is missing or changed"
            ) from exc
        try:
            answer_text = answer_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("owner-canary readable answer projection is not UTF-8") from exc
        if (
            hashlib.sha256(answer_bytes).hexdigest() != receipt.answer_sha256
            or word_count(answer_text) != receipt.word_count
        ):
            raise ValueError("owner-canary readable answer projection is missing or changed")
        try:
            release_projection_bytes = workspace.read_private_bytes(
                "cases", receipt.case_id, "release-attestation.json"
            )
        except FileNotFoundError as exc:
            raise ValueError("owner-canary release projection is missing or changed") from exc
        release_projection = ReleasedAnswerProjection.model_validate_json(release_projection_bytes)
        if release_projection.seal_sha256 != receipt.release_projection_seal_sha256:
            raise ValueError("owner-canary release projection is missing or changed")
        projections = {
            "evidence_projection_sha256": (
                "evidence-citation-maps",
                f"{receipt.case_id}.json",
            ),
            "ai_projection_sha256": ("ai-reviews", f"{receipt.case_id}.json"),
            "standards_projection_sha256": ("standards", f"{receipt.case_id}.json"),
            "gap_projection_sha256": ("gaps", f"{receipt.case_id}.json"),
            "metrics_projection_sha256": (
                "safe-metrics",
                f"{receipt.case_id}-metrics.json",
            ),
            "retry_projection_sha256": (
                "retry-trace",
                f"{receipt.case_id}-projection.json",
            ),
        }
        if any(
            _workspace_file_sha256(workspace, category, filename) != getattr(receipt, field)
            for field, (category, filename) in projections.items()
        ):
            raise ValueError("owner-canary machine projection is missing or changed")

    verified_runtime: VerifiedEndedOwnerCanaryRuntime | None = None
    if owned_runtime is not None:
        verified_runtime = require_verified_ended_owner_canary_runtime(owned_runtime)
        if (
            synthetic_non_authoritative
            or verified_runtime.start.run_id != authorization.run_id
            or verified_runtime.start.authorization_seal_sha256 != authorization.seal_sha256
            or verified_runtime.start.canary_manifest_seal_sha256 != manifest.seal_sha256
            or verified_runtime.start.workspace_seal_sha256 != workspace.manifest.seal_sha256
            or verified_runtime.end.case_ids != authorization.authorized_case_ids
        ):
            raise ValueError("owner-canary ended runtime differs from final package")
    trace_seals = tuple(
        seal for receipt in ordered for seal in receipt.reviewer_invocation_trace_seal_sha256s
    )
    material: dict[str, Any] = {
        "schema": FINAL_REVIEW_PACKAGE_SCHEMA,
        "workspace_seal_sha256": workspace.manifest.seal_sha256,
        "run_id": authorization.run_id,
        "lane": authorization.lane,
        "authorization_seal_sha256": authorization.seal_sha256,
        "canary_manifest_seal_sha256": manifest.seal_sha256,
        "circuit_result_seal_sha256": circuit_result.seal_sha256,
        "candidate_build_id": authorization.candidate_build_id,
        "candidate_manifest_sha256": authorization.candidate_manifest_sha256,
        "case_count": 30,
        "case_ids": list(authorization.authorized_case_ids),
        "projection_receipts": [item.model_dump(mode="json", by_alias=True) for item in ordered],
        "projection_receipt_seal_sha256s": [item.seal_sha256 for item in ordered],
        "answer_sha256s": [item.answer_sha256 for item in ordered],
        "reviewer_invocation_trace_seal_sha256s": list(trace_seals),
        "reviewer_total_duration_ms": sum(item.reviewer_total_duration_ms for item in ordered),
        "reviewer_total_input_tokens": sum(item.reviewer_total_input_tokens for item in ordered),
        "reviewer_total_output_tokens": sum(item.reviewer_total_output_tokens for item in ordered),
        "reviewer_token_counts_complete": all(
            item.reviewer_token_counts_complete for item in ordered
        ),
        "exact_case_projection_reconciled": True,
        "answer_only": True,
        "plaintext_questions_included": False,
        "tuning_input_allowed": authorization.lane == "development",
        "eligible_for_training": False,
        "training_export_allowed": False,
        "create_only": True,
        "authoritative_owned_runtime": verified_runtime is not None,
        "synthetic_non_authoritative": synthetic_non_authoritative,
    }
    if verified_runtime is not None:
        material.update(
            {
                "owned_runtime_start_attestation_sha256": (verified_runtime.start.seal_sha256),
                "owned_runtime_end_attestation_sha256": verified_runtime.end.seal_sha256,
                "owned_runtime_instance_sha256": (verified_runtime.start.runtime_instance_sha256),
                "owned_runtime_memory_policy_sha256": (verified_runtime.start.memory_policy_sha256),
                "owned_runtime_checkpoint_set_sha256": (verified_runtime.end.checkpoint_set_sha256),
            }
        )
    material["seal_sha256"] = sealed_sha256(material)
    package = OwnerCanaryFinalReviewPackage.model_validate(material)
    workspace.write_safe_json(
        category="safe-metrics",
        filename="final-review-package.json",
        value=package.model_dump(mode="json", by_alias=True),
    )
    return package


@dataclass(frozen=True, slots=True)
class OwnerCanaryReviewExecution:
    circuit_result: OwnerCanaryCircuitResult
    final_package: OwnerCanaryFinalReviewPackage | None


def execute_owner_quality_canary_review(
    *,
    authorization: OwnerCanaryAuthorization,
    manifest: OwnerQualityCanaryManifest,
    bundle: LiveEvaluationBundle,
    workspace: CanaryReviewWorkspace,
    cipher: LocalCipher,
    initial_input_revision_sha256_by_case: Mapping[str, str],
    case_callback: OwnerCanaryCaseCallback | CaseCallback,
    answer_loader: ReleasedAnswerLoader | AnswerLoader,
    gap_inventory_by_case: Mapping[str, Sequence[OwnerCanaryGapDisposition | Mapping[str, Any]]],
    case_projected_callback: Callable[[str], Any] | None = None,
    owned_runtime_finalizer: Callable[[], VerifiedEndedOwnerCanaryRuntime] | None = None,
    synthetic_non_authoritative: bool = False,
) -> OwnerCanaryReviewExecution:
    """Concrete fail-closed call site joining authorization, circuit and review output."""

    adapter = OwnerCanaryProjectionAdapter(
        workspace=workspace,
        authorization=authorization,
        manifest=manifest,
        answer_loader=answer_loader,
        gap_inventory_by_case=gap_inventory_by_case,
        pre_readable_commit_callback=case_projected_callback,
    )
    circuit = run_owner_canary_serial(
        authorization=authorization,
        manifest=manifest,
        bundle=bundle,
        workspace=workspace,
        cipher=cipher,
        initial_input_revision_sha256_by_case=initial_input_revision_sha256_by_case,
        case_callback=case_callback,
        case_projector=adapter.project,
    )
    if circuit.status != "passed":
        return OwnerCanaryReviewExecution(circuit_result=circuit, final_package=None)
    ended_runtime = owned_runtime_finalizer() if owned_runtime_finalizer is not None else None
    adapter.commit_readable_answers(ended_runtime=ended_runtime)
    package = finalize_owner_canary_review_package(
        workspace=workspace,
        authorization=authorization,
        manifest=manifest,
        circuit_result=circuit,
        receipts=adapter.receipts,
        owned_runtime=ended_runtime,
        synthetic_non_authoritative=synthetic_non_authoritative,
    )
    return OwnerCanaryReviewExecution(circuit_result=circuit, final_package=package)
