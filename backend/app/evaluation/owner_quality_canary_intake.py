"""Explicit structured owner-review intake bound to the rendered DOCX.

DOCX checkbox marks are deliberately not parsed.  A sealed companion control
binds an editable JSON form to the exact answer-only document and its render
receipt.  Intake requires an explicit owner confirmation for every exact
case/answer pair, then appends encrypted feedback and creates the exact-30
acceptance summary only when all latest decisions pass.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..crypto import LocalCipher
from ..privacy import contains_absolute_private_path
from .canary_review_workspace import (
    CANARY_REVIEW_CATEGORIES,
    CanaryReviewWorkspace,
    CanaryReviewWorkspaceManifest,
)
from .live30 import assert_safe_evaluation_payload
from .live_suite import sealed_sha256
from .owner_quality_canary_acceptance import (
    OWNER_CANARY_ACCEPTANCE_FILENAME,
    OwnerCanaryAcceptanceSummary,
    create_owner_canary_acceptance_summary,
    verify_owner_canary_acceptance_summary,
)
from .owner_quality_canary_docx import (
    OwnerQualityCanaryDocxControl,
    OwnerQualityCanaryDocxInspectionAttestation,
    OwnerQualityCanaryDocxRenderReceipt,
    require_trusted_owner_quality_canary_docx_inspection,
)
from .owner_quality_canary_feedback import (
    OwnerCanaryFeedbackIndex,
    OwnerCanaryFeedbackRecord,
    OwnerCanaryVersionDiffIndex,
    OwnerCanaryVersionDiffRecord,
    append_owner_canary_feedback,
    load_owner_canary_feedback_index_chain,
    record_owner_canary_development_diff,
)
from .owner_quality_canary_projection import OwnerCanaryFinalReviewPackage
from .secure_artifact_io import open_directory_at, read_private_file_at

OWNER_REVIEW_COMPANION_CONTROL_SCHEMA = "legalbot.owner-canary-review-companion-control.v1"
OWNER_REVIEW_SUBMISSION_SCHEMA = "legalbot.owner-canary-review-submission.v1"
OWNER_REVIEW_INTAKE_RECEIPT_SCHEMA = "legalbot.owner-canary-review-intake-receipt.v1"
OWNER_REVIEW_COMPANION_CONTROL_FILENAME = "review-companion-control.json"
OWNER_REVIEW_COMPANION_FORM_FILENAME = "review-companion-form.json"


class OwnerReviewCompanionControl(BaseModel):
    """Sealed immutable bindings for the editable structured owner form."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-canary-review-companion-control.v1"] = Field(
        default="legalbot.owner-canary-review-companion-control.v1", alias="schema"
    )
    companion_id: str = Field(pattern=r"^owner-review-companion-[0-9a-f]{16}$")
    workspace_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    final_package_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    docx_control_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    docx_document_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    render_receipt_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    owner_inspection_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    lane: Literal["development", "blind_holdout"]
    case_count: Literal[30]
    case_ids: tuple[str, ...]
    answer_sha256s: tuple[str, ...]
    editable_form_schema: Literal["legalbot.owner-canary-review-submission.v1"]
    explicit_owner_confirmation_required: Literal[True]
    docx_checkbox_marks_parsed: Literal[False]
    owner_decisions_inferred: Literal[False]
    feedback_chain_persisted_encrypted_only: Literal[True]
    plaintext_submission_retention: Literal["owner_managed"]
    plaintext_questions_included: Literal[False]
    eligible_for_training: Literal[False]
    training_export_allowed: Literal[False]
    create_only: Literal[True]
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def companion_is_exact_and_sealed(self) -> Self:
        if (
            len(self.case_ids) != 30
            or len(set(self.case_ids)) != 30
            or len(self.answer_sha256s) != 30
            or self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True))
        ):
            raise ValueError("owner-review companion control is incomplete or unsealed")
        return self


class OwnerReviewDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    answer_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision: Literal["pass", "revise", "reject"]
    feedback_text: str = Field(min_length=1, max_length=100_000)
    explicit_owner_confirmation: Literal[True]

    @field_validator("feedback_text")
    @classmethod
    def feedback_is_private_and_nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("owner-review feedback is blank")
        if contains_absolute_private_path(value):
            raise ValueError("owner-review feedback contains a prohibited private path")
        return value


class OwnerReviewSubmission(BaseModel):
    """Unsealed owner-filled form; intake computes its digest after validation."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-canary-review-submission.v1"] = Field(
        default="legalbot.owner-canary-review-submission.v1", alias="schema"
    )
    companion_control_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    final_package_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    docx_control_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    render_receipt_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    owner_inspection_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    lane: Literal["development", "blind_holdout"]
    owner_ref: str = Field(pattern=r"^owner:[0-9a-f]{64}$")
    submitted_at: datetime
    explicit_owner_confirmation: Literal[True]
    decisions: tuple[OwnerReviewDecision, ...]

    @field_validator("submitted_at")
    @classmethod
    def submitted_at_is_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("owner-review submission timestamp must be timezone-aware")
        return value

    @model_validator(mode="after")
    def decisions_are_exact(self) -> Self:
        case_ids = tuple(item.case_id for item in self.decisions)
        if len(case_ids) != 30 or len(set(case_ids)) != 30:
            raise ValueError("owner-review submission requires exactly 30 case decisions")
        return self


class OwnerReviewIntakeReceipt(BaseModel):
    """Prose-free exact-30 receipt for one encrypted feedback append batch."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-canary-review-intake-receipt.v1"] = Field(
        default="legalbot.owner-canary-review-intake-receipt.v1", alias="schema"
    )
    intake_id: str = Field(pattern=r"^owner-review-intake-[0-9a-f]{16}$")
    workspace_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    final_package_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    companion_control_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    docx_control_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    render_receipt_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    owner_inspection_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    submission_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    lane: Literal["development", "blind_holdout"]
    case_count: Literal[30]
    case_ids: tuple[str, ...]
    answer_sha256s: tuple[str, ...]
    decisions: tuple[Literal["pass", "revise", "reject"], ...]
    decision_counts: dict[str, int]
    feedback_record_seal_sha256s: tuple[str, ...]
    feedback_index_seal_sha256s: tuple[str, ...]
    owner_confirmation_explicit: Literal[True]
    docx_marks_inferred: Literal[False]
    feedback_chain_encrypted: Literal[True]
    plaintext_submission_retention: Literal["owner_managed"]
    all_decisions_passed: bool
    acceptance_summary_created: bool
    acceptance_summary_seal_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    tuning_input_allowed_case_ids: tuple[str, ...]
    development_version_diff_required_case_ids: tuple[str, ...]
    holdout_feedback_used_for_tuning: Literal[False]
    authorizes_active: Literal[False]
    authorizes_o04: Literal[False]
    eligible_for_training: Literal[False]
    training_export_allowed: Literal[False]
    create_only: Literal[True]
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def receipt_is_exact_and_sealed(self) -> Self:
        expected_counts = dict(sorted(Counter(self.decisions).items()))
        expected_tuning = tuple(
            case_id
            for case_id, decision in zip(self.case_ids, self.decisions, strict=True)
            if self.lane == "development" and decision == "revise"
        )
        if (
            len(self.case_ids) != 30
            or len(set(self.case_ids)) != 30
            or len(self.answer_sha256s) != 30
            or len(self.decisions) != 30
            or len(self.feedback_record_seal_sha256s) != 30
            or len(self.feedback_index_seal_sha256s) != 30
            or self.decision_counts != expected_counts
            or self.all_decisions_passed != all(item == "pass" for item in self.decisions)
            or self.acceptance_summary_created != self.all_decisions_passed
            or (self.acceptance_summary_seal_sha256 is not None) != self.acceptance_summary_created
            or self.tuning_input_allowed_case_ids != expected_tuning
            or self.development_version_diff_required_case_ids != expected_tuning
            or self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True))
        ):
            raise ValueError("owner-review intake receipt is incomplete or inconsistent")
        return self


def load_owner_review_workspace(root: Path) -> CanaryReviewWorkspace:
    """Open one existing private workspace without following symlinks."""

    absolute = root.absolute()
    manifest = CanaryReviewWorkspaceManifest.model_validate_json(
        read_private_file_at(
            absolute.parent,
            (absolute.name, "workspace-manifest.json"),
            required_parent_mode=0o700,
            required_file_mode=0o600,
        )
    )
    if root.name != manifest.run_id:
        raise ValueError("owner-review workspace path differs from its run identity")
    with open_directory_at(absolute.parent, (absolute.name,)) as workspace_fd:
        if stat.S_IMODE(os.fstat(workspace_fd).st_mode) != 0o700:
            raise ValueError("owner-review workspace must have mode 0700")
    workspace = CanaryReviewWorkspace(root=absolute, manifest=manifest)
    for category in CANARY_REVIEW_CATEGORIES:
        try:
            with workspace.open_private_directory(category) as category_fd:
                if stat.S_IMODE(os.fstat(category_fd).st_mode) != 0o700:
                    raise ValueError("owner-review workspace category is not private")
        except (FileNotFoundError, ValueError) as exc:
            raise ValueError("owner-review workspace category is missing or unsafe") from exc
    return workspace


def load_owner_review_package(workspace: CanaryReviewWorkspace) -> OwnerCanaryFinalReviewPackage:
    package = OwnerCanaryFinalReviewPackage.model_validate_json(
        workspace.read_private_bytes("safe-metrics", "final-review-package.json")
    )
    if (
        package.workspace_seal_sha256 != workspace.manifest.seal_sha256
        or package.run_id != workspace.manifest.run_id
        or package.lane != workspace.manifest.lane
        or package.case_ids != workspace.manifest.expected_case_ids
    ):
        raise ValueError("owner-review final package differs from its workspace")
    return package


def _load_docx_bindings(
    *, workspace: CanaryReviewWorkspace, package: OwnerCanaryFinalReviewPackage
) -> tuple[
    OwnerQualityCanaryDocxControl,
    OwnerQualityCanaryDocxRenderReceipt,
    OwnerQualityCanaryDocxInspectionAttestation,
]:
    control = OwnerQualityCanaryDocxControl.model_validate_json(
        workspace.read_private_bytes("review-docx", "docx-control.json")
    )
    receipt = OwnerQualityCanaryDocxRenderReceipt.model_validate_json(
        workspace.read_private_bytes("review-docx", "render-receipt.json")
    )
    docx_bytes = workspace.read_private_bytes("review-docx", f"{control.document_id}.docx")
    if (
        control.workspace_seal_sha256 != workspace.manifest.seal_sha256
        or control.final_package_seal_sha256 != package.seal_sha256
        or control.case_ids != package.case_ids
        or control.answer_sha256s != package.answer_sha256s
        or receipt.docx_control_seal_sha256 != control.seal_sha256
        or receipt.document_sha256 != control.document_sha256
        or not receipt.technical_render_passed
        or receipt.authorizes_owner_review_companion
        or hashlib.sha256(docx_bytes).hexdigest() != control.document_sha256
    ):
        raise ValueError("owner-review DOCX or render binding differs from the exact package")
    inspection = require_trusted_owner_quality_canary_docx_inspection(
        workspace=workspace,
        control=control,
        receipt=receipt,
    )
    return control, receipt, inspection


def create_owner_review_companion(
    *, workspace: CanaryReviewWorkspace, package: OwnerCanaryFinalReviewPackage
) -> tuple[Path, Path, OwnerReviewCompanionControl]:
    """Create one sealed control and one blank editable JSON form."""

    package = OwnerCanaryFinalReviewPackage.model_validate(
        package.model_dump(mode="json", by_alias=True)
    )
    persisted = load_owner_review_package(workspace)
    if persisted != package:
        raise ValueError("owner-review companion package differs from the persisted package")
    docx, render, inspection = _load_docx_bindings(workspace=workspace, package=package)
    existing = workspace.list_private_directory("review-docx")
    if (
        OWNER_REVIEW_COMPANION_CONTROL_FILENAME in existing
        or OWNER_REVIEW_COMPANION_FORM_FILENAME in existing
    ):
        raise FileExistsError("owner-review companion is create-only")
    identity = sealed_sha256(
        {
            "workspace_seal_sha256": workspace.manifest.seal_sha256,
            "final_package_seal_sha256": package.seal_sha256,
            "docx_control_seal_sha256": docx.seal_sha256,
            "render_receipt_seal_sha256": render.seal_sha256,
            "owner_inspection_seal_sha256": inspection.seal_sha256,
        }
    )[:16]
    material: dict[str, Any] = {
        "schema": OWNER_REVIEW_COMPANION_CONTROL_SCHEMA,
        "companion_id": f"owner-review-companion-{identity}",
        "workspace_seal_sha256": workspace.manifest.seal_sha256,
        "final_package_seal_sha256": package.seal_sha256,
        "docx_control_seal_sha256": docx.seal_sha256,
        "docx_document_sha256": docx.document_sha256,
        "render_receipt_seal_sha256": render.seal_sha256,
        "owner_inspection_seal_sha256": inspection.seal_sha256,
        "run_id": package.run_id,
        "lane": package.lane,
        "case_count": 30,
        "case_ids": list(package.case_ids),
        "answer_sha256s": list(package.answer_sha256s),
        "editable_form_schema": OWNER_REVIEW_SUBMISSION_SCHEMA,
        "explicit_owner_confirmation_required": True,
        "docx_checkbox_marks_parsed": False,
        "owner_decisions_inferred": False,
        "feedback_chain_persisted_encrypted_only": True,
        "plaintext_submission_retention": "owner_managed",
        "plaintext_questions_included": False,
        "eligible_for_training": False,
        "training_export_allowed": False,
        "create_only": True,
    }
    assert_safe_evaluation_payload(material)
    material["seal_sha256"] = sealed_sha256(material)
    control = OwnerReviewCompanionControl.model_validate(material)
    form = {
        "schema": OWNER_REVIEW_SUBMISSION_SCHEMA,
        "companion_control_seal_sha256": control.seal_sha256,
        "final_package_seal_sha256": package.seal_sha256,
        "docx_control_seal_sha256": docx.seal_sha256,
        "render_receipt_seal_sha256": render.seal_sha256,
        "owner_inspection_seal_sha256": inspection.seal_sha256,
        "run_id": package.run_id,
        "lane": package.lane,
        "owner_ref": None,
        "submitted_at": None,
        "explicit_owner_confirmation": False,
        "decisions": [
            {
                "case_id": case_id,
                "answer_sha256": answer_sha256,
                "decision": None,
                "feedback_text": "",
                "explicit_owner_confirmation": False,
            }
            for case_id, answer_sha256 in zip(package.case_ids, package.answer_sha256s, strict=True)
        ],
    }
    control_path = workspace.write_private_bytes(
        "review-docx",
        OWNER_REVIEW_COMPANION_CONTROL_FILENAME,
        payload=(
            json.dumps(
                control.model_dump(mode="json", by_alias=True),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8"),
    )
    try:
        form_path = workspace.write_private_bytes(
            "review-docx",
            OWNER_REVIEW_COMPANION_FORM_FILENAME,
            payload=(json.dumps(form, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
                "utf-8"
            ),
        )
    except Exception:
        workspace.unlink_private_file(
            "review-docx", OWNER_REVIEW_COMPANION_CONTROL_FILENAME, missing_ok=True
        )
        raise
    return control_path, form_path, control


def _load_companion(
    *, workspace: CanaryReviewWorkspace, package: OwnerCanaryFinalReviewPackage
) -> OwnerReviewCompanionControl:
    control = OwnerReviewCompanionControl.model_validate_json(
        workspace.read_private_bytes("review-docx", OWNER_REVIEW_COMPANION_CONTROL_FILENAME)
    )
    docx, render, inspection = _load_docx_bindings(workspace=workspace, package=package)
    if (
        control.workspace_seal_sha256 != workspace.manifest.seal_sha256
        or control.final_package_seal_sha256 != package.seal_sha256
        or control.docx_control_seal_sha256 != docx.seal_sha256
        or control.render_receipt_seal_sha256 != render.seal_sha256
        or control.owner_inspection_seal_sha256 != inspection.seal_sha256
        or control.case_ids != package.case_ids
        or control.answer_sha256s != package.answer_sha256s
    ):
        raise ValueError("owner-review companion differs from the exact rendered package")
    return control


def _load_submission(path: Path) -> OwnerReviewSubmission:
    raw = read_private_file_at(
        path.parent,
        (path.name,),
        required_parent_mode=0o700,
        required_file_mode=0o600,
    )
    if len(raw) > 5_000_000:
        raise ValueError("owner-review submission exceeds the private form limit")
    return OwnerReviewSubmission.model_validate_json(raw)


def _feedback_signature(
    *, decision: OwnerReviewDecision, owner_ref: str, submitted_at: datetime
) -> tuple[str, str, str, str, datetime, str]:
    return (
        decision.case_id,
        decision.answer_sha256,
        decision.decision,
        owner_ref,
        submitted_at,
        hashlib.sha256(decision.feedback_text.encode("utf-8")).hexdigest(),
    )


def _index_signature(
    index: OwnerCanaryFeedbackIndex,
) -> tuple[str, str, str, str, datetime, str]:
    return (
        index.case_id,
        index.answer_sha256,
        index.decision,
        index.owner_ref,
        index.submitted_at,
        index.feedback_text_sha256,
    )


def _decrypt_feedback_record(
    *, workspace: CanaryReviewWorkspace, index: OwnerCanaryFeedbackIndex, cipher: LocalCipher
) -> OwnerCanaryFeedbackRecord:
    ciphertext = workspace.read_private_bytes("owner-feedback", f"{index.feedback_id}.enc")
    record = OwnerCanaryFeedbackRecord.model_validate_json(cipher.decrypt_bytes(ciphertext))
    if (
        record.seal_sha256 != index.feedback_record_seal_sha256
        or record.feedback_id != index.feedback_id
        or record.sequence_number != index.sequence_number
        or record.case_id != index.case_id
        or record.answer_sha256 != index.answer_sha256
    ):
        raise ValueError("decrypted owner feedback differs from its safe index")
    return record


def _submission_prefix(
    *, chain: tuple[OwnerCanaryFeedbackIndex, ...], expected: tuple[tuple[Any, ...], ...]
) -> int:
    maximum = min(len(chain), len(expected))
    for count in range(maximum, 0, -1):
        observed = tuple(_index_signature(item) for item in chain[-count:])
        if observed == expected[:count]:
            return count
    submitted_at = expected[0][4]
    owner_ref = expected[0][3]
    if any(item.submitted_at == submitted_at and item.owner_ref == owner_ref for item in chain):
        raise ValueError("owner-review submission is forked or no longer at the chain head")
    return 0


def _receipt_filename(submission_sha256: str) -> str:
    return f"owner-review-intake-{submission_sha256[:16]}.json"


def ingest_owner_review_submission(
    *,
    workspace: CanaryReviewWorkspace,
    package: OwnerCanaryFinalReviewPackage,
    submission_path: Path,
    cipher: LocalCipher,
) -> OwnerReviewIntakeReceipt:
    """Append exactly 30 explicit decisions; never infer them from DOCX marks."""

    package = OwnerCanaryFinalReviewPackage.model_validate(
        package.model_dump(mode="json", by_alias=True)
    )
    if load_owner_review_package(workspace) != package:
        raise ValueError("owner-review intake package differs from persisted bytes")
    companion = _load_companion(workspace=workspace, package=package)
    submission = _load_submission(submission_path)
    if (
        submission.companion_control_seal_sha256 != companion.seal_sha256
        or submission.final_package_seal_sha256 != package.seal_sha256
        or submission.docx_control_seal_sha256 != companion.docx_control_seal_sha256
        or submission.render_receipt_seal_sha256 != companion.render_receipt_seal_sha256
        or submission.owner_inspection_seal_sha256 != companion.owner_inspection_seal_sha256
        or submission.run_id != package.run_id
        or submission.lane != package.lane
        or tuple(item.case_id for item in submission.decisions) != package.case_ids
        or tuple(item.answer_sha256 for item in submission.decisions) != package.answer_sha256s
    ):
        raise ValueError("owner-review submission differs from the exact rendered answers")
    submission_sha256 = sealed_sha256(submission.model_dump(mode="json", by_alias=True))
    receipt_filename = _receipt_filename(submission_sha256)
    safe_metric_names = set(workspace.list_private_directory("safe-metrics"))
    if receipt_filename in safe_metric_names:
        receipt = OwnerReviewIntakeReceipt.model_validate_json(
            workspace.read_private_bytes("safe-metrics", receipt_filename)
        )
        if receipt.submission_sha256 != submission_sha256:
            raise ValueError("owner-review intake receipt differs from this submission")
        chain = load_owner_canary_feedback_index_chain(workspace=workspace, package=package)
        expected_index_seals = receipt.feedback_index_seal_sha256s
        found = False
        for start in range(0, len(chain) - 29):
            window = chain[start : start + 30]
            if tuple(item.seal_sha256 for item in window) == expected_index_seals:
                if tuple(item.feedback_record_seal_sha256 for item in window) != (
                    receipt.feedback_record_seal_sha256s
                ):
                    raise ValueError("owner-review intake receipt record chain differs")
                found = True
                break
        if not found:
            raise ValueError("owner-review intake receipt is absent from the feedback chain")
        if receipt.acceptance_summary_created:
            verified_acceptance = verify_owner_canary_acceptance_summary(
                workspace=workspace,
                package=package,
            )
            if verified_acceptance.seal_sha256 != receipt.acceptance_summary_seal_sha256:
                raise ValueError("owner-review intake acceptance binding differs")
        return receipt
    chain = load_owner_canary_feedback_index_chain(workspace=workspace, package=package)
    expected = tuple(
        _feedback_signature(
            decision=item,
            owner_ref=submission.owner_ref,
            submitted_at=submission.submitted_at,
        )
        for item in submission.decisions
    )
    prefix = _submission_prefix(chain=chain, expected=expected)
    indexes = list(chain[-prefix:] if prefix else ())
    previous = (
        _decrypt_feedback_record(workspace=workspace, index=chain[-1], cipher=cipher)
        if chain
        else None
    )
    for decision in submission.decisions[prefix:]:
        previous, index = append_owner_canary_feedback(
            workspace=workspace,
            package=package,
            cipher=cipher,
            case_id=decision.case_id,
            decision=decision.decision,
            feedback_text=decision.feedback_text,
            owner_ref=submission.owner_ref,
            submitted_at=submission.submitted_at,
            previous=previous,
        )
        indexes.append(index)
    if len(indexes) != 30 or tuple(_index_signature(item) for item in indexes) != expected:
        raise RuntimeError("owner-review encrypted append did not reconcile exact decisions")

    all_passed = all(item.decision == "pass" for item in submission.decisions)
    acceptance: OwnerCanaryAcceptanceSummary | None = None
    acceptance_exists = OWNER_CANARY_ACCEPTANCE_FILENAME in set(
        workspace.list_private_directory("safe-metrics")
    )
    if all_passed:
        if acceptance_exists:
            acceptance = verify_owner_canary_acceptance_summary(
                workspace=workspace,
                package=package,
            )
        else:
            acceptance = create_owner_canary_acceptance_summary(
                workspace=workspace,
                package=package,
                created_at=submission.submitted_at,
            )
            acceptance = verify_owner_canary_acceptance_summary(
                workspace=workspace,
                package=package,
                expected=acceptance,
            )
    elif acceptance_exists:
        raise ValueError("owner-review acceptance exists but latest decisions do not all pass")
    tuning_case_ids = tuple(
        item.case_id
        for item in submission.decisions
        if package.lane == "development" and item.decision == "revise"
    )
    intake_id = f"owner-review-intake-{submission_sha256[:16]}"
    material: dict[str, Any] = {
        "schema": OWNER_REVIEW_INTAKE_RECEIPT_SCHEMA,
        "intake_id": intake_id,
        "workspace_seal_sha256": workspace.manifest.seal_sha256,
        "final_package_seal_sha256": package.seal_sha256,
        "companion_control_seal_sha256": companion.seal_sha256,
        "docx_control_seal_sha256": companion.docx_control_seal_sha256,
        "render_receipt_seal_sha256": companion.render_receipt_seal_sha256,
        "owner_inspection_seal_sha256": companion.owner_inspection_seal_sha256,
        "submission_sha256": submission_sha256,
        "run_id": package.run_id,
        "lane": package.lane,
        "case_count": 30,
        "case_ids": list(package.case_ids),
        "answer_sha256s": list(package.answer_sha256s),
        "decisions": [item.decision for item in submission.decisions],
        "decision_counts": dict(
            sorted(Counter(item.decision for item in submission.decisions).items())
        ),
        "feedback_record_seal_sha256s": [item.feedback_record_seal_sha256 for item in indexes],
        "feedback_index_seal_sha256s": [item.seal_sha256 for item in indexes],
        "owner_confirmation_explicit": True,
        "docx_marks_inferred": False,
        "feedback_chain_encrypted": True,
        "plaintext_submission_retention": "owner_managed",
        "all_decisions_passed": all_passed,
        "acceptance_summary_created": acceptance is not None,
        "acceptance_summary_seal_sha256": (
            acceptance.seal_sha256 if acceptance is not None else None
        ),
        "tuning_input_allowed_case_ids": list(tuning_case_ids),
        "development_version_diff_required_case_ids": list(tuning_case_ids),
        "holdout_feedback_used_for_tuning": False,
        "authorizes_active": False,
        "authorizes_o04": False,
        "eligible_for_training": False,
        "training_export_allowed": False,
        "create_only": True,
    }
    assert_safe_evaluation_payload(material)
    material["seal_sha256"] = sealed_sha256(material)
    receipt = OwnerReviewIntakeReceipt.model_validate(material)
    workspace.write_safe_json(
        category="safe-metrics",
        filename=receipt_filename,
        value=receipt.model_dump(mode="json", by_alias=True),
    )
    return receipt


def _decrypt_version_diff_record(
    *, workspace: CanaryReviewWorkspace, index: OwnerCanaryVersionDiffIndex, cipher: LocalCipher
) -> OwnerCanaryVersionDiffRecord:
    record = OwnerCanaryVersionDiffRecord.model_validate_json(
        cipher.decrypt_bytes(workspace.read_private_bytes("version-diffs", f"{index.diff_id}.enc"))
    )
    if record.seal_sha256 != index.diff_record_seal_sha256 or record.diff_id != index.diff_id:
        raise ValueError("decrypted owner version diff differs from its safe index")
    return record


def _version_diff_indexes(
    *, workspace: CanaryReviewWorkspace, package: OwnerCanaryFinalReviewPackage
) -> tuple[OwnerCanaryVersionDiffIndex, ...]:
    filenames = workspace.list_private_directory("safe-metrics")
    indexes = tuple(
        sorted(
            (
                OwnerCanaryVersionDiffIndex.model_validate_json(
                    workspace.read_private_bytes("safe-metrics", filename)
                )
                for filename in filenames
                if filename.startswith("owner-version-diff-") and filename.endswith("-index.json")
            ),
            key=lambda item: item.sequence_number,
        )
    )
    previous: str | None = None
    for ordinal, index in enumerate(indexes, start=1):
        if (
            index.sequence_number != ordinal
            or index.workspace_seal_sha256 != workspace.manifest.seal_sha256
            or index.target_package_seal_sha256 != package.seal_sha256
            or index.previous_diff_seal_sha256 != previous
        ):
            raise ValueError("owner version-diff chain is incomplete or forked")
        previous = index.diff_record_seal_sha256
    return indexes


def record_development_diff_from_owner_feedback(
    *,
    source_workspace: CanaryReviewWorkspace,
    source_package: OwnerCanaryFinalReviewPackage,
    target_workspace: CanaryReviewWorkspace,
    target_package: OwnerCanaryFinalReviewPackage,
    feedback_id: str,
    case_id: str,
    cipher: LocalCipher,
) -> OwnerCanaryVersionDiffRecord:
    """Record an encrypted diff only for accepted development revise feedback."""

    source_package = OwnerCanaryFinalReviewPackage.model_validate(
        source_package.model_dump(mode="json", by_alias=True)
    )
    target_package = OwnerCanaryFinalReviewPackage.model_validate(
        target_package.model_dump(mode="json", by_alias=True)
    )
    if (
        load_owner_review_package(source_workspace) != source_package
        or load_owner_review_package(target_workspace) != target_package
        or source_package.lane != "development"
        or target_package.lane != "development"
        or source_workspace.manifest.lane != "development"
        or target_workspace.manifest.lane != "development"
    ):
        raise ValueError("owner-review version diffs are development-only")
    chain = load_owner_canary_feedback_index_chain(
        workspace=source_workspace, package=source_package
    )
    index = next((item for item in chain if item.feedback_id == feedback_id), None)
    if index is None or index.case_id != case_id or not index.tuning_input_allowed:
        raise ValueError("version diff requires the exact accepted revise feedback")
    feedback = _decrypt_feedback_record(workspace=source_workspace, index=index, cipher=cipher)
    before = source_workspace.read_private_bytes("cases", case_id, "released-answer.md").decode(
        "utf-8"
    )
    after = target_workspace.read_private_bytes("cases", case_id, "released-answer.md").decode(
        "utf-8"
    )
    diff_indexes = _version_diff_indexes(workspace=target_workspace, package=target_package)
    previous = (
        _decrypt_version_diff_record(
            workspace=target_workspace, index=diff_indexes[-1], cipher=cipher
        )
        if diff_indexes
        else None
    )
    return record_owner_canary_development_diff(
        workspace=target_workspace,
        source_package=source_package,
        target_package=target_package,
        accepted_feedback=feedback,
        cipher=cipher,
        case_id=case_id,
        before_answer=before,
        after_answer=after,
        previous=previous,
    )
