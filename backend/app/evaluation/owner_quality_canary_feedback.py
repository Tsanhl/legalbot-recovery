"""Encrypted, hash-chained owner feedback and development-only answer diffs."""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
from datetime import datetime
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..crypto import LocalCipher
from .canary_review_workspace import CanaryReviewWorkspace, EncryptedCanaryProjection
from .live_suite import sealed_sha256
from .owner_quality_canary_projection import OwnerCanaryFinalReviewPackage
from .secure_artifact_io import read_file_at

OWNER_FEEDBACK_SCHEMA = "legalbot.owner-canary-feedback.v1"
OWNER_FEEDBACK_INDEX_SCHEMA = "legalbot.owner-canary-feedback-index.v1"
VERSION_DIFF_SCHEMA = "legalbot.owner-canary-version-diff.v1"
VERSION_DIFF_INDEX_SCHEMA = "legalbot.owner-canary-version-diff-index.v1"

_OWNER_REF = re.compile(r"^owner:[0-9a-f]{64}$")


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validated_package(
    value: OwnerCanaryFinalReviewPackage,
) -> OwnerCanaryFinalReviewPackage:
    return OwnerCanaryFinalReviewPackage.model_validate(
        value.model_dump(mode="json", by_alias=True)
    )


def _answer_sha256(package: OwnerCanaryFinalReviewPackage, case_id: str) -> str:
    try:
        index = package.case_ids.index(case_id)
    except ValueError as exc:
        raise ValueError("owner feedback case is outside the final review package") from exc
    return package.answer_sha256s[index]


class OwnerCanaryFeedbackRecord(BaseModel):
    """Full encrypted owner decision; feedback prose never enters its safe index."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-canary-feedback.v1"] = Field(
        default="legalbot.owner-canary-feedback.v1", alias="schema"
    )
    feedback_id: str = Field(pattern=r"^owner-feedback-[0-9]{4}-[0-9a-f]{16}$")
    sequence_number: int = Field(ge=1, le=9999)
    workspace_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    lane: Literal["development", "blind_holdout"]
    final_package_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    case_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    answer_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision: Literal["pass", "revise", "reject"]
    owner_pass: bool
    accepted_for_change: bool
    tuning_input_allowed: bool
    owner_ref: str = Field(pattern=r"^owner:[0-9a-f]{64}$")
    submitted_at: datetime
    previous_feedback_seal_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    feedback_text: str = Field(min_length=1, max_length=100_000)
    feedback_text_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    feedback_utf8_byte_count: int = Field(ge=1, le=1_000_000)
    encrypted_at_rest: Literal[True]
    plaintext_feedback_exported: Literal[False]
    eligible_for_training: Literal[False]
    training_export_allowed: Literal[False]
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("feedback_text")
    @classmethod
    def feedback_is_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("owner feedback is blank")
        return value

    @field_validator("submitted_at")
    @classmethod
    def submitted_at_is_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("owner feedback timestamp must be timezone-aware")
        return value

    @model_validator(mode="after")
    def feedback_chain_and_lane_are_exact(self) -> Self:
        encoded = self.feedback_text.encode("utf-8")
        if (
            self.feedback_text_sha256 != hashlib.sha256(encoded).hexdigest()
            or self.feedback_utf8_byte_count != len(encoded)
            or self.owner_pass != (self.decision == "pass")
            or self.accepted_for_change
            != (self.lane == "development" and self.decision == "revise")
            or self.tuning_input_allowed != self.accepted_for_change
            or (self.sequence_number == 1) != (self.previous_feedback_seal_sha256 is None)
        ):
            raise ValueError("owner feedback decision, chain or content digest is inconsistent")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("owner feedback seal does not match")
        return self


class OwnerCanaryFeedbackIndex(BaseModel):
    """Prose-free chain entry written outside encrypted feedback."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-canary-feedback-index.v1"] = Field(
        default="legalbot.owner-canary-feedback-index.v1", alias="schema"
    )
    feedback_id: str = Field(pattern=r"^owner-feedback-[0-9]{4}-[0-9a-f]{16}$")
    sequence_number: int = Field(ge=1, le=9999)
    workspace_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    lane: Literal["development", "blind_holdout"]
    final_package_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    case_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    answer_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision: Literal["pass", "revise", "reject"]
    owner_pass: bool
    accepted_for_change: bool
    tuning_input_allowed: bool
    owner_ref: str = Field(pattern=r"^owner:[0-9a-f]{64}$")
    submitted_at: datetime
    previous_feedback_seal_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    feedback_text_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    feedback_record_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    encrypted_projection_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ciphertext_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    plaintext_feedback_retained: Literal[False]
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("submitted_at")
    @classmethod
    def submitted_at_is_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("owner feedback index timestamp must be timezone-aware")
        return value

    @model_validator(mode="after")
    def index_is_sealed(self) -> Self:
        if (
            self.owner_pass != (self.decision == "pass")
            or self.accepted_for_change
            != (self.lane == "development" and self.decision == "revise")
            or self.tuning_input_allowed != self.accepted_for_change
            or (self.sequence_number == 1) != (self.previous_feedback_seal_sha256 is None)
        ):
            raise ValueError("owner feedback index grants invalid decision or tuning authority")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("owner feedback index seal does not match")
        return self


def _feedback_chain(
    workspace: CanaryReviewWorkspace,
    package: OwnerCanaryFinalReviewPackage,
) -> tuple[OwnerCanaryFeedbackIndex, ...]:
    indexes: list[OwnerCanaryFeedbackIndex] = []
    with (
        workspace.open_private_directory("safe-metrics") as metrics_fd,
        workspace.open_private_directory("owner-feedback") as feedback_fd,
    ):
        metric_names = tuple(sorted(str(name) for name in os.listdir(metrics_fd)))
        for name in metric_names:
            if not (name.startswith("owner-feedback-") and name.endswith("-index.json")):
                continue
            index = OwnerCanaryFeedbackIndex.model_validate_json(
                read_file_at(metrics_fd, name, required_mode=0o600)
            )
            if (
                name != f"{index.feedback_id}-index.json"
                or index.workspace_seal_sha256 != workspace.manifest.seal_sha256
                or index.run_id != package.run_id
                or index.lane != package.lane
                or index.final_package_seal_sha256 != package.seal_sha256
            ):
                raise ValueError("owner feedback index chain differs from this package")
            indexes.append(index)
        indexes.sort(key=lambda item: item.sequence_number)
        previous_seal: str | None = None
        for expected_sequence, index in enumerate(indexes, start=1):
            if (
                index.sequence_number != expected_sequence
                or not index.feedback_id.startswith(f"owner-feedback-{expected_sequence:04d}-")
                or index.previous_feedback_seal_sha256 != previous_seal
            ):
                raise ValueError("owner feedback index chain is forked or incomplete")
            previous_seal = index.feedback_record_seal_sha256

        feedback_names = tuple(sorted(str(name) for name in os.listdir(feedback_fd)))
        payloads = {
            name.removesuffix(".enc"): name
            for name in feedback_names
            if name.startswith("owner-feedback-") and name.endswith(".enc")
        }
        sidecars = {
            name.removesuffix(".json"): name
            for name in feedback_names
            if name.startswith("owner-feedback-") and name.endswith(".json")
        }
        expected_ids = {index.feedback_id for index in indexes}
        if set(payloads) != expected_ids or set(sidecars) != expected_ids:
            raise ValueError(
                "owner feedback index chain has a partial or unindexed encrypted record"
            )
        for index in indexes:
            encrypted = EncryptedCanaryProjection.model_validate_json(
                read_file_at(feedback_fd, sidecars[index.feedback_id], required_mode=0o600)
            )
            ciphertext = read_file_at(feedback_fd, payloads[index.feedback_id], required_mode=0o600)
            if (
                encrypted.workspace_seal_sha256 != workspace.manifest.seal_sha256
                or encrypted.category != "owner-feedback"
                or encrypted.artifact_id != index.feedback_id
                or encrypted.case_id != index.case_id
                or encrypted.seal_sha256 != index.encrypted_projection_seal_sha256
                or encrypted.ciphertext_sha256 != index.ciphertext_sha256
                or encrypted.ciphertext_sha256 != hashlib.sha256(ciphertext).hexdigest()
                or encrypted.ciphertext_byte_count != len(ciphertext)
            ):
                raise ValueError("owner feedback encrypted record differs from its safe index")
    return tuple(indexes)


def load_owner_canary_feedback_index_chain(
    *,
    workspace: CanaryReviewWorkspace,
    package: OwnerCanaryFinalReviewPackage,
) -> tuple[OwnerCanaryFeedbackIndex, ...]:
    """Load the exact append-only safe-index chain for one finalized package.

    Feedback prose remains encrypted.  This reader exposes only the already
    privacy-safe index identities needed by later owner-acceptance gates.
    """

    return _feedback_chain(workspace, _validated_package(package))


def append_owner_canary_feedback(
    *,
    workspace: CanaryReviewWorkspace,
    package: OwnerCanaryFinalReviewPackage,
    cipher: LocalCipher,
    case_id: str,
    decision: Literal["pass", "revise", "reject"],
    feedback_text: str,
    owner_ref: str,
    submitted_at: datetime,
    previous: OwnerCanaryFeedbackRecord | None = None,
) -> tuple[OwnerCanaryFeedbackRecord, OwnerCanaryFeedbackIndex]:
    """Append one encrypted owner decision to the immutable global feedback chain."""

    package = _validated_package(package)
    if (
        workspace.manifest.seal_sha256 != package.workspace_seal_sha256
        or workspace.manifest.run_id != package.run_id
        or workspace.manifest.lane != package.lane
        or not _OWNER_REF.fullmatch(owner_ref)
    ):
        raise ValueError("owner feedback inputs differ from the finalized package")
    chain = _feedback_chain(workspace, package)
    if previous is not None:
        previous = OwnerCanaryFeedbackRecord.model_validate(
            previous.model_dump(mode="json", by_alias=True)
        )
        if (
            previous.workspace_seal_sha256 != workspace.manifest.seal_sha256
            or previous.run_id != package.run_id
            or previous.lane != package.lane
            or previous.final_package_seal_sha256 != package.seal_sha256
        ):
            raise ValueError("previous owner feedback belongs to another package")
    if chain:
        if (
            previous is None
            or previous.seal_sha256 != chain[-1].feedback_record_seal_sha256
            or previous.sequence_number != chain[-1].sequence_number
        ):
            raise ValueError("owner feedback must append to the exact current chain head")
    elif previous is not None:
        raise ValueError("owner feedback chain has no matching previous record")
    sequence_number = len(chain) + 1
    encoded = feedback_text.encode("utf-8")
    identity = sealed_sha256(
        {
            "workspace_seal_sha256": workspace.manifest.seal_sha256,
            "final_package_seal_sha256": package.seal_sha256,
            "case_id": case_id,
            "answer_sha256": _answer_sha256(package, case_id),
            "sequence_number": sequence_number,
            "feedback_text_sha256": hashlib.sha256(encoded).hexdigest(),
            "previous_feedback_seal_sha256": (None if previous is None else previous.seal_sha256),
        }
    )[:16]
    feedback_id = f"owner-feedback-{sequence_number:04d}-{identity}"
    material: dict[str, Any] = {
        "schema": OWNER_FEEDBACK_SCHEMA,
        "feedback_id": feedback_id,
        "sequence_number": sequence_number,
        "workspace_seal_sha256": workspace.manifest.seal_sha256,
        "run_id": package.run_id,
        "lane": package.lane,
        "final_package_seal_sha256": package.seal_sha256,
        "case_id": case_id,
        "answer_sha256": _answer_sha256(package, case_id),
        "decision": decision,
        "owner_pass": decision == "pass",
        "accepted_for_change": package.lane == "development" and decision == "revise",
        "tuning_input_allowed": package.lane == "development" and decision == "revise",
        "owner_ref": owner_ref,
        "submitted_at": submitted_at.isoformat().replace("+00:00", "Z"),
        "previous_feedback_seal_sha256": (None if previous is None else previous.seal_sha256),
        "feedback_text": feedback_text,
        "feedback_text_sha256": hashlib.sha256(encoded).hexdigest(),
        "feedback_utf8_byte_count": len(encoded),
        "encrypted_at_rest": True,
        "plaintext_feedback_exported": False,
        "eligible_for_training": False,
        "training_export_allowed": False,
    }
    material["seal_sha256"] = sealed_sha256(material)
    record = OwnerCanaryFeedbackRecord.model_validate(material)
    _payload_path, sidecar_path = workspace.write_encrypted_projection(
        category="owner-feedback",
        artifact_id=feedback_id,
        content=(
            json.dumps(
                record.model_dump(mode="json", by_alias=True),
                ensure_ascii=False,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8"),
        cipher=cipher,
        case_id=case_id,
    )
    encrypted = EncryptedCanaryProjection.model_validate_json(
        workspace.read_private_bytes("owner-feedback", sidecar_path.name)
    )
    index_material: dict[str, Any] = {
        "schema": OWNER_FEEDBACK_INDEX_SCHEMA,
        "feedback_id": record.feedback_id,
        "sequence_number": record.sequence_number,
        "workspace_seal_sha256": record.workspace_seal_sha256,
        "run_id": record.run_id,
        "lane": record.lane,
        "final_package_seal_sha256": record.final_package_seal_sha256,
        "case_id": record.case_id,
        "answer_sha256": record.answer_sha256,
        "decision": record.decision,
        "owner_pass": record.owner_pass,
        "accepted_for_change": record.accepted_for_change,
        "tuning_input_allowed": record.tuning_input_allowed,
        "owner_ref": record.owner_ref,
        "submitted_at": record.submitted_at.isoformat().replace("+00:00", "Z"),
        "previous_feedback_seal_sha256": record.previous_feedback_seal_sha256,
        "feedback_text_sha256": record.feedback_text_sha256,
        "feedback_record_seal_sha256": record.seal_sha256,
        "encrypted_projection_seal_sha256": encrypted.seal_sha256,
        "ciphertext_sha256": encrypted.ciphertext_sha256,
        "plaintext_feedback_retained": False,
    }
    index_material["seal_sha256"] = sealed_sha256(index_material)
    index = OwnerCanaryFeedbackIndex.model_validate(index_material)
    workspace.write_safe_json(
        category="safe-metrics",
        filename=f"{feedback_id}-index.json",
        value=index.model_dump(mode="json", by_alias=True),
    )
    return record, index


class OwnerCanaryVersionDiffRecord(BaseModel):
    """Encrypted accepted development diff bound to source feedback and both runs."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-canary-version-diff.v1"] = Field(
        default="legalbot.owner-canary-version-diff.v1", alias="schema"
    )
    diff_id: str = Field(pattern=r"^owner-version-diff-[0-9]{4}-[0-9a-f]{16}$")
    sequence_number: int = Field(ge=1, le=9999)
    workspace_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    case_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    source_run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    target_run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    source_package_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_package_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    before_answer_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    after_answer_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    accepted_feedback_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    previous_diff_seal_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    diff_algorithm: Literal["unified-diff-zero-context-v1"]
    diff_text: str = Field(min_length=1, max_length=1_000_000)
    diff_text_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    tuning_input_allowed: Literal[True]
    development_only: Literal[True]
    encrypted_at_rest: Literal[True]
    plaintext_diff_exported: Literal[False]
    eligible_for_training: Literal[False]
    training_export_allowed: Literal[False]
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def diff_is_changed_chained_and_sealed(self) -> Self:
        if (
            self.source_run_id == self.target_run_id
            or self.source_package_seal_sha256 == self.target_package_seal_sha256
            or self.before_answer_sha256 == self.after_answer_sha256
            or self.diff_text_sha256 != _text_sha256(self.diff_text)
            or (self.sequence_number == 1) != (self.previous_diff_seal_sha256 is None)
        ):
            raise ValueError("owner-canary version diff identity or chain is inconsistent")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("owner-canary version diff seal does not match")
        return self


class OwnerCanaryVersionDiffIndex(BaseModel):
    """Prose-free immutable index for one encrypted development diff."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-canary-version-diff-index.v1"] = Field(
        default="legalbot.owner-canary-version-diff-index.v1", alias="schema"
    )
    diff_id: str = Field(pattern=r"^owner-version-diff-[0-9]{4}-[0-9a-f]{16}$")
    sequence_number: int = Field(ge=1, le=9999)
    workspace_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    case_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    source_run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    target_run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    source_package_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_package_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    before_answer_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    after_answer_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    accepted_feedback_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    previous_diff_seal_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    diff_text_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    diff_record_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    tuning_input_allowed: Literal[True]
    development_only: Literal[True]
    encrypted_projection_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ciphertext_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    plaintext_diff_retained: Literal[False]
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def index_is_chained_and_sealed(self) -> Self:
        if (
            self.source_run_id == self.target_run_id
            or self.source_package_seal_sha256 == self.target_package_seal_sha256
            or self.before_answer_sha256 == self.after_answer_sha256
            or (self.sequence_number == 1) != (self.previous_diff_seal_sha256 is None)
        ):
            raise ValueError("owner-canary diff index identity or chain is inconsistent")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("owner-canary diff index seal does not match")
        return self


def _version_diff_chain(
    workspace: CanaryReviewWorkspace,
    target_package: OwnerCanaryFinalReviewPackage,
) -> tuple[OwnerCanaryVersionDiffIndex, ...]:
    indexes: list[OwnerCanaryVersionDiffIndex] = []
    with workspace.open_private_directory("safe-metrics") as metrics_fd:
        names = tuple(sorted(str(name) for name in os.listdir(metrics_fd)))
        for name in names:
            if not (name.startswith("owner-version-diff-") and name.endswith("-index.json")):
                continue
            index = OwnerCanaryVersionDiffIndex.model_validate_json(
                read_file_at(metrics_fd, name, required_mode=0o600)
            )
            if (
                name != f"{index.diff_id}-index.json"
                or index.workspace_seal_sha256 != workspace.manifest.seal_sha256
                or index.target_run_id != target_package.run_id
                or index.target_package_seal_sha256 != target_package.seal_sha256
            ):
                raise ValueError("owner-canary diff index chain differs from this target package")
            indexes.append(index)
    indexes.sort(key=lambda item: item.sequence_number)
    previous_seal: str | None = None
    for expected_sequence, index in enumerate(indexes, start=1):
        if (
            index.sequence_number != expected_sequence
            or index.previous_diff_seal_sha256 != previous_seal
        ):
            raise ValueError("owner-canary diff index chain is forked or incomplete")
        previous_seal = index.diff_record_seal_sha256
    return tuple(indexes)


def record_owner_canary_development_diff(
    *,
    workspace: CanaryReviewWorkspace,
    source_package: OwnerCanaryFinalReviewPackage,
    target_package: OwnerCanaryFinalReviewPackage,
    accepted_feedback: OwnerCanaryFeedbackRecord,
    cipher: LocalCipher,
    case_id: str,
    before_answer: str,
    after_answer: str,
    previous: OwnerCanaryVersionDiffRecord | None = None,
) -> OwnerCanaryVersionDiffRecord:
    """Encrypt one accepted development-only before/after diff; holdout is forbidden."""

    source_package = _validated_package(source_package)
    target_package = _validated_package(target_package)
    accepted_feedback = OwnerCanaryFeedbackRecord.model_validate(
        accepted_feedback.model_dump(mode="json", by_alias=True)
    )
    if (
        source_package.lane != "development"
        or target_package.lane != "development"
        or workspace.manifest.lane != "development"
        or workspace.manifest.seal_sha256 != target_package.workspace_seal_sha256
        or source_package.run_id == target_package.run_id
        or accepted_feedback.final_package_seal_sha256 != source_package.seal_sha256
        or accepted_feedback.case_id != case_id
        or not accepted_feedback.tuning_input_allowed
        or _text_sha256(before_answer) != _answer_sha256(source_package, case_id)
        or _text_sha256(after_answer) != _answer_sha256(target_package, case_id)
    ):
        raise ValueError("only an accepted development feedback decision can create a diff")
    chain = _version_diff_chain(workspace, target_package)
    if previous is not None:
        previous = OwnerCanaryVersionDiffRecord.model_validate(
            previous.model_dump(mode="json", by_alias=True)
        )
        if previous.workspace_seal_sha256 != workspace.manifest.seal_sha256:
            raise ValueError("previous owner-canary diff belongs to another workspace")
    if chain:
        if (
            previous is None
            or previous.seal_sha256 != chain[-1].diff_record_seal_sha256
            or previous.sequence_number != chain[-1].sequence_number
        ):
            raise ValueError("owner-canary diff must append to the exact current chain head")
    elif previous is not None:
        raise ValueError("owner-canary diff chain has no matching previous record")
    sequence_number = len(chain) + 1
    diff_text = "\n".join(
        difflib.unified_diff(
            before_answer.splitlines(),
            after_answer.splitlines(),
            fromfile="before-answer",
            tofile="after-answer",
            n=0,
            lineterm="",
        )
    )
    if not diff_text:
        raise ValueError("owner-canary development diff is empty")
    identity = sealed_sha256(
        {
            "source_package_seal_sha256": source_package.seal_sha256,
            "target_package_seal_sha256": target_package.seal_sha256,
            "case_id": case_id,
            "accepted_feedback_seal_sha256": accepted_feedback.seal_sha256,
            "sequence_number": sequence_number,
            "diff_text_sha256": _text_sha256(diff_text),
        }
    )[:16]
    diff_id = f"owner-version-diff-{sequence_number:04d}-{identity}"
    material: dict[str, Any] = {
        "schema": VERSION_DIFF_SCHEMA,
        "diff_id": diff_id,
        "sequence_number": sequence_number,
        "workspace_seal_sha256": workspace.manifest.seal_sha256,
        "case_id": case_id,
        "source_run_id": source_package.run_id,
        "target_run_id": target_package.run_id,
        "source_package_seal_sha256": source_package.seal_sha256,
        "target_package_seal_sha256": target_package.seal_sha256,
        "before_answer_sha256": _text_sha256(before_answer),
        "after_answer_sha256": _text_sha256(after_answer),
        "accepted_feedback_seal_sha256": accepted_feedback.seal_sha256,
        "previous_diff_seal_sha256": None if previous is None else previous.seal_sha256,
        "diff_algorithm": "unified-diff-zero-context-v1",
        "diff_text": diff_text,
        "diff_text_sha256": _text_sha256(diff_text),
        "tuning_input_allowed": True,
        "development_only": True,
        "encrypted_at_rest": True,
        "plaintext_diff_exported": False,
        "eligible_for_training": False,
        "training_export_allowed": False,
    }
    material["seal_sha256"] = sealed_sha256(material)
    record = OwnerCanaryVersionDiffRecord.model_validate(material)
    _payload_path, sidecar_path = workspace.write_encrypted_projection(
        category="version-diffs",
        artifact_id=diff_id,
        content=(
            json.dumps(
                record.model_dump(mode="json", by_alias=True),
                ensure_ascii=False,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8"),
        cipher=cipher,
        case_id=case_id,
    )
    encrypted = EncryptedCanaryProjection.model_validate_json(
        workspace.read_private_bytes("version-diffs", sidecar_path.name)
    )
    index_material: dict[str, Any] = {
        "schema": VERSION_DIFF_INDEX_SCHEMA,
        "diff_id": record.diff_id,
        "sequence_number": record.sequence_number,
        "workspace_seal_sha256": record.workspace_seal_sha256,
        "case_id": record.case_id,
        "source_run_id": record.source_run_id,
        "target_run_id": record.target_run_id,
        "source_package_seal_sha256": record.source_package_seal_sha256,
        "target_package_seal_sha256": record.target_package_seal_sha256,
        "before_answer_sha256": record.before_answer_sha256,
        "after_answer_sha256": record.after_answer_sha256,
        "accepted_feedback_seal_sha256": record.accepted_feedback_seal_sha256,
        "previous_diff_seal_sha256": record.previous_diff_seal_sha256,
        "diff_text_sha256": record.diff_text_sha256,
        "diff_record_seal_sha256": record.seal_sha256,
        "tuning_input_allowed": True,
        "development_only": True,
        "encrypted_projection_seal_sha256": encrypted.seal_sha256,
        "ciphertext_sha256": encrypted.ciphertext_sha256,
        "plaintext_diff_retained": False,
    }
    index_material["seal_sha256"] = sealed_sha256(index_material)
    index = OwnerCanaryVersionDiffIndex.model_validate(index_material)
    workspace.write_safe_json(
        category="safe-metrics",
        filename=f"{diff_id}-index.json",
        value=index.model_dump(mode="json", by_alias=True),
    )
    return record
