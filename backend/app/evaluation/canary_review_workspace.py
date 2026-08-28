"""Private, create-only projections for owner review of one 30-case canary lane.

The authoritative run store remains elsewhere.  This module creates a dated,
Git-ignored owner-local projection containing only the sealed sample contract,
gate-passed released answers, safe machine artifacts and encrypted held data.
It never persists questions or held plaintext.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..crypto import LocalCipher
from ..privacy import contains_absolute_private_path
from ..text_metrics import word_count
from .live30 import assert_safe_evaluation_payload
from .live_suite import sealed_sha256
from .owner_quality_canary import (
    CanaryLane,
    OwnerQualityCanaryManifest,
    owner_quality_manifest_bytes,
)
from .secure_artifact_io import (
    create_private_directory_at,
    list_directory_at,
    open_directory_at,
    read_private_file_at,
    unlink_file_at,
    write_private_file_at,
)

CANARY_REVIEW_WORKSPACE_SCHEMA = "legalbot.canary-review-workspace.v1"
RELEASE_PROJECTION_SCHEMA = "legalbot.canary-released-answer-projection.v1"
ENCRYPTED_PROJECTION_SCHEMA = "legalbot.canary-encrypted-projection.v1"

CANARY_REVIEW_CATEGORIES = (
    "cases",
    "evidence-citation-maps",
    "ai-reviews",
    "standards",
    "gaps",
    "retry-trace",
    "safe-metrics",
    "owner-feedback",
    "version-diffs",
    "review-docx",
    "held-drafts",
    "debug-bundles",
)

REQUIRED_RELEASE_GATES = frozenset(
    {
        "ai_evidence_review",
        "applicable_standards",
        "citation_binding",
        "currentness",
        "evidence_binding",
        "evidence_identity",
        "jurisdiction",
        "material_claim_disposition",
        "privacy",
        "prompt_injection",
        "quotation_accuracy",
        "source_lane",
        "word_target",
    }
)

_SAFE_RUN_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_SAFE_FILE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_CASE_ID = re.compile(r"^(?:live30|live60)-q[0-9]{2}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_GATE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")


def _private_directory(path: Path, *, exist_ok: bool) -> None:
    """Create or validate one owner-private directory without following symlinks."""

    create_private_directory_at(path.parent, (path.name,), exist_ok=exist_ok)


def _prepare_parent_tree(project_root: Path, parts: tuple[str, ...]) -> Path:
    """Create a fixed relative directory tree and reject pre-existing symlinks."""

    create_private_directory_at(project_root, parts, exist_ok=True)
    return project_root.absolute().joinpath(*parts)


class CanaryReviewWorkspaceManifest(BaseModel):
    """Prose-free identity and privacy policy for a local review projection."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.canary-review-workspace.v1"] = Field(
        default="legalbot.canary-review-workspace.v1", alias="schema"
    )
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    review_date: date
    lane: CanaryLane
    canary_manifest_id: str = Field(pattern=r"^owner-quality-canary-[0-9a-f]{20}$")
    canary_manifest_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    canary_manifest_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    runtime_run_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_build_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    candidate_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_case_count: Literal[30] = 30
    expected_case_ids: tuple[str, ...]
    projection_categories: tuple[str, ...]
    purpose: Literal["evaluation_only"] = "evaluation_only"
    local_only: Literal[True] = True
    eligible_for_training: Literal[False] = False
    training_export_allowed: Literal[False] = False
    online_research_allowed: Literal[False] = False
    create_only: Literal[True] = True
    plaintext_policy: Literal["gate_passed_released_answers_only"] = (
        "gate_passed_released_answers_only"
    )
    held_content_policy: Literal["encrypted_only"] = "encrypted_only"
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("expected_case_ids")
    @classmethod
    def case_ids_are_exactly_thirty_and_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != 30 or len(set(values)) != 30:
            raise ValueError("canary review workspace requires 30 unique cases")
        if any(not _CASE_ID.fullmatch(value) for value in values):
            raise ValueError("canary review workspace contains an invalid case ID")
        return values

    @model_validator(mode="after")
    def workspace_contract_is_fixed_and_sealed(self) -> Self:
        if self.projection_categories != CANARY_REVIEW_CATEGORIES:
            raise ValueError("canary review projection categories differ from policy")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("canary review workspace seal does not match its contents")
        return self


class ReleasedAnswerProjection(BaseModel):
    """Safe attestation written alongside one readable released answer."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.canary-released-answer-projection.v1"] = Field(
        default="legalbot.canary-released-answer-projection.v1", alias="schema"
    )
    workspace_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    case_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    lane: CanaryLane
    answer_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    word_count: int = Field(ge=1)
    release_gates: dict[str, bool]
    all_required_release_gates_passed: Literal[True] = True
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def release_is_fully_gated_and_sealed(self) -> Self:
        if not REQUIRED_RELEASE_GATES.issubset(self.release_gates):
            raise ValueError("released answer is missing a required gate")
        if any(not _SAFE_GATE.fullmatch(key) for key in self.release_gates):
            raise ValueError("released answer has an invalid gate identity")
        if not all(self.release_gates.values()):
            raise ValueError("released answer contains a failed gate")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("released-answer projection seal does not match")
        return self


class EncryptedCanaryProjection(BaseModel):
    """Prose-free sidecar proving a held artifact was projected as ciphertext."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.canary-encrypted-projection.v1"] = Field(
        default="legalbot.canary-encrypted-projection.v1", alias="schema"
    )
    workspace_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    category: Literal["held-drafts", "debug-bundles", "owner-feedback", "version-diffs"]
    artifact_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    case_id: str | None = Field(default=None, pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    encryption_scheme: Literal["fernet-v1"] = "fernet-v1"
    ciphertext_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ciphertext_byte_count: int = Field(ge=1)
    plaintext_retained: Literal[False] = False
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def encrypted_projection_is_sealed(self) -> Self:
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("encrypted projection seal does not match")
        return self


@dataclass(frozen=True, slots=True)
class CanaryReviewWorkspace:
    """Transient filesystem handle; its absolute root is never serialized."""

    root: Path
    manifest: CanaryReviewWorkspaceManifest

    def _secure_location(self) -> tuple[Path, tuple[str, ...]]:
        """Return a stable anchor and lexical workspace path for fd traversal."""

        absolute = self.root.absolute()
        parts = absolute.parts
        marker = ("data", "evaluations", "canary-output-review")
        for index in range(0, len(parts) - len(marker) + 1):
            if parts[index : index + len(marker)] == marker:
                anchor = Path(*parts[:index])
                return anchor, tuple(parts[index:])
        return absolute.parent, (absolute.name,)

    @contextmanager
    def open_private_directory(self, *relative_parts: str) -> Iterator[int]:
        anchor, workspace_parts = self._secure_location()
        with open_directory_at(anchor, (*workspace_parts, *relative_parts)) as descriptor:
            yield descriptor

    def private_path(self, *relative_parts: str) -> Path:
        return self.root.joinpath(*relative_parts)

    def create_private_directory(self, *relative_parts: str, exist_ok: bool = False) -> Path:
        if not relative_parts:
            raise ValueError("canary review subdirectory requires a relative path")
        anchor, workspace_parts = self._secure_location()
        create_private_directory_at(
            anchor,
            (*workspace_parts, *relative_parts),
            exist_ok=exist_ok,
        )
        return self.private_path(*relative_parts)

    def write_private_bytes(self, *relative_parts: str, payload: bytes) -> Path:
        if not relative_parts:
            raise ValueError("canary review artifact requires a relative path")
        anchor, workspace_parts = self._secure_location()
        write_private_file_at(anchor, (*workspace_parts, *relative_parts), payload)
        return self.private_path(*relative_parts)

    def read_private_bytes(
        self,
        *relative_parts: str,
        required_file_mode: int | None = 0o600,
    ) -> bytes:
        if not relative_parts:
            raise ValueError("canary review artifact requires a relative path")
        anchor, workspace_parts = self._secure_location()
        return read_private_file_at(
            anchor,
            (*workspace_parts, *relative_parts),
            required_parent_mode=0o700,
            required_file_mode=required_file_mode,
        )

    def list_private_directory(self, *relative_parts: str) -> tuple[str, ...]:
        anchor, workspace_parts = self._secure_location()
        return list_directory_at(anchor, (*workspace_parts, *relative_parts))

    def unlink_private_file(self, *relative_parts: str, missing_ok: bool = False) -> None:
        anchor, workspace_parts = self._secure_location()
        unlink_file_at(
            anchor,
            (*workspace_parts, *relative_parts),
            missing_ok=missing_ok,
        )

    def _category_root(self, category: str) -> Path:
        if category not in CANARY_REVIEW_CATEGORIES:
            raise ValueError("unsupported canary review projection category")
        with self.open_private_directory(category):
            pass
        return self.private_path(category)

    @staticmethod
    def _safe_name(filename: str) -> str:
        if not _SAFE_FILE_NAME.fullmatch(filename):
            raise ValueError("canary review projection filename is unsafe")
        return filename

    def write_safe_json(self, *, category: str, filename: str, value: Mapping[str, Any]) -> Path:
        """Create a prose-free machine projection; overwrite is impossible."""

        if category in {
            "cases",
            "held-drafts",
            "owner-feedback",
            "review-docx",
            "version-diffs",
        }:
            raise ValueError("category requires its dedicated projection contract")
        name = self._safe_name(filename)
        if not name.endswith(".json"):
            raise ValueError("safe machine projection must use a .json filename")
        assert_safe_evaluation_payload(value)
        self._category_root(category)
        return self.write_private_bytes(
            category,
            name,
            payload=(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
                "utf-8"
            ),
        )

    def write_released_answer(
        self,
        *,
        case_id: str,
        content: str,
        release_gates: Mapping[str, bool],
    ) -> tuple[Path, Path]:
        """Create one readable answer only after every supplied hard gate passes."""

        if case_id not in self.manifest.expected_case_ids:
            raise ValueError("case is outside this canary review lane")
        if not content.strip() or contains_absolute_private_path(content):
            raise ValueError("released answer is empty or contains a private path")
        gates = dict(release_gates)
        if not REQUIRED_RELEASE_GATES.issubset(gates) or not all(gates.values()):
            raise ValueError("released answer has a missing or failed hard gate")
        if any(not isinstance(value, bool) for value in gates.values()):
            raise ValueError("released answer gates must be booleans")
        assert_safe_evaluation_payload(gates)

        encoded = content.encode("utf-8")
        material: dict[str, Any] = {
            "schema": RELEASE_PROJECTION_SCHEMA,
            "workspace_seal_sha256": self.manifest.seal_sha256,
            "case_id": case_id,
            "lane": self.manifest.lane,
            "answer_sha256": hashlib.sha256(encoded).hexdigest(),
            "word_count": word_count(content),
            "release_gates": dict(sorted(gates.items())),
            "all_required_release_gates_passed": True,
        }
        material["seal_sha256"] = sealed_sha256(material)
        projection = ReleasedAnswerProjection.model_validate(material)

        self._category_root("cases")
        self.create_private_directory("cases", case_id, exist_ok=False)
        answer_path = self.write_private_bytes(
            "cases", case_id, "released-answer.md", payload=encoded
        )
        attestation_path = self.write_private_bytes(
            "cases",
            case_id,
            "release-attestation.json",
            payload=(
                json.dumps(
                    projection.model_dump(mode="json", by_alias=True),
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8"),
        )
        return answer_path, attestation_path

    def write_encrypted_projection(
        self,
        *,
        category: Literal["held-drafts", "debug-bundles", "owner-feedback", "version-diffs"],
        artifact_id: str,
        content: bytes,
        cipher: LocalCipher,
        case_id: str | None = None,
    ) -> tuple[Path, Path]:
        """Encrypt in memory, then create ciphertext and a prose-free sidecar."""

        if not _SAFE_RUN_ID.fullmatch(artifact_id):
            raise ValueError("encrypted projection artifact identity is invalid")
        if case_id is not None and case_id not in self.manifest.expected_case_ids:
            raise ValueError("encrypted projection case is outside this canary lane")
        if not content:
            raise ValueError("encrypted projection content is empty")

        ciphertext = cipher.encrypt_bytes(content)
        digest = hashlib.sha256(ciphertext).hexdigest()
        material: dict[str, Any] = {
            "schema": ENCRYPTED_PROJECTION_SCHEMA,
            "workspace_seal_sha256": self.manifest.seal_sha256,
            "category": category,
            "artifact_id": artifact_id,
            "case_id": case_id,
            "encryption_scheme": "fernet-v1",
            "ciphertext_sha256": digest,
            "ciphertext_byte_count": len(ciphertext),
            "plaintext_retained": False,
        }
        material["seal_sha256"] = sealed_sha256(material)
        projection = EncryptedCanaryProjection.model_validate(material)
        self._category_root(category)
        payload_path = self.write_private_bytes(category, f"{artifact_id}.enc", payload=ciphertext)
        sidecar_path = self.write_private_bytes(
            category,
            f"{artifact_id}.json",
            payload=(
                json.dumps(
                    projection.model_dump(mode="json", by_alias=True),
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8"),
        )
        return payload_path, sidecar_path


def create_canary_review_workspace(
    *,
    project_root: Path,
    review_root: Path | None = None,
    review_date: date,
    run_id: str,
    lane: CanaryLane,
    canary_manifest: OwnerQualityCanaryManifest,
    runtime_run_manifest_sha256: str,
) -> CanaryReviewWorkspace:
    """Create ``.../YYYY-MM-DD/<run-id>`` once with owner-private permissions."""

    if not _SAFE_RUN_ID.fullmatch(run_id):
        raise ValueError("canary review run identity is invalid")
    if not _SHA256.fullmatch(runtime_run_manifest_sha256):
        raise ValueError("runtime run-manifest digest is invalid")
    manifest_bytes = owner_quality_manifest_bytes(canary_manifest)
    expected_ids = (
        canary_manifest.development_case_ids
        if lane == "development"
        else canary_manifest.blind_holdout_case_ids
    )
    material: dict[str, Any] = {
        "schema": CANARY_REVIEW_WORKSPACE_SCHEMA,
        "run_id": run_id,
        "review_date": review_date.isoformat(),
        "lane": lane,
        "canary_manifest_id": canary_manifest.manifest_id,
        "canary_manifest_seal_sha256": canary_manifest.seal_sha256,
        "canary_manifest_file_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "runtime_run_manifest_sha256": runtime_run_manifest_sha256,
        "candidate_build_id": canary_manifest.candidate_build_id,
        "candidate_manifest_sha256": canary_manifest.candidate_manifest_sha256,
        "expected_case_count": 30,
        "expected_case_ids": list(expected_ids),
        "projection_categories": list(CANARY_REVIEW_CATEGORIES),
        "purpose": "evaluation_only",
        "local_only": True,
        "eligible_for_training": False,
        "training_export_allowed": False,
        "online_research_allowed": False,
        "create_only": True,
        "plaintext_policy": "gate_passed_released_answers_only",
        "held_content_policy": "encrypted_only",
    }
    assert_safe_evaluation_payload(material)
    material["seal_sha256"] = sealed_sha256(material)
    manifest = CanaryReviewWorkspaceManifest.model_validate(material)

    parent_parts: tuple[str, ...]
    if review_root is None:
        anchor = project_root
        parent_parts = (
            "data",
            "evaluations",
            "canary-output-review",
            review_date.isoformat(),
        )
    else:
        if not review_root.is_absolute() or review_root.is_symlink():
            raise ValueError("approved canary review root must be an absolute safe directory")
        anchor = review_root.parent
        parent_parts = (review_root.name, review_date.isoformat())
    _prepare_parent_tree(anchor, parent_parts)
    root_parts = (*parent_parts, run_id)
    create_private_directory_at(anchor, root_parts, exist_ok=False)
    root = anchor.absolute().joinpath(*root_parts)
    for category in CANARY_REVIEW_CATEGORIES:
        create_private_directory_at(anchor, (*root_parts, category), exist_ok=False)

    workspace = CanaryReviewWorkspace(root=root, manifest=manifest)

    workspace.write_private_bytes(
        "workspace-manifest.json",
        payload=(
            json.dumps(
                manifest.model_dump(mode="json", by_alias=True),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8"),
    )
    workspace.write_private_bytes("sample-manifest.json", payload=manifest_bytes)
    workspace.write_private_bytes("owner-feedback", "ledger.jsonl", payload=b"")
    return workspace
