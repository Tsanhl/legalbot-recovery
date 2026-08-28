"""Create-only, evidence-bound stop records for judgments reserved to the owner.

Technical work can produce and verify these records, but it cannot resolve them.
The records intentionally contain safe codes and digests rather than questions,
answers, legal source prose, personal paths, or owner identity material.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..evaluation.secure_artifact_io import (
    create_private_directory_at,
    write_private_file_at,
)

OWNER_DECISION_REQUIRED = "OWNER_DECISION_REQUIRED"
REQUEST_SCHEMA = "legalbot.owner-decision-required.v1"
RESOLUTION_SCHEMA = "legalbot.owner-decision-resolution.v1"

DecisionCategory = Literal[
    "policy",
    "source_rights",
    "legal_currentness",
    "standards",
    "promotion",
    "o04",
    "competing_fix",
]

_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_SAFE_CODE = re.compile(r"^[A-Z][A-Z0-9_]{2,95}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _sealed_sha256(value: Mapping[str, Any]) -> str:
    material = dict(value)
    material.pop("seal_sha256", None)
    return hashlib.sha256(_canonical_json(material)).hexdigest()


class OwnerDecisionEvidence(BaseModel):
    """A privacy-safe pointer to immutable evidence, never the evidence prose."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    kind: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    summary_code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,95}$")


class OwnerDecisionOption(BaseModel):
    """One bounded option represented only by safe outcome/consequence codes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    option_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    outcome_code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,95}$")
    recommended: bool
    consequence_codes: tuple[str, ...] = ()

    @model_validator(mode="after")
    def consequences_are_safe_and_unique(self) -> Self:
        if len(set(self.consequence_codes)) != len(self.consequence_codes):
            raise ValueError("owner decision consequence codes must be unique")
        if any(_SAFE_CODE.fullmatch(item) is None for item in self.consequence_codes):
            raise ValueError("owner decision consequence code is invalid")
        return self


class OwnerDecisionRequest(BaseModel):
    """A sealed stop that blocks named actions until an owner resolution exists."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-decision-required.v1"] = Field(
        default="legalbot.owner-decision-required.v1", alias="schema"
    )
    state: Literal["OWNER_DECISION_REQUIRED"] = "OWNER_DECISION_REQUIRED"
    decision_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    category: DecisionCategory
    scope_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    reason_codes: tuple[str, ...]
    evidence: tuple[OwnerDecisionEvidence, ...]
    options: tuple[OwnerDecisionOption, ...]
    blocked_actions: tuple[str, ...]
    created_at: datetime
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def request_is_complete_and_sealed(self) -> Self:
        if not self.reason_codes or any(
            _SAFE_CODE.fullmatch(item) is None for item in self.reason_codes
        ):
            raise ValueError("owner decision requires safe reason codes")
        if len(set(self.reason_codes)) != len(self.reason_codes):
            raise ValueError("owner decision reason codes must be unique")
        if not self.evidence:
            raise ValueError("owner decision requires immutable evidence references")
        if len({item.evidence_id for item in self.evidence}) != len(self.evidence):
            raise ValueError("owner decision evidence IDs must be unique")
        if len(self.options) < 2 or len({item.option_id for item in self.options}) != len(
            self.options
        ):
            raise ValueError("owner decision requires at least two unique options")
        if sum(item.recommended for item in self.options) != 1:
            raise ValueError("owner decision requires exactly one recommended option")
        if not self.blocked_actions or any(
            _SAFE_ID.fullmatch(item) is None for item in self.blocked_actions
        ):
            raise ValueError("owner decision must name safe blocked actions")
        if len(set(self.blocked_actions)) != len(self.blocked_actions):
            raise ValueError("owner decision blocked actions must be unique")
        dumped = self.model_dump(mode="json", by_alias=True)
        if self.seal_sha256 != _sealed_sha256(dumped):
            raise ValueError("owner decision request seal does not match its contents")
        return self

    @property
    def recommended_option_id(self) -> str:
        return next(item.option_id for item in self.options if item.recommended)


class OwnerDecisionResolution(BaseModel):
    """Owner-signed selection bound to one exact request seal and option."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-decision-resolution.v1"] = Field(
        default="legalbot.owner-decision-resolution.v1", alias="schema"
    )
    decision_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    request_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    selected_option_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    owner_ref: str = Field(pattern=r"^owner:[0-9a-f]{64}$")
    decided_at: datetime
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def resolution_is_sealed(self) -> Self:
        dumped = self.model_dump(mode="json", by_alias=True)
        if self.seal_sha256 != _sealed_sha256(dumped):
            raise ValueError("owner decision resolution seal does not match its contents")
        return self


def seal_owner_decision_request(
    *,
    decision_id: str,
    category: DecisionCategory,
    scope_id: str,
    reason_codes: Sequence[str],
    evidence: Sequence[OwnerDecisionEvidence | Mapping[str, Any]],
    options: Sequence[OwnerDecisionOption | Mapping[str, Any]],
    blocked_actions: Sequence[str],
    created_at: datetime,
) -> OwnerDecisionRequest:
    material: dict[str, Any] = {
        "schema": REQUEST_SCHEMA,
        "state": OWNER_DECISION_REQUIRED,
        "decision_id": decision_id,
        "category": category,
        "scope_id": scope_id,
        "reason_codes": list(reason_codes),
        "evidence": [
            item.model_dump(mode="json") if isinstance(item, OwnerDecisionEvidence) else dict(item)
            for item in evidence
        ],
        "options": [
            item.model_dump(mode="json") if isinstance(item, OwnerDecisionOption) else dict(item)
            for item in options
        ],
        "blocked_actions": list(blocked_actions),
        "created_at": created_at.isoformat().replace("+00:00", "Z"),
    }
    material["seal_sha256"] = _sealed_sha256(material)
    return OwnerDecisionRequest.model_validate(material)


def seal_owner_decision_resolution(
    *,
    request: OwnerDecisionRequest,
    selected_option_id: str,
    owner_ref: str,
    decided_at: datetime,
) -> OwnerDecisionResolution:
    if selected_option_id not in {item.option_id for item in request.options}:
        raise ValueError("owner selected an option outside the sealed request")
    material = {
        "schema": RESOLUTION_SCHEMA,
        "decision_id": request.decision_id,
        "request_seal_sha256": request.seal_sha256,
        "selected_option_id": selected_option_id,
        "owner_ref": owner_ref,
        "decided_at": decided_at.isoformat().replace("+00:00", "Z"),
    }
    material["seal_sha256"] = _sealed_sha256(material)
    return OwnerDecisionResolution.model_validate(material)


def require_owner_resolution(
    request: OwnerDecisionRequest,
    resolution: OwnerDecisionResolution | None,
) -> OwnerDecisionResolution:
    if resolution is None:
        raise PermissionError(OWNER_DECISION_REQUIRED)
    if (
        resolution.decision_id != request.decision_id
        or resolution.request_seal_sha256 != request.seal_sha256
        or resolution.selected_option_id not in {item.option_id for item in request.options}
    ):
        raise PermissionError("owner resolution does not match the sealed decision request")
    return resolution


class OwnerDecisionStore:
    """Private create-only filesystem store; it never overwrites a judgment."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def _parts(self, decision_id: str, filename: str) -> tuple[str, str]:
        if _SAFE_ID.fullmatch(decision_id) is None:
            raise ValueError("invalid owner decision ID")
        if filename not in {"request.json", "resolution.json"}:
            raise ValueError("invalid owner decision filename")
        return decision_id, filename

    def _create_only(self, decision_id: str, filename: str, payload: BaseModel) -> Path:
        parts = self._parts(decision_id, filename)
        create_private_directory_at(
            self.root.parent,
            (self.root.name,),
            exist_ok=True,
        )
        create_private_directory_at(
            self.root,
            (parts[0],),
            exist_ok=True,
        )
        data = _canonical_json(payload.model_dump(mode="json", by_alias=True))
        write_private_file_at(self.root, parts, data)
        return self.root / parts[0] / parts[1]

    def write_request(self, request: OwnerDecisionRequest) -> Path:
        return self._create_only(request.decision_id, "request.json", request)

    def write_resolution(self, resolution: OwnerDecisionResolution) -> Path:
        return self._create_only(resolution.decision_id, "resolution.json", resolution)
