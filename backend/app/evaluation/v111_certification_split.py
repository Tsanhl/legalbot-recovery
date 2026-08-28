"""Keyed, post-qualification 30/30 split for v1.11 owner certification.

This module is deliberately inert during Phase-2 preparation.  It accepts a
32-byte owner-custodied secret only after an exact all-60 qualification exists;
it never creates, stores, logs or recovers that secret.  The historical
``owner_quality_canary`` split remains immutable regression history and is not
used as the v1.11 certification split.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import itertools
import json
import os
import re
import stat
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..governance.immutable_capability import ImmutableOpaqueCapability
from ..governance.v111_exact_private_root import (
    open_exact_private_root_descriptor,
    require_exact_private_root_descriptor_current,
)
from .live30 import assert_safe_evaluation_payload
from .live_suite import LiveEvaluationBundle, canonical_json, sealed_sha256

if TYPE_CHECKING:
    from .all60_qualification import ExactAll60Qualification
    from .sealed_candidate import SealedCandidateIdentity

V111_CERTIFICATION_SPLIT_SCHEMA = "legalbot.v111-certification-split-manifest.v1"
V111_CERTIFICATION_SPLIT_POLICY_VERSION = "legalbot.v111-certification-split-policy.v1"
V111_CERTIFICATION_SPLIT_POLICY: dict[str, Any] = {
    "schema": V111_CERTIFICATION_SPLIT_POLICY_VERSION,
    "development_count": 30,
    "sealed_validation_count": 30,
    "secret": {
        "bytes": 32,
        "generation": "owner-local-csprng-after-exact-qualification",
        "manifest_field": "sha256-commitment-only",
        "ranking": "hmac-sha256-v1",
    },
    "primary_strata": ["expected_research_route", "task_type", "word_band"],
    "secondary_balance": [
        "issue_band",
        "exact_issue_count",
        "exact_word_target",
        "duplicate_normalised_subject",
    ],
    "allocation": "minimum-primary-marginal-deviation-then-keyed-rank-v1",
    "word_bands": {
        "short_1000_2000": [1000, 2000],
        "medium_3000_5000": [3000, 5000],
        "long_6000_10000": [6000, 10000],
    },
    "issue_bands": {
        "compact_1_8": [1, 8],
        "standard_9_10": [9, 10],
        "extended_11_99": [11, 99],
    },
    "performance_results_used": False,
    "stage_a_used": False,
    "redraw_allowed": False,
}
V111_CERTIFICATION_SPLIT_POLICY_SHA256 = hashlib.sha256(
    canonical_json(V111_CERTIFICATION_SPLIT_POLICY)
).hexdigest()
V111_CERTIFICATION_SPLIT_FILENAME = "v111-certification-split.json"

_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_CASE_ID = re.compile(r"^(?:live30|live60)-q[0-9]{2}$")
_MAX_SPLIT_MANIFEST_BYTES = 2 * 1024 * 1024
_MAX_LEAK_SCAN_FILES = 4_096
_MAX_LEAK_SCAN_FILE_BYTES = 32 * 1024 * 1024
_MAX_LEAK_SCAN_TOTAL_BYTES = 256 * 1024 * 1024

_VERIFIED_V111_SPLIT_FREEZE_TOKEN = object()
_VERIFIED_SEALED_VALIDATION_CUSTODY_TOKEN = object()
_VERIFIED_DEVELOPMENT_REVIEW_CUSTODY_TOKEN = object()

CertificationLane = Literal["development", "sealed_validation"]
WordBand = Literal["short_1000_2000", "medium_3000_5000", "long_6000_10000"]
IssueBand = Literal["compact_1_8", "standard_9_10", "extended_11_99"]
PrimaryStratum = tuple[str, str, str]


def _word_band(word_target: int) -> WordBand:
    if 1_000 <= word_target <= 2_000:
        return "short_1000_2000"
    if 3_000 <= word_target <= 5_000:
        return "medium_3000_5000"
    if 6_000 <= word_target <= 10_000:
        return "long_6000_10000"
    raise ValueError("certification case word target is outside the frozen policy bands")


def _issue_band(issue_count: int) -> IssueBand:
    if 1 <= issue_count <= 8:
        return "compact_1_8"
    if 9 <= issue_count <= 10:
        return "standard_9_10"
    if 11 <= issue_count <= 99:
        return "extended_11_99"
    raise ValueError("certification case issue count is outside the frozen policy bands")


def _subject_sha256(subject: str) -> str:
    normalised = " ".join(subject.casefold().split())
    return hashlib.sha256(normalised.encode("utf-8")).hexdigest()


def _require_split_secret(secret: bytes) -> None:
    if not isinstance(secret, bytes) or len(secret) != 32:
        raise ValueError("v1.11 certification split requires one 32-byte local secret")


def split_secret_commitment(secret: bytes) -> str:
    """Return the domain-separated public commitment; never persist the secret."""

    _require_split_secret(secret)
    return hashlib.sha256(b"legalbot.v111-certification-split-secret.v1\0" + secret).hexdigest()


def _keyed_sha256(secret: bytes, *parts: str) -> str:
    material = "\0".join(parts).encode("utf-8")
    return hmac.new(secret, material, hashlib.sha256).hexdigest()


def _marginal_counts(allocation: Mapping[PrimaryStratum, int]) -> Counter[tuple[str, str]]:
    output: Counter[tuple[str, str]] = Counter()
    for (route, task, word_band), count in allocation.items():
        output[("route", route)] += count
        output[("task", task)] += count
        output[("word_band", word_band)] += count
    return output


def _allocation_for_strata(
    *,
    groups: Mapping[PrimaryStratum, Sequence[str]],
    secret: bytes,
    binding: str,
) -> dict[PrimaryStratum, int]:
    keys = tuple(sorted(groups))
    base = {key: len(groups[key]) // 2 for key in keys}
    odd = tuple(key for key in keys if len(groups[key]) % 2)
    if len(odd) > 20:  # fixed Live60 currently has two; guard future policy drift.
        raise ValueError("certification primary strata are too fragmented for frozen allocation")
    totals = _marginal_counts({key: len(groups[key]) for key in keys})
    best: tuple[tuple[int, int, str], dict[PrimaryStratum, int]] | None = None
    for bits in itertools.product((0, 1), repeat=len(odd)):
        allocation = dict(base)
        for key, bit in zip(odd, bits, strict=True):
            allocation[key] += bit
        if sum(allocation.values()) != 30:
            continue
        selected = _marginal_counts(allocation)
        deviations = tuple(abs(2 * selected[key] - total) for key, total in sorted(totals.items()))
        signature = ";".join(f"{'|'.join(key)}={allocation[key]}" for key in keys)
        tie = _keyed_sha256(
            secret,
            "legalbot.v111-certification-allocation.v1",
            binding,
            signature,
        )
        score = (max(deviations, default=0), sum(deviations), tie)
        if best is None or score < best[0]:
            best = (score, allocation)
    if best is None:
        raise ValueError("certification policy could not allocate an exact 30/30 complement")
    return best[1]


class V111CertificationSplitCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    ordinal: int = Field(ge=1, le=60)
    lane: CertificationLane
    task_type: Literal["essay", "problem"]
    expected_research_route: Literal["sectioned", "full_enquiry"]
    word_target: int = Field(ge=1_000, le=10_000)
    word_band: WordBand
    issue_count: int = Field(ge=1, le=99)
    issue_band: IssueBand
    subject_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    selection_rank_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def _distribution(cases: Sequence[V111CertificationSplitCase]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for case in cases:
        counts[f"route:{case.expected_research_route}"] += 1
        counts[f"task:{case.task_type}"] += 1
        counts[f"word_band:{case.word_band}"] += 1
        counts[f"issue_band:{case.issue_band}"] += 1
    return dict(sorted(counts.items()))


def _secondary_score(
    *,
    development: set[str],
    rows: Mapping[str, V111CertificationSplitCase],
) -> tuple[int, int, int, int]:
    feature_totals: Counter[tuple[str, str]] = Counter()
    feature_development: Counter[tuple[str, str]] = Counter()
    subject_groups: Counter[str] = Counter(row.subject_sha256 for row in rows.values())
    total_issues = 0
    development_issues = 0
    total_words = 0
    development_words = 0
    for case_id, row in rows.items():
        features: tuple[tuple[str, str], ...] = (
            ("issue_band", row.issue_band),
            ("issue_count", str(row.issue_count)),
            ("word_target", str(row.word_target)),
        )
        if subject_groups[row.subject_sha256] > 1:
            features = (*features, ("subject", row.subject_sha256))
        for feature in features:
            feature_totals[feature] += 1
            if case_id in development:
                feature_development[feature] += 1
        total_issues += row.issue_count
        total_words += row.word_target
        if case_id in development:
            development_issues += row.issue_count
            development_words += row.word_target
    deviations = tuple(
        abs(2 * feature_development[key] - total) for key, total in sorted(feature_totals.items())
    )
    return (
        max(deviations, default=0),
        sum(deviations),
        abs(2 * development_issues - total_issues),
        abs(2 * development_words - total_words),
    )


def _improve_secondary_balance(
    *,
    development: set[str],
    rows: Mapping[str, V111CertificationSplitCase],
    strata: Mapping[str, PrimaryStratum],
    secret: bytes,
    binding: str,
) -> set[str]:
    """Apply only same-primary-stratum swaps, preserving primary allocation."""

    output = set(development)
    all_ids = set(rows)
    while True:
        current = _secondary_score(development=output, rows=rows)
        candidates: list[tuple[tuple[int, int, int, int], str, str, str]] = []
        for left in sorted(output):
            for right in sorted(all_ids - output):
                if strata[left] != strata[right]:
                    continue
                swapped = (output - {left}) | {right}
                score = _secondary_score(development=swapped, rows=rows)
                if score >= current:
                    continue
                tie = _keyed_sha256(
                    secret,
                    "legalbot.v111-certification-secondary-swap.v1",
                    binding,
                    left,
                    right,
                )
                candidates.append((score, tie, left, right))
        if not candidates:
            return output
        _score, _tie, left, right = min(candidates)
        output.remove(left)
        output.add(right)


def _split_digest(value: Mapping[str, Any]) -> str:
    material = dict(value)
    material.pop("split_digest_sha256", None)
    material.pop("seal_sha256", None)
    return hashlib.sha256(canonical_json(material)).hexdigest()


def _field_digest(value: Mapping[str, Any], field: str) -> str:
    material = dict(value)
    material.pop(field, None)
    return hashlib.sha256(canonical_json(material)).hexdigest()


class V111CertificationSplitManifest(BaseModel):
    """Prose-free custody manifest; ordinary Development tooling must not load it."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.v111-certification-split-manifest.v1"] = Field(
        default="legalbot.v111-certification-split-manifest.v1", alias="schema"
    )
    split_id: str = Field(pattern=r"^v111-certification-split-[0-9a-f]{20}$")
    suite_id: Literal["live-evaluation-60-v1"]
    suite_manifest_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    suite_registry_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_build_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    candidate_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_source_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    qualification_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    qualification_issue_identity_set_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    qualification_as_of_date: str = Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
    certification_contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    owner_configuration_tranche_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    split_freeze_authorization_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    algorithm_version: Literal["legalbot.v111-certification-split-policy.v1"]
    algorithm_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    secret_commitment_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    secret_generated_after_qualification: Literal[True]
    secret_embedded: Literal[False]
    performance_results_used: Literal[False]
    stage_a_used: Literal[False]
    purpose: Literal["evaluation_only"] = "evaluation_only"
    eligible_for_training: Literal[False] = False
    training_export_allowed: Literal[False] = False
    local_only: Literal[True] = True
    immutable: Literal[True] = True
    case_count: Literal[60] = 60
    issue_count: Literal[585] = 585
    development_case_count: Literal[30] = 30
    sealed_validation_case_count: Literal[30] = 30
    development_case_ids: tuple[str, ...]
    sealed_validation_case_ids: tuple[str, ...]
    development_distribution: dict[str, int]
    sealed_validation_distribution: dict[str, int]
    cases: tuple[V111CertificationSplitCase, ...]
    split_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def exact_complement_is_consistent(self) -> Self:
        case_ids = tuple(row.case_id for row in self.cases)
        development = tuple(row.case_id for row in self.cases if row.lane == "development")
        validation = tuple(row.case_id for row in self.cases if row.lane == "sealed_validation")
        if (
            len(case_ids) != 60
            or len(set(case_ids)) != 60
            or any(not _CASE_ID.fullmatch(case_id) for case_id in case_ids)
            or development != self.development_case_ids
            or validation != self.sealed_validation_case_ids
            or len(development) != 30
            or len(validation) != 30
            or set(development) & set(validation)
            or set(development) | set(validation) != set(case_ids)
        ):
            raise ValueError("v1.11 certification split is not an exact 30/30 complement")
        development_rows = tuple(row for row in self.cases if row.lane == "development")
        validation_rows = tuple(row for row in self.cases if row.lane == "sealed_validation")
        if (
            self.development_distribution != _distribution(development_rows)
            or self.sealed_validation_distribution != _distribution(validation_rows)
            or self.algorithm_sha256 != V111_CERTIFICATION_SPLIT_POLICY_SHA256
        ):
            raise ValueError("v1.11 certification split distributions or policy differ")
        payload = self.model_dump(mode="json", by_alias=True)
        if self.split_digest_sha256 != _split_digest(payload):
            raise ValueError("v1.11 certification split digest differs")
        if self.seal_sha256 != sealed_sha256(payload):
            raise ValueError("v1.11 certification split seal differs")
        return self


class V111DevelopmentLeakCheck(BaseModel):
    """Path-free result of scanning a Development package from split custody."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.v111-development-validation-leak-check.v1"] = Field(
        default="legalbot.v111-development-validation-leak-check.v1", alias="schema"
    )
    split_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    scanned_file_count: int = Field(ge=0, le=_MAX_LEAK_SCAN_FILES)
    scanned_byte_count: int = Field(ge=0, le=_MAX_LEAK_SCAN_TOTAL_BYTES)
    leak_count: int = Field(ge=0)
    leak_file_sha256s: tuple[str, ...]
    reason_codes: tuple[str, ...]
    passed: bool
    authorizing: Literal[False] = False
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def result_is_consistent(self) -> Self:
        if (
            len(self.leak_file_sha256s) != len(set(self.leak_file_sha256s))
            or any(not _SHA256.fullmatch(value) for value in self.leak_file_sha256s)
            or len(self.reason_codes) != len(set(self.reason_codes))
            or self.passed != (self.leak_count == 0)
            or self.passed != (not self.leak_file_sha256s and not self.reason_codes)
        ):
            raise ValueError("v1.11 Development leak-check result is inconsistent")
        material = self.model_dump(mode="json", by_alias=True)
        if self.report_sha256 != _field_digest(material, "report_sha256"):
            raise ValueError("v1.11 Development leak-check report seal differs")
        return self


class VerifiedV111SplitFreezeAuthorization(ImmutableOpaqueCapability):
    """Opaque future gate output; no preparation code can mint this capability."""

    __slots__ = (
        "_bundle",
        "_candidate",
        "_certification_contract_sha256",
        "_owner_configuration_tranche_sha256",
        "_qualification",
        "_secret",
        "_token",
        "authorization_sha256",
    )

    def __init__(
        self,
        *,
        bundle: LiveEvaluationBundle,
        candidate: SealedCandidateIdentity,
        qualification: ExactAll60Qualification,
        certification_contract_sha256: str,
        owner_configuration_tranche_sha256: str,
        secret: bytes,
        authorization_sha256: str,
        _token: object,
    ) -> None:
        if _token is not _VERIFIED_V111_SPLIT_FREEZE_TOKEN:
            raise TypeError("trusted split-freeze authorization required")
        if (
            _SHA256.fullmatch(certification_contract_sha256) is None
            or _SHA256.fullmatch(owner_configuration_tranche_sha256) is None
            or _SHA256.fullmatch(authorization_sha256) is None
        ):
            raise ValueError("split-freeze authorization binding is invalid")
        self._bundle = bundle
        self._candidate = candidate
        self._qualification = qualification
        self._certification_contract_sha256 = certification_contract_sha256
        self._owner_configuration_tranche_sha256 = owner_configuration_tranche_sha256
        self._secret = secret
        self.authorization_sha256 = authorization_sha256
        self._token = _token

    def __repr__(self) -> str:
        return "<VerifiedV111SplitFreezeAuthorization>"


class VerifiedSealedValidationCustody(ImmutableOpaqueCapability):
    """Opaque exact-root capability issued only after signed configuration replay."""

    __slots__ = (
        "_project_root",
        "_root",
        "_token",
        "configuration_tranche_sha256",
        "owner_policy_tranche_sha256",
        "package_sha256",
        "release_binding_sha256",
        "root_identity_sha256",
    )

    def __init__(
        self,
        *,
        project_root: Path,
        root: Path,
        root_identity_sha256: str,
        release_binding_sha256: str,
        owner_policy_tranche_sha256: str,
        configuration_tranche_sha256: str,
        package_sha256: str,
        _token: object,
    ) -> None:
        identities = (
            root_identity_sha256,
            release_binding_sha256,
            owner_policy_tranche_sha256,
            configuration_tranche_sha256,
            package_sha256,
        )
        if _token is not _VERIFIED_SEALED_VALIDATION_CUSTODY_TOKEN:
            raise TypeError("trusted sealed-Validation custody required")
        if any(_SHA256.fullmatch(value) is None for value in identities):
            raise ValueError("sealed-Validation custody binding is invalid")
        self._project_root = project_root
        self._root = root
        self.root_identity_sha256 = root_identity_sha256
        self.release_binding_sha256 = release_binding_sha256
        self.owner_policy_tranche_sha256 = owner_policy_tranche_sha256
        self.configuration_tranche_sha256 = configuration_tranche_sha256
        self.package_sha256 = package_sha256
        self._token = _token

    def __repr__(self) -> str:
        return "<VerifiedSealedValidationCustody>"


class VerifiedDevelopmentReviewCustody(ImmutableOpaqueCapability):
    """Opaque exact Development-root capability from signed configuration replay."""

    __slots__ = (
        "_project_root",
        "_root",
        "_token",
        "configuration_tranche_sha256",
        "owner_policy_tranche_sha256",
        "package_sha256",
        "release_binding_sha256",
        "root_identity_sha256",
    )

    def __init__(
        self,
        *,
        project_root: Path,
        root: Path,
        root_identity_sha256: str,
        release_binding_sha256: str,
        owner_policy_tranche_sha256: str,
        configuration_tranche_sha256: str,
        package_sha256: str,
        _token: object,
    ) -> None:
        identities = (
            root_identity_sha256,
            release_binding_sha256,
            owner_policy_tranche_sha256,
            configuration_tranche_sha256,
            package_sha256,
        )
        if _token is not _VERIFIED_DEVELOPMENT_REVIEW_CUSTODY_TOKEN:
            raise TypeError("trusted Development review custody required")
        if any(_SHA256.fullmatch(value) is None for value in identities):
            raise ValueError("Development review custody binding is invalid")
        self._project_root = project_root
        self._root = root
        self.root_identity_sha256 = root_identity_sha256
        self.release_binding_sha256 = release_binding_sha256
        self.owner_policy_tranche_sha256 = owner_policy_tranche_sha256
        self.configuration_tranche_sha256 = configuration_tranche_sha256
        self.package_sha256 = package_sha256
        self._token = _token

    def __repr__(self) -> str:
        return "<VerifiedDevelopmentReviewCustody>"


def freeze_v111_certification_split(*, authorization: object) -> V111CertificationSplitManifest:
    """Freeze only from a future strict-replay, action-specific owner capability."""

    if (
        type(authorization) is not VerifiedV111SplitFreezeAuthorization
        or authorization._token is not _VERIFIED_V111_SPLIT_FREEZE_TOKEN
    ):
        raise PermissionError("trusted split-freeze authorization required")
    return _derive_v111_certification_split(
        bundle=authorization._bundle,
        candidate=authorization._candidate,
        qualification=authorization._qualification,
        certification_contract_sha256=authorization._certification_contract_sha256,
        owner_configuration_tranche_sha256=(authorization._owner_configuration_tranche_sha256),
        secret=authorization._secret,
        split_freeze_authorization_sha256=authorization.authorization_sha256,
    )


def _derive_v111_certification_split(
    *,
    bundle: LiveEvaluationBundle,
    candidate: SealedCandidateIdentity,
    qualification: ExactAll60Qualification,
    certification_contract_sha256: str,
    owner_configuration_tranche_sha256: str,
    secret: bytes,
    split_freeze_authorization_sha256: str,
) -> V111CertificationSplitManifest:
    """Pure derivation behind the opaque production authorization gate.

    This helper is intentionally private. Production callers must use
    ``freeze_v111_certification_split`` and cannot supply raw qualifications,
    hashes, or secrets.
    """

    from .all60_qualification import ExactAll60Qualification

    _require_split_secret(secret)
    if not isinstance(qualification, ExactAll60Qualification):
        raise ValueError("v1.11 certification split requires exact all-60 qualification")
    if (
        not _SHA256.fullmatch(certification_contract_sha256)
        or not _SHA256.fullmatch(owner_configuration_tranche_sha256)
        or not _SHA256.fullmatch(split_freeze_authorization_sha256)
        or not _SAFE_ID.fullmatch(candidate.build_id)
    ):
        raise ValueError("v1.11 certification split binding identity is invalid")
    registry_ids = tuple(case.case_id for case in bundle.registry.cases)
    case_bindings = {case.case_id: case for case in qualification.case_bindings}
    if (
        bundle.registry.case_count != 60
        or len(registry_ids) != 60
        or qualification.case_ids != registry_ids
        or tuple(case_bindings) != registry_ids
        or qualification.issue_count != 585
        or sum(case.issue_count for case in qualification.case_bindings) != 585
        or qualification.suite_id != bundle.manifest.suite_id
        or qualification.suite_manifest_seal_sha256 != bundle.manifest.seal_sha256
        or qualification.suite_registry_canonical_sha256 != bundle.registry.canonical_sha256
        or qualification.candidate_build_id != candidate.build_id
        or qualification.candidate_manifest_sha256 != candidate.candidate_manifest_sha256
        or qualification.candidate_seal_sha256 != candidate.candidate_seal_sha256
        or qualification.candidate_source_manifest_sha256 != candidate.source_manifest_sha256
        or candidate.status != "candidate"
    ):
        raise ValueError("v1.11 split inputs differ from exact qualification or candidate")

    commitment = split_secret_commitment(secret)
    binding = sealed_sha256(
        {
            "schema": "legalbot.v111-certification-split-binding.v1",
            "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
            "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
            "candidate_build_id": candidate.build_id,
            "candidate_manifest_sha256": candidate.candidate_manifest_sha256,
            "qualification_seal_sha256": qualification.seal_sha256,
            "certification_contract_sha256": certification_contract_sha256,
            "owner_configuration_tranche_sha256": owner_configuration_tranche_sha256,
            "split_freeze_authorization_sha256": split_freeze_authorization_sha256,
            "algorithm_sha256": V111_CERTIFICATION_SPLIT_POLICY_SHA256,
            "secret_commitment_sha256": commitment,
        }
    )
    groups: dict[PrimaryStratum, list[str]] = defaultdict(list)
    strata: dict[str, PrimaryStratum] = {}
    provisional: dict[str, V111CertificationSplitCase] = {}
    ranks: dict[str, str] = {}
    for case in bundle.registry.cases:
        issue_count = case_bindings[case.case_id].issue_count
        primary_stratum: PrimaryStratum = (
            case.expected_research_route,
            case.task_type,
            _word_band(case.word_target),
        )
        rank = _keyed_sha256(
            secret,
            "legalbot.v111-certification-case-rank.v1",
            binding,
            case.case_id,
            *primary_stratum,
            str(issue_count),
        )
        strata[case.case_id] = primary_stratum
        groups[primary_stratum].append(case.case_id)
        ranks[case.case_id] = rank
        provisional[case.case_id] = V111CertificationSplitCase(
            case_id=case.case_id,
            ordinal=case.ordinal,
            lane="sealed_validation",
            task_type=case.task_type,
            expected_research_route=case.expected_research_route,
            word_target=case.word_target,
            word_band=_word_band(case.word_target),
            issue_count=issue_count,
            issue_band=_issue_band(issue_count),
            subject_sha256=_subject_sha256(case.subject),
            selection_rank_sha256=rank,
        )
    allocation = _allocation_for_strata(groups=groups, secret=secret, binding=binding)
    development: set[str] = set()
    for primary_stratum in sorted(groups):
        ranked = sorted(groups[primary_stratum], key=lambda case_id: (ranks[case_id], case_id))
        development.update(ranked[: allocation[primary_stratum]])
    development = _improve_secondary_balance(
        development=development,
        rows=provisional,
        strata=strata,
        secret=secret,
        binding=binding,
    )
    if len(development) != 30:
        raise AssertionError("v1.11 certification allocator did not retain exactly 30 cases")

    rows = tuple(
        provisional[case_id].model_copy(
            update={"lane": "development" if case_id in development else "sealed_validation"}
        )
        for case_id in registry_ids
    )
    development_rows = tuple(row for row in rows if row.lane == "development")
    validation_rows = tuple(row for row in rows if row.lane == "sealed_validation")
    split_identifier = _keyed_sha256(
        secret,
        "legalbot.v111-certification-split-id.v1",
        binding,
        *[row.case_id for row in development_rows],
    )
    material: dict[str, Any] = {
        "schema": V111_CERTIFICATION_SPLIT_SCHEMA,
        "split_id": f"v111-certification-split-{split_identifier[:20]}",
        "suite_id": bundle.manifest.suite_id,
        "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
        "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
        "candidate_build_id": candidate.build_id,
        "candidate_manifest_sha256": candidate.candidate_manifest_sha256,
        "candidate_seal_sha256": candidate.candidate_seal_sha256,
        "candidate_source_manifest_sha256": candidate.source_manifest_sha256,
        "qualification_seal_sha256": qualification.seal_sha256,
        "qualification_issue_identity_set_sha256": qualification.issue_identity_set_sha256,
        "qualification_as_of_date": qualification.as_of_date.isoformat(),
        "certification_contract_sha256": certification_contract_sha256,
        "owner_configuration_tranche_sha256": owner_configuration_tranche_sha256,
        "split_freeze_authorization_sha256": split_freeze_authorization_sha256,
        "algorithm_version": V111_CERTIFICATION_SPLIT_POLICY_VERSION,
        "algorithm_sha256": V111_CERTIFICATION_SPLIT_POLICY_SHA256,
        "secret_commitment_sha256": commitment,
        "secret_generated_after_qualification": True,
        "secret_embedded": False,
        "performance_results_used": False,
        "stage_a_used": False,
        "purpose": "evaluation_only",
        "eligible_for_training": False,
        "training_export_allowed": False,
        "local_only": True,
        "immutable": True,
        "case_count": 60,
        "issue_count": 585,
        "development_case_count": 30,
        "sealed_validation_case_count": 30,
        "development_case_ids": [row.case_id for row in development_rows],
        "sealed_validation_case_ids": [row.case_id for row in validation_rows],
        "development_distribution": _distribution(development_rows),
        "sealed_validation_distribution": _distribution(validation_rows),
        "cases": [row.model_dump(mode="json") for row in rows],
    }
    assert_safe_evaluation_payload(material)
    material["split_digest_sha256"] = _split_digest(material)
    material["seal_sha256"] = sealed_sha256(material)
    return V111CertificationSplitManifest.model_validate(material)


def v111_certification_split_bytes(manifest: V111CertificationSplitManifest) -> bytes:
    payload = manifest.model_dump(mode="json", by_alias=True)
    assert_safe_evaluation_payload(payload)
    return (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def verify_v111_certification_split(
    manifest: V111CertificationSplitManifest,
    *,
    authorization: object,
) -> V111CertificationSplitManifest:
    """Replay only through the same opaque authorization used for freezing."""

    expected = freeze_v111_certification_split(authorization=authorization)
    if manifest != expected or v111_certification_split_bytes(manifest) != (
        v111_certification_split_bytes(expected)
    ):
        raise ValueError("v1.11 certification split is a redraw or replay mismatch")
    return expected


def _require_sealed_validation_custody(value: object) -> VerifiedSealedValidationCustody:
    if (
        type(value) is not VerifiedSealedValidationCustody
        or value._token is not _VERIFIED_SEALED_VALIDATION_CUSTODY_TOKEN
    ):
        raise PermissionError("trusted sealed-Validation custody required")
    from ..governance.v111_decision_generation import private_root_identity

    current = private_root_identity(value._root, project_root=value._project_root)
    if current != value.root_identity_sha256:
        raise RuntimeError("sealed-Validation custody root changed after signed replay")
    return value


def _require_development_review_custody(value: object) -> VerifiedDevelopmentReviewCustody:
    if (
        type(value) is not VerifiedDevelopmentReviewCustody
        or value._token is not _VERIFIED_DEVELOPMENT_REVIEW_CUSTODY_TOKEN
    ):
        raise PermissionError("trusted Development review custody required")
    from ..governance.v111_decision_generation import private_root_identity

    current = private_root_identity(value._root, project_root=value._project_root)
    if current != value.root_identity_sha256:
        raise RuntimeError("Development review custody root changed after signed replay")
    return value


def _scan_private_development_tree(
    root_descriptor: int,
    *,
    forbidden: Mapping[bytes, str],
) -> tuple[int, int, set[tuple[str, str]]]:
    """Descriptor-pin a private tree and return only bounded, path-free findings."""

    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory_flag is None:
        raise RuntimeError("secure Development leak scan is unavailable")
    directory_flags = os.O_RDONLY | directory_flag | no_follow
    file_flags = os.O_RDONLY | no_follow
    scanned_files = 0
    scanned_bytes = 0
    findings: set[tuple[str, str]] = set()

    def identity(value: os.stat_result) -> tuple[int, ...]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_uid,
            value.st_mode,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )

    def scan_directory(descriptor: int) -> None:
        nonlocal scanned_bytes, scanned_files
        directory_before = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(directory_before.st_mode)
            or directory_before.st_uid != os.getuid()
            or stat.S_IMODE(directory_before.st_mode) != 0o700
        ):
            raise ValueError("Development leak scan directory is not owner-private")
        for name in sorted(os.listdir(descriptor)):
            name_bytes = os.fsencode(name)
            name_sha256 = hashlib.sha256(
                b"legalbot.v111-development-member-name.v1\x00" + name_bytes
            ).hexdigest()
            for token, reason_code in forbidden.items():
                if token and token in name_bytes:
                    findings.add((name_sha256, reason_code))
            try:
                path_before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if stat.S_ISDIR(path_before.st_mode):
                    child = os.open(name, directory_flags, dir_fd=descriptor)
                    try:
                        if identity(os.fstat(child)) != identity(path_before):
                            raise ValueError("Development leak scan directory changed")
                        scan_directory(child)
                        path_after = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                        if identity(os.fstat(child)) != identity(path_after):
                            raise ValueError("Development leak scan directory changed")
                    finally:
                        os.close(child)
                    continue
                if not stat.S_ISREG(path_before.st_mode):
                    raise ValueError("Development leak scan found an unsafe member")
                member = os.open(name, file_flags, dir_fd=descriptor)
                try:
                    before = os.fstat(member)
                    if (
                        identity(before) != identity(path_before)
                        or before.st_uid != os.getuid()
                        or stat.S_IMODE(before.st_mode) != 0o600
                        or before.st_nlink != 1
                        or before.st_size > _MAX_LEAK_SCAN_FILE_BYTES
                    ):
                        raise ValueError("Development leak scan file is not owner-private")
                    scanned_files += 1
                    scanned_bytes += before.st_size
                    if (
                        scanned_files > _MAX_LEAK_SCAN_FILES
                        or scanned_bytes > _MAX_LEAK_SCAN_TOTAL_BYTES
                    ):
                        raise ValueError(
                            "Development leak check package exceeds frozen scan bounds"
                        )
                    blocks: list[bytes] = []
                    remaining = before.st_size
                    while remaining:
                        block = os.read(member, min(remaining, 1024 * 1024))
                        if not block:
                            raise ValueError("Development leak scan file changed")
                        blocks.append(block)
                        remaining -= len(block)
                    if os.read(member, 1):
                        raise ValueError("Development leak scan file changed")
                    content = b"".join(blocks)
                    after = os.fstat(member)
                    path_after = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                    if identity(before) != identity(after) or identity(before) != identity(
                        path_after
                    ):
                        raise ValueError("Development leak scan file changed")
                finally:
                    os.close(member)
            except OSError as exc:
                raise ValueError("Development leak scan tree is unsafe") from exc
            content_sha256 = hashlib.sha256(content).hexdigest()
            for token, reason_code in forbidden.items():
                if token and token in content:
                    findings.add((content_sha256, reason_code))
        directory_after = os.fstat(descriptor)
        if identity(directory_before) != identity(directory_after):
            raise ValueError("Development leak scan directory changed")

    scan_directory(root_descriptor)
    return scanned_files, scanned_bytes, findings


def write_v111_certification_split(
    *,
    custody: object,
    manifest: V111CertificationSplitManifest,
    authorization: object,
) -> Path:
    """Create only the exact action-authorized split in canonical custody."""

    verified = _require_sealed_validation_custody(custody)
    replayed = verify_v111_certification_split(
        manifest,
        authorization=authorization,
    )
    if replayed.owner_configuration_tranche_sha256 != verified.configuration_tranche_sha256:
        raise PermissionError("split manifest differs from signed custody configuration")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory_flag is None:
        raise RuntimeError("secure split-custody I/O is unavailable")
    root_descriptor, _root_identity = open_exact_private_root_descriptor(
        verified._root,
        project_root=verified._project_root,
        expected_identity_sha256=verified.root_identity_sha256,
    )
    member_descriptor = -1
    created = False
    try:
        member_descriptor = os.open(
            V111_CERTIFICATION_SPLIT_FILENAME,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | no_follow,
            0o600,
            dir_fd=root_descriptor,
        )
        created = True
        payload = v111_certification_split_bytes(replayed)
        with os.fdopen(member_descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        metadata = os.fstat(member_descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise RuntimeError("split custody artifact permissions are unsafe")
        os.lseek(member_descriptor, 0, os.SEEK_SET)
        replayed_bytes = b""
        while len(replayed_bytes) < len(payload):
            block = os.read(member_descriptor, len(payload) - len(replayed_bytes))
            if not block:
                raise RuntimeError("split custody artifact changed during exact replay")
            replayed_bytes += block
        if os.read(member_descriptor, 1) or replayed_bytes != payload:
            raise RuntimeError("split custody artifact changed during exact replay")
        path_metadata = os.stat(
            V111_CERTIFICATION_SPLIT_FILENAME,
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        if (
            path_metadata.st_dev != metadata.st_dev
            or path_metadata.st_ino != metadata.st_ino
            or path_metadata.st_uid != metadata.st_uid
            or path_metadata.st_mode != metadata.st_mode
            or path_metadata.st_nlink != metadata.st_nlink
            or path_metadata.st_size != metadata.st_size
        ):
            raise RuntimeError("split custody artifact changed during exact replay")
        os.fsync(root_descriptor)
        require_exact_private_root_descriptor_current(
            root_descriptor,
            root=verified._root,
            project_root=verified._project_root,
            expected_identity_sha256=verified.root_identity_sha256,
        )
    except BaseException:
        if created:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(V111_CERTIFICATION_SPLIT_FILENAME, dir_fd=root_descriptor)
                os.fsync(root_descriptor)
        raise
    finally:
        if member_descriptor >= 0:
            os.close(member_descriptor)
        os.close(root_descriptor)
    return verified._root / V111_CERTIFICATION_SPLIT_FILENAME


def load_v111_certification_split(
    *, custody: object, authorization: object
) -> V111CertificationSplitManifest:
    """Read and replay the canonical member against exact split authorization."""

    verified = _require_sealed_validation_custody(custody)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory_flag is None:
        raise RuntimeError("secure split-custody I/O is unavailable")
    root_descriptor, _root_identity = open_exact_private_root_descriptor(
        verified._root,
        project_root=verified._project_root,
        expected_identity_sha256=verified.root_identity_sha256,
    )
    member_descriptor = -1
    try:
        member_descriptor = os.open(
            V111_CERTIFICATION_SPLIT_FILENAME,
            os.O_RDONLY | no_follow,
            dir_fd=root_descriptor,
        )
        before = os.fstat(member_descriptor)
        path_before = os.stat(
            V111_CERTIFICATION_SPLIT_FILENAME,
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )

        def identity(value: os.stat_result) -> tuple[int, ...]:
            return (
                value.st_dev,
                value.st_ino,
                value.st_uid,
                value.st_mode,
                value.st_nlink,
                value.st_size,
                value.st_mtime_ns,
                value.st_ctime_ns,
            )

        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > _MAX_SPLIT_MANIFEST_BYTES
            or identity(before) != identity(path_before)
        ):
            raise ValueError("v1.11 certification split is not a bounded private file")
        blocks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            block = os.read(member_descriptor, min(remaining, 1024 * 1024))
            if not block:
                raise ValueError("v1.11 certification split changed during read")
            blocks.append(block)
            remaining -= len(block)
        if os.read(member_descriptor, 1):
            raise ValueError("v1.11 certification split changed during read")
        after = os.fstat(member_descriptor)
        path_after = os.stat(
            V111_CERTIFICATION_SPLIT_FILENAME,
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        if identity(before) != identity(after) or identity(before) != identity(path_after):
            raise ValueError("v1.11 certification split changed during read")
        raw = b"".join(blocks)
        require_exact_private_root_descriptor_current(
            root_descriptor,
            root=verified._root,
            project_root=verified._project_root,
            expected_identity_sha256=verified.root_identity_sha256,
        )
    except OSError as exc:
        raise ValueError("v1.11 certification split manifest is missing") from exc
    finally:
        if member_descriptor >= 0:
            os.close(member_descriptor)
        os.close(root_descriptor)
    try:
        manifest = V111CertificationSplitManifest.model_validate_json(raw)
    except Exception as exc:
        raise ValueError("v1.11 certification split contract is invalid") from exc
    if raw != v111_certification_split_bytes(manifest):
        raise ValueError("v1.11 certification split bytes are not canonical")
    if manifest.owner_configuration_tranche_sha256 != verified.configuration_tranche_sha256:
        raise PermissionError("split custody artifact differs from signed configuration")
    return verify_v111_certification_split(
        manifest,
        authorization=authorization,
    )


def scan_development_package_for_validation_leaks(
    *,
    custody: object,
    development_custody: object,
    authorization: object,
    manifest: V111CertificationSplitManifest,
    bundle: LiveEvaluationBundle,
) -> V111DevelopmentLeakCheck:
    """Reject direct Validation identity, question, or result material in Development.

    The report deliberately contains only content digests and reason codes, not
    filenames, private paths, Validation IDs, or Validation prose.  Historical
    exposure means the complement is not claimed genuinely unseen; this check
    still prevents fresh lane artifacts from being copied into iteration data.
    """

    verified = _require_sealed_validation_custody(custody)
    development = _require_development_review_custody(development_custody)
    manifest = verify_v111_certification_split(
        manifest,
        authorization=authorization,
    )
    if manifest.owner_configuration_tranche_sha256 != verified.configuration_tranche_sha256:
        raise PermissionError("Development leak check differs from signed custody configuration")
    if (
        development.configuration_tranche_sha256 != verified.configuration_tranche_sha256
        or development.release_binding_sha256 != verified.release_binding_sha256
        or development.package_sha256 != verified.package_sha256
        or development.owner_policy_tranche_sha256 != verified.owner_policy_tranche_sha256
        or development.root_identity_sha256 == verified.root_identity_sha256
        or development._root == verified._root
    ):
        raise PermissionError("Development and Validation custody bindings are not isolated")
    if (
        manifest.suite_id != bundle.manifest.suite_id
        or manifest.suite_manifest_seal_sha256 != bundle.manifest.seal_sha256
        or manifest.suite_registry_canonical_sha256 != bundle.registry.canonical_sha256
    ):
        raise ValueError("Development leak check suite differs from split custody")
    validation_ids = set(manifest.sealed_validation_case_ids)
    validation_cases = tuple(
        case for case in bundle.registry.cases if case.case_id in validation_ids
    )
    if len(validation_cases) != 30:
        raise ValueError("Development leak check cannot resolve exact Validation complement")

    forbidden: dict[bytes, str] = {
        token: "validation_lane_material"
        for token in (
            b'"sealed_validation"',
            b'"sealed_validation_case_ids"',
            b'"validation_stage_a"',
            b'"validation_answer"',
            b'"validation_reviewer"',
            b'"validation_result"',
        )
    }
    for case in validation_cases:
        forbidden[case.case_id.encode("ascii")] = "validation_case_identity"
        forbidden[case.question_sha256.encode("ascii")] = "validation_question_identity"
        forbidden[case.record_sha256.encode("ascii")] = "validation_question_identity"
        forbidden[case.question.encode("utf-8")] = "validation_question_text"
        escaped = json.dumps(case.question, ensure_ascii=False)[1:-1].encode("utf-8")
        forbidden[escaped] = "validation_question_text"

    validation_descriptor, _validation_identity = open_exact_private_root_descriptor(
        verified._root,
        project_root=verified._project_root,
        expected_identity_sha256=verified.root_identity_sha256,
    )
    development_descriptor = -1
    try:
        development_descriptor, _development_identity = open_exact_private_root_descriptor(
            development._root,
            project_root=development._project_root,
            expected_identity_sha256=development.root_identity_sha256,
        )
        validation_metadata = os.fstat(validation_descriptor)
        development_metadata = os.fstat(development_descriptor)
        if (validation_metadata.st_dev, validation_metadata.st_ino) == (
            development_metadata.st_dev,
            development_metadata.st_ino,
        ):
            raise PermissionError("Development and Validation custody roots are not distinct")
        scanned_files, scanned_bytes, findings = _scan_private_development_tree(
            development_descriptor,
            forbidden=forbidden,
        )
        require_exact_private_root_descriptor_current(
            development_descriptor,
            root=development._root,
            project_root=development._project_root,
            expected_identity_sha256=development.root_identity_sha256,
        )
        require_exact_private_root_descriptor_current(
            validation_descriptor,
            root=verified._root,
            project_root=verified._project_root,
            expected_identity_sha256=verified.root_identity_sha256,
        )
    finally:
        if development_descriptor >= 0:
            os.close(development_descriptor)
        os.close(validation_descriptor)

    leak_files = tuple(sorted({file_sha for file_sha, _reason in findings}))
    reasons = tuple(sorted({reason for _file_sha, reason in findings}))
    material: dict[str, Any] = {
        "schema": "legalbot.v111-development-validation-leak-check.v1",
        "split_digest_sha256": manifest.split_digest_sha256,
        "scanned_file_count": scanned_files,
        "scanned_byte_count": scanned_bytes,
        "leak_count": len(findings),
        "leak_file_sha256s": list(leak_files),
        "reason_codes": list(reasons),
        "passed": not findings,
        "authorizing": False,
    }
    material["report_sha256"] = _field_digest(material, "report_sha256")
    return V111DevelopmentLeakCheck.model_validate(material)


def assert_preparation_does_not_contain_split_secret(value: Mapping[str, Any]) -> None:
    """Guard preparation artifacts against accidentally materialising split authority."""

    forbidden = {
        "secret",
        "split_secret",
        "split_secret_hex",
        "development_case_ids",
        "sealed_validation_case_ids",
    }
    observed_keys: set[str] = set()

    def collect_keys(item: object) -> None:
        if isinstance(item, Mapping):
            for key, member in item.items():
                if isinstance(key, str):
                    observed_keys.add(key)
                collect_keys(member)
        elif isinstance(item, Sequence) and not isinstance(item, str | bytes | bytearray):
            for member in item:
                collect_keys(member)

    collect_keys(value)
    overlap = forbidden & observed_keys
    if overlap:
        raise ValueError("Phase-2 preparation must not contain split secret or lane allocation")
    encoded = canonical_json(value)
    if any(token in encoded for token in (b'"split_id"', b'"secret_commitment_sha256"')):
        raise ValueError("Phase-2 preparation must stop before split materialisation")
