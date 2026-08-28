"""Deterministic, immutable owner-quality 30/30 split for the sealed Live60 suite.

This is a separate evaluation manifest. It does not modify or supersede the
frozen Live60 question registry or generation run plan. Sampling is refused
until a sealed all-60 qualification artifact dispositions every case.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import re
import stat
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .live30 import _exclusive_write, _private_directory, assert_safe_evaluation_payload
from .live_suite import LiveEvaluationBundle, canonical_json, sealed_sha256

if TYPE_CHECKING:
    from .all60_qualification import ExactAll60Qualification
    from .sealed_candidate import SealedCandidateIdentity

ALL60_QUALIFICATION_SCHEMA = "legalbot.live60-all-case-qualification.v1"
OWNER_QUALITY_CANARY_SCHEMA = "legalbot.owner-quality-canary-manifest.v1"
OWNER_QUALITY_CANARY_POLICY_VERSION = "legalbot.owner-quality-canary-policy.v1"
OWNER_QUALITY_CANARY_POLICY = {
    "schema": OWNER_QUALITY_CANARY_POLICY_VERSION,
    "development_count": 30,
    "blind_holdout_count": 30,
    "primary_strata": ["expected_research_route", "task_type", "word_band"],
    "subject_balance": "normalised_subject_hash_duplicate_groups",
    "allocation": "minimum_marginal_deviation_then_seeded_rank_v1",
    "word_bands": {
        "short_1000_2000": [1000, 2000],
        "medium_3000_5000": [3000, 5000],
        "long_6000_10000": [6000, 10000],
    },
}
OWNER_QUALITY_CANARY_POLICY_SHA256 = hashlib.sha256(
    canonical_json(OWNER_QUALITY_CANARY_POLICY)
).hexdigest()

_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_OWNER_QUALITY_MANIFEST_BYTES = 2 * 1024 * 1024

CanaryLane = Literal["development", "blind_holdout"]
WordBand = Literal["short_1000_2000", "medium_3000_5000", "long_6000_10000"]


def _word_band(word_target: int) -> WordBand:
    if 1_000 <= word_target <= 2_000:
        return "short_1000_2000"
    if 3_000 <= word_target <= 5_000:
        return "medium_3000_5000"
    if 6_000 <= word_target <= 10_000:
        return "long_6000_10000"
    raise ValueError("Live60 word target is outside the owner-quality policy bands")


def _subject_sha256(subject: str) -> str:
    normalised = " ".join(subject.casefold().split())
    return hashlib.sha256(normalised.encode("utf-8")).hexdigest()


class All60CaseQualification(BaseModel):
    """Safe seal proving every Live60 case has a reviewed execution disposition."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal[
        "legalbot.live60-all-case-qualification.v1",
        "legalbot.live60-all-case-qualification.v2",
        "legalbot.live60-all-case-qualification.v3",
    ] = Field(default="legalbot.live60-all-case-qualification.v1", alias="schema")
    suite_id: Literal["live-evaluation-60-v1"]
    suite_manifest_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    suite_registry_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_build_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    case_count: Literal[60]
    case_ids: tuple[str, ...]
    qualified_case_ids: tuple[str, ...]
    limited_case_ids: tuple[str, ...] = ()
    review_complete: Literal[True]
    unreviewed_issue_count: Literal[0]
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("case_ids", "qualified_case_ids", "limited_case_ids")
    @classmethod
    def case_ids_are_safe_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not re.fullmatch(r"^(?:live30|live60)-q[0-9]{2}$", value) for value in values):
            raise ValueError("all-60 qualification contains an invalid case ID")
        if len(values) != len(set(values)):
            raise ValueError("all-60 qualification contains duplicate case IDs")
        return values

    @model_validator(mode="after")
    def all_cases_are_dispositioned_and_sealed(self) -> Self:
        if len(self.case_ids) != 60:
            raise ValueError("all-60 qualification must name exactly 60 cases")
        qualified = set(self.qualified_case_ids)
        limited = set(self.limited_case_ids)
        if qualified & limited or qualified | limited != set(self.case_ids):
            raise ValueError("all-60 qualification must disposition every case once")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("all-60 qualification seal does not match its contents")
        return self


def load_all60_qualification(path: Path) -> All60CaseQualification:
    """Load only the derived exact v3 artifact for file-based release gates.

    The v1 model remains available for pure unit-level contract construction,
    but it is intentionally not accepted from disk because its shallow case
    summary can be hand-authored without the 585 issue/span/reviewer derivation proof.
    """

    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise ValueError("all-60 qualification artifact is missing")
    from .all60_qualification import ExactAll60Qualification

    return ExactAll60Qualification.model_validate_json(path.read_bytes())


class OwnerQualityCanaryCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    ordinal: int = Field(ge=1, le=60)
    lane: CanaryLane
    task_type: Literal["essay", "problem"]
    expected_research_route: Literal["sectioned", "full_enquiry"]
    word_band: WordBand
    subject_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    selection_rank_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def _distribution(cases: Sequence[OwnerQualityCanaryCase]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for case in cases:
        counts[f"route:{case.expected_research_route}"] += 1
        counts[f"task:{case.task_type}"] += 1
        counts[f"word_band:{case.word_band}"] += 1
    return dict(sorted(counts.items()))


class OwnerQualityCanaryManifest(BaseModel):
    """Prose-free, sealed complement split bound to exact suite/candidate bytes."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-quality-canary-manifest.v1"] = Field(
        default="legalbot.owner-quality-canary-manifest.v1", alias="schema"
    )
    manifest_id: str = Field(pattern=r"^owner-quality-canary-[0-9a-f]{20}$")
    suite_id: Literal["live-evaluation-60-v1"]
    suite_manifest_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    suite_registry_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_build_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    candidate_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    qualification_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_version: Literal["legalbot.owner-quality-canary-policy.v1"]
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    seed_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    purpose: Literal["evaluation_only"] = "evaluation_only"
    eligible_for_training: Literal[False] = False
    training_export_allowed: Literal[False] = False
    local_only: Literal[True] = True
    online_research_allowed: Literal[False] = False
    immutable: Literal[True] = True
    case_count: Literal[60] = 60
    development_case_count: Literal[30] = 30
    blind_holdout_case_count: Literal[30] = 30
    development_case_ids: tuple[str, ...]
    blind_holdout_case_ids: tuple[str, ...]
    development_distribution: dict[str, int]
    blind_holdout_distribution: dict[str, int]
    cases: tuple[OwnerQualityCanaryCase, ...]
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def split_is_exact_complement_and_sealed(self) -> Self:
        case_ids = tuple(case.case_id for case in self.cases)
        if len(case_ids) != 60 or len(set(case_ids)) != 60:
            raise ValueError("owner-quality canary must contain 60 unique cases")
        development = tuple(case.case_id for case in self.cases if case.lane == "development")
        holdout = tuple(case.case_id for case in self.cases if case.lane == "blind_holdout")
        if development != self.development_case_ids or holdout != (self.blind_holdout_case_ids):
            raise ValueError("owner-quality lane lists differ from case records")
        if len(development) != 30 or len(holdout) != 30:
            raise ValueError("owner-quality split must be exactly 30/30")
        if set(development) & set(holdout) or set(development) | set(holdout) != set(case_ids):
            raise ValueError("owner-quality development and holdout are not complements")
        development_rows = tuple(case for case in self.cases if case.lane == "development")
        holdout_rows = tuple(case for case in self.cases if case.lane == "blind_holdout")
        if self.development_distribution != _distribution(development_rows):
            raise ValueError("owner-quality development distribution is invalid")
        if self.blind_holdout_distribution != _distribution(holdout_rows):
            raise ValueError("owner-quality holdout distribution is invalid")
        if self.policy_sha256 != OWNER_QUALITY_CANARY_POLICY_SHA256:
            raise ValueError("owner-quality policy digest differs from tracked policy")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("owner-quality canary seal does not match its contents")
        return self


def _seed_sha256(
    *,
    suite_manifest_seal_sha256: str,
    candidate_manifest_sha256: str,
    policy_version: str,
) -> str:
    material = "\0".join(
        (
            "legalbot.owner-quality-canary-seed.v1",
            suite_manifest_seal_sha256,
            candidate_manifest_sha256,
            policy_version,
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _rank_sha256(*, seed_sha256: str, case_id: str, stratum: tuple[str, str, str]) -> str:
    return hashlib.sha256("\0".join((seed_sha256, case_id, *stratum)).encode("utf-8")).hexdigest()


def _marginal_counts(
    allocation: Mapping[tuple[str, str, str], int],
) -> Counter[tuple[str, str]]:
    output: Counter[tuple[str, str]] = Counter()
    for (route, task, band), count in allocation.items():
        output[("route", route)] += count
        output[("task", task)] += count
        output[("word_band", band)] += count
    return output


def _allocation_for_strata(
    *,
    groups: Mapping[tuple[str, str, str], Sequence[str]],
    seed_sha256: str,
) -> dict[tuple[str, str, str], int]:
    keys = tuple(sorted(groups))
    base = {key: len(groups[key]) // 2 for key in keys}
    odd = tuple(key for key in keys if len(groups[key]) % 2)
    total_margins = _marginal_counts({key: len(groups[key]) for key in keys})
    best: tuple[tuple[int, int, int], dict[tuple[str, str, str], int]] | None = None
    for bits in itertools.product((0, 1), repeat=len(odd)):
        allocation = dict(base)
        for key, bit in zip(odd, bits, strict=True):
            allocation[key] += bit
        if sum(allocation.values()) != 30:
            continue
        development_margins = _marginal_counts(allocation)
        deviations = tuple(
            abs(2 * development_margins[key] - total)
            for key, total in sorted(total_margins.items())
        )
        signature = ";".join(f"{'|'.join(key)}={allocation[key]}" for key in keys)
        tie_break = int(
            hashlib.sha256(f"{seed_sha256}\0{signature}".encode()).hexdigest(),
            16,
        )
        score = (max(deviations, default=0), sum(deviations), tie_break)
        if best is None or score < best[0]:
            best = (score, allocation)
    if best is None:
        raise ValueError("owner-quality policy could not allocate an exact 30/30 split")
    return best[1]


def _subject_penalty(
    *,
    development: set[str],
    subject_by_id: Mapping[str, str],
) -> int:
    groups: dict[str, list[str]] = defaultdict(list)
    for case_id, subject_sha in subject_by_id.items():
        groups[subject_sha].append(case_id)
    return sum(
        abs(2 * sum(case_id in development for case_id in case_ids) - len(case_ids))
        for case_ids in groups.values()
        if len(case_ids) > 1
    )


def _improve_subject_balance(
    *,
    development: set[str],
    case_strata: Mapping[str, tuple[str, str, str]],
    subject_by_id: Mapping[str, str],
    seed_sha256: str,
) -> set[str]:
    """Use same-stratum swaps so route/task/band margins never change."""

    output = set(development)
    while True:
        current = _subject_penalty(development=output, subject_by_id=subject_by_id)
        candidates: list[tuple[int, str, str, str]] = []
        for left in sorted(output):
            for right in sorted(set(case_strata) - output):
                if case_strata[left] != case_strata[right]:
                    continue
                swapped = (output - {left}) | {right}
                penalty = _subject_penalty(development=swapped, subject_by_id=subject_by_id)
                if penalty >= current:
                    continue
                tie = hashlib.sha256(
                    f"{seed_sha256}\0subject-swap\0{left}\0{right}".encode()
                ).hexdigest()
                candidates.append((penalty, tie, left, right))
        if not candidates:
            return output
        _penalty, _tie, left, right = min(candidates)
        output.remove(left)
        output.add(right)


def freeze_owner_quality_canary_manifest(
    *,
    bundle: LiveEvaluationBundle,
    candidate_build_id: str,
    candidate_manifest_sha256: str,
    qualification: All60CaseQualification,
) -> OwnerQualityCanaryManifest:
    """Derive the non-redrawable split from exact suite/candidate/policy identities."""

    if not _SAFE_ID.fullmatch(candidate_build_id):
        raise ValueError("owner-quality candidate build ID is invalid")
    if not _SHA256.fullmatch(candidate_manifest_sha256):
        raise ValueError("owner-quality candidate manifest digest is invalid")
    registry_ids = tuple(case.case_id for case in bundle.registry.cases)
    if (
        len(registry_ids) != 60
        or qualification.suite_id != bundle.manifest.suite_id
        or qualification.suite_manifest_seal_sha256 != bundle.manifest.seal_sha256
        or qualification.suite_registry_canonical_sha256 != bundle.registry.canonical_sha256
        or qualification.candidate_build_id != candidate_build_id
        or qualification.case_ids != registry_ids
    ):
        raise ValueError("all-60 qualification is not bound to this suite and candidate")

    seed = _seed_sha256(
        suite_manifest_seal_sha256=bundle.manifest.seal_sha256,
        candidate_manifest_sha256=candidate_manifest_sha256,
        policy_version=OWNER_QUALITY_CANARY_POLICY_VERSION,
    )
    groups: dict[tuple[str, str, str], list[str]] = defaultdict(list)
    strata: dict[str, tuple[str, str, str]] = {}
    subjects: dict[str, str] = {}
    ranks: dict[str, str] = {}
    by_id = {case.case_id: case for case in bundle.registry.cases}
    for case in bundle.registry.cases:
        stratum = (
            case.expected_research_route,
            case.task_type,
            _word_band(case.word_target),
        )
        strata[case.case_id] = stratum
        subjects[case.case_id] = _subject_sha256(case.subject)
        ranks[case.case_id] = _rank_sha256(seed_sha256=seed, case_id=case.case_id, stratum=stratum)
        groups[stratum].append(case.case_id)

    allocation = _allocation_for_strata(groups=groups, seed_sha256=seed)
    development: set[str] = set()
    for key in sorted(groups):
        ranked = sorted(groups[key], key=lambda case_id: (ranks[case_id], case_id))
        development.update(ranked[: allocation[key]])
    development = _improve_subject_balance(
        development=development,
        case_strata=strata,
        subject_by_id=subjects,
        seed_sha256=seed,
    )
    if len(development) != 30:
        raise AssertionError("owner-quality allocator did not retain exactly 30 cases")

    rows: list[OwnerQualityCanaryCase] = []
    for case_id in registry_ids:
        case = by_id[case_id]
        rows.append(
            OwnerQualityCanaryCase(
                case_id=case.case_id,
                ordinal=case.ordinal,
                lane="development" if case_id in development else "blind_holdout",
                task_type=case.task_type,
                expected_research_route=case.expected_research_route,
                word_band=_word_band(case.word_target),
                subject_sha256=subjects[case_id],
                selection_rank_sha256=ranks[case_id],
            )
        )
    development_rows = tuple(item for item in rows if item.lane == "development")
    holdout_rows = tuple(item for item in rows if item.lane == "blind_holdout")
    material: dict[str, Any] = {
        "schema": OWNER_QUALITY_CANARY_SCHEMA,
        "manifest_id": f"owner-quality-canary-{seed[:20]}",
        "suite_id": bundle.manifest.suite_id,
        "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
        "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
        "candidate_build_id": candidate_build_id,
        "candidate_manifest_sha256": candidate_manifest_sha256,
        "qualification_seal_sha256": qualification.seal_sha256,
        "policy_version": OWNER_QUALITY_CANARY_POLICY_VERSION,
        "policy_sha256": OWNER_QUALITY_CANARY_POLICY_SHA256,
        "seed_sha256": seed,
        "purpose": "evaluation_only",
        "eligible_for_training": False,
        "training_export_allowed": False,
        "local_only": True,
        "online_research_allowed": False,
        "immutable": True,
        "case_count": 60,
        "development_case_count": 30,
        "blind_holdout_case_count": 30,
        "development_case_ids": [item.case_id for item in development_rows],
        "blind_holdout_case_ids": [item.case_id for item in holdout_rows],
        "development_distribution": _distribution(development_rows),
        "blind_holdout_distribution": _distribution(holdout_rows),
        "cases": [item.model_dump(mode="json") for item in rows],
    }
    assert_safe_evaluation_payload(material)
    material["seal_sha256"] = sealed_sha256(material)
    return OwnerQualityCanaryManifest.model_validate(material)


def owner_quality_manifest_bytes(manifest: OwnerQualityCanaryManifest) -> bytes:
    value = manifest.model_dump(mode="json", by_alias=True)
    assert_safe_evaluation_payload(value)
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def verify_owner_quality_canary_manifest(
    manifest: OwnerQualityCanaryManifest,
    *,
    bundle: LiveEvaluationBundle,
    candidate: SealedCandidateIdentity,
    qualification: ExactAll60Qualification,
) -> OwnerQualityCanaryManifest:
    """Recompute the full split and require exact canonical equality.

    A valid self-seal is not enough: every rank, stratum, allocation, lane and
    distribution is re-derived from authoritative suite, candidate and exact
    585-issue qualification identities.
    """

    from .all60_qualification import ExactAll60Qualification

    if not isinstance(qualification, ExactAll60Qualification):
        raise ValueError("owner-quality split requires the exact all-60 qualification")
    if (
        candidate.status not in {"candidate", "active"}
        or qualification.candidate_build_id != candidate.build_id
        or qualification.candidate_manifest_sha256 != candidate.candidate_manifest_sha256
        or qualification.candidate_seal_sha256 != candidate.candidate_seal_sha256
        or qualification.candidate_source_manifest_sha256 != candidate.source_manifest_sha256
    ):
        raise ValueError("owner-quality split candidate differs from authoritative qualification")
    expected = freeze_owner_quality_canary_manifest(
        bundle=bundle,
        candidate_build_id=candidate.build_id,
        candidate_manifest_sha256=candidate.candidate_manifest_sha256,
        qualification=qualification,
    )
    if manifest != expected or owner_quality_manifest_bytes(
        manifest
    ) != owner_quality_manifest_bytes(expected):
        raise ValueError("owner-quality canary manifest is a redraw or derivation mismatch")
    return expected


def load_verified_owner_quality_canary_manifest(
    path: Path,
    *,
    bundle: LiveEvaluationBundle,
    candidate: SealedCandidateIdentity,
    qualification_path: Path,
) -> OwnerQualityCanaryManifest:
    """Load only the canonical split derived from authoritative local bytes."""

    if path.is_symlink() or not path.is_file():
        raise ValueError("owner-quality canary manifest is missing")
    metadata = path.stat()
    if (
        stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size < 1
        or metadata.st_size > _MAX_OWNER_QUALITY_MANIFEST_BYTES
    ):
        raise ValueError("owner-quality canary manifest is not a private bounded file")
    qualification = load_all60_qualification(qualification_path)
    from .all60_qualification import ExactAll60Qualification

    if not isinstance(qualification, ExactAll60Qualification):
        raise ValueError("owner-quality split requires the exact all-60 qualification")
    raw = path.read_bytes()
    try:
        manifest = OwnerQualityCanaryManifest.model_validate_json(raw)
    except Exception as exc:
        raise ValueError("owner-quality canary manifest contract is invalid") from exc
    verified = verify_owner_quality_canary_manifest(
        manifest,
        bundle=bundle,
        candidate=candidate,
        qualification=qualification,
    )
    if raw != owner_quality_manifest_bytes(verified):
        raise ValueError("owner-quality canary manifest bytes are not canonical")
    return verified


def write_owner_quality_canary_manifest(path: Path, manifest: OwnerQualityCanaryManifest) -> Path:
    """Create the manifest once; identical bytes are idempotent, redraw is refused."""

    payload = owner_quality_manifest_bytes(manifest)
    if path.exists():
        if not path.is_file() or path.read_bytes() != payload:
            raise FileExistsError("owner-quality canary manifest is immutable")
        return path
    _private_directory(path.parent)
    _exclusive_write(path, payload)
    path.chmod(0o600)
    return path
