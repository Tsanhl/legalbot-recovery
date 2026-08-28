"""Sealed proof that a pinned candidate was searched before gap research.

The artifact is deliberately prose-free.  It records only opaque references,
digests and deterministic qualification dispositions from an offline retrieval
attempt.  Loading the artifact re-hashes both the file and its self-seal; a
caller-supplied digest alone is never evidence that the candidate was checked.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from ..config import Settings
from ..db import Database
from ..privacy import scrub_pii

RETRIEVAL_ATTEMPT_SCHEMA = "legalbot.research.candidate-retrieval-attempt.v2"
RETRIEVAL_ATTEMPT_TOOLCHAIN_VERSION = "legalbot.research.pinned-retrieval-executor.v1"
RETRIEVAL_ATTEMPT_TOP_K = 20
RETRIEVAL_ATTEMPT_POLICY = {
    "schema": "legalbot.research.gap-retrieval-policy.v1",
    "offline_candidate_only": True,
    "authority_lane_only": True,
    "jurisdiction_filter_required": True,
    "currentness_filter_required": True,
    "top_k": RETRIEVAL_ATTEMPT_TOP_K,
}
_ARTIFACT_DIRECTORY = Path("research") / "candidate-retrieval-attempts"
_MAX_ARTIFACT_BYTES = 256 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
_OPAQUE_CASE_REFERENCE = re.compile(r"^case:[0-9a-f]{64}$")
_OPAQUE_ISSUE_REFERENCE = re.compile(r"^issue:[0-9a-f]{64}$")


class HitQualificationDisposition(StrEnum):
    """Closed vocabulary used by the evidence qualification pass."""

    QUALIFYING_EXISTING_AUTHORITY = "qualifying_existing_authority"
    NO_MATERIAL_SUPPORT = "no_material_support"
    WRONG_JURISDICTION = "wrong_jurisdiction"
    NOT_CURRENT_AS_OF_DATE = "not_current_as_of_date"
    NON_AUTHORITY_LANE = "non_authority_lane"
    FILTER_REJECTED = "filter_rejected"


class RankedCandidateHit(BaseModel):
    """One privacy-safe ranked hit and its evidence qualification result."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rank: int = Field(ge=1, le=100)
    chunk_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    source_version_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    locator_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    hit_ref: str = Field(pattern=r"^hit:[0-9a-f]{64}$")
    hit_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_span_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_membership_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    qualification_disposition: HitQualificationDisposition


class CandidateRetrievalAttemptArtifact(BaseModel):
    """Persisted create-only result of one candidate-pinned offline search."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_name: Literal["legalbot.research.candidate-retrieval-attempt.v2"] = Field(alias="schema")
    created_at: datetime
    create_only: Literal[True]
    offline_candidate_only: Literal[True]
    network_used: Literal[False]
    feeds_current_answer: Literal[False]
    candidate_build_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    candidate_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    case_ref: str = Field(pattern=r"^case:[0-9a-f]{64}$")
    issue_ref: str = Field(pattern=r"^issue:[0-9a-f]{64}$")
    subject: str = Field(pattern=r"^[a-z][a-z0-9 _-]{0,79}$")
    jurisdiction: str = Field(min_length=1, max_length=80)
    as_of_date: date
    query_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    proposition_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    query_contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    retrieval_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    retrieval_toolchain_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    executor_invocation_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    candidate_rows_examined: int = Field(ge=1)
    retrieval_execution_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ranked_hits: tuple[RankedCandidateHit, ...] = Field(max_length=100)
    qualification_result: Literal["no_qualifying_existing_hit", "qualifying_existing_hit"]
    qualifying_hit_count: int = Field(ge=0, le=100)
    no_qualifying_existing_hit: bool
    qualification_proof_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class CandidateBuildBinding:
    """Exact sealed candidate identity required by research admission."""

    candidate_build_id: str
    candidate_seal_sha256: str
    source_manifest_sha256: str


@dataclass(frozen=True, slots=True)
class RetrievalAttemptBinding:
    """Expected gap identity used when revalidating a sealed attempt."""

    candidate_build_id: str
    candidate_seal_sha256: str
    source_manifest_sha256: str
    case_ref: str
    issue_ref: str
    subject: str
    jurisdiction: str
    as_of_date: date
    proposition_sha256: str | None = None
    query_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class RetrievalAttemptArtifactRef:
    path: Path
    artifact_sha256: str
    seal_sha256: str


@dataclass(frozen=True, slots=True)
class CandidateRetrievalExecutorHit:
    """Minimal hit identity returned by the pinned retrieval executor.

    Durable span and membership identities are deliberately *not* accepted
    from the executor. They are recomputed from the sealed candidate.
    """

    chunk_id: str
    qualification_disposition: HitQualificationDisposition


@dataclass(frozen=True, slots=True)
class CandidateRetrievalExecutorResult:
    """Completed executor envelope, before local candidate reconciliation."""

    invocation_id: str
    candidate_build_id: str
    candidate_rows_examined: int
    ranked_hits: tuple[CandidateRetrievalExecutorHit, ...]
    offline_candidate_only: bool = True
    network_used: bool = False


@dataclass(frozen=True, slots=True)
class PinnedCandidateRetrievalRequest:
    """Transient exact request delivered to the local retrieval executor."""

    candidate_build_id: str
    canonical_query: str
    query_sha256: str
    proposition_sha256: str
    subject: str
    jurisdiction: str
    as_of_date: date
    top_k: int
    retrieval_policy_sha256: str
    retrieval_toolchain_sha256: str


class CandidateRetrievalExecutor(Protocol):
    def __call__(
        self, request: PinnedCandidateRetrievalRequest
    ) -> CandidateRetrievalExecutorResult: ...


CandidateBuildBindingLoader = Callable[[Settings, Database, str], CandidateBuildBinding]


def load_sealed_candidate_build_binding(
    settings: Settings, database: Database, candidate_build_id: str
) -> CandidateBuildBinding:
    """Verify the full on-disk candidate seal without reading ``ACTIVE``."""

    # Import lazily so the research model layer does not initialise evaluation
    # tooling merely by being imported.
    from ..evaluation.sealed_candidate import load_sealed_candidate_identity

    identity = load_sealed_candidate_identity(
        settings=settings,
        database=database,
        candidate_build_id=candidate_build_id,
    )
    return CandidateBuildBinding(
        candidate_build_id=identity.build_id,
        candidate_seal_sha256=identity.candidate_seal_sha256,
        source_manifest_sha256=identity.source_manifest_sha256,
    )


def opaque_gap_reference(kind: Literal["case", "issue"], value: str) -> str:
    """Return the same one-way reference used by durable gap records."""

    if not value or not _SAFE_REFERENCE.fullmatch(value):
        raise ValueError("gap reference is unsafe")
    return f"{kind}:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sealed_sha256(value: Mapping[str, Any]) -> str:
    material = {key: item for key, item in value.items() if key != "seal_sha256"}
    return hashlib.sha256(_canonical_json(material)).hexdigest()


def retrieval_attempt_policy_sha256() -> str:
    """Identity of the fixed, tracked gap-retrieval policy."""

    return hashlib.sha256(_canonical_json(RETRIEVAL_ATTEMPT_POLICY)).hexdigest()


def retrieval_attempt_toolchain_sha256() -> str:
    """Identity of the executor/reconciliation contract used by admission."""

    return hashlib.sha256(
        _canonical_json(
            {
                "schema": RETRIEVAL_ATTEMPT_TOOLCHAIN_VERSION,
                "artifact_schema": RETRIEVAL_ATTEMPT_SCHEMA,
                "policy_sha256": retrieval_attempt_policy_sha256(),
                "candidate_membership": "sealed-lance-exact-row-v1",
                "execution_digest": "locally-derived-only-v1",
                "empty_result_allowed": False,
            }
        )
    ).hexdigest()


def _query_contract_sha256(*, binding: RetrievalAttemptBinding, query_sha256: str) -> str:
    return hashlib.sha256(
        _canonical_json(
            {
                "schema": "legalbot.research.canonical-query-contract.v1",
                "candidate_build_id": binding.candidate_build_id,
                "case_ref": binding.case_ref,
                "issue_ref": binding.issue_ref,
                "subject": binding.subject,
                "jurisdiction": binding.jurisdiction,
                "as_of_date": binding.as_of_date.isoformat(),
                "query_sha256": query_sha256,
                "proposition_sha256": binding.proposition_sha256,
            }
        )
    ).hexdigest()


def _qualification_proof_sha256(value: Mapping[str, Any]) -> str:
    fields = (
        "candidate_build_id",
        "candidate_seal_sha256",
        "source_manifest_sha256",
        "case_ref",
        "issue_ref",
        "subject",
        "jurisdiction",
        "as_of_date",
        "query_sha256",
        "proposition_sha256",
        "query_contract_sha256",
        "retrieval_policy_sha256",
        "retrieval_toolchain_sha256",
        "executor_invocation_id",
        "candidate_rows_examined",
        "retrieval_execution_sha256",
        "ranked_hits",
        "qualification_result",
        "qualifying_hit_count",
        "no_qualifying_existing_hit",
    )
    return hashlib.sha256(_canonical_json({field: value[field] for field in fields})).hexdigest()


def _validate_derived_result(artifact: CandidateRetrievalAttemptArtifact) -> None:
    hits = artifact.ranked_hits
    if not hits:
        raise ValueError("retrieval-attempt cannot use an empty caller-authored result")
    if tuple(hit.rank for hit in hits) != tuple(range(1, len(hits) + 1)):
        raise ValueError("retrieval-attempt hit ranks are not contiguous")
    hit_refs = tuple(hit.hit_ref for hit in hits)
    if len(set(hit_refs)) != len(hit_refs):
        raise ValueError("retrieval-attempt hit identities are duplicated")
    chunk_ids = tuple(hit.chunk_id for hit in hits)
    if len(set(chunk_ids)) != len(chunk_ids):
        raise ValueError("retrieval-attempt candidate chunks are duplicated")
    if artifact.candidate_rows_examined < len(hits):
        raise ValueError("retrieval-attempt examined-row count is inconsistent")
    if artifact.retrieval_policy_sha256 != retrieval_attempt_policy_sha256():
        raise ValueError("retrieval-attempt policy differs from tracked bytes")
    if artifact.retrieval_toolchain_sha256 != retrieval_attempt_toolchain_sha256():
        raise ValueError("retrieval-attempt toolchain differs from tracked bytes")
    qualifying = sum(
        hit.qualification_disposition is HitQualificationDisposition.QUALIFYING_EXISTING_AUTHORITY
        for hit in hits
    )
    no_hit = qualifying == 0
    expected_result = "no_qualifying_existing_hit" if no_hit else "qualifying_existing_hit"
    if (
        artifact.qualifying_hit_count != qualifying
        or artifact.no_qualifying_existing_hit is not no_hit
        or artifact.qualification_result != expected_result
    ):
        raise ValueError("retrieval-attempt qualification result is inconsistent")
    payload = artifact.model_dump(mode="json", by_alias=True)
    if artifact.qualification_proof_sha256 != _qualification_proof_sha256(payload):
        raise ValueError("retrieval-attempt qualification proof mismatch")
    if artifact.seal_sha256 != _sealed_sha256(payload):
        raise ValueError("retrieval-attempt self-seal mismatch")


def _artifact_root(settings: Settings, *, create: bool) -> Path:
    evaluation_root = settings.evaluation_dir
    research_root = evaluation_root / "research"
    root = evaluation_root / _ARTIFACT_DIRECTORY
    if create:
        evaluation_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        research_root.mkdir(exist_ok=True, mode=0o700)
        root.mkdir(exist_ok=True, mode=0o700)
    for private in (evaluation_root, research_root, root):
        try:
            private_stat = private.lstat()
        except OSError as exc:
            raise ValueError("retrieval-attempt artifact root is missing") from exc
        if not stat.S_ISDIR(private_stat.st_mode) or private.is_symlink():
            raise ValueError("retrieval-attempt artifact root is unsafe")
        if create:
            private.chmod(0o700)
        elif stat.S_IMODE(private_stat.st_mode) != 0o700:
            raise ValueError("retrieval-attempt artifact root is not private")
    return root


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _tree_sha256(root: Path) -> str:
    if not root.is_dir() or root.is_symlink():
        raise ValueError("sealed candidate Lance tree is missing")
    members = sorted(
        (path for path in root.rglob("*") if path.is_file()),
        key=lambda path: path.as_posix(),
    )
    if not members or any(path.is_symlink() for path in root.rglob("*")):
        raise ValueError("sealed candidate Lance tree is unsafe")
    digest = hashlib.sha256()
    for member in members:
        relative = member.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(bytes.fromhex(_file_sha256(member)))
    return digest.hexdigest()


def _json_object(path: Path, *, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"sealed candidate {label} is missing")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"sealed candidate {label} is invalid") from exc
    if not isinstance(value, dict):
        raise ValueError(f"sealed candidate {label} is invalid")
    return value


def _verified_candidate_root(settings: Settings, binding: RetrievalAttemptBinding) -> Path:
    root = settings.index_dir / "builds" / binding.candidate_build_id
    if root.is_symlink() or not root.is_dir():
        raise ValueError("sealed candidate build root is missing")
    manifest_path = root / "manifest.json"
    seal_path = root / "seal.json"
    manifest = _json_object(manifest_path, label="manifest")
    seal = _json_object(seal_path, label="seal")
    manifest_sha256 = _file_sha256(manifest_path)
    lance_sha256 = _tree_sha256(root / "lance")
    if (
        _file_sha256(seal_path) != binding.candidate_seal_sha256
        or str(manifest.get("build_id") or "") != binding.candidate_build_id
        or str(manifest.get("source_manifest_sha256") or "") != binding.source_manifest_sha256
        or str(seal.get("build_id") or "") != binding.candidate_build_id
        or str(seal.get("manifest_sha256") or "") != manifest_sha256
        or str(seal.get("lance_tree_sha256") or "") != lance_sha256
    ):
        raise ValueError("sealed candidate retrieval identity does not match durable bytes")
    return root


def _candidate_rows(
    settings: Settings,
    *,
    binding: RetrievalAttemptBinding,
    chunk_ids: Sequence[str],
) -> dict[str, dict[str, Any]]:
    root = _verified_candidate_root(settings, binding)
    authority = root / "lance" / "authority"
    if not authority.is_dir():
        raise ValueError("sealed candidate authority lane is missing")
    try:
        import lancedb  # type: ignore[import-untyped]

        table = lancedb.connect(str(authority)).open_table("chunks")
    except Exception as exc:
        raise ValueError("sealed candidate authority table is unavailable") from exc
    output: dict[str, dict[str, Any]] = {}
    columns = [
        "chunk_id",
        "source_version_id",
        "content_sha256",
        "locator",
        "catalog_lane",
        "catalog_jurisdiction",
        "identity_verified",
        "currentness_verified",
    ]
    for chunk_id in chunk_ids:
        if not _SAFE_REFERENCE.fullmatch(chunk_id):
            raise ValueError("retrieval executor returned an unsafe candidate chunk identity")
        escaped = chunk_id.replace("'", "''")
        try:
            rows = (
                table.search().where(f"chunk_id = '{escaped}'").select(columns).limit(2).to_list()
            )
        except Exception as exc:
            raise ValueError("sealed candidate membership lookup failed") from exc
        if len(rows) != 1:
            raise ValueError("retrieval executor hit is not an exact sealed-candidate member")
        row = dict(rows[0])
        if (
            str(row.get("chunk_id") or "") != chunk_id
            or str(row.get("catalog_lane") or "")
            not in {"primary_authority", "official_secondary", "scholarship"}
            or row.get("identity_verified") is not True
        ):
            raise ValueError("retrieval executor hit failed candidate authority membership")
        output[chunk_id] = row
    return output


def _ranked_hit_from_candidate(
    *,
    binding: RetrievalAttemptBinding,
    rank: int,
    executor_hit: CandidateRetrievalExecutorHit,
    candidate_row: Mapping[str, Any],
) -> RankedCandidateHit:
    source_version_id = str(candidate_row.get("source_version_id") or "")
    content_sha256 = str(candidate_row.get("content_sha256") or "")
    locator = str(candidate_row.get("locator") or "")
    if (
        not _SAFE_REFERENCE.fullmatch(source_version_id)
        or not _SHA256.fullmatch(content_sha256)
        or not locator
    ):
        raise ValueError("sealed candidate hit has an incomplete evidence identity")
    locator_sha256 = hashlib.sha256(locator.encode("utf-8")).hexdigest()
    membership_material = {
        "schema": "legalbot.research.candidate-hit-membership.v1",
        "candidate_build_id": binding.candidate_build_id,
        "candidate_seal_sha256": binding.candidate_seal_sha256,
        "chunk_id": executor_hit.chunk_id,
        "source_version_id": source_version_id,
        "content_sha256": content_sha256,
        "locator_sha256": locator_sha256,
        "catalog_lane": candidate_row.get("catalog_lane"),
        "catalog_jurisdiction": candidate_row.get("catalog_jurisdiction"),
        "identity_verified": candidate_row.get("identity_verified"),
        "currentness_verified": candidate_row.get("currentness_verified"),
    }
    membership_sha256 = hashlib.sha256(_canonical_json(membership_material)).hexdigest()
    evidence_sha256 = hashlib.sha256(
        _canonical_json(
            {
                "schema": "legalbot.research.candidate-evidence-span.v1",
                "chunk_id": executor_hit.chunk_id,
                "source_version_id": source_version_id,
                "content_sha256": content_sha256,
                "locator_sha256": locator_sha256,
            }
        )
    ).hexdigest()
    hit_ref = (
        "hit:"
        + hashlib.sha256(
            f"{binding.candidate_seal_sha256}\0{executor_hit.chunk_id}".encode()
        ).hexdigest()
    )
    hit_material = {
        "schema": "legalbot.research.ranked-candidate-hit.v1",
        "rank": rank,
        "hit_ref": hit_ref,
        "candidate_membership_sha256": membership_sha256,
        "evidence_span_sha256": evidence_sha256,
        "qualification_disposition": executor_hit.qualification_disposition.value,
    }
    return RankedCandidateHit(
        rank=rank,
        chunk_id=executor_hit.chunk_id,
        source_version_id=source_version_id,
        content_sha256=content_sha256,
        locator_sha256=locator_sha256,
        hit_ref=hit_ref,
        hit_sha256=hashlib.sha256(_canonical_json(hit_material)).hexdigest(),
        evidence_span_sha256=evidence_sha256,
        candidate_membership_sha256=membership_sha256,
        qualification_disposition=executor_hit.qualification_disposition,
    )


def execute_candidate_retrieval_attempt(
    *,
    settings: Settings,
    binding: RetrievalAttemptBinding,
    canonical_query: str,
    executor: CandidateRetrievalExecutor,
    created_at: datetime | None = None,
) -> RetrievalAttemptArtifactRef:
    """Execute, reconcile and seal one pinned offline candidate search.

    Callers cannot supply ranked-hit hashes or an execution digest. The local
    code invokes the executor, reconciles every returned hit to the sealed
    Lance authority lane, then derives all durable identities itself.
    """

    proposition_sha256 = binding.proposition_sha256 or ""
    normalised_query = " ".join(canonical_query.split())
    query_sha256 = hashlib.sha256(normalised_query.encode("utf-8")).hexdigest()
    for digest in (
        binding.candidate_seal_sha256,
        binding.source_manifest_sha256,
        proposition_sha256,
        query_sha256,
    ):
        if not _SHA256.fullmatch(digest):
            raise ValueError("retrieval-attempt digest is invalid")
    if binding.query_sha256 is None or binding.query_sha256 != query_sha256:
        raise ValueError("canonical retrieval query differs from its expected digest")
    if (
        not normalised_query
        or len(normalised_query) > 2_000
        or scrub_pii(normalised_query) != normalised_query
    ):
        raise ValueError("canonical retrieval query is unsafe")
    if not _OPAQUE_CASE_REFERENCE.fullmatch(binding.case_ref) or not (
        _OPAQUE_ISSUE_REFERENCE.fullmatch(binding.issue_ref)
    ):
        raise ValueError("retrieval-attempt gap reference is not opaque")
    if (
        scrub_pii(binding.subject) != binding.subject
        or scrub_pii(binding.jurisdiction) != binding.jurisdiction
    ):
        raise ValueError("retrieval-attempt safe taxonomy contains private data")
    policy_sha256 = retrieval_attempt_policy_sha256()
    toolchain_sha256 = retrieval_attempt_toolchain_sha256()
    request = PinnedCandidateRetrievalRequest(
        candidate_build_id=binding.candidate_build_id,
        canonical_query=normalised_query,
        query_sha256=query_sha256,
        proposition_sha256=proposition_sha256,
        subject=binding.subject,
        jurisdiction=binding.jurisdiction,
        as_of_date=binding.as_of_date,
        top_k=RETRIEVAL_ATTEMPT_TOP_K,
        retrieval_policy_sha256=policy_sha256,
        retrieval_toolchain_sha256=toolchain_sha256,
    )
    result = executor(request)
    if (
        not isinstance(result, CandidateRetrievalExecutorResult)
        or result.candidate_build_id != binding.candidate_build_id
        or not _SAFE_REFERENCE.fullmatch(result.invocation_id)
        or result.offline_candidate_only is not True
        or result.network_used is not False
        or not result.ranked_hits
        or len(result.ranked_hits) > request.top_k
        or result.candidate_rows_examined < len(result.ranked_hits)
        or len({hit.chunk_id for hit in result.ranked_hits}) != len(result.ranked_hits)
    ):
        raise ValueError("pinned retrieval executor returned an invalid completed result")
    candidate_rows = _candidate_rows(
        settings,
        binding=binding,
        chunk_ids=tuple(hit.chunk_id for hit in result.ranked_hits),
    )
    ranked_hits = tuple(
        _ranked_hit_from_candidate(
            binding=binding,
            rank=rank,
            executor_hit=hit,
            candidate_row=candidate_rows[hit.chunk_id],
        )
        for rank, hit in enumerate(result.ranked_hits, start=1)
    )
    query_contract_sha256 = _query_contract_sha256(binding=binding, query_sha256=query_sha256)
    execution_material = {
        "schema": "legalbot.research.pinned-retrieval-execution.v1",
        "query_contract_sha256": query_contract_sha256,
        "retrieval_policy_sha256": policy_sha256,
        "retrieval_toolchain_sha256": toolchain_sha256,
        "executor_invocation_id": result.invocation_id,
        "candidate_rows_examined": result.candidate_rows_examined,
        "ranked_hits": [hit.model_dump(mode="json") for hit in ranked_hits],
    }
    retrieval_execution_sha256 = hashlib.sha256(_canonical_json(execution_material)).hexdigest()
    qualifying = sum(
        hit.qualification_disposition is HitQualificationDisposition.QUALIFYING_EXISTING_AUTHORITY
        for hit in ranked_hits
    )
    no_hit = qualifying == 0
    resolved_created_at = (created_at or datetime.now(UTC)).astimezone(UTC)
    payload: dict[str, Any] = {
        "schema": RETRIEVAL_ATTEMPT_SCHEMA,
        "created_at": resolved_created_at.isoformat().replace("+00:00", "Z"),
        "create_only": True,
        "offline_candidate_only": True,
        "network_used": False,
        "feeds_current_answer": False,
        "candidate_build_id": binding.candidate_build_id,
        "candidate_seal_sha256": binding.candidate_seal_sha256,
        "source_manifest_sha256": binding.source_manifest_sha256,
        "case_ref": binding.case_ref,
        "issue_ref": binding.issue_ref,
        "subject": binding.subject,
        "jurisdiction": binding.jurisdiction,
        "as_of_date": binding.as_of_date.isoformat(),
        "query_sha256": query_sha256,
        "proposition_sha256": proposition_sha256,
        "query_contract_sha256": query_contract_sha256,
        "retrieval_policy_sha256": policy_sha256,
        "retrieval_toolchain_sha256": toolchain_sha256,
        "executor_invocation_id": result.invocation_id,
        "candidate_rows_examined": result.candidate_rows_examined,
        "retrieval_execution_sha256": retrieval_execution_sha256,
        "ranked_hits": [hit.model_dump(mode="json") for hit in ranked_hits],
        "qualification_result": (
            "no_qualifying_existing_hit" if no_hit else "qualifying_existing_hit"
        ),
        "qualifying_hit_count": qualifying,
        "no_qualifying_existing_hit": no_hit,
    }
    payload["qualification_proof_sha256"] = _qualification_proof_sha256(payload)
    payload["seal_sha256"] = _sealed_sha256(payload)
    artifact = CandidateRetrievalAttemptArtifact.model_validate(payload)
    _validate_derived_result(artifact)
    encoded = (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    artifact_sha256 = hashlib.sha256(encoded).hexdigest()
    root = _artifact_root(settings, create=True)
    path = root / f"{artifact_sha256}.json"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    path.chmod(0o600)
    directory = os.open(root, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return RetrievalAttemptArtifactRef(
        path=path,
        artifact_sha256=artifact_sha256,
        seal_sha256=artifact.seal_sha256,
    )


def load_verified_candidate_retrieval_attempt(
    *,
    settings: Settings,
    artifact_sha256: str,
    expected: RetrievalAttemptBinding,
    require_no_qualifying_hit: bool = True,
) -> CandidateRetrievalAttemptArtifact:
    """Re-hash and revalidate an exact candidate retrieval result."""

    if not _SHA256.fullmatch(artifact_sha256):
        raise ValueError("retrieval-attempt artifact digest is invalid")
    root = _artifact_root(settings, create=False)
    try:
        root_stat = root.lstat()
    except OSError as exc:
        raise ValueError("verified retrieval-attempt artifact is missing") from exc
    if not stat.S_ISDIR(root_stat.st_mode) or stat.S_IMODE(root_stat.st_mode) != 0o700:
        raise ValueError("retrieval-attempt artifact directory is not private")
    path = root / f"{artifact_sha256}.json"
    try:
        path_stat = path.lstat()
        if (
            not stat.S_ISREG(path_stat.st_mode)
            or stat.S_IMODE(path_stat.st_mode) != 0o600
            or path_stat.st_size > _MAX_ARTIFACT_BYTES
        ):
            raise ValueError("retrieval-attempt artifact is not a private regular file")
        raw = path.read_bytes()
    except OSError as exc:
        raise ValueError("verified retrieval-attempt artifact is missing") from exc
    if hashlib.sha256(raw).hexdigest() != artifact_sha256:
        raise ValueError("retrieval-attempt artifact hash mismatch")
    try:
        artifact = CandidateRetrievalAttemptArtifact.model_validate_json(raw)
    except Exception as exc:
        raise ValueError("retrieval-attempt artifact contract is invalid") from exc
    _validate_derived_result(artifact)
    exact: dict[str, object] = {
        "candidate_build_id": expected.candidate_build_id,
        "candidate_seal_sha256": expected.candidate_seal_sha256,
        "source_manifest_sha256": expected.source_manifest_sha256,
        "case_ref": expected.case_ref,
        "issue_ref": expected.issue_ref,
        "subject": expected.subject,
        "jurisdiction": expected.jurisdiction,
        "as_of_date": expected.as_of_date,
    }
    if expected.proposition_sha256 is not None:
        exact["proposition_sha256"] = expected.proposition_sha256
    for field, value in exact.items():
        if getattr(artifact, field) != value:
            raise ValueError(f"retrieval-attempt {field} binding mismatch")
    if expected.query_sha256 is not None and artifact.query_sha256 != expected.query_sha256:
        raise ValueError("retrieval-attempt query_sha256 binding mismatch")
    fully_bound_expected = replace(
        expected,
        query_sha256=artifact.query_sha256,
        proposition_sha256=artifact.proposition_sha256,
    )
    expected_query_contract = _query_contract_sha256(
        binding=fully_bound_expected,
        query_sha256=artifact.query_sha256,
    )
    if artifact.query_contract_sha256 != expected_query_contract:
        raise ValueError("retrieval-attempt canonical query contract mismatch")
    candidate_rows = _candidate_rows(
        settings,
        binding=fully_bound_expected,
        chunk_ids=tuple(hit.chunk_id for hit in artifact.ranked_hits),
    )
    reconstructed = tuple(
        _ranked_hit_from_candidate(
            binding=fully_bound_expected,
            rank=rank,
            executor_hit=CandidateRetrievalExecutorHit(
                chunk_id=hit.chunk_id,
                qualification_disposition=hit.qualification_disposition,
            ),
            candidate_row=candidate_rows[hit.chunk_id],
        )
        for rank, hit in enumerate(artifact.ranked_hits, start=1)
    )
    if reconstructed != artifact.ranked_hits:
        raise ValueError("retrieval-attempt hit membership provenance mismatch")
    execution_material = {
        "schema": "legalbot.research.pinned-retrieval-execution.v1",
        "query_contract_sha256": artifact.query_contract_sha256,
        "retrieval_policy_sha256": artifact.retrieval_policy_sha256,
        "retrieval_toolchain_sha256": artifact.retrieval_toolchain_sha256,
        "executor_invocation_id": artifact.executor_invocation_id,
        "candidate_rows_examined": artifact.candidate_rows_examined,
        "ranked_hits": [hit.model_dump(mode="json") for hit in artifact.ranked_hits],
    }
    if (
        artifact.retrieval_execution_sha256
        != hashlib.sha256(_canonical_json(execution_material)).hexdigest()
    ):
        raise ValueError("retrieval-attempt execution provenance mismatch")
    if require_no_qualifying_hit and not artifact.no_qualifying_existing_hit:
        raise ValueError("candidate already contains a qualifying existing hit")
    return artifact
