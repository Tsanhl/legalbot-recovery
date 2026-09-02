"""Pure planning and verification for immutable cross-candidate vector reuse.

This module deliberately performs no database, filesystem, LanceDB or embedding
work.  A future index-build integration may execute a returned plan only after
it has independently pinned the exact parent seal and identities supplied here.
Lexical data is never reusable under this contract.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .ge_generic_read_guard import require_generic_index_read_allowed

INDEX_SEAL_SCHEMA = "legalbot.index-seal.v2"
VECTOR_CARRY_FORWARD_SCHEMA = "legalbot.vector-carry-forward-plan.v1"
VECTOR_REUSE_REPORT_SCHEMA = "legalbot.vector-reuse-report.v1"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_BUILD_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+;=\-]{0,255}$")


class VectorCarryForwardError(ValueError):
    """The proposed carry-forward is not provably identity preserving."""


@dataclass(frozen=True, slots=True)
class VectorBuildIdentity:
    """Frozen embedding identities for one immutable candidate build."""

    build_id: str
    seal_sha256: str
    embedding_model_revision: str
    vector_dimensions: int
    vector_dtype: str
    parser_identity: str
    chunker_identity: str
    index_schema_version: str


@dataclass(frozen=True, slots=True)
class ChunkIdentity:
    """The stable chunk identity and exact canonical-content digest."""

    chunk_id: str
    content_sha256: str


@dataclass(frozen=True, slots=True)
class ParentVector:
    """One vector read from a verified immutable parent candidate."""

    chunk_id: str
    content_sha256: str
    vector: tuple[float, ...]


@dataclass(frozen=True, slots=True)
class VectorCarryForwardPlan:
    """A deterministic plan; execution must create and seal a new candidate."""

    schema: str
    parent_build_id: str
    parent_seal_sha256: str
    child_build_id: str
    reusable_vectors: tuple[ParentVector, ...]
    unchanged_chunk_ids: tuple[str, ...]
    changed_chunks: tuple[ChunkIdentity, ...]
    new_chunks: tuple[ChunkIdentity, ...]
    removed_chunk_ids: tuple[str, ...]
    lexical_rebuild_required: bool
    child_requires_new_seal: bool
    plan_sha256: str

    @property
    def chunks_requiring_embedding(self) -> tuple[ChunkIdentity, ...]:
        return self.changed_chunks + self.new_chunks


@dataclass(frozen=True, slots=True)
class VerifiedParentVectorSource:
    """Read-only identity of a parent generation verified for vector reuse."""

    identity: VectorBuildIdentity
    build_path: Path
    row_count: int
    physical_lanes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class VectorReuseReport:
    """Prose-free child report bound into the new candidate seal."""

    schema: str
    parent_build_id: str
    parent_seal_sha256: str
    child_build_id: str
    eligible_chunk_count: int
    reused_vector_count: int
    embedded_vector_count: int
    parent_row_count: int
    parent_rows_not_reused: int
    embedding_model_revision: str
    vector_dimensions: int
    vector_dtype: str
    parser_identity: str
    chunker_identity: str
    index_schema_version: str
    lexical_rebuild_required: bool
    active_write_allowed: bool
    seal_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def plan_vector_carry_forward(
    *,
    parent_identity: VectorBuildIdentity,
    child_identity: VectorBuildIdentity,
    parent_seal_bytes: bytes,
    parent_vectors: Iterable[ParentVector],
    child_chunks: Iterable[ChunkIdentity],
) -> VectorCarryForwardPlan:
    """Verify a sealed parent and classify exact reuse for a new candidate.

    Reuse requires equality of the chunk ID and canonical-content SHA-256, plus
    exact equality of every embedding/parser/chunker/index identity.  A changed
    or new chunk must be embedded.  Parent-only chunks are removed.  The plan
    never permits mutation of the parent or reuse of derived lexical data.
    """

    _validate_build_identity(parent_identity, role="parent")
    _validate_build_identity(child_identity, role="child")
    if parent_identity.build_id == child_identity.build_id:
        raise VectorCarryForwardError("carry-forward must target a new candidate build")
    _assert_compatible_identities(parent_identity, child_identity)
    _verify_parent_seal(parent_identity, parent_seal_bytes)

    parent_by_id: dict[str, ParentVector] = {}
    for record in parent_vectors:
        _validate_chunk_identity(record.chunk_id, record.content_sha256)
        _validate_vector(record.vector, parent_identity.vector_dimensions)
        if record.chunk_id in parent_by_id:
            raise VectorCarryForwardError("duplicate parent chunk identity")
        parent_by_id[record.chunk_id] = record

    child_by_id: dict[str, ChunkIdentity] = {}
    for chunk in child_chunks:
        _validate_chunk_identity(chunk.chunk_id, chunk.content_sha256)
        if chunk.chunk_id in child_by_id:
            raise VectorCarryForwardError("duplicate child chunk identity")
        child_by_id[chunk.chunk_id] = chunk

    unchanged_ids = tuple(
        sorted(
            chunk_id
            for chunk_id, child in child_by_id.items()
            if (parent := parent_by_id.get(chunk_id)) is not None
            and parent.content_sha256 == child.content_sha256
        )
    )
    unchanged_set = set(unchanged_ids)
    reusable = tuple(parent_by_id[chunk_id] for chunk_id in unchanged_ids)
    changed = tuple(
        child_by_id[chunk_id]
        for chunk_id in sorted((set(parent_by_id) & set(child_by_id)) - unchanged_set)
    )
    new = tuple(child_by_id[chunk_id] for chunk_id in sorted(set(child_by_id) - set(parent_by_id)))
    removed = tuple(sorted(set(parent_by_id) - set(child_by_id)))

    digest_payload = {
        "schema": VECTOR_CARRY_FORWARD_SCHEMA,
        "parent_build_id": parent_identity.build_id,
        "parent_seal_sha256": parent_identity.seal_sha256,
        "child_build_id": child_identity.build_id,
        "embedding_identity": {
            "embedding_model_revision": child_identity.embedding_model_revision,
            "vector_dimensions": child_identity.vector_dimensions,
            "vector_dtype": child_identity.vector_dtype,
            "parser_identity": child_identity.parser_identity,
            "chunker_identity": child_identity.chunker_identity,
            "index_schema_version": child_identity.index_schema_version,
        },
        "unchanged": [
            {
                "chunk_id": record.chunk_id,
                "content_sha256": record.content_sha256,
            }
            for record in reusable
        ],
        "changed": [asdict(chunk) for chunk in changed],
        "new": [asdict(chunk) for chunk in new],
        "removed": list(removed),
        "lexical_rebuild_required": True,
        "child_requires_new_seal": True,
    }
    plan_sha256 = hashlib.sha256(_canonical_json(digest_payload)).hexdigest()
    return VectorCarryForwardPlan(
        schema=VECTOR_CARRY_FORWARD_SCHEMA,
        parent_build_id=parent_identity.build_id,
        parent_seal_sha256=parent_identity.seal_sha256,
        child_build_id=child_identity.build_id,
        reusable_vectors=reusable,
        unchanged_chunk_ids=unchanged_ids,
        changed_chunks=changed,
        new_chunks=new,
        removed_chunk_ids=removed,
        lexical_rebuild_required=True,
        child_requires_new_seal=True,
        plan_sha256=plan_sha256,
    )


def verify_parent_vector_source(
    *,
    index_root: Path,
    parent_build_id: str,
    child_build_id: str,
    embedding_model_revision: str,
    vector_dimensions: int,
    vector_dtype: str,
    parser_identity: str,
    chunker_identity: str,
    index_schema_version: str,
) -> VerifiedParentVectorSource:
    """Authenticate immutable vector identities without current policy/attestation coupling."""

    if not _BUILD_ID.fullmatch(parent_build_id) or not _BUILD_ID.fullmatch(child_build_id):
        raise VectorCarryForwardError("vector reuse build identity is invalid")
    if parent_build_id == child_build_id:
        raise VectorCarryForwardError("carry-forward must target a new candidate build")
    builds_root = (index_root / "builds").resolve()
    build_path = index_root / "builds" / parent_build_id
    if build_path.is_symlink() or build_path.resolve(strict=False).parent != builds_root:
        raise VectorCarryForwardError("parent vector build escapes the immutable build root")
    if (
        not build_path.is_dir()
        or (index_root / "builds" / f".{parent_build_id}.incomplete").exists()
    ):
        raise VectorCarryForwardError("parent vector build is not a final immutable generation")
    require_generic_index_read_allowed(
        build_path,
        expected_build_id=parent_build_id,
    )

    seal_path = build_path / "seal.json"
    manifest_path = build_path / "manifest.json"
    source_path = build_path / "approved-source-manifest.json"
    lane_path = build_path / "lance" / "physical-lanes.json"
    if not all(
        path.is_file() and not path.is_symlink()
        for path in (seal_path, manifest_path, source_path, lane_path)
    ):
        raise VectorCarryForwardError("parent vector build is missing a sealed identity artifact")
    seal_bytes = seal_path.read_bytes()
    seal_sha256 = hashlib.sha256(seal_bytes).hexdigest()
    seal = _json_object_unique(seal_bytes, label="parent seal")
    manifest = _json_object_unique(manifest_path.read_bytes(), label="parent manifest")
    source = _json_object_unique(source_path.read_bytes(), label="parent source manifest")
    lanes = _json_object_unique(lane_path.read_bytes(), label="parent lane manifest")

    parent = VectorBuildIdentity(
        build_id=parent_build_id,
        seal_sha256=seal_sha256,
        embedding_model_revision=str(manifest.get("embedding_model") or ""),
        vector_dimensions=int(manifest.get("vector_dimensions") or 0),
        vector_dtype=_embedding_dtype(str(manifest.get("embedding_model") or "")),
        parser_identity=str(source.get("parser_version") or ""),
        chunker_identity=str(source.get("chunker_version") or ""),
        index_schema_version=str(source.get("index_schema_version") or ""),
    )
    child = VectorBuildIdentity(
        build_id=child_build_id,
        seal_sha256="0" * 64,
        embedding_model_revision=embedding_model_revision,
        vector_dimensions=vector_dimensions,
        vector_dtype=vector_dtype,
        parser_identity=parser_identity,
        chunker_identity=chunker_identity,
        index_schema_version=index_schema_version,
    )
    _validate_build_identity(parent, role="parent")
    _validate_build_identity(child, role="child")
    _assert_compatible_identities(parent, child)
    _verify_parent_seal(parent, seal_bytes)
    if seal.get("manifest_sha256") != _file_sha256(manifest_path):
        raise VectorCarryForwardError("parent manifest changed after sealing")
    if seal.get("source_manifest_file_sha256") != _file_sha256(source_path):
        raise VectorCarryForwardError("parent source manifest changed after sealing")
    if seal.get("physical_lane_manifest_sha256") != _file_sha256(lane_path):
        raise VectorCarryForwardError("parent lane manifest changed after sealing")
    if seal.get("lance_tree_sha256") != _tree_sha256(build_path / "lance"):
        raise VectorCarryForwardError("parent vector tree changed after sealing")
    if (
        manifest.get("schema") != "legalbot.lance-build.v1"
        or manifest.get("sealed") is not True
        or manifest.get("build_id") != parent_build_id
        or manifest.get("source_manifest_sha256") != source.get("manifest_sha256")
    ):
        raise VectorCarryForwardError("parent build manifest identities are inconsistent")
    raw_tables = lanes.get("tables")
    if (
        lanes.get("schema") != "legalbot.physical-lanes.v1"
        or lanes.get("separated") is not True
        or not isinstance(raw_tables, Mapping)
    ):
        raise VectorCarryForwardError("parent vector lanes are not physically separated")
    physical_lanes: list[str] = []
    row_count = 0
    for lane, value in sorted(raw_tables.items()):
        if (
            not isinstance(lane, str)
            or not _IDENTITY.fullmatch(lane)
            or not isinstance(value, Mapping)
        ):
            raise VectorCarryForwardError("parent vector lane identity is invalid")
        count = value.get("row_count")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise VectorCarryForwardError("parent vector lane count is invalid")
        if not (build_path / "lance" / lane).is_dir():
            raise VectorCarryForwardError("parent vector lane directory is missing")
        row_count += count
        physical_lanes.append(lane)
    if row_count != int(manifest.get("chunk_count") or 0) or row_count < 1:
        raise VectorCarryForwardError("parent vector row count differs from its sealed manifest")
    return VerifiedParentVectorSource(
        identity=parent,
        build_path=build_path,
        row_count=row_count,
        physical_lanes=tuple(physical_lanes),
    )


class ParentVectorBatchReader:
    """Bounded Lance lookup; it never copies a parent index or keeps all vectors in RAM."""

    def __init__(self, source: VerifiedParentVectorSource, lancedb_module: Any) -> None:
        require_generic_index_read_allowed(
            source.build_path,
            expected_build_id=source.identity.build_id,
        )
        self.source = source
        self._tables: list[Any] = []
        for lane in source.physical_lanes:
            connection = lancedb_module.connect(str(source.build_path / "lance" / lane))
            try:
                table = connection.open_table("chunks")
            except (FileNotFoundError, OSError, RuntimeError, ValueError):
                continue
            self._tables.append(table)

    def lookup(self, chunks: Sequence[ChunkIdentity]) -> dict[str, tuple[float, ...]]:
        if not chunks:
            return {}
        by_id = {chunk.chunk_id: chunk for chunk in chunks}
        if len(by_id) != len(chunks):
            raise VectorCarryForwardError("child vector lookup contains duplicate chunks")
        for chunk in chunks:
            _validate_chunk_identity(chunk.chunk_id, chunk.content_sha256)
        quoted = ",".join("'" + chunk_id.replace("'", "''") + "'" for chunk_id in sorted(by_id))
        predicate = f"chunk_id IN ({quoted})"
        observed: dict[str, tuple[str, tuple[float, ...]]] = {}
        for table in self._tables:
            rows = table.search().where(predicate, prefilter=True).limit(len(chunks) + 1).to_list()
            for row in rows:
                if not isinstance(row, Mapping):
                    raise VectorCarryForwardError("parent vector lookup returned an invalid row")
                chunk_id = str(row.get("chunk_id") or "")
                content_sha256 = str(row.get("content_sha256") or "")
                if chunk_id not in by_id:
                    raise VectorCarryForwardError(
                        "parent vector lookup escaped its requested batch"
                    )
                if chunk_id in observed:
                    raise VectorCarryForwardError(
                        "parent vector build contains duplicate chunk IDs"
                    )
                raw_vector = row.get("vector")
                if not isinstance(raw_vector, Sequence) or isinstance(
                    raw_vector, str | bytes | bytearray
                ):
                    raise VectorCarryForwardError("parent vector lookup returned no vector")
                vector = tuple(float(value) for value in raw_vector)
                _validate_chunk_identity(chunk_id, content_sha256)
                _validate_vector(vector, self.source.identity.vector_dimensions)
                observed[chunk_id] = (content_sha256, vector)
        return {
            chunk_id: vector
            for chunk_id, (content_sha256, vector) in observed.items()
            if content_sha256 == by_id[chunk_id].content_sha256
        }


def build_vector_reuse_report(
    *,
    parent: VerifiedParentVectorSource,
    child_build_id: str,
    eligible_chunk_count: int,
    reused_vector_count: int,
    embedded_vector_count: int,
) -> VectorReuseReport:
    if (
        eligible_chunk_count < 1
        or reused_vector_count < 0
        or embedded_vector_count < 0
        or reused_vector_count + embedded_vector_count != eligible_chunk_count
        or reused_vector_count > parent.row_count
    ):
        raise VectorCarryForwardError("vector reuse counts are inconsistent")
    material: dict[str, Any] = {
        "schema": VECTOR_REUSE_REPORT_SCHEMA,
        "parent_build_id": parent.identity.build_id,
        "parent_seal_sha256": parent.identity.seal_sha256,
        "child_build_id": child_build_id,
        "eligible_chunk_count": eligible_chunk_count,
        "reused_vector_count": reused_vector_count,
        "embedded_vector_count": embedded_vector_count,
        "parent_row_count": parent.row_count,
        "parent_rows_not_reused": parent.row_count - reused_vector_count,
        "embedding_model_revision": parent.identity.embedding_model_revision,
        "vector_dimensions": parent.identity.vector_dimensions,
        "vector_dtype": parent.identity.vector_dtype,
        "parser_identity": parent.identity.parser_identity,
        "chunker_identity": parent.identity.chunker_identity,
        "index_schema_version": parent.identity.index_schema_version,
        "lexical_rebuild_required": True,
        "active_write_allowed": False,
    }
    material["seal_sha256"] = hashlib.sha256(_canonical_json(material)).hexdigest()
    return VectorReuseReport(**material)


def _validate_build_identity(identity: VectorBuildIdentity, *, role: str) -> None:
    if not _BUILD_ID.fullmatch(identity.build_id):
        raise VectorCarryForwardError(f"{role} build identity contains an invalid value")
    for value in (
        identity.embedding_model_revision,
        identity.vector_dtype,
        identity.parser_identity,
        identity.chunker_identity,
        identity.index_schema_version,
    ):
        if not _IDENTITY.fullmatch(value):
            raise VectorCarryForwardError(f"{role} build identity contains an invalid value")
    if not _SHA256.fullmatch(identity.seal_sha256):
        raise VectorCarryForwardError(f"{role} seal SHA-256 is invalid")
    if isinstance(identity.vector_dimensions, bool) or identity.vector_dimensions <= 0:
        raise VectorCarryForwardError(f"{role} vector dimensions are invalid")


def _assert_compatible_identities(parent: VectorBuildIdentity, child: VectorBuildIdentity) -> None:
    fields = (
        "embedding_model_revision",
        "vector_dimensions",
        "vector_dtype",
        "parser_identity",
        "chunker_identity",
        "index_schema_version",
    )
    mismatches = [field for field in fields if getattr(parent, field) != getattr(child, field)]
    if mismatches:
        raise VectorCarryForwardError(
            "vector carry-forward identity mismatch: " + ", ".join(mismatches)
        )


def _verify_parent_seal(identity: VectorBuildIdentity, seal_bytes: bytes) -> None:
    if not isinstance(seal_bytes, bytes) or not seal_bytes:
        raise VectorCarryForwardError("parent seal bytes are required")
    actual = hashlib.sha256(seal_bytes).hexdigest()
    if actual != identity.seal_sha256:
        raise VectorCarryForwardError("parent seal byte digest mismatch")
    try:
        payload = json.loads(seal_bytes, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, VectorCarryForwardError) as exc:
        raise VectorCarryForwardError("parent seal is not unique-key UTF-8 JSON") from exc
    if not isinstance(payload, Mapping):
        raise VectorCarryForwardError("parent seal must be a JSON object")
    if payload.get("schema") != INDEX_SEAL_SCHEMA:
        raise VectorCarryForwardError("parent seal schema mismatch")
    if payload.get("build_id") != identity.build_id:
        raise VectorCarryForwardError("parent seal build identity mismatch")
    for field in ("manifest_sha256", "lance_tree_sha256"):
        value = payload.get(field)
        if not isinstance(value, str) or not _SHA256.fullmatch(value):
            raise VectorCarryForwardError(f"parent seal {field} is invalid")


def _validate_chunk_identity(chunk_id: str, content_sha256: str) -> None:
    if not _IDENTITY.fullmatch(chunk_id):
        raise VectorCarryForwardError("chunk identity is invalid")
    if not _SHA256.fullmatch(content_sha256):
        raise VectorCarryForwardError("chunk content SHA-256 is invalid")


def _validate_vector(vector: tuple[float, ...], dimensions: int) -> None:
    if not isinstance(vector, tuple) or len(vector) != dimensions:
        raise VectorCarryForwardError("parent vector dimensions do not match identity")
    if any(
        isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value)
        for value in vector
    ):
        raise VectorCarryForwardError("parent vector contains an invalid component")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VectorCarryForwardError("parent seal contains duplicate JSON keys")
        result[key] = value
    return result


def _json_object_unique(data: bytes, *, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(data, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, VectorCarryForwardError) as exc:
        raise VectorCarryForwardError(f"{label} is not unique-key UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise VectorCarryForwardError(f"{label} must be a JSON object")
    return payload


def _embedding_dtype(model_identity: str) -> str:
    match = re.search(r"(?:^|;)dtype=([A-Za-z0-9._+-]+)(?:;|$)", model_identity)
    return match.group(1) if match else "test"


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _tree_sha256(root: Path) -> str:
    if not root.is_dir():
        raise VectorCarryForwardError("parent vector tree is missing")
    if any(path.is_symlink() for path in root.rglob("*")):
        raise VectorCarryForwardError("parent vector tree contains a symlink")
    files = sorted(
        (path for path in root.rglob("*") if path.is_file()), key=lambda path: path.as_posix()
    )
    if not files:
        raise VectorCarryForwardError("parent vector tree is empty")
    digest = hashlib.sha256()
    for path in files:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(bytes.fromhex(_file_sha256(path)))
    return digest.hexdigest()


def _canonical_json(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
