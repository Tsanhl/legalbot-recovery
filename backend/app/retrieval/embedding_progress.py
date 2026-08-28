"""Durable embedding-progress checkpoints. Row count alone is never the resume cursor."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypedDict

CHECKPOINT_SCHEMA = "legalbot.embedding-progress.v1"
CHECKPOINT_RELATIVE = Path("lance") / "embedding-progress.v1.json"


class EmbeddingIdentityFields(TypedDict):
    build_id: str
    source_manifest_sha256: str
    ordered_chunk_stream_sha256: str
    parser_version: str
    chunker_version: str
    index_schema_version: str
    embedding_model: str
    dtype: str
    vector_dimensions: int
    batch_size: int
    policy_sha256: str
    assessment_bundle_sha256: str
    provision_verification_sha256: str
    parent_vector_build_id: str
    parent_vector_seal_sha256: str


@dataclass(frozen=True, slots=True)
class EmbeddingProgressCheckpoint:
    schema: str
    build_id: str
    source_manifest_sha256: str
    ordered_chunk_stream_sha256: str
    parser_version: str
    chunker_version: str
    index_schema_version: str
    embedding_model: str
    dtype: str
    vector_dimensions: int
    batch_size: int
    policy_sha256: str
    assessment_bundle_sha256: str
    provision_verification_sha256: str
    parent_vector_build_id: str
    parent_vector_seal_sha256: str
    completed_row_count: int
    last_deterministic_chunk_key: str
    rolling_digest: str
    physical_lane_counts: Mapping[str, int]
    checkpoint_timestamp: str
    checkpoint_sha256: str

    def identity_tuple(self) -> tuple[str, ...]:
        return (
            self.build_id,
            self.source_manifest_sha256,
            self.ordered_chunk_stream_sha256,
            self.parser_version,
            self.chunker_version,
            self.index_schema_version,
            self.embedding_model,
            self.dtype,
            str(self.vector_dimensions),
            str(self.batch_size),
            self.policy_sha256,
            self.assessment_bundle_sha256,
            self.provision_verification_sha256,
            self.parent_vector_build_id,
            self.parent_vector_seal_sha256,
        )


def chunk_key(source_version_id: str, ordinal: int, chunk_id: str) -> str:
    return f"{source_version_id}\t{ordinal}\t{chunk_id}"


def parse_chunk_key(value: str) -> tuple[str, int, str]:
    source_version_id, ordinal, chunk_id = value.split("\t", 2)
    return source_version_id, int(ordinal), chunk_id


def update_rolling_digest(previous: str, *, chunk_id: str, content_sha256: str) -> str:
    payload = f"{previous}|{chunk_id}|{content_sha256}".encode()
    return hashlib.sha256(payload).hexdigest()


def ordered_stream_digest(keys: Sequence[str]) -> str:
    return hashlib.sha256("\n".join(keys).encode("utf-8")).hexdigest()


def checkpoint_sha256(payload: Mapping[str, Any]) -> str:
    body = {key: value for key, value in payload.items() if key != "checkpoint_sha256"}
    encoded = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def build_checkpoint(
    *,
    build_id: str,
    source_manifest_sha256: str,
    ordered_chunk_stream_sha256: str,
    parser_version: str,
    chunker_version: str,
    index_schema_version: str,
    embedding_model: str,
    dtype: str,
    vector_dimensions: int,
    batch_size: int,
    policy_sha256: str,
    assessment_bundle_sha256: str,
    provision_verification_sha256: str,
    parent_vector_build_id: str = "",
    parent_vector_seal_sha256: str = "",
    completed_row_count: int,
    last_deterministic_chunk_key: str,
    rolling_digest: str,
    physical_lane_counts: Mapping[str, int],
    checkpoint_timestamp: str | None = None,
) -> EmbeddingProgressCheckpoint:
    payload = {
        "schema": CHECKPOINT_SCHEMA,
        "build_id": build_id,
        "source_manifest_sha256": source_manifest_sha256,
        "ordered_chunk_stream_sha256": ordered_chunk_stream_sha256,
        "parser_version": parser_version,
        "chunker_version": chunker_version,
        "index_schema_version": index_schema_version,
        "embedding_model": embedding_model,
        "dtype": dtype,
        "vector_dimensions": vector_dimensions,
        "batch_size": batch_size,
        "policy_sha256": policy_sha256,
        "assessment_bundle_sha256": assessment_bundle_sha256,
        "provision_verification_sha256": provision_verification_sha256,
        "parent_vector_build_id": parent_vector_build_id,
        "parent_vector_seal_sha256": parent_vector_seal_sha256,
        "completed_row_count": completed_row_count,
        "last_deterministic_chunk_key": last_deterministic_chunk_key,
        "rolling_digest": rolling_digest,
        "physical_lane_counts": dict(physical_lane_counts),
        "checkpoint_timestamp": checkpoint_timestamp or datetime.now(UTC).isoformat(),
    }
    payload["checkpoint_sha256"] = checkpoint_sha256(payload)
    return EmbeddingProgressCheckpoint(**payload)  # type: ignore[arg-type]


def checkpoint_path(staging: Path) -> Path:
    return staging / CHECKPOINT_RELATIVE


def load_checkpoint(staging: Path) -> EmbeddingProgressCheckpoint | None:
    path = checkpoint_path(staging)
    if not path.is_file():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("embedding progress checkpoint is not an object")
    digest = checkpoint_sha256(payload)
    if digest != str(payload.get("checkpoint_sha256") or ""):
        raise ValueError("embedding progress checkpoint SHA-256 mismatch")
    if str(payload.get("schema") or "") != CHECKPOINT_SCHEMA:
        raise ValueError("unsupported embedding progress checkpoint schema")
    return EmbeddingProgressCheckpoint(
        schema=str(payload["schema"]),
        build_id=str(payload["build_id"]),
        source_manifest_sha256=str(payload["source_manifest_sha256"]),
        ordered_chunk_stream_sha256=str(payload["ordered_chunk_stream_sha256"]),
        parser_version=str(payload["parser_version"]),
        chunker_version=str(payload["chunker_version"]),
        index_schema_version=str(payload["index_schema_version"]),
        embedding_model=str(payload["embedding_model"]),
        dtype=str(payload["dtype"]),
        vector_dimensions=int(payload["vector_dimensions"]),
        batch_size=int(payload["batch_size"]),
        policy_sha256=str(payload["policy_sha256"]),
        assessment_bundle_sha256=str(payload["assessment_bundle_sha256"]),
        provision_verification_sha256=str(payload["provision_verification_sha256"]),
        parent_vector_build_id=str(payload.get("parent_vector_build_id") or ""),
        parent_vector_seal_sha256=str(payload.get("parent_vector_seal_sha256") or ""),
        completed_row_count=int(payload["completed_row_count"]),
        last_deterministic_chunk_key=str(payload["last_deterministic_chunk_key"]),
        rolling_digest=str(payload["rolling_digest"]),
        physical_lane_counts={
            str(key): int(value) for key, value in dict(payload["physical_lane_counts"]).items()
        },
        checkpoint_timestamp=str(payload["checkpoint_timestamp"]),
        checkpoint_sha256=str(payload["checkpoint_sha256"]),
    )


def save_checkpoint(staging: Path, checkpoint: EmbeddingProgressCheckpoint) -> None:
    path = checkpoint_path(staging)
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(asdict(checkpoint), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(encoded, encoding="utf-8")
    temporary.replace(path)


def identities_match(
    checkpoint: EmbeddingProgressCheckpoint,
    *,
    build_id: str,
    source_manifest_sha256: str,
    ordered_chunk_stream_sha256: str,
    parser_version: str,
    chunker_version: str,
    index_schema_version: str,
    embedding_model: str,
    dtype: str,
    vector_dimensions: int,
    batch_size: int,
    policy_sha256: str,
    assessment_bundle_sha256: str,
    provision_verification_sha256: str,
    parent_vector_build_id: str = "",
    parent_vector_seal_sha256: str = "",
) -> bool:
    expected = EmbeddingProgressCheckpoint(
        schema=CHECKPOINT_SCHEMA,
        build_id=build_id,
        source_manifest_sha256=source_manifest_sha256,
        ordered_chunk_stream_sha256=ordered_chunk_stream_sha256,
        parser_version=parser_version,
        chunker_version=chunker_version,
        index_schema_version=index_schema_version,
        embedding_model=embedding_model,
        dtype=dtype,
        vector_dimensions=vector_dimensions,
        batch_size=batch_size,
        policy_sha256=policy_sha256,
        assessment_bundle_sha256=assessment_bundle_sha256,
        provision_verification_sha256=provision_verification_sha256,
        parent_vector_build_id=parent_vector_build_id,
        parent_vector_seal_sha256=parent_vector_seal_sha256,
        completed_row_count=0,
        last_deterministic_chunk_key="",
        rolling_digest="",
        physical_lane_counts={},
        checkpoint_timestamp="",
        checkpoint_sha256="",
    )
    return checkpoint.identity_tuple() == expected.identity_tuple()
