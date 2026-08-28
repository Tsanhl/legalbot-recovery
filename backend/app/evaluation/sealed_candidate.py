"""Read and verify a sealed candidate without consulting ``ACTIVE``."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from ..config import Settings
from ..db import Database
from ..retrieval.diagnostic_slice import (
    allowed_index_statuses_for_pin,
    refuse_diagnostic_slice_for_production,
)
from ..retrieval.service import _verify_sealed_build

_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class SealedCandidateIdentity:
    build_id: str
    status: str
    candidate_manifest_sha256: str
    candidate_seal_sha256: str
    source_manifest_sha256: str
    embedding_model: str
    reranker_model: str
    document_count: int
    chunk_count: int
    vector_count: int

    def safe_dict(self) -> dict[str, str | int]:
        return {
            "candidate_build_id": self.build_id,
            "candidate_status": self.status,
            "candidate_manifest_sha256": self.candidate_manifest_sha256,
            "candidate_seal_sha256": self.candidate_seal_sha256,
            "source_manifest_sha256": self.source_manifest_sha256,
            "embedding_model": self.embedding_model,
            "reranker_model": self.reranker_model,
            "document_count": self.document_count,
            "chunk_count": self.chunk_count,
            "vector_count": self.vector_count,
        }


def load_sealed_candidate_identity(
    *, settings: Settings, database: Database, candidate_build_id: str
) -> SealedCandidateIdentity:
    """Verify one explicit full candidate; no pointer read or promotion occurs."""

    if not _SAFE_ID.fullmatch(candidate_build_id):
        raise ValueError("candidate build ID is invalid")
    refuse_diagnostic_slice_for_production(
        candidate_build_id, purpose="full-candidate non-release evaluation"
    )
    row = database.fetchone("SELECT * FROM index_builds WHERE id=?", (candidate_build_id,))
    allowed = allowed_index_statuses_for_pin(candidate_build_id)
    if row is None or str(row["status"]) not in allowed:
        raise RuntimeError("candidate_not_sealed_or_evaluation_eligible")
    source_manifest_sha256 = _verify_sealed_build(settings, database, dict(row))
    if not _SHA256.fullmatch(source_manifest_sha256):
        raise RuntimeError("candidate_source_manifest_identity_invalid")
    build_root = settings.index_dir / "builds" / candidate_build_id
    manifest_sha256 = _file_sha256(build_root / "manifest.json")
    seal_sha256 = _file_sha256(build_root / "seal.json")
    if str(row["manifest_sha256"] or "") != seal_sha256:
        raise RuntimeError("candidate_catalogue_seal_identity_invalid")
    document_count = int(row["document_count"])
    chunk_count = int(row["chunk_count"])
    vector_count = int(row["vector_count"])
    if document_count < 1 or chunk_count < 1 or vector_count != chunk_count:
        raise RuntimeError("candidate_count_identity_invalid")
    return SealedCandidateIdentity(
        build_id=candidate_build_id,
        status=str(row["status"]),
        candidate_manifest_sha256=manifest_sha256,
        candidate_seal_sha256=seal_sha256,
        source_manifest_sha256=source_manifest_sha256,
        embedding_model=str(row["embedding_model"]),
        reranker_model=str(row["reranker_model"]),
        document_count=document_count,
        chunk_count=chunk_count,
        vector_count=vector_count,
    )
