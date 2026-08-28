from __future__ import annotations

import hashlib
import math

import pytest

from app.ingestion.models import Jurisdiction, MaterialLane
from app.retrieval.models import VECTOR_DIMENSIONS, IndexedChunk, ensure_vector
from app.retrieval.service import _indexed_to_lance_row, _lance_row_to_indexed


def _chunk(*, include_canonical: bool = True) -> IndexedChunk:
    text = "Prompt-safe indexed text."
    metadata: dict[str, object] = {
        "source_version_id": "source-version",
        "locator": "section 1",
        "catalog_lane": "primary_authority",
        "catalog_jurisdiction": "England and Wales",
    }
    if include_canonical:
        metadata["canonical_chunk_sha256"] = hashlib.sha256(b"Canonical source text.").hexdigest()
    return IndexedChunk(
        chunk_id="chunk-1",
        text=text,
        vector=(0.0,) * VECTOR_DIMENSIONS,
        jurisdiction=Jurisdiction.ENGLAND_WALES,
        material_lane=MaterialLane.PRIMARY_AUTHORITY,
        subject="contract",
        review_state="approved",
        source_identity="source-identity",
        content_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        metadata=metadata,
    )


@pytest.mark.parametrize("non_finite", [math.nan, math.inf, -math.inf])
def test_ensure_vector_rejects_non_finite_elements(non_finite: float) -> None:
    vector = [0.0] * VECTOR_DIMENSIONS
    vector[-1] = non_finite

    with pytest.raises(ValueError, match="only finite values"):
        ensure_vector(vector)


def test_lance_row_preserves_distinct_canonical_and_prompt_view_hashes() -> None:
    chunk = _chunk()

    row = _indexed_to_lance_row(chunk)
    restored = _lance_row_to_indexed(row)

    assert row["content_sha256"] == chunk.content_sha256
    assert row["canonical_chunk_sha256"] == chunk.metadata["canonical_chunk_sha256"]
    assert row["canonical_chunk_sha256"] != row["content_sha256"]
    assert row["canonical_chunk_sha256_binding"] == "bound"
    assert restored.metadata["canonical_chunk_sha256"] == row["canonical_chunk_sha256"]
    assert restored.metadata["canonical_chunk_sha256_binding"] == "bound"


def test_new_lance_row_requires_canonical_while_legacy_read_is_explicit() -> None:
    with pytest.raises(ValueError, match="require a canonical"):
        _indexed_to_lance_row(_chunk(include_canonical=False))
    row = _indexed_to_lance_row(_chunk())
    row.pop("canonical_chunk_sha256")
    row.pop("canonical_chunk_sha256_binding")
    restored = _lance_row_to_indexed(row)
    assert restored.metadata["canonical_chunk_sha256"] is None
    assert restored.metadata["canonical_chunk_sha256_binding"] == "legacy_missing"


def test_lance_row_rejects_prompt_view_hash_mismatch() -> None:
    row = _indexed_to_lance_row(_chunk())
    row["content_sha256"] = "f" * 64

    with pytest.raises(ValueError, match="prompt-view content SHA-256 does not match"):
        _lance_row_to_indexed(row)


def test_lance_row_rejects_inconsistent_canonical_binding() -> None:
    row = _indexed_to_lance_row(_chunk())
    row["canonical_chunk_sha256_binding"] = "legacy_missing"

    with pytest.raises(ValueError, match="canonical chunk binding is inconsistent"):
        _lance_row_to_indexed(row)
