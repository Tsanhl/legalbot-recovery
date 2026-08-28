from __future__ import annotations

import hashlib

from app.ingestion.models import Jurisdiction, MaterialLane
from app.retrieval.models import IndexedChunk, SearchHit
from app.retrieval.service import _latest_source_version_hits


def _hit(
    chunk_id: str,
    *,
    authority_id: str,
    source_version_id: str,
    as_of_date: str,
    last_updated: str,
) -> SearchHit:
    text = f"Authority text for {chunk_id}."
    return SearchHit(
        chunk=IndexedChunk(
            chunk_id=chunk_id,
            text=text,
            vector=(0.0,) * 1024,
            jurisdiction=Jurisdiction.ENGLAND_WALES,
            material_lane=MaterialLane.PRIMARY_AUTHORITY,
            subject="contract",
            review_state="approved",
            source_identity=authority_id,
            content_sha256=hashlib.sha256(text.encode()).hexdigest(),
            metadata={
                "authority_identity_id": authority_id,
                "source_version_id": source_version_id,
                "as_of_date": as_of_date,
                "source_date": "1977-07-29",
                "last_updated": last_updated,
            },
        ),
        score=0.9,
    )


def test_latest_version_filter_is_binary_and_preserves_relevance_order() -> None:
    hits = (
        _hit(
            "old-1",
            authority_id="ukpga:1977:50",
            source_version_id="version-old",
            as_of_date="2025-01-01",
            last_updated="2025-01-02T00:00:00+00:00",
        ),
        _hit(
            "other-authority",
            authority_id="ukpga:1979:54",
            source_version_id="version-other",
            as_of_date="2024-01-01",
            last_updated="2024-01-02T00:00:00+00:00",
        ),
        _hit(
            "new-1",
            authority_id="ukpga:1977:50",
            source_version_id="version-new",
            as_of_date="2026-08-14",
            last_updated="2026-08-24T00:00:00+00:00",
        ),
        _hit(
            "old-2",
            authority_id="ukpga:1977:50",
            source_version_id="version-old",
            as_of_date="2025-01-01",
            last_updated="2025-01-02T00:00:00+00:00",
        ),
    )

    selected, removed = _latest_source_version_hits(hits)

    assert [hit.chunk.chunk_id for hit in selected] == ["other-authority", "new-1"]
    assert removed == 2


def test_last_updated_breaks_ties_without_overwriting_original_source_date() -> None:
    hits = (
        _hit(
            "earlier-observation",
            authority_id="case:[2020] UKSC 1",
            source_version_id="case-version-a",
            as_of_date="2020-01-15",
            last_updated="2026-08-20T00:00:00+00:00",
        ),
        _hit(
            "later-observation",
            authority_id="case:[2020] UKSC 1",
            source_version_id="case-version-b",
            as_of_date="2020-01-15",
            last_updated="2026-08-24T00:00:00+00:00",
        ),
    )

    selected, removed = _latest_source_version_hits(hits)

    assert [hit.chunk.chunk_id for hit in selected] == ["later-observation"]
    assert selected[0].chunk.metadata["source_date"] == "1977-07-29"
    assert removed == 1
