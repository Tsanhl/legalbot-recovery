from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from app.api.main import app
from app.db import utc_iso


def _seed_reviews(database: Any) -> None:
    created_at = utc_iso()
    for index in range(120):
        database.execute(
            """
            INSERT INTO reviews(id, review_type, target_id, status, reason, created_at)
            VALUES (?, 'knowledge_gap', ?, 'pending', 'evidence gap', ?)
            """,
            (f"review-pending-{index:03d}", f"gap-{index:03d}", created_at),
        )
    for index in range(5):
        database.execute(
            """
            INSERT INTO reviews(id, review_type, target_id, status, reason, created_at)
            VALUES (?, 'document_safety', ?, 'approved', 'safety check', ?)
            """,
            (f"review-approved-{index:03d}", f"source-{index:03d}", created_at),
        )


def test_admin_review_page_is_stable_filtered_and_lossless(database: Any) -> None:
    _seed_reviews(database)

    assert len(database.admin_reviews()) == 50

    first_total, first = database.admin_review_page(
        limit=50, offset=0, review_type="knowledge_gap", status="pending"
    )
    second_total, second = database.admin_review_page(
        limit=50, offset=50, review_type="knowledge_gap", status="pending"
    )
    third_total, third = database.admin_review_page(
        limit=50, offset=100, review_type="knowledge_gap", status="pending"
    )

    assert first_total == second_total == third_total == 120
    assert [len(first), len(second), len(third)] == [50, 50, 20]
    all_ids = [str(row["id"]) for row in [*first, *second, *third]]
    assert len(all_ids) == len(set(all_ids)) == 120
    assert all_ids[0] == "review-pending-119"
    assert all_ids[-1] == "review-pending-000"
    assert database.admin_review_count(status="approved") == 5
    assert database.admin_review_count(review_type="document_safety", status="pending") == 0

    indexes = {str(row["name"]) for row in database.fetchall("PRAGMA index_list('reviews')")}
    assert "idx_reviews_status_created_id" in indexes


@pytest.mark.asyncio
async def test_admin_review_api_bounds_pages_and_validates_filters(database: Any) -> None:
    _seed_reviews(database)
    previous = getattr(app.state, "services", None)
    app.state.services = SimpleNamespace(database=database)
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 4321))
    try:
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8777"
        ) as client:
            default_page = await client.get("/api/v1/admin/reviews")
            assert default_page.status_code == 200
            assert default_page.json()["total"] == 125
            assert default_page.json()["limit"] == 50
            assert len(default_page.json()["items"]) == 50

            first = await client.get(
                "/api/v1/admin/reviews",
                params={
                    "limit": 500,
                    "offset": -10,
                    "review_type": "knowledge_gap",
                    "status": "pending",
                },
            )
            assert first.status_code == 200
            first_page = first.json()
            assert first_page["total"] == 120
            assert first_page["limit"] == 100
            assert first_page["offset"] == 0
            assert len(first_page["items"]) == 100

            huge_offset = await client.get("/api/v1/admin/reviews", params={"offset": 10**100})
            assert huge_offset.status_code == 200
            assert huge_offset.json()["offset"] == 2_147_483_647
            assert huge_offset.json()["items"] == []

            last = await client.get(
                "/api/v1/admin/reviews",
                params={
                    "limit": 50,
                    "offset": 100,
                    "review_type": "knowledge_gap",
                    "status": "pending",
                },
            )
            assert last.status_code == 200
            last_page = last.json()
            assert last_page["total"] == 120
            assert last_page["limit"] == 50
            assert last_page["offset"] == 100
            assert len(last_page["items"]) == 20
            assert not (
                {item["id"] for item in first_page["items"]}
                & {item["id"] for item in last_page["items"]}
            )

            bad_status = await client.get(
                "/api/v1/admin/reviews", params={"status": "not-a-review-status"}
            )
            assert bad_status.status_code == 422
            bad_type = await client.get(
                "/api/v1/admin/reviews", params={"review_type": "source_version; DROP"}
            )
            assert bad_type.status_code == 422
    finally:
        if previous is None:
            del app.state.services
        else:
            app.state.services = previous
