from app.orchestration.runner import AnswerRunner
from app.retrieval.development_query import select_reviewed_candidates
from app.types import EvidenceSpan


def _row(row_id: str, locator: str, text: str) -> dict:
    return {
        "id": row_id,
        "text": text,
        "structural_chunk": {"metadata": {"legal_locator": locator}},
    }


def test_reviewed_query_candidates_cover_distinct_relevant_provisions() -> None:
    rows = (
        _row("reject-1", "section 22", "The right to reject goods."),
        _row("reject-2", "section 22", "The right to reject goods before delivery."),
        _row("reject-3", "section 22", "The right to reject goods after delivery."),
        _row("refund", "section 20", "A trader must give a refund."),
        _row("quality", "section 9", "Goods must be of satisfactory quality."),
    )
    hits = [{"id": row["id"], "_distance": rank / 10} for rank, row in enumerate(rows)]
    hits.insert(0, {"id": "unreviewed", "_distance": 0.0})

    selected = select_reviewed_candidates(
        "What are satisfactory quality, rejection and refund rights?", hits, rows,
        limit=4,
    )

    assert {hit["id"] for hit in selected} >= {"quality", "refund"}
    assert "unreviewed" not in {hit["id"] for hit in selected}
    assert len(selected) == 4


def test_development_evidence_merge_preserves_distinct_issue_queries() -> None:
    def span(locator: str, number: int) -> EvidenceSpan:
        return EvidenceSpan(
            id=f"e-{number}", source_version_id="act-1", chunk_id=f"chunk-{number}",
            text=f"Synthetic {locator} text {number}.", locator=locator,
            lane="primary_authority", jurisdiction="England", subject="consumer",
            content_sha256="a" * 64, index_build_id="build-1",
        )

    batches = (
        tuple(span("section 22", n) for n in range(8)),
        (span("section 9", 8), span("section 20", 9)),
        (span("section 21", 10), span("section 19", 11)),
    )
    selected = AnswerRunner._dedupe_legal_evidence(batches, balance_issue_queries=True)

    assert {item.locator for item in selected[:8]} >= {
        "section 9", "section 19", "section 20", "section 21", "section 22",
    }
    assert [item.locator for item in AnswerRunner._dedupe_legal_evidence(batches)[:8]] == [
        "section 22"
    ] * 8


def test_reviewed_provision_hints_survive_vector_and_prompt_budgets() -> None:
    rows = (
        *(
            _row(f"s20-{n}", "section 20", f"The trader refunds or returns goods {n}.")
            for n in range(4)
        ),
        _row("s23", "section 23", "Repair or replacement must be within a reasonable time."),
        _row("s31", "section 31", "Section 9 is not excluded."),
    )
    hits = [{"id": row["id"], "_distance": rank / 10} for rank, row in enumerate(rows)]
    selected = select_reviewed_candidates(
        "Consumer Rights Act 2015 section 20 refund timing, section 23 repair",
        hits, rows, limit=4,
    )
    assert {rows_id["id"] for rows_id in selected} >= {"s20-0", "s23"}

    def span(locator: str, number: int) -> EvidenceSpan:
        return EvidenceSpan(
            id=f"e-{number}", source_version_id="act-1", chunk_id=f"chunk-{number}",
            text=f"Synthetic {locator} text {number}.", locator=locator,
            lane="primary_authority", jurisdiction="England", subject="consumer",
            content_sha256="a" * 64, index_build_id="build-1",
        )

    batches = ((span("section 22", 0), span("section 31", 1)),
               (span("section 9", 2), span("section 24", 3)),
               (span("section 23", 4), span("section 19", 5), span("section 20", 6)))
    packet = AnswerRunner._dedupe_legal_evidence(
        batches, balance_issue_queries=True,
        preferred_locators=("section 9", "section 19", "section 20", "section 22", "section 23"),
    )
    assert [item.locator for item in packet[:5]] == [
        "section 9", "section 19", "section 20", "section 22", "section 23",
    ]


def test_explicit_duration_hint_selects_matching_reviewed_clause() -> None:
    rows = (
        _row("generic", "section 22", "The short-term rejection period ends."),
        _row("duration", "section 22", "The short-term rejection period ends after 30 days."),
    )
    hits = [{"id": row["id"], "_distance": rank / 10} for rank, row in enumerate(rows)]
    selected = select_reviewed_candidates(
        "Consumer Rights Act 2015 section 22 short-term rejection period 30 days",
        hits, rows, limit=1,
    )
    assert selected[0]["id"] == "duration"


def test_consumer_packet_keeps_refund_return_and_period_clauses() -> None:
    def span(locator: str, text: str, number: int) -> EvidenceSpan:
        return EvidenceSpan(
            id=f"span-{number}", source_version_id="cra", chunk_id=f"chunk-{number}",
            text=text, locator=locator, lane="primary_authority", jurisdiction="England",
            subject="consumer", content_sha256="a" * 64, index_build_id="build-1",
        )

    batches = (
        (span("section 22", "A short-term right may expire.", 0),),
        (span("section 9", "Goods must meet satisfactory quality.", 1),),
        (span("section 19", "The consumer may reject goods.", 2),
         span("section 23", "Repair is an alternative.", 3)),
        (span("section 20", "Refund within 14 days.", 4),
         span("section 20", "Goods available for collection.", 5),
         span("section 20", "Trader bears reasonable costs.", 6)),
        (span("section 22", "Right lasts 30 days after relevant trigger.", 7),),
    )
    queries = (
        "consumer reject", "Consumer Rights Act 2015 section 9",
        "Consumer Rights Act 2015 section 19 section 23",
        "refund deadline, collection and return costs section 20",
        "rejection period 30 days section 22",
    )
    packet = AnswerRunner._dedupe_legal_evidence(
        batches, balance_issue_queries=True, issue_queries=queries,
        preferred_locators=("section 9", "section 19", "section 20", "section 22", "section 23"),
    )
    for phrase in ("14 days", "collection", "reasonable costs", "30 days"):
        assert any(phrase in item.text for item in packet[:8])
