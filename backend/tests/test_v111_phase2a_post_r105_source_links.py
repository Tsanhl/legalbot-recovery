from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from scripts import review_v111_phase2a_post_r105_source_links as review


def _body(
    *,
    request_id: str,
    link_id: str,
    assessment: str,
    block_id: str | None = None,
    quote: str | None = None,
    proposition: str | None = None,
) -> dict[str, Any]:
    structured = {
        "schema": review.OUTPUT_SCHEMA,
        "row_source_link_id": link_id,
        "assessment": assessment,
        "selected_block_id": block_id,
        "exact_quote": quote,
        "atomic_proposition": proposition,
    }
    raw = review.json.dumps(structured, separators=(",", ":"))
    return {
        "request_id": request_id,
        "model_version": review.base.EXPECTED_MODEL_VERSION,
        "backend": review.base.MODEL_BACKEND,
        "deterministic": True,
        "finish_reason": "complete",
        "warnings": [],
        "usage": {"input_tokens": 100, "output_tokens": 40, "total_tokens": 140},
        "structured": structured,
        "raw_text": raw,
        "generation_ms": 1,
        "time_to_first_token_ms": 1,
        "peak_memory_gb": 1.0,
    }


def test_review_pool_preserves_top_eight_and_getty_paragraph_90() -> None:
    source = review._load_sources()
    ranking = next(
        row for row in source.ranking_rows if row["row_id"] == "live30-q30:issue-16"
    )
    packet = source.packet_by_link[str(ranking["row_source_link_id"])]
    pool = review._review_pool(ranking_row=ranking, packet_row=packet)
    ids = {item["block_id"] for item in pool}
    top_ids = {
        item["candidate_block_id"] for item in ranking["all_ranked_candidates"][:8]
    }
    paragraph_90 = next(
        item for item in packet["candidate_blocks"] if item["locator"] == "paragraph 90"
    )

    assert len(pool) <= review.MAX_REVIEW_CANDIDATES
    assert top_ids.issubset(ids)
    assert paragraph_90["block_id"] in ids
    projected_90 = next(
        item for item in pool if item["block_id"] == paragraph_90["block_id"]
    )
    assert "output from Stable Diffusion" in projected_90["text"]


def test_model_projection_stays_bounded_without_dropping_validation_hashes() -> None:
    source = review._load_sources()
    projections = []
    for ranking in source.ranking_rows:
        packet = source.packet_by_link[str(ranking["row_source_link_id"])]
        row_input = review._row_input(ranking_row=ranking, packet_row=packet)
        projection = review._model_input(row_input)
        projections.append(
            review.json.dumps(projection, ensure_ascii=False, separators=(",", ":"))
        )
        assert all("full_text_sha256" in item for item in row_input["candidates"])
        assert all(
            "full_text_sha256" not in item for item in projection["candidates"]
        )

    assert max(map(len, projections)) < 24_000
    budget = review._token_budget_evidence(source)
    assert budget["maximum_conservative_total_tokens"] < 8192
    assert budget["silent_truncation_permitted"] is False


def test_changed_plan_binds_the_exact_prior_debug_stop() -> None:
    prior = review._load_prior_debug_stop()

    assert prior["debug_stop_content_sha256"] == (
        review.EXPECTED_PRIOR_DEBUG_STOP_CONTENT_SHA256
    )
    assert prior["failure_fingerprint"] == review.EXPECTED_PRIOR_FAILURE_FINGERPRINT
    assert prior["required_execution_plan_change"][
        "remove_model_authored_reason_codes"
    ] is True


def test_structural_diagnostics_persist_no_model_prose() -> None:
    row_input = {"row_source_link_id": "a" * 64}
    diagnostics = review._safe_structured_diagnostics(
        {
            "schema": "wrong",
            "row_source_link_id": "b" * 64,
            "assessment": "unrelated",
            "selected_block_id": None,
            "exact_quote": "private model prose",
            "atomic_proposition": None,
        },
        row_input=row_input,
    )

    assert diagnostics["normalized_assessment_if_safe"] == "UNRELATED"
    assert diagnostics["schema_matches"] is False
    assert diagnostics["prose_values_persisted"] is False
    assert "private model prose" not in review.json.dumps(diagnostics)


def test_exact_quote_and_atomic_material_fact_validation() -> None:
    source = review._load_sources()
    ranking = next(
        row
        for row in source.ranking_rows
        if row["row_id"] == "live30-q28:issue-05"
        and row["authority_identity_id"] == "neutral-citation:[2009] EWHC 1076 (Ch)"
    )
    packet = source.packet_by_link[str(ranking["row_source_link_id"])]
    row_input = review._row_input(ranking_row=ranking, packet_row=packet)
    candidate = row_input["candidates"][0]
    quote = candidate["text"]
    proposition = (
        "Disadvantage to the donor is not a necessary ingredient of undue influence."
    )
    request_id = "fixture-request"
    body = _body(
        request_id=request_id,
        link_id=str(row_input["row_source_link_id"]),
        assessment="DIRECT",
        block_id=str(candidate["block_id"]),
        quote=quote,
        proposition=proposition,
    )

    finding, metrics = review._validate_response(
        body=body,
        row_input=row_input,
        request_id=request_id,
    )
    assert finding["assessment"] == "DIRECT"
    assert finding["exact_span_binding"]["quote"] == quote
    assert finding["finding_codes"] == ["model_direct_exact_span_advisory"]
    assert finding["finding_codes_derived_deterministically"] is True
    assert metrics["raw_output_character_count"] > 0


def test_altered_material_fact_is_blocked() -> None:
    source = review._load_sources()
    ranking = next(
        row
        for row in source.ranking_rows
        if row["row_id"] == "live30-q28:issue-05"
        and row["authority_identity_id"] == "neutral-citation:[2009] EWHC 1076 (Ch)"
    )
    packet = source.packet_by_link[str(ranking["row_source_link_id"])]
    row_input = review._row_input(ranking_row=ranking, packet_row=packet)
    candidate = row_input["candidates"][0]
    request_id = "fixture-request"
    body = _body(
        request_id=request_id,
        link_id=str(row_input["row_source_link_id"]),
        assessment="DIRECT",
        block_id=str(candidate["block_id"]),
        quote=candidate["text"][:150],
        proposition="The claim must be brought within 99 years.",
    )

    with pytest.raises(review.ReviewValidationError, match="unsupported_material_fact"):
        review._validate_response(
            body=body,
            row_input=row_input,
            request_id=request_id,
        )


def test_same_invalid_response_twice_holds_before_third_attempt(tmp_path: Path) -> None:
    source = review._load_sources()
    ranking = source.ranking_rows[0]
    packet = source.packet_by_link[str(ranking["row_source_link_id"])]
    (tmp_path / "checkpoints").mkdir()
    (tmp_path / "diagnostics").mkdir()
    calls = 0

    def invalid(envelope: dict[str, Any]) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return _body(
            request_id=str(envelope["request_id"]),
            link_id=str(packet["row_source_link_id"]),
            assessment="UNRELATED",
        ) | {"structured": {"schema": "wrong"}}

    checkpoint, abort = review._review_one(
        ordinal=1,
        ranking_row=ranking,
        packet_row=packet,
        invoke=invalid,
        runtime_identity_sha256="b" * 64,
        output_root=tmp_path,
        epoch_id="fixture-epoch",
    )

    assert calls == 2
    assert checkpoint["finding"]["assessment"] == (
        "HELD_FOR_DEBUG_BEFORE_ANY_THIRD_ATTEMPT"
    )
    assert checkpoint["same_failure_fingerprint_twice"] is True
    assert checkpoint["debug_required_before_any_third_attempt"] is True
    assert checkpoint["prior_attempt_count_under_superseded_plan"] == 2
    assert checkpoint["total_attempt_count_for_link"] == 4
    assert checkpoint["execution_plan_materially_changed"] is True
    assert abort is False
    assert len(list((tmp_path / "diagnostics").glob("*.json"))) == 2
