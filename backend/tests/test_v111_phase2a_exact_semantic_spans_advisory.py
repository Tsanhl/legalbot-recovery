from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
from scripts import verify_v111_phase2a_exact_semantic_spans_advisory as verifier


def _row() -> dict[str, Any]:
    text = "Section 11 requires the term to have been a fair and reasonable one."
    chunk = verifier._exact_span_partition(
        {
            "chunk_id": "chunk-1",
            "locator": "section 11",
            "heading_path": "The reasonableness test",
            "text": text,
            "text_sha256": verifier._sha256(text.encode()),
        }
    )
    return {
        "row_id": "live30-q01:issue-01",
        "issue_label": "limitation clause",
        "legal_domain": "contract",
        "evidence_candidates": [
            {
                "authority_identity_id": "ukpga:1977:50",
                "source_version_id": "source-version-1",
                "title": "Unfair Contract Terms Act 1977",
                "canonical_url": "https://www.legislation.gov.uk/ukpga/1977/50",
                "as_of_date": "2026-08-14",
                "currentness_status": "latest_available",
                "locator_hint": "section 11",
                "candidate_source_metadata": {"currentness_verified": True},
                "chunks": [chunk],
            }
        ],
    }


def _body(
    row_input: dict[str, Any],
    request_id: str,
    *,
    chunk_id: str = "chunk-1",
    proposition: str = "Section 11 requires a term to have been fair and reasonable.",
    span_id: str | None = None,
) -> dict[str, Any]:
    selected_span_id = span_id or row_input["rows"][0]["evidence_candidates"][0][
        "chunks"
    ][0]["exact_span_options"][0]["span_id"]
    structured = {
        "schema": verifier.OUTPUT_SCHEMA,
        "case_id": row_input["case_id"],
        "rows": [
            {
                "row_id": row_input["rows"][0]["row_id"],
                "assessment": "DIRECT",
                "proposition": proposition,
                "support": {"chunk_id": chunk_id, "span_id": selected_span_id},
            }
        ],
    }
    raw = json.dumps(structured)
    return {
        "request_id": request_id,
        "model_version": verifier.EXPECTED_MODEL_VERSION,
        "backend": verifier.MODEL_BACKEND,
        "deterministic": True,
        "warnings": [],
        "finish_reason": "stop",
        "usage": {"input_tokens": 10, "output_tokens": 10, "total_tokens": 20},
        "generation_ms": 1,
        "time_to_first_token_ms": 1,
        "peak_memory_gb": 1.0,
        "raw_text": raw,
        "structured": structured,
    }


def _input() -> dict[str, Any]:
    return verifier._build_input(
        batch_ordinal=1,
        rows=[_row()],
        case={
            "case_id": "live30-q01",
            "subject": "contract",
            "question": "Assess the limitation clause.",
        },
        repair_error_code=None,
    )


def test_exact_span_and_typed_facts_are_bound() -> None:
    row_input = _input()
    assert row_input["schema"] == (
        "legalbot.v111.phase2a.exact-semantic-span-input.v3"
    )
    assert row_input["scenario"] == "Assess the limitation clause."
    assert row_input["scenario_text_supplied_to_exact_rule_extractor"] is True
    assert row_input["scenario_content_sha256"] == verifier._sha256(
        row_input["scenario"].encode()
    )
    findings, _metrics = verifier._validate_model_response(
        body=_body(row_input, "request-1"),
        row_input=row_input,
        request_id="request-1",
    )

    finding = findings[0]
    assert finding["assessment"] == "DIRECT_EXACT_SPAN_ADVISORY"
    assert finding["exact_span_binding"]["chunk_id"] == "chunk-1"
    assert finding["exact_span_binding"]["span_id"].startswith("span-")
    assert finding["exact_span_binding"]["start_character"] == 0
    assert finding["exact_span_binding"]["exact_text"] == (
        "Section 11 requires the term to have been a fair and reasonable one."
    )
    assert finding["deterministic_checks"]["model_reproduced_quote_text"] is False
    assert finding["deterministic_checks"]["unsupported_material_fact_count"] == 0
    assert finding["owner_outcome"] is None
    assert finding["technical_qualification_assigned"] is False


def test_altered_provision_and_invented_chunk_are_rejected() -> None:
    row_input = _input()
    try:
        verifier._validate_model_response(
            body=_body(
                row_input,
                "request-1",
                proposition="Section 12 requires a term to have been fair and reasonable.",
            ),
            row_input=row_input,
            request_id="request-1",
        )
    except verifier.SemanticValidationError as exc:
        assert exc.code == "structured_output_unsupported_material_fact"
    else:
        raise AssertionError("altered provision was accepted")

    try:
        verifier._validate_model_response(
            body=_body(row_input, "request-2", chunk_id="invented"),
            row_input=row_input,
            request_id="request-2",
        )
    except verifier.SemanticValidationError as exc:
        assert exc.code == "structured_output_invented_chunk"
    else:
        raise AssertionError("invented chunk was accepted")

    try:
        verifier._validate_model_response(
            body=_body(row_input, "request-3", span_id="invented-span"),
            row_input=row_input,
            request_id="request-3",
        )
    except verifier.SemanticValidationError as exc:
        assert exc.code == "structured_output_invented_span"
    else:
        raise AssertionError("invented span was accepted")


def test_altered_later_identifier_in_provision_series_is_rejected() -> None:
    row = _row()
    source_text = "Sections 15, 16, 20 and 21 apply to the obligations."
    row["evidence_candidates"][0]["chunks"] = [
        verifier._exact_span_partition(
            {
                "chunk_id": "chunk-list",
                "locator": "sections 15, 16, 20 and 21",
                "heading_path": "Interpretation",
                "text": source_text,
                "text_sha256": verifier._sha256(source_text.encode()),
            }
        )
    ]
    row_input = verifier._build_input(
        batch_ordinal=1,
        rows=[row],
        case={
            "case_id": "live30-q01",
            "subject": "contract",
            "question": "Assess the limitation clause.",
        },
        repair_error_code=None,
    )

    try:
        verifier._validate_model_response(
            body=_body(
                row_input,
                "request-list",
                chunk_id="chunk-list",
                proposition="Sections 15, 16, 20 and 22 apply to the obligations.",
            ),
            row_input=row_input,
            request_id="request-list",
        )
    except verifier.SemanticValidationError as exc:
        assert exc.code == "structured_output_unsupported_material_fact"
    else:
        raise AssertionError("altered later provision identifier was accepted")


def test_exact_span_partition_is_complete_and_byte_preserving() -> None:
    text = (
        "First proposition applies. " * 30
        + "Second proposition contains OCR negligen ce and th e exact spacing. " * 15
    )
    chunk = verifier._exact_span_partition(
        {
            "chunk_id": "chunk-long",
            "locator": "p 65",
            "heading_path": "",
            "text": text,
            "text_sha256": verifier._sha256(text.encode()),
        }
    )

    options = chunk["exact_span_options"]
    assert len(options) > 1
    assert "".join(option["exact_text"] for option in options) == text
    assert all(
        len(option["exact_text"]) <= verifier.MAX_QUOTE_CHARACTERS
        for option in options
    )
    assert options[0]["start_character"] == 0
    assert options[-1]["end_character_exclusive"] == len(text)
    assert chunk["source_text_reproduced_by_partition_sha256"] == chunk["text_sha256"]


def test_proposition_contract_reports_type_missing_and_length_separately() -> None:
    row_input = _input()

    non_string = _body(row_input, "request-type")
    non_string["structured"]["rows"][0]["proposition"] = 11
    try:
        verifier._validate_model_response(
            body=non_string,
            row_input=row_input,
            request_id="request-type",
        )
    except verifier.SemanticValidationError as exc:
        assert exc.code == "structured_output_proposition_type_invalid"
    else:
        raise AssertionError("non-string proposition was accepted")

    try:
        verifier._validate_model_response(
            body=_body(row_input, "request-missing", proposition=""),
            row_input=row_input,
            request_id="request-missing",
        )
    except verifier.SemanticValidationError as exc:
        assert exc.code == "structured_output_proposition_missing"
        assert exc.diagnostics == {"row_id": "live30-q01:issue-01"}
    else:
        raise AssertionError("missing proposition was accepted")

    too_long = "A" * (verifier.MAX_PROPOSITION_CHARACTERS + 1)
    try:
        verifier._validate_model_response(
            body=_body(row_input, "request-long", proposition=too_long),
            row_input=row_input,
            request_id="request-long",
        )
    except verifier.SemanticValidationError as exc:
        assert exc.code == "structured_output_proposition_too_long"
        assert exc.diagnostics["proposition_character_count"] == len(too_long)
        assert (
            exc.diagnostics["maximum_proposition_characters"]
            == verifier.MAX_PROPOSITION_CHARACTERS
        )
    else:
        raise AssertionError("overlong proposition was accepted")


def test_after_ceiling_source_cannot_enter_semantic_review() -> None:
    text = "Section 1 creates an offence."
    locator_record = {
        "resolved_selections": [
            {
                "authority_identity_id": "ukpga:1990:18",
                "locator_hint": "section 1",
                "candidate_source_metadata": {},
                "source_identity": {
                    "id": "source-version-after-ceiling",
                    "title": "Computer Misuse Act 1990",
                    "canonical_url": (
                        "https://www.legislation.gov.uk/ukpga/1990/18/"
                        "2026-08-17/data.xml"
                    ),
                    "as_of_date": "2026-08-17",
                    "currentness_status": "latest_available_revised_snapshot",
                },
                "exact_chunks": [
                    {
                        "chunk_id": "chunk-after-ceiling",
                        "locator": "section 1",
                        "heading_path": "Unauthorised access",
                        "text": text,
                        "text_sha256": verifier._sha256(text.encode()),
                    }
                ],
            }
        ]
    }
    try:
        verifier._review_row(
            {
                "item_id": "live60-q48:issue-01",
                "issue_label": "unauthorised access",
                "legal_domain": "cybercrime",
            },
            locator_record,
            {},
        )
    except ValueError as exc:
        assert str(exc) == "phase2a_semantic_source_after_target_ceiling"
    else:
        raise AssertionError("after-ceiling source entered semantic review")


def test_review_projection_exposes_only_the_deterministic_top_candidate() -> None:
    direct_text = (
        "section 11 Every contract to supply goods by description is to be treated "
        "as including a term that the goods will match the description."
    )
    distractor_text = "section 12 A service may have a description."

    def selection(
        authority: str, locator: str, chunk_id: str, text: str, score: float
    ) -> dict[str, Any]:
        return {
            "authority_identity_id": authority,
            "locator_hint": locator,
            "candidate_source_metadata": {
                "already_in_sealed_candidate": True,
                "combined_advisory_score": score,
                "identity_verified": True,
            },
            "source_identity": {
                "id": f"source-version-{chunk_id}",
                "authority_identity_id": authority,
                "title": authority,
                "canonical_url": f"https://www.legislation.gov.uk/{authority}",
                "version_sha256": "a" * 64,
                "stable_identifier": authority,
                "lane": "primary_authority",
                "document_status": "citable",
                "as_of_date": "2026-08-14",
                "currentness_status": "latest_available_revised_snapshot",
            },
            "selection_origin": "TEST",
            "whole_chunks_only": True,
            "silent_text_truncation": False,
            "complete_locator_result_used": True,
            "omitted_chunk_count": 0,
            "omitted_chunk_identities_sha256": "a" * 64,
            "selection_content_sha256": "b" * 64,
            "exact_chunks": [
                {
                    "chunk_id": chunk_id,
                    "locator": locator,
                    "heading_path": locator,
                    "text": text,
                    "text_sha256": verifier._sha256(text.encode()),
                }
            ],
        }

    selections = [
        selection("ukpga:2015:15", "section 11", "direct", direct_text, 2.0),
        selection(
            "ukpga:1982:29",
            "section 12",
            "distractor",
            distractor_text,
            1.0,
        ),
    ]
    candidate_sources = {
        str(item["source_identity"]["id"]): {
            "authority_identity_id": item["authority_identity_id"],
            "version_sha256": item["source_identity"]["version_sha256"],
            "stable_identifier": item["source_identity"]["stable_identifier"],
            "canonical_url": item["source_identity"]["canonical_url"],
            "lane": "primary_authority",
            "document_status": "citable",
        }
        for item in selections
    }
    projected = verifier._review_row(
        {
            "item_id": "live30-q02:issue-03",
            "issue_label": "description",
            "legal_domain": "consumer",
        },
        {"resolved_selections": selections},
        candidate_sources,
    )

    assert projected is not None
    assert verifier.MAX_REVIEW_EVIDENCE_CANDIDATES_PER_ROW == 1
    assert len(projected["evidence_candidates"]) == 1
    assert (
        projected["evidence_candidates"][0]["authority_identity_id"]
        == "ukpga:2015:15"
    )


def test_scenario_aware_prior_selection_precedes_issue_label_only_recovery() -> None:
    direct_text = "section 11 Goods supplied by description must match it."
    prior_text = "The context-specific supplied rule applies."

    def selection(
        *, source_id: str, authority: str, text: str, origin: str, score: float
    ) -> dict[str, Any]:
        return {
            "authority_identity_id": authority,
            "locator_hint": "section 1",
            "candidate_source_metadata": {
                "already_in_sealed_candidate": True,
                "combined_advisory_score": score,
                "identity_verified": True,
            },
            "source_identity": {
                "id": source_id,
                "authority_identity_id": authority,
                "title": authority,
                "canonical_url": f"https://www.legislation.gov.uk/{authority}",
                "version_sha256": "a" * 64,
                "stable_identifier": authority,
                "lane": "primary_authority",
                "document_status": "citable",
                "as_of_date": "2026-08-14",
                "currentness_status": "latest_available_revised_snapshot",
            },
            "selection_origin": origin,
            "whole_chunks_only": True,
            "silent_text_truncation": False,
            "complete_locator_result_used": True,
            "omitted_chunk_count": 0,
            "omitted_chunk_identities_sha256": "a" * 64,
            "selection_content_sha256": "b" * 64,
            "exact_chunks": [
                {
                    "chunk_id": f"chunk-{source_id}",
                    "locator": "section 1",
                    "heading_path": "section 1",
                    "text": text,
                    "text_sha256": verifier._sha256(text.encode()),
                }
            ],
        }

    global_recovery = selection(
        source_id="source-version-global",
        authority="ukpga:2015:15",
        text=direct_text,
        origin="GLOBAL_ISSUE_LABEL_RECOVERY",
        score=9.0,
    )
    prior = selection(
        source_id="source-version-prior",
        authority="ukpga:2020:1",
        text=prior_text,
        origin="PRIOR_EXACT_SELECTION_REPROJECTED",
        score=1.0,
    )
    candidate_sources = {
        str(item["source_identity"]["id"]): {
            "authority_identity_id": item["authority_identity_id"],
            "version_sha256": item["source_identity"]["version_sha256"],
            "stable_identifier": item["source_identity"]["stable_identifier"],
            "canonical_url": item["source_identity"]["canonical_url"],
            "lane": "primary_authority",
            "document_status": "citable",
        }
        for item in (global_recovery, prior)
    }

    projected = verifier._review_row(
        {
            "item_id": "live30-q02:issue-03",
            "issue_label": "description",
            "legal_domain": "consumer",
        },
        {"resolved_selections": [global_recovery, prior]},
        candidate_sources,
    )

    assert projected is not None
    assert projected["evidence_candidates"][0]["source_version_id"] == (
        "source-version-prior"
    )


def test_exact_candidate_manifest_membership_overrides_stale_boolean_metadata() -> None:
    text = "The exact rule governs the issue."

    def selection(source_id: str, authority: str, score: float) -> dict[str, Any]:
        return {
            "authority_identity_id": authority,
            "locator_hint": "section 1",
            "candidate_source_metadata": {
                "already_in_sealed_candidate": True,
                "combined_advisory_score": score,
                "identity_verified": True,
            },
            "source_identity": {
                "id": source_id,
                "authority_identity_id": authority,
                "title": authority,
                "canonical_url": f"https://www.legislation.gov.uk/{authority}",
                "version_sha256": "a" * 64,
                "stable_identifier": authority,
                "lane": "primary_authority",
                "document_status": "citable",
                "as_of_date": "2026-08-14",
                "currentness_status": "latest_available_revised_snapshot",
            },
            "selection_origin": "TEST",
            "whole_chunks_only": True,
            "silent_text_truncation": False,
            "complete_locator_result_used": True,
            "omitted_chunk_count": 0,
            "omitted_chunk_identities_sha256": "a" * 64,
            "selection_content_sha256": "b" * 64,
            "exact_chunks": [
                {
                    "chunk_id": f"chunk-{source_id}",
                    "locator": "section 1",
                    "heading_path": "section 1",
                    "text": text,
                    "text_sha256": verifier._sha256(text.encode()),
                }
            ],
        }

    stale = selection("source-version-stale", "ukpga:2000:1", 9.0)
    admitted = selection("source-version-admitted", "ukpga:2000:2", 1.0)
    projected = verifier._review_row(
        {
            "item_id": "live30-q01:issue-01",
            "issue_label": "exact rule",
            "legal_domain": "contract",
        },
        {"resolved_selections": [stale, admitted]},
        {
            "source-version-admitted": {
                "authority_identity_id": "ukpga:2000:2",
                "version_sha256": "a" * 64,
                "stable_identifier": "ukpga:2000:2",
                "canonical_url": "https://www.legislation.gov.uk/ukpga:2000:2",
                "lane": "primary_authority",
                "document_status": "citable",
            }
        },
    )

    assert projected is not None
    assert projected["evidence_candidates"][0]["source_version_id"] == (
        "source-version-admitted"
    )


def test_pinned_candidate_manifest_excludes_known_misclassified_source() -> None:
    sources, digest, file_digest = verifier._load_candidate_manifest(
        verifier.DEFAULT_CANDIDATE_MANIFEST
    )

    assert digest == verifier.EXPECTED_CANDIDATE_MANIFEST_SHA256
    assert len(sources) == verifier.EXPECTED_CANDIDATE_SOURCE_COUNT
    assert len(file_digest) == 64
    assert "source-version-5e1963ec7ed2cb7e17094f9c447deaf9a3a21c5a" not in sources


def test_full_advisory_batches_are_singleton_after_multirow_false_gap() -> None:
    first = _row()
    second = {**_row(), "row_id": "live30-q01:issue-02"}
    batches, oversized = verifier._pack_batches(
        [first, second],
        {
            "live30-q01": {
                "case_id": "live30-q01",
                "subject": "contract",
                "question": "Assess the limitation clause.",
            }
        },
    )

    assert verifier.BATCH_SIZE == 1
    assert oversized == []
    assert [[row["row_id"] for row in batch] for batch in batches] == [
        ["live30-q01:issue-01"],
        ["live30-q01:issue-02"],
    ]


def test_model_http_limit_error_is_machine_specific_and_sanitized(
    monkeypatch,
) -> None:
    request = httpx.Request("POST", "http://127.0.0.1:8779/api/v1/generate")
    health_request = httpx.Request("GET", "http://127.0.0.1:8779/api/v1/health")

    class FakeClient:
        def __init__(self, **_kwargs: Any) -> None:
            pass

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *_args: Any) -> None:
            return None

        def get(self, _url: str) -> httpx.Response:
            return httpx.Response(
                200,
                request=health_request,
                json={
                    "backend": verifier.MODEL_BACKEND,
                    "model_id": verifier.EXPECTED_MODEL_ID,
                    "model_loaded": True,
                    "stub_mode": False,
                    "memory_profile": {
                        "context_window_tokens": 8192,
                        "max_output_tokens": 2048,
                        "single_flight_generation": True,
                    },
                },
            )

        def post(self, _url: str, *, json: dict[str, Any]) -> httpx.Response:
            return httpx.Response(
                422,
                request=request,
                json={
                    "request_id": json["request_id"],
                    "error": {
                        "code": "safe_limit_exceeded",
                        "message": "sensitive runtime detail is not persisted",
                    },
                },
            )

    monkeypatch.setattr(verifier.httpx, "Client", FakeClient)
    invoke, _runtime = verifier._http_invoker("http://127.0.0.1:8779", 1.0)
    envelope, _request_id = verifier._envelope(_input())

    try:
        invoke(envelope)
    except verifier.SemanticValidationError as exc:
        assert exc.code == "model_http_safe_limit_exceeded"
        assert exc.diagnostics["http_status"] == 422
        assert exc.diagnostics["service_error_code"] == "safe_limit_exceeded"
        assert exc.diagnostics["request_id_matches"] is True
        assert len(str(exc.diagnostics["response_body_sha256"])) == 64
        assert "sensitive" not in json.dumps(exc.diagnostics)
    else:
        raise AssertionError("model HTTP limit failure was accepted")


def test_two_unchanged_failures_persist_diagnostics_and_hold(tmp_path: Path) -> None:
    calls = 0

    def invalid(envelope: dict[str, Any]) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return _body(
            envelope["payload"],
            envelope["request_id"],
            chunk_id="invented",
        )

    checkpoints = tmp_path / "checkpoints"
    diagnostics = tmp_path / "diagnostics"
    checkpoints.mkdir()
    diagnostics.mkdir()
    result = verifier._review_batch(
        ordinal=1,
        rows=[_row()],
        case={
            "case_id": "live30-q01",
            "subject": "contract",
            "question": "Assess the limitation clause.",
        },
        invoke=invalid,
        checkpoints_root=checkpoints,
        diagnostics_root=diagnostics,
        runtime_identity_sha256="a" * 64,
    )

    assert calls == 2
    assert result["status"] == "HELD_FOR_DEBUG_BEFORE_ANY_THIRD_ATTEMPT"
    assert result["same_failure_fingerprint_twice"] is True
    assert len(list(diagnostics.glob("*.json"))) == 2
    assert len(list(checkpoints.glob("*.json"))) == 1
