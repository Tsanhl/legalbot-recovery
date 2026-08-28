from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from scripts import plan_v111_phase2a_material_gap_research as planner


def _model_body(*, case_id: str, rows: list[dict[str, object]]) -> dict[str, object]:
    return {
        "request_id": "request-1",
        "model_version": planner.EXPECTED_MODEL_VERSION,
        "backend": planner.MODEL_BACKEND,
        "deterministic": True,
        "finish_reason": "stop",
        "warnings": [],
        "peak_memory_gb": 1.0,
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "structured": {
            "schema": planner.OUTPUT_SCHEMA,
            "case_id": case_id,
            "rows": rows,
        },
        "raw_text": "not persisted",
    }


def test_advisory_batch_size_is_four_rows() -> None:
    rows = [{"case_id": "live30-q01", "row_id": f"row-{index}"} for index in range(9)]

    batches = planner._batch_rows(rows)

    assert [len(batch) for batch in batches] == [4, 4, 1]


def test_advisory_envelope_uses_reduced_output_cap() -> None:
    envelope, _request_id = planner._envelope(
        {
            "schema": "legalbot.v111.phase2a.material-gap-plan-input.v1",
            "case_id": "live30-q01",
            "rows": [],
        }
    )

    assert planner.MAX_OUTPUT_TOKENS == 900
    assert envelope["max_tokens"] == 900


def test_advisory_envelope_accepts_smaller_debug_budget_only() -> None:
    envelope, _request_id = planner._envelope(
        {
            "schema": "legalbot.v111.phase2a.material-gap-plan-input.v1",
            "case_id": "live30-q01",
            "rows": [],
        },
        max_output_tokens=512,
    )

    assert envelope["max_tokens"] == 512
    with pytest.raises(ValueError, match="phase2a_gap_plan_output_token_budget_invalid"):
        planner._envelope({}, max_output_tokens=planner.MAX_OUTPUT_TOKENS + 1)


def test_transport_timeout_is_held_after_one_attempt(tmp_path: Path) -> None:
    checkpoints = tmp_path / "checkpoints"
    diagnostics = tmp_path / "diagnostics"
    checkpoints.mkdir()
    diagnostics.mkdir()
    calls = 0

    def invoke(_envelope: dict[str, object]) -> dict[str, object]:
        nonlocal calls
        calls += 1
        request = httpx.Request("POST", "http://127.0.0.1:8779/api/v1/generate")
        raise httpx.ReadTimeout("bounded test timeout", request=request)

    held = planner._review_batch(
        ordinal=1,
        batch=[
            {
                "row_id": "live30-q01:issue-01",
                "issue_label": "breach",
                "legal_domain": "contract",
                "triage_class": "UNRESOLVED_SOURCE_PLAN_GAP",
            }
        ],
        case={
            "case_id": "live30-q01",
            "subject": "contract",
            "question": "Synthetic immutable scenario",
        },
        sources=[],
        candidate_authorities=frozenset(),
        invoke=invoke,
        checkpoints_root=checkpoints,
        diagnostics_root=diagnostics,
    )

    assert calls == 1
    assert held["status"] == "HELD_FOR_DEBUG_BEFORE_ANY_RETRY"
    assert held["attempt_count"] == 1
    assert held["failure_fingerprints"]
    assert held["nonrepairable_runtime_failure"] is True
    assert held["repairable_model_output_failure"] is False
    assert held["debug_required_before_retry"] is True
    assert held["debug_required_before_third_attempt"] is False
    assert len(list(checkpoints.glob("*.json"))) == 1
    assert len(list(diagnostics.glob("*-a1.json"))) == 1
    assert not list(diagnostics.glob("*-a2.json"))


def test_issue_link_accepts_narrow_doctrinal_aliases() -> None:
    assert planner._issue_token_linked(
        "classification of contractual terms",
        "A condition, warranty or innominate term controls the available remedy.",
    )
    assert planner._issue_token_linked(
        "termination",
        "A repudiatory breach may entitle the innocent party to discharge the contract.",
    )
    assert planner._issue_token_linked(
        "causation",
        "The loss must have been caused by the defendant's breach.",
    )
    assert planner._issue_token_linked(
        "remoteness",
        "Loss is recoverable only if it was reasonably foreseeable when contracted.",
    )
    assert planner._issue_token_linked(
        "mitigation",
        "The injured party must take reasonable steps to mitigate its loss.",
    )
    assert not planner._issue_token_linked(
        "causation",
        "A warranty is a contractual promise.",
    )


def test_issue_link_normalizes_consonant_y_plural_without_false_rejection() -> None:
    assert planner._light_stem("remedies") == "remedy"
    assert planner._light_stem("remedied") == "remedy"
    assert planner._issue_token_linked(
        "remedies",
        "A court may grant a proprietary remedy where the claim succeeds.",
    )


def test_issue_link_normalizes_compounds_possessives_and_known_morphology() -> None:
    assert planner._light_stem("priorities") == "prior"
    assert planner._light_stem("priority") == "prior"
    assert planner._light_stem("liability") == "liable"
    assert planner._light_stem("defences") == "defence"
    assert planner._issue_token_linked(
        "public-authority liability",
        "Public authorities may be liable for incompatible acts.",
    )
    assert planner._issue_token_linked(
        "set-off",
        "Mutual debts may be set off in the insolvency.",
    )
    assert planner._issue_token_linked(
        "principal’s duties",
        "A principal owes the identified duty.",
    )
    assert planner._issue_token_linked(
        "constitution and imperfect gifts",
        "A trust is constituted only when the transfer is complete.",
    )
    assert planner._issue_token_linked(
        "testamentary capacity",
        "The testator must understand the will and possess a sound mind.",
    )
    assert planner._issue_token_linked(
        "causal relevance",
        "The insurer must prove causation of the loss.",
    )
    assert planner._issue_token_linked(
        "notification",
        "The insured must give notice when a claim arises.",
    )
    assert planner._issue_token_linked(
        "tupe",
        "The Transfer of Undertakings Regulations protect employment rights.",
    )
    assert planner._issue_token_linked(
        "interim relief",
        "A freezing order may be granted where assets risk dissipation.",
    )
    assert planner._issue_token_linked(
        "corporate residence",
        "A company may be UK resident where central management is exercised.",
    )
    assert not planner._issue_token_linked(
        "unfair relationships",
        "A bank may be liable where it knowingly participates in undue influence.",
    )


def test_failure_fingerprint_is_stable_across_repair_envelopes() -> None:
    first = planner._failure_fingerprint(
        batch_ordinal=1,
        row_ids=["live30-q01:issue-01"],
        error_code="structured_output_proposition_not_linked_to_issue",
        validation_context={
            "row_id": "live30-q01:issue-01",
            "issue_label": "breach",
            "proposition_sha256": "1" * 64,
        },
    )
    second = planner._failure_fingerprint(
        batch_ordinal=1,
        row_ids=["live30-q01:issue-01"],
        error_code="structured_output_proposition_not_linked_to_issue",
        validation_context={
            "row_id": "live30-q01:issue-01",
            "issue_label": "breach",
            "proposition_sha256": "2" * 64,
        },
    )

    assert first == second


def test_failure_fingerprint_changes_for_different_affected_row() -> None:
    first = planner._failure_fingerprint(
        batch_ordinal=1,
        row_ids=["live30-q01:issue-01", "live30-q01:issue-02"],
        error_code="structured_output_proposition_not_linked_to_issue",
        validation_context={
            "row_id": "live30-q01:issue-01",
            "issue_label": "breach",
        },
    )
    second = planner._failure_fingerprint(
        batch_ordinal=1,
        row_ids=["live30-q01:issue-01", "live30-q01:issue-02"],
        error_code="structured_output_proposition_not_linked_to_issue",
        validation_context={
            "row_id": "live30-q01:issue-02",
            "issue_label": "classification of contractual terms",
        },
    )

    assert first != second


def test_failure_fingerprint_binds_changed_execution_plan() -> None:
    first = planner._failure_fingerprint(
        batch_ordinal=1,
        row_ids=["live30-q01:issue-01"],
        error_code="read_timeout",
        validation_context={},
        execution_plan_sha256="1" * 64,
    )
    second = planner._failure_fingerprint(
        batch_ordinal=1,
        row_ids=["live30-q01:issue-01"],
        error_code="read_timeout",
        validation_context={},
        execution_plan_sha256="2" * 64,
    )

    assert first != second


def test_selected_source_registry_tracks_only_evidence_relevant_identity() -> None:
    source = SimpleNamespace(
        source_version_id="source-version-1",
        authority_identity_id="ukpga:2000:1",
        stable_identifier="ukpga:2000:1:latest-available@2026-08-14",
        version_sha256="1" * 64,
        as_of_date="2026-08-14",
        currentness_status="latest_available_revised_snapshot",
        identity_verified=True,
        currentness_verified=True,
        family="legislation_or_procedural_instrument",
        subject="general",
        title="Display title ignored by the registry identity",
        canonical_url="https://example.invalid/ignored",
    )

    registry = planner._selected_source_registry([source])

    assert registry == [
        {
            "source_version_id": "source-version-1",
            "authority_identity_id": "ukpga:2000:1",
            "stable_identifier": "ukpga:2000:1:latest-available@2026-08-14",
            "version_sha256": "1" * 64,
            "as_of_date": "2026-08-14",
            "currentness_status": "latest_available_revised_snapshot",
            "identity_verified": True,
            "currentness_verified": True,
            "family": "legislation_or_procedural_instrument",
            "catalogue_subject": "general",
        }
    ]


def test_top_level_failure_is_persisted_before_output_exists(tmp_path: Path) -> None:
    output = tmp_path / "failed"

    planner._persist_top_level_failure(
        output,
        ValueError("phase2a_gap_plan_selected_source_registry_changed"),
    )

    failure = json.loads((output / "FAILURE.json").read_bytes())
    assert failure["error_code"] == ("phase2a_gap_plan_selected_source_registry_changed")
    assert failure["automatic_indexing"] is False
    assert failure["phase2b_authorized"] is False
    material = dict(failure)
    supplied = material.pop("failure_content_sha256")
    assert supplied == planner._sealed(material)


def test_invented_authority_repair_requires_supplied_id_or_search() -> None:
    value = planner._build_input(
        ordinal=3,
        batch=[
            {
                "row_id": "live30-q04:issue-01",
                "issue_label": "homicide",
                "legal_domain": "criminal",
                "triage_class": "UNRESOLVED_SOURCE_PLAN_GAP",
            }
        ],
        case={
            "case_id": "live30-q04",
            "subject": "criminal",
            "question": "Synthetic immutable scenario",
        },
        sources=[],
        candidate_authorities=frozenset(),
        repair_error="structured_output_invented_authority",
    )

    assert "copied character-for-character" in value["repair_instruction"]
    assert "selections []" in value["repair_instruction"]


def test_repair_instructions_are_specific_and_preserve_safe_context() -> None:
    common = {
        "ordinal": 3,
        "batch": [
            {
                "row_id": "live30-q04:issue-01",
                "issue_label": "homicide",
                "legal_domain": "criminal",
                "triage_class": "UNRESOLVED_SOURCE_PLAN_GAP",
            }
        ],
        "case": {
            "case_id": "live30-q04",
            "subject": "criminal",
            "question": "Synthetic immutable scenario",
        },
        "sources": [],
        "candidate_authorities": frozenset(),
    }
    overlength = planner._build_input(
        **common,
        repair_error="structured_output_proposition_too_long",
        repair_context={
            "row_id": "live30-q04:issue-01",
            "issue_label": "homicide",
            "observed_characters": 271,
            "maximum_characters": 240,
            "proposition_sha256": "1" * 64,
        },
    )
    assert "no more than 240 characters" in overlength["repair_instruction"]
    assert overlength["rejected_output_context"] == {
        "issue_label": "homicide",
        "maximum_characters": 240,
        "observed_characters": 271,
        "row_id": "live30-q04:issue-01",
    }

    row_invalid = planner._build_input(
        **common,
        repair_error="structured_output_row_invalid",
        repair_context={
            "row_id": "live30-q04:issue-01",
            "output_index": 0,
            "observed_classification": "ANALYTICAL_DIMENSION",
            "expected_classification": "LEGAL_PROPOSITION",
        },
    )
    assert "row_id exactly once" in row_invalid["repair_instruction"]
    assert "advisory_classification_hint exactly" in row_invalid["repair_instruction"]


def test_row_invalid_and_overlength_diagnostics_identify_exact_row() -> None:
    row_input = {
        "case_id": "live30-q04",
        "rows": [
            {
                "row_id": "live30-q04:issue-01",
                "issue_label": "homicide",
                "advisory_classification_hint": "LEGAL_PROPOSITION",
            }
        ],
        "authorities": [],
    }
    invalid_row = {
        "row_id": "live30-q04:issue-01",
        "classification": "ANALYTICAL_DIMENSION",
        "proposition": "",
        "selections": [],
        "search_query": "",
    }
    with pytest.raises(planner.GapPlanValidationError) as caught:
        planner._validate_model_response(
            body=_model_body(case_id="live30-q04", rows=[invalid_row]),
            row_input=row_input,
            request_id="request-1",
        )
    assert caught.value.code == "structured_output_row_invalid"
    assert caught.value.context == {
        "output_index": 0,
        "row_id": "live30-q04:issue-01",
        "issue_label": "homicide",
        "observed_classification": "ANALYTICAL_DIMENSION",
        "expected_classification": "LEGAL_PROPOSITION",
        "row_id_supplied": True,
        "classification_allowed": True,
    }

    overlength_row = {
        **invalid_row,
        "classification": "LEGAL_PROPOSITION",
        "proposition": "Homicide " + ("x" * planner.MAX_PROPOSITION_CHARACTERS),
        "search_query": "England Wales official homicide authority",
    }
    with pytest.raises(planner.GapPlanValidationError) as caught:
        planner._validate_model_response(
            body=_model_body(case_id="live30-q04", rows=[overlength_row]),
            row_input=row_input,
            request_id="request-1",
        )
    assert caught.value.code == "structured_output_proposition_too_long"
    assert caught.value.context["row_id"] == "live30-q04:issue-01"
    assert caught.value.context["observed_characters"] > 240
    assert caught.value.context["maximum_characters"] == 240


def test_invented_authority_diagnostic_identifies_row() -> None:
    row_input = {
        "case_id": "live30-q04",
        "rows": [
            {
                "row_id": "live30-q04:issue-01",
                "issue_label": "homicide",
                "advisory_classification_hint": "LEGAL_PROPOSITION",
            }
        ],
        "authorities": [{"id": "ukpga:1957:11"}],
    }
    body = {
        "request_id": "request-1",
        "model_version": planner.EXPECTED_MODEL_VERSION,
        "backend": planner.MODEL_BACKEND,
        "deterministic": True,
        "finish_reason": "stop",
        "warnings": [],
        "peak_memory_gb": 1.0,
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "structured": {
            "schema": planner.OUTPUT_SCHEMA,
            "case_id": "live30-q04",
            "rows": [
                {
                    "row_id": "live30-q04:issue-01",
                    "classification": "LEGAL_PROPOSITION",
                    "proposition": "Homicide liability requires the elements of an offence.",
                    "selections": [{"id": "neutral-citation:[2025] UKSC 999", "locator": "para 1"}],
                    "search_query": "",
                }
            ],
        },
        "raw_text": "not persisted",
    }

    with pytest.raises(planner.GapPlanValidationError) as caught:
        planner._validate_model_response(
            body=body,
            row_input=row_input,
            request_id="request-1",
        )

    assert caught.value.code == "structured_output_invented_authority"
    assert caught.value.context["row_id"] == "live30-q04:issue-01"
    assert caught.value.context["invented_authority_id"] == ("neutral-citation:[2025] UKSC 999")

    plans, metrics = planner._validate_model_response(
        body=body,
        row_input=row_input,
        request_id="request-1",
        allow_invented_authority_fallback=True,
    )
    assert plans[0]["selections"] == []
    assert plans[0]["official_source_search_query"] == (
        "England Wales official primary authority homicide"
    )
    assert metrics["deterministic_validation_repair_count"] == 1
    assert metrics["deterministic_validation_repairs"][0]["reason_code"] == (
        "INVENTED_AUTHORITY_SELECTION_DROPPED"
    )
