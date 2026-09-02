from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from scripts.run_ge_retrieval_training_cycle import (
    ISSUE_LOCATOR_HINTS as CYCLE_HINTS,
)
from scripts.run_ge_retrieval_training_cycle import (
    _exact_locator_candidates,
    _expand_unseen,
    _training_row,
)

from app.evaluation.ge_diagnostic_evaluator import (
    alphanumeric_token_count,
    assemble_locator_passages,
    combined_answer,
    evaluate_factual_checks,
    is_punctuation_only,
    locator_hints_for_case,
    passage_completeness,
    safety_check,
    training_eligibility,
    training_example_label,
    unseen_family_summary,
    VIDEO_WILL_TAGS,
)

ROOT = Path.cwd()
R3 = ROOT / (
    "data/evaluations/general-enquiries/LegalBot-GE-2026-09-01-improvement-training-unseen-r3"
)
R2_DOCX = ROOT / "output/docx/LegalBot-GE-331-Training-and-60-Unseen-Full-Review-r2.docx"

DOTS = ". . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ."
WILLS_COLLAPSE = "No will shall be valid unless—but no form of attestation shall be necessary."
S174 = (
    "to get on to and off regulated public service vehicles in safety and without "
    "unreasonable difficulty (and, in the case of disabled persons in wheelchairs, "
    "to do so while remaining in their wheelchairs)"
)
ARB_S9 = (
    "On an application under this section the court shall grant a stay unless "
    "satisfied that the arbitration agreement is null and void, inoperative, or "
    "incapable of being performed."
)


def _row(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "source_version_id": "sv-1",
        "chunk_id": "chunk-1",
        "title": "Example Act",
        "locator": "section 1",
        "quote": "A person shall not do the prohibited act.",
        "stored_text": "A person shall not do the prohibited act.",
        "oscola_parenthetical": "(Example Act, s 1)",
        "evidence_span_sha256": "a" * 64,
        "identity_verified": True,
        "jurisdiction": "United Kingdom",
        "provision_extent_status": "unverified",
        "currentness_verified": False,
        "full_current_law_verification_eligible": False,
        "currentness_reviewed_as_of_date": "2026-08-14",
        "unapplied_effect_count": None,
    }
    value.update(overrides)
    return value


def test_historical_r3_pack_and_r2_docx_are_preserved() -> None:
    manifest = json.loads((R3 / "RUN-MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["content_sha256"] == (
        "e4e5d59377b7377ec1311774cae4e3810cccbf3baef8c106a4c4b150cf4ee123"
    )
    assert (R3 / "visible/RESULTS.jsonl").stat().st_size == 1512063
    assert (R3 / "unseen/PRIVATE-QUESTIONS.jsonl").stat().st_size == 73437
    assert R2_DOCX.exists()
    digest = hashlib.sha256(R2_DOCX.read_bytes()).hexdigest()
    assert digest == "fca6310b4c88b5fe99de3f4087e01614faa956ff6469deba42db7215d3b43117"


def test_punctuation_only_dots_fail_completeness_and_claim_support() -> None:
    assert is_punctuation_only(DOTS)
    assert alphanumeric_token_count(DOTS) == 0
    completeness = passage_completeness(
        title="Law Reform (Contributory Negligence) Act 1945",
        locator="section 1",
        stored_text=DOTS,
        displayed_quote_text=DOTS,
    )
    assert completeness.outcome == "FAIL"
    result = evaluate_factual_checks(
        case={
            "prompt": (
                "I was hurt in an accident involving a cyclist and a broken streetlight, "
                "and I was distracted too. Can I still claim?"
            ),
            "issue_tags": ["contributory-negligence"],
            "primary_jurisdiction": "ENGLAND_AND_WALES",
            "legal_currentness_cutoff": "2026-08-28",
        },
        evidence_rows=[
            _row(
                title="Law Reform (Contributory Negligence) Act 1945",
                locator="section 1",
                quote=DOTS,
                stored_text=DOTS,
            )
        ],
        source_manifest_sha256="b" * 64,
        user_facing_answer_text="Your question is repeated.",
    )
    assert result.diagnostic_checks["source_identity"]["outcome"] == "PASS"
    assert result.diagnostic_checks["passage_completeness"]["outcome"] == "FAIL"
    assert result.checks["claim_evidence_support"] == "FAIL"
    assert result.checks["citation_and_quotation_identity"] == "PASS"


def test_equality_act_s174_is_irrelevant_to_online_form() -> None:
    result = evaluate_factual_checks(
        case={
            "prompt": (
                "A public authority’s online form is inaccessible to me because of a "
                "disability. How can I get help using the service and raise a complaint?"
            ),
            "issue_tags": ["accessibility", "public-duty", "equality"],
            "primary_jurisdiction": "ENGLAND_AND_WALES",
            "legal_currentness_cutoff": "2026-08-28",
        },
        evidence_rows=[
            _row(
                title="Equality Act 2010",
                locator="section 174",
                quote=S174,
                stored_text=S174,
            )
        ],
        source_manifest_sha256="b" * 64,
        user_facing_answer_text="Your question is repeated.",
    )
    assert result.diagnostic_checks["issue_relevance"]["outcome"] == "FAIL"
    assert result.checks["claim_evidence_support"] == "FAIL"
    assert "public-service-vehicle" in result.reasons["claim_evidence_support"]


def test_equality_act_s208_and_s210_are_irrelevant_to_online_form() -> None:
    prompt = (
        "A public authority’s online form is inaccessible to me because of a "
        "disability. How can I get help using the service and raise a complaint?"
    )
    for locator, needle in (
        ("section 208", "order-making"),
        ("section 210", "order-making"),
    ):
        result = evaluate_factual_checks(
            case={
                "prompt": prompt,
                "issue_tags": ["accessibility", "public-duty", "equality"],
                "primary_jurisdiction": "ENGLAND_AND_WALES",
                "legal_currentness_cutoff": "2026-08-28",
            },
            evidence_rows=[
                _row(
                    title="Equality Act 2010",
                    locator=locator,
                    quote="The Secretary of State may by order amend the list.",
                    stored_text="The Secretary of State may by order amend the list.",
                )
            ],
            source_manifest_sha256="b" * 64,
            user_facing_answer_text="Your question is repeated.",
        )
        assert result.diagnostic_checks["issue_relevance"]["outcome"] == "FAIL"
        assert needle in result.reasons["claim_evidence_support"]


def test_arbitration_s9_does_not_support_icc_mediation() -> None:
    result = evaluate_factual_checks(
        case={
            "prompt": (
                "Our contract chooses English law and says we must use ICC mediation "
                "before going to an English court, but it does not name a mediator."
            ),
            "issue_tags": ["icc-mediation", "certainty", "stay"],
            "primary_jurisdiction": "CROSS_BORDER",
            "legal_currentness_cutoff": "2026-08-28",
        },
        evidence_rows=[
            _row(
                title="Arbitration Act 1996",
                locator="section 9",
                quote=ARB_S9,
                stored_text=ARB_S9,
            )
        ],
        source_manifest_sha256="b" * 64,
        user_facing_answer_text="Your question is repeated.",
    )
    assert result.diagnostic_checks["issue_relevance"]["outcome"] == "FAIL"
    assert result.checks["claim_evidence_support"] == "FAIL"
    hints = locator_hints_for_case(
        ["icc-mediation", "stay", "certainty"],
        CYCLE_HINTS,
    )
    assert ("Arbitration Act 1996", "section 9") not in hints
    assert any(title.startswith("ICC Mediation Rules") for title, _locator in hints)


def test_incomplete_wills_act_s9_fails_completeness() -> None:
    result = evaluate_factual_checks(
        case={
            "prompt": (
                "In England on 15 January 2024, a will-maker and two witnesses used a "
                "live video link and signed the will in several stages. Could that will be valid?"
            ),
            "issue_tags": ["formalities", "video-will"],
            "primary_jurisdiction": "ENGLAND_AND_WALES",
            "legal_currentness_cutoff": "2026-08-28",
        },
        evidence_rows=[
            _row(
                title="Wills Act 1837",
                locator="section 9",
                quote=WILLS_COLLAPSE,
                stored_text=WILLS_COLLAPSE,
            )
        ],
        source_manifest_sha256="b" * 64,
        user_facing_answer_text="Your question is repeated.",
    )
    assert result.diagnostic_checks["passage_completeness"]["outcome"] == "FAIL"
    assert result.checks["claim_evidence_support"] == "FAIL"
    assert result.checks["requested_date_and_currentness"] == "FAIL"
    assert "15 January 2024" in result.reasons["requested_date_and_currentness"]


def test_no_evidence_currentness_is_not_assessable() -> None:
    result = evaluate_factual_checks(
        case={
            "prompt": "What is the rule?",
            "issue_tags": ["ai"],
            "primary_jurisdiction": "ENGLAND_AND_WALES",
            "legal_currentness_cutoff": "2026-08-28",
        },
        evidence_rows=[],
        source_manifest_sha256="b" * 64,
        user_facing_answer_text="No provision was selected.",
    )
    assert result.checks["requested_date_and_currentness"] == "NOT_ASSESSABLE"
    assert "NOT_ASSESSABLE_BECAUSE_EVIDENCE_MISSING" in result.reasons["requested_date_and_currentness"]
    assert "no provision was selected" in result.reasons["requested_date_and_currentness"]
    assert result.diagnostic_checks["jurisdiction_origin"]["outcome"] == "NOT_ASSESSABLE"


def test_jurisdiction_origin_is_not_applicability() -> None:
    result = evaluate_factual_checks(
        case={
            "prompt": "A local authority refused my housing review.",
            "issue_tags": ["judicial-review"],
            "primary_jurisdiction": "ENGLAND_AND_WALES",
            "legal_currentness_cutoff": "2026-08-28",
        },
        evidence_rows=[_row(quote="The court may grant relief.", stored_text="The court may grant relief.")],
        source_manifest_sha256="b" * 64,
        user_facing_answer_text="Your question is repeated.",
    )
    assert result.diagnostic_checks["jurisdiction_origin"]["outcome"] == "PASS"
    assert result.diagnostic_checks["jurisdiction_applicability"]["outcome"] == "FAIL"
    assert result.checks["jurisdiction_scope"] == "FAIL"


def test_safety_inspects_rendered_answer_not_planner_intent() -> None:
    case = {
        "prompt": "A wellness device told me to change my dose.",
        "issue_tags": ["wellness-device", "urgent"],
        "proposed_clarification_criteria": {
            "safe_first_response": (
                "Prioritise emergency clinical help immediately, with no legal checklist before care."
            )
        },
        "primary_jurisdiction": "ENGLAND_AND_WALES",
        "legal_currentness_cutoff": "2026-08-28",
    }
    planner_only = combined_answer(case, [])
    # Force a failing rendered body by evaluating the planner text as if it were the answer
    # without the user-facing urgent lead-in.
    failing = safety_check(
        user_facing_answer_text="Explain which medical-device rules might apply.",
        case=case,
    )
    assert failing.outcome == "FAIL"
    passing = safety_check(user_facing_answer_text=planner_only, case=case)
    assert passing.outcome == "PASS"
    assert "Planner output" in planner_only
    assert "Answer shown to the user" in planner_only
    assert planner_only.index("Planner output") < planner_only.index("Answer shown to the user")


def test_unseen_rows_are_exposed_regression_families_and_not_tuning_consumed() -> None:
    rows = _expand_unseen(
        (
            {
                "topic_id": "contract-law",
                "scenario_family_id": "unseen-consumer-cancellation",
                "prompt": "Can I cancel?",
                "issue_tags": ["consumer"],
                "documents": ["Order"],
                "questions": ["When?"],
                "safe": "Preserve the order.",
            },
        )
        * 15,
        count=60,
    )
    summary = unseen_family_summary(rows)
    assert summary["question_record_count"] == 60
    assert summary["scenario_family_base_count"] == 1
    assert rows[0]["usage_role"] == "EXPOSED_DIAGNOSTIC_REGRESSION"
    assert rows[0]["fresh_unseen"] is False
    flags = training_eligibility(lane="diagnostic_unseen")
    assert flags["retrieval_planner_tuning"] is False
    assert flags["retrieval_planner_tuning_consumed"] is False
    assert flags["answer_weight_training"] is False


def test_wrong_route_is_a_negative_planner_label() -> None:
    evaluation = evaluate_factual_checks(
        case={
            "prompt": "Our contract requires ICC mediation before court.",
            "issue_tags": ["icc-mediation", "stay"],
            "primary_jurisdiction": "CROSS_BORDER",
            "legal_currentness_cutoff": "2026-08-28",
        },
        evidence_rows=[
            _row(
                title="Arbitration Act 1996",
                locator="section 9",
                quote=ARB_S9,
                stored_text=ARB_S9,
            )
        ],
        source_manifest_sha256="b" * 64,
        user_facing_answer_text="Your question is repeated.",
    )
    label = training_example_label(
        evidence_rows=[_row(title="Arbitration Act 1996", locator="section 9")],
        diagnostic_checks=evaluation.diagnostic_checks,
    )
    assert label["label"] == "negative_wrong_route"
    assert label["eligible_for_prompt_and_retrieval_tuning"] is False
    row = _training_row(
        {
            "case_id": "international-commercial-mediation:cp-d01",
            "scenario_family_id": "ge-family-mediation-multistep-clause",
            "question": "ICC mediation clause",
            "evidence": [_row(title="Arbitration Act 1996", locator="section 9")],
            "factual_result": {"diagnostic_checks": evaluation.diagnostic_checks},
        }
    )
    assert row["label"] == "negative_wrong_route"
    assert row["eligible_for_weight_training"] is False


def test_locator_assembly_skips_punctuation_and_restores_operative_wills_text() -> None:
    assembled = assemble_locator_passages(
        [
            {
                "chunk_id": "c1",
                "ordinal": 1,
                "locator": "section 9",
                "body": "section 9 " + WILLS_COLLAPSE,
            },
            {
                "chunk_id": "c2",
                "ordinal": 2,
                "locator": "section 9",
                "body": "section 9 it is in writing, and signed by the testator, or by some other person in his presence and by his direction; and",
            },
            {
                "chunk_id": "c3",
                "ordinal": 3,
                "locator": "section 9",
                "body": "section 9 the signature is made or acknowledged by the testator in the presence of two or more witnesses present at the same time; and",
            },
        ]
    )
    assert assembled is not None
    assert assembled.punctuation_only is False
    assert "writing" in assembled.text.casefold()
    assert "witnesses" in assembled.text.casefold()
    assert "unless—but" not in assembled.text.casefold()
    assert "c1" not in assembled.assembled_chunk_ids
    dots_only = assemble_locator_passages(
        [
            {"chunk_id": "d1", "ordinal": 1, "locator": "section 1", "body": DOTS},
            {"chunk_id": "d2", "ordinal": 2, "locator": "section 1", "body": DOTS},
        ]
    )
    assert dots_only is not None
    assert dots_only.punctuation_only is True


def test_exact_locator_prefers_substantive_contributory_negligence_fragment(tmp_path: Path) -> None:
    db = tmp_path / "chunks.sqlite3"
    connection = sqlite3.connect(db)
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        CREATE TABLE chunk_meta(
          chunk_id TEXT PRIMARY KEY,
          source_version_id TEXT NOT NULL,
          title TEXT NOT NULL,
          locator TEXT NOT NULL,
          body TEXT NOT NULL,
          ordinal INTEGER NOT NULL
        )
        """
    )
    connection.executemany(
        "INSERT INTO chunk_meta VALUES (?,?,?,?,?,?)",
        [
            ("chunk-dots", "sv-cn", "Law Reform (Contributory Negligence) Act 1945", "section 1", DOTS, 1),
            (
                "chunk-operative",
                "sv-cn",
                "Law Reform (Contributory Negligence) Act 1945",
                "section 1",
                (
                    "Where any person suffers damage as the result partly of his own fault and "
                    "partly of the fault of any other person or persons, a claim in respect of "
                    "that damage shall not be defeated by reason of the fault of the person "
                    "suffering the damage."
                ),
                2,
            ),
        ],
    )
    connection.commit()
    sources = {
        "sv-cn": {
            "currentness_status": "latest_available_revised_snapshot",
            "currentness_reviewed_as_of_date": "2026-08-14",
            "currentness_verified": False,
            "full_current_law_verification_eligible": False,
            "identity_verified": True,
            "jurisdiction": "England and Wales",
            "canonical_url": None,
            "stable_identifier": "ukpga/Geo6/8-9/28",
            "authority_identity_id": None,
            "provision_extent_status": "unverified",
            "unapplied_effect_count": None,
            "lane": "primary_authority",
        }
    }
    evidence = _exact_locator_candidates(
        connection,
        topic="tort-law",
        issue_tags=["contributory-negligence"],
        sources=sources,
    )
    connection.close()
    assert len(evidence) == 1
    assert "shall not be defeated" in evidence[0].text
    assert "punctuation_only" not in evidence[0].passage_flags
    assert "chunk-dots" not in evidence[0].assembled_chunk_ids


def test_accessibility_locator_hints_are_services_not_psv() -> None:
    hints = locator_hints_for_case(["accessibility", "public-duty"], CYCLE_HINTS)
    assert ("Equality Act 2010", "section 20") in hints
    assert ("Equality Act 2010", "section 21") in hints
    assert ("Equality Act 2010", "section 29") in hints
    assert ("Equality Act 2010", "schedule 2") in hints
    assert ("Equality Act 2010", "section 174") not in hints
    assert ("Equality Act 2010", "section 208") not in hints


def test_video_will_does_not_use_latest_wills_act_locator() -> None:
    assert VIDEO_WILL_TAGS
    hints = locator_hints_for_case(
        ["video-will", "formalities", "two-witnesses"],
        CYCLE_HINTS,
    )
    assert all(title != "Wills Act 1837" for title, _locator in hints)


def test_cable_and_wireless_is_rejected_from_mandatory_route() -> None:
    from scripts.run_ge_retrieval_training_cycle import (
        MISSING_PRIMARY_BY_TOPIC,
        _is_rejected_mandatory,
    )

    missing = MISSING_PRIMARY_BY_TOPIC["international-commercial-mediation"]
    assert all("cable" not in name.casefold() for name in missing)
    assert _is_rejected_mandatory("Cable & Wireless plc v IBM United Kingdom Ltd", None) is True
    from scripts.run_ge_retrieval_training_cycle import _keep_exact_chunk

    assert _keep_exact_chunk(
        title="Equality Act 2010",
        locator="schedule 2",
        body="schedule 2 paragraph 3 This paragraph applies to vehicles.",
    ) is False
    assert _keep_exact_chunk(
        title="Equality Act 2010",
        locator="schedule 2",
        body="schedule 2 paragraph 1 This Schedule applies where a duty to make reasonable adjustments applies.",
    ) is True
