from __future__ import annotations

import hashlib
import json

from app.evaluation.ge_answer_weight_training import (
    AUTHORIZED_CASE_IDS,
    OWNER_AUTHORIZATION_TEXT,
    OWNER_AUTHORIZATION_TEXT_SHA256,
    TEST_CASE_IDS,
    TRAIN_CASE_IDS,
    VALID_CASE_IDS,
    _maximum_cross_split_similarity,
    _privacy_findings,
    _sealed,
    build_training_records,
    parse_training_metrics,
    validate_authorized_sources,
)
from app.evaluation.ge_phase2_progress import (
    ANSWER_WEIGHT_TRAINING_COMPLETE_AWAITING_FRESH_VISIBLE_EVALUATION,
    phase2_progress,
)


def _source_row(case_id: str) -> dict[str, object]:
    question = f"What is the supported route for {case_id}?"
    answer = "Use the supplied rule, preserve the records, and obtain advice if facts differ."
    evidence_hash = hashlib.sha256(f"evidence:{case_id}".encode()).hexdigest()
    return {
        "case_id": case_id,
        "topic": case_id.split(":", 1)[0],
        "question": question,
        "question_hash": hashlib.sha256(question.encode()).hexdigest(),
        "candidate_answer": answer,
        "candidate_answer_hash": hashlib.sha256(answer.encode()).hexdigest(),
        "reviewed_evidence_hash": hashlib.sha256(f"manifest:{case_id}".encode()).hexdigest(),
        "material_claims": [
            {
                "title": f"Authority for {case_id}",
                "locator": "section 1",
                "quote": "The supplied exact legal proposition applies subject to the facts.",
                "evidence_span_sha256": evidence_hash,
            }
        ],
    }


def test_authorized_inventory_and_split_are_exact() -> None:
    assert len(AUTHORIZED_CASE_IDS) == 13
    assert len(TRAIN_CASE_IDS) == 9
    assert len(VALID_CASE_IDS) == 3
    assert len(TEST_CASE_IDS) == 1
    assert TRAIN_CASE_IDS.isdisjoint(VALID_CASE_IDS)
    assert TRAIN_CASE_IDS.isdisjoint(TEST_CASE_IDS)
    assert VALID_CASE_IDS.isdisjoint(TEST_CASE_IDS)
    assert hashlib.sha256(OWNER_AUTHORIZATION_TEXT.encode()).hexdigest() == (
        OWNER_AUTHORIZATION_TEXT_SHA256
    )


def test_real_authorized_sources_reconcile_without_opening_unseen_prompts() -> None:
    accepted, holds = validate_authorized_sources()
    assert len(accepted) == 13
    assert len(holds) == 7
    assert {row["case_id"] for row in accepted} == AUTHORIZED_CASE_IDS
    assert AUTHORIZED_CASE_IDS.isdisjoint({row["case_id"] for row in holds})


def test_training_records_use_frozen_9_3_1_topic_split() -> None:
    datasets, records = build_training_records([_source_row(case) for case in AUTHORIZED_CASE_IDS])
    assert {key: len(value) for key, value in datasets.items()} == {
        "train": 9,
        "valid": 3,
        "test": 1,
    }
    assert len(records) == 13
    assert {row["case_id"] for row in records} == AUTHORIZED_CASE_IDS
    assert all(row["owner_authorized"] is True for row in records)


def test_privacy_scan_is_fail_closed_for_owner_paths_and_email() -> None:
    clean, _ = build_training_records([_source_row(case) for case in AUTHORIZED_CASE_IDS])
    assert _privacy_findings(clean) == []
    contaminated = json.loads(json.dumps(clean))
    contaminated["train"][0]["messages"][1]["content"] += " /Users/example/private a@b.com"
    assert set(_privacy_findings(contaminated)) == {"absolute_owner_path", "email_address"}


def test_cross_split_similarity_is_bounded_and_deterministic() -> None:
    datasets, _ = build_training_records([_source_row(case) for case in AUTHORIZED_CASE_IDS])
    first = _maximum_cross_split_similarity(datasets)
    second = _maximum_cross_split_similarity(datasets)
    assert first == second
    assert 0 <= first <= 1


def test_training_metric_parser_requires_real_series() -> None:
    baseline = "Test loss 3.000, Test ppl 20.086."
    trained = "\n".join(
        [
            "Iter 1: Val loss 2.900, Val took 1.000s",
            "Iter 5: Train loss 2.100, Learning Rate 1.000e-05, It/sec 1.000, Tokens/sec 10.000, Trained Tokens 50, Peak mem 8.000 GB",
            "Iter 5: Val loss 2.000, Val took 1.000s",
            "Test loss 2.100, Test ppl 8.166.",
        ]
    )
    metrics = parse_training_metrics(baseline, trained, "Test loss 2.100, Test ppl 8.166.")
    assert metrics["internal_test_loss_improved"] is True
    assert metrics["validation_loss_improved"] is True
    assert metrics["peak_memory_gb"] == 8.0
    assert metrics["quality_70_reassessment_performed"] is False


def test_sealed_hash_binds_body() -> None:
    sealed = _sealed({"schema": "example.v1", "value": 1})
    expected = hashlib.sha256(b'{"schema":"example.v1","value":1}').hexdigest()
    assert sealed["content_sha256"] == expected


def test_phase_progress_advances_to_fresh_visible_evaluation_gate() -> None:
    ledger = phase2_progress(
        case_results=[{"case_id": "case-1", "factual_result": {"outcome": "FACTUAL_PASS"}}],
        diagnostic_report="APPROVED",
        routed=True,
        ai_auto_review_complete=True,
        answer_weight_training_complete=True,
    )
    assert ledger["overall_state"] == (
        ANSWER_WEIGHT_TRAINING_COMPLETE_AWAITING_FRESH_VISIBLE_EVALUATION
    )
