from __future__ import annotations

import json

from app.evaluation.operational import build_operational_metrics


def test_operational_metrics_are_safe_aggregates(database, cipher) -> None:
    database.create_job(
        job_id="metrics-job",
        encrypted_question=cipher.encrypt_text("private"),
        question_summary="Private encrypted question",
        request={"word_target": 1000},
        route="sectioned",
    )
    database.store_stage_attempt(
        attempt_id="metrics-stage",
        job_id="metrics-job",
        stage_key="draft",
        section_key="one",
        attempt_number=1,
        status="running",
        encrypted_output=None,
    )
    database.finish_stage_attempt(
        "metrics-stage",
        status="complete",
        encrypted_output=cipher.encrypt_text("held"),
        metrics={
            "duration_ms": 500,
            "generation_ms": 450,
            "time_to_first_token_ms": 100,
            "input_tokens": 20,
            "output_tokens": 30,
            "peak_memory_gb": 5.1,
        },
    )
    report = build_operational_metrics(database)
    encoded = json.dumps(report)
    assert report["queue"]["depth"] == 1
    assert report["latency_ms"]["generation"]["p95"] == 450
    assert report["usage"]["input_tokens"] == 20
    assert report["safe_aggregate_only"] is True
    assert "private" not in encoded
