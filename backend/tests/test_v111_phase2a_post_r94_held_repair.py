from __future__ import annotations

import json
from pathlib import Path

from scripts import repair_v111_phase2a_post_r94_held_exact_spans as repair


def _runtime_identity() -> dict:
    return repair._runtime_identity(
        health={
            "backend": repair.base.MODEL_BACKEND,
            "model_id": repair.base.EXPECTED_MODEL_ID,
            "model_loaded": True,
            "stub_mode": False,
            "memory_profile": {
                "context_window_tokens": 8192,
                "max_output_tokens": repair.REPAIR_MAX_OUTPUT_TOKENS,
                "prefill_step_size": 256,
                "kv_cache_bits": 4,
                "kv_group_size": 64,
                "clear_cache_after_request": True,
                "single_flight_generation": True,
            },
        },
        port=repair.DEFAULT_PORT,
        timeout_seconds=repair.DEFAULT_TIMEOUT_SECONDS,
    )


def _gap_invoke(envelope: dict) -> dict:
    payload = envelope["payload"]
    row_id = payload["rows"][0]["row_id"]
    structured = {
        "schema": repair.base.OUTPUT_SCHEMA,
        "case_id": payload["case_id"],
        "rows": [
            {
                "row_id": row_id,
                "assessment": "GAP",
                "proposition": "",
                "support": None,
            }
        ],
    }
    raw = json.dumps(structured, sort_keys=True, separators=(",", ":"))
    return {
        "request_id": envelope["request_id"],
        "model_version": repair.base.EXPECTED_MODEL_VERSION,
        "backend": repair.base.MODEL_BACKEND,
        "raw_text": raw,
        "structured": structured,
        "finish_reason": "complete",
        "usage": {"input_tokens": 100, "output_tokens": 20, "total_tokens": 120},
        "generation_ms": 10,
        "time_to_first_token_ms": 2,
        "deterministic": True,
        "peak_memory_gb": 2.0,
        "warnings": ["rubric_scoring_is_external"],
    }


def _prepare(tmp_path: Path):
    source = repair._load_source()
    output = tmp_path / "r100"
    runtime = _runtime_identity()
    repair._prepare_output_root(output, resume=False)
    repair._initialize_or_verify_intent(
        output_root=output,
        source=source,
        runtime_identity=runtime,
    )
    return source, output, runtime


def test_r99b_source_contract_is_exact_and_fail_closed() -> None:
    source = repair._load_source()
    assert source.r99b_digest == repair.EXPECTED_R99B_ARTIFACT_CONTENT_SHA256
    assert source.recovery_digest == (
        "ad1d23ce7feabbd8936eb083fe678be2028f4723b60ffb8b42228a220de02ebf"
    )
    assert len(source.held_row_ids) == repair.EXPECTED_HELD_ROW_COUNT
    assert set(source.projected_rows) == set(source.held_row_ids)
    assert set(source.diagnostic_history) == set(source.held_row_ids)
    assert all(len(history) == 2 for history in source.diagnostic_history.values())
    assert source.r99b["phase2b_authorized"] is False
    assert source.r99b["development30_authorized"] is False


def test_epoch_is_append_only_and_resume_skips_completed_rows(tmp_path: Path) -> None:
    source, output, runtime = _prepare(tmp_path)
    first, abort = repair._process_epoch(
        output_root=output,
        source=source,
        invoke=_gap_invoke,
        runtime_identity=runtime,
        epoch_id="test-epoch-1",
        row_limit=2,
    )
    assert first == list(source.held_row_ids[:2])
    assert abort is False
    second, abort = repair._process_epoch(
        output_root=output,
        source=source,
        invoke=_gap_invoke,
        runtime_identity=runtime,
        epoch_id="test-epoch-2",
        row_limit=1,
    )
    assert second == [source.held_row_ids[2]]
    assert abort is False
    checkpoints = repair._load_repair_checkpoints(
        output_root=output,
        source=source,
    )
    assert tuple(checkpoints) == source.held_row_ids[:3]
    assert all(item["total_attempt_ordinal_for_row"] == 3 for item in checkpoints.values())
    assert all(item["phase2b_authorized"] is False for item in checkpoints.values())
    assert not list((output / "diagnostics").glob("*.json"))


def test_infrastructure_failure_persists_and_aborts_epoch(tmp_path: Path) -> None:
    source, output, runtime = _prepare(tmp_path)

    def unavailable(_envelope: dict) -> dict:
        raise RuntimeError("connect_error")

    processed, abort = repair._process_epoch(
        output_root=output,
        source=source,
        invoke=unavailable,
        runtime_identity=runtime,
        epoch_id="failed-epoch",
        row_limit=repair.MAX_ROWS_PER_EPOCH,
    )
    assert processed == [source.held_row_ids[0]]
    assert abort is True
    checkpoints = repair._load_repair_checkpoints(
        output_root=output,
        source=source,
    )
    checkpoint = checkpoints[source.held_row_ids[0]]
    assert checkpoint["status"] == "HELD_AFTER_CHANGED_PLAN_ATTEMPT"
    assert checkpoint["finding"]["assessment"] == ("HELD_AFTER_DEBUGGED_NEW_PLAN_ATTEMPT")
    diagnostic = repair._load_object(next((output / "diagnostics").glob("*.json")))
    assert diagnostic["error_code"] == "connect_error"
    assert diagnostic["no_further_attempt_authorized_under_this_plan"] is True
    assert diagnostic["phase2b_authorized"] is False


def test_full_fake_repair_merges_all_361_rows_without_authorizing_gate(
    tmp_path: Path,
) -> None:
    source, output, runtime = _prepare(tmp_path)
    completed = 0
    epoch = 0
    while completed < len(source.held_row_ids):
        epoch += 1
        processed, abort = repair._process_epoch(
            output_root=output,
            source=source,
            invoke=_gap_invoke,
            runtime_identity=runtime,
            epoch_id=f"test-epoch-{epoch}",
            row_limit=repair.MAX_ROWS_PER_EPOCH,
        )
        assert abort is False
        log_path = output / "runtime-epochs" / f"{epoch:03d}.log"
        log_path.write_bytes(b"test runtime log; no model output\n")
        repair._write_epoch_receipt(
            output_root=output,
            epoch_number=epoch,
            epoch_id=f"test-epoch-{epoch}",
            started_at="2026-08-26T00:00:00+00:00",
            processed=processed,
            abort_epoch=False,
            runtime_identity=runtime,
            log_path=log_path,
            stop_mode="test",
            exit_code=0,
            epoch_error_code=None,
        )
        completed += len(processed)
    merged = repair._finalize(output_root=output, source=source)
    assert merged["row_count"] == 361
    assert merged["remaining_held_row_count"] == 0
    assert merged["assessment_counts"] == {
        "DIRECT_EXACT_SPAN_ADVISORY": 34,
        "MATERIAL_GAP_ADVISORY": 323,
        "PARTIAL_EXACT_SPAN_ADVISORY": 4,
    }
    assert merged["owner_decisions_applied"] is False
    assert merged["technical_qualification_assigned"] is False
    assert merged["source_admission_authorized"] is False
    assert merged["candidate_mutated"] is False
    assert merged["phase2b_authorized"] is False
    assert merged["development30_authorized"] is False
    assert (output / "SHA256SUMS.txt").is_file()


def test_managed_runtime_environment_uses_full_revision() -> None:
    environment = repair._runtime_environment(port=repair.DEFAULT_PORT)
    assert environment["LEGALBOT_MODEL_REVISION"] == repair.PINNED_RUNTIME_REVISION
    assert environment["HF_HUB_OFFLINE"] == "1"
    assert environment["TRANSFORMERS_OFFLINE"] == "1"
    assert environment["LEGALBOT_MODEL_MAX_OUTPUT_TOKENS"] == "512"


def test_model_runtime_python_preserves_virtualenv_symlink() -> None:
    path = repair._model_runtime_python()
    assert str(path).endswith("model-runtime/.venv/bin/python")
    assert path.is_symlink()
