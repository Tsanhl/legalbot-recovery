"""Synthetic public-controller tests; no protected bank, model or worker IO."""
from __future__ import annotations

import hashlib
import json
from contextlib import nullcontext
from pathlib import Path

import pytest
from scripts import continue_reconciled_ge_codex_unseen as prior
from scripts import continue_reconciled_ge_codex_unseen_r2 as successor


class PublicRunner:
    RUN_ID = "synthetic-run"

    def __init__(self, root: Path):
        self.ROOT = root
        self.PUBLIC = root / "public"
        self.PUBLIC.mkdir()
        self.PRIVATE = root / "synthetic-private"
        self.PRIVATE.mkdir()

    def seal(self, value):
        return {**value, "content_sha256": hashlib.sha256(
            json.dumps(value, sort_keys=True).encode()).hexdigest()}

    def write(self, path, value):
        path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")

    def read(self, path):
        return json.loads(path.read_text(encoding="utf-8"))

    def sha(self, path):
        return hashlib.sha256(path.read_bytes()).hexdigest()


def harness(tmp_path, monkeypatch):
    runner = PublicRunner(tmp_path)
    runner.write(runner.PUBLIC / prior.START, {"run_id": runner.RUN_ID,
        "coordinator_pid": 12345, "controller_sha256": "a" * 64})
    runner.write(runner.PUBLIC / "PLAN-EXECUTION-AUTHORIZATION.json",
                 {"run_id": runner.RUN_ID, "authorized": True})
    monkeypatch.setattr(successor, "require_plan_execution", lambda r: None)
    monkeypatch.setattr(successor.prior, "_verified_reconciliation", lambda r: (
        {"construction": {"authored_slots": 431}}, "b" * 64))
    monkeypatch.setattr(successor, "_pid_present", lambda pid: False)
    monkeypatch.setattr(successor, "_protected_worker_process_present", lambda r: False)
    monkeypatch.setattr(successor.creation, "active_work", lambda r: set())
    monkeypatch.setattr(successor.creation, "coordinator_lock", lambda r: nullcontext())
    monkeypatch.setattr(successor.creation, "active_jobs", lambda r: 0)
    return runner


def test_r2_records_interruption_then_resumes_only_existing_worker(tmp_path, monkeypatch):
    runner = harness(tmp_path, monkeypatch)
    calls = []
    monkeypatch.setattr(successor.creation, "main",
                        lambda *, lock_held: calls.append(("worker", lock_held)))
    monkeypatch.setattr(successor, "publish_outcome", lambda r, *, schema_repair_resume: {
        "status": "CREATED", "outcome": {"overall_state": "CONSTRUCTION_TERMINAL_HOLD",
            "terminal": True, "construction_ready": False, "denominators": {"total": 443},
            "cases": {"legal": {"ready": 0}, "system": {"ready": 0}},
            "active_jobs": 0, "pending_jobs": 12, "content_sha256": "c" * 64}})
    result = successor.continue_construction(runner)
    assert calls == [("worker", True)]
    assert result["construction_ready"] is False and result["candidate_execution"] is False
    interruption = runner.read(runner.PUBLIC / successor.INTERRUPTION)
    assert interruption["attempt_counts_reset"] is False
    assert interruption["durable_outputs_preserved"] is True
    assert interruption["observed_terminal_exit_code"] is None
    assert interruption["termination_cause"] == "UNKNOWN_NOT_ATTESTED"
    assert interruption["signals_sent"] is None
    assert interruption["signals_sent_by_reconciler"] == []
    assert runner.read(runner.PUBLIC / successor.START)["no_third_fixture_attempt"] is True
    with pytest.raises(RuntimeError, match="ALREADY_ATTEMPTED"):
        successor.continue_construction(runner)


def test_r2_catches_interrupt_and_writes_failure_without_retry(tmp_path, monkeypatch):
    runner = harness(tmp_path, monkeypatch)
    monkeypatch.setattr(successor.creation, "main",
                        lambda *, lock_held: (_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        successor.continue_construction(runner)
    failure = runner.read(runner.PUBLIC / successor.FAILURE)
    assert failure["error_type"] == "KeyboardInterrupt"
    assert failure["automatic_retry"] is False
    assert failure["attempt_counts_reset"] is False


@pytest.mark.parametrize("receipt_exists", [False, True])
@pytest.mark.parametrize("process", ["coordinator", "worker"])
def test_reconciliation_checks_actual_processes_even_with_receipt(
    tmp_path, monkeypatch, receipt_exists, process,
):
    runner = harness(tmp_path, monkeypatch)
    if receipt_exists:
        successor._record_interruption(runner)
    if process == "coordinator":
        monkeypatch.setattr(successor, "_pid_present", lambda pid: True)
    else:
        monkeypatch.setattr(successor, "_protected_worker_process_present", lambda r: True)
    with pytest.raises(RuntimeError, match="PROCESS_STILL_PRESENT"):
        successor._record_interruption(runner)
    assert not (runner.PUBLIC / successor.START).exists()


def test_acknowledgement_consumes_attempt_without_adopting_output(tmp_path, monkeypatch):
    runner = harness(tmp_path, monkeypatch)
    work = runner.PRIVATE / "oracle-repair" / "shard-synthetic"
    work.mkdir(parents=True)
    runner.write(work / "INVOCATION.json", {"synthetic": "invocation"})
    runner.write(work / "output.json", {"synthetic": "uncompleted-output"})
    original = {path.name: path.read_bytes() for path in work.iterdir()}
    receipt = successor.creation.interruption_receipt_path(runner, work)
    receipt.parent.mkdir(parents=True)
    result = successor._acknowledge_interrupted_work(
        runner, work, prior_start_sha256=runner.sha(runner.PUBLIC / prior.START),
    )
    assert result == runner.sha(receipt)
    value = runner.read(receipt)
    assert value["attempt_consumed"] is True
    assert value["termination_cause"] == "UNKNOWN_NOT_ATTESTED"
    assert value["automatic_retry"] is False
    assert value["output_promoted"] is False
    assert {path.name: path.read_bytes() for path in work.iterdir()} == original
    assert successor.creation.interrupted_work_acknowledged(runner, work)
