#!/usr/bin/env python3
"""Resume the interrupted reconciliation-bound construction successor once.

This controller records absent processes and consumed incomplete attempts, then reuses the
existing protected construction worker for work that its durable ledger still
classifies as eligible.  It never resets attempt counts and cannot seal, freeze,
execute, score, train, promote or activate a candidate.
"""
from __future__ import annotations

import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from scripts import continue_ge_codex_unseen_creation as creation
from scripts import continue_reconciled_ge_codex_unseen as prior
from scripts import run_ge_codex_unseen as runner
from scripts.ge_unseen_creation_outcome import publish_outcome
from scripts.ge_unseen_research_gate import require_plan_execution

INTERRUPTION = "CONTINUOUS-RECONCILED-SUCCESSOR-INTERRUPTION-COMPLETE.json"
START = "CONTINUOUS-RECONCILED-SUCCESSOR-r2-START.json"
COMPLETE = "CONTINUOUS-RECONCILED-SUCCESSOR-r2-COMPLETE.json"
FAILURE = "CONTINUOUS-RECONCILED-SUCCESSOR-r2-FAILURE.json"


def _pid_present(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def _protected_worker_process_present(r=runner) -> bool:
    """Check for an actual process bound to this protected construction root."""

    output = subprocess.check_output(
        ["/bin/ps", "-axo", "pid=,command="], text=True
    )
    protected_root = str(r.PRIVATE)
    own_pid = os.getpid()
    for line in output.splitlines():
        fields = line.strip().split(maxsplit=1)
        if len(fields) != 2:
            continue
        try:
            pid = int(fields[0])
        except ValueError:
            continue
        if pid != own_pid and protected_root in fields[1]:
            return True
    return False


def _acknowledge_interrupted_work(r, work, *, prior_start_sha256: str) -> str:
    """Record a consumed interruption without changing the worker directory."""

    path = creation.interruption_receipt_path(r, work)
    expected = {
        "schema": "legalbot.ge-worker-interruption.v1",
        "run_id": r.RUN_ID,
        "work": work.relative_to(r.PRIVATE).as_posix(),
        "invocation_sha256": r.sha(work / "INVOCATION.json"),
        "prior_start_sha256": prior_start_sha256,
        "reason": "RECONCILED_INCOMPLETE_INVOCATION_WITH_NO_PROCESS",
        "termination_cause": "UNKNOWN_NOT_ATTESTED",
        "attempt_consumed": True,
        "automatic_retry": False,
        "original_work_artifacts_modified": False,
        "output_promoted": False,
    }
    if path.exists():
        if r.read(path) != expected:
            raise RuntimeError("INTERRUPTED_WORK_RECEIPT_CHANGED")
    else:
        r.write(path, expected)
    if not creation.interrupted_work_acknowledged(r, work):
        raise RuntimeError("INTERRUPTED_WORK_ACKNOWLEDGEMENT_INVALID")
    return r.sha(path)


def _record_interruption(r=runner):
    path = r.PUBLIC / INTERRUPTION
    start = r.read(r.PUBLIC / prior.START)
    if (r.PUBLIC / prior.COMPLETE).exists() or (r.PUBLIC / prior.FAILURE).exists():
        raise RuntimeError("PRIOR_SUCCESSOR_ALREADY_TERMINAL")
    if _pid_present(int(start["coordinator_pid"])):
        raise RuntimeError("PRIOR_SUCCESSOR_PROCESS_STILL_PRESENT")
    if _protected_worker_process_present(r):
        raise RuntimeError("PROTECTED_CONSTRUCTION_PROCESS_STILL_PRESENT")
    prior_start_sha256 = r.sha(r.PUBLIC / prior.START)
    if path.exists():
        value = r.read(path)
        if value.get("prior_start_sha256") != prior_start_sha256:
            raise RuntimeError("PRIOR_INTERRUPTION_RECEIPT_CHANGED")
        # A prior receipt cannot stand in for the fresh process checks above.
        # Preserve its historical bytes, including any independently unverified
        # handoff reports; this read never upgrades them to observed facts.
        return value
    interrupted = sorted(creation.active_work(r))
    receipt_hashes = [
        _acknowledge_interrupted_work(
            r, work, prior_start_sha256=prior_start_sha256
        )
        for work in interrupted
    ]
    if creation.active_jobs(r):
        raise RuntimeError("PROTECTED_CONSTRUCTION_JOB_STILL_ACTIVE")
    value = r.seal({"run_id": r.RUN_ID,
        "observed": datetime.now(UTC).isoformat(),
        "prior_start_sha256": prior_start_sha256,
        "prior_controller_sha256": start["controller_sha256"],
        "prior_coordinator_pid": start["coordinator_pid"],
        "prior_coordinator_pid_present": False,
        "stop_reason": "RECONCILED_ABSENT_PROCESSES_WITH_INCOMPLETE_INVOCATIONS",
        "observed_terminal_exit_code": None,
        "termination_cause": "UNKNOWN_NOT_ATTESTED",
        "signals_sent": None,
        "signals_sent_by_reconciler": [],
        "process_observation": "PRIOR_COORDINATOR_AND_PROTECTED_WORKERS_ABSENT",
        "active_protected_jobs": 0,
        "interrupted_work_count": len(interrupted),
        "interrupted_receipt_sha256": sorted(receipt_hashes),
        "durable_outputs_preserved": True,
        "attempt_counts_reset": False,
        "private_content_disclosed": False,
        "candidate_execution": False, "bank_seal": False,
        "runtime_freeze": False, "scoring": False,
        "training": False, "promotion": False, "live": False})
    r.write(path, value)
    return value


def continue_construction(r=runner):
    require_plan_execution(r)
    reconciliation, reconciliation_sha = prior._verified_reconciliation(r)
    for name in (START, COMPLETE, FAILURE, "BANK-SEAL.json", "RUN-FREEZE.json", "ONE-PASS-START.json"):
        if (r.PUBLIC / name).exists():
            raise RuntimeError("R2_SUCCESSOR_ALREADY_ATTEMPTED_OR_LATER_STAGE_EXISTS")
    with creation.coordinator_lock(r):
        interruption = _record_interruption(r)
        if creation.active_jobs(r):
            raise RuntimeError("PROTECTED_CONSTRUCTION_JOB_ALREADY_ACTIVE")
        start = r.seal({"run_id": r.RUN_ID,
            "started": datetime.now(UTC).isoformat(), "coordinator_pid": os.getpid(),
            "reconciliation_sha256": reconciliation_sha,
            "interruption_sha256": interruption["content_sha256"],
            "plan_execution_sha256": r.sha(r.PUBLIC / "PLAN-EXECUTION-AUTHORIZATION.json"),
            "controller_sha256": r.sha(Path(__file__).resolve()),
            "prior_authored_slots": reconciliation["construction"]["authored_slots"],
            "planned_slots": 443, "bounded_successor": True,
            "resume_after_owner_handoff": True, "attempt_counts_reset": False,
            "no_third_author_attempt": True, "no_third_fixture_attempt": True,
            "only_ledger_eligible_jobs_dispatchable": True,
            "private_projection_only": True, "candidate_execution": False,
            "bank_seal": False, "runtime_freeze": False, "scoring": False,
            "training": False, "promotion": False, "live": False})
        r.write(r.PUBLIC / START, start)
        try:
            creation.main(lock_held=True)
            publication = publish_outcome(r, schema_repair_resume=True)
            outcome = publication["outcome"]
            complete = r.seal({"run_id": r.RUN_ID,
                "completed": datetime.now(UTC).isoformat(),
                "start_sha256": r.sha(r.PUBLIC / START),
                "interruption_sha256": interruption["content_sha256"],
                "outcome_publication_status": publication["status"],
                "overall_state": outcome["overall_state"],
                "terminal": outcome["terminal"],
                "construction_ready": outcome["construction_ready"],
                "planned_slots": outcome["denominators"]["total"],
                "ready_slots": sum(row["ready"] for row in outcome["cases"].values()),
                "active_jobs": outcome["active_jobs"],
                "pending_jobs": outcome["pending_jobs"],
                "public_outcome_sha256": outcome.get("content_sha256"),
                "private_content_disclosed": False,
                "candidate_execution": False, "bank_seal": False,
                "runtime_freeze": False, "scoring": False,
                "training": False, "promotion": False, "live": False})
            r.write(r.PUBLIC / COMPLETE, complete)
            return complete
        except BaseException as exc:
            failure = r.seal({"run_id": r.RUN_ID,
                "failed": datetime.now(UTC).isoformat(),
                "start_sha256": r.sha(r.PUBLIC / START),
                "error_type": type(exc).__name__, "automatic_retry": False,
                "attempt_counts_reset": False, "private_content_disclosed": False,
                "candidate_execution_marker_present": (r.PUBLIC / "ONE-PASS-START.json").exists(),
                "training": False, "promotion": False, "live": False})
            if not (r.PUBLIC / FAILURE).exists():
                r.write(r.PUBLIC / FAILURE, failure)
            raise


def main():
    print(json.dumps(continue_construction(), sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
