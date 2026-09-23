#!/usr/bin/env python3
"""Continue the authorized construction -> seal -> one-pass route, with no training.

Only the coordinator starts this once, after retiring other dispatch loops. Worker
attempt receipts prevent replay; construction holds end here before any candidate
disclosure. The underlying bank and runtime validators remain mandatory.
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import UTC, datetime

from scripts import continue_ge_codex_unseen_creation as creation
from scripts import run_ge_codex_unseen as runner
from scripts.ge_unseen_creation_outcome import publish_outcome
from scripts.ge_unseen_research_gate import require_plan_execution, require_research_runtime

LATER_MARKERS = ("BANK-SEAL.json", "RUN-FREEZE.json", "ONE-PASS-START.json",
                 "STATE-TRANSITION-RECEIPT.json")
RESUME_START = "CONTINUOUS-PLAN-RESUME-START.json"
SCHEMA_RESUME_START = "CONTINUOUS-SCHEMA-REPAIR-START.json"


def _pid_running(pid):
    if type(pid) is not int or pid <= 0:
        raise RuntimeError("invalid interrupted coordinator PID")
    try:
        os.kill(pid, 0)  # Existence probe only; never signal or terminate workers.
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _start(r, resume, *, schema_repair_resume=False):
    r.require_execution_authority()
    if schema_repair_resume:
        if resume:
            raise RuntimeError("resume modes are mutually exclusive")
        require_plan_execution(r)
        if any((r.PUBLIC / name).exists() for name in (*LATER_MARKERS, SCHEMA_RESUME_START)):
            raise RuntimeError("schema repair route already attempted or later stage exists")
        prior_path = r.PUBLIC / RESUME_START
        pause_path = r.PUBLIC / "SCHEMA-REPAIR-DISPATCH-PAUSE.json"
        drained_path = r.PUBLIC / "SCHEMA-REPAIR-DISPATCH-DRAINED.json"
        prior, pause, drained = (r.read(path) for path in (prior_path, pause_path, drained_path))
        if any(value != r.seal(value) or value.get("run_id") != r.RUN_ID for value in (prior, pause, drained)):
            raise RuntimeError("invalid schema repair interruption evidence")
        pid = prior.get("coordinator_pid")
        if (pause.get("coordinator_pid") != pid or drained.get("coordinator_pid") != pid
                or pause.get("resume_start_sha256") != r.sha(prior_path)
                or drained.get("pause_sha256") != r.sha(pause_path)
                or pause.get("reason") != "FIXTURE_REMOTE_SCHEMA_MISSING_EXPLICIT_TYPE"
                or drained.get("active_jobs") != 0 or drained.get("exit_code") != 130
                or _pid_running(pid) or creation.active_jobs(r)):
            raise RuntimeError("schema repair predecessor is not safely drained")
        r.write(r.PUBLIC / SCHEMA_RESUME_START, r.seal({
            "run_id": r.RUN_ID, "started": datetime.now(UTC).isoformat(),
            "coordinator_pid": os.getpid(), "schema_repair_resume": True,
            "previous_resume_sha256": r.sha(prior_path), "drained_sha256": r.sha(drained_path),
            "plan_execution_sha256": r.sha(r.PUBLIC / "PLAN-EXECUTION-AUTHORIZATION.json"),
            "controller_sha256": r.sha(r.ROOT / "scripts/continue_authorized_ge_codex_unseen.py"),
            "changed_fixture_schema_code_sha256": r.sha(r.ROOT / "scripts/ge_unseen_fixture_repair.py"),
            "active_jobs_at_start": 0, "no_third_fixture_attempt": True,
            "construction_hold_stops_before_candidate": True,
            "training": False, "adapter_activation": False, "promotion": False, "live": False}))
        return
    initial_markers = () if resume else ("CONTINUOUS-RUN-START.json",)
    for name in (*LATER_MARKERS, RESUME_START, *initial_markers):
        r.safe_path(r.PUBLIC/name)
        if (r.PUBLIC/name).exists():
            raise RuntimeError("continuous route already attempted or later stage exists")
    binding = {}
    if resume:
        plan = require_plan_execution(r)
        original_path = r.PUBLIC / "CONTINUOUS-RUN-START.json"
        interruption_path = r.PUBLIC / "DISPATCH-INTERRUPTION-COMPLETE.json"
        original, interruption = r.read(original_path), r.read(interruption_path)
        if (original != r.seal(original) or original.get("run_id") != r.RUN_ID
                or interruption != r.seal(interruption) or interruption.get("run_id") != r.RUN_ID
                or interruption.get("original_start_sha256") != r.sha(original_path)):
            raise RuntimeError("invalid original start or interruption-complete binding")
        pid = interruption.get("coordinator_pid")
        if _pid_running(pid):
            raise RuntimeError("interrupted coordinator is still running")
        if creation.active_jobs(r):
            raise RuntimeError("construction jobs still active")
        binding = {"resume": True, "original_start_sha256": r.sha(original_path),
                   "interruption_complete_sha256": r.sha(interruption_path),
                   "plan_execution_sha256": r.sha(r.PUBLIC / "PLAN-EXECUTION-AUTHORIZATION.json"),
                   "accepted_plan_sha256": plan["accepted_plan_sha256"],
                   "prior_coordinator_pid": pid, "prior_coordinator_running": False,
                   "active_jobs_at_start": 0}
    r.write(r.PUBLIC/(RESUME_START if resume else "CONTINUOUS-RUN-START.json"),r.seal({
        "run_id":r.RUN_ID,"started":datetime.now(UTC).isoformat(),
        "coordinator_pid": os.getpid(), **binding,
        "owner_authorization_sha256":r.sha(r.PUBLIC/"OWNER-AUTHORIZATION.json"),
        "scope_amendment_sha256":r.sha(r.PUBLIC/"UK-USA-SCOPE-AMENDMENT.json"),
        "controller_sha256":r.sha(r.ROOT/"scripts/continue_authorized_ge_codex_unseen.py"),
        "route":["CONSTRUCTION","PRESEAL_REVIEW","SEAL_IF_READY","ONE_PASS","BLIND_REVIEW"],
        "construction_hold_stops_before_candidate":True,"training":False,
        "adapter_activation":False,"promotion":False,"live":False}))


def _research_hold(r):
    try:
        evidence = require_research_runtime(r)
        if not isinstance(evidence, dict) or evidence.get("status") != "PASS":
            raise RuntimeError("research runtime gate did not return validated PASS evidence")
    except Exception as exc:
        # Missing/stale/held evidence is a real pending gate, never a PASS and
        # never permission to disclose candidates. Do not expose validator text.
        return {"overall_state": "RESEARCH_RUNTIME_PENDING_OR_HELD",
                "research_runtime_ready": False, "error_type": type(exc).__name__,
                "candidate_executed": False, "training": False}
    return None


def continue_route(r=runner, drain=None, publish=publish_outcome, *, resume=False, schema_repair_resume=False):
    with creation.coordinator_lock(r):
        _start(r, resume, schema_repair_resume=schema_repair_resume)
        return _continue_started(r, drain, publish, resume, schema_repair_resume=schema_repair_resume)


def _continue_started(r, drain, publish, resume, *, schema_repair_resume=False):
    stage="CONSTRUCTION"
    try:
        if drain is None:
            creation.main(lock_held=True)
        else:
            drain()
        stage="CONSTRUCTION_OUTCOME"
        receipt = (publish(r, schema_repair_resume=True) if schema_repair_resume else
                   publish(r, resume=True) if resume else publish(r))
        outcome=receipt["outcome"]
        if (receipt["status"] not in ("CREATED","NO_OP") or
                outcome.get("terminal") is not True or
                outcome.get("construction_ready") is not True):
            return {"overall_state":outcome["overall_state"],
                    "candidate_executed":False,"training":False}
        stage="RESEARCH_RUNTIME_BEFORE_SEAL"
        held = _research_hold(r)
        if held:
            return held
        stage="BANK_SEAL"
        sealed=r.seal_bank()
        if sealed.get("bank_sealed") is not True:
            name = ("CONTINUOUS-SCHEMA-REPAIR-SEAL-HOLD.json" if schema_repair_resume else
                    "CONTINUOUS-PLAN-RESUME-SEAL-HOLD.json" if resume else "CONTINUOUS-SEAL-HOLD.json")
            r.write(r.PUBLIC/name,r.seal(sealed))
            return {**sealed,"candidate_executed":False,"training":False}
        stage="RESEARCH_RUNTIME_BEFORE_FREEZE"
        held = _research_hold(r)
        if held:
            return held
        stage="RUNTIME_FREEZE"
        r.prepare_candidates()
        stage="CANDIDATE_ONE_PASS"
        r.run("candidate")
        stage="FOLLOWUP_PREPARATION"
        r.prepare_followups()
        stage="FOLLOWUP_ONE_PASS"
        r.run("followup")
        stage="BLIND_REVIEW_PREPARATION"
        r.prepare_reviews()
        stage="BLIND_REVIEW"
        r.run("review")
        stage="FINALISE"
        return r.finalise()
    except Exception as exc:
        name = ("CONTINUOUS-SCHEMA-REPAIR-FAILURE.json" if schema_repair_resume else
                "CONTINUOUS-PLAN-RESUME-FAILURE.json" if resume else "CONTINUOUS-RUN-FAILURE.json")
        r.write(r.PUBLIC/name,r.seal({
            "run_id":r.RUN_ID,"stage":stage,"error_type":type(exc).__name__,
            "error_fingerprint":r.digest(str(exc)),"automatic_retry":False,
            "candidate_execution_marker_present":(r.PUBLIC/"ONE-PASS-START.json").exists(),
            "training":False,"adapter_activation":False,"promotion":False,"live":False}))
        raise


if __name__=="__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resume", action="store_true", help="Resume the exact interrupted preseal plan once")
    parser.add_argument("--schema-repair-resume", action="store_true", help="Resume the exact drained schema-correction route once")
    args = parser.parse_args()
    print(json.dumps(continue_route(resume=args.resume, schema_repair_resume=args.schema_repair_resume)),flush=True)
