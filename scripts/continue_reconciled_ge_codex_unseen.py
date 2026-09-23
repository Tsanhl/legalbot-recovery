#!/usr/bin/env python3
"""Run one reconciliation-bound protected construction successor.

The custody worker may read its restricted store internally.  This controller
publishes only redacted public state.  It never seals a bank, freezes or executes
a candidate, scores answers, trains, promotes, or activates live use.
"""
from __future__ import annotations

import json
import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path

from scripts import continue_ge_codex_unseen_creation as creation
from scripts import run_ge_codex_unseen as runner
from scripts.ge_unseen_creation_outcome import inspect_outcome, publish_outcome
from scripts.ge_unseen_research_gate import require_plan_execution


RECONCILIATION = "CONTINUOUS-SCHEMA-REPAIR-INTERRUPTION-COMPLETE.json"
START = "CONTINUOUS-RECONCILED-SUCCESSOR-START.json"
COMPLETE = "CONTINUOUS-RECONCILED-SUCCESSOR-COMPLETE.json"
FAILURE = "CONTINUOUS-RECONCILED-SUCCESSOR-FAILURE.json"


def _verified_reconciliation(r):
    path = r.PUBLIC / RECONCILIATION
    value = r.read(path)
    body = {key: item for key, item in value.items() if key != "content_sha256"}
    projected_sha = hashlib.sha256((json.dumps(body, ensure_ascii=False, sort_keys=True,
        separators=(",", ":")) + "\n").encode()).hexdigest()
    if (value.get("content_sha256") != projected_sha or value.get("run_id") != r.RUN_ID
            or value.get("observation_boundary") != "AUTHORIZED_CUSTODY_RECONCILIATION_PUBLIC_PROJECTION"
            or value.get("private_content_disclosed") is not False
            or value.get("process_reconciliation", {}).get("coordinator_lock") != "FREE"
            or value.get("process_reconciliation", {}).get("inspection_active_count") != 0
            or value.get("process_reconciliation", {}).get("scheduler_active_count") != 0
            or value.get("next_action", {}).get("action")
               != "ISSUE_ONE_BOUNDED_SUCCESSOR_FOR_REMAINING_ELIGIBLE_CONSTRUCTION_WORK"
            or value.get("next_action", {}).get("status") != "PREPARED_NOT_DISPATCHED"):
        raise RuntimeError("PUBLIC_RECONCILIATION_INVALID")
    constraints = set(value["next_action"].get("constraints", []))
    if constraints != {"NO_THIRD_FIXTURE_ATTEMPT",
                       "ONLY_TWO_UNATTEMPTED_FIXTURE_SUCCESSOR_JOBS_RETAIN_AN_ATTEMPT",
                       "NO_CANDIDATE_BEFORE_CONSTRUCTION_AND_FREEZE_GATES_PASS"}:
        raise RuntimeError("PUBLIC_RECONCILIATION_CONSTRAINTS_CHANGED")
    if value.get("construction", {}).get("planned_slots") != 443:
        raise RuntimeError("PUBLIC_RECONCILIATION_DENOMINATOR_CHANGED")
    return value, r.sha(path)


def continue_construction(r=runner, *, drain=None, publish=publish_outcome):
    require_plan_execution(r)
    reconciliation, reconciliation_sha = _verified_reconciliation(r)
    for name in (START, COMPLETE, FAILURE, "BANK-SEAL.json", "RUN-FREEZE.json", "ONE-PASS-START.json"):
        r.safe_path(r.PUBLIC / name)
        if (r.PUBLIC / name).exists():
            raise RuntimeError("RECONCILED_SUCCESSOR_ALREADY_ATTEMPTED_OR_LATER_STAGE_EXISTS")
    with creation.coordinator_lock(r):
        if creation.active_jobs(r):
            raise RuntimeError("PROTECTED_CONSTRUCTION_JOB_ALREADY_ACTIVE")
        start = r.seal({"run_id": r.RUN_ID, "started": datetime.now(UTC).isoformat(),
            "coordinator_pid": os.getpid(), "reconciliation_sha256": reconciliation_sha,
            "plan_execution_sha256": r.sha(r.PUBLIC / "PLAN-EXECUTION-AUTHORIZATION.json"),
            "controller_sha256": r.sha(Path(__file__).resolve()),
            "prior_authored_slots": reconciliation["construction"]["authored_slots"],
            "planned_slots": 443, "bounded_successor": True, "no_third_author_attempt": True,
            "no_third_fixture_attempt": True, "only_unattempted_jobs_dispatchable": True,
            "private_projection_only": True, "candidate_execution": False,
            "bank_seal": False, "runtime_freeze": False, "scoring": False,
            "training": False, "promotion": False, "live": False})
        r.write(r.PUBLIC / START, start)
        try:
            if drain is None:
                creation.main(lock_held=True)
            else:
                drain()
            outcome_receipt = publish(r, schema_repair_resume=True)
            outcome = outcome_receipt["outcome"]
            complete = r.seal({"run_id": r.RUN_ID, "completed": datetime.now(UTC).isoformat(),
                "start_sha256": r.sha(r.PUBLIC / START),
                "reconciliation_sha256": reconciliation_sha,
                "outcome_publication_status": outcome_receipt["status"],
                "overall_state": outcome["overall_state"], "terminal": outcome["terminal"],
                "construction_ready": outcome["construction_ready"],
                "planned_slots": outcome["denominators"]["total"],
                "ready_slots": sum(row["ready"] for row in outcome["cases"].values()),
                "active_jobs": outcome["active_jobs"], "pending_jobs": outcome["pending_jobs"],
                "public_outcome_sha256": outcome.get("content_sha256"),
                "private_content_disclosed": False, "candidate_execution": False,
                "bank_seal": False, "runtime_freeze": False, "scoring": False,
                "training": False, "promotion": False, "live": False})
            r.write(r.PUBLIC / COMPLETE, complete)
            return complete
        except Exception as exc:
            failure = r.seal({"run_id": r.RUN_ID, "failed": datetime.now(UTC).isoformat(),
                "start_sha256": r.sha(r.PUBLIC / START), "error_type": type(exc).__name__,
                "automatic_retry": False, "private_content_disclosed": False,
                "candidate_execution_marker_present": (r.PUBLIC / "ONE-PASS-START.json").exists(),
                "training": False, "promotion": False, "live": False})
            r.write(r.PUBLIC / FAILURE, failure)
            raise


def main():
    print(json.dumps(continue_construction(), sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
