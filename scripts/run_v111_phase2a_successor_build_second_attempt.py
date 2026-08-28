#!/usr/bin/env python3
"""Claim exactly attempt 2 of the same Phase-2A successor build once."""

from __future__ import annotations

import json

from backend.app.config import settings
from backend.app.db import Database
from backend.app.orchestration.index_worker import DedicatedIndexWorker
from backend.app.types import JobType

BUILD_ID = "current-law-ew-full-fp16-v111-20260827-phase2a-a"
JOB_ID = f"index-{BUILD_ID}"
WORKER_ID = "phase2a-successor-index-worker-20260827-b"


def main() -> None:
    database = Database(settings.database_path)
    try:
        database.initialize()
        expected = database.job(JOB_ID)
        checkpoint = json.loads(str(expected["checkpoint_json"] or "{}")) if expected else {}
        build = database.fetchone(
            "SELECT status,stage,failure_reason_code FROM index_builds WHERE id=?",
            (BUILD_ID,),
        )
        if (
            expected is None
            or build is None
            or expected["status"] != "queued"
            or int(expected["attempt_count"] or 0) != 1
            or int(expected["cancel_requested"] or 0) != 0
            or expected["lease_owner"] is not None
            or expected["pinned_index_build_id"] != BUILD_ID
            or checkpoint.get("schema") != "legalbot.index-lease-loss-recovery.v1"
            or checkpoint.get("build_id") != BUILD_ID
            or checkpoint.get("automatic_third_claim") is not False
            or build["status"] != "queued"
            or build["failure_reason_code"] is not None
        ):
            raise ValueError("exact Phase-2A successor is not queued for bounded attempt 2")
        row = database.claim_next_job(
            WORKER_ID,
            lease_seconds=120,
            job_types=(JobType.INDEX_BUILD,),
        )
        if row is None:
            raise ValueError("exact Phase-2A successor attempt 2 could not be claimed")
        if (
            row["id"] != JOB_ID
            or row["pinned_index_build_id"] != BUILD_ID
            or int(row["attempt_count"] or 0) != 2
        ):
            database.release_job_lease(str(row["id"]), WORKER_ID)
            raise ValueError("attempt-2 runner refused a different job or attempt")
        print(
            json.dumps(
                {
                    "status": "CLAIMED_EXACT_PHASE2A_SUCCESSOR_ATTEMPT_2",
                    "job_id": JOB_ID,
                    "build_id": BUILD_ID,
                    "attempt_count": 2,
                    "worker_id": WORKER_ID,
                    "automatic_third_claim": False,
                },
                indent=2,
                sort_keys=True,
            ),
            flush=True,
        )
        DedicatedIndexWorker(
            settings,
            database,
            worker_id=WORKER_ID,
            lease_seconds=120,
        )._run_claim(dict(row))
        final = database.job(JOB_ID)
        final_build = database.fetchone(
            "SELECT status,stage,failure_reason_code FROM index_builds WHERE id=?",
            (BUILD_ID,),
        )
        print(
            json.dumps(
                {
                    "status": "BOUNDED_ATTEMPT_2_RETURNED",
                    "job_status": final["status"] if final is not None else "missing",
                    "job_stage": final["stage"] if final is not None else "missing",
                    "attempt_count": (
                        int(final["attempt_count"] or 0) if final is not None else None
                    ),
                    "error_code": final["error_code"] if final is not None else None,
                    "build_status": (
                        final_build["status"] if final_build is not None else "missing"
                    ),
                    "build_stage": (
                        final_build["stage"] if final_build is not None else "missing"
                    ),
                    "failure_reason_code": (
                        final_build["failure_reason_code"]
                        if final_build is not None
                        else None
                    ),
                    "automatic_third_claim": False,
                },
                indent=2,
                sort_keys=True,
            ),
            flush=True,
        )
    finally:
        database.close()


if __name__ == "__main__":
    main()
