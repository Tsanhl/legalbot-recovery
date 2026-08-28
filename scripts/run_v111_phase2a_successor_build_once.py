#!/usr/bin/env python3
"""Claim and execute only the exact Phase-2A successor index job once."""

from __future__ import annotations

import json

from backend.app.config import settings
from backend.app.db import Database
from backend.app.orchestration.index_worker import DedicatedIndexWorker
from backend.app.types import JobType

BUILD_ID = "current-law-ew-full-fp16-v111-20260827-phase2a-a"
JOB_ID = f"index-{BUILD_ID}"
WORKER_ID = "phase2a-successor-index-worker-20260827-a"


def main() -> None:
    database = Database(settings.database_path)
    try:
        database.initialize()
        expected = database.job(JOB_ID)
        if (
            expected is None
            or expected["status"] != "queued"
            or int(expected["attempt_count"] or 0) != 0
            or expected["pinned_index_build_id"] != BUILD_ID
        ):
            raise ValueError("exact Phase-2A successor job is not queued for its first attempt")
        row = database.claim_next_job(
            WORKER_ID,
            job_types=(JobType.INDEX_BUILD,),
        )
        if row is None:
            raise ValueError("exact Phase-2A successor job could not be claimed")
        if row["id"] != JOB_ID or row["pinned_index_build_id"] != BUILD_ID:
            database.release_job_lease(str(row["id"]), WORKER_ID)
            raise ValueError("single-claim runner refused a different index job")
        print(
            json.dumps(
                {
                    "status": "CLAIMED_EXACT_PHASE2A_SUCCESSOR_BUILD",
                    "job_id": JOB_ID,
                    "build_id": BUILD_ID,
                    "attempt_count": row["attempt_count"],
                    "worker_id": WORKER_ID,
                    "automatic_second_claim": False,
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
        )._run_claim(dict(row))
        final = database.job(JOB_ID)
        build = database.fetchone(
            "SELECT status,stage,failure_reason_code FROM index_builds WHERE id=?",
            (BUILD_ID,),
        )
        print(
            json.dumps(
                {
                    "status": "SINGLE_CLAIM_COMPLETE",
                    "job_status": final["status"] if final is not None else "missing",
                    "job_stage": final["stage"] if final is not None else "missing",
                    "attempt_count": (
                        int(final["attempt_count"] or 0) if final is not None else None
                    ),
                    "error_code": final["error_code"] if final is not None else None,
                    "build_status": build["status"] if build is not None else "missing",
                    "build_stage": build["stage"] if build is not None else "missing",
                    "failure_reason_code": (
                        build["failure_reason_code"] if build is not None else None
                    ),
                    "automatic_second_claim": False,
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
