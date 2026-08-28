#!/usr/bin/env python3
"""Run the exact Phase-2A held retrieval re-attestation once."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from backend.app.config import settings
from backend.app.db import Database
from backend.app.retrieval.phase2a_held_reattest import (
    BUILD_ID,
    reattest_phase2a_held_successor,
)

RUN_NAME = "LegalBot-Phase2A-2026-08-27-held-retrieval-reattestation"


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_new_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(value)


def _write_new_json(path: Path, value: Any) -> None:
    _write_new_bytes(path, _canonical_json(value))


def _package_index(root: Path, *, status: str) -> dict[str, Any]:
    files = {
        path.relative_to(root).as_posix(): {
            "sha256": _sha256_file(path),
            "size": path.stat().st_size,
        }
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name not in {"PACKAGE-INDEX.json", "SHA256SUMS.txt"}
    }
    payload = {
        "schema": "legalbot.v111.phase2a.held-retrieval-reattestation-package.v1",
        "run_name": RUN_NAME,
        "build_id": BUILD_ID,
        "status": status,
        "files": files,
        "promotion_eligible": False,
        "answer_release_eligible": False,
        "active_or_previous_written": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    payload["package_content_sha256"] = _sha256_bytes(_canonical_json(payload))
    return payload


def _write_sums(root: Path) -> None:
    records = [
        f"{_sha256_file(path)}  {path.relative_to(root).as_posix()}"
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name != "SHA256SUMS.txt"
    ]
    _write_new_bytes(root / "SHA256SUMS.txt", ("\n".join(records) + "\n").encode())


def main() -> None:
    root = settings.evaluation_dir / "phase2a-owner-review" / RUN_NAME
    if root.exists():
        raise FileExistsError("held retrieval re-attestation run already exists; no retry allowed")
    root.mkdir(parents=True)
    started_at = datetime.now(UTC).isoformat()
    _write_new_json(
        root / "INTENT.json",
        {
            "schema": "legalbot.v111.phase2a.held-retrieval-reattestation-intent.v1",
            "started_at": started_at,
            "build_id": BUILD_ID,
            "single_attempt_only": True,
            "planner_model_invoked": False,
            "answer_model_invoked": False,
            "catalogue_status_change_authorized": False,
            "active_or_previous_write_authorized": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        },
    )
    database = Database(settings.database_path)
    try:
        database.initialize()
        summary = reattest_phase2a_held_successor(
            settings,
            database,
            destination=root / "HELD-RETRIEVAL-REATTESTATION.json",
        )
    except BaseException as exc:
        fingerprint_material = {
            "gate": "phase2a_held_retrieval_reattestation",
            "build_id": BUILD_ID,
            "exception_type": type(exc).__name__,
            "exception_message": str(exc),
        }
        _write_new_json(
            root / "FAILURE-REPORT.json",
            {
                "schema": "legalbot.v111.phase2a.held-retrieval-failure.v1",
                "created_at": datetime.now(UTC).isoformat(),
                **fingerprint_material,
                "failure_fingerprint": _sha256_bytes(_canonical_json(fingerprint_material)),
                "attempt_count": 1,
                "unchanged_retry_authorized": False,
                "root_cause_status": "DEBUG_REQUIRED_BEFORE_ANY_NEW_METHODOLOGY",
                "completed_work": "failure evidence persisted; build remains held",
                "candidate_mutated": False,
                "active_or_previous_written": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            },
        )
        _write_new_bytes(
            root / "OUTCOME.txt",
            b"PHASE 2A HELD RETRIEVAL RE-ATTESTATION SAFELY STOPPED - DEBUG REQUIRED\n",
        )
        package = _package_index(root, status="SAFELY_STOPPED_DEBUG_REQUIRED")
        _write_new_json(root / "PACKAGE-INDEX.json", package)
        _write_sums(root)
        raise
    finally:
        database.close()

    _write_new_json(root / "SUMMARY.json", summary)
    _write_new_bytes(
        root / "OUTCOME.txt",
        (
            "PHASE 2A HELD RETRIEVAL RE-ATTESTATION PASSED\n"
            "BUILD REMAINS BUILT_UNSCORED, NON-ACTIVE, AND ANSWER-INELIGIBLE\n"
        ).encode(),
    )
    package = _package_index(root, status="PASSED_NON_AUTHORIZING_HELD_EVIDENCE")
    _write_new_json(root / "PACKAGE-INDEX.json", package)
    _write_sums(root)
    print(json.dumps(summary, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
