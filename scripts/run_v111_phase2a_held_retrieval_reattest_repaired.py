#!/usr/bin/env python3
"""Run the one targeted repaired Phase-2A held retrieval re-attestation."""

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

RUN_NAME = "LegalBot-Phase2A-2026-08-27-held-retrieval-reattestation-r2"
REPAIRED_FAILURE_FINGERPRINT = "4c32a571c5c2d8770676b48ffb8b0566fb024d70ba0a240b8253fa678fd7692f"
EXPECTED_QUALIFICATION_SHA256 = "7248e70bb68548b96c12d5dddd1ea18b01fd481a1c7d86c33c834ae7274e2349"
EXPECTED_ROLL_FORWARD_PACKAGE_SHA256 = (
    "d565c4b09eaca7180addd257e80089d91d85d73b241abd4d52aacaa3db252545"
)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_new(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(raw)


def _write_new_json(path: Path, value: Any) -> None:
    _write_new(path, _canonical_json(value))


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"required repaired re-attestation input is unavailable: {path.name}")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise RuntimeError(f"required repaired re-attestation input is invalid: {path.name}")
    return value


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
        "attempt_count": 2,
        "repair_of_failure_fingerprint": REPAIRED_FAILURE_FINGERPRINT,
        "candidate_qualification_sha256": EXPECTED_QUALIFICATION_SHA256,
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
    _write_new(root / "SHA256SUMS.txt", ("\n".join(records) + "\n").encode())


def _verify_repair_binding() -> None:
    qualification_path = settings.project_root / "config/candidate_provision_qualification.v1.json"
    if _sha256_file(qualification_path) != EXPECTED_QUALIFICATION_SHA256:
        raise RuntimeError("repaired candidate qualification identity changed")
    qualification = _load_object(qualification_path)
    if (
        qualification.get("status") != "active"
        or (qualification.get("candidate") or {}).get("build_id") != BUILD_ID
        or qualification.get("record_count") != 4
    ):
        raise RuntimeError("repaired candidate qualification boundary changed")
    roll_forward = _load_object(
        settings.evaluation_dir
        / "phase2a-owner-review"
        / "LegalBot-Phase2A-2026-08-27-candidate-provision-qualification-roll-forward"
        / "PACKAGE-INDEX.json"
    )
    if roll_forward.get("package_content_sha256") != EXPECTED_ROLL_FORWARD_PACKAGE_SHA256:
        raise RuntimeError("candidate qualification roll-forward evidence identity changed")


def main() -> None:
    root = settings.evaluation_dir / "phase2a-owner-review" / RUN_NAME
    if root.exists():
        raise FileExistsError("repaired held retrieval re-attestation already exists")
    root.mkdir(parents=True)
    _write_new_json(
        root / "INTENT.json",
        {
            "schema": "legalbot.v111.phase2a.held-retrieval-reattestation-intent.v1",
            "started_at": datetime.now(UTC).isoformat(),
            "build_id": BUILD_ID,
            "attempt_count": 2,
            "repair_of_failure_fingerprint": REPAIRED_FAILURE_FINGERPRINT,
            "targeted_change": "candidate_provision_qualification_build_binding_only",
            "candidate_qualification_sha256": EXPECTED_QUALIFICATION_SHA256,
            "unchanged_retry": False,
            "automatic_third_attempt": False,
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
        _verify_repair_binding()
        database.initialize()
        summary = reattest_phase2a_held_successor(
            settings,
            database,
            destination=root / "HELD-RETRIEVAL-REATTESTATION.json",
        )
    except BaseException as exc:
        fingerprint_material = {
            "gate": "phase2a_held_retrieval_reattestation_repaired",
            "build_id": BUILD_ID,
            "candidate_qualification_sha256": EXPECTED_QUALIFICATION_SHA256,
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
                "attempt_count": 2,
                "automatic_third_attempt": False,
                "unchanged_retry_authorized": False,
                "root_cause_status": "DEBUG_REQUIRED_BEFORE_ANY_THIRD_METHODOLOGY",
                "completed_work": "failure evidence persisted; build remains held",
                "candidate_mutated": False,
                "active_or_previous_written": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            },
        )
        _write_new(
            root / "OUTCOME.txt",
            b"PHASE 2A HELD RETRIEVAL RE-ATTESTATION R2 SAFELY STOPPED - DEBUG REQUIRED\n",
        )
        package = _package_index(root, status="SAFELY_STOPPED_DEBUG_REQUIRED")
        _write_new_json(root / "PACKAGE-INDEX.json", package)
        _write_sums(root)
        raise
    finally:
        database.close()

    _write_new_json(root / "SUMMARY.json", summary)
    _write_new(
        root / "OUTCOME.txt",
        b"PHASE 2A HELD RETRIEVAL RE-ATTESTATION R2 PASSED\n"
        b"BUILD REMAINS BUILT_UNSCORED, NON-ACTIVE, AND ANSWER-INELIGIBLE\n",
    )
    package = _package_index(root, status="PASSED_NON_AUTHORIZING_HELD_EVIDENCE")
    _write_new_json(root / "PACKAGE-INDEX.json", package)
    _write_sums(root)
    print(
        json.dumps(
            {**summary, "package_content_sha256": package["package_content_sha256"]},
            indent=2,
            sort_keys=True,
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
