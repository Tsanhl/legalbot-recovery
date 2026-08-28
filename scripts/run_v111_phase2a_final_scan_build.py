#!/usr/bin/env python3
"""Preflight and execute the one receipt-bound final Phase-2A scan/build.

`preflight` is the default and is read-only.  Mutating subcommands require the
exact execution-authority SHA on the command line and never run a later phase.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.config import Settings  # noqa: E402
from backend.app.crypto import LocalCipher  # noqa: E402
from backend.app.db import Database  # noqa: E402
from backend.app.retrieval.phase2a_dynamic_scope import (  # noqa: E402
    freeze_dynamic_phase2a_scope,
)
from backend.app.retrieval.phase2a_scan_build_execution import (  # noqa: E402
    EXECUTION_AUTHORITY_CONTENT_SHA256,
    OWNER_APPROVAL_RECEIPT_CONTENT_SHA256,
    assess_same_identity_embedding_resume,
    build_preflight,
    run_complete_source_scan_once,
    run_non_active_successor_build_once,
)

DEFAULT_PREDECESSOR_BUILD_ID = "current-law-ew-full-fp16-v111-20260827-phase2a-a"


def _load_object(path: Path, *, code: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(code)
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(code)
    return value


def _require_execution_token(value: str | None) -> None:
    if value != EXECUTION_AUTHORITY_CONTENT_SHA256:
        raise ValueError("exact Phase-2A execution-authority SHA is required")


def _write_new_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            raw = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
                "utf-8"
            )
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _require_stage_output(settings: Settings, path: Path, *, filename: str) -> None:
    if path.name != filename or path.exists() or path.is_symlink():
        raise ValueError(f"create-only {filename} output is required")
    review_root = (settings.evaluation_dir / "phase2a-owner-review").resolve()
    try:
        path.parent.resolve().relative_to(review_root)
    except ValueError as exc:
        raise ValueError(f"{filename} must remain under the Phase-2A review root") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command")

    preflight = subparsers.add_parser("preflight", help="read-only exact preflight")
    preflight.add_argument("--materialization-ledger", type=Path)
    preflight.add_argument("--predecessor-build-id", default=DEFAULT_PREDECESSOR_BUILD_ID)
    preflight.add_argument("--output", type=Path)

    scan = subparsers.add_parser("run-scan", help="run the one complete source scan")
    scan.add_argument("--preflight", type=Path, required=True)
    scan.add_argument("--execute-authority-sha", required=True)
    scan.add_argument("--receipt-output", type=Path, required=True)

    freeze = subparsers.add_parser(
        "freeze-scope", help="freeze the exact post-scan catalogue scope"
    )
    freeze.add_argument("--application-ledger", type=Path, required=True)
    freeze.add_argument("--materialization-ledger", type=Path, required=True)
    freeze.add_argument("--source-root-inventory-sha", required=True)
    freeze.add_argument("--output-root", type=Path, required=True)
    freeze.add_argument("--predecessor-build-id", default=DEFAULT_PREDECESSOR_BUILD_ID)
    freeze.add_argument("--execute-authority-sha", required=True)

    build = subparsers.add_parser("run-build", help="claim one non-ACTIVE successor build attempt")
    build.add_argument("--corpus-id", required=True)
    build.add_argument("--worker-id", required=True)
    build.add_argument("--execute-authority-sha", required=True)
    build.add_argument("--receipt-output", type=Path, required=True)

    resume = subparsers.add_parser("assess-resume", help="read-only same-build resume eligibility")
    resume.add_argument("--corpus-id", required=True)
    resume.add_argument("--build-id", required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    command = args.command or "preflight"
    settings = Settings()
    database = Database(settings.database_path)
    try:
        if command == "preflight":
            output = getattr(args, "output", None)
            if output is not None:
                _require_stage_output(settings, output, filename="PRE-SCAN-PREFLIGHT.json")
            result = build_preflight(
                settings,
                database,
                predecessor_build_id=str(
                    getattr(args, "predecessor_build_id", DEFAULT_PREDECESSOR_BUILD_ID)
                ),
                materialization_ledger_path=getattr(args, "materialization_ledger", None),
            )
        elif command == "run-scan":
            _require_execution_token(args.execute_authority_sha)
            _require_stage_output(
                settings,
                args.receipt_output,
                filename="SOURCE-SCAN-RECEIPT.json",
            )
            database.initialize()
            result = run_complete_source_scan_once(
                settings,
                database,
                LocalCipher.from_local_key(create=False),
                preflight=_load_object(
                    args.preflight, code="phase2a scan preflight is unavailable"
                ),
            )
        elif command == "freeze-scope":
            _require_execution_token(args.execute_authority_sha)
            database.initialize()
            owner_receipt = (
                settings.evaluation_dir
                / "phase2a-owner-review"
                / "LegalBot-Phase2A-2026-08-28-final-remediation-owner-approved-r1"
                / "OWNER-ADOPTION-RECEIPT.json"
            )
            frozen = freeze_dynamic_phase2a_scope(
                settings,
                database,
                owner_approval_receipt_path=owner_receipt,
                owner_approval_receipt_content_sha256=(OWNER_APPROVAL_RECEIPT_CONTENT_SHA256),
                application_ledger_path=args.application_ledger,
                materialization_ledger_path=args.materialization_ledger,
                output_root=args.output_root,
                predecessor_build_id=args.predecessor_build_id,
                source_root_inventory_content_sha256=(args.source_root_inventory_sha),
            )
            result = {
                "status": "DYNAMIC_SCOPE_FROZEN_BUILD_NOT_STARTED",
                "corpus_id": frozen["scope"]["corpus_id"],
                "scope_content_sha256": frozen["scope"]["scope_content_sha256"],
                "package_content_sha256": frozen["package"]["package_content_sha256"],
                "source_count": frozen["scope"]["source_count"],
                "chunk_count": frozen["scope"]["chunk_count"],
                "source_scan_run": False,
                "successor_build_run": False,
                "active_or_previous_written": False,
            }
        elif command == "run-build":
            _require_execution_token(args.execute_authority_sha)
            _require_stage_output(
                settings,
                args.receipt_output,
                filename="SUCCESSOR-BUILD-RECEIPT.json",
            )
            database.initialize()
            result = run_non_active_successor_build_once(
                settings,
                database,
                corpus_id=args.corpus_id,
                worker_id=args.worker_id,
            )
        elif command == "assess-resume":
            result = assess_same_identity_embedding_resume(
                settings,
                database,
                corpus_id=args.corpus_id,
                build_id=args.build_id,
            )
        else:  # pragma: no cover - argparse owns this boundary
            raise ValueError("unsupported Phase-2A scan/build command")
        output = getattr(args, "output", None) or getattr(args, "receipt_output", None)
        if output is not None:
            _write_new_json(output, result)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    finally:
        database.close()


if __name__ == "__main__":
    # The command never relies on environment-selected source roots.  The scan
    # helper installs its exact tuple through Settings.explicit_source_roots.
    os.umask(0o077)
    main()
