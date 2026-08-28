#!/usr/bin/env python3
"""Create or consume the explicit DOCX-bound owner-review companion."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.crypto import LocalCipher  # noqa: E402
from app.evaluation.owner_quality_canary_intake import (  # noqa: E402
    create_owner_review_companion,
    ingest_owner_review_submission,
    load_owner_review_package,
    record_development_diff_from_owner_feedback,
)
from app.evaluation.owner_quality_canary_intake_verification import (  # noqa: E402
    load_verified_owner_review_workspace,
)

_SAFE_CODE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    companion = commands.add_parser(
        "companion-template",
        help="Create a sealed DOCX/render control plus an editable JSON form",
    )
    companion.add_argument("--workspace", required=True, type=Path)
    ingest = commands.add_parser(
        "ingest",
        help="Append an explicitly confirmed exact-30 JSON submission",
    )
    ingest.add_argument("--workspace", required=True, type=Path)
    ingest.add_argument("--submission", required=True, type=Path)
    diff = commands.add_parser(
        "development-diff",
        help="Record an encrypted accepted development-only answer diff",
    )
    diff.add_argument("--source-workspace", required=True, type=Path)
    diff.add_argument("--target-workspace", required=True, type=Path)
    diff.add_argument("--feedback-id", required=True)
    diff.add_argument("--case-id", required=True)
    return parser


def _safe_error_code(exc: BaseException) -> str:
    candidate = re.sub(r"(?<!^)(?=[A-Z])", "_", type(exc).__name__).casefold()
    return candidate if _SAFE_CODE.fullmatch(candidate) else "owner_review_intake_failed"


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "companion-template":
            workspace = load_verified_owner_review_workspace(
                args.workspace.resolve(), project_root=PROJECT_ROOT
            )
            package = load_owner_review_package(workspace)
            _control_path, _form_path, control = create_owner_review_companion(
                workspace=workspace,
                package=package,
            )
            result = {
                "status": "created",
                "companion_id": control.companion_id,
                "companion_control_seal_sha256": control.seal_sha256,
                "case_count": control.case_count,
                "docx_checkbox_marks_parsed": False,
            }
        elif args.command == "ingest":
            workspace = load_verified_owner_review_workspace(
                args.workspace.resolve(), project_root=PROJECT_ROOT
            )
            package = load_owner_review_package(workspace)
            receipt = ingest_owner_review_submission(
                workspace=workspace,
                package=package,
                submission_path=args.submission.resolve(),
                cipher=LocalCipher.from_local_key(create=False),
            )
            result = {
                "status": "accepted_for_recording",
                "intake_id": receipt.intake_id,
                "intake_receipt_seal_sha256": receipt.seal_sha256,
                "case_count": receipt.case_count,
                "all_decisions_passed": receipt.all_decisions_passed,
                "acceptance_summary_created": receipt.acceptance_summary_created,
                "holdout_feedback_used_for_tuning": False,
            }
        else:
            source_workspace = load_verified_owner_review_workspace(
                args.source_workspace.resolve(), project_root=PROJECT_ROOT
            )
            target_workspace = load_verified_owner_review_workspace(
                args.target_workspace.resolve(), project_root=PROJECT_ROOT
            )
            record = record_development_diff_from_owner_feedback(
                source_workspace=source_workspace,
                source_package=load_owner_review_package(source_workspace),
                target_workspace=target_workspace,
                target_package=load_owner_review_package(target_workspace),
                feedback_id=str(args.feedback_id),
                case_id=str(args.case_id),
                cipher=LocalCipher.from_local_key(create=False),
            )
            result = {
                "status": "created",
                "diff_id": record.diff_id,
                "diff_record_seal_sha256": record.seal_sha256,
                "development_only": True,
                "tuning_input_allowed": True,
            }
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "stopped", "error_code": _safe_error_code(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
