#!/usr/bin/env python3
"""Run the fixed, non-authorizing v1.11 Integration Baseline verification."""

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

from app.evaluation.v111_integration_verification import (  # noqa: E402
    run_integration_verification,
)

_GIT_SHA = re.compile(r"^[0-9a-f]{40,64}$")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--expected-head", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        expected_head = str(args.expected_head)
        if _GIT_SHA.fullmatch(expected_head) is None:
            raise ValueError("expected HEAD is invalid")
        report = run_integration_verification(
            project_root=PROJECT_ROOT,
            run_id=str(args.run_id),
            expected_head=expected_head,
        )
        print(
            json.dumps(
                {
                    "schema": report["schema"],
                    "authorizing": False,
                    "run_id": report["run_id"],
                    "commit": report["git"]["commit"],
                    "tree": report["git"]["tree"],
                    "report_sha256": report["report_sha256"],
                    "failed_check_ids": report["failed_check_ids"],
                    "status": report["status"],
                },
                sort_keys=True,
            )
        )
        return 0 if report["passed"] is True else 1
    except Exception as exc:
        print(
            json.dumps(
                {
                    "schema": "legalbot.v111-integration-verification-stop.v1",
                    "authorizing": False,
                    "status": "stopped",
                    "reason_code": type(exc).__name__.casefold(),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
