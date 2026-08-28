#!/usr/bin/env python3
"""Build the non-authorizing v1.11 complete scorer-closure comparison."""

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

from app.retrieval.scorer_closure import (  # noqa: E402
    build_scorer_closure_manifest,
    write_create_only_scorer_closure_manifest,
)

_GIT_SHA = re.compile(r"^[0-9a-f]{40,64}$")
DEFAULT_ATTESTATION = (
    PROJECT_ROOT
    / "data/evaluations/retrieval/current-law-ew-full-fp16-v111-20260818-a/v1.1-attestation.json"
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--legacy-attestation", type=Path, default=DEFAULT_ATTESTATION)
    parser.add_argument("--out", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        expected_head = str(args.expected_head)
        if _GIT_SHA.fullmatch(expected_head) is None:
            raise ValueError("expected HEAD is invalid")
        output = args.out.resolve()
        allowed = (PROJECT_ROOT / "data/evaluations/retrieval").resolve()
        if not output.is_relative_to(allowed):
            raise ValueError("scorer closure output escaped its private root")
        manifest = build_scorer_closure_manifest(
            project_root=PROJECT_ROOT,
            legacy_attestation_path=args.legacy_attestation.resolve(),
            expected_head=expected_head,
        )
        write_create_only_scorer_closure_manifest(output, manifest)
        print(
            json.dumps(
                {
                    "schema": manifest["schema"],
                    "authorizing": False,
                    "manifest_sha256": manifest["manifest_sha256"],
                    "baseline_aggregate_sha256": manifest["integration_baseline_closure"][
                        "aggregate_sha256"
                    ],
                    "historical_reconstruction_status": manifest["historical_reconstruction"][
                        "status"
                    ],
                    "equivalence_proven": manifest["equivalence_proven"],
                    "reattestation_required": manifest["reattestation_required"],
                },
                sort_keys=True,
            )
        )
        return 0
    except Exception as exc:
        print(
            json.dumps(
                {
                    "schema": "legalbot.scorer-closure-stop.v1",
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
