#!/usr/bin/env python3
"""Create a path-free owner request for one exact external canary output root."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.governance.owner_stop import OwnerDecisionStore  # noqa: E402
from app.governance.v111_decision_generation import (  # noqa: E402
    build_canary_output_privacy_decision_request,
    private_root_identity,
    require_exact_clean_head,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="create-v111-canary-output-privacy-decision")
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--integration-sha", required=True)
    parser.add_argument(
        "--store-root",
        default=str(PROJECT_ROOT / "data/evaluations/owner-decisions"),
    )
    return parser


def _sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("canary privacy implementation file is unsafe")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    integration_sha = require_exact_clean_head(PROJECT_ROOT, str(args.integration_sha))
    root_identity = private_root_identity(args.root, project_root=PROJECT_ROOT)
    runtime_sha256 = _sha256(
        PROJECT_ROOT / "backend/app/evaluation/owner_quality_canary_runtime.py"
    )
    request = build_canary_output_privacy_decision_request(
        root_identity_sha256=root_identity,
        runtime_implementation_sha256=runtime_sha256,
        integration_sha=integration_sha,
        created_at=datetime.now(UTC),
    )
    store_root = Path(args.store_root)
    if private_root_identity(args.root, project_root=PROJECT_ROOT) != root_identity:
        raise RuntimeError("owner private root changed before request write")
    require_exact_clean_head(PROJECT_ROOT, integration_sha)
    destination = OwnerDecisionStore(store_root).write_request(request)
    if private_root_identity(args.root, project_root=PROJECT_ROOT) != root_identity:
        raise RuntimeError("owner private root changed while request was written")
    print(
        json.dumps(
            {
                "state": request.state,
                "decision_id": request.decision_id,
                "request_store_relative_path": destination.relative_to(store_root).as_posix(),
                "request_seal_sha256": request.seal_sha256,
                "root_identity_sha256": root_identity,
                "recommended_option_id": request.recommended_option_id,
                "option_ids": [item.option_id for item in request.options],
                "bound_integration_sha": integration_sha,
                "resolution_created": False,
                "root_created": False,
                "canary_started": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
