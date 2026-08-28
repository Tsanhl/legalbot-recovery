#!/usr/bin/env python3
"""Create the exact v1.11 completion-memory owner request; never resolve it."""

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

from app.config import Settings  # noqa: E402
from app.evaluation.candidate_completion_authority import (  # noqa: E402
    host_physical_memory_bytes,
    load_readonly_sealed_candidate,
)
from app.evaluation.candidate_completion_runtime import (  # noqa: E402
    build_local_completion_runtime_binding,
)
from app.governance.owner_stop import OwnerDecisionStore  # noqa: E402
from app.governance.v111_decision_generation import (  # noqa: E402
    build_completion_memory_decision_request,
    require_exact_clean_head,
)
from app.observability.live_metrics import load_slo_policy  # noqa: E402


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="create-v111-completion-memory-decision")
    parser.add_argument("--candidate-build-id", required=True)
    parser.add_argument("--integration-sha", required=True)
    parser.add_argument(
        "--store-root",
        default=str(PROJECT_ROOT / "data/evaluations/owner-decisions"),
    )
    return parser


def _sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("completion memory identity file is unsafe")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    integration_sha = require_exact_clean_head(PROJECT_ROOT, str(args.integration_sha))
    settings = Settings(project_root=PROJECT_ROOT)
    if not settings.database_path.is_file():
        raise RuntimeError("completion memory request requires the existing catalogue")
    candidate = load_readonly_sealed_candidate(
        settings=settings,
        candidate_build_id=str(args.candidate_build_id),
    )
    if candidate.status != "candidate":
        raise RuntimeError("completion memory request requires the sealed candidate")
    slo = load_slo_policy(settings.observability_slo_path)
    runtime_binding = build_local_completion_runtime_binding(
        settings=settings,
        candidate=candidate,
        slo_policy_id=slo.policy_id,
        slo_policy_sha256=_sha256(settings.observability_slo_path),
        integration_sha=integration_sha,
    )
    request = build_completion_memory_decision_request(
        candidate_build_id=candidate.build_id,
        candidate_manifest_sha256=candidate.candidate_manifest_sha256,
        runtime_binding_sha256=str(runtime_binding["seal_sha256"]),
        integration_sha=integration_sha,
        host_physical_memory_bytes=host_physical_memory_bytes(),
        trusted_model_identity_file_sha256=_sha256(
            PROJECT_ROOT / "config/completion_preflight_model_identity.json"
        ),
        trusted_toolchain_identity_file_sha256=_sha256(
            PROJECT_ROOT / "config/completion_preflight_toolchain_identity.json"
        ),
        created_at=datetime.now(UTC),
    )
    store_root = Path(args.store_root)
    if (
        load_readonly_sealed_candidate(
            settings=settings,
            candidate_build_id=str(args.candidate_build_id),
        )
        != candidate
    ):
        raise RuntimeError("completion memory candidate changed before request write")
    require_exact_clean_head(PROJECT_ROOT, integration_sha)
    destination = OwnerDecisionStore(store_root).write_request(request)
    print(
        json.dumps(
            {
                "state": request.state,
                "decision_id": request.decision_id,
                "request_store_relative_path": destination.relative_to(store_root).as_posix(),
                "request_seal_sha256": request.seal_sha256,
                "recommended_option_id": request.recommended_option_id,
                "option_ids": [item.option_id for item in request.options],
                "bound_candidate_build_id": candidate.build_id,
                "bound_integration_sha": integration_sha,
                "resolution_created": False,
                "policy_created": False,
                "model_launched": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
