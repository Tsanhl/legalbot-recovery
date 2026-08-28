#!/usr/bin/env python3
"""Create the sealed owner stop for exclusive canary model transport.

This command creates no resolution, key, listener, model process or canary
output.  It records the bounded transport choice required by the clean-room
rule that prohibits adding auth without a new approval phase.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.governance.owner_stop import (  # noqa: E402
    OwnerDecisionStore,
    seal_owner_decision_request,
)
from app.governance.v111_decision_generation import (  # noqa: E402
    require_exact_clean_head,
)

_INTEGRATION_SHA = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


def _sha256(path: Path) -> str:
    resolved = path.resolve(strict=True)
    root = PROJECT_ROOT.resolve(strict=True)
    if not resolved.is_relative_to(root) or path.is_symlink() or not resolved.is_file():
        raise ValueError("owner-canary transport evidence file is unsafe")
    return hashlib.sha256(resolved.read_bytes()).hexdigest()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="create-v111-owner-canary-transport-decision")
    parser.add_argument("--integration-sha", required=True)
    parser.add_argument(
        "--store-root",
        default=str(PROJECT_ROOT / "data/evaluations/owner-decisions"),
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    integration_sha = str(args.integration_sha)
    if _INTEGRATION_SHA.fullmatch(integration_sha) is None:
        raise ValueError("integration SHA is invalid")
    integration_sha = require_exact_clean_head(PROJECT_ROOT, integration_sha)
    suffix = integration_sha[:12]
    runtime_path = PROJECT_ROOT / ("backend/app/evaluation/owner_quality_owned_model_runtime.py")
    service_path = PROJECT_ROOT / "backend/app/model_runtime/service.py"
    clean_room_path = PROJECT_ROOT / "AGENTS.md"
    request = seal_owner_decision_request(
        decision_id=f"v111-owner-canary-transport-{suffix}",
        category="policy",
        scope_id=f"owner-canary-transport:{suffix}",
        reason_codes=(
            "EXCLUSIVE_MODEL_TRANSPORT_OWNER_DECISION_REQUIRED",
            "LOOPBACK_GENERATE_ENDPOINT_HAS_NO_CLIENT_LINEAGE",
            "AUTH_CHANGE_REQUIRES_NEW_APPROVAL_PHASE",
            "AUTHORITATIVE_CANARY_BLOCKED_BEFORE_LAUNCH",
        ),
        evidence=(
            {
                "evidence_id": f"integration-commit-{suffix}",
                "kind": "integration_commit",
                "sha256": hashlib.sha256(integration_sha.encode("ascii")).hexdigest(),
                "summary_code": "EXACT_FAIL_CLOSED_INTEGRATION",
            },
            {
                "evidence_id": f"owned-runtime-{suffix}",
                "kind": "runtime_implementation",
                "sha256": _sha256(runtime_path),
                "summary_code": "OWNED_RUNTIME_PRELAUNCH_STOP",
            },
            {
                "evidence_id": f"model-service-{suffix}",
                "kind": "model_service_implementation",
                "sha256": _sha256(service_path),
                "summary_code": "LOOPBACK_GENERATE_ROUTE_WITHOUT_CLIENT_LINEAGE",
            },
            {
                "evidence_id": f"clean-room-policy-{suffix}",
                "kind": "clean_room_policy",
                "sha256": _sha256(clean_room_path),
                "summary_code": "AUTH_REQUIRES_NEW_APPROVAL_PHASE",
            },
        ),
        options=(
            {
                "option_id": "private-unix-domain-socket",
                "outcome_code": "USE_PRIVATE_UNIX_DOMAIN_SOCKET",
                "recommended": True,
                "consequence_codes": (
                    "NO_NETWORK_GENERATION_ENDPOINT",
                    "PRIVATE_0600_SOCKET_ROOT",
                    "REQUIRE_MODEL_RUNTIME_TRANSPORT_CHANGE",
                    "REATTEST_EXACT_REQUEST_LINEAGE",
                ),
            },
            {
                "option_id": "approve-loopback-session-capability",
                "outcome_code": "APPROVE_LOOPBACK_SESSION_CAPABILITY_AUTH_PHASE",
                "recommended": False,
                "consequence_codes": (
                    "NEW_AUTH_APPROVAL_PHASE",
                    "EPHEMERAL_SESSION_CAPABILITY",
                    "REQUEST_LINEAGE_AUDIT_REQUIRED",
                    "KEEP_LITERAL_LOOPBACK_ONLY",
                ),
            },
            {
                "option_id": "verified-in-process-mlx",
                "outcome_code": "USE_VERIFIED_IN_PROCESS_MLX",
                "recommended": False,
                "consequence_codes": (
                    "REMOVE_NETWORK_CLIENT_RACE",
                    "REQUIRE_PRODUCTION_PARITY_REATTESTATION",
                    "CHANGE_RUNTIME_TOPOLOGY",
                ),
            },
        ),
        blocked_actions=(
            "authoritative-development-canary",
            "authoritative-holdout-canary",
            "owner-live-promotion",
            "normal-owner-only-live",
        ),
        created_at=datetime.now(UTC),
    )
    store_root = Path(args.store_root)
    require_exact_clean_head(PROJECT_ROOT, integration_sha)
    destination = OwnerDecisionStore(store_root).write_request(request)
    print(
        json.dumps(
            {
                "state": request.state,
                "reason_code": "owner_canary_exclusive_model_transport_unresolved",
                "decision_id": request.decision_id,
                "request_store_relative_path": destination.relative_to(store_root).as_posix(),
                "request_seal_sha256": request.seal_sha256,
                "recommended_option_id": request.recommended_option_id,
                "option_ids": [item.option_id for item in request.options],
                "bound_integration_sha": integration_sha,
                "resolution_created": False,
                "model_launched": False,
                "canary_started": False,
                "active_written": False,
                "o04_written": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
