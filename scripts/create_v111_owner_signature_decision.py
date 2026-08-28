#!/usr/bin/env python3
"""Create the sealed owner stop for v1.11 trusted-signature policy.

This command creates no key and no resolution.  It records the bounded shared
owner-trust choice and keeps every owner-only authority boundary closed until
a trusted verifier is selected and implemented.
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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="create-v111-owner-signature-decision")
    parser.add_argument("--integration-sha", required=True)
    parser.add_argument(
        "--store-root",
        default=str(PROJECT_ROOT / "data/evaluations/owner-decisions"),
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    if _INTEGRATION_SHA.fullmatch(args.integration_sha) is None:
        raise ValueError("integration SHA is invalid")
    integration_sha = require_exact_clean_head(PROJECT_ROOT, str(args.integration_sha))
    implementation_paths = {
        "all60-currentness": PROJECT_ROOT / "backend/app/evaluation/all60_qualification.py",
        "completion-memory-authority": PROJECT_ROOT
        / "backend/app/evaluation/candidate_completion_authority.py",
        "completion-memory-preflight": PROJECT_ROOT
        / "backend/app/evaluation/candidate_completion_preflight.py",
        "owner-decision-envelope": PROJECT_ROOT / "backend/app/governance/owner_stop.py",
        "privacy-root-authority": PROJECT_ROOT
        / "backend/app/governance/v111_decision_generation.py",
        "owner-canary-authorization": PROJECT_ROOT
        / "backend/app/evaluation/owner_quality_canary_authorization.py",
        "owner-canary-runtime": PROJECT_ROOT
        / "backend/app/evaluation/owner_quality_canary_runtime.py",
        "docx-inspection": PROJECT_ROOT / "backend/app/evaluation/owner_quality_canary_docx.py",
        "promotion": PROJECT_ROOT / "backend/app/evaluation/owner_quality_v111_promotion.py",
        "normal-live": PROJECT_ROOT
        / "backend/app/evaluation/owner_quality_normal_live_readiness.py",
        "first-live-rollback": PROJECT_ROOT
        / "backend/app/evaluation/v111_technical_attestation.py",
    }
    implementation_hashes: dict[str, str] = {}
    for boundary, path in sorted(implementation_paths.items()):
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("trusted owner gate implementation is unsafe")
        implementation_hashes[boundary] = hashlib.sha256(path.read_bytes()).hexdigest()
    verifier_boundary_sha256 = hashlib.sha256(
        (
            json.dumps(
                {
                    "schema": "legalbot.v111-fail-closed-owner-boundaries.v1",
                    "members": implementation_hashes,
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    ).hexdigest()
    commit_evidence_sha256 = hashlib.sha256(integration_sha.encode()).hexdigest()
    suffix = integration_sha[:12]
    request = seal_owner_decision_request(
        decision_id=f"v111-trusted-owner-signature-{suffix}",
        category="policy",
        scope_id=f"v111-owner-quality-{suffix}",
        reason_codes=(
            "TRUSTED_OWNER_SIGNATURE_POLICY_REQUIRED",
            "SELF_SEALED_INTENT_NOT_AUTHORITY",
            "MEMORY_POLICY_SIGNATURE_REQUIRED",
            "LEGAL_CURRENTNESS_SIGNATURE_REQUIRED",
            "OUTPUT_PRIVACY_ROOT_SIGNATURE_REQUIRED",
            "DOCX_VISUAL_INSPECTION_SIGNATURE_REQUIRED",
            "PROMOTION_SIGNATURE_REQUIRED",
            "O04_SIGNATURE_REQUIRED",
            "POST_RUN_ACCEPTANCE_SIGNATURE_REQUIRED",
            "BOOTSTRAP_POLICY_SELECTION_NOT_TECHNICAL_READINESS",
        ),
        evidence=(
            {
                "evidence_id": f"integration-commit-{suffix}",
                "kind": "integration_commit",
                "sha256": commit_evidence_sha256,
                "summary_code": "HARDENED_GATE_COMMIT",
            },
            {
                "evidence_id": f"signature-boundaries-{suffix}",
                "kind": "signature_boundary_implementation",
                "sha256": verifier_boundary_sha256,
                "summary_code": "EXACT_FAIL_CLOSED_SIGNATURE_BOUNDARIES",
            },
        ),
        options=(
            {
                "option_id": "local-ed25519-pinned-key",
                "outcome_code": "PIN_LOCAL_ED25519_PUBLIC_KEY",
                "recommended": True,
                "consequence_codes": (
                    "ENABLE_TRUSTED_OWNER_VERIFICATION",
                    "KEEP_PRIVATE_LOCAL_BOUNDARY",
                    "PIN_PUBLIC_KEY_IN_TRACKED_CONFIG",
                    "KEEP_ENCRYPTED_PASSPHRASE_PRIVATE_KEY_OUTSIDE_PROJECT",
                ),
            },
            {
                "option_id": "hardware-backed-signature",
                "outcome_code": "USE_HARDWARE_BACKED_SIGNATURE",
                "recommended": False,
                "consequence_codes": ("REQUIRE_HARDWARE_INTEGRATION",),
            },
            {
                "option_id": "defer-and-keep-closed",
                "outcome_code": "KEEP_AUTHORITY_GATES_CLOSED",
                "recommended": False,
                "consequence_codes": ("NO_AUTHORITATIVE_LIVE_TRANSITION",),
            },
        ),
        blocked_actions=(
            "authoritative_completion_memory_policy",
            "authoritative_legal_currentness",
            "authoritative_private_output_root",
            "authoritative_canary_output",
            "docx_visual_acceptance",
            "active_promotion",
            "o04_authorization",
            "post_run_owner_acceptance",
            "normal_live",
        ),
        created_at=datetime.now(UTC),
    )
    require_exact_clean_head(PROJECT_ROOT, integration_sha)
    destination = OwnerDecisionStore(Path(args.store_root)).write_request(request)
    print(
        json.dumps(
            {
                "state": request.state,
                "decision_id": request.decision_id,
                "request_seal_sha256": request.seal_sha256,
                "recommended_option_id": request.recommended_option_id,
                "request_filename": destination.name,
                "resolution_created": False,
                "key_created": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
