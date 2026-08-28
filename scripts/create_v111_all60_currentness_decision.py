#!/usr/bin/env python3
"""Create the exact All60/legal-currentness owner stop; never resolve it.

The request binds the candidate, source manifest, legal as-of date, integration
commit and qualified issue inventory.  It creates no crawl admission, candidate,
ACTIVE pointer, owner resolution, or legal-currentness assertion.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import UTC, date, datetime
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

_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_INTEGRATION_SHA = re.compile(r"^[0-9a-f]{40,64}$")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="create-v111-all60-currentness-decision")
    parser.add_argument("--candidate-build-id", required=True)
    parser.add_argument("--candidate-manifest-sha256", required=True)
    parser.add_argument("--source-manifest-sha256", required=True)
    parser.add_argument("--all60-inventory-sha256", required=True)
    parser.add_argument("--as-of-date", required=True, type=date.fromisoformat)
    parser.add_argument("--integration-sha", required=True)
    parser.add_argument(
        "--store-root",
        default=str(PROJECT_ROOT / "data/evaluations/owner-decisions"),
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    digests = (
        args.candidate_manifest_sha256,
        args.source_manifest_sha256,
        args.all60_inventory_sha256,
    )
    if (
        _SAFE_ID.fullmatch(args.candidate_build_id) is None
        or any(_SHA256.fullmatch(value) is None for value in digests)
        or _INTEGRATION_SHA.fullmatch(args.integration_sha) is None
    ):
        raise ValueError("All60 currentness decision binding is invalid")
    integration_sha = require_exact_clean_head(PROJECT_ROOT, str(args.integration_sha))
    candidate_root = PROJECT_ROOT / "data/indexes/builds" / args.candidate_build_id
    manifest_path = candidate_root / "manifest.json"
    source_manifest_path = candidate_root / "approved-source-manifest.json"

    def exact_candidate_files() -> bool:
        return (
            not candidate_root.is_symlink()
            and not manifest_path.is_symlink()
            and manifest_path.is_file()
            and not source_manifest_path.is_symlink()
            and source_manifest_path.is_file()
            and hashlib.sha256(manifest_path.read_bytes()).hexdigest()
            == args.candidate_manifest_sha256
            and hashlib.sha256(source_manifest_path.read_bytes()).hexdigest()
            == args.source_manifest_sha256
        )

    if not exact_candidate_files():
        raise RuntimeError("All60 currentness request candidate files differ")
    from app.evaluation.live_suite import sealed_sha256

    identity = sealed_sha256(
        {
            "schema": "legalbot.all60-currentness-owner-decision-identity.v1",
            "candidate_build_id": args.candidate_build_id,
            "candidate_manifest_sha256": args.candidate_manifest_sha256,
            "candidate_source_manifest_sha256": args.source_manifest_sha256,
            "all60_inventory_sha256": args.all60_inventory_sha256,
            "as_of_date": args.as_of_date.isoformat(),
            "integration_sha": integration_sha,
        }
    )
    request = seal_owner_decision_request(
        decision_id=f"v111-all60-currentness-{identity[:20]}",
        category="legal_currentness",
        scope_id=f"currentness:{identity[:20]}",
        reason_codes=(
            "LEGAL_CURRENTNESS_OWNER_JUDGMENT_REQUIRED",
            "FAVORABLE_QUALIFICATION_NOT_CURRENTNESS_AUTHORITY",
            "CRAWLER_OUTPUT_STAGING_ONLY",
            "CURRENT_CANDIDATE_IMMUTABLE",
        ),
        evidence=(
            {
                "evidence_id": "candidate-manifest",
                "kind": "candidate_manifest",
                "sha256": args.candidate_manifest_sha256,
                "summary_code": "EXACT_SEALED_CANDIDATE",
            },
            {
                "evidence_id": "candidate-source-manifest",
                "kind": "source_manifest",
                "sha256": args.source_manifest_sha256,
                "summary_code": "EXACT_APPROVED_SOURCE_SET",
            },
            {
                "evidence_id": "all60-inventory",
                "kind": "all60_inventory",
                "sha256": args.all60_inventory_sha256,
                "summary_code": "EXACT_ALL60_ISSUE_INVENTORY",
            },
            {
                "evidence_id": "legal-as-of-date",
                "kind": "legal_as_of_date",
                "sha256": hashlib.sha256(args.as_of_date.isoformat().encode("ascii")).hexdigest(),
                "summary_code": "EXACT_LEGAL_AS_OF_DATE",
            },
            {
                "evidence_id": "integration",
                "kind": "integration_commit",
                "sha256": hashlib.sha256(integration_sha.encode("ascii")).hexdigest(),
                "summary_code": "EXACT_INTEGRATION_COMMIT",
            },
        ),
        options=(
            {
                "option_id": "stage-official-currentness-review",
                "outcome_code": "STAGE_ALLOWLISTED_OFFICIAL_CURRENTNESS_REVIEW",
                "recommended": True,
                "consequence_codes": (
                    "CRAWLER_ASYNC_STAGING_ONLY",
                    "NO_CURRENT_ANSWER_FEED",
                    "NEW_CANDIDATE_IF_MATERIAL_CHANGES",
                    "RERUN_QUALIFICATION_PREFLIGHT_STAGE_A",
                ),
            },
            {
                "option_id": "owner-accepts-bound-as-of-date",
                "outcome_code": "OWNER_ACCEPTS_BOUND_LEGAL_AS_OF_DATE",
                "recommended": False,
                "consequence_codes": (
                    "NO_SILENT_CURRENTNESS_INFERENCE",
                    "BIND_EXACT_AS_OF_DATE",
                ),
            },
            {
                "option_id": "defer-and-keep-closed",
                "outcome_code": "KEEP_CURRENTNESS_DEPENDENT_GATES_CLOSED",
                "recommended": False,
                "consequence_codes": ("NO_AUTHORITATIVE_CANARY",),
            },
        ),
        blocked_actions=(
            "authoritative_all60_qualification",
            "authoritative_stage_a",
            "authoritative_development_canary",
            "active_promotion",
            "normal_live",
        ),
        created_at=datetime.now(UTC),
    )
    if not exact_candidate_files():
        raise RuntimeError("All60 currentness request candidate changed before write")
    require_exact_clean_head(PROJECT_ROOT, integration_sha)
    destination = OwnerDecisionStore(Path(args.store_root)).write_request(request)
    print(
        json.dumps(
            {
                "state": request.state,
                "decision_id": request.decision_id,
                "request_store_relative_path": destination.relative_to(
                    Path(args.store_root)
                ).as_posix(),
                "request_seal_sha256": request.seal_sha256,
                "recommended_option_id": request.recommended_option_id,
                "bound_as_of_date": args.as_of_date.isoformat(),
                "resolution_created": False,
                "crawl_started": False,
                "candidate_changed": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
