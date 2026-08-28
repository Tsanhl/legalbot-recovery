#!/usr/bin/env python3
"""Read-only tooling for the v1.11 owner-decision package protocol.

The command cannot generate keys, create packages, sign, append a tranche, or
authorize a run.  Emitting canonical bytes for an external signer additionally
requires an explicit later owner invocation phrase.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.governance.v111_owner_decision_package import (  # noqa: E402
    DetachedOwnerDecisionSignature,
    OwnerDecisionPackage,
    ReleaseBinding,
    build_signature_statement,
    canonical_signature_payload,
    require_exact_release_binding,
    seal_release_binding,
    verify_complete_signature_set,
)
from app.governance.v111_owner_public_key import (  # noqa: E402
    load_pinned_owner_public_key,
)
from app.governance.v111_phase2_preparation import (  # noqa: E402
    Phase2LocalConfiguration,
)

OWNER_INVOCATION_PHRASE = "OWNER-PREPARE-SIGNATURE-PAYLOAD"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="v111-owner-decision-package")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")

    validate = commands.add_parser("validate-package")
    validate.add_argument("--package", required=True, type=Path)

    payload = commands.add_parser("signing-payload")
    payload.add_argument("--package", required=True, type=Path)
    payload.add_argument("--tranche-sequence", required=True, type=int, choices=(1, 2, 3))
    payload.add_argument("--signed-at-utc", required=True)
    payload.add_argument("--owner-invocation", required=True)

    verify = commands.add_parser("verify-signature-set")
    verify.add_argument("--package", required=True, type=Path)
    verify.add_argument("--signature", required=True, action="append", type=Path)
    return parser


def _load_package(path: Path) -> OwnerDecisionPackage:
    return OwnerDecisionPackage.model_validate_json(path.read_bytes())


def _safe_result(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def _reconstruct_release_binding(package: OwnerDecisionPackage) -> ReleaseBinding:
    """Replay current Git, candidate and index bytes without trusting package fields."""

    from app.config import Settings
    from app.evaluation.v111_certification_preparation import (
        exact_clean_code_binding,
        load_candidate_source_inventory,
        load_phase2_candidate_and_retrieval_evidence,
        open_immutable_phase2_catalogue,
    )

    claimed = package.policy_tranche.release_binding
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    code = exact_clean_code_binding(PROJECT_ROOT, expected_head=head)
    settings = Settings(project_root=PROJECT_ROOT)
    with open_immutable_phase2_catalogue(settings.database_path) as database:
        candidate, _retrieval_evidence = load_phase2_candidate_and_retrieval_evidence(
            settings=settings,
            database=database,
            candidate_build_id=claimed.candidate_id,
            code=code,
        )
    _sources, policies = load_candidate_source_inventory(
        build_root=settings.index_dir / "builds" / candidate.build_id,
        candidate=candidate,
    )
    with open_immutable_phase2_catalogue(settings.database_path) as database:
        final_candidate, final_retrieval_evidence = load_phase2_candidate_and_retrieval_evidence(
            settings=settings,
            database=database,
            candidate_build_id=claimed.candidate_id,
            code=code,
        )
    final_sources, final_policies = load_candidate_source_inventory(
        build_root=settings.index_dir / "builds" / final_candidate.build_id,
        candidate=final_candidate,
    )
    final_code = exact_clean_code_binding(PROJECT_ROOT, expected_head=head)
    if (
        final_code != code
        or final_candidate != candidate
        or final_retrieval_evidence != _retrieval_evidence
        or final_sources != _sources
        or final_policies != policies
    ):
        raise RuntimeError("owner-decision release binding changed during reconstruction")
    return seal_release_binding(
        git_commit_sha=final_code.commit_sha,
        git_tree_sha=final_code.tree_sha,
        candidate_id=candidate.build_id,
        candidate_manifest_sha256=candidate.candidate_manifest_sha256,
        candidate_seal_sha256=candidate.candidate_seal_sha256,
        candidate_index_tree_sha256=policies.index_tree_sha256,
        candidate_source_manifest_sha256=candidate.source_manifest_sha256,
    )


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    if args.command == "status":
        _safe_result(
            {
                "schema": "legalbot.v111-owner-decision-package-cli-status.v1",
                "state": "OWNER_INVOCATION_REQUIRED",
                "key_generation_supported": False,
                "signature_creation_supported": False,
                "package_creation_supported": False,
                "split_append_supported": False,
                "configuration_evidence_replay_supported": False,
                "split_evidence_replay_supported": False,
                "development_30_authorized": False,
                "sealed_validation_authorized": False,
                "promotion_authorized": False,
                "live_authorized": False,
            }
        )
        return

    package = _load_package(args.package)
    if args.command == "validate-package":
        _safe_result(
            {
                "schema": "legalbot.v111-owner-decision-package-validation.v1",
                "package_id": package.package_id,
                "package_sha256": package.package_sha256,
                "tranche_count": len(package.tranches),
                "schema_valid": True,
                "owner_authorization_inferred": False,
            }
        )
        return

    if args.command == "signing-payload":
        if args.owner_invocation != OWNER_INVOCATION_PHRASE:
            raise SystemExit("OWNER_INVOCATION_REQUIRED")
        if args.tranche_sequence != 1:
            raise SystemExit("TRUSTED_CONFIGURATION_OR_SPLIT_EVIDENCE_REPLAY_REQUIRED")
        expected_release_binding = _reconstruct_release_binding(package)
        require_exact_release_binding(
            package,
            expected_release_binding=expected_release_binding,
        )
        pinned_key = load_pinned_owner_public_key(
            Phase2LocalConfiguration.from_environment(project_root=PROJECT_ROOT)
        )
        statement = build_signature_statement(
            package,
            tranche_sequence=args.tranche_sequence,
            public_key_bytes=pinned_key.public_key_bytes,
            signed_at_utc=args.signed_at_utc,
        )
        payload = canonical_signature_payload(statement)
        _safe_result(
            {
                "schema": "legalbot.v111-owner-decision-signing-payload.v1",
                "statement": statement.model_dump(mode="json", by_alias=True),
                "payload_base64": base64.b64encode(payload).decode("ascii"),
                "payload_sha256": hashlib.sha256(payload).hexdigest(),
                "pinned_public_key_identity_sha256": (pinned_key.observation.identity_sha256),
                "signature_created": False,
                "owner_authorization_inferred": False,
            }
        )
        return

    if args.command == "verify-signature-set":
        if package.configuration_tranche is not None:
            raise SystemExit("TRUSTED_CONFIGURATION_OR_SPLIT_EVIDENCE_REPLAY_REQUIRED")
        signatures = tuple(
            DetachedOwnerDecisionSignature.model_validate_json(path.read_bytes())
            for path in args.signature
        )
        expected_release_binding = _reconstruct_release_binding(package)
        pinned_key = load_pinned_owner_public_key(
            Phase2LocalConfiguration.from_environment(project_root=PROJECT_ROOT)
        )
        result = verify_complete_signature_set(
            package=package,
            detached_signatures=signatures,
            pinned_public_key_bytes=pinned_key.public_key_bytes,
            expected_release_binding=expected_release_binding,
        )
        _safe_result(
            {
                **result.model_dump(mode="json", by_alias=True),
                "pinned_public_key_identity_sha256": (pinned_key.observation.identity_sha256),
            }
        )
        return

    raise AssertionError("unreachable owner decision package command")


if __name__ == "__main__":
    main()
