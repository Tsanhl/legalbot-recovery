#!/usr/bin/env python3
"""Owner-quality v1.11 canary and promotion commands.

Nothing runs by default.  ``run`` invokes the real localhost answer workflow;
``prepare-promotion`` is non-authorizing; ``authorize-promotion`` requires the
owner's exact presentation-bound confirmation; only ``promote`` writes ACTIVE.
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

from app.config import Settings  # noqa: E402
from app.crypto import LocalCipher  # noqa: E402
from app.db import Database  # noqa: E402
from app.evaluation.all60_evidence_review import All60OwnerDecisionRequired  # noqa: E402
from app.evaluation.live_suite import sealed_sha256  # noqa: E402
from app.evaluation.owner_quality_canary_authorization import (  # noqa: E402
    OwnerDecisionRequired,
)
from app.evaluation.owner_quality_canary_runtime import (  # noqa: E402
    execute_owner_quality_canary_with_owned_runtime,
)
from app.evaluation.owner_quality_normal_live_readiness import (  # noqa: E402
    activate_owner_quality_normal_live_readiness,
)
from app.evaluation.owner_quality_v111_promotion import (  # noqa: E402
    prepare_owner_quality_v111_promotion_presentation,
    promote_candidate_index_v111,
    write_owner_quality_v111_promotion_authorization,
)
from app.evaluation.secure_artifact_io import read_private_file_at  # noqa: E402
from app.governance.owner_stop import OwnerDecisionRequest  # noqa: E402

_TECHNICAL_STOP_REASONS = frozenset(
    {
        "authoritative_completion_preflight_required",
        "authoritative_owner_canary_owned_model_runtime_required",
        "trusted_offline_python_matrix_environment_missing",
        "typed_operational_evidence_replay_contract_missing",
    }
)
_SHARED_TRUST_STOP_REASONS = frozenset(
    {
        "trusted_owner_promotion_signature_policy_missing",
        "trusted_owner_o04_signature_verifier_missing",
        "trusted_post_run_owner_acceptance_signature_verifier_missing",
        "trusted_owner_memory_signature_verifier_missing",
        "trusted_owner_decision_signature_verifier_missing",
        "TRUSTED_OWNER_DECISION_SIGNATURE_VERIFIER_MISSING",
        "trusted_owner_docx_inspection_signature_verifier_missing",
    }
)
_PRIVACY_STOP_REASONS = frozenset(
    {
        "trusted_canary_output_privacy_verifier_missing",
        "canary_output_privacy_owner_decision_unresolved",
        "canary_output_root_not_proven_non_synced",
    }
)
_TRANSPORT_STOP_REASONS = frozenset({"owner_canary_exclusive_model_transport_unresolved"})
_MEMORY_STOP_REASONS = frozenset(
    {
        "completion_memory_policy_missing",
        "completion_memory_owner_resolution_missing",
    }
)


def _parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="owner-quality-v111")
    commands = root.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run", help="Run one exact owner-quality 30-case lane")
    run.add_argument("--manifest", required=True)
    run.add_argument("--all60-qualification", required=True)
    run.add_argument("--all60-expert-qualification", required=True)
    run.add_argument("--authorization", required=True)
    run.add_argument("--review-date", required=True)
    run.add_argument("--legal-date", required=True)
    run.add_argument("--base-url", default="http://127.0.0.1:8777")
    run.add_argument("--case-timeout-seconds", type=float, default=10_800.0)

    prepare = commands.add_parser(
        "prepare-promotion",
        help="Verify exact dev30 evidence and create a non-authorizing presentation",
    )
    prepare.add_argument("--manifest", required=True)
    prepare.add_argument("--all60-qualification", required=True)
    prepare.add_argument("--development-authorization", required=True)
    prepare.add_argument("--development-final-package", required=True)
    prepare.add_argument("--development-owner-acceptance", required=True)
    prepare.add_argument("--technical-attestation-admission", required=True)
    prepare.add_argument("--out", required=True)

    authorize = commands.add_parser(
        "authorize-promotion", help="Owner-only creation of the exact ACTIVE authorization"
    )
    authorize.add_argument("--presentation", required=True)
    authorize.add_argument("--owner-ref", required=True)
    authorize.add_argument("--confirm", required=True)
    authorize.add_argument("--out", required=True)

    promote = commands.add_parser(
        "promote", help="Reverify presentation/owner authorization and atomically write ACTIVE"
    )
    promote.add_argument("--presentation", required=True)
    promote.add_argument("--owner-authorization", required=True)
    commands.add_parser(
        "activate-normal-live",
        help=(
            "Admit the exact trusted readiness generation into the catalogue; "
            "fails closed while owner signature policy is unresolved"
        ),
    )
    return root


def _execute(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    settings = Settings(project_root=PROJECT_ROOT)
    if args.command == "run":
        if args.base_url != "http://127.0.0.1:8777":
            raise ValueError("authoritative owner canary does not use an ambient HTTP origin")
        result = execute_owner_quality_canary_with_owned_runtime(
            settings=settings,
            cipher=LocalCipher.from_local_key(create=False),
            manifest_path=Path(args.manifest),
            qualification_path=Path(args.all60_qualification),
            expert_qualification_path=Path(args.all60_expert_qualification),
            authorization_path=Path(args.authorization),
            review_date=date.fromisoformat(args.review_date),
            legal_date=date.fromisoformat(args.legal_date),
            case_timeout_seconds=float(args.case_timeout_seconds),
        )
        print(
            json.dumps(
                {
                    "circuit_status": result.circuit_result.status,
                    "circuit_result_seal_sha256": result.circuit_result.seal_sha256,
                    "final_package_seal_sha256": (
                        result.final_package.seal_sha256 if result.final_package else None
                    ),
                    "writes_active": False,
                    "writes_o04": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return

    database = Database(settings.database_path)
    database.initialize()
    try:
        if args.command == "prepare-promotion":
            presentation = prepare_owner_quality_v111_promotion_presentation(
                settings=settings,
                database=database,
                canary_manifest_path=Path(args.manifest),
                all60_qualification_path=Path(args.all60_qualification),
                development_authorization_path=Path(args.development_authorization),
                development_final_package_path=Path(args.development_final_package),
                development_owner_acceptance_path=Path(args.development_owner_acceptance),
                technical_attestation_admission_path=Path(args.technical_attestation_admission),
                destination=Path(args.out),
                created_at=datetime.now(UTC),
            )
            output: dict[str, object] = {
                "presentation_id": presentation.presentation_id,
                "presentation_seal_sha256": presentation.seal_sha256,
                "candidate_build_id": presentation.candidate_build_id,
                "owner_decision_required": True,
                "authorizes_active": False,
            }
        elif args.command == "authorize-promotion":
            authorization = write_owner_quality_v111_promotion_authorization(
                presentation_path=Path(args.presentation),
                destination=Path(args.out),
                owner_ref=args.owner_ref,
                exact_confirmation=args.confirm,
                authorized_at=datetime.now(UTC),
            )
            output = {
                "authorization_id": authorization.authorization_id,
                "authorization_seal_sha256": authorization.seal_sha256,
                "candidate_build_id": authorization.candidate_build_id,
                "authorizes_active": True,
                "authorizes_o04": False,
            }
        elif args.command == "promote":
            promotion_result = promote_candidate_index_v111(
                settings=settings,
                database=database,
                presentation_path=Path(args.presentation),
                owner_authorization_path=Path(args.owner_authorization),
            )
            output = {}
            output.update(promotion_result)
        else:
            authority_sha256 = activate_owner_quality_normal_live_readiness(
                settings.project_root,
                database=database,
                settings=settings,
            )
            output = {
                "normal_live_generation_admitted": True,
                "normal_live_authority_sha256": authority_sha256,
                "writes_active": False,
                "writes_o04": False,
            }
    finally:
        database.close()
    print(json.dumps(output, indent=2, sort_keys=True))


def _owner_stop_envelope(
    *,
    boundary: str,
    reason_code: str,
    row_id: str | None,
    decision_id_hint: str | None = None,
) -> dict[str, object]:
    safe_boundary = boundary if re.fullmatch(r"[a-z][a-z0-9-]{1,63}", boundary) else "unknown"
    decision_root = PROJECT_ROOT / "data/evaluations/owner-decisions"
    technical_stop = reason_code in _TECHNICAL_STOP_REASONS
    expected_decision_id: str | None = None
    fallback_options: list[str]
    fallback_recommended: str
    if technical_stop:
        fallback_options = ["implement-and-reverify", "defer-and-keep-closed"]
        fallback_recommended = "implement-and-reverify"
    elif reason_code in _TRANSPORT_STOP_REASONS:
        try:
            from app.retrieval.retrieval_reattest import _clean_integration_sha

            integration_sha = _clean_integration_sha(PROJECT_ROOT)
            expected_decision_id = f"v111-owner-canary-transport-{integration_sha[:12]}"
        except (OSError, RuntimeError):
            expected_decision_id = "v111-owner-canary-transport-current-commit"
        fallback_options = [
            "private-unix-domain-socket",
            "approve-loopback-session-capability",
            "verified-in-process-mlx",
        ]
        fallback_recommended = "private-unix-domain-socket"
    elif reason_code in _SHARED_TRUST_STOP_REASONS:
        try:
            from app.retrieval.retrieval_reattest import _clean_integration_sha

            integration_sha = _clean_integration_sha(PROJECT_ROOT)
            expected_decision_id = f"v111-trusted-owner-signature-{integration_sha[:12]}"
        except (OSError, RuntimeError):
            expected_decision_id = "v111-trusted-owner-signature-current-commit"
        fallback_options = [
            "local-ed25519-pinned-key",
            "hardware-backed-signature",
            "defer-and-keep-closed",
        ]
        fallback_recommended = "local-ed25519-pinned-key"
    elif decision_id_hint is not None:
        expected_decision_id = decision_id_hint
        fallback_options = [
            "stage-official-currentness-review",
            "owner-accepts-bound-as-of-date",
            "defer-and-keep-closed",
        ]
        fallback_recommended = "stage-official-currentness-review"
    elif reason_code in _MEMORY_STOP_REASONS:
        # The authoritative memory request ID is candidate/runtime/host/HEAD
        # derived by create_v111_completion_memory_decision.py.  This generic
        # stop has no candidate binding and must not guess or reuse the legacy
        # fixed request ID.
        expected_decision_id = None
        fallback_options = [
            "max-12884901888-min-3221225472",
            "max-10737418240-min-4294967296",
        ]
        fallback_recommended = "max-12884901888-min-3221225472"
    elif reason_code in _PRIVACY_STOP_REASONS:
        try:
            from app.governance.v111_decision_generation import (
                canary_output_privacy_decision_id,
                private_root_identity,
            )
            from app.retrieval.retrieval_reattest import _clean_integration_sha

            settings = Settings(project_root=PROJECT_ROOT)
            configured_root = settings.canary_review_root
            if configured_root is None:
                raise RuntimeError("exact private root is not configured")
            integration_sha = _clean_integration_sha(PROJECT_ROOT)
            runtime_path = PROJECT_ROOT / "backend/app/evaluation/owner_quality_canary_runtime.py"
            expected_decision_id = canary_output_privacy_decision_id(
                root_identity_sha256=private_root_identity(
                    configured_root, project_root=PROJECT_ROOT
                ),
                runtime_implementation_sha256=hashlib.sha256(runtime_path.read_bytes()).hexdigest(),
                integration_sha=integration_sha,
            )
        except (OSError, RuntimeError, ValueError):
            expected_decision_id = None
        fallback_options = [
            "approve-owner-private-nonsynced-root",
            "select-different-private-root",
            "defer-and-keep-closed",
        ]
        fallback_recommended = "approve-owner-private-nonsynced-root"
    else:
        # Source-rights, legal-standard and competing-fix judgments need their
        # own evidence-bound request.  Do not misroute them to the generic
        # signature-policy choice.
        expected_decision_id = None
        fallback_options = ["create-exact-owner-decision-request", "defer-and-keep-closed"]
        fallback_recommended = "create-exact-owner-decision-request"
    decision_request: OwnerDecisionRequest | None = None
    request_relative_path: str | None = None
    if expected_decision_id is not None and re.fullmatch(
        r"[a-z0-9][a-z0-9._:-]{2,127}", expected_decision_id
    ):
        request_relative_path = (
            Path("data/evaluations/owner-decisions") / expected_decision_id / "request.json"
        ).as_posix()
        try:
            decision_request = OwnerDecisionRequest.model_validate_json(
                read_private_file_at(decision_root, (expected_decision_id, "request.json"))
            )
            if decision_request.decision_id != expected_decision_id:
                decision_request = None
        except (FileNotFoundError, OSError, ValueError):
            decision_request = None
    prior_request_seal: str | None = None
    if (
        decision_id_hint is not None
        and decision_id_hint != expected_decision_id
        and re.fullmatch(r"[a-z0-9][a-z0-9._:-]{2,127}", decision_id_hint)
    ):
        try:
            prior_request = OwnerDecisionRequest.model_validate_json(
                read_private_file_at(decision_root, (decision_id_hint, "request.json"))
            )
            if prior_request.decision_id == decision_id_hint:
                prior_request_seal = prior_request.seal_sha256
        except (FileNotFoundError, OSError, ValueError):
            prior_request_seal = None
    stop_identity = hashlib.sha256(
        f"legalbot-owner-quality-stop-v1\0{safe_boundary}\0{reason_code}\0{row_id or ''}".encode()
    ).hexdigest()
    material: dict[str, object] = {
        "schema": "legalbot.owner-quality-v111-stop.v1",
        "state": (
            "TECHNICAL_IMPLEMENTATION_REQUIRED" if technical_stop else "OWNER_DECISION_REQUIRED"
        ),
        "reason_code": reason_code,
        "boundary": safe_boundary,
        "decision_id": expected_decision_id,
        "decision_request_relative_path": request_relative_path,
        "decision_request_seal_sha256": (
            decision_request.seal_sha256 if decision_request is not None else None
        ),
        "bounded_option_ids": (
            [option.option_id for option in decision_request.options]
            if decision_request is not None
            else fallback_options
        ),
        "safe_evidence_codes": (
            [item.summary_code for item in decision_request.evidence]
            if decision_request is not None
            else [
                (
                    "TECHNICAL_IMPLEMENTATION_NOT_COMPLETE"
                    if technical_stop
                    else "EXACT_OWNER_DECISION_REQUEST_NOT_CREATED"
                )
            ]
        ),
        "safe_evidence_digests": [
            {"kind": "stop_context", "sha256": stop_identity},
            *(
                [{"kind": "resolved_substantive_request", "sha256": prior_request_seal}]
                if prior_request_seal is not None
                else []
            ),
        ],
        "recommended_option_id": (
            decision_request.recommended_option_id
            if decision_request is not None
            else fallback_recommended
        ),
        "continuation_allowed": False,
        "writes_active": False,
        "writes_o04": False,
    }
    material["seal_sha256"] = sealed_sha256(material)
    return material


def main(argv: list[str] | None = None) -> None:
    raw = list(argv) if argv is not None else list(sys.argv[1:])
    boundary = raw[0] if raw else "unknown"
    try:
        _execute(raw)
    except (OwnerDecisionRequired, All60OwnerDecisionRequired) as exc:
        reason_code = exc.reason_code
        row_id = exc.row_id if isinstance(exc, All60OwnerDecisionRequired) else None
        decision_id_hint = exc.decision_id if isinstance(exc, All60OwnerDecisionRequired) else None
        print(
            json.dumps(
                _owner_stop_envelope(
                    boundary=boundary,
                    reason_code=reason_code,
                    row_id=row_id,
                    decision_id_hint=decision_id_hint,
                ),
                indent=2,
                sort_keys=True,
            )
        )
        raise SystemExit(3) from None
    except RuntimeError as exc:
        raw_reason = str(exc.args[0]) if exc.args else ""
        technical_prefix = "TECHNICAL_IMPLEMENTATION_REQUIRED:"
        owner_prefix = "OWNER_DECISION_REQUIRED:"
        if raw_reason.startswith(technical_prefix):
            reason_code = raw_reason.removeprefix(technical_prefix)
            if reason_code not in _TECHNICAL_STOP_REASONS:
                raise
            print(
                json.dumps(
                    _owner_stop_envelope(
                        boundary=boundary,
                        reason_code=reason_code,
                        row_id=None,
                    ),
                    indent=2,
                    sort_keys=True,
                )
            )
            raise SystemExit(4) from None
        if raw_reason.startswith(owner_prefix):
            print(
                json.dumps(
                    _owner_stop_envelope(
                        boundary=boundary,
                        reason_code=raw_reason.removeprefix(owner_prefix),
                        row_id=None,
                    ),
                    indent=2,
                    sort_keys=True,
                )
            )
            raise SystemExit(3) from None
        raise


if __name__ == "__main__":
    main()
