#!/usr/bin/env python3
"""Run the fixed create-only v1.11 technical-attestation matrix."""

from __future__ import annotations

import argparse
import json
import re
import stat
import sys
from collections.abc import Sequence
from datetime import UTC, date, datetime
from pathlib import Path
from typing import cast

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.config import Settings  # noqa: E402
from app.db import Database  # noqa: E402
from app.evaluation.all60_qualification import ExactAll60Qualification  # noqa: E402
from app.evaluation.live_suite import load_live_evaluation_bundle  # noqa: E402
from app.evaluation.live_suite_gold import (  # noqa: E402
    load_suite_expert_qualification,
)
from app.evaluation.sealed_candidate import (  # noqa: E402
    load_sealed_candidate_identity,
)
from app.evaluation.v111_technical_attestation import (  # noqa: E402
    StageAReplayInputs,
    load_verified_v111_technical_attestation,
    run_v111_technical_attestation_create_only,
    write_first_live_rollback_decision_request,
)
from app.evaluation.v111_technical_attestation_admission import (  # noqa: E402
    admit_verified_v111_technical_attestation,
)
from app.governance.existing_catalogue_read import (  # noqa: E402
    open_existing_catalogue_read_database,
)
from app.governance.v111_decision_generation import (  # noqa: E402
    require_exact_clean_head,
)
from app.retrieval.retrieval_reattest import _clean_integration_sha  # noqa: E402

_SAFE_CODE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_BUNDLE_ROOT = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="Run and strictly replay the fixed matrix")
    run.add_argument("--run-id", required=True)
    run.add_argument("--candidate-build-id", required=True)
    run.add_argument("--stage-a-run-id", required=True)
    run.add_argument("--as-of-date", required=True, type=date.fromisoformat)
    run.add_argument("--all60-qualification", required=True, type=Path)
    run.add_argument("--expert-qualification", required=True, type=Path)
    run.add_argument("--completion-preflight-seal", required=True)
    decision = commands.add_parser(
        "create-rollback-decision",
        help="Create the first-promotion rollback owner request without resolving it",
    )
    decision.add_argument("--candidate-build-id", required=True)
    decision.add_argument("--integration-sha", required=True)
    return parser


def _private_input(value: Path) -> Path:
    if value.is_symlink() or not value.is_file() or stat.S_IMODE(value.stat().st_mode) != 0o600:
        raise RuntimeError("technical_attestation_input_not_private")
    return value


def _safe_error_code(exc: BaseException) -> str:
    if isinstance(exc, RuntimeError) and exc.args:
        explicit = str(exc.args[0]).strip().casefold().replace("-", "_")
        if _SAFE_CODE.fullmatch(explicit):
            return explicit
    candidate = re.sub(r"(?<!^)(?=[A-Z])", "_", type(exc).__name__).casefold()
    return candidate if _SAFE_CODE.fullmatch(candidate) else "technical_attestation_stopped"


def _require_owned_files_at_integration(integration_sha: str) -> str:
    try:
        return require_exact_clean_head(PROJECT_ROOT, integration_sha)
    except (ValueError, RuntimeError) as exc:
        raise RuntimeError("rollback_decision_requires_exact_clean_integration") from exc


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    database: Database | None = None
    try:
        settings = Settings(project_root=PROJECT_ROOT)
        if not settings.database_path.is_file():
            raise RuntimeError("technical_attestation_catalogue_missing")
        if args.command == "create-rollback-decision":
            integration_sha = _require_owned_files_at_integration(str(args.integration_sha))
            readonly_database = open_existing_catalogue_read_database(settings.database_path)
            try:
                candidate = load_sealed_candidate_identity(
                    settings=settings,
                    database=cast(Database, readonly_database),
                    candidate_build_id=str(args.candidate_build_id),
                )
                request, destination = write_first_live_rollback_decision_request(
                    settings=settings,
                    database=cast(Database, readonly_database),
                    candidate=candidate,
                    integration_sha=integration_sha,
                    created_at=datetime.now(UTC),
                )
            finally:
                readonly_database.close()
            print(
                json.dumps(
                    {
                        "state": request.state,
                        "decision_id": request.decision_id,
                        "request_seal_sha256": request.seal_sha256,
                        "recommended_option_id": request.recommended_option_id,
                        "request_member": destination.name,
                        "resolution_created": False,
                        "active_changed": False,
                    },
                    sort_keys=True,
                )
            )
            return 0
        database = Database(settings.database_path)
        database.initialize()
        candidate = load_sealed_candidate_identity(
            settings=settings,
            database=database,
            candidate_build_id=str(args.candidate_build_id),
        )
        completion_seal = str(args.completion_preflight_seal)
        if not _SHA256.fullmatch(completion_seal):
            raise ValueError("completion preflight seal is invalid")
        qualification_input = _private_input(args.all60_qualification)
        expert_input = _private_input(args.expert_qualification)
        integration_sha = _clean_integration_sha(PROJECT_ROOT)
        bundle = load_live_evaluation_bundle(_BUNDLE_ROOT)
        all60 = ExactAll60Qualification.model_validate_json(qualification_input.read_bytes())
        if all60.as_of_date != args.as_of_date:
            raise RuntimeError("technical_attestation_all60_date_mismatch")
        expert = load_suite_expert_qualification(
            expert_input,
            bundle=bundle,
            index_build_id=candidate.build_id,
            as_of_date=args.as_of_date,
            catalog_path=settings.database_path,
        )
        stage_a = StageAReplayInputs(
            output_root=settings.evaluation_dir / "stage-a-v2",
            run_id=str(args.stage_a_run_id),
            bundle=bundle,
            all60_qualification=all60,
            expert_qualification=expert,
            as_of_date=args.as_of_date,
            completion_preflight_verified_result_sha256=completion_seal,
        )
        completed = run_v111_technical_attestation_create_only(
            run_id=str(args.run_id),
            settings=settings,
            database=database,
            candidate=candidate,
            stage_a=stage_a,
            expected_integration_sha=integration_sha,
        )
        verified = load_verified_v111_technical_attestation(
            completed,
            settings=settings,
            database=database,
            candidate=candidate,
            stage_a=stage_a,
            expected_integration_sha=integration_sha,
        )
        admission = admit_verified_v111_technical_attestation(
            verified,
            settings=settings,
            database=database,
            candidate=candidate,
            stage_a=stage_a,
            expected_integration_sha=integration_sha,
        )
        print(
            json.dumps(
                {
                    "run_id": completed.run_id,
                    "candidate_build_id": verified.candidate_build_id,
                    "integration_sha": verified.integration_sha,
                    "attestation_seal_sha256": verified.seal_sha256,
                    "technical_admission_id": admission.admission_id,
                    "technical_admission_seal_sha256": admission.seal_sha256,
                    "technical_admission_member": admission.receipt_path.name,
                    "status": "verified_and_admitted",
                },
                sort_keys=True,
            )
        )
        return 0
    except Exception as exc:
        print(
            json.dumps(
                {
                    "run_id": str(getattr(args, "run_id", "decision-request")),
                    "status": "stopped",
                    "reason_code": _safe_error_code(exc),
                },
                sort_keys=True,
            )
        )
        return 2
    finally:
        if database is not None:
            database.close()


if __name__ == "__main__":
    raise SystemExit(main())
