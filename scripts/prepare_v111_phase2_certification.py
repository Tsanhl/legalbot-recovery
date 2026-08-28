#!/usr/bin/env python3
"""Create the exact non-authorizing v1.11 Phase-2 preparation package."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.config import Settings  # noqa: E402
from app.evaluation.live_suite import load_live_evaluation_bundle  # noqa: E402
from app.evaluation.v111_certification_preparation import (  # noqa: E402
    build_phase2_preparation_package,
    exact_clean_code_binding,
    load_candidate_source_inventory,
    load_phase2_candidate_and_retrieval_evidence,
    open_immutable_phase2_catalogue,
    verify_phase2_preparation_package,
    write_phase2_preparation_package,
)

DEFAULT_BUNDLE = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"
ALLOWED_OUTPUT_ROOT = PROJECT_ROOT / "data/evaluations/phase2-preparation"


class Phase2PreparationCommandStop(RuntimeError):
    """One stable, path-free command-gate failure fingerprint."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-build-id", required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--output-directory", required=True, type=Path)
    return parser


def _safe_error_code(exc: BaseException) -> str:
    if isinstance(exc, Phase2PreparationCommandStop):
        return exc.reason_code
    return "unexpected_phase2_preparation_failure"


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    output: Path | None = None
    created_output = False
    try:
        try:
            output = args.output_directory.resolve()
            allowed = ALLOWED_OUTPUT_ROOT.resolve()
            if not output.is_relative_to(allowed) or output == allowed:
                raise ValueError
        except Exception as exc:
            raise Phase2PreparationCommandStop("output_location_invalid") from exc
        try:
            settings = Settings(project_root=PROJECT_ROOT)
            if settings.online_default != "local_only" or settings.official_research_enabled:
                raise ValueError
        except Exception as exc:
            raise Phase2PreparationCommandStop("offline_profile_required") from exc
        try:
            code = exact_clean_code_binding(PROJECT_ROOT, expected_head=str(args.expected_head))
        except Exception as exc:
            raise Phase2PreparationCommandStop("code_binding_invalid") from exc
        try:
            bundle = load_live_evaluation_bundle(DEFAULT_BUNDLE.resolve(strict=True))
        except Exception as exc:
            raise Phase2PreparationCommandStop("owner_certification_registry_invalid") from exc
        try:
            with open_immutable_phase2_catalogue(settings.database_path) as database:
                candidate, retrieval_evidence = load_phase2_candidate_and_retrieval_evidence(
                    settings=settings,
                    database=database,
                    candidate_build_id=str(args.candidate_build_id),
                    code=code,
                )
        except Exception as exc:
            raise Phase2PreparationCommandStop("candidate_catalogue_replay_failed") from exc
        build_root = settings.index_dir / "builds" / candidate.build_id
        try:
            candidate_sources, candidate_policies = load_candidate_source_inventory(
                build_root=build_root,
                candidate=candidate,
            )
        except Exception as exc:
            raise Phase2PreparationCommandStop("candidate_source_replay_failed") from exc
        try:
            if (
                exact_clean_code_binding(PROJECT_ROOT, expected_head=str(args.expected_head))
                != code
            ):
                raise ValueError
        except Exception as exc:
            raise Phase2PreparationCommandStop("code_binding_changed") from exc
        try:
            package = build_phase2_preparation_package(
                generated_at=datetime.now(UTC),
                code=code,
                candidate=candidate,
                bundle=bundle,
                candidate_sources=candidate_sources,
                candidate_policies=candidate_policies,
                retrieval_evidence=retrieval_evidence,
            )
        except Exception as exc:
            raise Phase2PreparationCommandStop("contract_draft_build_failed") from exc
        try:
            index = write_phase2_preparation_package(output, package)
            created_output = True
        except Exception as exc:
            raise Phase2PreparationCommandStop("preparation_package_write_failed") from exc
        try:
            replay = verify_phase2_preparation_package(output)
        except Exception as exc:
            raise Phase2PreparationCommandStop("preparation_package_replay_failed") from exc
        if replay != index:
            raise Phase2PreparationCommandStop("preparation_package_replay_mismatch")
        try:
            with open_immutable_phase2_catalogue(settings.database_path) as database:
                final_candidate, final_retrieval_evidence = (
                    load_phase2_candidate_and_retrieval_evidence(
                        settings=settings,
                        database=database,
                        candidate_build_id=str(args.candidate_build_id),
                        code=code,
                    )
                )
            final_sources, final_policies = load_candidate_source_inventory(
                build_root=build_root,
                candidate=final_candidate,
            )
            if (
                final_candidate != candidate
                or final_retrieval_evidence != retrieval_evidence
                or final_sources != candidate_sources
                or final_policies != candidate_policies
            ):
                raise ValueError
        except Exception as exc:
            raise Phase2PreparationCommandStop("candidate_durable_tree_changed") from exc
        try:
            if (
                exact_clean_code_binding(PROJECT_ROOT, expected_head=str(args.expected_head))
                != code
            ):
                raise ValueError
        except Exception as exc:
            raise Phase2PreparationCommandStop("final_code_binding_changed") from exc
        print(
            json.dumps(
                {
                    "schema": index.schema_name,
                    "status": "draft_created",
                    "authorizing": False,
                    "owner_signature_required": True,
                    "development_30_authorized": False,
                    "answer_model_invoked": False,
                    "stage_a_invoked": False,
                    "split_created": False,
                    "case_count": package.contract.registry.case_count,
                    "issue_count": package.contract.registry.issue_count,
                    "candidate_build_id": package.contract.candidate.build_id,
                    "commit_sha": package.contract.code.commit_sha,
                    "tree_sha": package.contract.code.tree_sha,
                    "contract_draft_sha256": package.contract.contract_draft_sha256,
                    "qualification_report_sha256": package.qualification.report_sha256,
                    "retrieval_semantic_closure_sha256": (
                        package.contract.retrieval_evidence.current_semantic_closure_sha256
                    ),
                    "index_sha256": index.index_sha256,
                },
                sort_keys=True,
            )
        )
        return 0
    except Exception as exc:
        failure: BaseException = exc
        if created_output and output is not None and output.exists():
            try:
                shutil.rmtree(output)
            except OSError as cleanup_exc:
                failure = Phase2PreparationCommandStop("preparation_failure_cleanup_failed")
                failure.__cause__ = cleanup_exc
        print(
            json.dumps(
                {
                    "schema": "legalbot.v111-phase2-preparation-stop.v1",
                    "status": "stopped",
                    "authorizing": False,
                    "reason_code": _safe_error_code(failure),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
