#!/usr/bin/env python3
"""Manage the sealed, evaluation-only Live60 workflow without self-approval."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
from collections.abc import Sequence
from datetime import date
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.assessment.guidance_bundle import OWNER_ASSESSMENT_BUNDLE  # noqa: E402
from app.config import Settings  # noqa: E402
from app.crypto import LocalCipher  # noqa: E402
from app.evaluation.live30 import RunProvenance  # noqa: E402
from app.evaluation.live_suite import (  # noqa: E402
    admission_as_of_date,
    load_live_evaluation_bundle,
)
from app.evaluation.live_suite_coverage import run_suite_coverage  # noqa: E402
from app.evaluation.live_suite_gold import (  # noqa: E402
    load_suite_expert_qualification,
    qualification_template_for_suite,
)
from app.evaluation.live_suite_store import LiveSuiteRunStore  # noqa: E402
from app.orchestration.classifier import CLASSIFIER_VERSION  # noqa: E402
from app.orchestration.routing import ROUTER_VERSION  # noqa: E402
from app.quality.policy import POLICY_SHA256  # noqa: E402
from app.runtime_adapters import PROMPT_VERSION  # noqa: E402

DEFAULT_BUNDLE = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"


def _require_current_runtime_identities(args: argparse.Namespace) -> None:
    """Refuse a run manifest whose caller-supplied identities are stale.

    The command keeps the identities explicit at the operator boundary, but
    they are assertions rather than arbitrary labels.  This prevents an old
    prompt, router, classifier, policy, assessment bundle or model name from
    being sealed into a new Live60 run while different code is actually
    installed.
    """

    settings = Settings(project_root=PROJECT_ROOT)
    expected = {
        "model_version": settings.model_id,
        "prompt_version": PROMPT_VERSION,
        "router_version": ROUTER_VERSION,
        "classifier_version": CLASSIFIER_VERSION,
        "policy_sha256": POLICY_SHA256,
        "assessment_rules_sha256": OWNER_ASSESSMENT_BUNDLE.sha256,
    }
    mismatched = tuple(name for name, value in expected.items() if getattr(args, name) != value)
    if mismatched:
        raise SystemExit("create-run runtime identity mismatch: " + ", ".join(mismatched))


def _git_identity(project_root: Path) -> tuple[str, bool]:
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=project_root,
        capture_output=True,
        check=True,
        text=True,
    ).stdout.strip()
    dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=project_root,
            capture_output=True,
            check=True,
            text=True,
        ).stdout.strip()
    )
    return revision, dirty


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, default=DEFAULT_BUNDLE)
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--source", type=Path)
    verify.add_argument("--accepted-memo", type=Path)
    commands.add_parser("summary")

    template = commands.add_parser("qualification-template")
    template.add_argument("--index-build-id", required=True)
    template.add_argument("--as-of-date", type=date.fromisoformat)
    template.add_argument("--output", type=Path, required=True)

    create = commands.add_parser("create-run")
    create.add_argument("--run-id", required=True)
    create.add_argument("--index-build-id", required=True)
    create.add_argument("--model-version", required=True)
    create.add_argument("--prompt-version", required=True)
    create.add_argument("--router-version", required=True)
    create.add_argument("--classifier-version", required=True)
    create.add_argument("--policy-sha256", required=True)
    create.add_argument("--assessment-rules-sha256", required=True)

    coverage = commands.add_parser("coverage")
    coverage.add_argument("--run-id", required=True)
    coverage.add_argument("--build-id", required=True)
    coverage.add_argument("--expert-qualification", type=Path, required=True)

    execution_preflight = commands.add_parser("execution-preflight")
    execution_preflight.add_argument("--run-id", required=True)
    execution_preflight.add_argument("--authorization", type=Path)
    execution_preflight.add_argument("--base-url", default="http://127.0.0.1:8777")

    execute = commands.add_parser("execute")
    execute.add_argument("--run-id", required=True)
    execute.add_argument("--authorization", type=Path)
    execute.add_argument("--base-url", default="http://127.0.0.1:8777")
    execute.add_argument("--case-timeout-seconds", type=float, default=14_400.0)

    finalize = commands.add_parser("finalize")
    finalize.add_argument("--run-id", required=True)
    return parser


def _exclusive_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    bundle = load_live_evaluation_bundle(
        args.bundle,
        new_question_source=getattr(args, "source", None),
        accepted_no_go_memo=getattr(args, "accepted_memo", None),
    )
    if args.command == "verify":
        print(bundle.manifest.seal_sha256)
        return 0
    if args.command == "summary":
        print(
            json.dumps(
                {
                    "suite_id": bundle.manifest.suite_id,
                    "baseline_status": bundle.manifest.accepted_baseline_status,
                    "case_count": bundle.registry.case_count,
                    "suite_total_word_target": bundle.registry.total_word_target,
                    "generation_case_count": bundle.run_plan.generation_case_count,
                    "generation_total_word_target": (bundle.run_plan.generation_total_word_target),
                    "expert_annotation_required": True,
                    "eligible_for_training": False,
                    "training_export_allowed": False,
                    "required_runtime_identities": {
                        "model_version": Settings(project_root=PROJECT_ROOT).model_id,
                        "prompt_version": PROMPT_VERSION,
                        "router_version": ROUTER_VERSION,
                        "classifier_version": CLASSIFIER_VERSION,
                        "policy_sha256": POLICY_SHA256,
                        "assessment_rules_sha256": OWNER_ASSESSMENT_BUNDLE.sha256,
                    },
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    if args.command == "qualification-template":
        template = qualification_template_for_suite(
            bundle,
            index_build_id=args.index_build_id,
            as_of_date=args.as_of_date or admission_as_of_date(),
        )
        _exclusive_json(args.output.resolve(), template)
        print(json.dumps({"created": True, "approved": False}, sort_keys=True))
        return 0

    if args.command == "create-run":
        _require_current_runtime_identities(args)
    cipher = LocalCipher.from_local_key(create=False)
    store = LiveSuiteRunStore(PROJECT_ROOT, cipher)
    if args.command == "create-run":
        git_sha, git_dirty = _git_identity(PROJECT_ROOT)
        manifest = store.create_run(
            run_id=args.run_id,
            bundle=bundle,
            provenance=RunProvenance(
                git_sha=git_sha,
                git_dirty=git_dirty,
                model_version=args.model_version,
                index_build_id=args.index_build_id,
                prompt_version=args.prompt_version,
                router_version=args.router_version,
                classifier_version=args.classifier_version,
                policy_sha256=args.policy_sha256,
                assessment_rules_sha256=args.assessment_rules_sha256,
            ),
        )
        print(
            json.dumps(
                {
                    "run_id": manifest.run_id,
                    "case_count": manifest.case_count,
                    "generation_case_count": manifest.generation_case_count,
                    "as_of_date": manifest.as_of_date,
                    "generation_started": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    if args.command == "coverage":
        from app.db import Database
        from app.retrieval.service import HybridRetrievalService

        run_manifest = store.load_run_manifest(args.run_id)
        if run_manifest.provenance.index_build_id != args.build_id:
            raise SystemExit("run is not bound to the requested candidate build")
        if not (
            run_manifest.provenance.policy_sha256
            and run_manifest.provenance.assessment_rules_sha256
        ):
            raise SystemExit("coverage requires frozen policy and assessment identities")
        expert = load_suite_expert_qualification(
            args.expert_qualification.resolve(),
            bundle=bundle,
            index_build_id=args.build_id,
            as_of_date=date.fromisoformat(run_manifest.as_of_date),
        )
        settings = Settings(project_root=PROJECT_ROOT)
        database = Database(settings.database_path)
        database.initialize()
        try:
            retriever = HybridRetrievalService(settings, database, pinned_build_id=args.build_id)
            summary = asyncio.run(
                run_suite_coverage(
                    store=store,
                    retriever=retriever,
                    run_id=args.run_id,
                    bundle=bundle,
                    qualification=expert,
                )
            )
        finally:
            database.close()
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    if args.command in {"execution-preflight", "execute"}:
        from app.evaluation.live_suite_execute import verify_execution_prerequisites
        from app.evaluation.live_suite_http_execute import (
            execute_live60_with_httpx,
            finalize_live60_review_export,
            verify_live60_runtime_bindings,
        )

        authorization_path = (
            args.authorization.resolve()
            if args.authorization is not None
            else store._run_path(args.run_id) / "execution-authorization.json"
        )
        preflight = verify_execution_prerequisites(
            store=store,
            bundle=bundle,
            run_id=args.run_id,
            authorization_path=authorization_path,
            require_sealed_case_artifacts=True,
        )
        runtime = verify_live60_runtime_bindings(
            project_root=PROJECT_ROOT,
            bundle=bundle,
            preflight=preflight,
            base_url=args.base_url,
        )
        if args.command == "execution-preflight":
            print(
                json.dumps(
                    {
                        "run_id": runtime.run_id,
                        "as_of_date": runtime.as_of_date.isoformat(),
                        "active_build_id": runtime.index_build_id,
                        "authorized_case_count": len(preflight.generated_case_ids),
                        "generation_eligible_case_count": len(preflight.evidence_ready_case_ids),
                        "local_only": True,
                        "online_research_allowed": False,
                        "execution_started": False,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        outcomes = asyncio.run(
            execute_live60_with_httpx(
                store=store,
                bundle=bundle,
                preflight=preflight,
                runtime=runtime,
                case_timeout_seconds=args.case_timeout_seconds,
            )
        )
        review = finalize_live60_review_export(
            store=store,
            bundle=bundle,
            run_id=args.run_id,
            owner_identifiers=runtime.owner_identifiers,
        )
        print(
            json.dumps(
                {
                    "run_id": args.run_id,
                    "terminal_outcome_count": len(outcomes),
                    "released_count": sum(item.released for item in outcomes),
                    "held_or_error_count": sum(not item.released for item in outcomes),
                    "review_case_count": len(review.cases),
                    "complete": True,
                    "eligible_for_training": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    if args.command == "finalize":
        from app.evaluation.live_suite_http_execute import (
            finalize_live60_review_export,
        )

        settings = Settings(project_root=PROJECT_ROOT)
        review = finalize_live60_review_export(
            store=store,
            bundle=bundle,
            run_id=args.run_id,
            owner_identifiers=settings.owner_identifiers,
        )
        print(
            json.dumps(
                {
                    "run_id": review.run_id,
                    "case_count": len(review.cases),
                    "privacy_passed": review.privacy_report_passed,
                    "complete": review.run_status == "completed",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    raise AssertionError("unreachable command")


if __name__ == "__main__":
    raise SystemExit(main())
