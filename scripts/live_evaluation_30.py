#!/usr/bin/env python3
"""Standalone owner CLI for the immutable live-evaluation-30-v1 suite.

The verification/registration commands do not invoke the model.  The explicit
``execute`` command drives the loopback API only after expert gold, coverage
and the exact owner-promoted ACTIVE build pass fail-closed prerequisites.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
import uuid
from collections.abc import Sequence
from datetime import UTC, date, datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.crypto import LocalCipher  # noqa: E402
from app.evaluation.live30 import (  # noqa: E402
    E2ERunEvent,
    Live30RunStore,
    RunEventType,
    RunProvenance,
    RunStage,
    RunStatus,
    SensitiveArtifactKind,
    load_live30_suite,
    safe_summary,
    write_suite_manifest,
)

DEFAULT_REGISTRY = (
    PROJECT_ROOT / "benchmarks" / "evaluation" / "live-evaluation-30-v1" / "cases.jsonl"
)
DEFAULT_MANIFEST = (
    PROJECT_ROOT / "benchmarks" / "evaluation" / "live-evaluation-30-v1" / "manifest.json"
)


def _git_identity(project_root: Path) -> tuple[str, bool]:
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return sha, bool(status.strip())


def _parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="live-evaluation-30")
    root.add_argument("--project-root", type=Path, default=PROJECT_ROOT)
    root.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    commands = root.add_subparsers(dest="command", required=True)

    commands.add_parser("verify", help="Verify all immutable cases and print safe totals")

    freeze = commands.add_parser(
        "freeze-manifest", help="Create the immutable safe suite manifest without replacing it"
    )
    freeze.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)

    create = commands.add_parser(
        "create-run", help="Create an encrypted local run and register all 30 questions"
    )
    create.add_argument("--run-id", required=True)
    create.add_argument("--model-version")
    create.add_argument("--index-build-id")
    create.add_argument("--prompt-version")
    create.add_argument("--router-version")
    create.add_argument("--classifier-version")
    create.add_argument("--policy-sha256")
    create.add_argument("--assessment-rules-sha256")
    create.add_argument(
        "--as-of-date",
        type=date.fromisoformat,
        help="Immutable legal as-of date for this run (default: local run date)",
    )

    event = commands.add_parser("record-event", help="Append an allowlisted ID/timing event")
    event.add_argument("--run-id", required=True)
    event.add_argument("--case-id")
    event.add_argument(
        "--event-type", required=True, choices=[value.value for value in RunEventType]
    )
    event.add_argument("--stage", required=True, choices=[value.value for value in RunStage])
    event.add_argument("--status", required=True, choices=[value.value for value in RunStatus])
    event.add_argument("--duration-ms", type=int)
    event.add_argument("--attempt", type=int)
    event.add_argument("--artifact-id")
    event.add_argument("--error-code")

    artifact = commands.add_parser(
        "store-artifact", help="Encrypt an answer/review/issue/gap file inside an existing run"
    )
    artifact.add_argument("--run-id", required=True)
    artifact.add_argument("--case-id", required=True)
    artifact.add_argument(
        "--kind", required=True, choices=[value.value for value in SensitiveArtifactKind]
    )
    artifact.add_argument("--artifact-id", required=True)
    artifact.add_argument("--input", type=Path, required=True)

    coverage = commands.add_parser(
        "coverage",
        help="Run retrieval/evidence readiness for all 30 against one sealed candidate",
    )
    coverage.add_argument("--run-id", required=True)
    coverage.add_argument("--build-id", required=True)
    coverage.add_argument(
        "--expert-qualification",
        type=Path,
        help="Owner-approved, sealed source/span overlay; generation stays blocked without it",
    )

    qualification = commands.add_parser(
        "qualification-template",
        help="Write a prose-free owner annotation template; this does not create or approve gold",
    )
    qualification.add_argument("--run-id", required=True)
    qualification.add_argument("--output", type=Path, required=True)

    execute = commands.add_parser(
        "execute",
        help="Serially execute a controlled localhost pass after every hard prerequisite passes",
    )
    execute.add_argument("--run-id", required=True)
    execute.add_argument("--pass-number", type=int, choices=(1, 2, 3), required=True)
    execute.add_argument(
        "--stability-sample",
        action="store_true",
        help="Required for passes 2 and 3; submits only the frozen nine-case sample",
    )
    execute.add_argument("--base-url", default="http://127.0.0.1:8777")
    execute.add_argument("--case-timeout-seconds", type=float, default=14_400)

    finalize = commands.add_parser(
        "finalize-review",
        help=(
            "Create review-export.json only after all 48 planned outcomes "
            "(30 first-pass plus two nine-case stability passes) are terminal"
        ),
    )
    finalize.add_argument("--run-id", required=True)
    return root


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    project_root = args.project_root.resolve()

    if args.command == "verify":
        suite = load_live30_suite(args.registry.resolve())
        print(json.dumps(safe_summary(suite), indent=2, sort_keys=True))
        return 0

    if args.command == "freeze-manifest":
        suite = load_live30_suite(args.registry.resolve())
        destination = write_suite_manifest(args.manifest.resolve(), suite)
        print(
            json.dumps(
                {
                    "manifest": destination.name,
                    "suite_id": "live-evaluation-30-v1",
                    "case_count": suite.case_count,
                    "total_word_target": suite.total_word_target,
                    "canonical_sha256": suite.canonical_sha256,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    cipher = LocalCipher.from_local_key(create=False)
    store = Live30RunStore(project_root, cipher)

    if args.command == "qualification-template":
        from app.evaluation.live30_gold import qualification_template

        suite = load_live30_suite(args.registry.resolve())
        manifest = store.load_run_manifest(args.run_id)
        build_id = manifest.provenance.index_build_id
        if not build_id:
            raise SystemExit("qualification template requires a run bound to an index build")
        output = args.output.resolve()
        if output.exists():
            raise SystemExit("qualification template destination already exists")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(
                qualification_template(
                    suite,
                    index_build_id=build_id,
                    as_of_date=manifest.as_of_date,
                ),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        print(json.dumps({"created": True, "approved": False, "name": output.name}, indent=2))
        return 0

    if args.command == "execute":
        from app.evaluation.live30_execute import (
            execute_with_httpx,
            verify_execution_prerequisites,
        )

        suite = load_live30_suite(args.registry.resolve())
        preflight = verify_execution_prerequisites(
            project_root=project_root,
            store=store,
            suite=suite,
            run_id=args.run_id,
            base_url=args.base_url,
        )
        outcomes = asyncio.run(
            execute_with_httpx(
                store=store,
                suite=suite,
                preflight=preflight,
                pass_number=args.pass_number,
                stability_sample=args.stability_sample,
                case_timeout_seconds=args.case_timeout_seconds,
            )
        )
        counts: dict[str, int] = {}
        for outcome in outcomes:
            counts[outcome.release_state] = counts.get(outcome.release_state, 0) + 1
        print(
            json.dumps(
                {
                    "run_id": args.run_id,
                    "pass_number": args.pass_number,
                    "case_count": len(outcomes),
                    "release_state_counts": dict(sorted(counts.items())),
                    "evaluation_only": True,
                    "training_export_allowed": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    if args.command == "finalize-review":
        from app.evaluation.live30_execute import finalize_review_export

        suite = load_live30_suite(args.registry.resolve())
        review = finalize_review_export(store=store, suite=suite, run_id=args.run_id)
        print(
            json.dumps(
                {
                    "run_id": review.run_id,
                    "case_count": len(review.cases),
                    "privacy_report_passed": review.privacy_report_passed,
                    "review_export": "review-export.json",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    if args.command == "coverage":
        from app.config import Settings
        from app.db import Database
        from app.evaluation.live30_coverage import run_suite_coverage
        from app.evaluation.live30_gold import load_expert_qualification
        from app.retrieval.service import HybridRetrievalService

        suite = load_live30_suite(args.registry.resolve())
        manifest = store.load_run_manifest(args.run_id)
        if manifest.suite_canonical_sha256 != suite.canonical_sha256:
            raise SystemExit("run and immutable live-30 registry identities differ")
        if manifest.provenance.index_build_id != args.build_id:
            raise SystemExit("run manifest is not bound to the requested candidate build")
        if not (manifest.provenance.policy_sha256 and manifest.provenance.assessment_rules_sha256):
            raise SystemExit("coverage requires frozen policy and assessment-bundle identities")
        runtime_settings = Settings(project_root=project_root)
        expert_qualification = (
            load_expert_qualification(
                args.expert_qualification.resolve(),
                suite=suite,
                index_build_id=args.build_id,
                as_of_date=manifest.as_of_date,
            )
            if args.expert_qualification is not None
            else None
        )
        database = Database(runtime_settings.database_path)
        database.initialize()
        try:
            retriever = HybridRetrievalService(
                runtime_settings,
                database,
                pinned_build_id=args.build_id,
            )
            summary = asyncio.run(
                run_suite_coverage(
                    store=store,
                    retriever=retriever,
                    run_id=args.run_id,
                    suite=suite,
                    qualification=expert_qualification,
                )
            )
        finally:
            database.close()
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    if args.command == "create-run":
        suite = load_live30_suite(args.registry.resolve())
        git_sha, git_dirty = _git_identity(project_root)
        manifest = store.create_run(
            run_id=args.run_id,
            suite=suite,
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
            as_of_date=args.as_of_date,
        )
        print(
            json.dumps(
                {
                    "run_id": manifest.run_id,
                    "suite_canonical_sha256": manifest.suite_canonical_sha256,
                    "case_count": manifest.case_count,
                    "total_word_target": manifest.total_word_target,
                    "as_of_date": manifest.as_of_date.isoformat(),
                    "sensitive_inputs": "encrypted",
                    "generation_started": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    if args.command == "record-event":
        event = E2ERunEvent(
            event_id=uuid.uuid4().hex,
            timestamp=datetime.now(UTC),
            run_id=args.run_id,
            case_id=args.case_id,
            event_type=RunEventType(args.event_type),
            stage=RunStage(args.stage),
            status=RunStatus(args.status),
            duration_ms=args.duration_ms,
            attempt=args.attempt,
            artifact_id=args.artifact_id,
            error_code=args.error_code,
        )
        store.record_event(event)
        print(json.dumps({"event_id": event.event_id, "recorded": True}, indent=2))
        return 0

    if args.command == "store-artifact":
        content = args.input.read_text(encoding="utf-8")
        destination = store.store_sensitive_artifact(
            run_id=args.run_id,
            case_id=args.case_id,
            kind=SensitiveArtifactKind(args.kind),
            artifact_id=args.artifact_id,
            content=content,
        )
        print(
            json.dumps(
                {
                    "artifact_id": args.artifact_id,
                    "case_id": args.case_id,
                    "kind": args.kind,
                    "encrypted": True,
                    "stored_name": destination.name,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
