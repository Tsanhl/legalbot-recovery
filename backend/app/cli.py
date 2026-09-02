from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import uvicorn

from .config import settings
from .crypto import LocalCipher
from .db import Database


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="legalbot")
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="Initialise the local SQLite catalogue and Keychain key")
    serve = commands.add_parser("serve", help="Run the loopback-only API")
    serve.add_argument("--host", default=settings.host)
    serve.add_argument("--port", type=int, default=settings.port)
    commands.add_parser("scan", help="Account for configured source documents")
    commands.add_parser("worker", help="Run the durable loopback-only answer worker")
    commands.add_parser(
        "index-worker",
        help="Run the dedicated durable index-build worker (never claims answers)",
    )
    enqueue = commands.add_parser(
        "research-enqueue",
        help="Queue one official-source crawl/update job (does not search the open web)",
    )
    enqueue.add_argument(
        "--task-type",
        required=True,
        choices=("source_update_check", "gap_research", "broad_discovery"),
    )
    enqueue.add_argument("--subject", required=True)
    enqueue.add_argument(
        "--priority",
        default="medium",
        choices=("high", "medium", "low"),
    )
    enqueue.add_argument("--source-id", help="Registered adapter, e.g. legislation_gov_uk")
    enqueue.add_argument(
        "--authority-identity-id", help="Stable public identity, e.g. ukpga:1980:58"
    )
    enqueue.add_argument(
        "--knowledge-gap-id", help="Existing knowledge_gaps.id; required for gap_research"
    )
    enqueue.add_argument("--source-locator", help="Official path locator without query string")
    enqueue.add_argument(
        "--public-query",
        help="Registered crawl taxonomy term only; never a user question",
    )
    queue = commands.add_parser(
        "research-queue",
        help="Show official crawl queue depth and recent task ids",
    )
    queue.add_argument("--limit", type=int, default=50)
    research_worker = commands.add_parser(
        "research-worker",
        help="Run the official crawl worker (not started by first-live start.sh)",
    )
    research_worker.add_argument(
        "--once",
        action="store_true",
        help="Claim and run at most one queued research job, then exit",
    )
    commands.add_parser("readiness", help="Write the aggregate production-readiness report")
    commands.add_parser("metrics", help="Write safe aggregate worker and latency metrics")
    build = commands.add_parser("build-index", help="Enqueue a durable candidate index-build job")
    build.add_argument("--id")
    build.add_argument("--corpus-id", default="current-law-ew-core-slice-v1")
    build.add_argument("--max-chunks", type=int)
    build.add_argument(
        "--no-chunk-cap",
        action="store_true",
        help="Do not cap source selection by chunk count",
    )
    build.add_argument(
        "--preferred-small-first",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Prefer smaller approved sources when a chunk cap is set",
    )
    build.add_argument(
        "--reuse-vectors-from-build-id",
        help=(
            "Reuse only exact hash-matched vectors from this sealed parent; "
            "the new candidate still rebuilds lexical/vector indexes and seals independently"
        ),
    )
    build.add_argument(
        "--run",
        action="store_true",
        help="Deprecated and refused; the dedicated leased index worker runs queued builds",
    )
    promote = commands.add_parser("promote", help="Atomically promote a passing candidate")
    promote.add_argument("build_id")
    commands.add_parser("rollback", help="Restore ACTIVE from PREVIOUS.json")
    replay = commands.add_parser("replay-dlq", help="Replay a non-answer DLQ/terminal job")
    replay.add_argument("job_id")
    audit_incomplete = commands.add_parser(
        "audit-incomplete-index",
        help="Read-only audit of incomplete index staging (never mutates files)",
    )
    audit_incomplete.add_argument("build_id")
    recover_embedding = commands.add_parser(
        "recover-index-embedding",
        help="Recover a verified complete embedding after a post-hoc stage_timeout",
    )
    recover_embedding.add_argument("build_id")
    recover_embedding.add_argument(
        "--expected-audit-report-sha256",
        required=True,
        help="Exact report_sha256 from a fresh audit-incomplete-index result",
    )
    recover_embedding.add_argument(
        "--continue-build",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Continue lexical/vector/validation after recovery",
    )
    resume_index = commands.add_parser(
        "resume-index-build",
        help="Resume a failed or interrupted index-build job with fresh deadlines",
    )
    resume_index.add_argument("job_id")
    retry_index = commands.add_parser(
        "retry-index-build",
        help="Preserve prior staging and enqueue a fresh retry-lineage build id",
    )
    retry_index.add_argument("job_id")
    retry_index.add_argument("--new-build-id", required=True)
    archive_incomplete = commands.add_parser(
        "archive-incomplete-index",
        help="Owner-explicit archive of incomplete staging; never used by normal start",
    )
    archive_incomplete.add_argument("build_id")
    retrieval_v1 = commands.add_parser(
        "retrieval-v1.1",
        help="Score owner-frozen retrieval v1.1 against a candidate (no ACTIVE.json or answer model)",
    )
    retrieval_v1.add_argument("--build-id", required=True)
    retrieval_v1.add_argument(
        "--splits",
        default="development,promotion",
        help="Comma-separated splits: development,promotion,adversarial_holdout",
    )
    retrieval_v1.add_argument("--out", help="Write JSON report to this path")
    attest = commands.add_parser(
        "attest-index",
        help="Run frozen retrieval v1.1 and mark a passing built_unscored generation candidate",
    )
    attest.add_argument("build_id")
    reattest = commands.add_parser(
        "reattest-index",
        help=(
            "Re-run frozen retrieval v1.1 for an existing sealed candidate and "
            "select a create-only current-scorer proof (never writes ACTIVE)"
        ),
    )
    reattest.add_argument("build_id")
    reattest.add_argument(
        "--scorer-closure-manifest",
        required=True,
        type=Path,
        help="Exact private legalbot.scorer-closure-manifest.v1 bound to this clean HEAD",
    )
    owner_intake_template = commands.add_parser(
        "live60-owner-intake-template",
        help="Write the local-only unsigned Path-B owner decision DOCX",
    )
    owner_intake_template.add_argument("--out", required=True)
    owner_intake_template.add_argument("--as-of-date", default="2026-08-16")
    owner_intake_template.add_argument("--overwrite", action="store_true")
    owner_intake = commands.add_parser(
        "live60-owner-intake",
        help="Validate a filled owner DOCX and write an unsigned draft plus diff",
    )
    owner_intake.add_argument("--docx", required=True)
    owner_intake.add_argument("--out", required=True, help="Destination draft JSON")
    owner_intake.add_argument("--diff", required=True, help="Destination review diff Markdown")
    owner_intake.add_argument("--as-of-date", default="2026-08-16")
    owner_intake.add_argument("--overwrite", action="store_true")
    owner_intake_migrate = commands.add_parser(
        "live60-owner-intake-migrate",
        help="Migrate the old Path-A status DOCX into the current Path-B form",
    )
    owner_intake_migrate.add_argument("--legacy-docx", required=True)
    owner_intake_migrate.add_argument("--out", required=True)
    owner_intake_migrate.add_argument("--report", required=True)
    owner_intake_migrate.add_argument("--as-of-date", default="2026-08-16")
    owner_intake_migrate.add_argument("--overwrite", action="store_true")
    evidence_pack = commands.add_parser(
        "live60-evidence-pack",
        help="Write local owner-review DOCXs for all 305 selected-paper issues",
    )
    evidence_pack.add_argument("--out-dir", required=True)
    evidence_pack.add_argument("--catalog")
    evidence_pack.add_argument("--evidence-map")
    evidence_pack.add_argument("--as-of-date", default="2026-08-16")
    evidence_pack.add_argument("--overwrite", action="store_true")
    evidence_import = commands.add_parser(
        "live60-evidence-import",
        help="Validate filled evidence DOCXs into owner-reviewed Path-B rows",
    )
    evidence_import.add_argument("--workbook-dir", required=True)
    evidence_import.add_argument("--review-export", required=True)
    evidence_import.add_argument("--out", required=True)
    evidence_import.add_argument("--catalog")
    evidence_import.add_argument("--evidence-map")
    evidence_import.add_argument("--as-of-date", default="2026-08-16")
    evidence_import.add_argument("--overwrite", action="store_true")
    final_check_pack = commands.add_parser(
        "live60-final-check-pack",
        help="Write extracted official quotes as JSON plus display-only Word",
    )
    final_check_pack.add_argument("--out-dir", required=True)
    final_check_pack.add_argument("--catalog")
    final_check_pack.add_argument("--evidence-map")
    final_check_pack.add_argument("--as-of-date", default="2026-08-16")
    final_check_pack.add_argument("--overwrite", action="store_true")
    final_check_import = commands.add_parser(
        "live60-final-check-import",
        help="Import owner-accepted final-check JSON hashes; Word is ignored",
    )
    final_check_import.add_argument("--pack", required=True)
    final_check_import.add_argument("--review-export", required=True)
    final_check_import.add_argument("--out", required=True)
    final_check_import.add_argument("--catalog")
    final_check_import.add_argument("--as-of-date", default="2026-08-16")
    final_check_import.add_argument("--overwrite", action="store_true")
    final_check_import.add_argument(
        "--confirm",
        help="Owner confirmation token; required if the JSON token field is blank",
    )
    remaining_search = commands.add_parser(
        "live60-remaining-search-pack",
        help="Write search questions for remaining selected Path-B issues; Word is display-only",
    )
    remaining_search.add_argument("--imported", required=True)
    remaining_search.add_argument("--draft", required=True)
    remaining_search.add_argument("--out", required=True)
    remaining_search.add_argument("--overwrite", action="store_true")
    review_export = commands.add_parser(
        "live60-review-export",
        help="Export sealed Live60 candidate review rows (no ACTIVE, no O-04, no gold seal)",
    )
    review_export.add_argument("--out", required=True, help="Destination JSON path")
    review_export.add_argument("--as-of-date", default="2026-08-16")
    review_export.add_argument("--ticks", help="Optional owner tick-draft JSON")
    review_import = commands.add_parser(
        "live60-review-import",
        help="Import owner-reviewed Live60 rows from a sealed export only",
    )
    review_import.add_argument("--export", required=True)
    review_import.add_argument("--reviewed", required=True)
    review_import.add_argument("--out", help="Write the verified import JSON")
    review_import.add_argument("--repair", help="Optional repair-span JSON")
    overlay_seal = commands.add_parser(
        "live60-overlay-seal",
        help="Owner-only overlay seal from reconstructed 585 dispositions",
    )
    overlay_seal.add_argument("--reconstruction", required=True)
    overlay_seal.add_argument("--reviewer-ref", required=True)
    overlay_seal.add_argument("--index-build-id", required=True)
    overlay_seal.add_argument("--run-id", required=True)
    overlay_seal.add_argument("--contrary-review", required=True)
    overlay_seal.add_argument("--owner-decisions", required=True)
    overlay_seal.add_argument("--out", help="Write expert-qualification.json if sealable")
    review_seal = commands.add_parser(
        "live60-review-seal",
        help="Owner-only Path-B seal bound to contrary-review and D1-D15 artifacts",
    )
    review_seal.add_argument("--run-id", required=True)
    review_seal.add_argument("--reviewed-rows", required=True)
    review_seal.add_argument("--contrary-review", required=True)
    review_seal.add_argument("--owner-decisions", required=True)
    review_seal.add_argument("--index-build-id", required=True)
    review_seal.add_argument("--reviewer-ref", required=True)
    review_seal.add_argument("--out", help="Write expert-qualification.json if sealable")
    owner_control = commands.add_parser(
        "live60-owner-control-confirm",
        help="Owner confirmation that seals D1-D15 and contrary-review JSON only",
    )
    owner_control.add_argument("--decisions", required=True)
    owner_control.add_argument("--contrary", required=True)
    owner_control.add_argument("--decisions-out", required=True)
    owner_control.add_argument("--contrary-out", required=True)
    owner_control.add_argument("--index-build-id", required=True)
    owner_control.add_argument("--run-id", required=True)
    owner_control.add_argument("--confirm", required=True)
    owner_control.add_argument("--as-of-date", default="2026-08-16")
    owner_control.add_argument("--overwrite", action="store_true")
    full_run_status = commands.add_parser(
        "live60-full-run-status",
        help="Record why Path-B overlay, Stage A and owner live gates remain blocked",
    )
    full_run_status.add_argument("--out")
    full_run_status.add_argument("--as-of-date", default="2026-08-16")
    current_state = commands.add_parser(
        "live60-current-state",
        help="Write the authoritative Path-B current-state report using the v2 resolver",
    )
    current_state.add_argument("--out")
    current_state.add_argument("--candidate-build-id")
    source_admission = commands.add_parser(
        "live60-source-admission-v2",
        help="Re-evaluate held official sources under actor-neutral V2 admission",
    )
    source_admission.add_argument("--old-pack", required=True)
    source_admission.add_argument("--out-dir", required=True)
    source_admission.add_argument("--scan-id", default="a6200da832c587e7")
    source_admission.add_argument("--as-of-date", default="2026-08-17")
    source_admission.add_argument(
        "--apply-auto",
        action="store_true",
        help="Apply auto-eligible APPROVE/REJECT without an owner token",
    )
    evaluate_v2 = commands.add_parser(
        "live60-evaluate-v2",
        help="Run evaluation-only Live60 against a pinned candidate (no ACTIVE, no O-04)",
    )
    evaluate_v2.add_argument("--run-id", required=True)
    evaluate_v2.add_argument("--candidate-build-id", required=True)
    evaluate_v2.add_argument("--overlay", required=True)
    evaluate_v2.add_argument("--stage-a", required=True)
    evaluate_v2.add_argument("--as-of-date", default="2026-08-16")
    evaluate_v2.add_argument("--plan-only", action="store_true")
    evaluate_v2.add_argument("--case-id")
    evaluate_v2.add_argument("--out")
    admitted_semantic = commands.add_parser(
        "live60-admitted-semantic-v2",
        help="One independent semantic pass for V2-admitted exact-span HOLD rows",
    )
    admitted_semantic.add_argument("--overlay", required=True)
    admitted_semantic.add_argument("--checkpoint", required=True)
    admitted_semantic.add_argument("--catalog", default="data/catalog.sqlite3")
    admitted_semantic.add_argument("--limit", type=int)
    promote.add_argument(
        "--live60-attestation",
        help="Path to legalbot.production-promotion-attestation.v2 for Live60 production",
    )
    return root


def main(argv: Sequence[str] | None = None) -> None:
    args = parser().parse_args(argv)
    if args.command == "reattest-index":
        from .retrieval.retrieval_reattest import (
            initialize_retrieval_reattest_schema,
            open_existing_retrieval_reattest_database,
            reattest_retrieval_v1,
        )

        database_path = settings.database_path
        if database_path.is_symlink() or not database_path.is_file():
            raise SystemExit("retrieval re-attestation requires the existing local catalogue")
        reattest_database = open_existing_retrieval_reattest_database(database_path)
        try:
            initialize_retrieval_reattest_schema(reattest_database)
            result = reattest_retrieval_v1(
                settings,
                reattest_database,
                build_id=args.build_id,
                scorer_closure_manifest_path=args.scorer_closure_manifest,
            )
            print(json.dumps(result, indent=2, sort_keys=True, default=str))
        finally:
            reattest_database.close()
        return

    settings.ensure_runtime_dirs()
    database = Database(settings.database_path)
    database.initialize()
    if args.command == "init":
        cipher = LocalCipher.from_local_key(create=True)
        database.migrate_sensitive_content(cipher)
        print("LegalBot-New local storage initialised; no old runtime was imported.")
        database.close()
        return
    if args.command == "serve":
        if args.host not in {"127.0.0.1", "::1", "localhost"}:
            raise SystemExit("First release must bind to loopback only")
        database.close()
        uvicorn.run("app.api:app", app_dir="backend", host=args.host, port=args.port, reload=False)
        return
    if args.command == "worker":
        database.close()
        from .orchestration.worker import run_worker
        from .services import build_services

        asyncio.run(run_worker(build_services(settings)))
        return
    if args.command == "index-worker":
        database.close()
        from .orchestration.index_worker import run_index_worker

        run_index_worker(settings)
        return
    if args.command == "readiness":
        from .readiness import build_readiness_report, write_readiness_report

        report = build_readiness_report(settings, database)
        path = write_readiness_report(settings, report)
        print(
            json.dumps({"report": str(path.relative_to(settings.project_root)), **report}, indent=2)
        )
        database.close()
        return
    if args.command == "metrics":
        from .evaluation.operational import build_operational_metrics, write_operational_metrics

        report = build_operational_metrics(database)
        path = write_operational_metrics(settings, report)
        print(
            json.dumps({"report": str(path.relative_to(settings.project_root)), **report}, indent=2)
        )
        database.close()
        return
    if args.command in {
        "live60-owner-intake-template",
        "live60-owner-intake",
        "live60-owner-intake-migrate",
        "live60-owner-control-confirm",
        "live60-full-run-status",
    }:
        from datetime import date as date_cls

        from .evaluation.live_suite_owner_intake import (
            export_owner_decision_intake_template,
            migrate_legacy_owner_decision_docx,
            write_owner_decision_intake,
        )

        legal_date = date_cls.fromisoformat(str(args.as_of_date))
        if args.command == "live60-owner-intake-template":
            result = export_owner_decision_intake_template(
                project_root=settings.project_root,
                output_path=Path(args.out),
                as_of_date=legal_date,
                overwrite=bool(args.overwrite),
            )
        elif args.command == "live60-owner-intake":
            result = write_owner_decision_intake(
                workbook_path=Path(args.docx),
                project_root=settings.project_root,
                as_of_date=legal_date,
                draft_path=Path(args.out),
                diff_path=Path(args.diff),
                overwrite=bool(args.overwrite),
            )
        elif args.command == "live60-owner-intake-migrate":
            result = migrate_legacy_owner_decision_docx(
                workbook_path=Path(args.legacy_docx),
                project_root=settings.project_root,
                output_path=Path(args.out),
                report_path=Path(args.report),
                as_of_date=legal_date,
                overwrite=bool(args.overwrite),
            )
        elif args.command == "live60-owner-control-confirm":
            from .evaluation.live_suite_owner_control_confirm import (
                confirm_owner_control_records,
            )

            result = confirm_owner_control_records(
                project_root=settings.project_root,
                decisions_path=Path(args.decisions),
                contrary_path=Path(args.contrary),
                decisions_destination=Path(args.decisions_out),
                contrary_destination=Path(args.contrary_out),
                confirmation_token=str(args.confirm),
                index_build_id=str(args.index_build_id),
                run_id=str(args.run_id),
                as_of_date=legal_date,
                overwrite=bool(args.overwrite),
            )
        else:
            from .evaluation.live_suite_full_run_status import (
                write_full_run_remaining_status,
            )

            result = write_full_run_remaining_status(
                project_root=settings.project_root,
                as_of_date=legal_date,
                destination=Path(args.out) if args.out else None,
            )
        print(json.dumps(result, indent=2, sort_keys=True))
        database.close()
        return
    if args.command == "live60-current-state":
        from .evaluation.live_suite_current_state import CurrentLiveStateResolver

        resolver = CurrentLiveStateResolver(
            project_root=settings.project_root,
            candidate_build_id=str(args.candidate_build_id) if args.candidate_build_id else None,
        )
        result = resolver.report()
        if args.out:
            Path(args.out).write_text(
                json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        print(json.dumps(result, indent=2, sort_keys=True))
        database.close()
        return
    if args.command == "live60-source-admission-v2":
        from .evaluation.live_suite_official_bind import official_search_dirs
        from .evaluation.live_suite_source_hold_review import run_held_source_v2_review

        old_pack = json.loads(Path(args.old_pack).read_text(encoding="utf-8"))
        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        result = run_held_source_v2_review(
            database=database,
            old_pack=old_pack,
            search_dirs=official_search_dirs(settings.project_root),
            code_sha=subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=settings.project_root
            )
            .decode()
            .strip(),
            scan_id=str(args.scan_id),
            as_of_date=str(args.as_of_date),
            apply_auto=bool(args.apply_auto),
        )
        batch = result.pop("batch")
        receipt = result.pop("applied_receipt")
        (out_dir / "source-hold-review-v2.json").write_text(
            json.dumps(
                {key: value for key, value in batch.items() if key != "reviews"},
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        (out_dir / "source-admission-auto-pack-v2.json").write_text(
            json.dumps(batch["auto_pack"], ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (out_dir / "source-admission-operator-pack-v2.json").write_text(
            json.dumps(batch["operator_pack"], ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if receipt is not None:
            (out_dir / "source-admission-auto-applied.json").write_text(
                json.dumps(
                    {key: value for key, value in receipt.items() if key != "decisions"},
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
        print(json.dumps(result, indent=2, sort_keys=True))
        database.close()
        return
    if args.command == "live60-admitted-semantic-v2":
        from .evaluation.live_suite import load_live_evaluation_bundle
        from .evaluation.live_suite_admitted_semantic import run_admitted_semantic_pass
        from .evaluation.live_suite_path_b import LIVE60_ROOT

        overlay_path = Path(args.overlay)
        checkpoint_path = Path(args.checkpoint)
        catalog_path = Path(args.catalog)
        bundle = load_live_evaluation_bundle(settings.project_root / LIVE60_ROOT)

        async def _semantic() -> dict[str, Any]:
            return await run_admitted_semantic_pass(
                settings=settings,
                bundle=bundle,
                overlay_path=overlay_path,
                checkpoint_path=checkpoint_path,
                catalog_path=catalog_path,
                limit=args.limit,
            )

        result = asyncio.run(_semantic())
        print(json.dumps(result, indent=2, sort_keys=True))
        database.close()
        return
    if args.command == "live60-evaluate-v2":
        import asyncio as _asyncio

        import httpx

        from .evaluation.live_suite_evaluate_cli import run_live60_evaluate_v2

        cipher = LocalCipher.from_local_key(create=True)

        async def _run() -> dict[str, Any]:
            async with httpx.AsyncClient(timeout=30.0) as client:
                return await run_live60_evaluate_v2(
                    settings=settings,
                    database=database,
                    cipher=cipher,
                    run_id=str(args.run_id),
                    candidate_build_id=str(args.candidate_build_id),
                    overlay_path=Path(args.overlay),
                    stage_a_path=Path(args.stage_a),
                    client=client,
                    as_of_date=str(args.as_of_date),
                    execute=not bool(args.plan_only),
                    case_id=str(args.case_id) if args.case_id else None,
                )

        result = _asyncio.run(_run())
        if args.out:
            Path(args.out).write_text(
                json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        print(json.dumps(result, indent=2, sort_keys=True, default=str))
        database.close()
        return
    if args.command == "live60-evidence-pack":
        from datetime import date as date_cls

        from .evaluation.live_suite_evidence_pack import export_owner_evidence_pack

        result = export_owner_evidence_pack(
            project_root=settings.project_root,
            catalog_path=(Path(args.catalog) if args.catalog else settings.database_path),
            evidence_map_path=(
                Path(args.evidence_map)
                if args.evidence_map
                else settings.project_root
                / "Live60-2026-08-16"
                / "go-execution"
                / "issue-candidate-evidence-map.json"
            ),
            output_dir=Path(args.out_dir),
            as_of_date=date_cls.fromisoformat(str(args.as_of_date)),
            overwrite=bool(args.overwrite),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        database.close()
        return
    if args.command == "live60-evidence-import":
        from datetime import date as date_cls

        from .evaluation.live_suite_evidence_pack import (
            write_owner_evidence_reviews,
        )

        result = write_owner_evidence_reviews(
            project_root=settings.project_root,
            catalog_path=(Path(args.catalog) if args.catalog else settings.database_path),
            evidence_map_path=(
                Path(args.evidence_map)
                if args.evidence_map
                else settings.project_root
                / "Live60-2026-08-16"
                / "go-execution"
                / "issue-candidate-evidence-map.json"
            ),
            workbook_dir=Path(args.workbook_dir),
            review_export_path=Path(args.review_export),
            output_path=Path(args.out),
            as_of_date=date_cls.fromisoformat(str(args.as_of_date)),
            overwrite=bool(args.overwrite),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        database.close()
        return
    if args.command == "live60-final-check-pack":
        from datetime import date as date_cls

        from .evaluation.live_suite_final_check import export_owner_final_check_pack

        result = export_owner_final_check_pack(
            project_root=settings.project_root,
            catalog_path=(Path(args.catalog) if args.catalog else settings.database_path),
            evidence_map_path=(
                Path(args.evidence_map)
                if args.evidence_map
                else settings.project_root
                / "Live60-2026-08-16"
                / "go-execution"
                / "issue-candidate-evidence-map.json"
            ),
            output_dir=Path(args.out_dir),
            as_of_date=date_cls.fromisoformat(str(args.as_of_date)),
            overwrite=bool(args.overwrite),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        database.close()
        return
    if args.command == "live60-final-check-import":
        from datetime import date as date_cls

        from .evaluation.live_suite_final_check import write_owner_final_check_reviews

        result = write_owner_final_check_reviews(
            project_root=settings.project_root,
            catalog_path=(Path(args.catalog) if args.catalog else settings.database_path),
            pack_path=Path(args.pack),
            review_export_path=Path(args.review_export),
            output_path=Path(args.out),
            as_of_date=date_cls.fromisoformat(str(args.as_of_date)),
            overwrite=bool(args.overwrite),
            confirmation_token=str(args.confirm) if args.confirm else None,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        database.close()
        return
    if args.command == "live60-remaining-search-pack":
        from .evaluation.live_suite_remaining_search import export_remaining_search_pack

        result = export_remaining_search_pack(
            project_root=settings.project_root,
            imported_path=Path(args.imported),
            draft_path=Path(args.draft),
            output_path=Path(args.out),
            overwrite=bool(args.overwrite),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        database.close()
        return
    cipher = LocalCipher.from_local_key(create=True)
    database.migrate_sensitive_content(cipher)
    if args.command == "scan":
        from .ingestion.service import scan_configured_sources

        result = scan_configured_sources(settings, database, cipher, os.urandom(8).hex())
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.command == "build-index":
        from .retrieval.index_build import enqueue_index_build
        from .retrieval.retrieval_v1 import verify_owner_freeze
        from .retrieval.source_manifest import (
            is_current_law_full_corpus,
            is_current_law_slice_corpus,
        )

        if is_current_law_slice_corpus(args.corpus_id) or is_current_law_full_corpus(
            args.corpus_id
        ):
            verify_owner_freeze(
                settings.project_root,
                settings.project_root / "benchmarks" / "retrieval" / "v1.1.jsonl",
            )

        if args.run:
            raise RuntimeError(
                "build-index --run is disabled; enqueue the build and let the "
                "dedicated leased index worker claim it"
            )
        result = enqueue_index_build(
            settings,
            database,
            corpus_id=args.corpus_id,
            build_id=args.id,
            max_chunks=None if args.no_chunk_cap else args.max_chunks,
            preferred_small_first=bool(args.preferred_small_first),
            reuse_vectors_from_build_id=args.reuse_vectors_from_build_id,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.command == "promote":
        from .retrieval.service import promote_candidate_index

        attestation = Path(args.live60_attestation) if args.live60_attestation else None
        result = promote_candidate_index(
            settings,
            database,
            args.build_id,
            live60_attestation_path=attestation,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.command == "rollback":
        from .retrieval.service import rollback_active_index

        restored = rollback_active_index(settings, database)
        print(json.dumps(restored, indent=2))
    elif args.command == "replay-dlq":
        changed = database.replay_dlq_job(args.job_id)
        print(json.dumps({"job_id": args.job_id, "replayed": changed}, indent=2))
    elif args.command == "audit-incomplete-index":
        from .retrieval.incomplete_index_audit import audit_incomplete_index

        report = audit_incomplete_index(settings, database, args.build_id)
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
    elif args.command == "recover-index-embedding":
        from .retrieval.index_recovery import recover_index_embedding

        result = recover_index_embedding(
            settings,
            database,
            args.build_id,
            continue_build=bool(args.continue_build),
            expected_audit_report_sha256=str(args.expected_audit_report_sha256),
        )
        print(json.dumps(result, indent=2, sort_keys=True, default=str))
    elif args.command == "resume-index-build":
        from .retrieval.index_recovery import resume_index_build

        result = resume_index_build(settings, database, args.job_id)
        print(json.dumps(result, indent=2, sort_keys=True, default=str))
    elif args.command == "retry-index-build":
        from .retrieval.index_recovery import retry_index_build

        result = retry_index_build(settings, database, args.job_id, new_build_id=args.new_build_id)
        print(json.dumps(result, indent=2, sort_keys=True, default=str))
    elif args.command == "archive-incomplete-index":
        from .retrieval.lancedb import ImmutableLanceRepository
        from .retrieval.service import _validate_build_id

        _validate_build_id(args.build_id)
        archived = ImmutableLanceRepository(settings.index_dir).archive_incomplete_staging(
            args.build_id
        )
        print(
            json.dumps(
                {"build_id": args.build_id, "archived": archived.name},
                indent=2,
                sort_keys=True,
            )
        )
    elif args.command == "retrieval-v1.1":
        from .retrieval.retrieval_v1 import run_retrieval_v1

        splits = tuple(item.strip() for item in str(args.splits).split(",") if item.strip())
        report = run_retrieval_v1(settings, build_id=args.build_id, splits=splits)
        if args.out:
            dest = Path(args.out)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(
                json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            report = {**report, "report_path": str(dest)}
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
    elif args.command == "attest-index":
        from .retrieval.retrieval_v1 import attest_retrieval_v1

        result = attest_retrieval_v1(settings, database, build_id=args.build_id)
        print(json.dumps(result, indent=2, sort_keys=True, default=str))
    elif args.command == "live60-review-export":
        from datetime import date as date_cls

        from .evaluation.live_suite_path_b import export_review_candidates

        ticks = None
        if args.ticks:
            ticks = json.loads(Path(args.ticks).read_text(encoding="utf-8"))
        result = export_review_candidates(
            project_root=settings.project_root,
            destination=Path(args.out),
            cipher=cipher,
            as_of_date=date_cls.fromisoformat(str(args.as_of_date)),
            ticks=ticks,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.command == "live60-review-import":
        from .evaluation.live_suite_path_b import import_reviewed_rows

        repair = None
        if args.repair:
            repair = json.loads(Path(args.repair).read_text(encoding="utf-8"))
        else:
            from .evaluation.live_suite_path_b import load_default_v2_repair

            repair = load_default_v2_repair(settings.project_root)
        result = import_reviewed_rows(
            project_root=settings.project_root,
            export_path=Path(args.export),
            reviewed_path=Path(args.reviewed),
            catalog_path=settings.database_path if settings.database_path.is_file() else None,
            repair=repair,
        )
        if args.out:
            Path(args.out).write_text(
                json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        print(
            json.dumps({k: v for k, v in result.items() if k != "rows"}, indent=2, sort_keys=True)
        )
    elif args.command in {"live60-overlay-seal", "live60-review-seal"}:
        from datetime import date as date_cls

        from .evaluation.live_suite_path_b import (
            OVERLAY_RECONSTRUCTION_SCHEMA,
            REVIEW_IMPORT_SCHEMA,
            reconstruct_overlay,
            seal_overlay_from_reviewed_rows,
        )

        reviewed_path = Path(
            args.reviewed_rows if args.command == "live60-review-seal" else args.reconstruction
        )
        imported = json.loads(reviewed_path.read_text(encoding="utf-8"))
        reconstruction = imported
        if imported.get("schema") in {REVIEW_IMPORT_SCHEMA, "legalbot.live60-review-import.v1"}:
            reconstruction = reconstruct_overlay(
                project_root=settings.project_root,
                imported=imported,
                as_of_date=date_cls.fromisoformat(str(imported.get("as_of_date") or "2026-08-16")),
            )
        elif imported.get("schema") != OVERLAY_RECONSTRUCTION_SCHEMA:
            raise SystemExit("review seal requires imported rows or a reconstruction")
        result = seal_overlay_from_reviewed_rows(
            project_root=settings.project_root,
            reconstruction=reconstruction,
            reviewer_ref=str(args.reviewer_ref),
            index_build_id=str(args.index_build_id),
            run_id=str(args.run_id),
            contrary_review_path=Path(args.contrary_review),
            owner_decisions_path=Path(args.owner_decisions),
            destination=Path(args.out) if args.out else None,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.command == "research-enqueue":
        from .research.jobs import enqueue_official_crawl_job

        result = enqueue_official_crawl_job(
            settings,
            database,
            task_type=args.task_type,
            subject=args.subject,
            priority=args.priority,
            source_id=args.source_id,
            authority_identity_id=args.authority_identity_id,
            knowledge_gap_id=args.knowledge_gap_id,
            source_locator=args.source_locator,
            public_query=args.public_query,
            cipher=cipher,
        )
        print(json.dumps(result, indent=2, sort_keys=True, default=str))
    elif args.command == "research-queue":
        from .research.jobs import format_queue_json, research_queue_snapshot

        print(format_queue_json(research_queue_snapshot(database, limit=args.limit)))
    elif args.command == "research-worker":
        from .research.jobs import run_research_worker

        result = asyncio.run(run_research_worker(settings, database, cipher, once=args.once))
        if args.once:
            print(json.dumps(result, indent=2, sort_keys=True, default=str))
    database.close()


if __name__ == "__main__":
    main()
