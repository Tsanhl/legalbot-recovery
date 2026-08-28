"""CLI orchestration for evaluation-only Live60 v2 execution."""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..assessment.guidance_bundle import OWNER_ASSESSMENT_BUNDLE
from ..config import Settings
from ..crypto import LocalCipher
from ..db import Database
from ..orchestration.classifier import CLASSIFIER_VERSION
from ..orchestration.routing import ROUTER_VERSION
from ..quality.policy import POLICY_SHA256
from ..runtime_adapters import PROMPT_VERSION
from .live30 import RunProvenance
from .live_suite import load_live_evaluation_bundle
from .live_suite_evaluation_auth import issue_evaluation_authorization_v2
from .live_suite_evaluation_run import execute_evaluation_only_run, plan_evaluation_only_run
from .live_suite_execute import Live60ExecutionPreflight
from .live_suite_http_execute import Live60Executor, Live60RuntimeBinding
from .live_suite_overlay_complete import overlay_complete_v2
from .live_suite_path_b import LIVE60_ROOT, selected_generation_case_ids
from .live_suite_store import LiveSuiteRunStore


def _git_provenance(project_root: Path) -> tuple[str, bool]:
    """Resolve real execution provenance before persistent run creation."""

    try:
        sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=project_root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        dirty = bool(
            subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=project_root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError("Live60 execution requires readable Git provenance") from exc

    if len(sha) != 40 or any(character not in "0123456789abcdef" for character in sha):
        raise RuntimeError("Live60 execution resolved an invalid Git SHA")

    return sha, dirty


async def run_live60_evaluate_v2(
    *,
    settings: Settings,
    database: Database,
    cipher: LocalCipher,
    run_id: str,
    candidate_build_id: str,
    overlay_path: Path,
    stage_a_path: Path,
    client: Any,
    as_of_date: str,
    execute: bool = True,
    case_id: str | None = None,
) -> dict[str, Any]:
    bundle = load_live_evaluation_bundle(settings.project_root / LIVE60_ROOT)
    overlay = json.loads(overlay_path.read_text(encoding="utf-8"))
    complete = overlay
    if overlay.get("issues"):
        complete = overlay_complete_v2(
            selected_issues=list(overlay.get("issues") or ()),
            bundle=bundle,
        )
        if complete.get("review_overlay_complete") is not True:
            raise ValueError("v2 overlay is not complete")
    authorization = issue_evaluation_authorization_v2(
        evaluation_run_id=run_id,
        bundle=bundle,
        candidate_build_id=candidate_build_id,
        overlay_path=overlay_path,
        stage_a_path=stage_a_path,
        database=database,
        as_of_date=as_of_date,
        issued_at=datetime.now(UTC),
        settings=settings,
    )
    selected = selected_generation_case_ids(bundle)
    if case_id:
        if case_id not in selected:
            raise ValueError("case-id is not a selected generation case")
        selected = (case_id,)
    case_execution = list(complete.get("case_execution") or ())
    if not case_execution:
        issues_by_case: dict[str, list[dict[str, Any]]] = {}
        for issue in list(overlay.get("issues") or ()):
            if not isinstance(issue, dict):
                continue
            issues_by_case.setdefault(str(issue.get("case_id") or ""), []).append(issue)
        case_execution = [
            {
                "case_id": case_id_value,
                "issues": issues_by_case.get(case_id_value, []),
            }
            for case_id_value in selected
        ]
    if case_id:
        case_execution = [
            item for item in case_execution if str(item.get("case_id") or "") == case_id
        ]
    planned = plan_evaluation_only_run(
        authorization=authorization,
        candidate_build_id=candidate_build_id,
        selected_cases=case_execution,
        overlay_complete=complete.get("review_overlay_complete") is True,
        unreviewed_issue_count=int(complete.get("unreviewed_issue_count") or 0),
        active_build_id=database.active_index_id(),
    )
    if not execute:
        return planned

    git_sha, git_dirty = _git_provenance(settings.project_root)
    store = LiveSuiteRunStore(settings.project_root, cipher)
    run_root = store.runs_root / run_id
    if not (run_root / "manifest.json").is_file():
        provenance = RunProvenance(
            git_sha=git_sha,
            git_dirty=git_dirty,
            model_version=settings.model_id,
            index_build_id=candidate_build_id,
            prompt_version=PROMPT_VERSION,
            router_version=ROUTER_VERSION,
            classifier_version=CLASSIFIER_VERSION,
            policy_sha256=POLICY_SHA256,
            assessment_rules_sha256=OWNER_ASSESSMENT_BUNDLE.sha256,
        )
        store.create_run(
            run_id=run_id,
            bundle=bundle,
            provenance=provenance,
        )
    auth_path = run_root / "execution-authorization.json"
    auth_path.write_text(
        json.dumps(
            authorization.model_dump(mode="json", by_alias=True),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    manifest = store.load_run_manifest(run_id)
    preflight = Live60ExecutionPreflight(
        run_manifest=manifest,
        authorization=authorization,
        generated_case_ids=selected,
        evidence_ready_case_ids=tuple(
            item["case_id"]
            for item in planned["outcomes"]
            if item["planned_terminal_state"] in {"released", "verified_limited"}
        ),
        limited_or_held_case_ids=tuple(
            item["case_id"]
            for item in planned["outcomes"]
            if item["planned_terminal_state"] in {"held", "verified_limited"}
        ),
        limited_case_ids=tuple(
            item["case_id"]
            for item in planned["outcomes"]
            if item["planned_terminal_state"] == "verified_limited"
        ),
        held_case_ids=tuple(
            item["case_id"]
            for item in planned["outcomes"]
            if item["planned_terminal_state"] == "held"
        ),
    )
    runtime = Live60RuntimeBinding(
        run_id=run_id,
        base_url=f"http://{settings.host}:{settings.port}",
        index_build_id=candidate_build_id,
        model_version=settings.model_id,
        prompt_version=PROMPT_VERSION,
        router_version=ROUTER_VERSION,
        classifier_version=CLASSIFIER_VERSION,
        policy_sha256=POLICY_SHA256,
        assessment_bundle_sha256=OWNER_ASSESSMENT_BUNDLE.sha256,
        as_of_date=__import__("datetime").date.fromisoformat(as_of_date),
        owner_identifiers=tuple(settings.owner_identifiers),
        readiness_report_sha256="0" * 64,
        rollback_report_sha256="0" * 64,
        browser_recovery_report_sha256="0" * 64,
        evaluation_mode=True,
    )
    executor = Live60Executor(
        store=store,
        bundle=bundle,
        preflight=preflight,
        runtime=runtime,
        client=client,
    )
    return await execute_evaluation_only_run(
        authorization=authorization,
        candidate_build_id=candidate_build_id,
        executor=executor,
        active_build_id=database.active_index_id(),
    )
