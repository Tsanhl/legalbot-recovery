"""One independent semantic verification for V2-admitted exact-span rows.

The source is already admitted. This module does not hunt another source.
A completed sealed result is not re-run. Technical failures may retry once.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import traceback
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from ..config import Settings
from ..quality.policy import POLICY_SHA256
from ..runtime_adapters import LoopbackModelGateway
from .live_suite import LiveEvaluationBundle
from .live_suite_hold_taxonomy import classify_hold_queue
from .live_suite_overlay_complete import fully_verified_selected_case_ids
from .live_suite_overlay_io import write_overlay_with_issues
from .live_suite_path_b import (
    frozen_selected_issue_identities,
    selected_generation_case_ids,
)
from .live_suite_semantic_disposition import dispose_semantic_hold
from .live_suite_semantic_result import invoke_semantic_verifier
from .live_suite_span_accuracy import check_user_span_exact_match
from .prompt_templates import SEMANTIC_VERIFIER_TEMPLATE_SHA256

ADMITTED_SEMANTIC_SCHEMA = "legalbot.admitted-source-semantic-pass.v2"
PENDING_REASON = "source_admitted_semantic_pending"
MAX_EVIDENCE_ITEMS = 4
MAX_EVIDENCE_CHARS = 1800


def _sha_files(paths: Sequence[Path]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.read_bytes())
        digest.update(b"\n")
    return digest.hexdigest()


def proposition_text_by_row(bundle: LiveEvaluationBundle) -> dict[str, str]:
    selected = set(selected_generation_case_ids(bundle))
    mapping: dict[str, str] = {}
    for case in bundle.registry.cases:
        if case.case_id not in selected:
            continue
        for number, topic in enumerate(case.must_cover_issues, start=1):
            mapping[f"{case.case_id}:issue-{number:02d}"] = topic
    return mapping


def load_checkpoint(path: Path) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    if not path.is_file():
        return latest
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        row_id = str(row.get("row_id") or "")
        if row_id:
            latest[row_id] = row
    return latest


def append_checkpoint(path: Path, row: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(dict(row), ensure_ascii=False, sort_keys=True) + "\n")


def checkpoint_is_complete(row: Mapping[str, Any]) -> bool:
    nested = row.get("semantic_result")
    if isinstance(nested, Mapping) and nested.get("seal_sha256"):
        return True
    return row.get("reason") == "exception" and bool(row.get("technical_retried"))


def pending_admitted_issues(issues: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    pending: list[dict[str, Any]] = []
    for issue in issues:
        if str(issue.get("gap_reason") or "") != PENDING_REASON:
            continue
        if str(issue.get("final_verification_status") or "") == "VERIFIED":
            continue
        pending.append(dict(issue))
    return pending


def _chunk(connection: sqlite3.Connection, chunk_id: str) -> sqlite3.Row | None:
    row = connection.execute(
        """
        SELECT c.id, c.source_version_id, c.locator, c.text_sha256, c.markdown_text,
               sv.authority_identity_id, sv.currentness_status
        FROM chunks c
        LEFT JOIN source_versions sv ON sv.id = c.source_version_id
        WHERE c.id = ?
        """,
        (chunk_id,),
    ).fetchone()
    return cast(sqlite3.Row | None, row)


def _budget_evidence(evidence: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    budgeted: list[dict[str, Any]] = []
    used = 0
    for item in evidence:
        if len(budgeted) >= MAX_EVIDENCE_ITEMS:
            break
        text = str(item.get("text") or "")
        payload = dict(item)
        if budgeted and used + len(text) > MAX_EVIDENCE_CHARS:
            break
        if not budgeted and len(text) > MAX_EVIDENCE_CHARS:
            payload["text"] = text[:MAX_EVIDENCE_CHARS]
            text = payload["text"]
        budgeted.append(payload)
        used += len(text)
    return budgeted or [dict(item) for item in evidence[:1]]


async def verify_one_admitted_issue(
    *,
    model: LoopbackModelGateway,
    connection: sqlite3.Connection,
    issue: Mapping[str, Any],
    proposition_text: str,
    identity: Mapping[str, Any],
    catalog_path: Path,
    toolchain_sha256: str,
    model_id: str,
    model_version: str,
) -> dict[str, Any]:
    spans = list(issue.get("exact_gold_spans") or ())
    evidence: list[dict[str, Any]] = []
    for span in spans:
        chunk_id = str(span.get("chunk_id") or "")
        report = check_user_span_exact_match(
            chunk_id=chunk_id,
            content_sha256=str(span.get("content_sha256") or ""),
            legal_locator=str(span.get("legal_locator") or span.get("locator") or ""),
            source_version_id=span.get("source_version_id"),
            catalog_path=catalog_path,
            legal_authority_id=span.get("legal_authority_id"),
            legal_role=span.get("legal_role"),
            jurisdiction=span.get("jurisdiction"),
            source_type=span.get("source_type"),
            stable_source_id=span.get("stable_source_id"),
        )
        if report.get("exact_match") is not True:
            return {
                "schema": ADMITTED_SEMANTIC_SCHEMA,
                "row_id": issue.get("row_id"),
                "ok": False,
                "reason": "mechanical_exact_failed",
                "blocking_reason_codes": report.get("mismatches") or ["exact_match_failed"],
            }
        catalog_row = _chunk(connection, chunk_id)
        if catalog_row is None:
            continue
        evidence.append(
            {
                "id": catalog_row["id"],
                "chunk_id": catalog_row["id"],
                "content_sha256": catalog_row["text_sha256"],
                "text": catalog_row["markdown_text"],
                "legal_locator": catalog_row["locator"],
                "source_version_id": catalog_row["source_version_id"],
                "legal_authority_id": catalog_row["authority_identity_id"],
                "currentness_status": catalog_row["currentness_status"],
            }
        )
    if not evidence:
        return {
            "schema": ADMITTED_SEMANTIC_SCHEMA,
            "row_id": issue.get("row_id"),
            "ok": False,
            "reason": "catalogue_chunk_missing",
        }
    first = spans[0] if spans else {}
    semantic = await invoke_semantic_verifier(
        model=model,
        issue_id=str(issue.get("issue_id") or ""),
        proposition_hash=str(identity["topic_sha256"]),
        proposition_text=proposition_text,
        evidence=_budget_evidence(evidence),
        legal_locator=str(first.get("legal_locator") or first.get("locator") or ""),
        source_identity=str(first.get("legal_authority_id") or first.get("stable_source_id") or ""),
        citation_metadata={
            "source_type": first.get("source_type"),
            "legal_role": first.get("legal_role"),
            "jurisdiction": first.get("jurisdiction") or "England and Wales",
            "source_version_id": first.get("source_version_id"),
        },
        currentness_status=None,
        policy_sha256=POLICY_SHA256,
        toolchain_sha256=toolchain_sha256,
        model_id=model_id,
        model_version=model_version,
    )
    dumped = semantic.model_dump(mode="json", by_alias=True)
    record = {
        "row_id": issue.get("row_id"),
        "case_id": issue.get("case_id"),
        "issue_id": issue.get("issue_id"),
        "exact_gold_spans": spans,
        "semantic_result": dumped,
        "semantic_result_seal_sha256": dumped["seal_sha256"],
        "error": None,
    }
    disposed = dispose_semantic_hold(record)
    update = dict(disposed.get("issue_update") or {})
    verified = str(update.get("final_verification_status") or "") == "VERIFIED"
    return {
        "schema": ADMITTED_SEMANTIC_SCHEMA,
        "row_id": issue.get("row_id"),
        "case_id": issue.get("case_id"),
        "issue_id": issue.get("issue_id"),
        "ok": verified,
        "disposition": update.get("disposition") or disposed.get("recommendation"),
        "final_verification_status": update.get("final_verification_status") or "HOLD",
        "cause": disposed.get("cause"),
        "reason_code": disposed.get("reason_code"),
        "semantic_result": dumped,
        "semantic_result_seal_sha256": dumped["seal_sha256"],
        "issue_update": update,
        "proposition_hash": identity["topic_sha256"],
        "topic_sha256": identity["topic_sha256"],
        "question_sha256": identity["question_sha256"],
        "record_sha256": identity["record_sha256"],
        "verifier_prompt_sha256": SEMANTIC_VERIFIER_TEMPLATE_SHA256,
        "proposer_confidence": None,
        "writes_active": False,
        "writes_o04": False,
    }


def apply_issue_update(
    issue: Mapping[str, Any],
    update: Mapping[str, Any],
) -> dict[str, Any]:
    merged = dict(issue)
    merged.update(update)
    return merged


def overlay_counts(issues: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    taxonomy = classify_hold_queue(issues)
    return {
        "SOURCE_ADMITTED_SEMANTIC_PENDING": taxonomy["source_admitted_semantic_pending"],
        "VERIFIED_QUALIFIED": taxonomy["verified_qualified"],
        "VERIFIED_LIMITED": taxonomy["verified_limited"],
        "VERIFIED_KNOWLEDGE_GAP": taxonomy["verified_knowledge_gap"],
        "TOTAL_HOLD": taxonomy["total_hold"],
        "V2_VERIFIED_SELECTED": taxonomy["v2_verified_selected"],
        "FULLY_VERIFIED_SELECTED_CASE_IDS": list(fully_verified_selected_case_ids(issues)),
        "SOURCE_EFFECTS_HOLD": taxonomy["source_effects_hold"],
        "SOURCE_ADMISSION_REJECTED": taxonomy["source_admission_rejected"],
        "SEMANTIC_CONTRADICTION_HOLD": taxonomy["semantic_contradiction_hold"],
        "OWNER_ADJUDICATION_REQUIRED": taxonomy["owner_adjudication_required"],
        "OTHER_HOLD": taxonomy["other_hold"],
        "OWNER_CONFIRMATION_REQUIRED": taxonomy["owner_confirmation_required"],
    }


async def run_admitted_semantic_pass(
    *,
    settings: Settings,
    bundle: LiveEvaluationBundle,
    overlay_path: Path,
    checkpoint_path: Path,
    catalog_path: Path,
    limit: int | None = None,
) -> dict[str, Any]:
    overlay = json.loads(overlay_path.read_text(encoding="utf-8"))
    issues = [dict(item) for item in overlay.get("issues") or ()]
    pending = pending_admitted_issues(issues)
    identities = {item["row_id"]: item for item in frozen_selected_issue_identities(bundle)}
    topics = proposition_text_by_row(bundle)
    done = load_checkpoint(checkpoint_path)
    model = LoopbackModelGateway(settings)
    if not await model.health():
        raise RuntimeError("MODEL_RUNTIME_HEALTH is not ok")
    toolchain = _sha_files(
        [
            settings.project_root / "backend/app/evaluation/live_suite_semantic_result.py",
            settings.project_root / "backend/app/evaluation/live_suite_semantic_disposition.py",
            settings.project_root / "backend/app/evaluation/prompts/semantic_verifier.v2.txt",
        ]
    )
    connection = sqlite3.connect(f"file:{catalog_path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    attempted = 0
    verified = 0
    remaining = pending
    try:
        for issue in pending:
            if limit is not None and attempted >= limit:
                break
            row_id = str(issue.get("row_id") or "")
            prior = done.get(row_id)
            if prior is not None and checkpoint_is_complete(prior):
                update = prior.get("issue_update") or {}
                if update:
                    issues = [
                        apply_issue_update(item, update)
                        if str(item.get("row_id") or "") == row_id
                        else item
                        for item in issues
                    ]
                continue
            identity = identities.get(row_id)
            topic = topics.get(row_id)
            if identity is None or not topic:
                result = {
                    "schema": ADMITTED_SEMANTIC_SCHEMA,
                    "row_id": row_id,
                    "ok": False,
                    "reason": "frozen_identity_missing",
                }
                append_checkpoint(checkpoint_path, result)
                attempted += 1
                continue
            try:
                result = await verify_one_admitted_issue(
                    model=model,
                    connection=connection,
                    issue=issue,
                    proposition_text=topic,
                    identity=identity,
                    catalog_path=catalog_path,
                    toolchain_sha256=toolchain,
                    model_id=settings.model_id,
                    model_version=f"{settings.model_id}@runtime",
                )
            except Exception as exc:
                result = {
                    "schema": ADMITTED_SEMANTIC_SCHEMA,
                    "row_id": row_id,
                    "ok": False,
                    "reason": "exception",
                    "error": f"{type(exc).__name__}: {exc}"[:500],
                    "trace": traceback.format_exc()[-1500:],
                    "technical_retried": bool(prior),
                }
            append_checkpoint(checkpoint_path, result)
            attempted += 1
            update = result.get("issue_update")
            if isinstance(update, Mapping) and update:
                issues = [
                    apply_issue_update(item, update)
                    if str(item.get("row_id") or "") == row_id
                    else item
                    for item in issues
                ]
                write_overlay_with_issues(overlay_path, issues=issues, bundle=bundle)
            if result.get("ok"):
                verified += 1
            counts = overlay_counts(issues)
            print(
                json.dumps(
                    {
                        "row_id": row_id,
                        "ok": result.get("ok"),
                        "disposition": result.get("disposition") or result.get("reason"),
                        **counts,
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
    finally:
        connection.close()
    write_overlay_with_issues(overlay_path, issues=issues, bundle=bundle)
    remaining = pending_admitted_issues(issues)
    summary = {
        "schema": ADMITTED_SEMANTIC_SCHEMA,
        "attempted": attempted,
        "verified_this_run": verified,
        "source_admitted_semantic_pending_remaining": len(remaining),
        **overlay_counts(issues),
        "writes_active": False,
        "writes_o04": False,
    }
    return summary
