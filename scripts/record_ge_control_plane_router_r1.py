#!/usr/bin/env python3
"""Record scoped r1-vs-r2 approval, freeze r2, and emit the 293-hold router.

Create-only. Not gold, admission, training, unseen, promotion or live.
Does not retick the unsigned locator draft or rerun the 331.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.evaluation.ge_hold_reason_router import (
    CASE_008,
    CASE_174,
    CASE_312,
    route_results,
)
from app.evaluation.ge_phase2_progress import (
    evaluation_fingerprint,
    explicit_stage_states,
    phase2_progress,
)

ROOT = Path(__file__).resolve().parents[1]
PACK = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-control-plane-router-r1"
)
R2 = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-visible-331-diagnostic-r2"
)
R2_RESULTS = R2 / "visible/RESULTS.jsonl"
R2_MANIFEST = R2 / "RUN-MANIFEST.json"
COMPARISON_DOCX = ROOT / "output/docx/LegalBot-GE-2026-09-02-visible-331-diagnostic-r1-vs-r2.docx"
COMPARISON_JSON = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-visible-331-diagnostic-r2-comparison"
    / "COMPARISON.json"
)
REGISTER = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-per-locator-evaluation-gold-resolved-r2"
    / "LOCATOR-EVALUATION-GOLD-REGISTER.json"
)
DRAFT = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-per-locator-gold-draft-r1"
    / "LOCATOR-GOLD-DRAFT.json"
)
VISIBLE_PACK = ROOT / "data/evaluations/general-enquiries/LegalBot-GE-2026-09-01-review-r3"
EXPECTED_R2_MANIFEST = "d0ed806eee3ead78be77b5ca8eb150cbb7fd15f3eb9332637f230b38eef311c2"
EXPECTED_R2_RESULTS = "a3142fce995b7ae575864ae8411e9346d084306bf1197a4153326a8506a0908c"
EXPECTED_DOCX = "786a182fed3e4bccd572be856d0ad4c6bf85ecad36fcb97991d9a1b0ebdc5e79"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _digest(value: dict[str, Any]) -> dict[str, Any]:
    body = {key: item for key, item in value.items() if key != "content_sha256"}
    result = dict(value)
    result["content_sha256"] = hashlib.sha256(_canonical_bytes(body)).hexdigest()
    return result


def _write_text(path: Path, text: str) -> None:
    data = text.encode("utf-8")
    if not data.endswith(b"\n"):
        data += b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _write_json(path: Path, value: Any) -> None:
    _write_text(path, json.dumps(value, ensure_ascii=False, indent=2))


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def main() -> int:
    if PACK.exists() or PACK.is_symlink():
        raise FileExistsError(f"create-only pack exists: {PACK}")
    r2_manifest = json.loads(R2_MANIFEST.read_text(encoding="utf-8"))
    if r2_manifest.get("content_sha256") != EXPECTED_R2_MANIFEST:
        raise RuntimeError("frozen r2 RUN-MANIFEST identity mismatch")
    results_sha = _sha256_file(R2_RESULTS)
    if results_sha != EXPECTED_R2_RESULTS:
        raise RuntimeError("frozen r2 RESULTS identity mismatch")
    docx_sha = _sha256_file(COMPARISON_DOCX)
    if docx_sha != EXPECTED_DOCX:
        raise RuntimeError(f"scoped-approval DOCX hash mismatch: {docx_sha}")
    if not DRAFT.is_file():
        raise RuntimeError("unsigned locator draft is missing and must stay preserved")
    rows = _load_jsonl(R2_RESULTS)
    if len(rows) != 331:
        raise RuntimeError("r2 did not freeze 331 cases")
    routed = route_results(rows)
    if routed["hold_count"] != 293 or routed["factual_pass_count"] != 38:
        raise RuntimeError("r2 hold/pass counts drifted")
    holds_by_id = {item["case_id"]: item for item in routed["holds"]}
    if CASE_008 in holds_by_id:
        raise RuntimeError("case 008 must remain FACTUAL_PASS and frozen")
    if holds_by_id[CASE_174]["hold_reason_code"] != "JURISDICTION_SCOPE_REVIEW":
        raise RuntimeError("case 174 must route to jurisdiction-scope review")
    if holds_by_id[CASE_174]["machine_repairable"] is True:
        raise RuntimeError("case 174 is not machine-repairable")
    if holds_by_id[CASE_312]["hold_reason_code"] != "FACT_DEPENDENT_OUTCOME":
        raise RuntimeError("case 312 must remain fact-dependent")
    visible_hash = ""
    manifest_path = VISIBLE_PACK / "PACK-MANIFEST.json"
    if manifest_path.is_file():
        visible_hash = str(json.loads(manifest_path.read_text(encoding="utf-8")).get("content_sha256") or "")
    fingerprint = evaluation_fingerprint(
        project_root=ROOT,
        locator_manifest_hash=_sha256_file(REGISTER),
        answer_set_hash=results_sha,
        visible_pack_hash=visible_hash,
    )
    progress = phase2_progress(
        case_results=rows,
        locator_hold_count=0,
        locator_pending_count=0,
        locator_reject_count=1,
        diagnostic_execution="COMPLETE",
        diagnostic_report="APPROVED_SCOPED",
        routed=True,
        runnable_queue_count=routed["runnable_queue_count"],
    )
    stages = explicit_stage_states()
    recorded_at = datetime.now(UTC).isoformat()
    PACK.mkdir(parents=True, mode=0o700)
    os.chmod(PACK, stat.S_IRWXU)

    receipt = _digest(
        {
            "schema": "legalbot.ge-control-plane-state-transition-receipt.v1",
            "recorded_at_utc": recorded_at,
            "signature_status": "session_instruction_hash_bound_not_cryptographic_signature",
            "owner_scoped_approval": {
                "artifact": COMPARISON_DOCX.as_posix(),
                "file_sha256": EXPECTED_DOCX,
                "scope": "locator_level_r1_versus_r2_diagnostic_receipt_only",
                "qualified_legal_review": "NOT_STARTED",
                "answer_legal_gold": "NOT_STARTED",
                "catalogue_admission": "NOT_STARTED",
                "answer_weight_training": "NOT_STARTED",
                "sealed_unseen_execution": "NOT_STARTED",
                "promotion": "NOT_STARTED",
                "live": "NOT_STARTED",
            },
            "frozen_r2": {
                "run_id": "LegalBot-GE-2026-09-02-visible-331-diagnostic-r2",
                "run_manifest_content_sha256": EXPECTED_R2_MANIFEST,
                "visible_results_sha256": EXPECTED_R2_RESULTS,
                "immutable": True,
            },
            "locator_package": {
                "state": "RESOLVED_66_APPROVE_0_HOLD_1_REJECT",
                "register_path": REGISTER.as_posix(),
                "do_not_retick_unsigned_draft": True,
                "unsigned_draft_preserved": DRAFT.as_posix(),
                "tick_sheet_created_or_modified": False,
            },
            "cable_and_wireless": {
                "mandatory_locator": "REJECTED",
                "negative_or_contextual_record": True,
                "missing_primary": False,
                "automatic_reopen": False,
            },
            "named_case_invariants": {
                CASE_008: "FACTUAL_PASS_FROZEN_REGRESSION",
                CASE_174: "JURISDICTION_SCOPE_REVIEW_NO_CABLE_NO_ARB_S9",
                CASE_312: "FACT_DEPENDENT_OUTCOME_NO_FURTHER_RETRIEVAL",
            },
            "stage_states": stages,
            "progress": {
                "overall_progress": progress["overall_progress"],
                "overall_state": progress["overall_state"],
                "runnable_queue_count": progress["runnable_queue_count"],
                "phase2_r2_complete": progress["phase2_r2_complete"],
            },
            "downstream_gates_once": {name: "NOT_STARTED" for name in (
                "qualified_legal_review",
                "answer_legal_gold",
                "legal_gold",
                "catalogue_admission",
                "full_current_law_eligible",
                "answer_weight_training",
                "sealed_unseen_execution",
                "promotion",
                "live",
            )},
            "confirmations": {
                "tick_sheet_created_or_modified": False,
                "locator_package_reopened": False,
                "gold_admission_training_unseen_promotion_live_changed": False,
                "full_331_rerun": False,
            },
        }
    )
    summary = _digest(
        {
            "schema": "legalbot.ge-hold-reason-summary.v1",
            "source_run_id": "LegalBot-GE-2026-09-02-visible-331-diagnostic-r2",
            "hold_count": routed["hold_count"],
            "factual_pass_count": routed["factual_pass_count"],
            "counts_by_hold_reason_code": routed["counts_by_hold_reason_code"],
            "counts_by_next_route": routed["counts_by_next_route"],
            "runnable_queue_count": routed["runnable_queue_count"],
            "terminal_queue_count": routed["terminal_queue_count"],
            "targeted_repair_case_ids": routed["targeted_repair_case_ids"],
            "evidence_absent_holds": sum(not item["evidence_present"] for item in routed["holds"]),
            "claim_support_pass_holds": sum(
                item["claim_support_status"] == "PASS" for item in routed["holds"]
            ),
        }
    )
    _write_json(PACK / "STATE-TRANSITION-RECEIPT.json", receipt)
    _write_json(PACK / "HOLD-REASON-SUMMARY.json", summary)
    _write_json(PACK / "EVALUATION-FINGERPRINT.json", fingerprint)
    _write_json(
        PACK / "HOLD-REASON-MANIFEST.json",
        _digest(
            {
                "schema": "legalbot.ge-hold-reason-manifest.v1",
                "source_run_id": "LegalBot-GE-2026-09-02-visible-331-diagnostic-r2",
                "rows": routed["holds"],
            }
        ),
    )
    _write_json(
        PACK / "TARGETED-REPAIR-QUEUE.json",
        _digest(
            {
                "schema": "legalbot.ge-targeted-repair-queue.v1",
                "case_ids": routed["targeted_repair_case_ids"],
                "count": routed["runnable_queue_count"],
                "full_331_rerun": False,
            }
        ),
    )
    _write_json(
        PACK / "FROZEN-PASS-REGRESSION.json",
        _digest(
            {
                "schema": "legalbot.ge-frozen-pass-regression.v1",
                "rows": routed["frozen_pass_cases"],
            }
        ),
    )
    _write_text(
        PACK / "README.md",
        (
            "# Control-plane and hold-reason router r1\n\n"
            "Scoped approval of the r1-versus-r2 diagnostic report. r2 is frozen. "
            "Locator review is complete. Downstream gates are NOT_STARTED, not failed. "
            "No tick sheet was created.\n"
        ),
    )
    print(
        json.dumps(
            {
                "receipt": receipt["content_sha256"],
                "summary": summary["content_sha256"],
                "overall_state": progress["overall_state"],
                "runnable_queue_count": routed["runnable_queue_count"],
                "terminal_queue_count": routed["terminal_queue_count"],
                "counts_by_hold_reason_code": routed["counts_by_hold_reason_code"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
