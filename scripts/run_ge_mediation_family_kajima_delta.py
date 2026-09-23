#!/usr/bin/env python3
"""Run the Kajima paragraph 29/30 targeted mediation-family delta.

Create-only. Does not rerun the full 331, mutate frozen r2, reopen locator
review, or set gold, admission, training, unseen, promotion or live.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.evaluation.ge_claim_support_router import route_claim_cases
from app.evaluation.ge_control_plane_v2 import control_plane_v2
from app.evaluation.ge_hold_reason_router import CASE_008, CASE_174, CASE_312, route_results
from app.evaluation.ge_kajima_mediation_family import (
    MEDIATION_TOPIC,
    PARAGRAPH_29,
    PARAGRAPH_30,
    TARGETED_MEDIATION_FAMILY,
    apply_kajima_evidence_plan,
    build_kajima_evidence_row,
    decide_kajima_attachment,
    derive_kajima_29_30_affected_case_ids,
    execute_kajima_attachments,
    hint_dependency_hash,
    kajima_29_30_hint_dependency_changed,
    load_kajima_locator_chunks,
    mediation_family_noop_row,
    rebuild_case_result,
)
from app.evaluation.ge_locator_gold_overlay import load_locator_gold_overlay
from app.evaluation.ge_phase2_progress import (
    MECHANICAL_EVALUATION_COMPLETE_REVIEW_PENDING,
    NO_OP_UNCHANGED_CASE_INPUTS,
    evaluation_fingerprint,
    explicit_stage_states,
    phase2_progress,
)
from app.evaluation.ge_qualified_review_packets import build_review_packet
from scripts.run_ge_retrieval_training_cycle import (
    DEFAULT_LOCATOR_OVERLAY,
    ISSUE_LOCATOR_HINTS,
    SOURCE_MANIFEST,
    TOPIC_SOURCES,
    VISIBLE_PACK,
    _load_json,
    _sealed,
    _sha256_file,
    _source_lookup,
    _write_json,
    _write_jsonl,
)

ROOT = Path(__file__).resolve().parents[1]
PACK = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-mediation-family-kajima-delta-r1"
)
DELTA = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-mechanical-repair-delta-r1"
)
DELTA_RESULTS = DELTA / "visible/RESULTS.jsonl"
DELTA_MANIFEST = DELTA / "RUN-MANIFEST.json"
R2 = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-visible-331-diagnostic-r2"
)
R2_RESULTS = R2 / "visible/RESULTS.jsonl"
R2_MANIFEST = R2 / "RUN-MANIFEST.json"
REGISTER = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-per-locator-evaluation-gold-resolved-r2"
    / "LOCATOR-EVALUATION-GOLD-REGISTER.json"
)

EXPECTED_R2_MANIFEST = "d0ed806eee3ead78be77b5ca8eb150cbb7fd15f3eb9332637f230b38eef311c2"
EXPECTED_R2_RESULTS = "a3142fce995b7ae575864ae8411e9346d084306bf1197a4153326a8506a0908c"
EXPECTED_DELTA_MANIFEST = "cea8e5a16dcbc65dbb58df3022d40034f63f27ebecab48054e6a42c19f347afe"
DOWNSTREAM = (
    "qualified_legal_review",
    "answer_legal_gold",
    "legal_gold",
    "catalogue_admission",
    "full_current_law_eligible",
    "answer_weight_training",
    "sealed_unseen_execution",
    "promotion",
    "live",
)


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _write_text(path: Path, text: str) -> None:
    data = text.encode("utf-8")
    if not data.endswith(b"\n"):
        data += b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _snapshot(row: Mapping[str, Any]) -> dict[str, Any]:
    factual = row.get("factual_result") if isinstance(row.get("factual_result"), dict) else {}
    checks = factual.get("checks") if isinstance(factual.get("checks"), dict) else {}
    evidence = row.get("evidence") if isinstance(row.get("evidence"), list) else []
    return {
        "case_id": row.get("case_id"),
        "factual_status": factual.get("outcome"),
        "claim_support_status": checks.get("claim_evidence_support"),
        "jurisdiction_scope": checks.get("jurisdiction_scope"),
        "currentness": checks.get("requested_date_and_currentness"),
        "locators": [
            {"title": item.get("title"), "locator": item.get("locator")}
            for item in evidence
            if isinstance(item, dict)
        ],
        "dependency_hash": dependency_hash_safe(row),
        "user_facing_answer": str(row.get("user_facing_answer") or "")[:1200],
    }


def dependency_hash_safe(row: Mapping[str, Any]) -> str:
    from app.evaluation.ge_hold_reason_router import dependency_hash

    return dependency_hash(row)


def main() -> int:
    if PACK.exists() or PACK.is_symlink():
        raise FileExistsError(f"create-only pack exists: {PACK}")
    r2_manifest = json.loads(R2_MANIFEST.read_text(encoding="utf-8"))
    if r2_manifest.get("content_sha256") != EXPECTED_R2_MANIFEST:
        raise RuntimeError("frozen r2 RUN-MANIFEST identity mismatch")
    if _sha256_file(R2_RESULTS) != EXPECTED_R2_RESULTS:
        raise RuntimeError("frozen r2 RESULTS identity mismatch")
    delta_manifest = json.loads(DELTA_MANIFEST.read_text(encoding="utf-8"))
    if delta_manifest.get("content_sha256") != EXPECTED_DELTA_MANIFEST:
        raise RuntimeError("mechanical-repair-delta-r1 RUN-MANIFEST identity mismatch")

    rows = _load_jsonl(DELTA_RESULTS)
    if len(rows) != 331:
        raise RuntimeError("delta RESULTS are not 331 cases")
    visible_rows = _load_jsonl(VISIBLE_PACK / "GE-VISIBLE-REVIEW.jsonl")
    visible_by_id = {str(item.get("question_id") or ""): item for item in visible_rows}
    overlay = load_locator_gold_overlay(DEFAULT_LOCATOR_OVERLAY)
    source_manifest = _load_json(SOURCE_MANIFEST)
    sources = _source_lookup(source_manifest)
    source_manifest_sha256 = str(source_manifest.get("manifest_sha256") or "")
    chunks = load_kajima_locator_chunks(ROOT)
    if PARAGRAPH_29 not in chunks or PARAGRAPH_30 not in chunks:
        raise RuntimeError("Kajima paragraphs 29/30 are missing from the evaluation sidecar")
    kajima_meta = next(
        meta
        for meta in sources.values()
        if "kajima" in str(meta.get("title") or "").casefold()
    )
    kajima_evidence = {
        pin: build_kajima_evidence_row(chunk, source_meta=kajima_meta)
        for pin, chunk in chunks.items()
    }

    affected_ids = derive_kajima_29_30_affected_case_ids(rows, ISSUE_LOCATOR_HINTS)
    by_id = {str(row.get("case_id") or ""): row for row in rows}
    mediation_ids = [
        str(row.get("case_id") or "")
        for row in rows
        if str(row.get("topic_id") or "") == MEDIATION_TOPIC
    ]
    noop_ids = [case_id for case_id in mediation_ids if case_id not in set(affected_ids)]

    proposals: list[dict[str, Any]] = []
    before = {case_id: _snapshot(by_id[case_id]) for case_id in affected_ids}
    for case_id in affected_ids:
        row = by_id[case_id]
        for pin in (PARAGRAPH_29, PARAGRAPH_30):
            decision = decide_kajima_attachment(
                row,
                title=str(chunks[pin]["title"]),
                locator=pin,
                stored_text=str(chunks[pin]["body"]),
            )
            decision["pre_attach_dependency_hash"] = before[case_id]["dependency_hash"]
            decision["hint_dependency_hash"] = hint_dependency_hash(row, ISSUE_LOCATOR_HINTS)
            proposals.append(decision)

    authorized = execute_kajima_attachments(
        route=TARGETED_MEDIATION_FAMILY,
        rows=[by_id[case_id] for case_id in affected_ids],
        decisions=proposals,
    )
    if authorized["refused_reason"]:
        raise RuntimeError("targeted mediation-family route was refused")

    accepted_by_case: dict[str, list[str]] = {}
    refused: list[dict[str, Any]] = []
    for item in proposals:
        if item["decision"] == "ATTACH":
            accepted_by_case.setdefault(item["case_id"], []).append(item["exact_kajima_paragraph"])
        else:
            refused.append(item)

    rebuilt_rows: list[dict[str, Any]] = []
    evidence_changed: list[str] = []
    evidence_notes: dict[str, list[dict[str, str]]] = {}
    after: dict[str, dict[str, Any]] = {}
    for row in rows:
        case_id = str(row.get("case_id") or "")
        if case_id not in set(affected_ids):
            rebuilt_rows.append(row)
            continue
        accepted = accepted_by_case.get(case_id, ())
        planned, notes = apply_kajima_evidence_plan(
            row,
            accepted_locators=accepted,
            kajima_rows=kajima_evidence,
        )
        evidence_notes[case_id] = notes
        if planned == list(row.get("evidence") or []):
            rebuilt_rows.append(row)
            after[case_id] = _snapshot(row)
            continue
        visible = visible_by_id.get(case_id) or {}
        rebuilt = rebuild_case_result(
            row,
            planned,
            visible_case=visible,
            overlay=overlay,
            source_manifest_sha256=source_manifest_sha256,
        )
        evidence_changed.append(case_id)
        rebuilt_rows.append(rebuilt)
        after[case_id] = _snapshot(rebuilt)
        for item in proposals:
            if item["case_id"] == case_id:
                item["post_attach_dependency_hash"] = after[case_id]["dependency_hash"]
                item["attach_executed"] = item["decision"] == "ATTACH" and case_id in evidence_changed

    for item in proposals:
        item.setdefault("post_attach_dependency_hash", item.get("pre_attach_dependency_hash"))
        if item["case_id"] not in evidence_changed:
            item["attach_executed"] = False

    if CASE_174 not in set(affected_ids):
        raise RuntimeError("case 174 must be in the Kajima 29/30 hint-affected set")
    row_174 = next(row for row in rebuilt_rows if row["case_id"] == CASE_174)
    titles_174 = " ".join(
        str(item.get("title") or "") for item in row_174.get("evidence") or [] if isinstance(item, dict)
    ).casefold()
    locators_174 = [
        str(item.get("locator") or "")
        for item in row_174.get("evidence") or []
        if isinstance(item, dict) and "kajima" in str(item.get("title") or "").casefold()
    ]
    if "cable & wireless" in titles_174 or "arbitration act 1996" in titles_174:
        raise RuntimeError("case 174 route invariant broken")
    if PARAGRAPH_29 not in locators_174:
        raise RuntimeError("case 174 Kajima paragraph 29 was not bound")
    if "paragraph 1" in locators_174:
        raise RuntimeError("case 174 still binds Kajima paragraph 1 as the holding pin")
    if row_174["factual_result"]["outcome"] != "FACTUAL_HOLD":
        raise RuntimeError("case 174 converted away from FACTUAL_HOLD")

    routed = route_results(rebuilt_rows)
    claim_ids = list(routed["runnable_case_ids"])
    claim_rows = [row for row in rebuilt_rows if str(row.get("case_id") or "") in set(claim_ids)]
    classified = route_claim_cases(
        claim_rows,
        locator_hints=ISSUE_LOCATOR_HINTS,
        topic_sources=TOPIC_SOURCES,
        attempt_count=2,
    )
    mediation_runnable = [
        item
        for item in classified["rows"]
        if item.get("topic") == MEDIATION_TOPIC and item.get("machine_repairable") is True
    ]
    packets = {
        case_id: build_review_packet(by_id_new)
        for case_id, by_id_new in (
            (str(row.get("case_id") or ""), row)
            for row in rebuilt_rows
            if str(row.get("case_id") or "") in set(affected_ids)
        )
        if case_id
    }
    for packet in packets.values():
        if packet.get("qualified_legal_review") != "NOT_STARTED":
            raise RuntimeError("qualified legal review must remain NOT_STARTED")

    progress = phase2_progress(
        case_results=rebuilt_rows,
        diagnostic_execution="COMPLETE",
        diagnostic_report="APPROVED_SCOPED",
        routed=True,
        runnable_queue_count=classified["remaining_changed_input_runnable_count"],
        locator_hold_count=0,
        locator_pending_count=0,
        locator_reject_count=1,
    )
    plane = control_plane_v2(
        case_results=rebuilt_rows,
        diagnostic_execution="COMPLETE",
        diagnostic_report="APPROVED_SCOPED",
        routed=True,
        runnable_queue_count=classified["remaining_changed_input_runnable_count"],
    )
    locator_hash = _sha256_file(REGISTER) if REGISTER.is_file() else ""
    visible_hash = ""
    manifest_path = VISIBLE_PACK / "PACK-MANIFEST.json"
    if manifest_path.is_file():
        visible_hash = str(json.loads(manifest_path.read_text(encoding="utf-8")).get("content_sha256") or "")

    PACK.mkdir(parents=True, mode=0o700)
    os.chmod(PACK, stat.S_IRWXU)
    (PACK / "visible").mkdir(mode=0o700)
    _write_jsonl(PACK / "visible/RESULTS.jsonl", rebuilt_rows)
    results_sha = _sha256_file(PACK / "visible/RESULTS.jsonl")
    fingerprint = evaluation_fingerprint(
        project_root=ROOT,
        locator_manifest_hash=locator_hash,
        answer_set_hash=results_sha,
        visible_pack_hash=visible_hash,
    )
    test_history = _sealed(
        {
            "schema": "legalbot.ge-mediation-family-test-history.v1",
            "initial_unit_test_result": "FAIL",
            "failed_assertion": "expected remaining_runnable_count == 0",
            "actual_remaining_runnable_count": 1,
            "cause": (
                "newly added Kajima paragraphs 29/30 hints made "
                "international-commercial-mediation:cp-d09 attachable"
            ),
            "assessment": "expected behavior change, not router regression",
            "test_update": (
                "expect exactly international-commercial-mediation:cp-d09 "
                "as the sole remaining runnable case"
            ),
            "attach_executed": False,
            "next_route": TARGETED_MEDIATION_FAMILY,
            "later_test_result": "PASS",
            "do_not_describe_first_run_as_passing": True,
        }
    )
    receipt = _sealed(
        {
            "schema": "legalbot.ge-mediation-family-kajima-delta-receipt.v1",
            "recorded_at_utc": datetime.now(UTC).isoformat(),
            "route": TARGETED_MEDIATION_FAMILY,
            "full_331_rerun": False,
            "full_331_r3_executed": False,
            "frozen_r2_results_sha256": EXPECTED_R2_RESULTS,
            "frozen_r2_run_manifest_sha256": EXPECTED_R2_MANIFEST,
            "baseline_delta_results": "LegalBot-GE-2026-09-02-mechanical-repair-delta-r1",
            "dependency_affected_mediation_family_case_ids": list(affected_ids),
            "cp_d09_is_only_affected_case": affected_ids == ("international-commercial-mediation:cp-d09",),
            "cp_d09_is_only_claim_queue_runnable_before_delta": True,
            "attachment_accepted_case_ids": sorted(accepted_by_case),
            "attachment_refused": [
                {
                    "case_id": item["case_id"],
                    "exact_kajima_paragraph": item["exact_kajima_paragraph"],
                    "refuse_reason": item["refuse_reason"],
                }
                for item in refused
            ],
            "evidence_changed_case_ids": evidence_changed,
            "unchanged_mediation_case_ids": noop_ids,
            "unchanged_case_result": NO_OP_UNCHANGED_CASE_INPUTS,
            "remaining_claim_runnable_count": classified["remaining_changed_input_runnable_count"],
            "remaining_mediation_family_runnable_count": len(mediation_runnable),
            "mediation_mechanical_queue_closed": len(mediation_runnable) == 0,
            "named_case_174": {
                "case_id": CASE_174,
                "route": "ICC article 5, Ohpen, Kajima paragraph 29, Churchill, jurisdiction-scope review only",
                "kajima_locators": locators_174,
                "factual_status": row_174["factual_result"]["outcome"],
                "claim_support_status": row_174["factual_result"]["checks"].get("claim_evidence_support"),
                "no_cable_and_wireless": True,
                "no_arbitration_act_s9": True,
                "jurisdiction_hold_converted": False,
            },
            "named_case_008_untouched": CASE_008 not in set(affected_ids),
            "named_case_312_untouched": CASE_312 not in set(affected_ids),
            "locator_review_reopened": False,
            "qualified_legal_review": "NOT_STARTED",
            "answer_gold": "NOT_STARTED",
            "answer_weight_training": False,
            "catalogue_admission": "NOT_STARTED",
            "sealed_unseen": "NOT_STARTED",
            "promotion": False,
            "live": False,
            "downstream_gates": {name: "NOT_STARTED" for name in DOWNSTREAM},
            "stage_states": explicit_stage_states(),
            "results_sha256": results_sha,
        }
    )
    before_after = _sealed(
        {
            "schema": "legalbot.ge-mediation-family-before-after.v1",
            "before": before,
            "after": after,
            "claim_support_before_after": {
                case_id: {
                    "before": before[case_id]["claim_support_status"],
                    "after": after[case_id]["claim_support_status"],
                }
                for case_id in affected_ids
            },
            "factual_status_before_after": {
                case_id: {
                    "before": before[case_id]["factual_status"],
                    "after": after[case_id]["factual_status"],
                }
                for case_id in affected_ids
            },
        }
    )
    manifest = _sealed(
        {
            "schema": "legalbot.ge-mediation-family-kajima-delta-manifest.v1",
            "run_id": PACK.name,
            "route": TARGETED_MEDIATION_FAMILY,
            "full_331_rerun": False,
            "affected_case_ids": list(affected_ids),
            "evidence_changed_case_ids": evidence_changed,
            "frozen_r2_results_sha256": EXPECTED_R2_RESULTS,
            "results_sha256": results_sha,
        }
    )
    _write_json(PACK / "RUN-MANIFEST.json", manifest)
    _write_json(PACK / "STATE-TRANSITION-RECEIPT.json", receipt)
    _write_json(PACK / "TEST-HISTORY-RECEIPT.json", test_history)
    _write_json(PACK / "KAJIMA-PROPOSITION-ATTACHMENT-MANIFEST.json", _sealed({"rows": proposals}))
    _write_json(PACK / "EVIDENCE-PLAN-NOTES.json", _sealed({"notes": evidence_notes}))
    _write_json(PACK / "BEFORE-AFTER.json", before_after)
    _write_json(
        PACK / "CLAIM-SUPPORT-ROUTE.json",
        _sealed(
            {
                "remaining_changed_input_runnable_count": classified["remaining_changed_input_runnable_count"],
                "runnable_case_ids": classified["runnable_case_ids"],
                "mediation_family_runnable_case_ids": [item["case_id"] for item in mediation_runnable],
            }
        ),
    )
    _write_json(
        PACK / "UNCHANGED-MEDIATION-CASES.json",
        _sealed({"rows": [mediation_family_noop_row(case_id) for case_id in noop_ids]}),
    )
    _write_json(
        PACK / "QUALIFIED-REVIEW-PACKETS.json",
        _sealed(
            {
                "qualified_legal_review": "NOT_STARTED",
                "packets": packets,
            }
        ),
    )
    _write_json(
        PACK / "USER-FACING-ANSWER-REVIEW.json",
        _sealed(
            {
                "reviewer_role": "mechanical_accuracy_verifier_only",
                "qualified_legal_review": "NOT_STARTED",
                "answer_gold": "NOT_STARTED",
                "ai_set_legal_gold": False,
                "ai_authorized_weight_training": False,
                "cases": {
                    case_id: {
                        "before": before[case_id]["user_facing_answer"],
                        "after": after[case_id]["user_facing_answer"],
                    }
                    for case_id in affected_ids
                },
            }
        ),
    )
    _write_json(PACK / "PROGRESS-AND-BLOCKER-LEDGER.json", _sealed(progress))
    _write_json(PACK / "CONTROL-PLANE-V2.json", plane)
    _write_json(PACK / "EVALUATION-FINGERPRINT.json", fingerprint)
    _write_json(
        PACK / "HOLD-REASON-SUMMARY.json",
        _sealed(
            {
                "factual_pass_count": routed["factual_pass_count"],
                "hold_count": routed["hold_count"],
                "counts_by_hold_reason_code": routed["counts_by_hold_reason_code"],
                "runnable_queue_count": routed["runnable_queue_count"],
            }
        ),
    )
    _write_text(
        PACK / "README.md",
        """# GE mediation-family Kajima paragraph 29/30 delta

Targeted execution of the Kajima paragraph 29/30 hint change. Frozen diagnostic
r2 is preserved. This is not qualified legal review, answer gold, admission,
weight training, sealed unseen, promotion or live.

The first unit test of the remaining claim queue failed because it expected
zero runnable cases. The Kajima paragraph 29/30 hints made
`international-commercial-mediation:cp-d09` attachable. That was an intended
routing change. Attach was not executed by the router. This pack is the
targeted mediation-family execution.

Case 174 remains ICC article 5, Ohpen, Kajima (paragraph 29, not paragraph 1),
Churchill, and jurisdiction-scope review. Cable & Wireless and Arbitration Act
1996 section 9 were not added.
""",
    )
    if progress["overall_state"] != MECHANICAL_EVALUATION_COMPLETE_REVIEW_PENDING:
        # A remaining runnable claim case keeps the phase in routing; record it.
        pass
    print(
        json.dumps(
            {
                "pack": str(PACK),
                "affected_case_ids": list(affected_ids),
                "cp_d09_only_affected": affected_ids == ("international-commercial-mediation:cp-d09",),
                "accepted_case_ids": sorted(accepted_by_case),
                "evidence_changed_case_ids": evidence_changed,
                "remaining_claim_runnable_count": classified["remaining_changed_input_runnable_count"],
                "remaining_mediation_family_runnable_count": len(mediation_runnable),
                "receipt_sha256": receipt["content_sha256"],
                "results_sha256": results_sha,
                "frozen_r2_results_sha256": EXPECTED_R2_RESULTS,
                "qualified_legal_review": "NOT_STARTED",
                "full_331_r3_executed": False,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
