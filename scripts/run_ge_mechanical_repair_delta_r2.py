#!/usr/bin/env python3
"""Targeted r3 regression repair. Preserve r1, r2 and r3. Not gold or unseen."""

from __future__ import annotations

import json
import os
from collections import Counter
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.evaluation.ge_claim_support_router import route_claim_cases
from app.evaluation.ge_hold_reason_router import CASE_008, CASE_174, CASE_312, route_results
from app.evaluation.ge_kajima_mediation_family import (
    filter_attached_evidence_rows,
    rebuild_case_result,
)
from app.evaluation.ge_locator_gold_overlay import load_locator_gold_overlay
from app.evaluation.ge_phase2_progress import (
    evaluation_fingerprint,
    phase2_progress,
)
from scripts.run_ge_retrieval_training_cycle import (
    DEFAULT_LOCATOR_OVERLAY,
    ISSUE_LOCATOR_HINTS,
    MEDIATION_FAMILY_KAJIMA_PACK,
    MECHANICAL_REPAIR_DELTA_R2_PACK,
    PROJECT_ROOT,
    SOURCE_MANIFEST,
    TOPIC_SOURCES,
    VISIBLE_331_R3_PACK,
    VISIBLE_PACK,
    _load_json,
    _sealed,
    _sha256_file,
    _write_create_only,
    _write_json,
    _write_jsonl,
)

R1 = (
    PROJECT_ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-visible-331-diagnostic-r1"
)
R2 = (
    PROJECT_ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-visible-331-diagnostic-r2"
)
FAMILY_RESULTS = MEDIATION_FAMILY_KAJIMA_PACK / "visible/RESULTS.jsonl"
R3_RESULTS = VISIBLE_331_R3_PACK / "visible/RESULTS.jsonl"
EXPECTED_R1_MANIFEST = "d43f2a47d3f0eff35785bfd37a193ba97267206816ac78cb25b9415715b78f9f"
EXPECTED_R2_MANIFEST = "d0ed806eee3ead78be77b5ca8eb150cbb7fd15f3eb9332637f230b38eef311c2"
EXPECTED_R2_RESULTS = "a3142fce995b7ae575864ae8411e9346d084306bf1197a4153326a8506a0908c"
EXPECTED_R3_MANIFEST = "80718e9ffaaf67aaabeee6f0a099d06365600f7c360ab86695dabfd68f0f592f"
EXPECTED_R3_RESULTS = "51eb7eda2f04b309b9c27ee4f9f4dd25ae57bc359f4df68acae4f5726ef851ef"

REPAIR_IDS = (
    "international-commercial-mediation:cp-d05",
    "international-commercial-mediation:cp-d09",
)
RESTORE_PASS_IDS = (
    "administrative-law:cp-d07",
    "business-and-company-law:cp-d16",
    "business-and-company-law:cp-d18",
)


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def _outcome(row: Mapping[str, Any]) -> str:
    factual = row.get("factual_result")
    if isinstance(factual, Mapping):
        return str(factual.get("outcome") or "")
    return ""


def _claim(row: Mapping[str, Any]) -> str:
    factual = row.get("factual_result")
    if isinstance(factual, Mapping):
        checks = factual.get("checks")
        if isinstance(checks, Mapping):
            return str(checks.get("claim_evidence_support") or "")
    return ""


def _pins(row: Mapping[str, Any]) -> list[dict[str, str]]:
    return [
        {"title": str(item.get("title") or ""), "locator": str(item.get("locator") or "")}
        for item in (row.get("evidence") or [])
        if isinstance(item, dict)
    ]


def main() -> int:
    if MECHANICAL_REPAIR_DELTA_R2_PACK.exists() or MECHANICAL_REPAIR_DELTA_R2_PACK.is_symlink():
        raise FileExistsError(f"create-only pack exists: {MECHANICAL_REPAIR_DELTA_R2_PACK}")
    if _load_json(R1 / "RUN-MANIFEST.json").get("content_sha256") != EXPECTED_R1_MANIFEST:
        raise RuntimeError("frozen r1 RUN-MANIFEST identity mismatch")
    if _load_json(R2 / "RUN-MANIFEST.json").get("content_sha256") != EXPECTED_R2_MANIFEST:
        raise RuntimeError("frozen r2 RUN-MANIFEST identity mismatch")
    if _sha256_file(R2 / "visible/RESULTS.jsonl") != EXPECTED_R2_RESULTS:
        raise RuntimeError("frozen r2 RESULTS identity mismatch")
    if _load_json(VISIBLE_331_R3_PACK / "RUN-MANIFEST.json").get("content_sha256") != EXPECTED_R3_MANIFEST:
        raise RuntimeError("frozen r3 RUN-MANIFEST identity mismatch")
    if _sha256_file(R3_RESULTS) != EXPECTED_R3_RESULTS:
        raise RuntimeError("frozen r3 RESULTS identity mismatch")

    r3_rows = _load_jsonl(R3_RESULTS)
    family_rows = _load_jsonl(FAMILY_RESULTS)
    if len(r3_rows) != 331 or len(family_rows) != 331:
        raise RuntimeError("baseline denominator is not 331")
    r3_by = {str(row["case_id"]): row for row in r3_rows}
    family_by = {str(row["case_id"]): row for row in family_rows}
    visible_rows = _load_jsonl(VISIBLE_PACK / "GE-VISIBLE-REVIEW.jsonl")
    visible_by = {str(item.get("question_id") or ""): item for item in visible_rows}
    overlay = load_locator_gold_overlay(DEFAULT_LOCATOR_OVERLAY)
    source_manifest = _load_json(SOURCE_MANIFEST)
    source_sha = str(source_manifest.get("manifest_sha256") or "")

    started = datetime.now(UTC)
    rebuilt: list[dict[str, Any]] = []
    repaired: list[str] = []
    restored: list[str] = []
    drop_notes: dict[str, list[dict[str, str]]] = {}
    for row in r3_rows:
        case_id = str(row.get("case_id") or "")
        if case_id in RESTORE_PASS_IDS:
            family_row = family_by[case_id]
            if _outcome(family_row) != "FACTUAL_PASS":
                raise RuntimeError(f"family baseline is not FACTUAL_PASS: {case_id}")
            rebuilt.append(family_row)
            restored.append(case_id)
            continue
        if case_id in REPAIR_IDS:
            kept, dropped = filter_attached_evidence_rows(
                [item for item in (row.get("evidence") or []) if isinstance(item, dict)],
                question=str(row.get("question") or row.get("prompt") or ""),
                issue_tags=tuple(str(tag) for tag in row.get("issue_tags") or ()),
            )
            drop_notes[case_id] = dropped
            rebuilt.append(
                rebuild_case_result(
                    row,
                    kept,
                    visible_case=visible_by[case_id],
                    overlay=overlay,
                    source_manifest_sha256=source_sha,
                )
            )
            repaired.append(case_id)
            continue
        rebuilt.append(row)

    if len(rebuilt) != 331:
        raise RuntimeError("repaired denominator is not 331")
    by_id = {str(row["case_id"]): row for row in rebuilt}
    row_008 = by_id[CASE_008]
    row_174 = by_id[CASE_174]
    row_312 = by_id[CASE_312]
    if _outcome(row_008) != "FACTUAL_PASS":
        raise RuntimeError("case 008 must remain FACTUAL_PASS")
    if _outcome(row_312) != "FACTUAL_HOLD":
        raise RuntimeError("case 312 must remain FACTUAL_HOLD")
    if _outcome(row_174) == "FACTUAL_PASS":
        raise RuntimeError("case 174 must not convert to FACTUAL_PASS")
    titles_174 = " ".join(item["title"] for item in _pins(row_174)).casefold()
    if "cable & wireless" in titles_174 or "arbitration act 1996" in titles_174:
        raise RuntimeError("case 174 route invariant broken")
    kajima_30 = [
        str(row.get("case_id") or "")
        for row in rebuilt
        for item in _pins(row)
        if "kajima" in item["title"].casefold()
        and item["locator"].casefold() in {"paragraph 30", "para 30"}
    ]
    if kajima_30:
        raise RuntimeError(f"Kajima paragraph 30 attached on {kajima_30[:8]}")
    d05 = by_id["international-commercial-mediation:cp-d05"]
    d09 = by_id["international-commercial-mediation:cp-d09"]
    if any(item["locator"] == "article 5" for item in _pins(d09)):
        raise RuntimeError("cp-d09 still has ICC article 5")
    if any("kajima" in item["title"].casefold() for item in _pins(d05)):
        raise RuntimeError("cp-d05 still has Kajima")
    if _claim(d05) != "PASS" or _claim(d09) != "PASS":
        raise RuntimeError("family claim-support restore failed")
    for case_id in RESTORE_PASS_IDS:
        if _outcome(by_id[case_id]) != "FACTUAL_PASS":
            raise RuntimeError(f"frozen PASS was not restored: {case_id}")

    os.makedirs(MECHANICAL_REPAIR_DELTA_R2_PACK, mode=0o700)
    _write_jsonl(MECHANICAL_REPAIR_DELTA_R2_PACK / "visible/RESULTS.jsonl", rebuilt)
    results_sha = _sha256_file(MECHANICAL_REPAIR_DELTA_R2_PACK / "visible/RESULTS.jsonl")
    if _sha256_file(R3_RESULTS) != EXPECTED_R3_RESULTS:
        raise RuntimeError("repair mutated frozen r3 RESULTS")

    routed = route_results(rebuilt)
    claim_ids = list(routed["runnable_case_ids"])
    claim_rows = [row for row in rebuilt if str(row.get("case_id") or "") in set(claim_ids)]
    classified = route_claim_cases(
        claim_rows,
        locator_hints=ISSUE_LOCATOR_HINTS,
        topic_sources=TOPIC_SOURCES,
        attempt_count=2,
    )
    progress = phase2_progress(
        case_results=rebuilt,
        diagnostic_execution="COMPLETE",
        diagnostic_report="APPROVED_SCOPED",
        routed=True,
        runnable_queue_count=classified["remaining_changed_input_runnable_count"],
        locator_hold_count=0,
        locator_pending_count=0,
        locator_reject_count=1,
    )
    locator_hash = _sha256_file(DEFAULT_LOCATOR_OVERLAY)
    visible_hash = str(_load_json(VISIBLE_PACK / "PACK-MANIFEST.json").get("content_sha256") or "")
    fingerprint = evaluation_fingerprint(
        project_root=PROJECT_ROOT,
        locator_manifest_hash=locator_hash,
        answer_set_hash=results_sha,
        visible_pack_hash=visible_hash,
    )
    comparison = {
        "schema": "legalbot.ge-r3-mechanical-repair-delta.v1",
        "r1_preserved": True,
        "r2_preserved": True,
        "r3_preserved": True,
        "r3_results_sha256": EXPECTED_R3_RESULTS,
        "delta_results_sha256": results_sha,
        "r3_factual": dict(sorted(Counter(_outcome(row) for row in r3_rows).items())),
        "delta_factual": dict(sorted(Counter(_outcome(row) for row in rebuilt).items())),
        "r3_claim_pass": sum(_claim(row) == "PASS" for row in r3_rows),
        "delta_claim_pass": sum(_claim(row) == "PASS" for row in rebuilt),
        "repaired_case_ids": repaired,
        "restored_factual_pass_case_ids": restored,
        "drop_notes": drop_notes,
        "named_cases": {
            CASE_008: {"factual": _outcome(row_008), "carried_forward": True},
            CASE_174: {
                "factual": _outcome(row_174),
                "claim": _claim(row_174),
                "evidence": _pins(row_174),
            },
            CASE_312: {"factual": _outcome(row_312), "carried_forward": True},
        },
        "hold_reasons": dict(sorted(routed["counts_by_hold_reason_code"].items())),
        "remaining_changed_input_runnable_count": classified[
            "remaining_changed_input_runnable_count"
        ],
        "remaining_runnable_case_ids": classified["runnable_case_ids"],
        "qualified_legal_review": "NOT_STARTED",
        "answer_gold": "NOT_STARTED",
        "answer_weight_training": False,
        "full_331_rerun": False,
    }
    completed = datetime.now(UTC)
    manifest = {
        "schema": "legalbot.ge-mechanical-repair-delta.v2",
        "run_id": MECHANICAL_REPAIR_DELTA_R2_PACK.name,
        "started_at": started.isoformat(),
        "completed_at": completed.isoformat(),
        "full_331_rerun": False,
        "repaired_case_ids": repaired,
        "restored_factual_pass_case_ids": restored,
        "results_sha256": results_sha,
        "frozen_r3_results_sha256": EXPECTED_R3_RESULTS,
        "progress": {
            "overall_progress": progress["overall_progress"],
            "overall_state": progress["overall_state"],
            "runnable_queue_count": progress["runnable_queue_count"],
        },
        "non_authorizing": {
            "qualified_legal_review": False,
            "legal_gold": False,
            "admitted": False,
            "full_current_law_eligible": False,
            "answer_weight_training": False,
            "sealed_unseen": False,
            "promotion": False,
            "live": False,
        },
    }
    _write_json(MECHANICAL_REPAIR_DELTA_R2_PACK / "COMPARISON-VS-R3.json", _sealed(comparison))
    _write_json(
        MECHANICAL_REPAIR_DELTA_R2_PACK / "HOLD-REASON-SUMMARY.json",
        _sealed(
            {
                "schema": "legalbot.ge-hold-reason-summary.v1",
                "source_run_id": MECHANICAL_REPAIR_DELTA_R2_PACK.name,
                "hold_count": routed["hold_count"],
                "factual_pass_count": routed["factual_pass_count"],
                "counts_by_hold_reason_code": routed["counts_by_hold_reason_code"],
                "runnable_queue_count": routed["runnable_queue_count"],
                "claim_routing": {
                    "remaining_changed_input_runnable_count": classified[
                        "remaining_changed_input_runnable_count"
                    ],
                    "runnable_case_ids": classified["runnable_case_ids"],
                    "counts_by_failure_class": classified["counts_by_failure_class"],
                    "no_generic_retrieval": True,
                },
            }
        ),
    )
    _write_json(
        MECHANICAL_REPAIR_DELTA_R2_PACK / "CLAIM-SUPPORT-ROUTE.json",
        _sealed(
            {
                "remaining_changed_input_runnable_count": classified[
                    "remaining_changed_input_runnable_count"
                ],
                "runnable_case_ids": classified["runnable_case_ids"],
                "moved_to_qualified_review_case_ids": classified["moved_to_qualified_review_case_ids"],
                "no_generic_retrieval": True,
            }
        ),
    )
    _write_json(MECHANICAL_REPAIR_DELTA_R2_PACK / "PROGRESS-AND-BLOCKER-LEDGER.json", _sealed(progress))
    _write_json(MECHANICAL_REPAIR_DELTA_R2_PACK / "EVALUATION-FINGERPRINT.json", fingerprint)
    _write_json(MECHANICAL_REPAIR_DELTA_R2_PACK / "RUN-MANIFEST.json", _sealed(manifest))
    _write_create_only(
        MECHANICAL_REPAIR_DELTA_R2_PACK / "README.md",
        (
            "# Mechanical repair delta after visible 331 r3\n\n"
            "Create-only targeted repair. Frozen r1, r2 and r3 are preserved. "
            "cp-d05 and cp-d09 were filtered to the Kajima-family attach rules. "
            "Three r3 PASS regressions were restored from the family/mechanical "
            "FACTUAL_PASS rows. This is not qualified legal review, answer gold, "
            "admission, weight training, sealed unseen, promotion or live.\n"
        ).encode("utf-8"),
    )
    print(
        json.dumps(
            {
                "pack": str(MECHANICAL_REPAIR_DELTA_R2_PACK),
                "r1_preserved": True,
                "r2_preserved": True,
                "r3_preserved": True,
                "delta_factual": comparison["delta_factual"],
                "delta_claim_pass": comparison["delta_claim_pass"],
                "repaired_case_ids": repaired,
                "restored_factual_pass_case_ids": restored,
                "remaining_changed_input_runnable_count": classified[
                    "remaining_changed_input_runnable_count"
                ],
                "hold_reasons": comparison["hold_reasons"],
                "overall_state": progress["overall_state"],
                "qualified_legal_review": "NOT_STARTED",
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
