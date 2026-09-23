#!/usr/bin/env python3
"""Run visible diagnostic 331 r3. Preserve r1 and r2. Not gold or unseen."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from app.evaluation.ge_hold_reason_router import (
    CASE_008,
    CASE_174,
    CASE_312,
    route_results,
)
from scripts.run_ge_retrieval_training_cycle import (
    DEFAULT_LOCATOR_OVERLAY,
    MEDIATION_FAMILY_KAJIMA_PACK,
    PROJECT_ROOT,
    VISIBLE_331_R3_PACK,
    _sha256_file,
    run,
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
EXPECTED_R1_MANIFEST = "d43f2a47d3f0eff35785bfd37a193ba97267206816ac78cb25b9415715b78f9f"
EXPECTED_R2_MANIFEST = "d0ed806eee3ead78be77b5ca8eb150cbb7fd15f3eb9332637f230b38eef311c2"
EXPECTED_R2_RESULTS = "a3142fce995b7ae575864ae8411e9346d084306bf1197a4153326a8506a0908c"
FAMILY_RESULTS = MEDIATION_FAMILY_KAJIMA_PACK / "visible/RESULTS.jsonl"


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"expected JSON object: {path}")
    return value


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def _outcome(row: dict[str, Any]) -> str:
    factual = row.get("factual_result")
    if isinstance(factual, dict):
        return str(factual.get("outcome") or "")
    return ""


def _claim(row: dict[str, Any]) -> str:
    factual = row.get("factual_result")
    if isinstance(factual, dict):
        checks = factual.get("checks")
        if isinstance(checks, dict):
            return str(checks.get("claim_evidence_support") or "")
    return ""


def main() -> int:
    if VISIBLE_331_R3_PACK.exists() or VISIBLE_331_R3_PACK.is_symlink():
        raise FileExistsError(f"create-only pack exists: {VISIBLE_331_R3_PACK}")
    r1_manifest = _load_json(R1 / "RUN-MANIFEST.json")
    if r1_manifest.get("content_sha256") != EXPECTED_R1_MANIFEST:
        raise RuntimeError("frozen r1 RUN-MANIFEST identity mismatch")
    r2_manifest = _load_json(R2 / "RUN-MANIFEST.json")
    if r2_manifest.get("content_sha256") != EXPECTED_R2_MANIFEST:
        raise RuntimeError("frozen r2 RUN-MANIFEST identity mismatch")
    if _sha256_file(R2 / "visible/RESULTS.jsonl") != EXPECTED_R2_RESULTS:
        raise RuntimeError("frozen r2 RESULTS identity mismatch")
    if not FAMILY_RESULTS.is_file():
        raise RuntimeError("mediation-family baseline RESULTS missing")

    owner_instruction = {
        "schema": "legalbot.owner-session-instruction-record.v1",
        "instruction_summary": (
            "Owner authorized visible diagnostic 331 r3, keeping r1 and r2 "
            "immutable. This remains Phase 2 evaluation. Qualified legal review, "
            "answer gold, admission, weight training, sealed unseen, promotion "
            "and live stay NOT_STARTED. The 306 private bank stays sealed. "
            "Cases 008 and 312 are carried forward. Retrieval drops incomplete "
            "or out-of-scope hinted locators, including Kajima paragraph 30."
        ),
        "evaluation_state": True,
        "authorized": [
            "visible_331_diagnostic_r3",
            "keep_visible_331_diagnostic_r1",
            "keep_visible_331_diagnostic_r2",
            "factual_first_evaluation_gate",
        ],
        "not_authorized_or_not_supplied": [
            "answer_weight_training",
            "qualified_england_and_wales_legal_reviewer_identity",
            "legal_gold",
            "runtime_admission_of_staging_sources",
            "full_current_law_eligible",
            "sealed_validation_private_root",
            "fresh_unseen_or_private_306_disclosure",
            "promotion",
            "live_activation",
            "git_mutation",
            "deletion",
            "locator_package_reopen",
            "tick_sheet",
        ],
        "signature_status": "session_instruction_not_cryptographic_signature",
    }
    manifest = run(
        VISIBLE_331_R3_PACK,
        diagnostic_probe="omit",
        allow_full_visible_331=True,
        locator_overlay_path=DEFAULT_LOCATOR_OVERLAY,
        baseline_results_path=FAMILY_RESULTS,
        carry_forward_case_ids=(CASE_008, CASE_312),
        owner_instruction=owner_instruction,
    )
    if manifest.get("result") in {"NO_OP_UNCHANGED_INPUTS", "NO_OP_UNCHANGED_CASE_INPUTS"}:
        raise RuntimeError(f"visible 331 r3 was not executed: {manifest.get('result')}")

    if _load_json(R1 / "RUN-MANIFEST.json").get("content_sha256") != EXPECTED_R1_MANIFEST:
        raise RuntimeError("r3 mutated frozen r1 RUN-MANIFEST")
    if _load_json(R2 / "RUN-MANIFEST.json").get("content_sha256") != EXPECTED_R2_MANIFEST:
        raise RuntimeError("r3 mutated frozen r2 RUN-MANIFEST")
    if _sha256_file(R2 / "visible/RESULTS.jsonl") != EXPECTED_R2_RESULTS:
        raise RuntimeError("r3 mutated frozen r2 RESULTS")

    r2_rows = _load_jsonl(R2 / "visible/RESULTS.jsonl")
    r3_rows = _load_jsonl(VISIBLE_331_R3_PACK / "visible/RESULTS.jsonl")
    if len(r3_rows) != 331 or len(r2_rows) != 331:
        raise RuntimeError("r3 denominator is not 331")
    r3_by = {str(row["case_id"]): row for row in r3_rows}
    row_008 = r3_by[CASE_008]
    row_174 = r3_by[CASE_174]
    row_312 = r3_by[CASE_312]
    if _outcome(row_008) != "FACTUAL_PASS":
        raise RuntimeError("case 008 must remain FACTUAL_PASS")
    if _outcome(row_312) != "FACTUAL_HOLD":
        raise RuntimeError("case 312 must remain FACTUAL_HOLD")
    if _outcome(row_174) == "FACTUAL_PASS":
        raise RuntimeError("case 174 must not convert to FACTUAL_PASS")
    titles_174 = " ".join(
        str(item.get("title") or "")
        for item in (row_174.get("evidence") or [])
        if isinstance(item, dict)
    ).casefold()
    if "cable & wireless" in titles_174:
        raise RuntimeError("case 174 must not receive Cable & Wireless")
    if "arbitration act 1996" in titles_174:
        raise RuntimeError("case 174 must not receive Arbitration Act 1996")
    kajima_30 = []
    for row in r3_rows:
        for item in row.get("evidence") or []:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title") or "").casefold()
            locator = str(item.get("locator") or "").casefold()
            if "kajima" in title and locator in {"paragraph 30", "para 30"}:
                kajima_30.append(str(row.get("case_id") or ""))
    if kajima_30:
        raise RuntimeError(f"Kajima paragraph 30 attached on {kajima_30[:8]}")
    r2_by = {str(row["case_id"]): row for row in r2_rows}
    flips: list[dict[str, str]] = []
    for row in r3_rows:
        case_id = str(row["case_id"])
        before = r2_by[case_id]
        if _outcome(before) != _outcome(row) or _claim(before) != _claim(row):
            flips.append(
                {
                    "case_id": case_id,
                    "factual_before": _outcome(before),
                    "factual_after": _outcome(row),
                    "claim_before": _claim(before),
                    "claim_after": _claim(row),
                }
            )
    comparison = {
        "schema": "legalbot.ge-visible-331-diagnostic-r2-vs-r3.v1",
        "r1_preserved": True,
        "r2_preserved": True,
        "r1_run_manifest_sha256": EXPECTED_R1_MANIFEST,
        "r2_run_manifest_sha256": EXPECTED_R2_MANIFEST,
        "r2_results_sha256": EXPECTED_R2_RESULTS,
        "r3_results_sha256": _sha256_file(VISIBLE_331_R3_PACK / "visible/RESULTS.jsonl"),
        "r2_factual": dict(sorted(Counter(_outcome(row) for row in r2_rows).items())),
        "r3_factual": dict(sorted(Counter(_outcome(row) for row in r3_rows).items())),
        "r2_claim_pass": sum(_claim(row) == "PASS" for row in r2_rows),
        "r3_claim_pass": sum(_claim(row) == "PASS" for row in r3_rows),
        "status_flip_count": len(flips),
        "status_flips": flips,
        "r3_hold_reasons": dict(
            sorted(route_results(r3_rows)["counts_by_hold_reason_code"].items())
        ),
        "named_cases": {
            CASE_008: {
                "carried_forward": True,
                "factual": _outcome(row_008),
            },
            CASE_174: {
                "carried_forward": False,
                "factual": _outcome(row_174),
                "claim": _claim(row_174),
                "evidence": [
                    {
                        "title": str(item.get("title") or ""),
                        "locator": str(item.get("locator") or ""),
                    }
                    for item in (row_174.get("evidence") or [])
                    if isinstance(item, dict)
                ],
                "no_cable_and_wireless": True,
                "no_arbitration_act_1996": True,
                "no_kajima_paragraph_30": True,
            },
            CASE_312: {
                "carried_forward": True,
                "factual": _outcome(row_312),
            },
        },
        "qualified_legal_review": "NOT_STARTED",
        "answer_gold": "NOT_STARTED",
        "answer_weight_training": False,
        "sealed_unseen_opened": False,
    }
    from scripts.run_ge_retrieval_training_cycle import _sealed, _write_create_only, _write_json

    _write_json(VISIBLE_331_R3_PACK / "COMPARISON-VS-R2.json", _sealed(comparison))
    _write_create_only(
        VISIBLE_331_R3_PACK / "README.md",
        (
            "# Visible diagnostic 331 r3\n\n"
            "Create-only diagnostic rerun of all 331 visible GE cases after the Kajima\n"
            "mediation-family delta. Frozen r1 and r2 are preserved. This is not qualified\n"
            "legal review, answer gold, admission, weight training, sealed unseen,\n"
            "promotion or live. Cases 008 and 312 were carried forward. The 306 private\n"
            "bank was not opened.\n"
        ).encode("utf-8"),
    )
    print(
        json.dumps(
            {
                "pack": str(VISIBLE_331_R3_PACK),
                "r1_preserved": True,
                "r2_preserved": True,
                "r2_results_sha256": EXPECTED_R2_RESULTS,
                "r3_results_sha256": comparison["r3_results_sha256"],
                "r3_factual": comparison["r3_factual"],
                "r3_claim_pass": comparison["r3_claim_pass"],
                "status_flip_count": comparison["status_flip_count"],
                "qualified_legal_review": "NOT_STARTED",
                "answer_gold": "NOT_STARTED",
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
