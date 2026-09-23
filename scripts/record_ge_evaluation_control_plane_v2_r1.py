#!/usr/bin/env python3
"""Record Evaluation Control Plane v2 without rerunning the 331.

Create-only. Preserves frozen r2, does not set gold, admission, training,
unseen, promotion or live, and does not reopen locator review.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.contracts.schema_registry import ContractSchemaRegistry, content_sha256
from app.evaluation.ge_control_plane_v2 import LOCATOR_EVALUATION_LABEL, control_plane_v2
from app.evaluation.ge_factual_gap_fill import sidecar_packs
from app.evaluation.ge_hold_reason_router import CASE_008, CASE_174, CASE_312
from app.evaluation.ge_phase2_progress import (
    MECHANICAL_EVALUATION_COMPLETE_REVIEW_PENDING,
    evaluation_fingerprint,
    explicit_stage_states,
)
from app.evaluation.ge_principal_blocker import classify_principal_blocker
from app.evaluation.ge_proposition_receipts import build_proposition_receipt
from app.evaluation.ge_run_lineage import bind_track, build_effective_source_set, build_run_lineage

ROOT = Path(__file__).resolve().parents[1]
PACK = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-evaluation-control-plane-v2-r1"
)
DELTA = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-mechanical-repair-delta-r1"
)
DELTA_RESULTS = DELTA / "visible/RESULTS.jsonl"
DELTA_MANIFEST = DELTA / "RUN-MANIFEST.json"
CLAIM = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-claim-level-and-review-prep-r1"
)
CLAIM_RECEIPT = CLAIM / "STATE-TRANSITION-RECEIPT.json"
R1 = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-visible-331-diagnostic-r1"
)
R1_RESULTS = R1 / "visible/RESULTS.jsonl"
R1_MANIFEST = R1 / "RUN-MANIFEST.json"
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
DRAFT = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-per-locator-gold-draft-r1"
    / "LOCATOR-GOLD-DRAFT.json"
)
VISIBLE_PACK = ROOT / "data/evaluations/general-enquiries/LegalBot-GE-2026-09-01-review-r3"

EXPECTED_R2_MANIFEST = "d0ed806eee3ead78be77b5ca8eb150cbb7fd15f3eb9332637f230b38eef311c2"
EXPECTED_R2_RESULTS = "a3142fce995b7ae575864ae8411e9346d084306bf1197a4153326a8506a0908c"
EXPECTED_DELTA_MANIFEST = "cea8e5a16dcbc65dbb58df3022d40034f63f27ebecab48054e6a42c19f347afe"
EXPECTED_CLAIM_RECEIPT = "42ca4cb32a82109440d2bd1736c30ff2adf7339ac7539a82c3c17133f07c354a"
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


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _digest(value: dict[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result["content_sha256"] = content_sha256(result)
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


def _latest_priority1_pack() -> Path | None:
    packs = [
        pack
        for pack in sidecar_packs(ROOT)
        if "priority1-authority-intake" in pack.name
    ]
    return packs[-1] if packs else None


def _track(*, track_id: str, run_id: str, present: bool, note: str, **hashes: str) -> dict[str, Any]:
    body = {
        "track_id": track_id,
        "run_id": run_id,
        "present": present,
        "note": note,
        "question_pack_sha256": "",
        "effective_source_set_sha256": "",
        "retriever_config_sha256": "",
        "reranker_sha256": "",
        "prompt_sha256": "",
        "model_or_adapter_sha256": "",
        "evaluator_sha256": "",
        "locator_receipt_sha256": "",
        "result_sha256": "",
    }
    return bind_track(body, **hashes)


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
    claim_receipt = json.loads(CLAIM_RECEIPT.read_text(encoding="utf-8"))
    if claim_receipt.get("content_sha256") != EXPECTED_CLAIM_RECEIPT:
        raise RuntimeError("claim-level-and-review-prep-r1 receipt identity mismatch")
    if not DRAFT.is_file():
        raise RuntimeError("unsigned locator draft is missing and must stay preserved")

    rows = _load_jsonl(DELTA_RESULTS)
    if len(rows) != 331:
        raise RuntimeError("delta results are not 331 cases")
    plane = control_plane_v2(
        case_results=rows,
        diagnostic_execution="COMPLETE",
        diagnostic_report="APPROVED_SCOPED",
        routed=True,
        runnable_queue_count=0,
        locator_hold_count=0,
        locator_pending_count=0,
        locator_reject_count=1,
    )
    if plane["phase_execution_state"] != "ACTIVE":
        raise RuntimeError("phase_execution_state must remain ACTIVE")
    if plane["overall_progress"] is not True:
        raise RuntimeError("case holds must not set phase progress false")
    if plane["answer_legal_gold"] is not False or plane["training_gold"] is not False:
        raise RuntimeError("control plane v2 set gold")
    if plane["legacy_overall_state"] != MECHANICAL_EVALUATION_COMPLETE_REVIEW_PENDING:
        raise RuntimeError("legacy overall_state drifted")

    visible_hash = ""
    manifest_path = VISIBLE_PACK / "PACK-MANIFEST.json"
    if manifest_path.is_file():
        visible_hash = str(
            json.loads(manifest_path.read_text(encoding="utf-8")).get("content_sha256") or ""
        )
    locator_hash = _sha256_file(REGISTER) if REGISTER.is_file() else ""
    evaluator_hash = _sha256_file(ROOT / "backend/app/evaluation/ge_diagnostic_evaluator.py")
    r1_present = R1_MANIFEST.is_file() and R1_RESULTS.is_file()
    historical_r1 = _track(
        track_id="historical_r1_immutable",
        run_id="LegalBot-GE-2026-09-02-visible-331-diagnostic-r1",
        present=r1_present,
        note=(
            "Immutable diagnostic r1. Case 008 used Equality Act ss 174/208/210; "
            "case 174 used Arbitration Act 1996 s9; case 312 used an incomplete "
            "Wills Act s9 passage. Do not treat a later comparison summary as this track."
        ),
        question_pack_sha256=visible_hash,
        locator_receipt_sha256=locator_hash,
        result_sha256=_sha256_file(R1_RESULTS) if r1_present else "",
        evaluator_sha256="",
    )
    if r1_present:
        historical_r1["retriever_config_sha256"] = str(
            json.loads(R1_MANIFEST.read_text(encoding="utf-8")).get("content_sha256") or ""
        )
    new_r2 = _track(
        track_id="new_r2_generated_and_scored_under_r2_evaluator",
        run_id="LegalBot-GE-2026-09-02-visible-331-diagnostic-r2",
        present=True,
        note="Frozen diagnostic r2 generated and scored under the r2 evaluator. Not qualified legal gold.",
        question_pack_sha256=visible_hash,
        locator_receipt_sha256=locator_hash,
        result_sha256=EXPECTED_R2_RESULTS,
        retriever_config_sha256=EXPECTED_R2_MANIFEST,
        evaluator_sha256=evaluator_hash,
    )
    lineage = build_run_lineage(historical_r1=historical_r1, new_r2=new_r2)
    source_set = build_effective_source_set(project_root=ROOT)
    lineage["tracks"]["historical_r1_immutable"]["effective_source_set_sha256"] = source_set[
        "base_source_manifest_sha256"
    ]
    lineage["tracks"]["new_r2_generated_and_scored_under_r2_evaluator"][
        "effective_source_set_sha256"
    ] = source_set["effective_source_set_sha256"]
    lineage["content_sha256"] = content_sha256(lineage)

    registry = ContractSchemaRegistry.from_project_root(ROOT)
    registry.validate_new(plane)
    registry.validate_new(lineage)
    registry.validate_new(source_set)

    sample_receipt = build_proposition_receipt(
        source_version_id="control-plane-v2-sample",
        official_bytes_sha256="a" * 64,
        canonical_sha256="b" * 64,
        locator="section 29",
        proposition_id="sample-not-gold",
        proposition_text="Sample sidecar receipt. Not answer gold.",
        evidence_span_ids=["sample-span"],
        evidence_span_sha256s=["c" * 64],
        decision="PENDING",
        title="Equality Act 2010",
    )
    registry.validate_new(sample_receipt)

    priority1 = _latest_priority1_pack()
    priority1_manifest = None
    if priority1 is not None:
        manifest_file = priority1 / "STAGED-SOURCE-MANIFEST.json"
        if manifest_file.is_file():
            priority1_manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            if priority1_manifest.get("admitted") or priority1_manifest.get("legal_gold"):
                raise RuntimeError("priority1 intake set admission or gold")

    fingerprint = evaluation_fingerprint(
        project_root=ROOT,
        locator_manifest_hash=locator_hash,
        answer_set_hash=_sha256_file(DELTA_RESULTS),
        visible_pack_hash=visible_hash,
    )
    stages = explicit_stage_states()
    recorded_at = datetime.now(UTC).isoformat()
    PACK.mkdir(parents=True, mode=0o700)
    os.chmod(PACK, stat.S_IRWXU)

    blockers = [
        {
            "case_id": str(row.get("case_id") or ""),
            "principal_blocker": classify_principal_blocker(row),
            "factual_outcome": str((row.get("factual_result") or {}).get("outcome") or ""),
        }
        for row in rows
    ]
    named = {row["case_id"]: row for row in blockers}
    receipt = _digest(
        {
            "schema": "legalbot.ge-evaluation-control-plane-v2-receipt.v1",
            "recorded_at_utc": recorded_at,
            "owner_design_decision": {
                "full_architecture_redesign": False,
                "evaluation_control_plane_v2_required": True,
                "proposition_receipt_schema_required": True,
                "run_lineage_manifest_required": True,
                "effective_source_set_manifest_required": True,
                "scoped_blocker_state_machine_required": True,
                "independent_evaluator_gates_required": True,
                "issue_led_authority_intake_required": True,
                "current_r2_may_be_preserved_as_diagnostic": True,
                "current_r2_is_qualified_legal_pass": False,
                "do_not_bulk_add_authorities_for_every_hold": True,
                "classify_each_hold_before_intake": True,
                "case_local_hold_must_not_set_phase_progress_false": True,
                "answer_weight_training": False,
                "sealed_unseen": False,
                "promotion": False,
                "live": False,
            },
            "locator_evaluation_label": LOCATOR_EVALUATION_LABEL,
            "phase_execution_state": plane["phase_execution_state"],
            "run_execution_state": plane["run_execution_state"],
            "legacy_overall_state": plane["legacy_overall_state"],
            "frozen_r2_run_manifest_sha256": EXPECTED_R2_MANIFEST,
            "frozen_r2_results_sha256": EXPECTED_R2_RESULTS,
            "named_cases": {
                CASE_008: named.get(CASE_008),
                CASE_174: named.get(CASE_174),
                CASE_312: named.get(CASE_312),
            },
            "priority1_pack": None if priority1 is None else priority1.name,
            "priority1_ingested_count": None
            if priority1_manifest is None
            else priority1_manifest.get("ingested_count"),
            "priority1_failed_count": None
            if priority1_manifest is None
            else priority1_manifest.get("failed_count"),
            "moseley_fail_closed_without_unique_fcl_title": True,
            "uksc_16_issue_limited_to_article_5": True,
            "full_331_r3_executed": False,
            "answer_weight_training": False,
            "sealed_unseen": False,
            "promotion": False,
            "live": False,
            "downstream_gates": {name: "NOT_STARTED" for name in DOWNSTREAM},
            "stage_states": stages,
        }
    )
    _write_json(PACK / "CONTROL-PLANE-V2.json", plane)
    _write_json(PACK / "RUN-LINEAGE.json", lineage)
    _write_json(PACK / "EFFECTIVE-SOURCE-SET.json", source_set)
    _write_json(PACK / "PRINCIPAL-BLOCKERS.json", {"rows": blockers, "counts": plane["principal_blocker_counts"]})
    _write_json(PACK / "SAMPLE-PROPOSITION-RECEIPT.json", sample_receipt)
    _write_json(PACK / "EVALUATION-FINGERPRINT.json", fingerprint)
    _write_json(PACK / "STATE-TRANSITION-RECEIPT.json", receipt)
    _write_text(
        PACK / "README.md",
        """# GE Evaluation Control Plane v2

Targeted Phase 2 control-plane upgrade. Frozen diagnostic r2 is preserved and
is not qualified legal gold. Locator owner-adoption is labelled
OWNER_ADOPTED_LOCATOR_EVALUATION_DECISION. Case-local holds keep phase
execution ACTIVE. Priority 1 intake is evaluation-sidecar only.
331 r3, weight training, sealed unseen, promotion and live were not run.
""",
    )
    print(
        json.dumps(
            {
                "pack": str(PACK),
                "receipt_sha256": receipt["content_sha256"],
                "phase_execution_state": plane["phase_execution_state"],
                "run_execution_state": plane["run_execution_state"],
                "principal_blocker_counts": plane["principal_blocker_counts"],
                "priority1_pack": None if priority1 is None else priority1.name,
                "answer_legal_gold": False,
                "full_331_r3_executed": False,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
