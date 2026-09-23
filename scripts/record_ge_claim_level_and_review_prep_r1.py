#!/usr/bin/env python3
"""Record claim-level routing and non-approving qualified-review packets.

Create-only. Does not rerun the 331, mutate frozen r2, reopen locator review,
or set gold, admission, training, unseen, promotion or live.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.evaluation.ge_claim_support_router import route_claim_cases
from app.evaluation.ge_hold_reason_router import (
    CASE_008,
    CASE_174,
    CASE_312,
    route_results,
)
from app.evaluation.ge_phase2_progress import (
    MECHANICAL_EVALUATION_COMPLETE_REVIEW_PENDING,
    evaluation_fingerprint,
    explicit_stage_states,
    phase2_progress,
)
from app.evaluation.ge_qualified_review_packets import build_review_pack
from scripts.run_ge_retrieval_training_cycle import ISSUE_LOCATOR_HINTS, TOPIC_SOURCES

ROOT = Path(__file__).resolve().parents[1]
PACK = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-claim-level-and-review-prep-r1"
)
DELTA = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-mechanical-repair-delta-r1"
)
DELTA_RESULTS = DELTA / "visible/RESULTS.jsonl"
DELTA_MANIFEST = DELTA / "RUN-MANIFEST.json"
DELTA_RECEIPT = DELTA / "STATE-TRANSITION-RECEIPT.json"
CONTROL_PLANE = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-control-plane-router-r1"
)
CONTROL_RECEIPT = CONTROL_PLANE / "STATE-TRANSITION-RECEIPT.json"
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
EXPECTED_DELTA_RECEIPT = "f6e39456f95d148ce96aa1f8331eb233d92ce0e23559de21aceac8639ca4eae9"
EXPECTED_CONTROL_RECEIPT = "01fb8a3991a80bb5fb5c18207fb9ce7e28d29577bc63f9c1d8315662e696215e"
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
    if _sha256_file(R2_RESULTS) != EXPECTED_R2_RESULTS:
        raise RuntimeError("frozen r2 RESULTS identity mismatch")
    delta_manifest = json.loads(DELTA_MANIFEST.read_text(encoding="utf-8"))
    if delta_manifest.get("content_sha256") != EXPECTED_DELTA_MANIFEST:
        raise RuntimeError("mechanical-repair-delta-r1 RUN-MANIFEST identity mismatch")
    delta_receipt = json.loads(DELTA_RECEIPT.read_text(encoding="utf-8"))
    if delta_receipt.get("content_sha256") != EXPECTED_DELTA_RECEIPT:
        raise RuntimeError("mechanical-repair-delta-r1 receipt identity mismatch")
    control_receipt = json.loads(CONTROL_RECEIPT.read_text(encoding="utf-8"))
    if control_receipt.get("content_sha256") != EXPECTED_CONTROL_RECEIPT:
        raise RuntimeError("control-plane-router-r1 receipt identity mismatch")
    if not DRAFT.is_file():
        raise RuntimeError("unsigned locator draft is missing and must stay preserved")

    rows = _load_jsonl(DELTA_RESULTS)
    if len(rows) != 331:
        raise RuntimeError("delta results are not 331 cases")
    routed = route_results(rows)
    if routed["factual_pass_count"] != 41 or routed["hold_count"] != 290:
        raise RuntimeError("delta pass/hold counts drifted")
    if routed["runnable_queue_count"] != 53:
        raise RuntimeError("claim-level input queue is not 53")
    if routed["qualified_review_ready_count"] != 278:
        raise RuntimeError("qualified-review-ready starting count is not 278")
    if routed["terminal_for_entire_pipeline_count"] != 0:
        raise RuntimeError("mechanical holds must not be pipeline-dead")
    holds_by_id = {item["case_id"]: item for item in routed["holds"]}
    frozen_by_id = {item["case_id"]: item for item in routed["frozen_pass_cases"]}
    if CASE_008 not in frozen_by_id:
        raise RuntimeError("case 008 must remain FACTUAL_PASS")
    if holds_by_id[CASE_174]["hold_reason_code"] != "JURISDICTION_SCOPE_REVIEW":
        raise RuntimeError("case 174 must remain jurisdiction-scope review")
    if holds_by_id[CASE_312]["hold_reason_code"] != "FACT_DEPENDENT_OUTCOME":
        raise RuntimeError("case 312 must remain fact-dependent")

    claim_ids = list(routed["runnable_case_ids"])
    claim_rows = [row for row in rows if str(row.get("case_id") or "") in set(claim_ids)]
    classified = route_claim_cases(
        claim_rows,
        locator_hints=ISSUE_LOCATOR_HINTS,
        topic_sources=TOPIC_SOURCES,
        attempt_count=2,
    )
    if classified["remaining_changed_input_runnable_count"] != 0:
        raise RuntimeError("changed-input mechanical work remains; do not generic-retrieve")
    if classified["mechanically_repaired_case_ids"]:
        raise RuntimeError("no deterministic on-topic attach was executed")
    if sorted(classified["moved_to_qualified_review_case_ids"]) != sorted(claim_ids):
        raise RuntimeError("all 53 claim cases must move to qualified review")
    for case_id in (CASE_008, CASE_174, CASE_312):
        if case_id in classified["moved_to_qualified_review_case_ids"]:
            raise RuntimeError(f"{case_id} is not in the 53-case claim queue")

    currentness_holds = [
        item for item in routed["holds"] if item["hold_reason_code"] == "CURRENTNESS_UNRESOLVED"
    ]
    if len(currentness_holds) != 184:
        raise RuntimeError("currentness queue is not 184")
    currentness_counts = dict(
        sorted(Counter(item.get("currentness_subreason") for item in currentness_holds).items())
    )
    if any(not item.get("currentness_subreason") for item in currentness_holds):
        raise RuntimeError("a currentness case still has only a generic label")

    original_ready = list(routed["qualified_review_ready_case_ids"])
    after_ready = original_ready + classified["moved_to_qualified_review_case_ids"]
    if len(after_ready) != 331 or len(set(after_ready)) != 331:
        raise RuntimeError("review-ready after claim routing is not 331 unique cases")

    routed_by_id = {**frozen_by_id, **holds_by_id}
    claim_by_id = {item["case_id"]: item for item in classified["rows"]}
    pack_body = build_review_pack(
        rows,
        ready_ids=after_ready,
        routed_by_id=routed_by_id,
        claim_by_id=claim_by_id,
    )
    original_pack = build_review_pack(
        rows,
        ready_ids=original_ready,
        routed_by_id=routed_by_id,
        claim_by_id=claim_by_id,
    )
    if original_pack["packet_count"] != 278:
        raise RuntimeError("starting qualified-review packet count is not 278")
    if pack_body["packet_count"] != 331:
        raise RuntimeError("after-claim packet count is not 331")
    if any(item.get("qualified_legal_review") != "NOT_STARTED" for item in pack_body["packets"]):
        raise RuntimeError("a packet set qualified_legal_review")

    visible_hash = ""
    manifest_path = VISIBLE_PACK / "PACK-MANIFEST.json"
    if manifest_path.is_file():
        visible_hash = str(json.loads(manifest_path.read_text(encoding="utf-8")).get("content_sha256") or "")
    fingerprint = evaluation_fingerprint(
        project_root=ROOT,
        locator_manifest_hash=_sha256_file(REGISTER),
        answer_set_hash=_sha256_file(DELTA_RESULTS),
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
        runnable_queue_count=0,
        qualified_review_ready_count=331,
    )
    if progress["overall_state"] != MECHANICAL_EVALUATION_COMPLETE_REVIEW_PENDING:
        raise RuntimeError("overall_state must be MECHANICAL_EVALUATION_COMPLETE_REVIEW_PENDING")
    stages = explicit_stage_states()
    recorded_at = datetime.now(UTC).isoformat()
    PACK.mkdir(parents=True, mode=0o700)
    os.chmod(PACK, stat.S_IRWXU)

    claim_manifest = _digest(
        {
            "schema": "legalbot.ge-claim-level-support-manifest.v1",
            "source_run_id": "LegalBot-GE-2026-09-02-mechanical-repair-delta-r1",
            "baseline_run_id": "LegalBot-GE-2026-09-02-visible-331-diagnostic-r2",
            "no_generic_retrieval": True,
            "case_count": classified["case_count"],
            "counts_by_failure_class": classified["counts_by_failure_class"],
            "mechanically_repaired_case_ids": classified["mechanically_repaired_case_ids"],
            "moved_to_qualified_review_case_ids": classified["moved_to_qualified_review_case_ids"],
            "remaining_changed_input_runnable_count": classified["remaining_changed_input_runnable_count"],
            "rows": classified["rows"],
        }
    )
    currentness_manifest = _digest(
        {
            "schema": "legalbot.ge-currentness-subreason-counts.v1",
            "case_count": 184,
            "counts_by_currentness_subreason": currentness_counts,
            "case_ids_by_subreason": {
                code: sorted(
                    item["case_id"]
                    for item in currentness_holds
                    if item.get("currentness_subreason") == code
                )
                for code in currentness_counts
            },
        }
    )
    review_manifest = _digest(
        {
            "schema": "legalbot.ge-qualified-review-preparation-manifest.v1",
            "qualified_legal_review": "NOT_STARTED",
            "answer_legal_gold": "NOT_STARTED",
            "substantive_approval_recorded": False,
            "original_qualified_review_ready_count": 278,
            "original_qualified_review_ready_case_ids": original_ready,
            "moved_from_mechanical_count": 53,
            "moved_from_mechanical_case_ids": classified["moved_to_qualified_review_case_ids"],
            "after_claim_routing_packet_count": 331,
            "case_ids": pack_body["case_ids"],
            "reviewer_options": pack_body["reviewer_options"],
            "counts_by_review_queue_bucket": dict(
                sorted(Counter(item.get("review_queue_bucket") for item in pack_body["packets"]).items())
            ),
            "currentness_subreason_counts_in_packets": pack_body["currentness_subreason_counts_in_packets"],
            "packets_jsonl": "QUALIFIED-REVIEW-PACKETS.jsonl",
        }
    )
    receipt = _digest(
        {
            "schema": "legalbot.ge-control-plane-state-transition-receipt.v1",
            "recorded_at_utc": recorded_at,
            "signature_status": "session_instruction_hash_bound_not_cryptographic_signature",
            "kind": "claim_level_and_qualified_review_preparation_r1",
            "owner_scoped_acceptance": {
                "accepted_receipts": [
                    {
                        "path": CONTROL_PLANE.as_posix(),
                        "state_transition_receipt_content_sha256": EXPECTED_CONTROL_RECEIPT,
                    },
                    {
                        "path": DELTA.as_posix(),
                        "run_manifest_content_sha256": EXPECTED_DELTA_MANIFEST,
                        "state_transition_receipt_content_sha256": EXPECTED_DELTA_RECEIPT,
                    },
                ],
                "accepts": [
                    "corrected_control_plane",
                    "targeted_191_case_execution",
                    "full_evidence_presence",
                    "claim_support_and_hold_classifications",
                    "frozen_r2_preservation",
                    "downstream_legal_training_boundaries",
                ],
                "does_not_approve": "substantive_legal_correctness_of_the_331_answers",
            },
            "frozen_r2": {
                "run_id": "LegalBot-GE-2026-09-02-visible-331-diagnostic-r2",
                "run_manifest_content_sha256": EXPECTED_R2_MANIFEST,
                "visible_results_sha256": EXPECTED_R2_RESULTS,
                "immutable": True,
            },
            "accepted_counts_before_claim_routing": {
                "cases": 331,
                "FACTUAL_PASS": 41,
                "FACTUAL_HOLD": 290,
                "evidence_present": 331,
                "claim_support_PASS": 278,
                "machine_repairable": 53,
                "terminal_for_mechanical_route": 237,
                "qualified_review_ready": 278,
            },
            "claim_level": {
                "input_case_count": 53,
                "counts_by_failure_class": classified["counts_by_failure_class"],
                "mechanically_repaired_case_ids": classified["mechanically_repaired_case_ids"],
                "moved_to_qualified_review_case_ids": classified["moved_to_qualified_review_case_ids"],
                "remaining_changed_input_runnable_count": 0,
                "no_generic_retrieval": True,
            },
            "terminal_status_correction": {
                "terminal_for_mechanical_route": True,
                "terminal_for_entire_pipeline": False,
                "qualified_review_ready": True,
            },
            "named_case_invariants": {
                CASE_008: "FACTUAL_PASS_INCLUDED_IN_QUALIFIED_REVIEW_NO_MECHANICAL_RERUN",
                CASE_174: "JURISDICTION_SCOPE_REVIEW_ICC_OHPEN_KAJIMA_CHURCHILL_NO_CABLE_NO_ARB_S9",
                CASE_312: "FACTUAL_HOLD_FACT_DEPENDENT_OUTCOME_CONDITIONAL_ANSWER_PACKET",
            },
            "overall_progress": progress["overall_progress"],
            "overall_state": progress["overall_state"],
            "runnable_queue_count": 0,
            "qualified_review_ready_count": 331,
            "phase2_r2_complete": progress["phase2_r2_complete"],
            "stage_states": stages,
            "downstream_gates_once": {name: "NOT_STARTED" for name in DOWNSTREAM},
            "confirmations": {
                "full_331_rerun": False,
                "tick_sheet_created_or_modified": False,
                "locator_package_reopened": False,
                "frozen_r2_altered": False,
                "cable_and_wireless_reopened": False,
                "gold_admission_training_unseen_promotion_live_changed": False,
                "qualified_legal_review_set_true": False,
                "weight_training_started": False,
            },
        }
    )

    _write_json(PACK / "CLAIM-SUPPORT-MANIFEST.json", claim_manifest)
    _write_json(
        PACK / "CLAIM-FAILURE-COUNTS.json",
        _digest(
            {
                "schema": "legalbot.ge-claim-failure-counts.v1",
                "counts_by_failure_class": classified["counts_by_failure_class"],
                "mechanically_repaired_case_ids": classified["mechanically_repaired_case_ids"],
                "moved_to_qualified_review_case_ids": classified["moved_to_qualified_review_case_ids"],
                "remaining_changed_input_runnable_count": 0,
            }
        ),
    )
    _write_json(
        PACK / "MECHANICALLY-REPAIRED-CASES.json",
        _digest(
            {
                "schema": "legalbot.ge-mechanically-repaired-cases.v1",
                "case_ids": [],
                "count": 0,
                "note": "No deterministic on-topic locator attach or answer contraction was executed.",
            }
        ),
    )
    _write_json(
        PACK / "MOVED-TO-QUALIFIED-REVIEW.json",
        _digest(
            {
                "schema": "legalbot.ge-moved-to-qualified-review.v1",
                "case_ids": classified["moved_to_qualified_review_case_ids"],
                "count": 53,
                "from_queue": "CLAIM_NOT_SUPPORTED",
                "mechanical_status": "EXHAUSTED",
                "next_route": "QUALIFIED_LEGAL_REVIEW_QUEUE",
            }
        ),
    )
    _write_json(
        PACK / "CLAIM-EXHAUSTED-CASE-IDS.json",
        _digest(
            {
                "schema": "legalbot.ge-claim-exhausted-case-ids.v1",
                "case_ids": classified["exhausted_case_ids"],
                "count": len(classified["exhausted_case_ids"]),
            }
        ),
    )
    _write_json(
        PACK / "TARGETED-REPAIR-QUEUE.json",
        _digest(
            {
                "schema": "legalbot.ge-targeted-repair-queue.v1",
                "case_ids": [],
                "count": 0,
                "full_331_rerun": False,
                "source_run_id": PACK.name,
                "remaining_changed_input_runnable_count": 0,
            }
        ),
    )
    _write_json(PACK / "CURRENTNESS-SUBREASON-COUNTS.json", currentness_manifest)
    _write_json(PACK / "QUALIFIED-REVIEW-PREPARATION-MANIFEST.json", review_manifest)
    packet_lines = "".join(
        json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        for item in pack_body["packets"]
    )
    _write_text(PACK / "QUALIFIED-REVIEW-PACKETS.jsonl", packet_lines)
    _write_json(PACK / "EVALUATION-FINGERPRINT.json", fingerprint)
    _write_json(PACK / "STATE-TRANSITION-RECEIPT.json", receipt)
    _write_json(
        PACK / "OWNER-INSTRUCTION.json",
        _digest(
            {
                "schema": "legalbot.owner-session-instruction-record.v1",
                "recorded_at": recorded_at,
                "instruction_summary": (
                    "Claim-level delta and qualified-review preparation. "
                    "Accept the control-plane and mechanical-repair receipts. "
                    "Do not generic-retrieve the 53. Prepare reviewer packets without "
                    "setting qualified_legal_review. Factual PASS is not answer gold."
                ),
                "evaluation_state": True,
                "authorized": [
                    "claim_level_proposition_routing",
                    "qualified_review_packet_preparation",
                    "currentness_subrouting",
                    "terminal_mechanical_hold_status_correction",
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
                    "full_visible_331_rerun",
                    "generic_topic_retrieval_of_claim_queue",
                ],
                "signature_status": "session_instruction_not_cryptographic_signature",
            }
        ),
    )
    _write_text(
        PACK / "README.md",
        (
            "# Claim-level routing and qualified-review preparation r1\n\n"
            "The 53 remaining CLAIM_NOT_SUPPORTED cases were classified at "
            "proposition level without another generic retrieval run. All 53 are "
            "mechanical-route exhausted and moved to qualified-review preparation. "
            "Reviewer packets were prepared for all 331 cases. "
            "`qualified_legal_review` remains NOT_STARTED. Frozen r2 is unchanged.\n"
        ),
    )
    print(
        json.dumps(
            {
                "receipt": receipt["content_sha256"],
                "claim_manifest": claim_manifest["content_sha256"],
                "review_manifest": review_manifest["content_sha256"],
                "overall_state": progress["overall_state"],
                "remaining_changed_input_runnable_count": 0,
                "counts_by_failure_class": classified["counts_by_failure_class"],
                "currentness_counts": currentness_counts,
                "packet_count": 331,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
