#!/usr/bin/env python3
"""Prepare exact, non-authorizing inputs for the visible 331-case GE run.

This command records the owner's approval of the process, not a legal judgment,
signature, model capability, private-root capability, or execution authority.
It never opens unseen prompts, invokes a model, writes an index pointer, creates
training data, or deletes an artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.contracts import canonical_json_bytes, seal_contract  # noqa: E402
from app.evaluation.ge_coverage_authorization import (  # noqa: E402
    build_ge_coverage_decision_request,
    ge_coverage_decision_binding,
)
from app.evaluation.ge_improvement_loop import (  # noqa: E402
    build_coverage_topology_predecision,
    required_ge_coverage_cells,
)
from app.evaluation.ge_visible_harness import VisibleGEPack  # noqa: E402

SOURCE_PACK = (
    ROOT / "data/evaluations/general-enquiries/LegalBot-GE-2026-09-01-review-r3"
)
PREPARATION = ROOT / "data/evaluations/general-enquiries/LegalBot-Phase2-2026-09-01"
OUTPUT = (
    ROOT
    / "data/evaluations/general-enquiries/LegalBot-GE-2026-09-01-execution-readiness-r1"
)
CANDIDATE_ID = "current-law-ew-full-fp16-v111-20260829-recovery-b"
CANDIDATE = ROOT / "data/indexes/builds" / CANDIDATE_ID
APPROVAL_DOCX = ROOT / "output/docx/LegalBot-Phase2-Evaluation-Execution-Approval.docx"
VERIFICATION = (
    ROOT / "docs/status/LegalBot-GE-2026-09-01-verification-r2/VERIFICATION.json"
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode() + b"\n"


def _write_new(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _owner_process_approval(*, created_at: datetime) -> dict[str, Any]:
    return seal_contract(
        {
            "schema": "legalbot.ge-owner-process-approval-receipt.v1",
            "receipt_id": "ge-visible-331-process-approval-2026-09-01",
            "approval_source": "owner-message-in-current-task",
            "approved_document_sha256": _sha256(APPROVAL_DOCX),
            "approved_scope": {
                "visible_case_count": 331,
                "system_scenario_count_separate": 32,
                "factual_gate_first": True,
                "quality_threshold": 70,
                "complete_rerun_after_material_change": True,
                "gap_loop_create_only": True,
            },
            "process_approved": True,
            "exact_section_7_fields_supplied": False,
            "trusted_signature_present": False,
            "legal_currentness_judgment_present": False,
            "model_execution_authority_present": False,
            "authorizing": False,
            "recorded_at": created_at.isoformat(),
        }
    )


def _unseen_custody_ledger(*, pack: VisibleGEPack, created_at: datetime) -> dict[str, Any]:
    source_manifest = json.loads((SOURCE_PACK / "PACK-MANIFEST.json").read_text())
    private = source_manifest["private_unseen"]
    return seal_contract(
        {
            "schema": "legalbot.ge-unseen-custody-ledger.v1",
            "ledger_id": "ge-private-r2-custody-2026-09-01",
            "visible_pack_manifest_sha256": pack.pack_manifest_sha256,
            "unseen_content_version": private["content_version"],
            "unseen_case_count": private["count"],
            "unseen_archive_sha256": private["archive_sha256"],
            "custody_note_sha256": _sha256(SOURCE_PACK / "UNSEEN-CUSTODY.md"),
            "prompt_content_inspected": False,
            "prompt_content_decoded": False,
            "used_for_visible_evaluation": False,
            "used_for_training": False,
            "owner_frozen": False,
            "semantic_independence_verified": False,
            "authorizing": False,
            "recorded_at": created_at.isoformat(),
        }
    )


def _resource_proposal(*, created_at: datetime) -> dict[str, Any]:
    return seal_contract(
        {
            "schema": "legalbot.ge-resource-envelope-proposal.v1",
            "proposal_id": "ge-visible-331-local-16gib-2026-09-01",
            "host_physical_memory_bytes": 17_179_869_184,
            "max_peak_combined_working_set_bytes": 12 * 1024**3,
            "minimum_host_available_memory_bytes": 3 * 1024**3,
            "generation_worker_count": 1,
            "single_flight_generation": True,
            "context_window_tokens": 8192,
            "max_output_tokens": 2048,
            "prefill_step_size": 512,
            "kv_cache_bits": 8,
            "kv_group_size": 64,
            "clear_cache_after_request": True,
            "transport": "private-uds-grpc-only",
            "network_fallback_allowed": False,
            "transport_retries": 0,
            "same_fingerprint_attempt_limit": 2,
            "basis": "accepted-design-12gib-ceiling-3gib-free-admission",
            "candidate_runtime_binding_pending": True,
            "owner_decision_signature_pending": True,
            "authorizing": False,
            "created_at": created_at.isoformat(),
        }
    )


def _legal_work_item(case: Any, *, ordinal: int) -> dict[str, Any]:
    raw = case.raw
    return seal_contract(
        {
            "schema": "legalbot.ge-qualified-legal-review-work-item.v1",
            "ordinal": ordinal,
            "case_id": case.case_id,
            "case_version_id": case.version_id,
            "case_version_sha256": case.record_sha256,
            "scenario_family_id": case.scenario_family_id,
            "topic_id": raw.get("topic_id"),
            "prompt": case.prompt,
            "primary_jurisdiction": raw.get("primary_jurisdiction"),
            "requested_currentness_cutoff": raw.get("legal_currentness_cutoff"),
            "material_dates": raw.get("material_dates"),
            "issue_tags": raw.get("issue_tags"),
            "clarification_criteria": raw.get("proposed_clarification_criteria"),
            "immediate_actions": raw.get("immediate_actions"),
            "prohibited_overstatement": raw.get("prohibited_overstatement"),
            "negative_propositions": raw.get("gold_answer_negative_propositions"),
            "required_review": {
                "admitted_source_versions": [],
                "evidence_spans": [],
                "material_propositions": [],
                "contrary_authority": [],
                "currentness_checked_at": None,
                "currentness_decision": None,
                "gold_answer_or_explicit_hold": None,
                "reviewer_role": None,
                "reviewer_identity_reference": None,
                "review_decision_sha256": None,
            },
            "review_status": "AWAITING_QUALIFIED_LEGAL_REVIEW",
            "ai_may_act_as_legal_reviewer": False,
            "answer_model_authorized": False,
            "authorizing": False,
        }
    )


def prepare(output: Path) -> dict[str, Any]:
    output = output.absolute()
    allowed_parent = (ROOT / "data/evaluations/general-enquiries").resolve(strict=True)
    if output.parent.resolve(strict=True) != allowed_parent or output.exists():
        raise ValueError("output must be one new direct child of the GE evaluation directory")
    created_at = datetime.now(UTC)
    pack = VisibleGEPack.load(SOURCE_PACK)
    if len(pack.cases) != 331 or len(pack.system_scenarios) != 32:
        raise RuntimeError("GE denominator changed")
    for required in (
        CANDIDATE / "seal.json",
        CANDIDATE / "manifest.json",
        APPROVAL_DOCX,
        VERIFICATION,
        PREPARATION / "GE-FACTUAL-GATE-POLICY.json",
        PREPARATION / "GE-QUALITY-GATE-POLICY.json",
    ):
        if required.is_symlink() or not required.is_file():
            raise RuntimeError(f"required readiness input is missing: {required.name}")

    candidate_seal = json.loads((CANDIDATE / "seal.json").read_text())
    if (
        candidate_seal.get("build_id") != CANDIDATE_ID
        or candidate_seal.get("promotion") != "not_requested"
    ):
        raise RuntimeError("candidate identity or non-ACTIVE state changed")

    cells = required_ge_coverage_cells(pack=pack, public_assignment_ids={})
    topology = build_coverage_topology_predecision(
        pack=pack,
        manifest_id="ge-visible-331-coverage-2026-09-01",
        cells=cells,
        proposed_at=created_at,
    )
    topology_binding = ge_coverage_decision_binding(topology)
    topology_request = build_ge_coverage_decision_request(
        binding=topology_binding,
        created_at=created_at,
    ).model_dump(mode="json", by_alias=True)
    approval = _owner_process_approval(created_at=created_at)
    custody = _unseen_custody_ledger(pack=pack, created_at=created_at)
    resources = _resource_proposal(created_at=created_at)
    legal_items = [_legal_work_item(case, ordinal=i) for i, case in enumerate(pack.cases, 1)]

    output.mkdir(mode=0o700)
    output.chmod(0o700)
    _write_new(output / "GE-OWNER-PROCESS-APPROVAL-RECEIPT.json", _json_bytes(approval))
    _write_new(output / "GE-UNSEEN-CUSTODY-LEDGER.json", _json_bytes(custody))
    _write_new(output / "GE-RESOURCE-ENVELOPE-PROPOSAL.json", _json_bytes(resources))
    _write_new(output / "GE-COVERAGE-TOPOLOGY-PREDECISION.json", _json_bytes(topology))
    _write_new(output / "GE-COVERAGE-OWNER-DECISION-REQUEST.json", _json_bytes(topology_request))
    _write_new(
        output / "GE-331-QUALIFIED-LEGAL-REVIEW-WORK-ORDER.jsonl",
        b"".join(canonical_json_bytes(item) for item in legal_items),
    )

    model_target = ROOT / "models/runtime/Qwen3.5-9B-4bit"
    ready = seal_contract(
        {
            "schema": "legalbot.ge-execution-readiness.v1",
            "readiness_id": output.name,
            "visible_case_count": 331,
            "system_scenario_count_separate": 32,
            "quality_threshold": 70,
            "candidate": {
                "build_id": CANDIDATE_ID,
                "state": "NON_ACTIVE_BUILT_UNSCORED",
                "seal_file_sha256": _sha256(CANDIDATE / "seal.json"),
                "source_manifest_sha256": "1ab9e139e2d97e2f4b935fb8619a46c98ee257f855ce8f9a99ec309905f7623b",
                "ready": True,
            },
            "bindings_ready": {
                "visible_pack": True,
                "factual_gate_policy": True,
                "quality_gate_policy": True,
                "system_suite_identity": True,
                "unseen_custody_ledger": True,
                "coverage_topology_predecision": True,
                "qualified_legal_review_work_order": True,
            },
            "identities": {
                "approved_docx_sha256": _sha256(APPROVAL_DOCX),
                "verification_snapshot_sha256": _sha256(VERIFICATION),
                "visible_pack_manifest_sha256": pack.pack_manifest_sha256,
                "case_manifest_sha256": pack.case_manifest_sha256,
                "case_order_sha256": pack.case_order_sha256,
                "input_projection_sha256": pack.input_projection_sha256,
                "system_manifest_sha256": pack.system_manifest_sha256,
                "system_order_sha256": pack.system_order_sha256,
                "factual_gate_policy_file_sha256": _sha256(
                    PREPARATION / "GE-FACTUAL-GATE-POLICY.json"
                ),
                "quality_gate_policy_file_sha256": _sha256(
                    PREPARATION / "GE-QUALITY-GATE-POLICY.json"
                ),
                "unseen_custody_ledger_sha256": custody["content_sha256"],
                "resource_proposal_sha256": resources["content_sha256"],
                "coverage_predecision_sha256": topology["content_sha256"],
                "coverage_owner_request_sha256": topology_request["seal_sha256"],
                "owner_process_approval_receipt_sha256": approval["content_sha256"],
            },
            "model_pin": {
                "model_id": "mlx-community/Qwen3.5-9B-4bit",
                "revision": "8b2b98c00a6b4d291155e4890773ca8f769aee53",
                "trusted_runtime_model_sha256": "1d4172150e0b972bbf600bb42e1dc0f293cf4878a6abe221fe664ad353a5ed1b",
                "artifact_present": model_target.is_dir(),
                "download_executed": False,
            },
            "legal_review": {
                "work_item_count": len(legal_items),
                "approved_gold_count": 0,
                "approved_currentness_count": 0,
                "qualified_reviewer_decision_present": False,
            },
            "blocking_reason_codes": [
                "ANSWER_MODEL_ARTIFACT_ABSENT",
                "PRIVATE_UDS_MODEL_CAPABILITY_ABSENT",
                "QUALIFIED_331_CASE_GOLD_CURRENTNESS_PACKAGE_ABSENT",
                "DEVELOPMENT_PRIVATE_ROOT_CAPABILITY_ABSENT",
                "TRUSTED_OWNER_SIGNATURE_VERIFIER_ABSENT",
                "CANDIDATE_BOUND_RESOURCE_POLICY_ABSENT",
                "TEN_CAPABILITY_EXECUTION_MANIFEST_ABSENT",
                "ADMITTED_331_ANSWER_RUNNER_ABSENT",
            ],
            "execution_ready": False,
            "model_invoked": False,
            "evaluation_executed": False,
            "unseen_opened": False,
            "training_executed": False,
            "promotion_executed": False,
            "live_activated": False,
            "deletion_performed": False,
            "created_at": created_at.isoformat(),
        }
    )
    _write_new(output / "GE-EXECUTION-READINESS.json", _json_bytes(ready))

    readme = """# GE 331 execution readiness

The owner approved the visible GE process and 70+ factual-first standard. This
package converts that direction into exact, reviewable inputs without inventing
the still-missing owner-only or qualified-legal authorities.

The non-ACTIVE retrieval candidate is now ready. The exact 331 visible cases,
32 separate system scenarios, quality policies, unseen custody ledger, 23-domain
coverage predecision, resource proposal and 331-item legal-review work order are
bound here. The six separate public-access domains remain explicit empty cells
until dedicated visible diagnostic cases are prepared after an authorized
baseline or a separately approved pre-baseline coverage decision.

No answer model or evaluation ran. The readiness record lists the exact remaining
gates. In particular, owner process approval does not make Codex a qualified legal
reviewer and does not fabricate an owner signature, private-root capability,
model transport capability or execution manifest.
"""
    _write_new(output / "README.md", readme.encode())

    artifacts = [
        {"path": path.name, "sha256": _sha256(path), "size": path.stat().st_size}
        for path in sorted(output.iterdir())
        if path.is_file()
    ]
    manifest = seal_contract(
        {
            "schema": "legalbot.ge-execution-readiness-package.v1",
            "package_id": output.name,
            "artifact_count": len(artifacts),
            "artifacts": artifacts,
            "visible_case_count": 331,
            "system_scenario_count_separate": 32,
            "authorizing": False,
            "model_invoked": False,
            "evaluation_executed": False,
            "unseen_opened": False,
            "training_executed": False,
            "deletion_performed": False,
            "created_at": created_at.isoformat(),
        }
    )
    _write_new(output / "MANIFEST.json", _json_bytes(manifest))
    return ready


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    result = prepare(args.output)
    print(
        json.dumps(
            {
                "schema": result["schema"],
                "status": "PREPARED_NOT_EXECUTED",
                "visible_case_count": result["visible_case_count"],
                "blocking_reason_codes": result["blocking_reason_codes"],
                "content_sha256": result["content_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
