#!/usr/bin/env python3
"""Build the complete sanitized machine package for the blocked Phase-2A verdict."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OWNER_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
RUN_NAME = "LegalBot-Phase2A-2026-08-27-final-owner-review-blocked"
FINAL_ROOT = OWNER_ROOT / RUN_NAME
MACHINE_ROOT = FINAL_ROOT / "machine"
BUILD_ID = "current-law-ew-full-fp16-v111-20260827-phase2a-a"

R47 = OWNER_ROOT / "LegalBot-Phase2AB-2026-08-24-r47-consolidated-owner-gate"
ALL585 = OWNER_ROOT / "LegalBot-Phase2A-2026-08-27-deterministic-all585-qualification"
CROSSWALK = OWNER_ROOT / "LegalBot-Phase2A-2026-08-27-deterministic-exact-span-crosswalk-r2"
ADMISSION = OWNER_ROOT / "LegalBot-Phase2A-2026-08-27-consolidated-source-admission"
STAGING = OWNER_ROOT / "LegalBot-Phase2A-2026-08-27-consolidated-source-staging"
RETRIEVAL_R1 = OWNER_ROOT / "LegalBot-Phase2A-2026-08-27-held-retrieval-reattestation"
RETRIEVAL_R2 = OWNER_ROOT / "LegalBot-Phase2A-2026-08-27-held-retrieval-reattestation-r2"
BUILD_FAILURE = OWNER_ROOT / "LegalBot-Phase2A-2026-08-27-successor-build-runtime-debug-r1"
BUILD_RECOVERY = OWNER_ROOT / "LegalBot-Phase2A-2026-08-27-successor-build-recovery-r2"
METADATA_REPAIR = OWNER_ROOT / (
    "LegalBot-Phase2A-2026-08-27-successor-resume-metadata-reconciliation"
)
QUALIFICATION_REPAIR = OWNER_ROOT / (
    "LegalBot-Phase2A-2026-08-27-candidate-provision-qualification-roll-forward"
)
PLANNER_AUDIT = OWNER_ROOT / "LegalBot-Phase2A-2026-08-27-planner-cap-corrective-audit-v2"
DETERMINISTIC_AUTH = OWNER_ROOT / (
    "LegalBot-Phase2A-2026-08-27-deterministic-only-owner-authorized"
)
SEMINAR_APPROVAL = OWNER_ROOT / "LegalBot-Phase2A-2026-08-27-seminar-source-owner-approved"
CANDIDATE = PROJECT_ROOT / "data/indexes/builds" / BUILD_ID

TERMINAL_VERDICT = "PHASE 2A SAFELY STOPPED - PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED"
_FORBIDDEN = (
    b"/Users/",
    b"/private/",
    b"BEGIN PRIVATE KEY",
    b"BEGIN OPENSSH PRIVATE KEY",
    b"session_secret",
    b"csrf_secret",
)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _scan(raw: bytes) -> None:
    if any(marker in raw for marker in _FORBIDDEN):
        raise RuntimeError("machine package input contains forbidden private material")


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"required machine-package input is unavailable: {path.name}")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise RuntimeError(f"required machine-package input is invalid: {path.name}")
    return value


def _write_new(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _scan(raw)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _write_new_json(path: Path, value: Any) -> None:
    _write_new(path, _pretty_json(value))


def _copy_new(source: Path, destination: Path) -> None:
    if source.is_symlink() or not source.is_file():
        raise RuntimeError(f"machine package source is missing or unsafe: {source.name}")
    _write_new(destination, source.read_bytes())


def _sealed(value: dict[str, Any], *, field: str) -> dict[str, Any]:
    output = dict(value)
    output[field] = _sha256(_canonical_json(output))
    return output


def _csv_bytes(headers: list[str], rows: list[list[Any]]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(headers)
    writer.writerows(rows)
    return stream.getvalue().encode("utf-8")


def _git(*args: str, binary: bool = False) -> bytes | str:
    result = subprocess.run(
        ["git", *args],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
    )
    return result.stdout if binary else result.stdout.decode("utf-8", errors="strict").strip()


def _code_identity() -> dict[str, Any]:
    status_raw = _git("status", "--porcelain=v1", "-z", binary=True)
    assert isinstance(status_raw, bytes)
    entries = [item.decode("utf-8") for item in status_raw.split(b"\0") if item]
    diff_raw = _git("diff", "--binary", "--no-ext-diff", binary=True)
    assert isinstance(diff_raw, bytes)
    critical = (
        "backend/app/db.py",
        "backend/app/orchestration/index_worker.py",
        "backend/app/retrieval/candidate_qualification.py",
        "backend/app/retrieval/incomplete_index_audit.py",
        "backend/app/retrieval/index_build.py",
        "backend/app/retrieval/index_recovery.py",
        "backend/app/retrieval/index_stage_policy.py",
        "backend/app/retrieval/phase2a_frozen_scope.py",
        "backend/app/retrieval/phase2a_held_reattest.py",
        "backend/app/evaluation/phase2a_deterministic_qualification.py",
        "config/candidate_provision_qualification.v1.json",
        "scripts/reconcile_v111_phase2a_successor_resume_metadata.py",
        "scripts/roll_forward_v111_phase2a_candidate_qualification.py",
        "scripts/run_v111_phase2a_held_retrieval_reattest_repaired.py",
        "scripts/build_v111_phase2a_deterministic_all585_qualification.py",
    )
    hashes = {
        name: _sha256_file(PROJECT_ROOT / name)
        for name in critical
        if (PROJECT_ROOT / name).is_file()
    }
    return {
        "schema": "legalbot.v111.phase2a.code-identity-and-worktree-status.v1",
        "head_sha256": _git("rev-parse", "HEAD"),
        "branch": _git("branch", "--show-current"),
        "worktree_clean": not entries,
        "exact_head_verification_passed": not entries,
        "worktree_status_entry_count": len(entries),
        "worktree_status_entries": entries,
        "tracked_diff_sha256": _sha256(diff_raw),
        "critical_file_sha256s": dict(sorted(hashes.items())),
        "candidate_build_code_reproducible_from_clean_head_only": False,
        "note": (
            "The exact Git HEAD is recorded, but the working tree is dirty; this report does "
            "not describe the candidate as a clean-HEAD build."
        ),
    }


def _authorization_digests() -> dict[str, Any]:
    sources = {
        "deterministic_route_owner_choice_receipt": DETERMINISTIC_AUTH
        / "OWNER-CHOICE-RECEIPT.json",
        "seminar_source_owner_approval_receipt": SEMINAR_APPROVAL
        / "OWNER-APPROVAL-RECEIPT.json",
        "r94_owner_approval_receipt": OWNER_ROOT
        / "LegalBot-Phase2AB-2026-08-25-r95-substantive-owner-approved"
        / "OWNER-APPROVAL-RECEIPT-R94.json",
        "r111_owner_approval_receipt": OWNER_ROOT
        / "LegalBot-Phase2AB-2026-08-26-r113-post-r110-owner-approved"
        / "OWNER-APPROVAL-RECEIPT-R111.json",
        "consolidated_source_admission_package": ADMISSION / "PACKAGE-INDEX.json",
    }
    return {
        "schema": "legalbot.v111.phase2a.authorization-digest-register.v1",
        "records": [
            {
                "label": label,
                "relative_path": path.relative_to(PROJECT_ROOT).as_posix(),
                "file_sha256": _sha256_file(path),
            }
            for label, path in sorted(sources.items())
        ],
        "scope": "phase2a_only",
        "professional_legal_certification": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }


def _debug_register() -> dict[str, Any]:
    build_failure = _load_object(BUILD_FAILURE / "FAILURE-REPORT.json")
    retrieval_failure = _load_object(RETRIEVAL_R1 / "FAILURE-REPORT.json")
    return {
        "schema": "legalbot.v111.phase2a.debug-and-anti-loop-register.v1",
        "same_failure_third_attempts": 0,
        "incidents": [
            {
                "stage": "planner_flow",
                "status": "SEALED_EXCLUDED_FROM_ADMISSIBLE_SUBSTANTIVE_EVIDENCE",
                "finding": "38 rows exceeded the cumulative two-invocation cap",
                "repair": "owner-authorized deterministic-only route",
                "third_attempt": False,
            },
            {
                "stage": "successor_build",
                "failure_fingerprint": build_failure.get("failure_fingerprint"),
                "attempt_1": "lease_lost_after_3712_physical_rows",
                "debug": "exact-prefix reconciliation and heartbeat/lease hardening",
                "attempt_2": "passed_built_unscored",
                "third_attempt": False,
            },
            {
                "stage": "post_build_identity_audit",
                "finding": "resumed counters omitted the 3712-row prefix",
                "repair": "metadata-only compare-and-swap reconciliation",
                "candidate_bytes_changed": False,
                "third_attempt": False,
            },
            {
                "stage": "held_retrieval_reattestation",
                "failure_fingerprint": retrieval_failure.get("failure_fingerprint"),
                "attempt_1": "stopped_before_scoring_on_predecessor_build_binding",
                "debug": "same-four-record deterministic qualification roll-forward",
                "attempt_2": "passed_all_frozen_retrieval_gates",
                "third_attempt": False,
            },
        ],
        "planner_or_answer_model_used_in_deterministic_route": False,
        "active_or_previous_written": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }


def _copy_evidence() -> None:
    mapping = {
        "registries/COMPLETE-REMEDIATION-MATRIX-585.json": R47
        / "COMPLETE-REMEDIATION-MATRIX-585.json",
        "registries/COMPLETE-GOLD-CASE-RECONCILIATION-509.json": R47
        / "COMPLETE-GOLD-CASE-RECONCILIATION-509.json",
        "registries/COMPLETE-CANDIDATE-IMPACT-RECONCILIATION-76.json": R47
        / "COMPLETE-CANDIDATE-IMPACT-RECONCILIATION-76.json",
        "registries/COMPLETE-LEGISLATIVE-EFFECT-REGISTER-1896.json": R47
        / "COMPLETE-LEGISLATIVE-EFFECT-REGISTER-1896.json",
        "registries/COMPLETE-JUDGMENT-LATER-TREATMENT-REGISTER-20.json": R47
        / "COMPLETE-JUDGMENT-LATER-TREATMENT-REGISTER-20.json",
        "registries/COMPLETE-LEGISLATION-BYTE-MISMATCH-REGISTER-65.json": R47
        / "COMPLETE-LEGISLATION-BYTE-MISMATCH-REGISTER-65.json",
        "registries/UNAVAILABLE-OFFICIAL-RECORDS-3.json": R47
        / "UNAVAILABLE-OFFICIAL-RECORDS-3.json",
        "registries/SOURCE-CUSTODY-AND-ADMISSION-REGISTER.json": R47
        / "SOURCE-CUSTODY-AND-ADMISSION-REGISTER.json",
        "qualification/DETERMINISTIC-ALL585-QUALIFICATION.json": ALL585
        / "DETERMINISTIC-ALL585-QUALIFICATION.json",
        "qualification/ALL585-SUMMARY.json": ALL585 / "SUMMARY.json",
        "qualification/ALL585-PACKAGE-INDEX.json": ALL585 / "PACKAGE-INDEX.json",
        "crosswalk/DETERMINISTIC-EXACT-SPAN-PACKETS-364.json": CROSSWALK
        / "DETERMINISTIC-EXACT-SPAN-PACKETS-364.json",
        "crosswalk/APPROVED-142-SOURCE-CROSSWALK.json": CROSSWALK
        / "APPROVED-142-SOURCE-CROSSWALK.json",
        "crosswalk/PENDING-OUT-OF-PACKET-AUTHORITY-SCOPE.json": CROSSWALK
        / "PENDING-OUT-OF-PACKET-AUTHORITY-SCOPE.json",
        "source/FROZEN-SUCCESSOR-SOURCE-SCOPE.json": ADMISSION
        / "FROZEN-SUCCESSOR-SOURCE-SCOPE.json",
        "source/SOURCE-ADMISSION-PACKAGE-INDEX.json": ADMISSION / "PACKAGE-INDEX.json",
        "source/CONSOLIDATED-SOURCE-STAGING.json": STAGING
        / "CONSOLIDATED-SOURCE-STAGING.json",
        "source/SOURCE-STAGING-PACKAGE-INDEX.json": STAGING / "PACKAGE-INDEX.json",
        "candidate/approved-source-manifest.json": CANDIDATE / "approved-source-manifest.json",
        "candidate/manifest.json": CANDIDATE / "manifest.json",
        "candidate/seal.json": CANDIDATE / "seal.json",
        "candidate/evaluation.json": CANDIDATE / "evaluation.json",
        "candidate/privacy-report.json": CANDIDATE / "privacy-report.json",
        "candidate/candidate-provision-qualification.v1.json": PROJECT_ROOT
        / "config/candidate_provision_qualification.v1.json",
        "retrieval/HELD-RETRIEVAL-REATTESTATION.json": RETRIEVAL_R2
        / "HELD-RETRIEVAL-REATTESTATION.json",
        "retrieval/RETRIEVAL-SUMMARY.json": RETRIEVAL_R2 / "SUMMARY.json",
        "retrieval/RETRIEVAL-PACKAGE-INDEX.json": RETRIEVAL_R2 / "PACKAGE-INDEX.json",
        "debug/RETRIEVAL-ATTEMPT-1-FAILURE.json": RETRIEVAL_R1 / "FAILURE-REPORT.json",
        "debug/RETRIEVAL-ATTEMPT-1-PACKAGE-INDEX.json": RETRIEVAL_R1
        / "PACKAGE-INDEX.json",
        "debug/SUCCESSOR-BUILD-ATTEMPT-1-FAILURE.json": BUILD_FAILURE
        / "FAILURE-REPORT.json",
        "debug/SUCCESSOR-BUILD-RECOVERY-SUMMARY.json": BUILD_RECOVERY / "SUMMARY.json",
        "debug/SUCCESSOR-BUILD-CHECKPOINT-RECONCILIATION.json": BUILD_RECOVERY
        / "CHECKPOINT-RECONCILIATION.json",
        "debug/SUCCESSOR-BUILD-RECOVERY-PACKAGE-INDEX.json": BUILD_RECOVERY
        / "PACKAGE-INDEX.json",
        "debug/RESUME-METADATA-RECONCILIATION.json": METADATA_REPAIR
        / "RECONCILIATION.json",
        "debug/RESUME-METADATA-PACKAGE-INDEX.json": METADATA_REPAIR
        / "PACKAGE-INDEX.json",
        "debug/CANDIDATE-QUALIFICATION-ROLL-FORWARD.json": QUALIFICATION_REPAIR
        / "ROLL-FORWARD.json",
        "debug/CANDIDATE-QUALIFICATION-ROLL-FORWARD-PACKAGE-INDEX.json": (
            QUALIFICATION_REPAIR / "PACKAGE-INDEX.json"
        ),
        "debug/PLANNER-CAP-CORRECTIVE-AUDIT.json": PLANNER_AUDIT
        / "PLANNER-CAP-CORRECTIVE-AUDIT.json",
        "debug/PLANNER-OVER-CAP-ROW-INVENTORY.json": PLANNER_AUDIT
        / "OVER-CAP-ROW-INVENTORY.json",
        "debug/PLANNER-PROCESS-QUIESCENCE.json": PLANNER_AUDIT / "PROCESS-QUIESCENCE.json",
    }
    # Validate the complete immutable input set before the first package write.  A
    # failed preflight therefore cannot leave a deceptively partial evidence set.
    for source in mapping.values():
        if source.is_symlink() or not source.is_file():
            raise RuntimeError(
                f"machine package source is missing or unsafe: {source.name}"
            )
        _scan(source.read_bytes())
    for relative, source in mapping.items():
        _copy_new(source, MACHINE_ROOT / relative)


def main() -> None:
    if FINAL_ROOT.exists():
        raise FileExistsError("final blocked owner-review package already exists")
    MACHINE_ROOT.mkdir(parents=True, mode=0o700)
    _copy_evidence()

    qualification = _load_object(ALL585 / "DETERMINISTIC-ALL585-QUALIFICATION.json")
    summary = _load_object(ALL585 / "SUMMARY.json")
    source_manifest = _load_object(CANDIDATE / "approved-source-manifest.json")
    retrieval = _load_object(RETRIEVAL_R2 / "HELD-RETRIEVAL-REATTESTATION.json")
    if (
        qualification.get("issue_count") != 585
        or qualification.get("case_count") != 60
        or qualification.get("phase2a_technical_qualification_passed") is not False
        or qualification.get("terminal_verdict") != TERMINAL_VERDICT
        or summary.get("status_counts")
        != {
            "BLOCKED_MATERIAL_GAP": 98,
            "OWNER_DECISION_REQUIRED": 263,
            "TECHNICALLY_EVIDENCE_READY_FOR_OWNER_ADOPTION": 224,
        }
        or retrieval.get("retrieval_quality_passed") is not True
        or source_manifest.get("source_count") != 251
        or source_manifest.get("chunk_count") != 222_200
    ):
        raise RuntimeError("final blocked package inputs changed")

    rows = qualification["rows"]
    blocked = [row for row in rows if row["qualification_status"] == "BLOCKED_MATERIAL_GAP"]
    decisions = [
        row for row in rows if row["qualification_status"] == "OWNER_DECISION_REQUIRED"
    ]
    headers = [
        "ordinal",
        "row_id",
        "case_id",
        "issue_id",
        "legal_domain",
        "issue_label",
        "qualification_status",
        "basis_class",
        "candidate_evidence_packet_count",
        "record_content_sha256",
    ]

    def issue_values(row: dict[str, Any]) -> list[Any]:
        basis = row.get("basis") or {}
        return [
            row.get("ordinal"),
            row.get("row_id"),
            row.get("case_id"),
            row.get("issue_id"),
            row.get("legal_domain"),
            row.get("issue_label"),
            row.get("qualification_status"),
            basis.get("basis_class"),
            basis.get("candidate_evidence_packet_count"),
            row.get("record_content_sha256"),
        ]

    _write_new(
        MACHINE_ROOT / "review/UNRESOLVED-MATERIAL-GAPS-98.csv",
        _csv_bytes(headers, [issue_values(row) for row in blocked]),
    )
    _write_new(
        MACHINE_ROOT / "review/OWNER-DECISIONS-REQUIRED-263.csv",
        _csv_bytes(headers, [issue_values(row) for row in decisions]),
    )
    _write_new(
        MACHINE_ROOT / "review/CASE-QUALIFICATION-SUMMARY-60.csv",
        _csv_bytes(
            ["case_id", "issue_count", "all_issues_technically_ready", "status_counts_json"],
            [
                [
                    case["case_id"],
                    case["issue_count"],
                    case["all_issues_technically_ready"],
                    json.dumps(case["status_counts"], sort_keys=True),
                ]
                for case in qualification["cases"]
            ],
        ),
    )
    source_headers = [
        "source_version_id",
        "authority_identity_id",
        "stable_identifier",
        "title",
        "source_date",
        "last_updated",
        "currentness_verified",
        "subsequent_treatment_check_required",
        "subsequent_treatment_verified",
        "full_current_law_verification_eligible",
    ]
    _write_new(
        MACHINE_ROOT / "review/SOURCE-CURRENTNESS-AND-LATER-TREATMENT-HOLDS-251.csv",
        _csv_bytes(
            source_headers,
            [
                [source.get(field) for field in source_headers]
                for source in source_manifest["sources"]
            ],
        ),
    )

    verdict = _sealed(
        {
            "schema": "legalbot.v111.phase2a.final-blocked-verdict.v1",
            "route": "OWNER_ADOPTED_INTERNAL_DETERMINISTIC_ONLY",
            "professional_legal_certification": False,
            "case_count": 60,
            "issue_count": 585,
            "status_counts": summary["status_counts"],
            "candidate_identity": summary["candidate_identity"],
            "retrieval_reattestation": summary["retrieval_reattestation"],
            "source_holds": summary["successor_source_holds"],
            "material_blockers": summary["material_blockers"],
            "common_legal_currentness_cutoff": None,
            "phase2a_technical_qualification_passed": False,
            "successful_phase2a_adoption_payload_available": False,
            "phase2b_eligible": False,
            "development30_eligible": False,
            "validation_or_live_eligible": False,
            "active_or_previous_written": False,
            "terminal_verdict": TERMINAL_VERDICT,
        },
        field="verdict_content_sha256",
    )
    _write_new_json(MACHINE_ROOT / "FINAL-PHASE2A-VERDICT.json", verdict)
    _write_new_json(MACHINE_ROOT / "AUTHORIZATION-DIGESTS.json", _authorization_digests())
    _write_new_json(MACHINE_ROOT / "DEBUG-AND-ANTI-LOOP-REGISTER.json", _debug_register())
    _write_new_json(MACHINE_ROOT / "CODE-IDENTITY-AND-WORKTREE-STATUS.json", _code_identity())
    _write_new_json(
        MACHINE_ROOT / "ADVISORY-AI-AUDIT.json",
        {
            "schema": "legalbot.v111.phase2a.advisory-ai-audit.v1",
            "route": "deterministic_only",
            "official_source_and_deterministic_checks_first": True,
            "planner_or_advisory_model_invoked_for_final_route": False,
            "answer_generation_model_invoked": False,
            "retrieval_embedding_and_reranker_used": True,
            "retrieval_models_are_not_substantive_owner_reviewers": True,
            "prior_over_cap_planner_outputs_admissible": False,
            "reviewer_model_independent_from_drafting": None,
            "reviewer_status": "UNAVAILABLE_NOT_INVOKED_DETERMINISTIC_ROUTE",
            "owner_adopted_qualification_assigned_by_ai": False,
        },
    )
    _write_new_json(
        MACHINE_ROOT / "OWNER-REVIEW-ACTIONS.json",
        {
            "schema": "legalbot.v111.phase2a.owner-review-actions.v1",
            "status": "MATERIAL_REMEDIATION_REQUIRED",
            "actions": [
                {"code": "RESEARCH_EXACT_SPANS", "issue_count": 98},
                {"code": "MAKE_SUBSTANTIVE_OWNER_SELECTIONS", "issue_count": 263},
                {"code": "VERIFY_SOURCE_CURRENTNESS", "source_count": 186},
                {"code": "COMPLETE_LATER_TREATMENT_REVIEW", "source_count": 135},
            ],
            "counts_may_overlap": True,
            "successful_phase2a_digest_adoption_available": False,
            "phase2b_available_now": False,
            "next_gate": "new_digest_bound_owner_decisions_after_remaining_evidence_is_prepared",
        },
    )
    _write_new_json(
        MACHINE_ROOT / "UNSIGNED-OWNER-ACKNOWLEDGEMENT-DRAFT.json",
        {
            "schema": "legalbot.v111.phase2a.unsigned-owner-acknowledgement-draft.v1",
            "status": "ACKNOWLEDGEMENT_ONLY_NOT_PHASE2A_ADOPTION",
            "draft_text": (
                "I acknowledge receipt of the exact blocked Phase-2A owner-review package. "
                "This acknowledgement does not adopt Phase 2A, authorize Phase 2B, or "
                "authorize Development 30."
            ),
            "signature_requested": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        },
    )
    readme = (
        "LegalBot v1.11 Phase 2A final blocked owner-review machine package\n\n"
        f"Verdict: {TERMINAL_VERDICT}\n\n"
        "This package is non-authorizing. It contains no source blobs, vectors, private "
        "keys, session/CSRF secrets, private review roots, model socket, split secret, "
        "ACTIVE/PREVIOUS pointer, Development payload, Validation material or live state.\n"
    ).encode()
    _write_new(MACHINE_ROOT / "README.txt", readme)

    files = {
        path.relative_to(MACHINE_ROOT).as_posix(): {
            "sha256": _sha256_file(path),
            "bytes": path.stat().st_size,
        }
        for path in sorted(MACHINE_ROOT.rglob("*"))
        if path.is_file() and path.name not in {"MACHINE-PACKAGE-INDEX.json", "SHA256SUMS.txt"}
    }
    package = _sealed(
        {
            "schema": "legalbot.v111.phase2a.final-blocked-machine-package.v1",
            "run_name": RUN_NAME,
            "created_at": datetime.now(UTC).isoformat(),
            "status": "COMPLETE_NON_AUTHORIZING_BLOCKED_PHASE2A_EVIDENCE",
            "terminal_verdict": TERMINAL_VERDICT,
            "file_count": len(files),
            "files": files,
            "case_count": 60,
            "issue_count": 585,
            "status_counts": summary["status_counts"],
            "candidate_build_id": BUILD_ID,
            "retrieval_quality_passed": True,
            "phase2a_technical_qualification_passed": False,
            "successful_phase2a_adoption_payload_available": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
            "active_or_previous_written": False,
            "private_paths_included": False,
            "secrets_or_private_keys_included": False,
            "source_blobs_or_vectors_included": False,
        },
        field="machine_package_content_sha256",
    )
    _write_new_json(MACHINE_ROOT / "MACHINE-PACKAGE-INDEX.json", package)
    sums = "\n".join(
        f"{_sha256_file(path)}  {path.relative_to(MACHINE_ROOT).as_posix()}"
        for path in sorted(MACHINE_ROOT.rglob("*"))
        if path.is_file() and path.name != "SHA256SUMS.txt"
    )
    _write_new(MACHINE_ROOT / "SHA256SUMS.txt", (sums + "\n").encode())
    print(
        json.dumps(
            {
                "status": package["status"],
                "machine_root": str(MACHINE_ROOT),
                "file_count": package["file_count"],
                "machine_package_content_sha256": package[
                    "machine_package_content_sha256"
                ],
                "terminal_verdict": TERMINAL_VERDICT,
            },
            indent=2,
            sort_keys=True,
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
