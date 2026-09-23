"""Verify the completed one-pass GE sealed-unseen Codex evaluation.

The verifier is intentionally read-only.  It cannot reopen the bank, generate an
answer, change a score, authorize training, or turn the AI result into legal gold.
"""

from __future__ import annotations

import hashlib
import json
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .ge_currentness_packets import PROJECT_ROOT

CAMPAIGN_ID = "LegalBot-GE-2026-09-04-sealed-unseen-codex-evaluation-r1"
CORRECTION_ID = "LegalBot-GE-2026-09-04-sealed-unseen-integrity-correction-r1"
SUMMARY_CORRECTION_ID = (
    "LegalBot-GE-2026-09-04-sealed-unseen-public-summary-correction-r1"
)
DEFAULT_PUBLIC_ROOT = PROJECT_ROOT / "data/evaluations/general-enquiries" / CAMPAIGN_ID
DEFAULT_CORRECTION_ROOT = PROJECT_ROOT / "data/evaluations/general-enquiries" / CORRECTION_ID
DEFAULT_SUMMARY_CORRECTION_ROOT = (
    PROJECT_ROOT / "data/evaluations/general-enquiries" / SUMMARY_CORRECTION_ID
)

EXPECTED_STATE_SHA256 = "8fddc8b4d461dbdb58cff2531e7688fe03eb0d2ff00c17e8d473e65b115d0244"
EXPECTED_METRIC_SHA256 = "93f1ecfc424fb9c4412937e847f829b65c54f9dbfa6ab02d77c3b0867436eb4e"
EXPECTED_CORRECTION_SHA256 = "3f1f7f01c5cf82ae09989b76315d54f2aaa90d80e3416b74d0fceee4d88db454"
EXPECTED_SUMMARY_CORRECTION_SHA256 = (
    "1548321233e26eb56d9eec2e8ae4d47e5ed91760f3303e76fdb4382b8edd1e28"
)
EXPECTED_PRIVATE_ROOT_IDENTITY_SHA256 = (
    "6640e0e011be976a71730d5a941cfab621bb23bf9384b0ba8b53b70bfe0c6d1d"
)

_PRIVATE_FIELDS = {
    "prompt",
    "candidate_answer",
    "question_id",
    "claim",
    "exact_excerpt",
    "official_url",
    "authorization_text",
}


class SealedUnseenVerificationError(RuntimeError):
    """The completed one-pass receipt does not match its frozen contract."""


@dataclass(frozen=True, slots=True)
class SealedUnseenVerification:
    overall_state: str
    overall_pass_count: int
    overall_hold_count: int
    terminal_disposition_count: int
    private_run_verified: bool


def _canonical_json(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise SealedUnseenVerificationError(f"{path.name} is not a JSON object")
    return value


def _verify_content_seal(value: dict[str, Any], *, label: str) -> None:
    claimed = value.get("content_sha256")
    material = dict(value)
    material.pop("content_sha256", None)
    actual = hashlib.sha256(_canonical_json(material)).hexdigest()
    if claimed != actual:
        raise SealedUnseenVerificationError(f"{label} content seal mismatch")


def _keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for item in value.values() for key in _keys(item)}
    if isinstance(value, list):
        return {key for item in value for key in _keys(item)}
    return set()


def _verify_register(root: Path, *, private: bool) -> None:
    register_path = root / "ARTIFACT-SHA256-REGISTER.json"
    register = _load_json(register_path)
    artifacts = register.get("artifacts")
    if not isinstance(artifacts, dict):
        raise SealedUnseenVerificationError("artifact register is malformed")
    actual = {
        path.relative_to(root).as_posix(): _sha256(path)
        for path in sorted(root.rglob("*"))
        if path.is_file() and path != register_path
    }
    if artifacts != actual:
        raise SealedUnseenVerificationError("artifact register does not match the directory")
    if private:
        bad_directories = [
            path
            for path in (root, *(item for item in root.rglob("*") if item.is_dir()))
            if stat.S_IMODE(path.stat().st_mode) != 0o700
        ]
        bad_files = [
            path
            for path in root.rglob("*")
            if path.is_file() and stat.S_IMODE(path.stat().st_mode) != 0o600
        ]
        if bad_directories or bad_files:
            raise SealedUnseenVerificationError("private artifact permissions changed")


def _verify_root_identity(root: Path) -> str:
    # Import lazily because the governance package imports evaluation modules.
    from app.governance.v111_decision_generation import private_root_identity

    return private_root_identity(root, project_root=PROJECT_ROOT)


def verify_completed_campaign(
    *,
    public_root: Path = DEFAULT_PUBLIC_ROOT,
    correction_root: Path = DEFAULT_CORRECTION_ROOT,
    summary_correction_root: Path = DEFAULT_SUMMARY_CORRECTION_ROOT,
    private_root: Path | None = None,
) -> SealedUnseenVerification:
    """Verify aggregate closure and, when supplied, the owner-private run tree."""

    _verify_register(public_root, private=False)
    if _sha256(public_root / "STATE-TRANSITION-RECEIPT.json") != EXPECTED_STATE_SHA256:
        raise SealedUnseenVerificationError("state receipt identity changed")
    if _sha256(public_root / "METRIC-REPORT.json") != EXPECTED_METRIC_SHA256:
        raise SealedUnseenVerificationError("metric report identity changed")

    metric = _load_json(public_root / "METRIC-REPORT.json")
    state = _load_json(public_root / "STATE-TRANSITION-RECEIPT.json")
    for name, value in (("metric", metric), ("state", state)):
        _verify_content_seal(value, label=name)
    if _keys(metric) & _PRIVATE_FIELDS or _keys(state) & _PRIVATE_FIELDS:
        raise SealedUnseenVerificationError("private case content entered the public receipts")
    if (
        metric.get("case_count") != 306
        or metric.get("terminal_disposition_count") != 306
        or metric.get("overall_pass_count") != 157
        or metric.get("overall_hold_count") != 149
        or metric.get("candidate_factual_pass_count") != 160
        or metric.get("candidate_quality_70_floor_pass_count") != 157
        or metric.get("declared_material_claim_count") != 540
        or metric.get("reviewed_material_claim_count") != 540
        or metric.get("case_disposition_coverage_pct") != 100.0
        or metric.get("material_claim_review_coverage_pct") != 100.0
        or sum(metric.get("decision_counts", {}).values()) != 306
    ):
        raise SealedUnseenVerificationError("sealed-unseen metrics do not reconcile")
    if (
        state.get("overall_state") != "SEALED_UNSEEN_ONE_PASS_COMPLETE_HOLD_NO_REPAIR"
        or state.get("sealed_unseen_execution") != "COMPLETE_ONE_PASS_CONSUMED"
        or state.get("sealed_unseen_result") != "HOLD"
        or state.get("private_306_bank") != "OPENED_ONCE_AND_RETIRED_FROM_FRESH_UNSEEN_USE"
        or state.get("reexecution_permitted") is not False
        or state.get("unseen_findings_repair_eligible") is not False
        or state.get("unseen_findings_training_eligible") is not False
        or state.get("promotion") != "NOT_STARTED"
        or state.get("live") != "NOT_STARTED"
    ):
        raise SealedUnseenVerificationError("one-pass terminal controls changed")

    correction = _load_json(correction_root / "CORRECTION-RECEIPT.json")
    _verify_content_seal(correction, label="private-root correction")
    if (
        _sha256(correction_root / "CORRECTION-RECEIPT.json") != EXPECTED_CORRECTION_SHA256
        or correction.get("source_state_transition_receipt_sha256") != EXPECTED_STATE_SHA256
        or correction.get("canonical_private_root_identity_sha256")
        != EXPECTED_PRIVATE_ROOT_IDENTITY_SHA256
        or correction.get("execution_rerun") is not False
        or correction.get("metrics_changed") is not False
    ):
        raise SealedUnseenVerificationError("private-root correction changed")

    _verify_register(summary_correction_root, private=False)
    summary_correction = _load_json(summary_correction_root / "CORRECTION-RECEIPT.json")
    _verify_content_seal(summary_correction, label="public-summary correction")
    if (
        _sha256(summary_correction_root / "CORRECTION-RECEIPT.json")
        != EXPECTED_SUMMARY_CORRECTION_SHA256
        or summary_correction.get("source_state_receipt_sha256") != EXPECTED_STATE_SHA256
        or summary_correction.get("execution_rerun") is not False
        or summary_correction.get("metrics_changed") is not False
        or summary_correction.get("state_changed") is not False
    ):
        raise SealedUnseenVerificationError("public-summary correction changed")
    for name in ("OWNER-AUTHORIZATION-SUMMARY.json", "PROMPT-DISCLOSURE-SUMMARY.json"):
        summary = _load_json(summary_correction_root / name)
        _verify_content_seal(summary, label=name)
        if _keys(summary) & _PRIVATE_FIELDS:
            raise SealedUnseenVerificationError("private content entered corrected summary")

    private_verified = False
    if private_root is not None:
        if _verify_root_identity(private_root) != EXPECTED_PRIVATE_ROOT_IDENTITY_SHA256:
            raise SealedUnseenVerificationError("owner-private root identity changed")
        private_run = private_root / "runs/2026-09-04" / CAMPAIGN_ID
        _verify_register(private_run, private=True)
        if _sha256(private_run / "STATE-TRANSITION-RECEIPT.json") != EXPECTED_STATE_SHA256:
            raise SealedUnseenVerificationError("private and public state receipts differ")
        if _sha256(private_run / "METRIC-REPORT.json") != EXPECTED_METRIC_SHA256:
            raise SealedUnseenVerificationError("private and public metric reports differ")
        private_verified = True

    return SealedUnseenVerification(
        overall_state=str(state["overall_state"]),
        overall_pass_count=int(metric["overall_pass_count"]),
        overall_hold_count=int(metric["overall_hold_count"]),
        terminal_disposition_count=int(metric["terminal_disposition_count"]),
        private_run_verified=private_verified,
    )


__all__ = [
    "CAMPAIGN_ID",
    "CORRECTION_ID",
    "SUMMARY_CORRECTION_ID",
    "SealedUnseenVerification",
    "SealedUnseenVerificationError",
    "verify_completed_campaign",
]
