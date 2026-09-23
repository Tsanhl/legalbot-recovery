"""Fail-closed verification for the question-free new unseen-bank design."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DESIGN_ID = "LegalBot-GE-2026-09-04-new-unseen-bank-design-r1"
DEFAULT_ROOT = (
    Path(__file__).resolve().parents[3]
    / "data/evaluations/general-enquiries"
    / DESIGN_ID
)
EXPECTED_FILES = {
    "ARTIFACT-SHA256-REGISTER.json",
    "NEW-UNSEEN-BANK-DESIGN.json",
    "OWNER-GATE.md",
    "README.md",
    "STATE-TRANSITION-RECEIPT.json",
}


class NewUnseenBankDesignVerificationError(RuntimeError):
    """Raised when the design package no longer matches its safe proposal state."""


@dataclass(frozen=True)
class VerifiedNewUnseenBankDesign:
    design_id: str
    legal_case_count: int
    system_case_count: int
    overall_state: str
    bank_created: bool
    execution_authorized: bool


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_sealed(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    claimed = str(value.pop("content_sha256", ""))
    actual = hashlib.sha256(_canonical(value)).hexdigest()
    if claimed != actual:
        raise NewUnseenBankDesignVerificationError(f"content seal mismatch: {path.name}")
    value["content_sha256"] = claimed
    return value


def verify_design_package(
    root: Path = DEFAULT_ROOT,
) -> VerifiedNewUnseenBankDesign:
    files = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}
    if files != EXPECTED_FILES:
        raise NewUnseenBankDesignVerificationError("unexpected or missing design artifact")

    register = json.loads((root / "ARTIFACT-SHA256-REGISTER.json").read_text())
    actual = {
        name: _sha256_file(root / name)
        for name in sorted(EXPECTED_FILES - {"ARTIFACT-SHA256-REGISTER.json"})
    }
    if register.get("artifacts") != actual:
        raise NewUnseenBankDesignVerificationError("artifact register mismatch")

    design = _load_sealed(root / "NEW-UNSEEN-BANK-DESIGN.json")
    state = _load_sealed(root / "STATE-TRANSITION-RECEIPT.json")
    if design.get("design_id") != DESIGN_ID or state.get("design_id") != DESIGN_ID:
        raise NewUnseenBankDesignVerificationError("design identity mismatch")
    if design.get("contains_question_text") is not False:
        raise NewUnseenBankDesignVerificationError("question text must be absent")
    if design.get("contains_answer_text") is not False:
        raise NewUnseenBankDesignVerificationError("answer text must be absent")
    if design.get("bank_created") is not False or state.get("new_unseen_bank") != "NOT_CREATED":
        raise NewUnseenBankDesignVerificationError("bank creation is not authorized")
    if state.get("new_unseen_execution") != "NOT_AUTHORIZED_NOT_STARTED":
        raise NewUnseenBankDesignVerificationError("execution is not authorized")
    if state.get("answer_weight_training") != "NOT_AUTHORIZED_NOT_PERFORMED":
        raise NewUnseenBankDesignVerificationError("training is not authorized")
    if state.get("r2_adapter") != "INACTIVE_NOT_USED":
        raise NewUnseenBankDesignVerificationError("adapter must remain inactive")
    if design.get("legal_case_count") != 92 or design.get("domain_count") != 23:
        raise NewUnseenBankDesignVerificationError("legal-bank denominator mismatch")
    if design.get("separate_system_case_count") != 23:
        raise NewUnseenBankDesignVerificationError("system-bank denominator mismatch")

    return VerifiedNewUnseenBankDesign(
        design_id=DESIGN_ID,
        legal_case_count=92,
        system_case_count=23,
        overall_state=str(state["overall_state"]),
        bank_created=False,
        execution_authorized=False,
    )
