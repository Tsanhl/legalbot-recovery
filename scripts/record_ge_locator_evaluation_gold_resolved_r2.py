#!/usr/bin/env python3
"""Record the owner-adopted 67-locator evaluation-gold resolution. Create-only.

This is locator-level evaluation gold only. It is not qualified legal review,
answer gold, runtime admission, weight training, unseen, promotion or live.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.evaluation.ge_locator_gold_overlay import split_locator_label

ROOT = Path(__file__).resolve().parents[1]
PACK = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-per-locator-evaluation-gold-resolved-r2"
)
DECISIONS = PACK / "LegalBot-GE-2026-09-02-Per-Locator-Evaluation-Gold-Resolved-r2.json"
DOCX = ROOT / "output/docx/LegalBot-GE-2026-09-02-Per-Locator-Evaluation-Gold-Resolved-r2.docx"
PROMPT = PACK / "LegalBot-GE-Phase2-Continue-Evaluation-No-Global-Stall-Prompt-r2.md"
DRAFT = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-per-locator-gold-draft-r1"
    / "LOCATOR-GOLD-DRAFT.json"
)
EXPECTED_DOCX = "a6f512012973d96860c379ac045e88fe6d3c10b219359031a18076c68d2b3594"
EXPECTED_JSON = "993e54d39c38adaaf620e82756262ba412d78c7aaceb5e4a18398429e5ef4257"
EXPECTED_PROMPT = "0a7dbc88888d4715d9c3debdc9ab764b983ef326bee46b41cb9ecf76e42c17a1"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


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


def _digest(value: dict[str, Any]) -> dict[str, Any]:
    body = {key: item for key, item in value.items() if key != "content_sha256"}
    result = dict(value)
    result["content_sha256"] = hashlib.sha256(_canonical_bytes(body)).hexdigest()
    return result


def main() -> int:
    for path, expected in (
        (DOCX, EXPECTED_DOCX),
        (DECISIONS, EXPECTED_JSON),
        (PROMPT, EXPECTED_PROMPT),
    ):
        got = _sha256_file(path)
        if got != expected:
            raise RuntimeError(f"hash mismatch for {path.name}: {got}")
    if not DRAFT.is_file():
        raise RuntimeError("unsigned gold draft r1 is missing")
    raw = json.loads(DECISIONS.read_text(encoding="utf-8"))
    rows_in = raw.get("rows")
    if not isinstance(rows_in, list) or len(rows_in) != 67:
        raise RuntimeError("resolved locator rows are not the 67-row pack")
    locators: list[dict[str, Any]] = []
    for item in rows_in:
        if not isinstance(item, dict):
            raise RuntimeError("locator row is invalid")
        combined = str(item.get("locator") or "")
        title, pin = split_locator_label(combined)
        decision = str(item.get("owner_evaluation_decision") or "")
        approve = decision == "APPROVE"
        pit = "2024-01-15" if "15 january 2024" in combined.casefold() else None
        locators.append(
            {
                "ordinal": item.get("ordinal"),
                "combined_locator": combined,
                "title": title,
                "locator": pin,
                "owner_signed": True,
                "owner_decision": decision,
                "effects_reviewed": approve,
                "provision_extent_status": "verified" if approve else "unverified",
                "currentness_reviewed_as_of_date": "2026-08-28",
                "evaluation_as_of_date": "2026-08-28",
                "point_in_time_as_at": pit,
                "locator_evaluation_gold": approve,
                "legal_gold": False,
                "admitted": False,
                "runtime_admitted": False,
                "full_current_law_eligible": False,
                "qualified_legal_review": False,
                "answer_legal_gold": False,
                "mandatory_evidence_route": decision != "REJECT",
                "decision_scope": str(item.get("decision_scope") or ""),
            }
        )
    counts = {
        "locators": len(locators),
        "APPROVE": sum(row["owner_decision"] == "APPROVE" for row in locators),
        "HOLD": sum(row["owner_decision"] == "HOLD" for row in locators),
        "REJECT": sum(row["owner_decision"] == "REJECT" for row in locators),
        "PENDING": sum(row["owner_decision"] == "PENDING" for row in locators),
    }
    if counts != {"locators": 67, "APPROVE": 66, "HOLD": 0, "REJECT": 1, "PENDING": 0}:
        raise RuntimeError(f"unexpected locator counts: {counts}")

    recorded_at = datetime.now(UTC).isoformat()
    receipt = _digest(
        {
            "schema": "legalbot.ge-owner-locator-evaluation-decision-receipt.v1",
            "recorded_at_utc": recorded_at,
            "classification": "AI_ASSISTED_OWNER_ADVISORY_EVALUATION_DECISION_THEN_OWNER_ADOPTED",
            "owner_adopted": True,
            "owner_pack_signed": True,
            "signature_status": "session_instruction_hash_bound_not_cryptographic_signature",
            "decision_json_file_sha256": EXPECTED_JSON,
            "decision_docx_file_sha256": EXPECTED_DOCX,
            "continuation_prompt_file_sha256": EXPECTED_PROMPT,
            "evaluation_as_of_date": "2026-08-28",
            "counts": counts,
            "meaning": {
                "APPROVE": "locator_evaluation_gold only; not answer gold or qualified review",
                "REJECT": "remove from the mandatory evaluation evidence route; not a finding of bad law",
            },
            "boundaries": {
                "qualified_legal_review": False,
                "answer_legal_gold": False,
                "legal_gold": False,
                "runtime_admitted": False,
                "full_current_law_eligible": False,
                "answer_weight_training": False,
                "sealed_unseen_execution": False,
                "promotion": False,
                "live": False,
            },
            "unsigned_draft_preserved": DRAFT.as_posix(),
            "do_not_retick_unsigned_draft": True,
        }
    )
    register = _digest(
        {
            "schema": "legalbot.ge-locator-evaluation-gold-register.v1",
            "evaluation_as_of_date": "2026-08-28",
            "owner_pack_signed": True,
            "owner_adopted": True,
            "receipt_content_sha256": receipt["content_sha256"],
            "decision_json_file_sha256": EXPECTED_JSON,
            "locators": locators,
            "counts": counts,
            "non_authorizing": {
                "qualified_legal_review": False,
                "legal_gold": False,
                "admitted": False,
                "full_current_law_eligible": False,
            },
        }
    )
    receipt_path = PACK / "OWNER-LOCATOR-EVALUATION-DECISION-RECEIPT.json"
    register_path = PACK / "LOCATOR-EVALUATION-GOLD-REGISTER.json"
    readme_path = PACK / "README.md"
    _write_json(receipt_path, receipt)
    _write_json(register_path, register)
    _write_text(
        readme_path,
        (
            "# Per-locator evaluation-gold resolution r2\n\n"
            "Owner-adopted hash-bound receipt of the 67-locator evaluation "
            "package. APPROVE is locator-level evaluation gold only. The unsigned "
            "all-PENDING draft r1 is preserved and must not be reticked.\n\n"
            f"- decision JSON file SHA-256 `{EXPECTED_JSON}`\n"
            f"- DOCX SHA-256 `{EXPECTED_DOCX}`\n"
            f"- counts: 66 APPROVE, 0 HOLD, 1 REJECT, 0 PENDING\n"
            "- Cable & Wireless is REJECT from the mandatory evaluation evidence route.\n"
            "- Case 312 validity remains HOLD / fact-dependent and is not a global stall.\n"
        ),
    )
    os.chmod(PACK, stat.S_IRWXU)
    print(json.dumps({"receipt": receipt["content_sha256"], "register": register["content_sha256"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
