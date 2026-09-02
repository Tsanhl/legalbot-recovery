#!/usr/bin/env python3
"""Record the owner 331 diagnostic-rerun authorization. Create-only. Not gold."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PACK = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-visible-331-rerun-authorization-r1"
)
ADOPTION = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-owner-adoption-r1"
    / "OWNER-ADOPTION.json"
)
EXPECTED_ADOPTION = "f9f71c875b709c89a4af6d43f2ad9750269e1f9a46b93d29e64602e47c686543"


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


def main() -> int:
    if PACK.exists() or PACK.is_symlink():
        raise FileExistsError(f"create-only pack exists: {PACK}")
    adoption = json.loads(ADOPTION.read_text(encoding="utf-8"))
    if adoption["content_sha256"] != EXPECTED_ADOPTION:
        raise RuntimeError("adoption receipt mutated")
    PACK.mkdir(parents=True, mode=0o700)
    os.chmod(PACK, stat.S_IRWXU)
    receipt = _digest(
        {
            "schema": "legalbot.ge-visible-331-rerun-authorization.v1",
            "recorded_at_utc": datetime.now(UTC).isoformat(),
            "disposition": "OWNER_AUTHORIZATION_VISIBLE_331_DIAGNOSTIC_EVALUATION_RERUN",
            "phase": "evaluation",
            "evaluation_state": True,
            "owner_adoption_content_sha256": EXPECTED_ADOPTION,
            "owner_approves_factual_first_gate": True,
            "owner_statement": (
                "Owner authorized the 331 rerun and approved the factual-first "
                "evaluation gate. This remains evaluation. Fact-checking is the "
                "evaluation method; it does not itself make a source admitted, "
                "full-current-law eligible, qualified legal review, or legal gold."
            ),
            "authorized": {
                "visible_331_diagnostic_rerun": True,
                "factual_first_evaluation_gate": True,
            },
            "qualified_legal_review": False,
            "legal_gold": False,
            "admitted": False,
            "full_current_law_eligible": False,
            "answer_weight_training": False,
            "sealed_unseen": False,
            "fresh_unseen": False,
            "promotion": False,
            "live": False,
            "why_those_remain_false": {
                "qualified_legal_review": "Owner process approval is not the qualified England-and-Wales legal-reviewer identity or second review.",
                "legal_gold": "Gold still requires exact reviewed spans, currentness, extent and an adopted gold decision per case.",
                "admitted": "Staging capture is not runtime catalogue admission.",
                "full_current_law_eligible": "The adopted batch hold remains: reviewed through 2026-08-14, cutoff 2026-08-28 unconfirmed, no per-locator qualification receipt.",
                "answer_weight_training": "No gold corpus and no separate weight-training authorization.",
                "sealed_unseen": "The 306 private bank stays sealed; the previous 60 are exposed regression only.",
                "promotion": "Phase 3 / live-last remains withheld.",
                "live": "Phase 3 / live-last remains withheld.",
            },
        }
    )
    _write_json(PACK / "AUTHORIZATION.json", receipt)
    _write_text(
        PACK / "README.md",
        """# Visible 331 diagnostic rerun authorization

The owner authorized a factual-first evaluation rerun of the 331 visible cases.

This is still evaluation. It is not gold, admission, qualified legal review,
weight training, unseen disclosure, promotion or live.
""",
    )
    print(json.dumps({"pack": str(PACK), "content_sha256": receipt["content_sha256"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
