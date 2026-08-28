#!/usr/bin/env python3
"""Record Agnes's Option-A deterministic-only Phase-2A methodology choice."""

from __future__ import annotations

import argparse
import json
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
for root in (PROJECT_ROOT, BACKEND_ROOT):
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

from scripts import plan_v111_phase2a_material_gap_research as planner  # noqa: E402

REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
AUDIT_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2A-2026-08-27-planner-cap-corrective-audit-v2"
    / "PLANNER-CAP-CORRECTIVE-AUDIT.json"
)
DEFAULT_OUTPUT = REVIEW_ROOT / "LegalBot-Phase2A-2026-08-27-deterministic-only-owner-authorized"
EXPECTED_AUDIT_CONTENT_SHA256 = "402a4d702e0d2f2422e48b527e9e17bd5b25f5e8eecec009bd6337405bebc33d"
PARTIAL_AUDIT_CONTENT_SHA256 = "9dd23e03e8579b55a1a06941e00599e897a0c8ef926c30775564bc227acf0711"


def _load_audit(path: Path = AUDIT_PATH) -> dict[str, Any]:
    value = planner._load_object(path)
    observed = planner._verify_seal(
        value,
        "artifact_content_sha256",
        "phase2a_deterministic_owner_choice_audit_seal_invalid",
    )
    if (
        observed != EXPECTED_AUDIT_CONTENT_SHA256
        or value.get("schema") != "legalbot.v111.phase2a.planner-cap-corrective-audit.v2"
        or value.get("status") != "PHASE_2A_SAFELY_STOPPED_OWNER_INPUT_REQUIRED"
        or value.get("over_cap_row_count") != 38
        or value.get("over_cap_results_admissible_as_substantive_evidence") is not False
        or value.get("phase2b_authorized") is not False
        or value.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_deterministic_owner_choice_audit_boundary_invalid")
    return value


def apply_choice(
    *, output_root: Path, recorded_at: datetime, owner_reply: str = "A"
) -> dict[str, Any]:
    if recorded_at.tzinfo is None:
        raise ValueError("phase2a_deterministic_owner_choice_recorded_at_naive")
    if owner_reply != "A":
        raise ValueError("phase2a_deterministic_owner_choice_reply_invalid")
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_deterministic_owner_choice_output_exists")
    audit = _load_audit()
    material = {
        "schema": "legalbot.v111.phase2a.deterministic-only-owner-choice.v1",
        "owner_typed_name": "Agnes",
        "owner_decision_date": "2026-08-27",
        "recorded_at": recorded_at.astimezone(UTC).isoformat(timespec="seconds"),
        "owner_reply": owner_reply,
        "selected_methodology": "DETERMINISTIC_ONLY_PATH",
        "source_complete_corrective_audit_content_sha256": audit["artifact_content_sha256"],
        "source_partial_corrective_audit_content_sha256": (PARTIAL_AUDIT_CONTENT_SHA256),
        "complete_over_cap_row_count": 38,
        "over_cap_planner_results_admissible_as_substantive_evidence": False,
        "further_planner_or_advisory_model_invocations_authorized": False,
        "deterministic_official_source_and_exact_span_work_authorized": True,
        "phase2a_continuation_authorized": True,
        "unseen_substantive_owner_decisions_approved": False,
        "unseen_source_admissions_approved": False,
        "candidate_mutated": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
        "validation30_authorized": False,
        "live_activation_authorized": False,
    }
    receipt = {**material, "receipt_content_sha256": planner._sealed(material)}
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_deterministic_owner_choice_output_mode_invalid")
    planner._write_exclusive(
        output_root / "OWNER-CHOICE-RECEIPT.json", planner._pretty_json(receipt)
    )
    planner._write_exclusive(output_root / "OWNER-REPLY-VERBATIM.txt", b"A\n")
    outcome = (
        "OPTION A RECORDED: PHASE 2A MAY CONTINUE DETERMINISTICALLY ONLY. "
        "NO FURTHER PLANNER-MODEL CALLS. PHASE 2B AND DEVELOPMENT 30 REMAIN "
        "GATED.\n"
    )
    planner._write_exclusive(output_root / "OUTCOME.txt", outcome.encode())
    names = (
        "OUTCOME.txt",
        "OWNER-CHOICE-RECEIPT.json",
        "OWNER-REPLY-VERBATIM.txt",
    )
    checksums = "".join(f"{planner._sha256_file(output_root / name)}  {name}\n" for name in names)
    planner._write_exclusive(output_root / "SHA256SUMS.txt", checksums.encode())
    return receipt


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> None:
    args = _arguments()
    result = apply_choice(
        output_root=args.output_root.resolve(),
        recorded_at=datetime.now(UTC),
    )
    print(
        json.dumps(
            {
                "output_root": str(args.output_root),
                "selected_methodology": result["selected_methodology"],
                "receipt_content_sha256": result["receipt_content_sha256"],
                "phase2a_continuation_authorized": result["phase2a_continuation_authorized"],
                "phase2b_authorized": result["phase2b_authorized"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
