from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.build_v111_phase2a_post_54_inventory import (
    EXPECTED_APPROVED_PACKAGE_DIGEST,
    _pretty_json,
    _sealed,
    build_inventory,
)

ROOT = Path(__file__).resolve().parents[2]
OWNER_REVIEW = ROOT / "data" / "evaluations" / "phase2a-owner-review"
UNRESOLVED = (
    OWNER_REVIEW
    / "LegalBot-Phase2AB-2026-08-24-r17"
    / "UNRESOLVED-502-LEXICAL-RESEARCH-PACKETS.json"
)
APPROVED = (
    OWNER_REVIEW
    / "LegalBot-Phase2AB-2026-08-24-r28"
    / "OWNER-DECISIONS-APPROVED-54.json"
)
SOURCE_SCOPE = (
    OWNER_REVIEW
    / "LegalBot-Phase2AB-2026-08-24-r28"
    / "OWNER-APPROVED-SOURCE-ADMISSION-SCOPE-16.json"
)
QUARANTINES = [
    OWNER_REVIEW / "LegalBot-Phase2AB-2026-08-24-r12-quarantine",
    OWNER_REVIEW / "LegalBot-Phase2AB-2026-08-24-r21-quarantine",
]


def _build(tmp_path: Path) -> dict[str, object]:
    return build_inventory(
        unresolved_path=UNRESOLVED,
        approved_package_path=APPROVED,
        source_scope_path=SOURCE_SCOPE,
        quarantine_roots=QUARANTINES,
        output_root=tmp_path / "output",
    )


def test_builds_exact_448_remainder_and_verified_16_source_custody(
    tmp_path: Path,
) -> None:
    result = _build(tmp_path)

    assert result["remaining_owner_decision_issue_count"] == 448
    assert result["approved_source_authority_count"] == 16
    assert result["all_approved_source_bytes_verified"] is True
    assert result["candidate_mutated"] is False
    assert result["phase2b_authorized"] is False
    assert result["development30_authorized"] is False

    output = tmp_path / "output"
    remainder = json.loads((output / "REMAINING-448-RESEARCH-PACKETS.json").read_bytes())
    custody = json.loads((output / "APPROVED-SOURCE-CUSTODY-16.json").read_bytes())
    assert remainder["row_count"] == 448
    assert len({row["row_id"] for row in remainder["rows"]}) == 448
    assert custody["authority_count"] == 16
    assert custody["all_approved_authorities_bound_to_verified_quarantine_bytes"] is True
    assert all(record["indexed"] is False for record in custody["records"])
    assert all(record["embedded"] is False for record in custody["records"])
    crime_act = next(
        record
        for record in custody["records"]
        if record["authority_identity"] == "ukpga:2026:20"
    )
    assert crime_act["official_file_sha256"].startswith("f286b09e")
    assert crime_act["quarantine_root"].endswith("r21-quarantine")


def test_rejects_resealed_approval_that_expands_indexing_authority(
    tmp_path: Path,
) -> None:
    approved = json.loads(APPROVED.read_bytes())
    assert approved.pop("approved_package_content_sha256") == EXPECTED_APPROVED_PACKAGE_DIGEST
    approved["automatic_indexing_or_embedding_authorized"] = True
    approved["approved_package_content_sha256"] = _sealed(approved)
    tampered = tmp_path / "tampered-approved.json"
    tampered.write_bytes(_pretty_json(approved))

    with pytest.raises(ValueError, match="phase2a_post54_input_boundary_invalid"):
        build_inventory(
            unresolved_path=UNRESOLVED,
            approved_package_path=tampered,
            source_scope_path=SOURCE_SCOPE,
            quarantine_roots=QUARANTINES,
            output_root=tmp_path / "output",
        )


def test_rejects_quarantine_member_byte_mismatch(tmp_path: Path) -> None:
    copied_root = tmp_path / "quarantine"
    copied_root.mkdir()
    source_manifest = json.loads((QUARANTINES[1] / "QUARANTINE-MANIFEST.json").read_bytes())
    copied_manifest = copied_root / "QUARANTINE-MANIFEST.json"
    copied_manifest.write_bytes(_pretty_json(source_manifest))
    for record in source_manifest["records"]:
        source = QUARANTINES[1] / record["quarantine_member"]
        target = copied_root / record["quarantine_member"]
        target.write_bytes(source.read_bytes())
    crime_member = next(
        record["quarantine_member"]
        for record in source_manifest["records"]
        if record.get("authority_identity") == "ukpga:2026:20"
    )
    (copied_root / crime_member).write_bytes(b"tampered")

    with pytest.raises(
        ValueError,
        match="phase2a_post54_quarantine_member_integrity_failed",
    ):
        build_inventory(
            unresolved_path=UNRESOLVED,
            approved_package_path=APPROVED,
            source_scope_path=SOURCE_SCOPE,
            quarantine_roots=[QUARANTINES[0], copied_root],
            output_root=tmp_path / "output",
        )
