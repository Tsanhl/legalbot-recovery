from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from scripts.build_seminar_source_owner_packet import build_package

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _sealed(value: dict[str, object], field: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field))
    raw = json.dumps(
        material,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    assert hashlib.sha256(raw).hexdigest() == supplied
    return supplied


def test_seminar_source_owner_packet_is_exact_and_non_authorizing(tmp_path: Path) -> None:
    del tmp_path
    # The package is historical and immutable; its admitted source rows no
    # longer have their pre-adoption catalogue state.
    output = (
        PROJECT_ROOT / "data/evaluations/phase2a-owner-review/"
        "LegalBot-Phase2A-2026-08-27-seminar-source-owner-packet"
    )
    package_index = json.loads((output / "PACKAGE-INDEX.json").read_bytes())
    historical_batch = json.loads(
        (output / "SEMINAR-SOURCE-OWNER-DECISION-BATCH.json").read_bytes()
    )
    historical_exclusions = json.loads((output / "EXCLUDED-SOURCES.json").read_bytes())
    result = {
        **package_index,
        "source_authority_count": historical_batch["source_authority_count"],
        "source_family_counts": historical_batch["source_family_counts"],
        "exclusion_counts": historical_exclusions["counts"],
    }

    assert result["source_authority_count"] == 142
    assert result["source_family_counts"] == {
        "legislation": 43,
        "official_judgment": 99,
    }
    assert result["exclusion_counts"] == {
        "ocr_held_authority_count": 1,
        "ewhc_unresolved_count": 4,
        "fcl_unavailable_count": 40,
        "legislation_unmapped_or_not_exact_count": 21,
        "unconfirmed_alias_identity_count": 38,
        "noncitable_representation_count": 3,
    }
    assert result["source_admission_authorized"] is False
    assert result["embedding_authorized"] is False
    assert result["candidate_mutated"] is False
    assert result["active_pointer_written"] is False

    batch = json.loads((output / "SEMINAR-SOURCE-OWNER-DECISION-BATCH.json").read_bytes())
    _sealed(batch, "owner_decision_batch_content_sha256")
    assert batch["source_authority_count"] == 142
    assert len(batch["records"]) == 142
    assert len({item["source_key"] for item in batch["records"]}) == 142
    assert all(item["source_admission"]["owner_outcome"] is None for item in batch["records"])
    assert all(item["source_admission"]["authorized"] is False for item in batch["records"])
    assert all(item["embedding_authorized"] is False for item in batch["records"])
    assert all(
        item["selected_source_version"]["review_status"] == "staged" for item in batch["records"]
    )

    exclusions = json.loads((output / "EXCLUDED-SOURCES.json").read_bytes())
    _sealed(exclusions, "artifact_content_sha256")
    assert exclusions["counts"] == result["exclusion_counts"]

    approval = json.loads((output / "OWNER-APPROVAL-PAYLOAD.json").read_bytes())
    _sealed(approval, "owner_approval_payload_content_sha256")
    assert approval["owner_approved"] is False
    assert approval["source_admission_authorized"] is False
    assert approval["embedding_authorized"] is False
    assert approval["candidate_build_authorized"] is False
    assert approval["approval_scope_if_explicitly_owner_approved"] == {
        "source_authority_count": 142,
        "adopt_each_proposed_metadata_binding": True,
        "source_admission_for_private_research_index": True,
        "retain_currentness_and_later_treatment_holds": True,
        "answer_release_eligible": False,
        "one_full_source_scan_authorized": True,
        "one_successor_candidate_build_and_embedding_authorized": True,
        "successor_must_remain_non_active": True,
    }

    package = json.loads((output / "PACKAGE-INDEX.json").read_bytes())
    _sealed(package, "package_index_content_sha256")
    assert package["file_count"] == 6
    assert package["source_admission_authorized"] is False
    assert package["embedding_authorized"] is False
    all_output = "\n".join(
        path.read_text(errors="replace") for path in output.iterdir() if path.is_file()
    ).casefold()
    assert "/users/" not in all_output
    assert "file:" not in all_output


def test_seminar_source_owner_packet_refuses_existing_output(tmp_path: Path) -> None:
    output = tmp_path / "owner-packet"
    output.mkdir()
    try:
        build_package(
            output_root=output,
            catalogue_path=PROJECT_ROOT / "data/catalog.sqlite3",
            recorded_at=datetime(2026, 8, 27, 1, 30, tzinfo=UTC),
        )
    except ValueError as exc:
        assert str(exc) == "seminar_owner_packet_output_already_exists"
    else:
        raise AssertionError("existing output root was not rejected")
