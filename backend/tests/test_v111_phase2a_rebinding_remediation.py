from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest
from scripts.build_v111_phase2a_35_rebinding_proposal import (
    QUEUE_SCHEMA,
    VERIFICATION_SCHEMA,
    _pretty_json,
    _sealed,
    build_proposal,
)
from scripts.collect_v111_phase2a_rebinding_sources import (
    _safe_url,
    _target_url,
)
from scripts.verify_v111_phase2a_rebinding_sources import (
    _component_check,
    _normalise_text,
)


def test_official_target_derivation_handles_regnal_acts_and_moved_cpr() -> None:
    target_date = date(2026, 8, 14)
    assert (
        _target_url("https://www.legislation.gov.uk/ukpga/2015/15/section/47", target_date)[0]
        == "https://www.legislation.gov.uk/ukpga/2015/15/2026-08-14/data.xml"
    )
    assert _target_url(
        "https://www.legislation.gov.uk/ukpga/Geo5/15-16/19/section/61",
        target_date,
    )[0] == ("https://www.legislation.gov.uk/ukpga/Geo5/15-16/19/2026-08-14/data.xml")
    assert _target_url(
        "https://www.justice.gov.uk/courts/procedure-rules/civil/rules/part44",
        target_date,
    )[0].endswith("/part-44-general-rules-about-costs")


def test_official_target_allowlist_rejects_credentials_and_nonofficial_hosts() -> None:
    with pytest.raises(ValueError, match="outside_allowlist"):
        _safe_url("https://example.com/ukpga/2015/15")
    with pytest.raises(ValueError, match="forbidden_component"):
        _safe_url("https://user@www.legislation.gov.uk/ukpga/2015/15")


def test_exact_matching_preserves_material_numbers_and_provisions() -> None:
    official = _normalise_text(
        "1 If the test applies— (a) within 14 days; and (b) at section 50(ii)."
    )
    exact = _normalise_text("If the test applies— (a) within 14 days; and (b) at section 50(ii).")
    altered_days = _normalise_text(
        "If the test applies— (a) within 21 days; and (b) at section 50(ii)."
    )
    altered_section = _normalise_text(
        "If the test applies— (a) within 14 days; and (b) at section 51(ii)."
    )

    assert exact in official
    assert altered_days not in official
    assert altered_section not in official


def test_exact_text_under_wrong_anchor_requires_locator_review() -> None:
    component = _normalise_text("A precise operative proposition.")
    check = _component_check(
        component=component,
        expected_stems=("section-50",),
        documents=[
            {
                "target_id": "official-1",
                "target_type": "point_in_time_legislation_xml",
                "official_url": "https://www.legislation.gov.uk/example",
                "file_sha256": "a" * 64,
                "document_kind": "xml",
                "normalized_text": component,
                "anchors": (("section-51-1", component),),
            }
        ],
    )

    assert check["exact_normalized_component_match"] is True
    assert check["stated_locator_anchor_match"] is False


def _proposal_inputs(tmp_path: Path) -> tuple[Path, Path]:
    queue_items = [
        {
            "row_id": f"row-{ordinal:02d}",
            "official_source_type": "legislation_or_procedural_instrument",
            "official_source_url": "https://www.legislation.gov.uk/ukpga/2020/1",
            "record_content_sha256": "a" * 64,
        }
        for ordinal in range(1, 90)
    ]
    queue_material: dict[str, object] = {
        "schema": QUEUE_SCHEMA,
        "item_count": 89,
        "items": queue_items,
        "automatic_source_admission": False,
        "phase2b_authorized": False,
    }
    queue = {**queue_material, "artifact_content_sha256": _sealed(queue_material)}
    queue_path = tmp_path / "queue.json"
    queue_path.write_bytes(_pretty_json(queue))

    records: list[dict[str, object]] = []
    for ordinal in range(1, 90):
        exact = ordinal <= 35
        if ordinal <= 32:
            status = "EXACT_OFFICIAL_TEXT_AND_STATED_LOCATOR_MATCH"
        elif exact:
            status = "EXACT_OFFICIAL_TEXT_DIFFERENT_OR_UNCONFIRMED_LOCATOR"
        else:
            status = "STAGING_PROPOSITION_DIFFERS_FROM_FRESH_OFFICIAL_BYTES"
        action = (
            "OWNER_SOURCE_ADMISSION_DECISION_REQUIRED"
            if ordinal <= 23
            else "CANDIDATE_REBIND_OR_SUCCESSOR_DECISION_REQUIRED"
        )
        material: dict[str, object] = {
            "row_id": f"row-{ordinal:02d}",
            "all_components_exact_in_fresh_official_bytes": exact,
            "verification_status": status,
            "required_candidate_action": action,
            "proposed_exact_proposition_text": f"Proposition {ordinal}",
            "official_source_title": "Example Act 2020",
            "official_citation": "2020 c 1",
            "stated_official_legal_locator": "s 1",
        }
        records.append({**material, "record_content_sha256": _sealed(material)})
    verification_material: dict[str, object] = {
        "schema": VERIFICATION_SCHEMA,
        "record_count": 89,
        "exact_official_text_count": 35,
        "correction_required_count": 54,
        "source_queue_content_sha256": queue["artifact_content_sha256"],
        "issue_technical_qualification_count": 0,
        "phase2b_authorized": False,
        "records": records,
    }
    verification = {
        **verification_material,
        "artifact_content_sha256": _sealed(verification_material),
    }
    verification_path = tmp_path / "verification.json"
    verification_path.write_bytes(_pretty_json(verification))
    return verification_path, queue_path


def test_35_row_proposal_does_not_apply_or_build_candidate(tmp_path: Path) -> None:
    verification, queue = _proposal_inputs(tmp_path)
    output = tmp_path / "output"

    result = build_proposal(
        verification_path=verification,
        queue_path=queue,
        output_root=output,
        owner_name="Agnes",
        owner_decision_date="2026-08-24",
    )

    assert result["item_count"] == 35
    assert result["source_admission_row_count"] == 23
    assert result["candidate_rebind_row_count"] == 12
    assert result["phase2b_authorized"] is False
    proposal = json.loads((output / "PROPOSED-OWNER-DECISIONS-35.json").read_bytes())
    assert proposal["authority_if_explicitly_approved"]["candidate_build_now"] is False
    assert proposal["authority_if_explicitly_approved"]["phase2b"] is False
