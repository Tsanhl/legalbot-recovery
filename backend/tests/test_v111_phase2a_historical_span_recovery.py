from __future__ import annotations

from xml.etree import ElementTree as ET

from scripts.reconcile_v111_phase2a_historical_candidate_spans import (
    _base_official_url,
    _expected_locators,
    _match_record,
)
from scripts.verify_v111_phase2a_candidate_spans_fresh_official import _span_check


def _source() -> dict[str, object]:
    return {
        "source_version_id": "source-version-1",
        "title": "Example Act 2020",
    }


def _row(*, locator: str, text: str) -> dict[str, object]:
    return {
        "chunk_id": f"chunk-{locator}-{text}",
        "source_version_id": "source-version-1",
        "title": "Example Act 2020",
        "canonical_url": "https://www.legislation.gov.uk/ukpga/2020/1",
        "canonical_citation": "Example Act 2020",
        "locator": locator,
        "content_sha256": "a" * 64,
        "text": text,
        "currentness_status": "latest_available_revised_snapshot",
        "identity_verified": True,
        "currentness_verified": True,
        "legal_role": "statutory_text",
        "as_of_date": "2026-08-14",
    }


def _provenance() -> dict[str, list[dict[str, object]]]:
    return {
        "source-version-1": [
            {
                "target_id": "source-version-1",
                "result": "DOWNLOADED_QUARANTINED",
                "matches_expected_version_sha256": False,
            }
        ]
    }


def test_locator_and_official_url_normalization() -> None:
    assert _expected_locators("ss 94(1) and 139(1)") == {
        "section 94",
        "section 139",
    }
    assert _base_official_url(
        "https://www.legislation.gov.uk/ukpga/2015/15/section/50/data.xml"
    ) == "https://www.legislation.gov.uk/ukpga/2015/15"


def test_exact_candidate_components_remain_owner_review_only() -> None:
    result = _match_record(
        record={
            "legal_locator": "s 50(1)",
            "operative_text": "First operative component. Second operative component.",
        },
        candidate_sources=[_source()],
        candidate_rows=[
            _row(locator="section 50", text="section 50 First operative component."),
            _row(locator="section 50", text="section 50 Second operative component."),
        ],
        provenance=_provenance(),
    )

    assert result["match_status"] == (
        "DETERMINISTIC_CANDIDATE_COMPONENTS_LOCATED_OWNER_REVIEW_REQUIRED"
    )
    assert result["matched_component_count"] == 2
    assert result["semantic_proposition_binding_verified"] is False
    assert result["owner_adopted"] is False
    assert result["source_admission_authorized"] is False
    assert result["fresh_official_source_check"]["all_exact_candidate_byte_matches"] is False


def test_valid_looking_text_under_wrong_provision_cannot_pass() -> None:
    result = _match_record(
        record={
            "legal_locator": "s 50(1)",
            "operative_text": "First operative component. Second operative component.",
        },
        candidate_sources=[_source()],
        candidate_rows=[
            _row(locator="section 51", text="section 51 First operative component."),
            _row(locator="section 51", text="section 51 Second operative component."),
        ],
        provenance=_provenance(),
    )

    assert result["normalized_character_coverage_ratio"] > 0.75
    assert result["locator_constraint_applied"] is False
    assert result["match_status"] == "PARTIAL_CANDIDATE_COMPONENTS_OWNER_REVIEW_REQUIRED"
    assert result["semantic_proposition_binding_verified"] is False


def test_fresh_official_anchor_match_does_not_qualify() -> None:
    raw = (
        b'<Legislation><P1 id="section-50" '
        b'DocumentURI="https://example.test/section/50">'
        b"<Text>First operative component.</Text></P1></Legislation>"
    )
    root = ET.fromstring(raw)
    anchors = {element.attrib["id"]: element for element in root.iter() if "id" in element.attrib}
    check = _span_check(
        span=_row(locator="section 50", text="section 50 First operative component."),
        provenance={
            "matches_expected_version_sha256": False,
            "final_url": "https://www.legislation.gov.uk/example/data.xml",
        },
        raw=raw,
        anchors=anchors,
    )

    assert check["fresh_official_anchor_found"] is True
    assert check["candidate_body_exact_normalized_match_in_fresh_anchor"] is True
    assert check["whole_document_candidate_byte_match"] is False
    assert check["qualification_effect"] == "NONE_OWNER_REVIEW_REQUIRED"


def test_fresh_official_wrong_anchor_cannot_match() -> None:
    raw = b'<Legislation><P1 id="section-51"><Text>First operative component.</Text></P1></Legislation>'
    root = ET.fromstring(raw)
    anchors = {element.attrib["id"]: element for element in root.iter() if "id" in element.attrib}
    check = _span_check(
        span=_row(locator="section 50", text="section 50 First operative component."),
        provenance={"matches_expected_version_sha256": False},
        raw=raw,
        anchors=anchors,
    )

    assert check["fresh_official_anchor_found"] is False
    assert check["candidate_body_exact_normalized_match_in_fresh_anchor"] is False
