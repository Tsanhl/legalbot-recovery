from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest
from scripts import build_v111_phase2a_materiality_batch as materiality_batch
from scripts import build_v111_phase2a_remediation as remediation
from scripts import collect_v111_phase2a_official_sources as collector
from scripts import collect_v111_phase2a_supplemental_sources as supplemental_collector
from scripts import verify_v111_phase2a_rebinding_sources as rebinding_verifier
from scripts import verify_v111_phase2a_supplemental_sources as supplemental_verifier

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CANDIDATE_MANIFEST = (
    PROJECT_ROOT
    / "data/indexes/builds/current-law-ew-full-fp16-v111-20260818-a/approved-source-manifest.json"
)
PACKAGE_ROOT = (
    PROJECT_ROOT / "data/evaluations/phase2a-currentness/v111-phase2a-20260823-r4-ee47fda9d00a"
)
BUNDLE_CASES = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1/cases.jsonl"
SUPPLEMENTAL_PLAN = PROJECT_ROOT / "config/phase2a_supplemental_official_sources.v1.json"
SUPPLEMENTAL_BINDING_PLAN = PROJECT_ROOT / "config/phase2a_supplemental_binding_plan.v1.json"


def test_official_source_allowlist_is_fail_closed() -> None:
    assert collector._safe_url("https://www.legislation.gov.uk/ukpga/2025/18/data.xml")
    assert collector._safe_url("https://caselaw.nationalarchives.gov.uk/uksc/2026/30/data.xml")
    with pytest.raises(ValueError, match="outside_allowlist"):
        collector._safe_url("https://example.com/ukpga/2025/18/data.xml")
    with pytest.raises(ValueError, match="outside_allowlist"):
        collector._safe_url("http://www.legislation.gov.uk/ukpga/2025/18/data.xml")
    with pytest.raises(ValueError, match="forbidden_component"):
        collector._safe_url("https://www.legislation.gov.uk/a#fragment")


def test_collection_target_inventory_is_exact_and_non_admitting() -> None:
    manifest = json.loads(CANDIDATE_MANIFEST.read_bytes())
    targets = collector._targets(
        candidate_manifest=manifest,
        findings=collector._phase2a_findings(PACKAGE_ROOT),
        target_date=date(2026, 8, 14),
    )

    counts: dict[str, int] = {}
    for target in targets:
        counts[target["target_type"]] = counts.get(target["target_type"], 0) + 1
        collector._safe_url(target["url"])
    assert counts == {
        "candidate_judgment_source": 20,
        "candidate_legislation": 65,
        "external_finding_source": 11,
    }
    trade_secrets = next(
        target
        for target in targets
        if target["target_id"] == "source-version-f1d2fba5d67d7ecbb060841435513960b9bb861c"
    )
    assert trade_secrets["url"] == (
        "https://www.legislation.gov.uk/uksi/2018/597/2026-08-14/data.xml"
    )
    twinsectra = sorted(
        target["url"]
        for target in targets
        if target["authority_identity"] == "neutral-citation:[2002] UKHL 12"
    )
    assert twinsectra == [
        "https://publications.parliament.uk/pa/ld200102/ldjudgmt/jd020321/yardle-1.htm",
        "https://publications.parliament.uk/pa/ld200102/ldjudgmt/jd020321/yardle-3.htm",
        "https://publications.parliament.uk/pa/ld200102/ldjudgmt/jd020321/yardle-4.htm",
    ]
    assert all(
        target["expected_version_sha256"]
        for target in targets
        if target["target_type"] == "candidate_judgment_source"
    )


def test_legacy_parliament_judgment_representation_is_identity_bound() -> None:
    source = {
        "canonical_url": (
            "https://publications.parliament.uk/pa/ld200102/ldjudgmt/jd020321/yardle-1.htm"
        ),
        "official_representation_id": "ukhl-2002-12-part-4",
    }

    assert collector._candidate_judgment_url(source, "neutral-citation:[2002] UKHL 12").endswith(
        "/yardle-4.htm"
    )
    with pytest.raises(ValueError, match="identity_mismatch"):
        collector._candidate_judgment_url(source, "neutral-citation:[2003] UKHL 12")


def test_quarantine_member_extension_preserves_official_html_format() -> None:
    target = {
        "target_type": "candidate_judgment_source",
        "target_id": "source-version-test",
        "url": "https://publications.parliament.uk/example/yardle-1.htm",
        "page": None,
    }

    assert collector._member_name(target, b"<html>judgment</html>").endswith(".html")


def test_bulk_later_treatment_search_requires_separate_licence_evidence() -> None:
    manifest = json.loads(CANDIDATE_MANIFEST.read_bytes())
    targets = collector._targets(
        candidate_manifest=manifest,
        findings=collector._phase2a_findings(PACKAGE_ROOT),
        target_date=date(2026, 8, 14),
        include_bulk_later_treatment_search=True,
    )

    assert sum(target["target_type"] == "later_treatment_search" for target in targets) == 18
    assert all(
        target["url"].startswith("https://caselaw.nationalarchives.gov.uk/atom.xml?")
        for target in targets
        if target["target_type"] == "later_treatment_search"
    )


def test_supplemental_source_plan_is_non_admitting_and_point_in_time() -> None:
    plan = json.loads(SUPPLEMENTAL_PLAN.read_bytes())

    targets = supplemental_collector._validate_plan(plan)

    assert len(targets) == 2
    assert {target["authority_identity"] for target in targets} == {
        "ukpga:1996:23",
        "ukpga:2026:20",
    }
    assert all(target["official_url"].endswith("/2026-08-14/data.xml") for target in targets)
    assert plan["automatic_source_admission"] is False
    assert plan["automatic_indexing"] is False


def test_supplemental_xml_digest_ignores_attribute_order_only() -> None:
    first = b'<Legislation xmlns="urn:test"><Section id="80" status="current"/></Legislation>'
    reordered = b'<Legislation xmlns="urn:test"><Section status="current" id="80"/></Legislation>'

    assert collector._sha256(first) != collector._sha256(reordered)
    assert supplemental_collector._canonical_xml_sha256(
        first
    ) == supplemental_collector._canonical_xml_sha256(reordered)


def test_supplemental_xml_digest_rejects_malformed_xml() -> None:
    with pytest.raises(ValueError, match="supplemental_source_xml_invalid"):
        supplemental_collector._canonical_xml_sha256(b"<Legislation>")


def test_supplemental_plan_allows_immutable_as_made_instrument_xml() -> None:
    plan = json.loads(SUPPLEMENTAL_PLAN.read_bytes())
    plan["targets"] = [
        {
            "target_id": "commencement-order",
            "target_type": "as_made_legislation_xml",
            "authority_identity": "uksi:2007:1897",
            "source_title": "Commencement Order",
            "official_url": ("https://www.legislation.gov.uk/uksi/2007/1897/made/data.xml"),
            "required_locators": ["article-2"],
            "affected_rows": ["live30-q20:issue-01"],
            "research_reason": "Currentness evidence only.",
        }
    ]

    targets = supplemental_collector._validate_plan(plan)

    assert targets[0]["target_type"] == "as_made_legislation_xml"


def test_supplemental_plan_rejects_mismatched_representation_route() -> None:
    plan = json.loads(SUPPLEMENTAL_PLAN.read_bytes())
    plan["targets"][0]["official_url"] = (
        "https://www.legislation.gov.uk/ukpga/1996/23/made/data.xml"
    )

    with pytest.raises(ValueError, match="target_boundary_invalid"):
        supplemental_collector._validate_plan(plan)


def test_supplemental_binding_plan_requires_owner_admission() -> None:
    plan = json.loads(SUPPLEMENTAL_BINDING_PLAN.read_bytes())

    bindings = supplemental_verifier._validate_plan(plan)

    assert len(bindings) == 2
    assert {row for binding in bindings for row in binding["row_ids"]} == {
        "live30-q29:issue-01",
        "live60-q43:issue-02",
        "live60-q48:issue-07",
    }
    assert plan["owner_materiality_decision_required"] is True
    assert plan["owner_source_admission_required"] is True
    assert plan["automatic_source_admission"] is False
    assert plan["phase2b_authorized"] is False


def test_supplemental_exact_claim_span_is_uniquely_bound() -> None:
    record = {
        "target_id": "source-one",
        "source_title": "Official Act",
        "final_url": "https://www.legislation.gov.uk/ukpga/2025/18/made/data.xml",
        "sha256": "a" * 64,
    }
    claim = {
        "claim_id": "claim-one",
        "proposition": "A decision has no meaningful human involvement.",
        "anchor_id": "section-80-1",
        "exact_normalized_span_text": (
            "a decision is based solely on automated processing if there is no "
            "meaningful human involvement in the taking of the decision"
        ),
    }

    span = supplemental_verifier._exact_claim_span(
        claim=claim,
        anchors={
            "section-80-1": (
                "1 a decision is based solely on automated processing if there is no "
                "meaningful human involvement in the taking of the decision, and a "
                "decision is significant if it produces a legal effect."
            )
        },
        source_record=record,
    )

    assert span["claim_id"] == "claim-one"
    assert span["start_character"] == 2
    assert span["span_truncated"] is False


def test_supplemental_exact_claim_span_rejects_unrelated_evidence() -> None:
    with pytest.raises(ValueError, match="exact_span_not_unique_in_anchor"):
        supplemental_verifier._exact_claim_span(
            claim={
                "claim_id": "claim-one",
                "proposition": "Unsupported proposition.",
                "anchor_id": "section-80-1",
                "exact_normalized_span_text": "unrelated authority",
            },
            anchors={"section-80-1": "automated decisions require safeguards"},
            source_record={
                "target_id": "source-one",
                "source_title": "Official Act",
                "final_url": "https://www.legislation.gov.uk/ukpga/2025/18/made/data.xml",
                "sha256": "a" * 64,
            },
        )


def test_supplemental_verifier_source_inventory_can_preserve_unavailable_records() -> None:
    assert supplemental_verifier._is_downloaded_record(
        {"result": "DOWNLOADED_QUARANTINED_NOT_ADMITTED"}
    )
    assert not supplemental_verifier._is_downloaded_record(
        {"result": "OFFICIAL_SOURCE_UNAVAILABLE"}
    )


@pytest.mark.parametrize(
    ("url", "title", "citation", "expected"),
    (
        (
            "https://www.legislation.gov.uk/ukpga/1996/23/2026-08-14/data.xml",
            "Arbitration Act 1996",
            "1996 c 23",
            "ukpga:1996:23",
        ),
        (
            "https://www.legislation.gov.uk/ukpga/Will4and1Vict/7/26/2026-08-14/data.xml",
            "Wills Act 1837",
            "1837 c 26",
            "ukpga:Will4and1Vict:7:26",
        ),
        (
            "https://www.justice.gov.uk/courts/procedure-rules/civil/rules/part31",
            "Civil Procedure Rules",
            "CPR",
            "uksi:1998:3132",
        ),
        (
            "https://www.judiciary.uk/example.pdf",
            "Ayinde",
            "[2025] EWHC 1383 (Admin)",
            "neutral-citation:[2025] EWHC 1383 (Admin)",
        ),
    ),
)
def test_materiality_batch_maps_official_authority_identity(
    url: str,
    title: str,
    citation: str,
    expected: str,
) -> None:
    assert (
        materiality_batch._authority_identity(
            url=url,
            title=title,
            citation=citation,
        )
        == expected
    )


def test_later_treatment_search_stops_at_configured_page_cap() -> None:
    target = {
        "target_type": "later_treatment_search",
        "target_id": "search:[2002] UKHL 12",
        "page": 20,
    }

    assert collector._next_search_target(target, 50) is None


@pytest.mark.parametrize(
    ("requires_applied", "in_force", "expected", "blocks"),
    (
        (
            False,
            [],
            "APPLICABLE_ONLY_TO_METADATA_OR_CURRENTNESS",
            True,
        ),
        (
            True,
            [{"Applied": "false", "Prospective": "true"}],
            "NOT_YET_COMMENCED",
            False,
        ),
        (
            True,
            [{"Applied": "false", "Date": "2027-01-01"}],
            "NOT_YET_COMMENCED_AT_TARGET_CEILING",
            False,
        ),
        (
            True,
            [{"Applied": "false", "Date": "2026-01-01"}],
            "APPLICABLE_AND_MUST_BE_INCORPORATED_OR_EXPLAINED",
            True,
        ),
        (
            True,
            [{"Applied": "true", "Date": "2026-01-01"}],
            "OWNER_DECISION_REQUIRED_PARTIAL_OR_EXTENT_STATE",
            True,
        ),
    ),
)
def test_effect_disposition_is_conservative(
    requires_applied: bool,
    in_force: list[dict[str, str]],
    expected: str,
    blocks: bool,
) -> None:
    disposition, actual_blocks, _ = remediation._effect_disposition(
        requires_applied=requires_applied,
        in_force=in_force,
        ceiling=date(2026, 8, 14),
    )
    assert disposition == expected
    assert actual_blocks is blocks


def test_registry_snapshot_accounts_for_all_rows_without_question_prose() -> None:
    snapshot, rows = remediation._registry(BUNDLE_CASES)

    assert snapshot["case_count"] == 60
    assert snapshot["issue_count"] == 585
    assert len(rows) == 585
    assert snapshot["contains_question_prose"] is False
    assert all("question" not in case for case in snapshot["cases"])
    assert all("issue_label" in row for row in rows.values())


def test_missing_bindings_are_not_converted_to_a_pass() -> None:
    defects = remediation._determined_defects(
        {
            "primary_status": "GOLD_OR_CASE_DEFECT",
            "registry_gold_binding_sha256": None,
            "gold_source_ids": [],
            "official_source_version_ids": [],
            "gold_span_binding_sha256s": [],
        },
        candidates=[],
    )

    assert defects == [
        "MISSING_PROPOSITION_BINDING",
        "MISSING_OFFICIAL_SOURCE_BINDING",
        "MISSING_SOURCE_VERSION_BINDING",
        "MISSING_EXACT_SPAN_BINDING",
        "POSSIBLE_ADDITIONAL_CANDIDATE_COVERAGE_GAP",
    ]


def test_atom_parser_keeps_only_evidence_metadata() -> None:
    raw = b"""<?xml version='1.0'?>
    <feed xmlns='http://www.w3.org/2005/Atom'
          xmlns:tna='https://caselaw.nationalarchives.gov.uk'>
      <entry><title>Later Case</title><published>2026-01-02T00:00:00+00:00</published>
      <updated>2026-01-03T00:00:00+00:00</updated>
      <link rel='alternate' href='https://caselaw.nationalarchives.gov.uk/ewca/civ/2026/1'/>
      <link rel='alternate' type='application/akn+xml'
            href='https://caselaw.nationalarchives.gov.uk/ewca/civ/2026/1/data.xml'/>
      <tna:identifier type='ukncn'>[2026] EWCA Civ 1</tna:identifier>
      <tna:contenthash>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</tna:contenthash>
      </entry></feed>"""

    entries = remediation._atom_entries(raw)

    assert entries == [
        {
            "title": "Later Case",
            "neutral_citation": "[2026] EWCA Civ 1",
            "published": "2026-01-02T00:00:00+00:00",
            "updated": "2026-01-03T00:00:00+00:00",
            "html_url": "https://caselaw.nationalarchives.gov.uk/ewca/civ/2026/1",
            "xml_url": "https://caselaw.nationalarchives.gov.uk/ewca/civ/2026/1/data.xml",
            "content_sha256": "a" * 64,
        }
    ]


def test_official_source_summary_does_not_overstate_byte_mismatch() -> None:
    summary = remediation._official_source_summary(
        [
            {
                "target_type": "candidate_legislation",
                "result": "DOWNLOADED_QUARANTINED",
                "matches_expected_version_sha256": False,
            },
            {
                "target_type": "candidate_legislation",
                "result": "DOWNLOADED_QUARANTINED",
                "matches_expected_version_sha256": True,
            },
            {
                "target_type": "candidate_judgment_source",
                "result": "OFFICIAL_SOURCE_UNAVAILABLE",
            },
        ]
    )

    assert summary["candidate_legislation_record_count"] == 2
    assert summary["candidate_legislation_downloaded_count"] == 2
    assert summary["candidate_legislation_exact_hash_match_count"] == 1
    assert summary["candidate_legislation_byte_mismatch_count"] == 1
    assert summary["official_source_unavailable_count"] == 1
    assert (
        "does not alone prove a substantive legal change" in summary["byte_mismatch_interpretation"]
    )


def test_rebinding_html_parser_binds_empty_heading_anchor_to_rule_body() -> None:
    raw = b"""
    <html><body>
      <h3><a id="rule44.2"></a>Court discretion as to costs</h3>
      <p><strong>44.2</strong></p>
      <p>(1) The court has discretion as to costs.</p>
      <h3><a id="rule44.3"></a>Basis of assessment</h3>
      <p><strong>44.3</strong> The court will assess costs.</p>
    </body></html>
    """

    _, anchors, kind = rebinding_verifier._parse_document(
        raw=raw,
        content_type="text/html",
    )

    assert kind == "html"
    rule_text = dict(anchors)["rule-44.2"]
    assert "the court has discretion as to costs" in rule_text
    assert "basis of assessment" not in rule_text
    assert rebinding_verifier._anchor_id_matches("rule44.2", ("rule-44.2",))


def test_rebinding_pdf_parser_exposes_numbered_paragraph_anchors() -> None:
    anchors = dict(
        rebinding_verifier._pdf_anchors(
            "5. Earlier text.\n"
            "6. Generative tools cannot conduct reliable legal research.\n"
            "They may invent sources.\n"
            "7. Users must check accuracy against authoritative sources.\n"
        )
    )

    assert anchors["paragraph-6"] == (
        "6. generative tools cannot conduct reliable legal research. they may invent sources."
    )
    assert anchors["paragraph-7"] == ("7. users must check accuracy against authoritative sources.")
    assert rebinding_verifier._expected_anchor_stems("[6]-[7]") == (
        "paragraph-6",
        "paragraph-7",
    )
    assert rebinding_verifier._expected_anchor_stems("s 47(1)") == (
        "section-47",
        "section-47-1",
    )


def test_rebinding_xml_parser_aliases_schedule_article_rules() -> None:
    raw = b"""
    <Legislation>
      <Part id="schedule-part-3">
        <Number>Article III</Number>
        <P id="schedule-part-3-paragraph-1">
          <Text>The carrier shall exercise due diligence.</Text>
        </P>
        <P id="schedule-part-3-paragraph-6">
          <Text>Suit must be brought within one year.</Text>
        </P>
      </Part>
    </Legislation>
    """

    _, anchors, kind = rebinding_verifier._parse_document(
        raw=raw,
        content_type="application/xml",
    )

    assert kind == "xml"
    alias_text = dict(anchors)["article-iii-rule-6"]
    assert alias_text == "suit must be brought within one year."
    assert rebinding_verifier._anchor_id_matches(
        "article-iii-rule-6",
        ("article-iii", "rule-6"),
    )


def test_stated_locator_correction_omits_empty_or_ellipsis_only_span() -> None:
    documents = [
        {
            "target_id": "official-a",
            "target_type": "point_in_time_legislation_xml",
            "official_url": "https://www.legislation.gov.uk/ukpga/2023/56/data.xml",
            "file_sha256": "a" * 64,
            "document_kind": "xml",
            "anchors": (("section-196", "..."),),
        }
    ]

    corrections = rebinding_verifier._stated_locator_corrections(
        "failure to prevent fraud",
        ("section-196",),
        documents,
    )

    assert corrections == []
    assert (
        rebinding_verifier._stated_locator_evidence_state(
            ("section-196",),
            documents,
        )
        == "EMPTY_OR_OMITTED_AT_TARGET_DATE"
    )


def test_stated_locator_correction_prefers_exact_provision_over_child() -> None:
    documents = [
        {
            "target_id": "official-wills",
            "target_type": "point_in_time_legislation_xml",
            "official_url": "https://www.legislation.gov.uk/example/data.xml",
            "file_sha256": "b" * 64,
            "document_kind": "xml",
            "anchors": (
                ("section-9", "9 no will shall be valid unless all requirements are met"),
                ("section-9-a", "a it is in writing and signed by the testator"),
            ),
        }
    ]

    corrections = rebinding_verifier._stated_locator_corrections(
        "a will must be in writing",
        ("section-9",),
        documents,
    )

    assert corrections[0]["anchor_id"] == "section-9"
    assert (
        corrections[0]["locator_match_specificity_score"]
        > corrections[1]["locator_match_specificity_score"]
    )


def test_compound_locator_prefers_anchor_matching_article_and_rule() -> None:
    stems = rebinding_verifier._expected_anchor_stems("Art III, r 6")

    compound = rebinding_verifier._anchor_match_score("article-iii-rule-6", stems)
    article_only = rebinding_verifier._anchor_match_score("article-iii", stems)

    assert compound > article_only
