from __future__ import annotations

import io
import json
from datetime import UTC, datetime
from pathlib import Path
from xml.etree import ElementTree as ET

import httpx
import pytest
from scripts import collect_v111_phase2a_post_r108_currentness_sources as collector


def _judgment_xml(authority: str, required: list[str], *, use_paragraph_eid: bool = True) -> bytes:
    citation = authority.removeprefix("neutral-citation:")
    blocks = []
    for locator in required:
        number = locator.removeprefix("paragraph ")
        eid = f' eId="para_{number}"' if use_paragraph_eid else ""
        blocks.append(
            f"<paragraph{eid}><num>{number}.</num>"
            f"<content><p>Exact official paragraph {number} text.</p></content>"
            "</paragraph>"
        )
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<akomaNtoso xmlns="http://docs.oasis-open.org/legaldocml/ns/akn/3.0">
  <judgment name="judgment">
    <meta><identification source="#tna"><FRBRWork>
      <FRBRdate date="2025-01-01" name="judgment"/>
      <FRBRname value="Synthetic official judgment"/>
    </FRBRWork></identification></meta>
    <header><p><neutralCitation>{citation}</neutralCitation></p></header>
    <judgmentBody><decision>{"".join(blocks)}</decision></judgmentBody>
  </judgment>
</akomaNtoso>
""".encode()


def _legislation_xml() -> bytes:
    return b"""<?xml version="1.0" encoding="UTF-8"?>
<Legislation xmlns="http://www.legislation.gov.uk/namespaces/legislation"
 DocumentURI="http://www.legislation.gov.uk/uksi/2006/246/2026-08-14">
  <Metadata xmlns:dc="http://purl.org/dc/elements/1.1/">
    <dc:title>The Transfer of Undertakings (Protection of Employment) Regulations 2006</dc:title>
    <SecondaryMetadata><Year Value="2006"/><Number Value="246"/></SecondaryMetadata>
  </Metadata>
  <Secondary><Body>
    <P1 id="regulation-4"><Pnumber>4</Pnumber><P1para><Text>Transfer text.</Text></P1para></P1>
    <P1 id="regulation-10"><Pnumber>10</Pnumber><P1para><Text>Pensions text.</Text></P1para></P1>
    <P1 id="regulation-13"><Pnumber>13</Pnumber><P1para><Text>Consultation text.</Text></P1para></P1>
  </Body></Secondary>
</Legislation>
"""


def _mock_plan(tmp_path: Path) -> tuple[Path, httpx.MockTransport]:
    plan = collector._load_plan()
    by_url: dict[str, bytes] = {}
    for target in plan["targets"]:
        authority = target["authority_identity_id"]
        raw = (
            _judgment_xml(authority, target["required_locators"])
            if authority.startswith("neutral-citation:")
            else _legislation_xml()
        )
        target["preflight_response_sha256"] = collector._sha256(raw)
        canonical = ET.canonicalize(from_file=io.BytesIO(raw), with_comments=False).encode("utf-8")
        target["expected_canonical_xml_sha256"] = collector._sha256(canonical)
        by_url[target["official_url"]] = raw
    path = tmp_path / "plan.json"
    path.write_bytes(collector._pretty_json(plan))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/xml"},
            content=by_url[str(request.url)],
            request=request,
        )

    return path, httpx.MockTransport(handler)


def test_plan_is_exactly_bounded_and_all_gates_are_closed() -> None:
    plan = collector._load_plan()
    targets = collector._validate_targets(plan)

    assert len(targets) == 4
    assert {target["authority_identity_id"] for target in targets} == {
        "neutral-citation:[2021] UKSC 3",
        "neutral-citation:[2025] UKSC 22",
        "neutral-citation:[2025] EWHC 2863 (Ch)",
        "uksi:2006:246",
    }
    assert {httpx.URL(target["official_url"]).host for target in targets} == {
        "caselaw.nationalarchives.gov.uk",
        "www.legislation.gov.uk",
    }


def test_judgment_extractor_accepts_legacy_tna_paragraphs_without_eid() -> None:
    authority = "neutral-citation:[2021] UKSC 3"
    extraction = collector._judgment_extraction(
        authority,
        _judgment_xml(
            authority,
            ["paragraph 21", "paragraph 102"],
            use_paragraph_eid=False,
        ),
    )

    assert [block["locator"] for block in extraction["blocks"]] == [
        "paragraph 21",
        "paragraph 102",
    ]
    assert [block["element_id"] for block in extraction["blocks"]] == [
        "para_21",
        "para_102",
    ]


def test_collector_quarantines_without_admission(tmp_path: Path) -> None:
    plan_path, transport = _mock_plan(tmp_path)
    output = tmp_path / "r109"
    fixed = datetime(2026, 8, 26, 16, 0, tzinfo=UTC)
    manifest = collector.collect(
        output_root=output,
        plan_path=plan_path,
        transport=transport,
        clock=lambda: fixed,
    )

    assert manifest["record_count"] == 4
    assert manifest["row_link_count"] == 4
    assert all(
        manifest[field] is False
        for field in (
            "automatic_source_admission",
            "automatic_gold_change",
            "automatic_indexing",
            "automatic_embedding",
            "candidate_mutated",
            "technical_qualification_assigned",
            "phase2b_authorized",
            "development30_authorized",
        )
    )
    persisted = json.loads((output / "QUARANTINE-MANIFEST.json").read_bytes())
    assert persisted == manifest
    for line in (output / "SHA256SUMS.txt").read_text().splitlines():
        digest, name = line.split("  ", 1)
        assert collector._sha256_file(output / name) == digest


def test_canonical_digest_change_fails_before_admission(tmp_path: Path) -> None:
    plan_path, transport = _mock_plan(tmp_path)
    plan = json.loads(plan_path.read_bytes())
    plan["targets"][0]["expected_canonical_xml_sha256"] = "0" * 64
    plan_path.write_bytes(collector._pretty_json(plan))

    with pytest.raises(ValueError, match="phase2a_r109c_canonical_xml_digest_mismatch"):
        collector.collect(
            output_root=tmp_path / "r109",
            plan_path=plan_path,
            transport=transport,
        )


def test_raw_byte_variant_is_recorded_when_canonical_xml_is_exact(
    tmp_path: Path,
) -> None:
    plan_path, transport = _mock_plan(tmp_path)
    plan = json.loads(plan_path.read_bytes())
    plan["targets"][0]["preflight_response_sha256"] = "0" * 64
    plan_path.write_bytes(collector._pretty_json(plan))

    manifest = collector.collect(
        output_root=tmp_path / "r109",
        plan_path=plan_path,
        transport=transport,
    )

    assert manifest["records"][0]["raw_byte_status"] == ("CANONICAL_XML_IDENTICAL_RAW_BYTE_VARIANT")
    assert manifest["records"][0]["automatically_admitted"] is False


def test_collector_is_create_only(tmp_path: Path) -> None:
    plan_path, transport = _mock_plan(tmp_path)
    output = tmp_path / "r109"
    collector.collect(
        output_root=output,
        plan_path=plan_path,
        transport=transport,
    )
    with pytest.raises(ValueError, match="phase2a_r109_output_already_exists"):
        collector.collect(
            output_root=output,
            plan_path=plan_path,
            transport=transport,
        )


def test_failure_record_is_sealed_and_gate_closed(tmp_path: Path) -> None:
    output = tmp_path / "r109"
    collector._persist_failure(output, ValueError("diagnostic-example"))
    failure = json.loads((output / "FAILURE.json").read_bytes())
    assert failure["phase2b_authorized"] is False
    assert failure["development30_authorized"] is False
    material = dict(failure)
    supplied = material.pop("failure_content_sha256")
    assert supplied == collector._sealed(material)
