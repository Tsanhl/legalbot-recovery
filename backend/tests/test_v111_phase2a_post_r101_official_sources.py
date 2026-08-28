from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from scripts import collect_v111_phase2a_post_r101_official_sources as collector


def _judgment_xml(authority: str) -> bytes:
    citation = authority.removeprefix("neutral-citation:")
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<akomaNtoso xmlns="http://docs.oasis-open.org/legaldocml/ns/akn/3.0">
  <judgment name="judgment">
    <meta><identification source="#tna"><FRBRWork>
      <FRBRdate date="2024-01-01" name="judgment"/>
      <FRBRname value="Synthetic official judgment"/>
    </FRBRWork></identification></meta>
    <header><p><neutralCitation>{citation}</neutralCitation></p></header>
    <judgmentBody><decision><paragraph eId="para_1"><num>1.</num>
      <content><p>Exact official paragraph text.</p></content>
    </paragraph></decision></judgmentBody>
  </judgment>
</akomaNtoso>
""".encode()


def _legislation_xml() -> bytes:
    return b"""<?xml version="1.0" encoding="UTF-8"?>
<Legislation xmlns="http://www.legislation.gov.uk/namespaces/legislation"
 DocumentURI="http://www.legislation.gov.uk/ukpga/Eliz2/5-6/31/2026-08-14">
  <Metadata xmlns:dc="http://purl.org/dc/elements/1.1/">
    <dc:title>Occupiers' Liability Act 1957</dc:title>
    <PrimaryMetadata><Year Value="1957"/><Number Value="31"/></PrimaryMetadata>
  </Metadata>
  <Primary><Body><P1 id="section-1"><Pnumber>1</Pnumber>
    <P1para><Text>Exact statutory text.</Text></P1para>
  </P1></Body></Primary>
</Legislation>
"""


def _transport() -> httpx.MockTransport:
    r102 = collector._load_verified(collector.R102_PATH)
    r71 = collector._load_verified(collector.R71_PATH)
    by_url = {
        target["official_url"]: target["authority_identity_id"]
        for target in collector._targets(r102, r71)
    }

    def handler(request: httpx.Request) -> httpx.Response:
        authority = by_url[str(request.url)]
        raw = (
            _judgment_xml(authority)
            if authority.startswith("neutral-citation:")
            else _legislation_xml()
        )
        return httpx.Response(
            200,
            headers={"content-type": "application/xml"},
            content=raw,
            request=request,
        )

    return httpx.MockTransport(handler)


def test_exact_r102_scope_derives_sixteen_narrow_official_targets() -> None:
    r102 = collector._load_verified(collector.R102_PATH)
    r71 = collector._load_verified(collector.R71_PATH)
    targets = collector._targets(r102, r71)

    assert len(targets) == 16
    assert sum(len(target["affected_row_ids"]) for target in targets) == 26
    assert {httpx.URL(target["official_url"]).host for target in targets} == {
        "caselaw.nationalarchives.gov.uk",
        "www.legislation.gov.uk",
    }
    by_authority = {target["authority_identity_id"]: target for target in targets}
    assert by_authority["neutral-citation:[2007] EWCA Crim 125"]["official_url"].endswith(
        "/ewca/crim/2007/125/data.xml"
    )
    assert by_authority["ukpga:1957:31"]["official_url"].endswith(
        "/ukpga/1957/31/2026-08-14/data.xml"
    )


def test_collector_quarantines_exact_scope_without_admission(tmp_path: Path) -> None:
    output = tmp_path / "r103"
    fixed = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
    manifest = collector.collect(
        output_root=output,
        transport=_transport(),
        clock=lambda: fixed,
    )

    assert manifest["record_count"] == 16
    assert manifest["row_link_count"] == 26
    assert manifest["result_counts"] == {"OFFICIAL_SOURCE_QUARANTINED_NOT_ADMITTED": 16}
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
    legislation = next(
        record
        for record in manifest["records"]
        if record["authority_identity_id"] == "ukpga:1957:31"
    )
    assert legislation["canonical_authority_identity_id"] == "ukpga:Eliz2:5-6:31"
    assert legislation["automatically_admitted"] is False
    persisted = json.loads((output / "QUARANTINE-MANIFEST.json").read_bytes())
    assert persisted == manifest
    for line in (output / "SHA256SUMS.txt").read_text().splitlines():
        digest, name = line.split("  ", 1)
        assert collector._sha256_file(output / name) == digest


def test_collector_is_create_only(tmp_path: Path) -> None:
    output = tmp_path / "r103"
    collector.collect(output_root=output, transport=_transport())
    with pytest.raises(ValueError, match="phase2a_r103_output_already_exists"):
        collector.collect(output_root=output, transport=_transport())


def test_failure_record_is_sealed_and_gate_closed(tmp_path: Path) -> None:
    output = tmp_path / "r103"
    collector._persist_failure(output, ValueError("diagnostic-example"))
    failure = json.loads((output / "FAILURE.json").read_bytes())
    assert failure["phase2b_authorized"] is False
    assert failure["development30_authorized"] is False
    material = dict(failure)
    supplied = material.pop("failure_content_sha256")
    assert supplied == collector._sealed(material)
