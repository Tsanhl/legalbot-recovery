from __future__ import annotations

from scripts import collect_v111_phase2a_official_sources as official
from scripts import collect_v111_phase2a_supplemental_sources as supplemental


def test_xml_canonicalization_distinguishes_serialization_from_legal_text() -> None:
    prior = b'<Act xmlns="urn:test"><Section id="80" status="current">Rule</Section></Act>'
    current = b'<Act xmlns="urn:test"><Section status="current" id="80">Rule</Section></Act>'
    changed = b'<Act xmlns="urn:test"><Section id="80" status="current">New rule</Section></Act>'

    assert official._sha256(prior) != official._sha256(current)
    assert supplemental._canonical_xml_sha256(prior) == supplemental._canonical_xml_sha256(current)
    assert supplemental._canonical_xml_sha256(prior) != supplemental._canonical_xml_sha256(changed)
