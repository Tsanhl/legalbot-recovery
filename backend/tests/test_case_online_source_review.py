from datetime import date

import pytest

from app.research.case_source_review import qualify_review
from app.research.official_capture import extract_segments
from app.types import EvidenceSpan


def test_review_cannot_admit_unknown_ids_or_override_failed_currentness():
    span = EvidenceSpan(
        id="e1", source_version_id="s1", chunk_id="c1", text="A complete synthetic test provision.",
        locator="s 1", lane="primary_authority", jurisdiction="England", subject="consumer",
        citation_data={"source_type": "legislation", "title": "Synthetic Test Act 2026"},
        canonical_citation="Synthetic Test Act 2026", currentness_status="unverified",
        content_sha256="a" * 64, index_build_id="online-stage:test", identity_verified=True,
        currentness_verified=False,
    )
    decision = {"evidence_id": "e1", "relevant": True, "context_sufficient": True,
                "applicability_supported": True, "supported_proposition": "A synthetic test rule.",
                "limitations": []}
    kwargs = dict(as_of=date(2026, 9, 23), question="synthetic test", model_id="test-only")
    assert qualify_review([span], {"items": [decision]}, **kwargs)[0] == []
    with pytest.raises(ValueError, match="ids_mismatch"):
        qualify_review([span], {"items": [{**decision, "evidence_id": "other"}]}, **kwargs)
    verified = span.model_copy(update={"currentness_verified": True,
                                      "currentness_status": "point_in_time:2026-09-23;unapplied_effects:0"})
    assert qualify_review([verified], {"items": [{**decision, "context_sufficient": False}]}, **kwargs)[0] == []
    accepted, receipt = qualify_review([verified], {"items": [decision]}, **kwargs)
    assert len(accepted) == 1
    assert accepted[0].retrieval_threshold_policy_sha256 == receipt["sha256"]
    assert receipt["shared_admission"] is False
    assert receipt["professional_legal_validation"] is False


def test_capture_offsets_are_not_legal_pinpoints_and_xml_entities_are_refused():
    paragraphs = extract_segments(b'<html><nav>menu</nav><main><h1>Title</h1><p id="para7">Actual text.</p></main></html>', "text/html")
    assert paragraphs[-1] == {"capture_locator": "para7", "text": "Actual text."}
    assert not any(p["text"] == "menu" for p in paragraphs)
    with pytest.raises(ValueError, match="unsafe"):
        extract_segments(b'<!DOCTYPE x [<!ENTITY x SYSTEM "file:///etc/passwd">]><x>&x;</x>', "text/xml")
