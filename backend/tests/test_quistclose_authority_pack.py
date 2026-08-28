from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from backend.app.citations.oscola import render_oscola
from backend.app.config import Settings
from backend.app.retrieval.source_manifest import (
    FAMILY_OFFICIAL_JUDGMENT,
    _source_selection_key,
    load_pack_identities,
    source_family,
)
from scripts.approve_quistclose_authority_pack import require_fresh_complete_scan
from scripts.import_quistclose_authority_pack import (
    PARLIAMENT_CONTENT_HOSTS,
    UKSC_HOSTS,
    _safe_host,
    validate_manifest,
    verify_representation_payload,
)
from scripts.materialize_quistclose_evidence import (
    DERIVED_SCHEMA,
    ZERO_REVIEWED_REPRESENTATIONS,
    apply_present_law_treatment_hold,
    derive_passage_chunks,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = PROJECT_ROOT / "config" / "quistclose_authority_pack.json"


def _manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def test_reviewed_manifest_has_exact_official_scope_and_legal_roles() -> None:
    manifest = _manifest()
    representations = validate_manifest(manifest)

    assert len(manifest["items"]) == 3
    assert len(representations) == 7
    assert {item["neutral_citation"] for item in manifest["items"]} == {
        "[2002] UKHL 12",
        "[2015] UKSC 66",
        "[2016] UKSC 47",
    }
    for item in manifest["items"]:
        roles = {passage["legal_role"] for passage in item["reviewed_passages"]}
        assert roles <= {"holding_ratio", "obiter"}
        assert "holding_ratio" in roles
        assert "obiter" in roles

    twinsectra = manifest["items"][0]
    assert any(
        passage["locator"] == "[12]-[17]" and passage["legal_role"] == "holding_ratio"
        for passage in twinsectra["reviewed_passages"]
    )
    assert any(
        passage["locator"] == "[77]-[95]" and passage["legal_role"] == "obiter"
        for passage in twinsectra["reviewed_passages"]
    )
    menelaou = manifest["items"][1]
    assert any(
        passage["locator"] == "[53]" and passage["legal_role"] == "obiter"
        for passage in menelaou["reviewed_passages"]
    )
    assert any(
        passage["locator"] == "[94]-[99]" and passage["legal_role"] == "holding_ratio"
        for passage in menelaou["reviewed_passages"]
    )
    angove = manifest["items"][2]
    assert any(
        passage["locator"] == "[24]-[31]" and passage["legal_role"] == "holding_ratio"
        for passage in angove["reviewed_passages"]
    )
    assert any(
        passage["locator"] == "[32]" and passage["legal_role"] == "obiter"
        for passage in angove["reviewed_passages"]
    )
    representations_with_passages = {
        passage["representation_id"]
        for item in manifest["items"]
        for passage in item["reviewed_passages"]
    }
    all_representation_ids = {
        representation["representation_id"]
        for item in manifest["items"]
        for representation in item["representations"]
    }
    assert all_representation_ids - representations_with_passages == set(
        ZERO_REVIEWED_REPRESENTATIONS
    )


def test_manifest_uses_only_reviewed_official_hosts_and_pinned_bytes() -> None:
    manifest = _manifest()
    for item in manifest["items"]:
        allowed = (
            PARLIAMENT_CONTENT_HOSTS if item["neutral_citation"] == "[2002] UKHL 12" else UKSC_HOSTS
        )
        assert _safe_host(item["official_case_url"], allowed)
        for representation in item["representations"]:
            assert _safe_host(representation["official_url"], allowed)
            assert len(representation["sha256"]) == 64
            assert representation["bytes"] > 0

    assert not _safe_host("https://supremecourt.uk.evil.example/uploads/judgment.pdf", UKSC_HOSTS)
    assert not _safe_host("http://supremecourt.uk/judgment.pdf", UKSC_HOSTS)


def test_payload_verifier_fails_before_accepting_changed_bytes() -> None:
    manifest = _manifest()
    item = manifest["items"][0]
    representation = item["representations"][0]
    changed = b"x" * representation["bytes"]
    with pytest.raises(ValueError, match="SHA-256 differs"):
        verify_representation_payload(item, representation, changed)


def test_oscola_renderer_accepts_all_three_verified_case_identities() -> None:
    rendered = [
        render_oscola(
            {
                "source_type": "case",
                "case_name": item["case_name"],
                "neutral_citation": item["neutral_citation"],
                "decision_date": item["decision_date"],
            }
        )
        for item in _manifest()["items"]
    ]
    assert rendered == [
        "*Twinsectra Ltd v Yardley* [2002] UKHL 12",
        "*Bank of Cyprus UK Ltd v Menelaou* [2015] UKSC 66",
        "*Bailey v Angove’s Pty Ltd* [2016] UKSC 47",
    ]


class _FakeDatabase:
    def __init__(self, *, stale: bool = False, omit_hash: bool = False) -> None:
        created_at = "2026-08-14T09:00:00+00:00" if stale else "2026-08-14T11:00:00+00:00"
        self.scan = {
            "id": "scan-fresh",
            "status": "complete",
            "expected_file_count": 2,
            "files_accounted": 2,
            "manifest_sha256": "f" * 64,
            "created_at": created_at,
            "completed_at": created_at,
        }
        self.omit_hash = omit_hash

    def fetchone(self, query: str, parameters: tuple = ()) -> dict | None:
        if "queued','running" in query:
            return None
        return self.scan

    def fetchall(self, query: str, parameters: tuple = ()) -> list[dict]:
        rows = [
            {"content_sha256": "a" * 64, "status": "citable"},
            {"content_sha256": "b" * 64, "status": "duplicate"},
        ]
        return rows[:1] if self.omit_hash else rows


def _freshness_report() -> dict:
    return {
        "downloaded_at": "2026-08-14T10:00:00+00:00",
        "items": [{"sha256": "a" * 64}, {"sha256": "b" * 64}],
    }


def test_approval_gate_requires_a_post_download_reconciled_scan() -> None:
    scan = require_fresh_complete_scan(_FakeDatabase(), _freshness_report())
    assert scan["id"] == "scan-fresh"

    with pytest.raises(ValueError, match="not created after"):
        require_fresh_complete_scan(_FakeDatabase(stale=True), _freshness_report())
    with pytest.raises(ValueError, match="did not safely account"):
        require_fresh_complete_scan(_FakeDatabase(omit_hash=True), _freshness_report())


def test_reviewed_paragraph_derivation_is_exact_stable_and_role_gated() -> None:
    data = b"""
    <html><body>
      <p>12. The undertaking restricted use of the money.</p>
      <p>13. The recipient had no free disposal.</p>
      <p>14. This paragraph discusses a theoretical alternative.</p>
      <p>15. Boundary paragraph.</p>
    </body></html>
    """
    item = {
        "authority_id": "neutral-citation:[2002] UKHL 12",
        "case_name": "Twinsectra Ltd v Yardley",
        "reviewed_passages": [
            {
                "representation_id": "rep-one",
                "locator": "[12]-[13]",
                "legal_role": "holding_ratio",
                "issues": ["restricted purpose"],
                "review_note": "Necessary reasoning.",
            },
            {
                "representation_id": "rep-one",
                "locator": "[14]",
                "legal_role": "obiter",
                "issues": ["theoretical alternative"],
                "review_note": "Not necessary to the result.",
            },
        ],
    }
    representation = {
        "representation_id": "rep-one",
        "kind": "browser_rendered_official_html_snapshot",
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    first = derive_passage_chunks(
        item=item,
        representation=representation,
        data=data,
        source_version_id="source-version-one",
        source_pack_manifest_sha256="f" * 64,
    )
    second = derive_passage_chunks(
        item=item,
        representation=representation,
        data=data,
        source_version_id="source-version-one",
        source_pack_manifest_sha256="f" * 64,
    )

    assert first == second
    assert [chunk.locator for chunk in first] == ["[12]", "[13]", "[14]"]
    assert all(
        chunk.text_sha256 == hashlib.sha256(chunk.text.encode()).hexdigest() for chunk in first
    )
    metadata = [json.loads(chunk.metadata_json) for chunk in first]
    assert all(value["schema"] == DERIVED_SCHEMA for value in metadata)
    assert [value["legal_role"] for value in metadata] == [
        "holding_ratio",
        "holding_ratio",
        "obiter",
    ]
    assert [value["material_claim_support_eligible"] for value in metadata] == [
        True,
        True,
        False,
    ]


def test_reviewed_paragraph_derivation_rejects_overlapping_roles() -> None:
    data = b"<html><body><p>12. One paragraph.</p></body></html>"
    item = {
        "authority_id": "neutral-citation:[2002] UKHL 12",
        "case_name": "Twinsectra Ltd v Yardley",
        "reviewed_passages": [
            {
                "representation_id": "rep-one",
                "locator": "[12]",
                "legal_role": "holding_ratio",
                "issues": ["issue"],
                "review_note": "Ratio.",
            },
            {
                "representation_id": "rep-one",
                "locator": "[12]",
                "legal_role": "obiter",
                "issues": ["issue"],
                "review_note": "Obiter.",
            },
        ],
    }
    representation = {
        "representation_id": "rep-one",
        "kind": "browser_rendered_official_html_snapshot",
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    with pytest.raises(ValueError, match="overlapping legal-role"):
        derive_passage_chunks(
            item=item,
            representation=representation,
            data=data,
            source_version_id="source-version-one",
            source_pack_manifest_sha256="f" * 64,
        )


def test_pack_is_sealed_into_official_judgment_identity_selection() -> None:
    packs = load_pack_identities(Settings())
    expected_bytes = MANIFEST_PATH.read_bytes()

    assert packs["quistclose_pack_version"] == _manifest()["version"]
    assert packs["quistclose_pack_sha256"] == hashlib.sha256(expected_bytes).hexdigest()
    assert set(packs["quistclose_neutral_citations"]) == {
        "neutral-citation:[2002] UKHL 12",
        "neutral-citation:[2015] UKSC 66",
        "neutral-citation:[2016] UKSC 47",
    }
    assert source_family("neutral-citation:[2002] UKHL 12") == FAMILY_OFFICIAL_JUDGMENT


def test_split_official_judgment_selection_key_accepts_sqlite_rows() -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("CREATE TABLE rows(stable_identifier TEXT, metadata_json TEXT)")
        for representation_id in ("part-1", "part-3"):
            connection.execute(
                "INSERT INTO rows VALUES (?, ?)",
                (
                    "neutral-citation:[2002] UKHL 12",
                    json.dumps(
                        {
                            "reviewed_evidence_materialization": {"chunk_count": 1},
                            "official_snapshot": {"representation_id": representation_id},
                        }
                    ),
                ),
            )
        rows = connection.execute("SELECT * FROM rows").fetchall()
        keys = [_source_selection_key(row) for row in rows]
    finally:
        connection.close()

    assert len(set(keys)) == 2
    assert all("#official-representation:" in key for key in keys)


def test_historical_case_bytes_do_not_claim_present_law_currentness() -> None:
    metadata = apply_present_law_treatment_hold(
        {"identity_verified": True, "currentness_verified": True},
        source_pack_manifest_sha256="f" * 64,
    )

    assert metadata["identity_verified"] is True
    assert metadata["currentness_verified"] is False
    assert metadata["subsequent_treatment_check_required"] is True
    assert metadata["subsequent_treatment_verified"] is False
    assert metadata["present_law_retrieval_eligible"] is False
