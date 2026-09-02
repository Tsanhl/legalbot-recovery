from __future__ import annotations

import json
from pathlib import Path

from app.evaluation.ge_factual_gap_fill import (
    chunk_is_factual,
    fill_gaps,
    host_allowed,
    looks_officially_searchable,
    lookup_official,
    official_urls,
    remaining_fetchable_titles,
    resolve_official_search,
    scan_results,
    title_already_present,
)

SAMPLE_XML = (
    b'<Legislation DocumentURI="https://www.legislation.gov.uk/ukpga/2000/1">'
    b"<title>Rome I Regulation</title>"
    b"<Body>"
    b'<P1 DocumentURI="https://www.legislation.gov.uk/ukpga/2000/1/section/1">'
    b"<Pnumber>1</Pnumber>"
    b"<Text>A person shall not do the prohibited act without lawful authority "
    b"remaining in force after commencement of this provision.</Text>"
    b"</P1>"
    b"</Body>"
    b"</Legislation>"
)


def test_unidentified_mediation_act_is_never_looked_up() -> None:
    assert lookup_official("Mediation Act 2025") is None
    assert lookup_official("The unidentified Mediation Act 2025") is None


def test_wikipedia_and_commentary_hosts_are_rejected() -> None:
    assert host_allowed("https://en.wikipedia.org/wiki/Rome_I") is False
    assert host_allowed("https://www.bailii.org/ew/cases/EWHC/Comm/2002/2059.html") is False
    assert host_allowed("https://www.legislation.gov.uk/eur/2008/593/data.xml") is True
    assert (
        host_allowed("https://caselaw.nationalarchives.gov.uk/ewca/civ/2023/1416/data.xml") is True
    )


def test_pdf_is_only_a_fallback_after_official_xml() -> None:
    urls = official_urls({"kind": "legislation", "identifier": "eur/2008/593"})
    assert urls[0].endswith("/data.xml")
    assert any(url.endswith("/data.pdf") for url in urls)
    assert urls.index(next(url for url in urls if url.endswith("/data.pdf"))) > 0


def test_scan_records_gaps_and_wrong_routes_separately(tmp_path: Path) -> None:
    results = tmp_path / "RESULTS.jsonl"
    rows = [
        {
            "case_id": "gap:1",
            "known_missing_primary_authorities": ["Rome I Regulation"],
            "evidence": [],
            "factual_result": {"diagnostic_checks": {"issue_relevance": {"outcome": "FAIL"}}},
        },
        {
            "case_id": "wrong:1",
            "known_missing_primary_authorities": [],
            "evidence": [{"title": "Arbitration Act 1996", "locator": "section 9"}],
            "factual_result": {"diagnostic_checks": {"issue_relevance": {"outcome": "FAIL"}}},
        },
    ]
    results.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    scanned = scan_results(results)
    assert scanned["missing"][0]["title"] == "Rome I Regulation"
    assert scanned["wrong_routes"][0]["title"] == "Arbitration Act 1996"
    assert scanned["wrong_routes"][0]["reason"] == "negative_wrong_route"


def test_chunk_requires_locator_bound_operative_quote() -> None:
    body = (
        "A person shall not do the prohibited act without lawful authority "
        "remaining in force after commencement."
    )
    assert chunk_is_factual("Example Act", "section 1", body) is True
    assert chunk_is_factual("Example Act", "", body) is False
    assert chunk_is_factual("Example Act", "section 1", "...") is False


def test_fill_gaps_indexes_official_xml_and_refuses_unidentified(tmp_path: Path) -> None:
    results = tmp_path / "RESULTS.jsonl"
    rows = [
        {
            "case_id": "gap:rome",
            "known_missing_primary_authorities": ["Rome I Regulation"],
            "evidence": [],
            "factual_result": {"diagnostic_checks": {"issue_relevance": {"outcome": "FAIL"}}},
        },
        {
            "case_id": "gap:unknown",
            "known_missing_primary_authorities": ["Mediation Act 2025"],
            "evidence": [],
            "factual_result": {"diagnostic_checks": {"issue_relevance": {"outcome": "FAIL"}}},
        },
        {
            "case_id": "wrong:1",
            "known_missing_primary_authorities": [],
            "evidence": [{"title": "Arbitration Act 1996", "locator": "section 9"}],
            "factual_result": {"diagnostic_checks": {"issue_relevance": {"outcome": "FAIL"}}},
        },
    ]
    results.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    fetched: list[str] = []

    def fetch(url: str) -> dict[str, object]:
        fetched.append(url)
        if "wikipedia" in url or "bailii" in url:
            raise AssertionError(f"non-official host fetched: {url}")
        return {
            "ok": True,
            "url": url,
            "status": 200,
            "content_type": "application/xml",
            "bytes": len(SAMPLE_XML),
            "sha256": "a" * 64,
            "body": SAMPLE_XML,
        }

    output = tmp_path / "pack"
    manifest = fill_gaps(
        results_path=results,
        output=output,
        already_titled=set(),
        fetch=fetch,  # type: ignore[arg-type]
        project_root=tmp_path,
    )
    assert manifest["admitted"] is False
    assert manifest["legal_gold"] is False
    assert manifest["live_catalogue_insert"] is False
    assert manifest["wrong_routes_indexed"] is False
    assert manifest["ingested_count"] == 1
    assert manifest["sources"][0]["title"] == "Rome I Regulation"
    log = json.loads((output / "GAP-FILL-LOG.json").read_text(encoding="utf-8"))
    assert any(row["error"] == "do_not_admit_unidentified_title" for row in log["failed"])
    assert log["wrong_routes"][0]["title"] == "Arbitration Act 1996"
    assert fetched
    assert all(
        "legislation.gov.uk" in url or "caselaw.nationalarchives.gov.uk" in url for url in fetched
    )


def test_already_staged_title_is_not_refetched(tmp_path: Path) -> None:
    results = tmp_path / "RESULTS.jsonl"
    results.write_text(
        json.dumps(
            {
                "case_id": "gap:1",
                "known_missing_primary_authorities": ["Rome I Regulation"],
                "evidence": [],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    def fetch(url: str) -> dict[str, object]:
        raise AssertionError(f"should not fetch already staged title: {url}")

    output = tmp_path / "pack"
    manifest = fill_gaps(
        results_path=results,
        output=output,
        already_titled={"rome i regulation"},
        fetch=fetch,  # type: ignore[arg-type]
        project_root=tmp_path,
    )
    assert manifest["ingested_count"] == 0
    assert manifest["skipped_count"] == 1


def test_wills_alias_counts_as_already_staged() -> None:
    already = {"wills act 1837 (as at 2024-01-15)"}
    assert title_already_present(
        "Wills Act 1837 section 9 as it had effect on 2024-01-15", already
    )


def test_official_atom_search_accepts_only_unique_exact_title() -> None:
    atom = (
        b'<?xml version="1.0"?>'
        b'<feed xmlns="http://www.w3.org/2005/Atom">'
        b"<entry><title>Example Missing Act 2001</title>"
        b"<id>https://www.legislation.gov.uk/ukpga/2001/2</id></entry>"
        b"</feed>"
    )

    def fetch(url: str) -> dict[str, object]:
        assert "wikipedia" not in url
        assert "bailii" not in url
        return {
            "ok": True,
            "url": url,
            "status": 200,
            "content_type": "application/atom+xml",
            "bytes": len(atom),
            "sha256": "b" * 64,
            "body": atom,
        }

    spec = resolve_official_search("Example Missing Act 2001", fetch)
    assert spec == {
        "kind": "legislation",
        "identifier": "ukpga/2001/2",
        "resolved_by": "official_atom_exact_title",
    }


def test_official_atom_search_fails_closed_when_ambiguous() -> None:
    atom = (
        b'<?xml version="1.0"?>'
        b'<feed xmlns="http://www.w3.org/2005/Atom">'
        b"<entry><title>Example Missing Act 2001</title>"
        b"<id>https://www.legislation.gov.uk/ukpga/2001/2</id></entry>"
        b"<entry><title>Example Missing Act 2001</title>"
        b"<id>https://www.legislation.gov.uk/ukpga/2001/3</id></entry>"
        b"</feed>"
    )

    def fetch(url: str) -> dict[str, object]:
        return {"ok": True, "url": url, "status": 200, "content_type": "application/xml", "body": atom}

    assert resolve_official_search("Example Missing Act 2001", fetch) is None


def test_fill_gaps_searches_official_feed_then_indexes(tmp_path: Path) -> None:
    results = tmp_path / "RESULTS.jsonl"
    results.write_text(
        json.dumps(
            {
                "case_id": "gap:search",
                "known_missing_primary_authorities": ["Example Missing Act 2001"],
                "evidence": [],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    atom = (
        b'<?xml version="1.0"?>'
        b'<feed xmlns="http://www.w3.org/2005/Atom">'
        b"<entry><title>Example Missing Act 2001</title>"
        b"<id>https://www.legislation.gov.uk/ukpga/2001/2</id></entry>"
        b"</feed>"
    )
    fetched: list[str] = []

    def fetch(url: str) -> dict[str, object]:
        fetched.append(url)
        if "wikipedia" in url or "bailii" in url:
            raise AssertionError(url)
        if "/title/" in url:
            body = atom
            content_type = "application/atom+xml"
        else:
            body = SAMPLE_XML
            content_type = "application/xml"
        return {
            "ok": True,
            "url": url,
            "status": 200,
            "content_type": content_type,
            "bytes": len(body),
            "sha256": "c" * 64,
            "body": body,
        }

    manifest = fill_gaps(
        results_path=results,
        output=tmp_path / "pack",
        already_titled=set(),
        fetch=fetch,  # type: ignore[arg-type]
        project_root=tmp_path,
    )
    assert manifest["ingested_count"] == 1
    assert manifest["legal_gold"] is False
    assert any("/title/" in url for url in fetched)
    assert any(url.endswith("/data.xml") for url in fetched)


def test_remaining_includes_searchable_unregistered_titles(tmp_path: Path) -> None:
    results = tmp_path / "RESULTS.jsonl"
    results.write_text(
        json.dumps(
            {
                "case_id": "gap:1",
                "known_missing_primary_authorities": [
                    "Example Missing Act 2001",
                    "ICC Mediation Rules (contractually incorporated edition)",
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    remaining = remaining_fetchable_titles(results_path=results, already=set())
    assert remaining == ["Example Missing Act 2001"]
    assert looks_officially_searchable("Example Missing Act 2001") is True
    assert looks_officially_searchable("ICC Mediation Rules (contractually incorporated edition)") is False
