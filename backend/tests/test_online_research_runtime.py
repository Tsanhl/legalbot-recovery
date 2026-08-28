from __future__ import annotations

from datetime import date
from pathlib import Path

import httpx
import pytest

from app.config import Settings
from app.db import Database
from app.research.gap_queue import GapQueue, GapStatus
from app.research.runtime import AllowlistedHttpFetcher, OfficialOnlineResearcher
from app.research.source_registry import OfficialSourceRegistry

PROJECT_ROOT = Path(__file__).resolve().parents[2]
AS_OF = date(2026, 8, 11)

ATOM = b"""<?xml version="1.0"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <id>http://www.legislation.gov.uk/id/ukpga/2010/15</id>
    <title>Equality Act 2010</title>
  </entry>
</feed>
"""


def clml(
    *,
    identity: str = "ukpga/2010/15",
    valid: str = "2026-08-11",
    unapplied: bool = False,
    text: str = "A person has the protected statutory right described in this section.",
) -> bytes:
    effect = (
        "<ukm:UnappliedEffects><ukm:UnappliedEffect Type='amended'/></ukm:UnappliedEffects>"
        if unapplied
        else ""
    )
    return f"""<?xml version="1.0"?>
<Legislation xmlns="http://www.legislation.gov.uk/namespaces/legislation"
 xmlns:dc="http://purl.org/dc/elements/1.1/"
 xmlns:dct="http://purl.org/dc/terms/"
 xmlns:atom="http://www.w3.org/2005/Atom"
 xmlns:ukm="http://www.legislation.gov.uk/namespaces/metadata" RestrictExtent="E+W">
 <ukm:Metadata>
  <dc:title>Equality Act 2010</dc:title>
  <dct:valid>{valid}</dct:valid>
  <dct:modified>2026-08-01T09:00:00Z</dct:modified>
  <atom:link rel="self" href="http://www.legislation.gov.uk/{identity}/{valid}/data.xml"/>
  {effect}
 </ukm:Metadata>
 <Primary><Body><P1group><P1 id="section-1"><Pnumber>1</Pnumber>
  <P1para><Text>{text}</Text></P1para>
 </P1></P1group></Body></Primary>
</Legislation>""".encode()


def registry() -> OfficialSourceRegistry:
    return OfficialSourceRegistry.load(PROJECT_ROOT / "config" / "official_sources.json")


def make_runtime(
    tmp_path: Path, handler: httpx.MockTransport
) -> tuple[OfficialOnlineResearcher, Database, GapQueue]:
    database = Database(tmp_path / "catalog.sqlite3")
    database.initialize()
    queue = GapQueue(tmp_path / "official-candidates.json", allow_writes=True)
    researcher = OfficialOnlineResearcher(
        settings=Settings(project_root=tmp_path, official_research_enabled=True),
        database=database,
        registry=registry(),
        fetcher=AllowlistedHttpFetcher(transport=handler),
        gap_queue=queue,
    )
    return researcher, database, queue


@pytest.mark.asyncio
async def test_legislation_structured_api_returns_verified_answer_scoped_evidence(
    tmp_path: Path,
) -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        if request.url.path == "/search/data.feed":
            return httpx.Response(
                200, headers={"content-type": "application/atom+xml"}, content=ATOM
            )
        return httpx.Response(200, headers={"content-type": "application/xml"}, content=clml())

    researcher, database, queue = make_runtime(tmp_path, httpx.MockTransport(handler))
    spans, searches, rejections = await researcher.research_gap(
        proposition="What does Equality Act 2010 section 1 provide?",
        jurisdiction="England and Wales",
        subject="employment",
        as_of_date=AS_OF,
    )

    assert len(spans) == 1
    assert spans[0].locator == "s 1"
    assert spans[0].identity_verified and spans[0].currentness_verified
    assert spans[0].canonical_citation == "Equality Act 2010"
    assert searches == [
        {"source": "legislation_gov_uk", "action": "structured_api", "result": "qualified"}
    ]
    assert rejections == []
    assert all(url.startswith("https://www.legislation.gov.uk/") for url in requested)
    build = database.fetchone("SELECT * FROM index_builds WHERE id=?", (spans[0].index_build_id,))
    assert build is not None
    assert build["status"] == "online_answer_staging_nonpromotable"
    assert build["vector_count"] == 0
    document = database.fetchone(
        "SELECT * FROM documents WHERE id=(SELECT document_id FROM source_versions WHERE id=?)",
        (spans[0].source_version_id,),
    )
    assert document is not None
    assert document["retrieval_canonical"] == 0 and document["searchable_text"] == 0
    assert queue.list()[0].status is GapStatus.REVIEW_REQUIRED
    assert not (tmp_path / "data" / "indexes" / "ACTIVE").exists()
    database.store_evidence([spans[0].model_dump(mode="json")])
    database.close()


@pytest.mark.asyncio
async def test_redirect_cannot_escape_registered_origin(tmp_path: Path) -> None:
    requested_hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_hosts.append(str(request.url.host))
        return httpx.Response(302, headers={"location": "https://evil.example/private"})

    researcher, database, _ = make_runtime(tmp_path, httpx.MockTransport(handler))
    spans, _, rejections = await researcher.research_gap(
        proposition="What does Equality Act 2010 section 1 provide?",
        jurisdiction="England and Wales",
        subject="employment",
        as_of_date=AS_OF,
    )
    assert spans == []
    assert "official_url_outside_allowlist" in rejections
    assert requested_hosts == ["www.legislation.gov.uk"]
    database.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("feed", "expected"),
    [
        (b"not xml", "official_xml_malformed"),
        (b"<!DOCTYPE foo><feed/>", "official_xml_unsafe_or_empty"),
    ],
)
async def test_malformed_or_unsafe_official_data_is_rejected(
    tmp_path: Path, feed: bytes, expected: str
) -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200, headers={"content-type": "application/atom+xml"}, content=feed
        )
    )
    researcher, database, _ = make_runtime(tmp_path, transport)
    spans, _, rejections = await researcher.research_gap(
        proposition="What does Equality Act 2010 section 1 provide?",
        jurisdiction="England and Wales",
        subject=None,
        as_of_date=AS_OF,
    )
    assert spans == [] and expected in rejections
    database.close()


@pytest.mark.asyncio
async def test_network_failure_is_an_honest_gap_not_an_exception(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=request)

    researcher, database, _ = make_runtime(tmp_path, httpx.MockTransport(handler))
    spans, searches, rejections = await researcher.research_gap(
        proposition="What does Equality Act 2010 section 1 provide?",
        jurisdiction="England and Wales",
        subject=None,
        as_of_date=AS_OF,
    )
    assert spans == []
    assert searches[0]["result"] == "unavailable"
    assert rejections == ["official_network_unavailable"]
    database.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("document", "expected"),
    [
        (clml(identity="ukpga/2010/16"), "official_identity_mismatch"),
        (clml(valid="2026-08-10"), "official_point_in_time_mismatch"),
        (clml(unapplied=True), "official_unapplied_effects_present"),
    ],
)
async def test_identity_and_currentness_fail_closed(
    tmp_path: Path, document: bytes, expected: str
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/search/data.feed":
            return httpx.Response(
                200, headers={"content-type": "application/atom+xml"}, content=ATOM
            )
        return httpx.Response(200, headers={"content-type": "application/xml"}, content=document)

    researcher, database, _ = make_runtime(tmp_path, httpx.MockTransport(handler))
    spans, _, rejections = await researcher.research_gap(
        proposition="What does Equality Act 2010 section 1 provide?",
        jurisdiction="England and Wales",
        subject=None,
        as_of_date=AS_OF,
    )
    assert spans == [] and expected in rejections
    assert database.fetchone("SELECT id FROM index_builds") is None
    database.close()


@pytest.mark.asyncio
async def test_find_case_law_is_link_only_and_never_fetched_or_embedded(tmp_path: Path) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500)

    researcher, database, queue = make_runtime(tmp_path, httpx.MockTransport(handler))
    spans, searches, rejections = await researcher.research_gap(
        proposition="See https://caselaw.nationalarchives.gov.uk/uksc/2025/1",
        jurisdiction="England and Wales",
        subject=None,
        as_of_date=AS_OF,
    )
    assert spans == [] and calls == 0
    assert searches[0]["source"] == "find_case_law"
    assert rejections == ["find_case_law_metadata_only_no_full_text_or_vectors"]
    assert queue.list()[0].candidates[0].source_id == "find_case_law"
    assert database.fetchone("SELECT id FROM index_builds") is None
    database.close()


@pytest.mark.asyncio
async def test_raw_proposition_terms_never_become_network_search_text(
    tmp_path: Path,
) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500)

    researcher, database, queue = make_runtime(tmp_path, httpx.MockTransport(handler))
    spans, searches, rejections = await researcher.research_gap(
        proposition=(
            "The private factual account mentions contract negligence privacy "
            "remedies and asks what might apply."
        ),
        jurisdiction="England and Wales",
        subject=None,
        as_of_date=AS_OF,
    )

    assert spans == [] and searches == [] and rejections == []
    assert calls == 0
    assert queue.list() == ()
    database.close()


@pytest.mark.asyncio
async def test_proposition_url_is_review_signal_and_never_directly_fetched(
    tmp_path: Path,
) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500)

    researcher, database, queue = make_runtime(tmp_path, httpx.MockTransport(handler))
    spans, searches, rejections = await researcher.research_gap(
        proposition="Consider https://www.gov.uk/example-guidance?private=removed",
        jurisdiction="England and Wales",
        subject=None,
        as_of_date=AS_OF,
    )

    assert spans == [] and calls == 0
    assert searches == [
        {
            "source": "gov_uk",
            "action": "official_link_candidate",
            "result": "review_required",
        }
    ]
    assert rejections == ["official_link_requires_registered_identity_review"]
    candidate = queue.list()[0].candidates[0]
    assert candidate.canonical_url == "https://www.gov.uk/example-guidance"
    database.close()


def test_same_official_url_with_changed_content_gets_a_new_non_searchable_document(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "catalog.sqlite3")
    database.initialize()
    common = {
        "source_id": "legislation_gov_uk",
        "canonical_url": "https://www.legislation.gov.uk/ukpga/2010/15",
        "title": "Equality Act 2010",
        "as_of_date": AS_OF,
        "currentness_status": "point_in_time:2026-08-11;unapplied_effects:0",
        "licence_name": "Open Government Licence",
        "licence_url": None,
        "lane": "primary_authority",
        "jurisdiction": "England and Wales",
        "subject": "employment",
        "excerpts": [{"locator": "s 1", "text": "A sufficiently long official excerpt."}],
    }
    first = database.stage_online_source(content_sha256="a" * 64, **common)
    second = database.stage_online_source(content_sha256="b" * 64, **common)
    assert first["document_id"] != second["document_id"]
    rows = database.fetchall(
        "SELECT content_sha256, retrieval_canonical, searchable_text FROM documents ORDER BY id"
    )
    assert {row["content_sha256"] for row in rows} == {"a" * 64, "b" * 64}
    assert all(not row["retrieval_canonical"] and not row["searchable_text"] for row in rows)
    assert database.fetchone("SELECT id FROM index_builds WHERE status='active'") is None
    assert (
        len(database.fetchall("SELECT id FROM reviews WHERE review_type='online_source_version'"))
        == 2
    )
    database.close()


def test_online_staging_deduplicates_only_within_the_semantic_partition(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "catalog.sqlite3")
    database.initialize()
    common = {
        "source_id": "legislation_gov_uk",
        "title": "Official source",
        "content_sha256": "c" * 64,
        "as_of_date": AS_OF,
        "currentness_status": "point_in_time:2026-08-11;unapplied_effects:0",
        "licence_name": "Open Government Licence",
        "licence_url": None,
        "jurisdiction": "England and Wales",
        "subject": "employment",
        "excerpts": [{"locator": "s 1", "text": "A located official source excerpt."}],
    }
    primary = database.stage_online_source(
        canonical_url="https://www.legislation.gov.uk/ukpga/2010/15",
        lane="primary_authority",
        **common,
    )
    official = database.stage_online_source(
        canonical_url="https://www.legislation.gov.uk/ukpga/2010/15",
        lane="official_secondary",
        **common,
    )
    primary_alias = database.stage_online_source(
        canonical_url="https://www.legislation.gov.uk/ukpga/2010/15/section/1",
        lane="primary_authority",
        **common,
    )

    rows = {
        str(row["id"]): row
        for row in database.fetchall(
            "SELECT id, lane, duplicate_of, retrieval_canonical FROM documents"
        )
    }
    assert rows[primary["document_id"]]["duplicate_of"] is None
    assert rows[official["document_id"]]["duplicate_of"] is None
    assert rows[primary_alias["document_id"]]["duplicate_of"] == primary["document_id"]
    assert all(not row["retrieval_canonical"] for row in rows.values())
    assert database.admin_overview()["exact_duplicates"] == 2
    assert database.admin_overview()["logical_exact_duplicates"] == 1
    assert database.fetchall("PRAGMA foreign_key_check") == []
    database.close()
