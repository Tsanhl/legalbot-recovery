from __future__ import annotations

from datetime import date

from app.citations.oscola import render_oscola
from app.config import Settings
from app.jurisdictions import compatible
from app.quality.evidence import (
    RESEARCH_MODE_ROUTE,
    evidence_span_eligible_for_drafting,
    research_mode_unverified,
)
from app.retrieval.unified_local import UnifiedLocalRetriever, _Row
from app.types import EvidenceSpan, MaterialLane


def _span(**overrides) -> EvidenceSpan:
    values = dict(
        id="E0123456789", source_version_id="sv-1", chunk_id="c-1", text="Some provision.",
        locator="s 1", lane=MaterialLane.PRIMARY_AUTHORITY, jurisdiction="England and Wales",
        subject="land", citation_data={"source_type": "unverified_source", "title": "A Source"},
        content_sha256="0" * 64, index_build_id="candidate",
        retrieval_route=RESEARCH_MODE_ROUTE,
    )
    values.update(overrides)
    return EvidenceSpan(**values)


def test_only_research_mode_spans_bypass_verification_for_drafting() -> None:
    assert research_mode_unverified(_span())
    assert evidence_span_eligible_for_drafting(_span(), as_of_date=date(2026, 9, 25))
    ordinary = _span(retrieval_route="hybrid")
    assert not research_mode_unverified(ordinary)
    assert not evidence_span_eligible_for_drafting(ordinary, as_of_date=date(2026, 9, 25))
    # Official-record checks never lift a research span onto the reviewed-evidence gates.
    verified = _span(identity_verified=True, currentness_verified=True)
    assert research_mode_unverified(verified)


def test_unverified_source_citation_is_labelled() -> None:
    assert render_oscola({"source_type": "unverified_source", "title": "A Source"}) == (
        "A Source [unverified source]"
    )


def test_england_question_accepts_england_and_wales_but_not_scottish_sources() -> None:
    assert compatible("England", "England and Wales")
    assert compatible("Wales", "United Kingdom")
    assert not compatible("Scotland", "England and Wales")


def test_unified_span_marks_staged_sources_unverified(tmp_path) -> None:
    retriever = UnifiedLocalRetriever(Settings(project_root=tmp_path, test_mode=True), "candidate")
    record = {
        "source_version_id": "sv-9", "chunk_id": "chunk-9", "text": "Rule text.",
        "locator": "p 3", "lane": "scholarship", "jurisdiction": "England and Wales",
        "subject": "trusts", "review_status": "staged", "currentness_status": "unknown",
        "title": "An Article", "canonical_url": "", "content_sha256": "a" * 64,
    }
    span = retriever._span(_Row("Eaaaaaaaaaa", record, 0.5), jurisdiction="England")
    assert span.identity_verified is False and span.currentness_verified is False
    assert span.citation_data == {"source_type": "unverified_source", "title": "An Article"}
    assert span.retrieval_route == RESEARCH_MODE_ROUTE
    assert research_mode_unverified(span)


class _StageStore:
    def __init__(self):
        self.objects: dict[str, dict] = {}
        self.completed = None

    def completed_stage_attempt(self, *args):
        return self.completed

    def next_stage_attempt_number(self, *args):
        return 1

    def store_stage_attempt(self, **kwargs):
        pass

    def finish_stage_attempt(self, attempt_id, **kwargs):
        self.completed = {"output_object_key": kwargs["output_object_key"]}

    def put_json(self, *, namespace, value, metadata):
        key = f"k{len(self.objects)}"
        self.objects[key] = value
        return key

    def get_json(self, key):
        return self.objects[key]


def _runner(model):
    from types import SimpleNamespace

    store = _StageStore()
    settings = SimpleNamespace(research_mode=True, owner_identifiers=())
    return SimpleNamespace(settings=settings, database=store, objects=store, model=model)


FROZEN = (
    "Saved conversation (user facts and assistant questions; not legal authority).\n"
    "USER MESSAGE 1:\nMy landlord kept my deposit after my tenancy in Leeds ended.\n\n"
    "ASSISTANT MESSAGE 2:\nWas the deposit protected in a scheme?\n\n"
    "CURRENT USER MESSAGE:\nNo, it was never protected. What can I claim?"
)


def test_chat_follow_up_gets_a_standalone_retrieval_query() -> None:
    import asyncio

    from app.orchestration.runner import AnswerRunner

    class Model:
        async def invoke_json(self, **kwargs):
            return "", {
                "standalone_query": "What can a tenant claim when the landlord never protected the deposit?",
                "used_message_ids": ["frozen-1", "frozen-2"],
            }

    runner = _runner(Model())
    query = asyncio.run(AnswerRunner._chat_retrieval_query(runner, job_id="j1", question=FROZEN))
    assert query.startswith("What can a tenant claim")
    # A retry replays the checkpoint instead of calling the model again.
    runner.model = None
    assert asyncio.run(AnswerRunner._chat_retrieval_query(runner, job_id="j1", question=FROZEN)) == query


def test_rejected_rewrite_falls_back_to_the_full_question() -> None:
    import asyncio

    from app.orchestration.runner import AnswerRunner

    class Model:
        async def invoke_json(self, **kwargs):
            return "", {"standalone_query": "Tenant in Manchester paid £999", "used_message_ids": []}

    runner = _runner(Model())
    assert asyncio.run(
        AnswerRunner._chat_retrieval_query(runner, job_id="j2", question=FROZEN)
    ) == FROZEN


def test_foreign_material_must_name_its_legal_system() -> None:
    from app.jurisdictions import RESEARCH_FOREIGN_ROUTE, admissible, attributed_foreign_use

    assert attributed_foreign_use("Under EU law, Article 34 TFEU catches the rule.", "European Union")
    assert attributed_foreign_use("Comparatively, other jurisdictions differ.", "Comparative")
    assert attributed_foreign_use("Scots law takes a different view.", "Scotland")
    assert not attributed_foreign_use("The seller must deliver the goods.", "European Union")
    assert not attributed_foreign_use("", "")
    assert admissible("England", "England and Wales")
    assert not admissible("England", "Scotland")
    assert admissible("England", "Scotland", None, RESEARCH_FOREIGN_ROUTE)


def _row(scope: str, jurisdiction: str = "Scotland", score: float = 0.6) -> _Row:
    record = {
        "source_version_id": "sv-9", "chunk_id": "chunk-9", "text": "Rule text.",
        "locator": "p 3", "lane": "primary_authority", "jurisdiction": jurisdiction,
        "subject": "contract", "review_status": "staged", "currentness_status": "unknown",
        "title": "A Scottish Case", "canonical_url": "", "content_sha256": "a" * 64,
    }
    return _Row("Eaaaaaaaaaa", record, 0.5, score=score, scope=scope)


def test_research_spans_carry_the_rerank_floor_and_foreign_label(tmp_path) -> None:
    from app.jurisdictions import RESEARCH_FOREIGN_ROUTE

    retriever = UnifiedLocalRetriever(Settings(project_root=tmp_path, test_mode=True), "candidate")
    forum = retriever._span(_row("forum", "England and Wales"), jurisdiction="England")
    assert forum.retrieval_threshold_qualified is True
    assert forum.retrieval_relevance_score == 0.6
    assert forum.retrieval_route == RESEARCH_MODE_ROUTE
    foreign = retriever._span(_row("comparative"), jurisdiction="England")
    assert foreign.retrieval_route == RESEARCH_FOREIGN_ROUTE
    assert foreign.citation_data["title"] == "A Scottish Case (Scotland)"
    assert research_mode_unverified(foreign)


class _FakeQuery:
    def __init__(self, rows):
        self.rows = rows

    def limit(self, n):
        return self

    def to_list(self):
        return [dict(row) for row in self.rows]


class _FakeTable:
    def __init__(self, rows):
        self.rows = rows

    def search(self, *args, **kwargs):
        return _FakeQuery(self.rows)

    def list_indices(self):
        return []


class _Embedder:
    def embed_query(self, text):
        return (0.1, 0.2)


class _Reranker:
    def __init__(self, scores):
        self.scores = scores

    def rerank(self, query, hits, *, limit):
        from dataclasses import replace

        return [replace(hit, rerank_score=self.scores[hit.chunk.title]) for hit in hits]


def _record(title, jurisdiction, sha):
    return {
        "source_version_id": f"sv-{title}", "chunk_id": f"c-{title}", "text": f"{title} text",
        "lane": "primary_authority", "jurisdiction": jurisdiction, "subject": "x",
        "review_status": "staged", "title": title, "content_sha256": sha * 64,
    }


def test_eu_question_keeps_eu_sources_and_comparative_material_is_capped(tmp_path) -> None:
    retriever = UnifiedLocalRetriever(Settings(project_root=tmp_path, test_mode=True), "candidate")
    rows = [
        _record("forum", "England and Wales", "1"),
        _record("eu", "European Union", "2"),
        *[_record(f"scot{i}", "Scotland", str(3 + i)) for i in range(5)],
        _record("weak", "Comparative", "9"),
    ]
    scores = {"forum": 0.9, "eu": 0.8, "weak": 0.2, **{f"scot{i}": 0.7 for i in range(5)}}
    retriever._tables = {"authority": _FakeTable(rows)}
    retriever._embedder = _Embedder()
    retriever._reranker = _Reranker(scores)
    retriever._decisions = {}

    ordinary = {row.record["title"]: row.scope for row in retriever._search("Is the term fair?", "England")}
    assert ordinary["forum"] == "forum"
    assert ordinary["eu"] == "comparative"
    assert "weak" not in ordinary  # below the comparative floor
    assert sum(scope == "comparative" for scope in ordinary.values()) == 3  # capped

    eu = {row.record["title"]: row.scope for row in retriever._search("Does Article 34 TFEU apply?", "England")}
    assert eu["eu"] == "targeted"


def test_knowledge_notes_become_authority_queries() -> None:
    from app.orchestration.issues import build_issue_plan
    from app.types import IssueSpottingNote

    note = IssueSpottingNote(
        id="K1", source_version_id="knowledge-criminal-11", chunk_id="K1",
        text=(
            "Criminal — Duress — Exclusions\n"
            "- Not available for murder (Howe [1987] AC 417) or attempted murder "
            "(Gotts [1992] 2 AC 412)."
        ),
        jurisdiction="England and Wales", subject="criminal", content_sha256="b" * 64,
        index_build_id="candidate",
    )
    plan = build_issue_plan(
        question="Can my client rely on duress for attempted murder?",
        jurisdiction="England", subject="criminal", notes=[note],
    )
    knowledge = [query for query in plan.queries if "Authorities:" in query]
    assert knowledge == [
        "England criminal. Legal issue: Exclusions. Authorities: Howe [1987]; Gotts [1992]."
    ]
    assert "Not available for murder" not in " ".join(plan.queries)


def test_knowledge_builder_keeps_only_law_and_rules() -> None:
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parents[2] / "scripts/build_knowledge_lane.py"
    spec = importlib.util.spec_from_file_location("build_knowledge_lane", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    body = (
        "# Duress\n\n## Elements\n- Threat of death or serious injury (Hasan [2005] UKHL 22).\n"
        "### Worked pattern\n- Facts about a bank robbery.\n"
        "## Reflection questions\n- Is the law fair?\n### Nested\n- dropped too\n"
        "## Method for problem questions\n1. Offence first.\n"
        "## Essay angles\n- Critique.\n"
    )
    kept, dropped = module.law_sections(body)
    assert [heading for heading, _ in kept] == ["Elements", "Method for problem questions"]
    assert "Facts about a bank robbery" not in kept[0][1]
    assert dropped == ["Worked pattern", "Reflection questions", "Essay angles"]


def test_official_record_check_upgrades_citation_but_keeps_research_path(tmp_path) -> None:
    retriever = UnifiedLocalRetriever(Settings(project_root=tmp_path, test_mode=True), "candidate")
    retriever._verified = {
        "sv-9": {
            "identity_verified": True,
            "currentness_verified": False,
            "currentness_status": "case_later_treatment_unchecked",
            "citation_data": {
                "source_type": "case", "case_name": "R v Noye",
                "neutral_citation": "[2011] EWCA Crim 650",
                "research_note": "later treatment not checked",
            },
        }
    }
    span = retriever._span(_row("forum", "England and Wales"), jurisdiction="England")
    assert span.identity_verified and not span.currentness_verified
    assert research_mode_unverified(span)
    assert render_oscola(span.citation_data) == (
        "*R v Noye* [2011] EWCA Crim 650 [later treatment not checked]"
    )


def test_verifier_normalises_crown_case_names() -> None:
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parents[2] / "scripts/verify_unified_sources.py"
    spec = importlib.util.spec_from_file_location("verify_unified_sources", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.oscola_case_name("Noye, R. v") == "R v Noye"
    assert module.legislation_citation(
        "The Pension Protection Fund (Compensation) Regulations 2005",
        "http://www.legislation.gov.uk/uksi/2005/670",
    )["instrument_number"] == "SI 2005/670"


def test_uploaded_documents_become_labelled_citable_sources() -> None:
    from app.jurisdictions import admissible
    from app.orchestration.uploads import upload_research_evidence
    from app.types import UploadContextSpan

    def context(lane: MaterialLane, ordinal: int) -> UploadContextSpan:
        return UploadContextSpan(
            id=f"upload-context-{ordinal}", text="The trustee must act unanimously.",
            lane=lane, locator="p 4", subject="trusts", jurisdiction="England",
            source_label=f"Uploaded document {ordinal}",
        )

    spans = upload_research_evidence(
        (
            context(MaterialLane.SCHOLARSHIP, 1),
            context(MaterialLane.PRIVATE_TEACHING, 2),
            context(MaterialLane.ASSESSMENT_GUIDANCE, 3),
        ),
        jurisdiction="England",
    )
    assert [span.citation_data["title"] for span in spans] == [
        "Uploaded document 1 (supplied by you)",
        "Uploaded document 2 (supplied by you)",
    ]
    assert spans[1].lane == MaterialLane.SCHOLARSHIP  # never promoted to authority
    for span in spans:
        assert research_mode_unverified(span)
        assert evidence_span_eligible_for_drafting(span, as_of_date=date(2026, 9, 25))
        assert admissible("England", span.jurisdiction, span.citation_data, span.retrieval_route)
        assert render_oscola(span.citation_data).endswith("[unverified source]")
        assert "source-" not in span.citation_data["title"]


def test_only_legislation_cases_journals_and_books_are_citable() -> None:
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parents[2] / "scripts/build_unified_exclusions.py"
    spec = importlib.util.spec_from_file_location("build_unified_exclusions", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source_type = module.source_type
    assert source_type("Seminar 4: easements", "scholarship", "article", "") == "teaching"
    assert source_type("Week 3 handout", "primary_authority", "", "") == "teaching"
    assert source_type("My essay", "scholarship", "student_work", "") == "own_work"
    assert source_type("", "primary_authority", "", "judgment") == "case"
    assert source_type("Land Registration Act 2002", "primary_authority", "", "") == "legislation"
    assert source_type("Examination prior to purchase", "scholarship", "article", "") == "journal"
    assert source_type("Gray & Gray, Elements of Land Law ch 5", "scholarship", "textbook_chapter", "") == "book"
    assert source_type("HMRC guidance note", "official_secondary", "", "") == "other"
    assert source_type("source-0123456789ab.pdf", "primary_authority", "", "") == "unknown"
    assert module.CITABLE_TYPES == {"legislation", "case", "journal", "book"}
