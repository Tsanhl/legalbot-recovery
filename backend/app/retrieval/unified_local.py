"""Research-mode retriever over the unified local index (owner decision 2026-09-25).

Searches ``data/indexes/unified-local-v1`` (built by
``scripts/build_unified_local_index.py``) with the pinned Qwen embedding and
reranker models. Approved catalogue sources keep their verified citation
metadata and verification flags. Staged sources are returned with
``identity_verified=False`` and an ``unverified_source`` citation, so the
answer labels them instead of treating them as reviewed authority. This
retriever is only constructed when ``Settings.research_mode`` is on.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from typing import Any

from ..config import Settings
from ..ingestion.models import Jurisdiction
from ..ingestion.models import MaterialLane as IngestionLane
from ..jurisdictions import RESEARCH_FOREIGN_ROUTE, attributed_foreign_use, compatible
from ..types import EvidenceSpan, IssueSpottingNote, MaterialLane
from .models import IndexedChunk, SearchHit

UNIFIED_INDEX_ID = "unified-local-v1"
_TABLE_DEPTH = {"authority": 40, "official_secondary": 12, "scholarship": 12}
_RERANK_POOL = 48
_RRF_K = 60
# Provisional floor on the reranker's 0-1 relevance probability (design layer 4:
# refuse weak context rather than hand it to the model). The frozen policy's
# semantic threshold is still uncalibrated; the baseline run calibrates this.
_MIN_RELEVANCE = float(os.getenv("LEGALBOT_RESEARCH_MIN_RELEVANCE", "0.10"))
_CURRENT_STATUSES = frozenset({"latest_available_revised_snapshot", "current"})
# EU or foreign material the question does not name is only comparative context:
# capped, and held to a higher relevance floor than forum material.
_COMPARATIVE_CAP = 3
_COMPARATIVE_MIN_RELEVANCE = float(os.getenv("LEGALBOT_COMPARATIVE_MIN_RELEVANCE", "0.30"))
_KNOWLEDGE_DIR = "knowledge-lance"
_POLICY_SHA256 = hashlib.sha256(
    json.dumps(
        {
            "policy": "unified-local-research-rerank-floor-v1",
            "min_relevance": _MIN_RELEVANCE,
            "comparative_min_relevance": _COMPARATIVE_MIN_RELEVANCE,
            "comparative_cap": _COMPARATIVE_CAP,
        },
        sort_keys=True,
    ).encode("utf-8")
).hexdigest()


@dataclass(frozen=True, slots=True)
class _Row:
    evidence_id: str
    record: Mapping[str, Any]
    distance: float
    score: float = 0.0
    scope: str = "forum"  # forum | targeted (question names that system) | comparative


class UnifiedLocalRetriever:
    """EvidenceRetriever over the single unified LanceDB folder."""

    def __init__(self, settings: Settings, build_id: str) -> None:
        self.settings = settings
        self._build_id = build_id
        self._root = settings.project_root / "data" / "indexes" / UNIFIED_INDEX_ID
        self._lock = threading.Lock()
        self._tables: dict[str, Any] | None = None
        self._embedder: Any = None
        self._reranker: Any = None
        self._citations: dict[str, dict[str, Any]] = {}
        self._decisions: dict[str, str] = {}
        # Official-record checks by scripts/verify_unified_sources.py (not legal review).
        self._verified: dict[str, Mapping[str, Any]] = {}
        self.last_retrieval_code: str | None = None
        self.last_query_trace: dict[str, Any] | None = None
        self.last_rerank_scores: list[float] = []

    def active_build_id(self) -> str:
        return self._build_id

    async def retrieve_issue_spotting_notes(
        self, *, query: str, jurisdiction: str, subject: str | None,
        as_of_date: date, limit: int = 8,
    ) -> Sequence[IssueSpottingNote]:
        """Law-and-rules extracts from the knowledge lane (issue spotting only).

        Returns nothing when the knowledge lane has not been built. The notes
        are never evidence: they only suggest issues and authorities to search.
        """

        del subject, as_of_date
        if not query.strip() or limit < 1:
            return ()
        return await asyncio.to_thread(self._knowledge_search, query, jurisdiction, limit)

    def _knowledge_search(
        self, query: str, jurisdiction: str, limit: int
    ) -> tuple[IssueSpottingNote, ...]:
        folder = self._root / _KNOWLEDGE_DIR
        if not folder.is_dir():
            return ()
        import lancedb

        self._load_models()
        table = lancedb.connect(str(folder)).open_table("knowledge")
        vector = list(self._embedder.embed_query(query))
        fused: dict[str, float] = {}
        records: dict[str, Mapping[str, Any]] = {}
        channels = [table.search(vector).limit(16).to_list()]
        if self._has_fts(table):
            channels.append(table.search(query, query_type="fts").limit(16).to_list())
        for channel in channels:
            for rank, record in enumerate(channel):
                key = str(record["chunk_id"])
                records.setdefault(key, record)
                fused[key] = fused.get(key, 0.0) + 1.0 / (_RRF_K + rank + 1)
        order = sorted(fused, key=lambda key: -fused[key])[:16]
        if not order:
            return ()
        hits = [self._hit(key, records[key]) for key in order]
        reranked = self._reranker.rerank(query, hits, limit=len(hits))
        notes: list[IssueSpottingNote] = []
        for hit in reranked:
            if float(hit.rerank_score or 0.0) < _MIN_RELEVANCE:
                continue
            record = records[hit.chunk.chunk_id]
            notes.append(
                IssueSpottingNote(
                    id=str(record["chunk_id"]),
                    source_version_id=str(record["source_version_id"]),
                    chunk_id=str(record["chunk_id"]),
                    text=str(record["text"]),
                    jurisdiction=str(record.get("jurisdiction") or jurisdiction),
                    subject=str(record.get("subject") or ""),
                    content_sha256=str(record["content_sha256"]),
                    index_build_id=self._build_id,
                )
            )
            if len(notes) >= limit:
                break
        return tuple(notes)

    def _load(self) -> dict[str, Any]:
        with self._lock:
            if self._tables is None:
                import lancedb

                if not (self._root / "MANIFEST.json").is_file():
                    raise RuntimeError("unified_local_index_incomplete")
                exclusions = self._root / "EXCLUSIONS.json"
                if not exclusions.is_file():
                    # Owner's own work and uncitable teaching must never be served.
                    raise RuntimeError("unified_local_exclusions_missing")
                self._decisions = {
                    key: str(value["action"])
                    for key, value in json.loads(exclusions.read_text())["decisions"].items()
                }
                ledger = self._root / "VERIFICATION.json"
                if ledger.is_file():
                    self._verified = {
                        key: value
                        for key, value in json.loads(ledger.read_text())["entries"].items()
                        if value.get("identity_verified") and value.get("citation_data")
                    }
                db = lancedb.connect(str(self._root / "lance"))
                self._tables = {
                    name: db.open_table(name) for name in _TABLE_DEPTH if name in db.table_names()
                }
        self._load_models()
        return self._tables

    def _load_models(self) -> None:
        with self._lock:
            if self._embedder is None:
                from .service import (
                    PINNED_EMBEDDING_REPO,
                    PINNED_EMBEDDING_REVISION,
                    PINNED_RERANKER_REPO,
                    PINNED_RERANKER_REVISION,
                    QwenEmbeddingProvider,
                    QwenRerankerProvider,
                )

                self._embedder = QwenEmbeddingProvider(
                    PINNED_EMBEDDING_REPO, PINNED_EMBEDDING_REVISION,
                    self.settings.embedding_model_path,
                )
                self._reranker = QwenRerankerProvider(
                    PINNED_RERANKER_REPO, PINNED_RERANKER_REVISION,
                    self.settings.reranker_model_path,
                )

    @staticmethod
    def _hit(key: str, record: Mapping[str, Any], distance: float = 2.0) -> SearchHit:
        return SearchHit(
            chunk=IndexedChunk(
                chunk_id=key,
                text=str(record["text"]),
                vector=(0.0,),
                jurisdiction=Jurisdiction.ENGLAND_WALES,
                material_lane=IngestionLane.PRIMARY_AUTHORITY,
                subject=str(record.get("subject") or ""),
                review_state=str(record.get("review_status") or ""),
                source_identity=str(record["source_version_id"]),
                content_sha256=str(record["content_sha256"]),
                title=str(record.get("title") or "") or None,
            ),
            score=-distance,
        )

    def _approved_citation(self, source_version_id: str) -> dict[str, Any]:
        if source_version_id not in self._citations:
            catalogue = self.settings.project_root / "data" / "catalog.sqlite3"
            with sqlite3.connect(f"file:{catalogue}?mode=ro", uri=True) as db:
                row = db.execute(
                    "SELECT json_extract(metadata_json, '$.citation_data') FROM source_versions "
                    "WHERE id=? AND review_status='approved'",
                    (source_version_id,),
                ).fetchone()
            value = json.loads(row[0]) if row and row[0] else {}
            self._citations[source_version_id] = value if isinstance(value, dict) else {}
        return self._citations[source_version_id]

    @staticmethod
    def _has_fts(table: Any) -> bool:
        try:
            return any("text" in (getattr(index, "columns", None) or ()) and
                       "FTS" in str(getattr(index, "index_type", "")).upper()
                       for index in table.list_indices())
        except Exception:
            return False

    def _search(self, query: str, jurisdiction: str) -> list[_Row]:
        """Hybrid search: vector and BM25 lists fused by reciprocal rank, then reranked."""
        tables = self._load()
        vector = list(self._embedder.embed_query(query))
        fused: dict[str, float] = {}
        records: dict[str, Mapping[str, Any]] = {}
        distances: dict[str, float] = {}
        scopes: dict[str, str] = {}
        for name, table in tables.items():
            channels = [table.search(vector).limit(_TABLE_DEPTH[name]).to_list()]
            if self._has_fts(table):
                channels.append(
                    table.search(query, query_type="fts").limit(_TABLE_DEPTH[name]).to_list()
                )
            for channel in channels:
                for rank, record in enumerate(channel):
                    action = self._decisions.get(str(record["source_version_id"]), "")
                    if action.startswith("exclude"):
                        continue
                    if action == "relane_scholarship":
                        record = {**record, "lane": "scholarship"}
                    source_jurisdiction = str(record.get("jurisdiction") or "")
                    if not source_jurisdiction:
                        continue
                    if compatible(jurisdiction, source_jurisdiction):
                        scopes_seen = "forum"
                    elif attributed_foreign_use(query, source_jurisdiction):
                        scopes_seen = "targeted"
                    else:
                        scopes_seen = "comparative"
                    evidence_id = "E" + str(record["content_sha256"])[:10]
                    records.setdefault(evidence_id, record)
                    scopes[evidence_id] = scopes_seen
                    fused[evidence_id] = fused.get(evidence_id, 0.0) + 1.0 / (_RRF_K + rank + 1)
                    if "_distance" in record:
                        distances[evidence_id] = float(record["_distance"])
        order = sorted(fused, key=lambda key: -fused[key])[:_RERANK_POOL]
        if not order:
            return []
        hits = [self._hit(key, records[key], distances.get(key, 2.0)) for key in order]
        reranked = self._reranker.rerank(query, hits, limit=len(hits))
        scores = {hit.chunk.chunk_id: float(hit.rerank_score or 0.0) for hit in reranked}
        self.last_rerank_scores = [round(scores[hit.chunk.chunk_id], 4) for hit in reranked]
        output: list[_Row] = []
        comparative = 0
        for hit in reranked:
            key = hit.chunk.chunk_id
            score, scope = scores[key], scopes[key]
            if score < _MIN_RELEVANCE:
                continue
            if scope == "comparative":
                if score < _COMPARATIVE_MIN_RELEVANCE or comparative >= _COMPARATIVE_CAP:
                    continue
                comparative += 1
            output.append(
                _Row(
                    evidence_id=key,
                    record=records[key],
                    distance=distances.get(key, 2.0),
                    score=score,
                    scope=scope,
                )
            )
        return output

    def _span(self, row: _Row, *, jurisdiction: str) -> EvidenceSpan:
        record = row.record
        source_version_id = str(record["source_version_id"])
        approved = str(record.get("review_status") or "") == "approved"
        citation = self._approved_citation(source_version_id) if approved else {}
        verified = approved and bool(citation)
        currentness = str(record.get("currentness_status") or "unknown")
        current_verified = verified and currentness in _CURRENT_STATUSES
        checked = None if verified else self._verified.get(source_version_id)
        if checked is not None:
            citation = dict(checked["citation_data"])
            verified = True
            current_verified = bool(checked.get("currentness_verified"))
            currentness = str(checked.get("currentness_status") or currentness)
        if not verified:
            title = str(record.get("title") or "Untitled source")
            if row.scope != "forum" and record.get("jurisdiction"):
                title = f"{title} ({record['jurisdiction']})"
            citation = {"source_type": "unverified_source", "title": title}
        return EvidenceSpan(
            id=row.evidence_id,
            source_version_id=source_version_id,
            chunk_id=str(record["chunk_id"]),
            text=str(record["text"]),
            locator=str(record.get("locator") or ""),
            lane=MaterialLane(str(record["lane"])),
            jurisdiction=str(record.get("jurisdiction") or jurisdiction),
            subject=str(record.get("subject") or ""),
            citation_data=citation,
            currentness_status=currentness,
            content_sha256=hashlib.sha256(str(record["text"]).encode("utf-8")).hexdigest(),
            index_build_id=self._build_id,
            canonical_url=str(record.get("canonical_url") or "") or None,
            retrieval_relevance_score=round(row.score, 6),
            retrieval_threshold=(
                _COMPARATIVE_MIN_RELEVANCE if row.scope == "comparative" else _MIN_RELEVANCE
            ),
            retrieval_threshold_qualified=True,
            retrieval_threshold_policy_sha256=_POLICY_SHA256,
            retrieval_qualification_reason=f"research_rerank_floor:{row.scope}",
            retrieval_route=(
                "unified_local_research_mode" if row.scope == "forum" else RESEARCH_FOREIGN_ROUTE
            ),
            identity_verified=verified,
            currentness_verified=current_verified,
        )

    async def retrieve(
        self, *, query: str, jurisdiction: str, subject: str | None,
        as_of_date: date, limit: int = 30, cacheable: bool = True,
    ) -> Sequence[EvidenceSpan]:
        del subject, as_of_date, cacheable
        if not query.strip() or limit < 1:
            return ()
        rows = await asyncio.to_thread(self._search, query, jurisdiction)
        spans = tuple(self._span(row, jurisdiction=jurisdiction) for row in rows[:limit])
        self.last_retrieval_code = None if spans else "no_threshold_qualified_evidence"
        self.last_query_trace = {
            "query_sha256": hashlib.sha256(query.encode("utf-8")).hexdigest(),
            "index": UNIFIED_INDEX_ID,
            "selected_ids": [span.id for span in spans],
            "unverified_count": sum(not span.identity_verified for span in spans),
            # Kept so the baseline run can calibrate the relevance floor.
            "rerank_scores": list(self.last_rerank_scores),
            "min_relevance": _MIN_RELEVANCE,
        }
        return spans
