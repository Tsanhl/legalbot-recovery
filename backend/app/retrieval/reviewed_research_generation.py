"""Read a hash-pinned, point-in-time GE research generation in development.

This is a consumer adapter, not source admission.  It reopens the original
prepared rows, immutable Lance generation, retrieval receipts and independent
research-only review before exposing EvidenceSpan objects to AnswerRunner.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from datetime import date
from pathlib import Path
from typing import Any

from ..citations.oscola import render_oscola
from ..config import Settings
from ..contracts.schema_registry import canonical_json_bytes, load_json_strict
from ..orchestration.contracts import EvidenceRetriever
from ..types import EvidenceSpan, IssueSpottingNote, MaterialLane

SCHEMA = "legalbot.ge-qwen-reviewed-research-consumer.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_QUERY_TERM = re.compile(r"[a-z0-9]+")
_STOP_TERMS = frozenset(
    {
        "and",
        "are",
        "can",
        "for",
        "from",
        "have",
        "how",
        "into",
        "must",
        "that",
        "the",
        "their",
        "this",
        "was",
        "what",
        "when",
        "where",
        "which",
        "with",
        "would",
    }
)


def _digest(value: Any) -> str:
    return hashlib.sha256(
        value if isinstance(value, bytes) else canonical_json_bytes(value)
    ).hexdigest()


def _sealed_sha256(value: Mapping[str, Any]) -> str:
    material = dict(value)
    material.pop("seal_sha256", None)
    return _digest(material)


def seal_reviewed_research_consumer_manifest(
    value: Mapping[str, Any]
) -> dict[str, Any]:
    result = dict(value)
    result["seal_sha256"] = _sealed_sha256(result)
    return result


def _safe_file(root: Path, relative: object, expected_sha256: object) -> tuple[Path, bytes]:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise RuntimeError("development_retrieval_path_invalid")
    if not _SHA256.fullmatch(str(expected_sha256 or "")):
        raise RuntimeError("development_retrieval_file_sha256_invalid")
    path = root / relative
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
        raise RuntimeError("development_retrieval_file_invalid")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise RuntimeError("development_retrieval_file_changed")
    return path, raw


def _retain_receipt_context(
    receipt_evidence: Mapping[str, dict[str, Any]],
    selected_ids: Sequence[str],
    retrieval_rows: dict[str, dict[str, Any]],
    receipt_rank: dict[str, int],
) -> None:
    """Keep the exact reviewed context expansion, not just its search hits.

    A retrieval receipt includes every source chunk in the reviewed groups
    touched by its selected hits.  The selected IDs rank the original hits;
    context rows remain searchable only after their prepared-row equality and
    source-review checks in ``_load`` have passed.
    """

    if not selected_ids or not set(selected_ids) <= set(receipt_evidence):
        raise RuntimeError("development_retrieval_selection_invalid")
    for row_id, row in receipt_evidence.items():
        existing = retrieval_rows.get(row_id)
        if existing is not None and existing != row:
            raise RuntimeError("development_retrieval_context_conflict")
        retrieval_rows[row_id] = row
    for ordinal, row_id in enumerate(selected_ids, start=1):
        receipt_rank[row_id] = min(receipt_rank.get(row_id, 10_000), ordinal)


def provision_context_rows(
    reviewed_rows: Sequence[dict[str, Any]],
) -> tuple[dict[str, Any], ...]:
    """Assemble reviewed provision fragments without changing the vector index.

    Vector hits remain the original child rows. Their parent context contains
    every retained, reviewed row of the same source/provision, in document
    order. New content IDs bind the exact join and its component hashes; no
    source bytes, date, review decision or original chunk identity is changed.
    This is context expansion, not a new embedding or source admission.
    """
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    ordinal_offset = max((row["structural_chunk"]["ordinal"] for row in reviewed_rows), default=0) + 1
    for row in reviewed_rows:
        locator = str(row["structural_chunk"].get("metadata", {}).get("legal_locator") or "")
        if not re.fullmatch(r"(?:section|article|regulation) \d+[A-Za-z]*", locator):
            continue
        groups.setdefault((str(row["capture_sha256"]), locator), []).append(row)
    parents = []
    for (capture, locator), children in groups.items():
        if len(children) < 2:
            continue
        children.sort(key=lambda row: (row["structural_chunk"]["ordinal"], row["id"]))
        for child in children:
            if _digest(str(child["text"]).encode()) != child["text_sha256"]:
                raise RuntimeError("development_context_child_text_changed")
        # A parent cannot cross review, validity, source or private-scope bounds.
        for field in ("review_sha256", "scope_sha256", "valid_from", "valid_to", "group"):
            if len({str(child.get(field)) for child in children}) != 1:
                raise RuntimeError("development_context_mixed_review_scope")
        text = "\n".join(str(child["text"]) for child in children)
        bindings = [{"id": row["id"], "text_sha256": row["text_sha256"]} for row in children]
        identity = _digest({"schema": "legalbot.reviewed-provision-context.v1",
                            "capture": capture, "locator": locator, "children": bindings})
        structural = children[0]["structural_chunk"]
        parents.append({
            **children[0], "id": identity, "text": text, "text_sha256": _digest(text.encode()),
            "structural_chunk": {
                **structural, "chunk_id": f"context:{identity}", "text": text,
                "ordinal": ordinal_offset + structural["ordinal"],
                "metadata": {**structural.get("metadata", {}),
                             "context_assembly": "all_reviewed_provision_rows_in_document_order",
                             "context_components": bindings},
            },
        })
    return tuple(parents)


class ReviewedResearchGenerationRetriever(EvidenceRetriever):
    """Fail-closed projection of one reviewed one-day generation."""

    def __init__(self, settings: Settings, build_id: str) -> None:
        self.settings = settings
        self._build_id = build_id
        self._rows: tuple[dict[str, Any], ...] | None = None
        self._manifest: dict[str, Any] | None = None
        self._receipt_rank: dict[str, int] = {}
        self.last_query_trace: dict[str, Any] | None = None

    def active_build_id(self) -> str:
        return self._build_id

    async def retrieve_issue_spotting_notes(
        self,
        *,
        query: str,
        jurisdiction: str,
        subject: str | None,
        as_of_date: date,
        limit: int = 8,
    ) -> Sequence[IssueSpottingNote]:
        del query, jurisdiction, subject, as_of_date, limit
        return ()

    def _load(self) -> tuple[dict[str, Any], tuple[dict[str, Any], ...]]:
        expected_manifest_sha256 = str(
            self.settings.development_retrieval_manifest_sha256 or ""
        )
        if not _SHA256.fullmatch(expected_manifest_sha256):
            raise RuntimeError("development_retrieval_manifest_not_configured")
        path = self.settings.development_retrieval_manifest_path
        if path.is_symlink() or not path.is_file() or path.resolve() != path:
            raise RuntimeError("development_retrieval_manifest_invalid")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected_manifest_sha256:
            raise RuntimeError("development_retrieval_manifest_changed")
        manifest = load_json_strict(raw)
        if not isinstance(manifest, dict) or set(manifest) != {
            "schema",
            "candidate_build_id",
            "adapter_runtime_sha256",
            "source_review_attestation_sha256",
            "jurisdiction",
            "as_of_date",
            "subject",
            "generation",
            "prepared_build",
            "complete_context",
            "retrievals",
            "sources",
            "production_admitted",
            "writes_active",
            "seal_sha256",
        }:
            raise RuntimeError("development_retrieval_manifest_shape_invalid")
        runtime_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        if (
            manifest.get("schema") != SCHEMA
            or manifest.get("candidate_build_id") != self._build_id
            or manifest.get("adapter_runtime_sha256") != runtime_sha256
            or not _SHA256.fullmatch(
                str(manifest.get("source_review_attestation_sha256") or "")
            )
            or not isinstance(manifest.get("jurisdiction"), str)
            or not isinstance(manifest.get("subject"), str)
            or manifest.get("production_admitted") is not False
            or manifest.get("writes_active") is not False
            or manifest.get("seal_sha256") != _sealed_sha256(manifest)
        ):
            raise RuntimeError("development_retrieval_manifest_binding_invalid")
        try:
            review_date = date.fromisoformat(str(manifest["as_of_date"]))
        except ValueError as exc:
            raise RuntimeError("development_retrieval_date_invalid") from exc
        root = self.settings.project_root.resolve()
        generation_path, generation_raw = _safe_file(
            root,
            manifest["generation"].get("path"),
            manifest["generation"].get("sha256"),
        )
        prepared_path, prepared_raw = _safe_file(
            root,
            manifest["prepared_build"].get("path"),
            manifest["prepared_build"].get("sha256"),
        )
        context_path, context_raw = _safe_file(
            root,
            manifest["complete_context"].get("path"),
            manifest["complete_context"].get("sha256"),
        )
        generation = load_json_strict(generation_raw)
        prepared = load_json_strict(prepared_raw)
        complete_context = load_json_strict(context_raw)
        if (
            not isinstance(generation, dict)
            or not isinstance(prepared, dict)
            or not isinstance(complete_context, list)
            or generation.get("schema") != "legalbot.ge-auto-index-generation.v1"
            or prepared.get("schema") != "legalbot.ge-auto-index-build.v1"
            or generation.get("generation_sha256")
            != _digest({k: v for k, v in generation.items() if k != "generation_sha256"})
            or generation.get("build_sha256") != _digest(prepared)
            or generation.get("generation_sha256")
            != manifest["generation"].get("generation_sha256")
            or generation.get("build_sha256") != manifest["generation"].get("build_sha256")
            or generation.get("non_live") is not True
            or generation.get("admitted") is not False
            or generation.get("full_current_law_eligible") is not False
            or generation.get("lineage", {}).get("jurisdiction") != manifest["jurisdiction"]
            or generation.get("lineage", {}).get("as_of_date") != review_date.isoformat()
            or prepared.get("lineage") != generation.get("lineage")
            or prepared.get("scope") != generation.get("scope")
            or len(prepared.get("rows") or ()) != int(generation.get("chunk_count") or -1)
            or len(complete_context) != int(manifest["complete_context"].get("row_count") or -1)
            or sorted(complete_context, key=lambda item: item["id"])
            != sorted(prepared.get("rows") or (), key=lambda item: item["id"])
        ):
            raise RuntimeError("development_retrieval_generation_invalid")

        generation_root = generation_path.parent
        actual_files: dict[str, str] = {}
        for child in generation_root.rglob("*"):
            if child.is_file() and child != generation_path:
                actual_files[str(child.relative_to(generation_root))] = hashlib.sha256(
                    child.read_bytes()
                ).hexdigest()
        if generation.get("files") != actual_files:
            raise RuntimeError("development_retrieval_generation_files_changed")

        import lancedb

        stored_rows = (
            lancedb.connect(str(generation_root / "lance" / "authority"))
            .open_table("chunks")
            .to_arrow()
            .to_pylist()
        )
        if _digest(sorted(stored_rows, key=lambda item: item["id"])) != generation.get(
            "rows_sha256"
        ):
            raise RuntimeError("development_retrieval_lance_rows_changed")
        stored_bindings = {
            str(item["id"]): load_json_strict(str(item["binding_json"]))
            for item in stored_rows
        }
        prepared_rows = {str(item["id"]): item for item in prepared["rows"]}
        if stored_bindings != prepared_rows:
            raise RuntimeError("development_retrieval_row_binding_changed")

        retrieval_rows: dict[str, dict[str, Any]] = {}
        receipt_rank: dict[str, int] = {}
        receipt_specs = manifest.get("retrievals")
        if not isinstance(receipt_specs, list) or not receipt_specs:
            raise RuntimeError("development_retrieval_receipts_missing")
        for spec in receipt_specs:
            if not isinstance(spec, dict) or set(spec) != {"path", "sha256"}:
                raise RuntimeError("development_retrieval_receipt_shape_invalid")
            _receipt_path, receipt_raw = _safe_file(root, spec["path"], spec["sha256"])
            receipt = load_json_strict(receipt_raw)
            if (
                not isinstance(receipt, dict)
                or receipt.get("schema") != "legalbot.ge-auto-index-retrieval.v1"
                or receipt.get("generation_sha256") != generation["generation_sha256"]
                or receipt.get("build_sha256") != generation["build_sha256"]
                or receipt.get("lineage") != generation["lineage"]
                or receipt.get("scope") != generation["scope"]
                or receipt.get("retrieval_sha256")
                != _digest({k: v for k, v in receipt.items() if k != "retrieval_sha256"})
            ):
                raise RuntimeError("development_retrieval_receipt_invalid")
            receipt_evidence: dict[str, dict[str, Any]] = {}
            for row in receipt.get("evidence") or ():
                if prepared_rows.get(str(row.get("id"))) != row:
                    raise RuntimeError("development_retrieval_receipt_row_changed")
                receipt_evidence[str(row["id"])] = row
            selected_ids = receipt.get("selected_ids")
            if (
                not isinstance(selected_ids, list)
                or not selected_ids
                or any(not isinstance(item, str) for item in selected_ids)
                or not set(selected_ids) <= set(receipt_evidence)
            ):
                raise RuntimeError("development_retrieval_selection_invalid")
            _retain_receipt_context(
                receipt_evidence, selected_ids, retrieval_rows, receipt_rank
            )

        sources = manifest.get("sources")
        if not isinstance(sources, list) or not sources:
            raise RuntimeError("development_retrieval_sources_missing")
        source_by_capture: dict[str, dict[str, Any]] = {}
        prepared_sources = {item["source_sha256"]: item for item in prepared["sources"]}
        review_by_capture = {item["capture_sha256"]: item for item in prepared["reviews"]}
        for source in sources:
            if not isinstance(source, dict) or set(source) != {
                "capture_sha256",
                "source_sha256",
                "source_identity_id",
                "title",
                "canonical_url",
                "source_type",
            }:
                raise RuntimeError("development_retrieval_source_shape_invalid")
            prepared_source = prepared_sources.get(source["source_sha256"])
            review = review_by_capture.get(source["capture_sha256"])
            if (
                prepared_source is None
                or review is None
                or prepared_source.get("canonical_url") != source["canonical_url"]
                or review.get("source_sha256") != source["source_sha256"]
                or review.get("decision") != "ELIGIBLE_RESEARCH_ONLY"
                or review.get("actual_review_attestation_sha256")
                != manifest["source_review_attestation_sha256"]
                or review.get("as_of_date") != review_date.isoformat()
                or review.get("valid_from") != review_date.isoformat()
                or review.get("valid_to") != review_date.isoformat()
                or review.get("checks") is None
                or set(review["checks"]) != {
                    "official_identity",
                    "authority_type",
                    "jurisdiction",
                    "date_commencement",
                    "amendments_effects",
                    "later_treatment",
                    "quote_support",
                    "issue_relevance",
                    "necessary_context",
                    "parser_binding",
                    "rights",
                }
            ):
                raise RuntimeError("development_retrieval_source_review_invalid")
            source_by_capture[source["capture_sha256"]] = source
        if set(row["capture_sha256"] for row in retrieval_rows.values()) - set(
            source_by_capture
        ):
            raise RuntimeError("development_retrieval_source_binding_missing")
        self._manifest = manifest
        self._receipt_rank = receipt_rank
        self._rows = tuple(retrieval_rows[key] for key in sorted(retrieval_rows))
        return manifest, self._rows

    async def retrieve(
        self,
        *,
        query: str,
        jurisdiction: str,
        subject: str | None,
        as_of_date: date,
        limit: int = 30,
        cacheable: bool = True,
    ) -> Sequence[EvidenceSpan]:
        del cacheable
        manifest, rows = self._load()
        manifest_subject = str(manifest["subject"])
        accepted_subjects = {manifest_subject, manifest_subject.removesuffix("-law")}
        if (
            jurisdiction != manifest["jurisdiction"]
            or as_of_date.isoformat() != manifest["as_of_date"]
            or (subject is not None and subject not in accepted_subjects)
        ):
            self.last_retrieval_code = "reviewed_generation_scope_mismatch"
            self.last_query_trace = {
                "query_sha256": hashlib.sha256(query.encode()).hexdigest(),
                "generation_sha256": manifest["generation"]["generation_sha256"],
                "selected_ids": [], "embedding_performed": False,
                "reason": self.last_retrieval_code,
                "reviewed_jurisdiction": manifest["jurisdiction"],
                "reviewed_as_of_date": manifest["as_of_date"],
            }
            return ()
        self.last_retrieval_code = None
        vector_trace = None
        if self.settings.development_chat_authority_sha256:
            from ..evaluation.ge_development_chat_authority import (
                GE_SESSION_CHAT_SCHEMA,
                _load_authority,
            )
            authority, _ = _load_authority(self.settings)
            if authority["schema"] == GE_SESSION_CHAT_SCHEMA:
                from ..crypto import LocalCipher
                from .development_query import query_reviewed_generation
                vector_trace = await asyncio.to_thread(
                    query_reviewed_generation, query,
                    self.settings.project_root / manifest["generation"]["path"], rows,
                )
                trace_dir = self.settings.vault_dir / "query-traces"
                trace_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                trace_path = trace_dir / (vector_trace["sha256"] + ".enc")
                with trace_path.open("xb") as handle:
                    handle.write(LocalCipher.from_local_key(create=False).encrypt_bytes(canonical_json_bytes(vector_trace)))
                trace_path.chmod(0o600)
                self.last_query_trace = {"sha256": vector_trace["sha256"], "query_sha256": vector_trace["query_sha256"], "selected_ids": vector_trace["selected_ids"], "generation_sha256": manifest["generation"]["generation_sha256"]}
        manifest_subject = str(manifest["subject"])
        accepted_subjects = {manifest_subject, manifest_subject.removesuffix("-law")}
        if (
            jurisdiction != manifest["jurisdiction"]
            or as_of_date.isoformat() != manifest["as_of_date"]
            or (subject is not None and subject not in accepted_subjects)
        ):
            return ()
        terms = {
            item
            for item in _QUERY_TERM.findall(query.casefold())
            if len(item) >= 3 and item not in _STOP_TERMS
        }
        if not terms:
            return ()

        def score(row: Mapping[str, Any]) -> tuple[float, int, str]:
            structural = row["structural_chunk"]
            metadata = structural.get("metadata") or {}
            searchable = " ".join(
                (
                    str(row.get("text") or ""),
                    " ".join(str(item) for item in structural.get("heading_path") or ()),
                    str(metadata.get("legal_locator") or ""),
                )
            ).casefold()
            row_terms = set(_QUERY_TERM.findall(searchable))
            overlap = terms & row_terms
            lexical = sum(1.0 + math.log1p(searchable.count(term)) for term in overlap)
            coverage = len(overlap) / len(terms)
            receipt_priority = self._receipt_rank.get(str(row["id"]), 10_000)
            frozen_selection_bonus = max(0, 9 - receipt_priority) * 2.0
            return (
                lexical + coverage * 4.0 + frozen_selection_bonus,
                -receipt_priority,
                str(row["id"]),
            )

        ranked = [row for row in sorted(rows, key=score, reverse=True) if score(row)[0] > 0]
        grouped: dict[str, list[dict[str, Any]]] = {}
        for row in ranked:
            locator = str(
                row["structural_chunk"].get("metadata", {}).get("legal_locator") or ""
            )
            grouped.setdefault(locator, []).append(row)
        group_order = list(grouped)
        # Give the four highest-scoring provisions their first two receipt
        # rows before adding lower-ranked provisions.  This lets the bounded
        # prompt retain a rule and its necessary condition/exception context.
        priority_groups = group_order[:4]
        remaining_groups = group_order[4:]
        diversified: list[dict[str, Any]] = []
        for offset in range(2):
            diversified.extend(
                grouped[group][offset]
                for group in priority_groups
                if len(grouped[group]) > offset
            )
        diversified.extend(grouped[group][0] for group in remaining_groups)
        used = {str(row["id"]) for row in diversified}
        diversified.extend(row for row in ranked if str(row["id"]) not in used)
        selected_rows = diversified[: max(1, min(limit, 30))]
        if vector_trace is not None:
            by_id = {row["id"]: row for row in rows}
            selected_rows = [by_id[key] for key in vector_trace["selected_ids"][:limit]]

        # Return whole reviewed provision context for each actual search hit.
        # The original vector receipt still records child IDs and rerank scores.
        contexts = provision_context_rows(rows)
        context_by_child = {
            child["id"]: parent for parent in contexts
            for child in parent["structural_chunk"]["metadata"]["context_components"]
        }
        expanded = {}
        for row in selected_rows:
            parent = context_by_child.get(row["id"], row)
            expanded.setdefault(parent["id"], parent)
        selected_rows = list(expanded.values())

        source_specs = {
            source["capture_sha256"]: source for source in manifest["sources"]
        }
        output: list[EvidenceSpan] = []
        for row in selected_rows:
            source = source_specs[row["capture_sha256"]]
            structural = row["structural_chunk"]
            locator = str(structural.get("metadata", {}).get("legal_locator") or "")
            source_type = str(source["source_type"])
            citation_data = {
                "source_type": source_type,
                "title": str(source["title"]),
                "provision": locator,
                "reviewed_as_of": str(manifest["as_of_date"]),
                "commencement_status": "reviewed_at_declared_point_in_time",
            }
            if source_type == "statutory_instrument":
                instrument = re.search(
                    r"/uksi/(\d{4})/(\d+)(?:/|$)", str(source["canonical_url"])
                )
                if instrument is None:
                    raise RuntimeError(
                        "development statutory-instrument number is unavailable"
                    )
                citation_data["instrument_number"] = (
                    f"SI {instrument.group(1)}/{instrument.group(2)}"
                )
            output.append(
                EvidenceSpan(
                    id=f"ge-research-{row['id'][:40]}",
                    source_version_id=f"ge-source-{source['source_sha256'][:40]}",
                    chunk_id=str(structural["chunk_id"]),
                    text=str(row["text"]),
                    locator=locator,
                    lane=MaterialLane.PRIMARY_AUTHORITY,
                    jurisdiction=str(manifest["jurisdiction"]),
                    subject=str(manifest["subject"]),
                    citation_data=citation_data,
                    canonical_citation=render_oscola(citation_data),
                    currentness_status="point_in_time",
                    content_sha256=str(row["text_sha256"]),
                    index_build_id=self._build_id,
                    canonical_url=(str(source["canonical_url"]).removesuffix("/data.xml")
                                   + "/" + locator.replace(" ", "/")),
                    retrieval_relevance_score=1.0,
                    retrieval_route="frozen_reviewed_research_receipt",
                    retrieval_threshold=1.0,
                    retrieval_threshold_policy_sha256=str(
                        manifest["source_review_attestation_sha256"]
                    ),
                    retrieval_threshold_qualified=True,
                    retrieval_qualification_reason="exact_frozen_research_receipt",
                    legal_role="statutory_rule",
                    unapplied_effect_count=0,
                    provision_extent_status="reviewed_for_declared_jurisdiction_and_date",
                    identity_verified=True,
                    currentness_verified=True,
                )
            )
        return tuple(output)


def validate_reviewed_research_generation_manifest(
    settings: Settings, build_id: str
) -> int:
    _manifest, rows = ReviewedResearchGenerationRetriever(settings, build_id)._load()
    return len(rows)


def register_scoped_development_retrieval_candidate(
    settings: Settings, database: Any
) -> int:
    """Register a closed development catalogue without admitting or activating it.

    The answer evidence ledger has foreign keys to the ordinary source catalogue.
    A reviewed-research consumer therefore needs exact local catalogue identities
    even though it remains research-only and cannot enter ordinary retrieval.
    """

    build_id = str(settings.development_candidate_build_id or "")
    manifest, rows = ReviewedResearchGenerationRetriever(settings, build_id)._load()
    vector_count = len(rows)
    rows = (*rows, *provision_context_rows(rows))
    row_count = len(rows)
    if database.active_index_id() is not None:
        raise RuntimeError("scoped development store unexpectedly contains ACTIVE")
    relative_path = str(
        settings.development_retrieval_manifest_path.relative_to(settings.project_root)
    )
    from ..db import utc_iso

    now = utc_iso()
    source_by_capture = {
        str(source["capture_sha256"]): source for source in manifest["sources"]
    }
    rows_by_source: dict[str, list[dict[str, Any]]] = {
        capture_sha256: [] for capture_sha256 in source_by_capture
    }
    for row in rows:
        rows_by_source[str(row["capture_sha256"])].append(row)

    with database.transaction() as connection:
        existing = connection.execute(
            "SELECT * FROM index_builds WHERE id=?", (build_id,)
        ).fetchone()
        expected_build = (
            "candidate",
            relative_path,
            len(manifest["sources"]),
            row_count,
            vector_count,
            settings.embedding_model,
            "NOT_RUN",
        )
        if existing is None:
            connection.execute(
                """
                INSERT INTO index_builds(
                  id,status,path,document_count,chunk_count,vector_count,
                  embedding_model,reranker_model,created_at
                ) VALUES (?, 'candidate', ?, ?, ?, ?, ?, 'NOT_RUN', ?)
                """,
                (
                    build_id,
                    relative_path,
                    len(manifest["sources"]),
                    row_count,
                    vector_count,
                    settings.embedding_model,
                    now,
                ),
            )
        else:
            observed_build = (
                str(existing["status"]),
                str(existing["path"]),
                int(existing["document_count"] or 0),
                int(existing["chunk_count"] or 0),
                int(existing["vector_count"] or 0),
                str(existing["embedding_model"]),
                str(existing["reranker_model"]),
            )
            if observed_build != expected_build:
                raise RuntimeError("development retrieval candidate registration differs")

        for capture_sha256, source in source_by_capture.items():
            source_sha256 = str(source["source_sha256"])
            document_id = f"ge-document-{source_sha256[:40]}"
            source_version_id = f"ge-source-{source_sha256[:40]}"
            document_expected = (
                source_sha256,
                str(source["source_identity_id"]),
                str(source["title"]),
                "application/xml",
                "quarantined",
                "primary_authority",
                str(manifest["subject"]),
                str(manifest["jurisdiction"]),
                0,
                0,
            )
            document = connection.execute(
                "SELECT * FROM documents WHERE id=?", (document_id,)
            ).fetchone()
            if document is None:
                connection.execute(
                    """
                    INSERT INTO documents(
                      id,content_sha256,source_identity_id,safe_display_name,
                      media_type,status,lane,subject_primary,jurisdiction,
                      retrieval_canonical,searchable_text,dedupe_status,
                      created_at,updated_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,0,0,'new',?,?)
                    """,
                    (
                        document_id,
                        *document_expected[:8],
                        now,
                        now,
                    ),
                )
            else:
                document_observed = (
                    str(document["content_sha256"]),
                    str(document["source_identity_id"]),
                    str(document["safe_display_name"]),
                    str(document["media_type"]),
                    str(document["status"]),
                    str(document["lane"]),
                    str(document["subject_primary"]),
                    str(document["jurisdiction"]),
                    int(document["retrieval_canonical"] or 0),
                    int(document["searchable_text"] or 0),
                )
                if document_observed != document_expected:
                    raise RuntimeError("development retrieval document identity differs")

            metadata = json.dumps(
                {
                    "capture_sha256": capture_sha256,
                    "consumer_manifest_seal_sha256": manifest["seal_sha256"],
                    "development_retrieval_only": True,
                    "production_admitted": False,
                    "source_review_attestation_sha256": manifest[
                        "source_review_attestation_sha256"
                    ],
                    "writes_active": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            version_expected = (
                document_id,
                str(source["source_identity_id"]),
                source_sha256,
                relative_path,
                str(source["title"]),
                str(manifest["as_of_date"]),
                str(source["canonical_url"]),
                f"research-only:{source['source_identity_id']}",
                "point_in_time",
                "staged",
                "ge-reviewed-research-consumer-v1",
                metadata,
            )
            version = connection.execute(
                "SELECT * FROM source_versions WHERE id=?", (source_version_id,)
            ).fetchone()
            if version is None:
                connection.execute(
                    """
                    INSERT INTO source_versions(
                      id,document_id,authority_identity_id,version_sha256,
                      canonical_markdown_path,title,as_of_date,canonical_url,
                      stable_identifier,currentness_status,review_status,
                      processing_fingerprint,metadata_json,created_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (source_version_id, *version_expected, now),
                )
            else:
                version_observed = tuple(
                    str(version[key] or "")
                    for key in (
                        "document_id",
                        "authority_identity_id",
                        "version_sha256",
                        "canonical_markdown_path",
                        "title",
                        "as_of_date",
                        "canonical_url",
                        "stable_identifier",
                        "currentness_status",
                        "review_status",
                        "processing_fingerprint",
                        "metadata_json",
                    )
                )
                if version_observed != version_expected:
                    raise RuntimeError("development retrieval source version differs")

            for row in rows_by_source[capture_sha256]:
                structural = row["structural_chunk"]
                chunk_id = str(structural["chunk_id"])
                chunk_metadata = json.dumps(
                    structural.get("metadata") or {},
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                chunk_expected = (
                    source_version_id,
                    int(structural["ordinal"]),
                    json.dumps(
                        structural.get("heading_path") or [],
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                    str((structural.get("metadata") or {}).get("legal_locator") or ""),
                    str(row["text_sha256"]),
                    str(row["text"]),
                    max(1, len(str(row["text"]).split())),
                    str(structural.get("stream") or "body"),
                    chunk_metadata,
                )
                chunk = connection.execute(
                    "SELECT * FROM chunks WHERE id=?", (chunk_id,)
                ).fetchone()
                if chunk is None:
                    connection.execute(
                        """
                        INSERT INTO chunks(
                          id,source_version_id,ordinal,heading_path,locator,
                          text_sha256,markdown_text,token_count,stream,metadata_json
                        ) VALUES (?,?,?,?,?,?,?,?,?,?)
                        """,
                        (chunk_id, *chunk_expected),
                    )
                else:
                    chunk_observed = (
                        str(chunk["source_version_id"]),
                        int(chunk["ordinal"]),
                        str(chunk["heading_path"] or ""),
                        str(chunk["locator"]),
                        str(chunk["text_sha256"]),
                        str(chunk["markdown_text"]),
                        int(chunk["token_count"]),
                        str(chunk["stream"]),
                        str(chunk["metadata_json"]),
                    )
                    if chunk_observed != chunk_expected:
                        raise RuntimeError("development retrieval chunk identity differs")
    return row_count


__all__ = [
    "SCHEMA",
    "ReviewedResearchGenerationRetriever",
    "register_scoped_development_retrieval_candidate",
    "seal_reviewed_research_consumer_manifest",
    "validate_reviewed_research_generation_manifest",
]
