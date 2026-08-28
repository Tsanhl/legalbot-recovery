#!/usr/bin/env python3
"""Byte-audit selected evidence in non-authorizing proposition drafts.

The ordinary proposition validator binds records to the frozen all-585 scope
and the sealed candidate source manifest.  This companion audit also reads the
sealed Lance rows and deterministic span corpus.  It proves that every
selected local chunk is the claimed source/authority and that each declared
text digest is either the whole sealed chunk or an exact, byte-reproduced span
within that chunk.

The output is diagnostic only.  It never applies a legal or owner decision,
admits a source, mutates an index, assigns qualification, or authorizes Phase
2B.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

validator = importlib.import_module("scripts.validate_v111_phase2a_proposition_working_drafts")

DEFAULT_SPAN_CORPUS = PROJECT_ROOT / (
    "data/evaluations/phase2a-owner-review/"
    "LegalBot-Phase2A-2026-08-27-deterministic-exact-span-crosswalk-r2/"
    "EXACT-SPAN-SOURCE-CORPUS.json"
)
DEFAULT_CANDIDATE_MANIFEST = validator.BLOCKED_MACHINE_ROOT / "candidate/manifest.json"
DEFAULT_BUILD_PARENT = PROJECT_ROOT / "data/indexes/builds"
FALSE_GATE_FIELDS = {
    "automatic_source_admission": False,
    "automatic_indexing": False,
    "automatic_embedding": False,
    "candidate_mutated": False,
    "owner_decisions_applied": False,
    "technical_qualification_assigned": False,
    "phase2b_authorized": False,
}


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _content_sha256(value: dict[str, Any], field: str) -> str:
    payload = dict(value)
    payload.pop(field, None)
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"required regular file unavailable: {path}")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"JSON object required: {path}")
    return value


def _require_sha256(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise ValueError(f"invalid SHA-256: {label}")
    return value


def _span_index(
    corpus: dict[str, Any],
) -> dict[tuple[str, str, str], list[dict[str, Any]]]:
    records = corpus.get("records")
    if not isinstance(records, list):
        raise ValueError("span corpus records must be a list")
    result: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("invalid span-corpus record")
        source_version_id = str(record.get("source_version_id") or "")
        chunk_id = str(record.get("chunk_id") or "")
        for option in record.get("exact_span_options") or []:
            if not isinstance(option, dict):
                raise ValueError("invalid exact-span option")
            exact_text = option.get("exact_text")
            digest = option.get("exact_text_sha256")
            if not isinstance(exact_text, str):
                raise ValueError("exact-span text must be present")
            _require_sha256(digest, "span.exact_text_sha256")
            if _sha256_text(exact_text) != digest:
                raise ValueError(f"span corpus digest mismatch: {chunk_id}")
            key = (source_version_id, chunk_id, str(digest))
            result.setdefault(key, []).append(option)
    return result


def _declared_chunk_ids(evidence: dict[str, Any]) -> list[str]:
    values: list[str] = []
    chunk_ids = evidence.get("chunk_ids")
    if chunk_ids is not None:
        if not isinstance(chunk_ids, list) or not all(
            isinstance(value, str) and value for value in chunk_ids
        ):
            raise ValueError("chunk_ids must contain non-empty strings")
        values.extend(chunk_ids)
    chunk_id = evidence.get("chunk_id")
    if chunk_id is not None:
        if not isinstance(chunk_id, str) or not chunk_id:
            raise ValueError("chunk_id must be a non-empty string")
        if chunk_id not in values:
            values.insert(0, chunk_id)
    if not values:
        raise ValueError("selected evidence has no chunk identity")
    if len(values) != len(set(values)):
        raise ValueError("selected evidence repeats a chunk identity")
    return values


def _verify_corpus_span(
    *,
    source_version_id: str,
    chunk_id: str,
    chunk_text: str,
    exact_digest: str,
    declared_span_ids: set[str],
    spans: dict[tuple[str, str, str], list[dict[str, Any]]],
) -> dict[str, Any] | None:
    options = spans.get((source_version_id, chunk_id, exact_digest), [])
    verified: list[dict[str, Any]] = []
    for option in options:
        start = option.get("start_character")
        end = option.get("end_character_exclusive")
        exact_text = option.get("exact_text")
        if not isinstance(start, int) or not isinstance(end, int):
            raise ValueError(f"invalid exact-span offsets: {chunk_id}")
        if start < 0 or end < start or end > len(chunk_text):
            raise ValueError(f"out-of-range exact-span offsets: {chunk_id}")
        if chunk_text[start:end] != exact_text:
            raise ValueError(f"exact span does not reproduce Lance text: {chunk_id}")
        verified.append(option)
    if not verified:
        return None
    canonical_ids = sorted({str(option.get("span_id") or "") for option in verified})
    canonical_ids = [value for value in canonical_ids if value]
    return {
        "canonical_span_ids": canonical_ids,
        "declared_span_ids": sorted(declared_span_ids),
        "declared_span_identity_matches_corpus": bool(
            declared_span_ids and declared_span_ids.intersection(canonical_ids)
        ),
    }


def _audit_evidence_item(
    evidence: dict[str, Any],
    *,
    row_id: str,
    lance_rows: dict[str, dict[str, Any]],
    spans: dict[tuple[str, str, str], list[dict[str, Any]]],
) -> dict[str, Any]:
    source_version_id = str(evidence.get("source_version_id") or "")
    authority_identity_id = str(evidence.get("authority_identity_id") or "")
    if not source_version_id or not authority_identity_id:
        raise ValueError(f"missing evidence source identity: {row_id}")
    chunk_ids = _declared_chunk_ids(evidence)
    chunk_hashes: dict[str, str] = {}
    for chunk_id in chunk_ids:
        row = lance_rows.get(chunk_id)
        if row is None:
            raise ValueError(f"selected Lance chunk unavailable: {row_id} {chunk_id}")
        if row.get("source_version_id") != source_version_id:
            raise ValueError(f"selected chunk/source mismatch: {row_id} {chunk_id}")
        if row.get("authority_identity_id") != authority_identity_id:
            raise ValueError(f"selected chunk/authority mismatch: {row_id} {chunk_id}")
        text = row.get("text")
        if not isinstance(text, str):
            raise ValueError(f"selected Lance chunk has no text: {row_id} {chunk_id}")
        chunk_hashes[chunk_id] = _sha256_text(text)

    declared_hashes = evidence.get("chunk_content_sha256s")
    if declared_hashes is not None:
        if not isinstance(declared_hashes, list) or len(declared_hashes) != len(chunk_ids):
            raise ValueError(f"chunk hash list mismatch: {row_id}")
        for chunk_id, digest in zip(chunk_ids, declared_hashes, strict=True):
            _require_sha256(digest, f"{row_id}.{chunk_id}.chunk_content_sha256")
            if chunk_hashes[chunk_id] != digest:
                raise ValueError(f"declared chunk digest mismatch: {row_id} {chunk_id}")

    primary_chunk_id = str(evidence.get("chunk_id") or chunk_ids[0])
    declared_chunk_digest = evidence.get("chunk_text_sha256")
    if declared_chunk_digest is not None:
        _require_sha256(declared_chunk_digest, f"{row_id}.chunk_text_sha256")
        if chunk_hashes[primary_chunk_id] != declared_chunk_digest:
            raise ValueError(f"primary chunk digest mismatch: {row_id}")

    exact_digest = evidence.get("exact_text_sha256")
    match_type = "CHUNKS_ONLY"
    canonical_span_ids: list[str] = []
    declared_span_ids = {
        str(value)
        for value in (evidence.get("span_id"), evidence.get("exact_span_id"))
        if isinstance(value, str) and value
    }
    span_identity_matches: bool | None = None
    if exact_digest is not None:
        _require_sha256(exact_digest, f"{row_id}.exact_text_sha256")
        whole_chunk_matches = [
            chunk_id for chunk_id, digest in chunk_hashes.items() if digest == exact_digest
        ]
        if whole_chunk_matches:
            match_type = "WHOLE_LANCE_CHUNK"
        else:
            verified_span = None
            for chunk_id in chunk_ids:
                verified_span = _verify_corpus_span(
                    source_version_id=source_version_id,
                    chunk_id=chunk_id,
                    chunk_text=str(lance_rows[chunk_id]["text"]),
                    exact_digest=exact_digest,
                    declared_span_ids=declared_span_ids,
                    spans=spans,
                )
                if verified_span is not None:
                    break
            if verified_span is None:
                raise ValueError(
                    f"exact text digest is neither a sealed chunk nor corpus span: {row_id}"
                )
            match_type = "BYTE_REPRODUCED_CORPUS_SPAN"
            canonical_span_ids = verified_span["canonical_span_ids"]
            span_identity_matches = verified_span["declared_span_identity_matches_corpus"]

    return {
        "row_id": row_id,
        "source_version_id": source_version_id,
        "authority_identity_id": authority_identity_id,
        "chunk_ids": chunk_ids,
        "chunk_text_sha256s": [chunk_hashes[value] for value in chunk_ids],
        "exact_text_sha256": exact_digest,
        "text_match_type": match_type,
        "declared_span_ids": sorted(declared_span_ids),
        "canonical_span_ids": canonical_span_ids,
        "declared_span_identity_matches_corpus": span_identity_matches,
    }


def _fetch_lance_rows(build_root: Path, chunk_ids: set[str]) -> dict[str, dict[str, Any]]:
    import lancedb

    table = lancedb.connect(str(build_root / "lance/authority")).open_table("chunks")
    result: dict[str, dict[str, Any]] = {}
    columns = ["chunk_id", "source_version_id", "authority_identity_id", "text"]
    for chunk_id in sorted(chunk_ids):
        escaped = chunk_id.replace("'", "''")
        rows = (
            table.search()
            .where(f"chunk_id = '{escaped}'", prefilter=True)
            .select(columns)
            .limit(2)
            .to_list()
        )
        if len(rows) != 1:
            raise ValueError(f"sealed Lance chunk identity is not unique: {chunk_id}")
        result[chunk_id] = rows[0]
    return result


def audit(
    draft_paths: list[Path],
    *,
    span_corpus_path: Path = DEFAULT_SPAN_CORPUS,
    candidate_manifest_path: Path = DEFAULT_CANDIDATE_MANIFEST,
    build_parent: Path = DEFAULT_BUILD_PARENT,
) -> dict[str, Any]:
    if not draft_paths:
        raise ValueError("at least one proposition draft is required")
    corpus = _load_object(span_corpus_path)
    spans = _span_index(corpus)
    manifest = _load_object(candidate_manifest_path)
    build_id = str(manifest.get("build_id") or "")
    if not build_id:
        raise ValueError("candidate build identity unavailable")
    build_root = build_parent / build_id

    evidence_items: list[tuple[str, dict[str, Any]]] = []
    input_drafts: dict[str, dict[str, Any]] = {}
    chunk_ids: set[str] = set()
    for path in sorted(draft_paths, key=lambda value: str(value)):
        validation = validator.validate_draft(path)
        draft = _load_object(path)
        input_drafts[str(path)] = {
            "sha256": _sha256_file(path),
            "record_count": validation["record_count"],
        }
        for record in draft["records"]:
            for evidence in record["selected_local_evidence"]:
                ids = _declared_chunk_ids(evidence)
                chunk_ids.update(ids)
                evidence_items.append((record["row_id"], evidence))

    lance_rows = _fetch_lance_rows(build_root, chunk_ids)
    records = [
        _audit_evidence_item(
            evidence,
            row_id=row_id,
            lance_rows=lance_rows,
            spans=spans,
        )
        for row_id, evidence in evidence_items
    ]
    match_counts = Counter(record["text_match_type"] for record in records)
    span_aliases = [
        {
            "row_id": record["row_id"],
            "declared_span_ids": record["declared_span_ids"],
            "canonical_span_ids": record["canonical_span_ids"],
        }
        for record in records
        if record["declared_span_identity_matches_corpus"] is False
    ]
    artifact: dict[str, Any] = {
        "schema": "legalbot.v111.phase2a.proposition-working-evidence-byte-audit.v1",
        "status": "PASS_NON_AUTHORIZING_BYTE_AUDIT",
        "candidate_build_id": build_id,
        "candidate_manifest_sha256": _sha256_file(candidate_manifest_path),
        "span_corpus_sha256": _sha256_file(span_corpus_path),
        "input_drafts": input_drafts,
        "selected_evidence_count": len(records),
        "unique_chunk_count": len(chunk_ids),
        "text_match_type_counts": dict(sorted(match_counts.items())),
        "span_identity_alias_count": len(span_aliases),
        "span_identity_aliases": span_aliases,
        "records": records,
        **FALSE_GATE_FIELDS,
    }
    artifact["artifact_content_sha256"] = _content_sha256(artifact, "artifact_content_sha256")
    return artifact


def write_new(path: Path, artifact: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(_canonical_json(artifact))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("drafts", nargs="+", type=Path)
    parser.add_argument("--span-corpus", type=Path, default=DEFAULT_SPAN_CORPUS)
    parser.add_argument("--candidate-manifest", type=Path, default=DEFAULT_CANDIDATE_MANIFEST)
    parser.add_argument("--build-parent", type=Path, default=DEFAULT_BUILD_PARENT)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    artifact = audit(
        args.drafts,
        span_corpus_path=args.span_corpus,
        candidate_manifest_path=args.candidate_manifest,
        build_parent=args.build_parent,
    )
    if args.output is not None:
        write_new(args.output, artifact)
    print(
        json.dumps(
            {
                "artifact_content_sha256": artifact["artifact_content_sha256"],
                "selected_evidence_count": artifact["selected_evidence_count"],
                "span_identity_alias_count": artifact["span_identity_alias_count"],
                "status": artifact["status"],
                "unique_chunk_count": artifact["unique_chunk_count"],
            },
            indent=2,
            sort_keys=True,
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
