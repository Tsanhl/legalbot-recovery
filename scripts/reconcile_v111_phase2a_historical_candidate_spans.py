#!/usr/bin/env python3
"""Recover deterministic candidate-span suggestions from historical staging rows.

The historical review file is never trusted as an owner decision unless its
recorded file hash matches.  Its text may still be used as candidate-discovery
input.  This command binds matching components to the exact sealed candidate,
records fresh-official-byte status, and emits an owner-review batch.  It never
qualifies an issue, admits a source, or authorizes another phase.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import stat
import unicodedata
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import lancedb  # type: ignore[import-untyped]

EXPECTED_HISTORICAL_REVIEW_SHA256 = (
    "e06d7f1179d58824c16ce2e45cbf46dcdce64365d69652729255738b9ddb1d2d"
)
HISTORICAL_SCHEMA = "legalbot.live60.owner-reviewed-search-answers.v1"
SNAPSHOT_SCHEMA = "legalbot.v111-phase2a-canonical-registry-snapshot.v1"
PROVENANCE_SCHEMA = "legalbot.v111-phase2a-official-source-provenance.v1"
SOURCE_MANIFEST_SCHEMA = "legalbot.approved-source-manifest.v1"
INDEX_SEAL_SCHEMA = "legalbot.index-seal.v2"
EXPECTED_RECORD_COUNT = 293
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SECTION = re.compile(
    r"(?:\bss?\.?|\bsections?|\band|,)\s*(?P<number>\d+[a-z]?)",
    re.IGNORECASE,
)
_REGULATION = re.compile(
    r"(?:\bregs?\.?|\bregulations?)\s*(?P<number>\d+[a-z]?)",
    re.IGNORECASE,
)
_ARTICLE = re.compile(
    r"(?:\barts?\.?|\barticles?)\s*(?P<number>\d+[a-z]?|[ivxlcdm]+)",
    re.IGNORECASE,
)
_RULE = re.compile(
    r"(?:\br\.?|\brules?)\s*(?P<number>\d+(?:\.\d+)?)",
    re.IGNORECASE,
)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _source_manifest_identity_sha256(value: Mapping[str, Any]) -> str:
    identity = {
        key: item
        for key, item in value.items()
        if key not in {"created_at", "manifest_sha256"}
    }
    return _sha256(_pretty_json(identity))


def _load_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_span_recovery_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_span_recovery_input_must_be_object")
    return value


def _verify_seal(value: dict[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or supplied != _sealed(material):
        raise ValueError(code)
    return supplied


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _normalise_text(value: str) -> str:
    value = html.unescape(unicodedata.normalize("NFKC", value or ""))
    value = (
        value.replace("–", "-")
        .replace("—", "-")
        .replace("’", "'")
        .replace("“", '"')
        .replace("”", '"')
    )
    return re.sub(r"\s+", " ", value).strip().casefold()


def _base_official_url(value: str) -> str:
    parsed = urlsplit(value)
    host = (parsed.hostname or "").casefold()
    parts = [part for part in parsed.path.split("/") if part]
    if host in {"legislation.gov.uk", "www.legislation.gov.uk"} and len(parts) >= 3:
        path = "/" + "/".join(parts[:3])
        return urlunsplit(("https", "www.legislation.gov.uk", path, "", ""))
    if host == "caselaw.nationalarchives.gov.uk" and len(parts) >= 3:
        path = "/" + "/".join(parts[:3])
        return urlunsplit(("https", host, path, "", ""))
    return urlunsplit((parsed.scheme.casefold(), parsed.netloc.casefold(), parsed.path.rstrip("/"), "", ""))


def _expected_locators(value: str) -> set[str]:
    locators: set[str] = set()
    for match in _SECTION.finditer(value):
        locators.add(f"section {match.group('number').casefold()}")
    for match in _REGULATION.finditer(value):
        locators.add(f"regulation {match.group('number').casefold()}")
    for match in _ARTICLE.finditer(value):
        locators.add(f"article {match.group('number').casefold()}")
    for match in _RULE.finditer(value):
        locators.add(f"rule {match.group('number').casefold()}")
    return locators


def _candidate_body(row: Mapping[str, Any]) -> str:
    body = _normalise_text(str(row.get("text") or ""))
    locator = _normalise_text(str(row.get("locator") or ""))
    if locator and body.startswith(locator + " "):
        return body[len(locator) + 1 :]
    return body


def _candidate_sources(
    record: Mapping[str, Any],
    *,
    by_title: Mapping[str, Sequence[Mapping[str, Any]]],
    by_url: Mapping[str, Sequence[Mapping[str, Any]]],
) -> tuple[Mapping[str, Any], ...]:
    title = str(record.get("source_title") or "").strip().casefold()
    if title and by_title.get(title):
        return tuple(by_title[title])
    url = _base_official_url(str(record.get("official_source_url") or ""))
    return tuple(by_url.get(url, ())) if url else ()


def _source_rows(table: Any, source: Mapping[str, Any]) -> list[dict[str, Any]]:
    source_version_id = str(source["source_version_id"])
    expected = int(source.get("body_chunk_count") or 0)
    limit = max(expected + 10, 100)
    rows = (
        table.search()
        .where(f"source_version_id = '{source_version_id}' AND retrieval_eligible = true")
        .limit(limit)
        .select(
            [
                "chunk_id",
                "source_version_id",
                "title",
                "canonical_url",
                "canonical_citation",
                "locator",
                "content_sha256",
                "text",
                "currentness_status",
                "identity_verified",
                "currentness_verified",
                "legal_role",
                "as_of_date",
            ]
        )
        .to_list()
    )
    if expected and len(rows) != expected:
        raise ValueError("phase2a_span_recovery_candidate_chunk_count_mismatch")
    return rows


def _fresh_official_status(
    source_version_ids: Sequence[str],
    provenance: Mapping[str, Sequence[Mapping[str, Any]]],
) -> dict[str, Any]:
    records = [record for source_id in source_version_ids for record in provenance.get(source_id, ())]
    if not records:
        return {
            "status": "NO_FRESH_OFFICIAL_RECORD_IN_PHASE2A_PROVENANCE",
            "record_count": 0,
            "all_exact_candidate_byte_matches": False,
        }
    exact = all(record.get("matches_expected_version_sha256") is True for record in records)
    return {
        "status": (
            "FRESH_OFFICIAL_BYTES_MATCH_SEALED_CANDIDATE"
            if exact
            else "FRESH_OFFICIAL_BYTES_DIFFER_OR_SOURCE_UNAVAILABLE_MATERIALITY_UNRESOLVED"
        ),
        "record_count": len(records),
        "all_exact_candidate_byte_matches": exact,
        "record_sha256s": [_sealed(record) for record in records],
    }


def _match_record(
    *,
    record: Mapping[str, Any],
    candidate_sources: Sequence[Mapping[str, Any]],
    candidate_rows: Sequence[Mapping[str, Any]],
    provenance: Mapping[str, Sequence[Mapping[str, Any]]],
) -> dict[str, Any]:
    operative = _normalise_text(str(record.get("operative_text") or ""))
    expected_locators = _expected_locators(str(record.get("legal_locator") or ""))
    locator_rows = [
        row
        for row in candidate_rows
        if _normalise_text(str(row.get("locator") or "")) in expected_locators
    ]
    locator_constraint_applied = bool(expected_locators and locator_rows)
    search_rows = locator_rows if locator_constraint_applied else list(candidate_rows)
    matches: list[tuple[int, int, Mapping[str, Any], str]] = []
    for row in search_rows:
        body = _candidate_body(row)
        if len(body) < 12:
            continue
        position = operative.find(body)
        if position >= 0:
            matches.append((position, position + len(body), row, body))
    matches.sort(key=lambda item: (item[0], item[1], str(item[2].get("chunk_id") or "")))
    deduplicated: list[tuple[int, int, Mapping[str, Any], str]] = []
    seen_chunks: set[str] = set()
    for match in matches:
        chunk_id = str(match[2].get("chunk_id") or "")
        if chunk_id and chunk_id not in seen_chunks:
            seen_chunks.add(chunk_id)
            deduplicated.append(match)
    covered: set[int] = set()
    for start, end, _, _ in deduplicated:
        covered.update(range(start, end))
    coverage_ratio = round(len(covered) / max(1, len(operative)), 6) if operative else 0.0
    source_ids = sorted({str(source["source_version_id"]) for source in candidate_sources})
    exact_candidate_controls = bool(deduplicated) and all(
        row.get("identity_verified") is True and row.get("currentness_verified") is True
        for _, _, row, _ in deduplicated
    )
    if not operative:
        status = "NO_OPERATIVE_TEXT_KEEP_GAP"
    elif not candidate_sources:
        status = "NO_MATCHING_SOURCE_IN_SEALED_CANDIDATE"
    elif not deduplicated:
        status = "NO_EXACT_CANDIDATE_TEXT_COMPONENT"
    elif coverage_ratio >= 0.75 and exact_candidate_controls and (
        locator_constraint_applied or not expected_locators
    ):
        status = "DETERMINISTIC_CANDIDATE_COMPONENTS_LOCATED_OWNER_REVIEW_REQUIRED"
    else:
        status = "PARTIAL_CANDIDATE_COMPONENTS_OWNER_REVIEW_REQUIRED"
    spans = [
        {
            "chunk_id": row.get("chunk_id"),
            "source_version_id": row.get("source_version_id"),
            "title": row.get("title"),
            "canonical_url": row.get("canonical_url"),
            "canonical_citation": row.get("canonical_citation"),
            "locator": row.get("locator"),
            "content_sha256": row.get("content_sha256"),
            "text": row.get("text"),
            "currentness_status": row.get("currentness_status"),
            "identity_verified": row.get("identity_verified"),
            "currentness_verified": row.get("currentness_verified"),
            "legal_role": row.get("legal_role"),
            "as_of_date": row.get("as_of_date"),
            "staging_text_start": start,
            "staging_text_end": end,
        }
        for start, end, row, _ in deduplicated
    ]
    return {
        "match_status": status,
        "candidate_source_count": len(candidate_sources),
        "candidate_source_version_ids": source_ids,
        "expected_locator_stems": sorted(expected_locators),
        "locator_constraint_applied": locator_constraint_applied,
        "matched_component_count": len(spans),
        "normalized_character_coverage_ratio": coverage_ratio,
        "candidate_identity_and_currentness_controls_passed": exact_candidate_controls,
        "fresh_official_source_check": _fresh_official_status(source_ids, provenance),
        "candidate_spans": spans,
        "semantic_proposition_binding_verified": False,
        "owner_adopted": False,
        "source_admission_authorized": False,
        "candidate_change_authorized": False,
    }


def reconcile(
    *,
    historical_path: Path,
    snapshot_path: Path,
    provenance_path: Path,
    candidate_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Emit deterministic candidate-span suggestions with all gates held."""

    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_span_recovery_output_already_exists")
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_span_recovery_output_mode_invalid")

    historical_sha256 = _sha256_file(historical_path)
    historical = _load_json(historical_path)
    records = historical.get("records")
    if (
        historical.get("schema") != HISTORICAL_SCHEMA
        or not isinstance(records, list)
        or len(records) != EXPECTED_RECORD_COUNT
        or historical_sha256 == EXPECTED_HISTORICAL_REVIEW_SHA256
    ):
        raise ValueError("phase2a_span_recovery_historical_staging_boundary_invalid")

    snapshot = _load_json(snapshot_path)
    snapshot_sha256 = _verify_seal(
        snapshot,
        "snapshot_sha256",
        "phase2a_span_recovery_snapshot_seal_invalid",
    )
    if snapshot.get("schema") != SNAPSHOT_SCHEMA or snapshot.get("issue_count") != 585:
        raise ValueError("phase2a_span_recovery_snapshot_invalid")
    canonical_rows = {
        str(issue["row_id"]): issue
        for case in snapshot.get("cases", [])
        for issue in case.get("issues", [])
    }
    issue_keys = [str(record.get("issue_key") or "") for record in records]
    if len(set(issue_keys)) != EXPECTED_RECORD_COUNT or not set(issue_keys) <= set(canonical_rows):
        raise ValueError("phase2a_span_recovery_historical_issue_identity_invalid")

    provenance_artifact = _load_json(provenance_path)
    provenance_sha256 = _verify_seal(
        provenance_artifact,
        "artifact_sha256",
        "phase2a_span_recovery_provenance_seal_invalid",
    )
    if provenance_artifact.get("schema") != PROVENANCE_SCHEMA:
        raise ValueError("phase2a_span_recovery_provenance_schema_invalid")
    provenance: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for item in provenance_artifact.get("records", []):
        if isinstance(item, Mapping):
            provenance[str(item.get("target_id") or "")].append(item)

    source_manifest_path = candidate_root / "approved-source-manifest.json"
    index_manifest_path = candidate_root / "manifest.json"
    index_seal_path = candidate_root / "seal.json"
    source_manifest = _load_json(source_manifest_path)
    manifest_sha256 = str(source_manifest.get("manifest_sha256") or "")
    index_seal = _load_json(index_seal_path)
    if (
        source_manifest.get("schema") != SOURCE_MANIFEST_SCHEMA
        or manifest_sha256 != _source_manifest_identity_sha256(source_manifest)
        or index_seal.get("schema") != INDEX_SEAL_SCHEMA
        or _sha256_file(source_manifest_path) != index_seal.get("source_manifest_file_sha256")
        or _sha256_file(index_manifest_path) != index_seal.get("manifest_sha256")
        or source_manifest.get("corpus_id") != index_seal.get("build_id")
    ):
        raise ValueError("phase2a_span_recovery_candidate_seal_invalid")

    sources = [item for item in source_manifest.get("sources", []) if isinstance(item, Mapping)]
    by_title: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    by_url: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for source in sources:
        by_title[str(source.get("title") or "").strip().casefold()].append(source)
        by_url[_base_official_url(str(source.get("canonical_url") or ""))].append(source)

    table = lancedb.connect(str(candidate_root / "lance" / "authority")).open_table("chunks")
    row_cache: dict[str, list[dict[str, Any]]] = {}
    reconciled: list[dict[str, Any]] = []
    for ordinal, record in enumerate(records, start=1):
        matched_sources = _candidate_sources(record, by_title=by_title, by_url=by_url)
        candidate_rows: list[dict[str, Any]] = []
        for source in matched_sources:
            source_id = str(source["source_version_id"])
            if source_id not in row_cache:
                row_cache[source_id] = _source_rows(table, source)
            candidate_rows.extend(row_cache[source_id])
        result = _match_record(
            record=record,
            candidate_sources=matched_sources,
            candidate_rows=candidate_rows,
            provenance=provenance,
        )
        canonical = canonical_rows[str(record["issue_key"])]
        material = {
            "ordinal": ordinal,
            "row_id": record["issue_key"],
            "canonical_issue_id": canonical["issue_id"],
            "canonical_issue_label_sha256": canonical["issue_label_sha256"],
            "historical_staging_record_sha256": _sealed(record),
            "historical_staging_file_sha256": historical_sha256,
            "historical_owner_decision_reused": False,
            "staging_question_sha256": _sha256(str(record.get("question") or "").encode()),
            "staging_operative_text_sha256": _sha256(
                str(record.get("operative_text") or "").encode()
            ),
            "staging_source_title": record.get("source_title"),
            "staging_source_type": record.get("source_type"),
            "staging_citation": record.get("citation"),
            "staging_legal_locator": record.get("legal_locator"),
            "staging_official_source_url": record.get("official_source_url"),
            **result,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        material["record_content_sha256"] = _sealed(material)
        reconciled.append(material)

    status_counts = Counter(str(item["match_status"]) for item in reconciled)
    review_rows = [
        item
        for item in reconciled
        if item["match_status"]
        == "DETERMINISTIC_CANDIDATE_COMPONENTS_LOCATED_OWNER_REVIEW_REQUIRED"
    ]
    full_material = {
        "schema": "legalbot.v111.phase2a.historical-candidate-span-reconciliation.v1",
        "status": "STAGING_ONLY_NOT_QUALIFICATION",
        "historical_staging_expected_sha256": EXPECTED_HISTORICAL_REVIEW_SHA256,
        "historical_staging_observed_sha256": historical_sha256,
        "historical_hash_match": False,
        "canonical_registry_snapshot_content_sha256": snapshot_sha256,
        "official_source_provenance_content_sha256": provenance_sha256,
        "candidate_build_id": source_manifest["corpus_id"],
        "candidate_source_manifest_content_sha256": manifest_sha256,
        "candidate_source_manifest_file_sha256": _sha256_file(source_manifest_path),
        "record_count": len(reconciled),
        "match_status_counts": dict(sorted(status_counts.items())),
        "owner_review_candidate_count": len(review_rows),
        "records": reconciled,
        "issue_technical_qualification_count": 0,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    full = {**full_material, "artifact_content_sha256": _sealed(full_material)}
    review_material = {
        "schema": "legalbot.v111.phase2a.candidate-span-owner-review-batch.v1",
        "status": "OWNER_REVIEW_REQUIRED",
        "source_reconciliation_content_sha256": full["artifact_content_sha256"],
        "item_count": len(review_rows),
        "items": review_rows,
        "owner_instruction": (
            "Review proposition relevance, exact component completeness, currentness and fresh "
            "official-byte mismatch materiality. These suggestions are not owner decisions."
        ),
        "issue_technical_qualification_count": 0,
        "source_admission_authorized": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    review = {**review_material, "batch_content_sha256": _sealed(review_material)}
    _write_exclusive(
        output_root / "HISTORICAL-CANDIDATE-SPAN-RECONCILIATION-293.json",
        _pretty_json(full),
    )
    _write_exclusive(
        output_root / "OWNER-REVIEW-CANDIDATE-SPANS.json",
        _pretty_json(review),
    )
    outcome = (
        f"PHASE 2A CANDIDATE-SPAN DISCOVERY COMPLETE — {len(review_rows)} ROWS REQUIRE "
        "OWNER REVIEW; ZERO ISSUES QUALIFIED; PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED\n"
    )
    _write_exclusive(output_root / "OUTCOME.txt", outcome.encode())
    files = sorted(path for path in output_root.iterdir() if path.is_file())
    _write_exclusive(
        output_root / "SHA256SUMS.txt",
        "".join(f"{_sha256_file(path)}  {path.name}\n" for path in files).encode(),
    )
    return {
        "output_root": str(output_root),
        "candidate_build_id": source_manifest["corpus_id"],
        "record_count": len(reconciled),
        "match_status_counts": dict(sorted(status_counts.items())),
        "owner_review_candidate_count": len(review_rows),
        "reconciliation_content_sha256": full["artifact_content_sha256"],
        "owner_review_batch_content_sha256": review["batch_content_sha256"],
        "issue_technical_qualification_count": 0,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }


def _persist_failure(output_root: Path, exc: BaseException) -> None:
    try:
        output_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        path = output_root / "FAILURE.json"
        if path.exists():
            return
        material = {
            "schema": "legalbot.v111.phase2a.historical-candidate-span-recovery-failure.v1",
            "exception_type": type(exc).__name__,
            "error": str(exc),
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        _write_exclusive(
            path,
            _pretty_json({**material, "failure_content_sha256": _sealed(material)}),
        )
    except Exception:
        return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--historical-review", required=True, type=Path)
    parser.add_argument("--canonical-snapshot", required=True, type=Path)
    parser.add_argument("--official-source-provenance", required=True, type=Path)
    parser.add_argument("--candidate-root", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = reconcile(
            historical_path=args.historical_review.resolve(strict=True),
            snapshot_path=args.canonical_snapshot.resolve(strict=True),
            provenance_path=args.official_source_provenance.resolve(strict=True),
            candidate_root=args.candidate_root.resolve(strict=True),
            output_root=args.output_root.resolve(),
        )
    except Exception as exc:
        _persist_failure(args.output_root.resolve(), exc)
        raise
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
