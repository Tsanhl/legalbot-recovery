#!/usr/bin/env python3
"""Resolve advisory Phase-2A authority plans to exact sealed-catalogue chunks.

This deterministic pass proves only source/version/locator/chunk identity.  It
does not decide whether the text supports the issue, select a proposition,
admit a source, mutate a candidate, or authorize a later phase.

If a planner locator does not resolve, a bounded row-specific fallback exposes
only exact chunks already named by the sealed research packets.  The later
semantic verifier must still reject unrelated or unsupported material.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import stat
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from datetime import date
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OWNER_REVIEW_ROOT = PROJECT_ROOT / "data" / "evaluations" / "phase2a-owner-review"
DEFAULT_PLANS = (
    OWNER_REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r50-authority-plan-advisory"
    / "ADVISORY-AUTHORITY-PLANS-448.json"
)
DEFAULT_ORIGINAL = (
    OWNER_REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-24-r29" / "REMAINING-448-RESEARCH-PACKETS.json"
)
DEFAULT_DEEP = (
    OWNER_REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-24-r40-deep-recovery"
    / "DEEP-CURRENT-OFFICIAL-CANDIDATES-176.json"
)
DEFAULT_CATALOGUE = PROJECT_ROOT / "data" / "catalog.sqlite3"
DEFAULT_OUTPUT = (
    OWNER_REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r51c-context-safe-locator-resolution"
)

EXPECTED_ORIGINAL_CONTENT_SHA256 = (
    "a7f7359c3ff12da02ee4056532198d39417459c9e20aac602f64437fb7cf5aa6"
)
EXPECTED_DEEP_CONTENT_SHA256 = "692cdafd0e10f8b864a96cc35165cb20441dc099b52a2f2cad90b38befcbbbf1"
EXPECTED_CATALOGUE_FILE_SHA256 = "8c700c3e8f9cc77abe4b03cf5011624db9ff14a74f02f3a37b59c1fcf595a10d"
EXPECTED_ISSUE_COUNT = 448
TARGET_CEILING_DATE = date(2026, 8, 14)
MAX_FALLBACK_CANDIDATES = 3
MAX_FALLBACK_TEXT_CHARACTERS = 8_000
MAX_FALLBACK_EXACT_CHUNKS_PER_ROW = 12
MAX_PLANNER_EXACT_CHUNKS_PER_SELECTION = 12
MAX_PLANNER_EXACT_CHUNKS_PER_ROW = 12
MAX_PLANNER_TEXT_CHARACTERS_PER_ROW = 8_000
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ISO_DATE_TOKEN = re.compile(r"(?<!\d)(\d{4}-\d{2}-\d{2})(?!\d)")
_SECTION = re.compile(r"^(?:s(?:ection)?\s*)?(\d+[a-z]?)(?:\([^)]*\))*$", re.IGNORECASE)
_SCHEDULE = re.compile(r"^(?:sch(?:edule)?\s*)(\d+[a-z]?)$", re.IGNORECASE)
_PAGE = re.compile(r"^(?:p(?:age)?\s*)(\d+)$", re.IGNORECASE)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_locator_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_locator_input_must_be_object")
    return value


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or supplied != _sealed(material):
        raise ValueError(code)
    return supplied


def canonical_locator(value: str) -> str:
    """Return the conservative catalogue locator coordinate for one hint."""

    text = " ".join(value.casefold().replace("§", "section ").split()).strip(" .")
    if match := _SECTION.fullmatch(text):
        return f"section {match.group(1).casefold()}"
    if match := _SCHEDULE.fullmatch(text):
        return f"schedule {match.group(1).casefold()}"
    if match := _PAGE.fullmatch(text):
        return f"p {int(match.group(1))}"
    parts = [part.strip() for part in text.split(">") if part.strip()]
    return (parts[-1] if parts else text)[:256]


def _candidate_rows(
    original_path: Path,
    deep_path: Path,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, str]]:
    original = _load_object(original_path)
    deep = _load_object(deep_path)
    original_sha256 = _verify_seal(
        original, "artifact_content_sha256", "phase2a_locator_original_seal_invalid"
    )
    deep_sha256 = _verify_seal(deep, "artifact_content_sha256", "phase2a_locator_deep_seal_invalid")
    if (
        original_sha256 != EXPECTED_ORIGINAL_CONTENT_SHA256
        or deep_sha256 != EXPECTED_DEEP_CONTENT_SHA256
    ):
        raise ValueError("phase2a_locator_candidate_identity_invalid")
    by_row: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for artifact in (original, deep):
        rows = artifact.get("rows")
        if not isinstance(rows, list):
            raise ValueError("phase2a_locator_candidate_rows_invalid")
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("candidates"), list):
                raise ValueError("phase2a_locator_candidate_row_invalid")
            by_row[str(row.get("row_id") or "")].extend(
                dict(candidate) for candidate in row["candidates"] if isinstance(candidate, dict)
            )
    return dict(by_row), {"original": original_sha256, "deep": deep_sha256}


def _choose_source_candidate(
    row_candidates: Sequence[Mapping[str, Any]], authority_id: str
) -> dict[str, Any] | None:
    matches = [
        dict(candidate)
        for candidate in row_candidates
        if str(candidate.get("authority_identity_id") or "") == authority_id
        and str(candidate.get("source_version_id") or "")
    ]
    if not matches:
        return None
    matches.sort(
        key=lambda candidate: (
            not _record_is_after_target_ceiling(candidate),
            candidate.get("identity_verified") is True,
            candidate.get("currentness_verified") is True,
            str(candidate.get("as_of_date") or ""),
            str(candidate.get("source_version_id") or ""),
        ),
        reverse=True,
    )
    return matches[0]


def _record_is_after_target_ceiling(value: Mapping[str, Any]) -> bool:
    """Return true only for an explicit ISO date later than the target ceiling."""

    candidates: list[str] = []
    for field in ("as_of_date", "source_date"):
        raw = str(value.get(field) or "").strip()
        if raw:
            candidates.append(raw[:10])
    for field in ("stable_identifier", "canonical_url"):
        raw = str(value.get(field) or "")
        candidates.extend(match.group(1) for match in _ISO_DATE_TOKEN.finditer(raw))
    for raw in candidates:
        try:
            observed = date.fromisoformat(raw)
        except ValueError:
            # Unknown/malformed dates remain for the later explicit currentness
            # review; this resolver does not silently assert that they are current.
            continue
        if observed > TARGET_CEILING_DATE:
            return True
    return False


def _open_catalogue(path: Path) -> sqlite3.Connection:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_locator_catalogue_missing")
    connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro&immutable=1", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def _source_identity(
    connection: sqlite3.Connection, source_version_id: str
) -> dict[str, Any] | None:
    row = connection.execute(
        """
        SELECT sv.id, sv.authority_identity_id, sv.version_sha256,
               sv.title, sv.canonical_url, sv.stable_identifier,
               sv.source_date, sv.as_of_date, sv.currentness_status,
               sv.review_status,
               d.status AS document_status, d.lane
        FROM source_versions sv
        JOIN documents d ON d.id=sv.document_id
        WHERE sv.id=?
        """,
        (source_version_id,),
    ).fetchone()
    return dict(row) if row is not None else None


def _locator_chunks(
    connection: sqlite3.Connection,
    *,
    source_version_id: str,
    locator_hint: str,
) -> list[dict[str, Any]]:
    target = canonical_locator(locator_hint)
    rows = connection.execute(
        """
        SELECT id, ordinal, heading_path, locator, text_sha256,
               markdown_text, token_count, metadata_json, stream
        FROM chunks
        WHERE source_version_id=?
        ORDER BY ordinal, id
        """,
        (source_version_id,),
    ).fetchall()
    exact: list[dict[str, Any]] = []
    for row in rows:
        locator = str(row["locator"] or "")
        heading = ""
        try:
            parsed_heading = json.loads(str(row["heading_path"] or "[]"))
            if isinstance(parsed_heading, list):
                heading = " > ".join(str(item) for item in parsed_heading)
        except json.JSONDecodeError:
            heading = str(row["heading_path"] or "")
        if canonical_locator(locator) != target and canonical_locator(heading) != target:
            continue
        text = str(row["markdown_text"] or "")
        supplied_sha256 = str(row["text_sha256"] or "")
        if not text or supplied_sha256 != _sha256(text.encode("utf-8")):
            raise ValueError("phase2a_locator_chunk_hash_invalid")
        exact.append(
            {
                "chunk_id": str(row["id"]),
                "ordinal": int(row["ordinal"]),
                "locator": locator,
                "heading_path": heading,
                "text": text,
                "text_sha256": supplied_sha256,
                "token_count": int(row["token_count"]),
                "stream": str(row["stream"] or ""),
                "metadata_json_sha256": _sha256(str(row["metadata_json"] or "{}").encode()),
            }
        )
    return exact


def _bounded_planner_chunks(
    chunks: Sequence[Mapping[str, Any]],
    *,
    remaining_characters: int,
    remaining_chunks: int,
) -> tuple[list[dict[str, Any]], dict[str, int | bool]]:
    """Accept a locator only when its complete result fits deterministic bounds."""

    available_count = len(chunks)
    available_characters = sum(len(str(chunk.get("text") or "")) for chunk in chunks)
    accepted = (
        available_count <= MAX_PLANNER_EXACT_CHUNKS_PER_SELECTION
        and available_count <= remaining_chunks
        and available_characters <= remaining_characters
    )
    return (
        [dict(chunk) for chunk in chunks] if accepted else [],
        {
            "available_exact_chunk_count": available_count,
            "available_exact_chunk_text_characters": available_characters,
            "complete_locator_result_within_bound": accepted,
        },
    )


def _bounded_fallback_chunks(
    chunks: Sequence[Mapping[str, Any]],
    *,
    remaining_characters: int,
    remaining_chunks: int,
) -> tuple[list[dict[str, Any]], dict[str, int | bool]]:
    """Accept a row candidate only when its complete chunk set fits the budget."""

    available_count = len(chunks)
    available_characters = sum(len(str(chunk.get("text") or "")) for chunk in chunks)
    accepted = available_count <= remaining_chunks and available_characters <= remaining_characters
    return (
        [dict(chunk) for chunk in chunks] if accepted else [],
        {
            "available_exact_chunk_count": available_count,
            "available_exact_chunk_text_characters": available_characters,
            "complete_candidate_result_within_bound": accepted,
        },
    )


def _candidate_chunks(
    connection: sqlite3.Connection,
    *,
    source_version_id: str,
    candidate: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Resolve a sealed research candidate's exact chunk identities in order."""

    chunk_ids = candidate.get("chunk_ids")
    chunk_hashes = candidate.get("chunk_text_sha256s")
    if (
        not isinstance(chunk_ids, list)
        or not isinstance(chunk_hashes, list)
        or not chunk_ids
        or len(chunk_ids) != len(chunk_hashes)
        or any(not str(chunk_id) for chunk_id in chunk_ids)
        or len({str(chunk_id) for chunk_id in chunk_ids}) != len(chunk_ids)
        or any(not _SHA256.fullmatch(str(value)) for value in chunk_hashes)
    ):
        raise ValueError("phase2a_locator_candidate_chunk_identity_invalid")
    placeholders = ",".join("?" for _ in chunk_ids)
    rows = connection.execute(
        f"""
        SELECT id, source_version_id, ordinal, heading_path, locator, text_sha256,
               markdown_text, token_count, metadata_json, stream
        FROM chunks
        WHERE source_version_id=? AND id IN ({placeholders})
        """,
        (source_version_id, *(str(chunk_id) for chunk_id in chunk_ids)),
    ).fetchall()
    by_id = {str(row["id"]): row for row in rows}
    if set(by_id) != {str(chunk_id) for chunk_id in chunk_ids}:
        raise ValueError("phase2a_locator_candidate_chunk_missing")
    exact: list[dict[str, Any]] = []
    for chunk_id, expected_sha256 in zip(chunk_ids, chunk_hashes, strict=True):
        row = by_id[str(chunk_id)]
        text = str(row["markdown_text"] or "")
        supplied_sha256 = str(row["text_sha256"] or "")
        if (
            not text
            or supplied_sha256 != str(expected_sha256)
            or supplied_sha256 != _sha256(text.encode("utf-8"))
        ):
            raise ValueError("phase2a_locator_candidate_chunk_hash_invalid")
        heading = ""
        try:
            parsed_heading = json.loads(str(row["heading_path"] or "[]"))
            if isinstance(parsed_heading, list):
                heading = " > ".join(str(item) for item in parsed_heading)
        except json.JSONDecodeError:
            heading = str(row["heading_path"] or "")
        exact.append(
            {
                "chunk_id": str(row["id"]),
                "ordinal": int(row["ordinal"]),
                "locator": str(row["locator"] or ""),
                "heading_path": heading,
                "text": text,
                "text_sha256": supplied_sha256,
                "token_count": int(row["token_count"]),
                "stream": str(row["stream"] or ""),
                "metadata_json_sha256": _sha256(str(row["metadata_json"] or "{}").encode()),
            }
        )
    return exact


def _fallback_candidates(
    row_candidates: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Return a bounded, stable set of existing row-specific research candidates."""

    selected: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for candidate in row_candidates:
        source_version_id = str(candidate.get("source_version_id") or "")
        authority_id = str(candidate.get("authority_identity_id") or "")
        locator = str(candidate.get("locator") or "")
        identity = (source_version_id, authority_id, locator)
        if (
            candidate.get("identity_verified") is not True
            or _record_is_after_target_ceiling(candidate)
            or not source_version_id
            or not authority_id
            or not locator
            or identity in seen
        ):
            continue
        seen.add(identity)
        selected.append(dict(candidate))
        if len(selected) == MAX_FALLBACK_CANDIDATES:
            break
    return selected


def resolve_plans(
    *,
    plans_path: Path,
    original_path: Path,
    deep_path: Path,
    catalogue_path: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Resolve every planner selection without assigning semantic support."""

    plans_artifact = _load_object(plans_path)
    plans_sha256 = _verify_seal(
        plans_artifact,
        "artifact_content_sha256",
        "phase2a_locator_plans_seal_invalid",
    )
    plans = plans_artifact.get("plans")
    held_row_ids = plans_artifact.get("held_row_ids")
    if (
        plans_artifact.get("issue_count") != EXPECTED_ISSUE_COUNT
        or not isinstance(plans, list)
        or not isinstance(held_row_ids, list)
        or len(plans) + len(held_row_ids) != EXPECTED_ISSUE_COUNT
        or plans_artifact.get("owner_decisions_applied") is not False
        or plans_artifact.get("source_admission_authorized") is not False
        or plans_artifact.get("candidate_mutated") is not False
        or plans_artifact.get("phase2b_authorized") is not False
        or plans_artifact.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_locator_plans_boundary_invalid")
    candidates_by_row, candidate_hashes = _candidate_rows(original_path, deep_path)
    if catalogue_path.is_symlink() or not catalogue_path.is_file():
        raise ValueError("phase2a_locator_catalogue_missing")
    catalogue_file_sha256 = _sha256_file(catalogue_path)
    if catalogue_file_sha256 != EXPECTED_CATALOGUE_FILE_SHA256:
        raise ValueError("phase2a_locator_catalogue_identity_invalid")
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_locator_output_already_exists")
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_locator_output_mode_invalid")

    connection = _open_catalogue(catalogue_path)
    records: list[dict[str, Any]] = []
    source_cache: dict[str, dict[str, Any] | None] = {}
    chunk_cache: dict[tuple[str, str], list[dict[str, Any]]] = {}
    candidate_chunk_cache: dict[tuple[str, tuple[str, ...]], list[dict[str, Any]]] = {}
    try:
        for ordinal, plan in enumerate(plans, start=1):
            if not isinstance(plan, dict):
                raise ValueError("phase2a_locator_plan_invalid")
            row_id = str(plan.get("row_id") or "")
            selections = plan.get("selections")
            if not row_id or not isinstance(selections, list):
                raise ValueError("phase2a_locator_plan_boundary_invalid")
            resolved: list[dict[str, Any]] = []
            remaining_planner_characters = MAX_PLANNER_TEXT_CHARACTERS_PER_ROW
            remaining_planner_chunks = MAX_PLANNER_EXACT_CHUNKS_PER_ROW
            for selection in selections:
                if not isinstance(selection, dict):
                    raise ValueError("phase2a_locator_selection_invalid")
                authority_id = str(selection.get("authority_id") or "")
                locator_hint = str(selection.get("locator_hint") or "")
                source_candidate = _choose_source_candidate(
                    candidates_by_row.get(row_id, ()), authority_id
                )
                if source_candidate is None:
                    resolved.append(
                        {
                            "authority_identity_id": authority_id,
                            "locator_hint": locator_hint,
                            "canonical_locator": canonical_locator(locator_hint),
                            "resolution_status": "AUTHORITY_NOT_BOUND_TO_ROW_CANDIDATE",
                            "source_identity": None,
                            "exact_chunks": [],
                        }
                    )
                    continue
                source_version_id = str(source_candidate["source_version_id"])
                if source_version_id not in source_cache:
                    source_cache[source_version_id] = _source_identity(
                        connection, source_version_id
                    )
                source = source_cache[source_version_id]
                if (
                    source is None
                    or str(source.get("authority_identity_id") or "") != authority_id
                    or source.get("review_status") != "approved"
                    or source.get("document_status") != "citable"
                    or source.get("lane") != "primary_authority"
                ):
                    resolved.append(
                        {
                            "authority_identity_id": authority_id,
                            "locator_hint": locator_hint,
                            "canonical_locator": canonical_locator(locator_hint),
                            "resolution_status": "SOURCE_VERSION_IDENTITY_OR_REVIEW_INVALID",
                            "source_identity": source,
                            "exact_chunks": [],
                        }
                    )
                    continue
                if _record_is_after_target_ceiling(source):
                    resolved.append(
                        {
                            "authority_identity_id": authority_id,
                            "locator_hint": locator_hint,
                            "canonical_locator": canonical_locator(locator_hint),
                            "resolution_status": "SOURCE_VERSION_AFTER_TARGET_CEILING",
                            "source_identity": source,
                            "exact_chunks": [],
                        }
                    )
                    continue
                chunk_key = (source_version_id, canonical_locator(locator_hint))
                if chunk_key not in chunk_cache:
                    chunk_cache[chunk_key] = _locator_chunks(
                        connection,
                        source_version_id=source_version_id,
                        locator_hint=locator_hint,
                    )
                exact_chunks, locator_budget = _bounded_planner_chunks(
                    chunk_cache[chunk_key],
                    remaining_characters=remaining_planner_characters,
                    remaining_chunks=remaining_planner_chunks,
                )
                remaining_planner_characters -= sum(
                    len(str(chunk["text"])) for chunk in exact_chunks
                )
                remaining_planner_chunks -= len(exact_chunks)
                resolved.append(
                    {
                        "authority_identity_id": authority_id,
                        "locator_hint": locator_hint,
                        "canonical_locator": canonical_locator(locator_hint),
                        "resolution_status": (
                            "EXACT_LOCATOR_CHUNKS_FOUND"
                            if exact_chunks
                            else (
                                "LOCATOR_NOT_FOUND_IN_SELECTED_SOURCE_VERSION"
                                if locator_budget["available_exact_chunk_count"] == 0
                                else "LOCATOR_AMBIGUOUS_EXCEEDS_DETERMINISTIC_BOUND"
                            )
                        ),
                        "source_identity": source,
                        "candidate_source_metadata": {
                            "canonical_citation": source_candidate.get("canonical_citation"),
                            "canonical_url": source_candidate.get("canonical_url"),
                            "identity_verified": source_candidate.get("identity_verified") is True,
                            "currentness_verified": source_candidate.get("currentness_verified")
                            is True,
                            "later_treatment_review_required": (
                                source_candidate.get("later_treatment_review_required") is True
                            ),
                            "already_in_sealed_candidate": (
                                source_candidate.get("already_in_sealed_candidate") is True
                            ),
                        },
                        "exact_chunk_count": len(exact_chunks),
                        **locator_budget,
                        "exact_chunks": exact_chunks,
                    }
                )
            fallback_used = False
            fallback_reason: str | None = None
            has_exact_planner_chunk = any(
                selection.get("resolution_status") == "EXACT_LOCATOR_CHUNKS_FOUND"
                and bool(selection.get("exact_chunks"))
                for selection in resolved
            )
            if plan.get("assessment") != "NONMATERIAL" and not has_exact_planner_chunk:
                fallback_reason = (
                    "PLANNER_GAP"
                    if plan.get("assessment") == "GAP"
                    else "PLANNER_SELECTIONS_DID_NOT_RESOLVE"
                )
                remaining_characters = MAX_FALLBACK_TEXT_CHARACTERS
                remaining_chunks = MAX_FALLBACK_EXACT_CHUNKS_PER_ROW
                for candidate in _fallback_candidates(candidates_by_row.get(row_id, ())):
                    source_version_id = str(candidate["source_version_id"])
                    authority_id = str(candidate["authority_identity_id"])
                    if source_version_id not in source_cache:
                        source_cache[source_version_id] = _source_identity(
                            connection, source_version_id
                        )
                    source = source_cache[source_version_id]
                    if (
                        source is None
                        or str(source.get("authority_identity_id") or "") != authority_id
                        or source.get("review_status") != "approved"
                        or source.get("document_status") != "citable"
                        or source.get("lane") != "primary_authority"
                        or _record_is_after_target_ceiling(source)
                    ):
                        continue
                    candidate_chunk_ids = tuple(
                        str(chunk_id) for chunk_id in candidate.get("chunk_ids") or ()
                    )
                    cache_key = (source_version_id, candidate_chunk_ids)
                    if cache_key not in candidate_chunk_cache:
                        candidate_chunk_cache[cache_key] = _candidate_chunks(
                            connection,
                            source_version_id=source_version_id,
                            candidate=candidate,
                        )
                    exact_chunks, candidate_budget = _bounded_fallback_chunks(
                        candidate_chunk_cache[cache_key],
                        remaining_characters=remaining_characters,
                        remaining_chunks=remaining_chunks,
                    )
                    candidate_metadata = {
                        "canonical_citation": candidate.get("canonical_citation"),
                        "canonical_url": candidate.get("canonical_url"),
                        "identity_verified": candidate.get("identity_verified") is True,
                        "currentness_verified": (candidate.get("currentness_verified") is True),
                        "later_treatment_review_required": (
                            candidate.get("later_treatment_review_required") is True
                        ),
                        "already_in_sealed_candidate": (
                            candidate.get("already_in_sealed_candidate") is True
                        ),
                        "candidate_record_content_sha256": candidate.get(
                            "candidate_record_content_sha256"
                        ),
                        "span_bundle_sha256": candidate.get("span_bundle_sha256"),
                        "rank": candidate.get("rank"),
                    }
                    resolved.append(
                        {
                            "authority_identity_id": authority_id,
                            "locator_hint": str(candidate.get("locator") or ""),
                            "canonical_locator": canonical_locator(
                                str(candidate.get("locator") or "")
                            ),
                            "resolution_status": (
                                "ROW_CANDIDATE_EXACT_CHUNK_FALLBACK_FOUND"
                                if exact_chunks
                                else "ROW_CANDIDATE_EXCEEDS_DETERMINISTIC_BOUND"
                            ),
                            "source_identity": source,
                            "candidate_source_metadata": candidate_metadata,
                            "exact_chunk_count": len(exact_chunks),
                            **candidate_budget,
                            "exact_chunks": exact_chunks,
                            "deterministic_fallback_only": True,
                        }
                    )
                    if not exact_chunks:
                        continue
                    fallback_used = True
                    remaining_characters -= candidate_budget[
                        "available_exact_chunk_text_characters"
                    ]
                    remaining_chunks -= candidate_budget["available_exact_chunk_count"]
                    if remaining_characters <= 0 or remaining_chunks <= 0:
                        break
            record_material = {
                "schema": "legalbot.v111.phase2a.locator-resolution-row.v1",
                "ordinal": ordinal,
                "row_id": row_id,
                "planner_assessment": plan.get("assessment"),
                "resolved_selections": resolved,
                "deterministic_candidate_span_fallback_used": fallback_used,
                "deterministic_candidate_span_fallback_reason": fallback_reason,
                "semantic_proposition_support_verified": False,
                "owner_outcome": None,
                "owner_decision_required": True,
                "technical_qualification_assigned": False,
                "source_admission_authorized": False,
                "candidate_mutated": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            }
            records.append({**record_material, "record_content_sha256": _sealed(record_material)})
    finally:
        connection.close()

    statuses = Counter(
        selection["resolution_status"]
        for record in records
        for selection in record["resolved_selections"]
    )
    artifact_material = {
        "schema": "legalbot.v111.phase2a.locator-resolution-448.v1",
        "status": "DETERMINISTIC_LOCATOR_RESOLUTION_COMPLETE_SEMANTIC_REVIEW_REQUIRED",
        "source_plans_content_sha256": plans_sha256,
        "source_plans_file_sha256": _sha256_file(plans_path),
        "source_original_content_sha256": candidate_hashes["original"],
        "source_deep_content_sha256": candidate_hashes["deep"],
        "resolver_code_file_sha256": _sha256_file(Path(__file__).resolve()),
        "catalogue_path_relative": str(catalogue_path.resolve().relative_to(PROJECT_ROOT)),
        "catalogue_file_sha256": catalogue_file_sha256,
        "target_ceiling_date": TARGET_CEILING_DATE.isoformat(),
        "planned_record_count": len(records),
        "held_row_count": len(held_row_ids),
        "held_row_ids": held_row_ids,
        "resolution_status_counts": dict(sorted(statuses.items())),
        "candidate_span_fallback_policy": {
            "trigger": "NO_EXACT_PLANNER_CHUNK_AND_NOT_NONMATERIAL",
            "maximum_candidates_per_row": MAX_FALLBACK_CANDIDATES,
            "maximum_exact_chunk_text_characters_per_row": (MAX_FALLBACK_TEXT_CHARACTERS),
            "maximum_exact_chunks_per_row": MAX_FALLBACK_EXACT_CHUNKS_PER_ROW,
            "row_specific_candidates_only": True,
            "catalogue_read_only": True,
            "complete_candidate_result_required": True,
            "silent_truncation": False,
            "over_bound_status": "ROW_CANDIDATE_EXCEEDS_DETERMINISTIC_BOUND",
            "semantic_support_assigned": False,
        },
        "planner_locator_bound_policy": {
            "complete_locator_result_required": True,
            "silent_truncation": False,
            "maximum_exact_chunks_per_selection": (MAX_PLANNER_EXACT_CHUNKS_PER_SELECTION),
            "maximum_exact_chunks_per_row": MAX_PLANNER_EXACT_CHUNKS_PER_ROW,
            "maximum_exact_chunk_text_characters_per_row": (MAX_PLANNER_TEXT_CHARACTERS_PER_ROW),
            "over_bound_status": ("LOCATOR_AMBIGUOUS_EXCEEDS_DETERMINISTIC_BOUND"),
            "semantic_support_assigned": False,
        },
        "candidate_span_fallback_row_count": sum(
            record["deterministic_candidate_span_fallback_used"] for record in records
        ),
        "records": records,
        "semantic_proposition_support_verified": False,
        "owner_decisions_applied": False,
        "technical_qualification_assigned": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    artifact = {
        **artifact_material,
        "artifact_content_sha256": _sealed(artifact_material),
    }
    name = "DETERMINISTIC-LOCATOR-RESOLUTION-448.json"
    _write_exclusive(output_root / name, _pretty_json(artifact))
    outcome = (
        f"LOCATOR RESOLUTION: {len(records)} PLANNED ROWS, {len(held_row_ids)} HELD. "
        "SEMANTIC PROPOSITION SUPPORT AND OWNER DECISIONS REMAIN REQUIRED. "
        "PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED.\n"
    )
    _write_exclusive(output_root / "OUTCOME.txt", outcome.encode())
    names = [name, "OUTCOME.txt"]
    sums = "".join(f"{_sha256_file(output_root / item)}  {item}\n" for item in names)
    _write_exclusive(output_root / "SHA256SUMS.txt", sums.encode())
    return artifact


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plans", type=Path, default=DEFAULT_PLANS)
    parser.add_argument("--original", type=Path, default=DEFAULT_ORIGINAL)
    parser.add_argument("--deep", type=Path, default=DEFAULT_DEEP)
    parser.add_argument("--catalogue", type=Path, default=DEFAULT_CATALOGUE)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> None:
    args = _arguments()
    result = resolve_plans(
        plans_path=args.plans,
        original_path=args.original,
        deep_path=args.deep,
        catalogue_path=args.catalogue,
        output_root=args.output_root,
    )
    print(
        json.dumps(
            {
                "output_root": str(args.output_root),
                "planned_record_count": result["planned_record_count"],
                "held_row_count": result["held_row_count"],
                "resolution_status_counts": result["resolution_status_counts"],
                "artifact_content_sha256": result["artifact_content_sha256"],
                "phase2b_authorized": result["phase2b_authorized"],
                "development30_authorized": result["development30_authorized"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
