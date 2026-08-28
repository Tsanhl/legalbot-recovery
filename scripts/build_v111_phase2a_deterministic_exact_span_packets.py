#!/usr/bin/env python3
"""Build the deterministic-only Phase-2A exact-span and source crosswalk packet.

This create-only pass replaces the stopped r114-r119 planner path.  It consumes
no planner output and invokes no model.  It independently rebinds every r98d
retrieval candidate to the exact sealed Lance build and to the current immutable
catalogue chunk, partitions source text without truncation, carries the three
already owner-approved r96 rows, and crosswalks the exact owner-approved
142-source packet by canonical authority identity and content SHA-256.

The output is evidence organisation only.  It cannot decide a proposition,
qualify a row, admit an unseen source, start a source scan, mutate/build a
candidate, or authorize Phase 2B or Development 30.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import stat
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
for root in (PROJECT_ROOT, BACKEND_ROOT):
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

from app.privacy import scrub_pii  # noqa: E402
from app.retrieval.source_manifest import approved_source_manifest_sha256  # noqa: E402

REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
DEFAULT_LEDGER = (
    REVIEW_ROOT
    / "LegalBot-Phase2A-2026-08-27-deterministic-only-work-ledger"
    / "DETERMINISTIC-WORK-LEDGER-364.json"
)
DEFAULT_RECOVERY = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-26-r98d-candidate-recovery"
    / "CANDIDATE-RECOVERY-361.json"
)
DEFAULT_READY = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-26-r96-approved-binding-reconciliation"
    / "TARGET-DATE-EVIDENCE-READY-ROWS-3.json"
)
DEFAULT_RETAINED = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-26-r96-approved-binding-reconciliation"
    / "RETAINED-DIRECT-OR-PARTIAL-GAPS-5.json"
)
DEFAULT_SOURCE_PACKET_ROOT = REVIEW_ROOT / "LegalBot-Phase2A-2026-08-27-seminar-source-owner-packet"
DEFAULT_SOURCE_RECEIPT = (
    REVIEW_ROOT
    / "LegalBot-Phase2A-2026-08-27-seminar-source-owner-approved"
    / "OWNER-APPROVAL-RECEIPT.json"
)
DEFAULT_PRIOR_ADMISSIONS = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-26-r113-post-r110-owner-approved"
    / "CUMULATIVE-APPROVED-SOURCE-ADMISSIONS-25.json"
)
DEFAULT_BUILD_ROOT = PROJECT_ROOT / "data/indexes/builds/current-law-ew-full-fp16-v111-20260818-a"
DEFAULT_CANDIDATE_MANIFEST = DEFAULT_BUILD_ROOT / "approved-source-manifest.json"
DEFAULT_CATALOGUE = PROJECT_ROOT / "data/catalog.sqlite3"
DEFAULT_OUTPUT_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2A-2026-08-27-deterministic-exact-span-crosswalk-r2"
)

EXPECTED_LEDGER_DIGEST = "17f240a5d415d731cff6c147a560d6ad224cecb811b56f1db4aad340fe93739d"
EXPECTED_RECOVERY_DIGEST = "ad1d23ce7feabbd8936eb083fe678be2028f4723b60ffb8b42228a220de02ebf"
EXPECTED_READY_DIGEST = "8c7bcebacb7a1c06cdcc9408a85fb97f48c0415f1c05265a97d49396f58b87f9"
EXPECTED_RETAINED_DIGEST = "5fa395cc3a9f52463eaec682dc3f61592fe8d00d23fd008022527eb957004fa3"
EXPECTED_SOURCE_BATCH_DIGEST = "6b2fc70e2c15e706bc26034aed7c6940b28b4220f66a7b0fbd28b97a0f53c8b6"
EXPECTED_SOURCE_RECEIPT_DIGEST = "878a1d2582a07c40dda7b5311aa22970885f78437e5f3d39109e667b9a6be7f9"
EXPECTED_SOURCE_EXCLUSIONS_DIGEST = (
    "ef886654959ba6bcb3154f396ae76cd2f6c52a776afa289ffaa34233bcf1fb27"
)
EXPECTED_PRIOR_ADMISSIONS_DIGEST = (
    "667fa9cb36188740fa28b0d4e0970ec71c82dcb123505f07584ea678bae9c32d"
)
EXPECTED_CANDIDATE_MANIFEST_DIGEST = (
    "d2c1434fd5fc44d4f2f7e4f7629293f646bb28ed9b8466687feb6c470ea53ac0"
)
EXPECTED_LANCE_TREE_DIGEST = "992f7c11184afc7667abedc6dca07a0b690bbcb34b0c9071cb7f5faa4d12e705"
EXPECTED_BUILD_MANIFEST_FILE_DIGEST = (
    "e28a4138e87cfeb2502e746073208ab25a647de8082a3c7fe96a44ed7d5cc74a"
)
EXPECTED_LEDGER_ROWS = 364
EXPECTED_RECOVERY_ROWS = 361
EXPECTED_READY_ROWS = 3
EXPECTED_APPROVED_SOURCES = 142
EXPECTED_CANDIDATE_SOURCES = 85
EXPECTED_CANDIDATE_CHUNKS = 149_855
MAX_SPAN_CHARACTERS = 700
LANCE_QUERY_BATCH = 80
SQLITE_QUERY_BATCH = 500

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"[a-z0-9]+(?:['’-][a-z0-9]+)?", re.IGNORECASE)
_LEGISLATION_VERSION = re.compile(
    r":(?:latest-available@[0-9]{4}-[0-9]{2}-[0-9]{2}|enacted)$",
    re.IGNORECASE,
)
_LEGACY_PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d[\d\s().-]{7,}\d)(?!\w)")
_STOPWORDS = frozenset(
    {
        "and",
        "are",
        "for",
        "from",
        "into",
        "law",
        "legal",
        "of",
        "or",
        "the",
        "to",
        "under",
        "with",
    }
)


def _canonical_json(value: Any, *, newline: bool = True) -> bytes:
    raw = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return (raw + ("\n" if newline else "")).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(value: Any, *, newline: bool = True) -> str:
    return _sha256(_canonical_json(value, newline=newline))


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_deterministic_span_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_deterministic_span_input_must_be_object")
    return value


def _verify_seal(
    value: Mapping[str, Any],
    field: str,
    code: str,
    *,
    expected: str | None = None,
    newline: bool = True,
) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if (
        not _SHA256.fullmatch(supplied)
        or supplied != _sealed(material, newline=newline)
        or (expected is not None and supplied != expected)
    ):
        raise ValueError(code)
    return supplied


def _sealed_artifact(
    schema: str,
    material: Mapping[str, Any],
    *,
    digest_field: str = "artifact_content_sha256",
) -> dict[str, Any]:
    payload = {"schema": schema, **dict(material)}
    return {**payload, digest_field: _sealed(payload)}


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _tree_sha256(root: Path) -> str:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("phase2a_deterministic_span_lance_tree_missing")
    members = sorted(
        (item for item in root.rglob("*") if item.is_file()),
        key=lambda item: item.as_posix(),
    )
    if not members or any(item.is_symlink() for item in root.rglob("*")):
        raise ValueError("phase2a_deterministic_span_lance_tree_unsafe")
    digest = hashlib.sha256()
    for member in members:
        relative = member.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(bytes.fromhex(_sha256_file(member)))
    return digest.hexdigest()


def _canonical_authority_id(value: str) -> str:
    identity = " ".join(str(value or "").strip().split())
    if not identity:
        return ""
    if identity.startswith("["):
        identity = f"neutral-citation:{identity}"
    if identity.casefold().startswith("judgment:"):
        identity = f"neutral-citation:{identity.split(':', 1)[1]}"
    if identity.startswith(("http://", "https://")):
        match = re.search(r"/(ukpga|uksi)/([^/]+)/([^/?#]+)", identity, re.I)
        if match:
            identity = ":".join(match.groups())
    identity = _LEGISLATION_VERSION.sub("", identity)
    if identity.casefold().startswith(("ukpga:", "uksi:")):
        return identity.casefold()
    if identity.casefold().startswith("neutral-citation:"):
        citation = identity.split(":", 1)[1]
        return f"neutral-citation:{' '.join(citation.split())}"
    return identity


def _authority_key(value: str) -> str:
    return _canonical_authority_id(value).casefold()


def _meaningful_tokens(value: str) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                token.casefold().replace("’", "'")
                for token in _TOKEN.findall(value)
                if len(token) >= 3 and token.casefold() not in _STOPWORDS
            }
        )
    )


def _locator_references(value: str) -> set[tuple[str, str]]:
    text = " ".join(str(value or "").casefold().split())
    references: set[tuple[str, str]] = set()
    patterns = (
        ("section", r"\b(?:section|s)\s*([0-9]+[a-z]?(?:\([0-9a-z]+\))*)"),
        ("paragraph", r"\b(?:paragraph|para|p)\s*([0-9]+[a-z]?)\b"),
        ("paragraph", r"\[([0-9]+[a-z]?)\]"),
        ("rule", r"\brule\s*([0-9]+(?:\.[0-9]+)*)"),
        ("regulation", r"\b(?:regulation|reg)\s*([0-9]+[a-z]?)"),
        ("schedule", r"\bschedule\s*([0-9]+[a-z]?)"),
        ("article", r"\barticle\s*([0-9]+[a-z]?)"),
    )
    for kind, pattern in patterns:
        references.update((kind, match) for match in re.findall(pattern, text))
    return references


def _locator_match(candidate: str, hints: Sequence[str]) -> str:
    candidate_refs = _locator_references(candidate)
    hint_refs = set().union(*(_locator_references(hint) for hint in hints)) if hints else set()
    if candidate_refs and candidate_refs & hint_refs:
        return "EXACT_CANONICAL_LOCATOR_REFERENCE"
    candidate_normalized = " ".join(_TOKEN.findall(candidate.casefold()))
    for hint in hints:
        hint_normalized = " ".join(_TOKEN.findall(hint.casefold()))
        if candidate_normalized and candidate_normalized == hint_normalized:
            return "EXACT_NORMALIZED_LOCATOR_TEXT"
    return "NO_EXACT_LOCATOR_MATCH"


def _partition_exact_text(*, chunk_id: str, text: str, text_sha256: str) -> dict[str, Any]:
    if not chunk_id or not text or _sha256(text.encode("utf-8")) != text_sha256:
        raise ValueError("phase2a_deterministic_span_source_text_invalid")
    offsets: list[tuple[int, int]] = []
    start = 0
    while start < len(text):
        hard_end = min(start + MAX_SPAN_CHARACTERS, len(text))
        if hard_end == len(text):
            end = hard_end
        else:
            window = text[start:hard_end]
            sentence_boundaries = [
                start + match.end()
                for match in re.finditer(r"(?<=[.!?])(?:[ \t]+|\r?\n+)", window)
                if match.end() >= 80
            ]
            if sentence_boundaries:
                end = sentence_boundaries[-1]
            else:
                whitespace = max(window.rfind(" "), window.rfind("\n"), window.rfind("\t"))
                end = start + whitespace + 1 if whitespace >= 80 else hard_end
        if end <= start or end - start > MAX_SPAN_CHARACTERS:
            raise ValueError("phase2a_deterministic_span_partition_boundary_invalid")
        offsets.append((start, end))
        start = end

    spans: list[dict[str, Any]] = []
    for ordinal, (start, end) in enumerate(offsets, start=1):
        exact_text = text[start:end]
        identity = {
            "schema": "legalbot.v111.phase2a.deterministic-span-identity.v1",
            "chunk_id": chunk_id,
            "ordinal": ordinal,
            "start_character": start,
            "end_character_exclusive": end,
            "exact_text_sha256": _sha256(exact_text.encode("utf-8")),
        }
        material = {
            **identity,
            "span_id": f"span-{_sealed(identity)[:24]}",
            "exact_text": exact_text,
        }
        spans.append({**material, "span_content_sha256": _sealed(material)})
    partition_identity = [
        {
            "span_id": span["span_id"],
            "start_character": span["start_character"],
            "end_character_exclusive": span["end_character_exclusive"],
            "exact_text_sha256": span["exact_text_sha256"],
        }
        for span in spans
    ]
    return {
        "exact_span_options": spans,
        "exact_span_option_count": len(spans),
        "exact_span_partition_complete": True,
        "exact_span_partition_content_sha256": _sealed(partition_identity),
        "source_text_reproduced_by_partition_sha256": _sha256(
            "".join(span["exact_text"] for span in spans).encode("utf-8")
        ),
        "silent_text_truncation": False,
    }


def _load_ledger(path: Path) -> tuple[dict[str, dict[str, Any]], str]:
    value = _load_object(path)
    digest = _verify_seal(
        value,
        "artifact_content_sha256",
        "phase2a_deterministic_span_ledger_seal_invalid",
        expected=EXPECTED_LEDGER_DIGEST,
    )
    rows = value.get("rows")
    if (
        value.get("schema") != "legalbot.v111.phase2a.deterministic-only-work-ledger-364.v1"
        or value.get("row_count") != EXPECTED_LEDGER_ROWS
        or value.get("planner_output_consumed_row_count") != 0
        or value.get("source_scan_started") is not False
        or value.get("candidate_mutated") is not False
        or value.get("phase2b_authorized") is not False
        or value.get("development30_authorized") is not False
        or not isinstance(rows, list)
        or len(rows) != EXPECTED_LEDGER_ROWS
    ):
        raise ValueError("phase2a_deterministic_span_ledger_boundary_invalid")
    by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("phase2a_deterministic_span_ledger_row_invalid")
        _verify_seal(
            row,
            "record_content_sha256",
            "phase2a_deterministic_span_ledger_row_seal_invalid",
        )
        row_id = str(row.get("row_id") or "")
        if not row_id or row_id in by_id or row.get("planner_output_consumed") is not False:
            raise ValueError("phase2a_deterministic_span_ledger_row_invalid")
        by_id[row_id] = dict(row)
    return by_id, digest


def _load_recovery(path: Path) -> tuple[dict[str, dict[str, Any]], str]:
    value = _load_object(path)
    digest = _verify_seal(
        value,
        "artifact_content_sha256",
        "phase2a_deterministic_span_recovery_seal_invalid",
        expected=EXPECTED_RECOVERY_DIGEST,
    )
    rows = value.get("rows")
    if (
        value.get("row_count") != EXPECTED_RECOVERY_ROWS
        or value.get("candidate_manifest_sha256") != EXPECTED_CANDIDATE_MANIFEST_DIGEST
        or value.get("advisory_planner_required") is not False
        or value.get("answer_model_invoked") is not False
        or value.get("owner_decisions_applied") is not False
        or value.get("candidate_mutated") is not False
        or value.get("phase2b_authorized") is not False
        or value.get("development30_authorized") is not False
        or not isinstance(rows, list)
        or len(rows) != EXPECTED_RECOVERY_ROWS
    ):
        raise ValueError("phase2a_deterministic_span_recovery_boundary_invalid")
    by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("phase2a_deterministic_span_recovery_row_invalid")
        _verify_seal(
            row,
            "checkpoint_content_sha256",
            "phase2a_deterministic_span_recovery_row_seal_invalid",
        )
        row_id = str(row.get("row_id") or "")
        candidates = row.get("candidates")
        if (
            not row_id
            or row_id in by_id
            or row.get("status") != "EXACT_CANDIDATE_CHUNKS_READY_FOR_SPAN_VERIFICATION"
            or not isinstance(candidates, list)
            or not candidates
            or row.get("owner_decision_required") is not True
            or row.get("technical_qualification_assigned") is not False
        ):
            raise ValueError("phase2a_deterministic_span_recovery_row_invalid")
        for expected_rank, candidate in enumerate(candidates, start=1):
            if not isinstance(candidate, dict):
                raise ValueError("phase2a_deterministic_span_candidate_invalid")
            _verify_seal(
                candidate,
                "candidate_content_sha256",
                "phase2a_deterministic_span_candidate_seal_invalid",
            )
            text = str(candidate.get("text") or "")
            if (
                candidate.get("rank") != expected_rank
                or candidate.get("already_in_exact_sealed_candidate") is not True
                or candidate.get("candidate_manifest_source_bound") is not True
                or candidate.get("content_sha256") != _sha256(text.encode("utf-8"))
            ):
                raise ValueError("phase2a_deterministic_span_candidate_invalid")
        by_id[row_id] = dict(row)
    return by_id, digest


def _load_ready(path: Path) -> tuple[dict[str, dict[str, Any]], str]:
    value = _load_object(path)
    digest = _verify_seal(
        value,
        "artifact_content_sha256",
        "phase2a_deterministic_span_ready_seal_invalid",
        expected=EXPECTED_READY_DIGEST,
    )
    records = value.get("records")
    if (
        value.get("record_count") != EXPECTED_READY_ROWS
        or value.get("owner_decisions_applied") is not True
        or value.get("technical_qualification_assigned") is not False
        or value.get("candidate_mutated") is not False
        or value.get("phase2b_authorized") is not False
        or value.get("development30_authorized") is not False
        or not isinstance(records, list)
        or len(records) != EXPECTED_READY_ROWS
    ):
        raise ValueError("phase2a_deterministic_span_ready_boundary_invalid")
    by_id = {str(record.get("row_id") or ""): dict(record) for record in records}
    if "" in by_id or len(by_id) != EXPECTED_READY_ROWS:
        raise ValueError("phase2a_deterministic_span_ready_rows_invalid")
    return by_id, digest


def _load_retained(path: Path) -> tuple[dict[str, dict[str, Any]], str]:
    value = _load_object(path)
    digest = _verify_seal(
        value,
        "artifact_content_sha256",
        "phase2a_deterministic_span_retained_seal_invalid",
        expected=EXPECTED_RETAINED_DIGEST,
    )
    records = value.get("records")
    if (
        value.get("schema") != "legalbot.v111.phase2a.post-r94-retained-binding-gaps.v1"
        or value.get("record_count") != 5
        or value.get("owner_decisions_applied") is not True
        or value.get("technical_qualification_assigned") is not False
        or value.get("candidate_mutated") is not False
        or value.get("phase2b_authorized") is not False
        or value.get("development30_authorized") is not False
        or not isinstance(records, list)
        or len(records) != 5
    ):
        raise ValueError("phase2a_deterministic_span_retained_boundary_invalid")
    by_id = {str(record.get("row_id") or ""): dict(record) for record in records}
    if "" in by_id or len(by_id) != 5:
        raise ValueError("phase2a_deterministic_span_retained_rows_invalid")
    return by_id, digest


def _load_candidate_manifest(
    path: Path,
) -> tuple[dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]], str]:
    value = _load_object(path)
    digest = approved_source_manifest_sha256(value)
    sources = value.get("sources")
    if (
        digest != EXPECTED_CANDIDATE_MANIFEST_DIGEST
        or value.get("manifest_sha256") != digest
        or value.get("source_count") != EXPECTED_CANDIDATE_SOURCES
        or value.get("chunk_count") != EXPECTED_CANDIDATE_CHUNKS
        or not isinstance(sources, list)
        or len(sources) != EXPECTED_CANDIDATE_SOURCES
    ):
        raise ValueError("phase2a_deterministic_span_candidate_manifest_invalid")
    by_version: dict[str, dict[str, Any]] = {}
    by_authority: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for source in sources:
        if not isinstance(source, dict):
            raise ValueError("phase2a_deterministic_span_candidate_source_invalid")
        source_version_id = str(source.get("source_version_id") or "")
        authority = str(source.get("authority_identity_id") or "")
        if (
            not source_version_id
            or source_version_id in by_version
            or not authority
            or source.get("lane") != "primary_authority"
            or source.get("document_status") != "citable"
            or source.get("identity_verified") is not True
        ):
            raise ValueError("phase2a_deterministic_span_candidate_source_invalid")
        copied = dict(source)
        by_version[source_version_id] = copied
        by_authority[_authority_key(authority)].append(copied)
    return by_version, by_authority, digest


def _verify_build(build_root: Path) -> dict[str, Any]:
    manifest_path = build_root / "manifest.json"
    seal = _load_object(build_root / "seal.json")
    manifest = _load_object(manifest_path)
    lance_root = build_root / "lance"
    tree_digest = _tree_sha256(lance_root)
    if (
        _sha256_file(manifest_path) != EXPECTED_BUILD_MANIFEST_FILE_DIGEST
        or manifest.get("sealed") is not True
        or manifest.get("chunk_count") != EXPECTED_CANDIDATE_CHUNKS
        or manifest.get("source_manifest_sha256") != EXPECTED_CANDIDATE_MANIFEST_DIGEST
        or seal.get("manifest_sha256") != EXPECTED_BUILD_MANIFEST_FILE_DIGEST
        or seal.get("lance_tree_sha256") != EXPECTED_LANCE_TREE_DIGEST
        or tree_digest != EXPECTED_LANCE_TREE_DIGEST
        or seal.get("promotion") != "not_requested"
    ):
        raise ValueError("phase2a_deterministic_span_candidate_build_invalid")
    return {
        "build_id": manifest["build_id"],
        "build_manifest_file_sha256": EXPECTED_BUILD_MANIFEST_FILE_DIGEST,
        "lance_tree_sha256": tree_digest,
        "candidate_manifest_sha256": EXPECTED_CANDIDATE_MANIFEST_DIGEST,
        "sealed": True,
        "promotion": "not_requested",
    }


def _chunks(values: Sequence[str], size: int) -> Iterable[Sequence[str]]:
    for start in range(0, len(values), size):
        yield values[start : start + size]


def _sql_placeholders(values: Sequence[str]) -> str:
    return ",".join("?" for _ in values)


def _load_catalogue_chunks(
    catalogue_path: Path, chunk_ids: Sequence[str]
) -> tuple[dict[str, dict[str, Any]], str]:
    if catalogue_path.is_symlink() or not catalogue_path.is_file():
        raise ValueError("phase2a_deterministic_span_catalogue_invalid")
    connection = sqlite3.connect(
        f"file:{catalogue_path.resolve()}?mode=ro&immutable=1",
        uri=True,
    )
    connection.row_factory = sqlite3.Row
    try:
        active = connection.execute(
            "SELECT id FROM source_scans WHERE status IN ('queued','running') LIMIT 1"
        ).fetchone()
        if active is not None:
            raise ValueError("phase2a_deterministic_span_active_source_scan_forbidden")
        by_id: dict[str, dict[str, Any]] = {}
        for batch in _chunks(list(chunk_ids), SQLITE_QUERY_BATCH):
            rows = connection.execute(
                f"""
                SELECT c.id AS chunk_id,
                       c.source_version_id,
                       c.locator,
                       c.heading_path,
                       c.text_sha256,
                       c.markdown_text,
                       sv.version_sha256,
                       sv.authority_identity_id,
                       sv.stable_identifier,
                       sv.review_status,
                       d.status AS document_status,
                       d.lane,
                       d.retrieval_canonical
                  FROM chunks c
                  JOIN source_versions sv ON sv.id=c.source_version_id
                  JOIN documents d ON d.id=sv.document_id
                 WHERE c.id IN ({_sql_placeholders(batch)})
                """,
                tuple(batch),
            ).fetchall()
            for row in rows:
                chunk_id = str(row["chunk_id"])
                if chunk_id in by_id:
                    raise ValueError("phase2a_deterministic_span_catalogue_chunk_duplicate")
                by_id[chunk_id] = dict(row)
    finally:
        connection.close()
    if set(by_id) != set(chunk_ids):
        raise ValueError("phase2a_deterministic_span_catalogue_chunk_missing")
    return by_id, _sha256_file(catalogue_path)


def _load_lance_chunks(build_root: Path, chunk_ids: Sequence[str]) -> dict[str, dict[str, Any]]:
    import lancedb

    database = lancedb.connect(str(build_root / "lance/authority"))
    if database.table_names() != ["chunks"]:
        raise ValueError("phase2a_deterministic_span_lance_table_invalid")
    table = database.open_table("chunks")
    if table.count_rows() != EXPECTED_CANDIDATE_CHUNKS:
        raise ValueError("phase2a_deterministic_span_lance_row_count_invalid")
    columns = [
        "chunk_id",
        "source_version_id",
        "source_identity",
        "text",
        "content_sha256",
        "locator",
    ]
    by_id: dict[str, dict[str, Any]] = {}
    for batch in _chunks(list(chunk_ids), LANCE_QUERY_BATCH):
        expression = (
            "chunk_id IN ("
            + ",".join(f"'{value.replace(chr(39), chr(39) * 2)}'" for value in batch)
            + ")"
        )
        rows = table.search().where(expression).select(columns).limit(len(batch) + 1).to_list()
        for row in rows:
            chunk_id = str(row.get("chunk_id") or "")
            if not chunk_id or chunk_id in by_id:
                raise ValueError("phase2a_deterministic_span_lance_chunk_duplicate")
            by_id[chunk_id] = dict(row)
    if set(by_id) != set(chunk_ids):
        raise ValueError("phase2a_deterministic_span_lance_chunk_missing")
    return by_id


def _candidate_source_material(candidate: Mapping[str, Any]) -> dict[str, Any]:
    fields = (
        "chunk_id",
        "source_version_id",
        "source_identity",
        "authority_identity_id",
        "title",
        "canonical_url",
        "citation",
        "canonical_citation",
        "locator",
        "text",
        "content_sha256",
        "source_version_sha256",
        "source_date",
        "as_of_date",
        "currentness_status",
        "currentness_verified",
        "legal_role",
    )
    return {field: candidate.get(field) for field in fields}


def _legacy_phone_projection(value: str) -> str:
    return _LEGACY_PHONE_RE.sub("[PHONE]", value)


def _build_source_corpus(
    *,
    recovery: Mapping[str, Mapping[str, Any]],
    candidate_sources: Mapping[str, Mapping[str, Any]],
    catalogue_chunks: Mapping[str, Mapping[str, Any]],
    lance_chunks: Mapping[str, Mapping[str, Any]],
    catalogue_file_sha256: str,
    build_identity: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], dict[str, int]]:
    candidates_by_chunk: dict[str, dict[str, Any]] = {}
    reference_counts: Counter[str] = Counter()
    for row in recovery.values():
        for candidate in row["candidates"]:
            chunk_id = str(candidate["chunk_id"])
            source_material = _candidate_source_material(candidate)
            prior = candidates_by_chunk.get(chunk_id)
            if prior is not None and prior != source_material:
                raise ValueError("phase2a_deterministic_span_candidate_chunk_conflict")
            candidates_by_chunk[chunk_id] = source_material
            reference_counts[chunk_id] += 1

    records: list[dict[str, Any]] = []
    projection_counts: Counter[str] = Counter()
    projection_reference_counts: Counter[str] = Counter()
    for chunk_id in sorted(candidates_by_chunk):
        candidate = candidates_by_chunk[chunk_id]
        catalogue = catalogue_chunks[chunk_id]
        lance = lance_chunks[chunk_id]
        source_version_id = str(candidate["source_version_id"])
        source = candidate_sources.get(source_version_id)
        if source is None:
            raise ValueError("phase2a_deterministic_span_source_version_not_manifest_bound")
        candidate_text = str(candidate["text"])
        catalogue_text = str(catalogue["markdown_text"])
        if (
            lance.get("source_version_id") != source_version_id
            or lance.get("source_identity") != candidate.get("source_identity")
            or lance.get("text") != candidate_text
            or lance.get("content_sha256") != candidate.get("content_sha256")
            or lance.get("locator") != candidate.get("locator")
            or _sha256(candidate_text.encode("utf-8")) != candidate.get("content_sha256")
            or catalogue.get("source_version_id") != source_version_id
            or catalogue.get("locator") != candidate.get("locator")
            or catalogue.get("version_sha256") != source.get("version_sha256")
            or catalogue.get("authority_identity_id") != source.get("authority_identity_id")
            or catalogue.get("review_status") != "approved"
            or catalogue.get("document_status") != "citable"
            or catalogue.get("lane") != "primary_authority"
            or int(catalogue.get("retrieval_canonical") or 0) != 1
        ):
            raise ValueError("phase2a_deterministic_span_candidate_binding_invalid")
        catalogue_sha256 = _sha256(catalogue_text.encode("utf-8"))
        if catalogue.get("text_sha256") != catalogue_sha256:
            raise ValueError("phase2a_deterministic_span_catalogue_text_hash_invalid")

        if catalogue_text == candidate_text:
            projection_status = "EXACT_CATALOGUE_AND_SEALED_LANCE_TEXT_MATCH"
            review_text = catalogue_text
            exact_source_evidence_eligible = True
            successor_rebuild_required = False
        elif (
            _legacy_phone_projection(catalogue_text) == candidate_text
            and scrub_pii(catalogue_text) == catalogue_text
        ):
            projection_status = "LEGACY_FALSE_PHONE_REDACTION_FIXED_FOR_SUCCESSOR_REBUILD"
            review_text = catalogue_text
            exact_source_evidence_eligible = True
            successor_rebuild_required = True
        else:
            raise ValueError("phase2a_deterministic_span_unexpected_projection_difference")

        review_text_sha256 = _sha256(review_text.encode("utf-8"))
        partition = _partition_exact_text(
            chunk_id=chunk_id,
            text=review_text,
            text_sha256=review_text_sha256,
        )
        material = {
            "schema": "legalbot.v111.phase2a.deterministic-span-source-chunk.v1",
            "chunk_id": chunk_id,
            "source_version_id": source_version_id,
            "authority_identity_id": source["authority_identity_id"],
            "stable_identifier": source["stable_identifier"],
            "title": source["title"],
            "canonical_url": source["canonical_url"],
            "locator": str(catalogue["locator"]),
            "heading_path": str(catalogue.get("heading_path") or ""),
            "candidate_reference_count": reference_counts[chunk_id],
            "sealed_lance_text_sha256": candidate["content_sha256"],
            "catalogue_source_text_sha256": catalogue_sha256,
            "review_exact_text_sha256": review_text_sha256,
            "projection_status": projection_status,
            "exact_source_evidence_eligible": exact_source_evidence_eligible,
            "successor_rebuild_required": successor_rebuild_required,
            "currentness_status": candidate.get("currentness_status"),
            "currentness_verified": candidate.get("currentness_verified"),
            "technical_qualification_assigned": False,
            **partition,
        }
        records.append({**material, "record_content_sha256": _sealed(material)})
        projection_counts[projection_status] += 1
        projection_reference_counts[projection_status] += reference_counts[chunk_id]

    artifact = _sealed_artifact(
        "legalbot.v111.phase2a.deterministic-span-source-corpus.v1",
        {
            "status": "EXACT_SOURCE_TEXT_PARTITIONED_NO_SUBSTANTIVE_DECISION",
            "source_recovery_content_sha256": EXPECTED_RECOVERY_DIGEST,
            "candidate_build_identity": dict(build_identity),
            "catalogue_file_sha256": catalogue_file_sha256,
            "chunk_count": len(records),
            "candidate_reference_count": sum(reference_counts.values()),
            "projection_status_counts": dict(sorted(projection_counts.items())),
            "projection_reference_status_counts": dict(sorted(projection_reference_counts.items())),
            "records": records,
            "planner_or_answer_model_invoked": False,
            "source_scan_started": False,
            "automatic_indexing": False,
            "automatic_embedding": False,
            "candidate_mutated": False,
            "technical_qualification_assigned": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        },
    )
    return artifact, {record["chunk_id"]: record for record in records}, dict(reference_counts)


def _row_packet(
    *,
    ledger: Mapping[str, Any],
    recovery: Mapping[str, Any],
    source_corpus: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    issue_terms = _meaningful_tokens(str(ledger["issue_label"]))
    planned_keys = {
        _authority_key(value) for value in ledger.get("effective_planned_authority_ids") or []
    }
    hints_by_authority: dict[str, list[str]] = defaultdict(list)
    for hint in ledger.get("deterministic_locator_hints") or []:
        hints_by_authority[_authority_key(hint["authority_identity_id"])].append(
            str(hint["locator_hint"])
        )

    candidates: list[dict[str, Any]] = []
    for candidate in recovery["candidates"]:
        chunk_id = str(candidate["chunk_id"])
        source = source_corpus[chunk_id]
        authority_key = _authority_key(str(candidate["authority_identity_id"]))
        planned = authority_key in planned_keys
        hints = sorted(set(hints_by_authority.get(authority_key, [])))
        locator_match = _locator_match(str(candidate.get("locator") or ""), hints)
        source_tokens = set(
            _meaningful_tokens(
                " ".join(span["exact_text"] for span in source["exact_span_options"])
            )
        )
        issue_term_hits = sorted(set(issue_terms) & source_tokens)
        candidates.append(
            {
                "candidate_rank": candidate["rank"],
                "chunk_id": chunk_id,
                "source_chunk_record_content_sha256": source["record_content_sha256"],
                "authority_identity_id": candidate["authority_identity_id"],
                "source_version_id": candidate["source_version_id"],
                "locator": candidate["locator"],
                "planned_authority_match": planned,
                "locator_hints": hints,
                "locator_match": locator_match,
                "issue_term_hits": issue_term_hits,
                "currentness_verified": candidate.get("currentness_verified") is True,
                "privacy_projection_status": source["projection_status"],
                "exact_source_evidence_eligible": source["exact_source_evidence_eligible"],
                "retrieval_scores_advisory_only": {
                    "rrf_score": candidate.get("rrf_score"),
                    "reranker_score": candidate.get("reranker_score"),
                    "threshold_applied": False,
                },
                "support_status": "NOT_SUBSTANTIVELY_ASSESSED",
            }
        )

    ordered = sorted(
        candidates,
        key=lambda item: (
            item["locator_match"] == "NO_EXACT_LOCATOR_MATCH",
            not item["planned_authority_match"],
            -len(item["issue_term_hits"]),
            not item["currentness_verified"],
            item["candidate_rank"],
            item["chunk_id"],
        ),
    )
    order = {item["chunk_id"]: index for index, item in enumerate(ordered, start=1)}
    for candidate in candidates:
        candidate["deterministic_owner_review_order"] = order[candidate["chunk_id"]]

    exact_locator = any(
        item["planned_authority_match"] and item["locator_match"] != "NO_EXACT_LOCATOR_MATCH"
        for item in candidates
    )
    planned_and_terms = any(
        item["planned_authority_match"] and item["issue_term_hits"] for item in candidates
    )
    planned = any(item["planned_authority_match"] for item in candidates)
    terms = any(item["issue_term_hits"] for item in candidates)
    if exact_locator:
        status = "EXACT_LOCATOR_AND_PLANNED_AUTHORITY_PACKET_READY"
    elif planned_and_terms:
        status = "PLANNED_AUTHORITY_AND_ISSUE_TERM_PACKET_READY"
    elif planned:
        status = "PLANNED_AUTHORITY_PACKET_READY_OWNER_SPAN_SELECTION_REQUIRED"
    elif terms:
        status = "CANDIDATE_ISSUE_TERM_PACKET_READY_OWNER_AUTHORITY_REVIEW_REQUIRED"
    else:
        status = "NO_DETERMINISTIC_EXACT_SPAN_MATCH_OWNER_RESEARCH_REQUIRED"
    material = {
        "schema": "legalbot.v111.phase2a.deterministic-exact-span-row.v1",
        "row_id": ledger["row_id"],
        "case_id": ledger["case_id"],
        "issue_label": ledger["issue_label"],
        "legal_domain": ledger["legal_domain"],
        "status": status,
        "issue_terms": list(issue_terms),
        "deterministic_work_class": ledger["deterministic_work_class"],
        "effective_planned_authority_ids": ledger["effective_planned_authority_ids"],
        "effective_outside_candidate_authority_ids": ledger[
            "effective_outside_candidate_authority_ids"
        ],
        "candidate_count": len(candidates),
        "candidate_evidence_packets": candidates,
        "atomic_proposition": None,
        "selected_exact_span_id": None,
        "owner_decision_required": True,
        "planner_output_consumed": False,
        "technical_qualification_assigned": False,
    }
    return {**material, "record_content_sha256": _sealed(material)}


def _build_row_packets(
    *,
    ledger: Mapping[str, Mapping[str, Any]],
    recovery: Mapping[str, Mapping[str, Any]],
    ready: Mapping[str, Mapping[str, Any]],
    source_corpus: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    if set(ledger) != set(recovery) | set(ready) or set(recovery) & set(ready):
        raise ValueError("phase2a_deterministic_span_row_coverage_invalid")
    rows: list[dict[str, Any]] = []
    status_counts: Counter[str] = Counter()
    for row_id in sorted(ledger):
        if row_id in ready:
            material = {
                "schema": "legalbot.v111.phase2a.deterministic-exact-span-row.v1",
                "row_id": row_id,
                "case_id": ledger[row_id]["case_id"],
                "issue_label": ledger[row_id]["issue_label"],
                "legal_domain": ledger[row_id]["legal_domain"],
                "status": "OWNER_APPROVED_EXACT_BINDINGS_READY_FOR_FINAL_QUALIFICATION",
                "owner_approved_r96_record": ready[row_id],
                "atomic_proposition": "PRESERVED_IN_OWNER_APPROVED_R96_BINDINGS",
                "selected_exact_span_id": "PRESERVED_IN_OWNER_APPROVED_R96_BINDINGS",
                "owner_decision_required": False,
                "planner_output_consumed": False,
                "technical_qualification_assigned": False,
            }
            row = {**material, "record_content_sha256": _sealed(material)}
        else:
            row = _row_packet(
                ledger=ledger[row_id],
                recovery=recovery[row_id],
                source_corpus=source_corpus,
            )
        rows.append(row)
        status_counts[str(row["status"])] += 1
    return _sealed_artifact(
        "legalbot.v111.phase2a.deterministic-exact-span-packets-364.v1",
        {
            "status": "DETERMINISTIC_EXACT_SPAN_OPTIONS_READY_OWNER_DECISIONS_REMAIN",
            "source_ledger_content_sha256": EXPECTED_LEDGER_DIGEST,
            "source_recovery_content_sha256": EXPECTED_RECOVERY_DIGEST,
            "source_owner_approved_ready_content_sha256": EXPECTED_READY_DIGEST,
            "row_count": len(rows),
            "owner_decision_required_row_count": sum(
                row["owner_decision_required"] is True for row in rows
            ),
            "owner_approved_ready_row_count": sum(
                row["owner_decision_required"] is False for row in rows
            ),
            "status_counts": dict(sorted(status_counts.items())),
            "rows": rows,
            "planner_or_answer_model_invoked": False,
            "new_substantive_owner_decisions_created": False,
            "new_source_admissions_created": False,
            "source_scan_started": False,
            "automatic_indexing": False,
            "automatic_embedding": False,
            "candidate_mutated": False,
            "technical_qualification_assigned": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        },
    )


def _load_source_approval(
    *, packet_root: Path, receipt_path: Path
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    receipt = _load_object(receipt_path)
    _verify_seal(
        receipt,
        "approval_receipt_content_sha256",
        "phase2a_deterministic_span_source_receipt_invalid",
        expected=EXPECTED_SOURCE_RECEIPT_DIGEST,
        newline=False,
    )
    batch = _load_object(packet_root / "SEMINAR-SOURCE-OWNER-DECISION-BATCH.json")
    _verify_seal(
        batch,
        "owner_decision_batch_content_sha256",
        "phase2a_deterministic_span_source_batch_invalid",
        expected=EXPECTED_SOURCE_BATCH_DIGEST,
        newline=False,
    )
    exclusions = _load_object(packet_root / "EXCLUDED-SOURCES.json")
    _verify_seal(
        exclusions,
        "artifact_content_sha256",
        "phase2a_deterministic_span_source_exclusions_invalid",
        expected=EXPECTED_SOURCE_EXCLUSIONS_DIGEST,
        newline=False,
    )
    records = batch.get("records")
    if (
        receipt.get("source_admission_authorized") is not True
        or receipt.get("source_authority_count") != EXPECTED_APPROVED_SOURCES
        or receipt.get("owner_decision_batch_content_sha256") != EXPECTED_SOURCE_BATCH_DIGEST
        or receipt.get("currentness_and_later_treatment_holds_retained") is not True
        or receipt.get("exclusions_retained") is not True
        or receipt.get("source_scan_started") is not False
        or receipt.get("candidate_build_started") is not False
        or receipt.get("phase2b_authorized") is not False
        or receipt.get("development30_authorized") is not False
        or not isinstance(records, list)
        or len(records) != EXPECTED_APPROVED_SOURCES
    ):
        raise ValueError("phase2a_deterministic_span_source_approval_boundary_invalid")
    copied: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("phase2a_deterministic_span_source_record_invalid")
        _verify_seal(
            record,
            "record_content_sha256",
            "phase2a_deterministic_span_source_record_seal_invalid",
            newline=False,
        )
        copied.append(dict(record))
    return copied, receipt, exclusions


def _load_prior_admissions(path: Path) -> tuple[set[str], str]:
    value = _load_object(path)
    digest = _verify_seal(
        value,
        "artifact_content_sha256",
        "phase2a_deterministic_span_prior_admissions_invalid",
        expected=EXPECTED_PRIOR_ADMISSIONS_DIGEST,
    )
    records = value.get("records")
    if (
        value.get("record_count") != 25
        or value.get("automatic_indexing") is not False
        or value.get("automatic_embedding") is not False
        or value.get("candidate_build_authorized") is not False
        or not isinstance(records, list)
        or len(records) != 25
    ):
        raise ValueError("phase2a_deterministic_span_prior_admissions_boundary_invalid")
    identities = {
        _authority_key(str(record.get("source_identity") or ""))
        for record in records
        if isinstance(record, dict)
    }
    identities.discard("")
    return identities, digest


def _verify_approved_source_versions(
    catalogue_path: Path, records: Sequence[Mapping[str, Any]]
) -> dict[str, dict[str, Any]]:
    source_ids = [str(record["selected_source_version"]["source_version_id"]) for record in records]
    if len(set(source_ids)) != EXPECTED_APPROVED_SOURCES:
        raise ValueError("phase2a_deterministic_span_approved_source_ids_invalid")
    connection = sqlite3.connect(
        f"file:{catalogue_path.resolve()}?mode=ro&immutable=1",
        uri=True,
    )
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            f"""
            SELECT sv.id AS source_version_id,
                   sv.version_sha256,
                   sv.authority_identity_id,
                   sv.stable_identifier,
                   sv.review_status,
                   d.status AS document_status,
                   d.lane,
                   d.retrieval_canonical,
                   COUNT(c.id) AS chunk_count
              FROM source_versions sv
              JOIN documents d ON d.id=sv.document_id
         LEFT JOIN chunks c ON c.source_version_id=sv.id AND c.stream='body'
             WHERE sv.id IN ({_sql_placeholders(source_ids)})
          GROUP BY sv.id, d.id
            """,
            tuple(source_ids),
        ).fetchall()
    finally:
        connection.close()
    by_id = {str(row["source_version_id"]): dict(row) for row in rows}
    if set(by_id) != set(source_ids):
        raise ValueError("phase2a_deterministic_span_approved_source_missing")
    for record in records:
        selected = record["selected_source_version"]
        row = by_id[str(selected["source_version_id"])]
        if (
            row["version_sha256"] != selected["version_sha256"]
            or selected["content_sha256"] != selected["version_sha256"]
            or row["review_status"] != "staged"
            or row["document_status"] != "citable"
            or row["lane"] != "primary_authority"
            or int(row["retrieval_canonical"] or 0) != 1
            or int(row["chunk_count"] or 0) != selected["chunk_count"]
        ):
            raise ValueError("phase2a_deterministic_span_approved_source_binding_invalid")
    return by_id


def _load_catalogue_authority_inventory(
    catalogue_path: Path, authority_ids: Sequence[str]
) -> dict[str, list[dict[str, Any]]]:
    connection = sqlite3.connect(
        f"file:{catalogue_path.resolve()}?mode=ro&immutable=1",
        uri=True,
    )
    connection.row_factory = sqlite3.Row
    try:
        inventory: dict[str, list[dict[str, Any]]] = {}
        for authority_id in authority_ids:
            key = _authority_key(authority_id)
            rows = connection.execute(
                """
                SELECT sv.id AS source_version_id,
                       sv.version_sha256,
                       sv.authority_identity_id,
                       sv.stable_identifier,
                       sv.review_status,
                       sv.currentness_status,
                       d.status AS document_status,
                       d.lane,
                       d.retrieval_canonical,
                       COUNT(c.id) AS chunk_count
                  FROM source_versions sv
                  JOIN documents d ON d.id=sv.document_id
             LEFT JOIN chunks c ON c.source_version_id=sv.id AND c.stream='body'
                 WHERE lower(sv.authority_identity_id)=lower(?)
                    OR lower(sv.stable_identifier)=lower(?)
              GROUP BY sv.id, d.id
              ORDER BY sv.version_sha256, sv.id
                """,
                (authority_id, authority_id),
            ).fetchall()
            usable = [
                dict(row)
                for row in rows
                if row["review_status"] == "approved"
                and row["document_status"] == "citable"
                and row["lane"] == "primary_authority"
                and int(row["retrieval_canonical"] or 0) == 1
                and int(row["chunk_count"] or 0) > 0
            ]
            if not usable:
                raise ValueError("phase2a_deterministic_span_outside_authority_catalogue_missing")
            inventory[key] = usable
    finally:
        connection.close()
    if len(inventory) != len({_authority_key(value) for value in authority_ids}):
        raise ValueError("phase2a_deterministic_span_outside_authority_inventory_invalid")
    return inventory


def _row_authority_links(
    ledger: Mapping[str, Mapping[str, Any]],
) -> dict[str, set[str]]:
    links: dict[str, set[str]] = defaultdict(set)
    for row in ledger.values():
        values = [
            *(row.get("effective_planned_authority_ids") or []),
            *(row.get("effective_outside_candidate_authority_ids") or []),
        ]
        values.extend(
            item.get("source_authority_identity_id")
            for item in (row.get("owner_approved_source_admissions") or [])
        )
        for value in values:
            key = _authority_key(str(value or ""))
            if key:
                links[key].add(str(row["row_id"]))
    return links


def _retained_hold_codes(record: Mapping[str, Any]) -> list[str]:
    holds: list[str] = []
    currentness = record.get("currentness") or {}
    later = record.get("later_treatment") or {}
    jurisdiction = record.get("jurisdiction_binding") or {}
    if currentness.get("currentness_verified") is not True:
        holds.append("CURRENTNESS_NOT_VERIFIED")
    if (
        record.get("source_family") == "legislation"
        and currentness.get("extent_effects_verified") is not True
    ):
        holds.append("EXTENT_EFFECTS_NOT_VERIFIED")
    if later.get("applicable") is True and later.get("verified") is not True:
        holds.append("LATER_TREATMENT_NOT_VERIFIED")
    if jurisdiction.get("territorial_extent_status") == "OWNER_REVIEW_REQUIRED":
        holds.append("TERRITORIAL_EXTENT_OWNER_REVIEW_REQUIRED")
    return sorted(set(holds))


def _build_source_crosswalk(
    *,
    approved_records: Sequence[Mapping[str, Any]],
    receipt: Mapping[str, Any],
    exclusions: Mapping[str, Any],
    approved_catalogue_sources: Mapping[str, Mapping[str, Any]],
    candidate_by_authority: Mapping[str, Sequence[Mapping[str, Any]]],
    ledger: Mapping[str, Mapping[str, Any]],
    retained_bindings: Mapping[str, Mapping[str, Any]],
    prior_admission_keys: set[str],
    outside_catalogue_inventory: Mapping[str, Sequence[Mapping[str, Any]]],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    links = _row_authority_links(ledger)
    rows: list[dict[str, Any]] = []
    class_counts: Counter[str] = Counter()
    approved_keys: set[str] = set()
    for record in sorted(approved_records, key=lambda item: str(item["source_key"])):
        canonical_id = _canonical_authority_id(str(record["proposed_stable_identifier"]))
        key = _authority_key(canonical_id)
        if not key or key in approved_keys:
            raise ValueError("phase2a_deterministic_span_source_identity_duplicate")
        approved_keys.add(key)
        selected = record["selected_source_version"]
        candidate_sources = list(candidate_by_authority.get(key, []))
        exact = [
            source
            for source in candidate_sources
            if source.get("version_sha256") == selected["version_sha256"]
        ]
        affected_rows = sorted(links.get(key, set()))
        if exact:
            classification = "EXACT_CURRENT_CANDIDATE_OVERLAP_REUSE_ONCE"
        elif candidate_sources:
            classification = "SAME_AUTHORITY_DIFFERENT_VERSION_NEW_VERSION_ONCE"
        elif affected_rows:
            classification = "APPROVED_NEW_SOURCE_LINKED_TO_REMAINING_ROW"
        else:
            classification = "APPROVED_NEW_SOURCE_NO_CURRENT_364_ROW_LINK"
        holds = _retained_hold_codes(record)
        material = {
            "schema": "legalbot.v111.phase2a.approved-source-crosswalk-row.v1",
            "source_key": record["source_key"],
            "source_family": record["source_family"],
            "canonical_authority_id": canonical_id,
            "official_identity": record["official_identity"],
            "official_canonical_url": record["official_canonical_url"],
            "selected_source_version_id": selected["source_version_id"],
            "selected_content_sha256": selected["content_sha256"],
            "selected_version_sha256": selected["version_sha256"],
            "catalogue_chunk_count": approved_catalogue_sources[str(selected["source_version_id"])][
                "chunk_count"
            ],
            "crosswalk_classification": classification,
            "candidate_source_versions": [
                {
                    "source_version_id": source["source_version_id"],
                    "stable_identifier": source["stable_identifier"],
                    "version_sha256": source["version_sha256"],
                }
                for source in sorted(
                    candidate_sources, key=lambda item: str(item["source_version_id"])
                )
            ],
            "affected_remaining_row_ids": affected_rows,
            "overlaps_prior_25_approval_by_authority_identity": key in prior_admission_keys,
            "owner_source_admission_authorized": True,
            "retained_hold_codes": holds,
            "holds_retained": bool(holds),
            "include_once_in_consolidated_source_manifest": not bool(exact),
            "reuse_existing_candidate_bytes": bool(exact),
            "answer_release_eligible": False,
            "technical_qualification_assigned": False,
        }
        rows.append({**material, "record_content_sha256": _sealed(material)})
        class_counts[classification] += 1

    exclusion_counts = dict(exclusions.get("counts") or {})
    crosswalk = _sealed_artifact(
        "legalbot.v111.phase2a.approved-142-source-crosswalk.v1",
        {
            "status": "EXACT_142_SOURCE_CROSSWALK_COMPLETE_EXECUTION_NOT_STARTED",
            "source_owner_approval_receipt_content_sha256": receipt[
                "approval_receipt_content_sha256"
            ],
            "source_owner_decision_batch_content_sha256": (EXPECTED_SOURCE_BATCH_DIGEST),
            "source_exclusions_content_sha256": EXPECTED_SOURCE_EXCLUSIONS_DIGEST,
            "source_prior_25_admissions_content_sha256": (EXPECTED_PRIOR_ADMISSIONS_DIGEST),
            "source_count": len(rows),
            "classification_counts": dict(sorted(class_counts.items())),
            "retained_exclusion_counts": exclusion_counts,
            "records": rows,
            "canonical_identity_and_content_sha_crosswalk_complete": True,
            "currentness_and_later_treatment_holds_retained": True,
            "all_packet_exclusions_retained": True,
            "deduplicate_by_canonical_identity_and_content_sha_required": True,
            "source_scan_started": False,
            "automatic_indexing": False,
            "automatic_embedding": False,
            "candidate_mutated": False,
            "technical_qualification_assigned": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        },
    )

    candidate_keys = set(candidate_by_authority)
    outside_rows: dict[str, set[str]] = defaultdict(set)
    display_ids: dict[str, str] = {}
    for row in ledger.values():
        for authority in row.get("effective_outside_candidate_authority_ids") or []:
            key = _authority_key(str(authority))
            display_ids.setdefault(key, _canonical_authority_id(str(authority)))
            outside_rows[key].add(str(row["row_id"]))
    pending_keys = sorted(set(outside_rows) - candidate_keys - approved_keys - prior_admission_keys)
    disposition_records: list[dict[str, Any]] = []
    pending_records: list[dict[str, Any]] = []
    for key in pending_keys:
        row_dispositions: list[dict[str, Any]] = []
        for row_id in sorted(outside_rows[key]):
            row = ledger[row_id]
            matching = [
                item
                for item in (row.get("owner_approved_mapping_dispositions") or [])
                if _authority_key(str(item.get("mapped_authority_identity_id") or "")) == key
            ]
            if len(matching) > 1:
                raise ValueError("phase2a_deterministic_span_mapping_disposition_duplicate")
            if matching:
                owner_outcome = str(matching[0].get("owner_outcome") or "")
                if owner_outcome == "RECOMMEND_REJECT_MAPPING":
                    disposition = "OWNER_APPROVED_MAPPING_REJECTED"
                elif owner_outcome == "RECOMMEND_SUPERSEDE_WITH_CURRENT_AUTHORITY":
                    disposition = "OWNER_APPROVED_MAPPING_SUPERSEDED"
                elif owner_outcome == "RECOMMEND_PARTIAL_EXISTING_SOURCE_BINDING":
                    disposition = "OWNER_APPROVED_PARTIAL_EXISTING_SOURCE_BINDING"
                elif owner_outcome == "RECOMMEND_PARTIAL_BINDING_AND_SOURCE_ADMISSION":
                    disposition = "OWNER_APPROVED_PARTIAL_BINDING_WITH_SEPARATE_ADMISSION"
                else:
                    raise ValueError("phase2a_deterministic_span_mapping_disposition_unknown")
            else:
                retained = retained_bindings.get(row_id)
                direct_bindings = [
                    binding
                    for binding in ((retained or {}).get("bindings") or [])
                    if binding.get("binding_scope") == "DIRECT"
                    and binding.get("owner_approval_bound_to_r94") is True
                ]
                if direct_bindings and (retained or {}).get("remaining_dependency") == (
                    "JUDGMENT_LATER_TREATMENT_CURRENTNESS_REVIEW"
                ):
                    disposition = (
                        "OWNER_APPROVED_DIRECT_BINDING_RETAINED_ALTERNATIVE_SOURCE_NOT_REQUIRED"
                    )
                else:
                    disposition = "UNRESOLVED_SOURCE_MATERIALITY"
            row_dispositions.append(
                {
                    "row_id": row_id,
                    "issue_label": row["issue_label"],
                    "disposition": disposition,
                }
            )

        unresolved_rows = [
            item["row_id"]
            for item in row_dispositions
            if item["disposition"] == "UNRESOLVED_SOURCE_MATERIALITY"
        ]
        catalogue_versions = list(outside_catalogue_inventory[key])
        unique_version_sha256s = sorted(
            {str(item["version_sha256"]) for item in catalogue_versions}
        )
        if len(unique_version_sha256s) != 1:
            raise ValueError("phase2a_deterministic_span_outside_authority_version_ambiguous")
        selected_reuse = min(catalogue_versions, key=lambda item: str(item["source_version_id"]))
        disposition_values = {item["disposition"] for item in row_dispositions}
        if unresolved_rows:
            classification = "OWNER_SOURCE_MATERIALITY_DECISION_REQUIRED"
        elif "OWNER_APPROVED_PARTIAL_EXISTING_SOURCE_BINDING" in disposition_values:
            classification = "OWNER_APPROVED_EXISTING_SOURCE_BINDING_NO_NEW_ADMISSION"
        elif "OWNER_APPROVED_MAPPING_SUPERSEDED" in disposition_values:
            classification = "OWNER_APPROVED_SUPERSEDED_MAPPING_NO_ADMISSION"
        elif (
            "OWNER_APPROVED_DIRECT_BINDING_RETAINED_ALTERNATIVE_SOURCE_NOT_REQUIRED"
            in disposition_values
        ):
            classification = "OWNER_APPROVED_DIRECT_BINDING_ALTERNATIVE_NOT_REQUIRED"
        else:
            classification = "OWNER_APPROVED_REJECTED_MAPPING_NO_ADMISSION"
        disposition_material = {
            "canonical_authority_id": display_ids[key],
            "affected_row_ids": sorted(outside_rows[key]),
            "row_dispositions": row_dispositions,
            "classification": classification,
            "catalogue_source_version_id_count": len(catalogue_versions),
            "catalogue_unique_version_sha256s": unique_version_sha256s,
            "selected_reuse_source_version_id": selected_reuse["source_version_id"],
            "selected_reuse_version_sha256": selected_reuse["version_sha256"],
            "source_bytes_already_local": True,
            "new_download_required": False,
            "new_source_admission_required": bool(unresolved_rows),
        }
        disposition_records.append(
            {
                **disposition_material,
                "record_content_sha256": _sealed(disposition_material),
            }
        )
        if unresolved_rows:
            pending_material = {
                "canonical_authority_id": display_ids[key],
                "affected_row_ids": unresolved_rows,
                "source_bytes_retrieved": True,
                "source_admission_authorized": False,
                "status": "OWNER_SOURCE_MATERIALITY_DECISION_REQUIRED",
            }
            pending_records.append(
                {
                    **pending_material,
                    "record_content_sha256": _sealed(pending_material),
                }
            )

    disposition_counts = Counter(record["classification"] for record in disposition_records)
    outside_crosswalk = _sealed_artifact(
        "legalbot.v111.phase2a.outside-authority-local-crosswalk.v2",
        {
            "status": "OWNER_DISPOSITIONS_AND_LOCAL_BYTES_CROSSWALKED",
            "source_ledger_content_sha256": EXPECTED_LEDGER_DIGEST,
            "source_retained_bindings_content_sha256": EXPECTED_RETAINED_DIGEST,
            "authority_count": len(disposition_records),
            "classification_counts": dict(sorted(disposition_counts.items())),
            "records": disposition_records,
            "automatic_download": False,
            "source_admission_authorized": False,
            "automatic_indexing": False,
            "automatic_embedding": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        },
    )
    pending = _sealed_artifact(
        "legalbot.v111.phase2a.pending-out-of-packet-authority-scope.v1",
        {
            "status": (
                "DETERMINISTIC_RESEARCH_REQUIRED_BEFORE_ANY_NEW_SOURCE_APPROVAL_BATCH"
                if pending_records
                else "NO_OUT_OF_PACKET_AUTHORITY_SCOPE_REMAINS"
            ),
            "authority_count": len(pending_records),
            "records": pending_records,
            "automatic_download": False,
            "source_admission_authorized": False,
            "automatic_indexing": False,
            "automatic_embedding": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        },
    )
    return crosswalk, outside_crosswalk, pending


def build_packets(
    output_root: Path,
    *,
    ledger_path: Path = DEFAULT_LEDGER,
    recovery_path: Path = DEFAULT_RECOVERY,
    ready_path: Path = DEFAULT_READY,
    retained_path: Path = DEFAULT_RETAINED,
    source_packet_root: Path = DEFAULT_SOURCE_PACKET_ROOT,
    source_receipt_path: Path = DEFAULT_SOURCE_RECEIPT,
    prior_admissions_path: Path = DEFAULT_PRIOR_ADMISSIONS,
    build_root: Path = DEFAULT_BUILD_ROOT,
    candidate_manifest_path: Path = DEFAULT_CANDIDATE_MANIFEST,
    catalogue_path: Path = DEFAULT_CATALOGUE,
) -> dict[str, dict[str, Any]]:
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_deterministic_span_output_already_exists")
    ledger, ledger_digest = _load_ledger(ledger_path)
    recovery, recovery_digest = _load_recovery(recovery_path)
    ready, ready_digest = _load_ready(ready_path)
    retained, retained_digest = _load_retained(retained_path)
    candidate_sources, candidate_by_authority, manifest_digest = _load_candidate_manifest(
        candidate_manifest_path
    )
    build_identity = _verify_build(build_root)
    if (
        ledger_digest != EXPECTED_LEDGER_DIGEST
        or recovery_digest != EXPECTED_RECOVERY_DIGEST
        or ready_digest != EXPECTED_READY_DIGEST
        or retained_digest != EXPECTED_RETAINED_DIGEST
        or manifest_digest != EXPECTED_CANDIDATE_MANIFEST_DIGEST
    ):
        raise ValueError("phase2a_deterministic_span_input_identity_invalid")

    unique_chunk_ids = sorted(
        {str(candidate["chunk_id"]) for row in recovery.values() for candidate in row["candidates"]}
    )
    catalogue_chunks, catalogue_file_sha256 = _load_catalogue_chunks(
        catalogue_path, unique_chunk_ids
    )
    lance_chunks = _load_lance_chunks(build_root, unique_chunk_ids)
    source_corpus, source_corpus_by_chunk, _ = _build_source_corpus(
        recovery=recovery,
        candidate_sources=candidate_sources,
        catalogue_chunks=catalogue_chunks,
        lance_chunks=lance_chunks,
        catalogue_file_sha256=catalogue_file_sha256,
        build_identity=build_identity,
    )
    row_packets = _build_row_packets(
        ledger=ledger,
        recovery=recovery,
        ready=ready,
        source_corpus=source_corpus_by_chunk,
    )

    approved_records, receipt, exclusions = _load_source_approval(
        packet_root=source_packet_root,
        receipt_path=source_receipt_path,
    )
    prior_admission_keys, _ = _load_prior_admissions(prior_admissions_path)
    approved_catalogue_sources = _verify_approved_source_versions(catalogue_path, approved_records)
    approved_source_keys = {
        _authority_key(str(record["proposed_stable_identifier"])) for record in approved_records
    }
    outside_authority_ids = sorted(
        {
            _canonical_authority_id(str(authority))
            for row in ledger.values()
            for authority in (row.get("effective_outside_candidate_authority_ids") or [])
            if _authority_key(str(authority)) not in candidate_by_authority
            and _authority_key(str(authority)) not in approved_source_keys
            and _authority_key(str(authority)) not in prior_admission_keys
        }
    )
    outside_catalogue_inventory = _load_catalogue_authority_inventory(
        catalogue_path, outside_authority_ids
    )
    crosswalk, outside_crosswalk, pending = _build_source_crosswalk(
        approved_records=approved_records,
        receipt=receipt,
        exclusions=exclusions,
        approved_catalogue_sources=approved_catalogue_sources,
        candidate_by_authority=candidate_by_authority,
        ledger=ledger,
        retained_bindings=retained,
        prior_admission_keys=prior_admission_keys,
        outside_catalogue_inventory=outside_catalogue_inventory,
    )

    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_deterministic_span_output_mode_invalid")
    artifacts = {
        "EXACT-SPAN-SOURCE-CORPUS.json": source_corpus,
        "DETERMINISTIC-EXACT-SPAN-PACKETS-364.json": row_packets,
        "APPROVED-142-SOURCE-CROSSWALK.json": crosswalk,
        "OUTSIDE-AUTHORITY-LOCAL-CROSSWALK-15.json": outside_crosswalk,
        "PENDING-OUT-OF-PACKET-AUTHORITY-SCOPE.json": pending,
    }
    for name, artifact in artifacts.items():
        _write_exclusive(output_root / name, _pretty_json(artifact))
    outcome = (
        "OPTION A DETERMINISTIC EXACT-SPAN/CROSSWALK PASS COMPLETE\n"
        f"ROWS: {row_packets['row_count']}\n"
        f"OWNER-APPROVED READY ROWS: {row_packets['owner_approved_ready_row_count']}\n"
        f"OWNER-DECISION ROWS: {row_packets['owner_decision_required_row_count']}\n"
        f"UNIQUE EXACT SOURCE CHUNKS: {source_corpus['chunk_count']}\n"
        f"APPROVED SOURCE CROSSWALK: {crosswalk['source_count']}\n"
        f"LOCAL OUTSIDE-AUTHORITY CROSSWALK: {outside_crosswalk['authority_count']}\n"
        f"UNPROVEN OUT-OF-PACKET AUTHORITIES: {pending['authority_count']}\n"
        "NO PLANNER OR ANSWER MODEL INVOKED; NO SOURCE SCAN OR CANDIDATE BUILD STARTED\n"
        "PHASE 2B AND DEVELOPMENT 30 REMAIN CLOSED\n"
    )
    _write_exclusive(output_root / "OUTCOME.txt", outcome.encode("utf-8"))

    indexed_names = (*artifacts, "OUTCOME.txt")
    files = [
        {
            "name": name,
            "byte_count": (output_root / name).stat().st_size,
            "file_sha256": _sha256_file(output_root / name),
        }
        for name in indexed_names
    ]
    package = _sealed_artifact(
        "legalbot.v111.phase2a.deterministic-exact-span-crosswalk-package.v1",
        {
            "status": "DETERMINISTIC_EVIDENCE_PACKET_COMPLETE_OWNER_REVIEW_REMAINS",
            "files": files,
            "file_count": len(files),
            "source_corpus_content_sha256": source_corpus["artifact_content_sha256"],
            "row_packets_content_sha256": row_packets["artifact_content_sha256"],
            "source_crosswalk_content_sha256": crosswalk["artifact_content_sha256"],
            "outside_authority_crosswalk_content_sha256": outside_crosswalk[
                "artifact_content_sha256"
            ],
            "pending_authority_scope_content_sha256": pending["artifact_content_sha256"],
            "planner_or_answer_model_invoked": False,
            "source_scan_started": False,
            "candidate_build_started": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        },
        digest_field="package_content_sha256",
    )
    _write_exclusive(output_root / "PACKAGE-INDEX.json", _pretty_json(package))
    checksum_names = (*indexed_names, "PACKAGE-INDEX.json")
    checksums = "".join(f"{_sha256_file(output_root / name)}  {name}\n" for name in checksum_names)
    _write_exclusive(output_root / "SHA256SUMS.txt", checksums.encode("utf-8"))
    return {**artifacts, "PACKAGE-INDEX.json": package}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    parser.add_argument("--recovery", type=Path, default=DEFAULT_RECOVERY)
    parser.add_argument("--ready", type=Path, default=DEFAULT_READY)
    parser.add_argument("--retained", type=Path, default=DEFAULT_RETAINED)
    parser.add_argument("--source-packet-root", type=Path, default=DEFAULT_SOURCE_PACKET_ROOT)
    parser.add_argument("--source-receipt", type=Path, default=DEFAULT_SOURCE_RECEIPT)
    parser.add_argument("--prior-admissions", type=Path, default=DEFAULT_PRIOR_ADMISSIONS)
    parser.add_argument("--build-root", type=Path, default=DEFAULT_BUILD_ROOT)
    parser.add_argument("--candidate-manifest", type=Path, default=DEFAULT_CANDIDATE_MANIFEST)
    parser.add_argument("--catalogue", type=Path, default=DEFAULT_CATALOGUE)
    arguments = parser.parse_args()
    result = build_packets(
        arguments.output_root,
        ledger_path=arguments.ledger,
        recovery_path=arguments.recovery,
        ready_path=arguments.ready,
        retained_path=arguments.retained,
        source_packet_root=arguments.source_packet_root,
        source_receipt_path=arguments.source_receipt,
        prior_admissions_path=arguments.prior_admissions,
        build_root=arguments.build_root,
        candidate_manifest_path=arguments.candidate_manifest,
        catalogue_path=arguments.catalogue,
    )
    print(result["PACKAGE-INDEX.json"]["package_content_sha256"])


if __name__ == "__main__":
    main()
