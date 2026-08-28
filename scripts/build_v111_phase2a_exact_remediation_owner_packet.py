#!/usr/bin/env python3
"""Build the exact, non-authorizing Phase-2A remediation owner packet.

The builder is deliberately create-only.  It binds the sealed 316-row official
research queue, the sealed 45-row direct exact-span advisory, explicitly named
and digest-bound research waves, and the sealed 251-source non-ACTIVE candidate
manifest.  It recommends decisions and proposed source admissions, but it does
not apply an owner outcome, admit a source, scan/build/embed an index, qualify a
row, or authorize any later phase.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import unicodedata
from collections import Counter
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.retrieval.source_manifest import (  # noqa: E402
    approved_source_manifest_sha256,
)

from scripts import (  # noqa: E402
    collect_v111_phase2a_research_wave_sources as source_collector,
)
from scripts import (  # noqa: E402
    validate_v111_phase2a_official_research_waves as wave_validator,
)

REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
WORKING_ROOT = REVIEW_ROOT / "LegalBot-Phase2A-2026-08-27-remediation-working-r1"
DEFAULT_QUEUE_PATH = WORKING_ROOT / "OFFICIAL-SOURCE-RESEARCH-QUEUE-316.json"
DEFAULT_DIRECT_PATH = WORKING_ROOT / "DIRECT-READY-HOLD-RESOLUTION-ADVISORY-45.json"
DEFAULT_CANONICAL_SET_PATH = WORKING_ROOT / "CANONICAL-RESEARCH-WAVE-BINDINGS-32.json"
DEFAULT_CANDIDATE_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2A-2026-08-27-final-owner-review-blocked"
    / "machine/candidate/approved-source-manifest.json"
)
DEFAULT_OUTPUT_ROOT = REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-exact-remediation-owner-packet-r1"

QUEUE_CONTENT_SHA256 = wave_validator.EXPECTED_QUEUE_CONTENT_SHA256
QUEUE_FILE_SHA256 = "7cdfaf81dab005dea418510884e741173f16ad378e64b026e3f52b7de9095391"
DIRECT_CONTENT_SHA256 = "a87dac0c0ae5c860b02678e99d4818a010b7a704adabdf1a64a7d3c2c559d951"
DIRECT_FILE_SHA256 = "01c347ca1a8b2ce345183bf1de0a5b1564b8a95ec48715ce0e8da81dee1d1ed6"
CANDIDATE_CONTENT_SHA256 = "b304ab1223987bf9b57d3e2560413b2f325c16213ae0071a45dface2e10dc206"
CANDIDATE_FILE_SHA256 = "0bbb1edb169c84a26e5f1d42e367f9e2f83fcdd9c652a9061980652f15979b21"
CANONICAL_SET_CONTENT_SHA256 = "2fb9416e0e948a40157ca392e4d2b295b1de44a875b81b0c1c03d1cf76f14937"
CANONICAL_SET_FILE_SHA256 = "2a0207ed1f302636b29ba70586ce88a9a62fad6d46ed0b341195f0cdcb4074b2"
REPRESENTATION_BINDING_SCHEMA = "legalbot.v111.phase2a.research-wave-quarantine-binding.v2"
PACKET_BUILDER_INTERFACE_SCHEMA = "legalbot.v111.phase2a.quarantine-to-owner-packet.v1"
CANONICAL_WAVE_SET_SCHEMA = source_collector.CANONICAL_WAVE_SET_SCHEMA
EXPECTED_CANONICAL_WAVE_COUNT = source_collector.EXPECTED_CANONICAL_WAVE_COUNT

PACKET_NAME = "EXACT-REMEDIATION-OWNER-PACKET-361.json"
PROMPT_NAME = "OWNER-APPROVAL-PROMPT.txt"
PACKAGE_NAME = "PACKAGE-MANIFEST.json"
CHECKSUM_NAME = "SHA256SUMS.txt"
CANONICAL_Q48_NAME = "research-live60-q48-q50-r3.json"
OLD_Q48_NAMES = frozenset(
    {
        "research-live60-q48-q50.json",
        "research-live60-q48-q50-r1.json",
        "research-live60-q48-q50-r2.json",
    }
)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_SOURCE_VERSION_ID = re.compile(r"source-version-[0-9a-f]{40}")
_PROPOSED_SOURCE_VERSION_ID = re.compile(r"proposed-source-version-[0-9a-f]{40}")
_DOCUMENT_ID = re.compile(r"document-[0-9a-f]{40}")
_ROW_ID = re.compile(r"live(?P<lane>30|60)-q(?P<question>\d+):issue-(?P<issue>\d+)")
_PRIVATE_PATH = re.compile(
    r"(?i)(?:/(?:Users|home|private)/[^\s\]\[)>,;:'\"]+|"
    r"[A-Z]:\\Users\\[^\s\]\[)>,;:'\"]+|file://|(?:^|\s)~/)"
)
_ABSOLUTE_POSIX_PATH = re.compile(r"(?<![\w:])/(?:[^/\s<>\]\[)('\\\"]+/)*[^/\s<>\]\[)('\\\"]+")
_ABSOLUTE_WINDOWS_PATH = re.compile(r"(?i)(?<![\w])(?:[A-Z]:\\|\\\\)[^\s]+")
_SECRET_VALUE = re.compile(
    r"(?i)(?:-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    r"\bsk-[A-Za-z0-9_-]{20,}\b|"
    r"\b(?:api[_-]?key|client[_-]?secret|password|access[_-]?token)\b"
    r"\s*[:=]\s*['\"]?[^'\"\s]{12,})"
)
_PERSONAL_FILENAME_KEYS = frozenset(
    {"original_filename", "personal_filename", "owner_filename", "source_filename"}
)
_SECRET_KEYS = frozenset(
    {
        "secret",
        "password",
        "api_key",
        "client_secret",
        "access_token",
        "private_key",
        "split_secret",
        "session_secret",
        "csrf_secret",
    }
)
_TOP_LEVEL_FALSE_FIELDS = (
    "owner_approved",
    "owner_decisions_applied",
    "owner_outcomes_applied",
    "source_admission_authorized",
    "source_admitted",
    "complete_source_scan_authorized",
    "source_scan_run",
    "successor_build_authorized",
    "successor_build_run",
    "index_build_authorized",
    "index_built",
    "automatic_indexing",
    "embedding_authorized",
    "embedding_run",
    "automatic_embedding",
    "candidate_mutated",
    "qualification_authorized",
    "technical_qualification_assigned",
    "retrieval_reattestation_run",
    "all585_qualification_run",
    "answer_model_authorized",
    "answer_model_run",
    "answer_release_authorized",
    "answer_released",
    "phase2b_authorized",
    "phase2b_run",
    "development30_authorized",
    "development30_run",
    "validation30_authorized",
    "validation30_run",
    "promotion_authorized",
    "promotion_run",
    "active_pointer_write_authorized",
    "active_pointer_written",
    "previous_pointer_write_authorized",
    "previous_pointer_written",
    "live_activation_authorized",
    "live_activation_run",
    "training_export_authorized",
    "training_export_run",
)

# These authority objects in the sealed 316-row research set conflate two
# independently versioned authorities behind one authority ordinal.  A URL or
# neutral-citation key chosen from such an object would silently discard the
# other authority.  Preserve the object, but hold it until an immutable split
# wave revision supplies one authority object per source identity.
_KNOWN_COMPOSITE_AUTHORITY_SIGNATURES = {
    ("live30-q28:issue-05", 4, 1): ("etridge", "waller-edwards"),
    ("live30-q28:issue-10", 5, 1): (
        "insolvency act 1986",
        "trusts of land and appointment",
    ),
    ("live60-q32:issue-11", 2, 1): (
        "civil procedure rules 1998",
        "civil procedure (amendment) rules 2025",
    ),
    ("live60-q34:issue-03", 1, 1): ("jogee", "odunewu"),
    ("live60-q34:issue-05", 1, 1): ("jogee", "tas"),
    ("live60-q34:issue-06", 1, 1): ("jogee", "tas"),
    ("live60-q34:issue-07", 1, 1): ("jogee", "tas"),
    ("live60-q34:issue-08", 1, 1): ("jogee", "odunewu"),
    ("live60-q35:issue-05", 2, 1): (
        "renters' rights act 2025",
        "commencement no 2",
    ),
    ("live60-q35:issue-06", 2, 1): (
        "housing act 1988",
        "landlord and tenant act 1985",
    ),
    ("live60-q37:issue-05", 1, 1): (
        "limited liability partnerships act 2000",
        "limited liability partnerships regulations 2001",
    ),
    ("live60-q40:issue-03", 1, 2): (
        "localism act 2011",
        "relevant authorities",
    ),
    ("live60-q41:issue-06", 1, 1): (
        "nationality and borders act 2022",
        "modern slavery act 2015",
    ),
    ("live60-q44:issue-04", 3, 1): ("cobs 2.2a", "cobs 14.3a"),
}


@dataclass(frozen=True)
class BoundArtifact:
    """An immutable path plus its expected logical and byte identities."""

    path: Path
    content_sha256: str
    file_sha256: str


@dataclass(frozen=True)
class CandidateIndex:
    by_version: dict[str, dict[str, Any]]
    aliases_by_version: dict[str, frozenset[str]]
    versions_by_alias: dict[str, frozenset[str]]


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


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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


def _validate_digest(value: str, *, error: str) -> None:
    if _SHA256.fullmatch(value) is None:
        raise ValueError(error)


def _portable_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        # Tests and independent verification may use a temporary root.  Never
        # leak an absolute path into a review artifact.
        return path.name


def _owner_identifiers() -> frozenset[str]:
    identifiers = {"agnes", "hltsang"}
    parts = PROJECT_ROOT.parts
    if len(parts) >= 3 and parts[1].casefold() == "users":
        identifiers.add(parts[2].casefold())
    return frozenset(item for item in identifiers if len(item) >= 3)


def _privacy_violation(value: Any, *, key_name: str | None = None) -> str | None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            key_text = str(key)
            violation = _privacy_violation(key_text)
            if violation is not None:
                return violation
            normalized_key = key_text.casefold().replace("-", "_")
            if (
                normalized_key in _PERSONAL_FILENAME_KEYS
                and nested is not None
                and nested != ""
                and nested is not False
            ):
                return "personal_filename"
            if (
                normalized_key in _SECRET_KEYS
                and nested is not None
                and nested != ""
                and nested is not False
            ):
                return "secret_key_value"
            violation = _privacy_violation(nested, key_name=normalized_key)
            if violation is not None:
                return violation
        return None
    if isinstance(value, list | tuple):
        for nested in value:
            violation = _privacy_violation(nested, key_name=key_name)
            if violation is not None:
                return violation
        return None
    if not isinstance(value, str):
        return None
    if _PRIVATE_PATH.search(value):
        return "absolute_private_path"
    without_web_urls = re.sub(r"https?://[^\s<>\]\[)('\\\"]+", "", value)
    if _ABSOLUTE_POSIX_PATH.search(without_web_urls) or _ABSOLUTE_WINDOWS_PATH.search(
        without_web_urls
    ):
        return "absolute_path"
    if _SECRET_VALUE.search(value):
        return "secret_value"
    casefolded = value.casefold()
    if any(
        re.search(rf"(?<![\w-]){re.escape(item)}(?![\w-])", casefolded)
        for item in _owner_identifiers()
    ):
        return "owner_identifier"
    if key_name in _PERSONAL_FILENAME_KEYS and value:
        return "personal_filename"
    return None


def _assert_privacy_safe(value: Any, *, role: str) -> None:
    if _privacy_violation(value) is not None:
        raise ValueError(f"phase2a_exact_packet_{role}_privacy_gate_failed")


def _load_json_file(binding: BoundArtifact, *, role: str) -> dict[str, Any]:
    _validate_digest(
        binding.content_sha256,
        error=f"phase2a_exact_packet_{role}_content_digest_invalid",
    )
    _validate_digest(
        binding.file_sha256,
        error=f"phase2a_exact_packet_{role}_file_digest_invalid",
    )
    path = binding.path
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"phase2a_exact_packet_{role}_must_be_regular_file")
    if _file_sha256(path) != binding.file_sha256:
        raise ValueError(f"phase2a_exact_packet_{role}_file_digest_invalid")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"phase2a_exact_packet_{role}_must_be_object")
    _assert_privacy_safe(value, role=role)
    return value


def _verify_self_seal(
    value: Mapping[str, Any],
    binding: BoundArtifact,
    *,
    role: str,
    require_embedded: bool,
) -> None:
    material = dict(value)
    supplied = material.pop("artifact_content_sha256", None)
    calculated = _sealed(material if supplied is not None else value)
    if calculated != binding.content_sha256:
        raise ValueError(f"phase2a_exact_packet_{role}_content_digest_invalid")
    if require_embedded and supplied is None:
        raise ValueError(f"phase2a_exact_packet_{role}_content_seal_missing")
    if supplied is not None and supplied != calculated:
        raise ValueError(f"phase2a_exact_packet_{role}_content_seal_invalid")


def _verify_record_seal(record: Mapping[str, Any], *, role: str) -> None:
    material = dict(record)
    supplied = str(material.pop("record_content_sha256", ""))
    if supplied != _sealed(material):
        raise ValueError(f"phase2a_exact_packet_{role}_record_seal_invalid")


def _load_queue(binding: BoundArtifact) -> dict[str, Any]:
    value = _load_json_file(binding, role="queue")
    _verify_self_seal(value, binding, role="queue", require_embedded=True)
    records = value.get("records")
    if (
        binding.content_sha256 != QUEUE_CONTENT_SHA256
        or not isinstance(records, list)
        or len(records) != 316
        or value.get("row_count") != 316
        or value.get("owner_decisions_applied") is not False
        or value.get("candidate_mutated") is not False
        or value.get("phase2b_authorized") is not False
    ):
        raise ValueError("phase2a_exact_packet_queue_scope_or_boundary_invalid")
    row_ids: list[str] = []
    for record in records:
        if not isinstance(record, Mapping):
            raise ValueError("phase2a_exact_packet_queue_record_invalid")
        _verify_record_seal(record, role="queue")
        row_ids.append(str(record.get("row_id") or ""))
    if len(set(row_ids)) != 316 or any(_ROW_ID.fullmatch(item) is None for item in row_ids):
        raise ValueError("phase2a_exact_packet_queue_row_identity_invalid")
    return value


def _load_direct(binding: BoundArtifact) -> dict[str, Any]:
    value = _load_json_file(binding, role="direct")
    _verify_self_seal(value, binding, role="direct", require_embedded=True)
    records = value.get("records")
    if (
        not isinstance(records, list)
        or len(records) != 45
        or value.get("record_count") != 45
        or value.get("owner_decisions_applied") is not False
        or value.get("source_admitted") is not False
        or value.get("candidate_mutated") is not False
        or value.get("phase2b_authorized") is not False
        or value.get("development30_authorized") is not False
        or value.get("validation30_authorized") is not False
        or value.get("active_pointer_write_authorized") is not False
    ):
        raise ValueError("phase2a_exact_packet_direct_scope_or_boundary_invalid")
    row_ids: list[str] = []
    for record in records:
        if not isinstance(record, Mapping):
            raise ValueError("phase2a_exact_packet_direct_record_invalid")
        _verify_record_seal(record, role="direct")
        if (
            record.get("owner_outcome") is not None
            or record.get("hold_cleared") is not False
            or record.get("technical_qualification_assigned") is not False
            or not isinstance(record.get("selected_local_evidence"), list)
            or not record.get("selected_local_evidence")
        ):
            raise ValueError("phase2a_exact_packet_direct_record_boundary_invalid")
        row_ids.append(str(record.get("row_id") or ""))
    if len(set(row_ids)) != 45 or any(_ROW_ID.fullmatch(item) is None for item in row_ids):
        raise ValueError("phase2a_exact_packet_direct_row_identity_invalid")
    return value


def _load_candidate(binding: BoundArtifact) -> dict[str, Any]:
    value = _load_json_file(binding, role="candidate")
    calculated = approved_source_manifest_sha256(value)
    if calculated != binding.content_sha256 or value.get("manifest_sha256") != calculated:
        raise ValueError("phase2a_exact_packet_candidate_content_seal_invalid")
    sources = value.get("sources")
    if (
        not isinstance(sources, list)
        or len(sources) != 251
        or value.get("source_count") != 251
        or value.get("successor_must_remain_non_active") is not True
        or value.get("active_or_previous_write_authorized") is not False
        or value.get("answer_release_eligible") is not False
        or value.get("phase2b_authorized") is not False
        or value.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_exact_packet_candidate_scope_or_boundary_invalid")
    return value


def _load_waves(bindings: Sequence[BoundArtifact]) -> list[dict[str, Any]]:
    if not bindings:
        raise ValueError("phase2a_exact_packet_explicit_wave_bindings_required")
    resolved_paths: set[Path] = set()
    names: set[str] = set()
    content_digests: set[str] = set()
    file_digests: set[str] = set()
    waves: list[dict[str, Any]] = []
    for binding in bindings:
        name = binding.path.name
        resolved = binding.path.resolve()
        if name in OLD_Q48_NAMES or ("q48-q50" in name and name != CANONICAL_Q48_NAME):
            raise ValueError("phase2a_exact_packet_old_q48_revision_forbidden")
        if (
            resolved in resolved_paths
            or name in names
            or binding.content_sha256 in content_digests
            or binding.file_sha256 in file_digests
        ):
            raise ValueError("phase2a_exact_packet_duplicate_wave")
        wave = _load_json_file(binding, role="wave")
        _verify_self_seal(wave, binding, role="wave", require_embedded=False)
        row_ids = [str(row.get("row_id") or "") for row in wave.get("records", [])]
        contains_q48_scope = any(
            row_id.startswith(("live60-q48:", "live60-q49:", "live60-q50:")) for row_id in row_ids
        )
        if contains_q48_scope and name != CANONICAL_Q48_NAME:
            raise ValueError("phase2a_exact_packet_q48_scope_not_canonical_r3")
        if name == CANONICAL_Q48_NAME and any(
            not row_id.startswith(("live60-q48:", "live60-q49:", "live60-q50:"))
            for row_id in row_ids
        ):
            raise ValueError("phase2a_exact_packet_q48_canonical_scope_invalid")
        resolved_paths.add(resolved)
        names.add(name)
        content_digests.add(binding.content_sha256)
        file_digests.add(binding.file_sha256)
        waves.append(wave)
    return waves


def _load_canonical_wave_set(
    binding: BoundArtifact,
    *,
    wave_bindings: Sequence[BoundArtifact],
) -> dict[str, Any]:
    if (
        binding.path.name != DEFAULT_CANONICAL_SET_PATH.name
        or binding.content_sha256 != CANONICAL_SET_CONTENT_SHA256
        or binding.file_sha256 != CANONICAL_SET_FILE_SHA256
    ):
        raise ValueError("phase2a_exact_packet_canonical_wave_set_exact_binding_mismatch")
    value = _load_json_file(binding, role="canonical_wave_set")
    _verify_self_seal(
        value,
        binding,
        role="canonical_wave_set",
        require_embedded=True,
    )
    entries = value.get("waves")
    queue_reference = value.get("queue_binding")
    excluded_obsolete = value.get("excluded_obsolete_wave_files")
    if (
        value.get("schema") != CANONICAL_WAVE_SET_SCHEMA
        or value.get("status") != "CANONICAL_32_WAVES_BOUND_NOT_AUTHORIZING"
        or value.get("source_queue_content_sha256") != QUEUE_CONTENT_SHA256
        or value.get("source_queue_file_sha256") != QUEUE_FILE_SHA256
        or value.get("exact_set_count") != EXPECTED_CANONICAL_WAVE_COUNT
        or value.get("total_row_count") != 316
        or value.get("wave_count") != EXPECTED_CANONICAL_WAVE_COUNT
        or not isinstance(entries, list)
        or len(entries) != EXPECTED_CANONICAL_WAVE_COUNT
        or not isinstance(queue_reference, Mapping)
        or queue_reference.get("file_name") != DEFAULT_QUEUE_PATH.name
        or queue_reference.get("content_sha256") != QUEUE_CONTENT_SHA256
        or queue_reference.get("file_sha256") != QUEUE_FILE_SHA256
        or queue_reference.get("row_count") != 316
        or _SHA256.fullmatch(str(queue_reference.get("record_content_sha256") or "")) is None
        or not isinstance(excluded_obsolete, list)
        or len(excluded_obsolete) != len(set(excluded_obsolete))
        or not set(OLD_Q48_NAMES).issubset(set(excluded_obsolete))
        or value.get("advisory_only") is not True
        or value.get("source_collected") is not False
        or value.get("source_collection_authorized") is not False
        or value.get("owner_decisions_applied") is not False
        or value.get("owner_outcomes_applied") is not False
        or value.get("source_admitted") is not False
        or value.get("catalogue_mutated") is not False
        or value.get("candidate_mutated") is not False
        or value.get("automatic_indexing") is not False
        or value.get("automatic_embedding") is not False
        or value.get("embedding_run") is not False
        or value.get("phase2b_authorized") is not False
        or value.get("development30_authorized") is not False
        or value.get("validation30_authorized") is not False
        or value.get("active_or_previous_write_authorized") is not False
        or value.get("live_activation_authorized") is not False
    ):
        raise ValueError("phase2a_exact_packet_canonical_wave_set_boundary_invalid")
    queue_material = dict(queue_reference)
    queue_record_seal = str(queue_material.pop("record_content_sha256", ""))
    if queue_record_seal != _sealed(queue_material):
        raise ValueError("phase2a_exact_packet_canonical_wave_set_queue_binding_invalid")
    expected: list[tuple[str, str, str]] = []
    total_rows = 0
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise ValueError("phase2a_exact_packet_canonical_wave_set_entry_invalid")
        file_name = str(entry.get("file_name") or "")
        content_sha256 = str(entry.get("content_sha256") or "")
        file_sha256 = str(entry.get("file_sha256") or "")
        record_content_sha256 = str(entry.get("record_content_sha256") or "")
        record_count = entry.get("record_count")
        if Path(file_name).name != file_name or not file_name.endswith(".json"):
            raise ValueError("phase2a_exact_packet_canonical_wave_set_filename_invalid")
        _validate_digest(
            content_sha256,
            error="phase2a_exact_packet_canonical_wave_set_entry_digest_invalid",
        )
        _validate_digest(
            file_sha256,
            error="phase2a_exact_packet_canonical_wave_set_entry_digest_invalid",
        )
        _validate_digest(
            record_content_sha256,
            error="phase2a_exact_packet_canonical_wave_set_entry_digest_invalid",
        )
        entry_material = dict(entry)
        entry_material.pop("record_content_sha256", None)
        if (
            record_content_sha256 != _sealed(entry_material)
            or not isinstance(record_count, int)
            or isinstance(record_count, bool)
            or record_count <= 0
        ):
            raise ValueError("phase2a_exact_packet_canonical_wave_set_record_count_invalid")
        total_rows += record_count
        expected.append((file_name, content_sha256, file_sha256))
    if (
        expected != sorted(expected)
        or len(set(expected)) != EXPECTED_CANONICAL_WAVE_COUNT
        or len({item[0] for item in expected}) != EXPECTED_CANONICAL_WAVE_COUNT
        or total_rows != 316
    ):
        raise ValueError("phase2a_exact_packet_canonical_wave_set_duplicate_or_order_invalid")
    names = {item[0] for item in expected}
    if (
        names & OLD_Q48_NAMES
        or CANONICAL_Q48_NAME not in names
        or any(Path(item).name != item or not item.endswith(".json") for item in excluded_obsolete)
        or names & set(excluded_obsolete)
    ):
        raise ValueError("phase2a_exact_packet_canonical_wave_set_q48_revision_invalid")
    supplied = sorted(
        (item.path.name, item.content_sha256, item.file_sha256) for item in wave_bindings
    )
    if supplied != expected or len(wave_bindings) != EXPECTED_CANONICAL_WAVE_COUNT:
        raise ValueError("phase2a_exact_packet_wave_bindings_not_canonical_set")
    return value


def _row_sort_key(row_id: str) -> tuple[int, int, int, str]:
    match = _ROW_ID.fullmatch(row_id)
    if match is None:
        raise ValueError("phase2a_exact_packet_row_id_invalid")
    return (
        int(match.group("lane")),
        int(match.group("question")),
        int(match.group("issue")),
        row_id,
    )


def _neutral_citation_alias(value: Any) -> str | None:
    text = unicodedata.normalize("NFKC", str(value or ""))
    match = re.search(
        r"\[(?P<year>\d{4})\]\s*"
        r"(?P<court>UKSC|UKHL|EWCA\s+(?:Civ|Crim)|EWHC\s+\d+\s*\([A-Za-z]+\))"
        r"(?:\s+(?P<number>\d+))?",
        text,
        flags=re.IGNORECASE,
    )
    if match is None:
        return None
    court = " ".join(match.group("court").split())
    if court.casefold().startswith("ewhc"):
        # EWHC number is already inside the captured court expression.
        citation = f"[{match.group('year')}] {court}"
    else:
        number = match.group("number")
        if number is None:
            return None
        citation = f"[{match.group('year')}] {court} {number}"
    return f"identity:neutral-citation:{citation.casefold()}"


def _url_identity_alias(url: str) -> str | None:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").casefold()
    key = _canonical_source_key(url)
    parts = [part for part in urlsplit(key).path.split("/") if part]
    if host in {"www.legislation.gov.uk", "legislation.gov.uk"} and len(parts) >= 3:
        return "identity:" + ":".join(parts).casefold()
    if host == "caselaw.nationalarchives.gov.uk":
        if len(parts) == 3 and parts[0] in {"uksc", "ukhl"}:
            return (
                f"identity:neutral-citation:[{parts[1]}] {parts[0].upper()} {parts[2]}"
            ).casefold()
        if (
            len(parts) == 4
            and parts[0] == "ewca"
            and parts[1]
            in {
                "civ",
                "crim",
            }
        ):
            division = "Civ" if parts[1] == "civ" else "Crim"
            return (f"identity:neutral-citation:[{parts[2]}] EWCA {division} {parts[3]}").casefold()
        if len(parts) == 4 and parts[0] == "ewhc":
            division = parts[1].upper() if parts[1] == "tcc" else parts[1].title()
            return (
                f"identity:neutral-citation:[{parts[2]}] EWHC {parts[3]} ({division})"
            ).casefold()
    return None


def _base_stable_identifier(value: Any) -> str:
    identifier = str(value or "")
    identifier = re.sub(r":latest-available@\d{4}-\d{2}-\d{2}$", "", identifier)
    return re.sub(r":enacted$", "", identifier)


def _identity_alias(value: Any) -> str | None:
    identity = _base_stable_identifier(value).strip()
    if not identity:
        return None
    return "identity:" + source_collector._identity_comparison_key(identity).casefold()


def _candidate_aliases(source: Mapping[str, Any]) -> frozenset[str]:
    aliases: set[str] = set()
    for field in ("authority_identity_id", "stable_identifier"):
        identity_alias = _identity_alias(source.get(field))
        if identity_alias:
            aliases.add(identity_alias)
    url = source.get("canonical_url")
    if isinstance(url, str) and url:
        aliases.add(f"url:{_canonical_source_key(url)}")
        identity_alias = _url_identity_alias(url)
        if identity_alias:
            aliases.add(identity_alias)
    citation_alias = _neutral_citation_alias(source.get("authority_identity_id"))
    if citation_alias:
        aliases.add(citation_alias)
    return frozenset(aliases)


def _authority_aliases(authority: Mapping[str, Any]) -> frozenset[str]:
    aliases: set[str] = set()
    url = authority.get("official_url")
    if isinstance(url, str) and url:
        aliases.add(f"url:{_canonical_source_key(url)}")
        identity_alias = _url_identity_alias(url)
        if identity_alias:
            aliases.add(identity_alias)
    for field in ("authority_identity_id", "stable_identifier"):
        identity_alias = _identity_alias(authority.get(field))
        if identity_alias:
            aliases.add(identity_alias)
    for field in ("title", "citation", "authority_identity_id", "stable_identifier"):
        citation_alias = _neutral_citation_alias(authority.get(field))
        if citation_alias:
            aliases.add(citation_alias)
    return frozenset(aliases)


def _canonical_authority_identity_key(authority: Mapping[str, Any]) -> str:
    identity, identity_holds = source_collector._authority_identity(authority)
    if identity_holds:
        raise ValueError("phase2a_exact_packet_authority_identity_not_admission_eligible")
    return "identity:" + source_collector.proposal_identity_key(identity)


def _candidate_index(candidate: Mapping[str, Any]) -> CandidateIndex:
    by_version: dict[str, dict[str, Any]] = {}
    aliases_by_version: dict[str, frozenset[str]] = {}
    versions_by_alias_mutable: dict[str, set[str]] = {}
    for source in candidate["sources"]:
        if not isinstance(source, Mapping):
            raise ValueError("phase2a_exact_packet_candidate_source_invalid")
        version_id = str(source.get("source_version_id") or "")
        if _SOURCE_VERSION_ID.fullmatch(version_id) is None or version_id in by_version:
            raise ValueError("phase2a_exact_packet_candidate_source_version_invalid")
        copied = copy.deepcopy(dict(source))
        aliases = _candidate_aliases(copied)
        if not aliases:
            raise ValueError("phase2a_exact_packet_candidate_source_identity_missing")
        by_version[version_id] = copied
        aliases_by_version[version_id] = aliases
        for alias in aliases:
            versions_by_alias_mutable.setdefault(alias, set()).add(version_id)
    return CandidateIndex(
        by_version=by_version,
        aliases_by_version=aliases_by_version,
        versions_by_alias={
            alias: frozenset(versions) for alias, versions in versions_by_alias_mutable.items()
        },
    )


def _collector_plan_set(
    *,
    wave_bindings: Sequence[BoundArtifact],
    waves: Sequence[Mapping[str, Any]],
    candidate: Mapping[str, Any],
) -> tuple[
    tuple[dict[str, Any], ...],
    dict[str, dict[str, Any]],
    tuple[str, ...],
    str,
]:
    named_waves = [
        (binding.path.name, wave) for binding, wave in zip(wave_bindings, waves, strict=True)
    ]
    plans = source_collector._plan_authorities(named_waves, candidate)
    by_identity: dict[str, dict[str, Any]] = {}
    for plan in plans:
        key = "identity:" + source_collector.proposal_identity_key(
            str(plan["authority_identity_comparison_key"])
        )
        if key in by_identity:
            raise ValueError("phase2a_exact_packet_collector_plan_identity_collision")
        by_identity[key] = copy.deepcopy(dict(plan))
    fetch_keys = tuple(
        "identity:" + key for key in source_collector.fetch_eligible_identity_keys(plans)
    )
    fetch_digest = source_collector.fetch_eligible_identity_set_sha256(plans)
    if len(fetch_keys) != len(set(fetch_keys)):
        raise ValueError("phase2a_exact_packet_collector_fetch_identity_collision")
    return plans, by_identity, fetch_keys, fetch_digest


def _metadata_completeness(authority: Mapping[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(source_collector.proposal_metadata_completeness(authority))


def _known_composite_authority_present(
    *,
    row_id: str,
    component_ordinal: int,
    authority_ordinal: int,
    authority: Mapping[str, Any],
) -> bool:
    markers = _KNOWN_COMPOSITE_AUTHORITY_SIGNATURES.get(
        (row_id, component_ordinal, authority_ordinal)
    )
    if markers is None:
        return False
    material = " ".join(
        str(authority.get(field) or "") for field in ("title", "citation")
    ).casefold()
    return all(marker.casefold() in material for marker in markers)


def _authority_candidate_crosscheck(
    *,
    authority: Mapping[str, Any],
    candidate_index: CandidateIndex,
) -> dict[str, Any]:
    aliases = _authority_aliases(authority)
    alias_matches = sorted(
        {
            version_id
            for alias in aliases
            for version_id in candidate_index.versions_by_alias.get(alias, ())
        }
    )
    alias_match_authority_identities = sorted(
        {
            _base_stable_identifier(
                candidate_index.by_version[version_id].get("authority_identity_id")
                or candidate_index.by_version[version_id].get("stable_identifier")
            ).casefold()
            for version_id in alias_matches
        }
        - {""}
    )
    claimed_candidate = authority.get("candidate_existing")
    claimed_admission = authority.get("source_admission_required")
    raw_ids = authority.get("candidate_source_version_ids")
    provided_ids = [str(item) for item in raw_ids] if isinstance(raw_ids, list) else []
    reason_codes: list[str] = []
    invalid_ids = sorted({item for item in provided_ids if item not in candidate_index.by_version})
    if invalid_ids:
        reason_codes.append("CANDIDATE_SOURCE_VERSION_ID_UNRESOLVED")
    if len(provided_ids) != len(set(provided_ids)):
        reason_codes.append("CANDIDATE_SOURCE_VERSION_ID_DUPLICATE")
    if len(alias_match_authority_identities) > 1:
        reason_codes.append("CANDIDATE_ALIAS_MATCH_AMBIGUOUS")
    valid_ids = sorted(set(provided_ids) & set(candidate_index.by_version))
    mismatched_ids = sorted(
        version_id
        for version_id in valid_ids
        if not (aliases & candidate_index.aliases_by_version[version_id])
    )
    if mismatched_ids:
        reason_codes.append("CANDIDATE_SOURCE_VERSION_IDENTITY_MISMATCH")
    if claimed_candidate == "unknown":
        reason_codes.append("CANDIDATE_MEMBERSHIP_UNKNOWN")
    elif claimed_candidate not in {True, False}:
        reason_codes.append("CANDIDATE_MEMBERSHIP_INVALID_OR_MISSING")
    if claimed_admission == "unknown":
        reason_codes.append("SOURCE_ADMISSION_REQUIREMENT_UNKNOWN")
    elif claimed_admission not in {True, False}:
        reason_codes.append("SOURCE_ADMISSION_REQUIREMENT_INVALID_OR_MISSING")
    reconciled_missing_ids = False
    if claimed_candidate is True:
        if claimed_admission is True:
            reason_codes.append("EXISTING_CANDIDATE_SOURCE_MARKED_FOR_ADMISSION")
        if not provided_ids:
            reconciled_missing_ids = bool(alias_matches)
            reason_codes.append("CANDIDATE_SOURCE_VERSION_BINDING_MISSING")
        if not alias_matches and not valid_ids:
            reason_codes.append("CLAIMED_CANDIDATE_SOURCE_NOT_FOUND")
    if claimed_candidate is False:
        if claimed_admission is False:
            reason_codes.append("NON_CANDIDATE_SOURCE_MARKED_NO_ADMISSION_REQUIRED")
        if provided_ids:
            reason_codes.append("NON_CANDIDATE_SOURCE_HAS_CANDIDATE_VERSION_IDS")
        if alias_matches:
            reason_codes.append("NON_CANDIDATE_CLAIM_CONTRADICTS_BOUND_MANIFEST")
    resolved_ids = valid_ids or (alias_matches if claimed_candidate is True else [])
    return {
        "claimed_candidate_existing": claimed_candidate,
        "claimed_source_admission_required": claimed_admission,
        "authority_aliases": sorted(aliases),
        "candidate_alias_match_source_version_ids": alias_matches,
        "candidate_alias_match_authority_identities": (alias_match_authority_identities),
        "provided_candidate_source_version_ids": provided_ids,
        "resolved_candidate_source_version_ids": resolved_ids,
        "invalid_candidate_source_version_ids": invalid_ids,
        "identity_mismatched_candidate_source_version_ids": mismatched_ids,
        "missing_ids_reconciled_from_manifest": reconciled_missing_ids,
        "verified_new_source": (
            claimed_candidate is False
            and claimed_admission is True
            and not provided_ids
            and not alias_matches
            and not reason_codes
        ),
        "reason_codes": sorted(set(reason_codes)),
    }


def _authority_assessments(
    *,
    record: Mapping[str, Any],
    candidate_index: CandidateIndex,
    collector_plans_by_identity: Mapping[str, Mapping[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    assessments: list[dict[str, Any]] = []
    component_holds: list[dict[str, Any]] = []
    for component_index, component in enumerate(record["atomic_components"], start=1):
        authorities = component.get("authorities", [])
        support_fit = component.get("support_fit")
        if support_fit in {"FULL", "PARTIAL"} and not authorities:
            component_holds.append(
                {
                    "component_ordinal": component_index,
                    "reason_code": "SUPPORT_BEARING_COMPONENT_HAS_NO_AUTHORITY",
                }
            )
        for authority_index, authority in enumerate(authorities, start=1):
            if support_fit in {"FULL", "PARTIAL"}:
                metadata = _metadata_completeness(authority)
            else:
                metadata = {
                    "status": "NOT_REQUIRED_FOR_EXPLICIT_NONE_COMPONENT",
                    "metadata_mode": "NOT_REQUIRED",
                    "exact_locators_complete": None,
                    "reason_codes": [],
                }
            candidate = _authority_candidate_crosscheck(
                authority=authority, candidate_index=candidate_index
            )
            authority_identity, identity_hold_reasons = source_collector._authority_identity(
                authority
            )
            collector_key = "identity:" + source_collector.proposal_identity_key(authority_identity)
            collector_plan = (
                collector_plans_by_identity.get(collector_key)
                if collector_plans_by_identity is not None
                else None
            )
            collector_reason_codes: list[str] = []
            if collector_plans_by_identity is not None:
                if collector_plan is None:
                    collector_reason_codes.append("COLLECTOR_AUTHORITY_PLAN_MISSING")
                elif collector_plan.get("disposition") == "HOLD_NO_FETCH":
                    collector_reason_codes.extend(
                        str(item) for item in collector_plan.get("hold_reason_codes") or []
                    )
                    collector_reason_codes.append("COLLECTOR_FETCH_ELIGIBILITY_HOLD")
            hold_reasons = sorted(
                set(metadata["reason_codes"])
                | set(candidate["reason_codes"])
                | set(identity_hold_reasons)
                | set(collector_reason_codes)
            )
            if _known_composite_authority_present(
                row_id=str(record["row_id"]),
                component_ordinal=component_index,
                authority_ordinal=authority_index,
                authority=authority,
            ):
                hold_reasons = sorted(
                    {*hold_reasons, "COMPOSITE_AUTHORITY_IDENTITY_REQUIRES_SPLIT"}
                )
            material = {
                "component_ordinal": component_index,
                "authority_ordinal": authority_index,
                "authority_content_sha256": _sealed(authority),
                "support_fit": support_fit,
                "canonical_authority_identity_id": authority_identity,
                "authority_identity_hold_reason_codes": list(identity_hold_reasons),
                "collector_plan_crosscheck": (
                    {
                        "identity_key": collector_key,
                        "plan_id": collector_plan["plan_id"],
                        "plan_content_sha256": collector_plan["plan_content_sha256"],
                        "disposition": collector_plan["disposition"],
                        "hold_reason_codes": copy.deepcopy(collector_plan["hold_reason_codes"]),
                        "fetch_eligible": (
                            collector_plan["disposition"] == "FETCH_ABSENT_FALSE_TRUE"
                        ),
                    }
                    if collector_plan is not None
                    else {
                        "identity_key": collector_key,
                        "plan_id": None,
                        "plan_content_sha256": None,
                        "disposition": None,
                        "hold_reason_codes": collector_reason_codes,
                        "fetch_eligible": None,
                    }
                ),
                "metadata_completeness": metadata,
                "candidate_crosscheck": candidate,
                "hold_reason_codes": hold_reasons,
                "adoption_eligible": not hold_reasons,
                "new_source_admission_proposal_eligible": (
                    not hold_reasons
                    and metadata["status"] == "COMPLETE"
                    and candidate["verified_new_source"] is True
                    and support_fit in {"FULL", "PARTIAL"}
                ),
            }
            assessments.append({**material, "assessment_content_sha256": _sealed(material)})
    return assessments, component_holds


def _wave_recommendation(
    record: Mapping[str, Any],
    assessments: Sequence[Mapping[str, Any]],
    component_holds: Sequence[Mapping[str, Any]],
) -> str:
    components = record.get("atomic_components")
    holds = record.get("unresolved_holds")
    if not isinstance(components, list) or not components:
        raise ValueError("phase2a_exact_packet_wave_components_invalid")
    support_fits = {str(component.get("support_fit") or "") for component in components}
    if support_fits == {"NONE"}:
        return "RETAIN_MATERIAL_HOLD_NO_SUPPORTED_OFFICIAL_PROPOSITION"
    if (
        holds
        or support_fits - {"FULL"}
        or component_holds
        or any(not assessment["adoption_eligible"] for assessment in assessments)
    ):
        return "ADOPT_ONLY_LISTED_SUPPORTED_COMPONENTS_AND_RETAIN_ALL_LISTED_HOLDS"
    return "ADOPT_LISTED_ATOMIC_COMPONENTS_AND_OFFICIAL_SOURCE_LOCATORS"


def _research_decision(
    *,
    record: Mapping[str, Any],
    queue_record: Mapping[str, Any],
    wave_binding: BoundArtifact,
    candidate_index: CandidateIndex,
    collector_plans_by_identity: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    assessments, component_holds = _authority_assessments(
        record=record,
        candidate_index=candidate_index,
        collector_plans_by_identity=collector_plans_by_identity,
    )
    material = {
        "decision_class": "OFFICIAL_RESEARCH_RECOMMENDATION",
        "row_id": record["row_id"],
        "recommended_owner_outcome": _wave_recommendation(record, assessments, component_holds),
        "source_queue_record": copy.deepcopy(dict(queue_record)),
        "source_research_record": copy.deepcopy(dict(record)),
        "authority_assessments": assessments,
        "component_completeness_holds": component_holds,
        "source_wave_reference": {
            "path": _portable_path(wave_binding.path),
            "content_sha256": wave_binding.content_sha256,
            "file_sha256": wave_binding.file_sha256,
        },
        "owner_decision_required": True,
        "owner_outcome": None,
        "source_admission_authorized": False,
        "source_admitted": False,
        "candidate_mutated": False,
        "technical_qualification_assigned": False,
    }
    return {**material, "decision_content_sha256": _sealed(material)}


def _direct_decision(
    *,
    record: Mapping[str, Any],
    direct_binding: BoundArtifact,
    candidate_index: CandidateIndex,
) -> dict[str, Any]:
    span_crosschecks: list[dict[str, Any]] = []
    for span in record["selected_local_evidence"]:
        if not isinstance(span, Mapping):
            raise ValueError("phase2a_exact_packet_direct_exact_span_invalid")
        version_id = str(span.get("source_version_id") or "")
        source = candidate_index.by_version.get(version_id)
        if source is None:
            raise ValueError("phase2a_exact_packet_direct_candidate_source_version_unresolved")
        if source.get("authority_identity_id") != span.get("authority_identity_id"):
            raise ValueError("phase2a_exact_packet_direct_candidate_authority_identity_mismatch")
        span_reference = span.get("span_id") or span.get("exact_span_id") or span.get("chunk_id")
        if not str(span_reference or "").strip() or not str(span.get("locator") or "").strip():
            raise ValueError("phase2a_exact_packet_direct_exact_span_invalid")
        span_crosschecks.append(
            {
                "span_reference": span_reference,
                "source_version_id": version_id,
                "authority_identity_id": span["authority_identity_id"],
                "candidate_source_resolved": True,
            }
        )
    material = {
        "decision_class": "DIRECT_EXACT_LOCAL_SPAN_RECOMMENDATION",
        "row_id": record["row_id"],
        "recommended_owner_outcome": record["recommended_owner_outcome"],
        "source_direct_record": copy.deepcopy(dict(record)),
        "candidate_span_crosschecks": span_crosschecks,
        "source_direct_reference": {
            "path": _portable_path(direct_binding.path),
            "content_sha256": direct_binding.content_sha256,
            "file_sha256": direct_binding.file_sha256,
        },
        "owner_decision_required": True,
        "owner_outcome": None,
        "source_admission_authorized": False,
        "source_admitted": False,
        "candidate_mutated": False,
        "technical_qualification_assigned": False,
    }
    return {**material, "decision_content_sha256": _sealed(material)}


def _canonical_source_key(url: str) -> str:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").casefold()
    path = parsed.path.rstrip("/") or "/"
    if host in {"www.legislation.gov.uk", "legislation.gov.uk"}:
        parts = [part for part in path.split("/") if part]
        if parts and parts[0] == "id":
            parts = parts[1:]
        if len(parts) >= 3:
            identity_length = 3 if re.fullmatch(r"\d{4}", parts[1]) else 4
            if len(parts) >= identity_length:
                path = "/" + "/".join(parts[:identity_length])
        host = "www.legislation.gov.uk"
        return urlunsplit(("https", host, path, "", ""))
    if host == "caselaw.nationalarchives.gov.uk" and path.endswith("/data.xml"):
        path = path[: -len("/data.xml")]
    return urlunsplit(("https", host, path, parsed.query, ""))


def _source_admission_proposals(
    decisions: Sequence[Mapping[str, Any]],
    *,
    eligible_identity_keys: Collection[str],
) -> list[dict[str, Any]]:
    expected_identity_keys = frozenset(str(item) for item in eligible_identity_keys)
    if any(not item.startswith("identity:") for item in expected_identity_keys):
        raise ValueError("phase2a_exact_packet_proposal_identity_key_invalid")
    grouped: dict[str, list[dict[str, Any]]] = {}
    independently_eligible_use_counts: Counter[str] = Counter()
    for decision in decisions:
        if decision.get("decision_class") != "OFFICIAL_RESEARCH_RECOMMENDATION":
            continue
        record = decision["source_research_record"]
        assessment_by_ordinal = {
            (item["component_ordinal"], item["authority_ordinal"]): item
            for item in decision["authority_assessments"]
        }
        for component_index, component in enumerate(record["atomic_components"], start=1):
            for authority_index, authority in enumerate(component.get("authorities", []), start=1):
                assessment = assessment_by_ordinal[(component_index, authority_index)]
                collector_crosscheck = assessment.get("collector_plan_crosscheck")
                if not isinstance(collector_crosscheck, Mapping):
                    raise ValueError("phase2a_exact_packet_collector_plan_crosscheck_missing")
                key = str(collector_crosscheck.get("identity_key") or "")
                if key not in expected_identity_keys:
                    continue
                url = authority.get("official_url")
                if not isinstance(url, str) or not url:
                    raise ValueError("phase2a_exact_packet_admission_url_missing")
                if _canonical_authority_identity_key(authority) != key:
                    raise ValueError(
                        "phase2a_exact_packet_collector_builder_authority_identity_mismatch"
                    )
                admission_support_eligible = (
                    assessment["new_source_admission_proposal_eligible"] is True
                )
                if admission_support_eligible:
                    independently_eligible_use_counts[key] += 1
                grouped.setdefault(key, []).append(
                    {
                        "row_id": decision["row_id"],
                        "source_wave_reference": copy.deepcopy(decision["source_wave_reference"]),
                        "component_ordinal": component_index,
                        "authority_ordinal": authority_index,
                        "atomic_proposition": component["proposition"],
                        "support_fit": component["support_fit"],
                        "authority": copy.deepcopy(dict(authority)),
                        "metadata_completeness": copy.deepcopy(assessment["metadata_completeness"]),
                        "candidate_crosscheck": copy.deepcopy(assessment["candidate_crosscheck"]),
                        "collector_plan_crosscheck": copy.deepcopy(collector_crosscheck),
                        "admission_support_eligible": admission_support_eligible,
                        "retained_hold_reason_codes": copy.deepcopy(
                            assessment["hold_reason_codes"]
                        ),
                    }
                )
    if set(grouped) != set(expected_identity_keys) or any(
        independently_eligible_use_counts[key] < 1 for key in expected_identity_keys
    ):
        raise ValueError("phase2a_exact_packet_collector_builder_proposal_identity_set_mismatch")
    proposals: list[dict[str, Any]] = []
    for canonical_key, uses in sorted(grouped.items()):
        uses.sort(
            key=lambda use: (
                _row_sort_key(str(use["row_id"])),
                int(use["component_ordinal"]),
                int(use["authority_ordinal"]),
                str(use["source_wave_reference"]["path"]),
            )
        )
        authorities = [use["authority"] for use in uses]
        candidate_states = ["False"]
        admission_states = ["True"]
        material = {
            "proposal_id": f"proposed-source-{_sha256(canonical_key.encode())[:24]}",
            "canonical_authority_identity_key": canonical_key,
            "canonical_source_keys": sorted(
                {_canonical_source_key(str(authority["official_url"])) for authority in authorities}
            ),
            "official_urls": sorted({str(authority["official_url"]) for authority in authorities}),
            "titles": sorted(
                {
                    str(authority.get("title") or "")
                    for authority in authorities
                    if authority.get("title")
                }
            ),
            "citations": sorted(
                {
                    str(authority.get("citation") or "")
                    for authority in authorities
                    if authority.get("citation")
                }
            ),
            "affected_row_ids": sorted({str(use["row_id"]) for use in uses}, key=_row_sort_key),
            "candidate_existing_states": candidate_states,
            "source_admission_required_states": admission_states,
            "uses": uses,
            "exact_wave_use_count": len(uses),
            "independently_eligible_support_use_count": (
                independently_eligible_use_counts[canonical_key]
            ),
            "recommended_owner_outcome": (
                "ADMIT_PROPOSITION_LEVEL_OFFICIAL_SOURCE_WITH_ALL_LISTED_HOLDS_RETAINED"
            ),
            "owner_source_admission_required": True,
            "owner_outcome": None,
            "source_admission_authorized": False,
            "source_admitted": False,
            "automatic_indexing": False,
            "automatic_embedding": False,
            "candidate_mutated": False,
        }
        proposals.append({**material, "proposal_content_sha256": _sealed(material)})
    return proposals


def _source_identity_anomalies(
    decisions: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Seal every incomplete authority/component as an explicit retained hold."""

    anomalies: list[dict[str, Any]] = []
    for decision in decisions:
        if decision.get("decision_class") != "OFFICIAL_RESEARCH_RECOMMENDATION":
            continue
        record = decision["source_research_record"]
        components = record["atomic_components"]
        for assessment in decision["authority_assessments"]:
            reasons = assessment["hold_reason_codes"]
            if not reasons:
                continue
            component_index = int(assessment["component_ordinal"])
            authority_index = int(assessment["authority_ordinal"])
            component = components[component_index - 1]
            authority = component["authorities"][authority_index - 1]
            material = {
                "anomaly_id": (
                    "source-identity-hold-"
                    + _sha256(
                        _canonical_json(
                            {
                                "row_id": decision["row_id"],
                                "component_ordinal": component_index,
                                "authority_ordinal": authority_index,
                                "reasons": reasons,
                            }
                        )
                    )[:24]
                ),
                "row_id": decision["row_id"],
                "source_wave_reference": copy.deepcopy(decision["source_wave_reference"]),
                "component_ordinal": component_index,
                "authority_ordinal": authority_index,
                "atomic_proposition": component["proposition"],
                "support_fit": component["support_fit"],
                "authority": copy.deepcopy(dict(authority)),
                "authority_assessment": copy.deepcopy(dict(assessment)),
                "hold_reason_codes": reasons,
                "recommended_owner_outcome": (
                    "RETAIN_TECHNICAL_SOURCE_IDENTITY_METADATA_OR_ADMISSION_HOLD"
                ),
                "owner_outcome": None,
                "source_admission_authorized": False,
                "source_admitted": False,
                "automatic_indexing": False,
                "automatic_embedding": False,
                "candidate_mutated": False,
            }
            anomalies.append({**material, "anomaly_content_sha256": _sealed(material)})
        for hold in decision["component_completeness_holds"]:
            component_index = int(hold["component_ordinal"])
            component = components[component_index - 1]
            reasons = [str(hold["reason_code"])]
            material = {
                "anomaly_id": (
                    "component-completeness-hold-"
                    + _sha256(
                        _canonical_json(
                            {
                                "row_id": decision["row_id"],
                                "component_ordinal": component_index,
                                "reasons": reasons,
                            }
                        )
                    )[:24]
                ),
                "row_id": decision["row_id"],
                "source_wave_reference": copy.deepcopy(decision["source_wave_reference"]),
                "component_ordinal": component_index,
                "authority_ordinal": None,
                "atomic_proposition": component["proposition"],
                "support_fit": component["support_fit"],
                "authority": None,
                "authority_assessment": None,
                "hold_reason_codes": reasons,
                "recommended_owner_outcome": (
                    "RETAIN_SUPPORT_BEARING_COMPONENT_AUTHORITY_COMPLETENESS_HOLD"
                ),
                "owner_outcome": None,
                "source_admission_authorized": False,
                "source_admitted": False,
                "automatic_indexing": False,
                "automatic_embedding": False,
                "candidate_mutated": False,
            }
            anomalies.append({**material, "anomaly_content_sha256": _sealed(material)})
    return sorted(
        anomalies,
        key=lambda item: (
            _row_sort_key(str(item["row_id"])),
            int(item["component_ordinal"]),
            int(item["authority_ordinal"] or 0),
        ),
    )


_COLLECTOR_BINDING_FIELDS = (
    "record_id",
    "record_content_sha256",
    "authority_identity_id",
    "representation_role",
    "selected_for_proposed_admission",
    "authority_representation_set_complete",
    "eligible_for_owner_packet",
    "raw_sha256",
    "canonical_content_sha256",
    "content_type",
    "bytes",
    "final_url",
    "quarantine_member",
    "proposed_source_version_id",
    "exact_locators",
    "affected_row_ids",
)
_COLLECTOR_DERIVED_BINDING_FIELDS = frozenset(
    {"authority_representation_set_complete", "eligible_for_owner_packet"}
)
_COLLECTOR_RECORD_BINDING_FIELDS = tuple(
    field for field in _COLLECTOR_BINDING_FIELDS if field not in _COLLECTOR_DERIVED_BINDING_FIELDS
)
_COLLECTOR_FALSE_FIELDS = (
    "owner_decisions_applied",
    "source_admission_authorized",
    "source_admitted",
    "catalogue_mutated",
    "source_scan_run",
    "candidate_mutated",
    "index_built",
    "automatic_indexing",
    "embedding_run",
    "automatic_embedding",
    "technical_qualification_assigned",
    "promotion_authorized",
    "active_pointer_write_authorized",
    "previous_pointer_write_authorized",
    "phase2b_authorized",
    "development30_authorized",
    "validation30_authorized",
    "live_activation_authorized",
    "training_export_authorized",
)


def _collector_identity_key(value: Any) -> str:
    identity = str(value or "").strip()
    if not identity:
        raise ValueError("phase2a_exact_packet_quarantine_authority_identity_missing")
    return "identity:" + source_collector.proposal_identity_key(identity)


def _verify_manifest_seal(
    value: Mapping[str, Any],
    binding: BoundArtifact,
) -> None:
    material = dict(value)
    supplied = str(material.pop("manifest_content_sha256", ""))
    if supplied != binding.content_sha256 or supplied != _sealed(material):
        raise ValueError("phase2a_exact_packet_quarantine_manifest_content_digest_invalid")


def _verify_collector_input_bindings(
    value: Mapping[str, Any],
    *,
    queue_binding: BoundArtifact,
    candidate_binding: BoundArtifact,
    canonical_set_binding: BoundArtifact,
    wave_bindings: Sequence[BoundArtifact],
) -> None:
    queue_reference = value.get("queue_binding")
    candidate_reference = value.get("candidate_binding")
    wave_references = value.get("wave_bindings")
    canonical_set_reference = value.get("canonical_wave_set_binding")
    if (
        not isinstance(queue_reference, Mapping)
        or queue_reference.get("file_name") != queue_binding.path.name
        or queue_reference.get("content_sha256") != queue_binding.content_sha256
        or queue_reference.get("file_sha256") != queue_binding.file_sha256
        or queue_reference.get("row_count") != 316
        or not isinstance(candidate_reference, Mapping)
        or candidate_reference.get("file_name") != candidate_binding.path.name
        or candidate_reference.get("content_sha256") != candidate_binding.content_sha256
        or candidate_reference.get("file_sha256") != candidate_binding.file_sha256
        or candidate_reference.get("source_count") != 251
        or not isinstance(canonical_set_reference, Mapping)
        or canonical_set_reference.get("file_name") != canonical_set_binding.path.name
        or canonical_set_reference.get("content_sha256") != canonical_set_binding.content_sha256
        or canonical_set_reference.get("file_sha256") != canonical_set_binding.file_sha256
        or canonical_set_reference.get("wave_count") != EXPECTED_CANONICAL_WAVE_COUNT
        or not isinstance(wave_references, list)
    ):
        raise ValueError("phase2a_exact_packet_quarantine_input_binding_mismatch")
    expected_waves = [
        {
            "file_name": binding.path.name,
            "content_sha256": binding.content_sha256,
            "file_sha256": binding.file_sha256,
        }
        for binding in sorted(wave_bindings, key=lambda item: item.path.name)
    ]
    actual_waves = [
        {
            "file_name": item.get("file_name"),
            "content_sha256": item.get("content_sha256"),
            "file_sha256": item.get("file_sha256"),
        }
        for item in wave_references
        if isinstance(item, Mapping)
    ]
    if actual_waves != expected_waves or len(actual_waves) != len(wave_references):
        raise ValueError("phase2a_exact_packet_quarantine_wave_binding_mismatch")


def _verify_collector_record(record: Any) -> dict[str, Any]:
    if not isinstance(record, Mapping):
        raise ValueError("phase2a_exact_packet_quarantine_record_invalid")
    _verify_record_seal(record, role="quarantine")
    record_id = str(record.get("record_id") or "")
    if (
        not record_id
        or record.get("owner_decision_applied") is not False
        or record.get("source_admission_authorized") is not False
        or record.get("source_admitted") is not False
        or record.get("catalogue_mutated") is not False
        or record.get("candidate_mutated") is not False
        or record.get("automatic_indexing") is not False
        or record.get("automatic_embedding") is not False
    ):
        raise ValueError("phase2a_exact_packet_quarantine_record_invalid")
    return copy.deepcopy(dict(record))


def _verify_collector_binding(
    item: Any,
    *,
    records_by_id: Mapping[str, Mapping[str, Any]],
    manifest_binding: BoundArtifact,
) -> dict[str, Any]:
    if not isinstance(item, Mapping):
        raise ValueError("phase2a_exact_packet_quarantine_representation_binding_invalid")
    if set(item) != set(_COLLECTOR_BINDING_FIELDS):
        raise ValueError("phase2a_exact_packet_quarantine_representation_binding_invalid")
    record_id = str(item.get("record_id") or "")
    record = records_by_id.get(record_id)
    if record is None or any(
        record.get(field) != item.get(field) for field in _COLLECTOR_RECORD_BINDING_FIELDS
    ):
        raise ValueError("phase2a_exact_packet_quarantine_representation_record_mismatch")
    representation_set_complete = item.get("authority_representation_set_complete")
    eligible_for_owner_packet = item.get("eligible_for_owner_packet")
    selected_for_admission = item.get("selected_for_proposed_admission")
    if (
        representation_set_complete not in {True, False}
        or eligible_for_owner_packet not in {True, False}
        or eligible_for_owner_packet
        is not (selected_for_admission is True and representation_set_complete is True)
    ):
        raise ValueError("phase2a_exact_packet_quarantine_representation_eligibility_invalid")
    raw_sha256 = str(item.get("raw_sha256") or "")
    canonical_content_value = item.get("canonical_content_sha256")
    _validate_digest(
        raw_sha256,
        error="phase2a_exact_packet_representation_raw_digest_invalid",
    )
    if canonical_content_value is None:
        if record.get("canonicalization_algorithm") != (
            "RAW_BYTES_ONLY_MEDIA_TYPE_NOT_CANONICALIZED"
        ):
            raise ValueError("phase2a_exact_packet_representation_content_identity_invalid")
    else:
        _validate_digest(
            str(canonical_content_value),
            error="phase2a_exact_packet_representation_content_identity_invalid",
        )
    member = str(item.get("quarantine_member") or "")
    if (
        not member
        or Path(member).name != member
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{1,200}", member) is None
    ):
        raise ValueError("phase2a_exact_packet_representation_member_invalid")
    representation_path = manifest_binding.path.parent / member
    if representation_path.is_symlink() or not representation_path.is_file():
        raise ValueError("phase2a_exact_packet_representation_member_missing")
    raw = representation_path.read_bytes()
    if _sha256(raw) != raw_sha256 or len(raw) != item.get("bytes"):
        raise ValueError("phase2a_exact_packet_representation_raw_digest_invalid")
    calculated_content_identity, calculated_algorithm, canonicalization_holds = (
        source_collector._canonical_content(
            raw,
            content_type=str(item.get("content_type") or "").casefold(),
        )
    )
    if (
        canonicalization_holds
        or calculated_content_identity != canonical_content_value
        or calculated_algorithm != record.get("canonicalization_algorithm")
    ):
        raise ValueError("phase2a_exact_packet_representation_content_identity_invalid")
    if record.get("result") != "DOWNLOADED_QUARANTINED_BOUND" or record.get(
        "hold_reason_codes"
    ) not in ([], ()):
        raise ValueError("phase2a_exact_packet_quarantine_representation_held")
    selected = item.get("selected_for_proposed_admission") is True
    version_id = item.get("proposed_source_version_id")
    if selected:
        version_material = {
            "authority_identity_id": item.get("authority_identity_id"),
            "raw_sha256": raw_sha256,
            "canonical_content_sha256": canonical_content_value,
        }
        expected_version_id = "proposed-source-version-" + _sealed(version_material)[:40]
        if (
            item.get("representation_role") != "PROPOSED_ADMISSION_REPRESENTATION"
            or _PROPOSED_SOURCE_VERSION_ID.fullmatch(str(version_id or "")) is None
            or version_id != expected_version_id
        ):
            raise ValueError("phase2a_exact_packet_proposed_source_version_identity_invalid")
    elif (
        item.get("representation_role") != "CORROBORATING_ALIAS_REPRESENTATION"
        or version_id is not None
    ):
        raise ValueError("phase2a_exact_packet_corroborating_alias_boundary_invalid")
    return copy.deepcopy(dict(item))


def _load_representation_bindings(
    binding: BoundArtifact,
    *,
    queue_binding: BoundArtifact,
    candidate_binding: BoundArtifact,
    canonical_set_binding: BoundArtifact,
    wave_bindings: Sequence[BoundArtifact],
    expected_fetch_identity_keys: Sequence[str],
    expected_fetch_identity_set_sha256: str,
) -> tuple[
    dict[str, Any],
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
    dict[str, list[dict[str, Any]]],
    dict[str, list[dict[str, Any]]],
]:
    value = _load_json_file(binding, role="quarantine_manifest")
    _verify_manifest_seal(value, binding)
    records = value.get("records")
    interface = value.get("packet_builder_interface")
    expected_fetch_keys = tuple(expected_fetch_identity_keys)
    expected_unprefixed_fetch_keys = [
        item.removeprefix("identity:") for item in expected_fetch_keys
    ]
    if (
        value.get("schema") != REPRESENTATION_BINDING_SCHEMA
        or value.get("status") != "QUARANTINE_BINDINGS_CREATED_NOT_ADMITTED"
        or value.get("source_ceiling_date") != source_collector.TARGET_DATE.isoformat()
        or not isinstance(records, list)
        or value.get("collection_record_count") != len(records)
        or value.get("fetch_eligible_identity_count") != len(expected_fetch_keys)
        or value.get("fetch_eligible_identity_set_sha256") != expected_fetch_identity_set_sha256
        or value.get("advisory_only") is not True
        or any(value.get(field) is not False for field in _COLLECTOR_FALSE_FIELDS)
        or not isinstance(interface, Mapping)
        or interface.get("schema") != PACKET_BUILDER_INTERFACE_SCHEMA
        or interface.get("manifest_digest_field") != "manifest_content_sha256"
        or interface.get("record_digest_field") != "record_content_sha256"
        or interface.get("owner_must_adopt_exact_packet_before_admission") is not True
        or interface.get("owner_decisions_applied") is not False
        or interface.get("source_admission_authorized") is not False
        or interface.get("source_admitted") is not False
        or interface.get("candidate_mutated") is not False
        or interface.get("fetch_eligible_authority_identity_keys") != expected_unprefixed_fetch_keys
        or interface.get("fetch_eligible_authority_identity_set_sha256")
        != expected_fetch_identity_set_sha256
    ):
        raise ValueError("phase2a_exact_packet_quarantine_manifest_boundary_invalid")
    wave_validation = value.get("wave_validation")
    if not isinstance(wave_validation, Mapping) or (
        wave_validation.get("status"),
        wave_validation.get("covered_row_count"),
        wave_validation.get("missing_row_count"),
    ) != ("PASS_COMPLETE", 316, 0):
        raise ValueError("phase2a_exact_packet_quarantine_wave_validation_invalid")
    _verify_collector_input_bindings(
        value,
        queue_binding=queue_binding,
        candidate_binding=candidate_binding,
        canonical_set_binding=canonical_set_binding,
        wave_bindings=wave_bindings,
    )

    records_by_id: dict[str, dict[str, Any]] = {}
    for raw_record in records:
        record = _verify_collector_record(raw_record)
        record_id = str(record["record_id"])
        if record_id in records_by_id:
            raise ValueError("phase2a_exact_packet_quarantine_record_duplicate")
        records_by_id[record_id] = record

    representation_items = value.get("representation_bindings")
    selected_items = value.get("selected_admission_bindings")
    held_selected_items = value.get("held_selected_bindings")
    corroborating_items = value.get("corroborating_alias_bindings")
    if not all(
        isinstance(items, list)
        for items in (
            representation_items,
            selected_items,
            held_selected_items,
            corroborating_items,
        )
    ):
        raise ValueError("phase2a_exact_packet_quarantine_binding_lists_invalid")
    verified_all = [
        _verify_collector_binding(
            item,
            records_by_id=records_by_id,
            manifest_binding=binding,
        )
        for item in representation_items
    ]
    all_by_id = {str(item["record_id"]): item for item in verified_all}
    if len(all_by_id) != len(verified_all):
        raise ValueError("phase2a_exact_packet_quarantine_binding_duplicate")
    selected_ids = [str(item.get("record_id") or "") for item in selected_items]
    held_selected_ids = [str(item.get("record_id") or "") for item in held_selected_items]
    corroborating_ids = [str(item.get("record_id") or "") for item in corroborating_items]
    if (
        selected_ids != interface.get("selected_admission_record_ids")
        or selected_ids != interface.get("eligible_representation_record_ids")
        or held_selected_ids != interface.get("held_selected_record_ids")
        or corroborating_ids != interface.get("corroborating_alias_record_ids")
        or len(set(selected_ids + held_selected_ids + corroborating_ids))
        != len(selected_ids + held_selected_ids + corroborating_ids)
        or set(selected_ids + held_selected_ids + corroborating_ids) != set(all_by_id)
    ):
        raise ValueError("phase2a_exact_packet_quarantine_interface_id_mismatch")
    selected = [all_by_id[item] for item in selected_ids]
    held_selected = [all_by_id[item] for item in held_selected_ids]
    corroborating = [all_by_id[item] for item in corroborating_ids]
    if (
        any(item.get("selected_for_proposed_admission") is not True for item in selected)
        or any(item.get("authority_representation_set_complete") is not True for item in selected)
        or any(item.get("eligible_for_owner_packet") is not True for item in selected)
        or any(item.get("selected_for_proposed_admission") is not True for item in held_selected)
        or any(
            item.get("authority_representation_set_complete") is not False for item in held_selected
        )
        or any(item.get("eligible_for_owner_packet") is not False for item in held_selected)
        or any(item.get("selected_for_proposed_admission") is not False for item in corroborating)
        or any(item.get("eligible_for_owner_packet") is not False for item in corroborating)
        or selected != selected_items
        or held_selected != held_selected_items
        or corroborating != corroborating_items
        or value.get("held_selected_binding_count") != len(held_selected)
    ):
        raise ValueError("phase2a_exact_packet_quarantine_selection_boundary_invalid")

    selected_by_key: dict[str, dict[str, Any]] = {}
    selected_version_ids: set[str] = set()
    for item in selected:
        key = _collector_identity_key(item["authority_identity_id"])
        version_id = str(item["proposed_source_version_id"])
        if key in selected_by_key or version_id in selected_version_ids:
            raise ValueError("phase2a_exact_packet_quarantine_selected_identity_duplicate")
        selected_by_key[key] = item
        selected_version_ids.add(version_id)

    held_selected_by_key: dict[str, dict[str, Any]] = {}
    for item in held_selected:
        key = _collector_identity_key(item["authority_identity_id"])
        if key in held_selected_by_key or key in selected_by_key:
            raise ValueError("phase2a_exact_packet_quarantine_held_selected_identity_duplicate")
        held_selected_by_key[key] = item

    corroborating_by_key: dict[str, list[dict[str, Any]]] = {}
    for item in corroborating:
        key = _collector_identity_key(item["authority_identity_id"])
        corroborating_by_key.setdefault(key, []).append(item)
    for items in corroborating_by_key.values():
        items.sort(key=lambda item: (str(item["record_id"]), str(item["final_url"])))

    comparisons_by_key: dict[str, list[dict[str, Any]]] = {}
    comparisons = value.get("representation_comparisons")
    if not isinstance(comparisons, list):
        raise ValueError("phase2a_exact_packet_representation_comparisons_invalid")
    for comparison in comparisons:
        if not isinstance(comparison, Mapping):
            raise ValueError("phase2a_exact_packet_representation_comparison_invalid")
        material = dict(comparison)
        supplied = str(material.pop("comparison_content_sha256", ""))
        if (
            supplied != _sealed(material)
            or comparison.get("representation_equivalence_assumed") is not False
            or comparison.get("corroborating_alias_selected_for_admission") is not False
            or str(comparison.get("corroborating_record_id") or "") not in records_by_id
            or (
                comparison.get("selected_record_id") is not None
                and str(comparison.get("selected_record_id")) not in records_by_id
            )
        ):
            raise ValueError("phase2a_exact_packet_representation_comparison_invalid")
        key = _collector_identity_key(comparison.get("authority_identity_id"))
        corroborating_record = records_by_id[str(comparison["corroborating_record_id"])]
        selected_record = (
            records_by_id[str(comparison["selected_record_id"])]
            if comparison.get("selected_record_id") is not None
            else None
        )
        if (
            _collector_identity_key(corroborating_record["authority_identity_id"]) != key
            or (
                selected_record is not None
                and (
                    _collector_identity_key(selected_record["authority_identity_id"]) != key
                    or selected_record.get("selected_for_proposed_admission") is not True
                )
            )
            or corroborating_record.get("selected_for_proposed_admission") is not False
        ):
            raise ValueError("phase2a_exact_packet_representation_comparison_identity_invalid")
        comparisons_by_key.setdefault(key, []).append(copy.deepcopy(dict(comparison)))
    for items in comparisons_by_key.values():
        items.sort(key=lambda item: str(item["corroborating_record_id"]))

    authority_plans = value.get("authority_plans")
    preflight_holds = value.get("preflight_holds")
    collection_holds = value.get("collection_holds")
    if not all(
        isinstance(items, list) for items in (authority_plans, preflight_holds, collection_holds)
    ):
        raise ValueError("phase2a_exact_packet_quarantine_hold_lists_invalid")
    plans_by_id: dict[str, dict[str, Any]] = {}
    for plan in authority_plans:
        if not isinstance(plan, Mapping):
            raise ValueError("phase2a_exact_packet_quarantine_authority_plan_invalid")
        material = dict(plan)
        supplied = str(material.pop("plan_content_sha256", ""))
        plan_id = str(plan.get("plan_id") or "")
        if not plan_id or plan_id in plans_by_id or supplied != _sealed(material):
            raise ValueError("phase2a_exact_packet_quarantine_authority_plan_invalid")
        plans_by_id[plan_id] = copy.deepcopy(dict(plan))
    preflight_identities: set[str] = set()
    for hold in preflight_holds:
        if not isinstance(hold, Mapping):
            raise ValueError("phase2a_exact_packet_quarantine_preflight_hold_invalid")
        plan = plans_by_id.get(str(hold.get("plan_id") or ""))
        if (
            plan is None
            or hold.get("plan_content_sha256") != plan["plan_content_sha256"]
            or hold.get("authority_identity_id") != plan["authority_identity_id"]
            or not hold.get("hold_reason_codes")
        ):
            raise ValueError("phase2a_exact_packet_quarantine_preflight_hold_invalid")
        preflight_identities.add(str(hold["authority_identity_id"]))
    collection_hold_identities: set[str] = set()
    authority_collection_holds: list[dict[str, Any]] = []
    authority_collection_holds_by_key: dict[str, dict[str, Any]] = {}
    representation_collection_holds_by_record_id: dict[str, dict[str, Any]] = {}
    for hold in collection_holds:
        if not isinstance(hold, Mapping):
            raise ValueError("phase2a_exact_packet_quarantine_collection_hold_invalid")
        hold_type = hold.get("hold_type")
        if hold_type == "REPRESENTATION_COLLECTION_HOLD":
            record_id = str(hold.get("record_id") or "")
            record = records_by_id.get(record_id)
            valid = (
                record is not None
                and record_id not in representation_collection_holds_by_record_id
                and hold.get("record_content_sha256") == record["record_content_sha256"]
                and hold.get("authority_identity_id") == record["authority_identity_id"]
                and hold.get("hold_reason_codes") == record["hold_reason_codes"]
                and bool(hold.get("hold_reason_codes"))
                and record.get("result") != "DOWNLOADED_QUARANTINED_BOUND"
            )
            if valid:
                representation_collection_holds_by_record_id[record_id] = copy.deepcopy(dict(hold))
        elif hold_type == "AUTHORITY_REPRESENTATION_SET_INCOMPLETE":
            material = dict(hold)
            supplied = str(material.pop("hold_content_sha256", ""))
            failed_ids = hold.get("failed_record_ids")
            failed_digests = hold.get("failed_record_content_sha256s")
            selected_id = hold.get("selected_record_id")
            selected_record = (
                records_by_id.get(str(selected_id)) if selected_id is not None else None
            )
            authority_identity_id = str(hold.get("authority_identity_id") or "")
            key = _collector_identity_key(authority_identity_id)
            failed_records = (
                [records_by_id.get(str(record_id)) for record_id in failed_ids]
                if isinstance(failed_ids, list)
                else []
            )
            expected_failed_record_ids = sorted(
                record_id
                for record_id, record in records_by_id.items()
                if record.get("authority_identity_id") == authority_identity_id
                and record.get("result") != "DOWNLOADED_QUARANTINED_BOUND"
            )
            valid = (
                supplied == _sealed(material)
                and isinstance(failed_ids, list)
                and isinstance(failed_digests, list)
                and bool(failed_ids)
                and failed_ids == expected_failed_record_ids
                and all(record is not None for record in failed_records)
                and sorted(record["record_content_sha256"] for record in failed_records)
                == failed_digests
                and len(failed_ids) == len(failed_digests)
                and selected_record is not None
                and selected_record.get("selected_for_proposed_admission") is True
                and selected_record.get("authority_identity_id") == authority_identity_id
                and hold.get("selected_record_content_sha256")
                == selected_record["record_content_sha256"]
                and hold.get("selected_proposed_source_version_id")
                == selected_record["proposed_source_version_id"]
                and all(
                    record.get("authority_identity_id") == authority_identity_id
                    and record.get("result") != "DOWNLOADED_QUARANTINED_BOUND"
                    and bool(record.get("hold_reason_codes"))
                    for record in failed_records
                )
                and hold.get("selected_binding_eligible") is False
                and bool(hold.get("hold_reason_codes"))
                and key not in authority_collection_holds_by_key
            )
            if valid:
                sealed_hold = copy.deepcopy(dict(hold))
                authority_collection_holds.append(sealed_hold)
                authority_collection_holds_by_key[key] = sealed_hold
        else:
            valid = False
        if (
            not valid
            or hold.get("owner_decision_applied") is not False
            or hold.get("source_admission_authorized") is not False
            or hold.get("source_admitted") is not False
            or hold.get("candidate_mutated") is not False
        ):
            raise ValueError("phase2a_exact_packet_quarantine_collection_hold_invalid")
        collection_hold_identities.add(str(hold["authority_identity_id"]))
    for key, hold in authority_collection_holds_by_key.items():
        failed_ids = [str(record_id) for record_id in hold["failed_record_ids"]]
        if any(
            record_id not in representation_collection_holds_by_record_id
            for record_id in failed_ids
        ):
            raise ValueError("phase2a_exact_packet_quarantine_collection_hold_invalid")
        held_selected = held_selected_by_key.get(key)
        selected_record = records_by_id[str(hold["selected_record_id"])]
        if selected_record["result"] == "DOWNLOADED_QUARANTINED_BOUND":
            if (
                held_selected is None
                or held_selected["record_id"] != selected_record["record_id"]
                or held_selected["record_content_sha256"]
                != selected_record["record_content_sha256"]
                or held_selected["proposed_source_version_id"]
                != selected_record["proposed_source_version_id"]
            ):
                raise ValueError(
                    "phase2a_exact_packet_quarantine_authority_hold_selected_binding_invalid"
                )
        elif held_selected is not None:
            raise ValueError(
                "phase2a_exact_packet_quarantine_authority_hold_selected_binding_invalid"
            )
    expected_failed_record_ids = {
        str(record_id)
        for hold in authority_collection_holds_by_key.values()
        for record_id in hold["failed_record_ids"]
    }
    if set(representation_collection_holds_by_record_id) != expected_failed_record_ids:
        raise ValueError("phase2a_exact_packet_quarantine_collection_hold_invalid")
    expected_held_identities = sorted(preflight_identities | collection_hold_identities)
    if (
        value.get("preflight_hold_count") != len(preflight_holds)
        or value.get("collection_hold_count") != len(collection_holds)
        or value.get("authority_collection_holds") != authority_collection_holds
        or interface.get("held_authority_identity_ids") != expected_held_identities
    ):
        raise ValueError("phase2a_exact_packet_quarantine_hold_summary_invalid")

    held_identities = set(interface.get("held_authority_identity_ids") or [])
    for item in held_selected_by_key.values():
        if item["authority_identity_id"] not in held_identities:
            raise ValueError("phase2a_exact_packet_quarantine_held_selected_without_hold")
    selected_keys = set(selected_by_key)
    authority_hold_keys = set(authority_collection_holds_by_key)
    if selected_keys & authority_hold_keys:
        raise ValueError("phase2a_exact_packet_quarantine_fetch_identity_accounting_overlap")
    if selected_keys | authority_hold_keys != set(expected_fetch_keys):
        raise ValueError("phase2a_exact_packet_quarantine_fetch_identity_set_mismatch")
    if not set(held_selected_by_key).issubset(authority_hold_keys):
        raise ValueError("phase2a_exact_packet_quarantine_held_selected_without_authority_hold")
    return (
        value,
        selected_by_key,
        held_selected_by_key,
        authority_collection_holds_by_key,
        corroborating_by_key,
        comparisons_by_key,
    )


def _verify_proposal_representation_coverage(
    proposals: Sequence[Mapping[str, Any]],
    *,
    selected_by_key: Mapping[str, Mapping[str, Any]],
    held_selected_by_key: Mapping[str, Mapping[str, Any]],
    authority_collection_holds_by_key: Mapping[str, Mapping[str, Any]],
    representation_manifest: Mapping[str, Any],
) -> None:
    proposal_by_key = {
        str(proposal["canonical_authority_identity_key"]): proposal for proposal in proposals
    }
    accounted_proposal_keys = set(selected_by_key) | set(authority_collection_holds_by_key)
    if len(proposal_by_key) != len(proposals) or accounted_proposal_keys != set(proposal_by_key):
        raise ValueError("phase2a_exact_packet_quarantine_proposal_coverage_mismatch")
    records_by_id = {
        str(record["record_id"]): record for record in representation_manifest["records"]
    }
    held_identities = set(
        representation_manifest["packet_builder_interface"].get("held_authority_identity_ids") or []
    )
    for key, proposal in proposal_by_key.items():
        selected_item = selected_by_key.get(key)
        if selected_item is not None:
            if selected_item["authority_identity_id"] in held_identities:
                raise ValueError("phase2a_exact_packet_quarantine_selected_identity_held")
            selected_record = records_by_id[str(selected_item["record_id"])]
        else:
            authority_hold = authority_collection_holds_by_key[key]
            selected_record = records_by_id[str(authority_hold["selected_record_id"])]
            held_selected = held_selected_by_key.get(key)
            if (
                held_selected is not None
                and held_selected["record_id"] != selected_record["record_id"]
            ):
                raise ValueError(
                    "phase2a_exact_packet_quarantine_authority_hold_selected_binding_invalid"
                )
        if not set(proposal["affected_row_ids"]).issubset(
            set(selected_record.get("affected_row_ids") or [])
        ):
            raise ValueError("phase2a_exact_packet_quarantine_proposal_row_mismatch")
        if not set(proposal["official_urls"]).issubset(
            set(selected_record.get("official_urls") or [])
        ):
            raise ValueError("phase2a_exact_packet_quarantine_proposal_url_mismatch")
        proposal_locators = {
            str(locator)
            for use in proposal["uses"]
            for locator in use["authority"].get("exact_locators", [])
        }
        if not proposal_locators.issubset(set(selected_record.get("exact_locators") or [])):
            raise ValueError("phase2a_exact_packet_quarantine_proposal_locator_mismatch")


def _bind_proposals_to_representations(
    proposals: Sequence[Mapping[str, Any]],
    *,
    selected_by_key: Mapping[str, Mapping[str, Any]],
    held_selected_by_key: Mapping[str, Mapping[str, Any]],
    authority_collection_holds_by_key: Mapping[str, Mapping[str, Any]],
    corroborating_by_key: Mapping[str, Sequence[Mapping[str, Any]]],
    comparisons_by_key: Mapping[str, Sequence[Mapping[str, Any]]],
    representation_manifest: Mapping[str, Any],
    representation_binding: BoundArtifact,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    bound: list[dict[str, Any]] = []
    held: list[dict[str, Any]] = []
    for proposal in proposals:
        material = dict(proposal)
        material.pop("proposal_content_sha256", None)
        key = str(proposal["canonical_authority_identity_key"])
        if key in authority_collection_holds_by_key:
            authority_hold = authority_collection_holds_by_key[key]
            held_selected = held_selected_by_key.get(key)
            authority_identity_id = str(authority_hold["authority_identity_id"])
            relevant_holds = [
                copy.deepcopy(dict(item))
                for item in representation_manifest["collection_holds"]
                if item.get("authority_identity_id") == authority_identity_id
            ]
            hold_material = {
                "hold_id": ("quarantine-admission-hold-" + _sha256(key.encode("utf-8"))[:24]),
                "canonical_authority_identity_key": key,
                "unbound_source_admission_recommendation": material,
                "held_selected_binding": (
                    copy.deepcopy(dict(held_selected)) if held_selected is not None else None
                ),
                "authority_collection_hold": copy.deepcopy(dict(authority_hold)),
                "corroborating_alias_bindings": copy.deepcopy(
                    list(corroborating_by_key.get(key, ()))
                ),
                "representation_comparisons": copy.deepcopy(list(comparisons_by_key.get(key, ()))),
                "collection_holds": relevant_holds,
                "recommended_owner_outcome": (
                    "RETAIN_QUARANTINE_REPRESENTATION_SET_HOLD_NO_SOURCE_ADMISSION"
                ),
                "owner_outcome": None,
                "source_admission_authorized": False,
                "source_admitted": False,
                "automatic_indexing": False,
                "automatic_embedding": False,
                "candidate_mutated": False,
            }
            held.append(
                {
                    **hold_material,
                    "hold_content_sha256": _sealed(hold_material),
                }
            )
            continue
        selected = selected_by_key[key]
        material["quarantine_representation_binding"] = {
            "manifest_path": _portable_path(representation_binding.path),
            "manifest_content_sha256": representation_binding.content_sha256,
            "manifest_file_sha256": representation_binding.file_sha256,
            "canonical_source_keys": proposal["canonical_source_keys"],
            "selected_admission_binding": copy.deepcopy(dict(selected)),
            "corroborating_alias_bindings": copy.deepcopy(list(corroborating_by_key.get(key, ()))),
            "representation_comparisons": copy.deepcopy(list(comparisons_by_key.get(key, ()))),
            "representation_equivalence_assumed": False,
        }
        material["representation_binding_complete"] = True
        bound.append({**material, "proposal_content_sha256": _sealed(material)})
    return bound, held


def _input_reference(binding: BoundArtifact, *, record_count: int | None = None) -> dict[str, Any]:
    reference: dict[str, Any] = {
        "path": _portable_path(binding.path),
        "content_sha256": binding.content_sha256,
        "file_sha256": binding.file_sha256,
    }
    if record_count is not None:
        reference["record_count"] = record_count
    return reference


def _validated_output_root(output_root: Path, *, review_root: Path) -> Path:
    if review_root.is_symlink() or not review_root.is_dir():
        raise ValueError("phase2a_exact_packet_review_root_invalid")
    review_resolved = review_root.resolve()
    output_resolved = output_root.resolve()
    if output_resolved == review_resolved or not output_resolved.is_relative_to(review_resolved):
        raise ValueError("phase2a_exact_packet_output_outside_review_root")
    parent = output_resolved.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError("phase2a_exact_packet_output_parent_invalid")
    if output_resolved.exists() or output_resolved.is_symlink():
        raise ValueError("phase2a_exact_packet_output_already_exists")
    return output_resolved


def _atomic_publish(staging_root: Path, output_root: Path) -> None:
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_exact_packet_output_already_exists")
    os.rename(staging_root, output_root)
    try:
        parent_descriptor = os.open(output_root.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except BaseException:
        # A Python-visible durability failure must not leave a package that the
        # caller could mistake for a successfully returned transaction.
        if output_root.exists() and not staging_root.exists():
            os.rename(output_root, staging_root)
        raise


def _write_transactional_package(
    output_root: Path,
    *,
    artifacts: Mapping[str, bytes],
) -> None:
    staging_root = Path(
        tempfile.mkdtemp(
            prefix=f".{output_root.name}.staging-",
            dir=output_root.parent,
        )
    )
    try:
        staging_root.chmod(0o700)
        if stat.S_IMODE(staging_root.stat().st_mode) != 0o700:
            raise ValueError("phase2a_exact_packet_staging_mode_invalid")
        for name, raw in sorted(artifacts.items()):
            _write_exclusive(staging_root / name, raw)
        directory_descriptor = os.open(staging_root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        _atomic_publish(staging_root, output_root)
    finally:
        if staging_root.exists():
            shutil.rmtree(staging_root)


def _sanitized_reason_code(exc: BaseException) -> str:
    message = str(exc)
    if re.fullmatch(r"phase2a_exact_packet_[a-z0-9_]+", message):
        return message
    return f"phase2a_exact_packet_unexpected_{type(exc).__name__.casefold()}"


def build(
    output_root: Path,
    *,
    wave_bindings: Sequence[BoundArtifact],
    canonical_set_binding: BoundArtifact | None = None,
    representation_binding: BoundArtifact | None = None,
    queue_binding: BoundArtifact | None = None,
    direct_binding: BoundArtifact | None = None,
    candidate_binding: BoundArtifact | None = None,
) -> dict[str, Any]:
    """Validate all inputs and create one exact non-authorizing packet."""

    output_root = _validated_output_root(output_root, review_root=REVIEW_ROOT)
    if representation_binding is None:
        raise ValueError("phase2a_exact_packet_representation_binding_required")
    if canonical_set_binding is None:
        raise ValueError("phase2a_exact_packet_canonical_wave_set_binding_required")
    queue_binding = queue_binding or BoundArtifact(
        DEFAULT_QUEUE_PATH, QUEUE_CONTENT_SHA256, QUEUE_FILE_SHA256
    )
    direct_binding = direct_binding or BoundArtifact(
        DEFAULT_DIRECT_PATH, DIRECT_CONTENT_SHA256, DIRECT_FILE_SHA256
    )
    candidate_binding = candidate_binding or BoundArtifact(
        DEFAULT_CANDIDATE_PATH, CANDIDATE_CONTENT_SHA256, CANDIDATE_FILE_SHA256
    )
    queue = _load_queue(queue_binding)
    direct = _load_direct(direct_binding)
    candidate = _load_candidate(candidate_binding)
    candidate_index = _candidate_index(candidate)
    waves = _load_waves(wave_bindings)
    canonical_wave_set = _load_canonical_wave_set(
        canonical_set_binding,
        wave_bindings=wave_bindings,
    )
    (
        collector_plans,
        collector_plans_by_identity,
        collector_fetch_identity_keys,
        collector_fetch_identity_set_sha256,
    ) = _collector_plan_set(
        wave_bindings=wave_bindings,
        waves=waves,
        candidate=candidate,
    )

    validation = wave_validator.validate_waves(
        queue_path=queue_binding.path,
        wave_paths=[binding.path for binding in wave_bindings],
    )
    if (
        validation.get("status") != "PASS_COMPLETE"
        or validation.get("covered_row_count") != 316
        or validation.get("missing_row_count") != 0
        or validation.get("missing_row_ids") != []
    ):
        raise ValueError("phase2a_exact_packet_research_coverage_not_exact_316")

    queue_by_row = {str(record["row_id"]): record for record in queue["records"]}
    research_decisions: list[dict[str, Any]] = []
    for binding, wave in sorted(
        zip(wave_bindings, waves, strict=True), key=lambda item: item[0].path.name
    ):
        for record in wave["records"]:
            row_id = str(record["row_id"])
            research_decisions.append(
                _research_decision(
                    record=record,
                    queue_record=queue_by_row[row_id],
                    wave_binding=binding,
                    candidate_index=candidate_index,
                    collector_plans_by_identity=collector_plans_by_identity,
                )
            )
    direct_decisions = [
        _direct_decision(
            record=record,
            direct_binding=direct_binding,
            candidate_index=candidate_index,
        )
        for record in direct["records"]
    ]
    research_ids = [str(row["row_id"]) for row in research_decisions]
    direct_ids = [str(row["row_id"]) for row in direct_decisions]
    if (
        len(research_ids) != 316
        or len(set(research_ids)) != 316
        or len(direct_ids) != 45
        or len(set(direct_ids)) != 45
        or set(research_ids) & set(direct_ids)
    ):
        raise ValueError("phase2a_exact_packet_361_row_partition_invalid")
    decisions = sorted(
        research_decisions + direct_decisions, key=lambda row: _row_sort_key(row["row_id"])
    )
    if len(decisions) != 361:
        raise ValueError("phase2a_exact_packet_decision_count_invalid")
    (
        representation_manifest,
        selected_by_key,
        held_selected_by_key,
        authority_collection_holds_by_key,
        corroborating_by_key,
        comparisons_by_key,
    ) = _load_representation_bindings(
        representation_binding,
        queue_binding=queue_binding,
        candidate_binding=candidate_binding,
        canonical_set_binding=canonical_set_binding,
        wave_bindings=wave_bindings,
        expected_fetch_identity_keys=collector_fetch_identity_keys,
        expected_fetch_identity_set_sha256=(collector_fetch_identity_set_sha256),
    )
    representation_accounted_keys = tuple(
        sorted(set(selected_by_key) | set(authority_collection_holds_by_key))
    )
    unbound_proposals = _source_admission_proposals(
        decisions,
        eligible_identity_keys=representation_accounted_keys,
    )
    proposal_identity_keys = tuple(
        str(item["canonical_authority_identity_key"]) for item in unbound_proposals
    )
    builder_proposal_identity_set_sha256 = _sealed(
        {
            "schema": "legalbot.v111.phase2a.fetch-eligible-identity-set.v1",
            "authority_identity_keys": [
                item.removeprefix("identity:") for item in proposal_identity_keys
            ],
        }
    )
    if (
        proposal_identity_keys != collector_fetch_identity_keys
        or builder_proposal_identity_set_sha256 != collector_fetch_identity_set_sha256
    ):
        raise ValueError("phase2a_exact_packet_collector_builder_proposal_identity_set_mismatch")
    _verify_proposal_representation_coverage(
        unbound_proposals,
        selected_by_key=selected_by_key,
        held_selected_by_key=held_selected_by_key,
        authority_collection_holds_by_key=authority_collection_holds_by_key,
        representation_manifest=representation_manifest,
    )
    proposals, quarantine_admission_holds = _bind_proposals_to_representations(
        unbound_proposals,
        selected_by_key=selected_by_key,
        held_selected_by_key=held_selected_by_key,
        authority_collection_holds_by_key=authority_collection_holds_by_key,
        corroborating_by_key=corroborating_by_key,
        comparisons_by_key=comparisons_by_key,
        representation_manifest=representation_manifest,
        representation_binding=representation_binding,
    )
    identity_anomalies = _source_identity_anomalies(decisions)
    authority_assessments = [
        assessment
        for decision in research_decisions
        for assessment in decision["authority_assessments"]
    ]
    component_holds = [
        hold for decision in research_decisions for hold in decision["component_completeness_holds"]
    ]
    recommendation_counts = dict(
        sorted(Counter(row["recommended_owner_outcome"] for row in decisions).items())
    )
    proposal_recommendation_counts = dict(
        sorted(Counter(row["recommended_owner_outcome"] for row in proposals).items())
    )
    anomaly_reason_counts = dict(
        sorted(
            Counter(
                reason for anomaly in identity_anomalies for reason in anomaly["hold_reason_codes"]
            ).items()
        )
    )

    boundary = {field: False for field in _TOP_LEVEL_FALSE_FIELDS}
    packet_material: dict[str, Any] = {
        "schema": "legalbot.v111.phase2a.exact-remediation-owner-packet.v1",
        "status": "EXACT_361_OWNER_DECISIONS_READY_NOT_ADOPTED",
        "route": "OWNER_ADOPTED_INTERNAL_PRIVATE_RESEARCH_TOOL",
        "not_professional_legal_certification": True,
        "input_bindings": {
            "official_research_queue": _input_reference(queue_binding, record_count=316),
            "direct_exact_span_advisory": _input_reference(direct_binding, record_count=45),
            "non_active_candidate_manifest": {
                **_input_reference(candidate_binding, record_count=251),
                "corpus_id": candidate["corpus_id"],
                "source_scan_id": candidate["source_scan_id"],
                "chunk_count": candidate["chunk_count"],
                "successor_must_remain_non_active": True,
            },
            "canonical_research_waves": [
                _input_reference(binding, record_count=len(wave["records"]))
                for binding, wave in sorted(
                    zip(wave_bindings, waves, strict=True),
                    key=lambda item: item[0].path.name,
                )
            ],
            "canonical_research_wave_set": {
                **_input_reference(
                    canonical_set_binding,
                    record_count=canonical_wave_set["wave_count"],
                ),
                "schema": canonical_wave_set["schema"],
                "source_queue_content_sha256": canonical_wave_set["source_queue_content_sha256"],
            },
            "research_wave_quarantine_manifest": {
                **_input_reference(
                    representation_binding,
                    record_count=len(representation_manifest["records"]),
                ),
                "schema": representation_manifest["schema"],
                "selected_admission_binding_count": len(
                    representation_manifest["selected_admission_bindings"]
                ),
                "held_selected_binding_count": len(
                    representation_manifest["held_selected_bindings"]
                ),
                "corroborating_alias_binding_count": len(
                    representation_manifest["corroborating_alias_bindings"]
                ),
            },
        },
        "research_wave_validation": {
            "schema": validation["schema"],
            "status": validation["status"],
            "wave_count": validation["wave_count"],
            "covered_row_count": validation["covered_row_count"],
            "missing_row_count": validation["missing_row_count"],
        },
        "decision_summary": {
            "decision_count": 361,
            "research_decision_count": 316,
            "direct_exact_span_decision_count": 45,
            "unique_row_count": 361,
            "recommendation_counts": recommendation_counts,
            "proposed_new_source_admission_count": len(proposals),
            "source_admission_recommendation_counts": proposal_recommendation_counts,
            "collector_authority_plan_count": len(collector_plans),
            "collector_fetch_eligible_identity_count": len(collector_fetch_identity_keys),
            "collector_fetch_eligible_identity_set_sha256": (collector_fetch_identity_set_sha256),
            "builder_proposal_identity_set_sha256": (builder_proposal_identity_set_sha256),
            "collector_builder_proposal_identity_set_equal": True,
            "source_identity_anomaly_hold_count": len(identity_anomalies),
            "source_identity_anomaly_reason_counts": anomaly_reason_counts,
            "authority_crosscheck_count": len(authority_assessments),
            "metadata_incomplete_authority_count": sum(
                item["metadata_completeness"]["status"] != "COMPLETE"
                for item in authority_assessments
            ),
            "candidate_crosscheck_hold_authority_count": sum(
                bool(item["candidate_crosscheck"]["reason_codes"]) for item in authority_assessments
            ),
            "candidate_missing_id_reconciled_authority_count": sum(
                item["candidate_crosscheck"]["missing_ids_reconciled_from_manifest"] is True
                for item in authority_assessments
            ),
            "support_bearing_component_without_authority_count": len(component_holds),
            "composite_authority_identity_hold_count": sum(
                "COMPOSITE_AUTHORITY_IDENTITY_REQUIRES_SPLIT" in item["hold_reason_codes"]
                for item in authority_assessments
            ),
            "representation_bound_source_admission_count": len(proposals),
            "quarantine_source_admission_hold_count": len(quarantine_admission_holds),
            "quarantine_preflight_hold_count": len(representation_manifest["preflight_holds"]),
            "quarantine_collection_hold_count": len(representation_manifest["collection_holds"]),
            "quarantine_held_selected_binding_count": len(
                representation_manifest["held_selected_bindings"]
            ),
        },
        "decisions": decisions,
        "proposed_new_source_admissions": proposals,
        "quarantine_source_admission_holds": quarantine_admission_holds,
        "source_identity_and_admission_holds": identity_anomalies,
        "quarantine_evidence_holds": {
            "preflight_holds": copy.deepcopy(representation_manifest["preflight_holds"]),
            "collection_holds": copy.deepcopy(representation_manifest["collection_holds"]),
        },
        "approval_required_for": [
            "EVERY_LISTED_EXACT_ROW_RECOMMENDATION",
            "EVERY_LISTED_PROPOSITION_LEVEL_SOURCE_ADMISSION_OR_HOLD",
            "ONE_COMPLETE_SOURCE_SCAN",
            "ONE_NON_ACTIVE_SUCCESSOR_CANDIDATE_BUILD_WITH_EMBEDDING",
            "RETRIEVAL_REATTESTATION_AND_ALL585_QUALIFICATION_ONLY",
        ],
        "approval_does_not_authorize": [
            "ANSWER_MODEL_OR_ANSWER_RELEASE",
            "PHASE2B",
            "DEVELOPMENT30",
            "VALIDATION30",
            "PROMOTION",
            "ACTIVE_OR_PREVIOUS_POINTER_WRITES",
            "LIVE_ACTIVATION",
            "TRAINING_EXPORT",
        ],
        **boundary,
    }
    packet = {
        **packet_material,
        "artifact_content_sha256": _sealed(packet_material),
    }
    packet_raw = _pretty_json(packet)
    packet_file_sha256 = _sha256(packet_raw)
    packet_digest = packet["artifact_content_sha256"]
    prompt = f"""PHASE-2A EXACT REMEDIATION OWNER APPROVAL

Review the complete machine-readable packet before using this text:

- Packet: {PACKET_NAME}
- Exact packet content SHA-256: {packet_digest}
- Exact packet file SHA-256: {packet_file_sha256}
- Row decisions: 361 (316 official-research recommendations and 45 direct exact-span recommendations)
- Deduplicated proposed new source admissions: {len(proposals)}
- Representation-bound proposed source admissions: {len(proposals)}
- Quarantine representation-set admission holds: {len(quarantine_admission_holds)}
- Explicit source identity/admission anomaly holds: {len(identity_anomalies)}

APPROVAL TEXT

I approve exact Phase-2A remediation owner packet content SHA-256
`{packet_digest}` and every recommendation and retained hold it contains.

I authorize Codex to apply only those exact 361 owner decisions; admit only the
exact source proposals whose listed recommendation is admission and whose raw
bytes, content identity and source-version identity are sealed in this packet;
retain every
listed currentness, later-treatment, jurisdiction, factual, identity and other
hold; run one complete source scan; and build/embed one successor candidate
that remains non-ACTIVE and answer-ineligible.  After that build, I authorize
retrieval re-attestation and all-585 technical qualification only.

I do not authorize an answer-model run or answer release, Phase 2B,
Development 30, Validation 30, promotion, ACTIVE/PREVIOUS writes, live
activation or training export.  If qualification still finds a material gap or
unresolved owner decision, the workflow must stop and report it without
claiming a successful Phase-2A package.

Owner typed name:
Decision date:
"""
    prompt_raw = prompt.encode("utf-8")
    package_material = {
        "schema": "legalbot.v111.phase2a.exact-remediation-owner-package.v1",
        "status": packet["status"],
        "packet_content_sha256": packet_digest,
        "artifacts": [
            {
                "name": PACKET_NAME,
                "file_sha256": packet_file_sha256,
                "content_sha256": packet_digest,
            },
            {"name": PROMPT_NAME, "file_sha256": _sha256(prompt_raw)},
        ],
        **boundary,
    }
    package = {
        **package_material,
        "artifact_content_sha256": _sealed(package_material),
    }
    package_raw = _pretty_json(package)

    checksum_lines = "".join(
        f"{_sha256(raw)}  {name}\n"
        for name, raw in sorted(
            {
                PACKET_NAME: packet_raw,
                PROMPT_NAME: prompt_raw,
                PACKAGE_NAME: package_raw,
            }.items()
        )
    )
    output_objects = [packet, package, prompt]
    _assert_privacy_safe(output_objects, role="output")
    _write_transactional_package(
        output_root,
        artifacts={
            PACKET_NAME: packet_raw,
            PROMPT_NAME: prompt_raw,
            PACKAGE_NAME: package_raw,
            CHECKSUM_NAME: checksum_lines.encode("utf-8"),
        },
    )
    return packet


def _binding_from_cli(values: Sequence[str]) -> BoundArtifact:
    path, content_sha256, file_sha256 = values
    return BoundArtifact(Path(path).resolve(strict=True), content_sha256, file_sha256)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--queue", type=Path, default=DEFAULT_QUEUE_PATH)
    parser.add_argument("--queue-content-sha256", default=QUEUE_CONTENT_SHA256)
    parser.add_argument("--queue-file-sha256", default=QUEUE_FILE_SHA256)
    parser.add_argument("--direct", type=Path, default=DEFAULT_DIRECT_PATH)
    parser.add_argument("--direct-content-sha256", default=DIRECT_CONTENT_SHA256)
    parser.add_argument("--direct-file-sha256", default=DIRECT_FILE_SHA256)
    parser.add_argument("--candidate", type=Path, default=DEFAULT_CANDIDATE_PATH)
    parser.add_argument("--candidate-content-sha256", default=CANDIDATE_CONTENT_SHA256)
    parser.add_argument("--candidate-file-sha256", default=CANDIDATE_FILE_SHA256)
    parser.add_argument(
        "--canonical-set-binding",
        nargs=3,
        required=True,
        metavar=("PATH", "CONTENT_SHA256", "FILE_SHA256"),
        help=("Sealed exact 32-wave canonical-set path and its expected logical/file digests."),
    )
    parser.add_argument(
        "--quarantine-manifest",
        nargs=3,
        required=True,
        metavar=("PATH", "CONTENT_SHA256", "FILE_SHA256"),
        help=(
            "Sealed research-wave quarantine manifest path and its expected logical/file digests."
        ),
    )
    parser.add_argument(
        "--wave",
        nargs=3,
        action="append",
        required=True,
        metavar=("PATH", "CONTENT_SHA256", "FILE_SHA256"),
        help="Explicit canonical wave path and its expected logical/file digests.",
    )
    args = parser.parse_args(argv)
    try:
        packet = build(
            args.output_root.resolve(),
            queue_binding=BoundArtifact(
                args.queue.resolve(strict=True),
                args.queue_content_sha256,
                args.queue_file_sha256,
            ),
            direct_binding=BoundArtifact(
                args.direct.resolve(strict=True),
                args.direct_content_sha256,
                args.direct_file_sha256,
            ),
            candidate_binding=BoundArtifact(
                args.candidate.resolve(strict=True),
                args.candidate_content_sha256,
                args.candidate_file_sha256,
            ),
            canonical_set_binding=_binding_from_cli(args.canonical_set_binding),
            representation_binding=_binding_from_cli(args.quarantine_manifest),
            wave_bindings=[_binding_from_cli(values) for values in args.wave],
        )
    except Exception as exc:
        print(
            json.dumps(
                {
                    "status": "FAILED",
                    "reason_code": _sanitized_reason_code(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(
        json.dumps(
            {
                "status": packet["status"],
                "artifact_content_sha256": packet["artifact_content_sha256"],
                "decision_summary": packet["decision_summary"],
                "owner_approved": False,
                "source_admission_authorized": False,
                "candidate_mutated": False,
                "phase2b_authorized": False,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
