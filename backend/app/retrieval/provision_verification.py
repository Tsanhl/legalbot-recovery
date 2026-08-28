"""Validated provision-level qualification, separate from corpus selection.

Provision review is tied to one immutable official source version.  A registry
date matching the current-law pack is not enough: a qualification is applied
only when both catalogue hashes match the reviewed official bytes.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import date
from pathlib import Path, PurePosixPath
from typing import Any

RELATIVE_PATH = "config/provision_verification.v1.json"
CURRENT_PACK_RELATIVE_PATH = "config/current_legislation_pack.json"
SCHEMA = "legalbot.provision-verification.v1"
CURRENT_PACK_SCHEMA = "legalbot.current-legislation-pack.v1"
TEST_EMPTY_BYTES = (
    b'{"schema":"legalbot.provision-verification.v1","version":"test-empty","records":[]}\n'
)
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_PROVENANCE_ARCHIVE_PREFIX = PurePosixPath("config/archive/provision-verification")
_SNAPSHOT_RE = re.compile(
    r"(?P<authority>(?:ukpga|uksi)(?::[A-Za-z0-9-]+){2,4})"
    r":latest-available@(?P<as_of>20\d{2}-\d{2}-\d{2})"
)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _valid_date(value: object, *, field: str) -> str:
    text = str(value or "")
    try:
        parsed = date.fromisoformat(text)
    except ValueError as exc:
        raise RuntimeError(f"{field} is invalid") from exc
    if parsed.isoformat() != text:
        raise RuntimeError(f"{field} is invalid")
    return text


def _safe_project_path(project_root: Path, value: object, *, field: str) -> Path:
    text = str(value or "")
    relative = PurePosixPath(text)
    if not text or relative.is_absolute() or ".." in relative.parts:
        raise RuntimeError(f"{field} is not a safe project-relative path")
    return project_root.joinpath(*relative.parts)


def _canonical_sha256(value: object) -> str:
    return _sha256(
        json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )


def _load_current_pack(project_root: Path) -> tuple[dict[str, Any], bytes, str, set[str]]:
    path = project_root / CURRENT_PACK_RELATIVE_PATH
    raw = path.read_bytes()
    payload = json.loads(raw)
    if not isinstance(payload, dict) or payload.get("schema") != CURRENT_PACK_SCHEMA:
        raise RuntimeError("current-legislation pack is invalid")
    as_of_date = _valid_date(payload.get("as_of_date"), field="current-law as_of_date")
    items = payload.get("items")
    if not isinstance(items, list) or not items:
        raise RuntimeError("current-legislation pack is empty")
    identities: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            raise RuntimeError("current-legislation item must be an object")
        identity = str(item.get("identity") or "")
        authority = ":".join(identity.split("/"))
        if (
            not re.fullmatch(r"(?:ukpga|uksi)(?::[A-Za-z0-9-]+){2,4}", authority)
            or authority in identities
        ):
            raise RuntimeError("current-legislation identity is invalid or duplicated")
        identities.add(authority)
    return payload, raw, as_of_date, identities


def _verify_bound_artifact(
    project_root: Path,
    binding: object,
    *,
    field: str,
) -> bytes:
    if not isinstance(binding, dict):
        raise RuntimeError(f"{field} binding is invalid")
    expected = str(binding.get("sha256") or "")
    if _SHA256_RE.fullmatch(expected) is None:
        raise RuntimeError(f"{field} digest is invalid")
    path = _safe_project_path(project_root, binding.get("relative_path"), field=field)
    relative = PurePosixPath(str(binding.get("relative_path") or ""))
    prefix_parts = _PROVENANCE_ARCHIVE_PREFIX.parts
    if relative.parts[: len(prefix_parts)] != prefix_parts:
        raise RuntimeError(f"{field} must be stored in the tracked provision-verification archive")
    raw = path.read_bytes()
    if _sha256(raw) != expected:
        raise RuntimeError(f"{field} digest mismatch")
    return raw


def load_provision_verifications(
    project_root: Path,
    *,
    allow_test_empty: bool = False,
) -> tuple[dict[tuple[str, str], dict[str, Any]], str]:
    path = project_root / RELATIVE_PATH
    if not path.is_file() and allow_test_empty:
        return {}, _sha256(TEST_EMPTY_BYTES)
    raw = path.read_bytes()
    payload = json.loads(raw)
    if not isinstance(payload, dict) or payload.get("schema") != SCHEMA:
        raise RuntimeError("provision-verification registry is invalid")
    records = payload.get("records")
    if not isinstance(records, list) or (not records and not allow_test_empty):
        raise RuntimeError("provision-verification registry is empty")
    if not records and allow_test_empty:
        return {}, _sha256(raw)

    pack, pack_raw, pack_date, pack_identities = _load_current_pack(project_root)
    registry_date = _valid_date(
        payload.get("as_of_date"), field="provision-verification as_of_date"
    )
    if registry_date != pack_date:
        raise RuntimeError("provision-verification and current-law dates do not match")
    if payload.get("status") != "active":
        raise RuntimeError("provision-verification registry is not active")
    if payload.get("current_legislation_pack_sha256") != _sha256(pack_raw):
        raise RuntimeError("provision-verification current-law manifest digest mismatch")

    predecessor_binding = payload.get("predecessor_registry")
    predecessor_raw = _verify_bound_artifact(
        project_root, predecessor_binding, field="predecessor registry"
    )
    predecessor_payload = json.loads(predecessor_raw)
    if (
        not isinstance(predecessor_binding, dict)
        or predecessor_binding.get("status") != "superseded"
        or not isinstance(predecessor_payload, dict)
        or predecessor_payload.get("schema") != SCHEMA
    ):
        raise RuntimeError("predecessor registry provenance is invalid")
    predecessor_date = _valid_date(
        predecessor_binding.get("as_of_date"), field="predecessor as_of_date"
    )
    if predecessor_date >= registry_date:
        raise RuntimeError("predecessor registry date is not earlier than active registry")
    predecessor_records = predecessor_payload.get("records")
    if not isinstance(predecessor_records, list) or not predecessor_records:
        raise RuntimeError("predecessor registry is empty")
    predecessor_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for item in predecessor_records:
        if not isinstance(item, dict):
            raise RuntimeError("predecessor provision record must be an object")
        key = (str(item.get("stable_source_id") or ""), str(item.get("legal_locator") or ""))
        if key in predecessor_by_key:
            raise RuntimeError("predecessor provision record is duplicated")
        predecessor_by_key[key] = item

    download_raw = _verify_bound_artifact(
        project_root, payload.get("download_report"), field="download report"
    )
    download_report = json.loads(download_raw)
    if (
        not isinstance(download_report, dict)
        or download_report.get("schema") != "legalbot.current-legislation-download-report.v1"
        or download_report.get("as_of_date") != registry_date
        or download_report.get("manifest_version") != pack.get("version")
    ):
        raise RuntimeError("download report is not coherent with the active current-law pack")
    exception_raw = _verify_bound_artifact(
        project_root, payload.get("exception_report"), field="exception report"
    )
    exception_report = json.loads(exception_raw)
    if (
        not isinstance(exception_report, dict)
        or exception_report.get("schema") != "legalbot.provision-verification-exceptions.v1"
        or exception_report.get("as_of_date") != registry_date
        or exception_report.get("predecessor_as_of_date") != predecessor_date
        or exception_report.get("contains_source_text") is not False
        or exception_report.get("contains_filesystem_paths") is not False
        or exception_report.get("excluded_record_count") != payload.get("excluded_record_count")
    ):
        raise RuntimeError("provision-verification exception report is incoherent")
    if payload.get("inherited_record_count") != len(records):
        raise RuntimeError("provision-verification inherited record count is incoherent")

    output: dict[tuple[str, str], dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict):
            raise RuntimeError("provision-verification record must be an object")
        source_id = str(record.get("stable_source_id") or "")
        locator = str(record.get("legal_locator") or "")
        url = str(record.get("official_source_url") or "")
        extent = str(record.get("verified_extent") or "")
        effects = record.get("section_unapplied_effect_count")
        materiality = str(record.get("unapplied_effect_materiality") or "")
        source_content_sha256 = str(record.get("source_content_sha256") or "")
        source_version_sha256 = str(record.get("source_version_sha256") or "")
        official_version = record.get("official_version")
        official_version_sha256 = str(record.get("official_version_sha256") or "")
        provenance = record.get("predecessor_provenance")
        match = _SNAPSHOT_RE.fullmatch(source_id)
        key = (source_id, locator)
        if (
            match is None
            or match.group("as_of") != registry_date
            or match.group("authority") not in pack_identities
            or not locator.startswith("section ")
            or not url.startswith("https://www.legislation.gov.uk/")
            or "E+W" not in extent
            or not isinstance(effects, int)
            or effects < 0
            or materiality not in {"none_recorded", "not_material_to_queried_proposition"}
            or _SHA256_RE.fullmatch(source_content_sha256) is None
            or source_version_sha256 != source_content_sha256
            or not isinstance(official_version, dict)
            or official_version_sha256 != _canonical_sha256(official_version)
            or not isinstance(provenance, dict)
            or provenance.get("registry_sha256") != _sha256(predecessor_raw)
            or provenance.get("source_content_sha256") != source_content_sha256
            or provenance.get("source_version_sha256") != source_version_sha256
            or provenance.get("official_version_sha256") != official_version_sha256
            or key in output
        ):
            raise RuntimeError(f"invalid or duplicate provision qualification: {key!r}")
        predecessor_source_id = str(provenance.get("stable_source_id") or "")
        predecessor_key = (predecessor_source_id, locator)
        predecessor_record = predecessor_by_key.get(predecessor_key)
        predecessor_match = _SNAPSHOT_RE.fullmatch(predecessor_source_id)
        if (
            predecessor_match is None
            or predecessor_match.group("authority") != match.group("authority")
            or predecessor_match.group("as_of") != predecessor_date
            or predecessor_record is None
            or provenance.get("record_sha256") != _canonical_sha256(predecessor_record)
        ):
            raise RuntimeError(f"invalid predecessor provenance: {key!r}")
        output[key] = dict(record)
    return output, _sha256(raw)


def qualification_for(
    records: Mapping[tuple[str, str], Mapping[str, Any]],
    *,
    stable_source_id: str,
    legal_locator: str,
    source_content_sha256: str,
    source_version_sha256: str,
) -> dict[str, Any] | None:
    """Return a qualification only for the exact reviewed catalogue bytes."""

    record = records.get((stable_source_id, legal_locator))
    if record is None:
        return None
    expected = str(record.get("source_content_sha256") or "")
    if (
        _SHA256_RE.fullmatch(source_content_sha256) is None
        or source_version_sha256 != source_content_sha256
        or expected != source_content_sha256
        or record.get("source_version_sha256") != source_version_sha256
    ):
        return None
    return dict(record)
