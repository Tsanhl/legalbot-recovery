"""Identity-preserving roll-forward for provision qualification records.

This module does not approve changed law.  It carries a reviewed provision
forward only when the predecessor and successor official XML are byte-for-byte
identical and their extracted version metadata is identical.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from .provision_verification import CURRENT_PACK_SCHEMA, SCHEMA

DOWNLOAD_REPORT_SCHEMA = "legalbot.current-legislation-download-report.v1"
EXCEPTION_REPORT_SCHEMA = "legalbot.provision-verification-exceptions.v1"
ARCHIVE_INDEX_SCHEMA = "legalbot.provision-verification-archive-index.v1"
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_SNAPSHOT_RE = re.compile(
    r"(?P<authority>(?:ukpga|uksi)(?::[A-Za-z0-9-]+){2,4})"
    r":latest-available@(?P<as_of>20\d{2}-\d{2}-\d{2})"
)


@dataclass(frozen=True)
class RollForwardArtifacts:
    registry: dict[str, Any]
    exception_report: dict[str, Any]
    archive_index: dict[str, Any]
    predecessor_raw: bytes
    download_report_raw: bytes


def _canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _canonical_value_sha256(value: object) -> str:
    raw = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _element_text(root: ET.Element, name: str) -> str | None:
    for element in root.iter():
        if _local_name(element.tag) == name:
            text = " ".join("".join(element.itertext()).split())
            return text or None
    return None


def _official_version(raw: bytes, *, identity: str) -> dict[str, Any]:
    opening = raw[:100_000].upper()
    if b"<!DOCTYPE" in opening or b"<!ENTITY" in opening:
        raise RuntimeError("official XML contains a prohibited DTD or entity declaration")
    root = ET.fromstring(raw)
    if _local_name(root.tag) != "Legislation":
        raise RuntimeError("official source is not legislation XML")
    if root.attrib.get("DocumentURI") != f"http://www.legislation.gov.uk/{identity}":
        raise RuntimeError("official XML identity does not match its manifest identity")
    document_status: str | None = None
    for element in root.iter():
        if _local_name(element.tag) == "DocumentStatus":
            document_status = str(element.attrib.get("Value") or "") or None
            break
    return {
        "document_status": document_status,
        "restrict_start_date": root.attrib.get("RestrictStartDate"),
        "source_modified": _element_text(root, "modified"),
        "source_valid_from": _element_text(root, "valid"),
    }


def _load_object(raw: bytes, *, schema: str, name: str) -> dict[str, Any]:
    payload = json.loads(raw)
    if not isinstance(payload, dict) or payload.get("schema") != schema:
        raise RuntimeError(f"{name} is invalid")
    return payload


def _snapshot_date(records: list[object]) -> str:
    dates: set[str] = set()
    for value in records:
        if not isinstance(value, dict):
            raise RuntimeError("predecessor provision record must be an object")
        match = _SNAPSHOT_RE.fullmatch(str(value.get("stable_source_id") or ""))
        if match is None:
            raise RuntimeError("predecessor provision source identity is invalid")
        dates.add(match.group("as_of"))
    if len(dates) != 1:
        raise RuntimeError("predecessor registry does not describe one snapshot date")
    return dates.pop()


def _source_path(
    source_root: Path,
    *,
    item: dict[str, Any],
    as_of_date: str,
) -> Path:
    identity_leaf = str(item["identity"]).replace("/", "_")
    return (
        source_root
        / "Official Legislation"
        / "United Kingdom"
        / "Current"
        / str(item["subject_folder"])
        / f"{identity_leaf}__retrieved-{as_of_date}.xml"
    )


def build_roll_forward(
    *,
    predecessor_raw: bytes,
    current_pack_raw: bytes,
    download_report_raw: bytes,
    source_root: Path,
    predecessor_archive_relative_path: str,
    exception_report_relative_path: str,
    download_report_relative_path: str,
) -> RollForwardArtifacts:
    predecessor = _load_object(
        predecessor_raw, schema=SCHEMA, name="predecessor provision registry"
    )
    pack = _load_object(current_pack_raw, schema=CURRENT_PACK_SCHEMA, name="current-law pack")
    report = _load_object(
        download_report_raw,
        schema=DOWNLOAD_REPORT_SCHEMA,
        name="current-law download report",
    )
    records = predecessor.get("records")
    items = pack.get("items")
    report_items = report.get("items")
    if not isinstance(records, list) or not records:
        raise RuntimeError("predecessor provision registry is empty")
    if not isinstance(items, list) or not items:
        raise RuntimeError("current-law pack is empty")
    if not isinstance(report_items, list) or not report_items:
        raise RuntimeError("current-law download report is empty")
    predecessor_date = _snapshot_date(records)
    current_date = str(pack.get("as_of_date") or "")
    if (
        not re.fullmatch(r"20\d{2}-\d{2}-\d{2}", current_date)
        or current_date <= predecessor_date
        or report.get("as_of_date") != current_date
        or report.get("manifest_version") != pack.get("version")
    ):
        raise RuntimeError("current-law manifest and download report are temporally incoherent")

    pack_by_identity: dict[str, dict[str, Any]] = {}
    for value in items:
        if not isinstance(value, dict):
            raise RuntimeError("current-law pack item must be an object")
        identity = str(value.get("identity") or "")
        if not identity or identity in pack_by_identity:
            raise RuntimeError("current-law pack identity is empty or duplicated")
        pack_by_identity[identity] = value
    report_by_identity: dict[str, dict[str, Any]] = {}
    for value in report_items:
        if not isinstance(value, dict):
            raise RuntimeError("download report item must be an object")
        identity = str(value.get("identity") or "")
        if not identity or identity in report_by_identity:
            raise RuntimeError("download report identity is empty or duplicated")
        report_by_identity[identity] = value
    if set(pack_by_identity) != set(report_by_identity):
        raise RuntimeError("download report does not reconcile to the current-law manifest")

    predecessor_sha256 = _sha256(predecessor_raw)
    inherited: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    for value in records:
        assert isinstance(value, dict)
        predecessor_source_id = str(value.get("stable_source_id") or "")
        match = _SNAPSHOT_RE.fullmatch(predecessor_source_id)
        assert match is not None
        identity = match.group("authority").replace(":", "/")
        item = pack_by_identity.get(identity)
        downloaded = report_by_identity.get(identity)
        if item is None or downloaded is None:
            raise RuntimeError("reviewed provision authority is absent from the current-law pack")
        old_path = _source_path(
            source_root,
            item=item,
            as_of_date=predecessor_date,
        )
        new_path = _source_path(source_root, item=item, as_of_date=current_date)
        old_raw = old_path.read_bytes()
        new_raw = new_path.read_bytes()
        old_sha256 = _sha256(old_raw)
        new_sha256 = _sha256(new_raw)
        report_sha256 = str(downloaded.get("sha256") or "")
        if _SHA256_RE.fullmatch(report_sha256) is None or report_sha256 != new_sha256:
            raise RuntimeError("download report does not bind the current official source bytes")
        old_version = _official_version(old_raw, identity=identity)
        new_version = _official_version(new_raw, identity=identity)
        old_version_sha256 = _canonical_value_sha256(old_version)
        new_version_sha256 = _canonical_value_sha256(new_version)
        reasons: list[str] = []
        if old_sha256 != new_sha256:
            reasons.append("official_source_bytes_changed")
        if old_version != new_version:
            reasons.append("official_version_metadata_changed")
        if reasons:
            excluded.append(
                {
                    "authority_identity_id": match.group("authority"),
                    "legal_locator": str(value.get("legal_locator") or ""),
                    "new_official_version_sha256": new_version_sha256,
                    "new_source_content_sha256": new_sha256,
                    "predecessor_official_version_sha256": old_version_sha256,
                    "predecessor_source_content_sha256": old_sha256,
                    "reason_codes": reasons,
                    "review_action": "fresh_human_provision_review_required",
                }
            )
            continue
        successor_source_id = f"{match.group('authority')}:latest-available@{current_date}"
        successor = dict(value)
        successor["stable_source_id"] = successor_source_id
        successor["source_content_sha256"] = new_sha256
        successor["source_version_sha256"] = new_sha256
        successor["official_version"] = new_version
        successor["official_version_sha256"] = new_version_sha256
        successor["qualification_provenance"] = "inherited_identical_official_snapshot"
        successor["predecessor_provenance"] = {
            "as_of_date": predecessor_date,
            "official_version_sha256": old_version_sha256,
            "record_sha256": _canonical_value_sha256(value),
            "registry_sha256": predecessor_sha256,
            "source_content_sha256": old_sha256,
            "source_version_sha256": old_sha256,
            "stable_source_id": predecessor_source_id,
        }
        inherited.append(successor)

    exception_report = {
        "schema": EXCEPTION_REPORT_SCHEMA,
        "as_of_date": current_date,
        "predecessor_as_of_date": predecessor_date,
        "policy": "inherit_only_identical_official_bytes_and_version_metadata",
        "inherited_record_count": len(inherited),
        "excluded_record_count": len(excluded),
        "contains_source_text": False,
        "contains_filesystem_paths": False,
        "exceptions": excluded,
    }
    exception_raw = _canonical_bytes(exception_report)
    registry = {
        "schema": SCHEMA,
        "version": "1.1.0",
        "status": "active",
        "as_of_date": current_date,
        "jurisdiction": str(predecessor.get("jurisdiction") or "England and Wales"),
        "method": "inherited_identical_official_snapshot",
        "current_legislation_pack_sha256": _sha256(current_pack_raw),
        "download_report": {
            "relative_path": download_report_relative_path,
            "sha256": _sha256(download_report_raw),
        },
        "exception_report": {
            "relative_path": exception_report_relative_path,
            "sha256": _sha256(exception_raw),
        },
        "predecessor_registry": {
            "relative_path": predecessor_archive_relative_path,
            "sha256": predecessor_sha256,
            "as_of_date": predecessor_date,
            "status": "superseded",
        },
        "roll_forward_policy": "identical_official_bytes_and_version_metadata_only",
        "inherited_record_count": len(inherited),
        "excluded_record_count": len(excluded),
        "records": inherited,
    }
    registry_raw = _canonical_bytes(registry)
    archive_index = {
        "schema": ARCHIVE_INDEX_SCHEMA,
        "entries": [
            {
                "as_of_date": predecessor_date,
                "relative_path": predecessor_archive_relative_path,
                "sha256": predecessor_sha256,
                "status": "superseded",
                "successor_as_of_date": current_date,
                "successor_registry_sha256": _sha256(registry_raw),
            }
        ],
        "bound_artifacts": [
            {
                "artifact_type": "current_legislation_download_report",
                "as_of_date": current_date,
                "relative_path": download_report_relative_path,
                "sha256": _sha256(download_report_raw),
                "status": "bound_to_active_registry",
            },
            {
                "artifact_type": "provision_verification_exception_report",
                "as_of_date": current_date,
                "relative_path": exception_report_relative_path,
                "sha256": _sha256(exception_raw),
                "status": "bound_to_active_registry",
            },
        ],
    }
    return RollForwardArtifacts(
        registry=registry,
        exception_report=exception_report,
        archive_index=archive_index,
        predecessor_raw=predecessor_raw,
        download_report_raw=download_report_raw,
    )


def artifact_bytes(artifacts: RollForwardArtifacts) -> dict[str, bytes]:
    """Return deterministic bytes for callers that persist the artifacts."""

    return {
        "registry": _canonical_bytes(artifacts.registry),
        "exception_report": _canonical_bytes(artifacts.exception_report),
        "archive_index": _canonical_bytes(artifacts.archive_index),
        "predecessor": artifacts.predecessor_raw,
        "download_report": artifacts.download_report_raw,
    }
