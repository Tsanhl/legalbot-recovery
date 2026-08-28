"""Candidate-bound successor qualification for unchanged official provisions.

The sealed candidate keeps its original qualification registry immutable.  A
later qualification may supplement that registry only when an independently
reviewed predecessor provision, the predecessor official XML provision, and
the candidate official XML provision are all bound and byte-stable at the
provision level.  Whole-document drift elsewhere in an Act is not authority
to qualify a changed provision.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any
from xml.etree import ElementTree as ET

SCHEMA = "legalbot.candidate-provision-qualification.v1"
RELATIVE_PATH = "config/candidate_provision_qualification.v1.json"
_PREDECESSOR_SCHEMA = "legalbot.provision-verification.v1"
_SOURCE_MANIFEST_SCHEMA = "legalbot.approved-source-manifest.v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_ID_RE = re.compile(
    r"(?P<authority>(?:ukpga|uksi)(?::[A-Za-z0-9-]+){2,4})"
    r":latest-available@(?P<as_of>20\d{2}-\d{2}-\d{2})$"
)
_SECTION_RE = re.compile(r"section\s+(?P<section>[0-9]+[A-Za-z]*)$")
_PROVISION_CONTEXT_ATTRIBUTES = (
    "DocumentURI",
    "IdURI",
    "Match",
    "RestrictEndDate",
    "RestrictExtent",
    "RestrictStartDate",
    "Status",
    "id",
)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: object) -> str:
    return _sha256(
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()
    )


def _safe_project_path(project_root: Path, value: object, *, field: str) -> Path:
    relative = PurePosixPath(str(value or ""))
    if not relative.parts or relative.is_absolute() or ".." in relative.parts:
        raise RuntimeError(f"{field} is not a safe project-relative path")
    path = project_root.joinpath(*relative.parts)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"{field} is missing or unsafe")
    return path


def official_provision_snapshot(
    raw: bytes,
    *,
    authority_identity: str,
    legal_locator: str,
) -> dict[str, Any]:
    """Return a deterministic identity for one official XML provision.

    The identity covers the entire provision subtree plus all inherited
    effective-date, extent, status and URI attributes on its ancestor chain.
    It intentionally excludes unrelated sibling provisions and commentary.
    """

    opening = raw[:100_000].upper()
    if b"<!DOCTYPE" in opening or b"<!ENTITY" in opening:
        raise RuntimeError("official XML contains a prohibited DTD or entity declaration")
    locator_match = _SECTION_RE.fullmatch(legal_locator)
    if locator_match is None:
        raise RuntimeError("candidate qualification supports exact top-level sections only")
    root = ET.fromstring(raw)
    if root.attrib.get("DocumentURI") != (
        f"http://www.legislation.gov.uk/{authority_identity.replace(':', '/')}"
    ):
        raise RuntimeError("official XML identity does not match the qualification authority")
    node_id = f"section-{locator_match.group('section')}"
    nodes = [element for element in root.iter() if element.attrib.get("id") == node_id]
    if len(nodes) != 1:
        raise RuntimeError("official XML provision identity is missing or ambiguous")
    node = nodes[0]
    parents = {child: parent for parent in root.iter() for child in parent}
    chain: list[ET.Element] = []
    current: ET.Element | None = node
    while current is not None:
        chain.append(current)
        current = parents.get(current)
    inherited_context = [
        {
            "element": element.tag.rsplit("}", 1)[-1],
            "attributes": {
                name: element.attrib[name]
                for name in _PROVISION_CONTEXT_ATTRIBUTES
                if name in element.attrib
            },
        }
        for element in reversed(chain)
    ]
    serialized = ET.tostring(node, encoding="unicode")
    canonical = ET.canonicalize(serialized)
    if canonical is None:
        raise RuntimeError("official XML provision cannot be canonicalized")
    normalized_text = " ".join("".join(node.itertext()).split())
    snapshot = {
        "authority_identity_id": authority_identity,
        "legal_locator": legal_locator,
        "provision_c14n_sha256": _sha256(canonical.encode("utf-8")),
        "provision_text_sha256": _sha256(normalized_text.encode("utf-8")),
        "inherited_context": inherited_context,
        "inherited_context_sha256": _canonical_sha256(inherited_context),
    }
    snapshot["snapshot_sha256"] = _canonical_sha256(snapshot)
    return snapshot


def _verified_raw(path: Path, expected_sha256: object, *, field: str) -> bytes:
    expected = str(expected_sha256 or "")
    if _SHA256_RE.fullmatch(expected) is None:
        raise RuntimeError(f"{field} digest is invalid")
    raw = path.read_bytes()
    if _sha256(raw) != expected:
        raise RuntimeError(f"{field} digest mismatch")
    return raw


def load_candidate_provision_qualifications(
    project_root: Path,
    *,
    build_path: Path,
    build_id: str,
    qualification_path: Path | None = None,
) -> tuple[dict[tuple[str, str], dict[str, Any]], str]:
    """Load and independently replay the one selected successor artifact."""

    path = qualification_path or (project_root / RELATIVE_PATH)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("candidate provision qualification path is missing or unsafe")
    try:
        path.resolve().relative_to(project_root.resolve())
    except ValueError as exc:
        raise RuntimeError("candidate provision qualification path escapes the project") from exc
    raw = path.read_bytes()
    payload = json.loads(raw)
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != SCHEMA
        or payload.get("status") != "active"
    ):
        raise RuntimeError("candidate provision qualification is invalid")
    candidate = payload.get("candidate")
    if not isinstance(candidate, dict) or candidate.get("build_id") != build_id:
        raise RuntimeError("candidate provision qualification targets another build")
    manifest_raw = _verified_raw(
        build_path / "manifest.json",
        candidate.get("manifest_file_sha256"),
        field="candidate manifest",
    )
    seal_raw = _verified_raw(
        build_path / "seal.json", candidate.get("seal_file_sha256"), field="candidate seal"
    )
    manifest_payload = json.loads(manifest_raw)
    seal_payload = json.loads(seal_raw)
    if (
        not isinstance(manifest_payload, dict)
        or not isinstance(seal_payload, dict)
        or manifest_payload.get("build_id") != build_id
        or seal_payload.get("build_id") != build_id
        or seal_payload.get("manifest_sha256") != candidate.get("manifest_file_sha256")
        or seal_payload.get("lance_tree_sha256") != candidate.get("lance_tree_sha256")
    ):
        raise RuntimeError("candidate qualification immutable build binding is invalid")
    source_manifest_raw = _verified_raw(
        build_path / "approved-source-manifest.json",
        candidate.get("source_manifest_file_sha256"),
        field="candidate source manifest",
    )
    _verified_raw(
        build_path / "provision-verification.v1.json",
        candidate.get("embedded_provision_registry_sha256"),
        field="embedded provision registry",
    )
    source_manifest = json.loads(source_manifest_raw)
    if (
        not isinstance(source_manifest, dict)
        or source_manifest.get("schema") != _SOURCE_MANIFEST_SCHEMA
    ):
        raise RuntimeError("candidate source manifest is invalid")
    sources_value = source_manifest.get("sources")
    if not isinstance(sources_value, list):
        raise RuntimeError("candidate source manifest has no sources")
    sources = {
        str(item.get("authority_identity_id") or ""): item
        for item in sources_value
        if isinstance(item, dict)
    }

    predecessor_binding = payload.get("predecessor_registry")
    if not isinstance(predecessor_binding, dict):
        raise RuntimeError("candidate qualification predecessor binding is invalid")
    predecessor_path = _safe_project_path(
        project_root, predecessor_binding.get("relative_path"), field="predecessor registry"
    )
    predecessor_raw = _verified_raw(
        predecessor_path,
        predecessor_binding.get("sha256"),
        field="predecessor registry",
    )
    predecessor = json.loads(predecessor_raw)
    predecessor_values = predecessor.get("records") if isinstance(predecessor, dict) else None
    if predecessor.get("schema") != _PREDECESSOR_SCHEMA or not isinstance(predecessor_values, list):
        raise RuntimeError("candidate qualification predecessor registry is invalid")
    predecessor_records = {
        (str(item.get("stable_source_id") or ""), str(item.get("legal_locator") or "")): item
        for item in predecessor_values
        if isinstance(item, dict)
    }

    source_root = PurePosixPath(str(payload.get("source_root") or ""))
    if (
        source_root.is_absolute()
        or ".." in source_root.parts
        or source_root.parts[:1] != ("sources",)
    ):
        raise RuntimeError("candidate qualification source root is unsafe")
    records = payload.get("records")
    if not isinstance(records, list) or not records:
        raise RuntimeError("candidate provision qualification is empty")
    output: dict[tuple[str, str], dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict):
            raise RuntimeError("candidate qualification record is invalid")
        source_id = str(record.get("stable_source_id") or "")
        locator = str(record.get("legal_locator") or "")
        source_match = _SOURCE_ID_RE.fullmatch(source_id)
        source = sources.get(source_match.group("authority") if source_match else "")
        predecessor_source_id = str(record.get("predecessor_source_id") or "")
        predecessor_record = predecessor_records.get((predecessor_source_id, locator))
        if (
            source_match is None
            or source is None
            or str(source.get("stable_identifier") or "") != source_id
            or str(source.get("content_sha256") or "")
            != str(record.get("source_content_sha256") or "")
            or str(source.get("version_sha256") or "")
            != str(record.get("source_version_sha256") or "")
            or "E+W" not in str(record.get("verified_extent") or "")
            or predecessor_record is None
            or record.get("predecessor_record_sha256") != _canonical_sha256(predecessor_record)
            or record.get("verified_extent") != predecessor_record.get("verified_extent")
            or record.get("section_unapplied_effect_count")
            != predecessor_record.get("section_unapplied_effect_count")
            or record.get("unapplied_effect_materiality")
            != predecessor_record.get("unapplied_effect_materiality")
            or record.get("qualification_provenance")
            != "inherited_identical_official_provision_snapshot"
        ):
            raise RuntimeError("candidate qualification record does not bind its source")
        provenance = record.get("official_provision_provenance")
        if not isinstance(provenance, dict):
            raise RuntimeError("candidate qualification provision provenance is invalid")
        authority_path = source_match.group("authority").replace(":", "_")
        subject_folder = str(record.get("source_subject_folder") or "")
        if not subject_folder or "/" in subject_folder or subject_folder in {".", ".."}:
            raise RuntimeError("candidate qualification source folder is unsafe")
        old_date = str(provenance.get("predecessor_as_of_date") or "")
        new_date = str(provenance.get("candidate_as_of_date") or "")
        old_path = project_root.joinpath(
            *source_root.parts,
            "Official Legislation",
            "United Kingdom",
            "Current",
            subject_folder,
            f"{authority_path}__retrieved-{old_date}.xml",
        )
        new_path = project_root.joinpath(
            *source_root.parts,
            "Official Legislation",
            "United Kingdom",
            "Current",
            subject_folder,
            f"{authority_path}__retrieved-{new_date}.xml",
        )
        old_raw = _verified_raw(
            old_path, provenance.get("predecessor_source_sha256"), field="predecessor source"
        )
        new_raw = _verified_raw(
            new_path, provenance.get("candidate_source_sha256"), field="candidate source"
        )
        old_snapshot = official_provision_snapshot(
            old_raw,
            authority_identity=source_match.group("authority"),
            legal_locator=locator,
        )
        new_snapshot = official_provision_snapshot(
            new_raw,
            authority_identity=source_match.group("authority"),
            legal_locator=locator,
        )
        expected_snapshot = str(provenance.get("provision_snapshot_sha256") or "")
        if (
            old_snapshot != new_snapshot
            or old_snapshot.get("snapshot_sha256") != expected_snapshot
            or old_snapshot.get("provision_c14n_sha256") != provenance.get("provision_c14n_sha256")
            or old_snapshot.get("provision_text_sha256") != provenance.get("provision_text_sha256")
            or old_snapshot.get("inherited_context_sha256")
            != provenance.get("inherited_context_sha256")
            or record.get("official_source_url") != predecessor_record.get("official_source_url")
        ):
            raise RuntimeError("official provision changed or its provenance is invalid")
        key = (source_id, locator)
        if key in output:
            raise RuntimeError("candidate qualification record is duplicated")
        output[key] = dict(record)
    if int(payload.get("record_count") or -1) != len(output):
        raise RuntimeError("candidate qualification record count is incoherent")
    return output, _sha256(raw)
