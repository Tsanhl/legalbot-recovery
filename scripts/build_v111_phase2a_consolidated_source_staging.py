#!/usr/bin/env python3
"""Stage the exact owner-approved Phase-2A successor source scope.

This command is deliberately narrower than a source scan or candidate build. It
cross-checks the approved 142-source seminar packet and the cumulative 25-source
Phase-2A approval, deduplicates by canonical authority identity and raw content
SHA-256, and copies only bytes missing from the last complete source scan into a
dated repository source folder. It never changes catalogue review state, scans,
chunks, embeds, builds, promotes, or opens a later phase gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
CATALOGUE_PATH = PROJECT_ROOT / "data/catalog.sqlite3"
TARGET_SOURCE_ROOT = PROJECT_ROOT / "sources/phase2a-approved-2026-08-27"
OUTPUT_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2A-2026-08-27-consolidated-source-staging"
)

SEMINAR_PACKET_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2A-2026-08-27-seminar-source-owner-packet"
)
SEMINAR_BATCH_PATH = SEMINAR_PACKET_ROOT / "SEMINAR-SOURCE-OWNER-DECISION-BATCH.json"
SEMINAR_PAYLOAD_PATH = SEMINAR_PACKET_ROOT / "OWNER-APPROVAL-PAYLOAD.json"
SEMINAR_APPROVAL_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2A-2026-08-27-seminar-source-owner-approved"
)
CROSSWALK_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2A-2026-08-27-deterministic-exact-span-crosswalk-r2"
)
CROSSWALK_PATH = CROSSWALK_ROOT / "APPROVED-142-SOURCE-CROSSWALK.json"
CROSSWALK_PACKAGE_PATH = CROSSWALK_ROOT / "PACKAGE-INDEX.json"
CUMULATIVE_25_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-26-r113-post-r110-owner-approved"
    / "CUMULATIVE-APPROVED-SOURCE-ADMISSIONS-25.json"
)
R59_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r59-consolidated-judgment-advisory"
    / "CONSOLIDATED-JUDGMENT-ADVISORY-20-AND-SOURCE-PROPOSALS-9.json"
)
R83_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r83-supplemental-proposition-verification"
    / "OWNER-SOURCE-ADMISSION-BATCH.json"
)
R84_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r84-procurement-currentness-verification"
    / "OWNER-SOURCE-ADMISSION-BATCH.json"
)
R85_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r85-as-made-currentness-verification"
    / "OWNER-SOURCE-ADMISSION-BATCH.json"
)
R86_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r86-issue-source-rehoming-review"
    / "OWNER-ISSUE-SOURCE-ADMISSION-BATCH.json"
)
R111_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-26-r111-source-currentness-owner-batch"
    / "OWNER-SOURCE-CURRENTNESS-DECISION-BATCH.json"
)
QUARANTINE_ROOT = PROJECT_ROOT / "data/quarantine"

EXPECTED_SEMINAR_PAYLOAD_DIGEST = (
    "20e21e43aefc6348db5344782ddc3ab9d41a05c2c19aeb24b58a3fcd02371c73"
)
EXPECTED_SEMINAR_BATCH_DIGEST = (
    "6b2fc70e2c15e706bc26034aed7c6940b28b4220f66a7b0fbd28b97a0f53c8b6"
)
EXPECTED_SEMINAR_APPROVAL_RECEIPT_DIGEST = (
    "878a1d2582a07c40dda7b5311aa22970885f78437e5f3d39109e667b9a6be7f9"
)
EXPECTED_CROSSWALK_PACKAGE_DIGEST = (
    "80f666c6dae4f323778eff0924d4b4894cc960d6484b2ee57edea08592f527ba"
)
EXPECTED_CROSSWALK_DIGEST = (
    "0994b3be171601055d26f9bee7c275aaa5291538d4da1e3fdfdef084be13011b"
)
EXPECTED_CUMULATIVE_25_DIGEST = (
    "667fa9cb36188740fa28b0d4e0970ec71c82dcb123505f07584ea678bae9c32d"
)
EXPECTED_SCAN_ID = "1670d95fd8629a80-r1"
EXPECTED_SCAN_MANIFEST_SHA256 = (
    "034320999a3180d0bdd7eede82b8d969a6305bf79fee00cef058d986beccd257"
)
EXPECTED_SEMINAR_COUNT = 142
EXPECTED_PRIOR_COUNT = 25
EXPECTED_OVERLAP_COUNT = 1
EXPECTED_CONSOLIDATED_COUNT = 166
EXPECTED_FAMILY_COUNTS = {"official_judgment": 115, "legislation": 51}
NAMED_PRIOR_SOURCE_IDENTITIES = {
    "currentness-data-use-access-act-commencement-no-6-2026-as-made": (
        "uksi:2026:82"
    ),
    "currentness-mental-capacity-act-commencement-no-2-2007-as-made": (
        "uksi:2007:1897"
    ),
    "currentness-procurement-act-commencement-no-3-2024": "uksi:2024:716",
    "supplemental-carriage-of-goods-by-sea-act-1992": "ukpga:1992:50",
    "supplemental-data-use-and-access-act-2025": "ukpga:2025:18",
    "supplemental-mental-capacity-act-2005": "ukpga:2005:9",
    "supplemental-procurement-act-2023": "ukpga:2023:54",
}

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_SLUG = re.compile(r"[^a-z0-9]+")


@dataclass(slots=True)
class SourceSpec:
    authority_identity_id: str
    source_family: str
    content_sha256: str
    input_path: Path
    media_type: str
    title: str
    official_canonical_url: str
    approval_origins: list[str] = field(default_factory=list)
    retained_hold_codes: set[str] = field(default_factory=set)
    source_version_id: str | None = None


def _canonical_json(value: Any, *, newline: bool = True) -> bytes:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return (raw + ("\n" if newline else "")).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(
    value: Mapping[str, Any], field_name: str, *, newline: bool = True
) -> str:
    material = dict(value)
    supplied = str(material.pop(field_name, ""))
    if not _SHA256.fullmatch(supplied) or supplied != _sha256_bytes(
        _canonical_json(material, newline=newline)
    ):
        raise ValueError(f"invalid sealed artifact: {field_name}")
    return supplied


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"input is not a regular file: {path.name}")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"input is not an object: {path.name}")
    return value


def _require_exact_file(path: Path, expected_sha256: str) -> None:
    if not _SHA256.fullmatch(expected_sha256) or _sha256_file(path) != expected_sha256:
        raise ValueError(f"source bytes changed: {path.name}")


def _project_path(relative: str) -> Path:
    path = (PROJECT_ROOT / relative).resolve()
    if not path.is_relative_to(PROJECT_ROOT.resolve()):
        raise ValueError("source representation escapes the project root")
    if path.is_symlink() or not path.is_file():
        raise ValueError("approved source representation is unavailable")
    return path


def _family(authority_identity_id: str) -> str:
    if authority_identity_id.startswith("neutral-citation:"):
        return "official_judgment"
    if authority_identity_id.startswith(("ukpga:", "uksi:")):
        return "legislation"
    raise ValueError(f"unsupported approved authority identity: {authority_identity_id}")


def _judgment_identity(citation: str) -> str:
    return f"neutral-citation:{citation}"


def _media_type(path: Path, fallback: str = "application/octet-stream") -> str:
    suffix = path.suffix.lower()
    return {
        ".xml": "application/xml",
        ".pdf": "application/pdf",
        ".html": "text/html",
        ".htm": "text/html",
    }.get(suffix, fallback)


def _representation(value: Mapping[str, Any]) -> tuple[str, str]:
    for key in ("official_judgment_xml", "official_judgment_pdf", "official_case_page"):
        item = value.get(key)
        if not isinstance(item, Mapping):
            continue
        sha256 = str(item.get("sha256") or "")
        relative_path = str(item.get("relative_path") or "")
        if _SHA256.fullmatch(sha256) and relative_path:
            return sha256, relative_path
    raise ValueError("approved official judgment representation is unavailable")


def _load_142_specs(connection: sqlite3.Connection) -> list[SourceSpec]:
    payload = _load_object(SEMINAR_PAYLOAD_PATH)
    if (
        _sealed(
            payload,
            "owner_approval_payload_content_sha256",
            newline=False,
        )
        != EXPECTED_SEMINAR_PAYLOAD_DIGEST
    ):
        raise ValueError("seminar owner payload digest changed")
    batch = _load_object(SEMINAR_BATCH_PATH)
    if (
        _sealed(
            batch,
            "owner_decision_batch_content_sha256",
            newline=False,
        )
        != EXPECTED_SEMINAR_BATCH_DIGEST
    ):
        raise ValueError("seminar owner decision batch changed")
    approval = _load_object(SEMINAR_APPROVAL_ROOT / "OWNER-APPROVAL-RECEIPT.json")
    if (
        _sealed(
            approval,
            "approval_receipt_content_sha256",
            newline=False,
        )
        != EXPECTED_SEMINAR_APPROVAL_RECEIPT_DIGEST
        or approval.get("owner_approval_payload_content_sha256")
        != EXPECTED_SEMINAR_PAYLOAD_DIGEST
        or approval.get("owner_decision_batch_content_sha256")
        != EXPECTED_SEMINAR_BATCH_DIGEST
        or approval.get("source_admission_authorized") is not True
        or approval.get("one_consolidated_full_source_scan_authorized") is not True
        or approval.get("one_consolidated_successor_candidate_build_authorized")
        is not True
        or approval.get("embedding_in_consolidated_successor_authorized") is not True
        or approval.get("reuse_overlapping_staged_bytes_and_chunks_required")
        is not True
        or approval.get("canonical_identity_and_content_sha_crosswalk_required")
        is not True
        or approval.get("currentness_and_later_treatment_holds_retained") is not True
        or approval.get("exclusions_retained") is not True
        or approval.get("answer_release_eligible") is not False
        or approval.get("successor_must_remain_non_active") is not True
        or approval.get("source_scan_started") is not False
        or approval.get("candidate_build_started") is not False
        or approval.get("active_or_previous_write_authorized") is not False
        or approval.get("promotion_authorized") is not False
        or approval.get("phase2b_authorized") is not False
        or approval.get("development30_authorized") is not False
        or approval.get("validation30_authorized") is not False
        or approval.get("live_activation_authorized") is not False
        or approval.get("training_export_authorized") is not False
    ):
        raise ValueError("seminar owner approval boundary changed")
    crosswalk_package = _load_object(CROSSWALK_PACKAGE_PATH)
    if (
        _sealed(crosswalk_package, "package_content_sha256")
        != EXPECTED_CROSSWALK_PACKAGE_DIGEST
    ):
        raise ValueError("deterministic crosswalk package changed")
    crosswalk = _load_object(CROSSWALK_PATH)
    if (
        _sealed(crosswalk, "artifact_content_sha256")
        != EXPECTED_CROSSWALK_DIGEST
        or crosswalk.get("source_count") != EXPECTED_SEMINAR_COUNT
        or crosswalk.get("all_packet_exclusions_retained") is not True
        or crosswalk.get("currentness_and_later_treatment_holds_retained") is not True
    ):
        raise ValueError("approved 142-source crosswalk changed")

    specs: list[SourceSpec] = []
    for record in crosswalk.get("records", []):
        if not isinstance(record, Mapping):
            raise ValueError("invalid approved crosswalk record")
        if (
            record.get("owner_source_admission_authorized") is not True
            or record.get("include_once_in_consolidated_source_manifest") is not True
            or record.get("holds_retained") is not True
            or record.get("answer_release_eligible") is not False
        ):
            raise ValueError("approved crosswalk boundary changed")
        source_version_id = str(record.get("selected_source_version_id") or "")
        row = connection.execute(
            """
            SELECT sv.id,sv.metadata_json,sv.title,sv.canonical_url,
                   d.content_sha256,d.media_type,d.status,d.retrieval_canonical
            FROM source_versions sv JOIN documents d ON d.id=sv.document_id
            WHERE sv.id=?
            """,
            (source_version_id,),
        ).fetchone()
        if row is None:
            raise ValueError("approved crosswalk source version is missing")
        content_sha256 = str(record.get("selected_content_sha256") or "")
        if (
            row["content_sha256"] != content_sha256
            or row["status"] != "citable"
            or int(row["retrieval_canonical"] or 0) != 1
        ):
            raise ValueError("approved crosswalk catalogue binding changed")
        metadata = json.loads(row["metadata_json"] or "{}")
        raw_relative = str(metadata.get("raw_vault_path") or "")
        raw_path = _project_path(raw_relative)
        _require_exact_file(raw_path, content_sha256)
        authority_identity_id = str(record.get("canonical_authority_id") or "")
        specs.append(
            SourceSpec(
                authority_identity_id=authority_identity_id,
                source_family=str(record.get("source_family") or _family(authority_identity_id)),
                content_sha256=content_sha256,
                input_path=raw_path,
                media_type=str(row["media_type"] or "application/octet-stream"),
                title=str(row["title"] or record.get("official_identity") or ""),
                official_canonical_url=str(record.get("official_canonical_url") or ""),
                approval_origins=["SEMINAR_APPROVED_142"],
                retained_hold_codes=set(record.get("retained_hold_codes") or []),
                source_version_id=source_version_id,
            )
        )
    if len(specs) != EXPECTED_SEMINAR_COUNT:
        raise ValueError("approved seminar source count changed")
    return specs


def _lead_records() -> dict[str, Mapping[str, Any]]:
    records: dict[str, Mapping[str, Any]] = {}
    for path in QUARANTINE_ROOT.rglob("*.json"):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            root = json.loads(path.read_bytes())
        except (OSError, json.JSONDecodeError):
            continue
        stack = [root]
        while stack:
            value = stack.pop()
            if isinstance(value, dict):
                for key in ("lead_content_sha256", "artifact_content_sha256"):
                    digest = str(value.get(key) or "")
                    if _SHA256.fullmatch(digest) and any(
                        isinstance(value.get(item), Mapping)
                        for item in (
                            "official_judgment_xml",
                            "official_judgment_pdf",
                            "official_case_page",
                        )
                    ):
                        records[digest] = value
                stack.extend(value.values())
            elif isinstance(value, list):
                stack.extend(value)
    return records


def _hash_index(expected: set[str]) -> dict[str, Path]:
    found: dict[str, Path] = {}
    for path in QUARANTINE_ROOT.rglob("*"):
        if not expected - found.keys():
            break
        if path.is_symlink() or not path.is_file():
            continue
        digest = _sha256_file(path)
        if digest in expected:
            found[digest] = path.resolve()
    missing = expected - found.keys()
    if missing:
        raise ValueError(f"approved source bytes unavailable: {len(missing)}")
    return found


def _prior_source_inputs() -> dict[str, SourceSpec]:
    result: dict[str, SourceSpec] = {}

    r59 = _load_object(R59_PATH)
    _sealed(r59, "artifact_content_sha256")
    leads = _lead_records()
    for proposal in r59.get("source_admission_proposals", []):
        lead_sha = str(proposal.get("source_lead_content_sha256") or "")
        lead = leads.get(lead_sha)
        if lead is None:
            raise ValueError("approved later-treatment lead is unavailable")
        content_sha256, relative_path = _representation(lead)
        path = _project_path(relative_path)
        _require_exact_file(path, content_sha256)
        citation = str(proposal.get("candidate_neutral_citation") or "")
        identity = _judgment_identity(citation)
        result[identity] = SourceSpec(
            authority_identity_id=identity,
            source_family="official_judgment",
            content_sha256=content_sha256,
            input_path=path,
            media_type=_media_type(path),
            title=str(proposal.get("candidate_case_name") or citation),
            official_canonical_url="",
            approval_origins=["R95_JUDGMENT_LATER_TREATMENT"],
            retained_hold_codes={"CURRENTNESS_NOT_VERIFIED", "LATER_TREATMENT_NOT_VERIFIED"},
        )

    supplemental: dict[str, Mapping[str, Any]] = {}
    for path in (R83_PATH, R84_PATH, R85_PATH):
        artifact = _load_object(path)
        _sealed(artifact, "artifact_content_sha256")
        for proposal in artifact.get("proposals", []):
            target = str(proposal.get("source_target_id") or "")
            previous = supplemental.get(target)
            if previous is not None and (
                previous.get("official_file_sha256") != proposal.get("official_file_sha256")
                or previous.get("authority_identity") != proposal.get("authority_identity")
            ):
                raise ValueError("supplemental source proposal conflict")
            supplemental[target] = proposal

    r111 = _load_object(R111_PATH)
    _sealed(r111, "artifact_content_sha256")
    r111_sources = {
        str(item["authority_identity_id"]): item
        for item in r111.get("source_admission_decisions", [])
    }
    expected_hashes = {
        str(item.get("official_file_sha256") or "") for item in supplemental.values()
    } | {
        str(item.get("source_representation_sha256") or "")
        for item in r111_sources.values()
    }
    if any(not _SHA256.fullmatch(value) for value in expected_hashes):
        raise ValueError("approved source representation hash is invalid")
    located = _hash_index(expected_hashes)

    for target, proposal in supplemental.items():
        identity = str(proposal.get("authority_identity") or "")
        content_sha256 = str(proposal.get("official_file_sha256") or "")
        path = located[content_sha256]
        result[identity] = SourceSpec(
            authority_identity_id=identity,
            source_family="legislation",
            content_sha256=content_sha256,
            input_path=path,
            media_type=_media_type(path, "application/xml"),
            title=str(proposal.get("source_title") or target),
            official_canonical_url=str(proposal.get("official_url") or ""),
            approval_origins=["R95_SUPPLEMENTAL_OR_CURRENTNESS"],
            retained_hold_codes={"CURRENTNESS_EXTENT_EFFECTS_HOLD"},
        )

    r86 = _load_object(R86_PATH)
    _sealed(r86, "artifact_content_sha256")
    for review in r86.get("source_reviews", []):
        citation = str(review.get("neutral_citation") or "")
        if citation == "[2024] UKSC 17":
            continue
        content_sha256, relative_path = _representation(review)
        path = _project_path(relative_path)
        _require_exact_file(path, content_sha256)
        identity = _judgment_identity(citation)
        result[identity] = SourceSpec(
            authority_identity_id=identity,
            source_family="official_judgment",
            content_sha256=content_sha256,
            input_path=path,
            media_type=_media_type(path),
            title=str(review.get("case_name") or citation),
            official_canonical_url="",
            approval_origins=["R95_UKSC_REHOMING"],
            retained_hold_codes={"CURRENTNESS_NOT_VERIFIED", "LATER_TREATMENT_NOT_VERIFIED"},
        )

    for identity, item in r111_sources.items():
        content_sha256 = str(item.get("source_representation_sha256") or "")
        path = located[content_sha256]
        result[identity] = SourceSpec(
            authority_identity_id=identity,
            source_family=_family(identity),
            content_sha256=content_sha256,
            input_path=path,
            media_type=_media_type(path),
            title=str(item.get("source_title") or identity),
            official_canonical_url="",
            approval_origins=["R113_POST_R110"],
            retained_hold_codes=(
                {"CURRENTNESS_NOT_VERIFIED", "LATER_TREATMENT_NOT_VERIFIED"}
                if identity.startswith("neutral-citation:")
                else {"CURRENTNESS_EXTENT_EFFECTS_HOLD"}
            ),
        )
    return result


def _load_prior_25_specs() -> list[SourceSpec]:
    cumulative = _load_object(CUMULATIVE_25_PATH)
    if (
        _sealed(cumulative, "artifact_content_sha256")
        != EXPECTED_CUMULATIVE_25_DIGEST
        or cumulative.get("record_count") != EXPECTED_PRIOR_COUNT
        or cumulative.get("automatic_indexing") is not False
        or cumulative.get("automatic_embedding") is not False
    ):
        raise ValueError("cumulative 25-source owner approval changed")
    inputs = _prior_source_inputs()
    specs: list[SourceSpec] = []
    for record in cumulative.get("records", []):
        if (
            record.get("source_admission_authorized") is not True
            or record.get("automatic_indexing") is not False
            or record.get("automatic_embedding") is not False
            or record.get("phase2b_authorized") is not False
        ):
            raise ValueError("prior source approval boundary changed")
        identity = str(record.get("source_authority_identity_id") or "")
        if not identity:
            source_identity = str(record.get("source_identity") or "")
            if source_identity.startswith("["):
                identity = _judgment_identity(source_identity)
            elif source_identity.startswith(("ukpga:", "uksi:")):
                identity = source_identity
            else:
                identity = NAMED_PRIOR_SOURCE_IDENTITIES.get(source_identity, "")
        spec = inputs.get(identity)
        if spec is None:
            source_identity = str(record.get("source_identity") or "")
            matching = [
                value
                for value in inputs.values()
                if source_identity in value.title or value.title in source_identity
            ]
            if len(matching) != 1:
                raise ValueError(f"approved prior source cannot be resolved: {source_identity}")
            spec = matching[0]
        spec.approval_origins.append(
            f"OWNER_SOURCE_ADMISSION:{record['source_admission_content_sha256']}"
        )
        specs.append(spec)
    if len(specs) != EXPECTED_PRIOR_COUNT:
        raise ValueError("prior approved source count changed")
    return specs


def _merge_specs(specs: list[SourceSpec]) -> tuple[list[SourceSpec], int]:
    by_identity: dict[str, SourceSpec] = {}
    overlap_count = 0
    for spec in specs:
        existing = by_identity.get(spec.authority_identity_id)
        if existing is None:
            by_identity[spec.authority_identity_id] = spec
            continue
        if existing.content_sha256 != spec.content_sha256:
            raise ValueError("owner-approved authority has conflicting source bytes")
        overlap_count += 1
        existing.approval_origins = sorted(
            set(existing.approval_origins + spec.approval_origins)
        )
        existing.retained_hold_codes.update(spec.retained_hold_codes)
    merged = sorted(
        by_identity.values(), key=lambda item: (item.source_family, item.authority_identity_id)
    )
    hashes: dict[str, str] = {}
    for spec in merged:
        previous = hashes.setdefault(spec.content_sha256, spec.authority_identity_id)
        if previous != spec.authority_identity_id:
            raise ValueError("one approved byte representation maps to multiple authorities")
    return merged, overlap_count


def _latest_scan(connection: sqlite3.Connection) -> sqlite3.Row:
    row = connection.execute(
        """
        SELECT id,status,expected_file_count,files_accounted,manifest_sha256,completed_at
        FROM source_scans WHERE status='complete'
        ORDER BY completed_at DESC,created_at DESC LIMIT 1
        """
    ).fetchone()
    if (
        row is None
        or row["id"] != EXPECTED_SCAN_ID
        or row["manifest_sha256"] != EXPECTED_SCAN_MANIFEST_SHA256
        or int(row["expected_file_count"] or 0) != int(row["files_accounted"] or -1)
    ):
        raise ValueError("latest complete source scan identity changed")
    return row


def _covered_by_scan(
    connection: sqlite3.Connection, *, scan_id: str, content_sha256: str
) -> bool:
    row = connection.execute(
        """
        SELECT COUNT(*) AS n FROM source_scan_files
        WHERE scan_id=? AND content_sha256=? AND status IN ('citable','duplicate')
        """,
        (scan_id, content_sha256),
    ).fetchone()
    return bool(row and int(row["n"] or 0) > 0)


def _slug(value: str) -> str:
    slug = _SAFE_SLUG.sub("-", value.lower()).strip("-")
    return slug[:96] or "authority"


def _suffix(spec: SourceSpec) -> str:
    suffix = spec.input_path.suffix.lower()
    if suffix in {".xml", ".pdf", ".html", ".htm"}:
        return ".html" if suffix == ".htm" else suffix
    return {
        "application/xml": ".xml",
        "text/xml": ".xml",
        "application/pdf": ".pdf",
        "text/html": ".html",
    }.get(spec.media_type, ".bin")


def build_plan() -> dict[str, Any]:
    connection = sqlite3.connect(f"file:{CATALOGUE_PATH}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        scan = _latest_scan(connection)
        seminar = _load_142_specs(connection)
        prior = _load_prior_25_specs()
        merged, overlap_count = _merge_specs([*seminar, *prior])
        if overlap_count != EXPECTED_OVERLAP_COUNT:
            raise ValueError("approved source overlap count changed")
        if len(merged) != EXPECTED_CONSOLIDATED_COUNT:
            raise ValueError("consolidated approved source count changed")
        family_counts = {
            family: sum(item.source_family == family for item in merged)
            for family in EXPECTED_FAMILY_COUNTS
        }
        if family_counts != EXPECTED_FAMILY_COUNTS:
            raise ValueError("consolidated approved source family counts changed")

        stage_index = 0
        records: list[dict[str, Any]] = []
        for spec in merged:
            covered = _covered_by_scan(
                connection,
                scan_id=str(scan["id"]),
                content_sha256=spec.content_sha256,
            )
            staged_relative_path = None
            if not covered:
                stage_index += 1
                folder = (
                    "Official Judgments"
                    if spec.source_family == "official_judgment"
                    else "Official Legislation"
                )
                name = (
                    f"{stage_index:03d}-{_slug(spec.authority_identity_id)}-"
                    f"{spec.content_sha256[:16]}{_suffix(spec)}"
                )
                staged_relative_path = str(
                    (TARGET_SOURCE_ROOT / folder / name).relative_to(PROJECT_ROOT)
                )
            material = {
                "schema": "legalbot.v111.phase2a.consolidated-source-staging-row.v1",
                "authority_identity_id": spec.authority_identity_id,
                "source_family": spec.source_family,
                "content_sha256": spec.content_sha256,
                "media_type": spec.media_type,
                "title": spec.title,
                "official_canonical_url": spec.official_canonical_url,
                "source_version_id_before_final_scan": spec.source_version_id,
                "approval_origins": sorted(set(spec.approval_origins)),
                "retained_hold_codes": sorted(spec.retained_hold_codes),
                "answer_release_eligible": False,
                "covered_by_bound_scan": covered,
                "bound_scan_id": str(scan["id"]) if covered else None,
                "staged_relative_path": staged_relative_path,
                "requires_final_scan": not covered,
                "automatic_indexing": False,
                "automatic_embedding": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            }
            material["record_content_sha256"] = _sha256_bytes(_canonical_json(material))
            records.append(material)

        material = {
            "schema": "legalbot.v111.phase2a.consolidated-source-staging.v1",
            "status": "EXACT_OWNER_APPROVED_SOURCE_SCOPE_READY_FOR_ONE_FINAL_SCAN",
            "owner_qualification_route": "OWNER_ADOPTED_INTERNAL",
            "seminar_owner_payload_content_sha256": EXPECTED_SEMINAR_PAYLOAD_DIGEST,
            "seminar_owner_decision_batch_content_sha256": EXPECTED_SEMINAR_BATCH_DIGEST,
            "deterministic_crosswalk_package_content_sha256": (
                EXPECTED_CROSSWALK_PACKAGE_DIGEST
            ),
            "cumulative_prior_source_approval_content_sha256": (
                EXPECTED_CUMULATIVE_25_DIGEST
            ),
            "bound_pre_staging_scan_id": str(scan["id"]),
            "bound_pre_staging_scan_manifest_sha256": str(scan["manifest_sha256"]),
            "seminar_source_count": EXPECTED_SEMINAR_COUNT,
            "prior_approved_source_count": EXPECTED_PRIOR_COUNT,
            "deduplicated_overlap_count": overlap_count,
            "consolidated_source_count": len(merged),
            "source_family_counts": family_counts,
            "already_scan_covered_count": sum(
                record["covered_by_bound_scan"] for record in records
            ),
            "staging_required_count": sum(
                record["requires_final_scan"] for record in records
            ),
            "target_source_root": str(TARGET_SOURCE_ROOT.relative_to(PROJECT_ROOT)),
            "records": records,
            "all_packet_exclusions_retained": True,
            "all_currentness_and_later_treatment_holds_retained": True,
            "one_final_complete_source_scan_required": True,
            "source_scan_started": False,
            "catalogue_review_state_mutated": False,
            "candidate_mutated": False,
            "automatic_indexing": False,
            "automatic_embedding": False,
            "active_or_previous_write_authorized": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        material["artifact_content_sha256"] = _sha256_bytes(_canonical_json(material))
        return material
    finally:
        connection.close()


def _source_input_by_identity() -> dict[str, SourceSpec]:
    connection = sqlite3.connect(f"file:{CATALOGUE_PATH}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        seminar = _load_142_specs(connection)
    finally:
        connection.close()
    prior = _load_prior_25_specs()
    merged, _ = _merge_specs([*seminar, *prior])
    return {item.authority_identity_id: item for item in merged}


def _write_exclusive(path: Path, raw: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def apply_plan(plan: Mapping[str, Any]) -> None:
    if TARGET_SOURCE_ROOT.exists() or TARGET_SOURCE_ROOT.is_symlink():
        raise ValueError("target Phase-2A source staging root already exists")
    if OUTPUT_ROOT.exists() or OUTPUT_ROOT.is_symlink():
        raise ValueError("target Phase-2A staging evidence root already exists")
    inputs = _source_input_by_identity()
    staging_parent = TARGET_SOURCE_ROOT.parent
    staging_parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=".phase2a-approved-2026-08-27-", dir=staging_parent)
    )
    try:
        for record in plan["records"]:
            relative = record.get("staged_relative_path")
            if not relative:
                continue
            identity = str(record["authority_identity_id"])
            source = inputs[identity]
            destination = temporary / Path(str(relative)).relative_to(TARGET_SOURCE_ROOT.relative_to(PROJECT_ROOT))
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(source.input_path, destination, follow_symlinks=False)
            os.chmod(destination, 0o600)
            _require_exact_file(destination, str(record["content_sha256"]))
        os.rename(temporary, TARGET_SOURCE_ROOT)
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise

    OUTPUT_ROOT.mkdir(parents=True, mode=0o700)
    try:
        outcome = (
            "PHASE 2A OWNER-APPROVED SOURCE BYTES STAGED — ONE FINAL SOURCE SCAN REQUIRED\n"
            "No scan, indexing, embedding, candidate build, Phase 2B, or Development 30 was started.\n"
        ).encode()
        files = {
            "CONSOLIDATED-SOURCE-STAGING.json": _pretty_json(dict(plan)),
            "OUTCOME.txt": outcome,
        }
        for name, raw in files.items():
            _write_exclusive(OUTPUT_ROOT / name, raw)
        index_material = {
            "schema": "legalbot.v111.phase2a.consolidated-source-staging-package.v1",
            "status": "SOURCE_STAGING_COMPLETE_FINAL_SCAN_NOT_STARTED",
            "artifact_content_sha256": plan["artifact_content_sha256"],
            "file_count": len(files),
            "files": {
                name: {"sha256": _sha256_bytes(raw), "bytes": len(raw)}
                for name, raw in sorted(files.items())
            },
            "staged_source_count": plan["staging_required_count"],
            "source_scan_started": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        index_material["package_content_sha256"] = _sha256_bytes(
            _canonical_json(index_material)
        )
        _write_exclusive(OUTPUT_ROOT / "PACKAGE-INDEX.json", _pretty_json(index_material))
        sums = "".join(
            f"{_sha256_file(path)}  {path.name}\n"
            for path in sorted(OUTPUT_ROOT.iterdir())
            if path.is_file()
        )
        _write_exclusive(OUTPUT_ROOT / "SHA256SUMS.txt", sums.encode("utf-8"))
    except BaseException:
        raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Create the dated source and evidence folders; default is a read-only dry run",
    )
    args = parser.parse_args()
    plan = build_plan()
    if args.apply:
        apply_plan(plan)
    print(
        json.dumps(
            {
                "apply": bool(args.apply),
                "status": plan["status"],
                "consolidated_source_count": plan["consolidated_source_count"],
                "already_scan_covered_count": plan["already_scan_covered_count"],
                "staging_required_count": plan["staging_required_count"],
                "artifact_content_sha256": plan["artifact_content_sha256"],
                "source_scan_started": False,
                "candidate_mutated": False,
                "phase2b_authorized": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
