#!/usr/bin/env python3
"""Derive lossless canonical Markdown from the sealed Phase-2A FCA JSON.

This is a create-only, pre-owner transform.  It verifies the exact source-
binding delta and its r7 repair quarantine, converts all fifteen official FCA
JSON responses without selecting or paraphrasing legal content, and publishes
only an immutable quarantine package.  It never writes a source root,
catalogue, index, candidate, pointer, qualification result, or answer.

The canonical Markdown has two complementary representations:

* every official response field is present in visible canonical JSON blocks,
  with each provision name and content text also exposed as readable blocks;
* the complete canonical JSON response is embedded as base64 in a canonical
  block marker.  A verifier decodes it and proves semantic equality with the
  raw JSON object, while the raw byte SHA-256 preserves exact provenance.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.ingestion.markdown import CanonicalMarkdownConverter  # noqa: E402
from app.ingestion.models import (  # noqa: E402
    BlockKind,
    DocumentFormat,
    Jurisdiction,
    MaterialLane,
    ParseResult,
    ParseStatus,
    Provenance,
    SourceIdentity,
    StructuralBlock,
)
from app.ingestion.parsers import ParserRegistry  # noqa: E402

REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
R7_ROOT_NAME = "LegalBot-Phase2A-2026-08-28-source-binding-repair-quarantine-r7"
R7_ROOT = REVIEW_ROOT / R7_ROOT_NAME
R7_MANIFEST_NAME = "REPAIR-QUARANTINE-MANIFEST.json"
R7_PACKAGE_NAME = "PACKAGE-MANIFEST.json"
R7_CHECKSUMS_NAME = "SHA256SUMS.txt"
R7_MANIFEST_PATH = R7_ROOT / R7_MANIFEST_NAME
R7_PACKAGE_PATH = R7_ROOT / R7_PACKAGE_NAME
R7_CHECKSUMS_PATH = R7_ROOT / R7_CHECKSUMS_NAME

DELTA_ROOT_NAME = "LegalBot-Phase2A-2026-08-28-source-binding-delta-owner-packet-r1"
DELTA_ROOT = REVIEW_ROOT / DELTA_ROOT_NAME
DELTA_NAME = "EXACT-SOURCE-BINDING-DELTA-OWNER-PACKET.json"
DELTA_PATH = DELTA_ROOT / DELTA_NAME

DEFAULT_OUTPUT_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-fca-canonical-markdown-quarantine-r1"
)

EXPECTED_DELTA_CONTENT_SHA256 = "01312e142dd084271aa005b3d2a5ba8b93564bf3a841e1f5a4ec68c06a604ac0"
EXPECTED_DELTA_FILE_SHA256 = "a3498ce36e0782d941b9c167dd9ab3e78da1a7df2537e590946b1ccea666ca3a"
EXPECTED_R7_MANIFEST_CONTENT_SHA256 = (
    "8c6c7c926b8612208287ae1c15af4d64b7f47829e9a2ff988fd4a95e9879c817"
)
EXPECTED_R7_MANIFEST_FILE_SHA256 = (
    "955503ce1d3d79602f7fe90f1c6330c63c0aea2dea6588e87f0d821eac129639"
)
EXPECTED_R7_PACKAGE_CONTENT_SHA256 = (
    "6b494e7d933d7f165e603a15934c7a1a0f2eda044897e8186f264eacbf02328c"
)
EXPECTED_R7_PACKAGE_FILE_SHA256 = "38d6b0f6dade2e8f96d0f486250b401e3e46924fdab3666a6a6ef225d74791bf"

TRANSFORM_SCHEMA = "legalbot.v111.phase2a.fca-json-canonical-markdown.v1"
TRANSFORM_IDENTITY = "fca-official-json-full-object-to-canonical-markdown"
TRANSFORM_VERSION = "1.0.0"
MANIFEST_SCHEMA = "legalbot.v111.phase2a.fca-canonical-markdown-quarantine.v1"
PACKAGE_SCHEMA = "legalbot.v111.phase2a.fca-canonical-markdown-package.v1"
STATUS = "QUARANTINED_PRE_OWNER_NOT_ADMITTED"
POINT_IN_TIME_DATE = "2026-08-14"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_R7_MEMBER = re.compile(r"^repair-representation-\d{4}-[0-9a-f]{20}\.json$")
_OUTPUT_MEMBER = re.compile(r"^fca-canonical-\d{4}-[0-9a-f]{20}\.md$")
_BLOCK_MARKER = re.compile(r"<!-- legalbot-block (.*?) -->")
_EMAIL = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
_WINDOWS_DRIVE = re.compile(r"(?i)(?:^|[\s\"'])(?:[a-z]:[\\/])")
_WINDOWS_UNC = re.compile(r"\\\\[^\\\s]+\\[^\\\s]+")

_FALSE_BOUNDARY_FIELDS = (
    "owner_approved",
    "owner_adoption_recorded",
    "owner_decisions_applied",
    "owner_outcomes_applied",
    "source_admission_authorized",
    "source_admitted",
    "catalogue_mutated",
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
    "qualification_run",
    "technical_qualification_assigned",
    "retrieval_reattestation_authorized",
    "retrieval_reattestation_run",
    "all585_qualification_authorized",
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


def _false_boundaries() -> dict[str, bool]:
    return {field: False for field in _FALSE_BOUNDARY_FIELDS}


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256(path.read_bytes())


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _pretty_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sealed(value: object) -> str:
    # Phase-2A sealed-content digests use canonical JSON with one terminal LF.
    return _sha256((_canonical_json(value) + "\n").encode("utf-8"))


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"phase2a_fca_markdown_json_constant_invalid:{value}")


def _loads_object(raw: bytes, *, error_code: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8", "strict"), parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(error_code) from exc
    if not isinstance(value, dict):
        raise ValueError(error_code)
    return value


def _verify_seal(
    value: Mapping[str, Any],
    field: str,
    expected: str,
    *,
    error_code: str,
) -> None:
    actual = value.get(field)
    material = {key: item for key, item in value.items() if key != field}
    if actual != expected or _sealed(material) != expected:
        raise ValueError(error_code)


def _verify_regular_file(path: Path, expected_sha256: str, *, error_code: str) -> bytes:
    if path.is_symlink() or not path.is_file() or _SHA256.fullmatch(expected_sha256) is None:
        raise ValueError(error_code)
    raw = path.read_bytes()
    if _sha256(raw) != expected_sha256:
        raise ValueError(error_code)
    return raw


def _verify_package_inventory(
    root: Path,
    package: Mapping[str, Any],
    checksums: str,
) -> dict[str, Mapping[str, Any]]:
    files = package.get("files")
    if (
        not isinstance(files, list)
        or package.get("file_count") != len(files)
        or len(files) != 17
        or not all(isinstance(item, Mapping) for item in files)
    ):
        raise ValueError("phase2a_fca_markdown_r7_package_inventory_invalid")
    by_name = {str(item.get("path") or ""): item for item in files}
    if len(by_name) != len(files) or list(by_name) != sorted(by_name):
        raise ValueError("phase2a_fca_markdown_r7_package_inventory_invalid")
    for name, item in by_name.items():
        if not name or Path(name).name != name:
            raise ValueError("phase2a_fca_markdown_r7_package_inventory_invalid")
        raw = _verify_regular_file(
            root / name,
            str(item.get("sha256") or ""),
            error_code="phase2a_fca_markdown_r7_package_member_invalid",
        )
        if item.get("bytes") != len(raw):
            raise ValueError("phase2a_fca_markdown_r7_package_member_invalid")
    expected_checksums = (
        "".join(f"{by_name[name]['sha256']}  {name}\n" for name in sorted(by_name))
        + f"{EXPECTED_R7_PACKAGE_FILE_SHA256}  {R7_PACKAGE_NAME}\n"
    )
    if checksums != expected_checksums:
        raise ValueError("phase2a_fca_markdown_r7_checksums_invalid")
    return by_name


def _verify_inputs() -> list[tuple[dict[str, Any], dict[str, Any], bytes]]:
    for root, code in (
        (R7_ROOT, "phase2a_fca_markdown_r7_root_invalid"),
        (DELTA_ROOT, "phase2a_fca_markdown_delta_root_invalid"),
    ):
        if root.is_symlink() or not root.is_dir():
            raise ValueError(code)
    if _sha256_file(DELTA_PATH) != EXPECTED_DELTA_FILE_SHA256:
        raise ValueError("phase2a_fca_markdown_delta_file_digest_invalid")
    if _sha256_file(R7_MANIFEST_PATH) != EXPECTED_R7_MANIFEST_FILE_SHA256:
        raise ValueError("phase2a_fca_markdown_r7_manifest_file_digest_invalid")
    if _sha256_file(R7_PACKAGE_PATH) != EXPECTED_R7_PACKAGE_FILE_SHA256:
        raise ValueError("phase2a_fca_markdown_r7_package_file_digest_invalid")

    delta = _loads_object(
        DELTA_PATH.read_bytes(), error_code="phase2a_fca_markdown_delta_json_invalid"
    )
    manifest = _loads_object(
        R7_MANIFEST_PATH.read_bytes(),
        error_code="phase2a_fca_markdown_r7_manifest_json_invalid",
    )
    package = _loads_object(
        R7_PACKAGE_PATH.read_bytes(),
        error_code="phase2a_fca_markdown_r7_package_json_invalid",
    )
    _verify_seal(
        delta,
        "artifact_content_sha256",
        EXPECTED_DELTA_CONTENT_SHA256,
        error_code="phase2a_fca_markdown_delta_content_digest_invalid",
    )
    _verify_seal(
        manifest,
        "manifest_content_sha256",
        EXPECTED_R7_MANIFEST_CONTENT_SHA256,
        error_code="phase2a_fca_markdown_r7_manifest_content_digest_invalid",
    )
    _verify_seal(
        package,
        "package_content_sha256",
        EXPECTED_R7_PACKAGE_CONTENT_SHA256,
        error_code="phase2a_fca_markdown_r7_package_content_digest_invalid",
    )
    package_members = _verify_package_inventory(
        R7_ROOT,
        package,
        R7_CHECKSUMS_PATH.read_text(encoding="utf-8"),
    )

    if (
        delta.get("status") != "EXACT_SOURCE_BINDING_DELTA_READY_NOT_ADOPTED"
        or delta.get("new_exact_owner_adoption_required") is not True
        or delta.get("owner_adoption_recorded") is not False
        or delta.get("source_admission_authorized") is not False
        or manifest.get("status") != "EXACT_REPLACEMENTS_QUARANTINED_OWNER_DELTA_REQUIRED"
        or manifest.get("source_admitted") is not False
    ):
        raise ValueError("phase2a_fca_markdown_pre_owner_boundary_invalid")

    records = manifest.get("records")
    decisions = delta.get("proposed_corrected_source_admissions")
    if (
        not isinstance(records, list)
        or not isinstance(decisions, list)
        or len(records) != 15
        or len(decisions) != 15
    ):
        raise ValueError("phase2a_fca_markdown_scope_invalid")
    record_by_id = {str(record.get("record_id") or ""): record for record in records}
    if len(record_by_id) != 15:
        raise ValueError("phase2a_fca_markdown_scope_invalid")

    result: list[tuple[dict[str, Any], dict[str, Any], bytes]] = []
    seen_members: set[str] = set()
    for decision in sorted(decisions, key=lambda item: str(item.get("replacement_key") or "")):
        if not isinstance(decision, dict):
            raise ValueError("phase2a_fca_markdown_delta_decision_invalid")
        record_id = str(decision.get("repair_record_id") or "")
        record = record_by_id.get(record_id)
        if not isinstance(record, dict):
            raise ValueError("phase2a_fca_markdown_delta_crosslink_invalid")
        member = str(record.get("quarantine_member") or "")
        raw_sha256 = str(record.get("raw_sha256") or "")
        if (
            _R7_MEMBER.fullmatch(member) is None
            or member in seen_members
            or member not in package_members
            or decision.get("decision_kind")
            != "PROPOSE_CORRECTED_SUBSTANTIVE_REPRESENTATION_ADMISSION"
            or decision.get("owner_decision_required") is not True
            or decision.get("owner_decision_applied") is not False
            or decision.get("source_admission_authorized") is not False
            or decision.get("source_admitted") is not False
            or decision.get("repair_record_content_sha256") != record.get("record_content_sha256")
            or decision.get("replacement_key") != record.get("replacement_key")
            or decision.get("raw_sha256") != raw_sha256
            or decision.get("quarantine_member") != member
            or decision.get("proposed_source_version_id")
            != record.get("proposed_source_version_id")
            or package_members[member].get("sha256") != raw_sha256
            or record.get("content_type") != "application/json"
            or record.get("content_fitness_status") != "SUBSTANTIVE_BODY_AND_LOCATORS_VERIFIED"
            or record.get("json_point_in_time_date_verified") != "14-08-2026"
        ):
            raise ValueError("phase2a_fca_markdown_delta_crosslink_invalid")
        raw = _verify_regular_file(
            R7_ROOT / member,
            raw_sha256,
            error_code="phase2a_fca_markdown_raw_member_invalid",
        )
        if len(raw) != record.get("bytes"):
            raise ValueError("phase2a_fca_markdown_raw_member_invalid")
        seen_members.add(member)
        result.append((record, decision, raw))
    if len(result) != 15 or len(seen_members) != 15:
        raise ValueError("phase2a_fca_markdown_scope_invalid")
    return result


def _json_shape(value: object, depth: int = 0) -> dict[str, int]:
    counts = {
        "arrays": 0,
        "objects": 0,
        "keys": 0,
        "scalar_values": 0,
        "max_depth": depth,
    }
    if isinstance(value, dict):
        counts["objects"] = 1
        counts["keys"] = len(value)
        for item in value.values():
            child = _json_shape(item, depth + 1)
            for key in ("arrays", "objects", "keys", "scalar_values"):
                counts[key] += child[key]
            counts["max_depth"] = max(counts["max_depth"], child["max_depth"])
    elif isinstance(value, list):
        counts["arrays"] = 1
        for item in value:
            child = _json_shape(item, depth + 1)
            for key in ("arrays", "objects", "keys", "scalar_values"):
                counts[key] += child[key]
            counts["max_depth"] = max(counts["max_depth"], child["max_depth"])
    else:
        counts["scalar_values"] = 1
    return counts


def _validate_fca_payload(
    payload: Mapping[str, Any], record: Mapping[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if (
        payload.get("Success") is not True
        or payload.get("Error") is not None
        or payload.get("UnAuthorizedRequest") is not False
    ):
        raise ValueError("phase2a_fca_markdown_api_envelope_invalid")
    response = payload.get("Result")
    if not isinstance(response, dict):
        raise ValueError("phase2a_fca_markdown_result_invalid")
    provisions = response.get("provisions")
    if (
        not isinstance(provisions, list)
        or not provisions
        or len(provisions) != record.get("json_provision_count")
        or response.get("chapterId") != record.get("json_chapter_id_verified")
        or response.get("sectionId") != record.get("json_section_id_verified")
    ):
        raise ValueError("phase2a_fca_markdown_result_structure_invalid")
    seen_ids: set[str] = set()
    typed: list[dict[str, Any]] = []
    for provision in provisions:
        if not isinstance(provision, dict):
            raise ValueError("phase2a_fca_markdown_provision_invalid")
        entity_id = provision.get("entityId")
        if (
            not isinstance(entity_id, str)
            or not entity_id
            or entity_id in seen_ids
            or provision.get("isDeleted") is not False
            or not isinstance(provision.get("provisionName"), str)
            or not provision["provisionName"].strip()
            or not isinstance(provision.get("contentText"), str)
            or not provision["contentText"].strip()
            or not isinstance(provision.get("contentType"), str)
            or not provision["contentType"].strip()
        ):
            raise ValueError("phase2a_fca_markdown_provision_invalid")
        canonical_provision = _canonical_json(provision)
        if "```" in canonical_provision or "```" in provision["contentText"]:
            raise ValueError("phase2a_fca_markdown_fence_collision")
        seen_ids.add(entity_id)
        typed.append(provision)
    if _sealed(sorted(seen_ids)) != record.get("json_entity_id_set_sha256"):
        raise ValueError("phase2a_fca_markdown_entity_set_invalid")
    return response, typed


def _make_provenance(payload: Mapping[str, Any], record: Mapping[str, Any]) -> Provenance:
    response = payload["Result"]
    chapter_name = str(response.get("chapterName") or response.get("chapterId") or "FCA Handbook")
    return Provenance(
        source_identity=SourceIdentity(
            "fca-handbook-api",
            str(record["representation_url"]),
            str(record["source_version_mode"]),
        ),
        title=chapter_name,
        source_kind="official_regulator_rule_api_response",
        jurisdiction=Jurisdiction.UNITED_KINGDOM,
        material_lane=MaterialLane.REGULATOR_RULE,
        content_sha256=str(record["raw_sha256"]),
        retrieved_at=str(record["retrieved_at"]),
        canonical_url=str(record["canonical_url"]),
        effective_as_at=POINT_IN_TIME_DATE,
        modified_at=(
            str(response["lastModifiedDate"])
            if response.get("lastModifiedDate") is not None
            else None
        ),
        extra={
            "transform_schema": TRANSFORM_SCHEMA,
            "transform_identity": TRANSFORM_IDENTITY,
            "transform_version": TRANSFORM_VERSION,
            "source_binding_delta_content_sha256": EXPECTED_DELTA_CONTENT_SHA256,
            "repair_record_id": record["record_id"],
            "repair_record_content_sha256": record["record_content_sha256"],
            "proposed_source_version_id": record["proposed_source_version_id"],
            "representation_url": record["representation_url"],
        },
    )


def _build_parse_result(
    payload: Mapping[str, Any],
    record: Mapping[str, Any],
) -> tuple[ParseResult, bytes, dict[str, int]]:
    response, provisions = _validate_fca_payload(payload, record)
    canonical_raw = _canonical_json(payload).encode("utf-8")
    payload_base64 = base64.b64encode(canonical_raw).decode("ascii")
    title = str(response.get("chapterName") or response.get("chapterId"))
    response_metadata = {
        **{key: value for key, value in payload.items() if key != "Result"},
        "Result": {key: value for key, value in response.items() if key != "provisions"},
    }
    blocks: list[StructuralBlock] = [
        StructuralBlock(
            0,
            BlockKind.TITLE,
            title,
            (title,),
            source_anchor=str(response.get("chapterId") or "fca-handbook"),
            metadata={
                "level": 1,
                "transform_schema": TRANSFORM_SCHEMA,
                "transform_identity": TRANSFORM_IDENTITY,
                "transform_version": TRANSFORM_VERSION,
                "raw_sha256": record["raw_sha256"],
                "canonical_json_sha256": _sha256(canonical_raw),
                "canonical_json_base64": payload_base64,
            },
        ),
        StructuralBlock(
            1,
            BlockKind.HEADING,
            "Complete official response metadata",
            (title, "Complete official response metadata"),
            metadata={"level": 2},
        ),
        StructuralBlock(
            2,
            BlockKind.CODE,
            _canonical_json(response_metadata),
            (title, "Complete official response metadata"),
            metadata={"content_type": "application/json", "complete": True},
        ),
    ]
    for ordinal, provision in enumerate(provisions, 1):
        provision_name = str(provision["provisionName"])
        heading_path = (title, provision_name)
        blocks.extend(
            (
                StructuralBlock(
                    len(blocks),
                    BlockKind.HEADING,
                    provision_name,
                    heading_path,
                    source_anchor=str(provision["entityId"]),
                    metadata={
                        "level": 2,
                        "provision_ordinal": ordinal,
                        "entity_id": provision["entityId"],
                    },
                ),
                StructuralBlock(
                    len(blocks) + 1,
                    BlockKind.PARAGRAPH,
                    str(provision["contentText"]),
                    heading_path,
                    source_anchor=str(provision["entityId"]),
                    metadata={
                        "official_field": "contentText",
                        "content_sha256": _sha256(str(provision["contentText"]).encode("utf-8")),
                    },
                ),
                StructuralBlock(
                    len(blocks) + 2,
                    BlockKind.CODE,
                    _canonical_json(provision),
                    heading_path,
                    source_anchor=str(provision["entityId"]),
                    metadata={
                        "content_type": "application/json",
                        "complete_official_provision_object": True,
                        "provision_object_sha256": _sealed(provision),
                    },
                ),
            )
        )
    parsed = ParseResult(
        ParseStatus.READY,
        DocumentFormat.MARKDOWN,
        tuple(blocks),
    )
    return parsed, canonical_raw, _json_shape(payload)


def _extract_embedded_payload(markdown: str) -> tuple[dict[str, Any], bytes]:
    matches = _BLOCK_MARKER.findall(markdown)
    embedded: list[tuple[dict[str, Any], bytes]] = []
    for match in matches:
        try:
            marker = json.loads(match, parse_constant=_reject_json_constant)
        except json.JSONDecodeError as exc:
            raise ValueError("phase2a_fca_markdown_block_marker_invalid") from exc
        if not isinstance(marker, dict):
            raise ValueError("phase2a_fca_markdown_block_marker_invalid")
        metadata = marker.get("metadata")
        if not isinstance(metadata, dict) or metadata.get("transform_schema") != TRANSFORM_SCHEMA:
            continue
        payload_base64 = metadata.get("canonical_json_base64")
        if not isinstance(payload_base64, str):
            raise ValueError("phase2a_fca_markdown_embedded_payload_invalid")
        try:
            raw = base64.b64decode(payload_base64.encode("ascii"), validate=True)
        except (UnicodeEncodeError, ValueError) as exc:
            raise ValueError("phase2a_fca_markdown_embedded_payload_invalid") from exc
        embedded.append((metadata, raw))
    if len(embedded) != 1:
        raise ValueError("phase2a_fca_markdown_embedded_payload_invalid")
    return embedded[0]


def _normalized(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.casefold()).strip()


def _verify_derived(
    *,
    markdown_bytes: bytes,
    source_payload: Mapping[str, Any],
    source_canonical_json: bytes,
    source_parse_result: ParseResult,
    provenance: Provenance,
    record: Mapping[str, Any],
    json_shape: Mapping[str, int],
) -> dict[str, Any]:
    try:
        markdown = markdown_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ValueError("phase2a_fca_markdown_derived_utf8_invalid") from exc
    metadata, embedded = _extract_embedded_payload(markdown)
    try:
        embedded_payload = _loads_object(
            embedded,
            error_code="phase2a_fca_markdown_embedded_json_invalid",
        )
    except ValueError as exc:
        raise ValueError("phase2a_fca_markdown_equivalence_invalid") from exc
    if (
        embedded != source_canonical_json
        or embedded_payload != source_payload
        or _canonical_json(embedded_payload).encode("utf-8") != embedded
        or metadata.get("canonical_json_sha256") != _sha256(source_canonical_json)
        or metadata.get("raw_sha256") != record.get("raw_sha256")
        or metadata.get("transform_identity") != TRANSFORM_IDENTITY
        or metadata.get("transform_version") != TRANSFORM_VERSION
    ):
        raise ValueError("phase2a_fca_markdown_equivalence_invalid")

    response = source_payload["Result"]
    provisions = response["provisions"]
    block_texts = [block.text for block in source_parse_result.body_blocks]
    complete_provision_objects = {_canonical_json(item) for item in provisions}
    if (
        len(complete_provision_objects) != len(provisions)
        or not complete_provision_objects <= set(block_texts)
        or any(str(item["provisionName"]) not in block_texts for item in provisions)
        or any(str(item["contentText"]) not in block_texts for item in provisions)
    ):
        raise ValueError("phase2a_fca_markdown_visible_full_content_invalid")
    normalized_markdown = _normalized(markdown)
    if any(
        _normalized(str(marker)) not in normalized_markdown
        for marker in (*record["title_markers_verified"], *record["locator_markers_verified"])
    ):
        raise ValueError("phase2a_fca_markdown_marker_missing")

    parsed_again = ParserRegistry.default().parse(
        markdown_bytes,
        filename="official-fca-representation.md",
    )
    if (
        parsed_again.status is not ParseStatus.READY
        or not parsed_again.body_blocks
        or not parsed_again.comments
    ):
        raise ValueError("phase2a_fca_markdown_parser_incompatible")
    recanonical = CanonicalMarkdownConverter().convert(parsed_again, provenance)
    if not recanonical.body_markdown or not recanonical.body_sha256:
        raise ValueError("phase2a_fca_markdown_parser_incompatible")

    return {
        "equivalence": {
            "raw_byte_sha256_bound": True,
            "raw_byte_sha256": record["raw_sha256"],
            "canonical_json_sha256": _sha256(source_canonical_json),
            "canonical_json_bytes": len(source_canonical_json),
            "embedded_payload_base64_decoded": True,
            "full_json_object_semantic_equality": True,
            "canonical_json_idempotence": True,
            "json_shape": dict(json_shape),
        },
        "structural_verification": {
            "source_provision_count": len(provisions),
            "derived_block_count": len(source_parse_result.body_blocks),
            "visible_exact_provision_name_count": len(provisions),
            "visible_exact_content_text_count": len(provisions),
            "visible_complete_provision_object_count": len(provisions),
            "all_response_metadata_fields_preserved": True,
            "all_provision_fields_preserved": True,
            "title_markers_verified": list(record["title_markers_verified"]),
            "locator_markers_verified": list(record["locator_markers_verified"]),
        },
        "parser_compatibility": {
            "parser_registry_schema": ParserRegistry.schema,
            "detected_format": parsed_again.document_format.value,
            "parse_status": parsed_again.status.value,
            "parsed_body_block_count": len(parsed_again.body_blocks),
            "parsed_comment_count": len(parsed_again.comments),
            "canonical_converter_schema": CanonicalMarkdownConverter.schema,
            "recanonical_body_sha256": recanonical.body_sha256,
            "recanonical_comments_sha256": recanonical.comments_sha256,
            "passed": True,
        },
    }


def _privacy_check_string(value: str) -> None:
    casefolded = value.casefold()
    if (
        "hltsang" in casefolded
        or "agnes" in casefolded
        or "legalbot-new" in casefolded
        or str(PROJECT_ROOT).casefold() in casefolded
        or value.startswith(("~/", "~\\"))
        or "file://" in casefolded
        or "/users/" in casefolded
        or _WINDOWS_DRIVE.search(value)
        or _WINDOWS_UNC.search(value)
        or _EMAIL.search(value)
    ):
        raise ValueError("phase2a_fca_markdown_privacy_violation")


def _privacy_check(value: object) -> None:
    if isinstance(value, str):
        _privacy_check_string(value)
    elif isinstance(value, Mapping):
        for key, item in value.items():
            _privacy_check_string(str(key))
            _privacy_check(item)
    elif isinstance(value, list | tuple):
        for item in value:
            _privacy_check(item)


def _verify_false_boundaries_recursively(value: object) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if key in _FALSE_BOUNDARY_FIELDS and item is not False:
                raise ValueError("phase2a_fca_markdown_boundary_violation")
            _verify_false_boundaries_recursively(item)
    elif isinstance(value, list):
        for item in value:
            _verify_false_boundaries_recursively(item)


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _validated_output_root(output_root: Path, *, review_root: Path) -> Path:
    if review_root.is_symlink() or not review_root.is_dir():
        raise ValueError("phase2a_fca_markdown_review_root_invalid")
    review_resolved = review_root.resolve()
    output_absolute = output_root.absolute()
    if output_absolute.exists() or output_absolute.is_symlink():
        raise ValueError("phase2a_fca_markdown_output_exists")
    parent = output_absolute.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError("phase2a_fca_markdown_output_parent_invalid")
    output_resolved = parent.resolve() / output_absolute.name
    if (
        output_resolved.parent != review_resolved
        or output_resolved == review_resolved
        or not output_resolved.is_relative_to(review_resolved)
    ):
        raise ValueError("phase2a_fca_markdown_output_outside_review_root")
    return output_resolved


def _publish(output_root: Path, files: Mapping[str, bytes]) -> dict[str, str]:
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.staging-", dir=output_root.parent))
    try:
        staging.chmod(0o700)
        entries: list[dict[str, Any]] = []
        for name, raw in sorted(files.items()):
            if not name or Path(name).name != name:
                raise ValueError("phase2a_fca_markdown_output_member_invalid")
            _write_exclusive(staging / name, raw)
            entries.append({"path": name, "bytes": len(raw), "sha256": _sha256(raw)})
        package_material = {
            "schema": PACKAGE_SCHEMA,
            "status": STATUS,
            "files": entries,
            "file_count": len(entries),
            "source_binding_delta_content_sha256": EXPECTED_DELTA_CONTENT_SHA256,
            "owner_adoption_required": True,
            "source_admission_required_for_derived_representations": True,
            "answer_eligible": False,
            "no_replace_enforced": True,
            **_false_boundaries(),
        }
        package = {
            **package_material,
            "package_content_sha256": _sealed(package_material),
        }
        _verify_false_boundaries_recursively(package)
        _privacy_check(package)
        package_raw = _pretty_json(package)
        _write_exclusive(staging / "PACKAGE-MANIFEST.json", package_raw)
        checksum_lines = [f"{item['sha256']}  {item['path']}" for item in entries]
        checksum_lines.append(f"{_sha256(package_raw)}  PACKAGE-MANIFEST.json")
        checksums_raw = ("\n".join(checksum_lines) + "\n").encode("utf-8")
        _write_exclusive(staging / "SHA256SUMS.txt", checksums_raw)
        directory_descriptor = os.open(staging, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        if output_root.exists() or output_root.is_symlink():
            raise ValueError("phase2a_fca_markdown_output_exists")
        os.rename(staging, output_root)
        parent_descriptor = os.open(output_root.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
        return {
            "package_content_sha256": str(package["package_content_sha256"]),
            "package_file_sha256": _sha256(package_raw),
            "checksums_file_sha256": _sha256(checksums_raw),
        }
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def derive(
    *,
    output_root: Path,
    created_at: datetime,
    review_root: Path = REVIEW_ROOT,
) -> dict[str, Any]:
    output_root = _validated_output_root(output_root, review_root=review_root)
    if created_at.tzinfo is None:
        raise ValueError("phase2a_fca_markdown_created_at_naive")
    inputs = _verify_inputs()
    timestamp = created_at.astimezone(UTC).isoformat(timespec="seconds")
    records: list[dict[str, Any]] = []
    derived_files: dict[str, bytes] = {}
    total_raw_bytes = 0
    total_derived_bytes = 0
    total_provisions = 0
    for ordinal, (repair, decision, raw) in enumerate(inputs, 1):
        payload = _loads_object(raw, error_code="phase2a_fca_markdown_raw_json_invalid")
        provenance = _make_provenance(payload, repair)
        parsed, canonical_raw, json_shape = _build_parse_result(payload, repair)
        bundle = CanonicalMarkdownConverter().convert(parsed, provenance)
        markdown_bytes = bundle.body_markdown.encode("utf-8")
        verification = _verify_derived(
            markdown_bytes=markdown_bytes,
            source_payload=payload,
            source_canonical_json=canonical_raw,
            source_parse_result=parsed,
            provenance=provenance,
            record=repair,
            json_shape=json_shape,
        )
        member = f"fca-canonical-{ordinal:04d}-{repair['raw_sha256'][:20]}.md"
        if _OUTPUT_MEMBER.fullmatch(member) is None or member in derived_files:
            raise ValueError("phase2a_fca_markdown_output_member_invalid")
        derived_sha256 = _sha256(markdown_bytes)
        record_material = {
            "ordinal": ordinal,
            "transform_schema": TRANSFORM_SCHEMA,
            "transform_identity": TRANSFORM_IDENTITY,
            "transform_version": TRANSFORM_VERSION,
            "source_binding_delta_content_sha256": EXPECTED_DELTA_CONTENT_SHA256,
            "source_delta_decision_id": decision["decision_id"],
            "source_delta_decision_content_sha256": decision["decision_content_sha256"],
            "repair_record_id": repair["record_id"],
            "repair_record_content_sha256": repair["record_content_sha256"],
            "replacement_key": repair["replacement_key"],
            "proposed_source_version_id": repair["proposed_source_version_id"],
            "source_version_mode": repair["source_version_mode"],
            "canonical_url": repair["canonical_url"],
            "representation_url": repair["representation_url"],
            "retrieved_at": repair["retrieved_at"],
            "point_in_time_date": POINT_IN_TIME_DATE,
            "raw_member": repair["quarantine_member"],
            "raw_bytes": len(raw),
            "raw_sha256": repair["raw_sha256"],
            "derived_member": member,
            "derived_bytes": len(markdown_bytes),
            "derived_sha256": derived_sha256,
            "canonical_markdown_schema": CanonicalMarkdownConverter.schema,
            "provenance": provenance.to_dict(),
            **verification,
            "privacy_check_passed": True,
            "no_replace_enforced": True,
            "currentness_hold_retained": True,
            "later_treatment_hold_retained": True,
            "owner_adoption_required": True,
            "source_admission_required": True,
            "answer_eligible": False,
            **_false_boundaries(),
        }
        record = {
            **record_material,
            "record_content_sha256": _sealed(record_material),
        }
        _privacy_check(record)
        _verify_false_boundaries_recursively(record)
        derived_files[member] = markdown_bytes
        records.append(record)
        total_raw_bytes += len(raw)
        total_derived_bytes += len(markdown_bytes)
        total_provisions += int(verification["structural_verification"]["source_provision_count"])

    if len(records) != 15 or len(derived_files) != 15:
        raise ValueError("phase2a_fca_markdown_scope_invalid")
    manifest_material = {
        "schema": MANIFEST_SCHEMA,
        "status": STATUS,
        "created_at": timestamp,
        "transform_schema": TRANSFORM_SCHEMA,
        "transform_identity": TRANSFORM_IDENTITY,
        "transform_version": TRANSFORM_VERSION,
        "canonical_markdown_schema": CanonicalMarkdownConverter.schema,
        "source_binding_delta": {
            "root_name": DELTA_ROOT_NAME,
            "member": DELTA_NAME,
            "artifact_content_sha256": EXPECTED_DELTA_CONTENT_SHA256,
            "file_sha256": EXPECTED_DELTA_FILE_SHA256,
            "owner_adoption_recorded": False,
        },
        "source_repair_quarantine": {
            "root_name": R7_ROOT_NAME,
            "manifest_member": R7_MANIFEST_NAME,
            "manifest_content_sha256": EXPECTED_R7_MANIFEST_CONTENT_SHA256,
            "manifest_file_sha256": EXPECTED_R7_MANIFEST_FILE_SHA256,
            "package_content_sha256": EXPECTED_R7_PACKAGE_CONTENT_SHA256,
            "package_file_sha256": EXPECTED_R7_PACKAGE_FILE_SHA256,
        },
        "summary": {
            "raw_representation_count": len(records),
            "derived_representation_count": len(records),
            "total_raw_bytes": total_raw_bytes,
            "total_derived_bytes": total_derived_bytes,
            "total_provision_count": total_provisions,
            "semantic_equivalence_pass_count": len(records),
            "structural_verification_pass_count": len(records),
            "parser_compatibility_pass_count": len(records),
            "privacy_pass_count": len(records),
            "unchanged_r7_unresolved_repair_hold_count": 5,
        },
        "records": records,
        "holds": {
            "derived_representation_owner_adoption_required": True,
            "derived_representation_source_admission_required": True,
            "all_currentness_holds_retained": True,
            "all_later_treatment_holds_retained": True,
            "r7_unresolved_repair_holds_retained_unchanged": True,
            "r7_unresolved_repair_hold_count": 5,
            "r7_unresolved_repair_old_record_ids": [
                "quarantine-binding-0a370f8e41122c812c5f26d2",
                "quarantine-binding-3688eea8275753b9dcabf559",
                "quarantine-binding-678af407a5abea67aa817bee",
                "quarantine-binding-d07fad39256d15a7c6a25893",
                "quarantine-binding-caeef16146c2eea1e2b03d09",
            ],
        },
        "owner_adoption_required": True,
        "source_admission_required_for_derived_representations": True,
        "answer_eligible": False,
        "no_replace_enforced": True,
        "no_raw_source_bytes_copied": True,
        "no_source_root_materialization": True,
        **_false_boundaries(),
    }
    manifest = {
        **manifest_material,
        "manifest_content_sha256": _sealed(manifest_material),
    }
    _privacy_check(manifest)
    _verify_false_boundaries_recursively(manifest)
    manifest_raw = _pretty_json(manifest)
    outcome = (
        "PASS — 15 sealed FCA JSON representations were transformed losslessly into "
        "canonical Markdown and remain quarantined, non-admitted, non-indexed, "
        "non-embedded, non-qualified, non-ACTIVE, and answer-ineligible.\n"
    ).encode()
    publish_files = {
        **derived_files,
        "FCA-CANONICAL-MARKDOWN-QUARANTINE-MANIFEST.json": manifest_raw,
        "OUTCOME.txt": outcome,
    }
    package = _publish(output_root, publish_files)
    return {
        "output_root": output_root,
        "manifest": manifest,
        "manifest_file_sha256": _sha256(manifest_raw),
        **package,
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument(
        "--created-at",
        help="UTC timestamp for deterministic tests; defaults to current UTC.",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    created_at = (
        datetime.fromisoformat(args.created_at.replace("Z", "+00:00"))
        if args.created_at
        else datetime.now(UTC)
    )
    result = derive(output_root=args.output_root, created_at=created_at)
    manifest = result["manifest"]
    print(f"output_root={result['output_root']}")
    print(f"derived_representations={manifest['summary']['derived_representation_count']}")
    print(f"provisions={manifest['summary']['total_provision_count']}")
    print(f"manifest_content_sha256={manifest['manifest_content_sha256']}")
    print(f"manifest_file_sha256={result['manifest_file_sha256']}")
    print(f"package_content_sha256={result['package_content_sha256']}")
    print(f"package_file_sha256={result['package_file_sha256']}")
    print(f"checksums_file_sha256={result['checksums_file_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
