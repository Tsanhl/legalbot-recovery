#!/usr/bin/env python3
"""Verify proposed Phase-2A candidate spans against fresh official XML anchors.

This is a deterministic, create-only, non-admitting check.  Whole-document
byte mismatches remain recorded; an exact anchored text match only establishes
that the proposed component appears in the fresh point-in-time official XML.
It does not decide proposition relevance, legal materiality, or qualification.
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
from collections import Counter
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

BATCH_SCHEMA = "legalbot.v111.phase2a.candidate-span-owner-review-batch.v1"
PROVENANCE_SCHEMA = "legalbot.v111-phase2a-official-source-provenance.v1"
EXPECTED_ITEM_COUNT = 48
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


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


def _load_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_fresh_span_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_fresh_span_input_must_be_object")
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


def _candidate_body(span: dict[str, Any]) -> str:
    text = _normalise_text(str(span.get("text") or ""))
    locator = _normalise_text(str(span.get("locator") or ""))
    if locator and text.startswith(locator + " "):
        return text[len(locator) + 1 :]
    return text


def _anchor_id(locator: str) -> str:
    normalized = _normalise_text(locator)
    if not re.fullmatch(r"section\s+\d+[a-z]?", normalized):
        raise ValueError("phase2a_fresh_span_locator_not_supported")
    return normalized.replace(" ", "-")


def _parse_official_xml(raw: bytes) -> tuple[ET.Element, dict[str, ET.Element]]:
    opening = raw[:100_000].upper()
    if b"<!DOCTYPE" in opening or b"<!ENTITY" in opening:
        raise ValueError("phase2a_fresh_span_xml_forbidden_declaration")
    root = ET.fromstring(raw)
    anchors: dict[str, ET.Element] = {}
    for element in root.iter():
        identifier = str(element.attrib.get("id") or "").casefold()
        if identifier:
            anchors[identifier] = element
    return root, anchors


def _span_check(
    *,
    span: dict[str, Any],
    provenance: dict[str, Any],
    raw: bytes,
    anchors: dict[str, ET.Element],
) -> dict[str, Any]:
    anchor_id = _anchor_id(str(span.get("locator") or ""))
    anchor = anchors.get(anchor_id.casefold())
    candidate_body = _candidate_body(span)
    anchor_text = _normalise_text("".join(anchor.itertext())) if anchor is not None else ""
    exact = bool(candidate_body and anchor_text and candidate_body in anchor_text)
    material = {
        "chunk_id": span.get("chunk_id"),
        "source_version_id": span.get("source_version_id"),
        "candidate_content_sha256": span.get("content_sha256"),
        "candidate_locator": span.get("locator"),
        "candidate_body_sha256": _sha256(candidate_body.encode()),
        "fresh_official_file_sha256": _sha256(raw),
        "fresh_official_record_sha256": _sealed(provenance),
        "fresh_official_url": provenance.get("final_url"),
        "fresh_official_anchor_id": anchor_id,
        "fresh_official_anchor_found": anchor is not None,
        "fresh_official_anchor_document_uri": (
            anchor.attrib.get("DocumentURI") if anchor is not None else None
        ),
        "fresh_official_anchor_id_uri": anchor.attrib.get("IdURI") if anchor is not None else None,
        "fresh_official_anchor_restrict_start_date": (
            anchor.attrib.get("RestrictStartDate") if anchor is not None else None
        ),
        "fresh_official_anchor_restrict_extent": (
            anchor.attrib.get("RestrictExtent") if anchor is not None else None
        ),
        "fresh_official_anchor_text_sha256": (
            _sha256(anchor_text.encode()) if anchor_text else None
        ),
        "candidate_body_exact_normalized_match_in_fresh_anchor": exact,
        "whole_document_candidate_byte_match": (
            provenance.get("matches_expected_version_sha256") is True
        ),
        "qualification_effect": "NONE_OWNER_REVIEW_REQUIRED",
    }
    return {**material, "check_content_sha256": _sealed(material)}


def verify(
    *,
    batch_path: Path,
    provenance_path: Path,
    quarantine_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Verify all proposed components while retaining every owner gate."""

    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_fresh_span_output_already_exists")
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_fresh_span_output_mode_invalid")

    batch = _load_json(batch_path)
    batch_sha256 = _verify_seal(
        batch,
        "batch_content_sha256",
        "phase2a_fresh_span_batch_seal_invalid",
    )
    items = batch.get("items")
    if (
        batch.get("schema") != BATCH_SCHEMA
        or not isinstance(items, list)
        or len(items) != EXPECTED_ITEM_COUNT
        or batch.get("issue_technical_qualification_count") != 0
        or batch.get("source_admission_authorized") is not False
        or batch.get("phase2b_authorized") is not False
        or batch.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_fresh_span_batch_boundary_invalid")

    provenance_artifact = _load_json(provenance_path)
    provenance_sha256 = _verify_seal(
        provenance_artifact,
        "artifact_sha256",
        "phase2a_fresh_span_provenance_seal_invalid",
    )
    if provenance_artifact.get("schema") != PROVENANCE_SCHEMA:
        raise ValueError("phase2a_fresh_span_provenance_schema_invalid")
    by_source: dict[str, list[dict[str, Any]]] = {}
    for record in provenance_artifact.get("records", []):
        if isinstance(record, dict):
            by_source.setdefault(str(record.get("target_id") or ""), []).append(record)

    xml_cache: dict[str, tuple[bytes, dict[str, ET.Element], dict[str, Any]]] = {}
    verified_items: list[dict[str, Any]] = []
    for item in items:
        span_checks: list[dict[str, Any]] = []
        for span in item.get("candidate_spans", []):
            source_id = str(span.get("source_version_id") or "")
            records = [
                record
                for record in by_source.get(source_id, [])
                if record.get("result") == "DOWNLOADED_QUARANTINED"
                and record.get("quarantine_member")
            ]
            if len(records) != 1:
                raise ValueError("phase2a_fresh_span_provenance_record_missing_or_ambiguous")
            record = records[0]
            member = str(record["quarantine_member"])
            if member not in xml_cache:
                path = quarantine_root / member
                if path.is_symlink() or not path.is_file():
                    raise ValueError("phase2a_fresh_span_quarantine_member_missing")
                raw = path.read_bytes()
                if _sha256(raw) != record.get("sha256"):
                    raise ValueError("phase2a_fresh_span_quarantine_member_hash_mismatch")
                _, anchors = _parse_official_xml(raw)
                xml_cache[member] = (raw, anchors, record)
            raw, anchors, verified_record = xml_cache[member]
            span_checks.append(
                _span_check(
                    span=span,
                    provenance=verified_record,
                    raw=raw,
                    anchors=anchors,
                )
            )
        all_match = bool(span_checks) and all(
            check["candidate_body_exact_normalized_match_in_fresh_anchor"] is True
            for check in span_checks
        )
        status = (
            "ALL_CANDIDATE_COMPONENTS_MATCH_FRESH_OFFICIAL_ANCHORS_OWNER_REVIEW_REQUIRED"
            if all_match
            else "FRESH_OFFICIAL_ANCHOR_MISMATCH_MATERIAL_GAP"
        )
        material = {
            "row_id": item.get("row_id"),
            "source_candidate_record_content_sha256": item.get("record_content_sha256"),
            "verification_status": status,
            "all_candidate_components_match_fresh_official_anchors": all_match,
            "whole_document_byte_mismatch_retained": True,
            "span_checks": span_checks,
            "semantic_proposition_binding_verified": False,
            "legal_materiality_decided": False,
            "owner_decision_required": True,
            "issue_technically_qualified": False,
            "source_admission_authorized": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        verified_items.append({**material, "record_content_sha256": _sealed(material)})

    status_counts = Counter(str(item["verification_status"]) for item in verified_items)
    material = {
        "schema": "legalbot.v111.phase2a.fresh-official-candidate-span-verification.v1",
        "status": "OWNER_REVIEW_REQUIRED_NOT_QUALIFICATION",
        "source_owner_review_batch_content_sha256": batch_sha256,
        "official_source_provenance_content_sha256": provenance_sha256,
        "item_count": len(verified_items),
        "verification_status_counts": dict(sorted(status_counts.items())),
        "items": verified_items,
        "issue_technical_qualification_count": 0,
        "source_admission_authorized": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    artifact = {**material, "artifact_content_sha256": _sealed(material)}
    _write_exclusive(
        output_root / "FRESH-OFFICIAL-CANDIDATE-SPAN-VERIFICATION.json",
        _pretty_json(artifact),
    )
    outcome = (
        "PHASE 2A FRESH-OFFICIAL SPAN VERIFICATION COMPLETE — OWNER REVIEW REQUIRED; "
        "ZERO ISSUES QUALIFIED; PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED\n"
    )
    _write_exclusive(output_root / "OUTCOME.txt", outcome.encode())
    files = sorted(path for path in output_root.iterdir() if path.is_file())
    _write_exclusive(
        output_root / "SHA256SUMS.txt",
        "".join(f"{_sha256_file(path)}  {path.name}\n" for path in files).encode(),
    )
    return {
        "output_root": str(output_root),
        "item_count": len(verified_items),
        "verification_status_counts": dict(sorted(status_counts.items())),
        "artifact_content_sha256": artifact["artifact_content_sha256"],
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
            "schema": "legalbot.v111.phase2a.fresh-official-span-verification-failure.v1",
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
    parser.add_argument("--owner-review-batch", required=True, type=Path)
    parser.add_argument("--official-source-provenance", required=True, type=Path)
    parser.add_argument("--quarantine-root", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = verify(
            batch_path=args.owner_review_batch.resolve(strict=True),
            provenance_path=args.official_source_provenance.resolve(strict=True),
            quarantine_root=args.quarantine_root.resolve(strict=True),
            output_root=args.output_root.resolve(),
        )
    except Exception as exc:
        _persist_failure(args.output_root.resolve(), exc)
        raise
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
