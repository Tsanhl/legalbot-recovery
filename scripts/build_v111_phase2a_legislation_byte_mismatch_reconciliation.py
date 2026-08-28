#!/usr/bin/env python3
"""Reconcile 65 fresh legislation byte mismatches at provision-block level."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.ingestion.models import BlockKind, ParseStatus  # noqa: E402
from app.ingestion.parsers import LegislationXmlParser  # noqa: E402

DEFAULT_CANDIDATE_MANIFEST = (
    PROJECT_ROOT
    / "data/indexes/builds/current-law-ew-full-fp16-v111-20260818-a/approved-source-manifest.json"
)
DEFAULT_QUARANTINE_ROOT = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review/LegalBot-Phase2AB-2026-08-24-r34-quarantine"
)
DEFAULT_OUTPUT_ROOT = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review/LegalBot-Phase2AB-2026-08-24-r46-byte-mismatch-reconciliation"
)
EXPECTED_QUARANTINE_MANIFEST_DIGEST = (
    "5bd11e398bcf40a42b1dda5e3261a01bc2497fe9bd8fd41c886e1b8a18f502ff"
)
EXPECTED_RECORD_COUNT = 65
_BLOCK_MARKER = re.compile(r"<!-- legalbot-block (?P<json>\{.*?\}) -->\n", re.DOTALL)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_byte_mismatch_input_not_object")
    return value


def _verify_seal(value: Mapping[str, Any], field: str, expected: str) -> str:
    material = dict(value)
    supplied = material.pop(field, None)
    if supplied != expected or supplied != _sha256(_canonical_json(material)):
        raise ValueError("phase2a_byte_mismatch_source_seal_invalid")
    return str(supplied)


def _normal(value: str) -> str:
    return " ".join(value.replace("\u00a0", " ").split())


def _canonical_anchor(value: str) -> str:
    # Version selectors identify the representation to fetch, not the provision's
    # structural identity.  Removing them lets the comparison report the actual
    # text delta at a stable provision anchor.
    return re.sub(
        r"/(?:20\d{2}-\d{2}-\d{2}|made|enacted|prospective|adopted)$",
        "",
        value,
    )


def _safe_project_file(relative: str) -> Path:
    candidate = (PROJECT_ROOT / relative).resolve(strict=True)
    if not candidate.is_relative_to(PROJECT_ROOT) or candidate.is_symlink():
        raise ValueError("phase2a_byte_mismatch_candidate_path_invalid")
    return candidate


def _canonical_provisions(path: Path) -> dict[str, dict[str, str]]:
    raw = path.read_text(encoding="utf-8")
    matches = list(_BLOCK_MARKER.finditer(raw))
    provisions: dict[str, dict[str, str]] = {}
    anchor_occurrences: Counter[str] = Counter()
    for index, match in enumerate(matches):
        marker = json.loads(match.group("json"))
        if not isinstance(marker, dict):
            raise ValueError("phase2a_byte_mismatch_canonical_marker_invalid")
        metadata = marker.get("metadata")
        if (
            marker.get("kind") != "paragraph"
            or not isinstance(metadata, dict)
            or metadata.get("legal_locator_kind") != "legislative_provision"
        ):
            continue
        anchor = _canonical_anchor(str(marker.get("source_anchor") or ""))
        locator = str(metadata.get("legal_locator") or "")
        if not anchor or not locator:
            raise ValueError("phase2a_byte_mismatch_canonical_provision_identity_invalid")
        anchor_occurrences[anchor] += 1
        identity = f"{anchor}#occurrence={anchor_occurrences[anchor]}"
        end = matches[index + 1].start() if index + 1 < len(matches) else len(raw)
        text = _normal(raw[match.end() : end])
        if not text:
            raise ValueError("phase2a_byte_mismatch_canonical_provision_text_missing")
        provisions[identity] = {
            "source_anchor": anchor,
            "locator": locator,
            "text": text,
            "text_sha256": _sha256(text.encode()),
        }
    if not provisions:
        raise ValueError("phase2a_byte_mismatch_canonical_provisions_missing")
    return provisions


def _fresh_provisions(raw: bytes, filename: str) -> dict[str, dict[str, str]]:
    parsed = LegislationXmlParser().parse(raw, filename=filename)
    if parsed.status is not ParseStatus.READY:
        raise ValueError("phase2a_byte_mismatch_fresh_xml_parse_failed")
    provisions: dict[str, dict[str, str]] = {}
    anchor_occurrences: Counter[str] = Counter()
    for block in parsed.body_blocks:
        if (
            block.kind is not BlockKind.PARAGRAPH
            or block.metadata.get("legal_locator_kind") != "legislative_provision"
        ):
            continue
        anchor = _canonical_anchor(str(block.source_anchor or ""))
        locator = str(block.metadata.get("legal_locator") or "")
        text = _normal(block.text)
        if not anchor or not locator or not text:
            raise ValueError("phase2a_byte_mismatch_fresh_provision_identity_invalid")
        anchor_occurrences[anchor] += 1
        identity = f"{anchor}#occurrence={anchor_occurrences[anchor]}"
        provisions[identity] = {
            "source_anchor": anchor,
            "locator": locator,
            "text": text,
            "text_sha256": _sha256(text.encode()),
        }
    if not provisions:
        raise ValueError("phase2a_byte_mismatch_fresh_provisions_missing")
    return provisions


def _excerpt(value: str) -> str:
    return value if len(value) <= 240 else f"{value[:237]}..."


def _compare_provisions(
    old: Mapping[str, Mapping[str, str]],
    fresh: Mapping[str, Mapping[str, str]],
) -> dict[str, Any]:
    old_anchors = set(old)
    fresh_anchors = set(fresh)
    shared = sorted(old_anchors & fresh_anchors)
    changed = [anchor for anchor in shared if old[anchor]["text"] != fresh[anchor]["text"]]
    unchanged = [anchor for anchor in shared if anchor not in set(changed)]
    removed = sorted(old_anchors - fresh_anchors)
    added = sorted(fresh_anchors - old_anchors)
    if not changed and not removed and not added:
        classification = "SEMANTIC_PROVISION_TEXT_IDENTICAL_BYTE_MISMATCH_ONLY"
        recommendation = "APPROVE_NONMATERIAL_REPRESENTATION_BYTE_MISMATCH"
    elif not changed and not removed:
        classification = "FRESH_OFFICIAL_VERSION_HAS_ADDITIONAL_PROVISION_BLOCKS"
        recommendation = "REVIEW_ADDED_PROVISIONS_FOR_PROPOSITION_MATERIALITY"
    else:
        classification = "FRESH_OFFICIAL_VERSION_HAS_CHANGED_OR_REMOVED_PROVISION_BLOCKS"
        recommendation = "REVIEW_CHANGED_OR_REMOVED_PROVISIONS_FOR_PROPOSITION_MATERIALITY"
    return {
        "classification": classification,
        "advisory_recommendation": recommendation,
        "old_provision_count": len(old),
        "fresh_provision_count": len(fresh),
        "unchanged_anchor_count": len(unchanged),
        "changed_anchor_count": len(changed),
        "removed_anchor_count": len(removed),
        "added_anchor_count": len(added),
        "changed": [
            {
                "source_anchor": fresh[anchor].get("source_anchor", anchor),
                "locator": fresh[anchor]["locator"],
                "old_text_sha256": old[anchor]["text_sha256"],
                "fresh_text_sha256": fresh[anchor]["text_sha256"],
                "old_excerpt": _excerpt(old[anchor]["text"]),
                "fresh_excerpt": _excerpt(fresh[anchor]["text"]),
            }
            for anchor in changed
        ],
        "removed": [
            {
                "source_anchor": old[anchor].get("source_anchor", anchor),
                "locator": old[anchor]["locator"],
                "old_text_sha256": old[anchor]["text_sha256"],
                "old_excerpt": _excerpt(old[anchor]["text"]),
            }
            for anchor in removed
        ],
        "added": [
            {
                "source_anchor": fresh[anchor].get("source_anchor", anchor),
                "locator": fresh[anchor]["locator"],
                "fresh_text_sha256": fresh[anchor]["text_sha256"],
                "fresh_excerpt": _excerpt(fresh[anchor]["text"]),
            }
            for anchor in added
        ],
    }


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def build_reconciliation(
    *,
    candidate_manifest_path: Path,
    quarantine_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    candidate = _load(candidate_manifest_path)
    quarantine_path = quarantine_root / "QUARANTINE-MANIFEST.json"
    quarantine = _load(quarantine_path)
    quarantine_digest = _verify_seal(
        quarantine,
        "manifest_sha256",
        EXPECTED_QUARANTINE_MANIFEST_DIGEST,
    )
    sources = candidate.get("sources")
    records = quarantine.get("records")
    if not isinstance(sources, list) or not isinstance(records, list):
        raise ValueError("phase2a_byte_mismatch_source_collections_invalid")
    source_by_version = {
        str(source["source_version_id"]): source
        for source in sources
        if isinstance(source, Mapping)
    }
    mismatch_records = [
        record
        for record in records
        if isinstance(record, Mapping)
        and record.get("target_type") == "candidate_legislation"
        and record.get("result") == "DOWNLOADED_QUARANTINED"
        and record.get("matches_expected_version_sha256") is False
    ]
    if len(mismatch_records) != EXPECTED_RECORD_COUNT:
        raise ValueError("phase2a_byte_mismatch_record_count_invalid")
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_byte_mismatch_output_exists")
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_byte_mismatch_output_mode_invalid")

    reconciled: list[dict[str, Any]] = []
    classifications: Counter[str] = Counter()
    for ordinal, record in enumerate(mismatch_records, start=1):
        source_version_id = str(record.get("target_id") or "")
        source = source_by_version.get(source_version_id)
        if source is None:
            raise ValueError("phase2a_byte_mismatch_candidate_source_missing")
        if source.get("authority_identity_id") != record.get("authority_identity") or source.get(
            "version_sha256"
        ) != record.get("expected_version_sha256"):
            raise ValueError("phase2a_byte_mismatch_candidate_source_binding_invalid")
        canonical_path = _safe_project_file(str(source["canonical_markdown_path"]))
        member_name = str(record.get("quarantine_member") or "")
        fresh_path = (quarantine_root / member_name).resolve(strict=True)
        if (
            not fresh_path.is_relative_to(quarantine_root.resolve())
            or fresh_path.is_symlink()
            or _sha256_file(fresh_path) != record.get("sha256")
            or fresh_path.stat().st_size != record.get("bytes")
        ):
            raise ValueError("phase2a_byte_mismatch_quarantine_member_invalid")
        comparison = _compare_provisions(
            _canonical_provisions(canonical_path),
            _fresh_provisions(fresh_path.read_bytes(), fresh_path.name),
        )
        classifications[comparison["classification"]] += 1
        material = {
            "schema": "legalbot.v111.phase2a.legislation-byte-mismatch-row.v1",
            "ordinal": ordinal,
            "source_version_id": source_version_id,
            "authority_identity": record["authority_identity"],
            "title": source.get("title"),
            "official_url": record.get("final_url"),
            "sealed_version_sha256": source.get("version_sha256"),
            "fresh_official_sha256": record.get("sha256"),
            "candidate_canonical_markdown_sha256": _sha256_file(canonical_path),
            "fresh_quarantine_member": member_name,
            "comparison": comparison,
            "byte_identity_changed": True,
            "semantic_materiality_decided": False,
            "owner_decision_required": True,
            "owner_decision_options": [
                "APPROVE_NONMATERIAL_REPRESENTATION_BYTE_MISMATCH",
                "APPROVE_FRESH_VERSION_AND_SUCCESSOR_SOURCE_SCOPE",
                "CONFIRM_MATERIAL_GAP",
                "REQUEST_MORE_EVIDENCE",
            ],
            "source_admitted": False,
            "indexed": False,
            "embedded": False,
            "candidate_mutated": False,
            "technical_qualification_assigned": False,
        }
        reconciled.append(
            {
                **material,
                "row_content_sha256": _sha256(_canonical_json(material)),
            }
        )

    summary = {
        "record_count": len(reconciled),
        "classification_counts": dict(sorted(classifications.items())),
        "owner_decision_required_count": len(reconciled),
    }
    artifact_material = {
        "schema": "legalbot.v111.phase2a.legislation-byte-mismatch-reconciliation-65.v1",
        "status": "DETERMINISTIC_PROVISION_COMPARISON_COMPLETE_OWNER_DECISIONS_REQUIRED",
        "source_candidate_manifest_file_sha256": _sha256_file(candidate_manifest_path),
        "source_quarantine_manifest_content_sha256": quarantine_digest,
        "source_quarantine_manifest_file_sha256": _sha256_file(quarantine_path),
        "comparison_method": "EXACT_NORMALIZED_PROVISION_TEXT_BY_OFFICIAL_SOURCE_ANCHOR",
        "summary": summary,
        "records": reconciled,
        "owner_decisions_applied": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    artifact = {
        **artifact_material,
        "artifact_content_sha256": _sha256(_canonical_json(artifact_material)),
    }
    artifact_path = output_root / "LEGISLATION-BYTE-MISMATCH-RECONCILIATION-65.json"
    _write_exclusive(artifact_path, _pretty_json(artifact))
    outcome_path = output_root / "OUTCOME.txt"
    _write_exclusive(
        outcome_path,
        b"PHASE 2A LEGISLATION BYTE MISMATCH COMPARISON COMPLETE - OWNER DECISIONS REQUIRED; NO PHASE 2B\n",
    )
    _write_exclusive(
        output_root / "SHA256SUMS.txt",
        "".join(
            f"{_sha256_file(path)}  {path.name}\n" for path in sorted((artifact_path, outcome_path))
        ).encode(),
    )
    return {
        "output_root": str(output_root),
        "artifact_content_sha256": artifact["artifact_content_sha256"],
        "summary": summary,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-manifest", type=Path, default=DEFAULT_CANDIDATE_MANIFEST)
    parser.add_argument("--quarantine-root", type=Path, default=DEFAULT_QUARANTINE_ROOT)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    args = parser.parse_args()
    result = build_reconciliation(
        candidate_manifest_path=args.candidate_manifest.resolve(strict=True),
        quarantine_root=args.quarantine_root.resolve(strict=True),
        output_root=args.output_root.resolve(),
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
