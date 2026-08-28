#!/usr/bin/env python3
"""Seal the exact Patents Act 1977 section 60(7) Phase-2A delta.

The packet distinguishes a genuine official-text change from proposition
materiality.  It does not decide the owner outcome, admit the fresh source,
mutate a candidate, qualify an issue, or authorize a later phase.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.retrieval.source_manifest import approved_source_manifest_sha256  # noqa: E402
from scripts import (  # noqa: E402
    build_v111_phase2a_legislation_byte_mismatch_reconciliation as mismatch,
)

OWNER_REVIEW_ROOT = PROJECT_ROOT / "data" / "evaluations" / "phase2a-owner-review"
DEFAULT_REGISTER = (
    OWNER_REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-24-r47-consolidated-owner-gate"
    / "COMPLETE-LEGISLATION-BYTE-MISMATCH-REGISTER-65.json"
)
DEFAULT_CANDIDATE_MANIFEST = (
    PROJECT_ROOT
    / "data/indexes/builds/current-law-ew-full-fp16-v111-20260818-a"
    / "approved-source-manifest.json"
)
DEFAULT_QUARANTINE_ROOT = (
    OWNER_REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-24-r34-quarantine"
)
DEFAULT_OUTPUT = (
    OWNER_REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r53-patents-s60-7-advisory"
)

EXPECTED_REGISTER_CONTENT_SHA256 = (
    "f0a2f9e85789aaf3bcbe9a2b90cbc404d334530f1df367e2c77a32e84b175da0"
)
EXPECTED_CANDIDATE_MANIFEST_SHA256 = (
    "d2c1434fd5fc44d4f2f7e4f7629293f646bb28ed9b8466687feb6c470ea53ac0"
)
EXPECTED_QUARANTINE_MANIFEST_SHA256 = (
    "5bd11e398bcf40a42b1dda5e3261a01bc2497fe9bd8fd41c886e1b8a18f502ff"
)
AUTHORITY_ID = "ukpga:1977:37"
SOURCE_VERSION_ID = "source-version-4906106ab7d90de6eb231b983ede8cf1161c218d"
SOURCE_ANCHOR = "https://www.legislation.gov.uk/ukpga/1977/37/section/60/7"
EXPECTED_REMOVED_TEXT = "section 53 of the Civil Aviation Act 1949 "
EXPECTED_GENERAL_REFERENCE_COUNT = 17
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


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


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_patents_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_patents_input_must_be_object")
    return value


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
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


def _source_entry(manifest: Mapping[str, Any]) -> dict[str, Any]:
    sources = manifest.get("sources")
    if not isinstance(sources, list):
        raise ValueError("phase2a_patents_candidate_sources_invalid")
    matches = [
        dict(source)
        for source in sources
        if isinstance(source, dict)
        and source.get("source_version_id") == SOURCE_VERSION_ID
        and source.get("authority_identity_id") == AUTHORITY_ID
    ]
    if len(matches) != 1:
        raise ValueError("phase2a_patents_candidate_source_identity_invalid")
    return matches[0]


def _fresh_record(quarantine: Mapping[str, Any]) -> dict[str, Any]:
    records = quarantine.get("records")
    if not isinstance(records, list):
        raise ValueError("phase2a_patents_quarantine_records_invalid")
    matches = [
        dict(record)
        for record in records
        if isinstance(record, dict)
        and record.get("target_id") == SOURCE_VERSION_ID
        and record.get("authority_identity") == AUTHORITY_ID
        and record.get("target_type") == "candidate_legislation"
    ]
    if len(matches) != 1:
        raise ValueError("phase2a_patents_quarantine_record_identity_invalid")
    return matches[0]


def _changed_record(register: Mapping[str, Any]) -> dict[str, Any]:
    records = register.get("records")
    if not isinstance(records, list) or len(records) != 65:
        raise ValueError("phase2a_patents_register_records_invalid")
    matches = [
        dict(record)
        for record in records
        if isinstance(record, dict)
        and isinstance(record.get("byte_mismatch_record"), dict)
        and record["byte_mismatch_record"].get("authority_identity") == AUTHORITY_ID
    ]
    if len(matches) != 1:
        raise ValueError("phase2a_patents_register_row_identity_invalid")
    record = matches[0]
    _verify_seal(
        record,
        "record_content_sha256",
        "phase2a_patents_register_row_seal_invalid",
    )
    nested = record["byte_mismatch_record"]
    _verify_seal(
        nested,
        "row_content_sha256",
        "phase2a_patents_mismatch_row_seal_invalid",
    )
    if (
        nested.get("source_version_id") != SOURCE_VERSION_ID
        or record.get("exact_changed_locator_pending_issue_row_ids") != []
        or len(record.get("referencing_pending_issue_row_ids") or [])
        != EXPECTED_GENERAL_REFERENCE_COUNT
        or record.get("owner_outcome") is not None
    ):
        raise ValueError("phase2a_patents_register_row_boundary_invalid")
    return record


def _single_changed_provision(
    *, canonical_path: Path, fresh_path: Path
) -> tuple[dict[str, str], dict[str, str], list[dict[str, Any]]]:
    old = mismatch._canonical_provisions(canonical_path)
    fresh = mismatch._fresh_provisions(fresh_path.read_bytes(), fresh_path.name)
    changed = [key for key in sorted(set(old) & set(fresh)) if old[key]["text"] != fresh[key]["text"]]
    if changed != [f"{SOURCE_ANCHOR}#occurrence=1"]:
        raise ValueError("phase2a_patents_changed_anchor_fingerprint_invalid")
    old_row = old[changed[0]]
    fresh_row = fresh[changed[0]]
    differences: list[dict[str, Any]] = []
    for tag, old_start, old_end, fresh_start, fresh_end in difflib.SequenceMatcher(
        a=old_row["text"], b=fresh_row["text"]
    ).get_opcodes():
        if tag == "equal":
            continue
        differences.append(
            {
                "operation": tag.upper(),
                "old_start_character": old_start,
                "old_end_character_exclusive": old_end,
                "fresh_start_character": fresh_start,
                "fresh_end_character_exclusive": fresh_end,
                "old_text": old_row["text"][old_start:old_end],
                "fresh_text": fresh_row["text"][fresh_start:fresh_end],
            }
        )
    if (
        len(differences) != 1
        or differences[0]["operation"] != "DELETE"
        or differences[0]["old_text"] != EXPECTED_REMOVED_TEXT
        or differences[0]["fresh_text"] != ""
    ):
        raise ValueError("phase2a_patents_text_delta_fingerprint_invalid")
    return old_row, fresh_row, differences


def build_patents_delta_packet(
    *,
    register_path: Path,
    candidate_manifest_path: Path,
    quarantine_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Build the create-only exact-delta advisory packet."""

    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_patents_output_already_exists")
    register = _load_object(register_path)
    register_sha256 = _verify_seal(
        register,
        "artifact_content_sha256",
        "phase2a_patents_register_seal_invalid",
    )
    if register_sha256 != EXPECTED_REGISTER_CONTENT_SHA256:
        raise ValueError("phase2a_patents_register_identity_invalid")
    changed_record = _changed_record(register)

    candidate = _load_object(candidate_manifest_path)
    candidate_sha256 = approved_source_manifest_sha256(candidate)
    if (
        candidate.get("manifest_sha256") != candidate_sha256
        or candidate_sha256 != EXPECTED_CANDIDATE_MANIFEST_SHA256
    ):
        raise ValueError("phase2a_patents_candidate_manifest_invalid")
    source = _source_entry(candidate)
    canonical_path = (PROJECT_ROOT / str(source.get("canonical_markdown_path") or "")).resolve(
        strict=True
    )
    if (
        not canonical_path.is_relative_to(PROJECT_ROOT)
        or canonical_path.is_symlink()
        or _sha256_file(canonical_path)
        != changed_record["byte_mismatch_record"]["candidate_canonical_markdown_sha256"]
    ):
        raise ValueError("phase2a_patents_canonical_source_invalid")

    quarantine_path = quarantine_root / "QUARANTINE-MANIFEST.json"
    quarantine = _load_object(quarantine_path)
    quarantine_sha256 = _verify_seal(
        quarantine,
        "manifest_sha256",
        "phase2a_patents_quarantine_manifest_seal_invalid",
    )
    if quarantine_sha256 != EXPECTED_QUARANTINE_MANIFEST_SHA256:
        raise ValueError("phase2a_patents_quarantine_manifest_identity_invalid")
    fresh_record = _fresh_record(quarantine)
    fresh_path = (quarantine_root / str(fresh_record.get("quarantine_member") or "")).resolve(
        strict=True
    )
    if (
        not fresh_path.is_relative_to(quarantine_root.resolve())
        or fresh_path.is_symlink()
        or _sha256_file(fresh_path) != fresh_record.get("sha256")
        or fresh_path.stat().st_size != fresh_record.get("bytes")
    ):
        raise ValueError("phase2a_patents_fresh_source_invalid")

    old, fresh, differences = _single_changed_provision(
        canonical_path=canonical_path, fresh_path=fresh_path
    )
    material = {
        "schema": "legalbot.v111.phase2a.patents-s60-7-delta-advisory.v1",
        "status": "EXACT_TEXT_DELTA_VERIFIED_OWNER_DECISION_REMAINS_REQUIRED",
        "authority_identity_id": AUTHORITY_ID,
        "source_version_id": SOURCE_VERSION_ID,
        "title": source.get("title"),
        "official_url": fresh_record.get("final_url"),
        "source_anchor": SOURCE_ANCHOR,
        "source_register_content_sha256": register_sha256,
        "source_candidate_manifest_sha256": candidate_sha256,
        "source_quarantine_manifest_sha256": quarantine_sha256,
        "sealed_source": {
            "version_sha256": source.get("version_sha256"),
            "canonical_markdown_sha256": _sha256_file(canonical_path),
            "provision_text": old["text"],
            "provision_text_sha256": old["text_sha256"],
        },
        "fresh_official_source": {
            "quarantine_member": fresh_path.relative_to(PROJECT_ROOT).as_posix(),
            "retrieved_file_sha256": _sha256_file(fresh_path),
            "provision_text": fresh["text"],
            "provision_text_sha256": fresh["text_sha256"],
        },
        "exact_differences": differences,
        "removed_text": EXPECTED_REMOVED_TEXT,
        "changed_locator_pending_issue_row_ids": [],
        "authority_general_pending_issue_row_ids": changed_record[
            "referencing_pending_issue_row_ids"
        ],
        "authority_general_pending_issue_row_count": EXPECTED_GENERAL_REFERENCE_COUNT,
        "advisory_finding": (
            "The official text removes an obsolete Civil Aviation Act 1949 cross-reference. "
            "No pre-existing pending issue is bound to the exact changed subsection, but "
            "17 rows reference the Patents Act generally. Final proposition materiality and "
            "fresh-version admission must therefore be decided only after the exact 448-row "
            "bindings are complete."
        ),
        "advisory_recommendation": (
            "DEFER_OWNER_OUTCOME_UNTIL_FINAL_PATENTS_PROPOSITION_BINDINGS;_IF_THE_"
            "PATENTS_ACT_REMAINS_IN_SUCCESSOR_SCOPE_RECOMMEND_EXACT_FRESH_VERSION_"
            "ADMISSION_NOT_IN_PLACE_PATCHING"
        ),
        "owner_decision_options": [
            "APPROVE_NONMATERIAL_TO_FINAL_BOUND_PROPOSITIONS",
            "APPROVE_FRESH_VERSION_AND_SUCCESSOR_SOURCE_SCOPE",
            "CONFIRM_MATERIAL_GAP",
            "REQUEST_MORE_EVIDENCE",
        ],
        "owner_outcome": None,
        "owner_decision_required": True,
        "source_admitted": False,
        "indexed": False,
        "embedded": False,
        "candidate_mutated": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    artifact = {**material, "artifact_content_sha256": _sealed(material)}
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_patents_output_mode_invalid")
    name = "PATENTS-ACT-1977-S60-7-EXACT-DELTA-ADVISORY.json"
    _write_exclusive(output_root / name, _pretty_json(artifact))
    outcome = (
        "PATENTS ACT 1977 SECTION 60(7) EXACT DELTA VERIFIED. "
        "OWNER MATERIALITY AND SOURCE-ADMISSION DECISIONS REMAIN REQUIRED. "
        "PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED.\n"
    )
    _write_exclusive(output_root / "OUTCOME.txt", outcome.encode())
    sums = "".join(
        f"{_sha256_file(output_root / item)}  {item}\n" for item in (name, "OUTCOME.txt")
    )
    _write_exclusive(output_root / "SHA256SUMS.txt", sums.encode())
    return artifact


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--register", type=Path, default=DEFAULT_REGISTER)
    parser.add_argument("--candidate-manifest", type=Path, default=DEFAULT_CANDIDATE_MANIFEST)
    parser.add_argument("--quarantine-root", type=Path, default=DEFAULT_QUARANTINE_ROOT)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> None:
    args = _arguments()
    result = build_patents_delta_packet(
        register_path=args.register,
        candidate_manifest_path=args.candidate_manifest,
        quarantine_root=args.quarantine_root,
        output_root=args.output_root,
    )
    print(
        json.dumps(
            {
                "output_root": str(args.output_root),
                "status": result["status"],
                "artifact_content_sha256": result["artifact_content_sha256"],
                "owner_outcome": result["owner_outcome"],
                "source_admitted": result["source_admitted"],
                "phase2b_authorized": result["phase2b_authorized"],
                "development30_authorized": result["development30_authorized"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
