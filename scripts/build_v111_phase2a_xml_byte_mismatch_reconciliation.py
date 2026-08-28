#!/usr/bin/env python3
"""Seal the Data Act XML serialization-only mismatch reconciliation."""

from __future__ import annotations

import argparse
import json
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

if __package__:
    from scripts import collect_v111_phase2a_official_sources as official
    from scripts import collect_v111_phase2a_supplemental_sources as supplemental
else:
    import collect_v111_phase2a_official_sources as official
    import collect_v111_phase2a_supplemental_sources as supplemental

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PRIOR_ROOT = (
    PROJECT_ROOT / "data/evaluations/phase2a-owner-review/"
    "LegalBot-Phase2AB-2026-08-24-r34-quarantine"
)
DEFAULT_CURRENT_ROOT = (
    PROJECT_ROOT / "data/quarantine/2026-08-25/phase2a-target-date-legislation-r78"
)
DEFAULT_OUTPUT_ROOT = (
    PROJECT_ROOT / "data/evaluations/phase2a-owner-review/"
    "LegalBot-Phase2AB-2026-08-25-r79-xml-byte-mismatch-reconciliation"
)
AUTHORITY_IDENTITY = "ukpga:2025:18"
OFFICIAL_URL = "https://www.legislation.gov.uk/ukpga/2025/18/2026-08-14/data.xml"
EXPECTED_PRIOR_RAW_SHA256 = "f1fec747102b577509625ebb7aa135f39e791946a6b17d86c0c625670dc4bbbe"
EXPECTED_CURRENT_RAW_SHA256 = "c04c780aa20839962f65e466a655a7c52ec7f511a63b7db252061fbb3829abe7"
EXPECTED_CANONICAL_XML_SHA256 = "d989eb7e28f0f6f94712bd2de02b7d31e5dba1e23d4fd154f365962b2eea2e20"


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_xml_reconciliation_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_xml_reconciliation_input_must_be_object")
    return value


def _sealed(value: Any) -> str:
    return official._sha256(official._canonical_json(value))


def _verify_manifest_seal(
    manifest: Mapping[str, Any],
    *,
    field: str,
    code: str,
) -> str:
    material = dict(manifest)
    supplied = str(material.pop(field, ""))
    if not supplied or supplied != _sealed(material):
        raise ValueError(code)
    return supplied


def _select_record(manifest: Mapping[str, Any]) -> dict[str, Any]:
    records = manifest.get("records")
    if not isinstance(records, list):
        raise ValueError("phase2a_xml_reconciliation_records_invalid")
    matches = [
        dict(record)
        for record in records
        if isinstance(record, Mapping)
        and record.get("authority_identity") == AUTHORITY_IDENTITY
        and record.get("final_url") == OFFICIAL_URL
    ]
    if len(matches) != 1:
        raise ValueError("phase2a_xml_reconciliation_record_identity_invalid")
    return matches[0]


def _read_member(root: Path, record: Mapping[str, Any]) -> bytes:
    raw_member = root / str(record.get("quarantine_member") or "")
    if raw_member.is_symlink():
        raise ValueError("phase2a_xml_reconciliation_member_symlink_forbidden")
    member = raw_member.resolve(strict=True)
    if not member.is_relative_to(root) or not member.is_file():
        raise ValueError("phase2a_xml_reconciliation_member_invalid")
    raw = member.read_bytes()
    if official._sha256(raw) != record.get("sha256") or len(raw) != record.get("bytes"):
        raise ValueError("phase2a_xml_reconciliation_member_integrity_invalid")
    return raw


def _write_json_exclusive(path: Path, value: Any) -> None:
    raw = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    official._write_exclusive(path, raw)


def build(
    *,
    prior_root: Path,
    current_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Compare sealed same-URL bytes and persist a non-admitting finding."""

    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_xml_reconciliation_output_exists")
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_xml_reconciliation_output_mode_invalid")

    prior_manifest_path = prior_root / "QUARANTINE-MANIFEST.json"
    current_manifest_path = current_root / "QUARANTINE-MANIFEST.json"
    prior_manifest = _load_object(prior_manifest_path)
    current_manifest = _load_object(current_manifest_path)
    prior_manifest_digest = _verify_manifest_seal(
        prior_manifest,
        field="manifest_sha256",
        code="phase2a_xml_reconciliation_prior_manifest_seal_invalid",
    )
    current_manifest_digest = _verify_manifest_seal(
        current_manifest,
        field="manifest_content_sha256",
        code="phase2a_xml_reconciliation_current_manifest_seal_invalid",
    )
    if (
        prior_manifest.get("schema") != "legalbot.v111-phase2a-official-source-quarantine.v1"
        or current_manifest.get("schema") != supplemental.MANIFEST_SCHEMA
        or current_manifest.get("automatic_source_admission") is not False
        or current_manifest.get("automatic_indexing") is not False
        or current_manifest.get("candidate_mutated") is not False
        or current_manifest.get("phase2b_authorized") is not False
    ):
        raise ValueError("phase2a_xml_reconciliation_manifest_boundary_invalid")

    prior_record = _select_record(prior_manifest)
    current_record = _select_record(current_manifest)
    current_record_material = dict(current_record)
    current_record_seal = str(current_record_material.pop("record_content_sha256", ""))
    if not current_record_seal or current_record_seal != _sealed(current_record_material):
        raise ValueError("phase2a_xml_reconciliation_current_record_seal_invalid")
    if (
        prior_record.get("result") != "DOWNLOADED_QUARANTINED"
        or current_record.get("result") != "DOWNLOADED_QUARANTINED_NOT_ADMITTED"
    ):
        raise ValueError("phase2a_xml_reconciliation_source_state_invalid")

    prior_raw = _read_member(prior_root, prior_record)
    current_raw = _read_member(current_root, current_record)
    prior_raw_sha256 = official._sha256(prior_raw)
    current_raw_sha256 = official._sha256(current_raw)
    prior_canonical_sha256 = supplemental._canonical_xml_sha256(prior_raw)
    current_canonical_sha256 = supplemental._canonical_xml_sha256(current_raw)
    if (
        prior_raw_sha256 != EXPECTED_PRIOR_RAW_SHA256
        or current_raw_sha256 != EXPECTED_CURRENT_RAW_SHA256
        or prior_raw == current_raw
        or prior_canonical_sha256 != EXPECTED_CANONICAL_XML_SHA256
        or current_canonical_sha256 != EXPECTED_CANONICAL_XML_SHA256
    ):
        raise ValueError("phase2a_xml_reconciliation_expected_comparison_invalid")

    report_material = {
        "schema": "legalbot.v111.phase2a.xml-byte-mismatch-reconciliation.v1",
        "status": "CANONICAL_XML_IDENTICAL_RAW_BYTE_MISMATCH_RECONCILED",
        "phase": "2A",
        "authority_identity": AUTHORITY_IDENTITY,
        "source_title": "Data (Use and Access) Act 2025",
        "official_url": OFFICIAL_URL,
        "target_date": "2026-08-14",
        "prior": {
            "quarantine_manifest_sha256": prior_manifest_digest,
            "quarantine_manifest_file_sha256": official._sha256(prior_manifest_path.read_bytes()),
            "target_id": prior_record["target_id"],
            "retrieved_at": prior_record["retrieved_at"],
            "quarantine_member": prior_record["quarantine_member"],
            "raw_sha256": prior_raw_sha256,
            "canonical_xml_sha256": prior_canonical_sha256,
            "bytes": len(prior_raw),
        },
        "current": {
            "quarantine_manifest_sha256": current_manifest_digest,
            "quarantine_manifest_file_sha256": official._sha256(current_manifest_path.read_bytes()),
            "record_content_sha256": current_record_seal,
            "target_id": current_record["target_id"],
            "retrieved_at": current_record["retrieved_at"],
            "quarantine_member": current_record["quarantine_member"],
            "raw_sha256": current_raw_sha256,
            "canonical_xml_sha256": current_canonical_sha256,
            "bytes": len(current_raw),
        },
        "raw_bytes_identical": False,
        "byte_lengths_identical": len(prior_raw) == len(current_raw),
        "canonical_xml_identical": True,
        "legal_xml_infoset_change_detected": False,
        "classification": "XML_SERIALIZATION_ONLY_NONMATERIAL_BYTE_MISMATCH",
        "advisory_recommendation": (
            "RECORD_RAW_PROVENANCE_AND_TREAT_THE_BYTE_MISMATCH_AS_NONMATERIAL_TO_LEGAL_TEXT"
        ),
        "owner_materiality_decision": None,
        "owner_source_admission_still_required": True,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    report = {
        **report_material,
        "artifact_content_sha256": _sealed(report_material),
    }
    report_path = output_root / "XML-BYTE-MISMATCH-RECONCILIATION.json"
    _write_json_exclusive(report_path, report)

    package_material = {
        "schema": "legalbot.v111.phase2a.xml-byte-mismatch-package.v1",
        "status": report["status"],
        "report_content_sha256": report["artifact_content_sha256"],
        "report_file_sha256": official._sha256(report_path.read_bytes()),
        "owner_source_admission_still_required": True,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    package = {
        **package_material,
        "package_content_sha256": _sealed(package_material),
    }
    _write_json_exclusive(output_root / "PACKAGE-MANIFEST.json", package)
    official._write_exclusive(
        output_root / "OUTCOME.txt",
        (
            "PHASE 2A XML BYTE MISMATCH RECONCILED — CANONICAL XML IDENTICAL; "
            "SOURCE ADMISSION STILL REQUIRES OWNER APPROVAL; NO INDEX OR "
            "CANDIDATE CHANGE; PHASE 2B NOT AUTHORIZED\n"
        ).encode(),
    )
    return {
        "output_root": str(output_root),
        "status": report["status"],
        "report_content_sha256": report["artifact_content_sha256"],
        "package_content_sha256": package["package_content_sha256"],
        "canonical_xml_identical": True,
        "source_admission_authorized": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }


def _persist_failure(output_root: Path, exc: BaseException) -> None:
    try:
        output_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        failure_path = output_root / "FAILURE.json"
        if failure_path.exists():
            return
        material = {
            "schema": "legalbot.v111.phase2a.xml-byte-mismatch-failure.v1",
            "exception_type": type(exc).__name__,
            "error": str(exc),
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        _write_json_exclusive(
            failure_path,
            {**material, "failure_content_sha256": _sealed(material)},
        )
    except Exception:
        return


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prior-root", type=Path, default=DEFAULT_PRIOR_ROOT)
    parser.add_argument("--current-root", type=Path, default=DEFAULT_CURRENT_ROOT)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    output_root = args.output_root.resolve()
    try:
        result = build(
            prior_root=args.prior_root.resolve(strict=True),
            current_root=args.current_root.resolve(strict=True),
            output_root=output_root,
        )
    except Exception as exc:
        _persist_failure(output_root, exc)
        raise
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
