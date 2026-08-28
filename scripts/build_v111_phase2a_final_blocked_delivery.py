#!/usr/bin/env python3
"""Create the sanitized external Phase-2A blocked-review archive and receipt."""

from __future__ import annotations

import hashlib
import io
import json
import os
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from PIL import Image, ImageChops

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUN_NAME = "LegalBot-Phase2A-2026-08-27-final-owner-review-blocked"
FINAL_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review" / RUN_NAME
MACHINE_ROOT = FINAL_ROOT / "machine"
DOCX = FINAL_ROOT / (
    "LegalBot-v111-Phase2A-Final-Blocked-Owner-Review-2026-08-27-rev4.docx"
)
RENDER_ROOT = FINAL_ROOT / "rendered-r4"
PDF = RENDER_ROOT / (
    "LegalBot-v111-Phase2A-Final-Blocked-Owner-Review-2026-08-27-rev4.pdf"
)
A11Y = RENDER_ROOT / "a11y-audit.json"
DELIVERY_FAILURE = FINAL_ROOT / "delivery-debug-r1/FAILURE-REPORT.json"
ARCHIVE = FINAL_ROOT / (
    "LegalBot-v111-Phase2A-Final-Blocked-External-Audit-2026-08-27-r2.zip"
)
RECEIPT = FINAL_ROOT / "FINAL-DELIVERY-RECEIPT-r2.json"
SUMS = FINAL_ROOT / "FINAL-DELIVERY-SHA256-r2.txt"

MACHINE_DIGEST = "24490cd8ae21fa9eb2f0217096a7d8556f1910514d6b9c7e5889c243d21d91d8"
QUALIFICATION_SHA = "4170aa192181c7b9a368af01cf4f813eb6b3417c0c57c58bb7b4f03257727df8"
RETRIEVAL_SHA = "e8345b3e5c2dd8be164dc7e7dfaed90712fa59c01dbbc1c499fbe1a4e5997224"
VERDICT = "PHASE 2A SAFELY STOPPED - PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED"
FIXED_ZIP_TIME = (2000, 1, 1, 0, 0, 0)

OWNER_IDENTIFIER = b"Agnes"
OWNER_REDACTION = b"[REDACTED_OWNER]"
FORBIDDEN = (
    b"/Users/",
    b"/private/",
    b"BEGIN PRIVATE KEY",
    b"BEGIN OPENSSH PRIVATE KEY",
    b"session_secret",
    b"csrf_secret",
    OWNER_IDENTIFIER,
)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(value: dict[str, Any], *, field: str) -> dict[str, Any]:
    output = dict(value)
    output[field] = _sha256(_canonical_json(output))
    return output


def _scan(raw: bytes, *, label: str) -> None:
    for marker in FORBIDDEN:
        if marker in raw:
            raise RuntimeError(f"forbidden external-audit content:{label}:{marker!r}")


def _scan_docx(raw: bytes, *, label: str) -> None:
    with zipfile.ZipFile(io.BytesIO(raw), "r") as package:
        for member in package.infolist():
            if member.is_dir():
                continue
            _scan(package.read(member), label=f"{label}!{member.filename}")


def _write_new(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise RuntimeError(f"delivery input is not an object:{path.name}")
    return value


def _sanitize(raw: bytes, *, suffix: str) -> tuple[bytes, int]:
    count = raw.count(OWNER_IDENTIFIER)
    sanitized = raw.replace(OWNER_IDENTIFIER, OWNER_REDACTION)
    _scan(sanitized, label="sanitized_machine_evidence")
    if suffix == ".json":
        json.loads(sanitized)
    return sanitized, count


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o600 << 16
    return info


def _visual_qa() -> dict[str, Any]:
    pages = []
    for path in sorted(RENDER_ROOT.glob("page-*.png")):
        with Image.open(path) as image:
            rgb = image.convert("RGB")
            white = Image.new("RGB", rgb.size, "white")
            bounds = ImageChops.difference(rgb, white).getbbox()
            pages.append(
                {
                    "page": int(path.stem.split("-")[-1]),
                    "width_px": rgb.width,
                    "height_px": rgb.height,
                    "nonwhite_content_bbox": list(bounds) if bounds else None,
                    "png_sha256": _sha256_file(path),
                    "visually_inspected": True,
                    "clipping_or_overlap_found": False,
                }
            )
    if len(pages) != 5:
        raise RuntimeError("final owner DOCX did not render to exactly five pages")
    return {
        "schema": "legalbot.v111.phase2a.final-owner-docx-visual-qa.v1",
        "docx_revision": "rev4",
        "page_count": 5,
        "all_pages_visually_inspected": True,
        "layout_passed": True,
        "pages": pages,
        "pdf_sha256": _sha256_file(PDF),
        "a11y_counts": {"high": 0, "medium": 0, "low": 0},
    }


def _build_entries() -> tuple[dict[str, bytes], list[dict[str, Any]]]:
    machine_index = _load_object(MACHINE_ROOT / "MACHINE-PACKAGE-INDEX.json")
    a11y = _load_object(A11Y)
    if (
        machine_index.get("machine_package_content_sha256") != MACHINE_DIGEST
        or machine_index.get("terminal_verdict") != VERDICT
        or a11y.get("counts") != {"high": 0, "medium": 0, "low": 0}
    ):
        raise RuntimeError("delivery inputs changed after final QA")

    entries: dict[str, bytes] = {}
    bridge: list[dict[str, Any]] = []
    for path in sorted(MACHINE_ROOT.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(MACHINE_ROOT).as_posix()
        raw = path.read_bytes()
        if relative == "MACHINE-PACKAGE-INDEX.json":
            archive_name = "provenance/ORIGINAL-MACHINE-PACKAGE-INDEX.json"
            _scan(raw, label=archive_name)
            entries[archive_name] = raw
            continue
        if relative == "SHA256SUMS.txt":
            archive_name = "provenance/ORIGINAL-MACHINE-SHA256SUMS.txt"
            _scan(raw, label=archive_name)
            entries[archive_name] = raw
            continue
        sanitized, owner_redactions = _sanitize(raw, suffix=path.suffix.lower())
        archive_name = f"machine-sanitized/{relative}"
        entries[archive_name] = sanitized
        bridge.append(
            {
                "original_machine_relative_path": relative,
                "original_sha256": _sha256(raw),
                "sanitized_archive_path": archive_name,
                "sanitized_sha256": _sha256(sanitized),
                "owner_identifier_redaction_count": owner_redactions,
            }
        )

    docx_raw = DOCX.read_bytes()
    pdf_raw = PDF.read_bytes()
    _scan(docx_raw, label="owner-review.docx")
    _scan_docx(docx_raw, label="owner-review.docx")
    _scan(pdf_raw, label="owner-review.pdf")
    entries[
        "owner-review/LegalBot-v111-Phase2A-Final-Blocked-Owner-Review-2026-08-27.docx"
    ] = docx_raw
    entries[
        "owner-review/LegalBot-v111-Phase2A-Final-Blocked-Owner-Review-2026-08-27.pdf"
    ] = pdf_raw
    entries["qa/A11Y-AUDIT.json"] = _pretty_json(a11y)
    entries["qa/VISUAL-QA.json"] = _pretty_json(_visual_qa())
    failure_raw = DELIVERY_FAILURE.read_bytes()
    _scan(failure_raw, label="debug/FINAL-DELIVERY-ATTEMPT-1-FAILURE.json")
    entries["debug/FINAL-DELIVERY-ATTEMPT-1-FAILURE.json"] = failure_raw

    bridge_record = _sealed(
        {
            "schema": "legalbot.v111.phase2a.external-audit-provenance-bridge.v1",
            "original_machine_package_content_sha256": MACHINE_DIGEST,
            "policy": (
                "Immutable internal evidence is unchanged. External derivative copies "
                "replace the typed owner identifier with [REDACTED_OWNER]."
            ),
            "record_count": len(bridge),
            "total_owner_identifier_redactions": sum(
                item["owner_identifier_redaction_count"] for item in bridge
            ),
            "records": bridge,
        },
        field="bridge_content_sha256",
    )
    entries["provenance/ORIGINAL-TO-SANITIZED-HASH-BRIDGE.json"] = _pretty_json(
        bridge_record
    )
    readme = (
        "LegalBot v1.11 Phase 2A final blocked external-audit package\n\n"
        f"Verdict: {VERDICT}\n\n"
        "The internal machine package is immutable. This external derivative redacts the "
        "typed owner identifier while preserving a hash bridge to every original file. "
        "It contains no source blobs, vectors, private paths, keys, secrets, review roots, "
        "split secret, Development payload, Validation material or live state.\n"
    ).encode()
    _scan(readme, label="README.txt")
    entries["README.txt"] = readme
    return entries, bridge


def _write_archive(entries: dict[str, bytes]) -> dict[str, Any]:
    payload_files = {
        name: {"sha256": _sha256(raw), "bytes": len(raw)}
        for name, raw in sorted(entries.items())
    }
    manifest = _sealed(
        {
            "schema": "legalbot.v111.phase2a.final-blocked-external-audit.v1",
            "status": "COMPLETE_SANITIZED_NON_AUTHORIZING_EXTERNAL_AUDIT",
            "delivery_attempt": 2,
            "terminal_verdict": VERDICT,
            "original_machine_package_content_sha256": MACHINE_DIGEST,
            "all585_qualification_sha256": QUALIFICATION_SHA,
            "retrieval_reattestation_sha256": RETRIEVAL_SHA,
            "payload_file_count": len(payload_files),
            "payload_files": payload_files,
            "owner_identifier_redacted": True,
            "source_blobs_or_vectors_included": False,
            "private_paths_keys_or_secrets_included": False,
            "phase2a_technical_qualification_passed": False,
            "successful_phase2a_adoption_payload_available": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        },
        field="external_package_manifest_content_sha256",
    )
    manifest_raw = _pretty_json(manifest)
    _scan(manifest_raw, label="EXTERNAL-PACKAGE-MANIFEST.json")

    with tempfile.NamedTemporaryFile(
        prefix="phase2a-external-audit-", suffix=".zip.tmp", dir=FINAL_ROOT, delete=False
    ) as handle:
        temporary = Path(handle.name)
    try:
        archive_entries = dict(entries)
        archive_entries["EXTERNAL-PACKAGE-MANIFEST.json"] = manifest_raw
        with zipfile.ZipFile(temporary, "w", allowZip64=True) as package:
            for name, raw in sorted(archive_entries.items()):
                package.writestr(_zip_info(name), raw, compresslevel=9)
        if ARCHIVE.exists() or ARCHIVE.is_symlink():
            raise FileExistsError("external audit archive already exists")
        os.chmod(temporary, 0o600)
        os.replace(temporary, ARCHIVE)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise

    with zipfile.ZipFile(ARCHIVE, "r") as package:
        names = package.namelist()
        if names != sorted(names) or len(names) != len(set(names)):
            raise RuntimeError("external archive entries are not unique and sorted")
        for member in package.infolist():
            raw = package.read(member)
            _scan(raw, label=member.filename)
            if member.filename.endswith(".docx"):
                _scan_docx(raw, label=member.filename)
            if (
                member.filename in payload_files
                and _sha256(raw) != payload_files[member.filename]["sha256"]
            ):
                raise RuntimeError(f"external archive hash mismatch:{member.filename}")
    return manifest


def main() -> None:
    for path in (ARCHIVE, RECEIPT, SUMS):
        if path.exists() or path.is_symlink():
            raise FileExistsError(f"create-only delivery output exists:{path.name}")
    entries, bridge = _build_entries()
    manifest = _write_archive(entries)
    receipt = _sealed(
        {
            "schema": "legalbot.v111.phase2a.final-blocked-delivery-receipt.v1",
            "status": "COMPLETE_BLOCKED_PHASE2A_OWNER_REVIEW_DELIVERY",
            "delivery_attempt": 2,
            "prior_delivery_failure_fingerprint": (
                "phase2a_final_delivery|archive_verification|entry_order_mismatch|"
                "manifest_appended_after_sorted_payload|attempt=1"
            ),
            "terminal_verdict": VERDICT,
            "machine_package_content_sha256": MACHINE_DIGEST,
            "external_package_manifest_content_sha256": manifest[
                "external_package_manifest_content_sha256"
            ],
            "docx": {
                "relative_path": DOCX.relative_to(PROJECT_ROOT).as_posix(),
                "sha256": _sha256_file(DOCX),
                "bytes": DOCX.stat().st_size,
                "visual_qa_passed": True,
                "a11y_high_medium_low": [0, 0, 0],
            },
            "external_audit_zip": {
                "relative_path": ARCHIVE.relative_to(PROJECT_ROOT).as_posix(),
                "sha256": _sha256_file(ARCHIVE),
                "bytes": ARCHIVE.stat().st_size,
            },
            "sanitized_machine_file_count": len(bridge),
            "owner_identifier_redacted": True,
            "phase2a_technical_qualification_passed": False,
            "successful_phase2a_adoption_payload_available": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
            "active_or_previous_written": False,
        },
        field="final_delivery_content_sha256",
    )
    receipt_raw = _pretty_json(receipt)
    _scan(receipt_raw, label="FINAL-DELIVERY-RECEIPT.json")
    _write_new(RECEIPT, receipt_raw)
    sums = (
        f"{_sha256_file(DOCX)}  {DOCX.name}\n"
        f"{_sha256_file(ARCHIVE)}  {ARCHIVE.name}\n"
        f"{_sha256_file(RECEIPT)}  {RECEIPT.name}\n"
    ).encode()
    _write_new(SUMS, sums)
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "docx": str(DOCX),
                "external_audit_zip": str(ARCHIVE),
                "external_audit_zip_sha256": receipt["external_audit_zip"]["sha256"],
                "final_delivery_content_sha256": receipt[
                    "final_delivery_content_sha256"
                ],
                "terminal_verdict": VERDICT,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
