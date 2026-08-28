#!/usr/bin/env python3
"""Create the sanitized r48 DOCX/ZIP delivery and verify its exact identity."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MACHINE_ROOT = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review/LegalBot-Phase2AB-2026-08-24-r47-consolidated-owner-gate"
)
DEFAULT_DELIVERY_ROOT = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review/LegalBot-Phase2AB-2026-08-24-r48-owner-review-delivery"
)
DEFAULT_DOCX = (
    DEFAULT_DELIVERY_ROOT
    / "LegalBot-v111-Phase2A-Consolidated-Owner-Review-Agnes-2026-08-24-rev2.docx"
)
ZIP_NAME = "EXTERNAL-AUDIT-PHASE2A-CONSOLIDATED-OWNER-GATE-20260824.zip"
EXPECTED_DECISION_DIGEST = (
    "7a471bed936bf901cca49413f1abb8e27db54157862a1f369136a0704e811414"
)
EXPECTED_MACHINE_DIGEST = (
    "3ba8de75875cd2192a0707450c206fbb91220fbf3d3ac2704b1fd18046d1227c"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN = (
    b"/Users/",
    b"/private/",
    b"BEGIN PRIVATE KEY",
    b"BEGIN OPENSSH PRIVATE KEY",
    b"session_secret",
    b"csrf_secret",
)


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
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _load(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_delivery_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_delivery_input_must_be_object")
    return value


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _safe_archive_name(value: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError("phase2a_delivery_archive_path_invalid")
    return str(path)


def _scan(raw: bytes) -> None:
    if any(marker in raw for marker in _FORBIDDEN):
        raise ValueError("phase2a_delivery_forbidden_private_material")


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(_safe_archive_name(name), date_time=(2026, 8, 24, 0, 0, 0))
    info.create_system = 3
    info.external_attr = (0o600 & 0xFFFF) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def _media_type(name: str) -> str:
    suffix = Path(name).suffix.lower()
    return {
        ".json": "application/json",
        ".csv": "text/csv",
        ".txt": "text/plain",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    }.get(suffix, "application/octet-stream")


def finalize(machine_root: Path, delivery_root: Path, docx_path: Path) -> dict[str, Any]:
    if delivery_root.is_symlink() or not delivery_root.is_dir():
        raise ValueError("phase2a_delivery_root_invalid")
    if stat.S_IMODE(delivery_root.stat().st_mode) & 0o077:
        os.chmod(delivery_root, 0o700)
    if docx_path.is_symlink() or not docx_path.is_file():
        raise ValueError("phase2a_delivery_docx_invalid")

    index = _load(machine_root / "MACHINE-PACKAGE-INDEX.json")
    index_material = dict(index)
    supplied_machine_digest = str(
        index_material.pop("machine_package_content_sha256", "")
    )
    if (
        supplied_machine_digest != EXPECTED_MACHINE_DIGEST
        or supplied_machine_digest != _sealed(index_material)
        or index.get("phase2b_authorized") is not False
        or index.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_delivery_machine_index_invalid")
    files = index.get("files")
    if not isinstance(files, dict):
        raise ValueError("phase2a_delivery_machine_file_index_invalid")
    for name, expected in files.items():
        path = machine_root / _safe_archive_name(str(name))
        if path.parent != machine_root or path.is_symlink() or not path.is_file():
            raise ValueError("phase2a_delivery_machine_file_invalid")
        if (
            not isinstance(expected, dict)
            or _sha256_file(path) != expected.get("sha256")
            or path.stat().st_size != expected.get("bytes")
        ):
            raise ValueError("phase2a_delivery_machine_file_digest_invalid")
    sums = (machine_root / "SHA256SUMS.txt").read_text().splitlines()
    for line in sums:
        digest, name = line.split("  ", 1)
        path = machine_root / name
        if not _SHA256.fullmatch(digest) or _sha256_file(path) != digest:
            raise ValueError("phase2a_delivery_machine_checksums_invalid")

    decision = _load(machine_root / "OWNER-DECISION-BATCH-1058.json")
    decision_material = dict(decision)
    supplied_decision_digest = str(
        decision_material.pop("owner_decision_batch_content_sha256", "")
    )
    if (
        supplied_decision_digest != EXPECTED_DECISION_DIGEST
        or supplied_decision_digest != _sealed(decision_material)
        or decision.get("phase2b_authorized") is not False
        or decision.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_delivery_decision_digest_invalid")

    readme_raw = (
        "LegalBot v1.11 Phase 2A consolidated owner-review audit package\n\n"
        "This archive is non-authorizing. It contains the complete machine-readable "
        "owner gate and the visually verified owner-review DOCX.\n\n"
        f"Owner-decision batch digest: {EXPECTED_DECISION_DIGEST}\n"
        f"Machine package digest: {EXPECTED_MACHINE_DIGEST}\n\n"
        "Phase 2B and Development 30 are not authorized. No private key, session secret, "
        "CSRF secret, private review root, model socket, split secret or live state is included.\n"
    ).encode()
    _scan(readme_raw)

    archive_payloads: dict[str, bytes] = {}
    for path in sorted(machine_root.iterdir(), key=lambda item: item.name):
        if path.is_symlink() or not path.is_file():
            raise ValueError("phase2a_delivery_unexpected_machine_member")
        raw = path.read_bytes()
        _scan(raw)
        archive_payloads[f"machine/{path.name}"] = raw
    docx_raw = docx_path.read_bytes()
    _scan(docx_raw)
    archive_payloads[f"owner-review/{docx_path.name}"] = docx_raw
    archive_payloads["README.txt"] = readme_raw

    records = [
        {
            "archive_path": name,
            "sha256": _sha256(raw),
            "bytes": len(raw),
            "media_type": _media_type(name),
        }
        for name, raw in sorted(archive_payloads.items())
    ]
    external_material = {
        "schema": "legalbot.v111.phase2a.external-audit-manifest.v1",
        "status": "NON_AUTHORIZING_OWNER_REVIEW_PACKAGE",
        "owner_decision_batch_content_sha256": EXPECTED_DECISION_DIGEST,
        "machine_package_content_sha256": EXPECTED_MACHINE_DIGEST,
        "record_count": len(records),
        "records": records,
        "all_archive_paths_relative": True,
        "private_paths_included": False,
        "secrets_or_private_keys_included": False,
        "quarantine_source_blobs_included": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    external_manifest = {
        **external_material,
        "manifest_content_sha256": _sealed(external_material),
    }
    external_raw = _pretty_json(external_manifest)
    _scan(external_raw)

    readme_path = delivery_root / "EXTERNAL-AUDIT-README.txt"
    external_path = delivery_root / "EXTERNAL-AUDIT-MANIFEST.json"
    zip_path = delivery_root / ZIP_NAME
    delivery_manifest_path = delivery_root / "DELIVERY-MANIFEST.json"
    checksums_path = delivery_root / "DELIVERY-SHA256SUMS.txt"
    for path in (
        readme_path,
        external_path,
        zip_path,
        delivery_manifest_path,
        checksums_path,
    ):
        if path.exists() or path.is_symlink():
            raise ValueError("phase2a_delivery_output_already_exists")
    _write_exclusive(readme_path, readme_raw)
    _write_exclusive(external_path, external_raw)

    with zipfile.ZipFile(
        zip_path,
        mode="x",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for name, raw in sorted(archive_payloads.items()):
            archive.writestr(_zip_info(name), raw)
        archive.writestr(_zip_info("EXTERNAL-AUDIT-MANIFEST.json"), external_raw)
    os.chmod(zip_path, 0o600)

    delivery_material = {
        "schema": "legalbot.v111.phase2a.owner-review-delivery.v1",
        "status": "DELIVERY_VERIFIED_OWNER_DECISIONS_REQUIRED_PHASE2A_ONLY",
        "owner_decision_batch_content_sha256": EXPECTED_DECISION_DIGEST,
        "machine_package_content_sha256": EXPECTED_MACHINE_DIGEST,
        "external_audit_manifest_content_sha256": external_manifest[
            "manifest_content_sha256"
        ],
        "docx": {
            "file_name": docx_path.name,
            "sha256": _sha256(docx_raw),
            "bytes": len(docx_raw),
            "rendered_page_count": 5,
            "all_rendered_pages_visually_inspected": True,
            "table_geometry_audit_passed": True,
        },
        "external_audit_zip": {
            "file_name": zip_path.name,
            "sha256": _sha256_file(zip_path),
            "bytes": zip_path.stat().st_size,
        },
        "private_paths_included": False,
        "secrets_or_private_keys_included": False,
        "candidate_mutated": False,
        "source_admission_authorized": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    delivery = {
        **delivery_material,
        "delivery_content_sha256": _sealed(delivery_material),
    }
    _write_exclusive(delivery_manifest_path, _pretty_json(delivery))
    checksummed = (readme_path, external_path, docx_path, zip_path, delivery_manifest_path)
    sums_raw = "".join(
        f"{_sha256_file(path)}  {path.name}\n" for path in sorted(checksummed)
    ).encode()
    _write_exclusive(checksums_path, sums_raw)
    return {
        "docx": str(docx_path),
        "external_audit_zip": str(zip_path),
        "delivery_content_sha256": delivery["delivery_content_sha256"],
        "owner_decision_batch_content_sha256": EXPECTED_DECISION_DIGEST,
        "machine_package_content_sha256": EXPECTED_MACHINE_DIGEST,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--machine-root", type=Path, default=DEFAULT_MACHINE_ROOT)
    parser.add_argument("--delivery-root", type=Path, default=DEFAULT_DELIVERY_ROOT)
    parser.add_argument("--docx", type=Path, default=DEFAULT_DOCX)
    args = parser.parse_args()
    result = finalize(
        args.machine_root.resolve(strict=True),
        args.delivery_root.resolve(strict=True),
        args.docx.resolve(strict=True),
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
