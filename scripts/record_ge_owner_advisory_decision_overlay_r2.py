#!/usr/bin/env python3
"""Preserve the completed owner-advisory overlay without mutating originals.

Does not set qualified legal review, gold, admission, weight training, unseen,
promotion or live.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path("/Users/hltsang/Downloads/LegalBot-GE-owner-advisory-decision-overlay-r2.json")
PACK = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-owner-advisory-decision-overlay-r2"
)
MANIFEST = (
    ROOT
    / "data/indexes/builds/current-law-ew-full-fp16-v111-20260829-recovery-b"
    / "approved-source-manifest.json"
)
MATRIX = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-owner-advisory-source-matrix-input-r1"
    / "85-SOURCE-MATRIX.json"
)
CASES = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-owner-advisory-source-matrix-input-r1"
    / "CASES-008-174-312.json"
)
OVERLAY_R1 = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-pack-return-for-revision-r1"
)
EXPECTED_FILE_SHA256 = "51aecae99cf7820ebec181102ec4c0be0d3ee594ead1c6bd4f9f463a8779e816"
EXPECTED_CONTENT_SHA256 = "f7984a3f665ecc07127feda779945cabaa5a0a99dbbea743613424b5fec3a689"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _write_bytes(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _write_text(path: Path, text: str) -> None:
    data = text.encode("utf-8")
    if not data.endswith(b"\n"):
        data += b"\n"
    _write_bytes(path, data)


def _write_json(path: Path, value: Any) -> None:
    _write_text(path, json.dumps(value, ensure_ascii=False, indent=2))


def _source_class(row: dict[str, Any]) -> str:
    if row.get("subsequent_treatment_check_required") is True:
        return "judgment"
    if str(row.get("currentness_status") or "") == "historical":
        return "judgment"
    return "legislation"


def _currentness_row(row: dict[str, Any]) -> dict[str, Any]:
    kind = _source_class(row)
    if kind == "judgment":
        return {
            "source_version_id": row.get("source_version_id"),
            "authority_identity_id": row.get("authority_identity_id"),
            "title": row.get("title"),
            "source_class": kind,
            "source_identity": "CITABLE_HISTORICAL_IDENTITY",
            "proposition_currentness": "HOLD",
            "subsequent_treatment_verified": False,
            "full_current_law_eligible": False,
            "qualified_legal_review": False,
            "owner_decision": "BATCH_HOLD_AT_2026-08-28",
        }
    return {
        "source_version_id": row.get("source_version_id"),
        "authority_identity_id": row.get("authority_identity_id"),
        "title": row.get("title"),
        "source_class": kind,
        "source_snapshot_status": "CURRENT_TO_2026-08-14_ONLY",
        "cutoff_decision": "HOLD_FOR_2026-08-28",
        "full_current_law_eligible_2026_08_28": False,
        "qualified_legal_review": False,
        "unapplied_effect_count": row.get("unapplied_effect_count"),
        "owner_decision": "BATCH_HOLD_AT_2026-08-28",
    }


def main() -> int:
    if PACK.exists() or PACK.is_symlink():
        raise FileExistsError(f"create-only pack exists: {PACK}")
    raw = SOURCE.read_bytes()
    file_sha = hashlib.sha256(raw).hexdigest()
    if file_sha != EXPECTED_FILE_SHA256:
        raise RuntimeError(f"overlay file sha mismatch: {file_sha}")
    overlay = json.loads(raw)
    body = dict(overlay)
    claimed = str(body.pop("content_sha256") or "")
    content_sha = hashlib.sha256(_canonical_bytes(body)).hexdigest()
    if claimed != EXPECTED_CONTENT_SHA256 or content_sha != EXPECTED_CONTENT_SHA256:
        raise RuntimeError(f"overlay content sha mismatch: {content_sha}")
    matrix_sha = _sha256_file(MATRIX)
    cases_sha = _sha256_file(CASES)
    if matrix_sha != overlay["basis"]["source_matrix_declared_sha256"]:
        raise RuntimeError("bound source matrix hash mismatch")
    if cases_sha != overlay["basis"]["case_records_declared_sha256"]:
        raise RuntimeError("bound case-records hash mismatch")
    overlay_r1_sha = json.loads((OVERLAY_R1 / "PACKAGE-MANIFEST.json").read_text())["content_sha256"]
    if overlay_r1_sha != "3218ad24ef88880836f4af98ab166ea843bb8dbf080db87efdcc95de408136c8":
        raise RuntimeError("RETURN_FOR_REVISION overlay identity changed")

    PACK.mkdir(parents=True, mode=0o700)
    os.chmod(PACK, stat.S_IRWXU)
    dest = PACK / SOURCE.name
    _write_bytes(dest, raw)
    if _sha256_file(dest) != EXPECTED_FILE_SHA256:
        raise RuntimeError("copied overlay hash mismatch")

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    sources = list(manifest["sources"])
    if len(sources) != 85:
        raise RuntimeError("approved source manifest is not 85 rows")
    currentness_rows = [_currentness_row(row) for row in sources]
    kind_counts = {
        "legislation": sum(1 for row in currentness_rows if row["source_class"] == "legislation"),
        "judgment": sum(1 for row in currentness_rows if row["source_class"] == "judgment"),
    }
    currentness = {
        "schema": "legalbot.ge-85-currentness-batch-overlay.v1",
        "mutates_source_matrix": False,
        "mutates_approved_source_manifest": False,
        "qualified_legal_review": False,
        "legal_gold": False,
        "full_current_law_eligible": False,
        "runtime_admission": False,
        "source_manifest_sha256": manifest["manifest_sha256"],
        "source_matrix_sha256": matrix_sha,
        "reviewed_through": "2026-08-14",
        "hold_for": "2026-08-28",
        "kind_counts": kind_counts,
        "unapplied_effect_sum": sum(
            int(row["unapplied_effect_count"])
            for row in currentness_rows
            if isinstance(row.get("unapplied_effect_count"), int)
        ),
        "rows": currentness_rows,
    }
    currentness["content_sha256"] = hashlib.sha256(
        _canonical_bytes({key: value for key, value in currentness.items() if key != "content_sha256"})
    ).hexdigest()
    _write_json(PACK / "85-CURRENTNESS-BATCH-OVERLAY.json", currentness)

    receipt = {
        "schema": "legalbot.ge-owner-advisory-decision-overlay-receipt.v2",
        "recorded_at_utc": datetime.now(UTC).isoformat(),
        "classification": overlay["classification"],
        "qualified_legal_review": False,
        "qualified_england_and_wales_legal_reviewer": None,
        "legal_gold": False,
        "full_current_law_eligible": False,
        "runtime_admission": False,
        "answer_weight_training": False,
        "rerun_331_authorized": False,
        "sealed_unseen_disclosure": False,
        "promotion": False,
        "live": False,
        "original_packages_mutated": False,
        "overlay_file_sha256": EXPECTED_FILE_SHA256,
        "overlay_content_sha256": EXPECTED_CONTENT_SHA256,
        "source_matrix_sha256": matrix_sha,
        "case_records_sha256": cases_sha,
        "return_for_revision_overlay_content_sha256": overlay_r1_sha,
        "authorized_now": overlay["authorized_now"],
        "not_authorized_now": overlay["not_authorized_now"],
        "case_ids_unchanged": {
            "case_008": "administrative-law:cp-d08",
            "case_174": "international-commercial-mediation:cp-d01",
            "case_312": "wills-and-estates:cp-d02",
        },
    }
    receipt["content_sha256"] = hashlib.sha256(
        _canonical_bytes({key: value for key, value in receipt.items() if key != "content_sha256"})
    ).hexdigest()
    _write_json(PACK / "RECEIPT.json", receipt)
    _write_text(
        PACK / "README.md",
        """# Owner-advisory decision overlay r2

This folder preserves the completed five-item owner-advisory overlay.

It does **not** overwrite the 85-row source matrix, the approved-source
manifest, the RETURN_FOR_REVISION overlay, or the r3 run.

Classification: `AI_ASSISTED_OWNER_ADVISORY_RESEARCH_DECISION`.

Not set: qualified legal review, legal gold, runtime admission, full-current-law
eligibility, answer-weight training, 331 rerun, unseen disclosure, promotion or
live.
""",
    )
    artifacts = []
    for path in sorted(PACK.rglob("*")):
        if path.is_file():
            artifacts.append(f"{_sha256_file(path)}  {path.relative_to(PACK).as_posix()}")
    _write_text(PACK / "SHA256SUMS.txt", "\n".join(artifacts) + "\n")
    print(
        json.dumps(
            {
                "pack": str(PACK),
                "overlay_file_sha256": EXPECTED_FILE_SHA256,
                "overlay_content_sha256": EXPECTED_CONTENT_SHA256,
                "currentness_rows": len(currentness_rows),
                "kind_counts": kind_counts,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
