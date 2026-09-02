#!/usr/bin/env python3
"""Record owner adoption of the r2 advisory overlay. Create-only. Not gold."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OVERLAY = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-owner-advisory-decision-overlay-r2"
    / "LegalBot-GE-owner-advisory-decision-overlay-r2.json"
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
R1 = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-pack-return-for-revision-r1"
    / "PACKAGE-MANIFEST.json"
)
R3 = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-01-improvement-training-unseen-r3"
    / "RUN-MANIFEST.json"
)
PACK = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-owner-adoption-r1"
)
EXPECTED_FILE = "51aecae99cf7820ebec181102ec4c0be0d3ee594ead1c6bd4f9f463a8779e816"
EXPECTED_CONTENT = "f7984a3f665ecc07127feda779945cabaa5a0a99dbbea743613424b5fec3a689"
EXPECTED_MATRIX = "cde867cd2c911c893269330d381b3e4c3d1b88745a99158c9ba58e17b089f8ea"
EXPECTED_CASES = "f3fb6dc55187f556f37d92b23903bdf7cc7635471ffc709b9cb84c2c48b2a16c"
EXPECTED_R1 = "3218ad24ef88880836f4af98ab166ea843bb8dbf080db87efdcc95de408136c8"
EXPECTED_R3 = "e4e5d59377b7377ec1311774cae4e3810cccbf3baef8c106a4c4b150cf4ee123"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _write_text(path: Path, text: str) -> None:
    data = text.encode("utf-8")
    if not data.endswith(b"\n"):
        data += b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _write_json(path: Path, value: Any) -> None:
    _write_text(path, json.dumps(value, ensure_ascii=False, indent=2))


def _digest(value: dict[str, Any]) -> dict[str, Any]:
    body = {key: item for key, item in value.items() if key != "content_sha256"}
    result = dict(value)
    result["content_sha256"] = hashlib.sha256(_canonical_bytes(body)).hexdigest()
    return result


def main() -> int:
    if PACK.exists() or PACK.is_symlink():
        raise FileExistsError(f"create-only pack exists: {PACK}")
    raw = OVERLAY.read_bytes()
    file_sha = hashlib.sha256(raw).hexdigest()
    if file_sha != EXPECTED_FILE:
        raise RuntimeError(f"overlay file sha mismatch: {file_sha}")
    overlay = json.loads(raw)
    body = dict(overlay)
    claimed = str(body.pop("content_sha256") or "")
    content_sha = hashlib.sha256(_canonical_bytes(body)).hexdigest()
    if claimed != EXPECTED_CONTENT or content_sha != EXPECTED_CONTENT:
        raise RuntimeError(f"overlay content sha mismatch: {content_sha}")
    matrix_sha = _sha256_file(MATRIX)
    cases_sha = _sha256_file(CASES)
    r1_sha = json.loads(R1.read_text(encoding="utf-8"))["content_sha256"]
    r3_sha = json.loads(R3.read_text(encoding="utf-8"))["content_sha256"]
    if matrix_sha != EXPECTED_MATRIX:
        raise RuntimeError("source matrix mutated")
    if cases_sha != EXPECTED_CASES:
        raise RuntimeError("case records mutated")
    if r1_sha != EXPECTED_R1:
        raise RuntimeError("RETURN_FOR_REVISION overlay mutated")
    if r3_sha != EXPECTED_R3:
        raise RuntimeError("r3 run mutated")

    PACK.mkdir(parents=True, mode=0o700)
    os.chmod(PACK, stat.S_IRWXU)
    recorded_at = datetime.now(UTC).isoformat()

    adoption = _digest(
        {
            "schema": "legalbot.ge-owner-adoption.v1",
            "recorded_at_utc": recorded_at,
            "disposition": "OWNER_ADOPTION",
            "classification": "OWNER_ADOPTED_RESEARCH_AND_PROCESS_DECISION",
            "adopts_overlay_classification": overlay["classification"],
            "owner_role": "owner",
            "qualified_legal_review": False,
            "qualified_england_and_wales_legal_reviewer": None,
            "ai_is_not_the_qualified_legal_reviewer": True,
            "grok_or_chatgpt_are_not_the_legal_reviewer": True,
            "legal_gold": False,
            "admitted": False,
            "full_current_law_eligible": False,
            "runtime_admission": False,
            "answer_weight_training": False,
            "rerun_331": False,
            "sealed_unseen": False,
            "promotion": False,
            "live": False,
            "original_packages_mutated": False,
            "overlay_relative_path": (
                "data/evaluations/general-enquiries/"
                "LegalBot-GE-2026-09-02-owner-advisory-decision-overlay-r2/"
                "LegalBot-GE-owner-advisory-decision-overlay-r2.json"
            ),
            "overlay_file_sha256": EXPECTED_FILE,
            "overlay_content_sha256": EXPECTED_CONTENT,
            "source_matrix_sha256": EXPECTED_MATRIX,
            "case_records_sha256": EXPECTED_CASES,
            "return_for_revision_overlay_content_sha256": EXPECTED_R1,
            "r3_run_content_sha256": EXPECTED_R3,
            "adopted_decisions": {
                "CURRENTNESS_85": {
                    "decision": "BATCH_HOLD_AT_2026-08-28",
                    "legislation": "CURRENT_TO_2026-08-14_ONLY and HOLD_FOR_2026-08-28",
                    "judgments": "historical identity may remain citable; proposition currentness HOLD",
                    "full_current_law_eligible": False,
                },
                "MISSING_PRIMARY_AUTHORITIES": {
                    "decision": "AUTHORIZE_OFFICIAL_STAGING_INTAKE",
                    "runtime": "FAIL_CLOSED_UNTIL_VALIDATED_MAPPED_AND_QUALIFIED",
                    "core_source_deferral": False,
                    "do_not_admit_unidentified_title": ["Mediation Act 2025"],
                },
                "CASE_008": {
                    "case_id": "administrative-law:cp-d08",
                    "source_review_ordinal": 8,
                    "confirm": [
                        "Equality Act 2010 section 20",
                        "Equality Act 2010 section 21",
                        "Equality Act 2010 section 29",
                        "Equality Act 2010 Schedule 2",
                    ],
                    "add_where_in_scope": [
                        "Public Sector Bodies (Websites and Mobile Applications) (No. 2) Accessibility Regulations 2018"
                    ],
                    "reject": [
                        "Equality Act 2010 section 174",
                        "Equality Act 2010 section 208",
                        "Equality Act 2010 section 210",
                    ],
                    "gold": False,
                },
                "CASE_174": {
                    "case_id": "international-commercial-mediation:cp-d01",
                    "source_review_ordinal": 174,
                    "reject": "Arbitration Act 1996 section 9 as a substitute",
                    "authority_route": "clause + incorporated ICC Mediation Rules + English contractual-ADR authorities",
                    "singapore_convention": "NOT_CONTROLLING",
                    "gold": False,
                    "status": "FAIL_CLOSED_PENDING_INTAKE_AND_REVIEW",
                },
                "CASE_312": {
                    "case_id": "wills-and-estates:cp-d02",
                    "source_review_ordinal": 312,
                    "legal_date": "2024-01-15",
                    "temporal_method": "POINT_IN_TIME",
                    "video_will_window": "IN_SCOPE",
                    "latest_2026_text_only": "PROHIBITED",
                    "validity": "HOLD",
                    "gold": False,
                },
            },
            "authorized_now": {
                "official_create_only_staging_intake": True,
                "point_in_time_extent_commencement_and_effects_review": True,
                "proposition_and_case_route_mapping": True,
                "evaluator_retrieval_and_non_weight_planner_repair": True,
            },
            "not_authorized_now": {
                "qualified_legal_review": False,
                "legal_gold": False,
                "admitted": False,
                "full_current_law_eligible": False,
                "answer_weight_training": False,
                "rerun_331": False,
                "sealed_unseen": False,
                "promotion": False,
                "live": False,
            },
        }
    )
    _write_json(PACK / "OWNER-ADOPTION.json", adoption)
    _write_text(
        PACK / "README.md",
        """# Owner adoption r1

The owner adopted the exact r2 advisory overlay as an
**owner-adopted research and process decision**.

This is not qualified England-and-Wales legal review, legal gold, runtime
admission, full-current-law eligibility, a 331 rerun, weight training, unseen
disclosure, promotion or live activation.

The overlay, 85-row matrix, RETURN_FOR_REVISION pack and r3 run were not
overwritten.
""",
    )
    artifacts = []
    for path in sorted(PACK.rglob("*")):
        if path.is_file():
            artifacts.append(
                {
                    "path": path.relative_to(PACK).as_posix(),
                    "bytes": path.stat().st_size,
                    "sha256": _sha256_file(path),
                }
            )
    _write_text(
        PACK / "SHA256SUMS.txt",
        "\n".join(f"{item['sha256']}  {item['path']}" for item in artifacts) + "\n",
    )
    package = _digest(
        {
            "schema": "legalbot.ge-owner-adoption-package.v1",
            "run_id": PACK.name,
            "disposition": "OWNER_ADOPTION",
            "authorizing": False,
            "qualified_legal_review": False,
            "legal_gold": False,
            "admitted": False,
            "full_current_law_eligible": False,
            "rerun_331": False,
            "overlay_file_sha256": EXPECTED_FILE,
            "overlay_content_sha256": EXPECTED_CONTENT,
            "owner_adoption_content_sha256": adoption["content_sha256"],
            "original_packages_mutated": False,
            "artifacts": artifacts
            + [
                {
                    "path": "SHA256SUMS.txt",
                    "bytes": (PACK / "SHA256SUMS.txt").stat().st_size,
                    "sha256": _sha256_file(PACK / "SHA256SUMS.txt"),
                }
            ],
        }
    )
    _write_json(PACK / "PACKAGE-MANIFEST.json", package)
    print(
        json.dumps(
            {
                "pack": str(PACK),
                "adoption_content_sha256": adoption["content_sha256"],
                "package_content_sha256": package["content_sha256"],
                "overlay_file_sha256": EXPECTED_FILE,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
