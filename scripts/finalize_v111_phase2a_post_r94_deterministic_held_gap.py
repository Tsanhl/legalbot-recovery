#!/usr/bin/env python3
"""Resolve the sole r100 held row conservatively without another model call.

This create-only Phase-2A pass binds the exact r100 advisory and r98d sealed-
candidate recovery artifacts.  The remaining held row has no validated atomic
proposition/exact-span pair, and its two planned authorities are outside the
sealed candidate.  It is therefore retained as a material-gap *advisory* for
owner review.  No owner decision, source admission, candidate mutation, or
later-phase authority is created here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
DEFAULT_R100_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-26-r100-debugged-held-exact-span-repair"
)
DEFAULT_R98D_ROOT = REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-26-r98d-candidate-recovery"
DEFAULT_OUTPUT_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-26-r101-deterministic-held-gap-resolution"
)

R100_ARTIFACT_NAME = "REPAIRED-EXACT-SPAN-ADVISORY-361.json"
R100_REPAIR_NAME = "DEBUGGED-HELD-REPAIRS-95.json"
R100_DIAGNOSTIC_RELATIVE_PATH = "diagnostics/008-24128cbf0ebeb29b4170e23d.json"
R98D_ARTIFACT_NAME = "CANDIDATE-RECOVERY-361.json"

EXPECTED_R100_CONTENT_SHA256 = "ca28380093dfdae60715ffa2ac47aadce84cbfe8e0d0cdd6664869f04da543a6"
EXPECTED_R100_FILE_SHA256 = "742b1a2cae86d489285366c1b6d9d81849ca1b36f63302a8e32112b894d920d5"
EXPECTED_R100_REPAIR_CONTENT_SHA256 = (
    "a2746b69c764e05dc00f7bfbd00d5ed425c328ce8ccfd38de09c66fd944e8eb2"
)
EXPECTED_R100_REPAIR_FILE_SHA256 = (
    "805521e88ea850286345d2c0c5bc3b9dcc46c7d9ebe193eb502aa061bf74afb4"
)
EXPECTED_R100_DIAGNOSTIC_CONTENT_SHA256 = (
    "dd6dcf3c7219af2d0933b91edcd63daf3eb6f50480f4e15d3d5103bfa7dcf67c"
)
EXPECTED_R100_DIAGNOSTIC_FILE_SHA256 = (
    "d592240ae8418c08c01559a533b355d1a9711bdb82643cb1431b6e1c1b2a91e0"
)
EXPECTED_R98D_CONTENT_SHA256 = "ad1d23ce7feabbd8936eb083fe678be2028f4723b60ffb8b42228a220de02ebf"
EXPECTED_R98D_FILE_SHA256 = "94d729a2eb802b05b25c36d0f8a9bd7a5b7095cfac885e1ec11a8712a937c3f6"
HELD_ROW_ID = "live60-q50:issue-07"
EXPECTED_PLANNED_AUTHORITIES = (
    "neutral-citation:[2012] EWCA Civ 638",
    "neutral-citation:[2015] EWCA Civ 401",
)
EXPECTED_ISSUE_LABEL = "notification"
EXPECTED_OFFICIAL_SOURCE_SEARCH_QUERY = (
    "Issue: notification. Legal domain: commercial insurance. "
    "Subject: commercial insurance. England and Wales governing legal rule "
    "official primary authority."
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


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


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_r101_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_r101_input_must_be_object")
    return value


def _verify_seal(
    value: Mapping[str, Any],
    field: str,
    code: str,
    expected: str,
) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or supplied != expected or supplied != _sealed(material):
        raise ValueError(code)
    return supplied


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


def _load_and_verify_sources(
    *, r100_root: Path, r98d_root: Path
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    r100_path = r100_root / R100_ARTIFACT_NAME
    repair_path = r100_root / R100_REPAIR_NAME
    diagnostic_path = r100_root / R100_DIAGNOSTIC_RELATIVE_PATH
    r98d_path = r98d_root / R98D_ARTIFACT_NAME
    expected_file_hashes = {
        r100_path: EXPECTED_R100_FILE_SHA256,
        repair_path: EXPECTED_R100_REPAIR_FILE_SHA256,
        diagnostic_path: EXPECTED_R100_DIAGNOSTIC_FILE_SHA256,
        r98d_path: EXPECTED_R98D_FILE_SHA256,
    }
    if any(_sha256_file(path) != expected for path, expected in expected_file_hashes.items()):
        raise ValueError("phase2a_r101_source_file_digest_invalid")

    r100 = _load_object(r100_path)
    repair = _load_object(repair_path)
    diagnostic = _load_object(diagnostic_path)
    r98d = _load_object(r98d_path)
    _verify_seal(
        r100,
        "artifact_content_sha256",
        "phase2a_r101_r100_seal_invalid",
        EXPECTED_R100_CONTENT_SHA256,
    )
    _verify_seal(
        repair,
        "artifact_content_sha256",
        "phase2a_r101_r100_repair_seal_invalid",
        EXPECTED_R100_REPAIR_CONTENT_SHA256,
    )
    _verify_seal(
        diagnostic,
        "diagnostic_content_sha256",
        "phase2a_r101_r100_diagnostic_seal_invalid",
        EXPECTED_R100_DIAGNOSTIC_CONTENT_SHA256,
    )
    _verify_seal(
        r98d,
        "artifact_content_sha256",
        "phase2a_r101_r98d_seal_invalid",
        EXPECTED_R98D_CONTENT_SHA256,
    )
    boundary_fields = (
        "owner_decisions_applied",
        "technical_qualification_assigned",
        "source_admission_authorized",
        "candidate_mutated",
        "phase2b_authorized",
        "development30_authorized",
    )
    if (
        r100.get("row_count") != 361
        or len(r100.get("findings", [])) != 361
        or r100.get("remaining_held_row_count") != 1
        or any(r100.get(field) is not False for field in boundary_fields)
        or repair.get("row_count") != 95
        or repair.get("failure_count") != 1
        or any(repair.get(field) is not False for field in boundary_fields)
        or r98d.get("row_count") != 361
        or len(r98d.get("rows", [])) != 361
        or any(r98d.get(field) is not False for field in boundary_fields)
    ):
        raise ValueError("phase2a_r101_source_boundary_invalid")
    return r100, repair, diagnostic, r98d


def build_resolution(
    *,
    r100_root: Path = DEFAULT_R100_ROOT,
    r98d_root: Path = DEFAULT_R98D_ROOT,
    output_root: Path = DEFAULT_OUTPUT_ROOT,
) -> dict[str, Any]:
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_r101_output_already_exists")
    r100, repair, diagnostic, r98d = _load_and_verify_sources(
        r100_root=r100_root, r98d_root=r98d_root
    )
    held = [
        dict(item)
        for item in r100["findings"]
        if str(item.get("assessment", "")).startswith("HELD_")
    ]
    repair_held = [
        dict(item)
        for item in repair["findings"]
        if str(item.get("assessment", "")).startswith("HELD_")
    ]
    recovery_rows = {str(item.get("row_id")): item for item in r98d["rows"]}
    if (
        len(held) != 1
        or len(repair_held) != 1
        or held[0].get("row_id") != HELD_ROW_ID
        or repair_held[0].get("row_id") != HELD_ROW_ID
        or diagnostic.get("row_id") != HELD_ROW_ID
        or diagnostic.get("error_code") != "structured_output_keys_invalid"
        or diagnostic.get("no_further_attempt_authorized_under_this_plan") is not True
        or diagnostic.get("total_attempt_ordinal_for_row") != 3
    ):
        raise ValueError("phase2a_r101_held_scope_invalid")

    recovery = recovery_rows.get(HELD_ROW_ID)
    if not isinstance(recovery, dict):
        raise ValueError("phase2a_r101_recovery_row_missing")
    candidates = recovery.get("candidates")
    planned = tuple(recovery.get("planned_authority_ids_outside_candidate", []))
    if (
        recovery.get("issue_label") != EXPECTED_ISSUE_LABEL
        or recovery.get("official_source_search_query") != EXPECTED_OFFICIAL_SOURCE_SEARCH_QUERY
        or recovery.get("status") != "EXACT_CANDIDATE_CHUNKS_READY_FOR_SPAN_VERIFICATION"
        or recovery.get("planned_source_identities_in_candidate") != []
        or planned != EXPECTED_PLANNED_AUTHORITIES
        or not isinstance(candidates, list)
        or len(candidates) != 6
        or any(
            candidate.get("already_in_exact_sealed_candidate") is not True
            for candidate in candidates
        )
        or any(
            candidate.get("candidate_manifest_source_bound") is not True for candidate in candidates
        )
    ):
        raise ValueError("phase2a_r101_recovery_evidence_changed")

    disposition_material = {
        "schema": "legalbot.v111.phase2a.post-r94-deterministic-held-gap.v1",
        "row_id": HELD_ROW_ID,
        "assessment": "MATERIAL_GAP_ADVISORY",
        "atomic_proposition": None,
        "exact_span_binding": None,
        "gap_reason": (
            "NO_VALIDATED_ATOMIC_PROPOSITION_EXACT_SPAN_PAIR_AND_PLANNED_"
            "AUTHORITIES_ARE_OUTSIDE_THE_SEALED_CANDIDATE"
        ),
        "issue_label": EXPECTED_ISSUE_LABEL,
        "official_source_search_query": EXPECTED_OFFICIAL_SOURCE_SEARCH_QUERY,
        "planned_authority_ids_outside_candidate": list(planned),
        "inspected_candidate_chunk_ids": [str(candidate["chunk_id"]) for candidate in candidates],
        "inspected_candidate_binding_sha256s": [
            str(candidate["candidate_content_sha256"]) for candidate in candidates
        ],
        "source_r100_held_finding_sha256": _sealed(held[0]),
        "source_r100_diagnostic_content_sha256": diagnostic["diagnostic_content_sha256"],
        "conservative_no_support_outcome": True,
        "additional_model_invocations": 0,
        "model_output_text_salvaged": False,
        "owner_outcome": None,
        "owner_decision_required": True,
        "technical_qualification_assigned": False,
    }
    disposition = {
        **disposition_material,
        "record_content_sha256": _sealed(disposition_material),
    }
    merged_findings = [
        disposition if item["row_id"] == HELD_ROW_ID else dict(item) for item in r100["findings"]
    ]
    if any(str(item.get("assessment", "")).startswith("HELD_") for item in merged_findings):
        raise ValueError("phase2a_r101_resolution_still_held")
    counts = Counter(str(item["assessment"]) for item in merged_findings)
    if counts != Counter(
        {
            "DIRECT_EXACT_SPAN_ADVISORY": 34,
            "PARTIAL_EXACT_SPAN_ADVISORY": 4,
            "MATERIAL_GAP_ADVISORY": 323,
        }
    ):
        raise ValueError("phase2a_r101_assessment_counts_invalid")

    merged_material = {
        "schema": (
            "legalbot.v111.phase2a.post-r94-exact-span-advisory-361-deterministically-complete.v1"
        ),
        "status": "ADVISORY_EXACT_SPAN_CLASSIFICATION_COMPLETE_OWNER_REVIEW_REQUIRED",
        "source_r100_artifact_content_sha256": r100["artifact_content_sha256"],
        "source_r100_artifact_file_sha256": EXPECTED_R100_FILE_SHA256,
        "source_r100_repair_artifact_content_sha256": repair["artifact_content_sha256"],
        "source_r98d_artifact_content_sha256": r98d["artifact_content_sha256"],
        "row_count": len(merged_findings),
        "assessment_counts": dict(sorted(counts.items())),
        "positive_binding_count": 38,
        "positive_binding_currentness_or_later_treatment_pending_count": 38,
        "material_gap_count": 323,
        "remaining_held_row_count": 0,
        "deterministic_held_gap_disposition": disposition,
        "findings": merged_findings,
        "additional_model_invocations": 0,
        "owner_decisions_applied": False,
        "technical_qualification_assigned": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    merged = {
        **merged_material,
        "artifact_content_sha256": _sealed(merged_material),
    }
    disposition_artifact_material = {
        "schema": "legalbot.v111.phase2a.post-r94-deterministic-held-resolution.v1",
        "status": "SOLE_R100_HELD_ROW_RETAINED_AS_MATERIAL_GAP_ADVISORY",
        "source_r100_artifact_content_sha256": r100["artifact_content_sha256"],
        "source_r98d_artifact_content_sha256": r98d["artifact_content_sha256"],
        "row_count": 1,
        "records": [disposition],
        "additional_model_invocations": 0,
        "owner_decisions_applied": False,
        "technical_qualification_assigned": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    disposition_artifact = {
        **disposition_artifact_material,
        "artifact_content_sha256": _sealed(disposition_artifact_material),
    }

    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_r101_output_mode_invalid")
    files = {
        "DETERMINISTIC-HELD-GAP-DISPOSITION-1.json": _pretty_json(disposition_artifact),
        "COMPLETE-EXACT-SPAN-ADVISORY-361.json": _pretty_json(merged),
        "OUTCOME.txt": (
            b"EXACT-SPAN ADVISORY CLASSIFICATION COMPLETE. OWNER DECISIONS "
            b"REMAIN REQUIRED. PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED.\n"
        ),
    }
    for name, raw in files.items():
        _write_exclusive(output_root / name, raw)
    sums = "".join(f"{_sha256_file(output_root / name)}  {name}\n" for name in sorted(files))
    _write_exclusive(output_root / "SHA256SUMS.txt", sums.encode("utf-8"))
    return merged


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--r100-root", type=Path, default=DEFAULT_R100_ROOT)
    parser.add_argument("--r98d-root", type=Path, default=DEFAULT_R98D_ROOT)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    args = parser.parse_args()
    artifact = build_resolution(
        r100_root=args.r100_root,
        r98d_root=args.r98d_root,
        output_root=args.output_root,
    )
    print(
        json.dumps(
            {
                "artifact_content_sha256": artifact["artifact_content_sha256"],
                "assessment_counts": artifact["assessment_counts"],
                "remaining_held_row_count": artifact["remaining_held_row_count"],
                "output_root": str(args.output_root.resolve()),
                "phase2b_authorized": artifact["phase2b_authorized"],
                "development30_authorized": artifact["development30_authorized"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
