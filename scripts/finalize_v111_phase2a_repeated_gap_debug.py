#!/usr/bin/env python3
"""Seal the repeated exact-span canary GAP and its execution-plan change."""

from __future__ import annotations

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
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts import verify_v111_phase2a_exact_semantic_spans_advisory as verifier  # noqa: E402

OWNER_REVIEW_ROOT = PROJECT_ROOT / "data" / "evaluations" / "phase2a-owner-review"
CANARY_ROOTS = (
    OWNER_REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r61c-exact-span-canary",
    OWNER_REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r61d-exact-span-canary",
)
OUTPUT_ROOT = (
    OWNER_REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r61e-repeat-gap-debug"
)
AFFECTED_ROW_ID = "live30-q02:issue-03"
EXPECTED_AUTHORITY = "ukpga:2015:15"
EXPECTED_LOCATOR = "section 11"
EXPECTED_CHUNK_ID = "chunk-5797f79997092c263c215e7bb0905ff91b4dd70c"
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
        raise ValueError("phase2a_repeat_gap_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_repeat_gap_input_must_be_object")
    return value


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or supplied != _sealed(material):
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


def main() -> None:
    if OUTPUT_ROOT.exists() or OUTPUT_ROOT.is_symlink():
        raise ValueError("phase2a_repeat_gap_output_already_exists")

    canary_digests: list[str] = []
    for root in CANARY_ROOTS:
        artifact = _load_object(root / "CANARY-EXACT-SPANS-5.json")
        digest = _verify_seal(
            artifact,
            "artifact_content_sha256",
            "phase2a_repeat_gap_canary_seal_invalid",
        )
        findings = artifact.get("findings")
        affected = [
            row
            for row in findings or []
            if isinstance(row, dict) and row.get("row_id") == AFFECTED_ROW_ID
        ]
        if (
            artifact.get("status") != "CANARY_STOPPED_FURTHER_DEBUG_REQUIRED"
            or artifact.get("unsupported_row_ids") != [AFFECTED_ROW_ID]
            or artifact.get("held_batch_count") != 0
            or len(affected) != 1
            or affected[0].get("assessment") != "MATERIAL_GAP_ADVISORY"
            or artifact.get("owner_decisions_applied") is not False
            or artifact.get("source_admission_authorized") is not False
            or artifact.get("candidate_mutated") is not False
        ):
            raise ValueError("phase2a_repeat_gap_canary_fingerprint_changed")
        canary_digests.append(digest)

    issue_rows, _, _, held, _ = verifier._load_inputs(
        locators_path=verifier.DEFAULT_LOCATORS,
        plans_path=verifier.DEFAULT_PLANS,
        remaining_path=verifier.DEFAULT_REMAINING,
        cases_path=verifier.DEFAULT_CASES,
    )
    if held:
        raise ValueError("phase2a_repeat_gap_upstream_rows_held")
    locators = verifier._load_object(verifier.DEFAULT_LOCATORS)
    issue = next(row for row in issue_rows if row["item_id"] == AFFECTED_ROW_ID)
    locator = next(
        row for row in locators["records"] if row["row_id"] == AFFECTED_ROW_ID
    )
    review_row = verifier._review_row(issue, locator)
    if not isinstance(review_row, dict) or len(review_row["evidence_candidates"]) != 2:
        raise ValueError("phase2a_repeat_gap_projection_fingerprint_changed")
    first = review_row["evidence_candidates"][0]
    first_chunk = first["chunks"][0]
    if (
        first.get("authority_identity_id") != EXPECTED_AUTHORITY
        or first.get("locator_hint") != EXPECTED_LOCATOR
        or first_chunk.get("chunk_id") != EXPECTED_CHUNK_ID
        or "goods will match the description" not in str(first_chunk.get("text") or "")
    ):
        raise ValueError("phase2a_repeat_gap_direct_evidence_fingerprint_changed")

    fingerprint_material = {
        "schema": "legalbot.v111.phase2a.repeated-advisory-gap-fingerprint.v1",
        "affected_row_id": AFFECTED_ROW_ID,
        "canary_artifact_content_sha256s": canary_digests,
        "top_ranked_authority_identity_id": EXPECTED_AUTHORITY,
        "top_ranked_locator": EXPECTED_LOCATOR,
        "top_ranked_chunk_id": EXPECTED_CHUNK_ID,
        "repeated_assessment": "MATERIAL_GAP_ADVISORY",
    }
    failure_fingerprint = _sealed(fingerprint_material)
    report_material = {
        "schema": "legalbot.v111.phase2a.repeated-advisory-gap-debug.v1",
        "status": "ROOT_CAUSE_DEBUGGED_NEW_EXECUTION_PLAN_REQUIRED",
        "failure_fingerprint": failure_fingerprint,
        "affected_stage": "PHASE2A_EXACT_SPAN_CANARY",
        "affected_rows": [AFFECTED_ROW_ID],
        "completed_work": {
            "completed_canary_revisions": [
                str(root.relative_to(PROJECT_ROOT)) for root in CANARY_ROOTS
            ],
            "canary_artifact_content_sha256s": canary_digests,
            "deterministic_top_ranked_exact_span_confirmed": True,
            "model_gap_observed_twice": True,
        },
        "root_cause_status": (
            "CONFIRMED_ADVISORY_FALSE_NEGATIVE_WHILE_A_SECOND_LEXICALLY_"
            "RELATED_BUT_LESS_APPLICABLE_CANDIDATE_WAS_VISIBLE"
        ),
        "root_cause_evidence": {
            "issue_label": issue["issue_label"],
            "top_ranked_authority_identity_id": EXPECTED_AUTHORITY,
            "top_ranked_locator": EXPECTED_LOCATOR,
            "top_ranked_chunk_id": EXPECTED_CHUNK_ID,
            "top_ranked_chunk_text_sha256": first_chunk["text_sha256"],
            "top_ranked_chunk_character_count": len(first_chunk["text"]),
            "second_candidate_identity": review_row["evidence_candidates"][1][
                "authority_identity_id"
            ],
        },
        "required_change_in_execution_plan": [
            "Project only the deterministic top-ranked evidence candidate and its top whole chunk into each advisory request.",
            "Continue sealing all omitted candidates and chunks in the upstream append-only recovery artifact.",
            "Treat any model GAP as advisory disagreement for owner review; do not let the model select a lower-ranked distractor.",
            "Run a new singleton canary revision before the all-448 advisory pass.",
        ],
        "same_execution_plan_third_attempt_forbidden": True,
        "new_revision_required": True,
        "raw_model_output_persisted": False,
        "hidden_reasoning_persisted": False,
        "owner_decisions_applied": False,
        "technical_qualification_assigned": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    report = {**report_material, "report_content_sha256": _sealed(report_material)}
    OUTPUT_ROOT.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(OUTPUT_ROOT.stat().st_mode) != 0o700:
        raise ValueError("phase2a_repeat_gap_output_mode_invalid")
    _write_exclusive(OUTPUT_ROOT / "DEBUG-REPORT.json", _pretty_json(report))
    _write_exclusive(
        OUTPUT_ROOT / "OUTCOME.txt",
        (
            "REPEATED ADVISORY GAP SEALED; TOP-ONE DETERMINISTIC PROJECTION "
            "REQUIRED BEFORE A NEW CANARY.\n"
        ).encode(),
    )
    names = ("DEBUG-REPORT.json", "OUTCOME.txt")
    sums = "".join(
        f"{_sha256_file(OUTPUT_ROOT / name)}  {name}\n" for name in names
    ).encode()
    _write_exclusive(OUTPUT_ROOT / "SHA256SUMS.txt", sums)
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
