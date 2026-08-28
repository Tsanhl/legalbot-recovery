#!/usr/bin/env python3
"""Conservatively resolve r68 malformed GAP outputs without another model call."""

from __future__ import annotations

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
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts import repair_v111_phase2a_held_exact_spans as repair  # noqa: E402
from scripts import verify_v111_phase2a_exact_semantic_spans_advisory as verifier  # noqa: E402

OWNER_REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
R68_ROOT = (
    OWNER_REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r68-debugged-held-row-repair"
)
R68_ARTIFACT_PATH = R68_ROOT / "DEBUGGED-HELD-REPAIRS-5.json"
OUTPUT_ROOT = (
    OWNER_REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r69-deterministic-held-gap-resolution"
)
EXPECTED_R68_ARTIFACT_CONTENT_SHA256 = (
    "e7ffa28eb516b73732d4883a723615bc7fa229350decc2dda2807ae24e1540fb"
)
STATIC_GAPS = {
    "live30-q16:issue-06": {
        "source_version_id": (
            "source-version-f08689990adf41acb4bc811a881a066e4105ee04"
        ),
        "authority_identity_id": "ukpga:1975:63",
        "locator": "section 1",
        "required_text_markers": (
            "reasonable financial provision",
            "law relating to intestacy",
        ),
        "reason": (
            "SUPPLIED_SPAN_CREATES_A_FAMILY_PROVISION_APPLICATION_AND_DOES_"
            "NOT_STATE_THE_INTESTACY_DISTRIBUTION_RULE"
        ),
    },
    "live60-q51:issue-02": {
        "source_version_id": (
            "source-version-f1d2fba5d67d7ecbb060841435513960b9bb861c"
        ),
        "authority_identity_id": "uksi:2018:597:made",
        "locator": "regulation 3",
        "required_text_markers": (
            "trade secret holder",
            "breach of confidence",
        ),
        "reason": (
            "SUPPLIED_SPAN_IS_A_TRADE_SECRET_REMEDIES_GATEWAY_AND_DOES_NOT_"
            "STATE_THE_GENERAL_BREACH_OF_CONFIDENCE_RULE_FOR_THE_SCENARIO"
        ),
    },
}
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
        raise ValueError("phase2a_held_gap_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_held_gap_input_must_be_object")
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
        raise ValueError("phase2a_held_gap_output_already_exists")
    r68 = _load_object(R68_ARTIFACT_PATH)
    r68_digest = _verify_seal(
        r68,
        "artifact_content_sha256",
        "phase2a_held_gap_r68_artifact_invalid",
    )
    if (
        r68_digest != EXPECTED_R68_ARTIFACT_CONTENT_SHA256
        or r68.get("failure_count") != 2
        or r68.get("owner_decisions_applied") is not False
        or r68.get("candidate_mutated") is not False
    ):
        raise ValueError("phase2a_held_gap_r68_boundary_invalid")
    by_id = {str(row["row_id"]): row for row in r68["findings"]}
    if set(by_id) != set(repair.HELD_ROW_IDS):
        raise ValueError("phase2a_held_gap_r68_row_scope_invalid")

    diagnostic_by_id: dict[str, dict[str, Any]] = {}
    for path in sorted((R68_ROOT / "diagnostics").glob("*.json")):
        value = _load_object(path)
        _verify_seal(
            value,
            "diagnostic_content_sha256",
            "phase2a_held_gap_r68_diagnostic_invalid",
        )
        diagnostic_by_id[str(value["row_id"])] = value
    if set(diagnostic_by_id) != set(STATIC_GAPS):
        raise ValueError("phase2a_held_gap_r68_failure_scope_invalid")
    if any(
        value.get("error_code") != "structured_output_gap_contract_invalid"
        or value.get("no_further_attempt_authorized_under_this_plan") is not True
        for value in diagnostic_by_id.values()
    ):
        raise ValueError("phase2a_held_gap_r68_failure_type_changed")

    rows, _, _, upstream_held, candidate_sources, hashes = verifier._load_inputs(
        locators_path=verifier.DEFAULT_LOCATORS,
        plans_path=verifier.DEFAULT_PLANS,
        remaining_path=verifier.DEFAULT_REMAINING,
        cases_path=verifier.DEFAULT_CASES,
        candidate_manifest_path=verifier.DEFAULT_CANDIDATE_MANIFEST,
    )
    if upstream_held:
        raise ValueError("phase2a_held_gap_upstream_planner_held")
    issues = {str(row["item_id"]): row for row in rows}
    records = {
        str(row["row_id"]): row
        for row in verifier._load_object(verifier.DEFAULT_LOCATORS)["records"]
    }
    deterministic_records: list[dict[str, Any]] = []
    for row_id, expectation in STATIC_GAPS.items():
        projected = verifier._review_row(
            issues[row_id], records[row_id], candidate_sources
        )
        if projected is None or len(projected["evidence_candidates"]) != 1:
            raise ValueError("phase2a_held_gap_projection_missing")
        source = projected["evidence_candidates"][0]
        chunk = source["chunks"][0]
        exact_text = "".join(
            str(span["exact_text"]) for span in chunk["exact_span_options"]
        )
        if (
            source.get("source_version_id") != expectation["source_version_id"]
            or source.get("authority_identity_id")
            != expectation["authority_identity_id"]
            or chunk.get("locator") != expectation["locator"]
            or any(
                marker not in exact_text
                for marker in expectation["required_text_markers"]
            )
        ):
            raise ValueError("phase2a_held_gap_projection_identity_changed")
        material = {
            "schema": "legalbot.v111.phase2a.deterministic-held-gap.v1",
            "row_id": row_id,
            "assessment": "MATERIAL_GAP_ADVISORY",
            "atomic_proposition": None,
            "exact_span_binding": None,
            "gap_reason": expectation["reason"],
            "source_version_id_inspected": source["source_version_id"],
            "authority_identity_id_inspected": source["authority_identity_id"],
            "chunk_id_inspected": chunk["chunk_id"],
            "chunk_text_sha256_inspected": chunk["text_sha256"],
            "r68_diagnostic_content_sha256": diagnostic_by_id[row_id][
                "diagnostic_content_sha256"
            ],
            "conservative_no_support_outcome": True,
            "model_output_text_salvaged": False,
            "owner_outcome": None,
            "owner_decision_required": True,
            "technical_qualification_assigned": False,
        }
        deterministic_records.append(
            {**material, "record_content_sha256": _sealed(material)}
        )

    resolved_findings = []
    replacements = {row["row_id"]: row for row in deterministic_records}
    for row_id in repair.HELD_ROW_IDS:
        resolved_findings.append(replacements.get(row_id, by_id[row_id]))
    if any(
        row.get("assessment")
        in {
            "HELD_AFTER_DEBUGGED_THIRD_ATTEMPT",
            "HELD_FOR_DEBUG_BEFORE_ANY_THIRD_ATTEMPT",
        }
        for row in resolved_findings
    ):
        raise ValueError("phase2a_held_gap_resolution_still_held")
    counts = Counter(str(row["assessment"]) for row in resolved_findings)
    material = {
        "schema": "legalbot.v111.phase2a.resolved-held-findings-5.v1",
        "status": "ALL_FIVE_R67_HELD_ROWS_RESOLVED_FOR_OWNER_ADVISORY_PACKAGE",
        "source_r68_artifact_content_sha256": r68_digest,
        "source_r68_artifact_file_sha256": _sha256_file(R68_ARTIFACT_PATH),
        "source_candidate_manifest_sha256": hashes["candidate_manifest"],
        "source_candidate_manifest_file_sha256": hashes[
            "candidate_manifest_file"
        ],
        "row_count": len(resolved_findings),
        "assessment_counts": dict(sorted(counts.items())),
        "deterministic_gap_row_ids": sorted(STATIC_GAPS),
        "model_output_text_salvaged": False,
        "additional_model_invocations": 0,
        "findings": resolved_findings,
        "owner_decisions_applied": False,
        "technical_qualification_assigned": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    artifact = {**material, "artifact_content_sha256": _sealed(material)}
    OUTPUT_ROOT.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(OUTPUT_ROOT.stat().st_mode) != 0o700:
        raise ValueError("phase2a_held_gap_output_mode_invalid")
    _write_exclusive(
        OUTPUT_ROOT / "RESOLVED-HELD-FINDINGS-5.json", _pretty_json(artifact)
    )
    _write_exclusive(
        OUTPUT_ROOT / "OUTCOME.txt",
        b"ALL FIVE R67 HELD ROWS RESOLVED FOR OWNER ADVISORY REVIEW.\n",
    )
    names = ["RESOLVED-HELD-FINDINGS-5.json", "OUTCOME.txt"]
    sums = "".join(
        f"{_sha256_file(OUTPUT_ROOT / name)}  {name}\n" for name in names
    ).encode()
    _write_exclusive(OUTPUT_ROOT / "SHA256SUMS.txt", sums)
    print(json.dumps(artifact, sort_keys=True))


if __name__ == "__main__":
    main()
