from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from backend.app.evaluation.phase2a_blocker_semantic_advisory import (
    EXPECTED_FALLBACK_ROW_IDS,
    LEGAL_OR_POLICY_EVIDENCE_ONLY_ROW_IDS,
    NO_EXECUTION_FLAGS,
    build_blocker_semantic_advisory,
)

ROOT = Path(__file__).resolve().parents[2]
REVIEW = ROOT / "data/evaluations/phase2a-owner-review"
R3 = (
    REVIEW
    / "LegalBot-Phase2A-2026-08-28-prequalification-blockers-r3"
    / "PREQUALIFICATION-BLOCKER-REPORT.json"
)
ORIGINAL = (
    REVIEW
    / "LegalBot-Phase2A-2026-08-28-exact-remediation-owner-packet-r1"
    / "EXACT-REMEDIATION-OWNER-PACKET-361.json"
)
FALLBACK = (
    REVIEW
    / "LegalBot-Phase2A-2026-08-28-fact-only-fallback-coverage-advisory-r1"
    / "FACT-ONLY-FALLBACK-COVERAGE-ADVISORY-585.json"
)
CASES = ROOT / "benchmarks/evaluation/live-evaluation-60-v1/cases.jsonl"
MANIFEST = ROOT / "benchmarks/evaluation/live-evaluation-60-v1/manifest.json"


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _build() -> dict:
    return build_blocker_semantic_advisory(
        r3_report=_json(R3),
        original_packet=_json(ORIGINAL),
        fallback_advisory=_json(FALLBACK),
        cases_raw=CASES.read_bytes(),
        manifest_raw=MANIFEST.read_bytes(),
    )


def test_exact_partition_and_fallback_boundary() -> None:
    advisory = _build()
    assert advisory["counts"] == {
        "row_count": 146,
        "raw_hold_count": 461,
        "strict_matter_information_only_fallback_candidate_count": 0,
        "legal_or_policy_evidence_only_count": 8,
        "mixed_or_other_count": 138,
        "mixed_legal_and_matter_information_count": 99,
        "mixed_legal_and_analytical_or_policy_input_count": 39,
        "problem_row_count": 100,
        "essay_row_count": 46,
    }
    assert set(
        advisory["row_sets"]["legal_or_policy_evidence_only"]["row_ids"]
    ) == LEGAL_OR_POLICY_EVIDENCE_ONLY_ROW_IDS
    assert advisory["decisive_fallback_boundary"]["existing_exact_fallback_row_ids"] == sorted(
        EXPECTED_FALLBACK_ROW_IDS
    )
    assert not EXPECTED_FALLBACK_ROW_IDS & {row["row_id"] for row in advisory["rows"]}


def test_every_row_preserves_legal_blocker_and_every_raw_hold() -> None:
    r3 = _json(R3)
    r3_by_row = {row["row_id"]: row for row in r3["rows"]}
    advisory = _build()
    for row in advisory["rows"]:
        upstream = r3_by_row[row["row_id"]]
        assert row["existing_safe_fallback_eligible"] is False
        assert row["strict_matter_information_only"] is False
        assert row["legal_support_witnesses"]
        assert all(
            witness["support_fit"] in {"PARTIAL", "NONE"}
            for witness in row["legal_support_witnesses"]
        )
        assert [hold["hold_text"] for hold in row["all_raw_holds_preserved"]] == [
            hold["hold_text"] for hold in upstream["unclassified_unresolved_holds"]
        ]
        assert [hold["hold_text_sha256"] for hold in row["all_raw_holds_preserved"]] == [
            hold["hold_text_sha256"] for hold in upstream["unclassified_unresolved_holds"]
        ]
        if row["row_id"] in LEGAL_OR_POLICY_EVIDENCE_ONLY_ROW_IDS:
            assert row["nonlegal_dimension_witness"] is None
        else:
            witness = row["nonlegal_dimension_witness"]
            assert witness is not None
            assert witness["hold_text_sha256"] in {
                hold["hold_text_sha256"] for hold in upstream["unclassified_unresolved_holds"]
            }


def test_all_execution_and_authority_flags_remain_false() -> None:
    advisory = _build()
    for key, expected in NO_EXECUTION_FLAGS.items():
        assert advisory[key] is expected is False


def test_tampered_r3_fails_closed() -> None:
    r3 = _json(R3)
    tampered = copy.deepcopy(r3)
    tampered["rows"][0]["blocking_components"][0]["support_fit"] = "FULL"
    with pytest.raises(ValueError, match="input_seal_invalid"):
        build_blocker_semantic_advisory(
            r3_report=tampered,
            original_packet=_json(ORIGINAL),
            fallback_advisory=_json(FALLBACK),
            cases_raw=CASES.read_bytes(),
            manifest_raw=MANIFEST.read_bytes(),
        )
