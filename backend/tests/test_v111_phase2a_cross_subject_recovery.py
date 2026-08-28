from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest
from scripts.build_v111_phase2a_cross_subject_recovery import (
    _rank_rows,
    _target_rows,
    build_cross_subject_recovery,
)

from app.evaluation.phase2a_research_packets import ResearchSource, ResearchSpan

ROOT = Path(__file__).resolve().parents[2]
OWNER_REVIEW = ROOT / "data" / "evaluations" / "phase2a-owner-review"
REMAINDER = (
    OWNER_REVIEW
    / "LegalBot-Phase2AB-2026-08-24-r29"
    / "REMAINING-448-RESEARCH-PACKETS.json"
)
CASES = ROOT / "benchmarks" / "evaluation" / "live-evaluation-60-v1" / "cases.jsonl"
CANDIDATE = (
    ROOT
    / "data"
    / "indexes"
    / "builds"
    / "current-law-ew-full-fp16-v111-20260818-a"
    / "approved-source-manifest.json"
)


def _span(
    *, family: str, current: bool, subject: str, text: str, identity: str
) -> ResearchSpan:
    source = ResearchSource(
        source_version_id=f"source-{identity}",
        authority_identity_id=identity,
        stable_identifier=identity,
        title="Official source",
        canonical_citation="Official source",
        canonical_url="https://www.legislation.gov.uk/example",
        subject=subject,
        version_sha256="a" * 64,
        as_of_date="2026-08-14",
        currentness_status="latest_available_revised_snapshot",
        identity_verified=True,
        currentness_verified=current,
        family=family,
    )
    return ResearchSpan(
        source=source,
        locator="section 1",
        chunk_ids=("chunk-1",),
        chunk_text_sha256s=("b" * 64,),
        text=text,
        span_bundle_sha256="c" * 64,
    )


def test_exactly_37_rows_have_no_current_noncase_candidate() -> None:
    remainder = json.loads(REMAINDER.read_bytes())
    targets = _target_rows(remainder)
    assert len(targets) == 37
    assert targets[0]["row_id"] == "live30-q18:issue-02"
    assert targets[-1]["row_id"] == "live60-q58:issue-14"


def test_global_ranker_excludes_cases_and_unverified_sources() -> None:
    remainder = json.loads(REMAINDER.read_bytes())
    row = _target_rows(remainder)[0]
    cases = {
        line["case_id"]: line
        for raw in CASES.read_text(encoding="utf-8").splitlines()
        if raw.strip()
        for line in [json.loads(raw)]
    }
    spans = [
        _span(
            family="legislation_or_procedural_instrument",
            current=True,
            subject="unexpected subject",
            text="bank contractual duties negligence recovery",
            identity="ukpga:1:1",
        ),
        _span(
            family="case",
            current=True,
            subject="unexpected subject",
            text="bank contractual duties negligence recovery",
            identity="neutral-citation:[2024] UKSC 1",
        ),
        _span(
            family="legislation_or_procedural_instrument",
            current=False,
            subject="unexpected subject",
            text="bank contractual duties negligence recovery",
            identity="ukpga:2:2",
        ),
    ]
    packets, metrics = _rank_rows(
        rows=[row],
        cases=cases,
        spans=spans,
        candidate_authorities=frozenset({"ukpga:1:1"}),
        candidate_versions=frozenset(),
        limit=4,
    )
    assert metrics["eligible_current_noncase_span_count"] == 1
    assert packets[0]["candidate_count"] == 1
    candidate = packets[0]["candidates"][0]
    assert candidate["authority_identity_id"] == "ukpga:1:1"
    assert candidate["outside_original_subject_route"] is True
    assert candidate["already_in_sealed_candidate"] is True
    assert packets[0]["technical_qualification_assigned"] is False


def test_create_only_refuses_existing_output_before_expensive_reads(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    output.mkdir()
    with pytest.raises(ValueError, match="phase2a_cross_subject_output_already_exists"):
        build_cross_subject_recovery(
            remainder_path=REMAINDER,
            cases_path=CASES,
            candidate_manifest_path=CANDIDATE,
            catalogue_path=ROOT / "data" / "catalog.sqlite3",
            target_date=date(2026, 8, 14),
            output_root=output,
        )
