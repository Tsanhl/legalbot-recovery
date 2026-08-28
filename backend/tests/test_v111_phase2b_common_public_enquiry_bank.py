from __future__ import annotations

import hashlib
import json
import re
import stat
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
RUN_ROOT = (
    PROJECT_ROOT
    / "data/evaluations/phase2b-question-drafts"
    / "LegalBot-Phase2B-2026-08-28-common-public-enquiries-draft-r1"
)
EXPECTED_TOPICS = {
    "administrative-law",
    "ai-and-data-protection",
    "business-and-company-law",
    "commercial-law",
    "competition-law",
    "contemporary-biolaw-and-regulation",
    "contract-law",
    "criminal-law",
    "eu-internal-market-law",
    "international-commercial-mediation",
    "land-law",
    "law-and-medicine",
    "pensions-law",
    "private-international-law",
    "tort-law",
    "trusts-law",
    "wills-and-estates",
}


def _canonical_json(value: dict) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _assert_record_digest(record: dict) -> None:
    value = dict(record)
    expected = value.pop("record_content_sha256")
    assert hashlib.sha256(_canonical_json(value)).hexdigest() == expected


def test_common_public_package_counts_and_non_authorizing_state() -> None:
    manifest = json.loads((RUN_ROOT / "PACKAGE-MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "COMMON_PUBLIC_QUESTION_BANK_READY_FOR_OWNER_REVIEW_NOT_PHASE2B"
    assert manifest["topic_count"] == 17
    assert manifest["visible_question_count"] == 306
    assert manifest["unseen_custody_draft_question_count"] == 306
    assert manifest["total_question_record_count"] == 612
    assert manifest["frozen_validation_question_count"] == 0
    assert manifest["phase2a_running_task_read_or_consumed"] is False
    for key in (
        "source_admission_authorized",
        "source_admitted",
        "source_scan_run",
        "index_built",
        "embedding_run",
        "retrieval_run",
        "gold_answers_created",
        "evidence_spans_created",
        "answer_model_authorized",
        "answer_model_run",
        "model_training_authorized",
        "model_training_run",
        "phase2b_authorized",
        "phase2b_run",
        "validation_authorized",
        "promotion_authorized",
        "active_pointer_written",
        "previous_pointer_written",
        "phase2c_authorized",
        "live_activation_authorized",
        "live_activation_run",
    ):
        assert manifest[key] is False


def test_each_topic_has_18_visible_and_18_private_unseen_with_exact_mix() -> None:
    topic_dirs = {path.name for path in (RUN_ROOT / "topics").iterdir() if path.is_dir()}
    assert topic_dirs == EXPECTED_TOPICS
    all_ids: set[str] = set()
    all_prompts: set[str] = set()
    for topic_id in sorted(EXPECTED_TOPICS):
        topic_root = RUN_ROOT / "topics" / topic_id
        visible_path = topic_root / "development/COMMON-PUBLIC-QUESTION-SET.jsonl"
        unseen_path = topic_root / "unseen-custody/PRIVATE-COMMON-PUBLIC-UNSEEN.jsonl"
        visible = _read_jsonl(visible_path)
        unseen = _read_jsonl(unseen_path)
        assert len(visible) == len(unseen) == 18
        assert stat.S_IMODE(unseen_path.stat().st_mode) == 0o600
        assert not list((topic_root / "unseen-custody").glob("*.md"))
        expected_mix = {
            "EVERYDAY_SINGLE_ISSUE": 8,
            "MULTI_ISSUE_FACT_PATTERN": 5,
            "FALSE_PREMISE_CORRECTION": 3,
            "URGENT_OR_SAFETY_BOUNDARY": 2,
        }
        assert Counter(row["scenario_class"] for row in visible) == expected_mix
        assert Counter(row["scenario_class"] for row in unseen) == expected_mix
        assert sum(row["must_correct_false_premise"] for row in visible) == 3
        assert sum(row["must_correct_false_premise"] for row in unseen) == 3
        assert sum(row["urgency"] == "URGENT" for row in visible) == 2
        assert sum(row["urgency"] == "URGENT" for row in unseen) == 2
        for row in visible + unseen:
            _assert_record_digest(row)
            assert row["question_type"] == "GENERAL_ENQUIRY"
            assert row["fact_status"] == "HYPOTHETICAL"
            assert row["must_ask_clarifying_questions"] is True
            assert row["execution_bank_membership"] is False
            assert row["phase2b_run"] is False
            assert row["question_id"] not in all_ids
            assert row["prompt"] not in all_prompts
            all_ids.add(row["question_id"])
            all_prompts.add(row["prompt"])
    assert len(all_ids) == len(all_prompts) == 612


def test_unseen_leakage_and_owner_projection_boundary() -> None:
    audit = json.loads((RUN_ROOT / "UNSEEN-LEAKAGE-AUDIT.json").read_text(encoding="utf-8"))
    assert audit["status"] == "PASS_DRAFT_CUSTODY_SEPARATION"
    assert audit["exact_normalized_prompt_overlap_count"] == 0
    assert audit["maximum_similarity"] < audit["near_overlap_threshold_exclusive"] == 0.55
    review = (RUN_ROOT / "OWNER-REVIEW-GUIDE.md").read_text(encoding="utf-8")
    for topic_id in EXPECTED_TOPICS:
        for ordinal in range(1, 19):
            assert f"{topic_id}:cp-d{ordinal:02d}" in review
            assert f"{topic_id}:cp-u{ordinal:02d}" not in review


def test_checksums_and_no_private_path_or_identity_leakage() -> None:
    for line in (RUN_ROOT / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
        expected, relative = line.split("  ", 1)
        assert hashlib.sha256((RUN_ROOT / relative).read_bytes()).hexdigest() == expected
    forbidden = (re.compile(rb"/Users/", re.IGNORECASE), re.compile(rb"hltsang", re.IGNORECASE), re.compile(rb"\bAgnes\b", re.IGNORECASE))
    for path in RUN_ROOT.rglob("*"):
        if path.is_file():
            for pattern in forbidden:
                assert not pattern.search(path.read_bytes()), path


def test_function_contract_keeps_conversation_separate_from_legal_evidence() -> None:
    contract = json.loads((RUN_ROOT / "FUNCTION-TEST-CONTRACT.json").read_text(encoding="utf-8"))
    assert contract["status"] == "DRAFT_NOT_EXECUTED"
    assert "never counts as legal evidence or authority" in contract["conversation_context_rule"]
    assert "NO_CLAIM_OF_LAWYER_CLIENT_RELATIONSHIP" in contract["expected_function_checks"]
    assert contract["model_training_export"] is False
    assert contract["execution_authorized"] is False
