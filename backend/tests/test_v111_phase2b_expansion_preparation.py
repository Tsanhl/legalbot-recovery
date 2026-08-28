from __future__ import annotations

import importlib.util
import json
import stat
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = PROJECT_ROOT / "scripts/build_v111_phase2b_expansion_preparation.py"


def _load_builder():
    spec = importlib.util.spec_from_file_location("phase2b_expansion_builder", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_expansion_scope_and_combined_leakage_are_fail_closed() -> None:
    builder = _load_builder()
    r3 = builder._load_module("phase2b_expansion_test_r3", builder.SOURCE_BUILDER)
    questions = builder._load_module("phase2b_expansion_test_questions", builder.QUESTION_MODULE)
    questions.validate_expansion_topics()
    scope = builder._source_scope_proposal(questions.EXPANSION_TOPICS)
    existing_visible, existing_unseen = builder._source_r3_questions()
    expansion_visible: list[dict[str, object]] = []
    expansion_unseen: list[dict[str, object]] = []
    for topic_id, topic in questions.EXPANSION_TOPICS.items():
        core, stress, unseen = builder._question_records(topic_id, topic, r3)
        builder._validate_questions(core, stress, unseen)
        expansion_visible += core + stress
        expansion_unseen += unseen

    assert scope["status"] == "PROPOSED_NOT_OWNER_APPROVED_NOT_ADMITTED"
    assert scope["source_candidate_count"] == 22
    assert {row["topic_id"] for row in scope["records"]} == {
        "administrative-law",
        "wills-and-estates",
    }
    assert all(
        row["url"].startswith(
            (
                "https://www.legislation.gov.uk/",
                "https://www.justice.gov.uk/",
                "https://caselaw.nationalarchives.gov.uk/",
            )
        )
        for row in scope["records"]
    )
    assert all(row["source_admitted"] is False for row in scope["records"])
    assert len(expansion_visible) == 40
    assert len(expansion_unseen) == 36
    audit = r3._leakage_audit(
        existing_visible + expansion_visible,
        existing_unseen + expansion_unseen,
    )
    assert audit["exact_normalized_prompt_overlap_count"] == 0
    assert audit["maximum_similarity"] < 0.55


def test_builder_creates_preparation_not_gold_or_phase2b(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    builder = _load_builder()
    output_parent = tmp_path / "phase2b"
    output_root = output_parent / builder.RUN_NAME
    monkeypatch.setattr(builder, "OUTPUT_PARENT", output_parent)
    monkeypatch.setattr(builder, "OUTPUT_ROOT", output_root)

    assert builder.build() == output_root
    package = json.loads((output_root / "PACKAGE-MANIFEST.json").read_text())
    registry = json.loads((output_root / "REGISTRY.json").read_text())
    scope = json.loads((output_root / "OFFICIAL-SOURCE-SCOPE-PROPOSAL.json").read_text())

    assert package["status"] == "EXPANSION_AND_PRE_GOLD_PREPARATION_READY_NOT_PHASE2B"
    assert package["expansion_topic_count"] == 2
    assert package["official_source_candidate_count"] == 22
    assert package["expansion_visible_question_count"] == 40
    assert package["expansion_unseen_custody_draft_count"] == 36
    assert package["gold_answer_work_item_count"] == 340
    assert package["proposition_work_item_count"] == 1678
    assert package["completed_gold_answer_count"] == 0
    assert package["evidence_span_bound_count"] == 0
    assert package["phase2a_running_task_read_or_consumed"] is False
    assert registry["future_combined_topic_count"] == 17
    assert registry["future_combined_visible_question_count"] == 340
    assert registry["future_combined_unseen_custody_draft_count"] == 306
    assert scope["source_admission_authorized"] is False

    forbidden_true = (
        "source_admission_authorized",
        "source_admitted",
        "source_scan_run",
        "index_built",
        "embedding_run",
        "retrieval_run",
        "answer_model_run",
        "model_training_run",
        "gold_certified",
        "development_authorized",
        "validation_authorized",
        "phase2b_authorized",
        "phase2b_run",
        "promotion_authorized",
        "active_pointer_written",
        "previous_pointer_written",
        "live_activation_authorized",
    )
    assert all(package[field] is False for field in forbidden_true)

    for topic_id in ("administrative-law", "wills-and-estates"):
        topic_root = output_root / "expansion-topics" / topic_id
        core = _jsonl(topic_root / "development/CORE-QUESTION-SET.jsonl")
        stress = _jsonl(topic_root / "development/STRESS-QUESTION-SET.jsonl")
        unseen_path = topic_root / "unseen-custody/PRIVATE-UNSEEN-QUESTION-SET.jsonl"
        unseen = _jsonl(unseen_path)
        assert len(core) == 18
        assert len(stress) == 2
        assert len(unseen) == 18
        assert stat.S_IMODE(unseen_path.stat().st_mode) == 0o600
        assert not list((topic_root / "unseen-custody").glob("*.md"))
        assert all(row["execution_bank_membership"] is False for row in core + stress + unseen)

    proposition_rows: list[dict[str, object]] = []
    answer_rows: list[dict[str, object]] = []
    for path in (output_root / "pre-gold-ledgers/topics").rglob(
        "PROPOSITION-EVIDENCE-WORK-LEDGER.jsonl"
    ):
        proposition_rows += _jsonl(path)
    for path in (output_root / "pre-gold-ledgers/topics").rglob("GOLD-ANSWER-WORK-ITEMS.jsonl"):
        answer_rows += _jsonl(path)
    assert len(proposition_rows) == 1678
    assert len(answer_rows) == 340
    assert all(row["proposition_text"] is None for row in proposition_rows)
    assert all(row["evidence_span_ids"] == [] for row in proposition_rows)
    assert all(row["gold_eligible"] is False for row in proposition_rows)
    assert all(row["gold_answer_text"] is None for row in answer_rows)
    assert all(row["gold_certified"] is False for row in answer_rows)

    joined = b"\n".join(path.read_bytes() for path in output_root.rglob("*") if path.is_file())
    assert b"/Users/" not in joined
    assert b"hltsang" not in joined.lower()
    assert b"Agnes" not in joined

    with pytest.raises(FileExistsError):
        builder.build()
