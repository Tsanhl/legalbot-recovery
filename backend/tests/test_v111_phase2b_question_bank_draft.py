from __future__ import annotations

import importlib.util
import json
from collections import Counter
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = PROJECT_ROOT / "scripts/build_v111_phase2b_question_bank_draft.py"


def _load_builder():
    spec = importlib.util.spec_from_file_location("phase2b_question_bank_builder", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_question_bank_has_independent_balanced_topic_sets() -> None:
    builder = _load_builder()

    assert len(builder.TOPICS) == 15
    assert sum(len(topic["questions"]) for topic in builder.TOPICS.values()) == 270
    for topic_id, topic in builder.TOPICS.items():
        assert len(topic["questions"]) == 18, topic_id
        assert Counter(item["question_type"] for item in topic["questions"]) == {
            "ESSAY": 6,
            "PROBLEM_BASED": 6,
            "GENERAL_ENQUIRY": 6,
        }
        for academic_type in ("ESSAY", "PROBLEM_BASED"):
            assert Counter(
                item["difficulty"]
                for item in topic["questions"]
                if item["question_type"] == academic_type
            ) == {"SCHOOL_COMPARABLE": 2, "HARDER": 2, "EVEN_HARDER": 2}
        assert Counter(
            item["difficulty"]
            for item in topic["questions"]
            if item["question_type"] == "GENERAL_ENQUIRY"
        ) == {"EVERYDAY": 4, "MULTI_ISSUE": 1, "BOUNDARY_OR_URGENT": 1}


def test_builder_publishes_create_only_nonauthorizing_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    builder = _load_builder()
    output_parent = tmp_path / "drafts"
    output_root = output_parent / builder.RUN_NAME
    monkeypatch.setattr(builder, "OUTPUT_PARENT", output_parent)
    monkeypatch.setattr(builder, "OUTPUT_ROOT", output_root)

    assert builder.build() == output_root
    package = json.loads((output_root / "PACKAGE-MANIFEST.json").read_text())
    registry = json.loads((output_root / "TOPIC-REGISTRY.json").read_text())

    assert package["status"] == "QUESTION_BANK_DRAFT_READY_NOT_PHASE2B"
    assert package["revision"] == 2
    assert package["topic_count"] == 15
    assert package["question_count"] == 270
    assert package["frozen_validation_question_count"] == 0
    assert package["source_admitted"] is False
    assert package["index_built"] is False
    assert package["embedding_run"] is False
    assert package["retrieval_run"] is False
    assert package["answer_model_run"] is False
    assert package["phase2b_run"] is False
    assert package["active_pointer_written"] is False
    assert package["live_activation_run"] is False
    assert registry["recommended_execution_wave_size"] == 2
    assert registry["frozen_validation_questions_deferred"] is True

    topic_dirs = sorted(path for path in (output_root / "topics").iterdir() if path.is_dir())
    assert len(topic_dirs) == 15
    assert all((path / "QUESTION-SET.jsonl").is_file() for path in topic_dirs)
    assert all((path / "QUESTION-SET.md").is_file() for path in topic_dirs)
    assert all((path / "TOPIC-MANIFEST.json").is_file() for path in topic_dirs)
    assert all((path / "FUTURE-RUN-CHECKLIST.md").is_file() for path in topic_dirs)

    joined = b"\n".join(path.read_bytes() for path in output_root.rglob("*") if path.is_file())
    assert b"/Users/" not in joined
    assert b"hltsang" not in joined.lower()

    with pytest.raises(FileExistsError):
        builder.build()
