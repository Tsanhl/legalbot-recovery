from __future__ import annotations

import importlib.util
import json
import stat
from collections import Counter
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = PROJECT_ROOT / "scripts/build_v111_phase2b_full_question_bank_draft.py"


def _load_builder():
    spec = importlib.util.spec_from_file_location("phase2b_full_bank_builder", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _assert_balanced_18(records: list[dict[str, object]]) -> None:
    assert len(records) == 18
    assert Counter(row["question_type"] for row in records) == {
        "ESSAY": 6,
        "PROBLEM_BASED": 6,
        "GENERAL_ENQUIRY": 6,
    }
    for kind in ("ESSAY", "PROBLEM_BASED"):
        assert Counter(
            row["difficulty"] for row in records if row["question_type"] == kind
        ) == {"SCHOOL_COMPARABLE": 2, "HARDER": 2, "EVEN_HARDER": 2}
    assert Counter(
        row["difficulty"]
        for row in records
        if row["question_type"] == "GENERAL_ENQUIRY"
    ) == {"EVERYDAY": 4, "MULTI_ISSUE": 1, "BOUNDARY_OR_URGENT": 1}


def test_full_bank_question_sources_and_leakage_boundary() -> None:
    builder = _load_builder()
    _, amendments, additions, _ = builder._load_patch()
    r2 = builder._load_python_module("phase2b_test_r2", builder.SOURCE_BUILDER)
    unseen = builder._load_python_module("phase2b_test_unseen", builder.UNSEEN_MODULE)
    core, stress, custody = builder._build_question_sets(
        r2, unseen, amendments, additions
    )

    assert len(core) == len(stress) == len(custody) == 15
    assert sum(map(len, core.values())) == 270
    assert sum(map(len, stress.values())) == 30
    assert sum(map(len, custody.values())) == 270
    for topic_id in core:
        _assert_balanced_18(core[topic_id])
        _assert_balanced_18(custody[topic_id])
        assert Counter(row["question_type"] for row in stress[topic_id]) == {
            "PROBLEM_BASED": 1,
            "GENERAL_ENQUIRY": 1,
        }

    patched = next(
        row
        for row in core["ai-and-data-protection"]
        if row["question_id"] == "ai-and-data-protection:e02"
    )
    assert "UK rules governing significant automated decisions" in patched["prompt"]
    assert patched["amendment_record_sha256"] is not None
    assert sum(
        row["amendment_record_sha256"] is not None
        for records in core.values()
        for row in records
    ) == 44

    visible = [row for records in core.values() for row in records] + [
        row for records in stress.values() for row in records
    ]
    hidden = [row for records in custody.values() for row in records]
    audit = builder._leakage_audit(visible, hidden)
    assert audit["status"] == "PASS_DRAFT_CUSTODY_SEPARATION"
    assert audit["exact_normalized_prompt_overlap_count"] == 0
    assert audit["maximum_similarity"] < 0.55


def test_builder_publishes_create_only_full_nonauthorizing_package(
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
    patch_report = json.loads((output_root / "PATCH-APPLICATION-REPORT.json").read_text())
    custody_manifest = json.loads((output_root / "UNSEEN-CUSTODY-MANIFEST.json").read_text())

    assert package["status"] == "FULL_QUESTION_BANK_AND_UNSEEN_CUSTODY_DRAFT_READY_NOT_PHASE2B"
    assert package["topic_count"] == 15
    assert package["development_core_question_count"] == 270
    assert package["development_stress_question_count"] == 30
    assert package["development_question_count"] == 300
    assert package["unseen_custody_draft_question_count"] == 270
    assert package["frozen_validation_question_count"] == 0
    assert package["total_question_record_count"] == 570
    assert registry["recommended_execution_wave_size"] == 2
    assert registry["maximum_execution_wave_size"] == 2
    assert patch_report["amendment_count"] == 44
    assert patch_report["stress_addition_count"] == 30
    assert custody_manifest["owner_exact_hash_freeze_required_before_development"] is True

    authorization_flags = (
        "source_admission_authorized",
        "answer_model_authorized",
        "model_training_authorized",
        "phase2b_authorized",
        "development_authorized",
        "validation_authorized",
        "promotion_authorized",
        "phase2c_authorized",
        "live_activation_authorized",
    )
    assert all(package[field] is False for field in authorization_flags)
    assert package["active_pointer_written"] is False
    assert package["previous_pointer_written"] is False

    for topic in registry["topics"]:
        topic_id = topic["topic_id"]
        development = output_root / "development/topics" / topic_id
        custody = output_root / "unseen-custody/topics" / topic_id
        core = _read_jsonl(development / "CORE-QUESTION-SET.jsonl")
        stress = _read_jsonl(development / "STRESS-QUESTION-SET.jsonl")
        hidden = _read_jsonl(custody / "PRIVATE-UNSEEN-QUESTION-SET.jsonl")
        _assert_balanced_18(core)
        _assert_balanced_18(hidden)
        assert len(stress) == 2
        assert not list(custody.glob("*.md"))
        assert stat.S_IMODE((custody / "PRIVATE-UNSEEN-QUESTION-SET.jsonl").stat().st_mode) == 0o600
        assert all(row["visible_to_development_remediation"] is False for row in hidden)
        assert all(row["unseen_freeze_status"] == "CUSTODY_DRAFT_NOT_OWNER_FROZEN" for row in hidden)

    joined = b"\n".join(
        path.read_bytes() for path in output_root.rglob("*") if path.is_file()
    )
    assert b"/Users/" not in joined
    assert b"hltsang" not in joined.lower()
    assert b"Agnes" not in joined

    with pytest.raises(FileExistsError):
        builder.build()
