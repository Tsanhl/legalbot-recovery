from __future__ import annotations

import json
import stat
from collections import Counter
from datetime import date
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError

from app.crypto import LocalCipher
from app.evaluation.live30 import (
    EXPECTED_CASE_IDS,
    EXPECTED_TOTAL_WORD_TARGET,
    EXPECTED_WORD_TARGET_COUNTS,
    FULL_ENQUIRY_CASE_IDS,
    SECTIONED_CASE_IDS,
    STRATIFIED_SAMPLE_IDS,
    STRUCTURAL_STANDARD_IDS,
    E2ERunEvent,
    Live30RunStore,
    RunEventType,
    RunProvenance,
    RunStage,
    RunStatus,
    SensitiveArtifactKind,
    case_record_sha256,
    load_live30_suite,
    question_sha256,
    safe_json_lines,
    write_suite_manifest,
)


def _word_targets() -> list[int]:
    return [
        *([1_000] * 5),
        *([2_000] * 5),
        *([3_000] * 5),
        *([4_000] * 5),
        *([5_000] * 5),
        6_000,
        7_000,
        8_000,
        9_000,
        10_000,
    ]


def _case(ordinal: int, word_target: int) -> dict[str, object]:
    question = (
        f"Synthetic registry-contract fixture question {ordinal}; "
        "this text is not part of the owner-supplied evaluation suite."
    )
    value: dict[str, object] = {
        "schema": "legalbot.live-evaluation-case.v1",
        "suite_id": "live-evaluation-30-v1",
        "suite_version": "1.0.0",
        "split": "development_live",
        "purpose": "evaluation_only",
        "eligible_for_training": False,
        "training_export_allowed": False,
        "immutable": True,
        "case_id": f"live30-q{ordinal:02d}",
        "ordinal": ordinal,
        "question": question,
        "question_sha256": question_sha256(question),
        "task_type": "problem" if ordinal % 2 else "essay",
        "subject": f"fixture-subject-{ordinal:02d}",
        "jurisdiction": "England and Wales",
        "as_of_policy": "run_date",
        "word_target": word_target,
        "expected_research_route": (
            "sectioned" if f"live30-q{ordinal:02d}" in SECTIONED_CASE_IDS else "full_enquiry"
        ),
        "expected_drafting_route": "sectioned",
        "expected_behaviour": "answer",
        "structural_standard_ids": list(STRUCTURAL_STANDARD_IDS),
        "must_cover_issues": [f"fixture issue {ordinal}a", f"fixture issue {ordinal}b"],
        "acceptable_source_ids": [],
        "exact_gold_spans": [],
        "known_contrary_authority_ids": [],
        "forbidden_lanes": [],
        "coverage_status": "unqualified",
    }
    value["record_sha256"] = case_record_sha256(value)
    return value


def _registry(tmp_path: Path) -> Path:
    path = tmp_path / "cases.jsonl"
    cases = [_case(index, target) for index, target in enumerate(_word_targets(), start=1)]
    path.write_text(
        "".join(json.dumps(case, ensure_ascii=False, sort_keys=True) + "\n" for case in cases),
        encoding="utf-8",
    )
    return path


def test_complete_registry_contract_is_30_cases_115000_words_and_stratified(
    tmp_path: Path,
) -> None:
    suite = load_live30_suite(_registry(tmp_path))

    assert suite.case_count == 30
    assert tuple(case.case_id for case in suite.cases) == EXPECTED_CASE_IDS
    assert suite.total_word_target == EXPECTED_TOTAL_WORD_TARGET == 115_000
    assert Counter(case.word_target for case in suite.cases) == Counter(EXPECTED_WORD_TARGET_COUNTS)
    assert STRATIFIED_SAMPLE_IDS == (
        "live30-q01",
        "live30-q03",
        "live30-q07",
        "live30-q09",
        "live30-q13",
        "live30-q17",
        "live30-q25",
        "live30-q27",
        "live30-q30",
    )
    assert [case.case_id for case in suite.cases if case.case_id in STRATIFIED_SAMPLE_IDS] == [
        case_id for case_id in EXPECTED_CASE_IDS if case_id in STRATIFIED_SAMPLE_IDS
    ]
    assert suite.manifest()["eligible_for_training"] is False
    assert suite.manifest()["training_export_allowed"] is False


def test_question_or_metadata_tampering_breaks_immutable_record_hash(tmp_path: Path) -> None:
    path = _registry(tmp_path)
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    rows[0]["question"] += " tampered"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))

    with pytest.raises(ValueError, match="invalid live-30 record at line 1"):
        load_live30_suite(path)


def test_full_enquiry_and_sectioned_routes_are_enforced(tmp_path: Path) -> None:
    path = _registry(tmp_path)
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    rows[10]["expected_research_route"] = "sectioned"
    rows[10]["record_sha256"] = case_record_sha256(rows[10])
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))

    with pytest.raises(ValueError, match="invalid live-30 record at line 11"):
        load_live30_suite(path)


def test_frozen_per_case_route_matrix_matches_owner_plan() -> None:
    assert {
        *(f"live30-q{number:02d}" for number in range(1, 11)),
        "live30-q12",
        "live30-q14",
        "live30-q17",
        "live30-q19",
        "live30-q22",
        "live30-q24",
    } == SECTIONED_CASE_IDS
    assert {
        "live30-q11",
        "live30-q13",
        "live30-q15",
        "live30-q16",
        "live30-q18",
        "live30-q20",
        "live30-q21",
        "live30-q23",
        "live30-q25",
        "live30-q26",
        "live30-q27",
        "live30-q28",
        "live30-q29",
        "live30-q30",
    } == FULL_ENQUIRY_CASE_IDS


def test_run_registration_and_artifacts_encrypt_all_sensitive_text(tmp_path: Path) -> None:
    suite = load_live30_suite(_registry(tmp_path))
    cipher = LocalCipher(Fernet(Fernet.generate_key()))
    project_root = tmp_path / "project"
    store = Live30RunStore(project_root, cipher)
    run_id = "e2e-live30-test"
    manifest = store.create_run(
        run_id=run_id,
        suite=suite,
        provenance=RunProvenance(git_sha="a" * 40, git_dirty=True),
        as_of_date=date(2026, 8, 14),
    )

    assert manifest.case_count == 30
    assert manifest.total_word_target == 115_000
    first = suite.cases[0]
    encrypted_question = (
        project_root
        / "data"
        / "evaluations"
        / "e2e"
        / "runs"
        / run_id
        / "cases"
        / first.case_id
        / "question.enc"
    )
    assert first.question.encode() not in encrypted_question.read_bytes()
    as_of_date, registered = store.load_encrypted_question(run_id=run_id, case_id=first.case_id)
    assert as_of_date.isoformat() == "2026-08-14"
    assert registered == first

    answer = "PRIVATE GENERATED ANSWER SENTINEL"
    artifact_path = store.store_sensitive_artifact(
        run_id=run_id,
        case_id=first.case_id,
        kind=SensitiveArtifactKind.ANSWER,
        artifact_id="answer-v1",
        content=answer,
    )
    assert answer.encode() not in artifact_path.read_bytes()
    assert (
        store.load_sensitive_artifact(
            run_id=run_id,
            case_id=first.case_id,
            kind=SensitiveArtifactKind.ANSWER,
            artifact_id="answer-v1",
        )
        == answer
    )
    assert stat.S_IMODE(artifact_path.stat().st_mode) == 0o600

    normal_logs = store.events_log.read_text() + store.case_index_log.read_text()
    assert first.question not in normal_logs
    assert answer not in normal_logs
    assert "must_cover_issues" not in normal_logs
    assert "/Users/" not in normal_logs
    assert len(safe_json_lines(store.events_log)) == 32
    assert len(safe_json_lines(store.case_index_log)) == 31


def test_safe_event_schema_rejects_arbitrary_or_sensitive_fields() -> None:
    value = {
        "event_id": "a" * 32,
        "timestamp": "2026-08-14T00:00:00Z",
        "run_id": "e2e-live30-test",
        "event_type": RunEventType.CASE_STARTED,
        "stage": RunStage.RETRIEVAL,
        "status": RunStatus.RUNNING,
        "raw_question": "must never enter a normal log",
    }
    with pytest.raises(ValidationError):
        E2ERunEvent.model_validate(value)


def test_manifest_is_create_only_and_contains_no_question_text(tmp_path: Path) -> None:
    suite = load_live30_suite(_registry(tmp_path))
    manifest_path = tmp_path / "manifest.json"
    write_suite_manifest(manifest_path, suite)
    manifest_text = manifest_path.read_text()
    assert "Synthetic registry-contract fixture question" not in manifest_text
    assert json.loads(manifest_text)["case_count"] == 30
    with pytest.raises(FileExistsError):
        write_suite_manifest(manifest_path, suite)


def test_all_declared_json_schemas_are_parseable() -> None:
    schema_root = (
        Path(__file__).resolve().parents[2]
        / "benchmarks"
        / "evaluation"
        / "live-evaluation-30-v1"
        / "schemas"
    )
    names = {
        "case.schema.json",
        "suite-manifest.schema.json",
        "run-manifest.schema.json",
        "run-event.schema.json",
        "case-index.schema.json",
    }
    assert {path.name for path in schema_root.glob("*.json")} == names
    assert all(json.loads((schema_root / name).read_text())["$schema"] for name in names)
