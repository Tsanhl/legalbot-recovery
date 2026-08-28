from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.fernet import Fernet

from app.crypto import LocalCipher
from app.evaluation.live30 import RunProvenance
from app.evaluation.live_suite import LiveEvaluationBundle, load_live_evaluation_bundle
from app.evaluation.live_suite_coverage import run_suite_coverage
from app.evaluation.live_suite_store import LiveSuiteRunStore

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_ROOT = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"


class EmptyRetriever:
    async def retrieve(self, **_kwargs: Any) -> list[Any]:
        return []


def _store(tmp_path: Path) -> tuple[LiveSuiteRunStore, LiveEvaluationBundle]:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    store = LiveSuiteRunStore(tmp_path / "project", LocalCipher(Fernet(Fernet.generate_key())))
    return store, bundle


def test_live60_store_encrypts_all_questions_and_snapshots_exact_contract(
    tmp_path: Path,
) -> None:
    store, bundle = _store(tmp_path)
    manifest = store.create_run(
        run_id="live60-store-test",
        bundle=bundle,
        provenance=RunProvenance(git_sha="a" * 40, git_dirty=True),
        admitted_at=datetime(2026, 8, 15, 23, 30, tzinfo=UTC),
    )

    assert manifest.as_of_date == "2026-08-16"
    assert manifest.case_count == 60
    assert manifest.generation_case_count == 30
    run_root = store.runs_root / manifest.run_id
    assert (run_root / "suite-manifest.json").read_bytes() == (
        BUNDLE_ROOT / "manifest.json"
    ).read_bytes()
    assert (run_root / "generation-run-plan.json").read_bytes() == (
        BUNDLE_ROOT / "generation-run-plan.json"
    ).read_bytes()
    assert len(tuple((run_root / "cases").iterdir())) == 60

    new_case = bundle.registry.case("live60-q31")
    encrypted = run_root / "cases/live60-q31/question.enc"
    assert new_case.question.encode("utf-8") not in encrypted.read_bytes()
    as_of_date, loaded = store.load_encrypted_question(
        run_id=manifest.run_id, case_id=new_case.case_id
    )
    assert as_of_date.isoformat() == "2026-08-16"
    assert loaded == new_case
    logs = store.events_log.read_text() + store.case_index_log.read_text()
    assert new_case.question not in logs
    assert "/Users/" not in logs


def test_live60_store_is_create_only_and_case_plan_scoped(tmp_path: Path) -> None:
    store, bundle = _store(tmp_path)
    provenance = RunProvenance(git_sha="b" * 40, git_dirty=False)
    admitted_at = datetime(2026, 8, 15, 8, 0, tzinfo=UTC)
    store.create_run(
        run_id="live60-create-only",
        bundle=bundle,
        provenance=provenance,
        admitted_at=admitted_at,
    )
    with pytest.raises(FileExistsError):
        store.create_run(
            run_id="live60-create-only",
            bundle=bundle,
            provenance=provenance,
            admitted_at=admitted_at,
        )
    with pytest.raises(ValueError, match="not part"):
        store.load_encrypted_question(run_id="live60-create-only", case_id="live60-q99")


def test_live60_snapshot_tampering_fails_closed(tmp_path: Path) -> None:
    store, bundle = _store(tmp_path)
    store.create_run(
        run_id="live60-tamper",
        bundle=bundle,
        provenance=RunProvenance(git_sha="c" * 40, git_dirty=False),
        admitted_at=datetime(2026, 8, 15, 8, 0, tzinfo=UTC),
    )
    path = store.runs_root / "live60-tamper/generation-run-plan.json"
    value = json.loads(path.read_text())
    value["generation_total_word_target"] = 113_999
    path.chmod(0o600)
    path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ValueError):
        store.load_run_manifest("live60-tamper")


@pytest.mark.asyncio
async def test_unannotated_stage_a_covers_all_60_without_reporting_scores_or_generation(
    tmp_path: Path,
) -> None:
    store, bundle = _store(tmp_path)
    store.create_run(
        run_id="live60-coverage-unannotated",
        bundle=bundle,
        provenance=RunProvenance(
            git_sha="d" * 40,
            git_dirty=False,
            index_build_id="candidate-live60-test",
        ),
        admitted_at=datetime(2026, 8, 15, 8, 0, tzinfo=UTC),
    )
    summary = await run_suite_coverage(
        store=store,
        retriever=EmptyRetriever(),
        run_id="live60-coverage-unannotated",
        bundle=bundle,
        qualification=None,
    )

    assert summary["case_count"] == 60
    assert len(cast(list[str], summary["coverage_only_not_selected_case_ids"])) == 30
    assert summary["selected_generation_eligible_case_ids"] == []
    assert summary["ranking_metric_state"] == ("not_evaluated_without_expert_qualification")
    assert summary["recall_at_5"] is None
    assert summary["recall_at_10"] is None
    assert summary["mrr"] is None
    assert summary["stage_a_evaluated"] is False
    assert summary["stage_a_passed"] is False
    assert summary["generation_started"] is False
