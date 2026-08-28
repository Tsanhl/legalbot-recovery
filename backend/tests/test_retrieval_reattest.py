from __future__ import annotations

import hashlib
import json
import sqlite3
import stat
from collections.abc import Iterator
from pathlib import Path

import pytest

from app.config import Settings
from app.db import Database
from app.retrieval.retrieval_reattest import (
    CandidateRetrievalIdentity,
    _history_row,
    reattest_retrieval_v1,
    verify_selected_retrieval_attestation,
)
from app.retrieval.scorer_closure import ScorerClosureReference

BUILD_ID = "sealed-candidate"
OLD_SCORER = "0" * 64
NEW_SCORER = "1" * 64
INTEGRATION_SHA = "2" * 40
INTEGRATION_TREE = "d" * 40
CLOSURE_AGGREGATE = "e" * 64
FROZEN_ROWS = tuple(
    {
        "id": f"frozen-{number:02d}",
        "split": "development" if number <= 16 else "promotion",
        "match_mode": "source_and_locator",
        "primary_must_hit": True,
        "expected_source_id": f"source-{number:02d}",
        "expected_source_version_id": f"source-version-{number:02d}",
        "legal_locator": f"section {number}",
        "proposition_span_sha256": None,
        "gold_spans": [{"span_sha256": f"{number:064x}"}],
        "forbidden_lanes": ["private_teaching", "assessment_guidance"],
    }
    for number in range(1, 25)
)


def _write_json(path: Path, value: object) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _test_aggregate(results, *, project_root=None):
    del project_root
    return {
        "case_ids": [value["id"] for value in results],
        "go": True,
        "gates": {
            "mrr": True,
            "positive_recall_at_10": True,
            "primary_must_hit_recall_at_5": True,
            "private_path_hits_zero": True,
            "teaching_assessment_hits_zero": True,
            "wrong_version_zero": True,
        },
    }


def _quality_aggregate(results, *, project_root=None):
    del project_root
    primary = [value for value in results if value["primary_must_hit"] is True]
    gates = {
        "mrr": True,
        "positive_recall_at_10": all(value["hit@10"] is True for value in results),
        "primary_must_hit_recall_at_5": all(value["hit@5"] is True for value in primary),
        "private_path_hits_zero": True,
        "teaching_assessment_hits_zero": True,
        "wrong_version_zero": True,
    }
    return {
        "case_ids": [value["id"] for value in results],
        "go": all(gates.values()),
        "gates": gates,
    }


def _report(scorer: str) -> dict[str, object]:
    per_query = [
        {
            "id": row["id"],
            "split": row["split"],
            "match_mode": row["match_mode"],
            "polarity": "positive",
            "expected_source_id": row["expected_source_id"],
            "frozen_expected_source_id": row["expected_source_id"],
            "expected_source_version_id": row["expected_source_version_id"],
            "frozen_expected_source_version_id": row["expected_source_version_id"],
            "legal_locator": row["legal_locator"],
            "proposition_span_sha256": None,
            "gold_span_sha256s": [row["gold_spans"][0]["span_sha256"]],
            "gold_span_count": 1,
            "exact_span_hits_at_3": [row["gold_spans"][0]["span_sha256"]],
            "exact_span_hits_at_5": [row["gold_spans"][0]["span_sha256"]],
            "exact_span_hits_at_10": [row["gold_spans"][0]["span_sha256"]],
            "exact_span_recall_at_3": 1.0,
            "exact_span_recall_at_5": 1.0,
            "exact_span_recall_at_10": 1.0,
            "hit@3": True,
            "hit@5": True,
            "hit@10": True,
            "gold_rank": 1,
            "reciprocal_rank": 1.0,
            "primary_must_hit": True,
            "identity_only_allowed": False,
            "identity_only_ranks": [],
            "wrong_version": False,
            "wrong_version_ranks": [],
            "forbidden_lane": False,
            "forbidden_lane_ranks": [],
            "teaching_assessment_hits": 0,
            "private_path_hits": 0,
            "current_outranks_as_enacted": True,
            "top_chunk_ids": [f"chunk-{number:02d}"],
            "top_source_identities": [row["expected_source_id"]],
            "top_locators": [row["legal_locator"]],
            "top_lanes": ["primary_authority"],
            "top_currentness": ["current"],
            "top_hit_diagnostics": [
                {
                    "chunk_id": f"chunk-{number:02d}",
                    "fused_score": 1.0,
                    "lexical_rank": 1,
                    "vector_rank": 1,
                    "reranker_score": 1.0,
                }
            ],
            "hit_count": 1,
            "timings_ms": {"total": 1.0},
        }
        for number, row in enumerate(FROZEN_ROWS, start=1)
    ]
    aggregate = _test_aggregate(per_query)
    split_aggregates = {
        split: _test_aggregate([item for item in per_query if item["split"] == split])
        for split in ("development", "promotion")
    }
    return {
        "schema": "legalbot.offline-retrieval.v1.1",
        "created_at": "2026-08-20T00:00:00+00:00",
        "build_id": BUILD_ID,
        "splits": ["development", "promotion"],
        "jsonl_sha256": "b" * 64,
        "retrieval_policy_sha256": "a" * 64,
        "scorer_version": "legalbot.source-locator-retrieval.v1.1.1",
        "scorer_implementation_sha256": scorer,
        "answer_model_invoked": False,
        "active_json_written": False,
        "candidate_gold_binding": {
            "status": "bound",
            "row_count": 24,
            "issues": [],
            "bindings": [{"case_id": row["id"], "status": "bound"} for row in FROZEN_ROWS],
        },
        "per_query": per_query,
        "aggregates": aggregate,
        "split_aggregates": split_aggregates,
        "go": True,
    }


def _identity() -> CandidateRetrievalIdentity:
    return CandidateRetrievalIdentity(
        build_id=BUILD_ID,
        build_seal_sha256="3" * 64,
        source_manifest_file_sha256="4" * 64,
        source_manifest_sha256="5" * 64,
        candidate_manifest_hash="6" * 64,
        document_count=85,
        chunk_count=149_855,
        vector_count=149_855,
        embedding_model="Qwen/Qwen3-Embedding-0.6B",
        embedding_model_version="embedding-revision",
        reranker_model="Qwen/Qwen3-Reranker-0.6B",
        rerank_version="reranker-revision",
        quality_policy_sha256="7" * 64,
        assessment_bundle_sha256="8" * 64,
        retrieval_policy_sha256="a" * 64,
        benchmark_sha256="b" * 64,
        freeze_manifest_sha256="c" * 64,
        scorer_version="legalbot.source-locator-retrieval.v1.1.1",
        scorer_implementation_sha256=NEW_SCORER,
    )


@pytest.fixture
def reattest_catalog(
    tmp_path: Path,
) -> Iterator[tuple[Settings, Database, CandidateRetrievalIdentity, bytes]]:
    settings = Settings(project_root=tmp_path)
    settings.ensure_runtime_dirs()
    database = Database(settings.database_path)
    database.initialize()
    identity = _identity()
    legacy_path = settings.evaluation_dir / "retrieval" / BUILD_ID / "v1.1-attestation.json"
    legacy_payload = {
        "schema": "legalbot.retrieval-attestation.v1.1",
        "created_at": "2026-08-19T00:00:00+00:00",
        "build_id": BUILD_ID,
        "build_seal_sha256": identity.build_seal_sha256,
        "source_manifest_sha256": identity.source_manifest_file_sha256,
        "quality_policy_sha256": identity.quality_policy_sha256,
        "assessment_bundle_sha256": identity.assessment_bundle_sha256,
        "retrieval_policy_sha256": identity.retrieval_policy_sha256,
        "benchmark_sha256": identity.benchmark_sha256,
        "scorer_version": identity.scorer_version,
        "scorer_implementation_sha256": OLD_SCORER,
        "passed": True,
        "promotion_eligible": True,
        "report": _report(OLD_SCORER),
    }
    legacy_sha = _write_json(legacy_path, legacy_payload)
    relative = str(legacy_path.relative_to(settings.project_root))
    summary = {
        "schema": "legalbot.retrieval-attestation.v1.1",
        "passed": True,
        "promotion_eligible": True,
        "attestation_path": relative,
        "attestation_sha256": legacy_sha,
        "benchmark_sha256": identity.benchmark_sha256,
        "retrieval_policy_sha256": identity.retrieval_policy_sha256,
        "assessment_bundle_sha256": identity.assessment_bundle_sha256,
        "scorer_version": identity.scorer_version,
        "scorer_implementation_sha256": OLD_SCORER,
    }
    database.execute(
        """INSERT INTO index_builds(
             id,status,path,document_count,chunk_count,vector_count,
             embedding_model,reranker_model,manifest_sha256,created_at,
             stage,candidate_manifest_hash,benchmark_result_json,
             embedding_model_version,rerank_version,policy_sha256,
             assessment_bundle_sha256
           ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            BUILD_ID,
            "candidate",
            f"data/indexes/builds/{BUILD_ID}",
            identity.document_count,
            identity.chunk_count,
            identity.vector_count,
            identity.embedding_model,
            identity.reranker_model,
            identity.build_seal_sha256,
            "2026-08-19T00:00:00+00:00",
            "candidate",
            identity.candidate_manifest_hash,
            json.dumps(summary, sort_keys=True),
            identity.embedding_model_version,
            identity.rerank_version,
            identity.quality_policy_sha256,
            identity.assessment_bundle_sha256,
        ),
    )
    yield settings, database, identity, legacy_path.read_bytes()
    database.close()


def _patch_identity(monkeypatch: pytest.MonkeyPatch, identity: CandidateRetrievalIdentity) -> None:
    monkeypatch.setattr(
        "app.retrieval.retrieval_reattest._clean_integration_sha",
        lambda _root: INTEGRATION_SHA,
    )
    monkeypatch.setattr(
        "app.retrieval.retrieval_reattest._candidate_identity",
        lambda _settings, _row, **_kwargs: identity,
    )
    monkeypatch.setattr(
        "app.retrieval.retrieval_reattest._frozen_benchmark_rows",
        lambda _settings, _identity: FROZEN_ROWS,
    )
    monkeypatch.setattr(
        "app.retrieval.retrieval_reattest.aggregate_split",
        _test_aggregate,
    )
    monkeypatch.setattr(
        "app.retrieval.retrieval_reattest.load_scorer_closure_reference",
        lambda **kwargs: ScorerClosureReference(
            manifest_path=str(
                Path(kwargs["manifest_path"]).relative_to(Path(kwargs["project_root"]))
            ),
            manifest_file_sha256="f" * 64,
            manifest_sha256="a" * 64,
            aggregate_sha256=CLOSURE_AGGREGATE,
            member_count=42,
            integration_commit=INTEGRATION_SHA,
            integration_tree=INTEGRATION_TREE,
        ),
    )


def _reattest(settings: Settings, database: Database, **kwargs):
    closure = settings.evaluation_dir / "retrieval" / BUILD_ID / "scorer-closure.json"
    return reattest_retrieval_v1(
        settings,
        database,
        scorer_closure_manifest_path=closure,
        **kwargs,
    )


def _attempt_results(settings: Settings) -> list[Path]:
    root = settings.evaluation_dir / "retrieval" / BUILD_ID
    return sorted(root.glob("v1.1-reattest-attempt-*-result.json"))


def _attempt_starts(settings: Settings) -> list[Path]:
    root = settings.evaluation_dir / "retrieval" / BUILD_ID
    return sorted(root.glob("v1.1-reattest-attempt-*-start.json"))


def _attestation_artifacts(settings: Settings) -> list[Path]:
    root = settings.evaluation_dir / "retrieval" / BUILD_ID
    return sorted(
        path for path in root.glob("v1.1-reattest-*.json") if "-attempt-" not in path.name
    )


def _assert_attempt_sealed(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    stored = payload.pop("seal_sha256")
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    assert hashlib.sha256(canonical.encode("utf-8")).hexdigest() == stored
    payload["seal_sha256"] = stored
    return payload


def test_reattest_preserves_legacy_and_candidate_and_selects_current_proof(
    reattest_catalog, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, database, identity, legacy_bytes = reattest_catalog
    _patch_identity(monkeypatch, identity)
    row_before = dict(database.fetchone("SELECT * FROM index_builds WHERE id=?", (BUILD_ID,)))
    calls: list[tuple[str, ...]] = []

    def runner(_settings, *, build_id: str, splits: tuple[str, ...]):
        assert build_id == BUILD_ID
        calls.append(splits)
        return _report(NEW_SCORER)

    result = _reattest(settings, database, build_id=BUILD_ID, benchmark_runner=runner)
    assert result["benchmark_ran"] is True
    assert calls == [("development", "promotion")]
    assert dict(database.fetchone("SELECT * FROM index_builds WHERE id=?", (BUILD_ID,))) == (
        row_before
    )
    legacy_path = settings.evaluation_dir / "retrieval" / BUILD_ID / "v1.1-attestation.json"
    assert legacy_path.read_bytes() == legacy_bytes
    assert not (settings.index_dir / "ACTIVE.json").exists()
    assert not (settings.index_dir / "PREVIOUS.json").exists()
    selected = _history_row(database, BUILD_ID)
    assert selected is not None
    assert selected["prior_attestation_sha256"] == hashlib.sha256(legacy_bytes).hexdigest()
    assert selected["scorer_implementation_sha256"] == NEW_SCORER
    assert selected["integration_sha"] == INTEGRATION_SHA
    assert result["scorer_closure_aggregate_sha256"] == CLOSURE_AGGREGATE
    selected_payload = json.loads(
        (settings.project_root / result["selected_attestation_path"]).read_bytes()
    )
    assert selected_payload["schema"] == "legalbot.retrieval-reattestation.v2"
    assert selected_payload["scorer_closure"]["aggregate_sha256"] == CLOSURE_AGGREGATE
    assert len(_attempt_starts(settings)) == 1
    assert len(_attempt_results(settings)) == 1
    for path in (*_attempt_starts(settings), *_attempt_results(settings)):
        assert stat.S_IMODE(path.stat().st_mode) == 0o400
        assert path.stat().st_nlink == 1
    assert not list((settings.evaluation_dir / "retrieval" / BUILD_ID).glob(".*attempt*.tmp"))
    attempt = _assert_attempt_sealed(_attempt_results(settings)[0])
    assert attempt["schema"] == "legalbot.retrieval-reattestation-attempt.v1"
    assert attempt["authorizing"] is False
    assert attempt["execution"]["completion_state"] == "completed"
    assert attempt["execution"]["completed_query_count"] == 24
    assert attempt["quality"] == {
        "exception": None,
        "failed_gates": [],
        "status": "passed",
    }
    assert attempt["attestation_preconditions"] == {
        "exception": None,
        "status": "passed",
    }
    assert attempt["report"] == _report(NEW_SCORER)
    assert selected_payload["diagnostic_attempt"]["path"] == result["diagnostic_attempt_path"]
    assert selected_payload["diagnostic_attempt"]["sha256"] == result["diagnostic_attempt_sha256"]
    proof = verify_selected_retrieval_attestation(settings, database, row_before, identity)
    assert proof.sha256 == result["selected_attestation_sha256"]
    assert proof.scorer_closure_aggregate_sha256 == CLOSURE_AGGREGATE

    second = _reattest(
        settings,
        database,
        build_id=BUILD_ID,
        benchmark_runner=lambda *_args, **_kwargs: pytest.fail("benchmark reran"),
    )
    assert second["benchmark_ran"] is False
    assert second["recovered"] is True

    database.execute("UPDATE index_builds SET status='active' WHERE id=?", (BUILD_ID,))
    active_row = dict(database.fetchone("SELECT * FROM index_builds WHERE id=?", (BUILD_ID,)))
    assert (
        verify_selected_retrieval_attestation(settings, database, active_row, identity).sha256
        == proof.sha256
    )

    with pytest.raises(sqlite3.DatabaseError, match="immutable"):
        database.execute(
            "UPDATE retrieval_attestation_history SET integration_sha=? WHERE id=?",
            ("f" * 40, proof.sha256),
        )


def test_reattest_never_recovers_or_selects_an_orphan_file(
    reattest_catalog, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, database, identity, _legacy_bytes = reattest_catalog
    _patch_identity(monkeypatch, identity)
    import app.retrieval.retrieval_reattest as module

    real_append = module._append_and_select
    calls = 0

    def runner(_settings, *, build_id: str, splits: tuple[str, ...]):
        nonlocal calls
        calls += 1
        assert build_id == BUILD_ID
        assert splits == ("development", "promotion")
        return _report(NEW_SCORER)

    monkeypatch.setattr(
        module,
        "_append_and_select",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("simulated crash")),
    )
    with pytest.raises(RuntimeError, match="simulated crash"):
        _reattest(settings, database, build_id=BUILD_ID, benchmark_runner=runner)
    assert _history_row(database, BUILD_ID) is None
    artifacts = _attestation_artifacts(settings)
    assert len(artifacts) == 1
    orphan = artifacts[0]
    assert len(_attempt_starts(settings)) == 1
    assert len(_attempt_results(settings)) == 1

    monkeypatch.setattr(module, "_append_and_select", real_append)
    result = _reattest(settings, database, build_id=BUILD_ID, benchmark_runner=runner)
    assert result["recovered"] is False
    assert result["benchmark_ran"] is True
    assert calls == 2
    artifacts = _attestation_artifacts(settings)
    assert len(artifacts) == 2
    assert orphan in artifacts
    assert len(_attempt_starts(settings)) == 2
    assert len(_attempt_results(settings)) == 2
    selected = _history_row(database, BUILD_ID)
    assert selected is not None
    assert settings.project_root / selected["attestation_path"] != orphan


def test_reattest_fails_before_writing_when_candidate_state_changes(
    reattest_catalog, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, database, identity, _legacy_bytes = reattest_catalog
    _patch_identity(monkeypatch, identity)

    def runner(_settings, *, build_id: str, splits: tuple[str, ...]):
        assert build_id == BUILD_ID
        assert splits == ("development", "promotion")
        database.execute("UPDATE index_builds SET stage='changed' WHERE id=?", (BUILD_ID,))
        return _report(NEW_SCORER)

    with pytest.raises(RuntimeError, match="catalogue state changed"):
        _reattest(settings, database, build_id=BUILD_ID, benchmark_runner=runner)
    assert _history_row(database, BUILD_ID) is None
    assert _attestation_artifacts(settings) == []
    attempt = _assert_attempt_sealed(_attempt_results(settings)[0])
    assert attempt["quality"]["status"] == "passed"
    assert attempt["attestation_preconditions"]["status"] == "failed"


def test_reattest_rejects_claimed_gates_without_frozen_per_query_results(
    reattest_catalog, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, database, identity, _legacy_bytes = reattest_catalog
    _patch_identity(monkeypatch, identity)
    forged = _report(NEW_SCORER)
    forged.pop("per_query")

    with pytest.raises(RuntimeError, match="report structure"):
        _reattest(
            settings,
            database,
            build_id=BUILD_ID,
            benchmark_runner=lambda *_args, **_kwargs: forged,
        )
    assert _history_row(database, BUILD_ID) is None
    assert _attestation_artifacts(settings) == []
    attempt = _assert_attempt_sealed(_attempt_results(settings)[0])
    assert attempt["execution"]["completion_state"] == "completed"
    assert attempt["quality"]["status"] == "failed"
    assert attempt["report"] == forged


def test_failed_quality_report_is_complete_sealed_and_never_selected(
    reattest_catalog, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, database, identity, _legacy_bytes = reattest_catalog
    _patch_identity(monkeypatch, identity)
    failed = _report(NEW_SCORER)
    per_query = failed["per_query"]
    assert isinstance(per_query, list)
    first = per_query[0]
    assert isinstance(first, dict)
    first.update(
        {
            "exact_span_hits_at_3": [],
            "exact_span_hits_at_5": [],
            "exact_span_recall_at_3": 0.0,
            "exact_span_recall_at_5": 0.0,
            "hit@3": False,
            "hit@5": False,
            "gold_rank": 6,
            "reciprocal_rank": 1.0 / 6,
            "top_chunk_ids": ["miss-1", "miss-2", "miss-3", "miss-4", "miss-5", "chunk-01"],
            "top_source_identities": ["other"] * 5 + [first["expected_source_id"]],
            "top_locators": ["section 99"] * 5 + [first["legal_locator"]],
            "top_lanes": ["primary_authority"] * 6,
            "top_currentness": ["current"] * 6,
            "top_hit_diagnostics": [
                {
                    "chunk_id": chunk_id,
                    "fused_score": 1.0 / rank,
                    "lexical_rank": rank,
                    "vector_rank": rank,
                    "reranker_score": 1.0 / rank,
                }
                for rank, chunk_id in enumerate(
                    ["miss-1", "miss-2", "miss-3", "miss-4", "miss-5", "chunk-01"],
                    start=1,
                )
            ],
            "hit_count": 6,
        }
    )
    failed["aggregates"] = _quality_aggregate(per_query)
    failed["split_aggregates"] = {
        split: _quality_aggregate([item for item in per_query if item["split"] == split])
        for split in ("development", "promotion")
    }
    failed["go"] = False
    monkeypatch.setattr(
        "app.retrieval.retrieval_reattest.aggregate_split",
        _quality_aggregate,
    )

    with pytest.raises(RuntimeError, match="retrieval gates did not pass"):
        _reattest(
            settings,
            database,
            build_id=BUILD_ID,
            benchmark_runner=lambda *_args, **_kwargs: failed,
        )

    assert _history_row(database, BUILD_ID) is None
    assert _attestation_artifacts(settings) == []
    assert len(_attempt_starts(settings)) == 1
    attempt = _assert_attempt_sealed(_attempt_results(settings)[0])
    assert attempt["execution"]["completion_state"] == "completed"
    assert attempt["execution"]["completed_query_count"] == 24
    assert attempt["quality"]["status"] == "failed"
    assert attempt["quality"]["failed_gates"] == [
        "aggregate.primary_must_hit_recall_at_5",
        "split.development.primary_must_hit_recall_at_5",
    ]
    assert attempt["report"] == failed
    assert attempt["passing_attestation"]["eligible"] is False


def test_incomplete_runner_writes_start_and_result_without_attestation(
    reattest_catalog, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, database, identity, _legacy_bytes = reattest_catalog
    _patch_identity(monkeypatch, identity)

    def interrupted_runner(*_args, **_kwargs):
        raise RuntimeError("simulated retrieval interruption")

    with pytest.raises(RuntimeError, match="simulated retrieval interruption"):
        _reattest(
            settings,
            database,
            build_id=BUILD_ID,
            benchmark_runner=interrupted_runner,
        )

    assert _history_row(database, BUILD_ID) is None
    assert _attestation_artifacts(settings) == []
    assert len(_attempt_starts(settings)) == 1
    attempt = _assert_attempt_sealed(_attempt_results(settings)[0])
    assert attempt["execution"]["completion_state"] == "incomplete"
    assert attempt["execution"]["completed_query_count"] == 0
    assert attempt["quality"]["status"] == "not_evaluated"
    assert attempt["attestation_preconditions"]["exception"] == {
        "message": "simulated retrieval interruption",
        "message_sha256": hashlib.sha256(b"simulated retrieval interruption").hexdigest(),
        "stage": "benchmark_runner",
        "type": "RuntimeError",
    }
    assert attempt["report"] is None
    assert attempt["passing_attestation"]["eligible"] is False


def test_reattest_rechecks_clean_head_after_benchmark(
    reattest_catalog, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, database, identity, _legacy_bytes = reattest_catalog
    _patch_identity(monkeypatch, identity)
    revisions = iter((INTEGRATION_SHA, "f" * 40))
    monkeypatch.setattr(
        "app.retrieval.retrieval_reattest._clean_integration_sha",
        lambda _root: next(revisions),
    )

    with pytest.raises(RuntimeError, match="HEAD changed"):
        _reattest(
            settings,
            database,
            build_id=BUILD_ID,
            benchmark_runner=lambda *_args, **_kwargs: _report(NEW_SCORER),
        )
    assert _history_row(database, BUILD_ID) is None
    assert _attestation_artifacts(settings) == []
    attempt = _assert_attempt_sealed(_attempt_results(settings)[0])
    assert attempt["attestation_preconditions"]["status"] == "failed"


def test_reattest_rechecks_pointers_after_proof_write_before_cas(
    reattest_catalog, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, database, identity, _legacy_bytes = reattest_catalog
    _patch_identity(monkeypatch, identity)
    import app.retrieval.retrieval_reattest as module

    real_write = module._write_new_json

    def write_then_change_pointer(path: Path, payload) -> None:
        real_write(path, payload)
        _write_json(settings.index_dir / "ACTIVE.json", {"build_id": "other-candidate"})

    monkeypatch.setattr(module, "_write_new_json", write_then_change_pointer)
    with pytest.raises(RuntimeError, match="pointer changed"):
        _reattest(
            settings,
            database,
            build_id=BUILD_ID,
            benchmark_runner=lambda *_args, **_kwargs: _report(NEW_SCORER),
        )
    assert _history_row(database, BUILD_ID) is None
    assert len(_attestation_artifacts(settings)) == 1
    assert len(_attempt_starts(settings)) == 1
    assert len(_attempt_results(settings)) == 1


def test_runtime_rejects_unselected_or_stale_scorer_proof(
    reattest_catalog, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, database, identity, _legacy_bytes = reattest_catalog
    _patch_identity(monkeypatch, identity)
    row = dict(database.fetchone("SELECT * FROM index_builds WHERE id=?", (BUILD_ID,)))
    with pytest.raises(RuntimeError, match="no selected"):
        verify_selected_retrieval_attestation(settings, database, row, identity)

    summary = json.loads(row["benchmark_result_json"])
    legacy_sha = str(summary["attestation_sha256"])
    database.execute(
        """INSERT INTO retrieval_attestation_history(
             id,build_id,attestation_path,attestation_sha256,schema_version,
             prior_attestation_path,prior_attestation_sha256,build_seal_sha256,
             source_manifest_sha256,embedding_model,reranker_model,
             quality_policy_sha256,assessment_bundle_sha256,retrieval_policy_sha256,
             benchmark_sha256,freeze_manifest_sha256,scorer_version,
             scorer_implementation_sha256,integration_sha,created_at
           ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            legacy_sha,
            BUILD_ID,
            summary["attestation_path"],
            legacy_sha,
            "legalbot.retrieval-attestation.v1.1",
            None,
            None,
            identity.build_seal_sha256,
            identity.source_manifest_file_sha256,
            identity.embedding_model,
            identity.reranker_model,
            identity.quality_policy_sha256,
            identity.assessment_bundle_sha256,
            identity.retrieval_policy_sha256,
            identity.benchmark_sha256,
            identity.freeze_manifest_sha256,
            identity.scorer_version,
            OLD_SCORER,
            INTEGRATION_SHA,
            "2026-08-19T00:00:00+00:00",
        ),
    )
    database.execute(
        """INSERT INTO retrieval_attestation_selections(
             build_id,attestation_id,selected_at) VALUES (?,?,?)""",
        (BUILD_ID, legacy_sha, "2026-08-19T00:00:00+00:00"),
    )
    with pytest.raises(RuntimeError, match="current scorer"):
        verify_selected_retrieval_attestation(settings, database, row, identity)
