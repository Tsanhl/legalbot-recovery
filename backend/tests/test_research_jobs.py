from __future__ import annotations

from pathlib import Path

import pytest

from app.cli import parser
from app.config import FIRST_LIVE_LOCAL_ONLY_PROFILE, Settings
from app.db import Database
from app.research.jobs import (
    assert_research_worker_may_start,
    build_research_runtime,
    enqueue_official_crawl_job,
    research_queue_snapshot,
    run_research_worker,
)
from app.research.source_registry import OfficialSourceRegistry

PROJECT_ROOT = Path(__file__).resolve().parents[2]
REGISTRY = OfficialSourceRegistry.load(PROJECT_ROOT / "config" / "official_sources.json")


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    return Settings(project_root=tmp_path, test_mode=True, **overrides)


def test_cli_exposes_research_queue_commands() -> None:
    enqueue = parser().parse_args(
        [
            "research-enqueue",
            "--task-type",
            "source_update_check",
            "--subject",
            "contract",
            "--source-id",
            "legislation_gov_uk",
            "--authority-identity-id",
            "ukpga:1980:58",
        ]
    )
    assert enqueue.command == "research-enqueue"
    assert parser().parse_args(["research-queue"]).command == "research-queue"
    worker = parser().parse_args(["research-worker", "--once"])
    assert worker.command == "research-worker" and worker.once is True


def test_enqueue_lands_on_durable_queue_without_enabling_network(
    tmp_path: Path, database: Database
) -> None:
    settings = _settings(tmp_path, official_research_enabled=False)
    result = enqueue_official_crawl_job(
        settings,
        database,
        task_type="source_update_check",
        subject="contract",
        source_id="legislation_gov_uk",
        authority_identity_id="ukpga:1980:58",
        registry=REGISTRY,
    )
    assert result["status"] in {"queued", "deferred_capacity"}
    assert result["feeds_current_answer"] is False
    assert result["writes_active"] is False
    snapshot = research_queue_snapshot(database)
    assert snapshot["recent_tasks"][0]["id"] == result["task_id"]
    dumped = str(snapshot)
    assert "ukpga:1980:58" in dumped
    assert "question" not in snapshot["recent_tasks"][0]
    assert "encrypted_query" not in snapshot["recent_tasks"][0]


def test_enqueue_rejects_raw_user_question_as_public_query(
    tmp_path: Path, database: Database
) -> None:
    with pytest.raises(ValueError, match="registered crawl taxonomy"):
        enqueue_official_crawl_job(
            _settings(tmp_path),
            database,
            task_type="broad_discovery",
            subject="contract",
            public_query="Can a trustee mix trust money with their own?",
            registry=REGISTRY,
        )
    assert database.research_tasks(limit=1) == []


def test_enqueue_rejects_unregistered_discovery_source(tmp_path: Path, database: Database) -> None:
    with pytest.raises(ValueError, match="legislation_gov_uk"):
        enqueue_official_crawl_job(
            _settings(tmp_path),
            database,
            task_type="broad_discovery",
            subject="contract",
            source_id="find_case_law",
            public_query="contract",
            registry=REGISTRY,
        )


def test_gap_research_requires_existing_gap(tmp_path: Path, database: Database) -> None:
    with pytest.raises(ValueError, match="knowledge-gap identity"):
        enqueue_official_crawl_job(
            _settings(tmp_path),
            database,
            task_type="gap_research",
            subject="contract",
            public_query="contract",
            registry=REGISTRY,
        )


def test_first_live_and_disabled_flags_refuse_the_crawl_worker(
    tmp_path: Path,
) -> None:
    with pytest.raises(RuntimeError, match="first-live"):
        assert_research_worker_may_start(
            _settings(tmp_path, live_profile=FIRST_LIVE_LOCAL_ONLY_PROFILE)
        )
    with pytest.raises(RuntimeError, match="explicit operator enablement"):
        assert_research_worker_may_start(_settings(tmp_path, official_research_enabled=False))


def test_enabled_standard_profile_can_construct_crawl_worker(
    tmp_path: Path, database: Database, cipher: object
) -> None:
    settings = _settings(tmp_path, official_research_enabled=True)
    settings.ensure_runtime_dirs()
    worker, scheduler = build_research_runtime(settings, database, cipher, registry=REGISTRY)
    assert worker.max_concurrency == 2
    assert scheduler is not None


@pytest.mark.asyncio
async def test_research_worker_once_returns_safe_shape(
    tmp_path: Path, database: Database, cipher: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_once(self: object) -> bool:
        return True

    monkeypatch.setattr("app.research.jobs.ResearchWorker.run_once", fake_once)
    settings = _settings(tmp_path, official_research_enabled=True)
    settings.ensure_runtime_dirs()
    result = await run_research_worker(settings, database, cipher, once=True, registry=REGISTRY)
    assert result == {
        "worker": "official_research",
        "mode": "once",
        "claimed_job": True,
        "feeds_current_answer": False,
        "writes_active": False,
    }
    with pytest.raises(RuntimeError, match="first-live"):
        await run_research_worker(
            _settings(tmp_path, live_profile=FIRST_LIVE_LOCAL_ONLY_PROFILE),
            database,
            cipher,
            once=True,
            registry=REGISTRY,
        )
