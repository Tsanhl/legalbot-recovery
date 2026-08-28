from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from app.config import Settings
from app.db import Database
from app.orchestration.worker import DurableAnswerWorker
from app.research.control_plane import ResearchControlPlane
from app.research.fetch_policy import SafeFetchPolicy
from app.research.gap_queue import GapKind, GapQueue, LegacyGapQueueReadOnlyError
from app.research.legacy import DatabaseGapCandidateSink, LegacyResearchGapImporter
from app.research.models import (
    ResearchDispatchResult,
    ResearchPriority,
    ResearchTaskRequest,
    ResearchTaskType,
    ResearchTrigger,
    SourceUpdateDraft,
    SourceUpdateState,
)
from app.research.scheduler import (
    DAILY_SCHEDULE_ID,
    WEEKLY_SCHEDULE_ID,
    ResearchScheduler,
)
from app.research.source_registry import OfficialSourceRegistry
from app.research.worker import OfficialResearchDispatcher, ResearchWorker

PROJECT_ROOT = Path(__file__).resolve().parents[2]
REGISTRY = OfficialSourceRegistry.load(PROJECT_ROOT / "config" / "official_sources.json")


def _enqueue(
    database: Database,
    number: int,
    *,
    priority: str = "medium",
    origin: str | None = None,
    now: datetime | None = None,
) -> Any:
    digest = hashlib.sha256(f"query-{number}".encode()).hexdigest()
    return database.enqueue_research_task(
        task_id=f"research-{number:03d}",
        idempotency_key=f"idem-{number:03d}",
        task_type="gap_research",
        trigger_kind="manual",
        priority_band=priority,
        subject="contract",
        jurisdiction="England and Wales",
        as_of_date="2026-08-15",
        query_sha256=digest,
        origin_host=origin,
        now=now,
    )


def _control(tmp_path: Path, database: Database, cipher: Any | None = None) -> ResearchControlPlane:
    return ResearchControlPlane(
        Settings(project_root=tmp_path, test_mode=True),
        database,
        cipher=cipher,
        registry=REGISTRY,
    )


def test_research_queue_cap_defers_without_dropping_and_refills(database: Database) -> None:
    rows = [_enqueue(database, number) for number in range(21)]
    assert sum(row["status"] == "queued" for row in rows) == 20
    assert rows[-1]["status"] == "deferred_capacity"

    claimed = database.claim_research_task("research-worker")
    assert claimed is not None
    database.finish_research_task(str(claimed["id"]), "research-worker", status="completed")

    assert database.research_task("research-020")["status"] == "queued"
    assert (
        database.fetchone(
            """
        SELECT COUNT(*) AS n FROM research_tasks
        WHERE status IN ('queued','running','retry_wait')
        """
        )["n"]
        == 20
    )


def test_priority_aging_fifo_and_origin_concurrency(database: Database) -> None:
    now = datetime(2026, 8, 15, 12, tzinfo=UTC)
    _enqueue(database, 1, priority="low", origin="a.example", now=now - timedelta(days=16))
    _enqueue(database, 2, priority="high", origin="a.example", now=now)
    _enqueue(database, 3, priority="high", origin="b.example", now=now)

    first = database.claim_research_task("worker", now=now)
    assert first is not None and first["id"] == "research-001"
    second = database.claim_research_task("worker", now=now)
    assert second is not None and second["id"] == "research-003"
    assert database.claim_research_task("worker", now=now) is None

    database.finish_research_task("research-001", "worker", now=now)
    third = database.claim_research_task("worker", now=now)
    assert third is not None and third["id"] == "research-002"


def test_research_lease_retry_is_bounded_and_separate(database: Database) -> None:
    _enqueue(database, 1)
    claimed = database.claim_research_task("worker")
    assert claimed is not None and int(claimed["attempt_count"]) == 1
    status = database.retry_or_fail_research_task(
        "research-001",
        "worker",
        reason="official_network_unavailable",
        retryable=True,
        retry_after_seconds=60,
    )
    assert status == "retry_wait"
    assert database.claim_research_task("worker") is None


def test_candidate_limit_is_twenty(database: Database) -> None:
    _enqueue(database, 1)
    for number in range(20):
        database.add_research_candidate(
            candidate_id=f"candidate-{number:02d}",
            task_id="research-001",
            source_id="legislation_gov_uk",
            source_identity=f"ukpga/2026/{number + 1}",
            canonical_url=f"https://www.legislation.gov.uk/ukpga/2026/{number + 1}",
            metadata_sha256=hashlib.sha256(str(number).encode()).hexdigest(),
        )
    with pytest.raises(RuntimeError, match="candidate cap"):
        database.add_research_candidate(
            candidate_id="candidate-overflow",
            task_id="research-001",
            source_id="legislation_gov_uk",
            source_identity="ukpga/2026/99",
            canonical_url="https://www.legislation.gov.uk/ukpga/2026/99",
            metadata_sha256="a" * 64,
        )
    safe = dict(database.research_candidates(limit=1)[0])
    assert "canonical_url" not in safe and "content_object_key" not in safe


def test_candidate_and_update_require_explicit_review(database: Database) -> None:
    _enqueue(database, 1)
    candidate = database.add_research_candidate(
        candidate_id="candidate-reviewed",
        task_id="research-001",
        source_id="legislation_gov_uk",
        source_identity="ukpga/2026/1",
        canonical_url="https://www.legislation.gov.uk/ukpga/2026/1",
        metadata_sha256="a" * 64,
    )
    with pytest.raises(ValueError, match="initial status"):
        database.add_research_candidate(
            candidate_id="candidate-auto-approved",
            task_id="research-001",
            source_id="legislation_gov_uk",
            source_identity="ukpga/2026/2",
            canonical_url="https://www.legislation.gov.uk/ukpga/2026/2",
            metadata_sha256="b" * 64,
            status="approved",
        )
    database.execute("UPDATE research_tasks SET status='review_required' WHERE id='research-001'")
    database.mark_research_candidate_system_verified(
        str(candidate["id"]), verification_manifest_sha256="1" * 64
    )
    database.record_research_candidate_review(
        str(candidate["id"]),
        review_id="review-candidate-1",
        decision="approved",
        rights_state="verified",
        reviewer_ref=f"reviewer:{'2' * 64}",
        review_manifest_sha256="c" * 64,
    )
    reviewed_candidate = database.research_candidates()[0]
    assert reviewed_candidate["status"] == "source_intake_pending"
    assert reviewed_candidate["intake_review_id"] == "review-research-intake-candidate-reviewed"
    intake = database.fetchone(
        "SELECT * FROM reviews WHERE id=?", (reviewed_candidate["intake_review_id"],)
    )
    assert intake is not None
    assert intake["review_type"] == "research_source_intake"
    assert intake["status"] == "pending"

    database.add_source_update_observation(
        observation_id="update-1",
        task_id="research-001",
        candidate_id=str(candidate["id"]),
        source_id="legislation_gov_uk",
        authority_identity_id="ukpga:2026:1",
        comparison_state="changed",
        remote_content_sha256="d" * 64,
    )
    observation = database.source_update_observations()[0]
    assert observation["materiality_status"] == "unassessed"
    assert observation["review_status"] == "pending"
    database.record_source_update_review(
        "update-1",
        review_id="review-update-1",
        review_status="approved",
        materiality_status="material",
        reviewer_ref=f"reviewer:{'e' * 64}",
        review_manifest_sha256="f" * 64,
    )
    reviewed = database.source_update_observations()[0]
    assert reviewed["materiality_status"] == "material"
    assert reviewed["review_id"] == "review-update-1"


def test_unchanged_source_observation_needs_no_materiality_review(
    tmp_path: Path, database: Database
) -> None:
    control = _control(tmp_path, database)
    task = _enqueue(database, 1)
    control.persist_update(
        task,
        SourceUpdateDraft(
            source_id="legislation_gov_uk",
            authority_identity_id="ukpga:2026:1",
            comparison_state=SourceUpdateState.UNCHANGED,
            baseline_version_sha256="a" * 64,
            remote_content_sha256="a" * 64,
            observed_active_build_id=None,
            stale_active=False,
        ),
    )
    observation = database.source_update_observations()[0]
    assert observation["review_status"] == "not_required"
    assert observation["materiality_status"] == "non_material"


def test_refinement_events_are_append_only_and_safe_projection_excludes_note(
    database: Database, cipher: Any
) -> None:
    note = cipher.encrypt_text("Private owner note")
    row = database.create_refinement(
        refinement_id="refinement-1",
        fingerprint="missing:test",
        category="missing",
        scope="source",
        priority=90,
        origin="test",
        safe_target={"source_id": "source-safe"},
        encrypted_note=note,
        note_sha256=hashlib.sha256(b"Private owner note").hexdigest(),
    )
    assert row["status"] == "open"
    database.transition_refinement(
        "refinement-1",
        to_status="source_needed",
        event_type="owner_triage",
        safe_payload={"source_id": "source-safe"},
    )
    database.transition_refinement(
        "refinement-1",
        to_status="resolved",
        event_type="source_verified",
        root_cause="missing_verified_source",
        repair_version="source-review-v2",
        regression_case_id="regression-source-safe",
        resolution_evidence={
            "report_id": "report-source-safe",
            "report_sha256": "a" * 64,
        },
    )
    assert len(database.fetchall("SELECT * FROM refinement_events")) == 3
    projection = dict(database.refinements()[0])
    assert "encrypted_note" not in projection
    assert projection["status"] == "resolved"


def test_default_schedules_are_disabled_and_one_catchup_is_persisted(
    tmp_path: Path, database: Database
) -> None:
    control = _control(tmp_path, database)
    scheduler = ResearchScheduler(database, control)
    before = datetime(2026, 8, 15, 0, tzinfo=UTC)
    scheduler.install_defaults(now=before)
    rows = database.fetchall("SELECT * FROM research_schedules ORDER BY id")
    assert {row["id"] for row in rows} == {DAILY_SCHEDULE_ID, WEEKLY_SCHEDULE_ID}
    assert all(not row["enabled"] for row in rows)

    due = datetime(2026, 8, 16, 4, tzinfo=UTC)
    database.execute(
        "UPDATE research_schedules SET enabled=1, next_due_at=? WHERE id=?",
        ((due - timedelta(hours=1)).isoformat(), WEEKLY_SCHEDULE_ID),
    )
    result = scheduler.tick(now=due)
    assert result.schedules_advanced == 1 and result.tasks_admitted == 1
    schedule = database.fetchone(
        "SELECT * FROM research_schedules WHERE id=?", (WEEKLY_SCHEDULE_ID,)
    )
    assert datetime.fromisoformat(schedule["next_due_at"]) > due
    assert scheduler.tick(now=due).schedules_advanced == 0


def test_legacy_json_is_read_only_and_imported_once_then_encrypted(
    tmp_path: Path, database: Database, cipher: Any
) -> None:
    path = tmp_path / "legacy-gaps.json"
    payload = {
        "schema": "legalbot.gap-queue.v1",
        "items": [
            {
                "gap_id": "gap-old-1",
                "subject": "trusts",
                "jurisdiction": "england_wales",
                "kind": "case_authority",
                "reason_code": "missing_binding_authority",
                "description": "A generalized missing authority description.",
                "query_alias": None,
                "priority": 90,
                "status": "open",
                "created_at": "2026-08-10T00:00:00+00:00",
                "updated_at": "2026-08-10T00:00:00+00:00",
                "candidates": [],
                "metadata": {},
            }
        ],
    }
    original = (json.dumps(payload, sort_keys=True) + "\n").encode()
    path.write_bytes(original)
    queue = GapQueue(path)
    assert len(queue.list()) == 1
    with pytest.raises(LegacyGapQueueReadOnlyError):
        queue.enqueue(
            subject="trusts",
            jurisdiction="england_wales",
            kind=queue.list()[0].kind,
            reason_code="new_write",
            description="This must not be written.",
        )

    importer = LegacyResearchGapImporter(database, _control(tmp_path, database, cipher), cipher)
    first = importer.import_file(path)
    archive = path.with_name(f"{path.name}.enc")
    assert first["imported"] == 1
    assert not path.exists() and archive.is_file()
    assert archive.stat().st_mode & 0o777 == 0o600
    assert cipher.decrypt_text(archive.read_bytes()).encode("utf-8") == original
    assert database.fetchone("SELECT COUNT(*) AS n FROM refinements")["n"] == 1
    task = database.fetchone("SELECT * FROM research_tasks")
    assert task["status"] == "review_required"
    assert task["encrypted_query"] is None

    # A restart may encounter plaintext restored from backup after the DB marker
    # already exists.  It is re-verified against the immutable encrypted audit.
    path.write_bytes(original)
    second = importer.import_file(path)
    assert second["imported"] == 0 and not path.exists()
    assert cipher.decrypt_text(archive.read_bytes()).encode("utf-8") == original


def test_answer_time_candidate_sink_writes_sqlite_not_json(
    tmp_path: Path, database: Database
) -> None:
    sink = DatabaseGapCandidateSink(_control(tmp_path, database))
    gap = sink.enqueue(
        subject="trusts",
        jurisdiction="england_wales",
        kind=GapKind.CASE_AUTHORITY,
        reason_code="answer_time_official_candidate",
        description="A generic official candidate needs review.",
        priority=90,
    )
    sink.stage_candidate(
        gap.gap_id,
        source_id="find_case_law",
        source_identity="neutral_citation:[2026] UKSC 1",
        canonical_url="https://caselaw.nationalarchives.gov.uk/uksc/2026/1?unsafe=removed",
        metadata={"neutral_citation_sha256": "a" * 64},
    )
    sink.require_review(gap.gap_id)
    assert database.research_task(gap.gap_id)["status"] == "review_required"
    assert database.research_candidates()[0]["source_id"] == "find_case_law"
    assert not list(tmp_path.rglob("official-source-candidates.json"))


@pytest.mark.asyncio
async def test_safe_fetch_policy_rejects_private_dns_resolution() -> None:
    policy = REGISTRY.get("legislation_gov_uk")
    plan = __import__("app.research.adapters", fromlist=["FetchPlan"]).FetchPlan(
        "legislation_gov_uk",
        "https://www.legislation.gov.uk/ukpga/2026/1/data.xml",
        policy.content_mode,
    )

    async def private_resolver(host: str, port: int) -> tuple[str, ...]:
        return ("127.0.0.1",)

    with pytest.raises(ValueError, match="non_public"):
        await SafeFetchPolicy().validate_resolution(plan, policy, resolver=private_resolver)


@pytest.mark.asyncio
async def test_metadata_only_case_update_never_fetches_full_text(
    tmp_path: Path, database: Database
) -> None:
    control = _control(tmp_path, database)
    task = control.admit(
        ResearchTaskRequest(
            task_type=ResearchTaskType.SOURCE_UPDATE_CHECK,
            trigger=ResearchTrigger.MANUAL,
            priority=ResearchPriority.HIGH,
            subject="case law",
            jurisdiction="England and Wales",
            as_of_date=datetime.now(UTC).date(),
            source_id="find_case_law",
            authority_identity_id="neutral_citation:[2026] UKSC 1",
            source_locator="uksc/2026/1",
        )
    )

    class Fetcher:
        async def fetch(self, *args: Any, **kwargs: Any) -> Any:
            raise AssertionError("metadata-only case source must not fetch judgment bytes")

    result = await OfficialResearchDispatcher(control, fetcher=Fetcher()).dispatch(dict(task))
    assert result.updates[0].comparison_state.value == "unknown"
    assert result.candidates[0].rights_state == "metadata_only"


@pytest.mark.asyncio
async def test_research_worker_never_claims_answer_jobs(
    tmp_path: Path, database: Database, cipher: Any
) -> None:
    database.create_job(
        job_id="answer-job",
        encrypted_question=cipher.encrypt_text("Private question"),
        question_summary="Private encrypted question",
        request={"task_type": "general", "word_target": 500},
    )
    _enqueue(database, 1)

    class Dispatcher:
        async def dispatch(self, task: Any) -> ResearchDispatchResult:
            return ResearchDispatchResult(requires_review=False, safe_reason="no_candidates")

    worker = ResearchWorker(database, _control(tmp_path, database), Dispatcher())
    assert await worker.run_once()
    assert database.research_task("research-001")["status"] == "completed"
    assert database.job("answer-job")["status"] == "queued"


@pytest.mark.asyncio
async def test_retired_scheduled_job_is_refused_before_answer_runner(
    database: Database,
) -> None:
    database.execute(
        """INSERT INTO jobs(
             id,status,stage,progress,encrypted_question,question_summary,
             request_json,job_type,created_at,updated_at
           ) VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (
            "legacy-scheduled",
            "queued",
            "queued",
            0,
            b"",
            "Private encrypted question",
            '{"job_type":"scheduled_task","word_target":500}',
            "scheduled_task",
            "2026-08-22T00:00:00+00:00",
            "2026-08-22T00:00:00+00:00",
        ),
    )
    database.claim_next_job("answer-worker")

    class Runner:
        async def run(self, *args: Any, **kwargs: Any) -> None:
            raise AssertionError("AnswerRunner must not receive scheduled research")

    worker = DurableAnswerWorker(
        SimpleNamespace(database=database, runner=Runner()),
        worker_id="answer-worker",
    )
    await worker._reject_legacy_scheduled_job("legacy-scheduled")
    row = database.job("legacy-scheduled")
    assert row["status"] == "dlq"
    assert row["error_code"] == "scheduled_task_requires_research_queue"


def test_upload_lifecycle_columns_are_migration_safe(database: Database, cipher: Any) -> None:
    database.store_upload(
        upload_id="upload-1",
        content_sha256="a" * 64,
        safe_display_name="upload-a.bin",
        encrypted_original_name=cipher.encrypt_text("private-name.pdf"),
        media_type="application/pdf",
        byte_size=10,
        vault_path="data/uploads/a.enc",
    )
    row = database.fetchone("SELECT * FROM uploads WHERE id='upload-1'")
    assert not row["encrypted_blob"] and row["quarantine_status"] == "unreviewed"
    database.update_upload_lifecycle(
        "upload-1",
        encrypted_blob=True,
        review_pinned=True,
        quarantine_status="blocked",
    )
    row = database.fetchone("SELECT * FROM uploads WHERE id='upload-1'")
    assert row["encrypted_blob"] and row["review_pinned"]
    assert row["quarantine_status"] == "blocked"
