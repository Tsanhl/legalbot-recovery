from __future__ import annotations

import hashlib
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from app.api.main import app
from app.config import Settings
from app.observability.projections import OwnerProjectionWriter
from app.orchestration.object_store import EncryptedObjectStore
from app.research.control_plane import ResearchControlPlane
from app.research.models import (
    ResearchDispatchResult,
    ResearchPriority,
    ResearchTaskRequest,
    ResearchTaskType,
    ResearchTrigger,
)
from app.research.runtime import FetchedResponse
from app.research.source_registry import OfficialSourceRegistry
from app.research.worker import (
    EncryptedResearchQuarantine,
    OfficialResearchDispatcher,
    ResearchWorker,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
REGISTRY = OfficialSourceRegistry.load(PROJECT_ROOT / "config" / "official_sources.json")


def _settings(tmp_path: Path) -> Settings:
    settings = Settings(project_root=tmp_path, test_mode=True)
    settings.ensure_runtime_dirs()
    return settings


@pytest.mark.asyncio
async def test_connected_research_path_projects_every_safe_stage(
    tmp_path: Path, database: Any, cipher: Any
) -> None:
    settings = _settings(tmp_path)
    control = ResearchControlPlane(settings, database, cipher=cipher, registry=REGISTRY)
    control.admit(
        ResearchTaskRequest(
            task_type=ResearchTaskType.SOURCE_UPDATE_CHECK,
            trigger=ResearchTrigger.MANUAL,
            priority=ResearchPriority.HIGH,
            subject="contract",
            jurisdiction="England and Wales",
            as_of_date=datetime.now(UTC).date(),
            source_id="legislation_gov_uk",
            authority_identity_id="ukpga:2026:1",
            source_locator="ukpga/2026/1",
        )
    )

    class Fetcher:
        async def fetch(self, plan: Any, policy: Any) -> FetchedResponse:
            content = b"<Legislation><Body>Official test bytes</Body></Legislation>"
            return FetchedResponse(
                url=plan.url,
                status_code=200,
                headers={
                    "content-type": "application/xml",
                    "content-length": str(len(content)),
                },
                content=content,
            )

    async def public_resolver(host: str, port: int) -> tuple[str, ...]:
        return ("8.8.8.8",)

    writer = OwnerProjectionWriter(settings)
    dispatcher = OfficialResearchDispatcher(
        control,
        fetcher=Fetcher(),
        quarantine=EncryptedResearchQuarantine(
            EncryptedObjectStore(settings.runtime_object_dir, database, cipher)
        ),
        resolver=public_resolver,
        projections=writer,
    )
    worker = ResearchWorker(
        database,
        control,
        dispatcher,
        worker_id="research-observability-test",
        projections=writer,
    )

    assert await worker.run_once()
    task = database.research_tasks(limit=1)[0]
    assert task["status"] == "review_required"

    trace_path = settings.operational_traces_dir / "research.jsonl"
    traces = [json.loads(line) for line in trace_path.read_text().splitlines()]
    assert {
        "worker_claim",
        "validation",
        "fetch",
        "active_comparison",
        "quarantine",
        "stage",
        "review_link",
        "complete",
    }.issubset({row["stage"] for row in traces})
    serialised = trace_path.read_text()
    assert "Official test bytes" not in serialised
    assert "https://" not in serialised
    assert "ukpga:2026:1" not in serialised

    metric_path = settings.operational_metrics_dir / "research.jsonl"
    metrics = [json.loads(line) for line in metric_path.read_text().splitlines()]
    assert {
        "queue_depth",
        "oldest_task_age_seconds",
        "worker_utilisation",
        "fetch_duration_seconds",
        "validation_duration_seconds",
        "comparison_duration_seconds",
        "candidates_total",
        "terminal_total",
    }.issubset({row["metric"] for row in metrics})


@pytest.mark.asyncio
async def test_projection_failure_cannot_change_research_completion(
    tmp_path: Path, database: Any
) -> None:
    control = ResearchControlPlane(_settings(tmp_path), database, registry=REGISTRY)
    control.admit(
        ResearchTaskRequest(
            task_type=ResearchTaskType.BROAD_DISCOVERY,
            trigger=ResearchTrigger.SCHEDULED,
            priority=ResearchPriority.MEDIUM,
            subject="contract",
            jurisdiction="England and Wales",
            as_of_date=datetime.now(UTC).date(),
            source_id="legislation_gov_uk",
        )
    )

    class Dispatcher:
        async def dispatch(self, task: Any) -> ResearchDispatchResult:
            return ResearchDispatchResult(
                requires_review=False,
                safe_reason="official_discovery_no_candidates",
            )

    class BrokenWriter:
        def append_research_trace(self, **kwargs: Any) -> None:
            raise OSError("projection unavailable")

        def append_research_metric(self, **kwargs: Any) -> None:
            raise OSError("projection unavailable")

    worker = ResearchWorker(
        database,
        control,
        Dispatcher(),
        worker_id="research-broken-projection-test",
        projections=BrokenWriter(),  # type: ignore[arg-type]
    )
    assert await worker.run_once()
    assert database.research_tasks(limit=1)[0]["status"] == "completed"


@pytest.mark.asyncio
async def test_check_now_uses_fixed_taxonomy_and_projects_admission(
    tmp_path: Path, database: Any, cipher: Any
) -> None:
    settings = _settings(tmp_path)
    (settings.project_root / "config").mkdir(exist_ok=True)
    shutil.copy2(
        PROJECT_ROOT / "config" / "official_sources.json",
        settings.project_root / "config" / "official_sources.json",
    )
    previous = getattr(app.state, "services", None)
    app.state.services = SimpleNamespace(
        settings=settings,
        database=database,
        cipher=cipher,
    )
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 4312))
    try:
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8777"
        ) as client:
            accepted = await client.post(
                "/api/v1/admin/research/check-now",
                json={
                    "task_type": "source_update_check",
                    "priority": "high",
                    "subject": "case law",
                    "source_id": "find_case_law",
                    "authority_identity_id": "case:ewhc:2026:1",
                },
            )
            rejected = await client.post(
                "/api/v1/admin/research/check-now",
                json={
                    "task_type": "broad_discovery",
                    "priority": "high",
                    "subject": "paste the private user question here",
                },
            )
    finally:
        if previous is None:
            delattr(app.state, "services")
        else:
            app.state.services = previous

    assert accepted.status_code == 201
    assert rejected.status_code == 409
    task = database.research_task(accepted.json()["task_id"])
    assert task["source_id"] == "find_case_law"
    assert database.fetchone("SELECT COUNT(*) AS n FROM research_tasks")["n"] == 1

    traces = [
        json.loads(line)
        for line in (settings.operational_traces_dir / "research.jsonl").read_text().splitlines()
    ]
    assert any(row["stage"] == "admission" and row["status"] == "queued" for row in traces)
    assert any(row["stage"] == "admission" and row["status"] == "error" for row in traces)
    assert "paste the private user question here" not in json.dumps(traces)


def test_research_authority_identity_rejects_arbitrary_prose(tmp_path: Path, database: Any) -> None:
    control = ResearchControlPlane(_settings(tmp_path), database, registry=REGISTRY)
    with pytest.raises(ValueError, match="public stable identifier"):
        control.admit(
            ResearchTaskRequest(
                task_type=ResearchTaskType.SOURCE_UPDATE_CHECK,
                trigger=ResearchTrigger.MANUAL,
                priority=ResearchPriority.HIGH,
                subject="case law",
                jurisdiction="England and Wales",
                as_of_date=datetime.now(UTC).date(),
                source_id="find_case_law",
                authority_identity_id="please search for anything relevant to my facts",
            )
        )


@pytest.mark.asyncio
async def test_owner_research_review_api_only_hands_off_to_source_intake(
    tmp_path: Path, database: Any, cipher: Any
) -> None:
    settings = _settings(tmp_path)
    task = database.enqueue_research_task(
        task_id="research-api-review",
        idempotency_key="research-api-review-idempotency",
        task_type="source_update_check",
        trigger_kind="manual",
        priority_band="high",
        subject="contract",
        jurisdiction="England and Wales",
        as_of_date="2026-08-15",
        source_id="legislation_gov_uk",
        authority_identity_id="ukpga:2026:1",
        query_sha256=hashlib.sha256(b"ukpga:2026:1").hexdigest(),
    )
    candidate = database.add_research_candidate(
        candidate_id="candidate-api-review",
        task_id=str(task["id"]),
        source_id="legislation_gov_uk",
        source_identity="ukpga/2026/1",
        canonical_url="https://www.legislation.gov.uk/ukpga/2026/1",
        metadata_sha256="a" * 64,
    )
    database.execute(
        "UPDATE research_tasks SET status='review_required' WHERE id=?",
        (task["id"],),
    )
    previous = getattr(app.state, "services", None)
    app.state.services = SimpleNamespace(
        settings=settings,
        database=database,
        cipher=cipher,
    )
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 4313))
    try:
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8777"
        ) as client:
            listed = await client.get("/api/v1/admin/research/candidates")
            assert listed.status_code == 200
            assert "https://" not in listed.text and "canonical_url" not in listed.text

            verified = await client.post(
                f"/api/v1/admin/research/candidates/{candidate['id']}/system-verify"
            )
            assert verified.status_code == 200
            accepted = await client.post(
                f"/api/v1/admin/research/candidates/{candidate['id']}/review",
                json={
                    "decision": "accept_for_source_intake",
                    "rights_state": "verified",
                    "identity_review_state": "candidate_matched",
                    "currentness_review_state": "verified",
                    "reviewer_ref": f"reviewer:{'b' * 64}",
                    "review_manifest_sha256": "c" * 64,
                },
            )
            assert accepted.status_code == 200
            assert accepted.json()["automatic_source_approval"] is False
            assert accepted.json()["automatic_index_or_promotion"] is False

            database.add_source_update_observation(
                observation_id="update-api-review",
                task_id=str(task["id"]),
                candidate_id=str(candidate["id"]),
                source_id="legislation_gov_uk",
                authority_identity_id="ukpga:2026:1",
                comparison_state="changed",
                remote_content_sha256="d" * 64,
            )
            update = await client.post(
                "/api/v1/admin/source-updates/update-api-review/review",
                json={
                    "materiality_status": "material",
                    "review_status": "approved",
                    "scope_kind": "authority",
                    "reviewer_ref": f"reviewer:{'e' * 64}",
                    "review_manifest_sha256": "f" * 64,
                },
            )
            assert update.status_code == 200
            assert update.json()["automatic_source_or_active_change"] is False
            updates = await client.get("/api/v1/admin/source-updates")
            assert updates.status_code == 200
            assert "canonical_url" not in updates.text and "safe_detail_json" not in updates.text
    finally:
        if previous is None:
            delattr(app.state, "services")
        else:
            app.state.services = previous

    intake = database.fetchone(
        "SELECT status FROM reviews WHERE id='review-research-intake-candidate-api-review'"
    )
    assert intake["status"] == "pending"
    assert database.fetchone("SELECT COUNT(*) AS n FROM source_versions")["n"] == 0
    assert database.active_index_id() is None
