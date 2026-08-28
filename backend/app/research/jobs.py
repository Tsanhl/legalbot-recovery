"""Operator jobs for the official-source crawl queue.

This is a separate leased worker. It never claims answer jobs, never writes
ACTIVE, and never uses a raw user question as a network query. First-live
profiles cannot start the worker.
"""

from __future__ import annotations

import asyncio
import json
import signal
from collections.abc import Mapping
from contextlib import suppress
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

from ..config import FIRST_LIVE_LOCAL_ONLY_PROFILE, Settings
from ..crypto import LocalCipher
from ..db import Database
from ..observability.projections import OwnerProjectionWriter
from ..orchestration.object_store import EncryptedObjectStore
from .control_plane import (
    RESEARCH_PUBLIC_QUERIES,
    RESEARCH_SUBJECT_TAXONOMY,
    ResearchControlPlane,
)
from .models import (
    ResearchPriority,
    ResearchTaskRequest,
    ResearchTaskType,
    ResearchTrigger,
)
from .scheduler import ResearchScheduler
from .source_registry import OfficialSourceRegistry
from .worker import (
    EncryptedResearchQuarantine,
    OfficialResearchDispatcher,
    ResearchWorker,
)

LONDON = ZoneInfo("Europe/London")
ALLOWED_DISCOVERY_SOURCES = frozenset({"legislation_gov_uk"})
SAFE_TASK_FIELDS = (
    "id",
    "task_type",
    "trigger_kind",
    "priority_band",
    "subject",
    "jurisdiction",
    "as_of_date",
    "source_id",
    "authority_identity_id",
    "knowledge_gap_id",
    "status",
    "status_reason",
    "attempt_count",
    "pinned_index_build_id",
    "created_at",
    "updated_at",
)


def _safe_task_row(row: Any) -> dict[str, Any]:
    payload = {str(key): row[key] for key in row.keys()}  # noqa: SIM118
    return {key: payload[key] for key in SAFE_TASK_FIELDS if key in payload}


def enqueue_official_crawl_job(
    settings: Settings,
    database: Database,
    *,
    task_type: str,
    subject: str,
    priority: str = "medium",
    source_id: str | None = None,
    authority_identity_id: str | None = None,
    knowledge_gap_id: str | None = None,
    source_locator: str | None = None,
    public_query: str | None = None,
    cipher: LocalCipher | None = None,
    registry: OfficialSourceRegistry | None = None,
) -> dict[str, Any]:
    """Admit one official crawl/update job onto the durable research queue."""

    kind = ResearchTaskType(task_type)
    discovery = kind in {ResearchTaskType.BROAD_DISCOVERY, ResearchTaskType.GAP_RESEARCH}
    if discovery and source_id not in {None, *ALLOWED_DISCOVERY_SOURCES}:
        raise ValueError("connected discovery supports only legislation_gov_uk")
    effective_source = source_id or ("legislation_gov_uk" if discovery else None)
    if kind is ResearchTaskType.SOURCE_UPDATE_CHECK and (
        not effective_source or not authority_identity_id
    ):
        raise ValueError("update checks require a registered source and authority identity")
    if kind is ResearchTaskType.GAP_RESEARCH and not knowledge_gap_id:
        raise ValueError("gap research requires an existing knowledge-gap identity")
    cleaned_query = " ".join((public_query or "").split()) or None
    if cleaned_query and cleaned_query.casefold() not in RESEARCH_PUBLIC_QUERIES:
        raise ValueError("public query is not in the registered crawl taxonomy")
    if " ".join(subject.split()).casefold() not in RESEARCH_SUBJECT_TAXONOMY:
        raise ValueError("research subject is not in the registered taxonomy")
    control = ResearchControlPlane(settings, database, cipher=cipher, registry=registry)
    row = control.admit(
        ResearchTaskRequest(
            task_type=kind,
            trigger=ResearchTrigger.MANUAL,
            priority=ResearchPriority(priority),
            subject=subject,
            jurisdiction="England and Wales",
            as_of_date=datetime.now(LONDON).date(),
            source_id=effective_source,
            authority_identity_id=authority_identity_id,
            knowledge_gap_id=knowledge_gap_id,
            source_locator=source_locator,
            public_query=cleaned_query,
        )
    )
    return {
        "task_id": row["id"],
        "status": row["status"],
        "priority": row["priority_band"],
        "task_type": row["task_type"],
        "source_id": row["source_id"],
        "feeds_current_answer": False,
        "writes_active": False,
        "staging_only": True,
        "pinned_index_build_id": row["pinned_index_build_id"],
    }


def research_queue_snapshot(database: Database, *, limit: int = 50) -> dict[str, Any]:
    telemetry = database.research_queue_telemetry()
    tasks = [_safe_task_row(row) for row in database.research_tasks(limit=limit)]
    return {
        "schema": "legalbot.research-queue-snapshot.v1",
        "feeds_current_answer": False,
        "writes_active": False,
        "queue": telemetry,
        "recent_tasks": tasks,
    }


def assert_research_worker_may_start(settings: Settings) -> None:
    if settings.live_profile == FIRST_LIVE_LOCAL_ONLY_PROFILE:
        raise RuntimeError("the first-live profile cannot start the official crawl worker")
    settings.assert_online_research_adapter_allowed()


def build_research_runtime(
    settings: Settings,
    database: Database,
    cipher: LocalCipher,
    *,
    registry: OfficialSourceRegistry | None = None,
) -> tuple[ResearchWorker, ResearchScheduler]:
    assert_research_worker_may_start(settings)
    control = ResearchControlPlane(settings, database, cipher=cipher, registry=registry)
    scheduler = ResearchScheduler(database, control)
    scheduler.install_defaults(enabled=False)
    quarantine = EncryptedResearchQuarantine(
        EncryptedObjectStore(settings.runtime_object_dir, database, cipher)
    )
    projections = OwnerProjectionWriter(settings)
    dispatcher = OfficialResearchDispatcher(
        control,
        quarantine=quarantine,
        projections=projections,
        registry=registry,
    )
    worker = ResearchWorker(database, control, dispatcher, projections=projections)
    return worker, scheduler


async def run_research_worker(
    settings: Settings,
    database: Database,
    cipher: LocalCipher,
    *,
    once: bool = False,
    registry: OfficialSourceRegistry | None = None,
) -> dict[str, Any]:
    worker, scheduler = build_research_runtime(settings, database, cipher, registry=registry)
    if once:
        claimed = await worker.run_once()
        return {
            "worker": "official_research",
            "mode": "once",
            "claimed_job": claimed,
            "feeds_current_answer": False,
            "writes_active": False,
        }

    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()

    def stop() -> None:
        worker.stop()
        stopped.set()

    for signum in (signal.SIGINT, signal.SIGTERM):
        with suppress(NotImplementedError):
            loop.add_signal_handler(signum, stop)

    async def schedule_loop() -> None:
        while not stopped.is_set():
            scheduler.tick()
            with suppress(TimeoutError):
                await asyncio.wait_for(stopped.wait(), timeout=30)

    schedule_task = asyncio.create_task(schedule_loop())
    try:
        await worker.run_forever()
    finally:
        stopped.set()
        schedule_task.cancel()
        with suppress(asyncio.CancelledError):
            await schedule_task
    return {
        "worker": "official_research",
        "mode": "forever",
        "feeds_current_answer": False,
        "writes_active": False,
    }


def format_queue_json(snapshot: Mapping[str, Any]) -> str:
    return json.dumps(snapshot, indent=2, sort_keys=True, default=str)
