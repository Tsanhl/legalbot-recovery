from __future__ import annotations

import hashlib
from datetime import UTC, date, datetime

from app.research.freshness import (
    KnowledgeEventType,
    KnowledgeFreshnessCoordinator,
    KnowledgeUpdateEventRequest,
)


class _Admitter:
    def __init__(self, database) -> None:
        self.database = database
        self.calls = []

    def admit(self, request):
        self.calls.append(request)
        identity = hashlib.sha256(repr(request).encode()).hexdigest()
        return self.database.enqueue_research_task(
            task_id=f"research-{identity[:40]}",
            idempotency_key=identity,
            task_type=request.task_type.value,
            trigger_kind=request.trigger.value,
            priority_band=request.priority.value,
            subject=request.subject,
            jurisdiction=request.jurisdiction,
            as_of_date=request.as_of_date.isoformat(),
            query_sha256=request.query_sha256 or "a" * 64,
            source_id=request.source_id,
            authority_identity_id=request.authority_identity_id,
            knowledge_gap_id=request.knowledge_gap_id,
        )


def _source_event(*, suffix: str = "1") -> KnowledgeUpdateEventRequest:
    return KnowledgeUpdateEventRequest(
        event_type=KnowledgeEventType.SOURCE_CHANGED,
        subject="contract",
        source_id="legislation_gov_uk",
        authority_identity_id=f"ukpga:1977:50:{suffix}",
        source_date=date(1977, 7, 29),
        as_of_date=date(2026, 8, 14),
        observed_at=datetime(2026, 8, 24, 12, int(suffix), tzinfo=UTC),
        safe_payload={"change_kind": "official_version_observed"},
        detail="The official source bytes changed and require proposition-level review.",
    )


def test_source_change_is_durable_staging_only_and_idempotent(database, cipher) -> None:
    admitter = _Admitter(database)
    coordinator = KnowledgeFreshnessCoordinator(database, cipher, admitter)
    request = _source_event()

    first = coordinator.receive(request)
    second = coordinator.receive(request)

    assert first == second
    assert first.status == "queued_for_quarantine"
    assert first.owner_admission_required is True
    assert first.writes_index is False
    assert first.stages_quarantine_only is True
    assert len(admitter.calls) == 1
    row = database.fetchone("SELECT * FROM knowledge_update_events WHERE id=?", (first.event_id,))
    assert row is not None
    assert row["source_date"] == "1977-07-29"
    assert row["as_of_date"] == "2026-08-14"
    assert row["last_updated_at"] == "2026-08-24T12:01:00+00:00"
    assert row["encrypted_detail"] is not None
    assert b"official source bytes" not in bytes(row["encrypted_detail"])
    assert row["writes_index"] == 0


def test_exact_retry_resumes_an_event_left_before_queue_admission(database, cipher) -> None:
    admitter = _Admitter(database)
    coordinator = KnowledgeFreshnessCoordinator(database, cipher, admitter)
    request = _source_event()
    receipt = coordinator.receive(request)
    database.execute(
        """
        UPDATE knowledge_update_events
        SET status='received',research_task_id=NULL
        WHERE id=?
        """,
        (receipt.event_id,),
    )
    admitter.calls.clear()

    resumed = coordinator.receive(request)

    assert resumed.event_id == receipt.event_id
    assert resumed.status == "queued_for_quarantine"
    assert resumed.research_task_id is not None
    assert len(admitter.calls) == 1


def test_project_clarification_never_dispatches_or_indexes(database, cipher) -> None:
    admitter = _Admitter(database)
    coordinator = KnowledgeFreshnessCoordinator(database, cipher, admitter)

    receipt = coordinator.receive(
        KnowledgeUpdateEventRequest(
            event_type=KnowledgeEventType.PROJECT_CLARIFICATION,
            subject="general",
            safe_payload={"clarification_kind": "owner_input_needed"},
        )
    )

    assert receipt.status == "recorded_for_owner_review"
    assert receipt.research_task_id is None
    assert admitter.calls == []


def test_many_updates_switch_to_the_existing_bounded_queue_mode(database, cipher) -> None:
    admitter = _Admitter(database)
    coordinator = KnowledgeFreshnessCoordinator(
        database,
        cipher,
        admitter,
        batch_threshold=4,
    )

    receipts = [coordinator.receive(_source_event(suffix=str(value))) for value in range(1, 5)]

    assert receipts[0].dispatch_mode == "direct_durable_queue_admission"
    assert receipts[-1].dispatch_mode == "batched_durable_queue"
    assert all(receipt.writes_index is False for receipt in receipts)


def test_gap_without_verified_dispatch_identity_waits_for_owner_route(database, cipher) -> None:
    admitter = _Admitter(database)
    coordinator = KnowledgeFreshnessCoordinator(database, cipher, admitter)

    receipt = coordinator.receive(
        KnowledgeUpdateEventRequest(
            event_type=KnowledgeEventType.KNOWLEDGE_GAP,
            subject="contract",
            knowledge_gap_id="research-gap-example",
            query_sha256="b" * 64,
            safe_payload={"gap_kind": "missing_official_authority"},
        )
    )

    assert receipt.status == "owner_route_required"
    assert receipt.research_task_id is None
    assert admitter.calls == []
