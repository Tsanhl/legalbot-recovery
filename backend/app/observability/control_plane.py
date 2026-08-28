"""Privacy-safe operational snapshot for the local LegalBot control plane."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from ..config import Settings
from ..db import Database
from .storage_capacity import build_storage_capacity_snapshot


def _parse(value: object) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    parsed = datetime.fromisoformat(text)
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _age_seconds(value: object, *, now: datetime) -> float | None:
    parsed = _parse(value)
    if parsed is None:
        return None
    return round(max(0.0, (now - parsed).total_seconds()), 3)


def build_control_plane_snapshot(
    settings: Settings,
    database: Database,
    *,
    mode: str = "candidate",
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return only IDs, states, counts, ages, capacities and safe reason codes."""

    if mode not in {"candidate", "live"}:
        raise ValueError("mode must be candidate or live")
    stamp = now or datetime.now(UTC)
    if stamp.tzinfo is None:
        raise ValueError("snapshot time must be timezone-aware")

    queue_rows = database.fetchall(
        """
        SELECT COALESCE(job_type,'answer') AS job_type, status, COUNT(*) AS count,
               MIN(created_at) AS oldest_created_at
        FROM jobs GROUP BY COALESCE(job_type,'answer'), status
        ORDER BY job_type, status
        """
    )
    queues = [
        {
            "job_type": str(row["job_type"]),
            "status": str(row["status"]),
            "count": int(row["count"]),
            "oldest_age_seconds": _age_seconds(row["oldest_created_at"], now=stamp),
        }
        for row in queue_rows
    ]

    running_rows = database.fetchall(
        """
        SELECT id, COALESCE(job_type,'answer') AS job_type, stage, lease_owner,
               lease_expires_at, heartbeat_at, last_progress_at, updated_at
        FROM jobs WHERE status='running' ORDER BY created_at, id
        """
    )
    running = []
    expired_leases = 0
    for row in running_rows:
        lease = _parse(row["lease_expires_at"])
        expired = lease is not None and lease < stamp
        expired_leases += int(expired)
        running.append(
            {
                "job_id": str(row["id"]),
                "job_type": str(row["job_type"]),
                "stage": str(row["stage"]),
                "lease_owner": str(row["lease_owner"] or "") or None,
                "lease_expired": expired,
                "heartbeat_age_seconds": _age_seconds(row["heartbeat_at"], now=stamp),
                "progress_age_seconds": _age_seconds(
                    row["last_progress_at"] or row["updated_at"], now=stamp
                ),
            }
        )

    services = [
        {
            "service": str(row["service_key"]),
            "instance_id": str(row["instance_id"]),
            "heartbeat_age_seconds": _age_seconds(row["heartbeat_at"], now=stamp),
        }
        for row in database.fetchall(
            "SELECT service_key, instance_id, heartbeat_at FROM service_heartbeats "
            "ORDER BY service_key"
        )
    ]

    builds = [
        {
            "build_id": str(row["id"]),
            "status": str(row["status"]),
            "stage": str(row["stage"]),
            "documents": int(row["document_count"] or 0),
            "chunks": int(row["chunk_count"] or 0),
            "vectors": int(row["vector_count"] or 0),
            "promotion_decision": str(row["promotion_decision"] or ""),
        }
        for row in database.fetchall(
            """
            SELECT id,status,stage,document_count,chunk_count,vector_count,promotion_decision
            FROM index_builds ORDER BY created_at DESC LIMIT 10
            """
        )
    ]

    outbox = database.fetchone(
        "SELECT COUNT(*) AS count FROM release_outbox WHERE status<>'published'"
    )
    storage_capacity = build_storage_capacity_snapshot(settings, now=stamp)
    active = database.active_index_id()
    candidate_row = database.fetchone(
        "SELECT COUNT(*) AS count FROM index_builds WHERE status='candidate'"
    )
    candidate_count = int(candidate_row["count"] if candidate_row is not None else 0)
    blockers: list[str] = []
    if expired_leases:
        blockers.append("expired_running_lease")
    if "disk_free_critical" in storage_capacity["critical_codes"]:
        blockers.append("disk_free_critical")
    if mode == "candidate" and candidate_count < 1:
        blockers.append("candidate_missing")
    if mode == "live":
        if not active:
            blockers.append("active_index_missing")
        if not database.service_is_recent("answer-worker"):
            blockers.append("answer_worker_unavailable")

    snapshot: dict[str, Any] = {
        "schema": "legalbot.control-plane-snapshot.v1",
        "generated_at": stamp.astimezone(UTC).isoformat(),
        "mode": mode,
        "scope": "observe_only",
        "operationally_clear": not blockers,
        "certification_ready": False,
        "certification_note": (
            "Operational diagnostics only; this does not authorize Stage A, "
            "promotion or live serving."
        ),
        "blockers": blockers,
        "active_index": active,
        "candidate_count": candidate_count,
        "queues": queues,
        "running_jobs": running,
        "services": services,
        "recent_builds": builds,
        "pending_release_outbox": int(outbox["count"] if outbox is not None else 0),
        "disk": storage_capacity["disk"],
        "storage_capacity": storage_capacity,
    }
    assert_safe_control_plane_snapshot(snapshot)
    return snapshot


def assert_safe_control_plane_snapshot(value: Mapping[str, Any]) -> None:
    encoded = str(dict(value)).casefold()
    forbidden = (
        "question",
        "answer_text",
        "source_text",
        "system_prompt",
        "chain_of_thought",
        "/users/",
        "\\users\\",
        "authorization",
        "api_key",
        "password",
    )
    if any(item in encoded for item in forbidden):
        raise ValueError("control-plane snapshot contains a forbidden field or value")
