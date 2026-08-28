"""Persisted HKT scheduler for known-source checks and bounded discovery."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo

from ..db import Database
from .control_plane import ResearchControlPlane
from .models import ResearchPriority, ResearchTaskRequest, ResearchTaskType, ResearchTrigger

HONG_KONG = ZoneInfo("Asia/Hong_Kong")
LONDON = ZoneInfo("Europe/London")
DAILY_SCHEDULE_ID = "official-known-source-daily-hkt"
WEEKLY_SCHEDULE_ID = "official-discovery-weekly-hkt"


@dataclass(frozen=True, slots=True)
class ScheduleTickResult:
    schedules_advanced: int
    tasks_admitted: int
    tasks_deferred: int


def _next_occurrence(
    now: datetime,
    *,
    hour: int,
    minute: int,
    weekday: int | None,
) -> datetime:
    local_now = now.astimezone(HONG_KONG)
    candidate = datetime.combine(local_now.date(), time(hour, minute), HONG_KONG)
    if weekday is None:
        if candidate <= local_now:
            candidate += timedelta(days=1)
    else:
        candidate += timedelta(days=(weekday - candidate.weekday()) % 7)
        if candidate <= local_now:
            candidate += timedelta(days=7)
    return candidate.astimezone(UTC)


class ResearchScheduler:
    def __init__(self, database: Database, control: ResearchControlPlane) -> None:
        self.database = database
        self.control = control

    def install_defaults(
        self,
        *,
        enabled: bool = False,
        now: datetime | None = None,
    ) -> None:
        resolved = (now or datetime.now(UTC)).astimezone(UTC)
        self.database.upsert_research_schedule(
            schedule_id=DAILY_SCHEDULE_ID,
            task_type=ResearchTaskType.SOURCE_UPDATE_CHECK.value,
            timezone="Asia/Hong_Kong",
            local_hour=2,
            local_minute=0,
            weekday=None,
            enabled=enabled,
            next_due_at=_next_occurrence(resolved, hour=2, minute=0, weekday=None).isoformat(),
        )
        self.database.upsert_research_schedule(
            schedule_id=WEEKLY_SCHEDULE_ID,
            task_type=ResearchTaskType.BROAD_DISCOVERY.value,
            timezone="Asia/Hong_Kong",
            local_hour=3,
            local_minute=0,
            weekday=6,
            enabled=enabled,
            next_due_at=_next_occurrence(resolved, hour=3, minute=0, weekday=6).isoformat(),
        )
        if enabled:
            self.database.set_research_schedule_enabled(DAILY_SCHEDULE_ID, enabled=True)
            self.database.set_research_schedule_enabled(WEEKLY_SCHEDULE_ID, enabled=True)

    def tick(self, *, now: datetime | None = None) -> ScheduleTickResult:
        """Run at most one catch-up occurrence for each due schedule."""

        resolved = (now or datetime.now(UTC)).astimezone(UTC)
        admitted = 0
        deferred = 0
        advanced = 0
        for schedule in self.database.due_research_schedules(now=resolved):
            scheduled_for = str(schedule["next_due_at"])
            legal_date = resolved.astimezone(LONDON).date()
            if str(schedule["task_type"]) == ResearchTaskType.SOURCE_UPDATE_CHECK.value:
                requests = self._known_source_requests(scheduled_for, legal_date)
            else:
                requests = (self._discovery_request(scheduled_for, legal_date),)
            for request in requests:
                row = self.control.admit(request)
                if str(row["status"]) == "deferred_capacity":
                    deferred += 1
                else:
                    admitted += 1
            next_due = _next_occurrence(
                resolved,
                hour=int(schedule["local_hour"]),
                minute=int(schedule["local_minute"]),
                weekday=(int(schedule["weekday"]) if schedule["weekday"] is not None else None),
            )
            self.database.advance_research_schedule(
                str(schedule["id"]),
                scheduled_for=scheduled_for,
                next_due_at=next_due.isoformat(),
            )
            advanced += 1
        return ScheduleTickResult(advanced, admitted, deferred)

    def _known_source_requests(
        self, scheduled_for: str, as_of_date: date
    ) -> tuple[ResearchTaskRequest, ...]:
        output: list[ResearchTaskRequest] = []
        for item in self.control.known_active_authorities():
            identity_key = hashlib.sha256(
                "\0".join(
                    (
                        DAILY_SCHEDULE_ID,
                        scheduled_for,
                        item["source_id"],
                        item["authority_identity_id"],
                    )
                ).encode("utf-8")
            ).hexdigest()
            output.append(
                ResearchTaskRequest(
                    task_type=ResearchTaskType.SOURCE_UPDATE_CHECK,
                    trigger=ResearchTrigger.SCHEDULED,
                    priority=ResearchPriority.LOW,
                    subject="known_sources",
                    jurisdiction="England and Wales",
                    as_of_date=as_of_date,
                    source_id=item["source_id"],
                    authority_identity_id=item["authority_identity_id"],
                    source_locator=item["adapter_identity"],
                    idempotency_key=f"schedule:{identity_key}",
                )
            )
        return tuple(output)

    @staticmethod
    def _discovery_request(scheduled_for: str, as_of_date: date) -> ResearchTaskRequest:
        key = hashlib.sha256(f"{WEEKLY_SCHEDULE_ID}\0{scheduled_for}".encode()).hexdigest()
        return ResearchTaskRequest(
            task_type=ResearchTaskType.BROAD_DISCOVERY,
            trigger=ResearchTrigger.SCHEDULED,
            priority=ResearchPriority.LOW,
            subject="general",
            jurisdiction="England and Wales",
            as_of_date=as_of_date,
            source_id="legislation_gov_uk",
            public_query="general legislation",
            idempotency_key=f"schedule:{key}",
        )
