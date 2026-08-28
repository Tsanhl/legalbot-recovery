"""Dedicated leased research worker; never dispatches to ``AnswerRunner``."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import socket
from collections.abc import Mapping
from contextlib import suppress
from datetime import date
from time import perf_counter
from typing import Any, Protocol

from ..db import Database
from ..observability.live_tracing import TraceLevel
from ..observability.projections import OwnerProjectionWriter
from ..orchestration.object_store import EncryptedObjectStore
from .adapters import FetchPlan, LegislationGovUkAdapter, adapter_registry
from .control_plane import ResearchControlPlane, scrub_candidate_url
from .fetch_policy import AddressResolver, SafeFetchPolicy
from .models import (
    OWNER_DECISION_REQUIRED,
    ResearchCandidateDraft,
    ResearchCandidateStatus,
    ResearchDispatchResult,
    ResearchPriority,
    ResearchTaskRequest,
    ResearchTaskType,
    ResearchTrigger,
)
from .runtime import (
    AllowlistedHttpFetcher,
    OfficialFetcher,
    OnlineFetchError,
    _parse_atom_candidates,
)
from .source_registry import ContentMode, OfficialSourceRegistry


class TransientResearchError(RuntimeError):
    def __init__(self, code: str, *, retry_after_seconds: int = 60) -> None:
        self.code = code
        self.retry_after_seconds = retry_after_seconds
        super().__init__(code)


class PermanentResearchError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _projection_trace_id(task: Mapping[str, Any]) -> str:
    task_id = str(task.get("id") or "unadmitted")
    digest = hashlib.sha256(f"legalbot-research-trace-v1\0{task_id}".encode()).hexdigest()
    return f"trace-research-{digest[:40]}"


def _projection_event_id(task: Mapping[str, Any], stage: str, *, suffix: str = "event") -> str:
    material = "\0".join(
        (
            "legalbot-research-event-v1",
            str(task.get("id") or "unadmitted"),
            str(task.get("attempt_count") or 0),
            stage,
            suffix,
        )
    )
    return f"event-research-{hashlib.sha256(material.encode()).hexdigest()[:40]}"


def _projection_authority_id(value: Any) -> str | None:
    public_identity = " ".join(str(value or "").split())
    if not public_identity:
        return None
    digest = hashlib.sha256(public_identity.encode("utf-8")).hexdigest()
    return f"authority-{digest[:40]}"


def _projection_error_code(value: Any) -> str:
    code = str(value or "research_error")
    if (
        code
        and len(code) <= 128
        and all(character.isalnum() or character in "._:-" for character in code)
    ):
        return code
    digest = hashlib.sha256(code.encode("utf-8")).hexdigest()
    return f"research-error-{digest[:24]}"


def _project_trace(
    writer: OwnerProjectionWriter | None,
    task: Mapping[str, Any],
    *,
    stage: str,
    status: str,
    duration_ms: float,
    suffix: str = "event",
    candidate_id: str | None = None,
    level: TraceLevel = TraceLevel.INFO,
    error_code: str | None = None,
    force: bool = False,
) -> None:
    """Best-effort projection; observability can never change task state."""

    if writer is None:
        return
    with suppress(Exception):
        writer.append_research_trace(
            trace_id=_projection_trace_id(task),
            event_id=_projection_event_id(task, stage, suffix=suffix),
            stage=stage,
            status=status,
            duration_ms=max(0.0, duration_ms),
            task_id=str(task.get("id") or "") or None,
            candidate_id=candidate_id,
            source_id=str(task.get("source_id") or "") or None,
            authority_identity_id=_projection_authority_id(task.get("authority_identity_id")),
            task_type=str(task.get("task_type") or "") or None,
            priority=str(task.get("priority_band") or "") or None,
            level=level,
            error_code=_projection_error_code(error_code) if error_code else None,
            force=force,
        )


def _project_metric(
    writer: OwnerProjectionWriter | None,
    task: Mapping[str, Any],
    *,
    metric: str,
    value: float,
    suffix: str,
    status: str | None = None,
) -> None:
    if writer is None:
        return
    with suppress(Exception):
        writer.append_research_metric(
            metric=metric,
            value=max(0.0, value),
            event_id=_projection_event_id(task, metric, suffix=suffix),
            task_type=str(task.get("task_type") or "") or None,
            priority=str(task.get("priority_band") or "") or None,
            status=status,
        )


def _project_queue_snapshot(
    writer: OwnerProjectionWriter | None,
    database: Database,
    task: Mapping[str, Any],
    *,
    suffix: str,
) -> None:
    if writer is None:
        return
    try:
        snapshot = database.research_queue_telemetry()
        running = sum(int(values["running"]) for values in snapshot["by_priority"].values())
        measurements = {
            "queue_depth": float(snapshot["active_depth"]),
            "retries_total": float(snapshot["retries_total"]),
            "terminal_total": float(snapshot["terminal_total"]),
            "worker_utilisation": min(1.0, running / 2.0),
        }
        if snapshot["oldest_task_age_seconds"] is not None:
            measurements["oldest_task_age_seconds"] = float(snapshot["oldest_task_age_seconds"])
        for metric, value in measurements.items():
            _project_metric(
                writer,
                task,
                metric=metric,
                value=value,
                suffix=f"{suffix}-{metric}",
                status=str(task.get("status") or "queued"),
            )
    except Exception:
        # The durable SQLite state is authoritative. Projection failure is not
        # allowed to fail admission, fetching, staging or task completion.
        return


class ResearchQuarantine(Protocol):
    def store(
        self,
        *,
        source_id: str,
        source_identity: str,
        content: bytes,
        content_sha256: str,
    ) -> str: ...


class EncryptedResearchQuarantine:
    """Stores fetched bytes encrypted in the existing local object store."""

    def __init__(self, store: EncryptedObjectStore) -> None:
        self.object_store = store

    def store(
        self,
        *,
        source_id: str,
        source_identity: str,
        content: bytes,
        content_sha256: str,
    ) -> str:
        if hashlib.sha256(content).hexdigest() != content_sha256:
            raise RuntimeError("research quarantine content hash mismatch")
        return self.object_store.put_json(
            namespace="research_candidates",
            value={
                "source_id": source_id,
                "source_identity": source_identity,
                "content_sha256": content_sha256,
                "content_base64": base64.b64encode(content).decode("ascii"),
            },
            metadata={"source_id": source_id, "content_sha256": content_sha256},
            ttl_days=30,
        )


class ResearchDispatcher(Protocol):
    async def dispatch(self, task: Mapping[str, Any]) -> ResearchDispatchResult: ...


class OfficialResearchDispatcher:
    """Fetch registered official candidates and stage hashes/bytes for review only."""

    def __init__(
        self,
        control: ResearchControlPlane,
        *,
        registry: OfficialSourceRegistry | None = None,
        fetcher: OfficialFetcher | None = None,
        quarantine: ResearchQuarantine | None = None,
        fetch_policy: SafeFetchPolicy | None = None,
        resolver: AddressResolver | None = None,
        projections: OwnerProjectionWriter | None = None,
    ) -> None:
        self.control = control
        self.registry = registry or control.registry
        self.adapters = adapter_registry(self.registry)
        self.quarantine = quarantine
        self.fetch_policy = fetch_policy or SafeFetchPolicy()
        self.resolver = resolver
        self.fetcher = fetcher or AllowlistedHttpFetcher(
            fetch_policy=self.fetch_policy,
            resolver=self.resolver,
        )
        self.projections = projections

    async def dispatch(self, task: Mapping[str, Any]) -> ResearchDispatchResult:
        try:
            self.control.assert_task_gap_open(task)
        except ValueError as exc:
            raise PermanentResearchError("knowledge_gap_not_open_at_dispatch") from exc
        task_type = ResearchTaskType(str(task["task_type"]))
        if task_type is ResearchTaskType.SOURCE_UPDATE_CHECK:
            return await self._update(task)
        if task_type in {ResearchTaskType.GAP_RESEARCH, ResearchTaskType.BROAD_DISCOVERY}:
            return await self._discover(task)
        raise PermanentResearchError("research_task_type_not_registered")

    async def _fetch(self, plan: FetchPlan, source_id: str, task: Mapping[str, Any]) -> Any:
        policy = self.registry.get(source_id)
        stage = "validation"
        suffix = "request"
        started = perf_counter()
        try:
            self.fetch_policy.validate_plan(plan, policy)
            await self.fetch_policy.validate_resolution(plan, policy, resolver=self.resolver)
            duration_ms = (perf_counter() - started) * 1_000
            _project_trace(
                self.projections,
                task,
                stage=stage,
                status="ok",
                duration_ms=duration_ms,
                suffix=suffix,
            )
            _project_metric(
                self.projections,
                task,
                metric="validation_duration_seconds",
                value=duration_ms / 1_000,
                suffix=suffix,
                status="ok",
            )
            stage = "fetch"
            suffix = "response"
            started = perf_counter()
            response = await self.fetcher.fetch(plan, policy)
            duration_ms = (perf_counter() - started) * 1_000
            _project_trace(
                self.projections,
                task,
                stage=stage,
                status="ok",
                duration_ms=duration_ms,
                suffix=suffix,
            )
            _project_metric(
                self.projections,
                task,
                metric="fetch_duration_seconds",
                value=duration_ms / 1_000,
                suffix=suffix,
                status="ok",
            )
            stage = "validation"
            suffix = "response"
            started = perf_counter()
            final_plan = FetchPlan(
                source_id=source_id,
                url=response.url,
                expected_content_mode=plan.expected_content_mode,
                headers=plan.headers,
            )
            self.fetch_policy.validate_plan(final_plan, policy)
            self.fetch_policy.validate_response_headers(response.headers)
            duration_ms = (perf_counter() - started) * 1_000
            _project_trace(
                self.projections,
                task,
                stage=stage,
                status="ok",
                duration_ms=duration_ms,
                suffix=suffix,
            )
            _project_metric(
                self.projections,
                task,
                metric="validation_duration_seconds",
                value=duration_ms / 1_000,
                suffix=suffix,
                status="ok",
            )
            return response
        except OnlineFetchError as exc:
            duration_ms = (perf_counter() - started) * 1_000
            _project_trace(
                self.projections,
                task,
                stage=stage,
                status="error",
                duration_ms=duration_ms,
                suffix=suffix,
                level=TraceLevel.ERROR,
                error_code=exc.code,
            )
            _project_metric(
                self.projections,
                task,
                metric=(
                    "fetch_duration_seconds" if stage == "fetch" else "validation_duration_seconds"
                ),
                value=duration_ms / 1_000,
                suffix=f"{suffix}-error",
                status="error",
            )
            if exc.code in {
                "official_network_unavailable",
                "official_http_status_429",
                "official_http_status_500",
                "official_http_status_502",
                "official_http_status_503",
                "official_http_status_504",
            }:
                raise TransientResearchError(
                    exc.code, retry_after_seconds=exc.retry_after_seconds or 60
                ) from exc
            raise PermanentResearchError(exc.code) from exc
        except ValueError as exc:
            duration_ms = (perf_counter() - started) * 1_000
            _project_trace(
                self.projections,
                task,
                stage=stage,
                status="error",
                duration_ms=duration_ms,
                suffix=suffix,
                level=TraceLevel.ERROR,
                error_code="fetch_policy_rejected",
            )
            _project_metric(
                self.projections,
                task,
                metric=(
                    "fetch_duration_seconds" if stage == "fetch" else "validation_duration_seconds"
                ),
                value=duration_ms / 1_000,
                suffix=f"{suffix}-error",
                status="error",
            )
            raise PermanentResearchError(str(exc)) from exc

    def _compare(
        self,
        task: Mapping[str, Any],
        *,
        source_id: str,
        authority_identity_id: str,
        remote_content_sha256: str | None,
        withdrawn: bool = False,
    ) -> Any:
        started = perf_counter()
        try:
            update = self.control.compare_remote(
                task,
                source_id=source_id,
                authority_identity_id=authority_identity_id,
                remote_content_sha256=remote_content_sha256,
                withdrawn=withdrawn,
            )
        except Exception as exc:
            duration_ms = (perf_counter() - started) * 1_000
            _project_trace(
                self.projections,
                task,
                stage="active_comparison",
                status="error",
                duration_ms=duration_ms,
                level=TraceLevel.ERROR,
                error_code=type(exc).__name__,
            )
            _project_metric(
                self.projections,
                task,
                metric="comparison_duration_seconds",
                value=duration_ms / 1_000,
                suffix="error",
                status="error",
            )
            raise
        duration_ms = (perf_counter() - started) * 1_000
        _project_trace(
            self.projections,
            task,
            stage="active_comparison",
            status=update.comparison_state.value,
            duration_ms=duration_ms,
        )
        _project_metric(
            self.projections,
            task,
            metric="comparison_duration_seconds",
            value=duration_ms / 1_000,
            suffix=update.comparison_state.value,
            status=update.comparison_state.value,
        )
        return update

    async def _update(self, task: Mapping[str, Any]) -> ResearchDispatchResult:
        source_id = str(task.get("source_id") or "")
        authority_identity = str(task.get("authority_identity_id") or "")
        if not source_id or not authority_identity:
            raise PermanentResearchError("source_update_identity_missing")
        policy = self.registry.get(source_id)
        identity = str(task.get("source_locator") or "") or _adapter_identity(
            source_id, authority_identity
        )
        adapter = self.adapters[source_id]
        if policy.content_mode is not ContentMode.FULL_TEXT:
            plan = adapter.plan(identity)
            self.fetch_policy.validate_plan(plan, policy)
            rights_state = (
                "metadata_only"
                if policy.content_mode is ContentMode.METADATA_ONLY
                else "item_licence_required"
            )
            safe_metadata = {
                "disposition": "staged_only",
                "network_fetch": "not_permitted_without_reviewed_content_rights",
                "owner_decision_required": True,
            }
            candidate = ResearchCandidateDraft(
                source_id=source_id,
                source_identity=authority_identity,
                canonical_url=scrub_candidate_url(plan.url),
                metadata_sha256=hashlib.sha256(
                    json.dumps(safe_metadata, sort_keys=True).encode("utf-8")
                ).hexdigest(),
                status=ResearchCandidateStatus.DETECTED,
                rights_state=rights_state,
                safe_metadata=safe_metadata,
            )
            update = self._compare(
                task,
                source_id=source_id,
                authority_identity_id=authority_identity,
                remote_content_sha256=None,
            )
            return ResearchDispatchResult(
                candidates=(candidate,),
                updates=(update,),
                requires_review=True,
                safe_reason=OWNER_DECISION_REQUIRED,
                owner_decision_required=True,
            )
        try:
            response = await self._fetch(adapter.plan(identity), source_id, task)
        except PermanentResearchError as exc:
            if exc.code not in {"official_http_status_404", "official_http_status_410"}:
                raise
            update = self._compare(
                task,
                source_id=source_id,
                authority_identity_id=authority_identity,
                remote_content_sha256=None,
                withdrawn=True,
            )
            return ResearchDispatchResult(
                updates=(update,),
                requires_review=True,
                safe_reason=OWNER_DECISION_REQUIRED,
                owner_decision_required=True,
            )
        digest = hashlib.sha256(response.content).hexdigest()
        canonical_url = scrub_candidate_url(response.url)
        update = self._compare(
            task,
            source_id=source_id,
            authority_identity_id=authority_identity,
            remote_content_sha256=digest,
        )
        if update.comparison_state.value == "unchanged" and not update.stale_active:
            return ResearchDispatchResult(
                updates=(update,),
                requires_review=False,
                safe_reason="official_source_unchanged",
            )
        object_key: str | None = None
        candidate_content_sha: str | None = None
        rights_state = "unreviewed"
        if policy.content_mode is ContentMode.FULL_TEXT:
            if self.quarantine is None:
                raise PermanentResearchError("encrypted_research_quarantine_unavailable")
            started = perf_counter()
            try:
                object_key = self.quarantine.store(
                    source_id=source_id,
                    source_identity=authority_identity,
                    content=response.content,
                    content_sha256=digest,
                )
            except Exception as exc:
                _project_trace(
                    self.projections,
                    task,
                    stage="quarantine",
                    status="error",
                    duration_ms=(perf_counter() - started) * 1_000,
                    level=TraceLevel.ERROR,
                    error_code=type(exc).__name__,
                )
                raise
            _project_trace(
                self.projections,
                task,
                stage="quarantine",
                status="ok",
                duration_ms=(perf_counter() - started) * 1_000,
            )
            candidate_content_sha = digest
        safe_metadata = {
            "content_type": response.headers.get("content-type", "").split(";", 1)[0],
            "disposition": "staged_only",
            "response_sha256": digest,
            "owner_decision_required": True,
        }
        metadata_sha = hashlib.sha256(
            json.dumps(safe_metadata, sort_keys=True).encode("utf-8")
        ).hexdigest()
        candidate = ResearchCandidateDraft(
            source_id=source_id,
            source_identity=authority_identity,
            canonical_url=canonical_url,
            metadata_sha256=metadata_sha,
            content_sha256=candidate_content_sha,
            content_object_key=object_key,
            status=(
                ResearchCandidateStatus.QUARANTINED
                if object_key
                else ResearchCandidateStatus.FETCHED
            ),
            rights_state=rights_state,
            safe_metadata=safe_metadata,
        )
        return ResearchDispatchResult(
            candidates=(candidate,),
            updates=(update,),
            requires_review=True,
            safe_reason=OWNER_DECISION_REQUIRED,
            owner_decision_required=True,
        )

    async def _discover(self, task: Mapping[str, Any]) -> ResearchDispatchResult:
        source_id = str(task.get("source_id") or "")
        if not source_id:
            raise PermanentResearchError("official_discovery_source_missing")
        if source_id != "legislation_gov_uk":
            raise PermanentResearchError("official_discovery_adapter_not_registered")
        adapter = self.adapters[source_id]
        if not isinstance(adapter, LegislationGovUkAdapter):
            raise PermanentResearchError("legislation_discovery_adapter_missing")
        subject = " ".join(str(task.get("subject") or "general").split())
        if not subject or len(subject) > 80:
            raise PermanentResearchError("official_discovery_subject_invalid")
        try:
            as_of = date.fromisoformat(str(task["as_of_date"]))
        except ValueError as exc:
            raise PermanentResearchError("official_discovery_date_invalid") from exc
        response = await self._fetch(
            adapter.search_plan(subject, as_of_date=as_of, title_search=False, results_count=10),
            source_id,
            task,
        )
        validation_started = perf_counter()
        try:
            candidates = _parse_atom_candidates(response.content, subject, False)
        except Exception as exc:
            _project_trace(
                self.projections,
                task,
                stage="validation",
                status="error",
                duration_ms=(perf_counter() - validation_started) * 1_000,
                suffix="candidate-parse",
                level=TraceLevel.ERROR,
                error_code=type(exc).__name__,
            )
            raise
        _project_trace(
            self.projections,
            task,
            stage="validation",
            status="ok",
            duration_ms=(perf_counter() - validation_started) * 1_000,
            suffix="candidate-parse",
        )
        drafts: list[ResearchCandidateDraft] = []
        for candidate in candidates[:20]:
            safe_metadata = {
                "disposition": "staged_only",
                "title_sha256": hashlib.sha256(candidate.title.encode("utf-8")).hexdigest(),
                "owner_decision_required": True,
            }
            drafts.append(
                ResearchCandidateDraft(
                    source_id=source_id,
                    source_identity=candidate.identity,
                    canonical_url=candidate.canonical_url,
                    metadata_sha256=hashlib.sha256(
                        json.dumps(safe_metadata, sort_keys=True).encode("utf-8")
                    ).hexdigest(),
                    status=ResearchCandidateStatus.DETECTED,
                    safe_metadata=safe_metadata,
                )
            )
        return ResearchDispatchResult(
            candidates=tuple(drafts),
            requires_review=bool(drafts),
            safe_reason=(OWNER_DECISION_REQUIRED if drafts else "official_discovery_no_candidates"),
            owner_decision_required=bool(drafts),
        )


def _adapter_identity(source_id: str, authority_identity: str) -> str:
    if source_id == "legislation_gov_uk" and ":" in authority_identity:
        return authority_identity.replace(":", "/")
    return authority_identity


class ResearchWorker:
    def __init__(
        self,
        database: Database,
        control: ResearchControlPlane,
        dispatcher: ResearchDispatcher,
        *,
        worker_id: str | None = None,
        lease_seconds: int = 60,
        poll_seconds: float = 0.5,
        max_concurrency: int = 2,
        projections: OwnerProjectionWriter | None = None,
    ) -> None:
        if max_concurrency != 2:
            raise ValueError("research worker concurrency is fixed at two")
        self.database = database
        self.control = control
        self.dispatcher = dispatcher
        self.worker_id = worker_id or f"research-{socket.gethostname()}-{os.getpid()}"
        self.lease_seconds = lease_seconds
        self.poll_seconds = poll_seconds
        self.max_concurrency = max_concurrency
        self.projections = projections
        self._stop = asyncio.Event()

    def stop(self) -> None:
        self._stop.set()

    async def run_once(self) -> bool:
        row = self.database.claim_research_task(self.worker_id, lease_seconds=self.lease_seconds)
        if row is None:
            return False
        claimed_task = dict(row)
        _project_trace(
            self.projections,
            claimed_task,
            stage="worker_claim",
            status="running",
            duration_ms=0,
            force=True,
        )
        _project_queue_snapshot(
            self.projections, self.database, claimed_task, suffix="worker-claim"
        )
        await self._run_claim(claimed_task)
        return True

    async def run_forever(self) -> None:
        active: set[asyncio.Task[None]] = set()
        while not self._stop.is_set() or active:
            self.database.pulse_service(
                "research-worker",
                self.worker_id,
                {"fetch_concurrency": 2, "per_origin_concurrency": 1},
            )
            while not self._stop.is_set() and len(active) < self.max_concurrency:
                row = self.database.claim_research_task(
                    self.worker_id, lease_seconds=self.lease_seconds
                )
                if row is None:
                    break
                claimed_task = dict(row)
                _project_trace(
                    self.projections,
                    claimed_task,
                    stage="worker_claim",
                    status="running",
                    duration_ms=0,
                    force=True,
                )
                _project_queue_snapshot(
                    self.projections,
                    self.database,
                    claimed_task,
                    suffix="worker-claim",
                )
                active.add(asyncio.create_task(self._run_claim(claimed_task)))
            if not active:
                with suppress(TimeoutError):
                    await asyncio.wait_for(self._stop.wait(), timeout=self.poll_seconds)
                continue
            done, pending = await asyncio.wait(
                active,
                timeout=self.poll_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
            active = set(pending)
            for completed_task in done:
                completed_task.result()

    async def _run_claim(self, task: dict[str, Any]) -> None:
        task_id = str(task["id"])
        task_started = perf_counter()
        heartbeat = asyncio.create_task(self._heartbeat(task_id))
        try:
            dispatch = asyncio.create_task(self.dispatcher.dispatch(task))
            done, _ = await asyncio.wait({dispatch, heartbeat}, return_when=asyncio.FIRST_COMPLETED)
            if heartbeat in done:
                heartbeat.result()
                dispatch.cancel()
                with suppress(asyncio.CancelledError):
                    await dispatch
                raise RuntimeError("research lease heartbeat stopped")
            result = await dispatch
            candidate_ids: dict[tuple[str, str], str] = {}
            for ordinal, draft in enumerate(result.candidates, start=1):
                stage_started = perf_counter()
                row = self.control.stage_candidate(task_id, draft)
                candidate_ids[(draft.source_id, draft.source_identity)] = str(row["id"])
                _project_trace(
                    self.projections,
                    task,
                    stage="stage",
                    status="ok",
                    duration_ms=(perf_counter() - stage_started) * 1_000,
                    suffix=f"candidate-{ordinal}",
                    candidate_id=str(row["id"]),
                )
            if candidate_ids:
                _project_metric(
                    self.projections,
                    task,
                    metric="candidates_total",
                    value=float(len(candidate_ids)),
                    suffix="staged",
                    status="ok",
                )
            observation_ids: list[str] = []
            for update in result.updates:
                candidate_id = candidate_ids.get((update.source_id, update.authority_identity_id))
                observation_ids.append(
                    self.control.persist_update(task, update, candidate_id=candidate_id)
                )
                if update.stale_active:
                    self._enqueue_recomparison(task, update.source_id)
            if result.requires_review:
                review_started = perf_counter()
                self._link_refinement(
                    task,
                    candidate_ids=tuple(candidate_ids.values()),
                    observation_ids=tuple(observation_ids),
                )
                _project_trace(
                    self.projections,
                    task,
                    stage="review_link",
                    status="review_required",
                    duration_ms=(perf_counter() - review_started) * 1_000,
                )
            terminal_status = "review_required" if result.requires_review else "completed"
            self.database.finish_research_task(
                task_id,
                self.worker_id,
                status=terminal_status,
                reason=result.safe_reason,
            )
            _project_trace(
                self.projections,
                task,
                stage="complete",
                status=terminal_status,
                duration_ms=(perf_counter() - task_started) * 1_000,
                force=True,
            )
            _project_metric(
                self.projections,
                task,
                metric="terminal_total",
                value=1,
                suffix=terminal_status,
                status=terminal_status,
            )
        except TransientResearchError as exc:
            retry_status = self.database.retry_or_fail_research_task(
                task_id,
                self.worker_id,
                reason=exc.code,
                retryable=True,
                retry_after_seconds=exc.retry_after_seconds,
            )
            _project_trace(
                self.projections,
                task,
                stage="complete",
                status=retry_status,
                duration_ms=(perf_counter() - task_started) * 1_000,
                level=TraceLevel.WARN if retry_status == "retry_wait" else TraceLevel.ERROR,
                error_code=exc.code,
                force=True,
            )
            _project_metric(
                self.projections,
                task,
                metric=("retries_total" if retry_status == "retry_wait" else "terminal_total"),
                value=1,
                suffix=retry_status,
                status=retry_status,
            )
        except PermanentResearchError as exc:
            terminal_status = self.database.retry_or_fail_research_task(
                task_id,
                self.worker_id,
                reason=exc.code,
                retryable=False,
            )
            _project_trace(
                self.projections,
                task,
                stage="complete",
                status=terminal_status,
                duration_ms=(perf_counter() - task_started) * 1_000,
                level=TraceLevel.ERROR,
                error_code=exc.code,
                force=True,
            )
            _project_metric(
                self.projections,
                task,
                metric="terminal_total",
                value=1,
                suffix=terminal_status,
                status=terminal_status,
            )
        except Exception as exc:
            retry_status = self.database.retry_or_fail_research_task(
                task_id,
                self.worker_id,
                reason=type(exc).__name__,
                retryable=True,
                retry_after_seconds=60,
            )
            _project_trace(
                self.projections,
                task,
                stage="complete",
                status=retry_status,
                duration_ms=(perf_counter() - task_started) * 1_000,
                level=TraceLevel.ERROR,
                error_code=type(exc).__name__,
                force=True,
            )
            _project_metric(
                self.projections,
                task,
                metric=("retries_total" if retry_status == "retry_wait" else "terminal_total"),
                value=1,
                suffix=retry_status,
                status=retry_status,
            )
        finally:
            heartbeat.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await heartbeat
            self.database.release_research_task_lease(task_id, self.worker_id)
            final = self.database.research_task(task_id)
            _project_queue_snapshot(
                self.projections,
                self.database,
                dict(final) if final is not None else task,
                suffix="worker-finish",
            )

    def _link_refinement(
        self,
        task: Mapping[str, Any],
        *,
        candidate_ids: tuple[str, ...],
        observation_ids: tuple[str, ...],
    ) -> None:
        task_id = str(task["id"])
        safe_target = {
            "research_task_id": task_id,
            "candidate_ids": list(candidate_ids),
            "source_update_observation_ids": list(observation_ids),
        }
        existing_id = str(task.get("refinement_id") or "")
        if existing_id:
            row = self.database.fetchone(
                "SELECT status FROM refinements WHERE id=?", (existing_id,)
            )
            if row is None:
                raise RuntimeError("research task refinement link is invalid")
            self.database.transition_refinement(
                existing_id,
                to_status=str(row["status"]),
                event_type="research_candidates_staged",
                safe_payload=safe_target,
            )
            return
        digest = hashlib.sha256(f"research-refinement-v1\0{task_id}".encode()).hexdigest()
        refinement_id = f"refinement-{digest[:40]}"
        self.database.create_refinement(
            refinement_id=refinement_id,
            fingerprint=f"research-task:{task_id}",
            category="missing",
            scope="source",
            priority=int(task["base_priority"]),
            origin="research_worker",
            answer_id=str(task.get("answer_id") or "") or None,
            job_id=str(task.get("answer_job_id") or "") or None,
            knowledge_gap_id=str(task.get("knowledge_gap_id") or "") or None,
            research_task_id=task_id,
            safe_target=safe_target,
        )
        self.database.link_research_task_refinement(task_id, refinement_id)

    def _enqueue_recomparison(self, task: Mapping[str, Any], source_id: str) -> None:
        snapshot = self.control.active_snapshot()
        key_material = "\0".join(
            (
                "research-active-recompare-v1",
                str(task["id"]),
                snapshot.build_id or "none",
                snapshot.source_manifest_sha256 or "none",
            )
        )
        key = hashlib.sha256(key_material.encode()).hexdigest()
        self.control.admit(
            ResearchTaskRequest(
                task_type=ResearchTaskType.SOURCE_UPDATE_CHECK,
                trigger=ResearchTrigger(str(task["trigger_kind"])),
                priority=ResearchPriority(str(task["priority_band"])),
                subject=str(task["subject"]),
                jurisdiction=str(task["jurisdiction"]),
                as_of_date=date.fromisoformat(str(task["as_of_date"])),
                source_id=source_id,
                authority_identity_id=str(task.get("authority_identity_id") or "") or None,
                source_locator=str(task.get("source_locator") or "") or None,
                knowledge_gap_id=str(task.get("knowledge_gap_id") or "") or None,
                answer_id=str(task.get("answer_id") or "") or None,
                answer_job_id=str(task.get("answer_job_id") or "") or None,
                refinement_id=str(task.get("refinement_id") or "") or None,
                query_sha256=str(task["query_sha256"]),
                idempotency_key=f"recompare:{key}",
            )
        )

    async def _heartbeat(self, task_id: str) -> None:
        interval = max(2, self.lease_seconds // 3)
        while True:
            await asyncio.sleep(interval)
            if not self.database.heartbeat_research_task(
                task_id,
                self.worker_id,
                lease_seconds=self.lease_seconds,
            ):
                raise RuntimeError("research task lease was lost")
