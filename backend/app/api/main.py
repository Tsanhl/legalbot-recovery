from __future__ import annotations

import asyncio
import hashlib
import json
import re
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from dataclasses import asdict
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from time import perf_counter
from typing import Any, Literal, cast
from uuid import uuid4
from zoneinfo import ZoneInfo

from fastapi import (
    BackgroundTasks,
    FastAPI,
    File,
    HTTPException,
    Request,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, ORJSONResponse
from sse_starlette.sse import EventSourceResponse

from ..assessment.guidance_bundle import OWNER_ASSESSMENT_BUNDLE
from ..config import settings
from ..db import JobQueueCapacityError, SourceScanConflictError, SourceScanStateError
from ..evaluation.live_suite_admission import (
    Live60AdmissionBinding,
    Live60EvaluationAdmissionBinding,
    validate_live60_api_admission,
)
from ..evaluation.owner_quality_canary_runtime import (
    OwnerCanaryAdmissionBinding,
    build_owner_canary_runtime_attempt_envelope,
    owner_canary_idempotency_key,
    validate_owner_canary_api_admission,
)
from ..orchestration.classifier import CLASSIFIER_VERSION, classify_task
from ..orchestration.refinements import RefinementService
from ..orchestration.routing import ROUTER_VERSION, decide_route
from ..orchestration.upload_vault import read_upload, write_encrypted_upload
from ..orchestration.uploads import (
    UploadReferenceError,
    submit_upload_for_source_review,
    validate_upload_media,
    validate_upload_references,
)
from ..privacy import safe_source_name, safe_summary, scrub_pii, scrub_prompt_data
from ..quality.policy import POLICY_SHA256
from ..retrieval.diagnostic_slice import allowed_index_statuses_for_pin
from ..runtime_adapters import PROMPT_VERSION
from ..services import Services, build_services
from ..source_diagnostics import safe_exclusion_payload
from ..types import (
    CasePropositionReview,
    EvaluationIssueRequest,
    HealthView,
    JobStage,
    JobStatus,
    JobView,
    KnowledgeUpdateWebhookRequest,
    ObservabilityAdminView,
    ObservabilityTraceView,
    QuestionAccepted,
    QuestionRequest,
    RefinementTransitionRequest,
    ReleaseState,
    ResearchCandidateReviewRequest,
    ResearchCheckNowRequest,
    ReviewDecisionRequest,
    SourceUpdateResolutionRequest,
    SourceUpdateReviewRequest,
)
from .deps import row as request_row
from .routers import evaluation_router, feedback_router, incidents_router
from .routers.evaluation import (
    admin_live_evaluation,
    admin_live_evaluation_released_answer,
    admin_live_evaluations,
)
from .routers.feedback import create_answer_feedback
from .routers.incidents import admin_runtime_records

API_VERSION = "v1"
MAX_UPLOAD_BYTES = 100 * 1024 * 1024
WEB_DIST = settings.project_root / "web" / "dist"
ADMIN_REVIEW_DEFAULT_LIMIT = 50
ADMIN_REVIEW_MAX_LIMIT = 100
ADMIN_REVIEW_MAX_OFFSET = 2_147_483_647
_ADMIN_REVIEW_FILTER = re.compile(r"[a-z][a-z0-9_]{0,63}")
_ADMIN_REVIEW_STATUSES = frozenset({"pending", "approved", "rejected"})
PUBLIC_RELEASE_STATES = frozenset(
    {
        ReleaseState.VERIFIED_FULL.value,
    }
)
NORMAL_LIVE_CONTENT_CERTIFICATION_STOP = "normal_live_release_content_certification_missing"
SUPERSEDED_EVALUATION_CONTENT_CERTIFICATION_STOP = (
    "superseded_evaluation_release_content_certification_missing"
)
__all__ = [
    "admin_live_evaluation",
    "admin_live_evaluation_released_answer",
    "admin_live_evaluations",
    "admin_runtime_records",
    "app",
    "create_answer_feedback",
]
LONDON = ZoneInfo("Europe/London")


def _frozen_job_request(
    payload: QuestionRequest,
    *,
    admitted_on: date | None = None,
) -> dict[str, Any]:
    """Persist a complete request snapshot at admission time.

    ``as_of_date`` is part of the legal/retrieval snapshot.  Resolving a missing
    value later in a worker would allow a queued job to change meaning across a
    date boundary, so admission freezes the London civil date explicitly.
    """

    request = payload.model_dump(mode="json", exclude={"question"})
    effective_date = payload.as_of_date or admitted_on or datetime.now(LONDON).date()
    request["as_of_date"] = effective_date.isoformat()
    return request


_ALLOWED_BROWSER_ORIGINS = frozenset(
    {
        "http://127.0.0.1:8777",
        "http://localhost:8777",
        "http://127.0.0.1:3000",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    }
)
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_PUBLIC_DOI = re.compile(r"10\.\d{4,9}/[-._;()/:a-z0-9]+", re.IGNORECASE)
_PUBLIC_NEUTRAL_CITATION = re.compile(
    r"\[(?:19|20)\d{2}\]\s+(?:(?:UKSC|UKHL|UKPC|EWCA\s+(?:CIV|CRIM)|UKUT|UKFTT|EUECJ)\s+\d+|EWHC\s+\d+\s+\([A-Z]+\))",
    re.IGNORECASE,
)

# Only bibliographic values required to identify or deterministically re-render
# a citation may leave the evidence store.  In particular, URL/access-token
# fields and arbitrary nested source metadata are never mirrored into the
# normal answer DTO.  Web-only citations intentionally fall back to the
# already reviewed ``canonical_citation`` string.
_SAFE_EVIDENCE_CITATION_FIELDS: dict[str, frozenset[str]] = {
    "case": frozenset(
        {
            "source_type",
            "case_name",
            "title",
            "neutral_citation",
            "report_citation",
            "decision_date",
            "neutral_court_identifier",
            "court_identifier",
            "court_identifier_not_required",
            "pinpoint_type",
        }
    ),
    "legislation": frozenset({"source_type", "title", "provision"}),
    "statutory_instrument": frozenset({"source_type", "title", "instrument_number", "provision"}),
    "rule": frozenset({"source_type", "title", "provision"}),
    "journal": frozenset(
        {
            "source_type",
            "author",
            "title",
            "journal",
            "year",
            "year_format",
            "volume",
            "issue",
            "first_page",
            "online_only",
        }
    ),
    "book": frozenset(
        {
            "source_type",
            "author",
            "title",
            "publisher",
            "year",
            "translator",
            "editor",
            "additional_information",
            "edition",
            "volume",
        }
    ),
    "book_chapter": frozenset(
        {
            "source_type",
            "author",
            "title",
            "editor",
            "editor_role",
            "book_title",
            "publisher",
            "year",
            "additional_information",
            "edition",
        }
    ),
    "official_guidance": frozenset(
        {
            "source_type",
            "author_or_body",
            "title",
            "publication_date",
            "title_style",
        }
    ),
    "report": frozenset(
        {
            "source_type",
            "report_type",
            "author_or_body",
            "title",
            "report_number",
            "year",
            "additional_information",
            "session",
            "paper_number",
            "publication_date",
            "title_style",
        }
    ),
    "parliamentary": frozenset(
        {
            "source_type",
            "parliamentary_type",
            "house",
            "title",
            "date",
            "volume",
            "column",
            "columns",
        }
    ),
}
_SHA256_TEXT = re.compile(r"^[0-9a-f]{64}$")
_URL_LIKE_TEXT = re.compile(r"(?i)(?:https?|file)://")


def _source_scan_diagnostics(database: Any, scan_id: str) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for row in database.source_scan_exclusion_counts(scan_id):
        status_value = str(row["status"])
        safe = safe_exclusion_payload(status_value, row["reason"])
        if safe is None:
            continue
        key = (status_value, safe["reason_code"])
        existing = grouped.get(key)
        if existing is None:
            grouped[key] = {"status": status_value, "count": int(row["count"]), **safe}
        else:
            existing["count"] += int(row["count"])
    return [grouped[key] for key in sorted(grouped)]


def _safe_source_scan_file(row: Any) -> dict[str, Any]:
    item = _row(row)
    safe = safe_exclusion_payload(str(row["status"]), row["reason"])
    item.pop("reason", None)
    if safe is not None:
        item.update(safe)
    return item


def _safe_public_identifier_candidate(value: Any) -> dict[str, str] | None:
    """Expose only a parser-derived DOI or neutral citation for human-review prefill."""

    if not isinstance(value, dict):
        return None
    scheme = str(value.get("scheme") or "")
    public_value = " ".join(str(value.get("value") or "").split())
    stable_identifier = " ".join(str(value.get("stable_identifier") or "").split())
    if (
        scheme == "doi"
        and _PUBLIC_DOI.fullmatch(public_value)
        and stable_identifier == f"doi:{public_value}"
    ):
        return {
            "scheme": scheme,
            "value": public_value,
            "stable_identifier": stable_identifier,
        }
    if (
        scheme == "neutral_citation"
        and _PUBLIC_NEUTRAL_CITATION.fullmatch(public_value)
        and stable_identifier == f"neutral-citation:{public_value}"
    ):
        return {
            "scheme": scheme,
            "value": public_value,
            "stable_identifier": stable_identifier,
        }
    return None


def _clean_admin_review_filter(value: str | None, *, field: str) -> str | None:
    if value is None:
        return None
    cleaned = value.strip().lower()
    if not _ADMIN_REVIEW_FILTER.fullmatch(cleaned):
        raise HTTPException(422, f"Invalid {field} filter")
    if field == "status" and cleaned not in _ADMIN_REVIEW_STATUSES:
        raise HTTPException(422, "Review status must be pending, approved or rejected")
    return cleaned


def _services(request: Request | WebSocket) -> Services:
    return cast(Services, request.app.state.services)


def _conversation_id_for_job(services: Any, job_id: str) -> str | None:
    if getattr(services, "conversations", None) is None:
        return None
    row = services.database.fetchone(
        "SELECT conversation_id FROM conversation_job_bindings WHERE job_id=?",
        (job_id,),
    )
    return str(row["conversation_id"]) if row is not None else None


def _websocket_boundary_allowed(websocket: WebSocket) -> bool:
    """Mirror the current loopback Host/Origin boundary for non-HTTP middleware."""

    client = websocket.client.host if websocket.client else "unknown"
    if client not in {"127.0.0.1", "::1", "localhost", "testclient"}:
        return False
    host = websocket.headers.get("host", "").casefold()
    allowed_hosts = {
        f"{hostname}:{port}"
        for hostname in ("127.0.0.1", "localhost", "[::1]")
        for port in {settings.port, 8777, 3000, 5173}
    }
    if client == "testclient":
        allowed_hosts.add("testserver")
    origin = websocket.headers.get("origin")
    fetch_site = (websocket.headers.get("sec-fetch-site") or "").casefold()
    return bool(
        host in allowed_hosts
        and (origin is None or origin in _ALLOWED_BROWSER_ORIGINS)
        and fetch_site != "cross-site"
    )


def _row(row: Any) -> dict[str, Any]:
    return request_row(row)


def _owner_safe_summary(value: Any, *, owner_identifiers: tuple[str, ...], limit: int) -> str:
    """Keep normal admin JSON free of local owner identifiers."""

    return safe_summary(scrub_pii(str(value or ""), owner_identifiers), limit)


def _safe_evidence_citation_data(
    value: Any, *, owner_identifiers: tuple[str, ...]
) -> dict[str, str | int | float | bool]:
    """Return a flat, URL-free allowlisted citation projection."""

    if not isinstance(value, dict):
        return {}
    source_type = " ".join(str(value.get("source_type") or "").split()).casefold()
    allowed = _SAFE_EVIDENCE_CITATION_FIELDS.get(source_type)
    if allowed is None:
        # A web citation requires a URL to re-render.  The reviewed canonical
        # citation remains available, but arbitrary URL metadata does not.
        return {}
    projected: dict[str, str | int | float | bool] = {}
    for key in sorted(allowed):
        raw = value.get(key)
        if isinstance(raw, bool | int | float):
            projected[key] = raw
            continue
        if not isinstance(raw, str):
            continue
        cleaned = " ".join(raw.split())
        if not cleaned or len(cleaned) > 1_000 or _URL_LIKE_TEXT.search(cleaned) is not None:
            continue
        if scrub_pii(cleaned, owner_identifiers) != cleaned:
            continue
        projected[key] = cleaned
    return projected


def _safe_case_currentness_reviews(value: Any) -> list[dict[str, str]]:
    """Project reviewed case status without reviewer identities or legal prose."""

    if not isinstance(value, list):
        raise ValueError("case-currentness review metadata is not a list")
    projected: list[dict[str, str]] = []
    for item in value:
        review = CasePropositionReview.model_validate(item)
        projected.append(
            {
                "exact_span_sha256": review.exact_span_sha256,
                "proposition_hash": review.proposition_hash,
                "legal_role": review.legal_role,
                "later_treatment_reviewed_as_of_date": (
                    review.later_treatment_reviewed_as_of_date.isoformat()
                ),
                "later_treatment_status": review.later_treatment_status,
                "reviewer_role": review.reviewer_role,
                "review_scope": review.review_scope,
                "second_review_status": review.second_review_status,
                "seal_sha256": review.seal_sha256,
            }
        )
    return projected


def _safe_sha256_list(value: Any, *, label: str) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or _SHA256_TEXT.fullmatch(item) is None for item in value
    ):
        raise ValueError(f"{label} is not a SHA-256 list")
    if len(value) != len(set(value)):
        raise ValueError(f"{label} contains duplicate seals")
    return list(value)


def _is_public_release(value: Any) -> bool:
    return isinstance(value, str) and value in PUBLIC_RELEASE_STATES


_OWNER_CANARY_RELEASED_JOB_MESSAGE = "Verified owner-evaluation answer is ready for private review."


def _is_released_owner_canary_job(job: Any) -> bool:
    if not _is_public_release(job["release_state"]):
        return False
    try:
        authority = json.loads(str(job["evaluation_authority_json"] or ""))
    except (TypeError, json.JSONDecodeError):
        return False
    return isinstance(authority, dict) and authority.get("lane") == "owner_quality_canary"


def _released_job_message(job: Any) -> str | None:
    if _is_released_owner_canary_job(job):
        return _OWNER_CANARY_RELEASED_JOB_MESSAGE
    value = job["user_message"]
    return None if value is None else str(value)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    services = build_services(settings)
    app.state.services = services
    services.database.purge_expired_unreleased_versions()
    services.database.fail_interrupted_source_scans()
    yield
    services.database.close()


app = FastAPI(
    title="LegalBot-New",
    version="0.1.0",
    default_response_class=ORJSONResponse,
    lifespan=lifespan,
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=sorted(_ALLOWED_BROWSER_ORIGINS),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=[
        "Content-Type",
        "Last-Event-ID",
        "X-Idempotency-Key",
        "X-Evaluation-Run-ID",
        "X-Evaluation-Case-ID",
        "X-Owner-Canary-Review-Date",
        "X-Owner-Canary-Run-ID",
        "X-Owner-Canary-Case-ID",
        "X-Owner-Canary-Attempt",
        "X-Owner-Canary-Input-Revision",
        "X-Owner-Canary-Request-Seal",
        "X-Owner-Canary-Lane",
    ],
)
app.include_router(evaluation_router)
app.include_router(feedback_router)
app.include_router(incidents_router)


@app.middleware("http")
async def owner_only_and_headers(request: Request, call_next: Any) -> Any:
    client = request.client.host if request.client else "unknown"
    if client not in {"127.0.0.1", "::1", "localhost", "testclient"}:
        return ORJSONResponse(
            {"detail": "LegalBot-New first release is loopback-only"}, status_code=403
        )
    host = request.headers.get("host", "").casefold()
    allowed_hosts = {
        f"{hostname}:{port}"
        for hostname in ("127.0.0.1", "localhost", "[::1]")
        for port in {settings.port, 8777, 3000, 5173}
    }
    if client == "testclient":
        allowed_hosts.add("testserver")
    if host not in allowed_hosts:
        return ORJSONResponse(
            {"detail": "LegalBot-New rejected an untrusted Host header"},
            status_code=400,
        )
    origin = request.headers.get("origin")
    fetch_site = (request.headers.get("sec-fetch-site") or "").casefold()
    if origin is not None and origin not in _ALLOWED_BROWSER_ORIGINS:
        return ORJSONResponse(
            {"detail": "LegalBot-New rejected a cross-origin browser request"},
            status_code=403,
        )
    if fetch_site == "cross-site" or (
        request.method.upper() in _MUTATING_METHODS
        and fetch_site not in {"", "none", "same-origin", "same-site"}
    ):
        return ORJSONResponse(
            {"detail": "LegalBot-New rejected cross-site browser mutation"},
            status_code=403,
        )
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; connect-src 'self'; img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; script-src 'self'"
    )
    return response


def _serving_index_id(services: Any) -> str | None:
    retriever = getattr(services, "retriever", None)
    active_reader = getattr(retriever, "active_build_id", None)
    build_id = active_reader() if callable(active_reader) else services.database.active_index_id()
    if build_id in (None, ""):
        return None
    return str(build_id)


def _v111_normal_live_status(services: Any) -> dict[str, Any]:
    """Read-only exact owner-quality gate for ordinary first-live traffic."""

    from ..evaluation.owner_quality_normal_live_readiness import (
        owner_quality_normal_live_readiness_status,
    )

    underlying = dict(
        owner_quality_normal_live_readiness_status(
            services.settings.project_root,
            database=services.database,
            settings=services.settings,
        )
    )
    # The sealed readiness generation predates the per-answer semantic content
    # capability.  It must not make health, intake, history, or publication look
    # live until the generic normal-live content verifier is implemented.
    blocking = list(underlying.get("blocking_reason_codes") or ())
    if NORMAL_LIVE_CONTENT_CERTIFICATION_STOP not in blocking:
        blocking.append(NORMAL_LIVE_CONTENT_CERTIFICATION_STOP)
    underlying["normal_live_ready"] = False
    underlying["blocking_reason_codes"] = blocking
    underlying["technical_stop"] = NORMAL_LIVE_CONTENT_CERTIFICATION_STOP
    return underlying


def _require_released_job_read_authority(
    *,
    services: Any,
    job: Any,
    request: Request,
    answer: Any | None = None,
    connection: sqlite3.Connection | None = None,
) -> Any | None:
    """Reconcile a durable release, then gate its read authority.

    A public answer is never served from the answer row alone.  The linked job
    and the exactly-once published outbox are part of the release authority.
    Pending/non-release jobs remain readable so a sealed evaluation driver can
    poll them without turning a job-status read into a release decision.
    """

    answer_row = answer
    if answer_row is None and job["answer_id"] is not None:
        answer_row = (
            connection.execute(
                "SELECT * FROM answer_versions WHERE id=?", (str(job["answer_id"]),)
            ).fetchone()
            if connection is not None
            else services.database.answer(str(job["answer_id"]))
        )
    public_job = _is_public_release(job["release_state"])
    public_answer = answer_row is not None and _is_public_release(answer_row["release_state"])
    if not public_job and not public_answer:
        return None
    if answer_row is None:
        raise HTTPException(409, "Released job has no durable answer identity")
    if (
        not public_job
        or not public_answer
        or str(job["status"] or "") != JobStatus.COMPLETE
        or str(job["stage"] or "") != JobStage.COMPLETE
        or float(job["progress"] or 0.0) != 1.0
        or bool(job["cancel_requested"])
        or job["answer_id"] != answer_row["id"]
        or answer_row["job_id"] != job["id"]
        or job["release_state"] != answer_row["release_state"]
        or job["error_code"] not in (None, "")
        or job["terminal_reason_code"] not in (None, "")
    ):
        raise HTTPException(409, "Released answer durable state is inconsistent")
    outbox_rows = (
        connection.execute(
            "SELECT * FROM release_outbox WHERE job_id=?", (str(job["id"]),)
        ).fetchall()
        if connection is not None
        else services.database.fetchall(
            "SELECT * FROM release_outbox WHERE job_id=?",
            (str(job["id"]),),
        )
    )
    expected_idempotency = hashlib.sha256(f"release-v1\0{job['id']}".encode()).hexdigest()
    if len(outbox_rows) != 1:
        raise HTTPException(409, "Released answer has no unique published outbox")
    outbox = outbox_rows[0]
    if (
        outbox["answer_id"] != answer_row["id"]
        or outbox["release_state"] != answer_row["release_state"]
        or outbox["status"] != "published"
        or outbox["published_at"] in (None, "")
        or outbox["idempotency_key"] != expected_idempotency
        or outbox["evaluation_authority_sha256"] != job["evaluation_authority_sha256"]
    ):
        raise HTTPException(409, "Released answer outbox binding is inconsistent")
    evaluation_values = (
        job["evaluation_run_id"],
        job["evaluation_case_id"],
        job["evaluation_request_sha256"],
        job["evaluation_authority_json"],
        job["evaluation_authority_sha256"],
    )
    if any(value not in (None, "") for value in evaluation_values):
        if not all(value not in (None, "") for value in evaluation_values):
            raise HTTPException(409, "Released evaluation authority is incomplete")
        try:
            release_authority_value = json.loads(str(job["evaluation_authority_json"] or ""))
        except json.JSONDecodeError:
            release_authority_value = None
        if (
            not isinstance(release_authority_value, dict)
            or release_authority_value.get("lane") != "owner_quality_canary"
        ):
            raise HTTPException(
                409,
                "TECHNICAL_IMPLEMENTATION_REQUIRED:"
                "superseded_evaluation_release_content_certification_missing",
            )
        if outbox["release_audience"] != "owner_evaluation":
            raise HTTPException(409, "Evaluation output is not private owner-review output")
        if outbox["normal_live_authority_sha256"] not in (None, ""):
            raise HTTPException(409, "Evaluation output carries ordinary live authority")
        from ..evaluation.evaluation_job_authority import (
            replay_evaluation_job_authority,
            verified_owner_canary_content_graph,
        )

        try:
            request_value = json.loads(str(job["request_json"] or "{}"))
            if not isinstance(request_value, dict):
                raise ValueError
            request_value["question"] = services.cipher.decrypt_text(
                bytes(job["encrypted_question"])
            )
            replayed_authority = replay_evaluation_job_authority(
                settings=services.settings,
                database=services.database,
                cipher=services.cipher,
                row=job,
                payload=QuestionRequest.model_validate(request_value),
                answer_id=str(answer_row["id"]),
                owner_canary_publication_phase="released",
                connection=connection,
            )
            content_graph = verified_owner_canary_content_graph(replayed_authority)
            if (
                outbox["owner_canary_content_graph_sha256"] != content_graph.graph_sha256
                or outbox["answer_sha256"] != content_graph.answer_sha256
                or content_graph.job_id != str(job["id"])
                or content_graph.answer_id != str(answer_row["id"])
            ):
                raise RuntimeError("released owner-canary content graph differs")
        except (TypeError, ValueError, RuntimeError, OSError, json.JSONDecodeError):
            raise HTTPException(409, "Released evaluation authority replay failed") from None
        evaluation_run_id = str(job["evaluation_run_id"])
        evaluation_case_id = str(job["evaluation_case_id"])
        supplied = (
            request.headers.get("x-owner-canary-run-id")
            or request.headers.get("x-evaluation-run-id"),
            request.headers.get("x-owner-canary-case-id")
            or request.headers.get("x-evaluation-case-id"),
        )
        if supplied != (evaluation_run_id, evaluation_case_id):
            raise HTTPException(403, "Exact evaluation review identity is required")
        return outbox
    if outbox["release_audience"] != "normal_live":
        raise HTTPException(409, "Ordinary output release audience is inconsistent")
    if outbox["owner_canary_content_graph_sha256"] not in (None, "") or outbox[
        "answer_sha256"
    ] not in (None, ""):
        raise HTTPException(409, "Ordinary output carries a private canary content binding")
    raise HTTPException(
        status.HTTP_503_SERVICE_UNAVAILABLE,
        "TECHNICAL_IMPLEMENTATION_REQUIRED:normal_live_release_content_certification_missing",
    )


@app.get("/api/v1/health", response_model=HealthView)
async def health(request: Request) -> HealthView:
    services = _services(request)
    worker_ready = services.database.service_is_recent("answer-worker")
    model_ready = await services.model.health()
    reasons: list[str] = []
    try:
        active_index = _serving_index_id(services)
    except (RuntimeError, ValueError):
        active_index = None
        reasons.append("active_index_state_inconsistent")
    if active_index is None:
        reasons.append("active_index_missing")
    if not model_ready:
        reasons.append("model_unavailable")
    if not worker_ready:
        reasons.append("answer_worker_unavailable")
    normal_live = _v111_normal_live_status(services)
    normal_live_ready = normal_live.get("normal_live_ready") is True
    if not normal_live_ready:
        reasons.append(NORMAL_LIVE_CONTENT_CERTIFICATION_STOP)
    if not active_index or not normal_live_ready:
        health_status = "not_ready"
    elif reasons:
        health_status = "degraded"
    else:
        health_status = "ready"
    return HealthView(
        status=health_status,
        api_version=API_VERSION,
        database_ready=True,
        worker_ready=worker_ready,
        active_index=active_index,
        model_ready=model_ready,
        model_id=services.settings.model_id,
        prompt_version=PROMPT_VERSION,
        router_version=ROUTER_VERSION,
        classifier_version=CLASSIFIER_VERSION,
        policy_sha256=POLICY_SHA256,
        assessment_bundle_sha256=OWNER_ASSESSMENT_BUNDLE.sha256,
        reasons=reasons,
    )


@app.post(
    "/api/v1/questions",
    response_model=QuestionAccepted,
    status_code=status.HTTP_202_ACCEPTED,
)
async def create_question(payload: QuestionRequest, request: Request) -> QuestionAccepted:
    services = _services(request)
    observability = getattr(services, "observability", None)
    evaluation_run_id = request.headers.get("x-evaluation-run-id")
    evaluation_case_id = request.headers.get("x-evaluation-case-id")
    owner_header_names = (
        "x-owner-canary-review-date",
        "x-owner-canary-run-id",
        "x-owner-canary-case-id",
        "x-owner-canary-attempt",
        "x-owner-canary-input-revision",
        "x-owner-canary-request-seal",
        "x-owner-canary-lane",
    )
    owner_header_values = tuple(request.headers.get(name) for name in owner_header_names)
    if any(value is not None for value in owner_header_values) and not all(
        value is not None for value in owner_header_values
    ):
        raise HTTPException(422, "Owner-canary runtime headers must be supplied together")
    if evaluation_run_id is not None and all(value is not None for value in owner_header_values):
        raise HTTPException(422, "Owner-canary and legacy evaluation headers cannot be combined")
    raw_idempotency = request.headers.get("x-idempotency-key")
    idempotency_key = None
    if raw_idempotency is not None:
        if not re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", raw_idempotency):
            raise HTTPException(422, "X-Idempotency-Key has an invalid format")
        idempotency_key = hashlib.sha256(
            f"legalbot-intake-v1\0{raw_idempotency}".encode()
        ).hexdigest()
    if (evaluation_run_id is None) != (evaluation_case_id is None):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Evaluation run and case headers must be supplied together",
        )
    if evaluation_run_id is not None:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            f"TECHNICAL_IMPLEMENTATION_REQUIRED:{SUPERSEDED_EVALUATION_CONTENT_CERTIFICATION_STOP}",
        )
    from ..evaluation.live_runtime_separation import ordinary_live_admission_allowed
    from ..retrieval.diagnostic_slice import is_diagnostic_slice_build

    canary_build_id = request.headers.get("x-legalbot-canary-build-id")
    if canary_build_id:
        if evaluation_run_id is not None or all(value is not None for value in owner_header_values):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "Diagnostic canary cannot combine with Live60 evaluation headers",
            )
        if not is_diagnostic_slice_build(canary_build_id):
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "canary pin is not the diagnostic slice",
            )

    serving_index_present = bool(_serving_index_id(services))
    ordinary_owner_quality_ready = True
    ordinary_request = (
        evaluation_run_id is None
        and not all(value is not None for value in owner_header_values)
        and canary_build_id is None
    )
    if ordinary_request:
        ordinary_owner_quality_ready = (
            _v111_normal_live_status(services).get("normal_live_ready") is True
        )
    if ordinary_request and (
        not ordinary_owner_quality_ready
        or not ordinary_live_admission_allowed(
            serving_index_present=serving_index_present,
            path_b_qualified_issue_count=None,
        )
    ):
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            f"TECHNICAL_IMPLEMENTATION_REQUIRED:{NORMAL_LIVE_CONTENT_CERTIFICATION_STOP}",
        )
    live60_binding: (
        Live60AdmissionBinding
        | Live60EvaluationAdmissionBinding
        | OwnerCanaryAdmissionBinding
        | None
    ) = None
    if evaluation_run_id is not None and evaluation_case_id is not None:
        if observability is None:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "Live evaluation observability is unavailable",
            )
        try:
            observability.validate_live30_binding(
                evaluation_run_id, evaluation_case_id, payload.question
            )
        except (ValueError, OSError, json.JSONDecodeError):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "The live evaluation binding failed its immutable manifest or question-digest check",
            ) from None
        try:
            live60_binding = validate_live60_api_admission(
                settings=services.settings,
                cipher=services.cipher,
                run_id=evaluation_run_id,
                case_id=evaluation_case_id,
                payload=payload,
                database=services.database,
            )
        except (ValueError, RuntimeError, OSError, json.JSONDecodeError) as exc:
            detail = (
                "Live60 evaluation-only generation is not authorised by its sealed "
                "candidate, overlay and Stage A artifacts"
                if "evaluation" in str(exc).casefold() or "candidate" in str(exc).casefold()
                else "Live60 generation is not authorised by its sealed Stage A, runtime and O-04 gates"
            )
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                detail,
            ) from None
        if live60_binding is not None and idempotency_key is None:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "Live60 generation requires its deterministic idempotency key",
            )
    if all(value is not None for value in owner_header_values):
        if observability is None:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "Owner-canary observability is unavailable",
            )
        if raw_idempotency is None:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "Owner-canary generation requires its deterministic idempotency key",
            )
        try:
            review_date = date.fromisoformat(cast(str, owner_header_values[0]))
            attempt_number = int(cast(str, owner_header_values[3]))
            owner_binding = validate_owner_canary_api_admission(
                settings=services.settings,
                database=services.database,
                review_date=review_date,
                lane=cast(Literal["development", "blind_holdout"], owner_header_values[6]),
                run_id=cast(str, owner_header_values[1]),
                case_id=cast(str, owner_header_values[2]),
                attempt_number=attempt_number,
                input_revision_sha256=cast(str, owner_header_values[4]),
                attempt_request_seal_sha256=cast(str, owner_header_values[5]),
                raw_idempotency_key=raw_idempotency,
                payload=payload,
            )
        except (TypeError, ValueError, RuntimeError, OSError, json.JSONDecodeError):
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "Owner-canary generation is not authorised by its exact sealed runtime inputs",
            ) from None
        live60_binding = owner_binding
        evaluation_run_id = owner_binding.run_id
        evaluation_case_id = owner_binding.case_id
        assert idempotency_key is not None
    if live60_binding is not None and payload.conversation_id is not None:
        raise HTTPException(422, "Evaluation jobs cannot join ordinary conversation history")
    if payload.upload_ids:
        try:
            await asyncio.to_thread(
                validate_upload_references,
                services.settings,
                services.database,
                services.cipher,
                payload.upload_ids,
            )
        except UploadReferenceError:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "One or more upload references are unavailable or failed local-vault integrity checks",
            ) from None
    conversation_id: str | None = None
    conversation_store = getattr(services, "conversations", None)
    if ordinary_request:
        if conversation_store is None:
            if payload.conversation_id is not None:
                raise HTTPException(503, "Encrypted conversation storage is unavailable")
        else:
            from ..conversations import ConversationExpiredError

            try:
                conversation_id = conversation_store.create_session(payload.conversation_id)
            except ConversationExpiredError:
                raise HTTPException(409, "The conversation session has expired") from None
    evaluation_authority: dict[str, Any] | None = None
    evaluation_authority_sha256: str | None = None
    if live60_binding is not None:
        from ..evaluation.evaluation_job_authority import (
            bind_evaluation_job_case,
            build_evaluation_job_authority,
        )

        assert evaluation_run_id is not None and evaluation_case_id is not None
        evaluation_authority = bind_evaluation_job_case(
            build_evaluation_job_authority(live60_binding),
            run_id=evaluation_run_id,
            case_id=evaluation_case_id,
        )
        evaluation_authority_sha256 = str(evaluation_authority["seal_sha256"])
        prior_case_job = services.database.job_by_evaluation_binding(
            evaluation_run_id, evaluation_case_id
        )
        if prior_case_job is not None:
            if (
                prior_case_job["idempotency_key"] != idempotency_key
                or prior_case_job["evaluation_request_sha256"] != live60_binding.request_sha256
                or prior_case_job["evaluation_authority_sha256"] != evaluation_authority_sha256
            ):
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    "The evaluation case already has a different immutable admission request",
                )
            return QuestionAccepted(
                job_id=str(prior_case_job["id"]),
                status=prior_case_job["status"],
                stage=prior_case_job["stage"],
                events_url=f"/api/v1/jobs/{prior_case_job['id']}/events",
                conversation_id=_conversation_id_for_job(
                    services, str(prior_case_job["id"])
                ),
            )
    if idempotency_key is not None:
        existing = services.database.job_by_idempotency_key(idempotency_key)
        if existing is not None:
            existing_binding = (
                existing["evaluation_run_id"],
                existing["evaluation_case_id"],
            )
            requested_binding = (evaluation_run_id, evaluation_case_id)
            if existing_binding != requested_binding:
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    "The idempotency key is already bound to a different evaluation context",
                )
            if live60_binding is not None and (
                existing["evaluation_request_sha256"] != live60_binding.request_sha256
                or existing["evaluation_authority_sha256"] != evaluation_authority_sha256
            ):
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    "The idempotency key is bound to different evaluation request fields",
                )
            return QuestionAccepted(
                job_id=str(existing["id"]),
                status=existing["status"],
                stage=existing["stage"],
                events_url=f"/api/v1/jobs/{existing['id']}/events",
                conversation_id=_conversation_id_for_job(services, str(existing["id"])),
            )
    job_id = str(uuid4())
    task_type = classify_task(payload.question, payload.task_type)
    route = decide_route(payload.question, payload.word_target, task_type)
    from ..jobs import deadline_after, policy_for
    from ..types import JobType

    answer_policy = policy_for(JobType.ANSWER)
    pinned_index_build_id: str | None
    if isinstance(live60_binding, Live60EvaluationAdmissionBinding | OwnerCanaryAdmissionBinding):
        pinned_index_build_id = live60_binding.candidate_build_id
        serving = services.database.active_index_id()
        if serving and serving != pinned_index_build_id:
            # Evaluation must retrieve the authorised candidate, never ACTIVE.
            pass
        row = services.database.fetchone(
            "SELECT id, status FROM index_builds WHERE id=?",
            (pinned_index_build_id,),
        )
        if row is None or str(row["status"]) not in allowed_index_statuses_for_pin(
            pinned_index_build_id
        ):
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "Evaluation candidate is missing or failed sealed-build verification",
            )
    elif canary_build_id is not None:
        pinned_index_build_id = canary_build_id
        row = services.database.fetchone(
            "SELECT id, status FROM index_builds WHERE id=?",
            (pinned_index_build_id,),
        )
        if row is None or str(row["status"]) not in allowed_index_statuses_for_pin(
            pinned_index_build_id
        ):
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "diagnostic canary build is missing",
            )
    else:
        pinned_index_build_id = services.database.active_index_id()
    try:
        services.database.create_job(
            job_id=job_id,
            encrypted_question=services.cipher.encrypt_text(payload.question),
            question_summary="Private encrypted question",
            request=_frozen_job_request(payload),
            route=route.route,
            route_reasons=route.reasons,
            idempotency_key=idempotency_key,
            pinned_index_build_id=pinned_index_build_id,
            job_type=JobType.ANSWER,
            queue_wait_deadline_at=deadline_after(answer_policy.queue_wait_seconds),
            workflow_deadline_at=deadline_after(answer_policy.workflow_seconds),
            model_call_deadline_at=None,
            evaluation_run_id=evaluation_run_id,
            evaluation_case_id=evaluation_case_id,
            evaluation_request_sha256=(
                live60_binding.request_sha256 if live60_binding is not None else None
            ),
            evaluation_authority=evaluation_authority,
            trace_full_retention=evaluation_run_id is not None,
            word_target=payload.word_target,
        )
    except JobQueueCapacityError:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "The bounded local answer queue is full; retry after an existing job finishes",
        ) from None
    except sqlite3.IntegrityError:
        # A simultaneous retry may win either unique constraint between the
        # read and insert. Return only the byte-identical immutable binding;
        # never mask an idempotency/request collision.
        existing = (
            services.database.job_by_evaluation_binding(evaluation_run_id, evaluation_case_id)
            if live60_binding is not None
            and evaluation_run_id is not None
            and evaluation_case_id is not None
            else (
                services.database.job_by_idempotency_key(idempotency_key)
                if idempotency_key is not None
                else None
            )
        )
        if existing is None or existing["idempotency_key"] != idempotency_key:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "A different immutable request already owns this admission identity",
            ) from None
        if live60_binding is not None and (
            existing["evaluation_request_sha256"] != live60_binding.request_sha256
            or existing["evaluation_authority_sha256"] != evaluation_authority_sha256
        ):
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "A different evaluation request already owns this run/case identity",
            ) from None
        return QuestionAccepted(
            job_id=str(existing["id"]),
            status=existing["status"],
            stage=existing["stage"],
            events_url=f"/api/v1/jobs/{existing['id']}/events",
            conversation_id=_conversation_id_for_job(services, str(existing["id"])),
        )
    created = services.database.job(job_id)
    if conversation_id is not None and conversation_store is not None:
        try:
            user_message = conversation_store.append_message(
                conversation_id,
                role="user",
                content=payload.question,
                job_id=job_id,
            )
            conversation_store.bind_user_message_to_job(
                conversation_id=conversation_id,
                message_id=user_message.id,
                job_id=job_id,
            )
        except (RuntimeError, ValueError):
            services.database.request_cancel_job(job_id)
            raise HTTPException(
                409,
                "The answer job was stopped because its encrypted conversation binding failed",
            ) from None
    if created is not None and observability is not None:
        observability.record_intake(created)
    return QuestionAccepted(
        job_id=job_id,
        status=JobStatus.QUEUED,
        stage=JobStage.QUEUED,
        events_url=f"/api/v1/jobs/{job_id}/events",
        conversation_id=conversation_id,
    )


@app.get("/api/v1/jobs/{job_id}", response_model=JobView)
async def get_job(job_id: str, request: Request) -> JobView:
    services = _services(request)
    with services.database.detached_read_snapshot() as (_snapshot_database, connection):
        row = connection.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Answer job not found")
        release_outbox = _require_released_job_read_authority(
            services=services,
            job=row,
            request=request,
            connection=connection,
        )
        released_owner_canary = _is_released_owner_canary_job(row)
        bound_publication_at: datetime | None = None
        if released_owner_canary:
            if release_outbox is None:
                raise HTTPException(409, "Released evaluation outbox projection is missing")
            try:
                bound_publication_at = datetime.fromisoformat(str(release_outbox["published_at"]))
            except (TypeError, ValueError):
                raise HTTPException(
                    409, "Released evaluation publication timestamp is invalid"
                ) from None
        try:
            request_value = json.loads(str(row["request_json"] or "{}"))
        except json.JSONDecodeError:
            request_value = {}
        as_of_value = request_value.get("as_of_date") if isinstance(request_value, dict) else None
        projection = JobView(
            id=row["id"],
            status=row["status"],
            stage=row["stage"],
            progress=1.0 if released_owner_canary else row["progress"],
            question_summary=row["question_summary"],
            answer_id=row["answer_id"],
            release_state=row["release_state"],
            message=_released_job_message(row),
            route=row["route"],
            word_target=int(row["word_target"]),
            as_of_date=as_of_value,
            pinned_index_build_id=row["pinned_index_build_id"],
            evaluation_request_sha256=row["evaluation_request_sha256"],
            worker_prompt_version=row["worker_prompt_version"] or None,
            worker_router_version=row["worker_router_version"] or None,
            worker_classifier_version=row["worker_classifier_version"] or None,
            worker_policy_sha256=row["worker_policy_sha256"] or None,
            assessment_bundle_sha256=row["assessment_bundle_sha256"] or None,
            trace_id=row["trace_id"],
            last_progress_at=cast(
                Any,
                bound_publication_at
                if released_owner_canary
                else row["last_progress_at"] or row["updated_at"],
            ),
            created_at=row["created_at"],
            updated_at=cast(
                Any, bound_publication_at if released_owner_canary else row["updated_at"]
            ),
        )
    return projection


@app.get("/api/v1/jobs/{job_id}/events")
async def job_events(job_id: str, request: Request) -> EventSourceResponse:
    services = _services(request)
    with services.database.detached_read_snapshot() as (_snapshot_database, connection):
        initial_job = connection.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if initial_job is None:
            raise HTTPException(404, "Answer job not found")
        _require_released_job_read_authority(
            services=services,
            job=initial_job,
            request=request,
            connection=connection,
        )
    last_header = request.headers.get("last-event-id", "0")
    try:
        start = int(last_header)
    except ValueError:
        start = 0

    async def stream() -> AsyncIterator[dict[str, str]]:
        sequence = start
        while True:
            if await request.is_disconnected():
                return
            outgoing: list[dict[str, str]] = []
            terminal = False
            with services.database.detached_read_snapshot() as (
                _snapshot_database,
                connection,
            ):
                events = connection.execute(
                    "SELECT * FROM job_events WHERE job_id=? AND sequence>? ORDER BY sequence",
                    (job_id, sequence),
                ).fetchall()
                row = connection.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
                if row is None:
                    return
                try:
                    _require_released_job_read_authority(
                        services=services,
                        job=row,
                        request=request,
                        connection=connection,
                    )
                except HTTPException:
                    # Headers were already sent for SSE; fail closed without
                    # exposing a terminal release event under stale authority.
                    return
                if _is_released_owner_canary_job(row):
                    events = []
                for event in events:
                    sequence = int(event["sequence"])
                    outgoing.append(
                        {
                            "id": str(sequence),
                            "event": "progress",
                            "data": json.dumps(
                                {
                                    "stage": event["stage"],
                                    "progress": event["progress"],
                                    "message": event["message"],
                                    "payload": json.loads(event["payload_json"]),
                                }
                            ),
                        }
                    )
                terminal = row["status"] in {
                    "complete",
                    "held_for_review",
                    "system_error",
                    "cancelled",
                }
                if terminal:
                    outgoing.append(
                        {
                            "id": str(sequence),
                            "event": "done",
                            "data": json.dumps(
                                {
                                    "status": row["status"],
                                    "answer_id": row["answer_id"],
                                    "release_state": row["release_state"],
                                    "message": _released_job_message(row),
                                }
                            ),
                        }
                    )
            for event in outgoing:
                yield event
            if terminal:
                return
            await asyncio.sleep(0.5)

    return EventSourceResponse(stream())


@app.websocket("/api/v1/jobs/{job_id}/events/ws")
async def job_events_websocket(websocket: WebSocket, job_id: str) -> None:
    """Bounded replayable browser transport for safe job progress events.

    Raw model tokens and unvalidated draft sentences are never emitted here.
    The only answer identity in the terminal event is the already-published,
    deterministically validated answer ID.
    """

    if not _websocket_boundary_allowed(websocket):
        await websocket.close(code=1008, reason="loopback websocket boundary rejected")
        return
    offered = {
        value.strip()
        for value in websocket.headers.get("sec-websocket-protocol", "").split(",")
        if value.strip()
    }
    if "legalbot.job-events.v1" not in offered:
        await websocket.close(code=1002, reason="required websocket protocol was not offered")
        return
    raw_after = websocket.query_params.get("after", "0")
    try:
        sequence = int(raw_after)
    except ValueError:
        await websocket.close(code=1008, reason="invalid event sequence")
        return
    if not 0 <= sequence <= 9_223_372_036_854_775_807:
        await websocket.close(code=1008, reason="invalid event sequence")
        return
    services = _services(websocket)
    with services.database.detached_read_snapshot() as (_snapshot_database, connection):
        initial_job = connection.execute(
            "SELECT * FROM jobs WHERE id=?", (job_id,)
        ).fetchone()
        if initial_job is None:
            await websocket.close(code=4404, reason="answer job not found")
            return
        try:
            _require_released_job_read_authority(
                services=services,
                job=initial_job,
                request=websocket,  # type: ignore[arg-type]
                connection=connection,
            )
        except HTTPException:
            await websocket.close(code=1008, reason="job read authority rejected")
            return
    await websocket.accept(subprotocol="legalbot.job-events.v1")
    try:
        while True:
            outgoing: list[dict[str, Any]] = []
            terminal = False
            with services.database.detached_read_snapshot() as (
                _snapshot_database,
                connection,
            ):
                row = connection.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
                if row is None:
                    await websocket.close(code=1011, reason="answer job disappeared")
                    return
                try:
                    _require_released_job_read_authority(
                        services=services,
                        job=row,
                        request=websocket,  # type: ignore[arg-type]
                        connection=connection,
                    )
                except HTTPException:
                    await websocket.close(code=1008, reason="job read authority changed")
                    return
                events = connection.execute(
                    """
                    SELECT * FROM job_events
                    WHERE job_id=? AND sequence>? ORDER BY sequence LIMIT 100
                    """,
                    (job_id, sequence),
                ).fetchall()
                if _is_released_owner_canary_job(row):
                    events = []
                for event in events:
                    sequence = int(event["sequence"])
                    outgoing.append(
                        {
                            "schema": "legalbot.job-event.v1",
                            "sequence": sequence,
                            "event": "progress",
                            "data": {
                                "stage": event["stage"],
                                "progress": event["progress"],
                                "message": event["message"],
                                "payload": json.loads(event["payload_json"]),
                            },
                        }
                    )
                terminal = row["status"] in {
                    "complete",
                    "held_for_review",
                    "system_error",
                    "cancelled",
                }
                if terminal:
                    outgoing.append(
                        {
                            "schema": "legalbot.job-event.v1",
                            "sequence": sequence,
                            "event": "done",
                            "data": {
                                "status": row["status"],
                                "answer_id": row["answer_id"],
                                "release_state": row["release_state"],
                                "message": _released_job_message(row),
                            },
                        }
                    )
            for event in outgoing:
                await websocket.send_json(event)
            if terminal:
                await websocket.close(code=1000)
                return
            await asyncio.sleep(0.25)
    except WebSocketDisconnect:
        return


@app.post("/api/v1/jobs/{job_id}/cancel")
async def cancel_job(job_id: str, request: Request) -> dict[str, Any]:
    if not _services(request).database.request_cancel_job(job_id):
        raise HTTPException(404, "Answer job not found")
    return {"job_id": job_id, "cancel_requested": True}


@app.post("/api/v1/jobs/{job_id}/resume")
async def resume_job(job_id: str, request: Request) -> dict[str, Any]:
    try:
        resumed = _services(request).database.resume_answer_job(job_id)
    except JobQueueCapacityError:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "The bounded local answer queue is full; retry after an existing job finishes",
        ) from None
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(409, str(exc)) from None
    if not resumed:
        raise HTTPException(404, "Answer job not found")
    row = _services(request).database.job(job_id)
    if row is None:
        raise HTTPException(409, "The resumed answer identity could not be reconciled")
    return {
        "job_id": job_id,
        "status": "queued",
        "resume_mode": "digest_checked",
        "attempt_count": int(row["attempt_count"] or 0),
        "maximum_attempt_count": 3,
        "attempt_counter_reset": False,
    }


@app.get("/api/v1/answers/{answer_id}")
async def get_answer(answer_id: str, request: Request) -> dict[str, Any]:
    services = _services(request)
    with services.database.detached_read_snapshot() as (_snapshot_database, connection):
        row = connection.execute(
            "SELECT * FROM answer_versions WHERE id=?", (answer_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(404, "Answer version not found")
        if not _is_public_release(row["release_state"]):
            raise HTTPException(409, "This encrypted version has not been released")
        job = connection.execute("SELECT * FROM jobs WHERE id=?", (str(row["job_id"]),)).fetchone()
        if job is None:
            raise HTTPException(409, "Released answer has no durable job identity")
        _require_released_job_read_authority(
            services=services,
            job=job,
            request=request,
            answer=row,
            connection=connection,
        )
        try:
            request_value = json.loads(str(job["request_json"] or "{}"))
        except json.JSONDecodeError:
            request_value = {}
        quality_rows = connection.execute(
            """
            SELECT id, answer_version_id, evidence_passed, academic_score,
                   rubric_scores_json, findings_json, release_state,
                   policy_version, policy_sha256, ai_evidence_review_json,
                   ai_evidence_adjudication_json, assessment_standards_json, created_at
            FROM quality_reports WHERE answer_version_id=?
            ORDER BY created_at,id
            """,
            (answer_id,),
        ).fetchall()
        if len(quality_rows) > 1:
            raise HTTPException(409, "Released answer quality identity is ambiguous")
        quality = quality_rows[0] if quality_rows else None
        projection = {
            "id": row["id"],
            "job_id": row["job_id"],
            "content": services.cipher.decrypt_text(row["encrypted_content"]),
            "word_count": row["word_count"],
            "release_state": row["release_state"],
            "policy_version": row["policy_version"],
            "model_version": row["model_version"],
            "index_build_id": row["index_build_id"],
            "route": job["route"],
            "as_of_date": (
                request_value.get("as_of_date") if isinstance(request_value, dict) else None
            ),
            "word_target": int(job["word_target"]),
            "evaluation_request_sha256": job["evaluation_request_sha256"],
            "prompt_version": job["worker_prompt_version"],
            "router_version": job["worker_router_version"],
            "classifier_version": job["worker_classifier_version"],
            "runtime_policy_sha256": job["worker_policy_sha256"],
            "assessment_bundle_sha256": job["assessment_bundle_sha256"],
            "quality": (
                {
                    "id": quality["id"],
                    "answer_version_id": quality["answer_version_id"],
                    "evidence_passed": bool(quality["evidence_passed"]),
                    "academic_score": quality["academic_score"],
                    "rubric_scores_json": quality["rubric_scores_json"],
                    "findings_json": quality["findings_json"],
                    "release_state": quality["release_state"],
                    "policy_version": quality["policy_version"],
                    "policy_sha256": quality["policy_sha256"],
                    "ai_evidence_review_json": quality["ai_evidence_review_json"],
                    "ai_evidence_adjudication_json": quality["ai_evidence_adjudication_json"],
                    "assessment_standards_json": quality["assessment_standards_json"],
                    "created_at": quality["created_at"],
                }
                if quality
                else None
            ),
            "created_at": row["created_at"],
        }
    return projection


@app.get("/api/v1/answers/{answer_id}/evidence")
async def get_answer_evidence(answer_id: str, request: Request) -> dict[str, Any]:
    services = _services(request)
    with services.database.detached_read_snapshot() as (_snapshot_database, connection):
        answer = connection.execute(
            "SELECT * FROM answer_versions WHERE id=?", (answer_id,)
        ).fetchone()
        if answer is None:
            raise HTTPException(404, "Released answer not found")
        if not _is_public_release(answer["release_state"]):
            raise HTTPException(409, "This encrypted version has not been released")
        job = connection.execute(
            "SELECT * FROM jobs WHERE id=?", (str(answer["job_id"]),)
        ).fetchone()
        if job is None:
            raise HTTPException(409, "Released answer has no durable job identity")
        _require_released_job_read_authority(
            services=services,
            job=job,
            request=request,
            answer=answer,
            connection=connection,
        )
        claims = connection.execute(
            "SELECT * FROM claims WHERE answer_version_id=? ORDER BY ordinal,id",
            (answer_id,),
        ).fetchall()
        links = connection.execute(
            """
            SELECT ce.* FROM claim_evidence ce
            JOIN claims c ON c.id=ce.claim_id
            WHERE c.answer_version_id=? ORDER BY c.ordinal,ce.ordinal,ce.evidence_id
            """,
            (answer_id,),
        ).fetchall()
        evidence = connection.execute(
            """
            SELECT DISTINCT
              es.id,es.source_version_id,es.chunk_id,es.locator,es.lane,
              es.jurisdiction,es.subject,es.citation_data_json,
              es.canonical_citation,es.currentness_status,es.content_sha256,
              es.index_build_id,es.retrieval_relevance_score,es.retrieval_route,
              es.retrieval_threshold,es.retrieval_threshold_policy_sha256,
              es.retrieval_threshold_qualified,es.retrieval_qualification_reason,
              es.legal_role,
              es.unapplied_effect_count,es.provision_extent_status,
              es.identity_verified,es.currentness_verified,
              es.case_currentness_reviews_json,
              es.case_currentness_manifest_seals_json
            FROM evidence_spans es
            JOIN claim_evidence ce ON ce.evidence_id=es.id
            JOIN claims c ON c.id=ce.claim_id
            WHERE c.answer_version_id=? ORDER BY es.id
            """,
            (answer_id,),
        ).fetchall()
        evidence_ids: dict[str, list[str]] = {}
        for link in links:
            evidence_ids.setdefault(str(link["claim_id"]), []).append(str(link["evidence_id"]))
        evidence_records: list[dict[str, Any]] = []
        try:
            for row in evidence:
                citation_data = json.loads(row["citation_data_json"] or "{}")
                case_reviews = json.loads(row["case_currentness_reviews_json"] or "[]")
                manifest_seals = json.loads(row["case_currentness_manifest_seals_json"] or "[]")
                evidence_records.append(
                    {
                        "id": row["id"],
                        "source_version_id": row["source_version_id"],
                        "chunk_id": row["chunk_id"],
                        "locator": row["locator"],
                        "lane": row["lane"],
                        "jurisdiction": row["jurisdiction"],
                        "subject": row["subject"],
                        "canonical_citation": row["canonical_citation"],
                        "currentness_status": row["currentness_status"],
                        "content_sha256": row["content_sha256"],
                        "index_build_id": row["index_build_id"],
                        "retrieval_relevance_score": row["retrieval_relevance_score"],
                        "retrieval_route": row["retrieval_route"],
                        "retrieval_threshold": row["retrieval_threshold"],
                        "retrieval_threshold_policy_sha256": row[
                            "retrieval_threshold_policy_sha256"
                        ],
                        "retrieval_threshold_qualified": (
                            bool(row["retrieval_threshold_qualified"])
                            if row["retrieval_threshold_qualified"] is not None
                            else None
                        ),
                        "retrieval_qualification_reason": row[
                            "retrieval_qualification_reason"
                        ],
                        "legal_role": row["legal_role"],
                        "unapplied_effect_count": row["unapplied_effect_count"],
                        "provision_extent_status": row["provision_extent_status"],
                        "citation_data": _safe_evidence_citation_data(
                            citation_data,
                            owner_identifiers=services.settings.owner_identifiers,
                        ),
                        "identity_verified": bool(row["identity_verified"]),
                        "currentness_verified": bool(row["currentness_verified"]),
                        "case_currentness_reviews": _safe_case_currentness_reviews(case_reviews),
                        "case_currentness_manifest_seals": _safe_sha256_list(
                            manifest_seals,
                            label="case-currentness manifest seals",
                        ),
                    }
                )
            claim_records = [
                {
                    # The storage key is version scoped; the model ID is stable.
                    "id": row["model_claim_id"] or row["id"],
                    "section_id": row["section_id"],
                    "text": services.cipher.decrypt_text(row["encrypted_claim_text"]),
                    "material": bool(row["material"]),
                    "verification_status": row["verification_status"],
                    "verification_reason": row["verification_reason"],
                    "proposition_hash": row["proposition_hash"],
                    "evidence_ids": evidence_ids.get(str(row["id"]), []),
                }
                for row in claims
            ]
        except (TypeError, ValueError, json.JSONDecodeError):
            raise HTTPException(
                409, "Released evidence metadata failed its safe projection"
            ) from None
        projection = {
            "answer_id": answer_id,
            "claims": claim_records,
            "evidence": evidence_records,
        }
    return projection


@app.get("/api/v1/owner-canary/answers/{answer_id}/attempt-result")
async def get_owner_canary_attempt_result(answer_id: str, request: Request) -> dict[str, Any]:
    """Project a released durable answer into the sealed owner-canary contract."""

    services = _services(request)
    answer = services.database.answer(answer_id)
    if answer is None or not _is_public_release(answer["release_state"]):
        raise HTTPException(409, "Owner-canary attempt result requires a released answer")
    job = services.database.job(str(answer["job_id"]))
    if job is None:
        raise HTTPException(409, "Owner-canary released answer has no durable job")
    names = (
        "x-owner-canary-review-date",
        "x-owner-canary-run-id",
        "x-owner-canary-case-id",
        "x-owner-canary-attempt",
        "x-owner-canary-input-revision",
        "x-owner-canary-request-seal",
        "x-owner-canary-lane",
    )
    values = tuple(request.headers.get(name) for name in names)
    raw_idempotency = request.headers.get("x-idempotency-key")
    if not all(value is not None for value in values) or raw_idempotency is None:
        raise HTTPException(422, "Owner-canary runtime headers are required")
    try:
        request_value = json.loads(str(job["request_json"] or "{}"))
        if not isinstance(request_value, dict):
            raise ValueError("answer request is invalid")
        payload = QuestionRequest.model_validate(
            {
                **request_value,
                "question": services.cipher.decrypt_text(bytes(job["encrypted_question"])),
            }
        )
        binding = validate_owner_canary_api_admission(
            settings=services.settings,
            database=services.database,
            review_date=date.fromisoformat(cast(str, values[0])),
            lane=cast(Literal["development", "blind_holdout"], values[6]),
            run_id=cast(str, values[1]),
            case_id=cast(str, values[2]),
            attempt_number=int(cast(str, values[3])),
            input_revision_sha256=cast(str, values[4]),
            attempt_request_seal_sha256=cast(str, values[5]),
            raw_idempotency_key=raw_idempotency,
            payload=payload,
        )
        if raw_idempotency != owner_canary_idempotency_key(cast(str, values[5])):
            raise ValueError("owner-canary result idempotency differs")
        if (
            str(job["evaluation_run_id"] or "") != binding.run_id
            or str(job["evaluation_case_id"] or "") != binding.case_id
            or str(job["evaluation_request_sha256"] or "") != binding.request_sha256
        ):
            raise ValueError("owner-canary answer job differs from admission")
        envelope = build_owner_canary_runtime_attempt_envelope(
            settings=services.settings,
            database=services.database,
            cipher=services.cipher,
            binding=binding,
            answer_id=answer_id,
        )
    except (TypeError, ValueError, RuntimeError, OSError, json.JSONDecodeError):
        raise HTTPException(
            409, "Owner-canary durable answer failed exact runtime projection"
        ) from None
    return envelope.model_dump(mode="json", by_alias=True)


@app.post("/api/v1/answers/{answer_id}/issues", status_code=status.HTTP_201_CREATED)
async def create_answer_issue(
    answer_id: str, payload: EvaluationIssueRequest, request: Request
) -> dict[str, Any]:
    services = _services(request)
    answer = services.database.answer(answer_id)
    if answer is None:
        raise HTTPException(404, "Answer version not found")
    issue_id = str(uuid4())
    services.database.create_evaluation_issue(
        issue_id=issue_id,
        run_id=None,
        case_id=None,
        job_id=str(answer["job_id"]),
        category=payload.category,
        severity=payload.severity,
        affected_layer=payload.affected_layer,
        expected_ids=payload.expected_ids,
        observed_ids=payload.observed_ids,
        encrypted_note=(services.cipher.encrypt_text(payload.note) if payload.note else None),
        create_debug_refinement=True,
        answer_id=answer_id,
    )
    refinement_digest = hashlib.sha256(
        f"legalbot-evaluation-issue-refinement-v1\0{issue_id}".encode()
    ).hexdigest()
    return {
        "issue_id": issue_id,
        "refinement_id": f"refinement-issue-{refinement_digest[:40]}",
        "status": "open",
    }


@app.get("/api/v1/conversations")
async def conversations(request: Request, limit: int = 50) -> dict[str, Any]:
    services = _services(request)
    if _v111_normal_live_status(services).get("normal_live_ready") is not True:
        return {"items": []}
    requested_limit = min(max(limit, 1), 200)
    items: list[dict[str, Any]] = []
    with services.database.detached_read_snapshot() as (_snapshot_database, connection):
        rows = connection.execute(
            """
            SELECT av.*,j.question_summary FROM answer_versions av
            JOIN jobs j ON j.id=av.job_id
            WHERE av.release_state='verified_full'
            ORDER BY av.created_at DESC LIMIT 200
            """
        ).fetchall()
        for row in rows:
            job = connection.execute(
                "SELECT * FROM jobs WHERE id=?", (str(row["job_id"]),)
            ).fetchone()
            if job is None:
                continue
            try:
                _require_released_job_read_authority(
                    services=services,
                    job=job,
                    request=request,
                    answer=row,
                    connection=connection,
                )
            except HTTPException:
                continue
            # Conversations are ordinary normal-live history only.  Even an
            # exactly authorised evaluation review must never appear here.
            if job["evaluation_authority_sha256"] not in (None, ""):
                continue
            items.append(
                {
                    "answer_id": row["id"],
                    "job_id": row["job_id"],
                    "question_summary": row["question_summary"],
                    "release_state": row["release_state"],
                    "word_count": row["word_count"],
                    "created_at": row["created_at"],
                }
            )
            if len(items) == requested_limit:
                break
    return {"items": items}


@app.get("/api/v1/conversation-sessions/{conversation_id}/window")
async def conversation_window(
    conversation_id: str,
    request: Request,
    max_messages: int | None = None,
    max_tokens: int | None = None,
) -> dict[str, Any]:
    from ..conversations import ConversationExpiredError, ConversationNotFoundError

    services = _services(request)
    try:
        window = services.conversations.window(
            conversation_id,
            max_messages=max_messages,
            max_tokens=max_tokens,
        )
    except ConversationNotFoundError:
        raise HTTPException(404, "Conversation session not found") from None
    except ConversationExpiredError:
        raise HTTPException(410, "Conversation session expired") from None
    return {
        "conversation_id": window.conversation_id,
        "messages": [asdict(message) for message in window.messages],
        "total_message_count": window.total_message_count,
        "selected_message_count": window.selected_message_count,
        "selected_estimated_tokens": window.selected_estimated_tokens,
        "omitted_message_count": window.omitted_message_count,
        "limit_messages": window.limit_messages,
        "limit_tokens": window.limit_tokens,
        "truncated": window.truncated,
        "truncation_reason": window.truncation_reason,
        "expires_at": window.expires_at,
        "conversation_is_evidence": False,
    }


@app.post("/api/v1/internal/knowledge-events", status_code=status.HTTP_202_ACCEPTED)
async def receive_knowledge_update_webhook(
    payload: KnowledgeUpdateWebhookRequest,
    request: Request,
) -> dict[str, Any]:
    from ..research.freshness import KnowledgeEventType, KnowledgeUpdateEventRequest

    services = _services(request)
    try:
        receipt = services.freshness.receive(
            KnowledgeUpdateEventRequest(
                event_type=KnowledgeEventType(payload.event_type),
                subject=payload.subject,
                jurisdiction=payload.jurisdiction,
                source_id=payload.source_id,
                authority_identity_id=payload.authority_identity_id,
                knowledge_gap_id=payload.knowledge_gap_id,
                source_date=payload.source_date,
                as_of_date=payload.as_of_date,
                observed_at=payload.observed_at,
                query_sha256=payload.query_sha256,
                safe_payload=payload.safe_payload,
                detail=payload.detail,
            )
        )
    except ValueError:
        raise HTTPException(422, "Knowledge update event failed safe validation") from None
    return asdict(receipt)


@app.post("/api/v1/uploads", status_code=status.HTTP_201_CREATED)
async def upload_document(request: Request, file: UploadFile = File(...)) -> dict[str, Any]:
    services = _services(request)
    hasher = hashlib.sha256()
    payload = bytearray()
    byte_size = 0
    try:
        while chunk := await file.read(1024 * 1024):
            byte_size += len(chunk)
            if byte_size > MAX_UPLOAD_BYTES:
                raise HTTPException(413, "Upload exceeds the 100 MB local limit")
            hasher.update(chunk)
            payload.extend(chunk)
        digest = hasher.hexdigest()
        try:
            canonical_media_type = validate_upload_media(
                bytes(payload),
                filename=file.filename or "upload.bin",
                claimed_media_type=file.content_type,
            )
        except UploadReferenceError:
            raise HTTPException(
                415,
                "Upload type, MIME declaration or document signature is unsupported",
            ) from None
        destination = services.settings.upload_dir / digest[:2] / f"{digest}.enc"
        if destination.exists():
            existing = read_upload(destination, cipher=services.cipher, encrypted=True)
            if len(existing) != byte_size or hashlib.sha256(existing).hexdigest() != digest:
                raise HTTPException(409, "An existing encrypted upload failed integrity checks")
        else:
            write_encrypted_upload(destination, bytes(payload), cipher=services.cipher)
        upload_id = str(uuid4())
        safe_name = safe_source_name(Path(file.filename or "upload.bin"), digest)
        services.database.store_upload(
            upload_id=upload_id,
            content_sha256=digest,
            safe_display_name=safe_name,
            encrypted_original_name=services.cipher.encrypt_text(file.filename or "upload.bin"),
            media_type=canonical_media_type,
            byte_size=byte_size,
            vault_path=str(destination.relative_to(services.settings.project_root)),
            encrypted_blob=True,
            retention_until=(datetime.now(UTC) + timedelta(days=30)).isoformat(),
            quarantine_status="unreviewed",
        )
        return {"upload_id": upload_id, "display_name": safe_name, "status": "staged"}
    finally:
        payload.clear()


@app.post(
    "/api/v1/admin/uploads/{upload_id}/submit-for-source-review",
    status_code=status.HTTP_201_CREATED,
)
async def admin_submit_upload_for_source_review(upload_id: str, request: Request) -> dict[str, Any]:
    services = _services(request)
    try:
        submission = await asyncio.to_thread(
            submit_upload_for_source_review,
            services.settings,
            services.database,
            services.cipher,
            upload_id,
        )
    except UploadReferenceError:
        raise HTTPException(
            409, "Upload is unavailable or failed source-intake quarantine checks"
        ) from None
    return {
        "review_id": submission.review_id,
        "status": submission.status,
        "content_sha256": submission.content_sha256,
        "duplicate": submission.duplicate,
        "scope": "source_intake_review_only",
    }


@app.get("/api/v1/admin/overview")
async def admin_overview(request: Request) -> dict[str, Any]:
    services = _services(request)
    overview = services.database.admin_overview()
    overview["model_ready"] = await services.model.health()
    overview["owner_only"] = True
    return overview


@app.get("/api/v1/admin/observability", response_model=ObservabilityAdminView)
async def admin_observability(request: Request) -> dict[str, Any]:
    """Expose only safe IDs, bounded labels, progress state and aggregate timings."""

    return _services(request).observability.admin_view()


@app.get(
    "/api/v1/admin/observability/jobs/{job_id}/trace",
    response_model=ObservabilityTraceView,
)
async def admin_job_trace(job_id: str, request: Request) -> dict[str, Any]:
    try:
        return _services(request).observability.trace_summary(job_id)
    except LookupError:
        raise HTTPException(404, "Answer job not found") from None


@app.get("/api/v1/admin/sources")
async def admin_sources(request: Request, limit: int = 200, offset: int = 0) -> dict[str, Any]:
    rows = _services(request).database.admin_sources(min(max(limit, 1), 1000), max(offset, 0))
    return {"items": [_row(row) for row in rows]}


@app.get("/api/v1/admin/coverage")
async def admin_coverage(request: Request) -> dict[str, Any]:
    rows = _services(request).database.fetchall(
        """
        SELECT COALESCE(subject_primary, 'unclassified') AS subject,
               status, COALESCE(lane, 'unclassified') AS lane, COUNT(*) AS count
        FROM documents GROUP BY subject, status, lane ORDER BY subject, status, lane
        """
    )
    return {"items": [_row(row) for row in rows]}


@app.get("/api/v1/admin/index-builds")
async def admin_index_builds(request: Request) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for row in _services(request).database.admin_index_builds():
        item = _row(row)
        # A build's local directory is implementation metadata.  It must not
        # enter browser state or an application response.
        item.pop("path", None)
        item["metrics"] = json.loads(row["metrics_json"])
        item.pop("metrics_json", None)
        items.append(item)
    return {"items": items}


@app.get("/api/v1/admin/gaps")
async def admin_gaps(request: Request) -> dict[str, Any]:
    return {
        "items": [
            {
                **_row(row),
                # The proposition remains encrypted at rest and is not copied
                # into routine browser state.  A hash supports safe correlation.
                "missing_proposition": "Encrypted evidence gap",
            }
            for row in _services(request).database.admin_gaps()
        ]
    }


@app.get("/api/v1/admin/quality")
async def admin_quality(request: Request) -> dict[str, Any]:
    return {"items": _services(request).database.admin_quality()}


@app.get("/api/v1/admin/failures")
async def admin_failures(request: Request, limit: int = 200) -> dict[str, Any]:
    rows = _services(request).database.admin_failures(min(max(limit, 1), 500))
    return {
        "items": [
            {
                **_row(row),
                "user_or_owner_safe": safe_summary(str(row["user_or_owner_safe"] or ""), 800),
            }
            for row in rows
        ]
    }


@app.get("/api/v1/admin/evaluation-issues")
async def admin_evaluation_issues(request: Request, limit: int = 200) -> dict[str, Any]:
    rows = _services(request).database.admin_evaluation_issues(min(max(limit, 1), 500))
    items: list[dict[str, Any]] = []
    for row in rows:
        item = _row(row)
        item.pop("safe_expected_ids_json", None)
        item.pop("safe_observed_ids_json", None)
        item["expected_ids"] = json.loads(row["safe_expected_ids_json"] or "[]")
        item["observed_ids"] = json.loads(row["safe_observed_ids_json"] or "[]")
        item["has_note"] = bool(row["has_note"])
        item["root_cause"] = safe_summary(str(row["root_cause"] or ""), 800)
        item["corrective_action"] = safe_summary(str(row["corrective_action"] or ""), 800)
        items.append(item)
    return {"items": items}


@app.get("/api/v1/admin/evaluation-issues/{issue_id}/detail")
async def admin_evaluation_issue_detail(issue_id: str, request: Request) -> dict[str, Any]:
    """Deliberately decrypt one owner-selected issue note with an audit event."""

    services = _services(request)
    access_ref = f"owner-read-{uuid4().hex}"
    try:
        row = services.database.owner_evaluation_issue_note(issue_id, access_ref=access_ref)
    except KeyError:
        raise HTTPException(404, "Evaluation issue not found") from None
    except ValueError:
        raise HTTPException(422, "Evaluation issue identity is invalid") from None
    encrypted = row["encrypted_human_note"]
    return {
        "id": row["id"],
        "note": services.cipher.decrypt_text(encrypted) if encrypted else None,
        "access_ref": access_ref,
    }


@app.get("/api/v1/admin/refinements")
async def admin_refinements(request: Request, limit: int = 200) -> dict[str, Any]:
    rows = _services(request).database.refinements(limit=min(max(limit, 1), 500))
    items: list[dict[str, Any]] = []
    for row in rows:
        items.append(
            {
                "id": row["id"],
                "category": row["category"],
                "scope": row["scope"],
                "priority": row["priority"],
                "status": row["status"],
                "origin": row["origin"],
                "answer_id": row["answer_id"],
                "job_id": row["job_id"],
                "knowledge_gap_id": row["knowledge_gap_id"],
                "research_task_id": row["research_task_id"],
                "target": json.loads(row["safe_target_json"] or "{}"),
                "note_sha256": row["note_sha256"],
                "occurrence_count": row["occurrence_count"],
                "root_cause": row["root_cause"],
                "repair_version": row["repair_version"],
                "regression_case_id": row["regression_case_id"],
                "resolution_evidence": json.loads(row["resolution_evidence_json"] or "{}"),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "closed_at": row["closed_at"],
            }
        )
    return {"items": items}


@app.get("/api/v1/admin/refinements/{refinement_id}/detail")
async def admin_refinement_detail(refinement_id: str, request: Request) -> dict[str, Any]:
    """Deliberately decrypt one owner-selected feedback/refinement note."""

    services = _services(request)
    access_ref = f"owner-read-{uuid4().hex}"
    try:
        row = services.database.owner_refinement_note(refinement_id, access_ref=access_ref)
    except KeyError:
        raise HTTPException(404, "Refinement item not found") from None
    except ValueError:
        raise HTTPException(422, "Refinement identity is invalid") from None
    encrypted = row["encrypted_note"]
    return {
        "id": row["id"],
        "note": services.cipher.decrypt_text(encrypted) if encrypted else None,
        "note_sha256": row["note_sha256"],
        "access_ref": access_ref,
    }


@app.post("/api/v1/admin/refinements/{refinement_id}/transition")
async def admin_transition_refinement(
    refinement_id: str, payload: RefinementTransitionRequest, request: Request
) -> dict[str, Any]:
    services = _services(request)
    try:
        row = RefinementService(services.database, services.cipher).transition(
            refinement_id, payload
        )
    except KeyError:
        raise HTTPException(404, "Refinement item not found") from None
    except ValueError:
        raise HTTPException(409, "Refinement transition is not permitted") from None
    return {
        "id": row["id"],
        "status": row["status"],
        "updated_at": row["updated_at"],
    }


@app.get("/api/v1/admin/research/tasks")
async def admin_research_tasks(request: Request, limit: int = 200) -> dict[str, Any]:
    rows = _services(request).database.research_tasks(limit=min(max(limit, 1), 500))
    return {"items": [_row(row) for row in rows]}


@app.get("/api/v1/admin/research/candidates")
async def admin_research_candidates(request: Request, limit: int = 200) -> dict[str, Any]:
    from ..research.review import ResearchReviewService

    services = _services(request)
    rows = ResearchReviewService(services.settings, services.database).candidates(
        limit=min(max(limit, 1), 500)
    )
    return {"items": [asdict(row) for row in rows]}


@app.get("/api/v1/admin/source-updates")
async def admin_source_updates(request: Request, limit: int = 200) -> dict[str, Any]:
    from ..research.review import ResearchReviewService

    services = _services(request)
    rows = ResearchReviewService(services.settings, services.database).updates(
        limit=min(max(limit, 1), 500)
    )
    return {"items": [asdict(row) for row in rows]}


@app.post("/api/v1/admin/research/candidates/{candidate_id}/system-verify")
async def admin_system_verify_research_candidate(
    candidate_id: str, request: Request
) -> dict[str, Any]:
    from ..research.review import ResearchReviewService

    services = _services(request)
    try:
        digest = ResearchReviewService(
            services.settings, services.database
        ).system_verify_candidate(candidate_id)
    except KeyError:
        raise HTTPException(404, "Research candidate not found") from None
    except (ValueError, RuntimeError):
        raise HTTPException(
            409, "Research candidate did not pass deterministic envelope verification"
        ) from None
    return {"candidate_id": candidate_id, "system_verification_sha256": digest}


@app.post("/api/v1/admin/research/candidates/{candidate_id}/review")
async def admin_review_research_candidate(
    candidate_id: str,
    payload: ResearchCandidateReviewRequest,
    request: Request,
) -> dict[str, Any]:
    from ..research.review import OwnerDecisionRequired, ResearchReviewService

    services = _services(request)
    try:
        intake_review_id = ResearchReviewService(
            services.settings, services.database
        ).review_candidate(candidate_id, **payload.model_dump())
    except KeyError:
        raise HTTPException(404, "Research candidate not found") from None
    except OwnerDecisionRequired:
        raise HTTPException(409, "OWNER_DECISION_REQUIRED") from None
    except (ValueError, RuntimeError):
        raise HTTPException(
            409, "Research candidate decision failed its sealed review contract"
        ) from None
    return {
        "candidate_id": candidate_id,
        "decision": payload.decision,
        "source_intake_review_id": intake_review_id,
        "automatic_source_approval": False,
        "automatic_index_or_promotion": False,
    }


@app.post("/api/v1/admin/source-updates/{observation_id}/review")
async def admin_review_source_update(
    observation_id: str,
    payload: SourceUpdateReviewRequest,
    request: Request,
) -> dict[str, Any]:
    from ..research.review import ResearchReviewService

    services = _services(request)
    try:
        review_id = ResearchReviewService(services.settings, services.database).review_update(
            observation_id, **payload.model_dump()
        )
    except KeyError:
        raise HTTPException(404, "Source-update observation not found") from None
    except (ValueError, RuntimeError):
        raise HTTPException(
            409, "Source-update decision failed its sealed materiality contract"
        ) from None
    return {
        "observation_id": observation_id,
        "review_id": review_id,
        "materiality_status": payload.materiality_status,
        "automatic_source_or_active_change": False,
    }


@app.post("/api/v1/admin/source-updates/{observation_id}/resolve")
async def admin_resolve_source_update(
    observation_id: str,
    payload: SourceUpdateResolutionRequest,
    request: Request,
) -> dict[str, Any]:
    from ..research.review import ResearchReviewService

    services = _services(request)
    try:
        resolution_id = ResearchReviewService(
            services.settings, services.database
        ).resolve_material_update(observation_id, **payload.model_dump())
    except KeyError:
        raise HTTPException(404, "Source-update observation not found") from None
    except (ValueError, RuntimeError, OSError, json.JSONDecodeError):
        raise HTTPException(
            409,
            "Source update is not resolved by the exact newly promoted ACTIVE manifest",
        ) from None
    return {
        "observation_id": observation_id,
        "resolution_id": resolution_id,
        "automatic_promotion": False,
    }


@app.get("/api/v1/admin/subject-readiness")
async def admin_subject_readiness(request: Request) -> dict[str, Any]:
    from ..retrieval.subject_readiness import SubjectReadinessService

    services = _services(request)
    try:
        snapshot = SubjectReadinessService(services.settings, services.database).snapshot()
    except RuntimeError:
        raise HTTPException(409, "Subject readiness could not verify ACTIVE") from None
    return {
        "build_id": snapshot.build_id,
        "source_manifest_sha256": snapshot.source_manifest_sha256,
        "source_policy_id": snapshot.source_policy_id,
        "current_law_as_of_date": snapshot.current_law_as_of_date,
        "diagnostic_only": True,
        "subjects": list(snapshot.subjects),
    }


@app.post("/api/v1/admin/research/check-now", status_code=status.HTTP_201_CREATED)
async def admin_research_check_now(
    payload: ResearchCheckNowRequest, request: Request
) -> dict[str, Any]:
    from ..observability.live_tracing import TraceLevel
    from ..observability.projections import OwnerProjectionWriter
    from ..research.control_plane import ResearchControlPlane
    from ..research.models import (
        ResearchPriority,
        ResearchTaskRequest,
        ResearchTaskType,
        ResearchTrigger,
    )

    discovery_task = payload.task_type in {"broad_discovery", "gap_research"}
    if discovery_task and payload.source_id not in {None, "legislation_gov_uk"}:
        raise HTTPException(
            422,
            "This connected discovery canary supports only the registered legislation source",
        )
    effective_source_id = payload.source_id or ("legislation_gov_uk" if discovery_task else None)
    if payload.task_type == "source_update_check" and (
        not effective_source_id or not payload.authority_identity_id
    ):
        raise HTTPException(
            422,
            "A registered source and authority identity are required for update checks",
        )
    if payload.task_type == "gap_research" and not (
        payload.knowledge_gap_id or payload.authority_identity_id
    ):
        raise HTTPException(422, "A gap or authority identity is required for gap research")
    services = _services(request)
    control = ResearchControlPlane(services.settings, services.database, cipher=services.cipher)
    admission_started = perf_counter()
    admission_material = json.dumps(
        {
            "task_type": payload.task_type,
            "priority": payload.priority,
            "subject_sha256": hashlib.sha256(payload.subject.encode()).hexdigest(),
            "source_id": effective_source_id,
            "authority_sha256": (
                hashlib.sha256(payload.authority_identity_id.encode()).hexdigest()
                if payload.authority_identity_id
                else None
            ),
            "gap_id_sha256": (
                hashlib.sha256(payload.knowledge_gap_id.encode()).hexdigest()
                if payload.knowledge_gap_id
                else None
            ),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    admission_digest = hashlib.sha256(admission_material.encode()).hexdigest()

    def project_admission(
        *,
        admission_status: str,
        task: Any | None = None,
        error_code: str | None = None,
    ) -> None:
        """Projection failure must never alter durable admission state."""

        with suppress(Exception):
            writer = OwnerProjectionWriter(services.settings)
            task_id = str(task["id"]) if task is not None else None
            authority_id = (
                f"authority-{hashlib.sha256(payload.authority_identity_id.encode()).hexdigest()[:40]}"
                if payload.authority_identity_id
                else None
            )
            trace_id = f"trace-research-{admission_digest[:40]}"
            writer.append_research_trace(
                trace_id=trace_id,
                event_id=f"event-research-admission-{admission_digest[:32]}",
                stage="admission",
                status=admission_status,
                duration_ms=(perf_counter() - admission_started) * 1_000,
                task_id=task_id,
                source_id=effective_source_id,
                authority_identity_id=authority_id,
                task_type=payload.task_type,
                priority=payload.priority,
                level=TraceLevel.ERROR if error_code else TraceLevel.INFO,
                error_code=error_code,
                force=payload.priority == "high" or error_code is not None,
            )
            writer.append_research_metric(
                metric="admissions_total",
                value=1,
                event_id=f"metric-research-admission-{admission_digest[:32]}",
                task_type=payload.task_type,
                priority=payload.priority,
                status=admission_status,
            )
            if task is None:
                return
            queue = services.database.research_queue_telemetry()
            writer.append_research_metric(
                metric="queue_depth",
                value=float(queue["active_depth"]),
                event_id=f"metric-research-queue-{admission_digest[:32]}",
                task_type=payload.task_type,
                priority=payload.priority,
                status=admission_status,
            )
            if queue["oldest_task_age_seconds"] is not None:
                writer.append_research_metric(
                    metric="oldest_task_age_seconds",
                    value=float(queue["oldest_task_age_seconds"]),
                    event_id=f"metric-research-age-{admission_digest[:32]}",
                    task_type=payload.task_type,
                    priority=payload.priority,
                    status=admission_status,
                )

    try:
        row = control.admit(
            ResearchTaskRequest(
                task_type=ResearchTaskType(payload.task_type),
                trigger=ResearchTrigger.MANUAL,
                priority=ResearchPriority(payload.priority),
                subject=payload.subject,
                jurisdiction="England and Wales",
                as_of_date=datetime.now(LONDON).date(),
                source_id=effective_source_id,
                authority_identity_id=payload.authority_identity_id,
                knowledge_gap_id=payload.knowledge_gap_id,
                idempotency_key=payload.idempotency_key,
            )
        )
    except KeyError:
        project_admission(admission_status="error", error_code="source_not_registered")
        raise HTTPException(422, "Research source is not registered") from None
    except (RuntimeError, ValueError):
        project_admission(admission_status="error", error_code="admission_rejected")
        raise HTTPException(409, "Research task failed safe admission checks") from None
    project_admission(admission_status=str(row["status"]), task=row)
    return {
        "task_id": row["id"],
        "status": row["status"],
        "priority": row["priority_band"],
        "pinned_index_build_id": row["pinned_index_build_id"],
    }


@app.get("/api/v1/admin/reviews")
async def admin_reviews(
    request: Request,
    limit: int = ADMIN_REVIEW_DEFAULT_LIMIT,
    offset: int = 0,
    review_type: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    services = _services(request)
    owner_identifiers = tuple(
        value
        for value in getattr(getattr(services, "settings", None), "owner_identifiers", ())
        if isinstance(value, str) and value.strip()
    )
    page_limit = min(max(limit, 1), ADMIN_REVIEW_MAX_LIMIT)
    page_offset = min(max(offset, 0), ADMIN_REVIEW_MAX_OFFSET)
    review_type_filter = _clean_admin_review_filter(review_type, field="review_type")
    status_filter = _clean_admin_review_filter(status, field="status")
    total, rows = services.database.admin_review_page(
        limit=page_limit,
        offset=page_offset,
        review_type=review_type_filter,
        status=status_filter,
    )
    items: list[dict[str, Any]] = []
    for row in rows:
        item = {
            "id": row["id"],
            "review_type": row["review_type"],
            "target_id": row["target_id"],
            "status": row["status"],
            "reason": _owner_safe_summary(
                row["reason"], owner_identifiers=owner_identifiers, limit=500
            ),
            "decision_note": _owner_safe_summary(
                row["decision_note"], owner_identifiers=owner_identifiers, limit=500
            ),
            "created_at": row["created_at"],
            "decided_at": row["decided_at"],
        }
        if row["review_type"] == "source_version":
            try:
                metadata = json.loads(row["metadata_json"] or "{}")
            except (TypeError, json.JSONDecodeError):
                metadata = {}
            citation_data = metadata.get("citation_data", {})
            material_type = metadata.get("material_type") or metadata.get("material_type_candidate")
            source_context = {
                "display_name": row["safe_display_name"],
                "title": _owner_safe_summary(
                    row["source_title"], owner_identifiers=owner_identifiers, limit=300
                ),
                "media_type": row["media_type"],
                "document_status": row["document_status"],
                "lane": row["lane"],
                "subject": row["subject_primary"],
                "jurisdiction": row["jurisdiction"],
                "content_sha256": row["content_sha256"],
                "preview": _owner_safe_summary(
                    row["source_preview"],
                    owner_identifiers=owner_identifiers,
                    limit=800,
                ),
                "stable_identifier": row["stable_identifier"],
                "as_of_date": row["as_of_date"],
                "canonical_url": row["canonical_url"],
                "currentness_status": row["currentness_status"],
                "licence_name": row["licence_name"],
                "licence_url": row["licence_url"],
                "citation_data": citation_data if isinstance(citation_data, dict) else {},
                "material_type": material_type if isinstance(material_type, str) else None,
                "public_identifier_candidate": _safe_public_identifier_candidate(
                    metadata.get("public_identifier_candidate")
                ),
                "identity_title": _owner_safe_summary(
                    metadata.get("identity_title"),
                    owner_identifiers=owner_identifiers,
                    limit=300,
                ),
                "identity_verified": bool(metadata.get("identity_verified", False)),
                "currentness_verified": bool(metadata.get("currentness_verified", False)),
                "subsequent_treatment_check_required": bool(
                    metadata.get("subsequent_treatment_check_required", False)
                ),
                "subsequent_treatment_verified": bool(
                    metadata.get("subsequent_treatment_verified", False)
                ),
            }
            scrubbed_source_context = scrub_prompt_data(source_context, owner_identifiers)
            if not isinstance(scrubbed_source_context, dict):  # pragma: no cover
                raise RuntimeError("source review context must remain an object")
            item["source_context"] = scrubbed_source_context
        elif row["review_type"] == "assessment_rule":
            item["rule_context"] = {
                "task_type": row["task_type"],
                "subject": row["rule_subject"],
                "criterion": row["criterion"],
                "polarity": row["polarity"],
                "grade_band": row["grade_band"],
                "rule_text": _owner_safe_summary(
                    row["rule_text"], owner_identifiers=owner_identifiers, limit=800
                ),
                "remediation_text": _owner_safe_summary(
                    row["remediation_text"],
                    owner_identifiers=owner_identifiers,
                    limit=800,
                ),
            }
        items.append(item)
    return {
        "total": total,
        "limit": page_limit,
        "offset": page_offset,
        "items": items,
    }


@app.post("/api/v1/admin/reviews/{review_id}/{decision}")
async def decide_review(
    review_id: str,
    decision: str,
    request: Request,
    payload: ReviewDecisionRequest | None = None,
) -> dict[str, Any]:
    body = payload.model_dump(mode="json") if payload else {}
    try:
        changed = _services(request).database.decide_review(
            review_id,
            decision,
            body.get("note"),
            body.get("source_approval"),
            (
                _services(request).cipher.encrypt_text(str(body["note"]))
                if body.get("note")
                else None
            ),
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if not changed:
        raise HTTPException(409, "Review is missing or was already decided")
    return {"review_id": review_id, "status": decision}


@app.post("/api/v1/admin/sources/scan", status_code=status.HTTP_202_ACCEPTED)
async def scan_sources(request: Request, background: BackgroundTasks) -> dict[str, Any]:
    services = _services(request)
    try:
        from ..ingestion.service import scan_configured_sources
    except ImportError as exc:
        raise HTTPException(503, "The clean-room ingestion component is not installed") from exc
    scan_id = str(uuid4())
    try:
        services.database.create_source_scan(scan_id, services.settings.source_roots)
    except SourceScanConflictError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    background.add_task(
        scan_configured_sources,
        services.settings,
        services.database,
        services.cipher,
        scan_id,
    )
    return {"scan_id": scan_id, "status": "queued"}


@app.get("/api/v1/admin/source-scans")
async def source_scans(request: Request, limit: int = 100) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for row in _services(request).database.admin_source_scans(min(max(limit, 1), 500)):
        item = _row(row)
        item["required_roots"] = json.loads(row["required_roots_json"])
        item["roots_seen"] = json.loads(row["roots_seen_json"])
        item["statuses"] = json.loads(row["statuses_json"])
        item["exclusion_diagnostics"] = _source_scan_diagnostics(
            _services(request).database, str(row["id"])
        )
        for key in ("required_roots_json", "roots_seen_json", "statuses_json"):
            item.pop(key, None)
        items.append(item)
    return {"items": items}


@app.get("/api/v1/admin/source-scans/{scan_id}")
async def source_scan(scan_id: str, request: Request) -> dict[str, Any]:
    database = _services(request).database
    row = database.fetchone("SELECT * FROM source_scans WHERE id=?", (scan_id,))
    if row is None:
        raise HTTPException(404, "Source scan not found")
    item = _row(row)
    item["required_roots"] = json.loads(row["required_roots_json"])
    item["roots_seen"] = json.loads(row["roots_seen_json"])
    item["statuses"] = json.loads(row["statuses_json"])
    item["exclusion_diagnostics"] = _source_scan_diagnostics(database, scan_id)
    for key in ("required_roots_json", "roots_seen_json", "statuses_json"):
        item.pop(key, None)
    item["files"] = [_safe_source_scan_file(value) for value in database.source_scan_files(scan_id)]
    return item


@app.post(
    "/api/v1/admin/source-scans/{scan_id}/resume",
    status_code=status.HTTP_202_ACCEPTED,
)
async def resume_source_scan(
    scan_id: str, request: Request, background: BackgroundTasks
) -> dict[str, Any]:
    """Retry a failed scan as a new linked attempt, preserving the failed manifest."""

    services = _services(request)
    try:
        from ..ingestion.service import scan_configured_sources
    except ImportError as exc:
        raise HTTPException(503, "The clean-room ingestion component is not installed") from exc
    resumed_scan_id = str(uuid4())
    try:
        services.database.resume_source_scan(
            scan_id,
            resumed_scan_id,
            services.settings.source_roots,
        )
    except SourceScanConflictError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except SourceScanStateError as exc:
        message = str(exc)
        code = status.HTTP_404_NOT_FOUND if message == "Source scan not found" else 409
        raise HTTPException(code, message) from exc
    background.add_task(
        scan_configured_sources,
        services.settings,
        services.database,
        services.cipher,
        resumed_scan_id,
    )
    return {
        "scan_id": resumed_scan_id,
        "status": "queued",
        "resumed_from_scan_id": scan_id,
    }


@app.post("/api/v1/admin/index-builds", status_code=status.HTTP_202_ACCEPTED)
async def build_index(request: Request) -> dict[str, Any]:
    services = _services(request)
    try:
        from ..retrieval.index_build import IndexBuildConflictError, enqueue_index_build
        from ..retrieval.retrieval_v1 import (
            BenchmarkNotFrozenError,
            FrozenBenchmarkMismatchError,
            verify_owner_freeze,
        )
        from ..retrieval.source_manifest import CURRENT_LAW_SLICE_CORPUS_ID
    except ImportError as exc:
        raise HTTPException(503, "The clean-room hybrid index component is not installed") from exc
    try:
        verify_owner_freeze(
            services.settings.project_root,
            services.settings.retrieval_benchmark_path,
        )
    except (BenchmarkNotFrozenError, FrozenBenchmarkMismatchError) as exc:
        raise HTTPException(409, str(exc)) from exc
    try:
        result = enqueue_index_build(
            services.settings,
            services.database,
            corpus_id=CURRENT_LAW_SLICE_CORPUS_ID,
        )
    except IndexBuildConflictError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except JobQueueCapacityError as exc:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "The bounded local index queue is full; wait for the current build to finish",
        ) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return result


@app.post("/api/v1/admin/index-builds/{build_id}/promote")
async def promote_index(build_id: str, request: Request) -> dict[str, Any]:
    try:
        from ..retrieval.service import promote_candidate_index
    except ImportError as exc:
        raise HTTPException(503, "The clean-room hybrid index component is not installed") from exc
    try:
        promote_candidate_index(_services(request).settings, _services(request).database, build_id)
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(409, str(exc)) from exc
    return {"build_id": build_id, "status": "active"}


@app.get("/{client_path:path}", include_in_schema=False)
async def local_web_application(client_path: str) -> FileResponse:
    """Serve the built owner-only SPA without a second production web server."""

    if client_path == "api" or client_path.startswith("api/"):
        raise HTTPException(404, "API route not found")
    root = WEB_DIST.resolve()
    index = root / "index.html"
    if not index.is_file():
        raise HTTPException(503, "The local UI has not been built; run npm run build in web")
    candidate = (root / client_path).resolve()
    if candidate.is_file() and (candidate == root or root in candidate.parents):
        return FileResponse(candidate)
    return FileResponse(index)
