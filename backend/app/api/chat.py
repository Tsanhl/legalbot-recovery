"""Session UI facade over the existing candidate-pinned question/job pipeline."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field, SecretStr

from ..connections import (
    COOKIE,
    SESSION_SECONDS,
    ConnectionStore,
    ConnectionUnavailable,
    request_digest,
)
from ..evaluation.ge_development_chat_authority import (
    GE_SESSION_CHAT_SCHEMA,
    _load_authority,
    load_development_chat_route,
)
from ..types import QuestionRequest

router = APIRouter(prefix="/api/v1/chat")


def store(services: Any) -> ConnectionStore:
    return ConnectionStore(services.database, services.cipher)


def require_session(request: Request, services: Any) -> tuple[ConnectionStore, str]:
    vault = store(services)
    try:
        return vault, vault.session(request.cookies.get(COOKIE))
    except ConnectionUnavailable:
        raise HTTPException(401, "Reconnect in this browser to restore your session") from None


def config(services: Any) -> dict[str, Any]:
    try:
        authority, _ = _load_authority(services.settings)
        if authority["schema"] != GE_SESSION_CHAT_SCHEMA:
            raise RuntimeError("session_authority_required")
        return authority
    except (RuntimeError, ValueError, OSError):
        raise HTTPException(
            503, "Local chat is not configured; start the authorised chat launcher"
        ) from None


def install_headers(request: Request, services: Any, route_id: str, consent: bool = False) -> None:
    # Only server code can supply the development capability. It never enters a response.
    path = services.settings.development_chat_authority_path.with_name("CHAT-ACCESS-KEY.enc")
    if path.is_symlink() or not path.is_file():
        raise HTTPException(503, "Local chat launcher credential is unavailable")
    key = services.cipher.decrypt_text(path.read_bytes())
    additions = {
        "x-development-chat-authority-sha256": str(
            services.settings.development_chat_authority_sha256
        ),
        "x-development-chat-access-key": key,
        "x-development-chat-route": route_id,
        "x-development-chat-remote-consent": "yes" if consent else "no",
    }
    request.scope["headers"] = [
        (k, v) for k, v in request.scope["headers"] if k.decode().lower() not in additions
    ]
    request.scope["headers"].extend((k.encode(), v.encode()) for k, v in additions.items())
    if hasattr(request, "_headers"):
        del request._headers


def authorise_job_read(request: Request, services: Any, job: Any) -> None:
    # Applies even to queued jobs, held drafts, cancellation and reconnect.
    value = json.loads(str(job["request_json"] or "{}"))
    if not value.get("connection_id") and not hasattr(services, "cipher"):
        # Legacy non-chat callers can have a minimal service fixture.  A chat
        # request always carries a connection identity and must fail closed.
        return
    store(services)
    owned = services.database.fetchone(
        "SELECT * FROM chat_owned_jobs WHERE job_id=?", (str(job["id"]),)
    )
    if owned is None:
        if value.get("connection_id"):
            raise HTTPException(403, "Chat job ownership is unavailable")
        return
    if not value.get("connection_id"):
        raise HTTPException(409, "Chat job connection identity is unavailable")
    _, session = require_session(request, services)
    if owned["session_id"] != session:
        raise HTTPException(404, "Job not found")
    try:
        store(services).require_conversation(str(owned["conversation_id"]), session)
    except ConnectionUnavailable:
        raise HTTPException(404, "Conversation expired or unavailable") from None
    # Historical reads do not require a still-connected provider credential.
    connection = services.database.fetchone(
        "SELECT route_id FROM chat_connections WHERE id=?", (owned["connection_id"],)
    )
    if connection is None:
        raise HTTPException(409, "Chat connection provenance unavailable")
    install_headers(request, services, str(connection["route_id"]))


@router.post("/session")
async def session(request: Request, response: Response) -> dict[str, Any]:
    services = request.app.state.services
    authority = config(services)
    vault = store(services)
    try:
        identifier = vault.session(request.cookies.get(COOKIE))
    except ConnectionUnavailable:
        identifier, token = vault.create_session()
        response.set_cookie(
            COOKIE,
            token,
            httponly=True,
            samesite="strict",
            secure=request.url.scheme == "https",
            max_age=SESSION_SECONDS,
            path="/api",
        )
    return {
        "connections": vault.list(identifier),
        "routes": [
            {"route_id": r["route_id"], "model_id": r["model_id"], "kind": r["kind"]}
            for r in authority["routes"]
        ],
        "default_route": "codex_bridge",
        "online_research_available": services.settings.official_research_enabled,
        "coverage": "UK and USA; support is checked for each jurisdiction and date",
        "conversation_retention_days": services.settings.conversation_retention_days,
    }


class ConnectionInput(BaseModel):
    route_id: str = Field(min_length=3, max_length=128)
    api_key: SecretStr | None = None
    remember: bool = False


@router.get("/connections")
async def connections(request: Request) -> dict[str, Any]:
    vault, session_id = require_session(request, request.app.state.services)
    return {"items": vault.list(session_id)}


@router.post("/connections")
async def connect(payload: ConnectionInput, request: Request) -> dict[str, Any]:
    services = request.app.state.services
    config(services)
    vault, session_id = require_session(request, services)
    try:
        route = load_development_chat_route(services.settings, payload.route_id)
        return vault.create(
            session_id,
            route,
            secret=payload.api_key.get_secret_value() if payload.api_key else None,
            remember=payload.remember,
        )
    except (ConnectionUnavailable, RuntimeError):
        raise HTTPException(
            422,
            "Connection could not be created; check the provider, key and operating-system credential store",
        ) from None


@router.post("/connections/{connection_id}/disconnect")
async def disconnect(connection_id: str, request: Request) -> dict[str, Any]:
    vault, session_id = require_session(request, request.app.state.services)
    try:
        vault.disconnect(connection_id, session_id)
    except ConnectionUnavailable:
        raise HTTPException(
            409, "Connection revoked or unavailable; check credential-store status"
        ) from None
    return {"disconnected": True}


@router.post("/connections/{connection_id}/test")
async def test_connection(connection_id: str, request: Request) -> dict[str, Any]:
    services = request.app.state.services
    vault, session_id = require_session(request, services)
    try:
        row = vault.get(connection_id, session_id)
        token = services.model.select(
            str(row["route_id"]), connection_id=connection_id, connection_store=vault
        )
    except (RuntimeError, ConnectionUnavailable):
        raise HTTPException(404, "Connection unavailable") from None
    try:
        # Real minimal inference, not a key-presence or health assertion. No legal data.
        _, result = await asyncio.wait_for(
            services.model.invoke_json(
                system_prompt='Return only a JSON object {"connection_test":"ok"}.',
                user_payload={"connection_test": "Reply with ok"},
                mode="semantic_verify",
            ),
            timeout=90,
        )
        success = result == {"connection_test": "ok"}
    except Exception:
        success = False
    finally:
        services.model.reset(token)
    state = "passed" if success else "failed"
    services.database.execute(
        "UPDATE chat_connections SET test_status=?,tested_at=? WHERE id=?",
        (state, datetime.now(UTC).timestamp(), connection_id),
    )
    return {"status": state, "legal_answer_qualified": False, "route_id": row["route_id"]}


def project_terminal(services: Any, conversation_id: str) -> None:
    rows = services.database.fetchall(
        "SELECT j.* FROM chat_owned_jobs c JOIN jobs j ON j.id=c.job_id WHERE c.conversation_id=? ORDER BY j.created_at",
        (conversation_id,),
    )
    for row in rows:
        if row["status"] not in {
            "complete",
            "held_for_review",
            "system_error",
            "cancelled",
            "failed",
            "dlq",
        }:
            continue
        if services.database.fetchone(
            "SELECT id FROM conversation_messages WHERE job_id=? AND role='assistant'", (row["id"],)
        ):
            continue
        if services.conversations.append_released_answer(str(row["id"])):
            continue
        # Store only the exact displayed safe status/clarification, never a held legal draft.
        services.conversations.append_message(
            conversation_id,
            role="assistant",
            content=str(row["user_message"] or "The answer is incomplete."),
            job_id=str(row["id"]),
        )


@router.get("/conversations")
async def conversations(request: Request) -> dict[str, Any]:
    services = request.app.state.services
    vault, session_id = require_session(request, services)
    rows = services.database.fetchall(
        "SELECT o.id FROM chat_owned_conversations o JOIN conversation_sessions c ON c.id=o.id "
        "WHERE o.session_id=? AND c.status='active' AND c.expires_at>? ORDER BY o.created_at DESC",
        (session_id, datetime.now(UTC).isoformat()),
    )
    return {"items": [{"id": r["id"]} for r in rows]}


@router.get("/conversations/{conversation_id}")
async def conversation(conversation_id: str, request: Request) -> dict[str, Any]:
    services = request.app.state.services
    vault, session_id = require_session(request, services)
    try:
        vault.require_conversation(conversation_id, session_id)
    except ConnectionUnavailable:
        raise HTTPException(404, "Conversation not found") from None
    project_terminal(services, conversation_id)
    window = services.conversations.window(conversation_id)
    jobs = services.database.fetchall(
        "SELECT j.id,j.status,j.stage,json_extract(j.request_json,'$.jurisdiction') AS jurisdiction,json_extract(j.request_json,'$.as_of_date') AS as_of_date,json_extract(j.request_json,'$.task_type') AS task_type,json_extract(j.request_json,'$.word_target') AS word_target,c.connection_id FROM chat_owned_jobs c JOIN jobs j ON j.id=c.job_id WHERE c.conversation_id=? ORDER BY j.created_at",
        (conversation_id,),
    )
    provenance = {}
    for job in jobs:
        connection = services.database.fetchone("SELECT route_id FROM chat_connections WHERE id=?", (job["connection_id"],))
        route = load_development_chat_route(services.settings, str(connection["route_id"])) if connection else {}
        provenance[job["id"]] = {"selected_provider": route.get("route_id"),
                                 "selected_model": route.get("model_id"),
                                 "publication_status": job["status"]}
    return {
        "conversation_id": conversation_id,
        "messages": [{**asdict(m), **provenance.get(m.job_id, {}),
                      "display_origin": "released_answer" if m.answer_id else ("host_status" if m.role == "assistant" else "user")}
                     for m in window.messages],
        "truncated": window.truncated,
        "jobs": [dict(j) for j in jobs],
    }


@router.get("/jobs/{job_id}/draft-preview")
async def draft_preview(job_id: str, request: Request, response: Response) -> dict[str, Any]:
    """Show the session owner a saved draft without granting publication authority."""
    services = request.app.state.services
    settings = services.settings
    if (
        settings.environment != "development"
        or settings.host != "127.0.0.1"
        or not settings.development_state_id
    ):
        raise HTTPException(404, "Draft preview is unavailable")
    config(services)
    _, session_id = require_session(request, services)
    owned = services.database.fetchone(
        "SELECT j.status,j.answer_id,c.conversation_id FROM chat_owned_jobs c "
        "JOIN jobs j ON j.id=c.job_id WHERE c.job_id=? AND c.session_id=?",
        (job_id, session_id),
    )
    if owned is None:
        raise HTTPException(404, "Draft preview not found")
    try:
        store(services).require_conversation(str(owned["conversation_id"]), session_id)
    except ConnectionUnavailable:
        raise HTTPException(404, "Conversation expired or unavailable") from None
    response.headers["Cache-Control"] = "no-store"
    if owned["status"] == "complete" and owned["answer_id"]:
        return {"available": False, "reason": "released_answer"}
    version = services.database.fetchone(
        "SELECT id,version_number,version_kind,encrypted_content,word_count,model_version "
        "FROM answer_versions WHERE job_id=? "
        "AND version_kind IN ('structured','targeted_repair') "
        "ORDER BY version_number DESC LIMIT 1",
        (job_id,),
    )
    if version is None:
        return {"available": False, "reason": "no_saved_draft_yet"}
    try:
        content = services.cipher.decrypt_text(bytes(version["encrypted_content"]))
    except (TypeError, ValueError):
        raise HTTPException(409, "Saved draft could not be opened") from None
    report = services.database.fetchone(
        "SELECT findings_json FROM quality_reports WHERE answer_version_id=? "
        "ORDER BY rowid DESC LIMIT 1",
        (version["id"],),
    )
    findings: list[dict[str, str]] = []
    if report is not None:
        try:
            raw_findings = json.loads(str(report["findings_json"] or "[]"))
            findings = [
                {"code": str(item.get("code") or "review_finding"),
                 "message": str(item.get("message") or "")}
                for item in raw_findings
                if isinstance(item, dict)
                and item.get("severity") in {"hard_blocker", "repairable"}
            ][:12]
        except (TypeError, ValueError):
            findings = []
    return {
        "available": True,
        "status": "unverified_draft",
        "job_status": str(owned["status"]),
        "version": int(version["version_number"]),
        "model_version": str(version["model_version"]),
        "word_count": int(version["word_count"]),
        "content": content,
        "review_findings": findings,
        "review_complete": report is not None,
        "not_conversation_history": True,
        "not_released_answer": True,
    }


class DisplayMessage(BaseModel):
    id: str = Field(max_length=128)
    role: Literal["user", "assistant"]
    text: str = Field(max_length=200_000)


class DisplayReceipt(BaseModel):
    messages: list[DisplayMessage] = Field(min_length=1, max_length=64)


@router.post("/conversations/{conversation_id}/display-receipts")
async def display_receipt(conversation_id: str, payload: DisplayReceipt, request: Request) -> dict[str, str]:
    """Client-observed rendering evidence, never answer verification authority."""
    services = request.app.state.services
    vault, session_id = require_session(request, services)
    try:
        vault.require_conversation(conversation_id, session_id)
    except ConnectionUnavailable:
        raise HTTPException(404, "Conversation not found") from None
    window = services.conversations.window(conversation_id)
    if [(m.id, m.role) for m in window.messages] != [(m.id, m.role) for m in payload.messages]:
        raise HTTPException(409, "Display receipt does not match the saved message sequence")
    material = {"schema": "legalbot.browser-display-receipt.v1", "conversation_id": conversation_id,
                "origin": "browser DOM innerText; client-supplied observation, not trusted legal evidence",
                "messages": [m.model_dump() for m in payload.messages]}
    raw = json.dumps(material, ensure_ascii=False, sort_keys=True).encode()
    if len(raw) > 1_000_000:
        raise HTTPException(413, "Display receipt is too large")
    digest = hashlib.sha256(raw).hexdigest()
    directory = services.settings.vault_dir / "display-receipts"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / (digest + ".enc")
    try:
        with path.open("xb") as handle:
            handle.write(services.cipher.encrypt_bytes(raw))
        path.chmod(0o600)
    except FileExistsError:
        pass
    return {"sha256": digest}


@router.post("/questions", status_code=202)
async def question(payload: QuestionRequest, request: Request) -> Any:
    from .main import create_question

    services = request.app.state.services
    config(services)
    vault, session_id = require_session(request, services)
    if not payload.connection_id or not payload.conversation_id:
        raise HTTPException(422, "Select a connection and conversation")
    try:
        connection = vault.get(payload.connection_id, session_id)
        vault.claim_conversation(payload.conversation_id, session_id)
    except ConnectionUnavailable:
        raise HTTPException(404, "Connection or conversation unavailable") from None
    if connection["test_status"] == "failed":
        raise HTTPException(409, "Selected model failed its connection test")
    key = request.headers.get("x-idempotency-key", "")
    if not 8 <= len(key) <= 128:
        raise HTTPException(422, "An idempotency key is required")
    scoped_key = hashlib.sha256((session_id + "\0" + key).encode()).hexdigest()
    digest = request_digest(payload.model_dump(mode="json"))
    prior = services.database.fetchone(
        "SELECT * FROM chat_owned_jobs WHERE idempotency_sha256=?", (scoped_key,)
    )
    install_headers(
        request,
        services,
        str(connection["route_id"]),
        request.headers.get("x-remote-processing-consent") == "yes",
    )
    if prior:
        if prior["session_id"] != session_id or prior["input_sha256"] != digest:
            raise HTTPException(409, "Idempotency key belongs to a different message")
        row = services.database.job(str(prior["job_id"]))
        return {
            "job_id": row["id"],
            "status": row["status"],
            "stage": row["stage"],
            "events_url": f"/api/v1/jobs/{row['id']}/events",
            "conversation_id": prior["conversation_id"],
        }
    services.conversations.create_session(payload.conversation_id)
    project_terminal(services, payload.conversation_id)
    unfinished = services.database.fetchone(
        "SELECT j.id FROM chat_owned_jobs c JOIN jobs j ON j.id=c.job_id WHERE c.conversation_id=? AND j.status IN ('queued','running')",
        (payload.conversation_id,),
    )
    if unfinished:
        raise HTTPException(
            409, "Wait for the current answer or cancel it before sending a follow-up"
        )
    window = services.conversations.window(payload.conversation_id)
    if window.truncated:
        raise HTTPException(
            409,
            "This conversation exceeds the verified context window; start a new case with a confirmed summary",
        )
    context = "\n\n".join(
        f"{m.role.upper()} MESSAGE {m.ordinal}:\n{m.content}" for m in window.messages
    )
    text = (
        (
            "Saved conversation (user facts and assistant questions; not legal authority). Resolve contradictions explicitly; never silently replace a supplied fact.\n"
            + context
            + "\n\nCURRENT USER MESSAGE:\n"
            + payload.question
        )
        if context
        else payload.question
    )
    if len(text) > 30000:
        raise HTTPException(
            409, "The complete context is too long; no facts have been silently discarded"
        )
    request.state.chat_raw_message = payload.question
    request.state.chat_session_id = session_id
    # Namespace retries per browser so another session cannot collide with a job.
    request.scope["headers"] = [
        (k, v) for k, v in request.scope["headers"] if k != b"x-idempotency-key"
    ] + [(b"x-idempotency-key", scoped_key.encode())]
    if hasattr(request, "_headers"):
        del request._headers
    from ..conversations.clarification import resolved_jurisdiction
    jurisdiction = resolved_jurisdiction(payload.jurisdiction, text)
    accepted = await create_question(payload.model_copy(update={"question": text, "jurisdiction": jurisdiction}), request)
    services.database.execute(
        "INSERT INTO chat_owned_jobs VALUES (?,?,?,?,?,?)",
        (
            accepted.job_id,
            session_id,
            payload.connection_id,
            payload.conversation_id,
            digest,
            scoped_key,
        ),
    )
    return accepted
