import hashlib
import json
import time
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest
from test_ge_development_chat_authority import _fixture

from app.api.main import app
from app.connections import ConnectionStore, ConnectionUnavailable
from app.contracts.schema_registry import canonical_json_bytes
from app.conversations.store import ConversationStore
from app.db import utc_iso
from app.evaluation.ge_development_chat_authority import GE_SESSION_CHAT_SCHEMA, _load_authority
from app.evaluation.live_suite import sealed_sha256


def v2(tmp_path, database, cipher):
    settings, request, key, path = _fixture(tmp_path)
    authority = json.loads(path.read_bytes())
    authority["schema"] = GE_SESSION_CHAT_SCHEMA
    authority["capabilities"] = {
        "session_connections": True,
        "saved_conversations": True,
        "online_modes": ["local_only", "auto", "always"],
        "review_before_use": True,
        "shared_source_admission": False,
    }
    authority["seal_sha256"] = sealed_sha256(authority)
    raw = canonical_json_bytes(authority)
    path.write_bytes(raw)
    settings = replace(
        settings,
        development_chat_authority_sha256=hashlib.sha256(raw).hexdigest(),
        official_research_enabled=True,
        online_default="auto",
    )
    path.with_name("CHAT-ACCESS-KEY.enc").write_bytes(cipher.encrypt_text(key))
    database.execute(
        "INSERT INTO index_builds(id,status,path,embedding_model,reranker_model,created_at) VALUES (?,?,?,?,?,?)",
        (
            settings.development_candidate_build_id,
            "candidate",
            "data/indexes/candidate",
            settings.embedding_model,
            settings.reranker_model,
            utc_iso(),
        ),
    )
    services = SimpleNamespace(
        settings=settings,
        database=database,
        cipher=cipher,
        conversations=ConversationStore.from_settings(database, cipher, settings),
        observability=None,
        retriever=SimpleNamespace(active_build_id=lambda: None),
    )
    return services, request, path


def test_qwen_connection_is_session_owned_and_revocable(database, cipher):
    vault = ConnectionStore(database, cipher)
    owner, token = vault.create_session()
    stranger, _ = vault.create_session()
    route = {
        "route_id": "qwen_local", "kind": "qwen_local", "model_id": "qwen",
        "endpoint": "http://127.0.0.1:8778", "credential_env": None,
    }
    conn = vault.create(owner, route)
    assert "secret" not in conn and "remembered" not in conn
    with pytest.raises(ConnectionUnavailable):
        vault.get(conn["id"], stranger)
    with pytest.raises(ConnectionUnavailable):
        vault.create(owner, {**route, "route_id": "hosted_api", "kind": "hosted_api"})
    vault.disconnect(conn["id"], owner)
    with pytest.raises(ConnectionUnavailable):
        vault.get(conn["id"], owner)
    database.execute("UPDATE chat_browser_sessions SET expires_at=?", (time.time() - 1,))
    with pytest.raises(ConnectionUnavailable):
        vault.session(token)


@pytest.mark.asyncio
async def test_actual_api_saves_clarification_followup_and_blocks_other_session(
    tmp_path, database, cipher
):
    services, original, _ = v2(tmp_path, database, cipher)
    previous = getattr(app.state, "services", None)
    app.state.services = services
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 1234))
    try:
        async with (
            httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8777") as owner,
            httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8777") as other,
        ):
            response = await owner.post("/api/v1/chat/session", json={})
            assert response.status_code == 200
            assert "HttpOnly" in response.headers["set-cookie"]
            assert "access_key" not in response.text
            await other.post("/api/v1/chat/session", json={})
            conn = (
                await owner.post("/api/v1/chat/connections", json={"route_id": "qwen_local"})
            ).json()
            payload = {
                **original.model_dump(mode="json"),
                "connection_id": conn["id"],
                "conversation_id": "conversation-test",
                "question": "I rent in the UK. My landlord emailed on 21 September requiring departure by 5 October. Rent is £1,000.",
            }
            headers = {"X-Idempotency-Key": "first-turn"}
            database.execute(
                "UPDATE chat_connections SET test_status='failed' WHERE id=?", (conn["id"],)
            )
            rejected = await owner.post("/api/v1/chat/questions", json=payload, headers=headers)
            assert rejected.status_code == 409
            assert "failed its connection test" in rejected.text
            database.execute(
                "UPDATE chat_connections SET test_status='untested' WHERE id=?", (conn["id"],)
            )
            admitted = await owner.post("/api/v1/chat/questions", json=payload, headers=headers)
            assert admitted.status_code == 202, admitted.text
            job = admitted.json()["job_id"]
            assert (
                await owner.post("/api/v1/chat/questions", json=payload, headers=headers)
            ).json()["job_id"] == job
            assert (await other.get(f"/api/v1/jobs/{job}")).status_code == 404
            assert (await other.post(f"/api/v1/jobs/{job}/cancel", json={})).status_code == 404
            assert (
                await other.get("/api/v1/conversation-sessions/conversation-test/window")
            ).status_code == 404
            assert (
                await other.post("/api/v1/chat/questions", json=payload, headers=headers)
            ).status_code == 404
            database.execute(
                "UPDATE jobs SET status='held_for_review',stage='held_for_review',user_message=? WHERE id=?",
                ("Which UK nation? Does the landlord share your accommodation?", job),
            )
            window = (await owner.get("/api/v1/chat/conversations/conversation-test")).json()
            assert [m["role"] for m in window["messages"]] == ["user", "assistant"]
            follow = {
                **payload,
                "question": "Birmingham, England. I rent the whole flat; the landlord does not live there. There was no other notice.",
            }
            admitted2 = await owner.post(
                "/api/v1/chat/questions", json=follow, headers={"X-Idempotency-Key": "second-turn"}
            )
            assert admitted2.status_code == 202, admitted2.text
            row = database.job(admitted2.json()["job_id"])
            sent = cipher.decrypt_text(row["encrypted_question"])
            assert (
                "21 September" in sent
                and "£1,000" in sent
                and "Birmingham" in sent
                and "Which UK nation?" in sent
            )
            window = (await owner.get("/api/v1/chat/conversations/conversation-test")).json()
            assert window["messages"][-1]["content"] == follow["question"]
            # Direct intake cannot forge the facade's authenticated session state.
            assert (await owner.post("/api/v1/questions", json=follow)).status_code == 403
    finally:
        app.state.services = previous


@pytest.mark.asyncio
async def test_saved_held_draft_is_visible_only_to_its_local_session(
    tmp_path, database, cipher
):
    services, original, _ = v2(tmp_path, database, cipher)
    previous = getattr(app.state, "services", None)
    app.state.services = services
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 1234))
    draft_text = "## Draft\nThe retailer may owe a refund. [Unverified citation]"
    try:
        async with (
            httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8777") as owner,
            httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8777") as other,
        ):
            await owner.post("/api/v1/chat/session", json={})
            await other.post("/api/v1/chat/session", json={})
            connection = (await owner.post(
                "/api/v1/chat/connections", json={"route_id": "qwen_local"}
            )).json()
            payload = {
                **original.model_dump(mode="json"),
                "connection_id": connection["id"],
                "conversation_id": "conversation-draft-preview",
                "question": "I bought faulty goods. Can I get a refund?",
            }
            accepted = await owner.post(
                "/api/v1/chat/questions", json=payload,
                headers={"X-Idempotency-Key": "draft-preview-test"},
            )
            assert accepted.status_code == 202, accepted.text
            job_id = accepted.json()["job_id"]
            before = await owner.get(f"/api/v1/chat/jobs/{job_id}/draft-preview")
            assert before.json() == {"available": False, "reason": "no_saved_draft_yet"}
            database.store_answer_version(
                answer_id="draft-preview-answer",
                job_id=job_id,
                version_number=1,
                version_kind="structured",
                encrypted_content=cipher.encrypt_text(draft_text),
                word_count=9,
                policy_version="test",
                model_version="qwen-local-test",
                index_build_id=services.settings.development_candidate_build_id,
            )
            database.execute(
                "UPDATE jobs SET status='held_for_review',stage='held_for_review',user_message=? WHERE id=?",
                ("The answer is incomplete because evidence checks failed.", job_id),
            )
            shown = await owner.get(f"/api/v1/chat/jobs/{job_id}/draft-preview")
            assert shown.status_code == 200
            assert shown.headers["cache-control"] == "no-store"
            assert shown.json()["content"] == draft_text
            assert shown.json()["not_released_answer"] is True
            assert shown.json()["not_conversation_history"] is True
            assert (await other.get(f"/api/v1/chat/jobs/{job_id}/draft-preview")).status_code == 404
            conversation = (await owner.get(
                "/api/v1/chat/conversations/conversation-draft-preview"
            )).json()
            assert all(draft_text not in message["content"] for message in conversation["messages"])
            assert conversation["messages"][-1]["display_origin"] == "host_status"
            database.execute(
                "UPDATE conversation_sessions SET expires_at='2000-01-01T00:00:00+00:00' WHERE id=?",
                ("conversation-draft-preview",),
            )
            assert (await owner.get('/api/v1/chat/conversations')).json()['items'] == []
            assert (await owner.get('/api/v1/chat/conversations/conversation-draft-preview')).status_code == 404
            assert (await owner.get(f'/api/v1/chat/jobs/{job_id}/draft-preview')).status_code == 404
            assert (await owner.get(f'/api/v1/jobs/{job_id}')).status_code == 404
            # TTL removes browser access; immutable evaluation custody remains private.
            assert database.fetchone('SELECT id FROM answer_versions WHERE job_id=?', (job_id,)) is not None
    finally:
        app.state.services = previous


def test_v2_authority_still_expires(tmp_path, database, cipher):
    services, _, path = v2(tmp_path, database, cipher)
    authority = json.loads(path.read_bytes())
    authority["expires_at"] = "2020-01-01T00:00:00+00:00"
    authority["seal_sha256"] = sealed_sha256(authority)
    raw = canonical_json_bytes(authority)
    path.write_bytes(raw)
    settings = replace(
        services.settings, development_chat_authority_sha256=hashlib.sha256(raw).hexdigest()
    )
    with pytest.raises(RuntimeError, match="expired"):
        _load_authority(settings)
