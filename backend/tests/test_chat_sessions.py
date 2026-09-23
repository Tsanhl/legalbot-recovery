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


def test_credentials_encrypted_expired_and_revoked(database, cipher):
    vault = ConnectionStore(database, cipher)
    owner, token = vault.create_session()
    stranger, _ = vault.create_session()
    route = {
        "route_id": "hosted_api",
        "kind": "hosted_api",
        "model_id": "test-model",
        "endpoint": "https://api.openai.com/v1/responses",
        "credential_env": "OPENAI_API_KEY",
    }
    conn = vault.create(owner, route, secret="not-a-real-key-12345", remember=False)
    assert "secret" not in conn
    assert vault.secret(conn["id"]) == "not-a-real-key-12345"
    assert b"not-a-real-key" not in database.path.read_bytes()
    with pytest.raises(ConnectionUnavailable):
        vault.get(conn["id"], stranger)
    # Independent worker instance sees protected temporary credentials.
    assert ConnectionStore(database, cipher).secret(conn["id"]) == "not-a-real-key-12345"
    vault.disconnect(conn["id"], owner)
    with pytest.raises(ConnectionUnavailable):
        vault.secret(conn["id"])
    database.execute("UPDATE chat_browser_sessions SET expires_at=?", (time.time() - 1,))
    with pytest.raises(ConnectionUnavailable):
        vault.session(token)


def test_remember_requires_os_vault_and_disconnect_deletes(database, cipher):
    class Vault:
        def __init__(self):
            self.keys = {}

        def set_password(self, s, k, v):
            self.keys[(s, k)] = v

        def get_password(self, s, k):
            return self.keys.get((s, k))

        def delete_password(self, s, k):
            self.keys.pop((s, k))

    native = Vault()
    store = ConnectionStore(database, cipher, vault=native)
    owner, _ = store.create_session()
    route = {"route_id": "gemini_api", "kind": "gemini_api", "model_id": "test-model"}
    conn = store.create(owner, route, secret="secret-key-test", remember=True)
    assert store.get(conn["id"])["secret"] is None
    assert store.secret(conn["id"]) == "secret-key-test"
    store.disconnect(conn["id"], owner)
    assert not native.keys


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
