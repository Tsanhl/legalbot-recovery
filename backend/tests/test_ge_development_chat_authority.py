from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from app.api.main import app
from app.config import Settings
from app.contracts.schema_registry import canonical_json_bytes
from app.db import utc_iso
from app.evaluation.evaluation_job_authority import (
    build_evaluation_job_authority,
    replay_evaluation_job_authority,
    verified_evaluation_release_authority_sha256,
)
from app.evaluation.ge_development_chat_authority import (
    GE_DEVELOPMENT_CHAT_SCHEMA,
    validate_development_chat_admission,
    validate_development_chat_read_access,
)
from app.evaluation.ge_qwen_development_authority import persisted_job_idempotency_key
from app.evaluation.live_suite import sealed_sha256
from app.types import QuestionRequest


def _fixture(tmp_path):
    (tmp_path / "config").mkdir()
    (tmp_path / "config/official_sources.json").write_bytes((Path(__file__).resolve().parents[2] / "config/official_sources.json").read_bytes())
    base = Settings(
        project_root=tmp_path,
        development_state_id="owner-chat-test",
        development_candidate_build_id="candidate-chat-r1",
        development_retrieval_manifest_sha256="b" * 64,
    )
    key = "owner-chat-access-key-with-entropy"
    now = datetime.now(UTC)
    authority = {
        "schema": GE_DEVELOPMENT_CHAT_SCHEMA,
        "run_id": "owner-chat-run-r1",
        "owner_scope_sha256": "a" * 64,
        "development_state_id": base.development_state_id,
        "candidate_build_id": base.development_candidate_build_id,
        "retrieval_manifest_sha256": base.development_retrieval_manifest_sha256,
        "access_key_sha256": hashlib.sha256(key.encode()).hexdigest(),
        "issued_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "routes": [{
            "route_id": "qwen_local", "kind": "qwen_local",
            "model_id": base.model_id, "endpoint": base.model_url,
            "credential_env": None,
        }],
        "writes_active": False,
        "release_allowed": True,
        "release_audience": "owner_evaluation",
    }
    authority["seal_sha256"] = sealed_sha256(authority)
    path = base.development_chat_authority_path
    path.parent.mkdir(parents=True)
    raw = canonical_json_bytes(authority)
    path.write_bytes(raw)
    settings = Settings(
        project_root=tmp_path,
        development_state_id=base.development_state_id,
        development_candidate_build_id=base.development_candidate_build_id,
        development_retrieval_manifest_sha256=base.development_retrieval_manifest_sha256,
        development_chat_authority_sha256=hashlib.sha256(raw).hexdigest(),
    )
    request = QuestionRequest(
        question="What official source supports the notice period?",
        jurisdiction="England and Wales",
        as_of_date="2026-09-23",
        word_target=700,
        online_mode="local_only",
    )
    return settings, request, key, path


def test_chat_binding_replays_frozen_request_route_and_index(tmp_path):
    settings, request, key, _ = _fixture(tmp_path)
    raw_key = "chat-idempotency-001"
    binding = validate_development_chat_admission(
        settings=settings,
        supplied_authority_file_sha256=str(settings.development_chat_authority_sha256),
        access_key=key,
        route_id="qwen_local",
        raw_idempotency_key=raw_key,
        payload=request,
    )
    authority = build_evaluation_job_authority(binding)
    row = {
        "id": "job-chat-1",
        "job_type": "answer",
        "idempotency_key": persisted_job_idempotency_key(raw_key),
        "evaluation_run_id": binding.run_id,
        "evaluation_case_id": binding.case_id,
        "evaluation_request_sha256": binding.request_sha256,
        "evaluation_authority_json": json.dumps(authority),
        "evaluation_authority_sha256": authority["seal_sha256"],
        "pinned_index_build_id": binding.candidate_build_id,
        "normal_live_authority_sha256": None,
    }
    verified = replay_evaluation_job_authority(
        settings=settings,
        database=SimpleNamespace(fetchone=lambda *_args: {"status": "candidate"}),
        cipher=SimpleNamespace(),
        row=row, payload=request,
    )
    assert verified_evaluation_release_authority_sha256(verified) == authority["seal_sha256"]
    assert authority["route_id"] == "qwen_local"
    assert authority["writes_active"] is False
    with pytest.raises(RuntimeError, match="not_non_active"):
        replay_evaluation_job_authority(
            settings=settings,
            database=SimpleNamespace(fetchone=lambda *_args: {"status": "active"}),
            cipher=SimpleNamespace(), row=row, payload=request,
        )


def test_chat_rejects_bad_key_route_changed_request_and_upload(tmp_path):
    settings, request, key, _ = _fixture(tmp_path)
    common = dict(
        settings=settings,
        supplied_authority_file_sha256=str(settings.development_chat_authority_sha256),
        route_id="qwen_local", raw_idempotency_key="chat-idempotency-001",
        payload=request,
    )
    with pytest.raises(RuntimeError, match="access_key"):
        validate_development_chat_admission(**{**common, "access_key": "wrong"})
    with pytest.raises(RuntimeError, match="route_not_authorised"):
        validate_development_chat_admission(**{**common, "access_key": key, "route_id": "hosted_api"})
    with pytest.raises(RuntimeError, match="request_scope"):
        validate_development_chat_admission(**{
            **common, "access_key": key,
            "payload": request.model_copy(update={"upload_ids": ["upload-1"]}),
        })
    with pytest.raises(RuntimeError, match="read_access"):
        validate_development_chat_read_access(
            settings=settings,
            supplied_authority_file_sha256=str(settings.development_chat_authority_sha256),
            access_key="wrong", route_id="qwen_local",
        )


def test_chat_file_mutation_fails_closed(tmp_path):
    settings, request, key, path = _fixture(tmp_path)
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(RuntimeError, match="hash_changed"):
        validate_development_chat_admission(
            settings=settings,
            supplied_authority_file_sha256=str(settings.development_chat_authority_sha256),
            access_key=key, route_id="qwen_local",
            raw_idempotency_key="chat-idempotency-001", payload=request,
        )


@pytest.mark.parametrize("kind", ["hosted_api", "anthropic_api", "gemini_api", "codex_bridge", "local_endpoint"])
def test_authority_listing_a_removed_route_is_rejected(tmp_path, kind):
    settings, request, key, path = _fixture(tmp_path)
    authority = json.loads(path.read_text())
    authority["routes"].append({
        "route_id": kind, "kind": kind, "model_id": "synthetic-snapshot",
        "endpoint": None, "credential_env": None,
    })
    authority["seal_sha256"] = sealed_sha256(authority)
    raw = canonical_json_bytes(authority)
    path.write_bytes(raw)
    settings = Settings(
        project_root=tmp_path,
        development_state_id=settings.development_state_id,
        development_candidate_build_id=settings.development_candidate_build_id,
        development_retrieval_manifest_sha256=settings.development_retrieval_manifest_sha256,
        development_chat_authority_sha256=hashlib.sha256(raw).hexdigest(),
    )
    with pytest.raises(RuntimeError, match="development_chat_route_invalid"):
        validate_development_chat_admission(
            settings=settings,
            supplied_authority_file_sha256=str(settings.development_chat_authority_sha256),
            access_key=key, route_id=kind, raw_idempotency_key="chat-remote-001",
            payload=request,
        )


@pytest.mark.asyncio
async def test_api_chat_intake_freezes_provider_and_reuses_idempotency(tmp_path, database, cipher):
    settings, request, key, _ = _fixture(tmp_path)
    database.execute(
        """INSERT INTO index_builds(
          id,status,path,document_count,chunk_count,vector_count,
          embedding_model,reranker_model,created_at
        ) VALUES (?,?,?,?,?,?,?,?,?)""",
        (settings.development_candidate_build_id, "candidate", "data/indexes/candidate-chat-r1",
         1, 1, 1, settings.embedding_model, settings.reranker_model, utc_iso()),
    )
    previous = getattr(app.state, "services", None)
    app.state.services = SimpleNamespace(
        settings=settings, database=database, cipher=cipher,
        retriever=SimpleNamespace(active_build_id=lambda: None),
        conversations=None, observability=None,
    )
    headers = {
        "X-Development-Chat-Authority-SHA256": str(settings.development_chat_authority_sha256),
        "X-Development-Chat-Access-Key": key,
        "X-Development-Chat-Route": "qwen_local",
        "X-Idempotency-Key": "chat-idempotency-001",
    }
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 4312)),
            base_url="http://127.0.0.1:8777",
        ) as client:
            accepted = await client.post(
                "/api/v1/questions", headers=headers, json=request.model_dump(mode="json"),
            )
            repeated = await client.post(
                "/api/v1/questions", headers=headers, json=request.model_dump(mode="json"),
            )
            rejected = await client.post(
                "/api/v1/questions", headers={**headers, "X-Development-Chat-Route": "hosted_api"},
                json=request.model_dump(mode="json"),
            )
    finally:
        if previous is None:
            del app.state.services
        else:
            app.state.services = previous
    assert accepted.status_code == 202, accepted.text
    assert repeated.status_code == 202
    assert repeated.json()["job_id"] == accepted.json()["job_id"]
    assert rejected.status_code == 409
    row = database.job(accepted.json()["job_id"])
    assert row is not None
    authority = json.loads(row["evaluation_authority_json"])
    assert authority["lane"] == "ge_owner_development_chat"
    assert authority["route_id"] == "qwen_local"
    assert row["pinned_index_build_id"] == settings.development_candidate_build_id
