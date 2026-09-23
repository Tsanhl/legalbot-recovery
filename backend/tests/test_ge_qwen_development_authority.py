from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest

from app.api.main import app
from app.config import Settings
from app.contracts.schema_registry import canonical_json_bytes
from app.evaluation.evaluation_job_authority import (
    build_evaluation_job_authority,
    replay_evaluation_job_authority,
    verified_evaluation_release_authority_sha256,
)
from app.evaluation.ge_qwen_development_authority import (
    GE_QWEN_DEVELOPMENT_AUTHORITY_SCHEMA,
    development_idempotency_key_sha256,
    development_request_sha256,
    expected_runtime_binding,
    persisted_job_idempotency_key,
    seal_ge_qwen_development_authority,
    validate_ge_qwen_development_api_admission,
)
from app.types import QuestionRequest
from app.db import utc_iso


def _fixture(tmp_path):
    base = Settings(
        project_root=tmp_path,
        development_state_id="ge-qwen-test",
        development_candidate_build_id="candidate-visible-r1",
    )
    request = QuestionRequest(
        question="What notice must my landlord give before seeking possession?",
        jurisdiction="England and Wales",
        as_of_date="2026-09-05",
        word_target=700,
        online_mode="local_only",
    )
    raw_key = "visible-supported-0001"
    now = datetime.now(UTC)
    authority = seal_ge_qwen_development_authority(
        {
            "schema": GE_QWEN_DEVELOPMENT_AUTHORITY_SCHEMA,
            "run_id": "ge-qwen-visible-proof-r1",
            "owner_scope_sha256": "a" * 64,
            "development_state_id": base.development_state_id,
            "candidate_build_id": base.development_candidate_build_id,
            "runtime_binding": expected_runtime_binding(base),
            "issued_at": (now - timedelta(minutes=1)).isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
            "cases": [
                {
                    "case_id": "visible-supported-01",
                    "request_sha256": development_request_sha256(request),
                    "idempotency_key_sha256": development_idempotency_key_sha256(raw_key),
                    "expected_disposition": "supported_answer",
                }
            ],
            "writes_active": False,
            "release_allowed": True,
            "release_audience": "owner_evaluation",
        }
    )
    path = base.development_authority_path
    path.parent.mkdir(parents=True)
    raw = canonical_json_bytes(authority)
    path.write_bytes(raw)
    settings = Settings(
        project_root=tmp_path,
        development_state_id=base.development_state_id,
        development_candidate_build_id=base.development_candidate_build_id,
        development_authority_sha256=hashlib.sha256(raw).hexdigest(),
    )
    return settings, request, raw_key, path


def test_exact_admission_builds_durable_authority_and_replays(tmp_path):
    settings, request, raw_key, _path = _fixture(tmp_path)
    binding = validate_ge_qwen_development_api_admission(
        settings=settings,
        run_id="ge-qwen-visible-proof-r1",
        case_id="visible-supported-01",
        supplied_authority_file_sha256=str(settings.development_authority_sha256),
        raw_idempotency_key=raw_key,
        payload=request,
    )
    authority = build_evaluation_job_authority(binding)
    row = {
        "id": "job-one",
        "job_type": "answer",
        "idempotency_key": persisted_job_idempotency_key(raw_key),
        "evaluation_run_id": binding.run_id,
        "evaluation_case_id": binding.case_id,
        "evaluation_request_sha256": binding.request_sha256,
        "evaluation_authority_json": canonical_json_bytes(authority).decode("utf-8"),
        "evaluation_authority_sha256": authority["seal_sha256"],
        "pinned_index_build_id": binding.candidate_build_id,
        "normal_live_authority_sha256": None,
    }
    verified = replay_evaluation_job_authority(
        settings=settings,
        database=SimpleNamespace(),
        cipher=SimpleNamespace(),
        row=row,
        payload=request,
    )
    assert verified_evaluation_release_authority_sha256(verified) == authority["seal_sha256"]


@pytest.mark.parametrize(
    ("changed_request", "changed_key"),
    [
        ("A materially different question.", None),
        (None, "visible-supported-other"),
    ],
)
def test_changed_request_or_key_is_rejected(tmp_path, changed_request, changed_key):
    settings, request, raw_key, _path = _fixture(tmp_path)
    if changed_request is not None:
        request = request.model_copy(update={"question": changed_request})
    with pytest.raises(RuntimeError, match="request_mismatch"):
        validate_ge_qwen_development_api_admission(
            settings=settings,
            run_id="ge-qwen-visible-proof-r1",
            case_id="visible-supported-01",
            supplied_authority_file_sha256=str(settings.development_authority_sha256),
            raw_idempotency_key=changed_key or raw_key,
            payload=request,
        )


def test_changed_authority_bytes_are_rejected(tmp_path):
    settings, request, raw_key, path = _fixture(tmp_path)
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(RuntimeError, match="file_sha256_mismatch"):
        validate_ge_qwen_development_api_admission(
            settings=settings,
            run_id="ge-qwen-visible-proof-r1",
            case_id="visible-supported-01",
            supplied_authority_file_sha256=str(settings.development_authority_sha256),
            raw_idempotency_key=raw_key,
            payload=request,
        )


@pytest.mark.asyncio
async def test_real_api_intake_persists_exact_development_authority(
    tmp_path, database, cipher
):
    settings, request, raw_key, _path = _fixture(tmp_path)
    now = utc_iso()
    database.execute(
        """
        INSERT INTO index_builds(
          id,status,path,document_count,chunk_count,vector_count,
          embedding_model,reranker_model,created_at
        ) VALUES (?,?,?,?,?,?,?,?,?)
        """,
        (
            settings.development_candidate_build_id,
            "candidate",
            "data/indexes/candidate-visible-r1",
            1,
            1,
            1,
            settings.embedding_model,
            settings.reranker_model,
            now,
        ),
    )
    previous = getattr(app.state, "services", None)
    app.state.services = SimpleNamespace(
        settings=settings,
        database=database,
        cipher=cipher,
        retriever=SimpleNamespace(active_build_id=lambda: None),
        conversations=None,
        observability=None,
    )
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 4311))
    headers = {
        "X-GE-Development-Run-ID": "ge-qwen-visible-proof-r1",
        "X-GE-Development-Case-ID": "visible-supported-01",
        "X-GE-Development-Authority-SHA256": str(
            settings.development_authority_sha256
        ),
        "X-Idempotency-Key": raw_key,
    }
    try:
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8777"
        ) as client:
            accepted = await client.post(
                "/api/v1/questions",
                headers=headers,
                json=request.model_dump(mode="json"),
            )
            repeated = await client.post(
                "/api/v1/questions",
                headers=headers,
                json=request.model_dump(mode="json"),
            )
            rejected = await client.post(
                "/api/v1/questions",
                headers={**headers, "X-GE-Development-Authority-SHA256": "b" * 64},
                json=request.model_dump(mode="json"),
            )
    finally:
        if previous is None:
            del app.state.services
        else:
            app.state.services = previous

    assert accepted.status_code == 202, accepted.text
    assert repeated.status_code == 202, repeated.text
    assert repeated.json()["job_id"] == accepted.json()["job_id"]
    assert rejected.status_code == 409
    row = database.job(accepted.json()["job_id"])
    assert row is not None
    assert row["pinned_index_build_id"] == settings.development_candidate_build_id
    assert row["evaluation_run_id"] == "ge-qwen-visible-proof-r1"
    assert row["evaluation_case_id"] == "visible-supported-01"
    assert row["evaluation_request_sha256"] == development_request_sha256(request)
    assert row["normal_live_authority_sha256"] is None
