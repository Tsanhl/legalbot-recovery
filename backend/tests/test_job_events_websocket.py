from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.api.main import _browser_terminal_event, _job_attempt_identity, app
from app.config import Settings
from app.contracts import ContractSchemaRegistry, committed_terminal_event_id


def _terminal_job(database, cipher) -> int:
    stamp = datetime(2026, 8, 24, tzinfo=UTC).isoformat()
    database.execute(
        """
        INSERT INTO jobs(
          id,status,stage,progress,encrypted_question,question_summary,request_json,
          route,route_reasons_json,user_message,created_at,updated_at
        ) VALUES ('job-websocket-1','held_for_review','held_for_review',1,?,
          'Private encrypted question','{}','direct','[]',
          'Evidence requires owner review.',?,?)
        """,
        (cipher.encrypt_text("Owner question"), stamp, stamp),
    )
    cursor = database.execute(
        """
        INSERT INTO job_events(job_id,stage,progress,message,payload_json,created_at)
        VALUES ('job-websocket-1','qualifying_evidence',0.4,
                'Checking exact evidence spans.',?,?)
        """,
        (json.dumps({"validated_claims": 2}), stamp),
    )
    return int(cursor.lastrowid)


@contextmanager
def _services(database, cipher, tmp_path):
    previous = getattr(app.state, "services", None)
    app.state.services = SimpleNamespace(
        database=database,
        cipher=cipher,
        settings=Settings(project_root=tmp_path, test_mode=True),
    )
    try:
        yield
    finally:
        if previous is None:
            del app.state.services
        else:
            app.state.services = previous


def test_websocket_replays_safe_progress_then_terminal_event(database, cipher, tmp_path) -> None:
    sequence = _terminal_job(database, cipher)
    with _services(database, cipher, tmp_path):
        client = TestClient(app)
        with client.websocket_connect(
            "/api/v1/jobs/job-websocket-1/events/ws?after=0",
            subprotocols=["legalbot.job-events.v1"],
        ) as websocket:
            assert websocket.accepted_subprotocol == "legalbot.job-events.v1"
            progress = websocket.receive_json()
            done = websocket.receive_json()
        client.close()

    registry = ContractSchemaRegistry.from_project_root(Settings().project_root)
    registry.validate_new(progress)
    registry.validate_new(done)
    assert progress["schema"] == "legalbot.job-event.v1"
    assert progress["job_id"] == "job-websocket-1"
    assert progress["sequence"] == sequence
    assert progress["event"] == "progress"
    assert progress["data"] == {
        "stage": "qualifying_evidence",
        "progress": 0.4,
        "message_code": "job.stage.qualifying_evidence",
        "status": None,
        "release_state": None,
        "answer_id": None,
        "release_sha256": None,
        "status_url": "/api/v1/jobs/job-websocket-1",
        "release_id": None,
        "terminal_kind": None,
        "reset_from_sequence": None,
    }
    assert done["event"] == "done"
    assert done["sequence"] > progress["sequence"]
    assert done["event_id"] != progress["event_id"]
    assert done["data"]["status"] == "held"
    assert done["data"]["terminal_kind"] == "held"
    assert done["data"]["answer_id"] is None
    assert "token" not in json.dumps((progress, done)).casefold()
    assert "raw_text" not in json.dumps((progress, done)).casefold()


def test_websocket_after_sequence_does_not_replay_old_progress(database, cipher, tmp_path) -> None:
    sequence = _terminal_job(database, cipher)
    with _services(database, cipher, tmp_path):
        client = TestClient(app)
        with client.websocket_connect(
            f"/api/v1/jobs/job-websocket-1/events/ws?after={sequence}",
            subprotocols=["legalbot.job-events.v1"],
        ) as websocket:
            event = websocket.receive_json()
        client.close()

    assert event["event"] == "done"
    assert event["sequence"] == sequence + 1


def test_websocket_rejects_untrusted_host(database, cipher, tmp_path) -> None:
    _terminal_job(database, cipher)
    with _services(database, cipher, tmp_path):
        client = TestClient(app)
        with (
            pytest.raises(WebSocketDisconnect) as stopped,
            client.websocket_connect(
                "/api/v1/jobs/job-websocket-1/events/ws",
                headers={"host": "attacker.invalid"},
                subprotocols=["legalbot.job-events.v1"],
            ),
        ):
            pass
        client.close()
    assert stopped.value.code == 1008


def test_normal_live_terminal_uses_actual_selected_release_digest() -> None:
    job = {
        "id": "job-selected-terminal-1",
        "status": "complete",
        "answer_id": "answer-selected-terminal-1",
        "release_state": "verified_full",
        "attempt_count": 2,
        "updated_at": datetime(2026, 9, 1, tzinfo=UTC).isoformat(),
    }
    attempt_id, generation = _job_attempt_identity(job)
    sequence = 9
    terminal_id = committed_terminal_event_id(
        job_id=job["id"],
        attempt_id=attempt_id,
        lease_generation=generation,
        sequence=sequence,
    )
    outbox = {
        "id": "outbox-selected-terminal-1",
        "release_audience": "normal_live",
        "answer_sha256": None,
    }
    selected_chain = {
        "status": "verified_unpublished",
        "job_id": job["id"],
        "answer_id": job["answer_id"],
        "release_state": job["release_state"],
        "attempt_id": attempt_id,
        "lease_generation": generation,
        "terminal_sequence": sequence,
        "release_id": "verified-release-selected-terminal-1",
        "release_sha256": "a" * 64,
        "terminal_event_id": terminal_id,
    }

    event = _browser_terminal_event(
        job=job,
        sequence=sequence,
        release_outbox=outbox,
        selected_chain=selected_chain,
    )
    ContractSchemaRegistry.from_project_root(Settings().project_root).validate_new(event)
    assert event["event_id"] == terminal_id
    assert event["data"]["release_sha256"] == "a" * 64
    assert event["data"]["release_id"] == "verified-release-selected-terminal-1"
    assert event["data"]["terminal_kind"] == "committed"

    missing = _browser_terminal_event(
        job=job,
        sequence=sequence,
        release_outbox=outbox,
        selected_chain=None,
    )
    assert missing["data"]["terminal_kind"] == "system_error"
    assert missing["data"]["release_sha256"] is None


@pytest.mark.parametrize("subprotocols", [None, ["unrelated.protocol.v1"]])
def test_websocket_requires_exact_job_event_subprotocol(
    database, cipher, tmp_path, subprotocols
) -> None:
    _terminal_job(database, cipher)
    with _services(database, cipher, tmp_path):
        client = TestClient(app)
        kwargs = {"subprotocols": subprotocols} if subprotocols is not None else {}
        with (
            pytest.raises(WebSocketDisconnect) as stopped,
            client.websocket_connect(
                "/api/v1/jobs/job-websocket-1/events/ws",
                **kwargs,
            ),
        ):
            pass
        client.close()
    assert stopped.value.code == 1002
