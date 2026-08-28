from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.api.main import app
from app.config import Settings


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

    assert progress == {
        "schema": "legalbot.job-event.v1",
        "sequence": sequence,
        "event": "progress",
        "data": {
            "stage": "qualifying_evidence",
            "progress": 0.4,
            "message": "Checking exact evidence spans.",
            "payload": {"validated_claims": 2},
        },
    }
    assert done["event"] == "done"
    assert done["data"]["status"] == "held_for_review"
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
