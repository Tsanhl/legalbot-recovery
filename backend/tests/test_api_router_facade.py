from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
from cryptography.fernet import Fernet

from app.api.main import (
    admin_live_evaluation,
    admin_live_evaluations,
    admin_runtime_records,
    app,
    create_answer_feedback,
)
from app.crypto import LocalCipher
from app.db import Database
from app.runtime_records.service import RuntimeRecordService


def test_extracted_routes_remain_on_the_main_app() -> None:
    paths = {getattr(route, "path", "") for route in app.routes}
    assert "/api/v1/admin/live-evaluations" in paths
    assert "/api/v1/answers/{answer_id}/feedback" in paths
    assert "/api/v1/admin/runtime-records" in paths
    assert callable(admin_live_evaluations)
    assert callable(admin_live_evaluation)
    assert callable(create_answer_feedback)
    assert callable(admin_runtime_records)


@pytest.mark.asyncio
async def test_runtime_records_status_omits_plaintext_secrets(
    tmp_path,
) -> None:
    database = Database(tmp_path / "catalog.sqlite3")
    database.initialize()
    cipher = LocalCipher(Fernet(Fernet.generate_key()))
    objects = tmp_path / "objects"
    RuntimeRecordService(database, cipher, object_dir=objects).record_feedback(
        kind="wrong_answer",
        class_code="wrong_ratio",
        note="secret owner note",
    )
    previous = getattr(app.state, "services", None)
    app.state.services = SimpleNamespace(
        database=database,
        cipher=cipher,
        settings=SimpleNamespace(runtime_object_dir=objects),
    )
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://127.0.0.1:8777",
        ) as client:
            response = await client.get("/api/v1/admin/runtime-records")
        assert response.status_code == 200
        body = response.json()
        assert body["schema"] == "legalbot.runtime-records-status.v1"
        assert body["plaintext_secrets"] is False
        assert body["eligible_for_training"] is False
        assert body["training_export_allowed"] is False
        assert body["feedback_count"] == 1
        assert "secret owner note" not in response.text
    finally:
        database.close()
        if previous is None:
            del app.state.services
        else:
            app.state.services = previous
