from __future__ import annotations

from datetime import UTC, datetime

from app.config import Settings
from app.observability.control_plane import (
    assert_safe_control_plane_snapshot,
    build_control_plane_snapshot,
)


def test_candidate_snapshot_is_safe(tmp_path, database) -> None:
    settings = Settings(project_root=tmp_path, test_mode=True)
    snapshot = build_control_plane_snapshot(
        settings,
        database,
        mode="candidate",
        now=datetime(2026, 8, 19, tzinfo=UTC),
    )
    assert snapshot["schema"] == "legalbot.control-plane-snapshot.v1"
    assert "queues" in snapshot
    assert snapshot["scope"] == "observe_only"
    assert snapshot["certification_ready"] is False
    assert "ready" not in snapshot
    assert_safe_control_plane_snapshot(snapshot)


def test_snapshot_rejects_private_or_prompt_fields() -> None:
    for value in (
        {"question": "secret"},
        {"value": "/Users/owner/private"},
        {"system_prompt": "hidden"},
    ):
        try:
            assert_safe_control_plane_snapshot(value)
        except ValueError:
            pass
        else:  # pragma: no cover
            raise AssertionError("unsafe snapshot was accepted")
