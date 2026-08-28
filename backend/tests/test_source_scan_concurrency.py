from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from app.api.main import app
from app.db import (
    Database,
    SourceScanConflictError,
    SourceScanStateError,
    utc_iso,
)


def test_source_scan_creation_is_idempotent_for_its_worker_and_blocks_another(
    database: Database, tmp_path: Path
) -> None:
    roots = (tmp_path / "sources",)
    roots[0].mkdir()

    descriptors = database.create_source_scan("scan-one", roots)
    assert database.create_source_scan("scan-one", roots) == descriptors
    with pytest.raises(SourceScanConflictError, match="already queued"):
        database.create_source_scan("scan-two", roots)

    database.start_source_scan("scan-one", roots_seen=descriptors, expected_file_count=0)
    with pytest.raises(SourceScanStateError, match="duplicate worker"):
        database.start_source_scan("scan-one", roots_seen=descriptors, expected_file_count=0)
    with pytest.raises(SourceScanConflictError, match="already running"):
        database.create_source_scan("scan-two", roots)

    result = database.complete_source_scan("scan-one")
    assert result["status"] == "complete"
    assert database.create_source_scan("scan-two", roots)


def test_database_constraint_allows_only_one_concurrent_creator(tmp_path: Path) -> None:
    path = tmp_path / "catalog.sqlite3"
    first = Database(path)
    second = Database(path)
    first.initialize()
    second.initialize()
    root = tmp_path / "sources"
    root.mkdir()

    def create(database: Database, scan_id: str) -> str:
        try:
            database.create_source_scan(scan_id, (root,))
        except SourceScanConflictError:
            return "conflict"
        return "created"

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(
                executor.map(
                    lambda pair: create(*pair),
                    ((first, "scan-a"), (second, "scan-b")),
                )
            )
        assert sorted(outcomes) == ["conflict", "created"]
        active = first.fetchall(
            "SELECT id, status FROM source_scans WHERE status IN ('queued', 'running')"
        )
        assert len(active) == 1
        assert first.fetchone("PRAGMA quick_check")[0] == "ok"
    finally:
        first.close()
        second.close()


def test_failed_scan_resume_is_a_new_linked_attempt_and_keeps_history(
    database: Database, tmp_path: Path
) -> None:
    root = tmp_path / "sources"
    root.mkdir()
    roots = (root,)
    descriptors = database.create_source_scan("failed-scan", roots)
    database.start_source_scan("failed-scan", roots_seen=descriptors, expected_file_count=1)
    database.record_source_scan_file(
        "failed-scan",
        path_fingerprint="path-one",
        document_id=None,
        status="quarantined",
        content_sha256=None,
        reason="parse_failed",
    )
    assert database.fail_source_scan(
        "failed-scan", error_code="test_failure", error_message="retry safely"
    )

    database.resume_source_scan("failed-scan", "resumed-scan", roots)
    prior = database.fetchone("SELECT * FROM source_scans WHERE id='failed-scan'")
    resumed = database.fetchone("SELECT * FROM source_scans WHERE id='resumed-scan'")
    assert prior is not None and prior["status"] == "failed"
    assert prior["files_accounted"] == 1
    assert len(database.source_scan_files("failed-scan")) == 1
    assert resumed is not None and resumed["status"] == "queued"
    assert resumed["resumed_from_scan_id"] == "failed-scan"
    assert database.source_scan_files("resumed-scan") == []

    database.start_source_scan("resumed-scan", roots_seen=descriptors, expected_file_count=0)
    database.complete_source_scan("resumed-scan")
    with pytest.raises(SourceScanStateError, match="Only a failed"):
        database.resume_source_scan("resumed-scan", "invalid-resume", roots)


def test_restart_closes_interrupted_scan_as_visible_resumable_failure(
    database: Database, tmp_path: Path
) -> None:
    root = tmp_path / "sources"
    root.mkdir()
    descriptors = database.create_source_scan("interrupted-scan", (root,))
    database.start_source_scan("interrupted-scan", roots_seen=descriptors, expected_file_count=1)
    database.record_source_scan_file(
        "interrupted-scan",
        path_fingerprint="accounted-before-restart",
        document_id=None,
        status="quarantined",
        content_sha256=None,
        reason="parse_failed",
    )

    assert database.fail_interrupted_source_scans() == ["interrupted-scan"]
    row = database.fetchone("SELECT * FROM source_scans WHERE id='interrupted-scan'")
    assert row is not None and row["status"] == "failed"
    assert row["files_accounted"] == 1
    assert row["error_code"] == "interrupted_source_scan"
    assert row["completed_at"] is not None
    assert database.fail_interrupted_source_scans() == []
    database.resume_source_scan("interrupted-scan", "restart-attempt", (root,))


def test_initialize_reconciles_legacy_multiple_active_scans_without_hiding_them(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy.sqlite3"
    database = Database(path)
    database.initialize()
    database.execute("DROP INDEX idx_source_scans_single_active")
    now = utc_iso()
    roots = json.dumps([{"id": "source-root-1", "fingerprint": "a" * 64}])
    database.execute(
        """
        INSERT INTO source_scans(id, status, required_roots_json, created_at)
        VALUES ('legacy-running', 'running', ?, ?)
        """,
        (roots, now),
    )
    database.execute(
        """
        INSERT INTO source_scans(id, status, required_roots_json, created_at)
        VALUES ('legacy-queued', 'queued', ?, ?)
        """,
        (roots, now),
    )
    database.close()

    migrated = Database(path)
    try:
        migrated.initialize()
        rows = migrated.admin_source_scans()
        assert len(rows) == 2
        assert sum(row["status"] in {"queued", "running"} for row in rows) == 1
        reconciled = next(row for row in rows if row["status"] == "failed")
        assert reconciled["error_code"] == "concurrent_scan_reconciled"
        assert reconciled["completed_at"] is not None
    finally:
        migrated.close()


class _BackgroundScan:
    def __call__(
        self,
        settings: Any,
        database: Database,
        _cipher: Any,
        scan_id: str,
    ) -> None:
        descriptors = database.create_source_scan(scan_id, settings.source_roots)
        database.start_source_scan(scan_id, roots_seen=descriptors, expected_file_count=0)
        database.complete_source_scan(scan_id)


@pytest.mark.asyncio
async def test_scan_api_returns_clear_conflict_and_background_create_is_idempotent(
    database: Database,
    cipher: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "sources"
    source_root.mkdir()
    api_settings = SimpleNamespace(source_roots=(source_root,))
    services = SimpleNamespace(settings=api_settings, database=database, cipher=cipher)
    monkeypatch.setattr(
        "app.ingestion.service.scan_configured_sources",
        _BackgroundScan(),
    )
    previous = getattr(app.state, "services", None)
    app.state.services = services
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 4321))
    try:
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8777"
        ) as client:
            accepted = await client.post("/api/v1/admin/sources/scan")
            assert accepted.status_code == 202
            created_id = accepted.json()["scan_id"]
            created = database.fetchone("SELECT * FROM source_scans WHERE id=?", (created_id,))
            assert created is not None and created["status"] == "complete"

            descriptors = database.create_source_scan("blocking-scan", (source_root,))
            database.start_source_scan(
                "blocking-scan", roots_seen=descriptors, expected_file_count=0
            )
            conflict = await client.post("/api/v1/admin/sources/scan")
            assert conflict.status_code == 409
            assert "blocking-scan is already running" in conflict.json()["detail"]
            assert (
                database.fetchone(
                    "SELECT COUNT(*) AS n FROM source_scans WHERE status IN ('queued', 'running')"
                )["n"]
                == 1
            )
    finally:
        if previous is None:
            del app.state.services
        else:
            app.state.services = previous


@pytest.mark.asyncio
async def test_resume_api_preserves_failed_attempt_and_runs_new_attempt(
    database: Database,
    cipher: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "sources"
    source_root.mkdir()
    roots = (source_root,)
    descriptors = database.create_source_scan("failed-api-scan", roots)
    database.start_source_scan("failed-api-scan", roots_seen=descriptors, expected_file_count=0)
    database.fail_source_scan("failed-api-scan", error_code="synthetic", error_message="safe retry")
    monkeypatch.setattr(
        "app.ingestion.service.scan_configured_sources",
        _BackgroundScan(),
    )
    services = SimpleNamespace(
        settings=SimpleNamespace(source_roots=roots), database=database, cipher=cipher
    )
    previous = getattr(app.state, "services", None)
    app.state.services = services
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 4321))
    try:
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8777"
        ) as client:
            response = await client.post("/api/v1/admin/source-scans/failed-api-scan/resume")
            assert response.status_code == 202
            resumed_id = response.json()["scan_id"]
            assert response.json()["resumed_from_scan_id"] == "failed-api-scan"
            prior = database.fetchone("SELECT status FROM source_scans WHERE id='failed-api-scan'")
            resumed = database.fetchone(
                "SELECT status, resumed_from_scan_id FROM source_scans WHERE id=?",
                (resumed_id,),
            )
            assert prior is not None and prior["status"] == "failed"
            assert resumed is not None and resumed["status"] == "complete"
            assert resumed["resumed_from_scan_id"] == "failed-api-scan"
            history = await client.get("/api/v1/admin/source-scans")
            assert history.status_code == 200
            by_id = {item["id"]: item for item in history.json()["items"]}
            assert by_id["failed-api-scan"]["status"] == "failed"
            assert by_id[resumed_id]["status"] == "complete"
            assert by_id[resumed_id]["resumed_from_scan_id"] == "failed-api-scan"
    finally:
        if previous is None:
            del app.state.services
        else:
            app.state.services = previous
