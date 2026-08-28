from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from cryptography.fernet import Fernet

from app.crypto import LocalCipher
from app.db import SCHEMA_VERSION, Database
from app.observability.live_tracing import (
    TraceLevel,
    TraceOperation,
    TraceSpan,
    TraceStage,
    TraceStatus,
)
from app.observability.otel_jsonl import otel_available, span_to_otel_jsonl
from app.runtime_records.retention import cleanup_runtime_records, load_retention_config
from app.runtime_records.service import RuntimeRecordService


def _service(tmp_path: Path) -> RuntimeRecordService:
    database = Database(tmp_path / "catalog.sqlite3")
    database.initialize()
    return RuntimeRecordService(
        database,
        LocalCipher(Fernet(Fernet.generate_key())),
        object_dir=tmp_path / "objects",
    )


def test_schema_version_creates_runtime_tables(tmp_path: Path) -> None:
    database = Database(tmp_path / "catalog.sqlite3")
    database.initialize()
    row = database.fetchone("SELECT value FROM schema_meta WHERE key='schema_version'")
    assert row is not None
    assert row["value"] == str(SCHEMA_VERSION)
    assert SCHEMA_VERSION == 25
    for table in (
        "runtime_feedback",
        "runtime_incidents",
        "runtime_regressions",
        "runtime_curation",
    ):
        present = database.fetchone(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table,),
        )
        assert present is not None


def test_feedback_and_incident_keep_notes_encrypted(tmp_path: Path) -> None:
    service = _service(tmp_path)
    feedback = service.record_feedback(
        kind="wrong_answer",
        class_code="wrong_ratio",
        note="secret owner note",
        answer_id="answer-1",
    )
    assert feedback["eligible_for_training"] is False
    assert feedback["has_encrypted_note"] is True
    note_files = list((tmp_path / "objects").glob("*.enc"))
    assert note_files
    assert b"secret owner note" not in note_files[0].read_bytes()
    incident = service.record_incident(class_code="crash", crash_bundle="traceback secret")
    with pytest.raises(ValueError, match="regression"):
        service.close_incident(incident["id"])
    closed = service.close_incident(incident["id"], regression_case_id="reg-1")
    assert closed["status"] == "closed"


def test_curation_rejects_live_evaluation_contamination(tmp_path: Path) -> None:
    service = _service(tmp_path)
    with pytest.raises(ValueError, match="cannot enter curation"):
        service.start_curation(source_kind="live60")
    started = service.start_curation(source_kind="owner_upload")
    assert started["state"] == "quarantine"
    state = started["state"]
    for _ in range(6):
        advanced = service.advance_curation(started["id"])
        state = advanced["state"]
    assert state == "sealed_export"
    snapshot = service.status_snapshot()
    assert snapshot["eligible_for_training"] is False
    assert snapshot["curation_counts"]["sealed_export"] == 1


def test_retention_is_dry_run_and_skips_live60(tmp_path: Path) -> None:
    config = load_retention_config(Path("config/retention.yaml"))
    assert config["never_during_live60"] is True
    assert config["dry_run_default"] is True
    database = Database(tmp_path / "catalog.sqlite3")
    database.initialize()
    skipped = cleanup_runtime_records(database, config, dry_run=True, live60_in_progress=True)
    assert skipped["ran"] is False
    assert skipped["reason"] == "never_during_live60"
    dry = cleanup_runtime_records(database, config, dry_run=True)
    assert dry["dry_run"] is True
    assert dry["ran"] is False


def test_otel_jsonl_bridge_omits_raw_question_answer_source() -> None:
    span = TraceSpan(
        schema="legalbot.safe-trace-span.v1",
        trace_id="trace-otel-jsonl-001",
        span_id="span-otel-jsonl-001",
        parent_span_id=None,
        event_id="event-otel-jsonl-001",
        timestamp=datetime.now(UTC),
        operation=TraceOperation.RETRIEVAL,
        stage=TraceStage.RETRIEVAL,
        status=TraceStatus.OK,
        level=TraceLevel.INFO,
        duration_ms=1.5,
    )
    record = span_to_otel_jsonl(span)
    dumped = yaml.safe_dump(record)
    assert "question" not in dumped
    assert "answer" not in dumped
    assert record["exporter"] == "local_jsonl"
    assert record["external_endpoint"] is None
    assert isinstance(otel_available(), bool)
