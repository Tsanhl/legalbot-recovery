from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from app.api.main import app
from app.source_diagnostics import (
    DIAGNOSTICS,
    EXCLUSION_STATUSES,
    safe_exclusion_payload,
    validate_exclusion_reason,
)


def _running_scan(database, tmp_path: Path, scan_id: str) -> None:
    root = tmp_path / scan_id
    root.mkdir()
    descriptors = database.create_source_scan(scan_id, (root,))
    database.start_source_scan(scan_id, roots_seen=descriptors, expected_file_count=1)


def test_scan_finalization_rejects_missing_or_mismatched_exclusion_reasons(
    database, tmp_path: Path
) -> None:
    _running_scan(database, tmp_path, "diagnostic-scan")
    with pytest.raises(ValueError):
        validate_exclusion_reason("ocr_required", None)
    database.execute(
        """
        INSERT INTO source_scan_files(
          scan_id, path_fingerprint, document_id, status, content_sha256, reason
        ) VALUES ('diagnostic-scan', ?, NULL, 'ocr_required', ?, NULL)
        """,
        ("f" * 64, "a" * 64),
    )
    with pytest.raises(RuntimeError, match="diagnostics incomplete for status ocr_required"):
        database.complete_source_scan("diagnostic-scan")

    database.execute(
        "UPDATE source_scan_files SET reason='unsupported_file_type' "
        "WHERE scan_id='diagnostic-scan'"
    )
    with pytest.raises(RuntimeError, match="diagnostics incomplete for status ocr_required"):
        database.complete_source_scan("diagnostic-scan")

    database.record_source_scan_file(
        "diagnostic-scan",
        path_fingerprint="f" * 64,
        document_id=None,
        status="ocr_required",
        content_sha256="a" * 64,
        reason="ocr_toolchain_unavailable",
    )
    result = database.complete_source_scan("diagnostic-scan")
    assert result["statuses"] == {"ocr_required": 1}
    row = database.source_scan_files("diagnostic-scan")[0]
    assert row["reason"] == "ocr_toolchain_unavailable"


def test_all_exclusion_statuses_have_stable_safe_diagnostics() -> None:
    assert {"unsupported", "quarantined", "encrypted", "ocr_required"} == EXCLUSION_STATUSES
    for reason_code, diagnostic in DIAGNOSTICS.items():
        assert reason_code.replace("_", "").isalnum()
        assert diagnostic.statuses <= EXCLUSION_STATUSES
        for status in diagnostic.statuses:
            assert validate_exclusion_reason(status, reason_code) == reason_code
            payload = safe_exclusion_payload(status, reason_code)
            assert payload is not None
            assert payload["reason_code"] == reason_code
            assert payload["explanation"]
            assert payload["corrective_action"]
            assert "/Users/" not in str(payload)


def test_legacy_raw_reason_is_never_reflected_to_admin_payload() -> None:
    payload = safe_exclusion_payload(
        "quarantined", "read_error:/Users/private-owner/secret-file.pdf"
    )
    assert payload == {
        "reason_code": "legacy_exclusion_reason_missing",
        "explanation": "A legacy exclusion has no recognised stable diagnostic code.",
        "corrective_action": "Rescan the source to produce a precise corrective action.",
    }


def test_ready_status_does_not_require_an_exclusion_reason(database, tmp_path: Path) -> None:
    _running_scan(database, tmp_path, "ready-scan")
    database.record_source_scan_file(
        "ready-scan",
        path_fingerprint="e" * 64,
        document_id=None,
        status="citable",
        content_sha256="b" * 64,
    )
    assert database.complete_source_scan("ready-scan")["status"] == "complete"


@pytest.mark.asyncio
async def test_admin_scan_contract_surfaces_safe_reason_and_corrective_action(
    database, cipher: Any, tmp_path: Path
) -> None:
    _running_scan(database, tmp_path, "api-diagnostic-scan")
    database.record_source_scan_file(
        "api-diagnostic-scan",
        path_fingerprint="d" * 64,
        document_id=None,
        status="encrypted",
        content_sha256="c" * 64,
        reason="encrypted_or_restricted",
    )
    database.complete_source_scan("api-diagnostic-scan")
    previous = getattr(app.state, "services", None)
    app.state.services = SimpleNamespace(database=database, cipher=cipher)
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 4321))
    try:
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8777"
        ) as client:
            listing = await client.get("/api/v1/admin/source-scans")
            assert listing.status_code == 200
            diagnostic = listing.json()["items"][0]["exclusion_diagnostics"][0]
            assert diagnostic == {
                "status": "encrypted",
                "reason_code": "encrypted_or_restricted",
                "count": 1,
                "explanation": "The file is encrypted or access-restricted and was not opened.",
                "corrective_action": "Supply a lawfully accessible, decrypted copy and rescan it.",
            }
            detail = await client.get("/api/v1/admin/source-scans/api-diagnostic-scan")
            assert detail.status_code == 200
            file_record = detail.json()["files"][0]
            assert "reason" not in file_record
            assert file_record["reason_code"] == "encrypted_or_restricted"
            assert file_record["corrective_action"]
    finally:
        if previous is None:
            del app.state.services
        else:
            app.state.services = previous
