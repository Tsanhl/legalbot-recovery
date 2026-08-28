"""Incident and runtime-record status routes. No plaintext secrets."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

from ...runtime_records.service import RuntimeRecordService
from ..deps import services

router = APIRouter()


@router.get("/api/v1/admin/runtime-records")
async def admin_runtime_records(request: Request) -> dict[str, Any]:
    """Owner status for feedback, incidents, regressions and curation."""

    svc = services(request)
    snapshot = RuntimeRecordService(
        svc.database,
        svc.cipher,
        object_dir=svc.settings.runtime_object_dir,
    ).status_snapshot()
    snapshot["plaintext_secrets"] = False
    return snapshot
