"""Evaluation admin routes extracted from the API façade."""

from __future__ import annotations

import json
import re
from typing import Any, cast

from fastapi import APIRouter, HTTPException, Request

from ..deps import services

router = APIRouter()


def _live30_admin_reader(request: Request) -> Any:
    from ...evaluation.live30 import Live30RunStore
    from ...evaluation.live30_admin import Live30AdminReader

    svc = services(request)
    return Live30AdminReader(
        Live30RunStore(svc.settings.project_root, svc.cipher),
        owner_identifiers=svc.settings.owner_identifiers,
        database=getattr(svc, "database", None),
    )


def _live_suite_admin_reader(request: Request) -> Any:
    from ...evaluation.live_suite_admin import LiveSuiteAdminReader
    from ...evaluation.live_suite_store import LiveSuiteRunStore

    svc = services(request)
    return LiveSuiteAdminReader(
        LiveSuiteRunStore(svc.settings.project_root, svc.cipher),
        owner_identifiers=svc.settings.owner_identifiers,
    )


def _live_evaluation_reader_for_run(request: Request, run_id: str) -> Any:
    if not re.fullmatch(r"[a-z0-9][a-z0-9._:-]{2,127}", run_id):
        raise ValueError("Live evaluation run identity is invalid")
    svc = services(request)
    runs_root = (svc.settings.project_root / "data" / "evaluations" / "e2e" / "runs").resolve()
    manifest_path = (runs_root / run_id / "manifest.json").resolve()
    if not manifest_path.is_relative_to(runs_root) or not manifest_path.is_file():
        raise FileNotFoundError(run_id)
    if manifest_path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("Live evaluation manifest is oversized")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("Live evaluation manifest is invalid")
    schema_name = manifest.get("schema")
    if schema_name == "legalbot.live-evaluation-run-manifest.v2":
        return _live_suite_admin_reader(request)
    if schema_name == "legalbot.e2e-run-manifest.v1":
        return _live30_admin_reader(request)
    raise ValueError("Live evaluation manifest schema is not recognised")


@router.get("/api/v1/admin/live-evaluations")
async def admin_live_evaluations(request: Request) -> dict[str, Any]:
    """List local evaluation runs without decrypting questions or answers."""

    legacy = cast(dict[str, Any], _live30_admin_reader(request).list_runs())
    manifest_driven = cast(dict[str, Any], _live_suite_admin_reader(request).list_runs())
    items = [*legacy.get("items", []), *manifest_driven.get("items", [])]
    items.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
    return {
        "items": items,
        # The v2 reader treats a valid legacy schema as intentionally skipped;
        # unlike the historical reader, it does not count Live60 as corrupt.
        "invalid_run_count": int(manifest_driven.get("invalid_run_count", 0)),
    }


@router.get("/api/v1/admin/live-evaluations/{run_id}")
async def admin_live_evaluation(request: Request, run_id: str) -> dict[str, Any]:
    """Return all thirty safe case records, including explicit not-run rows."""

    from ...evaluation.live30_admin import Live30AdminIntegrityError
    from ...evaluation.live_suite_admin import LiveSuiteAdminIntegrityError

    try:
        return cast(
            dict[str, Any],
            _live_evaluation_reader_for_run(request, run_id).run_detail(run_id),
        )
    except FileNotFoundError as exc:
        raise HTTPException(404, "Live evaluation run not found") from exc
    except (
        Live30AdminIntegrityError,
        LiveSuiteAdminIntegrityError,
        ValueError,
        OSError,
        json.JSONDecodeError,
    ) as exc:
        raise HTTPException(409, "Live evaluation artifacts failed integrity checks") from exc


@router.get("/api/v1/admin/live-evaluations/{run_id}/cases/{case_id}/passes/{pass_number}/answer")
async def admin_live_evaluation_released_answer(
    request: Request, run_id: str, case_id: str, pass_number: int
) -> dict[str, Any]:
    """Keep superseded artifact answers encrypted until certified migration."""

    del request, run_id, case_id, pass_number
    raise HTTPException(
        503,
        "TECHNICAL_IMPLEMENTATION_REQUIRED:"
        "superseded_evaluation_release_content_certification_missing",
    )
