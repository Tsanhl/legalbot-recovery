from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from fastapi import HTTPException, Request

from app.api.main import build_index
from app.db import JobQueueCapacityError


@pytest.mark.asyncio
async def test_index_build_api_projects_bounded_queue_as_429(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.retrieval import index_build, retrieval_v1

    monkeypatch.setattr(retrieval_v1, "verify_owner_freeze", lambda *_args: None)

    def queue_full(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise JobQueueCapacityError("index_build_queue_capacity_exhausted")

    monkeypatch.setattr(index_build, "enqueue_index_build", queue_full)
    request = cast(
        Request,
        SimpleNamespace(
            app=SimpleNamespace(
                state=SimpleNamespace(
                    services=SimpleNamespace(
                        settings=SimpleNamespace(
                            project_root=tmp_path,
                            retrieval_benchmark_path=tmp_path / "benchmark.json",
                        ),
                        database=object(),
                    )
                )
            )
        ),
    )

    with pytest.raises(HTTPException) as stopped:
        await build_index(request)

    assert stopped.value.status_code == 429
    assert "bounded local index queue is full" in str(stopped.value.detail)
