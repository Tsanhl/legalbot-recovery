from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any

import pytest
from cryptography.fernet import Fernet

from app.config import Settings
from app.crypto import LocalCipher
from app.orchestration.runner import AnswerRunner
from app.retrieval.budget import (
    RetrievalBudgetExhausted,
    bind_retrieval_budget,
    raise_if_complete_rerank_plan_exceeds_remaining,
)
from app.retrieval.models import RetrievalPlanItem


@pytest.mark.asyncio
async def test_runner_uses_certified_plan_instead_of_per_query_retrieve(
    tmp_path: Path, database: Any
) -> None:
    class Retriever:
        def __init__(self) -> None:
            self.retrieve_calls = 0
            self.plan_calls = 0
            self.plan_sizes: list[int] = []

        def active_build_id(self) -> str:
            return "build-1"

        async def retrieve(self, **_kwargs: Any) -> list[Any]:
            self.retrieve_calls += 1
            return []

        async def retrieve_issue_spotting_notes(self, **_kwargs: Any) -> list[Any]:
            return []

        async def retrieve_certified_plan(self, requests: Any) -> tuple[tuple[Any, ...], ...]:
            self.plan_calls += 1
            items = tuple(requests)
            self.plan_sizes.append(len(items))
            assert all(isinstance(item, RetrievalPlanItem) for item in items)
            return tuple(() for _ in items)

    retriever = Retriever()
    settings = Settings(project_root=tmp_path, test_mode=True)
    settings.ensure_runtime_dirs()
    runner = AnswerRunner(
        settings=settings,
        database=database,
        cipher=LocalCipher(Fernet.generate_key()),
        retriever=retriever,  # type: ignore[arg-type]
        model=object(),  # type: ignore[arg-type]
    )
    batches = await runner._retrieve_research_plan(
        items=(("consideration", "contract"), ("estoppel", "contract")),
        jurisdiction="England and Wales",
        as_of=date(2026, 8, 14),
        cacheable=True,
    )
    assert retriever.plan_calls == 1
    assert retriever.plan_sizes == [2]
    assert retriever.retrieve_calls == 0
    assert len(batches) == 2


@pytest.mark.asyncio
async def test_runner_falls_back_to_retrieve_when_certified_plan_is_absent(
    tmp_path: Path, database: Any
) -> None:
    class Retriever:
        def __init__(self) -> None:
            self.retrieve_calls = 0

        def active_build_id(self) -> str:
            return "build-1"

        async def retrieve(self, **_kwargs: Any) -> list[Any]:
            self.retrieve_calls += 1
            return []

        async def retrieve_issue_spotting_notes(self, **_kwargs: Any) -> list[Any]:
            return []

    retriever = Retriever()
    settings = Settings(project_root=tmp_path, test_mode=True)
    settings.ensure_runtime_dirs()
    runner = AnswerRunner(
        settings=settings,
        database=database,
        cipher=LocalCipher(Fernet.generate_key()),
        retriever=retriever,  # type: ignore[arg-type]
        model=object(),  # type: ignore[arg-type]
    )
    batches = await runner._retrieve_research_plan(
        items=(("consideration", "contract"), ("estoppel", "contract")),
        jurisdiction="England and Wales",
        as_of=date(2026, 8, 14),
        cacheable=True,
    )
    assert retriever.retrieve_calls == 2
    assert len(batches) == 2


def test_two_section_live_plan_fails_closed_before_any_qwen() -> None:
    from datetime import UTC, datetime, timedelta

    bind_retrieval_budget(deadline_at=datetime.now(UTC) + timedelta(seconds=300))
    with pytest.raises(RetrievalBudgetExhausted, match="cannot fit"):
        raise_if_complete_rerank_plan_exceeds_remaining((32, 32), ranking_payload_tokens=1024)
