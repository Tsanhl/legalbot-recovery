"""Build-identity retriever factory. One HybridRetrievalService per sealed pin."""

from __future__ import annotations

import threading
from typing import Any

from ..config import Settings
from ..db import Database
from ..observability.runtime import RuntimeObservability
from ..orchestration.contracts import EvidenceRetriever
from .service import HybridRetrievalService


class PinnedRetrieverFactory:
    """Cache retrievers by immutable build ID. Never mutate a shared ACTIVE pin."""

    def __init__(
        self,
        settings: Settings,
        database: Database,
        *,
        observability: RuntimeObservability | None = None,
    ) -> None:
        self.settings = settings
        self.database = database
        self.observability = observability
        self._lock = threading.RLock()
        self._cache: dict[str, HybridRetrievalService] = {}

    def for_build(self, build_id: str) -> HybridRetrievalService:
        if not str(build_id or "").strip():
            raise RuntimeError("answer job is missing pinned_index_build_id")
        key = str(build_id)
        with self._lock:
            existing = self._cache.get(key)
            if existing is not None:
                return existing
            service = HybridRetrievalService(
                settings=self.settings,
                database=self.database,
                pinned_build_id=key,
                observability=self.observability,
            )
            self._cache[key] = service
            return service

    def cached_build_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._cache))


def build_evaluation_runner(
    settings: Settings,
    database: Any,
    cipher: Any,
    *,
    candidate_build_id: str,
    model: Any,
    observability: RuntimeObservability | None = None,
) -> Any:
    """Construct an AnswerRunner whose default retriever is the evaluation candidate."""

    from ..orchestration.runner import AnswerRunner

    factory = PinnedRetrieverFactory(settings, database, observability=observability)
    retriever: EvidenceRetriever = factory.for_build(candidate_build_id)
    return AnswerRunner(
        settings=settings,
        database=database,
        cipher=cipher,
        retriever=retriever,
        model=model,
        observability=observability,
        retriever_factory=factory,
    )
