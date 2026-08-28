from __future__ import annotations

import fcntl
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .config import Settings
from .conversations import ConversationStore
from .crypto import LocalCipher
from .db import Database
from .observability.runtime import RuntimeObservability
from .orchestration.contracts import EvidenceRetriever
from .orchestration.gaps import GapQueue
from .orchestration.runner import AnswerRunner
from .orchestration.uploads import migrate_legacy_uploads, purge_expired_uploads
from .research.control_plane import ResearchControlPlane
from .research.freshness import KnowledgeFreshnessCoordinator
from .research.legacy import LegacyResearchGapImporter
from .research.scheduler import ResearchScheduler
from .retrieval.pinned_factory import PinnedRetrieverFactory
from .runtime_adapters import EmptyRetriever, LoopbackModelGateway


@dataclass(slots=True)
class Services:
    settings: Settings
    database: Database
    cipher: LocalCipher
    retriever: EvidenceRetriever
    model: LoopbackModelGateway
    observability: RuntimeObservability
    runner: AnswerRunner
    conversations: ConversationStore
    freshness: KnowledgeFreshnessCoordinator
    retriever_factory: PinnedRetrieverFactory | None = None


@contextmanager
def _sensitive_state_startup_lock(path: Path) -> Iterator[None]:
    """Serialise destructive plaintext-to-encrypted startup migrations.

    The API and durable worker are separate processes and both construct the
    service graph.  Without a process lock they can race while replacing the
    same legacy review artifact.  The lock contains no sensitive content.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def build_services(settings: Settings) -> Services:
    settings.ensure_runtime_dirs()
    database = Database(settings.database_path)
    database.initialize()
    cipher = LocalCipher.from_local_key(create=True)
    with _sensitive_state_startup_lock(settings.data_dir / ".sensitive-state-migration.lock"):
        database.migrate_sensitive_content(cipher)
        migrate_legacy_uploads(settings, database, cipher)
        purge_expired_uploads(settings, database)
        legacy_research_queue = settings.gap_queue_dir / "official-source-candidates.json"
        if legacy_research_queue.is_file():
            LegacyResearchGapImporter(
                database,
                ResearchControlPlane(settings, database, cipher=cipher),
                cipher,
            ).import_file(legacy_research_queue)
        ResearchScheduler(
            database, ResearchControlPlane(settings, database, cipher=cipher)
        ).install_defaults(enabled=False)
        gap_queue = GapQueue(settings.gap_queue_dir, cipher)
        for legacy, encrypted in gap_queue.migrate_legacy_files():
            database.execute(
                "UPDATE knowledge_gaps SET review_file=? WHERE review_file=?",
                (
                    str(encrypted.relative_to(settings.project_root)),
                    str(legacy.relative_to(settings.project_root)),
                ),
            )
    observability = RuntimeObservability(settings, database, component="api")
    conversations = ConversationStore.from_settings(database, cipher, settings)
    conversations.purge_expired()
    research_control = ResearchControlPlane(settings, database, cipher=cipher)
    freshness = KnowledgeFreshnessCoordinator(
        database,
        cipher,
        research_control,
        batch_threshold=settings.knowledge_update_batch_threshold,
    )
    retriever_factory = PinnedRetrieverFactory(settings, database, observability=observability)

    # The import is intentionally one-way: a single new hybrid retriever or an honest empty state.
    try:
        from .retrieval.service import HybridRetrievalService

        retriever: EvidenceRetriever = HybridRetrievalService(
            settings=settings,
            database=database,
            observability=observability,
        )
    except (ImportError, RuntimeError):
        retriever = EmptyRetriever()

    model = LoopbackModelGateway(settings)
    from .conversations import ConversationQueryRewriter

    query_rewriter = ConversationQueryRewriter(
        model,
        enabled=settings.conversation_query_rewrite_enabled,
        owner_identifiers=settings.owner_identifiers,
    )
    runner = AnswerRunner(
        settings=settings,
        database=database,
        cipher=cipher,
        retriever=retriever,
        model=model,
        observability=observability,
        retriever_factory=retriever_factory,
        conversations=conversations,
        query_rewriter=query_rewriter,
    )
    return Services(
        settings=settings,
        database=database,
        cipher=cipher,
        retriever=retriever,
        model=model,
        observability=observability,
        runner=runner,
        conversations=conversations,
        freshness=freshness,
        retriever_factory=retriever_factory,
    )


def build_evaluation_services(settings: Settings, candidate_build_id: str) -> Services:
    """Service graph pinned to an evaluation candidate. Does not follow ACTIVE."""

    services = build_services(settings)
    if services.retriever_factory is None:
        raise RuntimeError("evaluation services require a pinned retriever factory")
    pinned = services.retriever_factory.for_build(candidate_build_id)
    services.retriever = pinned
    services.runner.retriever_factory = services.retriever_factory
    services.runner._default_retriever = pinned
    return services
