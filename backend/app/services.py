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
from .deletion_guard import DeletionGuard
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
from .model_routes import RoutedModelGateway
from .runtime_adapters import EmptyRetriever


@dataclass(slots=True)
class Services:
    settings: Settings
    database: Database
    cipher: LocalCipher
    retriever: EvidenceRetriever
    model: RoutedModelGateway
    observability: RuntimeObservability
    runner: AnswerRunner
    conversations: ConversationStore
    freshness: KnowledgeFreshnessCoordinator
    deletion_guard: DeletionGuard
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


def _select_retriever(
    settings: Settings,
    database: Database,
    observability: RuntimeObservability,
    factory: PinnedRetrieverFactory,
    candidate_build_id: str | None,
) -> EvidenceRetriever:
    """Select one route before constructing AnswerRunner; never fall back from a pin."""
    if candidate_build_id is not None:
        if settings.development_candidate_build_id is not None:
            row = database.fetchone(
                "SELECT status FROM index_builds WHERE id=?", (candidate_build_id,),
            )
            if row is None or str(row["status"]) != "candidate":
                raise RuntimeError("development pin requires a non-ACTIVE candidate in isolated storage")
        return factory.for_build(candidate_build_id)
    try:
        from .retrieval.service import HybridRetrievalService

        return HybridRetrievalService(
            settings=settings, database=database, observability=observability,
        )
    except (ImportError, RuntimeError):
        return EmptyRetriever()


def build_services(settings: Settings, *, candidate_build_id: str | None = None) -> Services:
    configured_pin = settings.development_candidate_build_id
    if configured_pin is not None:
        if candidate_build_id is not None and candidate_build_id != configured_pin:
            raise ValueError("explicit candidate differs from configured development candidate")
        candidate_build_id = configured_pin
    if candidate_build_id is not None and not candidate_build_id.strip():
        raise ValueError("evaluation candidate must not be empty")
    settings.ensure_runtime_dirs()
    database = Database(settings.database_path)
    database.initialize()
    cipher = LocalCipher.from_local_key(create=True)
    deletion_guard = DeletionGuard(audit_dir=settings.logs_dir / "deletion-attempts")
    with _sensitive_state_startup_lock(settings.data_dir / ".sensitive-state-migration.lock"):
        database.migrate_sensitive_content(cipher)
        migrate_legacy_uploads(settings, database, cipher)
        # Expiry remains a non-destructive eligibility state. Physical deletion
        # requires a separate exact owner authorization and is never attempted
        # during ordinary startup.
        purge_expired_uploads(settings, database, guard=deletion_guard)
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
    conversations = ConversationStore.from_settings(
        database,
        cipher,
        settings,
        deletion_guard=deletion_guard,
    )
    conversations.purge_expired()
    research_control = ResearchControlPlane(settings, database, cipher=cipher)
    freshness = KnowledgeFreshnessCoordinator(
        database,
        cipher,
        research_control,
        batch_threshold=settings.knowledge_update_batch_threshold,
    )
    retriever_factory = PinnedRetrieverFactory(settings, database, observability=observability)

    retriever = _select_retriever(
        settings, database, observability, retriever_factory, candidate_build_id,
    )

    model = RoutedModelGateway(settings)
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
        deletion_guard=deletion_guard,
        retriever_factory=retriever_factory,
    )


def build_evaluation_services(settings: Settings, candidate_build_id: str) -> Services:
    """Service graph pinned to an evaluation candidate. Does not follow ACTIVE."""

    return build_services(settings, candidate_build_id=candidate_build_id)
