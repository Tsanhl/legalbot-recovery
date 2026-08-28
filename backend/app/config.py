from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
STANDARD_LIVE_PROFILE = "standard"
FIRST_LIVE_LOCAL_ONLY_PROFILE = "first_live_local_only"
_ONLINE_MODES = frozenset({"local_only", "auto", "always"})


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_identifiers() -> tuple[str, ...]:
    raw = os.getenv("LEGALBOT_OWNER_IDENTIFIERS", "")
    return tuple(value.strip() for value in raw.split(",") if len(value.strip()) >= 3)


def _env_optional_path(name: str) -> Path | None:
    value = os.getenv(name, "").strip()
    return Path(value).expanduser() if value else None


@dataclass(frozen=True, slots=True)
class Settings:
    project_root: Path = PROJECT_ROOT
    host: str = os.getenv("LEGALBOT_HOST", "127.0.0.1")
    port: int = int(os.getenv("LEGALBOT_PORT", "8777"))
    environment: str = os.getenv("LEGALBOT_ENV", "development")
    live_profile: str = os.getenv("LEGALBOT_LIVE_PROFILE", STANDARD_LIVE_PROFILE)
    test_mode: bool = _env_bool("LEGALBOT_TEST_MODE")
    model_url: str = os.getenv("LEGALBOT_MODEL_URL", "http://127.0.0.1:8778")
    model_id: str = os.getenv("LEGALBOT_MODEL_ID", "mlx-community/Qwen3.5-9B-4bit")
    embedding_model: str = os.getenv("LEGALBOT_EMBEDDING_MODEL", "Qwen/Qwen3-Embedding-0.6B")
    reranker_model: str = os.getenv("LEGALBOT_RERANKER_MODEL", "Qwen/Qwen3-Reranker-0.6B")
    online_default: str = os.getenv("LEGALBOT_ONLINE_MODE", "local_only")
    # Connected official-source access is an explicit operator/canary mode.
    # A plain API/worker start must remain offline by default.
    official_research_enabled: bool = _env_bool("LEGALBOT_OFFICIAL_RESEARCH_ENABLED", False)
    xerj_enabled: bool = _env_bool("LEGALBOT_XERJ_ENABLED", False)
    phoenix_enabled: bool = _env_bool("LEGALBOT_PHOENIX_ENABLED", False)
    owner_identifiers: tuple[str, ...] = _env_identifiers()
    # Operator-scoped source scans may pin an exact root tuple without
    # mutating process-global environment state.  Ordinary application starts
    # leave this unset and continue to use LEGALBOT_SOURCE_ROOTS/the defaults.
    explicit_source_roots: tuple[Path, ...] | None = None
    # Conversation content is encrypted in the durable SQLite catalogue.  The
    # hot cache is deliberately bounded and process-local: an owner-only local
    # deployment does not need a network Redis dependency to retain sessions.
    conversation_retention_days: int = int(os.getenv("LEGALBOT_CONVERSATION_RETENTION_DAYS", "30"))
    conversation_hot_cache_ttl_seconds: int = int(
        os.getenv("LEGALBOT_CONVERSATION_HOT_CACHE_TTL_SECONDS", "604800")
    )
    conversation_hot_cache_max_sessions: int = int(
        os.getenv("LEGALBOT_CONVERSATION_HOT_CACHE_MAX_SESSIONS", "128")
    )
    conversation_window_max_messages: int = int(
        os.getenv("LEGALBOT_CONVERSATION_WINDOW_MAX_MESSAGES", "24")
    )
    conversation_window_max_tokens: int = int(
        os.getenv("LEGALBOT_CONVERSATION_WINDOW_MAX_TOKENS", "4096")
    )
    conversation_session_message_quota: int = int(
        os.getenv("LEGALBOT_CONVERSATION_SESSION_MESSAGE_QUOTA", "500")
    )
    # Prepared in Phase 2A but disabled until the exact Phase-2B model-
    # transport package authorizes model-backed standalone-query rewriting.
    conversation_query_rewrite_enabled: bool = _env_bool(
        "LEGALBOT_CONVERSATION_QUERY_REWRITE_ENABLED", False
    )
    knowledge_update_batch_threshold: int = int(
        os.getenv("LEGALBOT_KNOWLEDGE_UPDATE_BATCH_THRESHOLD", "4")
    )
    development_review_root: Path | None = field(
        default_factory=lambda: _env_optional_path("LEGALBOT_DEVELOPMENT_REVIEW_ROOT")
    )
    sealed_validation_review_root: Path | None = field(
        default_factory=lambda: _env_optional_path("LEGALBOT_SEALED_VALIDATION_REVIEW_ROOT")
    )
    # Legacy compatibility for explicitly synthetic/non-authoritative fixtures
    # only. Authoritative owner-quality lanes must use the two lane-specific
    # roots above and must never fall back to this setting.
    canary_review_root: Path | None = field(
        default_factory=lambda: _env_optional_path("LEGALBOT_CANARY_REVIEW_ROOT")
    )

    def __post_init__(self) -> None:
        if self.live_profile not in {
            STANDARD_LIVE_PROFILE,
            FIRST_LIVE_LOCAL_ONLY_PROFILE,
        }:
            raise ValueError("LEGALBOT_LIVE_PROFILE is not recognised")
        if self.online_default not in _ONLINE_MODES:
            raise ValueError("LEGALBOT_ONLINE_MODE is not recognised")
        if self.live_profile == FIRST_LIVE_LOCAL_ONLY_PROFILE:
            if self.online_default != "local_only":
                raise ValueError("the first-live profile requires LEGALBOT_ONLINE_MODE=local_only")
            if self.official_research_enabled:
                raise ValueError(
                    "the first-live profile requires LEGALBOT_OFFICIAL_RESEARCH_ENABLED=false"
                )
            if self.xerj_enabled or self.phoenix_enabled:
                raise ValueError("Xerj and Phoenix stay disabled before first live")
        if self.xerj_enabled and self.phoenix_enabled:
            raise ValueError("Phoenix or Xerj may be chosen later, never both")
        if not 1 <= self.conversation_retention_days <= 365:
            raise ValueError("conversation retention must be between 1 and 365 days")
        if not 60 <= self.conversation_hot_cache_ttl_seconds <= 2_592_000:
            raise ValueError("conversation hot-cache TTL must be between 60 seconds and 30 days")
        if not 1 <= self.conversation_hot_cache_max_sessions <= 10_000:
            raise ValueError("conversation hot-cache capacity is invalid")
        if not 1 <= self.conversation_window_max_messages <= 64:
            raise ValueError("conversation sliding-window message limit is invalid")
        if not 128 <= self.conversation_window_max_tokens <= 16_384:
            raise ValueError("conversation sliding-window token limit is invalid")
        if not 2 <= self.conversation_session_message_quota <= 10_000:
            raise ValueError("conversation session message quota is invalid")
        if not 2 <= self.knowledge_update_batch_threshold <= 100:
            raise ValueError("knowledge-update batch threshold is invalid")

    @property
    def evaluation_forbids_online_research(self) -> bool:
        """Whether any official-online adapter use invalidates the live evaluation."""

        return self.live_profile == FIRST_LIVE_LOCAL_ONLY_PROFILE

    def assert_online_research_adapter_allowed(self) -> None:
        """Fail closed if an evaluation attempts to activate online research."""

        if self.evaluation_forbids_online_research:
            raise RuntimeError(
                "online official research was attempted during the first-live evaluation"
            )
        if not self.official_research_enabled:
            raise RuntimeError("online official research requires explicit operator enablement")

    @property
    def data_dir(self) -> Path:
        return self.project_root / "data"

    @property
    def database_path(self) -> Path:
        return self.data_dir / "catalog.sqlite3"

    @property
    def vault_dir(self) -> Path:
        return self.data_dir / "vault"

    @property
    def index_dir(self) -> Path:
        return self.data_dir / "indexes"

    @property
    def answer_dir(self) -> Path:
        return self.data_dir / "answers"

    @property
    def upload_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def gap_queue_dir(self) -> Path:
        return self.data_dir / "review_queue" / "gaps"

    @property
    def runtime_object_dir(self) -> Path:
        return self.data_dir / "runtime_objects"

    @property
    def retrieval_cache_dir(self) -> Path:
        return self.data_dir / "retrieval_cache"

    @property
    def evaluation_dir(self) -> Path:
        return self.data_dir / "evaluations"

    @property
    def completion_memory_policy_path(self) -> Path:
        """Fixed owner-private completion-preflight memory policy location."""

        return self.evaluation_dir / "policies" / "completion-memory-policy.json"

    @property
    def owner_decision_root(self) -> Path:
        """Fixed private decision store used by authoritative prelive gates."""

        return self.evaluation_dir / "owner-decisions"

    @property
    def logs_dir(self) -> Path:
        return self.project_root / "logs"

    @property
    def operational_events_dir(self) -> Path:
        return self.logs_dir / "events"

    @property
    def operational_metrics_dir(self) -> Path:
        return self.logs_dir / "metrics"

    @property
    def operational_traces_dir(self) -> Path:
        return self.logs_dir / "traces"

    @property
    def e2e_observability_dir(self) -> Path:
        return self.evaluation_dir / "e2e"

    @property
    def live_metrics_dir(self) -> Path:
        return self.e2e_observability_dir / "metrics"

    @property
    def live_traces_dir(self) -> Path:
        return self.e2e_observability_dir / "traces"

    @property
    def incidents_dir(self) -> Path:
        return self.data_dir / "incidents"

    @property
    def curation_dir(self) -> Path:
        return self.data_dir / "curation"

    @property
    def retention_config_path(self) -> Path:
        return self.project_root / "config" / "retention.yaml"

    @property
    def otel_jsonl_path(self) -> Path:
        return self.live_traces_dir / "otel.jsonl"

    @property
    def observability_slo_path(self) -> Path:
        return self.project_root / "config" / "observability_slo.yaml"

    @property
    def retrieval_benchmark_path(self) -> Path:
        configured = os.getenv("LEGALBOT_RETRIEVAL_BENCHMARK")
        if configured:
            return Path(configured).expanduser()
        return self.project_root / "benchmarks" / "retrieval" / "v1.1.json"

    @property
    def relevance_threshold_policy_path(self) -> Path:
        return self.project_root / "config" / "relevance_threshold_policy.v1.json"

    @property
    def embedding_model_path(self) -> Path:
        return self.project_root / "models" / "retrieval" / "Qwen3-Embedding-0.6B"

    @property
    def reranker_model_path(self) -> Path:
        return self.project_root / "models" / "retrieval" / "Qwen3-Reranker-0.6B"

    @property
    def source_roots(self) -> tuple[Path, ...]:
        if self.explicit_source_roots is not None:
            return tuple(Path(value).expanduser() for value in self.explicit_source_roots)
        raw = os.getenv("LEGALBOT_SOURCE_ROOTS")
        if raw:
            return tuple(Path(value).expanduser() for value in raw.split(os.pathsep) if value)
        desktop = Path.home() / "Desktop"
        return (
            desktop / "Law",
            self.project_root / "sources" / "materials-2026-08-12",
        )

    def ensure_runtime_dirs(self) -> None:
        for path in (
            self.data_dir,
            self.vault_dir,
            self.index_dir,
            self.answer_dir,
            self.upload_dir,
            self.gap_queue_dir,
            self.runtime_object_dir,
            self.incidents_dir,
            self.curation_dir,
            self.retrieval_cache_dir,
            self.evaluation_dir,
            self.e2e_observability_dir,
            self.live_metrics_dir,
            self.live_traces_dir,
            self.logs_dir,
            self.operational_events_dir,
            self.operational_metrics_dir,
            self.operational_traces_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(0o700)


settings = Settings()
