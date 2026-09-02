"""Create-only retrieval re-attestation for an already sealed candidate.

This lane exists only to refresh the executable scorer proof.  It never edits
the candidate generation, its catalogue status, or an index pointer.  The
legacy v1.1 summary remains historical evidence; a separate append-only ledger
and compare-and-swap selector identify the proof accepted by runtime.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import subprocess
import threading
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager, suppress
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Protocol, cast

from ..assessment.guidance_bundle import OWNER_ASSESSMENT_BUNDLE
from ..config import Settings
from ..db import SCHEMA_VERSION, utc_iso
from ..privacy import safe_summary
from ..quality.policy import POLICY_SHA256
from .retrieval_v1 import (
    FREEZE_MANIFEST_RELATIVE,
    FROZEN_JSONL_RELATIVE,
    POLICY_RELATIVE,
    aggregate_split,
    load_retrieval_policy,
    load_retrieval_v1_jsonl,
    run_retrieval_v1,
    scorer_implementation_sha256,
    verify_owner_freeze,
)
from .scorer_closure import (
    ScorerClosureReference,
    load_scorer_closure_reference,
)

REATTESTATION_SCHEMA = "legalbot.retrieval-reattestation.v2"
LEGACY_ATTESTATION_SCHEMA = "legalbot.retrieval-attestation.v1.1"
REATTESTATION_ATTEMPT_START_SCHEMA = "legalbot.retrieval-reattestation-attempt-start.v1"
REATTESTATION_ATTEMPT_SCHEMA = "legalbot.retrieval-reattestation-attempt.v1"
REATTESTATION_ATTEMPT_REFERENCE_SCHEMA = "legalbot.retrieval-reattestation-attempt-reference.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_REATTEST_CATALOGUE_SCHEMA_VERSION = "19"
_REATTEST_CATALOGUE_JOURNAL_MODE = "wal"
_REATTEST_COMPATIBLE_CATALOGUE_SCHEMA_VERSIONS = frozenset(
    str(version)
    for version in range(int(_REATTEST_CATALOGUE_SCHEMA_VERSION), SCHEMA_VERSION + 1)
)

_REATTESTATION_SCHEMA_STATEMENTS = {
    "retrieval_attestation_history": """
        CREATE TABLE IF NOT EXISTS retrieval_attestation_history (
          id TEXT PRIMARY KEY,
          build_id TEXT NOT NULL REFERENCES index_builds(id),
          attestation_path TEXT NOT NULL UNIQUE,
          attestation_sha256 TEXT NOT NULL UNIQUE,
          schema_version TEXT NOT NULL,
          prior_attestation_path TEXT,
          prior_attestation_sha256 TEXT,
          build_seal_sha256 TEXT NOT NULL,
          source_manifest_sha256 TEXT NOT NULL,
          embedding_model TEXT NOT NULL,
          reranker_model TEXT NOT NULL,
          quality_policy_sha256 TEXT NOT NULL,
          assessment_bundle_sha256 TEXT NOT NULL,
          retrieval_policy_sha256 TEXT NOT NULL,
          benchmark_sha256 TEXT NOT NULL,
          freeze_manifest_sha256 TEXT NOT NULL,
          scorer_version TEXT NOT NULL,
          scorer_implementation_sha256 TEXT NOT NULL,
          integration_sha TEXT NOT NULL,
          created_at TEXT NOT NULL,
          UNIQUE(build_id, scorer_implementation_sha256, integration_sha,
                 prior_attestation_sha256)
        )
    """,
    "idx_retrieval_attestation_history_build": """
        CREATE INDEX IF NOT EXISTS idx_retrieval_attestation_history_build
          ON retrieval_attestation_history(build_id, created_at)
    """,
    "retrieval_attestation_selections": """
        CREATE TABLE IF NOT EXISTS retrieval_attestation_selections (
          build_id TEXT PRIMARY KEY REFERENCES index_builds(id),
          attestation_id TEXT NOT NULL REFERENCES retrieval_attestation_history(id),
          selected_at TEXT NOT NULL
        )
    """,
    "trg_retrieval_attestation_history_no_update": """
        CREATE TRIGGER IF NOT EXISTS trg_retrieval_attestation_history_no_update
        BEFORE UPDATE ON retrieval_attestation_history
        BEGIN
          SELECT RAISE(ABORT, 'retrieval attestation history is immutable');
        END
    """,
    "trg_retrieval_attestation_history_no_delete": """
        CREATE TRIGGER IF NOT EXISTS trg_retrieval_attestation_history_no_delete
        BEFORE DELETE ON retrieval_attestation_history
        BEGIN
          SELECT RAISE(ABORT, 'retrieval attestation history is immutable');
        END
    """,
}

_REQUIRED_INDEX_BUILD_COLUMNS = {
    "id": ("TEXT", 0, 1),
    "status": ("TEXT", 1, 0),
    "stage": ("TEXT", 1, 0),
    "path": ("TEXT", 1, 0),
    "document_count": ("INTEGER", 1, 0),
    "chunk_count": ("INTEGER", 1, 0),
    "vector_count": ("INTEGER", 1, 0),
    "embedding_model": ("TEXT", 1, 0),
    "embedding_model_version": ("TEXT", 0, 0),
    "reranker_model": ("TEXT", 1, 0),
    "rerank_version": ("TEXT", 0, 0),
    "manifest_sha256": ("TEXT", 0, 0),
    "candidate_manifest_hash": ("TEXT", 0, 0),
    "benchmark_result_json": ("TEXT", 1, 0),
    "policy_sha256": ("TEXT", 1, 0),
    "assessment_bundle_sha256": ("TEXT", 1, 0),
}


class RetrievalAttestationDatabase(Protocol):
    def transaction(self) -> AbstractContextManager[sqlite3.Connection]: ...

    def fetchone(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None: ...


class ExistingRetrievalAttestationDatabase:
    """Narrow existing-file SQLite handle for offline re-attestation only."""

    def __init__(
        self,
        *,
        path: Path,
        connection: sqlite3.Connection,
        directory_descriptor: int,
        lock_descriptor: int,
        directory_identity: tuple[int, int, int, int],
        database_identity: tuple[int, int, int, int],
    ) -> None:
        self.path = path
        self._connection = connection
        self._directory_descriptor = directory_descriptor
        self._lock_descriptor = lock_descriptor
        self._directory_identity = directory_identity
        self._database_identity = database_identity
        self._lock = threading.RLock()

    def _require_current_path_identity(self) -> None:
        if self.path.parent.resolve(strict=True) != self.path.parent:
            raise RuntimeError("re-attestation catalogue ancestor became a symbolic link")
        directory = os.stat(self.path.parent, follow_symlinks=False)
        database = os.stat(self.path, follow_symlinks=False)
        _require_private_existing_file(database, label="catalogue")
        if (
            not stat.S_ISDIR(directory.st_mode)
            or (
                directory.st_dev,
                directory.st_ino,
                directory.st_uid,
                directory.st_mode,
            )
            != self._directory_identity
            or (
                database.st_dev,
                database.st_ino,
                database.st_uid,
                database.st_mode,
            )
            != self._database_identity
        ):
            raise RuntimeError("re-attestation catalogue path identity changed")

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                self._require_current_path_identity()
                self._connection.execute("BEGIN IMMEDIATE")
                self._require_current_path_identity()
                yield self._connection
                self._require_current_path_identity()
                self._connection.commit()
                self._require_current_path_identity()
            except Exception:
                self._connection.rollback()
                raise

    def fetchone(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        with self._lock:
            self._require_current_path_identity()
            row = cast(sqlite3.Row | None, self._connection.execute(sql, params).fetchone())
            self._require_current_path_identity()
            return row

    def close(self) -> None:
        try:
            with self._lock:
                self._connection.close()
        finally:
            try:
                fcntl.flock(self._lock_descriptor, fcntl.LOCK_UN)
            finally:
                os.close(self._lock_descriptor)
                os.close(self._directory_descriptor)


def _require_private_existing_file(value: os.stat_result, *, label: str) -> None:
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_uid != os.getuid()
        or stat.S_IMODE(value.st_mode) != 0o600
        or value.st_nlink != 1
    ):
        raise RuntimeError(f"{label} must be one private owner file")


def open_existing_retrieval_reattest_database(
    path: Path,
) -> ExistingRetrievalAttestationDatabase:
    """Open the exact existing catalogue without migration or PRAGMA mutation."""

    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory_flag is None:
        raise RuntimeError("secure existing-catalogue open is unavailable")
    absolute = path.absolute()
    if absolute.parent.resolve(strict=True) != absolute.parent:
        raise RuntimeError("re-attestation catalogue ancestors must not be symbolic links")
    directory_descriptor = os.open(
        absolute.parent,
        os.O_RDONLY | directory_flag | no_follow,
    )
    lock_descriptor = -1
    connection: sqlite3.Connection | None = None
    try:
        lock_descriptor = os.open(
            ".catalog-initialize.lock",
            os.O_RDWR | no_follow,
            dir_fd=directory_descriptor,
        )
        _require_private_existing_file(os.fstat(lock_descriptor), label="catalogue lock")
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        directory_before = os.fstat(directory_descriptor)
        if not stat.S_ISDIR(directory_before.st_mode) or directory_before.st_uid != os.getuid():
            raise RuntimeError("catalogue directory identity is invalid")
        directory_identity = (
            directory_before.st_dev,
            directory_before.st_ino,
            directory_before.st_uid,
            directory_before.st_mode,
        )
        before = os.stat(
            absolute.name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        _require_private_existing_file(before, label="catalogue")

        connection = sqlite3.connect(
            absolute.as_uri() + "?mode=rw",
            uri=True,
            check_same_thread=False,
            timeout=30,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0])
        synchronous = int(connection.execute("PRAGMA synchronous").fetchone()[0])
        database_rows = connection.execute("PRAGMA database_list").fetchall()
        main_paths = [str(row["file"]) for row in database_rows if str(row["name"]) == "main"]
        after_from_descriptor = os.stat(
            absolute.name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        lexical_directory = os.stat(absolute.parent, follow_symlinks=False)
        lexical_database = os.stat(absolute, follow_symlinks=False)
        database_identity = (before.st_dev, before.st_ino, before.st_uid, before.st_mode)
        if (
            absolute.parent.resolve(strict=True) != absolute.parent
            or (
                lexical_directory.st_dev,
                lexical_directory.st_ino,
                lexical_directory.st_uid,
                lexical_directory.st_mode,
            )
            != directory_identity
            or (
                after_from_descriptor.st_dev,
                after_from_descriptor.st_ino,
                after_from_descriptor.st_uid,
                after_from_descriptor.st_mode,
            )
            != database_identity
            or (
                lexical_database.st_dev,
                lexical_database.st_ino,
                lexical_database.st_uid,
                lexical_database.st_mode,
            )
            != database_identity
            or main_paths != [str(absolute)]
            or journal_mode != _REATTEST_CATALOGUE_JOURNAL_MODE
            or synchronous != 2
        ):
            raise RuntimeError("existing re-attestation catalogue identity or mode differs")
        return ExistingRetrievalAttestationDatabase(
            path=absolute,
            connection=connection,
            directory_descriptor=directory_descriptor,
            lock_descriptor=lock_descriptor,
            directory_identity=directory_identity,
            database_identity=database_identity,
        )
    except Exception:
        if connection is not None:
            connection.close()
        if lock_descriptor >= 0:
            try:
                fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            finally:
                os.close(lock_descriptor)
        os.close(directory_descriptor)
        raise


@dataclass(frozen=True, slots=True)
class CandidateRetrievalIdentity:
    build_id: str
    build_seal_sha256: str
    source_manifest_file_sha256: str
    source_manifest_sha256: str
    candidate_manifest_hash: str
    document_count: int
    chunk_count: int
    vector_count: int
    embedding_model: str
    embedding_model_version: str
    reranker_model: str
    rerank_version: str
    quality_policy_sha256: str
    assessment_bundle_sha256: str
    retrieval_policy_sha256: str
    benchmark_sha256: str
    freeze_manifest_sha256: str
    scorer_version: str
    scorer_implementation_sha256: str


@dataclass(frozen=True, slots=True)
class AttestationReference:
    path: str
    sha256: str
    history_id: str | None
    scorer_implementation_sha256: str
    integration_sha: str | None
    schema: str
    scorer_closure_aggregate_sha256: str | None


@dataclass(frozen=True, slots=True)
class DiagnosticAttemptReference:
    attempt_id: str
    path: str
    sha256: str
    seal_sha256: str

    def safe_dict(self) -> dict[str, str]:
        return {
            "schema": REATTESTATION_ATTEMPT_REFERENCE_SCHEMA,
            "attempt_id": self.attempt_id,
            "path": self.path,
            "sha256": self.sha256,
            "seal_sha256": self.seal_sha256,
        }


def _normalised_schema_sql(value: str) -> str:
    without_guard = re.sub(r"\bIF\s+NOT\s+EXISTS\b", "", value, flags=re.IGNORECASE)
    return re.sub(r"\s+", " ", without_guard).strip().removesuffix(";").lower()


def _require_reattest_base_catalogue(
    connection: Any, *, allowed_schema_versions: frozenset[str]
) -> None:
    schema_meta = connection.execute(
        "SELECT type FROM sqlite_master WHERE name='schema_meta'"
    ).fetchone()
    if schema_meta is None or str(schema_meta["type"]) != "table":
        raise RuntimeError("retrieval re-attestation base catalogue differs")
    schema_version = connection.execute(
        "SELECT value FROM schema_meta WHERE key='schema_version'"
    ).fetchone()
    index_builds = connection.execute(
        "SELECT type FROM sqlite_master WHERE name='index_builds'"
    ).fetchone()
    index_columns = {
        str(row["name"]): (
            str(row["type"]).upper(),
            int(row["notnull"]),
            int(row["pk"]),
        )
        for row in connection.execute("PRAGMA table_info(index_builds)").fetchall()
    }
    if (
        schema_version is None
        or str(schema_version["value"]) not in allowed_schema_versions
        or index_builds is None
        or str(index_builds["type"]) != "table"
        or any(
            index_columns.get(name) != expected
            for name, expected in _REQUIRED_INDEX_BUILD_COLUMNS.items()
        )
    ):
        raise RuntimeError("retrieval re-attestation base catalogue differs")


def _require_exact_reattestation_schema(connection: Any) -> None:
    _require_reattest_base_catalogue(
        connection,
        allowed_schema_versions=_REATTEST_COMPATIBLE_CATALOGUE_SCHEMA_VERSIONS,
    )

    expected_types = {
        "retrieval_attestation_history": "table",
        "idx_retrieval_attestation_history_build": "index",
        "retrieval_attestation_selections": "table",
        "trg_retrieval_attestation_history_no_update": "trigger",
        "trg_retrieval_attestation_history_no_delete": "trigger",
    }
    for name, statement in _REATTESTATION_SCHEMA_STATEMENTS.items():
        row = connection.execute(
            "SELECT type,sql FROM sqlite_master WHERE name=?", (name,)
        ).fetchone()
        if (
            row is None
            or str(row["type"]) != expected_types[name]
            or not isinstance(row["sql"], str)
            or _normalised_schema_sql(str(row["sql"])) != _normalised_schema_sql(statement)
        ):
            raise RuntimeError("retrieval re-attestation schema differs from the sealed contract")

    history_foreign_keys = {
        (str(row["from"]), str(row["table"]), str(row["to"]))
        for row in connection.execute(
            "PRAGMA foreign_key_list(retrieval_attestation_history)"
        ).fetchall()
    }
    selection_foreign_keys = {
        (str(row["from"]), str(row["table"]), str(row["to"]))
        for row in connection.execute(
            "PRAGMA foreign_key_list(retrieval_attestation_selections)"
        ).fetchall()
    }
    if history_foreign_keys != {("build_id", "index_builds", "id")} or (
        selection_foreign_keys
        != {
            ("build_id", "index_builds", "id"),
            ("attestation_id", "retrieval_attestation_history", "id"),
        }
    ):
        raise RuntimeError("retrieval re-attestation foreign-key contract differs")


def initialize_retrieval_reattest_schema(database: RetrievalAttestationDatabase) -> None:
    """Create only the append-only re-attestation ledger on a legacy catalogue.

    This deliberately does not call the general catalogue migrator or update
    ``schema_meta``.  The real v1.11 candidate was sealed against schema v19;
    re-attesting its executable scorer must not rewrite unrelated catalogue
    rows as a side effect.
    """

    with database.transaction() as connection:
        foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()
        if foreign_keys is None or int(foreign_keys[0]) != 1:
            raise RuntimeError("retrieval re-attestation requires foreign keys")
        expected_names = set(_REATTESTATION_SCHEMA_STATEMENTS)
        existing_names = {
            str(row["name"])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE name IN (?,?,?,?,?)",
                tuple(sorted(expected_names)),
            ).fetchall()
        }
        if existing_names and existing_names != expected_names:
            raise RuntimeError("retrieval re-attestation schema differs from the sealed contract")
        if existing_names:
            _require_exact_reattestation_schema(connection)
            return
        _require_reattest_base_catalogue(
            connection,
            allowed_schema_versions=frozenset({_REATTEST_CATALOGUE_SCHEMA_VERSION}),
        )
        for statement in _REATTESTATION_SCHEMA_STATEMENTS.values():
            connection.execute(statement)
        _require_exact_reattestation_schema(connection)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"retrieval attestation JSON is unreadable: {path.name}") from exc
    if not isinstance(value, dict):
        raise RuntimeError("retrieval attestation JSON must be an object")
    return dict(value)


def _canonical_row(row: Mapping[str, Any]) -> str:
    return json.dumps(dict(row), ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _pointer_snapshot(settings: Settings) -> tuple[tuple[str, str], ...]:
    snapshots: list[tuple[str, str]] = []
    for name in ("ACTIVE.json", "PREVIOUS.json"):
        path = settings.index_dir / name
        if path.is_symlink():
            raise RuntimeError(f"{name} must not be a symbolic link")
        snapshots.append((name, _file_sha256(path) if path.is_file() else "missing"))
    return tuple(snapshots)


def _clean_integration_sha(project_root: Path) -> str:
    """Return HEAD only when its raw tracked bytes exactly match the worktree."""

    git = Path("/usr/bin/git")
    if git.is_symlink() or not git.is_file() or git.stat().st_uid != 0:
        raise RuntimeError("trusted system Git executable is unavailable")
    git_env = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }
    revision = subprocess.run(
        [
            str(git),
            "--no-replace-objects",
            "-C",
            str(project_root),
            "rev-parse",
            "--verify",
            "HEAD",
        ],
        check=True,
        capture_output=True,
        text=True,
        env=git_env,
    ).stdout.strip()
    if not _GIT_SHA.fullmatch(revision):
        raise RuntimeError("integration HEAD is not a supported Git object identity")
    # Import lazily so the retrieval module remains independent of owner-policy
    # model imports at module load.  This is the single raw-byte verifier used
    # by promotion, readiness, Stage A, All60, runtime and re-attestation.
    from ..governance.v111_decision_generation import require_exact_clean_head

    return require_exact_clean_head(project_root, revision)


def _attestation_path(settings: Settings, build_id: str, relative: str) -> Path:
    if not relative or Path(relative).is_absolute():
        raise RuntimeError("retrieval attestation path must be project-relative")
    raw_root = settings.evaluation_dir / "retrieval" / build_id
    raw_path = settings.project_root / relative
    if raw_root.is_symlink() or raw_path.is_symlink():
        raise RuntimeError("retrieval attestation storage must not use symbolic links")
    expected_root = raw_root.resolve()
    path = raw_path.resolve()
    if path.parent != expected_root:
        raise RuntimeError("retrieval attestation is not beside this candidate's prior proof")
    if not path.is_file():
        raise RuntimeError("retrieval attestation is missing or is a symbolic link")
    return path


def _attempt_seal(payload: Mapping[str, Any]) -> str:
    unsigned = dict(payload)
    unsigned.pop("seal_sha256", None)
    return hashlib.sha256(_canonical_row(unsigned).encode("utf-8")).hexdigest()


def _validate_attempt_reference(
    settings: Settings,
    identity: CandidateRetrievalIdentity,
    integration_sha: str,
    report: Mapping[str, Any],
    value: Any,
) -> DiagnosticAttemptReference:
    if not isinstance(value, Mapping):
        raise RuntimeError("selected retrieval diagnostic-attempt reference is invalid")
    relative = value.get("path")
    attempt_id = value.get("attempt_id")
    expected_sha256 = value.get("sha256")
    expected_seal = value.get("seal_sha256")
    if (
        value.get("schema") != REATTESTATION_ATTEMPT_REFERENCE_SCHEMA
        or not isinstance(relative, str)
        or not isinstance(attempt_id, str)
        or not re.fullmatch(r"[0-9a-f]{32}", attempt_id)
        or not isinstance(expected_sha256, str)
        or not _SHA256.fullmatch(expected_sha256)
        or not isinstance(expected_seal, str)
        or not _SHA256.fullmatch(expected_seal)
    ):
        raise RuntimeError("selected retrieval diagnostic-attempt reference is invalid")
    path = _attestation_path(settings, identity.build_id, relative)
    payload = _json_object(path)
    checkpoint = payload.get("checkpoint")
    candidate = payload.get("candidate")
    execution = payload.get("execution")
    quality = payload.get("quality")
    attestation_preconditions = payload.get("attestation_preconditions")
    start_reference = payload.get("start_receipt")
    if (
        _file_sha256(path) != expected_sha256
        or payload.get("schema") != REATTESTATION_ATTEMPT_SCHEMA
        or payload.get("attempt_id") != attempt_id
        or payload.get("authorizing") is not False
        or payload.get("seal_sha256") != expected_seal
        or _attempt_seal(payload) != expected_seal
        or not isinstance(checkpoint, Mapping)
        or checkpoint.get("commit") != integration_sha
        or not isinstance(candidate, Mapping)
        or candidate.get("build_id") != identity.build_id
        or candidate.get("build_seal_sha256") != identity.build_seal_sha256
        or not isinstance(execution, Mapping)
        or execution.get("completion_state") != "completed"
        or execution.get("completed_query_count") != 24
        or execution.get("answer_model_invoked") is not False
        or not isinstance(quality, Mapping)
        or quality.get("status") != "passed"
        or quality.get("failed_gates") != []
        or not isinstance(attestation_preconditions, Mapping)
        or attestation_preconditions.get("status") != "passed"
        or attestation_preconditions.get("exception") is not None
        or payload.get("report") != dict(report)
        or not isinstance(start_reference, Mapping)
    ):
        raise RuntimeError("selected retrieval diagnostic attempt is invalid")
    start_relative = start_reference.get("path")
    start_sha256 = start_reference.get("sha256")
    start_seal = start_reference.get("seal_sha256")
    if (
        start_reference.get("attempt_id") != attempt_id
        or not isinstance(start_relative, str)
        or not isinstance(start_sha256, str)
        or not _SHA256.fullmatch(start_sha256)
        or not isinstance(start_seal, str)
        or not _SHA256.fullmatch(start_seal)
    ):
        raise RuntimeError("selected retrieval diagnostic-attempt start reference is invalid")
    start_path = _attestation_path(settings, identity.build_id, start_relative)
    start_payload = _json_object(start_path)
    start_checkpoint = start_payload.get("checkpoint")
    start_candidate = start_payload.get("candidate")
    if (
        _file_sha256(start_path) != start_sha256
        or start_payload.get("schema") != REATTESTATION_ATTEMPT_START_SCHEMA
        or start_payload.get("attempt_id") != attempt_id
        or start_payload.get("authorizing") is not False
        or start_payload.get("seal_sha256") != start_seal
        or _attempt_seal(start_payload) != start_seal
        or not isinstance(start_checkpoint, Mapping)
        or start_checkpoint.get("commit") != integration_sha
        or not isinstance(start_candidate, Mapping)
        or start_candidate.get("build_id") != identity.build_id
    ):
        raise RuntimeError("selected retrieval diagnostic-attempt start receipt is invalid")
    return DiagnosticAttemptReference(
        attempt_id=attempt_id,
        path=relative,
        sha256=expected_sha256,
        seal_sha256=expected_seal,
    )


def _frozen_benchmark_rows(
    settings: Settings, identity: CandidateRetrievalIdentity
) -> tuple[dict[str, Any], ...]:
    path = settings.project_root / FROZEN_JSONL_RELATIVE
    rows = load_retrieval_v1_jsonl(path, identity.benchmark_sha256)
    selected = tuple(dict(row) for row in rows if row.get("split") in {"development", "promotion"})
    if len(selected) != 24:
        raise RuntimeError("frozen retrieval benchmark does not contain exactly 24 ranking cases")
    return selected


def _integer_rank_list(value: Any, *, label: str) -> tuple[int, ...]:
    if not isinstance(value, list) or any(
        isinstance(item, bool) or not isinstance(item, int) or not 1 <= item <= 10 for item in value
    ):
        raise RuntimeError(f"retrieval per-query {label} is invalid")
    if len(value) != len(set(value)) or value != sorted(value):
        raise RuntimeError(f"retrieval per-query {label} is not a unique rank sequence")
    return tuple(value)


def _validate_per_query_result(value: Mapping[str, Any], frozen: Mapping[str, Any]) -> None:
    """Validate one result as a ranking record, not a bag of claimed gate booleans."""

    if (
        value.get("id") != frozen.get("id")
        or value.get("split") != frozen.get("split")
        or value.get("match_mode") != frozen.get("match_mode")
        or value.get("primary_must_hit") is not frozen.get("primary_must_hit")
        or value.get("polarity") != "positive"
        or value.get("frozen_expected_source_id") != frozen.get("expected_source_id")
        or value.get("frozen_expected_source_version_id")
        != frozen.get("expected_source_version_id")
        or value.get("legal_locator") != frozen.get("legal_locator")
        or value.get("proposition_span_sha256") != frozen.get("proposition_span_sha256")
    ):
        raise RuntimeError("retrieval per-query frozen identity is invalid")
    if any(type(value.get(key)) is not bool for key in ("hit@3", "hit@5", "hit@10")):
        raise RuntimeError("retrieval per-query hit fields must be booleans")
    gold_rank = value.get("gold_rank")
    if gold_rank is not None and (
        isinstance(gold_rank, bool) or not isinstance(gold_rank, int) or not 1 <= gold_rank <= 10
    ):
        raise RuntimeError("retrieval per-query gold rank is invalid")
    expected_hits = (
        gold_rank is not None and gold_rank <= 3,
        gold_rank is not None and gold_rank <= 5,
        gold_rank is not None and gold_rank <= 10,
    )
    if tuple(value.get(key) for key in ("hit@3", "hit@5", "hit@10")) != expected_hits:
        raise RuntimeError("retrieval per-query hit fields disagree with the gold rank")
    reciprocal = value.get("reciprocal_rank")
    expected_reciprocal = 1.0 / gold_rank if gold_rank is not None else 0.0
    if (
        isinstance(reciprocal, bool)
        or not isinstance(reciprocal, int | float)
        or float(reciprocal) != expected_reciprocal
    ):
        raise RuntimeError("retrieval per-query reciprocal rank is invalid")

    wrong_ranks = _integer_rank_list(value.get("wrong_version_ranks"), label="wrong-version ranks")
    forbidden_ranks = _integer_rank_list(
        value.get("forbidden_lane_ranks"), label="forbidden-lane ranks"
    )
    private_ranks = _integer_rank_list(
        value.get("private_path_ranks", []), label="private-path ranks"
    )
    if (
        value.get("wrong_version") is not bool(wrong_ranks)
        or value.get("forbidden_lane") is not bool(forbidden_ranks)
        or value.get("current_outranks_as_enacted") is not (not wrong_ranks)
        or value.get("teaching_assessment_hits") != len(forbidden_ranks)
        or value.get("private_path_hits") != len(private_ranks)
    ):
        raise RuntimeError("retrieval per-query zero-tolerance fields are inconsistent")

    top_fields = (
        "top_chunk_ids",
        "top_source_identities",
        "top_locators",
        "top_lanes",
        "top_currentness",
    )
    top_values = tuple(value.get(key) for key in top_fields)
    if any(not isinstance(item, list) for item in top_values):
        raise RuntimeError("retrieval per-query top-ranking fields must be arrays")
    top_lengths = {len(item) for item in top_values if isinstance(item, list)}
    if len(top_lengths) != 1 or next(iter(top_lengths), 0) > 10:
        raise RuntimeError("retrieval per-query top-ranking arrays are inconsistent")
    top_count = next(iter(top_lengths), 0)
    if value.get("hit_count") != top_count:
        raise RuntimeError("retrieval per-query hit count is inconsistent")
    if any(
        not isinstance(item, str) for top in top_values if isinstance(top, list) for item in top
    ):
        raise RuntimeError("retrieval per-query top-ranking identity is invalid")
    hit_diagnostics = value.get("top_hit_diagnostics")
    if hit_diagnostics is not None:
        if not isinstance(hit_diagnostics, list) or len(hit_diagnostics) != top_count:
            raise RuntimeError("retrieval per-query hit diagnostics are inconsistent")
        for index, diagnostic in enumerate(hit_diagnostics):
            if not isinstance(diagnostic, Mapping):
                raise RuntimeError("retrieval per-query hit diagnostic is not an object")
            fused_score = diagnostic.get("fused_score")
            reranker_score = diagnostic.get("reranker_score")
            if (
                diagnostic.get("chunk_id") != value["top_chunk_ids"][index]
                or isinstance(fused_score, bool)
                or not isinstance(fused_score, int | float)
                or (
                    reranker_score is not None
                    and (
                        isinstance(reranker_score, bool)
                        or not isinstance(reranker_score, int | float)
                    )
                )
                or any(
                    rank is not None
                    and (isinstance(rank, bool) or not isinstance(rank, int) or rank < 1)
                    for rank in (
                        diagnostic.get("lexical_rank"),
                        diagnostic.get("vector_rank"),
                    )
                )
            ):
                raise RuntimeError("retrieval per-query hit diagnostic is invalid")
    expected_forbidden_ranks = tuple(
        index
        for index, lane in enumerate(value["top_lanes"], start=1)
        if lane
        in ({"private_teaching", "assessment_guidance"} | set(frozen.get("forbidden_lanes") or ()))
    )
    if forbidden_ranks != expected_forbidden_ranks:
        raise RuntimeError("retrieval per-query forbidden-lane ranks are not derived from hits")

    gold_hashes = value.get("gold_span_sha256s")
    if not isinstance(gold_hashes, list) or any(
        not isinstance(item, str) or not _SHA256.fullmatch(item) for item in gold_hashes
    ):
        raise RuntimeError("retrieval per-query gold-span identities are invalid")
    frozen_gold = frozen.get("gold_spans")
    expected_gold_count = len(frozen_gold) if isinstance(frozen_gold, list) else 0
    if value.get("gold_span_count") != len(gold_hashes) or len(gold_hashes) != expected_gold_count:
        raise RuntimeError("retrieval per-query gold-span count is invalid")
    for limit in (3, 5, 10):
        hits = value.get(f"exact_span_hits_at_{limit}")
        recall = value.get(f"exact_span_recall_at_{limit}")
        if (
            not isinstance(hits, list)
            or len(hits) != len(set(hits))
            or not set(hits) <= set(gold_hashes)
        ):
            raise RuntimeError("retrieval per-query exact-span hits are invalid")
        expected_recall = len(hits) / len(gold_hashes) if gold_hashes else None
        if recall != expected_recall:
            raise RuntimeError("retrieval per-query exact-span recall is inconsistent")
    timings = value.get("timings_ms")
    if not isinstance(timings, Mapping) or any(
        isinstance(item, bool) or not isinstance(item, int | float) or float(item) < 0
        for item in timings.values()
    ):
        raise RuntimeError("retrieval per-query timings are invalid")


def _validate_report(
    settings: Settings,
    report: Mapping[str, Any],
    identity: CandidateRetrievalIdentity,
) -> None:
    frozen_rows = _frozen_benchmark_rows(settings, identity)
    per_query_value = report.get("per_query")
    binding = report.get("candidate_gold_binding")
    if (
        report.get("schema") != "legalbot.offline-retrieval.v1.1"
        or report.get("build_id") != identity.build_id
        or report.get("splits") != ["development", "promotion"]
        or report.get("jsonl_sha256") != identity.benchmark_sha256
        or report.get("retrieval_policy_sha256") != identity.retrieval_policy_sha256
        or report.get("scorer_version") != identity.scorer_version
        or report.get("scorer_implementation_sha256") != identity.scorer_implementation_sha256
        or report.get("answer_model_invoked") is not False
        or report.get("active_json_written") is not False
        or not isinstance(per_query_value, list)
        or len(per_query_value) != 24
        or not isinstance(binding, Mapping)
        or binding.get("status") != "bound"
        or binding.get("row_count") != 24
        or binding.get("issues") != []
        or not isinstance(binding.get("bindings"), list)
        or len(binding["bindings"]) != 24
    ):
        raise RuntimeError("frozen retrieval report structure is invalid")
    per_query: list[dict[str, Any]] = []
    for value, frozen in zip(per_query_value, frozen_rows, strict=True):
        if not isinstance(value, Mapping):
            raise RuntimeError("retrieval per-query result is not an object")
        _validate_per_query_result(value, frozen)
        per_query.append(dict(value))
    expected_pairs = [(row["id"], row["split"]) for row in frozen_rows]
    observed_pairs = [(row.get("id"), row.get("split")) for row in per_query]
    if observed_pairs != expected_pairs or len(set(observed_pairs)) != 24:
        raise RuntimeError("retrieval report does not contain the exact frozen case sequence")
    binding_pairs = [
        (item.get("case_id"), item.get("status"))
        for item in binding["bindings"]
        if isinstance(item, Mapping)
    ]
    if binding_pairs != [(row["id"], "bound") for row in frozen_rows]:
        raise RuntimeError("retrieval candidate binding does not cover the frozen cases")

    aggregates = aggregate_split(per_query, project_root=settings.project_root)
    split_aggregates = {
        split: aggregate_split(
            [item for item in per_query if item["split"] == split],
            project_root=settings.project_root,
        )
        for split in ("development", "promotion")
    }
    if (
        report.get("aggregates") != aggregates
        or report.get("split_aggregates") != split_aggregates
        or report.get("go") is not all(bool(value["go"]) for value in split_aggregates.values())
        or report.get("go") is not True
        or any(
            not value.get("gates") or any(passed is not True for passed in value["gates"].values())
            for value in (aggregates, *split_aggregates.values())
        )
    ):
        raise RuntimeError("frozen development and promotion retrieval gates did not pass")


def _candidate_identity(
    settings: Settings,
    row: Mapping[str, Any],
    *,
    verify_tree: bool = True,
) -> CandidateRetrievalIdentity:
    """Verify sealed candidate bytes, then derive the re-attestation binding."""

    from .service import _verify_durable_candidate_tree

    if str(row.get("status") or "") not in {"candidate", "active"} or str(
        row.get("stage") or ""
    ) not in {"candidate", "active"}:
        raise RuntimeError("selected retrieval proof requires a sealed candidate or active build")
    build_id = str(row.get("id") or "")
    if verify_tree:
        _verify_durable_candidate_tree(settings, row)
    build_path = settings.index_dir / "builds" / build_id
    source_path = build_path / "approved-source-manifest.json"
    source = _json_object(source_path)
    freeze_path = settings.project_root / FREEZE_MANIFEST_RELATIVE
    freeze = verify_owner_freeze(
        settings.project_root, settings.project_root / FROZEN_JSONL_RELATIVE
    )
    policy, retrieval_policy_sha256 = load_retrieval_policy(settings.project_root)
    identity = CandidateRetrievalIdentity(
        build_id=build_id,
        build_seal_sha256=_file_sha256(build_path / "seal.json"),
        source_manifest_file_sha256=_file_sha256(source_path),
        source_manifest_sha256=str(source.get("manifest_sha256") or ""),
        candidate_manifest_hash=str(row.get("candidate_manifest_hash") or ""),
        document_count=int(row.get("document_count") or 0),
        chunk_count=int(row.get("chunk_count") or 0),
        vector_count=int(row.get("vector_count") or 0),
        embedding_model=str(row.get("embedding_model") or ""),
        embedding_model_version=str(row.get("embedding_model_version") or ""),
        reranker_model=str(row.get("reranker_model") or ""),
        rerank_version=str(row.get("rerank_version") or ""),
        quality_policy_sha256=POLICY_SHA256,
        assessment_bundle_sha256=OWNER_ASSESSMENT_BUNDLE.sha256,
        retrieval_policy_sha256=retrieval_policy_sha256,
        benchmark_sha256=str(freeze["jsonl_sha256"]),
        freeze_manifest_sha256=_file_sha256(freeze_path),
        scorer_version=str(policy["scorer"]),
        scorer_implementation_sha256=scorer_implementation_sha256(settings.project_root),
    )
    sealed_policy_path = build_path / "retrieval-policy.yaml"
    sealed_benchmark_path = build_path / "retrieval-benchmark-v1.1.jsonl"
    sealed_freeze_path = build_path / "retrieval-benchmark-v1.1.freeze.json"
    if (
        _file_sha256(sealed_policy_path) != _file_sha256(settings.project_root / POLICY_RELATIVE)
        or _file_sha256(sealed_benchmark_path)
        != _file_sha256(settings.project_root / FROZEN_JSONL_RELATIVE)
        or _file_sha256(sealed_freeze_path) != identity.freeze_manifest_sha256
    ):
        raise RuntimeError("candidate is sealed to a different retrieval freeze or policy")
    for value in (
        identity.build_seal_sha256,
        identity.source_manifest_file_sha256,
        identity.source_manifest_sha256,
        identity.quality_policy_sha256,
        identity.assessment_bundle_sha256,
        identity.retrieval_policy_sha256,
        identity.benchmark_sha256,
        identity.freeze_manifest_sha256,
        identity.scorer_implementation_sha256,
    ):
        if not _SHA256.fullmatch(value):
            raise RuntimeError("candidate retrieval identity contains an invalid digest")
    if not all(
        (
            identity.embedding_model,
            identity.embedding_model_version,
            identity.reranker_model,
            identity.rerank_version,
            identity.scorer_version,
        )
    ):
        raise RuntimeError("candidate retrieval model/scorer identity is incomplete")
    return identity


def _validate_legacy_attestation(
    settings: Settings,
    row: Mapping[str, Any],
    identity: CandidateRetrievalIdentity,
) -> AttestationReference:
    try:
        summary = json.loads(str(row.get("benchmark_result_json") or "{}"))
    except json.JSONDecodeError as exc:
        raise RuntimeError("legacy retrieval attestation summary is invalid") from exc
    if not isinstance(summary, dict):
        raise RuntimeError("legacy retrieval attestation summary is invalid")
    relative = str(summary.get("attestation_path") or "")
    path = _attestation_path(settings, identity.build_id, relative)
    digest = _file_sha256(path)
    payload = _json_object(path)
    report = payload.get("report")
    aggregates = report.get("aggregates") if isinstance(report, Mapping) else None
    gates = aggregates.get("gates") if isinstance(aggregates, Mapping) else None
    if (
        summary.get("schema") != LEGACY_ATTESTATION_SCHEMA
        or summary.get("passed") is not True
        or summary.get("promotion_eligible") is not True
        or summary.get("attestation_sha256") != digest
        or payload.get("schema") != LEGACY_ATTESTATION_SCHEMA
        or payload.get("build_id") != identity.build_id
        or payload.get("build_seal_sha256") != identity.build_seal_sha256
        or payload.get("source_manifest_sha256") != identity.source_manifest_file_sha256
        or payload.get("quality_policy_sha256") != identity.quality_policy_sha256
        or payload.get("assessment_bundle_sha256") != identity.assessment_bundle_sha256
        or payload.get("retrieval_policy_sha256") != identity.retrieval_policy_sha256
        or payload.get("benchmark_sha256") != identity.benchmark_sha256
        or payload.get("passed") is not True
        or payload.get("promotion_eligible") is not True
        or not isinstance(report, Mapping)
        or report.get("build_id") != identity.build_id
        or report.get("splits") != ["development", "promotion"]
        or report.get("go") is not True
        or report.get("answer_model_invoked") is not False
        or report.get("active_json_written") is not False
        or not isinstance(gates, Mapping)
        or not gates
        or any(value is not True for value in gates.values())
    ):
        raise RuntimeError("legacy retrieval attestation is missing, changed, or invalid")
    scorer = str(payload.get("scorer_implementation_sha256") or "")
    if not _SHA256.fullmatch(scorer):
        raise RuntimeError("legacy retrieval attestation scorer identity is invalid")
    return AttestationReference(
        path=relative,
        sha256=digest,
        history_id=None,
        scorer_implementation_sha256=scorer,
        integration_sha=None,
        schema=LEGACY_ATTESTATION_SCHEMA,
        scorer_closure_aggregate_sha256=None,
    )


def _history_row(database: RetrievalAttestationDatabase, build_id: str) -> Mapping[str, Any] | None:
    row = database.fetchone(
        """SELECT h.* FROM retrieval_attestation_selections s
           JOIN retrieval_attestation_history h ON h.id=s.attestation_id
           WHERE s.build_id=? AND h.build_id=s.build_id""",
        (build_id,),
    )
    return dict(row) if row is not None else None


def _validate_selected_artifact(
    settings: Settings,
    row: Mapping[str, Any],
    history: Mapping[str, Any],
    identity: CandidateRetrievalIdentity,
    *,
    require_current_scorer: bool,
) -> AttestationReference:
    relative = str(history.get("attestation_path") or "")
    path = _attestation_path(settings, identity.build_id, relative)
    digest = _file_sha256(path)
    payload = _json_object(path)
    report = payload.get("report")
    scorer = str(history.get("scorer_implementation_sha256") or "")
    integration_sha = str(history.get("integration_sha") or "")
    closure_reference: ScorerClosureReference | None = None
    if (
        history.get("id") != digest
        or history.get("attestation_sha256") != digest
        or history.get("build_id") != identity.build_id
        or history.get("build_seal_sha256") != identity.build_seal_sha256
        or history.get("source_manifest_sha256") != identity.source_manifest_file_sha256
        or history.get("embedding_model") != identity.embedding_model
        or history.get("reranker_model") != identity.reranker_model
        or history.get("quality_policy_sha256") != identity.quality_policy_sha256
        or history.get("assessment_bundle_sha256") != identity.assessment_bundle_sha256
        or history.get("retrieval_policy_sha256") != identity.retrieval_policy_sha256
        or history.get("benchmark_sha256") != identity.benchmark_sha256
        or history.get("freeze_manifest_sha256") != identity.freeze_manifest_sha256
        or history.get("scorer_version") != identity.scorer_version
        or not isinstance(report, Mapping)
    ):
        raise RuntimeError("selected retrieval attestation ledger binding is invalid")
    schema = str(payload.get("schema") or "")
    if schema == REATTESTATION_SCHEMA:
        prior = payload.get("prior_attestation")
        candidate = payload.get("candidate")
        closure_value = payload.get("scorer_closure")
        diagnostic_attempt = payload.get("diagnostic_attempt")
        if (
            history.get("schema_version") != REATTESTATION_SCHEMA
            or payload.get("build_id") != identity.build_id
            or payload.get("build_seal_sha256") != identity.build_seal_sha256
            or payload.get("source_manifest_sha256") != identity.source_manifest_file_sha256
            or payload.get("source_manifest_logical_sha256") != identity.source_manifest_sha256
            or payload.get("quality_policy_sha256") != identity.quality_policy_sha256
            or payload.get("assessment_bundle_sha256") != identity.assessment_bundle_sha256
            or payload.get("retrieval_policy_sha256") != identity.retrieval_policy_sha256
            or payload.get("benchmark_sha256") != identity.benchmark_sha256
            or payload.get("freeze_manifest_sha256") != identity.freeze_manifest_sha256
            or payload.get("scorer_version") != identity.scorer_version
            or payload.get("scorer_implementation_sha256")
            != history.get("scorer_implementation_sha256")
            or payload.get("integration_sha") != history.get("integration_sha")
            or not isinstance(closure_value, Mapping)
            or not isinstance(diagnostic_attempt, Mapping)
            or not isinstance(prior, Mapping)
            or prior.get("path") != history.get("prior_attestation_path")
            or prior.get("sha256") != history.get("prior_attestation_sha256")
            or not isinstance(candidate, Mapping)
            or candidate.get("document_count") != identity.document_count
            or candidate.get("chunk_count") != identity.chunk_count
            or candidate.get("vector_count") != identity.vector_count
            or candidate.get("candidate_manifest_hash") != identity.candidate_manifest_hash
            or candidate.get("embedding_model") != identity.embedding_model
            or candidate.get("embedding_model_version") != identity.embedding_model_version
            or candidate.get("reranker_model") != identity.reranker_model
            or candidate.get("rerank_version") != identity.rerank_version
            or payload.get("passed") is not True
            or payload.get("promotion_eligible") is not True
            or payload.get("candidate_tree_written") is not False
            or payload.get("candidate_status_written") is not False
            or payload.get("active_pointer_written") is not False
        ):
            raise RuntimeError("selected retrieval re-attestation contents are invalid")
        closure_path_value = closure_value.get("manifest_path")
        if not isinstance(closure_path_value, str) or not closure_path_value:
            raise RuntimeError("selected scorer closure reference is invalid")
        closure_path = settings.project_root / closure_path_value
        expected_closure_parent = (
            settings.evaluation_dir / "retrieval" / identity.build_id
        ).resolve()
        if closure_path.resolve().parent != expected_closure_parent:
            raise RuntimeError("selected scorer closure escaped the candidate evidence root")
        closure_reference = load_scorer_closure_reference(
            project_root=settings.project_root,
            manifest_path=closure_path,
            require_current=require_current_scorer,
            expected_head=integration_sha,
            expected_legacy_digest=scorer,
        )
        if dict(closure_value) != closure_reference.safe_dict():
            raise RuntimeError("selected scorer closure reference differs from its manifest")
        _validate_attempt_reference(
            settings,
            identity,
            integration_sha,
            report,
            diagnostic_attempt,
        )
    elif schema == LEGACY_ATTESTATION_SCHEMA:
        if (
            payload.get("build_id") != identity.build_id
            or payload.get("build_seal_sha256") != identity.build_seal_sha256
            or payload.get("source_manifest_sha256") != identity.source_manifest_file_sha256
            or payload.get("quality_policy_sha256") != identity.quality_policy_sha256
            or payload.get("assessment_bundle_sha256") != identity.assessment_bundle_sha256
            or payload.get("passed") is not True
            or payload.get("promotion_eligible") is not True
        ):
            raise RuntimeError("selected legacy retrieval attestation contents are invalid")
    else:
        raise RuntimeError("selected retrieval attestation schema is unsupported")
    if require_current_scorer and scorer != identity.scorer_implementation_sha256:
        raise RuntimeError("selected retrieval attestation does not prove the current scorer")
    report_identity = (
        identity
        if require_current_scorer
        else replace(identity, scorer_implementation_sha256=scorer)
    )
    _validate_report(settings, report, report_identity)
    return AttestationReference(
        path=relative,
        sha256=digest,
        history_id=str(history["id"]),
        scorer_implementation_sha256=scorer,
        integration_sha=str(history.get("integration_sha") or "") or None,
        schema=schema,
        scorer_closure_aggregate_sha256=(
            closure_reference.aggregate_sha256 if closure_reference is not None else None
        ),
    )


def _prior_reference(
    settings: Settings,
    database: RetrievalAttestationDatabase,
    row: Mapping[str, Any],
    identity: CandidateRetrievalIdentity,
) -> AttestationReference:
    history = _history_row(database, identity.build_id)
    if history is None:
        return _validate_legacy_attestation(settings, row, identity)
    return _validate_selected_artifact(
        settings, row, history, identity, require_current_scorer=False
    )


def _destination(
    settings: Settings,
    identity: CandidateRetrievalIdentity,
    prior: AttestationReference,
    integration_sha: str,
    nonce: str,
) -> Path:
    name = (
        "v1.1-reattest-"
        f"{identity.scorer_implementation_sha256[:16]}-"
        f"{integration_sha[:16]}-{prior.sha256[:16]}-{nonce}.json"
    )
    return settings.evaluation_dir / "retrieval" / identity.build_id / name


def _attempt_destinations(
    settings: Settings,
    identity: CandidateRetrievalIdentity,
    integration_sha: str,
    attempt_id: str,
) -> tuple[Path, Path]:
    stem = f"v1.1-reattest-attempt-{integration_sha[:16]}-{attempt_id}"
    root = settings.evaluation_dir / "retrieval" / identity.build_id
    return root / f"{stem}-start.json", root / f"{stem}-result.json"


def _attempt_identity_payload(
    identity: CandidateRetrievalIdentity,
    prior: AttestationReference,
    integration_sha: str,
    scorer_closure: ScorerClosureReference,
) -> dict[str, Any]:
    return {
        "checkpoint": {
            "commit": integration_sha,
            "tree": scorer_closure.integration_tree,
        },
        "candidate": {
            "build_id": identity.build_id,
            "build_seal_sha256": identity.build_seal_sha256,
            "source_manifest_file_sha256": identity.source_manifest_file_sha256,
            "source_manifest_logical_sha256": identity.source_manifest_sha256,
            "candidate_manifest_hash": identity.candidate_manifest_hash,
            "document_count": identity.document_count,
            "chunk_count": identity.chunk_count,
            "vector_count": identity.vector_count,
            "embedding_model": identity.embedding_model,
            "embedding_model_version": identity.embedding_model_version,
            "reranker_model": identity.reranker_model,
            "rerank_version": identity.rerank_version,
        },
        "suite": {
            "splits": ["development", "promotion"],
            "expected_query_count": 24,
            "benchmark_sha256": identity.benchmark_sha256,
            "freeze_manifest_sha256": identity.freeze_manifest_sha256,
            "retrieval_policy_sha256": identity.retrieval_policy_sha256,
            "scorer_version": identity.scorer_version,
            "scorer_implementation_sha256": identity.scorer_implementation_sha256,
        },
        "scorer_closure": scorer_closure.safe_dict(),
        "prior_attestation": {
            "path": prior.path,
            "sha256": prior.sha256,
            "history_id": prior.history_id,
        },
    }


def _exception_payload(exc: BaseException, *, stage: str) -> dict[str, str]:
    raw_message = str(exc)
    return {
        "type": type(exc).__name__,
        "stage": stage,
        "message": safe_summary(raw_message),
        "message_sha256": hashlib.sha256(raw_message.encode("utf-8")).hexdigest(),
    }


def _failed_gate_paths(report: Mapping[str, Any]) -> list[str]:
    failed: list[str] = []
    scopes: list[tuple[str, Any]] = [("aggregate", report.get("aggregates"))]
    split_value = report.get("split_aggregates")
    if isinstance(split_value, Mapping):
        scopes.extend(
            (f"split.{split}", split_value.get(split)) for split in ("development", "promotion")
        )
    for scope, summary in scopes:
        if not isinstance(summary, Mapping):
            continue
        gates = summary.get("gates")
        if not isinstance(gates, Mapping):
            continue
        failed.extend(
            f"{scope}.{name}" for name, passed in sorted(gates.items()) if passed is not True
        )
    if report.get("go") is not True and not failed:
        failed.append("report.go")
    return failed


def _sealed_attempt_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    sealed = dict(payload)
    sealed["seal_sha256"] = _attempt_seal(sealed)
    return sealed


def _write_atomic_new_json(path: Path, payload: Mapping[str, Any]) -> None:
    """Publish one immutable JSON artifact without exposing partial bytes."""

    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink() or path.is_symlink():
        raise RuntimeError("retrieval diagnostic-attempt storage is unsafe")
    path.parent.chmod(0o700)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory_flag is None:
        raise RuntimeError("atomic diagnostic-attempt publication is unavailable")
    data = (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    directory_descriptor = os.open(
        path.parent,
        os.O_RDONLY | directory_flag | no_follow,
    )
    temporary_name = f".{path.name}.{secrets.token_hex(12)}.tmp"
    temporary_created = False
    try:
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow,
            0o400,
            dir_fd=directory_descriptor,
        )
        temporary_created = True
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(
            temporary_name,
            path.name,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        os.unlink(temporary_name, dir_fd=directory_descriptor)
        temporary_created = False
        os.fsync(directory_descriptor)
    finally:
        if temporary_created:
            with suppress(FileNotFoundError):
                os.unlink(temporary_name, dir_fd=directory_descriptor)
        os.close(directory_descriptor)


def _write_attempt_artifact(
    settings: Settings,
    path: Path,
    attempt_id: str,
    payload: Mapping[str, Any],
) -> DiagnosticAttemptReference:
    sealed = _sealed_attempt_payload(payload)
    _write_atomic_new_json(path, sealed)
    return DiagnosticAttemptReference(
        attempt_id=attempt_id,
        path=str(path.relative_to(settings.project_root)),
        sha256=_file_sha256(path),
        seal_sha256=str(sealed["seal_sha256"]),
    )


def _attempt_result_payload(
    *,
    attempt_id: str,
    started_at: str,
    identity_payload: Mapping[str, Any],
    start_reference: DiagnosticAttemptReference,
    completion_state: str,
    quality_status: str,
    failed_gates: Sequence[str],
    quality_exception: Mapping[str, str] | None,
    attestation_precondition_status: str,
    attestation_precondition_exception: Mapping[str, str] | None,
    report: Mapping[str, Any] | None,
    partial_per_query: Sequence[Mapping[str, Any]],
    observed_binding: Mapping[str, Any] | None,
) -> dict[str, Any]:
    report_per_query = report.get("per_query") if report is not None else None
    completed_query_count = (
        len(report_per_query) if isinstance(report_per_query, list) else len(partial_per_query)
    )
    report_binding = report.get("candidate_gold_binding") if report is not None else None
    binding = report_binding if isinstance(report_binding, Mapping) else observed_binding
    report_dict = dict(report) if report is not None else None
    return {
        "schema": REATTESTATION_ATTEMPT_SCHEMA,
        "attempt_id": attempt_id,
        "authorizing": False,
        "started_at": started_at,
        "finished_at": utc_iso(),
        **dict(identity_payload),
        "start_receipt": start_reference.safe_dict(),
        "execution": {
            "completion_state": completion_state,
            "expected_query_count": 24,
            "completed_query_count": completed_query_count,
            "retrieval_call_count": completed_query_count,
            "answer_model_invoked": False,
        },
        "quality": {
            "status": quality_status,
            "failed_gates": list(failed_gates),
            "exception": (dict(quality_exception) if quality_exception is not None else None),
        },
        "attestation_preconditions": {
            "status": attestation_precondition_status,
            "exception": (
                dict(attestation_precondition_exception)
                if attestation_precondition_exception is not None
                else None
            ),
        },
        "candidate_gold_binding": dict(binding) if isinstance(binding, Mapping) else None,
        "partial_per_query": (
            [dict(value) for value in partial_per_query] if report is None else []
        ),
        "report": report_dict,
        "report_sha256": (
            hashlib.sha256(_canonical_row(report_dict).encode("utf-8")).hexdigest()
            if report_dict is not None
            else None
        ),
        "passing_attestation": {
            "eligible": (
                quality_status == "passed"
                and completion_state == "completed"
                and attestation_precondition_status == "passed"
            ),
            "history_record_written_by_attempt": False,
            "selection_written_by_attempt": False,
        },
        "side_effects": {
            "candidate_tree_written": False,
            "candidate_status_written": False,
            "active_pointer_written": False,
        },
    }


def _payload(
    identity: CandidateRetrievalIdentity,
    prior: AttestationReference,
    integration_sha: str,
    scorer_closure: ScorerClosureReference,
    report: Mapping[str, Any],
    diagnostic_attempt: DiagnosticAttemptReference,
) -> dict[str, Any]:
    return {
        "schema": REATTESTATION_SCHEMA,
        "created_at": utc_iso(),
        "build_id": identity.build_id,
        "build_seal_sha256": identity.build_seal_sha256,
        "source_manifest_sha256": identity.source_manifest_file_sha256,
        "source_manifest_logical_sha256": identity.source_manifest_sha256,
        "quality_policy_sha256": identity.quality_policy_sha256,
        "assessment_bundle_sha256": identity.assessment_bundle_sha256,
        "retrieval_policy_sha256": identity.retrieval_policy_sha256,
        "benchmark_sha256": identity.benchmark_sha256,
        "freeze_manifest_sha256": identity.freeze_manifest_sha256,
        "scorer_version": identity.scorer_version,
        "scorer_implementation_sha256": identity.scorer_implementation_sha256,
        "scorer_closure": scorer_closure.safe_dict(),
        "integration_sha": integration_sha,
        "prior_attestation": {
            "path": prior.path,
            "sha256": prior.sha256,
            "history_id": prior.history_id,
        },
        "diagnostic_attempt": diagnostic_attempt.safe_dict(),
        "candidate": {
            "candidate_manifest_hash": identity.candidate_manifest_hash,
            "document_count": identity.document_count,
            "chunk_count": identity.chunk_count,
            "vector_count": identity.vector_count,
            "embedding_model": identity.embedding_model,
            "embedding_model_version": identity.embedding_model_version,
            "reranker_model": identity.reranker_model,
            "rerank_version": identity.rerank_version,
        },
        "passed": True,
        "promotion_eligible": True,
        "candidate_tree_written": False,
        "candidate_status_written": False,
        "active_pointer_written": False,
        "report": dict(report),
    }


def _write_new_json(path: Path, payload: Mapping[str, Any]) -> None:
    from .service import _write_new_json as write_new_json

    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    write_new_json(path, payload)


def _assert_same_candidate_row(
    connection: Any,
    build_id: str,
    expected_row: Mapping[str, Any],
) -> None:
    current = connection.execute("SELECT * FROM index_builds WHERE id=?", (build_id,)).fetchone()
    if current is None or _canonical_row(dict(current)) != _canonical_row(expected_row):
        raise RuntimeError("candidate catalogue state changed during retrieval re-attestation")


def _assert_reattest_state(
    settings: Settings,
    database: RetrievalAttestationDatabase,
    *,
    row: Mapping[str, Any],
    identity: CandidateRetrievalIdentity,
    integration_sha: str,
    pointer_snapshot: tuple[tuple[str, str], ...],
) -> None:
    """Recheck every mutable release identity at a proof-write boundary."""

    if _clean_integration_sha(settings.project_root) != integration_sha:
        raise RuntimeError("integration HEAD changed during retrieval re-attestation")
    current_value = database.fetchone("SELECT * FROM index_builds WHERE id=?", (identity.build_id,))
    if current_value is None:
        raise RuntimeError("candidate disappeared during retrieval re-attestation")
    current = dict(current_value)
    if (
        _canonical_row(current) != _canonical_row(row)
        or str(current.get("status") or "") != "candidate"
        or str(current.get("stage") or "") != "candidate"
    ):
        raise RuntimeError("candidate catalogue state changed during retrieval re-attestation")
    if _candidate_identity(settings, current, verify_tree=False) != identity:
        raise RuntimeError("candidate seal changed during retrieval re-attestation")
    if _pointer_snapshot(settings) != pointer_snapshot:
        raise RuntimeError("index pointer changed during retrieval re-attestation")


def _append_and_select(
    settings: Settings,
    database: RetrievalAttestationDatabase,
    *,
    row: Mapping[str, Any],
    identity: CandidateRetrievalIdentity,
    prior: AttestationReference,
    relative_path: str,
    attestation_sha256: str,
    integration_sha: str,
    created_at: str,
    pointer_snapshot: tuple[tuple[str, str], ...],
) -> None:
    values = (
        attestation_sha256,
        identity.build_id,
        relative_path,
        attestation_sha256,
        REATTESTATION_SCHEMA,
        prior.path,
        prior.sha256,
        identity.build_seal_sha256,
        identity.source_manifest_file_sha256,
        identity.embedding_model,
        identity.reranker_model,
        identity.quality_policy_sha256,
        identity.assessment_bundle_sha256,
        identity.retrieval_policy_sha256,
        identity.benchmark_sha256,
        identity.freeze_manifest_sha256,
        identity.scorer_version,
        identity.scorer_implementation_sha256,
        integration_sha,
        created_at,
    )
    with database.transaction() as connection:
        _require_exact_reattestation_schema(connection)
        if _clean_integration_sha(settings.project_root) != integration_sha:
            raise RuntimeError("integration HEAD changed before attestation selection")
        if _pointer_snapshot(settings) != pointer_snapshot:
            raise RuntimeError("index pointer changed before attestation selection")
        _assert_same_candidate_row(connection, identity.build_id, row)
        current_identity = _candidate_identity(settings, row, verify_tree=False)
        if current_identity != identity:
            raise RuntimeError("candidate seal changed before attestation selection")
        selected = connection.execute(
            "SELECT attestation_id FROM retrieval_attestation_selections WHERE build_id=?",
            (identity.build_id,),
        ).fetchone()
        current_selected = str(selected["attestation_id"]) if selected is not None else None
        if current_selected != prior.history_id:
            raise RuntimeError("selected retrieval attestation changed before compare-and-swap")
        existing = connection.execute(
            "SELECT * FROM retrieval_attestation_history WHERE id=?",
            (attestation_sha256,),
        ).fetchone()
        if existing is None:
            connection.execute(
                """INSERT INTO retrieval_attestation_history(
                     id,build_id,attestation_path,attestation_sha256,schema_version,
                     prior_attestation_path,prior_attestation_sha256,build_seal_sha256,
                     source_manifest_sha256,embedding_model,reranker_model,
                     quality_policy_sha256,assessment_bundle_sha256,
                     retrieval_policy_sha256,benchmark_sha256,freeze_manifest_sha256,
                     scorer_version,scorer_implementation_sha256,integration_sha,created_at
                   ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                values,
            )
        elif tuple(existing) != values:
            raise RuntimeError("existing retrieval attestation history row is inconsistent")
        now = utc_iso()
        if selected is None:
            connection.execute(
                """INSERT INTO retrieval_attestation_selections(
                     build_id,attestation_id,selected_at) VALUES (?,?,?)""",
                (identity.build_id, attestation_sha256, now),
            )
        else:
            changed = connection.execute(
                """UPDATE retrieval_attestation_selections
                   SET attestation_id=?,selected_at=?
                   WHERE build_id=? AND attestation_id=?""",
                (attestation_sha256, now, identity.build_id, prior.history_id),
            ).rowcount
            if changed != 1:
                raise RuntimeError("retrieval attestation selection compare-and-swap failed")
        if _pointer_snapshot(settings) != pointer_snapshot:
            raise RuntimeError("index pointer changed during attestation selection")


def reattest_retrieval_v1(
    settings: Settings,
    database: RetrievalAttestationDatabase,
    *,
    build_id: str,
    scorer_closure_manifest_path: Path,
    benchmark_runner: Callable[..., dict[str, Any]] = run_retrieval_v1,
) -> dict[str, Any]:
    """Re-run frozen v1.1 and select a create-only current-scorer proof."""

    from .service import _validate_build_id

    _validate_build_id(build_id)
    integration_sha = _clean_integration_sha(settings.project_root)
    row_value = database.fetchone("SELECT * FROM index_builds WHERE id=?", (build_id,))
    if row_value is None:
        raise ValueError("candidate index build does not exist")
    row = dict(row_value)
    if str(row.get("status") or "") != "candidate" or str(row.get("stage") or "") != ("candidate"):
        raise RuntimeError("retrieval re-attestation requires status/stage candidate")
    pointer_before = _pointer_snapshot(settings)
    identity = _candidate_identity(settings, row)
    expected_closure_parent = (settings.evaluation_dir / "retrieval" / identity.build_id).resolve()
    if scorer_closure_manifest_path.resolve().parent != expected_closure_parent:
        raise RuntimeError("scorer closure manifest escaped the candidate evidence root")
    scorer_closure = load_scorer_closure_reference(
        project_root=settings.project_root,
        manifest_path=scorer_closure_manifest_path,
        require_current=True,
        expected_head=integration_sha,
        expected_legacy_digest=identity.scorer_implementation_sha256,
    )
    prior = _prior_reference(settings, database, row, identity)
    if (
        prior.scorer_implementation_sha256 == identity.scorer_implementation_sha256
        and prior.integration_sha == integration_sha
        and prior.history_id is not None
        and prior.scorer_closure_aggregate_sha256 == scorer_closure.aggregate_sha256
    ):
        return {
            "build_id": build_id,
            "status": "candidate",
            "selected_attestation_path": prior.path,
            "selected_attestation_sha256": prior.sha256,
            "scorer_implementation_sha256": identity.scorer_implementation_sha256,
            "integration_sha": integration_sha,
            "scorer_closure_aggregate_sha256": scorer_closure.aggregate_sha256,
            "recovered": True,
            "benchmark_ran": False,
        }
    attempt_id = secrets.token_hex(16)
    attempt_started_at = utc_iso()
    start_destination, result_destination = _attempt_destinations(
        settings,
        identity,
        integration_sha,
        attempt_id,
    )
    attempt_identity = _attempt_identity_payload(
        identity,
        prior,
        integration_sha,
        scorer_closure,
    )
    start_reference = _write_attempt_artifact(
        settings,
        start_destination,
        attempt_id,
        {
            "schema": REATTESTATION_ATTEMPT_START_SCHEMA,
            "attempt_id": attempt_id,
            "authorizing": False,
            "created_at": attempt_started_at,
            **attempt_identity,
            "execution": {
                "completion_state": "running",
                "expected_query_count": 24,
                "completed_query_count": 0,
                "retrieval_call_count": 0,
                "answer_model_invoked": False,
            },
            "passing_attestation": {
                "history_record_written": False,
                "selection_written": False,
            },
        },
    )
    observed_binding: dict[str, Any] | None = None
    partial_per_query: list[dict[str, Any]] = []

    def observe_result(event: Mapping[str, Any]) -> None:
        nonlocal observed_binding
        if event.get("stage") == "binding_completed":
            binding = event.get("candidate_gold_binding")
            if isinstance(binding, Mapping):
                observed_binding = dict(binding)
            return
        if event.get("stage") != "query_completed":
            return
        result = event.get("result")
        if not isinstance(result, Mapping):
            raise RuntimeError("retrieval result observer received an invalid query result")
        expected_count = len(partial_per_query) + 1
        if event.get("completed_query_count") != expected_count:
            raise RuntimeError("retrieval result observer sequence is invalid")
        partial_per_query.append(dict(result))

    try:
        if benchmark_runner is run_retrieval_v1:
            report = benchmark_runner(
                settings,
                build_id=build_id,
                splits=("development", "promotion"),
                result_observer=observe_result,
            )
        else:
            report = benchmark_runner(
                settings,
                build_id=build_id,
                splits=("development", "promotion"),
            )
    except BaseException as exc:
        _write_attempt_artifact(
            settings,
            result_destination,
            attempt_id,
            _attempt_result_payload(
                attempt_id=attempt_id,
                started_at=attempt_started_at,
                identity_payload=attempt_identity,
                start_reference=start_reference,
                completion_state="incomplete",
                quality_status="not_evaluated",
                failed_gates=(),
                quality_exception=None,
                attestation_precondition_status="not_evaluated",
                attestation_precondition_exception=_exception_payload(
                    exc, stage="benchmark_runner"
                ),
                report=None,
                partial_per_query=partial_per_query,
                observed_binding=observed_binding,
            ),
        )
        raise
    try:
        _validate_report(settings, report, identity)
    except Exception as exc:
        _write_attempt_artifact(
            settings,
            result_destination,
            attempt_id,
            _attempt_result_payload(
                attempt_id=attempt_id,
                started_at=attempt_started_at,
                identity_payload=attempt_identity,
                start_reference=start_reference,
                completion_state="completed",
                quality_status="failed",
                failed_gates=_failed_gate_paths(report),
                quality_exception=_exception_payload(exc, stage="report_validation"),
                attestation_precondition_status="not_evaluated",
                attestation_precondition_exception=None,
                report=report,
                partial_per_query=partial_per_query,
                observed_binding=observed_binding,
            ),
        )
        raise
    try:
        _assert_reattest_state(
            settings,
            database,
            row=row,
            identity=identity,
            integration_sha=integration_sha,
            pointer_snapshot=pointer_before,
        )
    except Exception as exc:
        _write_attempt_artifact(
            settings,
            result_destination,
            attempt_id,
            _attempt_result_payload(
                attempt_id=attempt_id,
                started_at=attempt_started_at,
                identity_payload=attempt_identity,
                start_reference=start_reference,
                completion_state="completed",
                quality_status="passed",
                failed_gates=(),
                quality_exception=None,
                attestation_precondition_status="failed",
                attestation_precondition_exception=_exception_payload(
                    exc, stage="post_run_state_validation"
                ),
                report=report,
                partial_per_query=partial_per_query,
                observed_binding=observed_binding,
            ),
        )
        raise
    attempt_reference = _write_attempt_artifact(
        settings,
        result_destination,
        attempt_id,
        _attempt_result_payload(
            attempt_id=attempt_id,
            started_at=attempt_started_at,
            identity_payload=attempt_identity,
            start_reference=start_reference,
            completion_state="completed",
            quality_status="passed",
            failed_gates=(),
            quality_exception=None,
            attestation_precondition_status="passed",
            attestation_precondition_exception=None,
            report=report,
            partial_per_query=partial_per_query,
            observed_binding=observed_binding,
        ),
    )
    destination = _destination(
        settings,
        identity,
        prior,
        integration_sha,
        secrets.token_hex(12),
    )
    payload = _payload(
        identity,
        prior,
        integration_sha,
        scorer_closure,
        report,
        attempt_reference,
    )
    _write_new_json(destination, payload)
    created_at = str(payload["created_at"])
    _assert_reattest_state(
        settings,
        database,
        row=row,
        identity=identity,
        integration_sha=integration_sha,
        pointer_snapshot=pointer_before,
    )
    relative = str(destination.relative_to(settings.project_root))
    digest = _file_sha256(destination)
    _append_and_select(
        settings,
        database,
        row=row,
        identity=identity,
        prior=prior,
        relative_path=relative,
        attestation_sha256=digest,
        integration_sha=integration_sha,
        created_at=created_at,
        pointer_snapshot=pointer_before,
    )
    selected = _history_row(database, build_id)
    if selected is None:
        raise RuntimeError("retrieval re-attestation selection was not recorded")
    _validate_selected_artifact(settings, row, selected, identity, require_current_scorer=True)
    return {
        "build_id": build_id,
        "status": "candidate",
        "selected_attestation_path": relative,
        "selected_attestation_sha256": digest,
        "prior_attestation_path": prior.path,
        "prior_attestation_sha256": prior.sha256,
        "scorer_implementation_sha256": identity.scorer_implementation_sha256,
        "integration_sha": integration_sha,
        "scorer_closure_manifest_path": scorer_closure.manifest_path,
        "scorer_closure_manifest_file_sha256": scorer_closure.manifest_file_sha256,
        "scorer_closure_aggregate_sha256": scorer_closure.aggregate_sha256,
        "diagnostic_attempt_path": attempt_reference.path,
        "diagnostic_attempt_sha256": attempt_reference.sha256,
        "diagnostic_attempt_seal_sha256": attempt_reference.seal_sha256,
        "recovered": False,
        "benchmark_ran": True,
        "active_written": False,
    }


def verify_selected_retrieval_attestation(
    settings: Settings,
    database: RetrievalAttestationDatabase,
    row: Mapping[str, Any],
    identity: CandidateRetrievalIdentity | None = None,
    *,
    tree_already_verified: bool = False,
) -> AttestationReference:
    """Require the catalogue-selected proof for the executable scorer."""

    with database.transaction() as connection:
        _require_exact_reattestation_schema(connection)
    candidate_identity = identity or _candidate_identity(
        settings, row, verify_tree=not tree_already_verified
    )
    history = _history_row(database, candidate_identity.build_id)
    if history is None:
        raise RuntimeError("candidate has no selected retrieval attestation")
    return _validate_selected_artifact(
        settings,
        row,
        history,
        candidate_identity,
        require_current_scorer=True,
    )
