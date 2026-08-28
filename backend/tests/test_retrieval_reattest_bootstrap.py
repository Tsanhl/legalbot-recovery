from __future__ import annotations

import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from app import cli
from app.db import Database
from app.retrieval import retrieval_reattest
from app.retrieval.retrieval_reattest import (
    initialize_retrieval_reattest_schema,
    open_existing_retrieval_reattest_database,
)


def _legacy_catalogue(path: Path, *, malformed_history: bool = False) -> None:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        PRAGMA foreign_keys=ON;
        CREATE TABLE schema_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        INSERT INTO schema_meta(key,value) VALUES('schema_version','19');
        CREATE TABLE index_builds(
          id TEXT PRIMARY KEY,
          status TEXT NOT NULL,
          stage TEXT NOT NULL,
          path TEXT NOT NULL,
          document_count INTEGER NOT NULL,
          chunk_count INTEGER NOT NULL,
          vector_count INTEGER NOT NULL,
          embedding_model TEXT NOT NULL,
          embedding_model_version TEXT,
          reranker_model TEXT NOT NULL,
          rerank_version TEXT,
          manifest_sha256 TEXT,
          candidate_manifest_hash TEXT,
          benchmark_result_json TEXT NOT NULL,
          policy_sha256 TEXT NOT NULL,
          assessment_bundle_sha256 TEXT NOT NULL
        );
        INSERT INTO index_builds(
          id,status,stage,path,document_count,chunk_count,vector_count,
          embedding_model,embedding_model_version,reranker_model,rerank_version,
          manifest_sha256,candidate_manifest_hash,benchmark_result_json,
          policy_sha256,assessment_bundle_sha256
        ) VALUES(
          'sealed-candidate','candidate','candidate','data/indexes/builds/sealed-candidate',
          1,1,1,'embedding','revision','reranker','revision',
          '', '', '{}', '', ''
        );
        CREATE TABLE unrelated_state(id TEXT PRIMARY KEY,value TEXT NOT NULL);
        INSERT INTO unrelated_state(id,value) VALUES('sentinel','unchanged');
        """
    )
    if malformed_history:
        connection.execute("CREATE TABLE retrieval_attestation_history(id TEXT PRIMARY KEY)")
    connection.commit()
    connection.close()
    path.chmod(0o600)


def test_surgical_bootstrap_preserves_legacy_catalogue_and_history_is_immutable(
    tmp_path: Path,
) -> None:
    path = tmp_path / "catalog.sqlite3"
    _legacy_catalogue(path)
    database = Database(path)
    try:
        initialize_retrieval_reattest_schema(database)

        assert (
            database.fetchone("SELECT value FROM schema_meta WHERE key='schema_version'")["value"]
            == "19"
        )
        assert (
            database.fetchone("SELECT value FROM unrelated_state WHERE id='sentinel'")["value"]
            == "unchanged"
        )
        assert (
            database.fetchone("SELECT name FROM sqlite_master WHERE type='table' AND name='jobs'")
            is None
        )

        history = {
            "id": "history-1",
            "build_id": "sealed-candidate",
            "attestation_path": "data/evaluations/retrieval/proof.json",
            "attestation_sha256": "1" * 64,
            "schema_version": "legalbot.retrieval-reattestation.v1",
            "prior_attestation_path": "data/evaluations/retrieval/prior.json",
            "prior_attestation_sha256": "2" * 64,
            "build_seal_sha256": "3" * 64,
            "source_manifest_sha256": "4" * 64,
            "embedding_model": "embedding-model",
            "reranker_model": "reranker-model",
            "quality_policy_sha256": "5" * 64,
            "assessment_bundle_sha256": "6" * 64,
            "retrieval_policy_sha256": "7" * 64,
            "benchmark_sha256": "8" * 64,
            "freeze_manifest_sha256": "9" * 64,
            "scorer_version": "scorer-v1",
            "scorer_implementation_sha256": "a" * 64,
            "integration_sha": "b" * 40,
            "created_at": "2026-08-20T00:00:00+00:00",
        }
        columns = ",".join(history)
        placeholders = ",".join("?" for _ in history)
        database.execute(
            f"INSERT INTO retrieval_attestation_history({columns}) VALUES({placeholders})",
            tuple(history.values()),
        )
        with pytest.raises(sqlite3.IntegrityError, match="history is immutable"):
            database.execute(
                "UPDATE retrieval_attestation_history SET scorer_version='changed' WHERE id=?",
                (history["id"],),
            )
        with pytest.raises(sqlite3.IntegrityError, match="history is immutable"):
            database.execute(
                "DELETE FROM retrieval_attestation_history WHERE id=?", (history["id"],)
            )
    finally:
        database.close()


def test_surgical_bootstrap_rejects_a_preexisting_lax_schema(tmp_path: Path) -> None:
    path = tmp_path / "catalog.sqlite3"
    _legacy_catalogue(path, malformed_history=True)
    database = Database(path)
    try:
        with pytest.raises(RuntimeError, match="schema differs"):
            initialize_retrieval_reattest_schema(database)
        assert (
            database.fetchone("SELECT value FROM unrelated_state WHERE id='sentinel'")["value"]
            == "unchanged"
        )
        assert (
            database.fetchone(
                "SELECT name FROM sqlite_master WHERE name='retrieval_attestation_selections'"
            )
            is None
        )
    finally:
        database.close()


def test_surgical_bootstrap_rejects_an_incomplete_base_before_ddl(tmp_path: Path) -> None:
    path = tmp_path / "catalog.sqlite3"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE schema_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        INSERT INTO schema_meta(key,value) VALUES('schema_version','19');
        CREATE TABLE index_builds(id TEXT PRIMARY KEY);
        """
    )
    connection.close()
    path.chmod(0o600)
    database = Database(path)
    try:
        with pytest.raises(RuntimeError, match="base catalogue differs"):
            initialize_retrieval_reattest_schema(database)
        assert (
            database.fetchone(
                "SELECT name FROM sqlite_master WHERE name='retrieval_attestation_history'"
            )
            is None
        )
    finally:
        database.close()


def test_existing_catalogue_opener_preserves_database_identity_and_mode(
    tmp_path: Path,
) -> None:
    path = tmp_path / "catalog.sqlite3"
    _legacy_catalogue(path)
    setup = Database(path)
    setup.close()
    before = path.stat()

    database = open_existing_retrieval_reattest_database(path)
    try:
        assert database.fetchone("PRAGMA journal_mode")[0] == "wal"
        assert database.fetchone("PRAGMA synchronous")[0] == 2
    finally:
        database.close()

    after = path.stat()
    assert (
        after.st_dev,
        after.st_ino,
        after.st_uid,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
    ) == (
        before.st_dev,
        before.st_ino,
        before.st_uid,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
    )


def test_existing_catalogue_opener_rejects_parent_replacement_during_connect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_parent = tmp_path / "database"
    original_parent.mkdir()
    original_path = original_parent / "catalog.sqlite3"
    _legacy_catalogue(original_path)
    original_setup = Database(original_path)
    original_setup.close()

    replacement_parent = tmp_path / "replacement"
    replacement_parent.mkdir()
    replacement_path = replacement_parent / "catalog.sqlite3"
    _legacy_catalogue(replacement_path)
    replacement_setup = Database(replacement_path)
    replacement_setup.execute("UPDATE unrelated_state SET value='replacement' WHERE id='sentinel'")
    replacement_setup.close()

    real_connect = sqlite3.connect

    def replacing_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        original_parent.rename(tmp_path / "detached-original")
        replacement_parent.rename(original_parent)
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(retrieval_reattest.sqlite3, "connect", replacing_connect)
    with pytest.raises(RuntimeError, match="identity or mode differs"):
        open_existing_retrieval_reattest_database(original_path)


def test_reattest_cli_bypasses_general_catalogue_initialisation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "catalog.sqlite3"
    path.write_bytes(b"existing")
    path.chmod(0o600)
    fake_settings = SimpleNamespace(
        database_path=path,
        host="127.0.0.1",
        port=8000,
        ensure_runtime_dirs=lambda: pytest.fail("general runtime setup must not run"),
    )
    calls: list[str] = []

    class FakeDatabase:
        def initialize(self) -> None:
            pytest.fail("general catalogue migration must not run")

        def close(self) -> None:
            calls.append("close")

    def fake_open(database_path: Path) -> FakeDatabase:
        assert database_path == path
        calls.append("open")
        return FakeDatabase()

    def fake_bootstrap(database: object) -> None:
        assert isinstance(database, FakeDatabase)
        calls.append("bootstrap")

    closure_path = tmp_path / "scorer-closure.json"

    def fake_reattest(
        settings: object,
        database: object,
        *,
        build_id: str,
        scorer_closure_manifest_path: Path,
    ) -> dict[str, object]:
        assert settings is fake_settings
        assert isinstance(database, FakeDatabase)
        assert build_id == "sealed-candidate"
        assert scorer_closure_manifest_path == closure_path
        calls.append("reattest")
        return {"build_id": build_id, "active_written": False}

    monkeypatch.setattr(cli, "settings", fake_settings)
    monkeypatch.setattr(
        cli,
        "Database",
        lambda _: pytest.fail("ordinary Database must not open re-attestation"),
    )
    monkeypatch.setattr(retrieval_reattest, "open_existing_retrieval_reattest_database", fake_open)
    monkeypatch.setattr(retrieval_reattest, "initialize_retrieval_reattest_schema", fake_bootstrap)
    monkeypatch.setattr(retrieval_reattest, "reattest_retrieval_v1", fake_reattest)

    cli.main(
        [
            "reattest-index",
            "sealed-candidate",
            "--scorer-closure-manifest",
            str(closure_path),
        ]
    )

    assert calls == ["open", "bootstrap", "reattest", "close"]
    assert '"active_written": false' in capsys.readouterr().out


def test_reattest_cli_requires_an_existing_non_symlink_catalogue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = tmp_path / "missing.sqlite3"
    target = tmp_path / "target.sqlite3"
    target.write_bytes(b"existing")
    symlink = tmp_path / "catalog-symlink.sqlite3"
    symlink.symlink_to(target)
    monkeypatch.setattr(
        cli,
        "Database",
        lambda _: pytest.fail("a missing catalogue must not be created"),
    )
    monkeypatch.setattr(
        retrieval_reattest,
        "open_existing_retrieval_reattest_database",
        lambda _: pytest.fail("an unsafe catalogue must not be opened"),
    )

    for unsafe in (missing, symlink):
        fake_settings = SimpleNamespace(
            database_path=unsafe,
            host="127.0.0.1",
            port=8000,
        )
        monkeypatch.setattr(cli, "settings", fake_settings)
        with pytest.raises(SystemExit, match="requires the existing local catalogue"):
            cli.main(
                [
                    "reattest-index",
                    "sealed-candidate",
                    "--scorer-closure-manifest",
                    str(tmp_path / "closure.json"),
                ]
            )
