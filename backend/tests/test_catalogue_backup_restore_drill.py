from __future__ import annotations

import importlib.util
import sqlite3
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/create_catalogue_backup_restore_drill.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("catalogue_backup_restore_drill", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_logical_state_and_restore_integrity_match(tmp_path: Path) -> None:
    module = _load_script()
    database = tmp_path / "catalog.sqlite3"
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        PRAGMA foreign_keys=ON;
        CREATE TABLE parent (id INTEGER PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE child (
          id INTEGER PRIMARY KEY,
          parent_id INTEGER NOT NULL REFERENCES parent(id)
        );
        INSERT INTO parent(value) VALUES ('sealed');
        INSERT INTO child(parent_id) VALUES (1);
        """
    )
    connection.commit()
    source_state = module._logical_state(connection)
    backup_path = tmp_path / "backup.sqlite3"
    module._create_sqlite_backup(connection, backup_path)
    connection.close()

    restored = sqlite3.connect(f"file:{backup_path}?mode=ro&immutable=1", uri=True)
    assert module._logical_state(restored) == source_state
    assert module._integrity(restored) == ("ok", 0)
    restored.close()


def test_receipt_is_explicitly_non_authorizing() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert '"authorizing": False' in source
    assert '"phase2b_authorized": False' in source
    assert '"promotion_authorized": False' in source
    assert '"live_authorized": False' in source
    assert '"third_source_copy_prohibited_by_repeated_failure_stop_policy": True' in source
