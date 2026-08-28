from __future__ import annotations

from pathlib import Path

from app.config import Settings
from app.ingestion.service import ingest_explicit_paths, scan_configured_sources


def test_ingest_explicit_paths_accounts_new_file_inside_configured_root(
    tmp_path: Path, database, cipher, monkeypatch
) -> None:
    law = tmp_path / "Law" / "Official Legislation"
    law.mkdir(parents=True)
    first = law / "held.md"
    first.write_text("# Held\n\nA provision.", encoding="utf-8")
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(tmp_path / "Law"))
    settings = Settings(project_root=tmp_path, test_mode=True)
    scan_configured_sources(settings, database, cipher, "explicit-seed")

    added = law / "acquired.md"
    added.write_text("# Acquired\n\nSection 1 says a later proposition.", encoding="utf-8")
    result = ingest_explicit_paths(settings, database, cipher, "explicit-new", [added])
    assert result["ingested"] == 1
    assert result["items"][0]["status"] == "citable"
    assert result["items"][0]["content_sha256"]
    assert result["wrote_active"] is False
    assert database.fetchone("SELECT COUNT(*) AS n FROM documents")["n"] == 2


def test_ingest_explicit_paths_rejects_outside_configured_roots(
    tmp_path: Path, database, cipher, monkeypatch
) -> None:
    law = tmp_path / "Law"
    law.mkdir()
    outsider = tmp_path / "elsewhere.md"
    outsider.write_text("# Outside", encoding="utf-8")
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(law))
    settings = Settings(project_root=tmp_path, test_mode=True)
    result = ingest_explicit_paths(settings, database, cipher, "explicit-outside", [outsider])
    assert result["ingested"] == 0
    assert result["items"][0]["reason"] == "path_outside_configured_source_roots"
