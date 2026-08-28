from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import date
from pathlib import Path
from shutil import copytree

import pytest

from app.config import Settings
from app.db import Database
from app.evaluation.live_suite import load_live_evaluation_bundle, sealed_sha256
from app.evaluation.live_suite_contrary_authority import (
    CONTRARY_REVIEW_SCHEMA,
    contrary_review_template,
    load_contrary_authority_review,
)
from app.evaluation.live_suite_owner_decision_contract import (
    OWNER_DECISION_IDS,
    OWNER_DECISIONS_SCHEMA,
    load_owner_decisions,
    owner_decision_template,
)
from app.evaluation.live_suite_owner_decisions import (
    build_active_promotion_status,
    export_owner_decision_artifacts,
)
from app.readiness import build_readiness_report

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_owner_decision_template_lists_d1_to_d15_and_is_unsigned() -> None:
    payload = owner_decision_template(as_of_date="2026-08-16")
    assert payload["schema"] == OWNER_DECISIONS_SCHEMA
    assert payload["unsigned"] is True
    assert payload["ai_self_authored"] is False
    assert payload["writes_active"] is False
    assert payload["writes_o04"] is False
    assert tuple(item["id"] for item in payload["decisions"]) == OWNER_DECISION_IDS
    later = {item["id"] for item in payload["decisions"] if item["later_owner_action"]}
    assert later == {"D-06", "D-07", "D-08", "D-09"}
    with pytest.raises(ValueError, match="missing"):
        load_owner_decisions(Path("/tmp/legalbot-missing-owner-decisions.json"))


def test_owner_decisions_loader_rejects_self_authored(tmp_path: Path) -> None:
    template = owner_decision_template(as_of_date="2026-08-16")
    decisions = []
    for item in template["decisions"]:
        state = "deferred_later_owner_action" if item["later_owner_action"] else "pending"
        decisions.append({**item, "state": state})
    payload = {
        **{key: value for key, value in template.items() if key not in {"unsigned", "seal_sha256"}},
        "owner_authored": True,
        "ai_self_authored": True,
        "suite_registry_canonical_sha256": "a" * 64,
        "run_plan_sha256": "b" * 64,
        "index_build_id": "candidate-test-v1",
        "run_id": "live60-d1-d15-test",
        "decisions": decisions,
    }
    payload["seal_sha256"] = sealed_sha256(payload)
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="self-author"):
        load_owner_decisions(path)
    payload["ai_self_authored"] = False
    payload["seal_sha256"] = sealed_sha256(payload)
    path.write_text(json.dumps(payload), encoding="utf-8")
    loaded = load_owner_decisions(path)
    assert loaded.owner_authored is True
    assert loaded.ai_self_authored is False


def test_contrary_none_does_not_mean_english_law_has_none() -> None:
    payload = contrary_review_template(as_of_date="2026-08-16")
    assert payload["schema"] == CONTRARY_REVIEW_SCHEMA
    assert payload["means_english_law_has_no_contrary_authority"] is False
    assert payload["critical_or_disputed_requires_independent_second_review"] is True
    assert payload["status"] == "unsigned"


def test_contrary_loader_rejects_english_law_has_none_claim(tmp_path: Path) -> None:
    payload = {
        "schema": CONTRARY_REVIEW_SCHEMA,
        "suite_id": "live-evaluation-60-v1",
        "as_of_date": "2026-08-16",
        "suite_registry_canonical_sha256": "a" * 64,
        "run_plan_sha256": "b" * 64,
        "index_build_id": "candidate-test-v1",
        "run_id": "live60-d1-d15-test",
        "owner_authored": True,
        "ai_self_authored": False,
        "status": "reviewed_none_in_defined_source_set",
        "defined_source_set_id": "live60-defined-source-set-v1",
        "defined_source_set_review_method": "owner_manual_named_source_set",
        "defined_source_set_reviewed_as_of_date": "2026-08-16",
        "reviewer_scope": "owner_primary_defined_source_set",
        "means_english_law_has_no_contrary_authority": True,
        "critical_or_disputed_requires_independent_second_review": True,
        "bound_contrary_span_count": 0,
        "independent_second_review_status": "needs_independent_review",
    }
    payload["seal_sha256"] = sealed_sha256(payload)
    path = tmp_path / "contrary.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="English law"):
        load_contrary_authority_review(path)
    payload["means_english_law_has_no_contrary_authority"] = False
    payload["seal_sha256"] = sealed_sha256(payload)
    path.write_text(json.dumps(payload), encoding="utf-8")
    loaded = load_contrary_authority_review(path)
    assert loaded.status == "reviewed_none_in_defined_source_set"
    assert loaded.means_english_law_has_no_contrary_authority is False


def test_active_status_invalid_or_tampered_and_never_writes(tmp_path: Path) -> None:
    active = tmp_path / "data" / "indexes" / "ACTIVE.json"
    active.parent.mkdir(parents=True)
    active.write_text("{not-json", encoding="utf-8")
    status = build_active_promotion_status(tmp_path)
    assert status["status"] == "invalid_or_tampered"
    assert status["promoted"] is False
    assert status["writes_active"] is False
    assert active.read_text(encoding="utf-8") == "{not-json"


def test_active_status_candidate_unpromoted(tmp_path: Path) -> None:
    catalog = tmp_path / "data" / "catalog.sqlite3"
    catalog.parent.mkdir(parents=True)
    connection = sqlite3.connect(catalog)
    connection.execute("CREATE TABLE index_builds (id TEXT, status TEXT, promoted_at TEXT)")
    connection.execute("INSERT INTO index_builds VALUES ('candidate-1', 'candidate', NULL)")
    connection.commit()
    connection.close()
    status = build_active_promotion_status(tmp_path)
    assert status["status"] == "candidate_unpromoted"
    assert status["promoted"] is False
    assert not (tmp_path / "data" / "indexes" / "ACTIVE.json").exists()


def test_active_status_reconciled_when_pointer_matches_catalogue(tmp_path: Path) -> None:
    index_dir = tmp_path / "data" / "indexes"
    build_dir = index_dir / "builds" / "build-1"
    build_dir.mkdir(parents=True)
    manifest = {"schema": "legalbot.lance-build.v1", "build_id": "build-1", "sealed": True}
    raw = (json.dumps(manifest, sort_keys=True) + "\n").encode()
    (build_dir / "manifest.json").write_bytes(raw)
    pointer = {
        "build_id": "build-1",
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "promoted_at": "2026-08-16T00:00:00+00:00",
    }
    (index_dir / "ACTIVE.json").write_text(json.dumps(pointer), encoding="utf-8")
    catalog = tmp_path / "data" / "catalog.sqlite3"
    connection = sqlite3.connect(catalog)
    connection.execute("CREATE TABLE index_builds (id TEXT, status TEXT, promoted_at TEXT)")
    connection.execute(
        "INSERT INTO index_builds VALUES ('build-1', 'active', '2026-08-16T00:00:00+00:00')"
    )
    connection.commit()
    connection.close()
    status = build_active_promotion_status(tmp_path)
    assert status["status"] == "active_reconciled"
    assert status["promoted"] is True
    assert status["writes_active"] is False


def test_export_status_readiness_verify_cannot_create_active(tmp_path: Path) -> None:
    project = tmp_path / "project"
    (project / "benchmarks" / "evaluation").mkdir(parents=True)
    copytree(
        PROJECT_ROOT / "benchmarks" / "evaluation" / "live-evaluation-60-v1",
        project / "benchmarks" / "evaluation" / "live-evaluation-60-v1",
    )
    copytree(
        PROJECT_ROOT / "benchmarks" / "evaluation" / "live-evaluation-30-v1",
        project / "benchmarks" / "evaluation" / "live-evaluation-30-v1",
    )
    export_owner_decision_artifacts(
        project_root=project,
        as_of_date=date(2026, 8, 16),
        catalog_path=tmp_path / "missing.sqlite3",
        fetch_official=None,
        copy_desktop=False,
    )
    build_active_promotion_status(project)
    settings = Settings(project_root=project, test_mode=True)
    database = Database(project / "data" / "catalog.sqlite3")
    database.initialize()
    build_readiness_report(settings, database)
    database.close()
    load_live_evaluation_bundle(project / "benchmarks" / "evaluation" / "live-evaluation-60-v1")
    assert not (project / "data" / "indexes" / "ACTIVE.json").exists()
    unsigned = json.loads(
        (
            project / "Live60-2026-08-16" / "artifacts" / "owner-decisions-d1-d15-unsigned.json"
        ).read_text()
    )
    assert unsigned["unsigned"] is True
    assert len(unsigned["decisions"]) == 15
