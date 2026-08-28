from __future__ import annotations

import json
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import httpx
import pytest

from app.api.main import app
from app.config import Settings
from app.observability.events import (
    EventStore,
    LogWriteError,
    public_event_view,
    record_index_stage_failure,
)
from app.retrieval.index_build import (
    INDEX_BUILD_STAGES,
    IndexBuildRunner,
    IndexBuildStageError,
    enqueue_index_build,
)
from app.retrieval.service import promote_candidate_index, rollback_active_index
from app.types import IndexBuildStage


def _write_packs(project: Path, *, uksc_items: list[dict] | None = None) -> None:
    (project / "config").mkdir(parents=True, exist_ok=True)
    (project / "config" / "official_legislation_pack.json").write_text(
        json.dumps(
            {
                "schema": "legalbot.official-legislation-pack.v1",
                "version": "test",
                "licence": {"name": "Open Government Licence", "version": "3.0", "url": "x"},
                "items": [{"identity": "ukpga/1977/50", "title": "Unfair Contract Terms Act 1977"}],
            }
        ),
        encoding="utf-8",
    )
    (project / "config" / "uksc_authority_pack.json").write_text(
        json.dumps(
            {
                "schema": "legalbot.uksc-authority-pack.v1",
                "version": "test",
                "licence": {"name": "Open Government Licence", "version": "3.0"},
                "items": uksc_items if uksc_items is not None else [],
            }
        ),
        encoding="utf-8",
    )


def _seed_authority(database, tmp_path: Path, *, n_chunks: int = 2) -> None:
    now = "2026-08-13T00:00:00+00:00"
    rel = "data/vault/source.md"
    (tmp_path / "data" / "vault").mkdir(parents=True, exist_ok=True)
    (tmp_path / rel).write_text("# Unfair Contract Terms Act 1977\n\nSection 2.", encoding="utf-8")
    database.execute(
        """
        INSERT INTO documents(
          id, content_sha256, source_identity_id, safe_display_name, media_type,
          status, lane, subject_primary, jurisdiction, retrieval_canonical,
          created_at, updated_at
        ) VALUES ('doc-ucta', ?, 'ukpga:1977:50', 'source-ucta.pdf', 'application/pdf',
                  'citable', 'primary_authority', 'contract', 'England and Wales', 1, ?, ?)
        """,
        ("a" * 64, now, now),
    )
    database.execute(
        """
        INSERT INTO source_versions(
          id, document_id, version_sha256, canonical_markdown_path, title,
          stable_identifier, currentness_status, licence_name, review_status,
          metadata_json, created_at
        ) VALUES ('sv-ucta', 'doc-ucta', ?, ?, 'Unfair Contract Terms Act 1977',
                  'ukpga:1977:50:enacted', 'historical', 'Open Government Licence v3.0',
                  'approved', ?, ?)
        """,
        (
            "a" * 64,
            rel,
            json.dumps(
                {
                    "eligible_for_model_use": True,
                    "ai_use_policy": "unreviewed",
                    "identity_verified": True,
                    "currentness_verified": False,
                    "citation_data": {"source_type": "legislation"},
                }
            ),
            now,
        ),
    )
    for index in range(n_chunks):
        database.execute(
            """
            INSERT INTO chunks(
              id, source_version_id, ordinal, locator, text_sha256, markdown_text,
              token_count, stream
            ) VALUES (?, 'sv-ucta', ?, 's 2', ?,
                      'Section 2 restricts exclusion of negligence liability.', 12, 'body')
            """,
            (f"chunk-{index}", index, "c" * 64),
        )


def _settings(tmp_path: Path) -> Settings:
    return Settings(project_root=tmp_path, test_mode=True)


def _store(database, tmp_path: Path) -> EventStore:
    return EventStore(database, tmp_path / "logs")


@pytest.mark.asyncio
async def test_admin_failure_and_evaluation_feeds_expose_only_safe_fields(
    database, tmp_path: Path
) -> None:
    store = _store(database, tmp_path)
    store.emit(
        event_type="operational_failure",
        component="worker",
        stage="drafting",
        failure_code="model_timeout",
        source_id="job-safe-feed",
        job_id="job-safe-feed",
        user_or_owner_safe="The drafting stage timed out.",
        internal_detail="/Users/private-owner/secret/model.log api_key=secret",
        retryable=True,
        blocking=True,
    )
    database.create_evaluation_issue(
        issue_id="issue-safe-feed",
        run_id=None,
        case_id="case-001",
        job_id=None,
        category="citation_error",
        severity="high",
        affected_layer="citation",
        expected_ids=["source:expected"],
        observed_ids=["source:observed"],
        encrypted_note=b"encrypted-owner-note",
    )

    previous = getattr(app.state, "services", None)
    app.state.services = SimpleNamespace(database=database)
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 4321))
    try:
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8777"
        ) as client:
            failures = await client.get("/api/v1/admin/failures")
            issues = await client.get("/api/v1/admin/evaluation-issues")
        assert failures.status_code == 200
        failure = failures.json()["items"][0]
        assert failure["user_or_owner_safe"] == "The drafting stage timed out."
        assert "internal_detail" not in failure
        assert "/Users/" not in json.dumps(failure)
        assert issues.status_code == 200
        issue = issues.json()["items"][0]
        assert issue["expected_ids"] == ["source:expected"]
        assert issue["observed_ids"] == ["source:observed"]
        assert "encrypted_human_note" not in issue
    finally:
        if previous is None:
            del app.state.services
        else:
            app.state.services = previous


def test_every_failed_index_build_stage_creates_a_failure_record(database, tmp_path) -> None:
    project = tmp_path / "project"
    _write_packs(project)
    _seed_authority(database, project)
    settings = _settings(project)
    runner = IndexBuildRunner(settings, database)
    failed_stages = [stage for stage in INDEX_BUILD_STAGES if stage != IndexBuildStage.CANDIDATE]
    for stage in failed_stages:
        build_id = f"fail-{stage.replace('_', '')[:12]}"
        queued = enqueue_index_build(
            settings,
            database,
            corpus_id=f"test-corpus-{stage}",
            build_id=build_id,
            fail_at_stage=stage,
            skip_embedding=True,
        )
        with pytest.raises(IndexBuildStageError):
            runner.run_sync(queued["job_id"])
        row = database.fetchone("SELECT status FROM index_builds WHERE id=?", (build_id,))
        assert row is not None and row["status"] == "failed"
        assert not (settings.index_dir / "ACTIVE.json").exists()
    store = EventStore.from_settings(settings, database)
    ledger = store.ledger_rows()
    stages_logged = {str(row["stage"]) for row in ledger}
    for stage in failed_stages:
        assert stage in stages_logged
    for extra in ("PROMOTION", "ROLLBACK"):
        record_index_stage_failure(
            store,
            stage=extra,
            reason_code="promotion_atomicity_failure"
            if extra == "PROMOTION"
            else "rollback_atomicity_failure",
            message=f"{extra} failed closed without writing ACTIVE.json.",
            build_id=f"pointer-{extra.lower()}",
            retryable=False,
            blocking=True,
        )
    stages_logged = {str(row["stage"]) for row in store.ledger_rows()}
    assert "PROMOTION" in stages_logged
    assert "ROLLBACK" in stages_logged
    assert not (settings.index_dir / "ACTIVE.json").exists()


def test_retries_link_to_the_original_failure(database, tmp_path) -> None:
    store = _store(database, tmp_path)
    original = store.emit(
        event_type="operational_failure",
        component="worker",
        stage="index_build",
        failure_code="crash",
        source_id="job-retry",
        job_id="job-retry",
        user_or_owner_safe="A worker crash was recorded.",
        retryable=True,
        blocking=True,
    )
    retry = store.schedule_retry(
        original["failure_id"],
        component="worker",
        stage="index_build",
        failure_code="crash",
        job_id="job-retry",
    )
    assert retry["parent_failure_id"] == original["failure_id"]
    assert retry["failure_id"] == original["failure_id"]
    ledger = store.ledger(original["failure_id"])
    assert ledger is not None
    assert ledger["state"] == "retrying"


def test_recovered_failures_are_closed(database, tmp_path) -> None:
    store = _store(database, tmp_path)
    original = store.emit(
        event_type="operational_failure",
        component="worker",
        stage="index_build",
        failure_code="timeout",
        source_id="job-recover",
        job_id="job-recover",
        user_or_owner_safe="A timeout was recorded.",
        retryable=True,
        blocking=True,
    )
    store.recover(original["failure_id"], component="worker", job_id="job-recover")
    ledger = store.ledger(original["failure_id"])
    assert ledger is not None
    assert ledger["state"] == "recovered"
    assert ledger["closed_at"]


def test_exhausted_failures_enter_terminal_dlq(database, tmp_path) -> None:
    store = _store(database, tmp_path)
    original = store.emit(
        event_type="operational_failure",
        component="worker",
        stage="index_build",
        failure_code="crash",
        source_id="job-dlq",
        job_id="job-dlq",
        user_or_owner_safe="A crash was recorded.",
        retryable=True,
        blocking=True,
    )
    store.exhaust(original["failure_id"], component="worker", dlq=True, job_id="job-dlq")
    ledger = store.ledger(original["failure_id"])
    assert ledger is not None
    assert ledger["state"] == "terminal"
    types = {event["event_type"] for event in store.events()}
    assert "terminal_failure" in types
    assert "dlq_transition" in types


def test_partial_source_family_truncation_cannot_become_candidate(database, tmp_path) -> None:
    project = tmp_path / "project"
    _write_packs(
        project,
        uksc_items=[
            {
                "neutral_citation": "[2020] UKSC 1",
                "case_name": "Example v Example",
            }
        ],
    )
    _seed_authority(database, project)
    settings = _settings(project)
    queued = enqueue_index_build(
        settings,
        database,
        corpus_id="test-corpus",
        build_id="cap-uksc",
        max_chunks=2,
        skip_embedding=True,
    )
    with pytest.raises(IndexBuildStageError):
        IndexBuildRunner(settings, database).run_sync(queued["job_id"])
    build = database.fetchone("SELECT * FROM index_builds WHERE id='cap-uksc'")
    assert build is not None
    assert build["status"] == "failed"
    assert build["stage"] != IndexBuildStage.CANDIDATE
    store = EventStore.from_settings(settings, database)
    codes = {str(row["failure_code"]) for row in store.ledger_rows()}
    assert "required_source_family_truncated" in codes
    assert not (settings.index_dir / "ACTIVE.json").exists()


def test_no_secret_or_absolute_path_in_public_safe_logs(database, tmp_path) -> None:
    store = _store(database, tmp_path)
    event = store.emit(
        event_type="privacy_failure",
        component="quality",
        stage="privacy",
        failure_code="privacy",
        source_id="job-privacy",
        job_id="job-privacy",
        user_or_owner_safe=(
            "Leak from /Users/hltsang/Desktop/secret.pdf; requested_secret=super-secret-token"
        ),
        internal_detail="C:\\Users\\hltsang\\private\\key.pem api_key=abcd",
        context={"requested_secret": "super-secret-token", "system_prompt": "never store"},
    )
    view = public_event_view(event)
    encoded = json.dumps(view)
    assert "/Users/" not in encoded
    assert "C:\\Users" not in encoded
    assert "super-secret-token" not in encoded
    assert "never store" not in encoded
    assert "[LOCAL_PATH]" in event["user_or_owner_safe"]
    assert "requested_secret=[REDACTED]" in event["user_or_owner_safe"]
    assert "internal_detail" not in view
    jsonl = (tmp_path / "logs" / "operational-events.jsonl").read_text(encoding="utf-8")
    assert "/Users/" not in jsonl
    assert "super-secret-token" not in jsonl
    assert "system_prompt" not in jsonl
    assert stat.S_IMODE((tmp_path / "logs").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "logs" / "operational-events.jsonl").stat().st_mode) == 0o600


def test_normal_observability_never_persists_debug_or_legal_prose(database, tmp_path) -> None:
    store = _store(database, tmp_path)
    sensitive_detail = "The claimant's private question and a copied judgment paragraph."
    event = store.emit(
        event_type="operational_failure",
        component="worker",
        stage="drafting",
        failure_code="model_error",
        source_id="/Users/private-owner/source.pdf",
        user_or_owner_safe="Drafting failed with a recorded diagnostic digest.",
        internal_detail=sensitive_detail,
        context={
            "answer_text": "never persist this answer",
            "source_excerpt": "never persist this authority text",
            "attempt": 2,
            "owner_reason": "private owner reasoning",
        },
    )

    assert event["internal_detail"].startswith("detail-sha256:")
    assert event["source_id"].startswith("id-sha256:")
    assert event["context"]["attempt"] == 2
    assert len(event["context"]["owner_reason_sha256"]) == 64
    assert "answer_text" not in event["context"]
    assert "source_excerpt" not in event["context"]
    row = database.fetchone(
        "SELECT internal_detail,context_json FROM operational_events WHERE event_id=?",
        (event["event_id"],),
    )
    assert row is not None
    persisted = f"{row['internal_detail']}\n{row['context_json']}\n" + (
        tmp_path / "logs" / "operational-events.jsonl"
    ).read_text(encoding="utf-8")
    assert sensitive_detail not in persisted
    assert "never persist this answer" not in persisted
    assert "never persist this authority text" not in persisted
    assert "private owner reasoning" not in persisted


def test_repeated_failures_aggregate_without_losing_counts(database, tmp_path) -> None:
    store = _store(database, tmp_path)
    last = None
    for _ in range(3):
        last = store.emit(
            event_type="data_quality_failure",
            component="index_build",
            stage="validating",
            failure_code="chunk_embedding_count_mismatch",
            source_id="build-agg",
            build_id="build-agg",
            user_or_owner_safe="Chunk and embedding counts do not match.",
            retryable=False,
            blocking=True,
        )
    assert last is not None
    assert last["occurrence_count"] == 3
    events = [
        item for item in store.events() if item["failure_code"] == "chunk_embedding_count_mismatch"
    ]
    assert len(events) == 1
    ledger = [row for row in store.ledger_rows() if row["fingerprint"] == last["fingerprint"]]
    assert len(ledger) == 1
    assert int(ledger[0]["occurrence_count"]) == 3


def test_policy_decisions_do_not_inflate_operational_failure_metrics(database, tmp_path) -> None:
    store = _store(database, tmp_path)
    before = store.operational_failure_count()
    for code in (
        "clarify",
        "refuse",
        "answer-safe-and-refuse-unsafe",
        "verified_limited:index_not_ready",
        "verified_limited:retrieval_zero_hits",
    ):
        store.emit(
            event_type="policy_decision",
            component="a2_policy",
            stage="behavior",
            failure_code=code,
            source_id=f"policy-{code}",
            user_or_owner_safe="A2 policy decision; not an operational failure.",
            open_ledger=False,
        )
    assert store.operational_failure_count() == before
    store.emit(
        event_type="operational_failure",
        component="worker",
        stage="answer",
        failure_code="crash",
        source_id="ops-one",
        user_or_owner_safe="A real operational failure.",
        retryable=True,
        blocking=True,
    )
    assert store.operational_failure_count() == before + 1


def test_logs_include_build_config_code_provenance(database, tmp_path) -> None:
    store = _store(database, tmp_path)
    event = store.emit(
        event_type="operational_failure",
        component="index_build",
        stage="validating",
        failure_code="integrity_failed",
        source_id="build-prov",
        build_id="build-prov",
        user_or_owner_safe="Integrity failed.",
        provenance={
            "source_manifest_hash": "ab" * 32,
            "embedding_model_version": "legalbot-test/hash-embedding-1024",
        },
        retryable=False,
        blocking=True,
    )
    provenance = event["provenance"]
    assert provenance["git_sha"]
    assert provenance["git_branch"]
    assert provenance["parser_version"]
    assert provenance["chunker_version"]
    assert provenance["index_schema_version"]
    assert provenance["source_manifest_hash"] == "ab" * 32
    assert "af36fcc" in provenance["git_sha"] or len(provenance["git_sha"]) >= 7


def test_log_writing_failure_does_not_silently_permit_promotion(database, tmp_path) -> None:
    settings = _settings(tmp_path / "project")
    settings.ensure_runtime_dirs()

    class BoomStore(EventStore):
        def require_writable(self, *, component: str, stage: str) -> dict:
            raise LogWriteError("observability jsonl is not writable")

    boom = BoomStore(database, tmp_path / "project" / "logs")
    with (
        pytest.raises(LogWriteError),
        patch("app.evaluation.owner_quality_v111_promotion.verify_v111_promotion_for_service"),
    ):
        promote_candidate_index(
            settings,
            database,
            "never-promoted",
            event_store=boom,
            v111_promotion_presentation=object(),
            v111_owner_authorization=object(),
        )
    assert not (settings.index_dir / "ACTIVE.json").exists()
    with pytest.raises(LogWriteError):
        rollback_active_index(settings, database, event_store=boom)
    assert not (settings.index_dir / "ACTIVE.json").exists()
    assert not (settings.index_dir / "PREVIOUS.json").exists()
