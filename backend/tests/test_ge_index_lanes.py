from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from test_resumable_index_embedding import _queued_build

from app.db import Database
from app.retrieval.embedding_progress import build_checkpoint, load_checkpoint, save_checkpoint
from app.retrieval.incomplete_index_audit import GE_SELECTION_POLICY
from app.retrieval.index_recovery import (
    _actual_checkpoint_reconciliation,
    _persisted_lease_loss_failure_fingerprint,
    resume_ge_lease_lost_index_build,
)
from app.retrieval.models import VECTOR_DIMENSIONS


def _sealed_audit_report(
    settings, build_id: str, source_manifest_sha256: str
) -> dict[str, object]:
    staging = settings.index_dir / "builds" / f".{build_id}.incomplete"
    save_checkpoint(
        staging,
        build_checkpoint(
            build_id=build_id,
            source_manifest_sha256=source_manifest_sha256,
            ordered_chunk_stream_sha256="b" * 64,
            parser_version="parser",
            chunker_version="chunker",
            index_schema_version="schema",
            embedding_model="embed",
            dtype="float16",
            vector_dimensions=VECTOR_DIMENSIONS,
            batch_size=8,
            policy_sha256="2" * 64,
            assessment_bundle_sha256="3" * 64,
            provision_verification_sha256="4" * 64,
            completed_row_count=2,
            last_deterministic_chunk_key="source\t1\tchunk",
            rolling_digest="c" * 64,
            physical_lane_counts={"authority": 2},
        ),
    )
    checkpoint = load_checkpoint(staging)
    assert checkpoint is not None
    report: dict[str, object] = {
        "schema": "legalbot.incomplete-index-audit.v1",
        "build_id": build_id,
        "source_manifest_match": True,
        "source_version_id_binding_match": True,
        "source_lane_binding_match": True,
        "exact_ordered_prefix": True,
        "checkpoint_prefix_match": True,
        "checkpoint_reconciliation_required": False,
        "observed_total_rows": 2,
        "ordered_prefix_verified_row_count": 2,
        "ordered_prefix_rolling_digest": "c" * 64,
        "ordered_prefix_last_deterministic_chunk_key": "source\t1\tchunk",
        "source_manifest_sha256": source_manifest_sha256,
        "checkpoint": {
            "present": True,
            "completed_row_count": 2,
            "checkpoint_sha256": checkpoint.checkpoint_sha256,
            "last_deterministic_chunk_key": "source\t1\tchunk",
        },
    }
    encoded = json.dumps(
        report,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    report["report_sha256"] = hashlib.sha256(encoded).hexdigest()
    return report


def test_ge_lease_loss_stops_before_attempt_three_on_same_persisted_failure(
    database: Database, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.retrieval import index_recovery as recovery_module

    build_id = "ge-lease-loss-retry-cap"
    settings, queued = _queued_build(
        database,
        tmp_path,
        build_id=build_id,
        skip_embedding=False,
    )
    decision_id = "decision-ge-retry-cap"
    decision_content_sha256 = "e" * 64
    job = database.job(str(queued["job_id"]))
    assert job is not None
    request = json.loads(str(job["request_json"]))
    request.update(
        {
            "selection_policy": GE_SELECTION_POLICY,
            "ge_index_build_owner_decision_id": decision_id,
            "ge_index_build_owner_decision_content_sha256": decision_content_sha256,
            "successor_must_remain_non_active": True,
        }
    )
    database.execute(
        "UPDATE jobs SET request_json=? WHERE id=?",
        (json.dumps(request, sort_keys=True), str(queued["job_id"])),
    )
    monkeypatch.setattr(
        recovery_module,
        "_verify_ge_recovery_authorization",
        lambda *_args, **_kwargs: (request, build_id),
    )
    report = _sealed_audit_report(
        settings, build_id, str(queued["source_manifest_hash"])
    )
    reconciliation = _actual_checkpoint_reconciliation(report, expected_build_id=build_id)
    monkeypatch.setattr(recovery_module, "audit_incomplete_index", lambda *_args: report)

    first_worker = "ge-retry-first-worker"
    first = database.claim_next_job(first_worker, job_types=("index_build",))
    assert first is not None and int(first["attempt_count"]) == 1
    assert database.terminalize_owned_index_execution(
        str(queued["job_id"]),
        first_worker,
        reason_code="lease_lost",
        message="Injected first GE lease loss",
    )
    resumed = resume_ge_lease_lost_index_build(
        settings,
        database,
        str(queued["job_id"]),
        decision_id=decision_id,
        decision_content_sha256=decision_content_sha256,
        expected_build_id=build_id,
        expected_attempt_count=1,
        expected_audit_report_sha256=str(report["report_sha256"]),
        expected_checkpoint_reconciliation_sha256=str(
            reconciliation["reconciliation_sha256"]
        ),
    )
    assert resumed["failure_fingerprint_sha256"]

    second_worker = "ge-retry-second-worker"
    second = database.claim_next_job(second_worker, job_types=("index_build",))
    assert second is not None and int(second["attempt_count"]) == 2
    assert database.terminalize_owned_index_execution(
        str(queued["job_id"]),
        second_worker,
        reason_code="lease_lost",
        message="Injected unchanged second GE lease loss",
    )
    with database.transaction() as connection:
        persisted_job = connection.execute(
            "SELECT * FROM jobs WHERE id=?", (str(queued["job_id"]),)
        ).fetchone()
        persisted_build = connection.execute(
            "SELECT * FROM index_builds WHERE id=?", (build_id,)
        ).fetchone()
        assert persisted_job is not None and persisted_build is not None
        _, second_failure_fingerprint = _persisted_lease_loss_failure_fingerprint(
            connection,
            job=persisted_job,
            build=persisted_build,
            job_id=str(queued["job_id"]),
            build_id=build_id,
        )
    assert second_failure_fingerprint == resumed["failure_fingerprint_sha256"]
    job_before = dict(database.job(str(queued["job_id"])))
    build_before = dict(
        database.fetchone("SELECT * FROM index_builds WHERE id=?", (build_id,))
    )
    event_count_before = len(database.job_events(str(queued["job_id"])))
    active_before = (
        settings.index_dir / "ACTIVE.json"
    ).read_bytes() if (settings.index_dir / "ACTIVE.json").exists() else None
    previous_before = (
        settings.index_dir / "PREVIOUS.json"
    ).read_bytes() if (settings.index_dir / "PREVIOUS.json").exists() else None

    with pytest.raises(RuntimeError, match="unchanged_ge_lease_loss_recovery_attempt_limit"):
        resume_ge_lease_lost_index_build(
            settings,
            database,
            str(queued["job_id"]),
            decision_id=decision_id,
            decision_content_sha256=decision_content_sha256,
            expected_build_id=build_id,
            # A caller-supplied lower count cannot bypass the persisted attempt-2 stop.
            expected_attempt_count=1,
            expected_audit_report_sha256=str(report["report_sha256"]),
            expected_checkpoint_reconciliation_sha256=str(
                reconciliation["reconciliation_sha256"]
            ),
        )

    assert dict(database.job(str(queued["job_id"]))) == job_before
    assert dict(database.fetchone("SELECT * FROM index_builds WHERE id=?", (build_id,))) == (
        build_before
    )
    assert len(database.job_events(str(queued["job_id"]))) == event_count_before
    assert (
        (settings.index_dir / "ACTIVE.json").read_bytes()
        if (settings.index_dir / "ACTIVE.json").exists()
        else None
    ) == active_before
    assert (
        (settings.index_dir / "PREVIOUS.json").read_bytes()
        if (settings.index_dir / "PREVIOUS.json").exists()
        else None
    ) == previous_before
