from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import Counter
from pathlib import Path

import pytest
from backend.app.config import Settings
from backend.app.db import Database
from backend.app.retrieval import phase2a_dynamic_scope as dynamic_scope
from scripts import apply_v111_phase2a_final_remediation as apply


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _initialised_connection(path: Path) -> sqlite3.Connection:
    database = Database(path)
    database.initialize()
    database.close()
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


def test_real_materialization_plan_is_exact_private_and_read_only() -> None:
    targets = (
        apply.MATERIALIZED_ROOT,
        apply.MATERIALIZATION_OUTPUT_ROOT,
        apply.POST_SCAN_OUTPUT_ROOT,
    )
    before = tuple((path.exists(), path.is_symlink()) for path in targets)
    plan = apply.build_materialization_plan()
    after = tuple((path.exists(), path.is_symlink()) for path in targets)

    assert before == after
    assert plan["artifact_content_sha256"] == (
        "de7b8e8c0d5d4a6e1f99f0f338d623bb7e371222b8c0341b35515fe1d1567c7b"
    )
    assert plan["status"] == "EXACT_OWNER_ADOPTED_MATERIALIZATION_READY_NOT_RUN"
    assert plan["representation_count"] == 254
    assert plan["index_eligible_representation_count"] == 250
    assert plan["provenance_companion_count"] == 4
    assert plan["prior_frozen_scope_source_count"] == 251
    assert plan["projected_successor_source_count"] == 501
    assert plan["retained_original_quarantine_hold_count"] == 31
    assert plan["retained_original_identity_admission_hold_count"] == 86
    assert len(plan["rejected_original_record_ids"]) == 16
    assert len(plan["retained_repair_hold_record_ids"]) == 2
    assert Counter(item["representation_kind"] for item in plan["representations"]) == {
        "ORIGINAL_AUDITED_PASS": 231,
        "FCA_CANONICAL_MARKDOWN": 15,
        "ECHR_CANONICAL_MARKDOWN": 4,
        "ECHR_RAW_PROVENANCE": 4,
    }
    assert len({item["content_sha256"] for item in plan["representations"]}) == 254
    assert len({item["target_relative_path"] for item in plan["representations"]}) == 254
    requirement = plan["support_crosswalk_requirement"]
    assert requirement["prior_evidence_ready_row_count"] == 224
    assert requirement["owner_remediation_decision_row_count"] == 361
    assert requirement["all585_row_count"] == 585
    assert requirement["regular_support_row_count"] == 583
    assert requirement["safe_fallback_row_count"] == 2
    assert requirement["support_resolution_run"] is False
    assert requirement["technical_success_predeclared"] is False
    assert requirement["required_success_conditions"] == {
        "material_gap_count": 0,
        "orphan_support_count": 0,
        "unresolved_owner_decision_count": 0,
    }
    rendered = json.dumps(plan, ensure_ascii=False, sort_keys=True)
    assert "/Users/" not in rendered
    assert "hltsang" not in rendered.casefold()
    assert "LegalBot-New" not in rendered
    assert plan["source_materialized"] is False
    assert plan["catalogue_mutated"] is False
    assert plan["source_scan_run"] is False
    assert plan["successor_build_run"] is False
    assert plan["embedding_run"] is False
    assert plan["active_pointer_written"] is False
    assert plan["previous_pointer_written"] is False


def test_original_crosslink_accepts_sealed_summary_fields_and_rejects_tamper() -> None:
    record = {
        "record_id": "record-one",
        "raw_sha256": "a" * 64,
        "record_content_sha256": "b" * 64,
        "selected_for_proposed_admission": True,
    }
    selected = {
        **record,
        "authority_representation_set_complete": True,
        "eligible_for_owner_packet": True,
    }
    proposal = {
        "proposal_content_sha256": "c" * 64,
        "quarantine_representation_binding": {"selected_admission_binding": selected},
    }
    decision = {
        "original_raw_sha256": "a" * 64,
        "original_record_content_sha256": "b" * 64,
        "original_proposal_content_sha256": "c" * 64,
        "audit_verdict": "PASS",
    }
    apply._verify_original_crosslink(
        decision=decision,
        record=record,
        proposal=proposal,
    )
    tampered = {**record, "raw_sha256": "d" * 64}
    with pytest.raises(ValueError, match="original_crosslink_invalid"):
        apply._verify_original_crosslink(
            decision=decision,
            record=tampered,
            proposal=proposal,
        )


def test_synthetic_materialization_is_create_only_and_runs_no_later_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root = tmp_path / "approved"
    source_root.mkdir()
    input_root = tmp_path / "inputs"
    input_root.mkdir()
    source_bytes = (b"canonical source", b"raw provenance")
    records = []
    for ordinal, raw in enumerate(source_bytes, start=1):
        member = f"input-{ordinal}.md"
        (input_root / member).write_bytes(raw)
        records.append(
            apply._seal_record(
                {
                    "ordinal": ordinal,
                    "input_artifact_root_name": "inputs",
                    "input_member": member,
                    "content_sha256": _sha256(raw),
                    "byte_size": len(raw),
                    "target_relative_path": f"Official Judgments/output-{ordinal}.md",
                    "index_eligible": ordinal == 1,
                    "provenance_only": ordinal == 2,
                }
            )
        )
    materialized_root = source_root / "final-r1"
    output_root = tmp_path / "evidence" / "materialized-r1"
    plan = {
        "schema": "test.plan.v1",
        "status": "EXACT_OWNER_ADOPTED_MATERIALIZATION_READY_NOT_RUN",
        "artifact_content_sha256": "1" * 64,
        "materialized_source_root_relative_path": "approved/final-r1",
        "representations": records,
        "source_materialized": False,
        "catalogue_mutated": False,
    }
    monkeypatch.setattr(apply, "SOURCE_ROOT", source_root)
    monkeypatch.setattr(apply, "EXPECTED_MATERIALIZED_REPRESENTATION_COUNT", 2)
    monkeypatch.setattr(apply, "EXPECTED_INDEX_REPRESENTATION_COUNT", 1)
    monkeypatch.setattr(apply, "EXPECTED_PROVENANCE_COMPANION_COUNT", 1)
    monkeypatch.setattr(apply, "build_materialization_plan", lambda: plan)
    monkeypatch.setattr(apply, "_input_roots", lambda: {"inputs": input_root})

    result = apply.materialize_exact_sources(
        output_root=output_root,
        materialized_root=materialized_root,
    )
    assert result["materialized_file_count"] == 2
    assert result["source_scan_run"] is False
    assert result["successor_build_run"] is False
    assert result["embedding_run"] is False
    assert result["phase2b_run"] is False
    assert (materialized_root / "Official Judgments/output-1.md").read_bytes() == source_bytes[0]
    assert (materialized_root / "Official Judgments/output-2.md").read_bytes() == source_bytes[1]
    ledger = json.loads((output_root / apply.MATERIALIZATION_LEDGER_NAME).read_text())
    assert ledger["catalogue_mutated"] is False
    assert ledger["active_pointer_written"] is False
    assert ledger["previous_pointer_written"] is False


def test_post_scan_ledger_passes_shared_dynamic_scope_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    settings = Settings(project_root=project, test_mode=True)
    connection = _initialised_connection(settings.database_path)
    now = "2026-08-28T00:00:00+00:00"
    connection.execute(
        """
        INSERT INTO source_scans(
          id,status,required_roots_json,roots_seen_json,expected_file_count,
          files_accounted,statuses_json,manifest_sha256,created_at,started_at,completed_at
        ) VALUES ('scan-one','complete','["root"]','["root"]',2,2,'{}',?,?,?,?)
        """,
        ("f" * 64, now, now, now),
    )
    representations = []
    for ordinal, index_eligible in ((1, True), (2, False)):
        document_id = f"document-{ordinal}"
        source_version_id = f"source-version-{ordinal}"
        digest = str(ordinal) * 64
        authority = f"neutral-citation:[2026] TEST {ordinal}"
        connection.execute(
            """
            INSERT INTO documents(
              id,content_sha256,source_identity_id,safe_display_name,media_type,
              status,lane,created_at,updated_at
            ) VALUES (?,?,?,?,?,'staged','quarantine',?,?)
            """,
            (
                document_id,
                digest,
                f"identity-{ordinal}",
                f"source-{ordinal}.md",
                "text/markdown",
                now,
                now,
            ),
        )
        connection.execute(
            """
            INSERT INTO source_versions(
              id,document_id,authority_identity_id,version_sha256,
              canonical_markdown_path,review_status,metadata_json,created_at
            ) VALUES (?,?,?,?,?,'staged','{}',?)
            """,
            (
                source_version_id,
                document_id,
                authority,
                digest,
                f"data/vault/{ordinal}.md",
                now,
            ),
        )
        if index_eligible:
            connection.execute(
                """
                INSERT INTO chunks(
                  id,source_version_id,ordinal,locator,text_sha256,markdown_text,
                  token_count,stream
                ) VALUES (?,?,0,'p 1',?,'support',1,'body')
                """,
                (f"chunk-{ordinal}", source_version_id, digest),
            )
        connection.execute(
            """
            INSERT INTO source_scan_files(
              scan_id,path_fingerprint,document_id,status,content_sha256
            ) VALUES ('scan-one',?,?,?,?)
            """,
            (f"path-{ordinal}", document_id, "ingested", digest),
        )
        representations.append(
            apply._seal_record(
                {
                    "ordinal": ordinal,
                    "owner_source_record_id": f"owner-source-{ordinal}",
                    "owner_decision_id": f"owner-decision-{ordinal}",
                    "authority_identity_id": authority,
                    "content_sha256": digest,
                    "index_eligible": index_eligible,
                    "provenance_only": not index_eligible,
                    "representation_kind": (
                        "ORIGINAL_AUDITED_PASS" if index_eligible else "ECHR_RAW_PROVENANCE"
                    ),
                }
            )
        )
    connection.commit()
    requirement = apply._support_crosswalk_requirement()
    materialization_ledger = {
        "artifact_content_sha256": "e" * 64,
        "representations": representations,
        "rejected_original_decision_ids": [],
        "rejected_original_record_ids": [],
        "retained_repair_hold_decision_ids": [],
        "retained_repair_hold_record_ids": [],
        "retained_original_quarantine_hold_count": 31,
        "retained_original_identity_admission_hold_count": 86,
        "support_crosswalk_requirement": requirement,
    }
    monkeypatch.setattr(apply, "EXPECTED_MATERIALIZED_REPRESENTATION_COUNT", 2)
    monkeypatch.setattr(apply, "EXPECTED_INDEX_REPRESENTATION_COUNT", 1)
    monkeypatch.setattr(apply, "EXPECTED_PROVENANCE_COMPANION_COUNT", 1)
    plan = apply.build_post_scan_plan(
        connection,
        materialization_ledger=materialization_ledger,
        scan_id="scan-one",
        scan_manifest_sha256="f" * 64,
    )
    assert plan["binding_count"] == 2
    assert plan["index_eligible_binding_count"] == 1
    assert plan["provenance_binding_count"] == 1
    assert plan["bindings"] == [
        {
            **plan["bindings"][0],
            "source_version_id": "source-version-1",
            "document_id": "document-1",
        },
        {
            **plan["bindings"][1],
            "source_version_id": "source-version-2",
            "document_id": "document-2",
        },
    ]
    apply._apply_post_scan_transaction(connection, plan=plan)
    ledger, prestate = apply._post_scan_ledger(
        connection,
        plan=plan,
        materialization_ledger=materialization_ledger,
    )
    connection.close()

    assert ledger["phase2a_owner_packet_content_sha256"] == (
        dynamic_scope.EXPECTED_OWNER_PACKET_CONTENT_SHA256
    )
    assert ledger["phase2a_owner_approval_receipt_content_sha256"] == (
        apply.EXPECTED_FINAL_APPROVAL_RECEIPT_CONTENT_SHA256
    )
    assert ledger["included_bindings"][0]["disposition"] == ("INCLUDE_IN_NON_ACTIVE_SUCCESSOR")
    assert ledger["excluded_bindings"][0]["disposition"] == "HOLD_EXCLUDE"
    assert ledger["excluded_bindings"][0]["candidate_included"] is False
    assert ledger["included_source_version_id_set_sha256"] == (
        dynamic_scope._source_version_set_sha256(["source-version-1"])
    )
    assert ledger["source_admission_applied"] is True
    assert ledger["answer_release_eligible"] is False
    assert ledger["successor_must_remain_non_active"] is True
    assert ledger["phase2b_authorized"] is False
    assert ledger["successor_build_run"] is False
    assert prestate["record_count"] == 2

    ledger_root = settings.evaluation_dir / "phase2a-owner-review" / "synthetic-ledger"
    ledger_root.mkdir(parents=True)
    ledger_path = ledger_root / apply.OWNER_APPLICATION_LEDGER_NAME
    ledger_path.write_text(json.dumps(ledger, sort_keys=True) + "\n", encoding="utf-8")
    loaded, content_sha, relative = dynamic_scope._verify_application_ledger(
        settings,
        ledger_path,
        expected_owner_approval_receipt_content_sha256=(
            apply.EXPECTED_FINAL_APPROVAL_RECEIPT_CONTENT_SHA256
        ),
    )
    included, excluded = dynamic_scope._ledger_records(loaded)
    assert content_sha == ledger["artifact_content_sha256"]
    assert relative == "synthetic-ledger/OWNER-APPLICATION-LEDGER.json"
    assert len(included) == 1
    assert len(excluded) == 1


def test_post_scan_application_rejects_nonstaged_source_and_rolls_back(
    tmp_path: Path,
) -> None:
    connection = _initialised_connection(tmp_path / "catalog.sqlite3")
    now = "2026-08-28T00:00:00+00:00"
    connection.execute(
        """
        INSERT INTO documents(
          id,content_sha256,source_identity_id,safe_display_name,media_type,
          status,lane,created_at,updated_at
        ) VALUES ('document-one',?,'identity-one','source.md','text/markdown',
                  'staged','quarantine',?,?)
        """,
        ("a" * 64, now, now),
    )
    connection.execute(
        """
        INSERT INTO source_versions(
          id,document_id,authority_identity_id,version_sha256,
          canonical_markdown_path,review_status,metadata_json,created_at
        ) VALUES ('source-one','document-one','neutral-citation:[2026] TEST 1',?,
                  'data/vault/one.md','approved','{}',?)
        """,
        ("a" * 64, now),
    )
    connection.commit()
    plan = {
        "source_scan_id": "scan-one",
        "source_scan_manifest_sha256": "b" * 64,
        "bindings": [
            {
                "source_version_id": "source-one",
                "document_id": "document-one",
                "authority_identity_id": "neutral-citation:[2026] TEST 1",
                "index_eligible": True,
                "pre_review_status": "staged",
            }
        ],
    }
    with pytest.raises(ValueError, match="source_changed_before_transaction"):
        apply._apply_post_scan_transaction(connection, plan=plan)
    document = connection.execute(
        "SELECT status,lane,retrieval_canonical FROM documents WHERE id='document-one'"
    ).fetchone()
    connection.close()
    assert tuple(document) == ("staged", "quarantine", 0)
