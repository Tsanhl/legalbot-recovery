from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from backend.app.config import Settings
from backend.app.db import Database
from backend.app.retrieval import phase2a_dynamic_scope as dynamic_scope
from backend.app.retrieval import phase2a_scan_build_execution as execution
from backend.app.retrieval import source_manifest


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def _seal(value: dict[str, object], field: str) -> dict[str, object]:
    output = dict(value)
    output[field] = hashlib.sha256(_canonical(output)).hexdigest()
    return output


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _settings(tmp_path: Path) -> Settings:
    project = tmp_path / "project"
    project.mkdir()
    for name in ("Qwen3-Embedding-0.6B", "Qwen3-Reranker-0.6B"):
        (project / "models" / "retrieval" / name).mkdir(parents=True)
    return Settings(project_root=project, test_mode=True)


def test_explicit_source_roots_override_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(tmp_path / "wrong"))
    settings = Settings(
        project_root=tmp_path,
        test_mode=True,
        explicit_source_roots=(first, second),
    )
    assert settings.source_roots == (first, second)


def test_real_execution_authority_is_exact_and_unspent() -> None:
    settings = Settings()
    result = execution.verify_execution_authority(settings)
    assert result["receipt"]["artifact_content_sha256"] == (
        execution.OWNER_APPROVAL_RECEIPT_CONTENT_SHA256
    )
    assert result["authority"]["artifact_content_sha256"] == (
        execution.EXECUTION_AUTHORITY_CONTENT_SHA256
    )
    assert result["authority"]["status"] == "AVAILABLE_UNSPENT"
    assert result["authority"]["phase2b_authorized"] is False


def test_source_root_inventory_is_aggregate_only_and_rejects_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    roots = tuple(tmp_path / value for value in ("law", "base", "approved"))
    for index, root in enumerate(roots):
        root.mkdir()
        (root / f"private-{index}.md").write_text(f"source {index}", encoding="utf-8")
    monkeypatch.setattr(execution, "exact_source_roots", lambda _settings: roots)
    inventory = execution.source_root_inventory(settings)
    assert inventory["file_count"] == 3
    assert inventory["root_count"] == 3
    assert inventory["absolute_paths_disclosed"] is False
    assert "private-" not in json.dumps(inventory)
    assert len(inventory["inventory_content_sha256"]) == 64

    (roots[2] / "unsafe-link").symlink_to(roots[2] / "private-2.md")
    with pytest.raises(ValueError, match="contains_symlink"):
        execution.source_root_inventory(settings)
    (roots[2] / "unsafe-link").unlink()
    root_alias = tmp_path / "approved-alias"
    root_alias.symlink_to(roots[2], target_is_directory=True)
    monkeypatch.setattr(
        execution,
        "exact_source_roots",
        lambda _settings: (roots[0], roots[1], root_alias),
    )
    with pytest.raises(ValueError, match="root_phase2a-approved-materialized_invalid"):
        execution.source_root_inventory(settings)


def test_preflight_is_read_only_and_blocks_without_materialization_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    database = Database(settings.database_path)
    database.initialize()
    predecessor = settings.index_dir / "builds" / "prior"
    predecessor.mkdir(parents=True)
    (predecessor / "sealed.bin").write_bytes(b"candidate")
    inventory = _seal(
        {
            "schema": execution.SOURCE_ROOT_INVENTORY_SCHEMA,
            "root_count": 3,
            "file_count": 5,
            "total_bytes": 50,
            "roots": [],
            "absolute_paths_disclosed": False,
            "old_project_fallback_used": False,
        },
        "inventory_content_sha256",
    )
    monkeypatch.setattr(
        execution,
        "verify_execution_authority",
        lambda _settings: {"authority": {"chain_id": "exact-chain"}},
    )
    monkeypatch.setattr(execution, "source_root_inventory", lambda _settings: inventory)
    monkeypatch.setattr(
        execution.shutil,
        "disk_usage",
        lambda _path: execution.shutil._ntuple_diskusage(100 * 1024**3, 1 * 1024**3, 99 * 1024**3),
    )
    before = settings.database_path.read_bytes()
    result = execution.build_preflight(
        settings,
        database,
        predecessor_build_id="prior",
        materialization_ledger_path=None,
    )
    prior_stage_inventory = _seal(
        {
            "schema": "legalbot.v111.phase2a.execution-stage-inventory.v1",
            "execution_authority_content_sha256": (execution.EXECUTION_AUTHORITY_CONTENT_SHA256),
            "stage_count": 1,
            "stages": [
                {
                    "stage": "scan_receipt",
                    "artifact_content_sha256": "a" * 64,
                    "relative_path": "prior/SOURCE-SCAN-RECEIPT.json",
                }
            ],
        },
        "inventory_content_sha256",
    )
    monkeypatch.setattr(
        execution,
        "execution_stage_inventory",
        lambda _settings: prior_stage_inventory,
    )
    duplicate = execution.build_preflight(
        settings,
        database,
        predecessor_build_id="prior",
        materialization_ledger_path=None,
    )
    after = settings.database_path.read_bytes()
    database.close()
    assert result["status"] == "BLOCKED_PREFLIGHT"
    assert result["blockers"] == ["MATERIALIZATION_LEDGER_NOT_SUPPLIED"]
    assert result["source_scan_run"] is False
    assert result["successor_build_run"] is False
    assert result["active_or_previous_write_authorized"] is False
    assert "PRIOR_EXECUTION_STAGE_RECEIPT_PRESENT" in duplicate["blockers"]
    assert before == after


def test_execution_stage_inventory_discovers_exact_authority_receipts(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    stage = _seal(
        {
            "schema": execution.SCAN_RECEIPT_SCHEMA,
            "phase2a_execution_authority_content_sha256": (
                execution.EXECUTION_AUTHORITY_CONTENT_SHA256
            ),
            "materialization_ledger_content_sha256": "a" * 64,
            "preflight_content_sha256": "b" * 64,
            "source_scan_id": "scan-exact",
            "source_scan_manifest_sha256": "c" * 64,
            "source_scan_run": True,
            "successor_build_run": False,
        },
        "scan_receipt_content_sha256",
    )
    path = (
        settings.evaluation_dir
        / "phase2a-owner-review"
        / "exact-chain"
        / "SOURCE-SCAN-RECEIPT.json"
    )
    _write_json(path, stage)
    inventory = execution.execution_stage_inventory(settings)
    assert inventory["stage_count"] == 1
    assert inventory["stages"][0]["stage"] == "scan_receipt"
    assert inventory["stages"][0]["source_scan_id"] == "scan-exact"
    assert "/Users/" not in json.dumps(inventory)


def test_source_version_set_digest_contract_and_duplicate_rejection() -> None:
    expected = hashlib.sha256(
        _canonical(
            {
                "schema": "legalbot.v111.phase2a.source-version-id-set.v1",
                "source_version_ids": ["source-a", "source-b"],
            }
        )
    ).hexdigest()
    assert dynamic_scope._source_version_set_sha256(["source-b", "source-a"]) == expected
    with pytest.raises(ValueError, match="duplicate_source_version"):
        dynamic_scope._source_version_set_sha256(["source-a", "source-a"])


def test_dynamic_scope_loader_binds_receipts_scan_and_non_active_boundary(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    ledger_sha = "a" * 64
    corpus_id = dynamic_scope.dynamic_corpus_id(ledger_sha)
    sources = []
    for index in range(2):
        sources.append(
            _seal(
                {
                    "binding_id": f"binding-{index}",
                    "source_version_id": f"source-version-{index}",
                    "document_id": f"document-{index}",
                    "stable_identifier": f"neutral-citation:[2026] TEST {index}",
                    "authority_identity_id": f"neutral-citation:[2026] TEST {index}",
                    "content_sha256": str(index) * 64,
                    "version_sha256": str(index) * 64,
                    "canonical_markdown_path": f"data/vault/{index}.md",
                    "body_chunk_count": index + 1,
                    "source_kind": "NEW_OWNER_ADMITTED",
                    "answer_release_eligible_in_successor": False,
                },
                "record_content_sha256",
            )
        )
    source_ids = [str(item["source_version_id"]) for item in sources]
    scope = _seal(
        {
            "schema": dynamic_scope.SCOPE_SCHEMA,
            "status": "OWNER_APPROVED_NON_ACTIVE_SUCCESSOR_SCOPE_FROZEN",
            "corpus_id": corpus_id,
            "phase2a_owner_packet_content_sha256": (
                dynamic_scope.EXPECTED_OWNER_PACKET_CONTENT_SHA256
            ),
            "phase2a_owner_approval_receipt_content_sha256": "b" * 64,
            "phase2a_owner_approval_receipt_relative_path": "receipt/owner.json",
            "phase2a_owner_application_ledger_content_sha256": ledger_sha,
            "phase2a_owner_application_ledger_relative_path": "ledger/apply.json",
            "phase2a_execution_authority_content_sha256": (
                dynamic_scope.EXPECTED_EXECUTION_AUTHORITY_CONTENT_SHA256
            ),
            "materialization_ledger_content_sha256": "8" * 64,
            "materialization_ledger_relative_path": "materialized/ledger.json",
            "execution_chain_run_id": dynamic_scope.execution_chain_run_id("8" * 64),
            "source_root_inventory_content_sha256": "c" * 64,
            "source_scan_id": "scan-one",
            "source_scan_manifest_sha256": "d" * 64,
            "source_scan_expected_file_count": 9,
            "source_scan_files_accounted": 9,
            "predecessor_build_id": "prior",
            "predecessor_source_manifest_content_sha256": "e" * 64,
            "predecessor_source_manifest_file_sha256": "f" * 64,
            "predecessor_scope_content_sha256": "1" * 64,
            "prior_source_count": 1,
            "newly_admitted_source_count": 1,
            "source_count": 2,
            "chunk_count": 3,
            "source_version_id_set_sha256": dynamic_scope._source_version_set_sha256(source_ids),
            "source_family_counts": {"NEW_OWNER_ADMITTED": 2},
            "excluded_source_binding_count": 4,
            "selection_policy": "exact-owner-approved-dynamic-phase2a-successor-scope",
            "sources": sources,
            "answer_release_eligible": False,
            "successor_must_remain_non_active": True,
            "common_legal_currentness_cutoff": None,
            "active_or_previous_write_authorized": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
            "validation30_authorized": False,
            "promotion_authorized": False,
        },
        "scope_content_sha256",
    )
    root = settings.evaluation_dir / "phase2a-owner-review" / "scope-r1"
    scope_path = root / dynamic_scope.SCOPE_FILENAME
    _write_json(scope_path, scope)
    package = _seal(
        {
            "schema": dynamic_scope.PACKAGE_SCHEMA,
            "status": "DYNAMIC_PHASE2A_SCOPE_FROZEN_BUILD_NOT_STARTED",
            "corpus_id": corpus_id,
            "scope_content_sha256": scope["scope_content_sha256"],
            "scope_file_sha256": hashlib.sha256(scope_path.read_bytes()).hexdigest(),
            "source_count": 2,
            "chunk_count": 3,
            "source_version_id_set_sha256": scope["source_version_id_set_sha256"],
            "phase2a_owner_packet_content_sha256": scope["phase2a_owner_packet_content_sha256"],
            "phase2a_owner_approval_receipt_content_sha256": scope[
                "phase2a_owner_approval_receipt_content_sha256"
            ],
            "phase2a_owner_application_ledger_content_sha256": ledger_sha,
            "phase2a_execution_authority_content_sha256": (
                dynamic_scope.EXPECTED_EXECUTION_AUTHORITY_CONTENT_SHA256
            ),
            "materialization_ledger_content_sha256": "8" * 64,
            "execution_chain_run_id": dynamic_scope.execution_chain_run_id("8" * 64),
            "source_scan_id": "scan-one",
            "source_scan_manifest_sha256": "d" * 64,
            "answer_release_eligible": False,
            "successor_must_remain_non_active": True,
            "candidate_build_started": False,
            "active_or_previous_written": False,
            "phase2b_authorized": False,
        },
        "package_content_sha256",
    )
    _write_json(root / dynamic_scope.PACKAGE_FILENAME, package)
    loaded = dynamic_scope.load_dynamic_phase2a_scope(settings, corpus_id)
    assert loaded["source_count"] == 2
    assert loaded["answer_release_eligible"] is False
    assert loaded["phase2b_authorized"] is False

    scope["answer_release_eligible"] = True
    _write_json(scope_path, scope)
    with pytest.raises(ValueError, match="scope_seal_invalid"):
        dynamic_scope.load_dynamic_phase2a_scope(settings, corpus_id)


def test_blocked_preflight_never_calls_scanner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    database = Database(settings.database_path)
    database.initialize()
    called = False

    def forbidden(*_args: object, **_kwargs: object) -> dict[str, object]:
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(execution, "scan_configured_sources", forbidden)
    preflight = _seal(
        {"schema": execution.PREFLIGHT_SCHEMA, "status": "BLOCKED_PREFLIGHT"},
        "preflight_content_sha256",
    )
    with pytest.raises(ValueError, match="not_ready"):
        execution.run_complete_source_scan_once(
            settings,
            database,
            object(),  # type: ignore[arg-type]
            preflight=preflight,
        )
    database.close()
    assert called is False


def test_dynamic_source_manifest_carries_all_qualification_bindings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    ledger_sha = "a" * 64
    receipt_sha = "b" * 64
    scan_sha = "c" * 64
    inventory_sha = "d" * 64
    source_set_sha = "e" * 64
    corpus_id = dynamic_scope.dynamic_corpus_id(ledger_sha)
    scope = {
        "schema": dynamic_scope.SCOPE_SCHEMA,
        "scope_content_sha256": "f" * 64,
        "source_count": 2,
        "chunk_count": 3,
        "source_scan_id": "scan-final",
        "source_scan_manifest_sha256": scan_sha,
        "phase2a_owner_packet_content_sha256": (dynamic_scope.EXPECTED_OWNER_PACKET_CONTENT_SHA256),
        "phase2a_owner_approval_receipt_content_sha256": receipt_sha,
        "phase2a_owner_application_ledger_content_sha256": ledger_sha,
        "phase2a_execution_authority_content_sha256": (
            dynamic_scope.EXPECTED_EXECUTION_AUTHORITY_CONTENT_SHA256
        ),
        "materialization_ledger_content_sha256": "8" * 64,
        "execution_chain_run_id": dynamic_scope.execution_chain_run_id("8" * 64),
        "source_root_inventory_content_sha256": inventory_sha,
        "source_version_id_set_sha256": source_set_sha,
        "predecessor_build_id": "prior-build",
    }
    rows = [
        {
            "source_version_id": "source-legislation",
            "document_id": "document-legislation",
            "document_status": "citable",
            "stable_identifier": "ukpga:2020:1:latest-available@2026-08-28",
            "authority_identity_id": "ukpga:2020:1",
            "title": "Act",
            "lane": "primary_authority",
            "jurisdiction": "England and Wales",
            "licence_name": "Open Government Licence v3.0",
            "canonical_url": "https://www.legislation.gov.uk/ukpga/2020/1",
            "content_sha256": "1" * 64,
            "version_sha256": "1" * 64,
            "canonical_markdown_path": "data/vault/act.md",
            "body_chunk_count": 1,
            "unfiltered_body_chunk_count": 1,
            "phase2a_scope_record_content_sha256": "6" * 64,
            "currentness_status": "latest_available_revised_snapshot",
            "source_date": "2020-01-01",
            "as_of_date": "2026-08-28",
            "last_updated": "2026-08-28T00:00:00+00:00",
            "metadata_json": json.dumps(
                {
                    "identity_verified": True,
                    "currentness_verified": False,
                    "subsequent_treatment_check_required": False,
                    "subsequent_treatment_verified": False,
                    "official_snapshot": {"unapplied_effect_count": 0},
                    "provision_extent_status": "england_and_wales_verified",
                }
            ),
        },
        {
            "source_version_id": "source-judgment",
            "document_id": "document-judgment",
            "document_status": "citable",
            "stable_identifier": "neutral-citation:[2026] UKSC 1",
            "authority_identity_id": "neutral-citation:[2026] UKSC 1",
            "title": "Case",
            "lane": "primary_authority",
            "jurisdiction": "United Kingdom",
            "licence_name": "Open Government Licence v3.0",
            "canonical_url": "https://www.supremecourt.uk/case.html",
            "content_sha256": "2" * 64,
            "version_sha256": "2" * 64,
            "canonical_markdown_path": "data/vault/case.md",
            "body_chunk_count": 2,
            "unfiltered_body_chunk_count": 2,
            "phase2a_scope_record_content_sha256": "7" * 64,
            "currentness_status": "held",
            "source_date": "2026-01-01",
            "as_of_date": None,
            "last_updated": "2026-08-28T00:00:00+00:00",
            "metadata_json": json.dumps(
                {
                    "identity_verified": True,
                    "currentness_verified": False,
                    "subsequent_treatment_check_required": True,
                    "subsequent_treatment_verified": False,
                    "citation_data": {},
                }
            ),
        },
    ]
    packs = {
        "legislation_pack_version": "test",
        "uksc_pack_version": "test",
        "uksc_pack_sha256": "3" * 64,
        "quistclose_pack_version": None,
        "quistclose_pack_sha256": None,
        "official_judgment_pack_versions": {},
        "official_judgment_pack_sha256s": {},
        "current_legislation_pack_version": "test",
        "current_law_as_of_date": "2026-08-28",
        "legislation_stable_ids": [rows[0]["stable_identifier"]],
        "official_judgment_neutral_citations": [rows[1]["stable_identifier"]],
    }
    monkeypatch.setattr(source_manifest, "load_dynamic_phase2a_scope", lambda *_: scope)
    monkeypatch.setattr(source_manifest, "load_pack_identities", lambda *_args, **_kwargs: packs)
    monkeypatch.setattr(
        source_manifest,
        "select_approved_authority_rows",
        lambda *_args, **_kwargs: rows,
    )
    monkeypatch.setattr(
        source_manifest,
        "load_current_law_slice_policy",
        lambda _settings: {
            "subjects": [],
            "max_source_body_chunks": 0,
            "schema": "legalbot.current-law-slice-policy.v1",
        },
    )
    import backend.app.ingestion.scan_attestation as scan_attestation
    import backend.app.retrieval.provision_verification as provision_verification

    monkeypatch.setattr(
        scan_attestation,
        "selected_sources_exclude_quarantine",
        lambda _rows: None,
    )
    monkeypatch.setattr(
        scan_attestation,
        "latest_complete_reconciled_scan",
        lambda _database: {"scan_id": "scan-final"},
    )
    monkeypatch.setattr(
        provision_verification,
        "load_provision_verifications",
        lambda *_args, **_kwargs: ({}, "4" * 64),
    )

    class _Database:
        @staticmethod
        def fetchone(_query: str, _parameters: tuple[str, ...]) -> dict[str, object]:
            return {
                "id": "scan-final",
                "manifest_sha256": scan_sha,
                "expected_file_count": 9,
                "files_accounted": 9,
            }

    manifest = source_manifest.build_approved_source_manifest(
        _Database(),  # type: ignore[arg-type]
        settings,
        corpus_id=corpus_id,
    )
    assert manifest["source_count"] == 2
    assert manifest["chunk_count"] == 3
    assert manifest["phase2a_owner_packet_content_sha256"] == (
        dynamic_scope.EXPECTED_OWNER_PACKET_CONTENT_SHA256
    )
    assert manifest["phase2a_owner_approval_receipt_content_sha256"] == receipt_sha
    assert manifest["phase2a_owner_application_ledger_content_sha256"] == ledger_sha
    assert manifest["phase2a_execution_authority_content_sha256"] == (
        dynamic_scope.EXPECTED_EXECUTION_AUTHORITY_CONTENT_SHA256
    )
    assert manifest["materialization_ledger_content_sha256"] == "8" * 64
    assert manifest["execution_chain_run_id"] == dynamic_scope.execution_chain_run_id("8" * 64)
    assert manifest["source_root_inventory_content_sha256"] == inventory_sha
    assert manifest["source_version_id_set_sha256"] == source_set_sha
    assert len(manifest["source_manifest_member_set_sha256"]) == 64
    assert all(len(source["phase2a_member_content_sha256"]) == 64 for source in manifest["sources"])
    assert manifest["source_scan_id"] == "scan-final"
    assert manifest["source_scan_manifest_sha256"] == scan_sha
    assert manifest["answer_release_eligible"] is False
    assert manifest["successor_must_remain_non_active"] is True
    assert manifest["active_or_previous_write_authorized"] is False
    assert manifest["phase2b_authorized"] is False
