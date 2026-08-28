from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import subprocess
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from pydantic import ValidationError
from scripts import prepare_v111_phase2_certification as preparation_cli

from app.evaluation.live_suite import load_live_evaluation_bundle
from app.evaluation.sealed_candidate import SealedCandidateIdentity
from app.evaluation.v111_certification_preparation import (
    CONTRACT_FILENAME,
    INDEX_FILENAME,
    QUALIFICATION_FILENAME,
    CandidatePolicyBinding,
    CandidateSourceInventory,
    CertificationContractDraft,
    CodeBinding,
    Phase2PreparationPackage,
    QualificationPreparationReport,
    RetrievalEvidenceBinding,
    build_phase2_preparation_package,
    build_retrieval_evidence_binding,
    exact_clean_code_binding,
    load_candidate_source_inventory,
    open_immutable_phase2_catalogue,
    verify_phase2_preparation_package,
    write_phase2_preparation_package,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_preparation_cli_has_stable_gate_fingerprints_and_no_bundle_override() -> None:
    first = preparation_cli.Phase2PreparationCommandStop("candidate_catalogue_replay_failed")
    second = preparation_cli.Phase2PreparationCommandStop("candidate_source_replay_failed")
    assert preparation_cli._safe_error_code(first) == "candidate_catalogue_replay_failed"
    assert preparation_cli._safe_error_code(second) == "candidate_source_replay_failed"
    assert preparation_cli._safe_error_code(RuntimeError("private detail")) == (
        "unexpected_phase2_preparation_failure"
    )
    with pytest.raises(SystemExit):
        preparation_cli._parser().parse_args(
            [
                "--candidate-build-id",
                "candidate-v111",
                "--expected-head",
                "a" * 40,
                "--output-directory",
                "ignored",
                "--bundle",
                "alternate-registry",
            ]
        )


def test_exact_code_binding_rejects_assume_unchanged_tracked_bytes(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    git = "/usr/bin/git"

    def run(*args: str) -> str:
        return subprocess.run(
            [git, *args],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    run("init", "-q")
    tracked = repository / "tracked.py"
    tracked.write_text("value = 1\n", encoding="utf-8")
    run("add", "tracked.py")
    run(
        "-c",
        "user.name=LegalBot Test",
        "-c",
        "user.email=legalbot@example.invalid",
        "commit",
        "-q",
        "-m",
        "fixture",
    )
    head = run("rev-parse", "HEAD")
    assert exact_clean_code_binding(repository, expected_head=head).commit_sha == head

    run("update-index", "--assume-unchanged", "tracked.py")
    tracked.write_text("value = 2\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="rejects nonstandard Git index flags"):
        exact_clean_code_binding(repository, expected_head=head)


def _candidate(
    *,
    source_manifest_sha256: str = "c" * 64,
    candidate_seal_sha256: str = "b" * 64,
) -> SealedCandidateIdentity:
    return SealedCandidateIdentity(
        build_id="current-law-ew-full-fp16-v111-fixture",
        status="candidate",
        candidate_manifest_sha256="a" * 64,
        candidate_seal_sha256=candidate_seal_sha256,
        source_manifest_sha256=source_manifest_sha256,
        embedding_model="embedding-fixture",
        reranker_model="reranker-fixture",
        document_count=2,
        chunk_count=10,
        vector_count=10,
    )


def _source_inventory() -> CandidateSourceInventory:
    return CandidateSourceInventory(
        source_manifest_file_sha256="d" * 64,
        source_manifest_identity_sha256="c" * 64,
        candidate_snapshot_date="2026-08-14",
        source_count=2,
        authority_lane_count=2,
        latest_revised_snapshot_count=1,
        historical_authority_count=1,
        current_law_eligible_count=1,
        subsequent_treatment_required_count=1,
        subsequent_treatment_verified_count=0,
        omitted_required_family_count=0,
    )


def _policies() -> CandidatePolicyBinding:
    return CandidatePolicyBinding(
        quality_policy_sha256="1" * 64,
        retrieval_policy_sha256="2" * 64,
        assessment_guidance_sha256="3" * 64,
        provision_verification_sha256="4" * 64,
        source_manifest_file_sha256="d" * 64,
        index_tree_sha256="5" * 64,
    )


def _closure(*, revision: str, tree: str, aggregate: str = "6" * 64) -> dict[str, object]:
    return {
        "revision": revision,
        "tree": tree,
        "member_count": 1,
        "members": [
            {
                "path": "backend/app/retrieval/retrieval_v1.py",
                "kind": "python_dependency",
                "size": 10,
                "sha256": "7" * 64,
            }
        ],
        "python_runtime": {
            "binding_state": "bound",
            "version": "3.13.7",
            "implementation": "cpython",
            "executable_sha256": "8" * 64,
        },
        "legacy_scorer_implementation_sha256": "9" * 64,
        "aggregate_sha256": aggregate,
    }


def _retrieval_evidence() -> RetrievalEvidenceBinding:
    code = CodeBinding(commit_sha="e" * 40, tree_sha="f" * 40, worktree_clean=True)
    return build_retrieval_evidence_binding(
        selected_attestation_schema="legalbot.retrieval-reattestation.v2",
        selected_attestation_sha256="a" * 64,
        selected_attestation_history_id="a" * 64,
        selected_integration_commit="b" * 40,
        selected_closure_manifest_file_sha256="c" * 64,
        selected_closure_manifest_sha256="d" * 64,
        selected_closure=_closure(revision="b" * 40, tree="c" * 40),
        current_closure=_closure(
            revision=code.commit_sha,
            tree=code.tree_sha,
            aggregate="d" * 64,
        ),
        code=code,
    )


def _package() -> Phase2PreparationPackage:
    bundle = load_live_evaluation_bundle(
        PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"
    )
    return build_phase2_preparation_package(
        generated_at=datetime(2026, 8, 22, 12, 0, tzinfo=UTC),
        code=CodeBinding(commit_sha="e" * 40, tree_sha="f" * 40, worktree_clean=True),
        candidate=_candidate(),
        bundle=bundle,
        candidate_sources=_source_inventory(),
        candidate_policies=_policies(),
        retrieval_evidence=_retrieval_evidence(),
    )


def test_contract_and_qualification_are_exact_pending_non_authority() -> None:
    package = _package()

    assert package.contract.authorizing is False
    assert package.contract.owner_signature_present is False
    assert package.contract.development_run_authorized is False
    assert package.contract.currentness.owner_cutoff_date is None
    assert package.contract.scoring.automated_academic_target_is_legal_safety_gate is False
    assert package.contract.execution.maximum_same_failure_fingerprint == 2
    assert package.contract.retrieval_evidence.semantic_equivalence_proven is True
    assert package.contract.retrieval_evidence.equivalence_ignores == ("revision", "tree")
    assert package.contract.registry.case_count == 60
    assert package.contract.registry.issue_count == 585
    assert package.qualification.pending_case_count == 60
    assert package.qualification.pending_issue_count == 585
    assert package.qualification.answer_model_invoked is False
    assert package.qualification.stage_a_invoked is False
    assert package.qualification.development_30_invoked is False
    assert package.qualification.split_created is False
    workflow = package.qualification.workflow
    assert workflow.index(
        "stage_official_primary_source_currentness_review_without_owner_cutoff"
    ) < workflow.index("owner_decides_and_signs_exact_cutoff_and_materiality_rule")
    assert workflow.index(
        "owner_decides_and_signs_exact_cutoff_and_materiality_rule"
    ) < workflow.index("replay_official_primary_sources_through_signed_cutoff")
    assert all(
        case.qualification_state == "pending_official_source_and_currentness_review"
        for case in package.qualification.cases
    )
    assert all(
        issue.qualification_state == "pending_official_source_and_currentness_review"
        for case in package.qualification.cases
        for issue in case.issues
    )


def test_contract_and_report_seals_reject_tampering() -> None:
    package = _package()
    contract = package.contract.model_dump(mode="json", by_alias=True)
    contract["scoring"]["stage_a_mrr_minimum"] = 0.1
    with pytest.raises(ValidationError):
        CertificationContractDraft.model_validate(contract)

    report = package.qualification.model_dump(mode="json", by_alias=True)
    report["cases"][0]["issues"][0]["material_gap_state"] = "not_assessed"
    report["cases"][0]["issues"][0]["issue_label_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="preparation seal does not match"):
        QualificationPreparationReport.model_validate(report)


def test_private_package_is_create_only_and_strictly_replayable(tmp_path: Path) -> None:
    target = tmp_path / "phase2-preparation"
    package = _package()
    index = write_phase2_preparation_package(target, package)

    assert stat.S_IMODE(target.stat().st_mode) == 0o700
    for name in (CONTRACT_FILENAME, QUALIFICATION_FILENAME, INDEX_FILENAME):
        assert stat.S_IMODE((target / name).stat().st_mode) == 0o600
    assert verify_phase2_preparation_package(target) == index
    with pytest.raises(FileExistsError):
        write_phase2_preparation_package(target, package)

    extra = target / "unexpected.json"
    extra.write_text("{}", encoding="utf-8")
    extra.chmod(0o600)
    with pytest.raises(RuntimeError, match="members are unsafe"):
        verify_phase2_preparation_package(target)
    extra.unlink()

    alias = tmp_path / "phase2-preparation-alias"
    alias.symlink_to(target, target_is_directory=True)
    with pytest.raises(RuntimeError, match="directory identity is unsafe"):
        verify_phase2_preparation_package(alias)

    hardlink = tmp_path / "contract-hardlink.json"
    os.link(target / CONTRACT_FILENAME, hardlink)
    with pytest.raises(RuntimeError, match="artifact identity is unsafe"):
        verify_phase2_preparation_package(target)
    hardlink.unlink()

    contract = json.loads((target / CONTRACT_FILENAME).read_bytes())
    qualification = json.loads((target / QUALIFICATION_FILENAME).read_bytes())
    encoded = json.dumps({"contract": contract, "qualification": qualification})
    assert '"question"' not in encoded
    assert '"answer"' not in encoded
    assert str(PROJECT_ROOT) not in encoded


def test_candidate_source_inventory_uses_only_sealed_aggregates(tmp_path: Path) -> None:
    source = {
        "manifest_sha256": "c" * 64,
        "current_law_as_of_date": "2026-08-14",
        "source_count": 2,
        "omitted_required_families": [],
        "sources": [
            {
                "canonical_markdown_path": "data/vault/objects/fixture",
                "title": "Never export source prose",
                "lane": "primary_authority",
                "currentness_status": "latest_available_revised_snapshot",
                "full_current_law_verification_eligible": True,
                "subsequent_treatment_check_required": False,
                "subsequent_treatment_verified": False,
            },
            {
                "lane": "primary_authority",
                "currentness_status": "historical",
                "full_current_law_verification_eligible": False,
                "subsequent_treatment_check_required": True,
                "subsequent_treatment_verified": False,
            },
        ],
    }
    source_bytes = json.dumps(source, sort_keys=True).encode()
    (tmp_path / "approved-source-manifest.json").write_bytes(source_bytes)
    seal = {
        "manifest_sha256": "a" * 64,
        "source_manifest_file_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "quality_policy_sha256": "1" * 64,
        "retrieval_policy_sha256": "2" * 64,
        "assessment_guidance_sha256": "3" * 64,
        "provision_verification_sha256": "4" * 64,
        "lance_tree_sha256": "5" * 64,
    }
    seal_bytes = json.dumps(seal).encode()
    (tmp_path / "seal.json").write_bytes(seal_bytes)

    inventory, policies = load_candidate_source_inventory(
        build_root=tmp_path,
        candidate=replace(
            _candidate(candidate_seal_sha256=hashlib.sha256(seal_bytes).hexdigest()),
            candidate_manifest_sha256="a" * 64,
        ),
    )

    assert inventory.source_count == 2
    assert inventory.current_law_eligible_count == 1
    assert inventory.subsequent_treatment_required_count == 1
    assert not hasattr(inventory, "canonical_markdown_path")
    assert policies.quality_policy_sha256 == "1" * 64

    seal["source_manifest_file_sha256"] = "0" * 64
    changed_seal_bytes = json.dumps(seal).encode()
    (tmp_path / "seal.json").write_bytes(changed_seal_bytes)
    with pytest.raises(RuntimeError, match="does not match"):
        load_candidate_source_inventory(
            build_root=tmp_path,
            candidate=replace(
                _candidate(candidate_seal_sha256=hashlib.sha256(changed_seal_bytes).hexdigest()),
                candidate_manifest_sha256="a" * 64,
            ),
        )

    with pytest.raises(RuntimeError, match="seal bytes differ"):
        load_candidate_source_inventory(
            build_root=tmp_path,
            candidate=_candidate(candidate_seal_sha256="b" * 64),
        )

    changed_seal = dict(seal)
    changed_seal["source_manifest_file_sha256"] = hashlib.sha256(source_bytes).hexdigest()
    changed_seal["manifest_sha256"] = "9" * 64
    changed_seal_bytes = json.dumps(changed_seal).encode()
    (tmp_path / "seal.json").write_bytes(changed_seal_bytes)
    with pytest.raises(RuntimeError, match="does not match"):
        load_candidate_source_inventory(
            build_root=tmp_path,
            candidate=replace(
                _candidate(candidate_seal_sha256=hashlib.sha256(changed_seal_bytes).hexdigest()),
                candidate_manifest_sha256="a" * 64,
            ),
        )


def test_scorer_semantic_equivalence_rejects_every_non_git_change() -> None:
    code = CodeBinding(commit_sha="e" * 40, tree_sha="f" * 40, worktree_clean=True)
    selected = _closure(revision="b" * 40, tree="c" * 40)
    current = _closure(revision=code.commit_sha, tree=code.tree_sha, aggregate="d" * 64)
    binding = build_retrieval_evidence_binding(
        selected_attestation_schema="legalbot.retrieval-reattestation.v2",
        selected_attestation_sha256="a" * 64,
        selected_attestation_history_id="a" * 64,
        selected_integration_commit="b" * 40,
        selected_closure_manifest_file_sha256="c" * 64,
        selected_closure_manifest_sha256="d" * 64,
        selected_closure=selected,
        current_closure=current,
        code=code,
    )
    assert binding.selected_closure_aggregate_sha256 != binding.current_closure_aggregate_sha256
    assert binding.selected_semantic_closure_sha256 == binding.current_semantic_closure_sha256

    mutations = (
        (
            "members",
            [
                {
                    **cast(list[dict[str, object]], current["members"])[0],
                    "sha256": "0" * 64,
                }
            ],
        ),
        (
            "python_runtime",
            {**cast(dict[str, object], current["python_runtime"]), "version": "3.13.8"},
        ),
        ("legacy_scorer_implementation_sha256", "0" * 64),
    )
    for field, value in mutations:
        changed = deepcopy(current)
        changed[field] = value
        with pytest.raises(RuntimeError, match="differs from selected historical proof"):
            build_retrieval_evidence_binding(
                selected_attestation_schema="legalbot.retrieval-reattestation.v2",
                selected_attestation_sha256="a" * 64,
                selected_attestation_history_id="a" * 64,
                selected_integration_commit="b" * 40,
                selected_closure_manifest_file_sha256="c" * 64,
                selected_closure_manifest_sha256="d" * 64,
                selected_closure=selected,
                current_closure=changed,
                code=code,
            )


def _sqlite_fixture(path: Path, *, invalid_foreign_key: bool = False) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            """
            PRAGMA foreign_keys=OFF;
            CREATE TABLE parent (id INTEGER PRIMARY KEY);
            CREATE TABLE child (
              id INTEGER PRIMARY KEY,
              parent_id INTEGER NOT NULL REFERENCES parent(id)
            );
            INSERT INTO parent(id) VALUES (1);
            """
        )
        connection.execute(
            "INSERT INTO child(id,parent_id) VALUES (?,?)",
            (1, 2 if invalid_foreign_key else 1),
        )
        connection.commit()
    finally:
        connection.close()
    path.chmod(0o600)


def test_immutable_catalogue_is_query_only_and_leaves_no_database_artifacts(
    tmp_path: Path,
) -> None:
    path = tmp_path / "catalog.sqlite3"
    _sqlite_fixture(path)
    before_bytes = path.read_bytes()
    before_stat = path.stat()

    with open_immutable_phase2_catalogue(path) as database:
        row = database.fetchone("SELECT parent_id FROM child WHERE id=?", (1,))
        assert row is not None and int(row["parent_id"]) == 1
        with (
            database.transaction() as connection,
            pytest.raises(sqlite3.OperationalError, match="readonly"),
        ):
            connection.execute("UPDATE child SET parent_id=2 WHERE id=1")

    after_stat = path.stat()
    assert path.read_bytes() == before_bytes
    assert (
        after_stat.st_dev,
        after_stat.st_ino,
        after_stat.st_mode,
        after_stat.st_nlink,
        after_stat.st_size,
        after_stat.st_mtime_ns,
        after_stat.st_ctime_ns,
    ) == (
        before_stat.st_dev,
        before_stat.st_ino,
        before_stat.st_mode,
        before_stat.st_nlink,
        before_stat.st_size,
        before_stat.st_mtime_ns,
        before_stat.st_ctime_ns,
    )
    assert not os.path.lexists(f"{path}-wal")
    assert not os.path.lexists(f"{path}-shm")
    assert not os.path.lexists(f"{path}-journal")


@pytest.mark.parametrize("suffix", ("-wal", "-shm", "-journal"))
def test_immutable_catalogue_refuses_sidecars_permissions_symlinks_and_bad_fks(
    tmp_path: Path,
    suffix: str,
) -> None:
    path = tmp_path / "catalog.sqlite3"
    _sqlite_fixture(path)
    sidecar = Path(f"{path}{suffix}")
    sidecar.write_bytes(b"forbidden")
    with pytest.raises(RuntimeError, match="journal sidecar"):
        open_immutable_phase2_catalogue(path)
    sidecar.unlink()

    path.chmod(0o644)
    with pytest.raises(RuntimeError, match="private owner file"):
        open_immutable_phase2_catalogue(path)
    path.chmod(0o600)

    symlink = tmp_path / "catalog-link.sqlite3"
    symlink.symlink_to(path)
    with pytest.raises((OSError, RuntimeError)):
        open_immutable_phase2_catalogue(symlink)

    invalid = tmp_path / "invalid.sqlite3"
    _sqlite_fixture(invalid, invalid_foreign_key=True)
    with pytest.raises(RuntimeError, match="foreign-key"):
        open_immutable_phase2_catalogue(invalid)
