from __future__ import annotations

import json
import os
import sqlite3
import stat
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from scripts import create_v111_owner_signature_decision as signature_cli

from app.evaluation.owner_quality_canary_authorization import OwnerDecisionRequired
from app.governance import existing_catalogue_read as catalogue_read
from app.governance import v111_decision_generation as decisions
from app.governance.existing_catalogue_read import open_existing_catalogue_read_database
from app.governance.owner_stop import (
    OwnerDecisionStore,
    seal_owner_decision_resolution,
)


def _memory_request(*, runtime: str = "b" * 64, integration: str = "d" * 40):
    return decisions.build_completion_memory_decision_request(
        candidate_build_id="candidate-v111",
        candidate_manifest_sha256="a" * 64,
        runtime_binding_sha256=runtime,
        integration_sha=integration,
        host_physical_memory_bytes=16 * 1024**3,
        trusted_model_identity_file_sha256="c" * 64,
        trusted_toolchain_identity_file_sha256="e" * 64,
        created_at=datetime(2026, 8, 20, 8, 0, tzinfo=UTC),
    )


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
    ).stdout.strip()


def test_memory_request_identity_is_runtime_and_head_bound() -> None:
    first = _memory_request()
    changed_runtime = _memory_request(runtime="f" * 64)
    changed_head = _memory_request(integration="1" * 40)
    assert first.decision_id.startswith("v111-completion-memory-")
    assert len({first.decision_id, changed_runtime.decision_id, changed_head.decision_id}) == 3
    assert first.recommended_option_id == "max-12884901888-min-3221225472"
    assert [item.option_id for item in first.options] == list(decisions.MEMORY_DECISION_OPTIONS)
    assert "completion-memory-envelope-v111-16g-20260820" not in first.model_dump_json()


def test_exact_clean_head_ignores_poisoned_status_config_and_detects_untracked(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init")
    _git(root, "config", "user.name", "LegalBot Test")
    _git(root, "config", "user.email", "legalbot@example.invalid")
    tracked = root / "tracked.txt"
    tracked.write_text("sealed\n", encoding="utf-8")
    _git(root, "add", "tracked.txt")
    _git(root, "commit", "-m", "initial")
    head = _git(root, "rev-parse", "HEAD")
    _git(root, "config", "status.showUntrackedFiles", "no")
    _git(root, "config", "core.untrackedCache", "true")
    assert decisions.require_exact_clean_head(root, head) == head

    (root / "untracked.txt").write_text("must be detected\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="clean integration tree"):
        decisions.require_exact_clean_head(root, head)


def test_exact_clean_head_accepts_cross_checked_linked_worktree(tmp_path: Path) -> None:
    primary = tmp_path / "primary"
    primary.mkdir()
    _git(primary, "init")
    _git(primary, "config", "user.name", "LegalBot Test")
    _git(primary, "config", "user.email", "legalbot@example.invalid")
    (primary / "tracked.txt").write_text("sealed\n", encoding="utf-8")
    _git(primary, "add", "tracked.txt")
    _git(primary, "commit", "-m", "initial")
    linked = tmp_path / "linked"
    _git(primary, "worktree", "add", "-b", "linked-test", str(linked))
    assert (linked / ".git").is_file()
    head = _git(linked, "rev-parse", "HEAD")
    assert decisions.require_exact_clean_head(linked, head) == head


def test_exact_clean_head_rejects_assume_unchanged_mutation(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init")
    _git(root, "config", "user.name", "LegalBot Test")
    _git(root, "config", "user.email", "legalbot@example.invalid")
    tracked = root / "tracked.txt"
    tracked.write_text("sealed\n", encoding="utf-8")
    _git(root, "add", "tracked.txt")
    _git(root, "commit", "-m", "initial")
    head = _git(root, "rev-parse", "HEAD")
    _git(root, "update-index", "--assume-unchanged", "tracked.txt")
    tracked.write_text("mutated\n", encoding="utf-8")
    assert _git(root, "status", "--porcelain=v1") == ""
    with pytest.raises(RuntimeError, match="nonstandard Git index flags"):
        decisions.require_exact_clean_head(root, head)


def test_exact_clean_head_rejects_raw_bytes_hidden_by_clean_filter(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init")
    _git(root, "config", "user.name", "LegalBot Test")
    _git(root, "config", "user.email", "legalbot@example.invalid")
    _git(root, "config", "filter.mask.clean", "/bin/echo sealed")
    _git(root, "config", "filter.mask.required", "true")
    (root / ".gitattributes").write_text("tracked.txt filter=mask\n", encoding="utf-8")
    tracked = root / "tracked.txt"
    tracked.write_text("sealed\n", encoding="utf-8")
    _git(root, "add", ".gitattributes", "tracked.txt")
    _git(root, "commit", "-m", "filtered")
    head = _git(root, "rev-parse", "HEAD")
    tracked.write_text("mutated\n", encoding="utf-8")
    _git(root, "add", "tracked.txt")
    assert _git(root, "status", "--porcelain=v1") == ""
    assert _git(root, "ls-files", "-v", "tracked.txt").startswith("H ")
    with pytest.raises(RuntimeError, match="tracked bytes differ from HEAD"):
        decisions.require_exact_clean_head(root, head)


def test_exact_clean_head_rejects_replacement_tree_for_expected_head(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init")
    _git(root, "config", "user.name", "LegalBot Test")
    _git(root, "config", "user.email", "legalbot@example.invalid")
    tracked = root / "tracked.txt"
    tracked.write_text("original\n", encoding="utf-8")
    _git(root, "add", "tracked.txt")
    _git(root, "commit", "-m", "original")
    expected_head = _git(root, "rev-parse", "HEAD")
    branch_ref = _git(root, "symbolic-ref", "HEAD")
    tracked.write_text("replacement\n", encoding="utf-8")
    _git(root, "add", "tracked.txt")
    _git(root, "commit", "-m", "replacement")
    replacement_commit = _git(root, "rev-parse", "HEAD")
    _git(root, "update-ref", branch_ref, expected_head)
    _git(root, "replace", expected_head, replacement_commit)
    assert _git(root, "rev-parse", "HEAD") == expected_head
    assert _git(root, "show", f"{expected_head}:tracked.txt") == "replacement"
    with pytest.raises(RuntimeError, match="replacement refs"):
        decisions.require_exact_clean_head(root, expected_head)


def test_exact_clean_head_rechecks_nested_untracked_after_raw_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repository"
    nested = root / "nested"
    nested.mkdir(parents=True)
    _git(root, "init")
    _git(root, "config", "user.name", "LegalBot Test")
    _git(root, "config", "user.email", "legalbot@example.invalid")
    (nested / "tracked.txt").write_text("sealed\n", encoding="utf-8")
    _git(root, "add", "nested/tracked.txt")
    _git(root, "commit", "-m", "initial")
    head = _git(root, "rev-parse", "HEAD")
    original = decisions._require_raw_head_worktree

    def mutate_after_raw(*args: Any, **kwargs: Any) -> None:
        original(*args, **kwargs)
        (nested / "late-untracked.txt").write_text("late\n", encoding="utf-8")

    monkeypatch.setattr(decisions, "_require_raw_head_worktree", mutate_after_raw)
    with pytest.raises(RuntimeError, match="worktree changed during raw verification"):
        decisions.require_exact_clean_head(root, head)


def test_exact_clean_head_rechecks_head_after_raw_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init")
    _git(root, "config", "user.name", "LegalBot Test")
    _git(root, "config", "user.email", "legalbot@example.invalid")
    tracked = root / "tracked.txt"
    tracked.write_text("sealed\n", encoding="utf-8")
    _git(root, "add", "tracked.txt")
    _git(root, "commit", "-m", "initial")
    expected_head = _git(root, "rev-parse", "HEAD")
    branch_ref = _git(root, "symbolic-ref", "HEAD")
    tracked.write_text("later\n", encoding="utf-8")
    _git(root, "add", "tracked.txt")
    _git(root, "commit", "-m", "later")
    later_head = _git(root, "rev-parse", "HEAD")
    _git(root, "reset", "--hard", expected_head)
    original = decisions._require_raw_head_worktree

    def move_head_after_raw(*args: Any, **kwargs: Any) -> None:
        original(*args, **kwargs)
        _git(root, "update-ref", branch_ref, later_head)

    monkeypatch.setattr(decisions, "_require_raw_head_worktree", move_head_after_raw)
    with pytest.raises(RuntimeError, match="HEAD changed during raw verification"):
        decisions.require_exact_clean_head(root, expected_head)


def test_exact_clean_head_rechecks_grafts_after_raw_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init")
    _git(root, "config", "user.name", "LegalBot Test")
    _git(root, "config", "user.email", "legalbot@example.invalid")
    (root / "tracked.txt").write_text("sealed\n", encoding="utf-8")
    _git(root, "add", "tracked.txt")
    _git(root, "commit", "-m", "initial")
    head = _git(root, "rev-parse", "HEAD")
    common_directory = Path(_git(root, "rev-parse", "--git-common-dir"))
    if not common_directory.is_absolute():
        common_directory = root / common_directory
    original = decisions._require_raw_head_worktree

    def add_graft_after_raw(*args: Any, **kwargs: Any) -> None:
        original(*args, **kwargs)
        info = common_directory / "info"
        info.mkdir(exist_ok=True)
        (info / "grafts").write_text(f"{head}\n", encoding="ascii")

    monkeypatch.setattr(decisions, "_require_raw_head_worktree", add_graft_after_raw)
    with pytest.raises(RuntimeError, match="graft metadata"):
        decisions.require_exact_clean_head(root, head)


def test_signature_generator_rechecks_head_immediately_before_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    implementation_names = (
        "backend/app/evaluation/all60_qualification.py",
        "backend/app/evaluation/candidate_completion_authority.py",
        "backend/app/evaluation/candidate_completion_preflight.py",
        "backend/app/evaluation/owner_quality_canary_authorization.py",
        "backend/app/evaluation/owner_quality_canary_docx.py",
        "backend/app/evaluation/owner_quality_canary_runtime.py",
        "backend/app/evaluation/owner_quality_normal_live_readiness.py",
        "backend/app/evaluation/owner_quality_v111_promotion.py",
        "backend/app/evaluation/v111_technical_attestation.py",
        "backend/app/governance/owner_stop.py",
        "backend/app/governance/v111_decision_generation.py",
    )
    for name in implementation_names:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(name, encoding="utf-8")
    calls = 0

    def guard(_root: Path, expected: str) -> str:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("tree changed before write")
        return expected

    monkeypatch.setattr(signature_cli, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(signature_cli, "require_exact_clean_head", guard)
    destination = tmp_path / "owner-decisions"
    with pytest.raises(RuntimeError, match="changed before write"):
        signature_cli.main(
            [
                "--integration-sha",
                "d" * 40,
                "--store-root",
                str(destination),
            ]
        )
    assert calls == 2
    assert not destination.exists()


def test_private_root_request_is_path_free_and_self_seal_never_authorizes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    root = tmp_path / "owner-private"
    root.mkdir(mode=0o700)
    root_identity = decisions.private_root_identity(root, project_root=project)
    request = decisions.build_canary_output_privacy_decision_request(
        root_identity_sha256=root_identity,
        runtime_implementation_sha256="a" * 64,
        integration_sha="b" * 40,
        created_at=datetime(2026, 8, 20, 8, 0, tzinfo=UTC),
    )
    serialized = request.model_dump_json()
    assert str(root) not in serialized
    assert [item.option_id for item in request.options] == list(decisions.PRIVACY_DECISION_OPTIONS)
    store_root = tmp_path / "owner-decisions"
    store = OwnerDecisionStore(store_root)
    store.write_request(request)
    resolution = seal_owner_decision_resolution(
        request=request,
        selected_option_id="approve-owner-private-nonsynced-root",
        owner_ref=f"owner:{'c' * 64}",
        decided_at=datetime(2026, 8, 20, 8, 5, tzinfo=UTC),
    )
    store.write_resolution(resolution)
    with pytest.raises(OwnerDecisionRequired) as stopped:
        decisions.load_verified_canary_output_private_root(
            root=root,
            project_root=project,
            owner_decision_root=store_root,
            runtime_implementation_sha256="a" * 64,
            integration_sha="b" * 40,
        )
    assert stopped.value.reason_code == "trusted_canary_output_privacy_verifier_missing"

    monkeypatch.setattr(
        decisions,
        "_verify_trusted_canary_output_privacy_signature",
        lambda _request, _resolution: None,
    )
    verified = decisions.load_verified_canary_output_private_root(
        root=root,
        project_root=project,
        owner_decision_root=store_root,
        runtime_implementation_sha256="a" * 64,
        integration_sha="b" * 40,
    )
    try:
        assert not hasattr(verified, "root")
        assert repr(verified) == "<VerifiedCanaryOutputPrivateRoot>"
        assert verified.root_identity_sha256 == root_identity
        verified.write_create_only(("proof.json",), b"approved\n")
        assert (root / "proof.json").read_bytes() == b"approved\n"
    finally:
        verified.close()


def test_private_root_rejects_ancestor_symlink_and_decision_member_symlink(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    actual = tmp_path / "actual"
    actual.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic links"):
        decisions.private_root_identity(alias, project_root=project)

    root = tmp_path / "owner-decisions"
    store = OwnerDecisionStore(root)
    request = _memory_request()
    request_path = store.write_request(request)
    replacement = tmp_path / "replacement.json"
    replacement.write_bytes(request_path.read_bytes())
    replacement.chmod(0o600)
    request_path.unlink()
    request_path.symlink_to(replacement)
    with pytest.raises(OSError):
        decisions.read_private_owner_decision_member(root, request.decision_id, "request.json")


def test_private_root_requires_current_service_uid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    root = tmp_path / "owner-private"
    root.mkdir(mode=0o700)
    actual_uid = os.getuid()
    monkeypatch.setattr(decisions.os, "getuid", lambda: actual_uid + 1)
    with pytest.raises(ValueError, match="owner private root"):
        decisions.private_root_identity(root, project_root=project)


def test_decision_member_replacement_during_fd_read_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store_root = tmp_path / "owner-decisions"
    request = _memory_request()
    request_path = OwnerDecisionStore(store_root).write_request(request)
    replacement = request_path.parent / "replacement.json"
    replacement.write_bytes(request_path.read_bytes())
    replacement.chmod(0o600)
    original_read = decisions.os.read
    replaced = False

    def replacing_read(descriptor: int, count: int) -> bytes:
        nonlocal replaced
        value = original_read(descriptor, count)
        if not replaced:
            replaced = True
            request_path.rename(request_path.parent / "original.json")
            replacement.rename(request_path)
        return value

    monkeypatch.setattr(decisions.os, "read", replacing_read)
    with pytest.raises(RuntimeError, match="changed during read"):
        decisions.read_private_owner_decision_member(
            store_root, request.decision_id, "request.json"
        )


def test_private_root_replacement_during_signature_verification_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    root_identity = decisions.private_root_identity(root, project_root=project)
    request = decisions.build_canary_output_privacy_decision_request(
        root_identity_sha256=root_identity,
        runtime_implementation_sha256="a" * 64,
        integration_sha="b" * 40,
        created_at=datetime(2026, 8, 20, 8, 0, tzinfo=UTC),
    )
    store_root = tmp_path / "owner-decisions"
    store = OwnerDecisionStore(store_root)
    store.write_request(request)
    store.write_resolution(
        seal_owner_decision_resolution(
            request=request,
            selected_option_id="approve-owner-private-nonsynced-root",
            owner_ref=f"owner:{'c' * 64}",
            decided_at=datetime(2026, 8, 20, 8, 5, tzinfo=UTC),
        )
    )

    def replace_root(_request: object, _resolution: object) -> None:
        root.rename(tmp_path / "private-original")
        root.mkdir(mode=0o700)

    monkeypatch.setattr(
        decisions,
        "_verify_trusted_canary_output_privacy_signature",
        replace_root,
    )
    with pytest.raises(RuntimeError, match="changed during verification"):
        decisions.load_verified_canary_output_private_root(
            root=root,
            project_root=project,
            owner_decision_root=store_root,
            runtime_implementation_sha256="a" * 64,
            integration_sha="b" * 40,
        )


def test_private_root_decision_cannot_replay_after_same_inode_move(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    approved = tmp_path / "approved-location"
    approved.mkdir(mode=0o700)
    root_identity = decisions.private_root_identity(approved, project_root=project)
    request = decisions.build_canary_output_privacy_decision_request(
        root_identity_sha256=root_identity,
        runtime_implementation_sha256="a" * 64,
        integration_sha="b" * 40,
        created_at=datetime(2026, 8, 20, 8, 0, tzinfo=UTC),
    )
    store_root = tmp_path / "owner-decisions"
    store = OwnerDecisionStore(store_root)
    store.write_request(request)
    store.write_resolution(
        seal_owner_decision_resolution(
            request=request,
            selected_option_id="approve-owner-private-nonsynced-root",
            owner_ref=f"owner:{'c' * 64}",
            decided_at=datetime(2026, 8, 20, 8, 5, tzinfo=UTC),
        )
    )
    moved = tmp_path / "different-location"
    approved.rename(moved)
    assert moved.stat().st_ino > 0
    assert decisions.private_root_identity(moved, project_root=project) != root_identity
    monkeypatch.setattr(
        decisions,
        "_verify_trusted_canary_output_privacy_signature",
        lambda _request, _resolution: None,
    )
    with pytest.raises(PermissionError, match="OWNER_DECISION_REQUIRED"):
        decisions.load_verified_canary_output_private_root(
            root=moved,
            project_root=project,
            owner_decision_root=store_root,
            runtime_implementation_sha256="a" * 64,
            integration_sha="b" * 40,
        )


def test_verified_private_root_rejects_replacement_after_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    root_identity = decisions.private_root_identity(root, project_root=project)
    request = decisions.build_canary_output_privacy_decision_request(
        root_identity_sha256=root_identity,
        runtime_implementation_sha256="a" * 64,
        integration_sha="b" * 40,
        created_at=datetime(2026, 8, 20, 8, 0, tzinfo=UTC),
    )
    store_root = tmp_path / "owner-decisions"
    store = OwnerDecisionStore(store_root)
    store.write_request(request)
    store.write_resolution(
        seal_owner_decision_resolution(
            request=request,
            selected_option_id="approve-owner-private-nonsynced-root",
            owner_ref=f"owner:{'c' * 64}",
            decided_at=datetime(2026, 8, 20, 8, 5, tzinfo=UTC),
        )
    )
    monkeypatch.setattr(
        decisions,
        "_verify_trusted_canary_output_privacy_signature",
        lambda _request, _resolution: None,
    )
    verified = decisions.load_verified_canary_output_private_root(
        root=root,
        project_root=project,
        owner_decision_root=store_root,
        runtime_implementation_sha256="a" * 64,
        integration_sha="b" * 40,
    )
    approved_root = tmp_path / "private-approved"
    root.rename(approved_root)
    root.mkdir(mode=0o700)
    try:
        with pytest.raises(RuntimeError, match="changed after verification"):
            verified.write_create_only(("must-not-write.json",), b"private\n")
        assert not (root / "must-not-write.json").exists()
        assert not (approved_root / "must-not-write.json").exists()
    finally:
        verified.close()


def test_verified_private_root_removes_member_when_replaced_during_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    root_identity = decisions.private_root_identity(root, project_root=project)
    request = decisions.build_canary_output_privacy_decision_request(
        root_identity_sha256=root_identity,
        runtime_implementation_sha256="a" * 64,
        integration_sha="b" * 40,
        created_at=datetime(2026, 8, 20, 8, 0, tzinfo=UTC),
    )
    store_root = tmp_path / "owner-decisions"
    store = OwnerDecisionStore(store_root)
    store.write_request(request)
    store.write_resolution(
        seal_owner_decision_resolution(
            request=request,
            selected_option_id="approve-owner-private-nonsynced-root",
            owner_ref=f"owner:{'c' * 64}",
            decided_at=datetime(2026, 8, 20, 8, 5, tzinfo=UTC),
        )
    )
    monkeypatch.setattr(
        decisions,
        "_verify_trusted_canary_output_privacy_signature",
        lambda _request, _resolution: None,
    )
    verified = decisions.load_verified_canary_output_private_root(
        root=root,
        project_root=project,
        owner_decision_root=store_root,
        runtime_implementation_sha256="a" * 64,
        integration_sha="b" * 40,
    )
    approved_root = tmp_path / "private-renamed"
    original_write = decisions.os.write
    replaced = False

    def replace_during_write(descriptor: int, data: object) -> int:
        nonlocal replaced
        written = original_write(descriptor, data)  # type: ignore[arg-type]
        if not replaced:
            replaced = True
            root.rename(approved_root)
            root.mkdir(mode=0o700)
        return written

    monkeypatch.setattr(decisions.os, "write", replace_during_write)
    try:
        with pytest.raises(RuntimeError, match="changed after verification"):
            verified.write_create_only(("must-be-removed.json",), b"private\n")
        assert not (root / "must-be-removed.json").exists()
        assert not (approved_root / "must-be-removed.json").exists()
    finally:
        verified.close()


def test_existing_catalogue_reader_is_nonmutating_and_detects_same_size_change(
    tmp_path: Path,
) -> None:
    data = tmp_path / "data"
    data.mkdir(mode=0o700)
    lock = data / ".catalog-initialize.lock"
    lock.touch(mode=0o600)
    database_path = data / "catalog.sqlite3"
    connection = sqlite3.connect(database_path)
    connection.execute("CREATE TABLE sample(id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
    connection.execute("INSERT INTO sample(value) VALUES ('alpha')")
    connection.commit()
    connection.close()
    database_path.chmod(0o600)
    before = {
        path.name: (path.stat().st_size, path.stat().st_mtime_ns, path.read_bytes())
        for path in data.iterdir()
        if path.is_file()
    }
    reader = open_existing_catalogue_read_database(database_path)
    try:
        row = reader.fetchone("SELECT value FROM sample WHERE id=1")
        assert row is not None and row["value"] == "alpha"
    finally:
        reader.close()
    after = {
        path.name: (path.stat().st_size, path.stat().st_mtime_ns, path.read_bytes())
        for path in data.iterdir()
        if path.is_file()
    }
    assert after == before

    reader = open_existing_catalogue_read_database(database_path)
    try:
        descriptor = os.open(database_path, os.O_RDWR)
        try:
            original = os.pread(descriptor, 1, 100)
            os.pwrite(descriptor, b"Z" if original != b"Z" else b"Y", 100)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        with pytest.raises(RuntimeError, match="identity changed"):
            reader.fetchone("SELECT value FROM sample WHERE id=1")
    finally:
        reader.close()


def test_existing_catalogue_reader_rejects_nonempty_wal(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir(mode=0o700)
    (data / ".catalog-initialize.lock").touch(mode=0o600)
    database_path = data / "catalog.sqlite3"
    connection = sqlite3.connect(database_path)
    connection.execute("CREATE TABLE sample(id INTEGER PRIMARY KEY)")
    connection.commit()
    connection.close()
    database_path.chmod(0o600)
    wal = data / "catalog.sqlite3-wal"
    wal.write_bytes(b"uncheckpointed")
    wal.chmod(0o600)
    with pytest.raises(RuntimeError, match="checkpointed"):
        open_existing_catalogue_read_database(database_path)


def test_existing_catalogue_connect_is_bound_to_pinned_descriptor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = tmp_path / "data"
    data.mkdir(mode=0o700)
    (data / ".catalog-initialize.lock").touch(mode=0o600)
    database_path = data / "catalog.sqlite3"
    replacement_path = data / "replacement.sqlite3"
    for path, value in ((database_path, "approved"), (replacement_path, "replacement")):
        connection = sqlite3.connect(path)
        connection.execute("CREATE TABLE sample(value TEXT NOT NULL)")
        connection.execute("INSERT INTO sample(value) VALUES (?)", (value,))
        connection.commit()
        connection.close()
        path.chmod(0o600)
    displaced_path = data / "displaced.sqlite3"
    original_connect = catalogue_read.sqlite3.connect
    observed: list[str] = []

    def swapping_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        assert str(args[0]).startswith("file:/dev/fd/")
        database_path.rename(displaced_path)
        replacement_path.rename(database_path)
        try:
            connection = original_connect(*args, **kwargs)
            observed.append(str(connection.execute("SELECT value FROM sample").fetchone()[0]))
            return connection
        finally:
            database_path.rename(replacement_path)
            displaced_path.rename(database_path)

    monkeypatch.setattr(catalogue_read.sqlite3, "connect", swapping_connect)
    with pytest.raises(RuntimeError, match="identity changed"):
        open_existing_catalogue_read_database(database_path)
    assert observed == ["approved"]


def test_shared_signature_choice_has_no_caller_authored_verification_claim() -> None:
    source = Path(signature_cli.__file__).read_text(encoding="utf-8")
    assert "verification-sha256" not in source
    assert "FOCUSED_SECURITY_TESTS_PASSED" not in source
    assert "BOOTSTRAP_POLICY_SELECTION_NOT_TECHNICAL_READINESS" in source


def test_privacy_request_json_has_only_safe_identity_not_original_path(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    request = decisions.build_canary_output_privacy_decision_request(
        root_identity_sha256=decisions.private_root_identity(root, project_root=project),
        runtime_implementation_sha256="1" * 64,
        integration_sha="2" * 40,
        created_at=datetime.now(UTC),
    )
    payload = json.loads(request.model_dump_json())
    assert str(root) not in json.dumps(payload)
    assert payload["options"][0]["option_id"] == "approve-owner-private-nonsynced-root"
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
