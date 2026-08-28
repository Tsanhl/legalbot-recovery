from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path

import pytest

from app.retrieval.scorer_closure import (
    SCORER_CLOSURE_MEMBER_SET_SCHEMA,
    SCORER_CLOSURE_ROOT_MODULES,
    build_closure,
    discover_python_closure,
    load_scorer_closure_reference,
    write_create_only_scorer_closure_manifest,
)


class MemoryReader:
    def __init__(self, members: dict[str, bytes]) -> None:
        self.members = members

    def read(self, relative: str) -> bytes:
        return self.members[relative]

    def exists(self, relative: str) -> bool:
        return relative in self.members


def _members() -> dict[str, bytes]:
    members = {
        "backend/app/retrieval/retrieval_v1.py": (
            b"from .matching import normalize\nSCORER_IMPLEMENTATION_FILES = ()\n"
        ),
        "backend/app/retrieval/retrieval_reattest.py": (
            b"from app.retrieval.retrieval_v1 import SCORER_IMPLEMENTATION_FILES\n"
        ),
        "backend/app/retrieval/matching.py": b"def normalize(value: str) -> str:\n    return value\n",
    }
    static_paths = (
        "benchmarks/retrieval/v1.1.jsonl",
        "benchmarks/retrieval/v1.1.freeze.json",
        "benchmarks/retrieval/v1.1.AMENDMENT-DIFF.json",
        "benchmarks/retrieval/v1.1.FACT-CHECK.json",
        "benchmarks/retrieval/v1.1.OWNER-DECISION.json",
        "config/policy.yaml",
        "config/retrieval_policy.yaml",
        ".python-version",
        "pyproject.toml",
        "uv.lock",
    )
    members.update({path: f"fixture:{path}\n".encode() for path in static_paths})
    return members


def test_discovery_is_recursive_case_agnostic_and_root_bound() -> None:
    closure = discover_python_closure(MemoryReader(_members()))
    assert SCORER_CLOSURE_ROOT_MODULES == (
        "app.retrieval.retrieval_v1",
        "app.retrieval.retrieval_reattest",
    )
    assert closure == (
        "backend/app/retrieval/matching.py",
        "backend/app/retrieval/retrieval_reattest.py",
        "backend/app/retrieval/retrieval_v1.py",
    )
    assert all("q31" not in path.casefold() for path in closure)


def test_aggregate_changes_when_an_imported_dependency_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "app.retrieval.scorer_closure.SCORER_IMPLEMENTATION_FILES",
        ("backend/app/retrieval/retrieval_v1.py",),
    )
    members = _members()
    first = build_closure(
        MemoryReader(members),
        revision="a" * 40,
        tree="b" * 40,
        python_runtime={"binding_state": "bound", "version": "3.13.7"},
    )
    members["backend/app/retrieval/matching.py"] += b"# changed\n"
    second = build_closure(
        MemoryReader(members),
        revision="a" * 40,
        tree="b" * 40,
        python_runtime={"binding_state": "bound", "version": "3.13.7"},
    )
    assert first["aggregate_sha256"] != second["aggregate_sha256"]
    aggregate = {
        "schema": SCORER_CLOSURE_MEMBER_SET_SCHEMA,
        "revision": first["revision"],
        "tree": first["tree"],
        "members": first["members"],
        "python_runtime": first["python_runtime"],
    }
    expected = hashlib.sha256(
        (json.dumps(aggregate, sort_keys=True, separators=(",", ":")) + "\n").encode()
    ).hexdigest()
    assert first["aggregate_sha256"] == expected


def test_manifest_write_is_scoped_by_caller_create_only_and_private(tmp_path: Path) -> None:
    target = tmp_path / "closure.json"
    manifest = {"schema": "legalbot.scorer-closure-manifest.v1", "authorizing": False}
    write_create_only_scorer_closure_manifest(target, manifest)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert json.loads(target.read_bytes()) == manifest
    with pytest.raises(FileExistsError):
        write_create_only_scorer_closure_manifest(target, manifest)


def test_private_manifest_reference_verifies_its_seal_and_exact_binding(tmp_path: Path) -> None:
    target = tmp_path / "data/evaluations/retrieval/candidate/closure.json"
    baseline = {
        "revision": "a" * 40,
        "tree": "b" * 40,
        "aggregate_sha256": "c" * 64,
        "legacy_scorer_implementation_sha256": "d" * 64,
        "member_count": 3,
    }
    manifest = {
        "schema": "legalbot.scorer-closure-manifest.v1",
        "authorizing": False,
        "integration_baseline_commit": "a" * 40,
        "integration_baseline_tree": "b" * 40,
        "integration_baseline_closure": baseline,
    }
    manifest["manifest_sha256"] = hashlib.sha256(
        (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    ).hexdigest()
    write_create_only_scorer_closure_manifest(target, manifest)

    reference = load_scorer_closure_reference(
        project_root=tmp_path,
        manifest_path=target,
        require_current=False,
        expected_head="a" * 40,
        expected_legacy_digest="d" * 64,
    )

    assert reference.aggregate_sha256 == "c" * 64
    assert reference.manifest_path == "data/evaluations/retrieval/candidate/closure.json"
    assert reference.safe_dict()["integration_tree"] == "b" * 40
    with pytest.raises(RuntimeError, match="different HEAD"):
        load_scorer_closure_reference(
            project_root=tmp_path,
            manifest_path=target,
            require_current=False,
            expected_head="e" * 40,
        )
