"""Complete, replayable scorer-closure identities for retrieval re-attestation."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from .retrieval_v1 import SCORER_IMPLEMENTATION_FILES

SCORER_CLOSURE_SCHEMA = "legalbot.scorer-closure-manifest.v1"
SCORER_CLOSURE_MEMBER_SET_SCHEMA = "legalbot.scorer-closure-member-set.v1"
SCORER_CLOSURE_ROOT_MODULES = (
    "app.retrieval.retrieval_v1",
    "app.retrieval.retrieval_reattest",
)
STATIC_CLOSURE_MEMBERS = (
    ("benchmarks/retrieval/v1.1.jsonl", "evaluation_input"),
    ("benchmarks/retrieval/v1.1.freeze.json", "evaluation_input"),
    ("benchmarks/retrieval/v1.1.AMENDMENT-DIFF.json", "evaluation_input"),
    ("benchmarks/retrieval/v1.1.FACT-CHECK.json", "evaluation_input"),
    ("benchmarks/retrieval/v1.1.OWNER-DECISION.json", "evaluation_input"),
    ("config/policy.yaml", "evaluator_configuration"),
    ("config/retrieval_policy.yaml", "evaluator_configuration"),
    (".python-version", "runtime_selector"),
    ("pyproject.toml", "dependency_configuration"),
    ("uv.lock", "dependency_lock"),
)
OPTIONAL_STATIC_CLOSURE_MEMBERS = (
    ("config/candidate_provision_qualification.v1.json", "evaluation_input"),
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40,64}$")


class ClosureReader(Protocol):
    def read(self, relative: str) -> bytes: ...

    def exists(self, relative: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class ScorerClosureReference:
    manifest_path: str
    manifest_file_sha256: str
    manifest_sha256: str
    aggregate_sha256: str
    member_count: int
    integration_commit: str
    integration_tree: str

    def safe_dict(self) -> dict[str, Any]:
        return {
            "schema": "legalbot.scorer-closure-reference.v1",
            "manifest_path": self.manifest_path,
            "manifest_file_sha256": self.manifest_file_sha256,
            "manifest_sha256": self.manifest_sha256,
            "aggregate_sha256": self.aggregate_sha256,
            "member_count": self.member_count,
            "integration_commit": self.integration_commit,
            "integration_tree": self.integration_tree,
        }


@dataclass(frozen=True, slots=True)
class WorktreeReader:
    root: Path

    def read(self, relative: str) -> bytes:
        path = self.root / relative
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("scorer closure member is missing or unsafe")
        return path.read_bytes()

    def exists(self, relative: str) -> bool:
        path = self.root / relative
        return not path.is_symlink() and path.is_file()


@dataclass(frozen=True, slots=True)
class GitReader:
    root: Path
    revision: str

    def read(self, relative: str) -> bytes:
        completed = subprocess.run(
            ["git", "show", f"{self.revision}:{relative}"],
            cwd=self.root,
            check=False,
            capture_output=True,
            shell=False,
        )
        if completed.returncode != 0:
            raise RuntimeError("historical scorer closure member is unavailable")
        return completed.stdout

    def exists(self, relative: str) -> bool:
        return (
            subprocess.run(
                ["git", "cat-file", "-e", f"{self.revision}:{relative}"],
                cwd=self.root,
                check=False,
                capture_output=True,
                shell=False,
            ).returncode
            == 0
        )


def _module_candidates(module: str) -> tuple[str, str]:
    if module == "app":
        return "backend/app/__init__.py", "backend/app.py"
    if not module.startswith("app."):
        return "", ""
    suffix = module.removeprefix("app.").replace(".", "/")
    return f"backend/app/{suffix}.py", f"backend/app/{suffix}/__init__.py"


def _resolve_module(reader: ClosureReader, module: str) -> str | None:
    for candidate in _module_candidates(module):
        if candidate and reader.exists(candidate):
            return candidate
    return None


def _module_name(relative: str) -> tuple[str, bool]:
    path = PurePosixPath(relative)
    parts = list(path.with_suffix("").parts)
    if parts[:2] != ["backend", "app"]:
        raise ValueError("scorer closure Python member is outside backend/app")
    module_parts = ["app", *parts[2:]]
    is_package = module_parts[-1:] == ["__init__"]
    if is_package:
        module_parts.pop()
    return ".".join(module_parts), is_package


def _imported_local_modules(reader: ClosureReader, relative: str) -> tuple[str, ...]:
    raw = reader.read(relative)
    tree = ast.parse(raw, filename=relative)
    module, is_package = _module_name(relative)
    package_parts = module.split(".") if is_package else module.split(".")[:-1]
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names if alias.name.startswith("app"))
            continue
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.level:
            trim = node.level - 1
            if trim > len(package_parts):
                continue
            base_parts = package_parts[: len(package_parts) - trim]
            if node.module:
                base_parts.extend(node.module.split("."))
            base = ".".join(base_parts)
        else:
            base = node.module or ""
        if base.startswith("app"):
            imports.add(base)
            for alias in node.names:
                candidate = f"{base}.{alias.name}"
                if _resolve_module(reader, candidate) is not None:
                    imports.add(candidate)
    return tuple(sorted(imports))


def discover_python_closure(reader: ClosureReader) -> tuple[str, ...]:
    pending = list(SCORER_CLOSURE_ROOT_MODULES)
    visited_modules: set[str] = set()
    members: set[str] = set()
    while pending:
        module = pending.pop()
        if module in visited_modules:
            continue
        visited_modules.add(module)
        relative = _resolve_module(reader, module)
        if relative is None:
            continue
        members.add(relative)
        pending.extend(_imported_local_modules(reader, relative))
    return tuple(sorted(members))


def _member(relative: str, kind: str, raw: bytes) -> dict[str, Any]:
    return {
        "path": relative,
        "kind": kind,
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _legacy_scorer_digest(reader: ClosureReader) -> str:
    digest = hashlib.sha256()
    for relative in SCORER_IMPLEMENTATION_FILES:
        encoded = relative.encode("utf-8")
        payload = reader.read(relative)
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def build_closure(
    reader: ClosureReader,
    *,
    revision: str,
    tree: str,
    python_runtime: Mapping[str, Any],
) -> dict[str, Any]:
    members = [
        _member(relative, "python_dependency", reader.read(relative))
        for relative in discover_python_closure(reader)
    ]
    members.extend(
        _member(relative, kind, reader.read(relative)) for relative, kind in STATIC_CLOSURE_MEMBERS
    )
    members.extend(
        _member(relative, kind, reader.read(relative))
        for relative, kind in OPTIONAL_STATIC_CLOSURE_MEMBERS
        if reader.exists(relative)
    )
    members.sort(key=lambda item: str(item["path"]))
    aggregate = {
        "schema": SCORER_CLOSURE_MEMBER_SET_SCHEMA,
        "revision": revision,
        "tree": tree,
        "members": members,
        "python_runtime": dict(python_runtime),
    }
    return {
        "revision": revision,
        "tree": tree,
        "member_count": len(members),
        "members": members,
        "python_runtime": dict(python_runtime),
        "legacy_scorer_implementation_sha256": _legacy_scorer_digest(reader),
        "aggregate_sha256": hashlib.sha256(
            (json.dumps(aggregate, sort_keys=True, separators=(",", ":")) + "\n").encode()
        ).hexdigest(),
    }


def _git(project_root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=project_root,
        check=False,
        capture_output=True,
        text=True,
        shell=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("scorer closure Git observation failed")
    return completed.stdout.strip()


def _file_sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("scorer closure runtime executable is unsafe")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _current_python_runtime() -> dict[str, Any]:
    return {
        "binding_state": "bound",
        "version": sys.version.split()[0],
        "implementation": sys.implementation.name,
        "executable_sha256": _file_sha256(Path(sys.executable).resolve()),
    }


def load_scorer_closure_reference(
    *,
    project_root: Path,
    manifest_path: Path,
    require_current: bool,
    expected_head: str | None = None,
    expected_legacy_digest: str | None = None,
) -> ScorerClosureReference:
    """Strictly load a closure reference and optionally replay it on the current HEAD."""

    root = project_root.resolve()
    allowed_root = (root / "data/evaluations/retrieval").resolve()
    path = manifest_path.resolve()
    if not path.is_relative_to(allowed_root) or path.is_symlink() or not path.is_file():
        raise RuntimeError("scorer closure manifest path is unsafe")
    observed = path.stat(follow_symlinks=False)
    if (
        observed.st_uid != os.getuid()
        or stat.S_IMODE(observed.st_mode) != 0o600
        or observed.st_nlink != 1
    ):
        raise RuntimeError("scorer closure manifest must be one private owner file")
    raw = path.read_bytes()
    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("scorer closure manifest is invalid JSON") from exc
    if not isinstance(manifest, dict):
        raise RuntimeError("scorer closure manifest must be an object")
    claimed_manifest_sha256 = str(manifest.get("manifest_sha256") or "")
    material = dict(manifest)
    material.pop("manifest_sha256", None)
    calculated_manifest_sha256 = hashlib.sha256(
        (json.dumps(material, sort_keys=True, separators=(",", ":")) + "\n").encode()
    ).hexdigest()
    baseline = manifest.get("integration_baseline_closure")
    if (
        manifest.get("schema") != SCORER_CLOSURE_SCHEMA
        or manifest.get("authorizing") is not False
        or not isinstance(baseline, dict)
        or claimed_manifest_sha256 != calculated_manifest_sha256
        or _SHA256.fullmatch(claimed_manifest_sha256) is None
    ):
        raise RuntimeError("scorer closure manifest seal is invalid")
    commit = str(manifest.get("integration_baseline_commit") or "")
    tree = str(manifest.get("integration_baseline_tree") or "")
    aggregate = str(baseline.get("aggregate_sha256") or "")
    legacy_digest = str(baseline.get("legacy_scorer_implementation_sha256") or "")
    member_count = baseline.get("member_count")
    if (
        _GIT_SHA.fullmatch(commit) is None
        or _GIT_SHA.fullmatch(tree) is None
        or _SHA256.fullmatch(aggregate) is None
        or _SHA256.fullmatch(legacy_digest) is None
        or isinstance(member_count, bool)
        or not isinstance(member_count, int)
        or member_count <= 0
        or baseline.get("revision") != commit
        or baseline.get("tree") != tree
    ):
        raise RuntimeError("scorer closure manifest binding is invalid")
    if expected_head is not None and commit != expected_head:
        raise RuntimeError("scorer closure manifest is bound to a different HEAD")
    if expected_legacy_digest is not None and legacy_digest != expected_legacy_digest:
        raise RuntimeError("scorer closure manifest legacy scorer binding differs")
    if require_current:
        if _git(root, "status", "--porcelain=v2", "--untracked-files=all"):
            raise RuntimeError("current scorer closure replay requires an exact clean HEAD")
        current_head = _git(root, "rev-parse", "HEAD")
        current_tree = _git(root, "rev-parse", "HEAD^{tree}")
        if current_head != commit or current_tree != tree:
            raise RuntimeError("current scorer closure Git identity differs")
        current = build_closure(
            WorktreeReader(root),
            revision=current_head,
            tree=current_tree,
            python_runtime=_current_python_runtime(),
        )
        if current != baseline:
            raise RuntimeError("current scorer closure replay differs from its manifest")
    return ScorerClosureReference(
        manifest_path=str(path.relative_to(root)),
        manifest_file_sha256=hashlib.sha256(raw).hexdigest(),
        manifest_sha256=claimed_manifest_sha256,
        aggregate_sha256=aggregate,
        member_count=member_count,
        integration_commit=commit,
        integration_tree=tree,
    )


def find_legacy_digest_revisions(project_root: Path, target_digest: str) -> tuple[str, ...]:
    if _SHA256.fullmatch(target_digest) is None:
        raise ValueError("legacy scorer digest is invalid")
    revisions = _git(project_root, "rev-list", "--all").splitlines()
    matches: list[str] = []
    for revision in revisions:
        reader = GitReader(project_root, revision)
        if any(not reader.exists(relative) for relative in SCORER_IMPLEMENTATION_FILES):
            continue
        if _legacy_scorer_digest(reader) == target_digest:
            matches.append(revision)
    return tuple(matches)


def build_scorer_closure_manifest(
    *,
    project_root: Path,
    legacy_attestation_path: Path,
    expected_head: str,
) -> dict[str, Any]:
    root = project_root.resolve()
    head = _git(root, "rev-parse", "HEAD")
    tree = _git(root, "rev-parse", "HEAD^{tree}")
    if (
        head != expected_head
        or _GIT_SHA.fullmatch(head) is None
        or _GIT_SHA.fullmatch(tree) is None
    ):
        raise RuntimeError("scorer closure is not bound to the expected integration baseline")
    if _git(root, "status", "--porcelain=v2", "--untracked-files=all"):
        raise RuntimeError("scorer closure requires an exact clean integration baseline")
    legacy_raw = legacy_attestation_path.read_bytes()
    legacy_attestation = json.loads(legacy_raw)
    if not isinstance(legacy_attestation, dict):
        raise RuntimeError("legacy retrieval attestation is invalid")
    legacy_digest = str(legacy_attestation.get("scorer_implementation_sha256") or "")
    if _SHA256.fullmatch(legacy_digest) is None:
        raise RuntimeError("legacy retrieval attestation scorer digest is invalid")
    matches = find_legacy_digest_revisions(root, legacy_digest)
    reconstructed: dict[str, Any]
    if len(matches) == 1:
        revision = matches[0]
        reconstructed = build_closure(
            GitReader(root, revision),
            revision=revision,
            tree=_git(root, "rev-parse", f"{revision}^{{tree}}"),
            python_runtime={"binding_state": "unbound-by-legacy-attestation"},
        )
        reconstruction_status = "implementation-reconstructed-runtime-unbound"
    else:
        reconstructed = {
            "revision_matches": list(matches),
            "match_count": len(matches),
            "aggregate_sha256": None,
        }
        reconstruction_status = "unavailable" if not matches else "ambiguous"
    baseline = build_closure(
        WorktreeReader(root),
        revision=head,
        tree=tree,
        python_runtime=_current_python_runtime(),
    )
    legacy_complete_closure_bound = False
    equivalence_proven = bool(
        reconstruction_status == "implementation-reconstructed-runtime-unbound"
        and reconstructed.get("aggregate_sha256") == baseline["aggregate_sha256"]
        and legacy_complete_closure_bound
    )
    manifest: dict[str, Any] = {
        "schema": SCORER_CLOSURE_SCHEMA,
        "authorizing": False,
        "integration_baseline_commit": head,
        "integration_baseline_tree": tree,
        "legacy_attestation": {
            "path": str(legacy_attestation_path.relative_to(root)),
            "file_sha256": hashlib.sha256(legacy_raw).hexdigest(),
            "scorer_implementation_sha256": legacy_digest,
            "complete_closure_bound": legacy_complete_closure_bound,
        },
        "historical_reconstruction": {
            "status": reconstruction_status,
            **reconstructed,
        },
        "integration_baseline_closure": baseline,
        "equivalence_proven": equivalence_proven,
        "reattestation_required": not equivalence_proven,
        "reattestation_reason_codes": [
            "legacy_attestation_does_not_bind_complete_closure",
            "historical_passing_runtime_not_bound",
            *(["historical_passing_implementation_not_reconstructable"] if not matches else []),
        ],
        "active_written": False,
        "promotion_executed": False,
        "answer_model_invoked": False,
    }
    manifest["manifest_sha256"] = hashlib.sha256(
        (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    ).hexdigest()
    return manifest


def write_create_only_scorer_closure_manifest(path: Path, manifest: Mapping[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    raw = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise RuntimeError("scorer closure manifest permissions are unsafe")
