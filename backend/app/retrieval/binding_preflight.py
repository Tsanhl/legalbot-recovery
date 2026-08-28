"""Zero-query production preflight for Frozen Retrieval v1.1 candidate binding."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any

from ..config import Settings
from ..db import utc_iso
from .retrieval_v1 import (
    bind_retrieval_rows_to_candidate,
    load_retrieval_v1_jsonl,
    verify_owner_freeze,
)

SCHEMA = "legalbot.retrieval-binding-preflight.v1"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _git(settings: Settings, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=settings.project_root,
        check=True,
        capture_output=True,
        text=True,
        shell=False,
    )
    return completed.stdout.strip()


def _seal(value: dict[str, Any]) -> dict[str, Any]:
    sealed = dict(value)
    sealed["seal_sha256"] = _sha256(
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()
    )
    return sealed


def run_binding_preflight(settings: Settings, *, build_id: str) -> dict[str, Any]:
    """Bind all frozen rows without constructing a retriever or model provider."""

    if os.environ.get("LEGALBOT_TEST_MODE") is not None:
        raise RuntimeError("LEGALBOT_TEST_MODE must be absent for production binding preflight")
    benchmark = settings.project_root / "benchmarks" / "retrieval" / "v1.1.jsonl"
    freeze = verify_owner_freeze(settings.project_root, benchmark)
    rows = load_retrieval_v1_jsonl(benchmark, str(freeze["jsonl_sha256"]))
    build_path = settings.index_dir / "builds" / build_id
    bound, binding = bind_retrieval_rows_to_candidate(
        build_path,
        rows,
        build_id=build_id,
        benchmark_sha256=str(freeze["jsonl_sha256"]),
        project_root=settings.project_root,
    )
    manifest_raw = (build_path / "manifest.json").read_bytes()
    seal_raw = (build_path / "seal.json").read_bytes()
    seal = json.loads(seal_raw)
    if len(bound) != 24 or binding.get("status") != "bound" or binding.get("issues") != []:
        raise RuntimeError("candidate binding preflight did not bind all frozen cases")
    return _seal(
        {
            "schema": SCHEMA,
            "created_at": utc_iso(),
            "status": "passed",
            "authorizing": False,
            "retrieval_query_count": 0,
            "answer_model_invoked": False,
            "production_configuration": True,
            "legalbot_test_mode_present": False,
            "integration_commit": _git(settings, "rev-parse", "HEAD"),
            "integration_tree": _git(settings, "rev-parse", "HEAD^{tree}"),
            "worktree_diff_sha256": _sha256(
                subprocess.run(
                    ["git", "diff", "--binary", "HEAD"],
                    cwd=settings.project_root,
                    check=True,
                    capture_output=True,
                    shell=False,
                ).stdout
            ),
            "candidate": {
                "build_id": build_id,
                "manifest_file_sha256": _sha256(manifest_raw),
                "seal_file_sha256": _sha256(seal_raw),
                "lance_tree_sha256": seal.get("lance_tree_sha256"),
                "source_manifest_file_sha256": seal.get("source_manifest_file_sha256"),
                "embedded_provision_registry_sha256": seal.get("provision_verification_sha256"),
            },
            "suite": {
                "identity": "Frozen Retrieval v1.1",
                "row_count": len(rows),
                "bound_row_count": len(bound),
                "case_ids": [str(row["id"]) for row in rows],
                "benchmark_sha256": freeze["jsonl_sha256"],
                "freeze_manifest_sha256": _sha256(
                    (
                        settings.project_root / "benchmarks" / "retrieval" / "v1.1.freeze.json"
                    ).read_bytes()
                ),
            },
            "binding": binding,
        }
    )


def write_new_report(path: Path, report: dict[str, Any]) -> None:
    """Persist canonical evidence without overwriting an existing identity."""

    if path.exists():
        raise RuntimeError("refusing to overwrite binding-preflight evidence")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        (json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode()
    )
