#!/usr/bin/env python3
"""Prepare one isolated reviewed-research consumer without writing ACTIVE."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from backend.app.config import Settings
from backend.app.contracts.schema_registry import canonical_json_bytes, load_json_strict
from backend.app.db import Database
from backend.app.retrieval.reviewed_research_generation import (
    SCHEMA,
    register_scoped_development_retrieval_candidate,
    seal_reviewed_research_consumer_manifest,
)


def _file_entry(root: Path, value: str) -> dict[str, Any]:
    path = Path(value).resolve()
    if not path.is_file() or not path.is_relative_to(root):
        raise ValueError(f"input is not a workspace file: {value}")
    return {
        "path": str(path.relative_to(root)),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _source(value: str) -> dict[str, str]:
    fields = value.split("|", 5)
    if len(fields) != 6:
        raise ValueError(
            "--source requires capture_sha|source_sha|identity|title|url|source_type"
        )
    return dict(
        zip(
            (
                "capture_sha256",
                "source_sha256",
                "source_identity_id",
                "title",
                "canonical_url",
                "source_type",
            ),
            fields,
            strict=True,
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-id", required=True)
    parser.add_argument("--candidate-build-id", required=True)
    parser.add_argument("--generation", required=True)
    parser.add_argument("--prepared-build", required=True)
    parser.add_argument("--complete-context", required=True)
    parser.add_argument("--retrieval", action="append", required=True)
    parser.add_argument("--source", action="append", required=True)
    parser.add_argument("--subject", required=True)
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    base_settings = Settings(
        project_root=root,
        development_state_id=args.state_id,
        development_candidate_build_id=args.candidate_build_id,
    )
    generation_entry = _file_entry(root, args.generation)
    generation = load_json_strict((root / generation_entry["path"]).read_bytes())
    prepared_entry = _file_entry(root, args.prepared_build)
    context_entry = _file_entry(root, args.complete_context)
    context = load_json_strict((root / context_entry["path"]).read_bytes())
    if not isinstance(generation, dict) or not isinstance(context, list):
        raise ValueError("generation or complete context is invalid")
    generation_entry.update(
        {
            "build_sha256": generation.get("build_sha256"),
            "generation_sha256": generation.get("generation_sha256"),
        }
    )
    context_entry["row_count"] = len(context)
    prepared = load_json_strict((root / prepared_entry["path"]).read_bytes())
    if not isinstance(prepared, dict) or not prepared.get("reviews"):
        raise ValueError("prepared build has no review bindings")
    review_seals = {
        str(item.get("actual_review_attestation_sha256") or "")
        for item in prepared["reviews"]
    }
    if len(review_seals) != 1:
        raise ValueError("prepared build has no single review attestation")
    runtime_path = (
        root / "backend/app/retrieval/reviewed_research_generation.py"
    )
    manifest = seal_reviewed_research_consumer_manifest(
        {
            "schema": SCHEMA,
            "candidate_build_id": args.candidate_build_id,
            "adapter_runtime_sha256": hashlib.sha256(runtime_path.read_bytes()).hexdigest(),
            "source_review_attestation_sha256": review_seals.pop(),
            "jurisdiction": generation["lineage"]["jurisdiction"],
            "as_of_date": generation["lineage"]["as_of_date"],
            "subject": args.subject,
            "generation": generation_entry,
            "prepared_build": prepared_entry,
            "complete_context": context_entry,
            "retrievals": [_file_entry(root, value) for value in args.retrieval],
            "sources": [_source(value) for value in args.source],
            "production_admitted": False,
            "writes_active": False,
        }
    )
    base_settings.development_authority_path.parent.mkdir(parents=True, exist_ok=True)
    output = base_settings.development_retrieval_manifest_path
    raw = canonical_json_bytes(manifest)
    if output.exists() and output.read_bytes() != raw:
        raise RuntimeError("a different development retrieval manifest already exists")
    output.write_bytes(raw)
    output.chmod(0o600)
    manifest_sha256 = hashlib.sha256(raw).hexdigest()
    settings = Settings(
        project_root=root,
        development_state_id=args.state_id,
        development_candidate_build_id=args.candidate_build_id,
        development_retrieval_manifest_sha256=manifest_sha256,
    )
    settings.ensure_runtime_dirs()
    database = Database(settings.database_path)
    database.initialize()
    try:
        row_count = register_scoped_development_retrieval_candidate(settings, database)
    finally:
        database.close()
    print(
        json.dumps(
            {
                "candidate_build_id": args.candidate_build_id,
                "manifest_path": str(output.relative_to(root)),
                "manifest_sha256": manifest_sha256,
                "retrieved_row_count": row_count,
                "active_written": False,
                "production_admitted": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
