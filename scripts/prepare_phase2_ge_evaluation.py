#!/usr/bin/env python3
"""Prepare the exact 331-case visible GE factual-first review harness.

This command never opens unseen question content, invokes a model, runs an
evaluation, creates training data, promotes a candidate or deletes anything.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.contracts import ContractSchemaRegistry, canonical_json_bytes  # noqa: E402
from app.evaluation.ge_visible_harness import (  # noqa: E402
    VisibleGEPack,
    policy_documents,
)

DEFAULT_SOURCE = (
    ROOT
    / "data/evaluations/general-enquiries/LegalBot-GE-2026-09-01-review-r3"
)
DEFAULT_OUTPUT = (
    ROOT
    / "data/evaluations/general-enquiries/LegalBot-Phase2-2026-09-01"
)


def _write_new(path: Path, payload: bytes, *, mode: int = 0o600) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode() + b"\n"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def prepare(source: Path, output: Path) -> dict[str, Any]:
    source = source.resolve(strict=True)
    output = output.absolute()
    allowed_parent = (ROOT / "data/evaluations/general-enquiries").resolve(strict=True)
    if output.parent.resolve(strict=True) != allowed_parent or output.exists():
        raise ValueError("output must be one new direct child of the GE evaluation directory")
    pack = VisibleGEPack.load(source)
    registry = ContractSchemaRegistry.from_project_root(ROOT)
    factual_policy, quality_policy = policy_documents()
    output.mkdir(mode=0o700)
    output.chmod(0o700)
    factual_path = output / "GE-FACTUAL-GATE-POLICY.json"
    quality_path = output / "GE-QUALITY-GATE-POLICY.json"
    worksheet_path = output / "GE-331-REVIEW-WORKSHEET.jsonl"
    _write_new(factual_path, _json_bytes(factual_policy))
    _write_new(quality_path, _json_bytes(quality_policy))
    worksheets = pack.review_worksheet()
    _write_new(
        worksheet_path,
        b"".join(canonical_json_bytes(record) for record in worksheets),
    )
    blockers = [
        {
            "code": "NON_ACTIVE_RETRIEVAL_CANDIDATE_MISSING",
            "owner_input_required": False,
            "resolution": "Build and qualify one new non-ACTIVE candidate after retrieval repair.",
        },
        {
            "code": "ANSWER_MODEL_ARTIFACT_AND_TRANSPORT_CAPABILITY_MISSING",
            "owner_input_required": True,
            "resolution": "Owner supplies the exact model-transport capability and approved model artifact.",
        },
        {
            "code": "VISIBLE_CASE_GOLD_AND_CURRENTNESS_DECISIONS_MISSING",
            "owner_input_required": True,
            "resolution": "Qualified legal review supplies exact case-level gold/currentness decisions.",
        },
        {
            "code": "DEVELOPMENT_REVIEW_ROOT_CAPABILITY_MISSING",
            "owner_input_required": True,
            "resolution": "Owner supplies a distinct private Development review root.",
        },
        {
            "code": "EVALUATION_EXECUTION_AUTHORITY_MISSING",
            "owner_input_required": True,
            "resolution": "Bind the final candidate, runtime, policies, denominator and resource envelope.",
        },
    ]
    preflight: dict[str, Any] = {
        "schema": "legalbot.ge-visible-evaluation-preflight.v1",
        "authorizing": False,
        "run_name": output.name,
        "source_pack": {
            "run_id": pack.run_id,
            "content_version": pack.content_version,
            "pack_manifest_sha256": pack.pack_manifest_sha256,
            "source_file_sha256": pack.source_file_sha256,
        },
        "denominator": {
            "visible_case_count": len(pack.cases),
            "core": 306,
            "stress": 25,
            "missing_or_deleted": 0,
            "system_scenarios_separate": 32,
            "unseen_opened": False,
            "unseen_used": False,
        },
        "identities": {
            "schema_selection_sha256": registry.manifest_sha256,
            "case_manifest_sha256": pack.case_manifest_sha256,
            "case_order_sha256": pack.case_order_sha256,
            "input_projection_sha256": pack.input_projection_sha256,
            "factual_gate_policy_sha256": factual_policy["content_sha256"],
            "quality_gate_policy_sha256": quality_policy["content_sha256"],
        },
        "gate_order": [
            "CASE_AND_RUNTIME_IDENTITY",
            "FACTUAL_LEGAL_HARD_GATE",
            "GENERAL_ENQUIRY_70_PLUS_QUALITY_GATE",
            "ROOT_CAUSE_CLASSIFICATION",
            "OWNER_READABLE_REVIEW",
        ],
        "preparation_ready": True,
        "execution_ready": False,
        "blockers": blockers,
        "actions_performed": {
            "visible_pack_verified": True,
            "worksheet_created": True,
            "model_invoked": False,
            "evaluation_run": False,
            "training_export_created": False,
            "training_run": False,
            "unseen_opened": False,
            "promotion_run": False,
            "live_run": False,
            "deletion_performed": False,
        },
    }
    preflight["content_sha256"] = hashlib.sha256(canonical_json_bytes(preflight)).hexdigest()
    preflight_path = output / "GE-EVALUATION-PREFLIGHT.json"
    _write_new(preflight_path, _json_bytes(preflight))
    readme = """# Phase 2 visible GE evaluation preparation

This directory binds the accepted `GE-visible-r3` set of 331 cases to a
factual-first review worksheet. All 331 cases remain in the denominator. The
32 synthetic system scenarios remain separate.

The factual/legal gate runs before quality. A factual hold receives no quality
score. The quality policy adapts the reviewed 70+ law-assessment standard to a
plain-language, practical General Enquiry response.

This preparation did not open unseen prompts, run an answer model, execute an
evaluation, create training data, promote a candidate, activate live or delete
anything. `GE-EVALUATION-PREFLIGHT.json` lists the remaining exact gates.
"""
    _write_new(output / "README.md", readme.encode())
    artifacts = []
    for path in sorted(output.iterdir()):
        if path.is_file():
            artifacts.append({"path": path.name, "sha256": _sha256(path), "size": path.stat().st_size})
    manifest = {
        "schema": "legalbot.ge-visible-evaluation-preparation-manifest.v1",
        "authorizing": False,
        "run_name": output.name,
        "case_count": len(pack.cases),
        "case_manifest_sha256": pack.case_manifest_sha256,
        "case_order_sha256": pack.case_order_sha256,
        "artifacts": artifacts,
        "model_run": False,
        "evaluation_run": False,
        "training_run": False,
        "unseen_opened": False,
        "deletion_performed": False,
    }
    manifest["content_sha256"] = hashlib.sha256(canonical_json_bytes(manifest)).hexdigest()
    _write_new(output / "MANIFEST.json", _json_bytes(manifest))
    return preflight


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUTPUT)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        result = prepare(args.source, args.out)
    except Exception as exc:
        print(
            json.dumps(
                {
                    "schema": "legalbot.ge-visible-evaluation-preparation-stop.v1",
                    "status": "STOPPED",
                    "reason_code": type(exc).__name__,
                },
                sort_keys=True,
            )
        )
        return 2
    print(
        json.dumps(
            {
                "schema": result["schema"],
                "status": "PREPARED_NOT_EXECUTED",
                "case_count": result["denominator"]["visible_case_count"],
                "content_sha256": result["content_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
