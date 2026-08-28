"""Synthetic answer-only owner-canary package for DOCX/render contract tests.

This helper cannot authorize a run, execute inference, write ACTIVE or satisfy
release readiness.  It creates only clearly synthetic, privacy-safe projection
bytes in an explicit empty directory so document tooling can be rendered and
visually inspected without touching real evaluation data.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Literal

from ..text_metrics import word_count
from .canary_review_workspace import (
    CANARY_REVIEW_CATEGORIES,
    REQUIRED_RELEASE_GATES,
    CanaryReviewWorkspace,
    CanaryReviewWorkspaceManifest,
    ReleasedAnswerProjection,
    _private_directory,
)
from .live30 import _exclusive_write
from .live_suite import sealed_sha256
from .owner_quality_canary_artifacts import OwnerCanaryCaseProjectionReceipt
from .owner_quality_canary_projection import OwnerCanaryFinalReviewPackage


@dataclass(frozen=True, slots=True)
class SyntheticOwnerCanaryReviewFixture:
    workspace: CanaryReviewWorkspace
    package: OwnerCanaryFinalReviewPackage
    answers: dict[str, str]


def _safe_projection(
    *, workspace: CanaryReviewWorkspace, category: str, filename: str, case_id: str
) -> Path:
    value: dict[str, Any] = {
        "schema": "legalbot.synthetic-owner-canary-projection.v1",
        "workspace_seal_sha256": workspace.manifest.seal_sha256,
        "case_id": case_id,
        "synthetic": True,
        "release_authority": False,
    }
    value["seal_sha256"] = sealed_sha256(value)
    return workspace.write_safe_json(category=category, filename=filename, value=value)


def create_synthetic_owner_canary_review_fixture(
    *,
    root: Path,
    run_id: str,
    lane: Literal["development", "blind_holdout"] = "development",
    answer_revision: str = "baseline",
) -> SyntheticOwnerCanaryReviewFixture:
    """Create a fully sealed 30-answer synthetic package in an empty directory."""

    if root.exists() or root.is_symlink():
        raise FileExistsError("synthetic owner-canary fixture root must be new")
    root.parent.mkdir(parents=True, exist_ok=True)
    _private_directory(root, exist_ok=False)
    for category in CANARY_REVIEW_CATEGORIES:
        _private_directory(root / category, exist_ok=False)

    case_ids = tuple(f"live30-q{number:02d}" for number in range(1, 31))
    canary_manifest_seal = hashlib.sha256(
        f"synthetic-manifest\0{run_id}\0{lane}".encode()
    ).hexdigest()
    workspace_material: dict[str, Any] = {
        "schema": "legalbot.canary-review-workspace.v1",
        "run_id": run_id,
        "review_date": date(2026, 8, 20).isoformat(),
        "lane": lane,
        "canary_manifest_id": "owner-quality-canary-" + canary_manifest_seal[:20],
        "canary_manifest_seal_sha256": canary_manifest_seal,
        "canary_manifest_file_sha256": hashlib.sha256(b"synthetic-sample\n").hexdigest(),
        "runtime_run_manifest_sha256": hashlib.sha256(
            f"synthetic-auth\0{run_id}".encode()
        ).hexdigest(),
        "candidate_build_id": "candidate-synthetic-v111",
        "candidate_manifest_sha256": hashlib.sha256(
            f"synthetic-candidate\0{answer_revision}".encode()
        ).hexdigest(),
        "expected_case_count": 30,
        "expected_case_ids": list(case_ids),
        "projection_categories": list(CANARY_REVIEW_CATEGORIES),
        "purpose": "evaluation_only",
        "local_only": True,
        "eligible_for_training": False,
        "training_export_allowed": False,
        "online_research_allowed": False,
        "create_only": True,
        "plaintext_policy": "gate_passed_released_answers_only",
        "held_content_policy": "encrypted_only",
    }
    workspace_material["seal_sha256"] = sealed_sha256(workspace_material)
    workspace_manifest = CanaryReviewWorkspaceManifest.model_validate(workspace_material)
    workspace = CanaryReviewWorkspace(root=root, manifest=workspace_manifest)
    _exclusive_write(
        root / "workspace-manifest.json",
        (
            json.dumps(
                workspace_manifest.model_dump(mode="json", by_alias=True),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8"),
    )
    _exclusive_write(
        root / "sample-manifest.json",
        (
            json.dumps(
                {
                    "schema": "legalbot.synthetic-owner-canary-sample.v1",
                    "case_ids": list(case_ids),
                    "synthetic": True,
                    "release_authority": False,
                },
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8"),
    )

    authorization_seal = workspace_manifest.runtime_run_manifest_sha256
    answers: dict[str, str] = {}
    receipts: list[OwnerCanaryCaseProjectionReceipt] = []
    for ordinal, case_id in enumerate(case_ids, start=1):
        content = (
            f"Synthetic evidence-bound answer {ordinal}. This {answer_revision} version "
            "exists only to exercise the owner review document, feedback, and render "
            "contracts. Every identifier is artificial and it carries no legal authority."
        )
        answers[case_id] = content
        answer_path, release_path = workspace.write_released_answer(
            case_id=case_id,
            content=content,
            release_gates={gate: True for gate in REQUIRED_RELEASE_GATES},
        )
        release_projection = ReleasedAnswerProjection.model_validate_json(release_path.read_bytes())
        projection_paths = {
            "evidence_projection_sha256": _safe_projection(
                workspace=workspace,
                category="evidence-citation-maps",
                filename=f"{case_id}.json",
                case_id=case_id,
            ),
            "ai_projection_sha256": _safe_projection(
                workspace=workspace,
                category="ai-reviews",
                filename=f"{case_id}.json",
                case_id=case_id,
            ),
            "standards_projection_sha256": _safe_projection(
                workspace=workspace,
                category="standards",
                filename=f"{case_id}.json",
                case_id=case_id,
            ),
            "gap_projection_sha256": _safe_projection(
                workspace=workspace,
                category="gaps",
                filename=f"{case_id}.json",
                case_id=case_id,
            ),
            "metrics_projection_sha256": _safe_projection(
                workspace=workspace,
                category="safe-metrics",
                filename=f"{case_id}-metrics.json",
                case_id=case_id,
            ),
            "retry_projection_sha256": _safe_projection(
                workspace=workspace,
                category="retry-trace",
                filename=f"{case_id}-projection.json",
                case_id=case_id,
            ),
        }
        synthetic_seals = {
            name: hashlib.sha256(f"{run_id}\0{case_id}\0{name}".encode()).hexdigest()
            for name in (
                "attempt",
                "evidence",
                "ai",
                "adjudication",
                "standards",
                "gates",
                "release",
            )
        }
        receipt_material: dict[str, Any] = {
            "schema": "legalbot.owner-canary-case-projection-receipt.v1",
            "workspace_seal_sha256": workspace_manifest.seal_sha256,
            "run_id": run_id,
            "authorization_seal_sha256": authorization_seal,
            "canary_manifest_seal_sha256": canary_manifest_seal,
            "case_id": case_id,
            "candidate_build_id": workspace_manifest.candidate_build_id,
            "candidate_manifest_sha256": workspace_manifest.candidate_manifest_sha256,
            "job_id": f"job-synthetic-{ordinal:02d}",
            "answer_version_id": f"answer-version-synthetic-{ordinal:02d}",
            "answer_artifact_id": f"answer-artifact-synthetic-{ordinal:02d}",
            "attempt_result_seal_sha256": synthetic_seals["attempt"],
            "answer_sha256": hashlib.sha256(answer_path.read_bytes()).hexdigest(),
            "answer_byte_count": len(answer_path.read_bytes()),
            "word_count": word_count(content),
            "release_projection_seal_sha256": release_projection.seal_sha256,
            **{
                field: hashlib.sha256(path.read_bytes()).hexdigest()
                for field, path in projection_paths.items()
            },
            "evidence_bundle_seal_sha256": synthetic_seals["evidence"],
            "ai_review_seal_sha256": synthetic_seals["ai"],
            "ai_adjudication_seal_sha256": synthetic_seals["adjudication"],
            "reviewer_invocation_trace_seal_sha256s": [],
            "reviewer_total_duration_ms": 0,
            "reviewer_total_input_tokens": 0,
            "reviewer_total_output_tokens": 0,
            "reviewer_token_counts_complete": True,
            "standards_report_seal_sha256": synthetic_seals["standards"],
            "deterministic_gate_report_seal_sha256": synthetic_seals["gates"],
            "release_attestation_seal_sha256": synthetic_seals["release"],
            "authoritative_answer_recomputed": True,
            "privacy_passed": True,
            "positive_artifacts_reverified": True,
            "plaintext_question_included": False,
        }
        receipt_material["seal_sha256"] = sealed_sha256(receipt_material)
        receipts.append(OwnerCanaryCaseProjectionReceipt.model_validate(receipt_material))

    package_material: dict[str, Any] = {
        "schema": "legalbot.owner-canary-final-review-package.v1",
        "workspace_seal_sha256": workspace_manifest.seal_sha256,
        "run_id": run_id,
        "lane": lane,
        "authorization_seal_sha256": authorization_seal,
        "canary_manifest_seal_sha256": canary_manifest_seal,
        "circuit_result_seal_sha256": hashlib.sha256(
            f"synthetic-circuit\0{run_id}".encode()
        ).hexdigest(),
        "candidate_build_id": workspace_manifest.candidate_build_id,
        "candidate_manifest_sha256": workspace_manifest.candidate_manifest_sha256,
        "case_count": 30,
        "case_ids": list(case_ids),
        "projection_receipts": [item.model_dump(mode="json", by_alias=True) for item in receipts],
        "projection_receipt_seal_sha256s": [item.seal_sha256 for item in receipts],
        "answer_sha256s": [item.answer_sha256 for item in receipts],
        "reviewer_invocation_trace_seal_sha256s": [],
        "reviewer_total_duration_ms": 0,
        "reviewer_total_input_tokens": 0,
        "reviewer_total_output_tokens": 0,
        "reviewer_token_counts_complete": True,
        "exact_case_projection_reconciled": True,
        "answer_only": True,
        "plaintext_questions_included": False,
        "tuning_input_allowed": lane == "development",
        "eligible_for_training": False,
        "training_export_allowed": False,
        "create_only": True,
    }
    package_material["seal_sha256"] = sealed_sha256(package_material)
    package = OwnerCanaryFinalReviewPackage.model_validate(package_material)
    workspace.write_safe_json(
        category="safe-metrics",
        filename="final-review-package.json",
        value=package.model_dump(mode="json", by_alias=True),
    )
    return SyntheticOwnerCanaryReviewFixture(
        workspace=workspace,
        package=package,
        answers=answers,
    )
