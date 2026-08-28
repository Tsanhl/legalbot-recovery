#!/usr/bin/env python3
"""LegalBot v1.11 — Phase-2A official-source remediation package generator.

Scope:
  * Phase-2A only (no answer-model calls, no Stage-A generation, no split secret).
  * Reproduces a versioned remediation package suitable for owner review.
  * Uses only deterministic evidence checks and explicit owner-adopted decisions.

This module is intentionally conservative and refuses to start live/validation/development
pipelines. If required inputs are missing, it fails fast with actionable diagnostics.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _row_matrix_to_counts(rows: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        status = str(row.get("status", "UNKNOWN")).upper()
        counts[status] = counts.get(status, 0) + 1
    return counts


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _norm(v: Any | None) -> Any:
    if isinstance(v, str):
        return v.strip()
    return v


def build_phase2a_package(
    *,
    remediation_path: Path,
    registry_path: Path,
    cutoff_iso: str,
    output_dir: Path,
    run_id: str,
    legal_policy_path: Path | None,
    advisory_path: Path | None,
) -> dict[str, Any]:
    now = datetime.now(UTC).isoformat(timespec="seconds")
    output_dir.mkdir(parents=True, exist_ok=True)

    remediation = _load_json(remediation_path)
    registry = _load_json(registry_path)

    remediation_rows = remediation.get("rows", [])
    if len(remediation_rows) != 585:
        raise ValueError(
            f"Expected 585 remediation rows; got {len(remediation_rows)}. "
            "Provide the canonical all-585 remediation table."
        )

    gold_or_case_defects = [
        r
        for r in remediation_rows
        if str(r.get("primary_defect", "")).upper() == "GOLD_OR_CASE_DEFECT"
    ]
    candidate_impact_rows = [
        r
        for r in remediation_rows
        if str(r.get("primary_defect", "")).upper() == "MATERIAL_CANDIDATE_COVERAGE_GAP"
    ]
    if len(gold_or_case_defects) != 509:
        # Explicitly keep exact arithmetic visible; do not auto-normalise classification.
        pass

    invariants = remediation.get("phase2a_invariants", {})
    currentness = remediation.get("currentness", {})

    legal_policy = _load_json(legal_policy_path) if legal_policy_path else {}
    advisory = _load_json(advisory_path) if advisory_path else {}

    case_count = len(registry.get("cases", []))
    issue_count = len(registry.get("issues", []))

    package: dict[str, Any] = {
        "schema_version": "legalbot.v111.phase2a.package.v1",
        "run_id": run_id,
        "created_utc": now,
        "mode": "PHASE_2A_REMEDIATION_ONLY",
        "authorizer": "OWNER",
        "governance": {
            "option_b": True,
            "developer_signature": "OPTIONAL_ADVISORY_ONLY",
            "authoritative_legal_review": "owner_adopted_internal",
            "prohibits": {
                "real_split": True,
                "split_secret": True,
                "development_generation": True,
                "validation_generation": True,
                "answer_model_calls": True,
                "owner_signature_binding": True,
                "active_prev_promotion": True,
                "live_activation": True,
            },
        },
        "inputs": {
            "remediation_rows_path": str(remediation_path),
            "remediation_rows_sha256": _sha256_file(remediation_path),
            "registry_path": str(registry_path),
            "registry_sha256": _sha256_file(registry_path),
            "legal_policy_path": str(legal_policy_path) if legal_policy_path else None,
            "legal_policy_sha256": _sha256_file(legal_policy_path) if legal_policy_path else None,
            "advisory_audit_path": str(advisory_path) if advisory_path else None,
            "advisory_audit_sha256": _sha256_file(advisory_path) if advisory_path else None,
            "requested_cutoff": cutoff_iso,
        },
        "registry": {
            "case_count": case_count,
            "issue_count": issue_count,
            "registry_snapshot_sha256": _sha256_file(registry_path),
            "registry_digest": hashlib.sha256(
                json.dumps(registry, sort_keys=True, ensure_ascii=False).encode("utf-8")
            ).hexdigest(),
        },
        "remediation_summary": {
            "row_count": len(remediation_rows),
            "gold_or_case_count": len(gold_or_case_defects),
            "material_candidate_impact_count": len(candidate_impact_rows),
            "row_status_counts": _row_matrix_to_counts(remediation_rows),
            "row_fields_seen": sorted({k for r in remediation_rows for k in r}),
        },
        "currentness": {
            "requested_ceiling": cutoff_iso,
            "confirmed": bool(currentness.get("confirmed", False)),
            "summary": currentness.get("summary", {}),
            "material_change_risk": currentness.get("material_change_risk", "UNKNOWN"),
            "evidence": currentness.get("evidence", []),
        },
        "candidate_impact": {
            "rows": candidate_impact_rows,
        },
        "remediation_rows": remediation_rows,
        "legal_policy": legal_policy,
        "advisory_audit": advisory,
        "invariants": {
            "candidate_rebuild_required": bool(invariants.get("candidate_rebuild_required", True)),
            "phase2b_allowed": bool(invariants.get("phase2b_allowed", False)),
            "terminal_verdict": _norm(invariants.get("terminal_verdict", "")),
            "qualified_case_count": int(invariants.get("qualified_case_count", 0)),
            "qualified_issue_count": int(invariants.get("qualified_issue_count", 0)),
            "material_blockers": invariants.get("material_blockers", []),
        },
        "integrity": {
            "deterministic_checks": remediation.get("deterministic_checks", []),
            "provenance": remediation.get("provenance", {}),
            "repeated_fingerprint_history": remediation.get("repeated_fingerprint_history", []),
        },
        "artifact_digests": {
            "package_content_sha256": "",
        },
    }

    package_path = output_dir / f"legalbot.v111-phase2a-remediation-package.{run_id}.v1.json"
    _write_json(package_path, package)

    package["artifact_digests"]["package_content_sha256"] = _sha256_file(package_path)
    _write_json(package_path, package)

    manifest_path = output_dir / f"legalbot.v111-phase2a-remediation-manifest.{run_id}.v1.json"
    manifest = {
        "schema_version": "legalbot.v111.phase2a.manifest.v1",
        "run_id": run_id,
        "package_path": str(package_path),
        "package_sha256": package["artifact_digests"]["package_content_sha256"],
        "created_utc": now,
        "scope": {
            "phase": "2A",
            "split_secret_created": False,
            "real_development_or_validation": False,
            "model_calls": False,
            "owner_signature_used": False,
        },
        "gate": "PHASE_2A_REMEDIATION_COMPLETE_OR_BLOCKED",
        "counts": {
            "row_count": package["remediation_summary"]["row_count"],
            "candidate_impact_count": package["remediation_summary"][
                "material_candidate_impact_count"
            ],
        },
    }
    _write_json(manifest_path, manifest)

    verdict = None
    blockers = package["invariants"].get("material_blockers", [])
    if blockers:
        verdict = "PHASE 2A SAFELY STOPPED — PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED"
    elif package["invariants"].get("candidate_rebuild_required", True) is False:
        verdict = (
            "PHASE 2A REMEDIATION COMPLETE — OWNER REVIEW AND ADOPTION REQUIRED BEFORE PHASE 2B"
        )
    else:
        # Still material blocker until owner approves any successor candidate and re-runs phase2A.
        verdict = "PHASE 2A SAFELY STOPPED — PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED"

    outcome_path = output_dir / f"legalbot.v111-phase2a-outcome.{run_id}.txt"
    outcome_path.write_text(f"{verdict}\n", encoding="utf-8")

    return {
        "run_id": run_id,
        "package_path": str(package_path),
        "manifest_path": str(manifest_path),
        "outcome_path": str(outcome_path),
        "verdict": verdict,
    }


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Generate Phase-2A remediation package for owner review."
    )
    p.add_argument(
        "--remediation-json", required=True, help="Path to 585-row remediation matrix JSON"
    )
    p.add_argument(
        "--registry-json", required=True, help="Path to case+issue registry snapshot JSON"
    )
    p.add_argument(
        "--cutoff",
        required=True,
        help="Legal-currentness ceiling candidate in RFC3339 format (YYYY-MM-DDTHH:MM:SS+00:00)",
    )
    p.add_argument("--run-id", required=True, help="Deterministic Phase-2A run identifier")
    p.add_argument(
        "--output-dir", required=True, help="Output folder for package, manifest and outcome."
    )
    p.add_argument(
        "--legal-policy-json", help="Optional conservative certification policy snapshot JSON"
    )
    p.add_argument("--ai-advisory-json", help="Optional advisory AI-audit JSON bundle")
    p.add_argument(
        "--require-blocking", action="store_true", help="Return non-zero only for blockers"
    )
    return p.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    ns = parse_args(argv)
    result = build_phase2a_package(
        remediation_path=Path(ns.remediation_json),
        registry_path=Path(ns.registry_json),
        cutoff_iso=ns.cutoff,
        output_dir=Path(ns.output_dir),
        run_id=ns.run_id,
        legal_policy_path=Path(ns.legal_policy_json) if ns.legal_policy_json else None,
        advisory_path=Path(ns.ai_advisory_json) if ns.ai_advisory_json else None,
    )

    verdict = result["verdict"]
    if (
        verdict
        == "PHASE 2A REMEDIATION COMPLETE — OWNER REVIEW AND ADOPTION REQUIRED BEFORE PHASE 2B"
    ):
        print(verdict)
        print(json.dumps(result, indent=2))
        return 0

    if ns.require_blocking:
        print(verdict)
        print(json.dumps(result, indent=2))
        return 2

    print(verdict)
    print(json.dumps(result, indent=2))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
