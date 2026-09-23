"""Bind the owner-authorized research change to visible evidence before freezing.

These are local execution receipts, not professional or cryptographic signatures.
The existing bank and execution authority checks remain mandatory.
"""
from __future__ import annotations

from pathlib import Path

REQUIRED_CHECKS = frozenset({
    "actual_pinned_embedding_inference", "actual_pinned_reranking_inference",
    "persisted_lexical_vector_readback",
    "wrong_jurisdiction_excluded", "wrong_date_excluded", "quote_mismatch_held",
    "superseded_version_retained", "duplicate_no_op", "interrupted_build_preserved",
    "active_unchanged", "cross_store_read_denied", "uk_nations_and_us_state_federal",
    "usable_upload", "multi_turn_fact_correction", "held_research_outcome",
    "candidate_case_local_consumer", "independent_source_and_claim_review",
})


def _relative_file(r, name):
    if not isinstance(name, str) or Path(name).is_absolute() or ".." in Path(name).parts:
        raise RuntimeError("invalid research evidence path")
    path = r.ROOT / name
    r.safe_path(path)
    return path


def require_plan_execution(r):
    path = r.PUBLIC / "PLAN-EXECUTION-AUTHORIZATION.json"
    value = r.read(path)
    if (value != r.seal(value) or value.get("run_id") != r.RUN_ID
            or value.get("owner_instruction") != "do in full then the plan"
            or value.get("creation_review_then_one_pass") is not True
            or value.get("training") is not False
            or value.get("production_admission") is not False
            or value.get("active_mutation") is not False
            or value.get("promotion") is not False or value.get("live") is not False
            or value.get("visible_research_gate_required") is not True
            or value.get("original_start_sha256") != r.sha(r.PUBLIC / "CONTINUOUS-RUN-START.json")
            or value.get("owner_authorization_sha256") != r.sha(r.PUBLIC / "OWNER-AUTHORIZATION.json")
            or value.get("scope_amendment_sha256") != r.sha(r.PUBLIC / "UK-USA-SCOPE-AMENDMENT.json")):
        raise RuntimeError("plan execution receipt missing or changed")
    source = _relative_file(r, value.get("accepted_plan_path"))
    if r.sha(source) != value.get("accepted_plan_sha256"):
        raise RuntimeError("accepted plan bytes changed")
    return value


def require_research_runtime(r):
    """No candidate preparation with a missing, held or stale visible proof."""
    require_plan_execution(r)
    path = r.PUBLIC / "AUTO-RESEARCH-VISIBLE-VALIDATION.json"
    value = r.read(path)
    if (value != r.seal(value) or value.get("run_id") != r.RUN_ID
            or value.get("status") != "PASS"
            or value.get("plan_execution_sha256") != r.sha(r.PUBLIC / "PLAN-EXECUTION-AUTHORIZATION.json")
            or value.get("runtime_files") != r.runtime_files()
            or value.get("runtime_environment") != r.runtime_environment()
            or value.get("private_bank_used") is not False
            or value.get("weight_training") is not False):
        raise RuntimeError("visible research evidence missing, held or runtime changed")
    checks = value.get("checks", {})
    if not isinstance(checks, dict) or set(checks) != REQUIRED_CHECKS:
        raise RuntimeError("visible research check coverage incomplete")
    artifacts = value.get("artifacts", {})
    if not artifacts:
        raise RuntimeError("visible validation needs actual evidence artifacts")
    for name, expected in artifacts.items():
        if r.sha(_relative_file(r, name)) != expected:
            raise RuntimeError("visible evidence artifact changed")
    for check in checks.values():
        if (not isinstance(check, dict) or check.get("status") != "PASS"
                or not check.get("evidence") or not set(check["evidence"]) <= set(artifacts)):
            raise RuntimeError("visible check lacks passing bound evidence")
    import re
    if any(not isinstance(value.get(k), str) or re.fullmatch(r"[0-9a-f]{64}", value[k]) is None
           for k in ("model_manifest_sha256", "baseline_generation_sha256")):
        raise RuntimeError("retrieval model or frozen baseline missing")
    return value
