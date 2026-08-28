from __future__ import annotations

import hashlib
import json
from pathlib import Path

from app.assessment.guidance_bundle import OWNER_ASSESSMENT_BUNDLE
from app.config import FIRST_LIVE_LOCAL_ONLY_PROFILE, Settings
from app.evaluation.live_suite import load_live_evaluation_bundle
from app.evaluation.live_suite_path_b import selected_generation_case_ids

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "config" / "live60-current-contract.json"
BUNDLE_ROOT = ROOT / "benchmarks" / "evaluation" / "live-evaluation-60-v1"


def _contract() -> dict[str, object]:
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def test_current_contract_matches_sealed_suite_and_owner_only_gates() -> None:
    contract = _contract()
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    selected = list(selected_generation_case_ids(bundle))
    issue_count = sum(len(case.must_cover_issues) for case in bundle.registry.cases)
    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
    connected = (ROOT / ".env.connected-research.example").read_text(encoding="utf-8")

    assert contract["schema"] == "legalbot.live60-current-contract.v1"
    assert contract["suite_id"] == "live-evaluation-60-v1"
    assert contract["suite_manifest_seal_sha256"] == bundle.manifest.seal_sha256
    assert contract["case_count"] == 60
    assert contract["selected_generation_case_count"] == 30
    assert contract["selected_generation_case_ids"] == selected
    assert len(selected) == 30
    assert issue_count == contract["issue_count"] == 585
    assert len(OWNER_ASSESSMENT_BUNDLE.rules) == contract["live_assessment_rule_count"] == 16
    assert OWNER_ASSESSMENT_BUNDLE.version == contract["live_assessment_bundle_version"]
    assert contract["first_live_bind"] == "127.0.0.1"
    assert contract["eligible_for_training"] is False
    assert contract["training_export_allowed"] is False
    assert contract["active_json_owner_only"] is True
    assert contract["o04_owner_only"] is True
    assert contract["promotion_command"] == "legalbot promote"
    assert contract["evaluation_requires_active"] is False
    assert contract["evaluation_requires_o04"] is False
    assert contract["evaluation_authorization_schema"] == (
        "legalbot.live60-evaluation-execution-authorization.v2"
    )
    assert contract["overlay_complete_rule"] == "verified_dispositions_v2"
    assert "canonical_selected_issue_state" not in contract
    pointer = json.loads(
        (ROOT / "data/evaluations/live60/CURRENT.json").read_text(encoding="utf-8")
    )
    assert pointer["schema"] == "legalbot.live60-current-pointer.v1"
    assert pointer["review_import_sha256"] == (
        "e06d7f1179d58824c16ce2e45cbf46dcdce64365d69652729255738b9ddb1d2d"
    )
    issue_state = json.loads(
        (ROOT / "data/evaluations/live60/issue-state.json").read_text(encoding="utf-8")
    )
    assert issue_state["counts"]["selected_qualified"] == 101
    assert issue_state["counts"]["selected_limited"] == 13
    assert issue_state["counts"]["selected_knowledge_gap"] == 191
    assert issue_state["v2_notes"]["v2_verified_selected"] == 305
    assert contract["xerj_enabled"] is False
    assert contract["phoenix_enabled"] is False
    assert "LEGALBOT_LIVE_PROFILE=first_live_local_only" in env_example
    assert "LEGALBOT_OFFICIAL_RESEARCH_ENABLED=false" in env_example
    assert "LEGALBOT_HOST=127.0.0.1" in env_example
    assert "LEGALBOT_LIVE_PROFILE=standard" in connected
    assert "LEGALBOT_OFFICIAL_RESEARCH_ENABLED=true" in connected
    first_live = Settings(
        live_profile=FIRST_LIVE_LOCAL_ONLY_PROFILE,
        online_default="local_only",
        official_research_enabled=False,
    )
    assert first_live.host == "127.0.0.1"
    assert first_live.xerj_enabled is False
    assert first_live.phoenix_enabled is False


def test_path_b_control_plane_and_go_manifest_do_not_drift() -> None:
    artifacts = ROOT / "Live60-2026-08-16" / "artifacts"
    authority = json.loads((artifacts / "artifact-authority-map.json").read_text(encoding="utf-8"))
    route = json.loads((artifacts / "owner-route-selection.json").read_text(encoding="utf-8"))
    progress = json.loads((artifacts / "owner-tick-progress.json").read_text(encoding="utf-8"))

    assert route["route"] == "path_b"
    assert route["target"] == "full_30_answer_run"
    assert route["full_run_requirement"]["selected_case_count"] == 30
    assert route["full_run_requirement"]["selected_issue_count"] == 305
    assert route["coverage_only_issue_count"] == 280
    assert route["writes_active"] is False
    assert route["writes_o04"] is False
    assert authority["current_issue_state"] == {
        "knowledge_gap": 508,
        "limited": 0,
        "qualified": 77,
        "spans_bound": 200,
        "reviewed_rows_sha256": "e06d7f1179d58824c16ce2e45cbf46dcdce64365d69652729255738b9ddb1d2d",
    }
    remaining = json.loads(
        (artifacts / "full-run-remaining-status.json").read_text(encoding="utf-8")
    )
    assert remaining["path_b_overlay"]["sealed"] is False
    assert remaining["candidate_stage_a"]["passed"] is False
    assert remaining["fabricated_any_pass"] is False
    assert remaining["generation_authorised"] is False
    assert remaining["writes_active"] is False
    assert remaining["writes_o04"] is False
    assert progress["qualified"] == 0
    assert progress["gap"] == 585
    assert remaining["current_issue_state"] != authority["current_issue_state"]
    unsigned_decisions = json.loads(
        (artifacts / "owner-decisions-d1-d15-unsigned.json").read_text(encoding="utf-8")
    )
    unsigned_contrary = json.loads(
        (artifacts / "contrary-authority-review-unsigned.json").read_text(encoding="utf-8")
    )
    assert unsigned_decisions["owner_authored"] is False
    assert unsigned_decisions["unsigned"] is True
    assert unsigned_contrary["owner_authored"] is False
    assert unsigned_contrary["means_english_law_has_no_contrary_authority"] is False
    repair = json.loads(
        (artifacts / "held-span-contiguous-repair-v2.json").read_text(encoding="utf-8")
    )
    assert repair["schema"] == "legalbot.live60-held-span-contiguous-repair.v2"
    assert repair["seals_expert_gold"] is False
    assert repair.get("qualified") is not True

    manifest_path = ROOT / "Live60-2026-08-16" / "go-execution" / "file-sha256-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    paths = {row["relative_path"] for row in manifest["files"]}
    assert "Live60-2026-08-16/go-execution/route-integrity-verified.json" in paths
    assert "Live60-2026-08-16/go-execution/route-mismatch-regression.json" not in paths
    for row in manifest["files"]:
        path = ROOT / row["relative_path"]
        payload = path.read_bytes()
        assert len(payload) == row["bytes"], path
        assert hashlib.sha256(payload).hexdigest() == row["sha256"], path
