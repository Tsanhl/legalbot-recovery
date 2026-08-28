"""Evaluation-only Live60 authorization bound to a candidate build, not ACTIVE.

V1 ``legalbot.live60-execution-authorization.v1`` remains the production O-04
reader. This v2 record must not require ACTIVE, PREVIOUS, promotion, rollback,
browser recovery, production readiness green, or O-04.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..db import Database
from .live30 import assert_safe_evaluation_payload
from .live_suite import LiveEvaluationBundle, sealed_sha256
from .live_suite_overlay_complete import overlay_complete_v2
from .live_suite_path_b import (
    frozen_selected_issue_identities,
    selected_generation_case_ids,
)
from .live_suite_stage_a_v2 import STAGE_A_V2_SCHEMA

EVALUATION_AUTHORIZATION_V2_SCHEMA = "legalbot.live60-evaluation-execution-authorization.v2"
OPERATOR_PRODUCT_DECISIONS = frozenset({f"D-{number:02d}" for number in range(6, 15)})
EVIDENCE_LIFECYCLE_DECISIONS = frozenset({"D-01", "D-02", "D-03", "D-04", "D-05", "D-15"})


class Live60EvaluationExecutionAuthorizationV2(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.live60-evaluation-execution-authorization.v2"] = Field(
        default="legalbot.live60-evaluation-execution-authorization.v2",
        alias="schema",
    )
    evaluation_run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    suite_id: Literal["live-evaluation-60-v1"]
    suite_manifest_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_plan_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_build_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    overlay_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    stage_a_result_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    as_of_date: str
    authorized_case_ids: tuple[str, ...]
    local_only: Literal[True]
    online_research_allowed: Literal[False]
    writes_active: Literal[False] = False
    writes_previous: Literal[False] = False
    writes_o04: Literal[False] = False
    requires_active: Literal[False] = False
    requires_owner_promotion_ref: Literal[False] = False
    requires_rollback_drill: Literal[False] = False
    requires_browser_recovery: Literal[False] = False
    requires_production_readiness_green: Literal[False] = False
    requires_o04: Literal[False] = False
    issued_at: datetime
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def authorization_is_evaluation_only(self) -> Self:
        if len(self.authorized_case_ids) != 30 or len(set(self.authorized_case_ids)) != 30:
            raise ValueError("evaluation authorization must name exactly 30 unique cases")
        dumped = self.model_dump(mode="json", by_alias=True)
        if self.seal_sha256 != sealed_sha256(dumped):
            raise ValueError("evaluation authorization seal does not match its contents")
        return self


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _load_artifact_object(path: Path, *, label: str) -> tuple[dict[str, Any], str]:
    if not path.is_file():
        raise ValueError(f"{label} artifact is missing")
    raw = path.read_bytes()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} artifact is invalid") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} artifact is not an object")
    return payload, _sha256_bytes(raw)


def seal_evaluation_authorization_v2(
    *,
    evaluation_run_id: str,
    bundle: LiveEvaluationBundle,
    candidate_build_id: str,
    overlay_seal_sha256: str,
    stage_a_result_sha256: str,
    as_of_date: str,
    authorized_case_ids: Sequence[str],
    issued_at: datetime,
) -> Live60EvaluationExecutionAuthorizationV2:
    """Seal a v2 authorization after artifact hashes have already been verified."""

    if overlay_seal_sha256 == "c" * 64 or stage_a_result_sha256 == "d" * 64:
        raise ValueError("evaluation authorization refuses placeholder artifact hashes")
    material = {
        "schema": EVALUATION_AUTHORIZATION_V2_SCHEMA,
        "evaluation_run_id": evaluation_run_id,
        "suite_id": "live-evaluation-60-v1",
        "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
        "run_plan_seal_sha256": bundle.run_plan.seal_sha256,
        "candidate_build_id": candidate_build_id,
        "overlay_seal_sha256": overlay_seal_sha256,
        "stage_a_result_sha256": stage_a_result_sha256,
        "as_of_date": as_of_date,
        "authorized_case_ids": list(authorized_case_ids),
        "local_only": True,
        "online_research_allowed": False,
        "writes_active": False,
        "writes_previous": False,
        "writes_o04": False,
        "requires_active": False,
        "requires_owner_promotion_ref": False,
        "requires_rollback_drill": False,
        "requires_browser_recovery": False,
        "requires_production_readiness_green": False,
        "requires_o04": False,
        "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
    }
    material["seal_sha256"] = sealed_sha256(material)
    return Live60EvaluationExecutionAuthorizationV2.model_validate(material)


def issue_evaluation_authorization_v2(
    *,
    evaluation_run_id: str,
    bundle: LiveEvaluationBundle,
    candidate_build_id: str,
    overlay_path: Path,
    stage_a_path: Path,
    database: Database,
    as_of_date: str,
    issued_at: datetime,
    settings: Any | None = None,
    overlay_seal_sha256: str | None = None,
    stage_a_result_sha256: str | None = None,
    authorized_case_ids: Sequence[str] | None = None,
) -> Live60EvaluationExecutionAuthorizationV2:
    """Issue evaluation-only authorization from validated overlay and Stage A bytes."""

    if overlay_seal_sha256 is not None or stage_a_result_sha256 is not None:
        raise ValueError(
            "evaluation authorization must bind overlay and Stage A files, not caller hashes"
        )
    overlay, overlay_file_sha = _load_artifact_object(overlay_path, label="overlay")
    stage_a, stage_a_file_sha = _load_artifact_object(stage_a_path, label="stage_a")
    if overlay.get("schema") != "legalbot.live60-overlay-complete.v2":
        raise ValueError("evaluation overlay schema is invalid")
    if overlay.get("review_overlay_complete") is not True:
        raise ValueError("evaluation overlay is not review-complete")
    unreviewed = overlay.get("unreviewed_issue_count")
    if unreviewed is None or int(unreviewed) != 0:
        raise ValueError("evaluation overlay still has unreviewed issues")
    overlay_seal = str(overlay.get("seal_sha256") or "")
    unsigned = {
        key: value
        for key, value in overlay.items()
        if key not in {"seal_sha256", "case_execution", "issues"}
    }
    if overlay_seal != sealed_sha256(unsigned):
        raise ValueError("evaluation overlay seal does not match its contents")
    if overlay.get("candidate_build_id") not in {None, candidate_build_id}:
        raise ValueError("overlay candidate_build_id does not match the evaluation candidate")
    if overlay.get("as_of_date") not in {None, as_of_date}:
        raise ValueError("overlay as_of_date does not match evaluation as_of_date")
    if overlay.get("review_overlay_complete") is not True:
        raise ValueError("evaluation overlay is not review-complete")
    if int(overlay.get("selected_issue_count") or 0) != 305:
        raise ValueError("evaluation overlay is not bound to exactly 305 selected issues")
    expected_cases = selected_generation_case_ids(bundle)
    expected_identity = sealed_sha256(
        {"row_ids": sorted(item["row_id"] for item in frozen_selected_issue_identities(bundle))}
    )
    if overlay.get("frozen_issue_identity_sha256") != expected_identity:
        raise ValueError("evaluation overlay is not bound to the frozen 305 issue identities")
    issues = list(overlay.get("issues") or ())
    if issues:
        recomputed = overlay_complete_v2(
            selected_issues=issues,
            bundle=bundle,
            enforce_frozen_identities=True,
        )
        if recomputed.get("review_overlay_complete") is not True:
            raise ValueError("evaluation overlay failed frozen 30/305 identity checks")
    named_cases = tuple(overlay.get("authorized_case_ids") or ())
    if named_cases and set(named_cases) != set(expected_cases):
        raise ValueError("evaluation overlay does not name the frozen 30 cases")
    if int(overlay.get("selected_case_count") or 0) != 30:
        raise ValueError("evaluation overlay does not name the frozen 30 cases")
    if stage_a.get("schema") != STAGE_A_V2_SCHEMA:
        raise ValueError("Stage A schema is invalid")
    stage_unsigned = {key: value for key, value in stage_a.items() if key != "seal_sha256"}
    if str(stage_a.get("seal_sha256") or "") != sealed_sha256(stage_unsigned):
        raise ValueError("Stage A seal does not match its contents")
    if (
        stage_a.get("stage_a_passed") is not True
        or stage_a.get("authorization_eligible") is not True
    ):
        raise ValueError("Stage A has not passed against the candidate")
    if stage_a.get("metrics_source") != "derived_rankings":
        raise ValueError("Stage A metrics were not derived from retrieval rankings")
    if str(stage_a.get("candidate_build_id") or "") != candidate_build_id:
        raise ValueError("Stage A is bound to a different candidate build")
    if stage_a.get("as_of_date") not in {None, as_of_date}:
        raise ValueError("Stage A as_of_date does not match evaluation as_of_date")
    row = database.fetchone(
        "SELECT * FROM index_builds WHERE id=?",
        (candidate_build_id,),
    )
    if row is None:
        raise ValueError("evaluation candidate build is missing")
    if str(row["status"]) not in {"candidate", "active"}:
        raise ValueError(
            "evaluation candidate is not a sealed candidate or approved evaluation build"
        )
    if settings is not None:
        from ..retrieval.service import _verify_sealed_build

        _verify_sealed_build(settings, database, dict(row))
    authorized = authorized_case_ids or expected_cases
    if tuple(authorized) != expected_cases:
        raise ValueError("evaluation authorization must name the frozen 30 selected cases")
    return seal_evaluation_authorization_v2(
        evaluation_run_id=evaluation_run_id,
        bundle=bundle,
        candidate_build_id=candidate_build_id,
        overlay_seal_sha256=overlay_file_sha,
        stage_a_result_sha256=stage_a_file_sha,
        as_of_date=as_of_date,
        authorized_case_ids=authorized,
        issued_at=issued_at,
    )


def load_evaluation_authorization_v2(
    path: Path,
) -> Live60EvaluationExecutionAuthorizationV2:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") == "legalbot.live60-execution-authorization.v1":
        raise ValueError("v1 O-04 cannot authorize evaluation-only execution")
    return Live60EvaluationExecutionAuthorizationV2.model_validate(payload)


def decision_lane(decision_id: str) -> str:
    if decision_id in OPERATOR_PRODUCT_DECISIONS:
        return "operator_product"
    if decision_id in EVIDENCE_LIFECYCLE_DECISIONS:
        return "evidence_lifecycle"
    raise ValueError("unknown Live60 decision identity")


def verify_evaluation_runtime_bindings(
    *,
    authorization: Live60EvaluationExecutionAuthorizationV2,
    candidate_build_id: str,
    active_build_id: str | None = None,
    database: Database | None = None,
    fallback_to_active: bool = False,
) -> dict[str, Any]:
    """Pin evaluation to the candidate. Refuse a silent ACTIVE fallback."""

    if fallback_to_active:
        raise ValueError("evaluation must not silently fall back to ACTIVE")
    if authorization.candidate_build_id != candidate_build_id:
        raise ValueError("evaluation candidate_build_id does not match authorization")
    if database is not None:
        row = database.fetchone(
            "SELECT id, status FROM index_builds WHERE id=?",
            (candidate_build_id,),
        )
        if row is None:
            raise ValueError("evaluation candidate build is missing")
        serving = database.active_index_id()
        if serving == candidate_build_id and active_build_id not in {
            None,
            candidate_build_id,
        }:
            raise ValueError("evaluation candidate must not be rewritten to ACTIVE")
    payload = {
        "schema": "legalbot.live60-evaluation-runtime-binding.v2",
        "evaluation_run_id": authorization.evaluation_run_id,
        "evaluation_candidate_build_id": candidate_build_id,
        "active_build_id": active_build_id,
        "used_active_fallback": False,
        "writes_active": False,
        "requires_o04": False,
        "local_only": True,
    }
    assert_safe_evaluation_payload(payload)
    return payload


def evaluation_authorization_refuses_production_fields(
    payload: Mapping[str, Any],
) -> list[str]:
    """Return blockers if a v2 record smuggles production O-04 requirements."""

    blockers: list[str] = []
    forbidden_true = (
        "requires_active",
        "requires_owner_promotion_ref",
        "requires_rollback_drill",
        "requires_browser_recovery",
        "requires_production_readiness_green",
        "requires_o04",
        "writes_active",
        "writes_previous",
        "writes_o04",
        "readiness_ready",
    )
    for key in forbidden_true:
        if payload.get(key) is True:
            blockers.append(f"evaluation_auth_forbids_{key}")
    if payload.get("active_build_id") and not payload.get("candidate_build_id"):
        blockers.append("evaluation_auth_must_pin_candidate_not_active")
    if payload.get("o04_authorization_ref"):
        blockers.append("evaluation_auth_forbids_o04_authorization_ref")
    if payload.get("owner_promotion_ref"):
        blockers.append("evaluation_auth_forbids_owner_promotion_ref")
    return blockers
