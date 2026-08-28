"""Owner confirmation for Path-B contrary-review and D1-D15 records.

Code never self-authors `owner_authored: true`. The owner must supply
`CONFIRM_OWNER_AUTHORED_SEAL`. This module still cannot write ACTIVE, PREVIOUS,
O-04, or an expert overlay.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import date
from pathlib import Path
from typing import Any

from .live30 import assert_safe_evaluation_payload
from .live_suite import load_live_evaluation_bundle, sealed_sha256
from .live_suite_contrary_authority import (
    CONTRARY_REVIEW_SCHEMA,
    ContraryAuthorityReview,
    contrary_review_template,
)
from .live_suite_owner_decision_contract import (
    CONDITIONAL_DECISION_IDS,
    LATER_OWNER_ACTIONS,
    OWNER_DECISION_IDS,
    OWNER_DECISIONS_SCHEMA,
    Live60OwnerDecisions,
    owner_decision_template,
)
from .live_suite_path_b import LIVE60_ROOT

OWNER_CONTROL_CONFIRMATION_TOKEN = "CONFIRM_OWNER_AUTHORED_SEAL"
OWNER_CONTROL_CONFIRM_RESULT_SCHEMA = "legalbot.live60-owner-control-confirm-result.v1"

REQUIRED_DECISION_STATES: Mapping[str, str] = {
    "D-01": "accepted",
    "D-02": "accepted",
    "D-03": "accepted",
    "D-04": "accepted",
    "D-05": "conditional",
    "D-06": "deferred_later_owner_action",
    "D-07": "deferred_later_owner_action",
    "D-08": "deferred_later_owner_action",
    "D-09": "deferred_later_owner_action",
    "D-10": "accepted",
    "D-11": "accepted",
    "D-12": "accepted",
    "D-13": "accepted",
    "D-14": "accepted",
    "D-15": "accepted",
}
ALLOWED_CONTRARY_STATUSES = frozenset(
    {
        "reviewed_none_in_defined_source_set",
        "reviewed_and_bound",
        "needs_independent_second_review",
    }
)


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("owner-control JSON must be an object")
    return payload


def write_unsigned_owner_control_templates(
    *,
    destination_dir: Path,
    as_of_date: date,
    overwrite: bool = False,
) -> dict[str, str]:
    """Write unsigned D1-D15 and contrary templates. Never owner-authored."""

    decisions_path = destination_dir / "owner-decisions-d1-d15-unsigned.json"
    contrary_path = destination_dir / "contrary-authority-review-unsigned.json"
    decisions = owner_decision_template(as_of_date=as_of_date.isoformat())
    contrary = contrary_review_template(as_of_date=as_of_date.isoformat())
    if overwrite or not decisions_path.exists():
        _write_json(decisions_path, decisions)
    if overwrite or not contrary_path.exists():
        _write_json(contrary_path, contrary)
    return {
        "owner_decisions": str(decisions_path),
        "contrary_review": str(contrary_path),
    }


def _bind_identities(
    payload: dict[str, Any],
    *,
    project_root: Path,
    index_build_id: str,
    run_id: str,
    as_of_date: date,
    include_write_flags: bool = False,
) -> dict[str, Any]:
    bundle = load_live_evaluation_bundle(project_root / LIVE60_ROOT)
    bound = dict(payload)
    bound["suite_id"] = "live-evaluation-60-v1"
    bound["as_of_date"] = as_of_date.isoformat()
    bound["suite_registry_canonical_sha256"] = bundle.registry.canonical_sha256
    bound["run_plan_sha256"] = bundle.manifest.run_plan_sha256
    bound["index_build_id"] = index_build_id
    bound["run_id"] = run_id
    bound["owner_authored"] = True
    bound["ai_self_authored"] = False
    bound.pop("unsigned", None)
    bound.pop("note", None)
    bound.pop("seal_sha256", None)
    if include_write_flags:
        bound["writes_active"] = False
        bound["writes_o04"] = False
    else:
        bound.pop("writes_active", None)
        bound.pop("writes_o04", None)
    return bound


def confirm_owner_decisions(
    *,
    project_root: Path,
    unsigned_path: Path,
    destination: Path,
    confirmation_token: str,
    index_build_id: str,
    run_id: str,
    as_of_date: date,
    overwrite: bool = False,
) -> dict[str, Any]:
    if confirmation_token != OWNER_CONTROL_CONFIRMATION_TOKEN:
        raise ValueError("owner control confirmation token is missing or invalid")
    if destination.exists() and not overwrite:
        raise FileExistsError("sealed owner-decision record already exists")
    payload = _load_json(unsigned_path)
    if payload.get("schema") != OWNER_DECISIONS_SCHEMA:
        raise ValueError("owner-decision confirmation requires the D1-D15 schema")
    if payload.get("ai_self_authored") is True:
        raise ValueError("code must not self-author Live60 owner decisions")
    if payload.get("owner_authored") is True:
        raise ValueError("owner-decision record is already marked owner-authored")
    if payload.get("writes_active") is True or payload.get("writes_o04") is True:
        raise ValueError("owner decisions cannot authorise ACTIVE or O-04")

    decisions = list(payload.get("decisions") or ())
    ids = tuple(item.get("id") for item in decisions)
    if ids != OWNER_DECISION_IDS:
        raise ValueError("owner decisions must contain D-01 through D-15 in order")
    for item in decisions:
        decision_id = str(item["id"])
        state = str(item.get("state") or "")
        required = REQUIRED_DECISION_STATES[decision_id]
        if state != required:
            if decision_id in LATER_OWNER_ACTIONS and state == "accepted":
                raise ValueError(f"{decision_id} cannot be accepted before the later owner gate")
            raise ValueError(f"{decision_id} must remain {required} for Path B full-30")
        if decision_id in LATER_OWNER_ACTIONS and not item.get("later_owner_action"):
            raise ValueError(f"{decision_id} must remain a later owner action")
        if decision_id in CONDITIONAL_DECISION_IDS and not item.get("conditional"):
            raise ValueError(f"{decision_id} must remain conditional")

    bound = _bind_identities(
        payload,
        project_root=project_root,
        index_build_id=index_build_id,
        run_id=run_id,
        as_of_date=as_of_date,
        include_write_flags=True,
    )
    bound["seal_sha256"] = sealed_sha256(bound)
    Live60OwnerDecisions.model_validate(bound)
    _write_json(destination, bound)
    return bound


def confirm_contrary_review(
    *,
    project_root: Path,
    unsigned_path: Path,
    destination: Path,
    confirmation_token: str,
    index_build_id: str,
    run_id: str,
    as_of_date: date,
    overwrite: bool = False,
) -> dict[str, Any]:
    if confirmation_token != OWNER_CONTROL_CONFIRMATION_TOKEN:
        raise ValueError("owner control confirmation token is missing or invalid")
    if destination.exists() and not overwrite:
        raise FileExistsError("sealed contrary-review record already exists")
    payload = _load_json(unsigned_path)
    if payload.get("schema") != CONTRARY_REVIEW_SCHEMA:
        raise ValueError("contrary confirmation requires the contrary-review schema")
    if payload.get("ai_self_authored") is True:
        raise ValueError("code must not self-author contrary-authority reviews")
    if payload.get("owner_authored") is True:
        raise ValueError("contrary-review record is already marked owner-authored")
    if payload.get("means_english_law_has_no_contrary_authority") is True:
        raise ValueError("reviewed_none cannot mean English law has no contrary authority")
    status = str(payload.get("status") or "")
    if status not in ALLOWED_CONTRARY_STATUSES:
        raise ValueError("contrary review is still unsigned or uses an unknown status")
    if not payload.get("defined_source_set_id"):
        raise ValueError("contrary review requires a named source set")
    if not payload.get("defined_source_set_review_method"):
        raise ValueError("contrary review requires a named review method")
    if str(payload.get("defined_source_set_reviewed_as_of_date") or "") != as_of_date.isoformat():
        raise ValueError("contrary source-set date must match the legal as-of date")
    if not payload.get("reviewer_scope"):
        raise ValueError("contrary review requires a reviewer scope")

    bound = _bind_identities(
        payload,
        project_root=project_root,
        index_build_id=index_build_id,
        run_id=run_id,
        as_of_date=as_of_date,
    )
    bound["seal_sha256"] = sealed_sha256(bound)
    ContraryAuthorityReview.model_validate(bound)
    _write_json(destination, bound)
    return bound


def confirm_owner_control_records(
    *,
    project_root: Path,
    decisions_path: Path,
    contrary_path: Path,
    decisions_destination: Path,
    contrary_destination: Path,
    confirmation_token: str,
    index_build_id: str,
    run_id: str,
    as_of_date: date,
    overwrite: bool = False,
) -> dict[str, Any]:
    """One owner confirmation for both control records. Does not seal the overlay."""

    decisions = confirm_owner_decisions(
        project_root=project_root,
        unsigned_path=decisions_path,
        destination=decisions_destination,
        confirmation_token=confirmation_token,
        index_build_id=index_build_id,
        run_id=run_id,
        as_of_date=as_of_date,
        overwrite=overwrite,
    )
    contrary = confirm_contrary_review(
        project_root=project_root,
        unsigned_path=contrary_path,
        destination=contrary_destination,
        confirmation_token=confirmation_token,
        index_build_id=index_build_id,
        run_id=run_id,
        as_of_date=as_of_date,
        overwrite=overwrite,
    )
    payload = {
        "schema": OWNER_CONTROL_CONFIRM_RESULT_SCHEMA,
        "owner_authored": True,
        "ai_self_authored": False,
        "decisions_sealed": True,
        "contrary_sealed": True,
        "decisions_seal_sha256": decisions["seal_sha256"],
        "contrary_seal_sha256": contrary["seal_sha256"],
        "ready_for_overlay_seal": False,
        "generation_authorised": False,
        "writes_active": False,
        "writes_previous": False,
        "writes_o04": False,
        "eligible_for_training": False,
        "training_export_allowed": False,
        "note": (
            "Owner-authored D1-D15 and contrary-review seals are not an overlay "
            "seal. All 305 selected issues still need positive exact spans."
        ),
    }
    assert_safe_evaluation_payload(payload)
    return payload
