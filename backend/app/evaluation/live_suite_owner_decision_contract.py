"""Sealed Live60 D1-D15 owner-decision contract.

Code never self-authors these records. D6-D9 remain later owner actions.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .live30 import assert_safe_evaluation_payload
from .live_suite import sealed_sha256

OWNER_DECISIONS_SCHEMA = "legalbot.live60-owner-decisions.v1"
OWNER_DECISION_IDS = tuple(f"D-{number:02d}" for number in range(1, 16))
CONDITIONAL_DECISION_IDS = ("D-05", "D-06", "D-07", "D-08", "D-09")
LATER_OWNER_ACTIONS = ("D-06", "D-07", "D-08", "D-09")
DecisionState = Literal[
    "unsigned",
    "pending",
    "conditional",
    "accepted",
    "deferred_later_owner_action",
]


class Live60OwnerDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^D-(?:0[1-9]|1[0-5])$")
    state: DecisionState
    later_owner_action: bool = False
    conditional: bool = False
    cannot_be_done_by_ai: Literal[True] = True
    notes: str | None = Field(default=None, max_length=240)


class Live60OwnerDecisions(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.live60-owner-decisions.v1"] = Field(alias="schema")
    suite_id: Literal["live-evaluation-60-v1"]
    as_of_date: str
    suite_registry_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    index_build_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    owner_authored: Literal[True]
    ai_self_authored: Literal[False]
    writes_active: Literal[False]
    writes_o04: Literal[False]
    decisions: tuple[Live60OwnerDecision, ...]
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def contract_is_complete(self) -> Live60OwnerDecisions:
        ids = tuple(item.id for item in self.decisions)
        if ids != OWNER_DECISION_IDS:
            raise ValueError("owner decisions must contain D-01 through D-15 in order")
        for item in self.decisions:
            if item.id in LATER_OWNER_ACTIONS and not item.later_owner_action:
                raise ValueError(f"{item.id} must remain a later owner action")
            if item.id in CONDITIONAL_DECISION_IDS and not item.conditional:
                raise ValueError(f"{item.id} must remain conditional")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("owner-decision seal does not match its contents")
        return self


def owner_decision_template(*, as_of_date: str) -> dict[str, Any]:
    """Unsigned contract. Never a sealed owner decision."""

    decisions = []
    for decision_id in OWNER_DECISION_IDS:
        later = decision_id in LATER_OWNER_ACTIONS
        conditional = decision_id in CONDITIONAL_DECISION_IDS
        decisions.append(
            {
                "id": decision_id,
                "state": "deferred_later_owner_action" if later else "unsigned",
                "later_owner_action": later,
                "conditional": conditional,
                "cannot_be_done_by_ai": True,
                "notes": None,
            }
        )
    payload = {
        "schema": OWNER_DECISIONS_SCHEMA,
        "suite_id": "live-evaluation-60-v1",
        "as_of_date": as_of_date,
        "suite_registry_canonical_sha256": None,
        "run_plan_sha256": None,
        "index_build_id": None,
        "run_id": None,
        "owner_authored": False,
        "ai_self_authored": False,
        "writes_active": False,
        "writes_o04": False,
        "decisions": decisions,
        "seal_sha256": None,
        "unsigned": True,
    }
    assert_safe_evaluation_payload(payload)
    return payload


def load_owner_decisions(path: Path) -> Live60OwnerDecisions:
    if not path.is_file():
        raise ValueError("owner-decision record is missing")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("ai_self_authored") is True:
        raise ValueError("code must not self-author Live60 owner decisions")
    return Live60OwnerDecisions.model_validate(payload)


def assert_not_self_authored(payload: Mapping[str, Any]) -> None:
    if payload.get("ai_self_authored") is True or payload.get("owner_authored") is not True:
        raise ValueError("Live60 owner decisions must be owner-authored")
