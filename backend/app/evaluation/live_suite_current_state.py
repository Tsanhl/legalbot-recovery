"""Single current-state resolver for Live60 Path-B counts and machine states.

Mutable counts live in a hashed pointer artifact, not Python source or the
invariant policy contract. Stale tick files remain audit history and cannot
override CURRENT.json.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .live30 import assert_safe_evaluation_payload
from .live_runtime_separation import classify_live_and_live60_state

CURRENT_STATE_REPORT_SCHEMA = "legalbot.live60-current-state-report.v2"
CURRENT_POINTER_SCHEMA = "legalbot.live60-current-pointer.v1"
ISSUE_STATE_SCHEMA = "legalbot.live60-issue-state.v1"
CURRENT_POINTER_RELATIVE = "data/evaluations/live60/CURRENT.json"
SELECTED_ISSUE_COUNT = 305
ISSUE_COUNT = 585
STALE_TICK_RELATIVE = "Live60-2026-08-16/artifacts/owner-tick-progress.json"
AUTHORITY_MAP_RELATIVE = "Live60-2026-08-16/artifacts/artifact-authority-map.json"


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_mapping(value: Mapping[str, Any]) -> str:
    encoded = (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _count(values: Mapping[str, Any], key: str, default: int = 0) -> int:
    raw = values.get(key)
    if isinstance(raw, bool) or raw is None:
        return default
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str) and raw.isdigit():
        return int(raw)
    return default


def selected_knowledge_gap_count(
    *,
    selected_qualified: int,
    selected_limited: int,
    selected_unreviewed: int,
    selected_issue_count: int = SELECTED_ISSUE_COUNT,
) -> int:
    return max(
        0,
        selected_issue_count - selected_qualified - selected_limited - selected_unreviewed,
    )


def load_current_pointer(project_root: Path) -> dict[str, Any]:
    path = project_root / CURRENT_POINTER_RELATIVE
    if not path.is_file():
        raise ValueError("Live60 CURRENT pointer is missing")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema") != CURRENT_POINTER_SCHEMA:
        raise ValueError("Live60 CURRENT pointer schema is invalid")
    return payload


def _load_hashed_artifact(
    project_root: Path, relative: str, expected_sha256: str
) -> dict[str, Any]:
    path = (project_root / relative).resolve()
    root = project_root.resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError("CURRENT pointer references a missing artifact")
    raw = path.read_bytes()
    if _sha256_bytes(raw) != expected_sha256:
        raise ValueError("CURRENT pointer artifact hash does not match")
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("CURRENT pointer artifact is not an object")
    return payload


def derive_issue_state_from_artifact(artifact: Mapping[str, Any]) -> dict[str, Any]:
    counts = artifact.get("counts") if isinstance(artifact.get("counts"), dict) else artifact
    if not isinstance(counts, Mapping):
        raise ValueError("issue-state artifact has no counts")
    selected_qualified = _count(counts, "selected_qualified", _count(counts, "qualified"))
    selected_limited = _count(counts, "selected_limited", _count(counts, "limited"))
    selected_unreviewed = _count(counts, "selected_unreviewed", _count(counts, "unreviewed"))
    selected_gap = selected_knowledge_gap_count(
        selected_qualified=selected_qualified,
        selected_limited=selected_limited,
        selected_unreviewed=selected_unreviewed,
    )
    return {
        "qualified": _count(counts, "qualified", selected_qualified),
        "limited": _count(counts, "limited", selected_limited),
        "knowledge_gap": _count(counts, "knowledge_gap_total", _count(counts, "knowledge_gap")),
        "spans_bound": _count(counts, "spans_bound"),
        "selected_qualified": selected_qualified,
        "selected_limited": selected_limited,
        "selected_unreviewed": selected_unreviewed,
        "selected_knowledge_gap": selected_gap,
        "selected_issue_count": SELECTED_ISSUE_COUNT,
        "issue_count": ISSUE_COUNT,
        "reviewed_rows_sha256": str(
            artifact.get("reviewed_rows_sha256") or counts.get("reviewed_rows_sha256") or ""
        ),
        "lineage_sha256": str(artifact.get("lineage_sha256") or ""),
        "supersedes": artifact.get("supersedes"),
    }


class CurrentLiveStateResolver:
    """Resolve authoritative Path-B issue state from CURRENT.json + hashed artifact."""

    def __init__(
        self,
        *,
        project_root: Path,
        candidate_build_id: str | None = None,
        source_run_id: str | None = None,
        overlay_v2: Mapping[str, Any] | None = None,
        ticks: Mapping[str, Any] | None = None,
        serving_index_present: bool = False,
        pointer: Mapping[str, Any] | None = None,
    ) -> None:
        self.project_root = project_root
        self.candidate_build_id = candidate_build_id
        self.source_run_id = source_run_id
        self.overlay_v2 = overlay_v2
        self.ticks = ticks
        self.serving_index_present = serving_index_present
        self.pointer = pointer

    def authoritative_issue_state(self) -> dict[str, Any]:
        pointer = self.pointer or load_current_pointer(self.project_root)
        relative = str(
            pointer.get("issue_state_path") or pointer.get("migration_or_overlay_path") or ""
        )
        expected = str(
            pointer.get("issue_state_sha256") or pointer.get("migration_or_overlay_sha256") or ""
        )
        artifact = _load_hashed_artifact(self.project_root, relative, expected)
        state = derive_issue_state_from_artifact(artifact)
        review_sha = str(pointer.get("review_import_sha256") or "")
        if review_sha:
            state["reviewed_rows_sha256"] = review_sha
        if self.overlay_v2 and self.overlay_v2.get("review_overlay_complete") is True:
            selected_qualified = int(self.overlay_v2.get("selected_qualified_issue_count") or 0)
            selected_limited = int(self.overlay_v2.get("selected_limited_issue_count") or 0)
            selected_unreviewed = int(self.overlay_v2.get("unreviewed_issue_count") or 0)
            if selected_unreviewed:
                raise ValueError("issue state cannot report REVIEW_COMPLETE while HOLD > 0")
            state.update(
                {
                    "selected_qualified": selected_qualified,
                    "selected_limited": selected_limited,
                    "selected_unreviewed": selected_unreviewed,
                    "selected_knowledge_gap": selected_knowledge_gap_count(
                        selected_qualified=selected_qualified,
                        selected_limited=selected_limited,
                        selected_unreviewed=selected_unreviewed,
                    ),
                }
            )
        return state

    def report(
        self,
        *,
        generated_at: datetime | None = None,
        overlay_sealed: bool = False,
        overlay_blockers: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        state = self.authoritative_issue_state()
        pointer = self.pointer or load_current_pointer(self.project_root)
        from ..retrieval.diagnostic_slice import (
            bind_current_candidate_build_id,
            refuse_diagnostic_slice_for_production,
        )
        from .live_suite_hold_taxonomy import issue_state_review_complete

        unreviewed = int(state.get("selected_unreviewed") or 0)
        if self.overlay_v2:
            unreviewed = int(self.overlay_v2.get("unreviewed_issue_count") or 0)
        candidate = self.candidate_build_id or pointer.get("candidate_build_id")
        if candidate:
            refuse_diagnostic_slice_for_production(
                str(candidate),
                purpose="CURRENT.candidate_build_id",
                pointer=pointer,
            )
        machines = classify_live_and_live60_state(
            serving_index_present=self.serving_index_present,
            previous_approved_active_present=self.serving_index_present,
            path_b_selected_qualified_with_spans=int(state["selected_qualified"]),
            overlay_sealed=overlay_sealed,
            overlay_blockers=overlay_blockers
            or (("selected_issues_missing_positive_exact_spans",) if not overlay_sealed else ()),
            candidate_build_present=bool(candidate),
            unreviewed_issue_count=unreviewed,
            hold_issue_count=unreviewed,
            review_complete=issue_state_review_complete(
                hold_count=unreviewed, unreviewed_count=unreviewed
            ),
        )
        payload = {
            "schema": CURRENT_STATE_REPORT_SCHEMA,
            "generated_at": (generated_at or datetime.now(UTC)).isoformat().replace("+00:00", "Z"),
            "source_run_id": self.source_run_id or pointer.get("run_id"),
            "candidate_build_id": bind_current_candidate_build_id(
                pointer, str(candidate) if candidate else None
            )["candidate_build_id"],
            "source_state_sha256": _sha256_mapping(state),
            "current_pointer_path": CURRENT_POINTER_RELATIVE,
            "authoritative": True,
            "superseded_by": None,
            "current_issue_state": state,
            "stale_tick_progress_ignored": True,
            "stale_tick_progress_path": STALE_TICK_RELATIVE,
            "live_runtime_separation": machines,
            "writes_active": False,
            "writes_o04": False,
            "eligible_for_training": False,
            "training_export_allowed": False,
        }
        assert_safe_evaluation_payload(
            {
                key: value
                for key, value in payload.items()
                if key not in {"current_issue_state", "live_runtime_separation"}
            }
        )
        return payload


def resolve_current_issue_state(
    *,
    project_root: Path,
    ticks: Mapping[str, Any] | None = None,
    overlay_v2: Mapping[str, Any] | None = None,
    candidate_build_id: str | None = None,
) -> dict[str, Any]:
    del ticks
    resolver = CurrentLiveStateResolver(
        project_root=project_root,
        overlay_v2=overlay_v2,
        candidate_build_id=candidate_build_id,
    )
    return resolver.authoritative_issue_state()


def ticks_are_known_stale(ticks: Mapping[str, Any] | None) -> bool:
    """Legacy helper. Tick files are never authoritative once CURRENT.json exists."""

    del ticks
    return True
