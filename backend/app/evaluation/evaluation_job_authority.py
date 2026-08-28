"""Durable, replayable authority for evaluation-bound answer jobs.

Evaluation marker columns are routing metadata, not authority.  This module
binds every such job to one sealed lane contract and replays the originating
authorization before model work and again immediately before release.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import date
from typing import Any, Literal, cast

from ..config import Settings
from ..crypto import LocalCipher
from ..db import Database
from ..types import QuestionRequest
from .live_suite import sealed_sha256
from .live_suite_admission import (
    Live60AdmissionBinding,
    Live60EvaluationAdmissionBinding,
    validate_live60_api_admission,
)
from .owner_canary_release_snapshot import (
    OwnerCanaryReleaseFilesystemSnapshot,
    OwnerCanaryReleaseSnapshotRecheck,
    bind_owner_canary_release_runtime_objects,
    build_owner_canary_release_snapshot_plan,
    capture_owner_canary_release_filesystem_snapshot,
    require_identical_owner_canary_release_snapshots,
    require_owner_canary_release_snapshot_current,
)
from .owner_quality_canary_runtime import (
    OwnerCanaryAdmissionBinding,
    VerifiedOwnerCanaryContentGraph,
    owner_canary_idempotency_key,
    require_authoritative_canary_output_root,
    require_owner_canary_content_graph_current,
    require_owner_canary_content_graph_runtime_object_paths,
    require_verified_owner_canary_content_graph,
    validate_owner_canary_api_admission,
    verify_owner_canary_runtime_content_graph,
)

EVALUATION_JOB_AUTHORITY_SCHEMA = "legalbot.persisted-evaluation-job-authority.v1"
COMPLETION_NONRELEASE_AUTHORITY_SCHEMA = "legalbot.candidate-completion-nonrelease-job-authority.v1"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_VERIFIED_EVALUATION_RELEASE_TOKEN = object()


@dataclass(frozen=True, slots=True, init=False, repr=False)
class VerifiedEvaluationReleaseAuthority:
    """Opaque capability minted only after a complete current lane replay."""

    seal_sha256: str
    _lane: str
    _owner_canary_snapshot: OwnerCanaryReleaseFilesystemSnapshot | None
    _owner_canary_content_graph: VerifiedOwnerCanaryContentGraph | None
    _token: object

    def __init__(
        self,
        seal_sha256: str,
        *,
        _lane: str,
        _owner_canary_snapshot: OwnerCanaryReleaseFilesystemSnapshot | None,
        _owner_canary_content_graph: VerifiedOwnerCanaryContentGraph | None,
        _token: object,
    ) -> None:
        if (
            _token is not _VERIFIED_EVALUATION_RELEASE_TOKEN
            or not _SHA256.fullmatch(seal_sha256)
            or _lane not in {"owner_quality_canary", "live60_evaluation_v2", "live60_o04_v1"}
            or (_lane == "owner_quality_canary")
            != (type(_owner_canary_snapshot) is OwnerCanaryReleaseFilesystemSnapshot)
            or (_owner_canary_content_graph is not None and _lane != "owner_quality_canary")
            or (
                _owner_canary_content_graph is not None
                and type(_owner_canary_content_graph) is not VerifiedOwnerCanaryContentGraph
            )
        ):
            raise ValueError("verified evaluation release authority is invalid")
        object.__setattr__(self, "seal_sha256", seal_sha256)
        object.__setattr__(self, "_lane", _lane)
        object.__setattr__(self, "_owner_canary_snapshot", _owner_canary_snapshot)
        object.__setattr__(self, "_owner_canary_content_graph", _owner_canary_content_graph)
        object.__setattr__(self, "_token", _token)

    def __repr__(self) -> str:
        return "<VerifiedEvaluationReleaseAuthority>"


def verified_evaluation_release_authority_sha256(value: object) -> str:
    if (
        type(value) is not VerifiedEvaluationReleaseAuthority
        or value._token is not _VERIFIED_EVALUATION_RELEASE_TOKEN
    ):
        raise RuntimeError("evaluation release authority was not replayed")
    return value.seal_sha256


def require_verified_owner_canary_release_snapshot_current(
    value: object,
) -> OwnerCanaryReleaseSnapshotRecheck:
    """Recheck only the opaque owner-canary capability's raw-path snapshot."""

    if (
        type(value) is not VerifiedEvaluationReleaseAuthority
        or value._token is not _VERIFIED_EVALUATION_RELEASE_TOKEN
        or value._lane != "owner_quality_canary"
        or type(value._owner_canary_snapshot) is not OwnerCanaryReleaseFilesystemSnapshot
    ):
        raise RuntimeError("owner-canary release snapshot authority was not replayed")
    return require_owner_canary_release_snapshot_current(value._owner_canary_snapshot)


def verified_owner_canary_content_graph(value: object) -> VerifiedOwnerCanaryContentGraph:
    """Extract only the opaque graph capability from a replayed lane authority."""

    if (
        type(value) is not VerifiedEvaluationReleaseAuthority
        or value._token is not _VERIFIED_EVALUATION_RELEASE_TOKEN
        or value._lane != "owner_quality_canary"
    ):
        raise RuntimeError("owner-canary evaluation authority was not replayed")
    return require_verified_owner_canary_content_graph(value._owner_canary_content_graph)


def require_verified_owner_canary_content_graph_current(
    connection: Any,
    *,
    authority: object,
    candidate_build_id: str,
    case_id: str,
    as_of_date: date,
    job_id: str,
    answer_id: str,
) -> VerifiedOwnerCanaryContentGraph:
    """Recompute the opaque graph at the atomic release boundary."""

    return require_owner_canary_content_graph_current(
        connection,
        capability=verified_owner_canary_content_graph(authority),
        candidate_build_id=candidate_build_id,
        case_id=case_id,
        as_of_date=as_of_date,
        job_id=job_id,
        answer_id=answer_id,
    )


def _seal(value: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(value)
    payload["seal_sha256"] = sealed_sha256(payload)
    return payload


def build_evaluation_job_authority(
    binding: Live60AdmissionBinding
    | Live60EvaluationAdmissionBinding
    | OwnerCanaryAdmissionBinding,
) -> dict[str, Any]:
    """Project one already-replayed API admission into a durable lane contract."""

    if isinstance(binding, OwnerCanaryAdmissionBinding):
        return _seal(
            {
                "schema": EVALUATION_JOB_AUTHORITY_SCHEMA,
                "lane": "owner_quality_canary",
                "mode": "candidate_pinned_evaluation_release",
                "run_id": binding.run_id,
                "case_id": binding.case_id,
                "request_sha256": binding.request_sha256,
                "candidate_build_id": binding.candidate_build_id,
                "authorization_seal_sha256": binding.authorization_seal_sha256,
                "canary_manifest_seal_sha256": binding.context.manifest.seal_sha256,
                "review_date": binding.review_date.isoformat(),
                "review_lane": binding.lane,
                "attempt_number": binding.attempt_number,
                "input_revision_sha256": binding.input_revision_sha256,
                "attempt_request_seal_sha256": binding.attempt_request_seal_sha256,
                "owned_runtime_start_attestation_sha256": (
                    binding.owned_runtime_start_attestation_sha256
                ),
                "owned_runtime_instance_sha256": binding.owned_runtime_instance_sha256,
                "owned_runtime_memory_policy_sha256": (binding.owned_runtime_memory_policy_sha256),
                "owned_runtime_before_checkpoint_sha256": (
                    binding.owned_runtime_before_checkpoint_sha256
                ),
                "owned_runtime_frontier_generation": (binding.owned_runtime_frontier_generation),
                "owned_runtime_state": binding.owned_runtime_state,
                "writes_active": False,
                "release_allowed": True,
            }
        )
    if isinstance(binding, Live60EvaluationAdmissionBinding):
        return _seal(
            {
                "schema": EVALUATION_JOB_AUTHORITY_SCHEMA,
                "lane": "live60_evaluation_v2",
                "mode": "candidate_pinned_evaluation_release",
                "run_id": binding.evaluation_run_id,
                "case_id": binding.case_id,
                "request_sha256": binding.request_sha256,
                "candidate_build_id": binding.candidate_build_id,
                "authorization_seal_sha256": binding.authorization_seal_sha256,
                "overlay_seal_sha256": binding.overlay_seal_sha256,
                "stage_a_result_sha256": binding.stage_a_result_sha256,
                "writes_active": False,
                "release_allowed": True,
            }
        )
    runtime = asdict(binding.runtime)
    runtime["as_of_date"] = binding.runtime.as_of_date.isoformat()
    return _seal(
        {
            "schema": EVALUATION_JOB_AUTHORITY_SCHEMA,
            "lane": "live60_o04_v1",
            "mode": "active_bound_o04_evaluation_release",
            "run_id": binding.runtime.run_id,
            # The caller supplies the immutable case ID separately below.
            "case_id": "__replace_case_id__",
            "request_sha256": binding.request_sha256,
            "candidate_build_id": binding.runtime.index_build_id,
            "runtime_binding_sha256": sealed_sha256(runtime),
            "writes_active": False,
            "release_allowed": True,
        }
    )


def bind_evaluation_job_case(
    authority: Mapping[str, Any], *, run_id: str, case_id: str
) -> dict[str, Any]:
    """Finish the legacy lane's case binding without weakening other lanes."""

    payload = dict(authority)
    if payload.get("lane") == "live60_o04_v1":
        if payload.get("run_id") != run_id or payload.get("case_id") != "__replace_case_id__":
            raise ValueError("legacy evaluation authority run binding differs")
        payload["case_id"] = case_id
        payload["seal_sha256"] = sealed_sha256(payload)
    if payload.get("run_id") != run_id or payload.get("case_id") != case_id:
        raise ValueError("evaluation authority run/case binding differs")
    return payload


def build_completion_nonrelease_job_authority(
    *,
    run_id: str,
    case_id: str,
    request_sha256: str,
    candidate_build_id: str,
    runtime_binding_sha256: str,
) -> dict[str, Any]:
    return _seal(
        {
            "schema": COMPLETION_NONRELEASE_AUTHORITY_SCHEMA,
            "lane": "candidate_completion_preflight",
            "mode": "isolated_nonrelease",
            "run_id": run_id,
            "case_id": case_id,
            "request_sha256": request_sha256,
            "candidate_build_id": candidate_build_id,
            "runtime_binding_sha256": runtime_binding_sha256,
            "writes_active": False,
            "release_allowed": False,
        }
    )


def load_job_authority(row: Any) -> dict[str, Any]:
    raw = row["evaluation_authority_json"]
    observed_seal = str(row["evaluation_authority_sha256"] or "")
    try:
        value = json.loads(str(raw or ""))
    except json.JSONDecodeError as exc:
        raise RuntimeError("evaluation_job_authority_invalid") from exc
    if (
        not isinstance(value, dict)
        or not _SHA256.fullmatch(observed_seal)
        or value.get("seal_sha256") != observed_seal
        or sealed_sha256(value) != observed_seal
        or value.get("run_id") != row["evaluation_run_id"]
        or value.get("case_id") != row["evaluation_case_id"]
        or value.get("request_sha256") != row["evaluation_request_sha256"]
        or value.get("candidate_build_id") != row["pinned_index_build_id"]
    ):
        raise RuntimeError("evaluation_job_authority_invalid")
    return value


def verify_completion_nonrelease_job_authority(
    row: Any,
    *,
    expected_candidate_build_id: str,
    expected_runtime_binding_sha256: str,
) -> str:
    value = load_job_authority(row)
    if (
        value.get("schema") != COMPLETION_NONRELEASE_AUTHORITY_SCHEMA
        or value.get("lane") != "candidate_completion_preflight"
        or value.get("mode") != "isolated_nonrelease"
        or value.get("candidate_build_id") != expected_candidate_build_id
        or value.get("runtime_binding_sha256") != expected_runtime_binding_sha256
        or value.get("writes_active") is not False
        or value.get("release_allowed") is not False
    ):
        raise RuntimeError("completion_nonrelease_job_authority_invalid")
    return str(value["seal_sha256"])


def replay_evaluation_job_authority(
    *,
    settings: Settings,
    database: Database,
    cipher: LocalCipher,
    row: Any,
    payload: QuestionRequest,
    answer_id: str | None = None,
    owner_canary_publication_phase: Literal["pre_release", "released"] | None = None,
    connection: Any | None = None,
) -> VerifiedEvaluationReleaseAuthority:
    """Replay the corresponding sealed lane and return its immutable seal."""

    replay_database = database.snapshot_view(connection) if connection is not None else database
    value = load_job_authority(row)
    if (
        value.get("schema") != EVALUATION_JOB_AUTHORITY_SCHEMA
        or value.get("writes_active") is not False
        or value.get("release_allowed") is not True
        or str(row["job_type"] or "") != "answer"
        or row["normal_live_authority_sha256"] not in (None, "")
    ):
        raise RuntimeError("evaluation_job_authority_invalid")
    lane = value.get("lane")
    if lane in {"live60_evaluation_v2", "live60_o04_v1"}:
        raise RuntimeError(
            "TECHNICAL_IMPLEMENTATION_REQUIRED:"
            "superseded_evaluation_release_content_certification_missing"
        )
    exact_keys_by_lane = {
        "owner_quality_canary": {
            "schema",
            "lane",
            "mode",
            "run_id",
            "case_id",
            "request_sha256",
            "candidate_build_id",
            "authorization_seal_sha256",
            "canary_manifest_seal_sha256",
            "review_date",
            "review_lane",
            "attempt_number",
            "input_revision_sha256",
            "attempt_request_seal_sha256",
            "owned_runtime_start_attestation_sha256",
            "owned_runtime_instance_sha256",
            "owned_runtime_memory_policy_sha256",
            "owned_runtime_before_checkpoint_sha256",
            "owned_runtime_frontier_generation",
            "owned_runtime_state",
            "writes_active",
            "release_allowed",
            "seal_sha256",
        },
        "live60_evaluation_v2": {
            "schema",
            "lane",
            "mode",
            "run_id",
            "case_id",
            "request_sha256",
            "candidate_build_id",
            "authorization_seal_sha256",
            "overlay_seal_sha256",
            "stage_a_result_sha256",
            "writes_active",
            "release_allowed",
            "seal_sha256",
        },
        "live60_o04_v1": {
            "schema",
            "lane",
            "mode",
            "run_id",
            "case_id",
            "request_sha256",
            "candidate_build_id",
            "runtime_binding_sha256",
            "writes_active",
            "release_allowed",
            "seal_sha256",
        },
    }
    if set(value) != exact_keys_by_lane.get(str(lane), set()):
        raise RuntimeError("evaluation_job_authority_shape_invalid")
    expected_mode = (
        "active_bound_o04_evaluation_release"
        if lane == "live60_o04_v1"
        else "candidate_pinned_evaluation_release"
    )
    if value.get("mode") != expected_mode:
        raise RuntimeError("evaluation_job_authority_mode_invalid")
    run_id = str(value["run_id"])
    case_id = str(value["case_id"])
    observed: tuple[Any, ...]
    expected: tuple[Any, ...]
    owner_canary_snapshot: OwnerCanaryReleaseFilesystemSnapshot | None = None
    owner_canary_content_graph: VerifiedOwnerCanaryContentGraph | None = None
    if lane == "owner_quality_canary":
        replay_review_date = date.fromisoformat(str(value["review_date"]))
        replay_review_lane = value.get("review_lane")
        if replay_review_lane not in {"development", "blind_holdout"}:
            raise RuntimeError("evaluation_job_authority_review_lane_invalid")
        # This repeats only the owner-policy root check so a still-unresolved
        # privacy decision keeps its established stop reason.  The subsequent
        # filesystem snapshot then brackets the full, expensive admission
        # replay without persisting any raw path.
        private_review_root = require_authoritative_canary_output_root(
            settings,
            cast(Literal["development", "blind_holdout"], replay_review_lane),
        )
        snapshot_plan = build_owner_canary_release_snapshot_plan(
            settings=settings,
            private_review_root=private_review_root,
            review_date=replay_review_date,
            run_id=run_id,
            candidate_build_id=str(value["candidate_build_id"]),
        )
        if answer_id is not None:
            object_rows = replay_database.fetchall(
                """
                SELECT DISTINCT ro.relative_path
                FROM runtime_objects ro
                WHERE ro.object_key IN (
                  SELECT output_object_key FROM job_stage_attempts
                  WHERE job_id=? AND output_object_key IS NOT NULL
                  UNION
                  SELECT object_key FROM evidence_packs
                  WHERE job_id=? AND object_key IS NOT NULL
                )
                ORDER BY ro.relative_path
                """,
                (str(row["id"]), str(row["id"])),
            )
            snapshot_plan = bind_owner_canary_release_runtime_objects(
                snapshot_plan,
                tuple(str(item["relative_path"]) for item in object_rows),
            )
        before_replay = capture_owner_canary_release_filesystem_snapshot(snapshot_plan)
        owner_binding = validate_owner_canary_api_admission(
            settings=settings,
            database=replay_database,
            review_date=replay_review_date,
            lane=cast(Literal["development", "blind_holdout"], replay_review_lane),
            run_id=run_id,
            case_id=case_id,
            attempt_number=int(value["attempt_number"]),
            input_revision_sha256=str(value["input_revision_sha256"]),
            attempt_request_seal_sha256=str(value["attempt_request_seal_sha256"]),
            raw_idempotency_key=owner_canary_idempotency_key(
                str(value["attempt_request_seal_sha256"])
            ),
            payload=payload,
        )
        if (answer_id is None) != (owner_canary_publication_phase is None):
            raise RuntimeError("owner_canary_content_graph_request_incomplete")
        if answer_id is not None:
            if owner_canary_publication_phase not in {"pre_release", "released"}:
                raise RuntimeError("owner_canary_content_graph_phase_invalid")
            owner_canary_content_graph, _envelope = verify_owner_canary_runtime_content_graph(
                settings=settings,
                database=database,
                cipher=cipher,
                binding=owner_binding,
                answer_id=answer_id,
                publication_phase=owner_canary_publication_phase,
                connection=connection,
            )
            require_owner_canary_content_graph_runtime_object_paths(
                owner_canary_content_graph,
                snapshot_plan.runtime_object_relative_paths,
            )
        owner_canary_snapshot = require_identical_owner_canary_release_snapshots(
            before_replay,
            capture_owner_canary_release_filesystem_snapshot(snapshot_plan),
        )
        observed = (
            owner_binding.lane,
            owner_binding.request_sha256,
            owner_binding.candidate_build_id,
            owner_binding.authorization_seal_sha256,
            owner_binding.context.manifest.seal_sha256,
            owner_binding.owned_runtime_start_attestation_sha256,
            owner_binding.owned_runtime_instance_sha256,
            owner_binding.owned_runtime_memory_policy_sha256,
            owner_binding.owned_runtime_before_checkpoint_sha256,
            owner_binding.owned_runtime_frontier_generation,
            owner_binding.owned_runtime_state,
        )
        expected = (
            replay_review_lane,
            value.get("request_sha256"),
            value.get("candidate_build_id"),
            value.get("authorization_seal_sha256"),
            value.get("canary_manifest_seal_sha256"),
            value.get("owned_runtime_start_attestation_sha256"),
            value.get("owned_runtime_instance_sha256"),
            value.get("owned_runtime_memory_policy_sha256"),
            value.get("owned_runtime_before_checkpoint_sha256"),
            value.get("owned_runtime_frontier_generation"),
            value.get("owned_runtime_state"),
        )
    elif lane in {"live60_evaluation_v2", "live60_o04_v1"}:
        live_binding = validate_live60_api_admission(
            settings=settings,
            cipher=cipher,
            run_id=run_id,
            case_id=case_id,
            payload=payload,
            database=replay_database,
        )
        if lane == "live60_evaluation_v2":
            if not isinstance(live_binding, Live60EvaluationAdmissionBinding):
                raise RuntimeError("evaluation_job_authority_lane_changed")
            observed = (
                live_binding.request_sha256,
                live_binding.candidate_build_id,
                live_binding.authorization_seal_sha256,
                live_binding.overlay_seal_sha256,
                live_binding.stage_a_result_sha256,
            )
            expected = (
                value.get("request_sha256"),
                value.get("candidate_build_id"),
                value.get("authorization_seal_sha256"),
                value.get("overlay_seal_sha256"),
                value.get("stage_a_result_sha256"),
            )
        else:
            if not isinstance(live_binding, Live60AdmissionBinding):
                raise RuntimeError("evaluation_job_authority_lane_changed")
            runtime = asdict(live_binding.runtime)
            runtime["as_of_date"] = live_binding.runtime.as_of_date.isoformat()
            observed = (
                live_binding.request_sha256,
                live_binding.runtime.index_build_id,
                sealed_sha256(runtime),
            )
            expected = (
                value.get("request_sha256"),
                value.get("candidate_build_id"),
                value.get("runtime_binding_sha256"),
            )
    else:
        raise RuntimeError("evaluation_job_authority_lane_invalid")
    if observed != expected:
        raise RuntimeError("evaluation_job_authority_replay_mismatch")
    return VerifiedEvaluationReleaseAuthority(
        str(value["seal_sha256"]),
        _lane=str(lane),
        _owner_canary_snapshot=owner_canary_snapshot,
        _owner_canary_content_graph=owner_canary_content_graph,
        _token=_VERIFIED_EVALUATION_RELEASE_TOKEN,
    )
