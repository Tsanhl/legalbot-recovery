"""Hash-pinned authority for visible, non-ACTIVE local-Qwen development jobs.

The HTTP headers only identify a case.  Authority comes from a fixed file in
the isolated runtime whose raw bytes are pinned in process configuration.  The
same file and request binding are replayed by the worker and release boundary.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, cast

from ..assessment.guidance_bundle import OWNER_ASSESSMENT_BUNDLE
from ..config import Settings
from ..contracts.schema_registry import canonical_json_bytes, load_json_strict
from ..quality.policy import POLICY_SHA256
from ..runtime_adapters import PROMPT_VERSION
from ..types import OnlineMode, QuestionRequest
from .live_suite import sealed_sha256

GE_QWEN_DEVELOPMENT_AUTHORITY_SCHEMA = "legalbot.ge-qwen-development-authority.v1"
GE_QWEN_DEVELOPMENT_LANE = "ge_qwen_visible_development"
GE_QWEN_DEVELOPMENT_MODE = "candidate_pinned_reviewed_release"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_EXPECTED_DISPOSITIONS = frozenset({"supported_answer", "hold_or_clarification"})


@dataclass(frozen=True, slots=True)
class GEQwenDevelopmentAdmissionBinding:
    run_id: str
    case_id: str
    request_sha256: str
    candidate_build_id: str
    authority_file_sha256: str
    authority_seal_sha256: str
    owner_scope_sha256: str
    runtime_binding_sha256: str
    idempotency_key_sha256: str
    expected_disposition: Literal["supported_answer", "hold_or_clarification"]


def development_request_sha256(payload: QuestionRequest) -> str:
    """Digest every caller-controlled request field in its JSON form."""

    return hashlib.sha256(
        canonical_json_bytes(
            {
                "schema": "legalbot.ge-qwen-development-request.v1",
                "request": payload.model_dump(mode="json"),
            }
        )
    ).hexdigest()


def development_idempotency_key_sha256(raw_idempotency_key: str) -> str:
    return hashlib.sha256(raw_idempotency_key.encode("utf-8")).hexdigest()


def persisted_job_idempotency_key(raw_idempotency_key: str) -> str:
    return hashlib.sha256(
        f"legalbot-intake-v1\0{raw_idempotency_key}".encode("utf-8")
    ).hexdigest()


def expected_runtime_binding(settings: Settings) -> dict[str, Any]:
    return {
        "schema": "legalbot.ge-qwen-development-runtime-binding.v1",
        "development_state_id": settings.development_state_id,
        "candidate_build_id": settings.development_candidate_build_id,
        "retrieval_manifest_sha256": settings.development_retrieval_manifest_sha256,
        "model_id": settings.model_id,
        "model_url": settings.model_url,
        "prompt_version": PROMPT_VERSION,
        "policy_sha256": POLICY_SHA256,
        "assessment_bundle_sha256": OWNER_ASSESSMENT_BUNDLE.sha256,
        "online_mode": OnlineMode.LOCAL_ONLY.value,
        "official_research_enabled": False,
        "adapter_id": None,
    }


def runtime_binding_sha256(settings: Settings) -> str:
    return hashlib.sha256(canonical_json_bytes(expected_runtime_binding(settings))).hexdigest()


def seal_ge_qwen_development_authority(value: Mapping[str, Any]) -> dict[str, Any]:
    sealed = dict(value)
    sealed["seal_sha256"] = sealed_sha256(sealed)
    return sealed


def _timestamp(value: object, *, label: str) -> datetime:
    try:
        result = datetime.fromisoformat(str(value))
    except ValueError as exc:
        raise RuntimeError(f"development_authority_{label}_invalid") from exc
    if result.tzinfo is None:
        raise RuntimeError(f"development_authority_{label}_invalid")
    return result.astimezone(UTC)


def _load_authority(settings: Settings) -> tuple[dict[str, Any], str]:
    configured_sha256 = str(settings.development_authority_sha256 or "")
    if not _SHA256.fullmatch(configured_sha256):
        raise RuntimeError("development_authority_not_configured")
    path = settings.development_authority_path
    if path.is_symlink() or not path.is_file() or path.resolve() != path:
        raise RuntimeError("development_authority_file_invalid")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != configured_sha256:
        raise RuntimeError("development_authority_file_sha256_mismatch")
    value = load_json_strict(raw)
    if not isinstance(value, dict):
        raise RuntimeError("development_authority_shape_invalid")
    exact_keys = {
        "schema",
        "run_id",
        "owner_scope_sha256",
        "development_state_id",
        "candidate_build_id",
        "runtime_binding",
        "issued_at",
        "expires_at",
        "cases",
        "writes_active",
        "release_allowed",
        "release_audience",
        "seal_sha256",
    }
    if set(value) != exact_keys:
        raise RuntimeError("development_authority_shape_invalid")
    if (
        value.get("schema") != GE_QWEN_DEVELOPMENT_AUTHORITY_SCHEMA
        or not _SAFE_ID.fullmatch(str(value.get("run_id") or ""))
        or not _SHA256.fullmatch(str(value.get("owner_scope_sha256") or ""))
        or value.get("development_state_id") != settings.development_state_id
        or value.get("candidate_build_id") != settings.development_candidate_build_id
        or value.get("runtime_binding") != expected_runtime_binding(settings)
        or value.get("writes_active") is not False
        or value.get("release_allowed") is not True
        or value.get("release_audience") != "owner_evaluation"
        or not isinstance(value.get("cases"), list)
        or not value["cases"]
        or value.get("seal_sha256") != sealed_sha256(value)
    ):
        raise RuntimeError("development_authority_invalid")
    issued_at = _timestamp(value["issued_at"], label="issued_at")
    expires_at = _timestamp(value["expires_at"], label="expires_at")
    now = datetime.now(UTC)
    if issued_at > now or expires_at <= issued_at or expires_at <= now:
        raise RuntimeError("development_authority_expired_or_not_yet_valid")
    case_ids: set[str] = set()
    for case in value["cases"]:
        if not isinstance(case, dict) or set(case) != {
            "case_id",
            "request_sha256",
            "idempotency_key_sha256",
            "expected_disposition",
        }:
            raise RuntimeError("development_authority_case_shape_invalid")
        case_id = str(case.get("case_id") or "")
        if (
            not _SAFE_ID.fullmatch(case_id)
            or case_id in case_ids
            or not _SHA256.fullmatch(str(case.get("request_sha256") or ""))
            or not _SHA256.fullmatch(str(case.get("idempotency_key_sha256") or ""))
            or case.get("expected_disposition") not in _EXPECTED_DISPOSITIONS
        ):
            raise RuntimeError("development_authority_case_invalid")
        case_ids.add(case_id)
    return cast(dict[str, Any], value), configured_sha256


def _case(value: Mapping[str, Any], case_id: str) -> Mapping[str, Any]:
    matches = [case for case in value["cases"] if case.get("case_id") == case_id]
    if len(matches) != 1:
        raise RuntimeError("development_authority_case_not_authorised")
    return cast(Mapping[str, Any], matches[0])


def validate_ge_qwen_development_api_admission(
    *,
    settings: Settings,
    run_id: str,
    case_id: str,
    supplied_authority_file_sha256: str,
    raw_idempotency_key: str,
    payload: QuestionRequest,
) -> GEQwenDevelopmentAdmissionBinding:
    if payload.as_of_date is None or payload.online_mode != OnlineMode.LOCAL_ONLY:
        raise RuntimeError("development_request_requires_date_and_local_only_mode")
    value, authority_file_sha256 = _load_authority(settings)
    if (
        supplied_authority_file_sha256 != authority_file_sha256
        or value["run_id"] != run_id
    ):
        raise RuntimeError("development_authority_header_mismatch")
    case = _case(value, case_id)
    request_sha256 = development_request_sha256(payload)
    key_sha256 = development_idempotency_key_sha256(raw_idempotency_key)
    if (
        case["request_sha256"] != request_sha256
        or case["idempotency_key_sha256"] != key_sha256
    ):
        raise RuntimeError("development_authority_request_mismatch")
    return GEQwenDevelopmentAdmissionBinding(
        run_id=run_id,
        case_id=case_id,
        request_sha256=request_sha256,
        candidate_build_id=str(value["candidate_build_id"]),
        authority_file_sha256=authority_file_sha256,
        authority_seal_sha256=str(value["seal_sha256"]),
        owner_scope_sha256=str(value["owner_scope_sha256"]),
        runtime_binding_sha256=runtime_binding_sha256(settings),
        idempotency_key_sha256=persisted_job_idempotency_key(raw_idempotency_key),
        expected_disposition=cast(
            Literal["supported_answer", "hold_or_clarification"],
            case["expected_disposition"],
        ),
    )


def replay_ge_qwen_development_admission(
    *,
    settings: Settings,
    row: Any,
    payload: QuestionRequest,
    authority: Mapping[str, Any],
) -> GEQwenDevelopmentAdmissionBinding:
    value, authority_file_sha256 = _load_authority(settings)
    run_id = str(authority.get("run_id") or "")
    case_id = str(authority.get("case_id") or "")
    case = _case(value, case_id)
    request_sha256 = development_request_sha256(payload)
    observed = (
        value.get("run_id"),
        value.get("candidate_build_id"),
        authority_file_sha256,
        value.get("seal_sha256"),
        value.get("owner_scope_sha256"),
        runtime_binding_sha256(settings),
        case.get("request_sha256"),
        str(row["idempotency_key"] or ""),
        case.get("expected_disposition"),
    )
    expected = (
        run_id,
        authority.get("candidate_build_id"),
        authority.get("authority_file_sha256"),
        authority.get("authorization_seal_sha256"),
        authority.get("owner_scope_sha256"),
        authority.get("runtime_binding_sha256"),
        request_sha256,
        authority.get("idempotency_key_sha256"),
        authority.get("expected_disposition"),
    )
    if observed != expected or request_sha256 != str(row["evaluation_request_sha256"] or ""):
        raise RuntimeError("development_authority_replay_mismatch")
    return GEQwenDevelopmentAdmissionBinding(
        run_id=run_id,
        case_id=case_id,
        request_sha256=request_sha256,
        candidate_build_id=str(value["candidate_build_id"]),
        authority_file_sha256=authority_file_sha256,
        authority_seal_sha256=str(value["seal_sha256"]),
        owner_scope_sha256=str(value["owner_scope_sha256"]),
        runtime_binding_sha256=runtime_binding_sha256(settings),
        idempotency_key_sha256=str(row["idempotency_key"]),
        expected_disposition=cast(
            Literal["supported_answer", "hold_or_clarification"],
            case["expected_disposition"],
        ),
    )


__all__ = [
    "GEQwenDevelopmentAdmissionBinding",
    "GE_QWEN_DEVELOPMENT_AUTHORITY_SCHEMA",
    "GE_QWEN_DEVELOPMENT_LANE",
    "development_idempotency_key_sha256",
    "development_request_sha256",
    "expected_runtime_binding",
    "replay_ge_qwen_development_admission",
    "runtime_binding_sha256",
    "seal_ge_qwen_development_authority",
    "validate_ge_qwen_development_api_admission",
]
