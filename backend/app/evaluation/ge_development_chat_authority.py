"""Owner-local, candidate-pinned chat admission for development only.

The authority file is pinned by its raw SHA-256 at API and worker startup.
Each job freezes the request, provider route and candidate; replay never trusts
the browser's route header. This lane is distinct from the exact-case Qwen
evaluation lane and cannot grant normal-live or ACTIVE authority.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

from ..assessment.guidance_bundle import OWNER_ASSESSMENT_BUNDLE
from ..config import Settings
from ..contracts.schema_registry import canonical_json_bytes, load_json_strict
from ..quality.policy import POLICY_SHA256
from ..runtime_adapters import PROMPT_VERSION
from ..types import OnlineMode, QuestionRequest
from .ge_qwen_development_authority import (
    development_request_sha256,
    persisted_job_idempotency_key,
)
from .live_suite import sealed_sha256

GE_DEVELOPMENT_CHAT_LANE = "ge_owner_development_chat"
GE_DEVELOPMENT_CHAT_SCHEMA = "legalbot.ge-owner-development-chat-authority.v1"
GE_SESSION_CHAT_SCHEMA = "legalbot.ge-owner-development-chat-authority.v2"
_SHA = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_ROUTE_KINDS = frozenset({"qwen_local", "local_endpoint", "hosted_api", "anthropic_api", "gemini_api", "codex_bridge"})


@dataclass(frozen=True, slots=True)
class GEDevelopmentChatAdmissionBinding:
    run_id: str
    case_id: str
    request_sha256: str
    candidate_build_id: str
    authority_file_sha256: str
    authority_seal_sha256: str
    owner_scope_sha256: str
    runtime_binding_sha256: str
    idempotency_key_sha256: str
    route_id: str
    route_sha256: str
    remote_processing_consent: bool
    expected_disposition: str = "supported_answer"


def route_sha256(route: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(route)).hexdigest()


def chat_runtime_binding_sha256(settings: Settings, route: Mapping[str, Any]) -> str:
    app_root = Path(__file__).resolve().parents[1]
    route_adapter_sha256 = hashlib.sha256((app_root / "model_routes.py").read_bytes()).hexdigest()
    prompt_gateway_sha256 = hashlib.sha256((app_root / "runtime_adapters.py").read_bytes()).hexdigest()
    answer_path_sha256 = {
        name: hashlib.sha256((app_root / name).read_bytes()).hexdigest()
        for name in (
            "orchestration/behavior.py", "orchestration/runner.py", "orchestration/worker.py",
            "orchestration/answer_structure.py", "orchestration/retry_policy.py",
            "orchestration/targeted_repair.py", "citations/oscola.py",
            "orchestration/gaps.py",
            "types.py", "quality/fact_provenance.py", "quality/ai_evidence_reviewer.py",
            "contracts/runtime_selected_chain.py", "research/runtime.py",
            "quality/evaluator.py", "assessment/guidance_bundle.py",
            "assessment/rules.py", "assessment/standards_scoring.py",
            "retrieval/reviewed_research_generation.py",
            "retrieval/development_query.py", "connections.py", "api/chat.py",
            "conversations/chat_facts.py", "conversations/clarification.py",
            "research/licence_permissions.py", "research/official_capture.py", "research/case_source_review.py",
            "research/discovery.py", "research/source_registry.py", "research/adapters.py",
            "prompt_templates.py",
            "evaluation/prompts/draft_generator.v5.txt",
            "evaluation/prompts/ai_evidence_reviewer.v3.txt",
            "evaluation/prompts/full_answer_reviewer.v2.txt",
        )
    }
    codex_wrapper_sha256 = None
    if route.get("kind") == "codex_bridge":
        wrapper = settings.project_root / "scripts" / "legalbot_codex_isolation_wrapper.py"
        if wrapper.is_symlink() or not wrapper.is_file():
            raise RuntimeError("development_chat_codex_wrapper_unavailable")
        codex_wrapper_sha256 = hashlib.sha256(wrapper.read_bytes()).hexdigest()
    return hashlib.sha256(canonical_json_bytes({
        "schema": "legalbot.ge-owner-development-chat-runtime.v1",
        "development_state_id": settings.development_state_id,
        "candidate_build_id": settings.development_candidate_build_id,
        "retrieval_manifest_sha256": settings.development_retrieval_manifest_sha256,
        "route_sha256": route_sha256(route),
        "route_adapter_sha256": route_adapter_sha256,
        "prompt_gateway_sha256": prompt_gateway_sha256,
        "answer_path_sha256": answer_path_sha256,
        "codex_wrapper_sha256": codex_wrapper_sha256,
        "prompt_version": PROMPT_VERSION,
        "policy_sha256": POLICY_SHA256,
        "assessment_bundle_sha256": OWNER_ASSESSMENT_BUNDLE.sha256,
        "online_mode": settings.online_default,
        "official_research_enabled": settings.official_research_enabled,
        "official_registry_sha256": hashlib.sha256((settings.project_root / "config/official_sources.json").read_bytes()).hexdigest(),
        "adapter_id": None,
    })).hexdigest()


def _valid_route(settings: Settings, route: object) -> bool:
    required_keys = {"route_id", "kind", "model_id", "endpoint", "credential_env"}
    if not isinstance(route, dict) or (
        set(route) != required_keys
        and not (route.get("kind") == "local_endpoint" and set(route) == required_keys | {"model_version"})
        and not (route.get("kind") == "codex_bridge" and set(route) == required_keys | {"auth_mode"})
    ):
        return False
    if (
        not _ID.fullmatch(str(route.get("route_id") or ""))
        or route.get("kind") not in _ROUTE_KINDS
        or not isinstance(route.get("model_id"), str)
        or not 3 <= len(route["model_id"]) <= 200
    ):
        return False
    kind = route["kind"]
    endpoint = route["endpoint"]
    credential_env = route["credential_env"]
    if kind == "qwen_local":
        return (
            route["model_id"] == settings.model_id
            and endpoint == settings.model_url.rstrip("/")
            and credential_env is None
        )
    if kind == "local_endpoint":
        parsed = urlsplit(str(endpoint))
        return (
            parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"}
            and parsed.port is not None and not parsed.username and not parsed.password
            and parsed.path in {"", "/"} and not parsed.query and not parsed.fragment
            and credential_env is None
            and isinstance(route.get("model_version", route["model_id"]), str)
            and 3 <= len(route.get("model_version", route["model_id"])) <= 200
        )
    if kind == "hosted_api":
        return (
            endpoint == "https://api.openai.com/v1/responses"
            and credential_env == "OPENAI_API_KEY"
        )
    if kind == "anthropic_api":
        return endpoint == "https://api.anthropic.com/v1/messages" and credential_env == "ANTHROPIC_API_KEY"
    if kind == "gemini_api":
        return (
            endpoint == f"https://generativelanguage.googleapis.com/v1beta/models/{route['model_id']}:generateContent"
            and credential_env == "GEMINI_API_KEY"
            and re.fullmatch(r"[A-Za-z0-9._-]+", route["model_id"]) is not None
        )
    if route.get("auth_mode") == "chatgpt_signin":
        return endpoint is None and credential_env is None
    return endpoint is None and credential_env == "LEGALBOT_CODEX_BRIDGE_KEY"


def _load_authority(settings: Settings) -> tuple[dict[str, Any], str]:
    configured = str(settings.development_chat_authority_sha256 or "")
    if not _SHA.fullmatch(configured):
        raise RuntimeError("development_chat_authority_not_configured")
    path = settings.development_chat_authority_path
    if path.is_symlink() or not path.is_file() or path.resolve() != path:
        raise RuntimeError("development_chat_authority_file_invalid")
    raw = path.read_bytes()
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), configured):
        raise RuntimeError("development_chat_authority_hash_changed")
    value = load_json_strict(raw)
    required = {
        "schema", "run_id", "owner_scope_sha256", "development_state_id",
        "candidate_build_id", "retrieval_manifest_sha256", "access_key_sha256",
        "issued_at", "expires_at", "routes", "writes_active", "release_allowed",
        "release_audience", "seal_sha256",
    }
    if isinstance(value, dict) and value.get("schema") == GE_SESSION_CHAT_SCHEMA:
        required.add("capabilities")
    if not isinstance(value, dict) or set(value) != required:
        raise RuntimeError("development_chat_authority_shape_invalid")
    if (
        value["schema"] not in {GE_DEVELOPMENT_CHAT_SCHEMA, GE_SESSION_CHAT_SCHEMA}
        or not _ID.fullmatch(str(value["run_id"] or ""))
        or not _SHA.fullmatch(str(value["owner_scope_sha256"] or ""))
        or not _SHA.fullmatch(str(value["access_key_sha256"] or ""))
        or value["development_state_id"] != settings.development_state_id
        or value["candidate_build_id"] != settings.development_candidate_build_id
        or value["retrieval_manifest_sha256"] != settings.development_retrieval_manifest_sha256
        or value["writes_active"] is not False
        or value["release_allowed"] is not True
        or value["release_audience"] != "owner_evaluation"
        or value["seal_sha256"] != sealed_sha256(value)
        or not isinstance(value["routes"], list)
        or not value["routes"]
    ):
        raise RuntimeError("development_chat_authority_invalid")
    route_ids: set[str] = set()
    for route in value["routes"]:
        if not _valid_route(settings, route) or route["route_id"] in route_ids:
            raise RuntimeError("development_chat_route_invalid")
        route_ids.add(route["route_id"])
    try:
        issued = datetime.fromisoformat(str(value["issued_at"]))
        expires = datetime.fromisoformat(str(value["expires_at"]))
    except ValueError as exc:
        raise RuntimeError("development_chat_authority_time_invalid") from exc
    if value["schema"] == GE_SESSION_CHAT_SCHEMA and (
        value["capabilities"] != {
            "session_connections": True, "saved_conversations": True,
            "online_modes": ["local_only", "auto", "always"],
            "review_before_use": True, "shared_source_admission": False,
        } or settings.xerj_enabled or settings.phoenix_enabled
    ):
        raise RuntimeError("development_chat_capabilities_invalid")
    if (
        issued.tzinfo is None or expires.tzinfo is None
        or issued.astimezone(UTC) > datetime.now(UTC)
        or expires.astimezone(UTC) <= datetime.now(UTC)
        or expires <= issued
    ):
        raise RuntimeError("development_chat_authority_expired")
    if value["schema"] == GE_DEVELOPMENT_CHAT_SCHEMA and (
        settings.official_research_enabled or settings.xerj_enabled
        or settings.phoenix_enabled or settings.online_default != "local_only"
    ):
        raise RuntimeError("development_chat_requires_offline_research")
    return cast(dict[str, Any], value), configured


def load_development_chat_route(settings: Settings, route_id: str) -> dict[str, Any]:
    value, _ = _load_authority(settings)
    matches = [route for route in value["routes"] if route["route_id"] == route_id]
    if len(matches) != 1:
        raise RuntimeError("development_chat_route_not_authorised")
    return dict(matches[0])


def validate_development_chat_read_access(
    *, settings: Settings, supplied_authority_file_sha256: str,
    access_key: str, route_id: str,
) -> str:
    value, file_sha = _load_authority(settings)
    if (
        not hmac.compare_digest(supplied_authority_file_sha256, file_sha)
        or not hmac.compare_digest(
            hashlib.sha256(access_key.encode("utf-8")).hexdigest(),
            str(value["access_key_sha256"]),
        )
    ):
        raise RuntimeError("development_chat_read_access_invalid")
    return route_sha256(load_development_chat_route(settings, route_id))


def _case_id(raw_idempotency_key: str) -> str:
    return "chat-" + persisted_job_idempotency_key(raw_idempotency_key)[:40]


def validate_development_chat_admission(
    *, settings: Settings, supplied_authority_file_sha256: str,
    access_key: str, route_id: str, raw_idempotency_key: str,
    payload: QuestionRequest, remote_processing_consent: bool = False,
) -> GEDevelopmentChatAdmissionBinding:
    value, file_sha = _load_authority(settings)
    _validate_scope(value, payload, remote_processing_consent)
    if not hmac.compare_digest(supplied_authority_file_sha256, file_sha):
        raise RuntimeError("development_chat_authority_header_mismatch")
    if not hmac.compare_digest(
        hashlib.sha256(access_key.encode("utf-8")).hexdigest(),
        str(value["access_key_sha256"]),
    ):
        raise RuntimeError("development_chat_access_key_invalid")
    route = load_development_chat_route(settings, route_id)
    if route["kind"] in {"hosted_api", "anthropic_api", "gemini_api", "codex_bridge"} and not remote_processing_consent:
        raise RuntimeError("development_chat_remote_processing_consent_required")
    remote_processing_consent = route["kind"] in {"hosted_api", "anthropic_api", "gemini_api", "codex_bridge"} or payload.online_mode != OnlineMode.LOCAL_ONLY
    return GEDevelopmentChatAdmissionBinding(
        run_id=str(value["run_id"]),
        case_id=_case_id(raw_idempotency_key),
        request_sha256=development_request_sha256(payload),
        candidate_build_id=str(value["candidate_build_id"]),
        authority_file_sha256=file_sha,
        authority_seal_sha256=str(value["seal_sha256"]),
        owner_scope_sha256=str(value["owner_scope_sha256"]),
        runtime_binding_sha256=chat_runtime_binding_sha256(settings, route),
        idempotency_key_sha256=persisted_job_idempotency_key(raw_idempotency_key),
        route_id=route_id,
        route_sha256=route_sha256(route),
        remote_processing_consent=remote_processing_consent,
    )


def replay_development_chat_admission(
    *, settings: Settings, row: Any, payload: QuestionRequest,
    authority: Mapping[str, Any],
) -> GEDevelopmentChatAdmissionBinding:
    value, file_sha = _load_authority(settings)
    route_id = str(authority.get("route_id") or "")
    route = load_development_chat_route(settings, route_id)
    expected = (
        value["run_id"], file_sha, value["seal_sha256"],
        value["owner_scope_sha256"], chat_runtime_binding_sha256(settings, route),
        route_sha256(route), development_request_sha256(payload),
        str(row["idempotency_key"] or ""),
        route["kind"] in {"hosted_api", "anthropic_api", "gemini_api", "codex_bridge"} or payload.online_mode != OnlineMode.LOCAL_ONLY,
    )
    observed = (
        authority.get("run_id"), authority.get("authority_file_sha256"),
        authority.get("authorization_seal_sha256"), authority.get("owner_scope_sha256"),
        authority.get("runtime_binding_sha256"), authority.get("route_sha256"),
        authority.get("request_sha256"), authority.get("idempotency_key_sha256"),
        authority.get("remote_processing_consent"),
    )
    if (
        observed != expected
        or authority.get("case_id") != _case_id_from_persisted_key(str(row["idempotency_key"] or ""))
        or str(row["evaluation_request_sha256"] or "") != expected[6]
    ):
        raise RuntimeError("development_chat_replay_mismatch")
    _validate_scope(value, payload, bool(authority.get("remote_processing_consent")))
    return GEDevelopmentChatAdmissionBinding(
        run_id=str(value["run_id"]), case_id=str(authority["case_id"]),
        request_sha256=expected[6], candidate_build_id=str(value["candidate_build_id"]),
        authority_file_sha256=file_sha, authority_seal_sha256=str(value["seal_sha256"]),
        owner_scope_sha256=str(value["owner_scope_sha256"]),
        runtime_binding_sha256=expected[4],
        idempotency_key_sha256=expected[7], route_id=route_id,
        route_sha256=expected[5],
        remote_processing_consent=expected[8],
    )


def _case_id_from_persisted_key(persisted: str) -> str:
    # The raw key is deliberately unavailable to the worker. The API uses its
    # persisted digest as the stable case identity instead.
    return "chat-" + persisted[:40]


def _validate_scope(value: dict[str, Any], payload: QuestionRequest, consent: bool) -> None:
    if payload.as_of_date is None or payload.upload_ids:
        raise RuntimeError("development_chat_request_scope_invalid")
    if value["schema"] == GE_DEVELOPMENT_CHAT_SCHEMA:
        if payload.online_mode != OnlineMode.LOCAL_ONLY or payload.conversation_id or payload.connection_id:
            raise RuntimeError("development_chat_request_scope_invalid")
    elif payload.connection_id is None or payload.conversation_id is None:
        raise RuntimeError("development_chat_session_required")
    if payload.online_mode != OnlineMode.LOCAL_ONLY and not consent:
        raise RuntimeError("development_chat_remote_processing_consent_required")
