"""Sealed semantic verification result. A caller boolean is not gold."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any, Literal, Self
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..orchestration.contracts import ModelDraft
from .live30 import assert_safe_evaluation_payload
from .live_suite import sealed_sha256
from .prompt_templates import (
    SEMANTIC_VERIFIER_TEMPLATE_NAME,
    SEMANTIC_VERIFIER_TEMPLATE_SHA256,
    prompt_template_text,
)

SEMANTIC_RESULT_SCHEMA = "legalbot.semantic-verification-result.v2"
SemanticResultValue = Literal["supported", "unsupported", "limited", "knowledge_gap", "HOLD"]


class SemanticVerificationResultV2(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.semantic-verification-result.v2"] = Field(
        default="legalbot.semantic-verification-result.v2", alias="schema"
    )
    issue_id: str
    proposition_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_span_ids: tuple[str, ...]
    evidence_span_hashes: tuple[str, ...]
    verifier_actor: Literal["human", "ai", "hybrid", "deterministic"]
    verifier_invocation_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    verifier_prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_id: str | None = None
    model_version: str | None = None
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    toolchain_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    claims_supported: bool
    unsupported_claim_count: int = Field(ge=0)
    contradiction_count: int = Field(ge=0)
    result: SemanticResultValue
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    proposer_confidence: Literal[None] = None
    chain_of_thought: Literal[None] = None

    @model_validator(mode="after")
    def result_matches_counts(self) -> Self:
        if self.claims_supported and self.result not in {"supported", "limited"}:
            raise ValueError("supported claims require supported or limited result")
        if self.result == "supported" and (
            self.unsupported_claim_count or self.contradiction_count
        ):
            raise ValueError("supported result cannot record unsupported claims")
        if self.verifier_actor == "ai" and (not self.model_id or not self.model_version):
            raise ValueError("AI semantic result must record model identity")
        dumped = self.model_dump(mode="json", by_alias=True)
        if self.seal_sha256 != sealed_sha256(dumped):
            raise ValueError("semantic verification seal does not match its contents")
        return self

    @property
    def passed(self) -> bool:
        return (
            self.result in {"supported", "limited", "knowledge_gap"}
            and self.contradiction_count == 0
            and (
                self.result == "knowledge_gap"
                or (self.claims_supported and self.unsupported_claim_count == 0)
                or self.result == "limited"
            )
        )


def seal_semantic_verification_result(
    material: Mapping[str, Any],
) -> SemanticVerificationResultV2:
    payload = dict(material)
    payload.setdefault("schema", SEMANTIC_RESULT_SCHEMA)
    payload["proposer_confidence"] = None
    payload["chain_of_thought"] = None
    payload["seal_sha256"] = sealed_sha256(payload)
    return SemanticVerificationResultV2.model_validate(payload)


def _test_only_semantic_result(
    *,
    issue_id: str,
    proposition_hash: str,
    evidence_span_ids: Sequence[str] = (),
    evidence_span_hashes: Sequence[str] = (),
    claims_supported: bool,
    result: SemanticResultValue | None = None,
    unsupported_claim_count: int = 0,
    contradiction_count: int = 0,
    verifier_actor: Literal["human", "ai", "hybrid", "deterministic"] = "deterministic",
    verifier_invocation_id: str = "invoke-test-semantic-01",
    policy_sha256: str | None = None,
    toolchain_sha256: str | None = None,
    model_id: str | None = None,
    model_version: str | None = None,
) -> SemanticVerificationResultV2:
    """Unit-test helper. Not callable by the release or evaluation CLI path."""

    judged: SemanticResultValue = result or ("supported" if claims_supported else "unsupported")
    return seal_semantic_verification_result(
        {
            "issue_id": issue_id,
            "proposition_hash": proposition_hash,
            "evidence_span_ids": list(evidence_span_ids),
            "evidence_span_hashes": list(evidence_span_hashes),
            "verifier_actor": verifier_actor,
            "verifier_invocation_id": verifier_invocation_id,
            "verifier_prompt_sha256": SEMANTIC_VERIFIER_TEMPLATE_SHA256,
            "model_id": model_id,
            "model_version": model_version,
            "policy_sha256": policy_sha256 or ("a" * 64),
            "toolchain_sha256": toolchain_sha256 or ("b" * 64),
            "claims_supported": claims_supported,
            "unsupported_claim_count": unsupported_claim_count,
            "contradiction_count": contradiction_count,
            "result": judged,
        }
    )


def _parse_verifier_json(raw: str | Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(raw) if isinstance(raw, Mapping) else json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("semantic verifier returned a non-object")
    return payload


async def invoke_semantic_verifier(
    *,
    model: Any,
    issue_id: str,
    proposition_hash: str,
    proposition_text: str,
    evidence: Sequence[Mapping[str, Any]],
    legal_locator: str | None,
    source_identity: str | None,
    citation_metadata: Mapping[str, Any] | None,
    currentness_status: str | None,
    policy_sha256: str,
    toolchain_sha256: str,
    model_id: str,
    model_version: str,
) -> SemanticVerificationResultV2:
    """Independent verifier invocation. Does not receive proposer confidence."""

    invocation_id = f"invoke-semantic-{uuid4().hex[:24]}"
    user_payload = {
        "mode": "semantic_verify",
        "issue_id": issue_id,
        "proposition_hash": proposition_hash,
        "proposition_text": proposition_text,
        "legal_locator": legal_locator,
        "source_identity": source_identity,
        "citation_metadata": dict(citation_metadata or {}),
        "currentness_status": currentness_status,
        "evidence": [
            {
                "id": item.get("id") or item.get("chunk_id"),
                "content_sha256": item.get("content_sha256"),
                "text": item.get("text") or item.get("markdown_text"),
                "legal_locator": item.get("legal_locator") or item.get("locator"),
                "source_version_id": item.get("source_version_id"),
                "legal_authority_id": item.get("legal_authority_id"),
                "currentness_status": item.get("currentness_status"),
            }
            for item in evidence
        ],
        "proposer_confidence": None,
    }
    parsed: dict[str, Any]
    if hasattr(model, "invoke_json"):
        _invocation, parsed = await model.invoke_json(
            system_prompt=prompt_template_text(SEMANTIC_VERIFIER_TEMPLATE_NAME),
            user_payload=user_payload,
            mode="semantic_verify",
        )
        if isinstance(_invocation, str) and _invocation:
            invocation_id = _invocation
    else:
        draft = await model.draft(
            question=json.dumps(user_payload, sort_keys=True),
            task_type="general",
            jurisdiction="England and Wales",
            as_of_date=__import__("datetime").date(2026, 8, 16),
            word_target=200,
            evidence=(),
            assessment_rules=(),
        )
        if not isinstance(draft, ModelDraft):
            raise ValueError("semantic verifier model returned an invalid draft")
        parsed = _parse_verifier_json(draft.raw_text or draft.structured.model_dump())
    result = str(parsed.get("result") or "HOLD")
    if result not in {"supported", "unsupported", "limited", "knowledge_gap", "HOLD"}:
        result = "HOLD"
    claims_supported = parsed.get("claims_supported") is True and result in {
        "supported",
        "limited",
    }
    return seal_semantic_verification_result(
        {
            "issue_id": str(parsed.get("issue_id") or issue_id),
            "proposition_hash": proposition_hash,
            "evidence_span_ids": [
                str(item.get("id") or item.get("chunk_id") or "")
                for item in evidence
                if item.get("id") or item.get("chunk_id")
            ],
            "evidence_span_hashes": [
                str(item.get("content_sha256") or "")
                for item in evidence
                if item.get("content_sha256")
            ],
            "verifier_actor": "ai",
            "verifier_invocation_id": invocation_id,
            "verifier_prompt_sha256": SEMANTIC_VERIFIER_TEMPLATE_SHA256,
            "model_id": model_id,
            "model_version": model_version,
            "policy_sha256": policy_sha256,
            "toolchain_sha256": toolchain_sha256,
            "claims_supported": claims_supported,
            "unsupported_claim_count": int(parsed.get("unsupported_claim_count") or 0),
            "contradiction_count": int(parsed.get("contradiction_count") or 0),
            "result": result,
        }
    )


def assert_independent_invocations(
    *,
    proposer_invocation_id: str,
    verifier_invocation_id: str,
    proposer_prompt_sha256: str,
    verifier_prompt_sha256: str,
) -> None:
    if proposer_invocation_id == verifier_invocation_id:
        raise ValueError("proposer invocation cannot stamp approval")
    if proposer_prompt_sha256 == verifier_prompt_sha256:
        raise ValueError("semantic verifier must use a different prompt template")
    assert_safe_evaluation_payload(
        {
            "proposer_invocation_id": proposer_invocation_id,
            "verifier_invocation_id": verifier_invocation_id,
        }
    )
