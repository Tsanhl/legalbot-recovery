from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from typing import Any, cast
from uuid import uuid4

import httpx

from .config import Settings
from .model_runtime.config import PINNED_RUNTIME_MODEL_VERSION, PINNED_RUNTIME_REPO
from .orchestration.contracts import ModelDraft
from .privacy import prompt_injection_hits, scrub_pii, scrub_prompt_data
from .prompt_templates import (
    DRAFT_GENERATOR_TEMPLATE_NAME,
    DRAFT_GENERATOR_TEMPLATE_SHA256,
    prompt_template_text,
)
from .types import (
    EvidenceSpan,
    IssueSpottingNote,
    QualityFinding,
    StructuredDraft,
    TaskType,
    UploadContextSpan,
)

PROMPT_VERSION = "evidence-first-structured-json-v4"

MODEL_CONTEXT_TOKENS = 8192
MODEL_OUTPUT_TOKENS = 2048
PROMPT_SAFETY_TOKENS = 844
MAX_INPUT_ESTIMATED_TOKENS = MODEL_CONTEXT_TOKENS - MODEL_OUTPUT_TOKENS - PROMPT_SAFETY_TOKENS
EVIDENCE_PROMPT_CHAR_BUDGET = 8500
EVIDENCE_PROMPT_TOKEN_BUDGET = 2800
REPAIR_EVIDENCE_CHAR_BUDGET = 6000
REPAIR_EVIDENCE_TOKEN_BUDGET = 1900
MAX_EVIDENCE_SPAN_CHARS = 4000
MAX_QUESTION_CHARS = 3500
MAX_ASSESSMENT_RULE_CHARS = 1800
UPLOAD_CONTEXT_CHAR_BUDGET = 3500
UPLOAD_CONTEXT_TOKEN_BUDGET = 1100

DRAFT_SYSTEM_PROMPT = prompt_template_text(DRAFT_GENERATOR_TEMPLATE_NAME)
DRAFT_SYSTEM_PROMPT_SHA256 = DRAFT_GENERATOR_TEMPLATE_SHA256
STRUCTURED_DRAFT_SCHEMA_SHA256 = hashlib.sha256(
    (
        json.dumps(
            StructuredDraft.model_json_schema(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
).hexdigest()
GENERATION_CONFIG = {
    "max_tokens": MODEL_OUTPUT_TOKENS,
    "temperature": 0.0,
    "top_p": 1.0,
    "seed": 0,
    "stop": [],
    "context_tokens": MODEL_CONTEXT_TOKENS,
    "input_estimated_token_limit": MAX_INPUT_ESTIMATED_TOKENS,
}
GENERATION_CONFIG_SHA256 = hashlib.sha256(
    (json.dumps(GENERATION_CONFIG, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
).hexdigest()


class EmptyRetriever:
    """Fail-honest adapter used until an ACTIVE immutable build exists."""

    async def retrieve_issue_spotting_notes(
        self,
        *,
        query: str,
        jurisdiction: str,
        subject: str | None,
        as_of_date: date,
        limit: int = 8,
    ) -> Sequence[IssueSpottingNote]:
        del query, jurisdiction, subject, as_of_date, limit
        return []

    async def retrieve(
        self,
        *,
        query: str,
        jurisdiction: str,
        subject: str | None,
        as_of_date: date,
        limit: int = 30,
        cacheable: bool = True,
    ) -> Sequence[EvidenceSpan]:
        del cacheable
        return []

    def active_build_id(self) -> str | None:
        return None


class NoOnlineResearcher:
    async def research_gap(
        self,
        *,
        proposition: str,
        jurisdiction: str,
        subject: str | None,
        as_of_date: date,
    ) -> tuple[Sequence[EvidenceSpan], list[dict[str, str]], list[str]]:
        return [], [], ["Online research is disabled or no allowlisted adapter is active"]


@dataclass(frozen=True, slots=True)
class EvidencePromptBundle:
    payloads: tuple[dict[str, Any], ...]
    excluded_document_safety_ids: tuple[str, ...]
    omitted_budget_ids: tuple[str, ...]
    estimated_tokens: int
    serialized_characters: int


def _estimate_prompt_tokens(text: str) -> int:
    """Conservative tokenizer-independent estimate used before exact MLX checks."""

    utf8_estimate = (len(text.encode("utf-8")) + 2) // 3
    word_estimate = (len(text.split()) * 3 + 1) // 2
    return max(1, utf8_estimate, word_estimate)


def _trim_at_word(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    if limit <= 1:
        return ""
    prefix = text[:limit].rsplit(maxsplit=1)[0].rstrip()
    return prefix or text[:limit].rstrip()


def _bounded_text(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    head = max(1, (limit - 35) * 2 // 3)
    tail = max(1, limit - head - 35)
    return f"{_trim_at_word(text, head)}\n[TRUNCATED FOR MODEL CONTEXT]\n{text[-tail:].lstrip()}"


def _evidence_payload(
    span: EvidenceSpan,
    owner_identifiers: Sequence[str] = (),
    *,
    as_of_date: date | None = None,
    text: str | None = None,
    text_truncated: bool = False,
) -> dict[str, Any]:
    case_reviews = [
        {
            "proposition_hash": review.proposition_hash,
            "review_seal_sha256": review.seal_sha256,
            "later_treatment_status": review.later_treatment_status,
            "later_treatment_reviewed_as_of_date": (
                review.later_treatment_reviewed_as_of_date.isoformat()
            ),
        }
        for review in span.case_currentness_reviews
        if review.qualifies_for_present_law
        and (as_of_date is None or review.later_treatment_reviewed_as_of_date == as_of_date)
    ]
    payload = {
        "id": span.id,
        "text": span.text if text is None else text,
        "text_truncated": text_truncated,
        "locator": span.locator,
        "lane": span.lane,
        "jurisdiction": span.jurisdiction,
        "subject": span.subject,
        "canonical_citation": span.canonical_citation,
        "citation_data": span.citation_data,
        "currentness_status": span.currentness_status,
        "case_proposition_reviews": case_reviews,
    }
    safe = scrub_prompt_data(payload, owner_identifiers)
    if not isinstance(safe, dict):  # pragma: no cover - fixed shape invariant
        raise TypeError("evidence prompt payload must remain an object")
    return cast(dict[str, Any], safe)


def _prompt_bundle_fits(
    payloads: Sequence[dict[str, Any]], *, char_budget: int, token_budget: int
) -> tuple[bool, int, int]:
    serialized = json.dumps(payloads, ensure_ascii=False, sort_keys=True)
    characters = len(serialized)
    tokens = _estimate_prompt_tokens(serialized)
    return characters <= char_budget and tokens <= token_budget, characters, tokens


def _budgeted_evidence_payloads(
    spans: Sequence[EvidenceSpan],
    owner_identifiers: Sequence[str] = (),
    *,
    as_of_date: date | None = None,
    char_budget: int = EVIDENCE_PROMPT_CHAR_BUDGET,
    token_budget: int = EVIDENCE_PROMPT_TOKEN_BUDGET,
) -> EvidencePromptBundle:
    """Build a deterministic, scrubbed evidence prefix within the 8k context plan."""

    payloads: list[dict[str, Any]] = []
    unsafe: list[str] = []
    omitted: list[str] = []
    for span in spans:
        safety_text = json.dumps(
            {
                "text": span.text,
                "locator": span.locator,
                "canonical_citation": span.canonical_citation,
                "citation_data": span.citation_data,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        if prompt_injection_hits(safety_text):
            unsafe.append(span.id)
            continue
        safe_text = scrub_pii(span.text, owner_identifiers).strip()
        if not safe_text:
            omitted.append(span.id)
            continue
        maximum = min(len(safe_text), MAX_EVIDENCE_SPAN_CHARS)
        minimum = min(len(safe_text), 80)
        low = minimum
        high = maximum
        best: dict[str, Any] | None = None
        while low <= high:
            midpoint = (low + high) // 2
            trimmed = _trim_at_word(safe_text, midpoint)
            payload = _evidence_payload(
                span,
                owner_identifiers,
                as_of_date=as_of_date,
                text=trimmed,
                text_truncated=len(trimmed) < len(safe_text),
            )
            fits, _, _ = _prompt_bundle_fits(
                [*payloads, payload], char_budget=char_budget, token_budget=token_budget
            )
            if fits:
                best = payload
                low = midpoint + 1
            else:
                high = midpoint - 1
        if best is None:
            omitted.append(span.id)
            continue
        payloads.append(best)

    _, characters, tokens = _prompt_bundle_fits(
        payloads, char_budget=char_budget, token_budget=token_budget
    )
    return EvidencePromptBundle(
        payloads=tuple(payloads),
        excluded_document_safety_ids=tuple(unsafe),
        omitted_budget_ids=tuple(omitted),
        estimated_tokens=tokens,
        serialized_characters=characters,
    )


def _bounded_rules(rules: Sequence[str], owner_identifiers: Sequence[str]) -> list[str]:
    remaining = MAX_ASSESSMENT_RULE_CHARS
    selected: list[str] = []
    for rule in rules:
        safe = scrub_pii(rule, owner_identifiers).strip()
        if not safe or remaining <= 0:
            continue
        # A partial rule can invert or destroy its meaning (for example,
        # retaining an anti-pattern but dropping its repair action).  Rule
        # budgeting is therefore atomic: include the complete reviewed rule or
        # omit it and record the immutable bundle separately.
        if len(safe) > remaining:
            continue
        selected.append(safe)
        remaining -= len(safe)
    return selected


def _budgeted_upload_context(
    contexts: Sequence[UploadContextSpan], owner_identifiers: Sequence[str]
) -> list[dict[str, Any]]:
    """Return bounded non-authoritative context, never evidence-shaped data."""

    selected: list[dict[str, Any]] = []
    for context in contexts:
        if prompt_injection_hits(context.text):
            continue
        safe = scrub_pii(context.text, owner_identifiers).strip()
        if not safe:
            continue
        candidate = {
            "context_id": context.id,
            "text": _bounded_text(safe, 1_200),
            "lane": context.lane,
            "locator": context.locator,
            "subject": context.subject,
            "jurisdiction": context.jurisdiction,
            "context_only": True,
            "legal_authority": False,
            "may_be_cited": False,
        }
        scrubbed = scrub_prompt_data(candidate, owner_identifiers)
        if not isinstance(scrubbed, dict):  # pragma: no cover - fixed shape invariant
            raise TypeError("upload context payload must remain an object")
        trial = [*selected, cast(dict[str, Any], scrubbed)]
        serialised = json.dumps(trial, ensure_ascii=False, sort_keys=True)
        if (
            len(serialised) > UPLOAD_CONTEXT_CHAR_BUDGET
            or _estimate_prompt_tokens(serialised) > UPLOAD_CONTEXT_TOKEN_BUDGET
        ):
            break
        selected = trial
    return selected


class ClientDisconnectedAfterGenerationError(RuntimeError):
    """The model ran, but the HTTP response was lost. That result is not VERIFIED."""


class LoopbackModelGateway:
    def __init__(self, settings: Settings) -> None:
        self.url = settings.model_url.rstrip("/")
        self.expected_model = settings.model_id
        self.allow_test_stub = settings.test_mode
        self.owner_identifiers = settings.owner_identifiers
        self._timeout = httpx.Timeout(connect=5, read=300, write=30, pool=5)

    def _validated_model_version(self, body: Mapping[str, Any]) -> str:
        warnings = body.get("warnings", ())
        is_stub = isinstance(warnings, Sequence) and "stub_mode" in warnings
        observed = str(body.get("model_version") or "")
        if is_stub and self.allow_test_stub and observed == "stub/legalbot-v1":
            return observed
        if self.expected_model != PINNED_RUNTIME_REPO or observed != PINNED_RUNTIME_MODEL_VERSION:
            raise RuntimeError("model runtime version differs from the pinned local identity")
        return observed

    async def health(self) -> bool:
        try:
            async with httpx.AsyncClient(
                timeout=5,
                trust_env=False,
                follow_redirects=False,
            ) as client:
                response = await client.get(f"{self.url}/api/v1/health")
                body = response.json()
                if not isinstance(body, dict):
                    return False
                if response.status_code != 200:
                    return False
                if bool(body.get("stub_mode")):
                    return self.allow_test_stub and bool(body.get("model_loaded"))
                return (
                    bool(body.get("model_loaded")) and body.get("model_id") == self.expected_model
                )
        except (httpx.HTTPError, TypeError, ValueError):
            return False

    async def draft(
        self,
        *,
        question: str,
        task_type: TaskType,
        jurisdiction: str,
        as_of_date: date,
        word_target: int,
        evidence: Sequence[EvidenceSpan],
        assessment_rules: Sequence[str],
        upload_context: Sequence[UploadContextSpan] = (),
    ) -> ModelDraft:
        bundle = _budgeted_evidence_payloads(
            evidence, self.owner_identifiers, as_of_date=as_of_date
        )
        payload = {
            "mode": "draft",
            "question": _bounded_text(
                scrub_pii(question, self.owner_identifiers), MAX_QUESTION_CHARS
            ),
            "task_type": task_type,
            "jurisdiction": jurisdiction,
            "as_of_date": as_of_date.isoformat(),
            "word_target": word_target,
            "evidence": list(bundle.payloads),
            "evidence_prompt_manifest": {
                "provided_ids": [span.id for span in evidence],
                "included_ids": [str(item["id"]) for item in bundle.payloads],
                "omitted_budget_ids": list(bundle.omitted_budget_ids),
                "excluded_document_safety_ids": list(bundle.excluded_document_safety_ids),
                "text_truncated_ids": [
                    str(item["id"])
                    for item in bundle.payloads
                    if item.get("text_truncated") is True
                ],
            },
            "uploaded_context": _budgeted_upload_context(upload_context, self.owner_identifiers),
            "assessment_rules": _bounded_rules(assessment_rules, self.owner_identifiers),
            "constraints": {
                "output": "structured_json_only",
                "citations": "use_evidence_ids_only_never_write_citation_strings",
                "citation_placement": (
                    "renderer_appends_full_oscola_immediately_after_each_supported_sentence"
                ),
                "assessment_rules": (
                    "follow_owner_approved_assessment_guidance_and_anti_patterns_only_"
                    "without_treating_them_as_a_calibrated_grade_guarantee"
                ),
                "material_claims": "each_requires_one_or_more_evidence_ids",
                "case_propositions": (
                    "claims_using_case_evidence_must_echo_one_supplied_proposition_hash"
                ),
                "provenance": "teaching_and_feedback_are_not_legal_authority",
                "uploaded_context": (
                    "facts_and_issue_spotting_only_never_legal_evidence_never_cite"
                ),
                "evidence_prompt_budget": {
                    "characters": EVIDENCE_PROMPT_CHAR_BUDGET,
                    "estimated_tokens": EVIDENCE_PROMPT_TOKEN_BUDGET,
                    "included": len(bundle.payloads),
                    "omitted_for_budget": len(bundle.omitted_budget_ids),
                    "excluded_for_document_safety": len(bundle.excluded_document_safety_ids),
                },
                "prompt_contract": {
                    "prompt_version": PROMPT_VERSION,
                    "prompt_sha256": DRAFT_SYSTEM_PROMPT_SHA256,
                    "structured_draft_schema_sha256": STRUCTURED_DRAFT_SCHEMA_SHA256,
                    "generation_config_sha256": GENERATION_CONFIG_SHA256,
                    "silent_truncation_forbidden": True,
                },
            },
        }
        return await self._call(payload, mode="draft")

    async def invoke_json(
        self,
        *,
        system_prompt: str,
        user_payload: Mapping[str, Any],
        mode: str,
    ) -> tuple[str, dict[str, Any]]:
        """Independent JSON invocation with a caller-supplied system prompt."""

        invocation_id = str(uuid4())
        safe_payload = scrub_prompt_data(dict(user_payload), self.owner_identifiers)
        if not isinstance(safe_payload, dict):
            raise TypeError("verifier payload must remain an object")
        messages = [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": json.dumps(safe_payload, ensure_ascii=False, sort_keys=True),
            },
        ]
        envelope = {
            "request_id": invocation_id,
            "mode": mode,
            "payload": {**safe_payload, "messages": messages},
            "messages": messages,
            "max_tokens": MODEL_OUTPUT_TOKENS,
            "temperature": 0.0,
            "top_p": 1.0,
            "seed": 0,
            "stop": [],
        }
        try:
            async with httpx.AsyncClient(
                timeout=self._timeout,
                trust_env=False,
                follow_redirects=False,
            ) as client:
                response = await client.post(f"{self.url}/api/v1/generate", json=envelope)
                response.raise_for_status()
        except (
            BrokenPipeError,
            ConnectionResetError,
            ConnectionAbortedError,
            httpx.RemoteProtocolError,
            httpx.ReadError,
            httpx.WriteError,
        ) as exc:
            raise ClientDisconnectedAfterGenerationError(
                "model HTTP response was lost; retry requires a new semantic-verifier invocation"
            ) from exc
        body = response.json()
        if not isinstance(body, dict):
            raise ValueError("model runtime returned a non-object response")
        self._validated_model_version(body)
        structured_value = body.get("structured")
        if isinstance(structured_value, str):
            structured_value = json.loads(structured_value)
        if isinstance(structured_value, dict):
            return invocation_id, structured_value
        raw = body.get("text") or body.get("raw_text") or "{}"
        if isinstance(raw, dict):
            return invocation_id, raw
        parsed = json.loads(raw) if isinstance(raw, str) else {}
        if not isinstance(parsed, dict):
            raise ValueError("semantic verifier returned a non-object")
        return invocation_id, parsed

    async def repair(
        self,
        *,
        question: str,
        prior: StructuredDraft,
        failed_sections: Sequence[str],
        findings: Sequence[QualityFinding],
        evidence: Mapping[str, EvidenceSpan],
        word_target: int,
        upload_context: Sequence[UploadContextSpan] = (),
    ) -> ModelDraft:
        bundle = _budgeted_evidence_payloads(
            list(evidence.values()),
            self.owner_identifiers,
            as_of_date=prior.as_of_date,
            char_budget=REPAIR_EVIDENCE_CHAR_BUDGET,
            token_budget=REPAIR_EVIDENCE_TOKEN_BUDGET,
        )
        payload = {
            "mode": "repair",
            "question": _bounded_text(
                scrub_pii(question, self.owner_identifiers), MAX_QUESTION_CHARS
            ),
            "word_target": word_target,
            "prior": prior.model_dump(mode="json"),
            "failed_sections": list(failed_sections),
            "findings": [item.model_dump(mode="json") for item in findings],
            "evidence": list(bundle.payloads),
            "evidence_prompt_manifest": {
                "provided_ids": list(evidence),
                "included_ids": [str(item["id"]) for item in bundle.payloads],
                "omitted_budget_ids": list(bundle.omitted_budget_ids),
                "excluded_document_safety_ids": list(bundle.excluded_document_safety_ids),
                "text_truncated_ids": [
                    str(item["id"])
                    for item in bundle.payloads
                    if item.get("text_truncated") is True
                ],
            },
            "uploaded_context": _budgeted_upload_context(upload_context, self.owner_identifiers),
            "constraints": {
                "preserve_unfailed_sections_exactly": True,
                "never_silently_delete_substantive_prose": True,
                "output": "structured_json_only",
                "prompt_contract": {
                    "prompt_version": PROMPT_VERSION,
                    "prompt_sha256": DRAFT_SYSTEM_PROMPT_SHA256,
                    "structured_draft_schema_sha256": STRUCTURED_DRAFT_SCHEMA_SHA256,
                    "generation_config_sha256": GENERATION_CONFIG_SHA256,
                    "silent_truncation_forbidden": True,
                },
            },
        }
        return await self._call(payload, mode="repair")

    async def _call(self, payload: dict[str, Any], *, mode: str) -> ModelDraft:
        system_prompt = DRAFT_SYSTEM_PROMPT
        safe_payload = scrub_prompt_data(payload, self.owner_identifiers)
        if not isinstance(safe_payload, dict):  # pragma: no cover - fixed shape invariant
            raise TypeError("model payload must remain an object")
        messages = [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": json.dumps(safe_payload, ensure_ascii=False, sort_keys=True),
            },
        ]
        estimated_input = _estimate_prompt_tokens(
            "\n".join(str(message["content"]) for message in messages)
        )
        if estimated_input > MAX_INPUT_ESTIMATED_TOKENS:
            raise ValueError(
                "scrubbed model prompt exceeds the conservative 8k context input budget"
            )
        envelope = {
            "request_id": str(uuid4()),
            "mode": mode,
            "payload": {**safe_payload, "messages": messages},
            "messages": messages,
            "max_tokens": GENERATION_CONFIG["max_tokens"],
            "temperature": GENERATION_CONFIG["temperature"],
            "top_p": GENERATION_CONFIG["top_p"],
            "seed": GENERATION_CONFIG["seed"],
            "stop": GENERATION_CONFIG["stop"],
        }
        async with httpx.AsyncClient(
            timeout=self._timeout,
            trust_env=False,
            follow_redirects=False,
        ) as client:
            response = await client.post(f"{self.url}/api/v1/generate", json=envelope)
            response.raise_for_status()
        body = response.json()
        if not isinstance(body, dict):
            raise ValueError("model runtime returned a non-object response")
        warnings = body.get("warnings", [])
        is_stub = isinstance(warnings, Sequence) and "stub_mode" in warnings
        if is_stub and not self.allow_test_stub:
            raise RuntimeError("deterministic stub output is forbidden outside explicit test mode")
        finish_reason = str(body.get("finish_reason") or "unknown").casefold()
        truncated_warning = isinstance(warnings, Sequence) and any(
            str(value).casefold() in {"output_truncated", "context_truncated"} for value in warnings
        )
        if not is_stub and (
            finish_reason in {"length", "max_tokens", "token_limit", "context_length", "truncated"}
            or truncated_warning
        ):
            raise ValueError("model output was truncated and cannot enter validation")
        model_version = self._validated_model_version(body)
        structured_value = body.get("structured")
        if isinstance(structured_value, str):
            structured_value = json.loads(structured_value)
        try:
            structured = StructuredDraft.model_validate(structured_value)
        except Exception:
            if not is_stub:
                raise
            task = safe_payload.get("task_type", "general")
            if task == "auto":
                task = "general"
            structured = StructuredDraft.model_validate(
                {
                    "title": "Deterministic runtime check",
                    "task_type": task,
                    "jurisdiction": safe_payload.get("jurisdiction", "England and Wales"),
                    "as_of_date": safe_payload.get("as_of_date"),
                    "sections": [
                        {
                            "id": "runtime-status",
                            "heading": "Runtime status",
                            "claims": [
                                {
                                    "id": str(uuid4()),
                                    "text": "The model service is running in deterministic test mode, so no legal proposition has been drafted",
                                    "evidence_ids": [],
                                    "material": False,
                                    "kind": "operational_status",
                                }
                            ],
                        }
                    ],
                    "limitations": ["Start the verified 4-bit MLX runtime before substantive use."],
                }
            )
        prompt_evidence = safe_payload.get("evidence")
        if not isinstance(prompt_evidence, list):
            raise ValueError("model prompt evidence must be a list")
        allowed_evidence_ids = {
            str(item.get("id"))
            for item in prompt_evidence
            if isinstance(item, Mapping) and item.get("id")
        }
        escaped_ids = {
            evidence_id
            for section in structured.sections
            for claim in section.claims
            for evidence_id in claim.evidence_ids
            if evidence_id not in allowed_evidence_ids
        }
        if escaped_ids:
            raise ValueError("model output cited evidence outside the exact prompt bundle")
        if not is_stub and any(
            not claim.material for section in structured.sections for claim in section.claims
        ):
            raise ValueError("model output attempted to bypass material-claim validation")
        return ModelDraft(
            raw_text=str(body.get("raw_text") or json.dumps(structured_value, indent=2)),
            structured=structured,
            rubric_scores={
                str(key): float(value) for key, value in body.get("rubric_scores", {}).items()
            },
            model_version=model_version,
            metrics={
                "input_tokens": int((body.get("usage") or {}).get("input_tokens", 0)),
                "output_tokens": int((body.get("usage") or {}).get("output_tokens", 0)),
                "total_tokens": int((body.get("usage") or {}).get("total_tokens", 0)),
                "generation_ms": int(body.get("generation_ms") or 0),
                "time_to_first_token_ms": (
                    int(body["time_to_first_token_ms"])
                    if body.get("time_to_first_token_ms") is not None
                    else None
                ),
                "peak_memory_gb": (
                    float(body["peak_memory_gb"])
                    if body.get("peak_memory_gb") is not None
                    else None
                ),
                "finish_reason": finish_reason,
                "prompt_version": PROMPT_VERSION,
                "prompt_sha256": DRAFT_SYSTEM_PROMPT_SHA256,
                "structured_draft_schema_sha256": STRUCTURED_DRAFT_SCHEMA_SHA256,
                "generation_config_sha256": GENERATION_CONFIG_SHA256,
                "prompt_evidence_count": len(allowed_evidence_ids),
            },
        )
