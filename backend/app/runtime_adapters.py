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
from .orchestration.answer_structure import section_contract
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

PROMPT_VERSION = "evidence-first-structured-json-v5"

MODEL_CONTEXT_TOKENS = 8192
# The 9B MLX runtime must finish a complete JSON object inside the durable
# worker's 300-second model-call boundary.  The previous 2,048-token request
# could still be generating when that boundary closed; 1,600 retains the
# observed 1,388-token visible draft while bounding worst-case generation.
MODEL_OUTPUT_TOKENS = 1600
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


@dataclass(frozen=True, slots=True)
class FullyVisibleEvidenceSelection:
    """Exact whole spans that fit the drafting prompt without text truncation."""

    spans: tuple[EvidenceSpan, ...]
    omitted_ids: tuple[str, ...]
    excluded_document_safety_ids: tuple[str, ...]
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


def select_fully_visible_evidence(
    spans: Sequence[EvidenceSpan],
    owner_identifiers: Sequence[str] = (),
    *,
    as_of_date: date | None = None,
    maximum_spans: int = 12,
) -> FullyVisibleEvidenceSelection:
    """Select only exact whole EvidenceSpan text for the selected-contract route.

    The ordinary prompt adapter can mark a span as truncated.  A selected
    RetrievalResult/EvidencePack cannot represent that altered text, so the
    development release route uses this stricter projection before generation.
    Re-running the normal prompt builder on the returned spans is guaranteed to
    include the same full text and no additional span.
    """

    if maximum_spans < 1 or maximum_spans > 32:
        raise ValueError("fully visible evidence limit is outside the contract budget")
    payloads: list[dict[str, Any]] = []
    selected: list[EvidenceSpan] = []
    omitted: list[str] = []
    unsafe: list[str] = []
    for span in spans:
        if len(selected) >= maximum_spans:
            omitted.append(span.id)
            continue
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
        # A selected evidence contract binds the source chunk digest.  If the
        # privacy projection changes those bytes, omit the span rather than
        # reviewing the model against different text later.
        if not safe_text or safe_text != span.text:
            omitted.append(span.id)
            continue
        payload = _evidence_payload(
            span,
            owner_identifiers,
            as_of_date=as_of_date,
            text=safe_text,
            text_truncated=False,
        )
        fits, _, _ = _prompt_bundle_fits(
            [*payloads, payload],
            char_budget=EVIDENCE_PROMPT_CHAR_BUDGET,
            token_budget=EVIDENCE_PROMPT_TOKEN_BUDGET,
        )
        if not fits:
            omitted.append(span.id)
            continue
        payloads.append(payload)
        selected.append(span)
    _, characters, tokens = _prompt_bundle_fits(
        payloads,
        char_budget=EVIDENCE_PROMPT_CHAR_BUDGET,
        token_budget=EVIDENCE_PROMPT_TOKEN_BUDGET,
    )
    replay = _budgeted_evidence_payloads(
        selected,
        owner_identifiers,
        as_of_date=as_of_date,
    )
    if (
        [item["id"] for item in replay.payloads] != [item.id for item in selected]
        or replay.omitted_budget_ids
        or replay.excluded_document_safety_ids
        or any(item.get("text_truncated") is True for item in replay.payloads)
    ):
        raise RuntimeError("fully visible evidence selection is not replayable")
    return FullyVisibleEvidenceSelection(
        spans=tuple(selected),
        omitted_ids=tuple(omitted),
        excluded_document_safety_ids=tuple(unsafe),
        estimated_tokens=tokens,
        serialized_characters=characters,
    )


def _bounded_rules(
    rules: Sequence[str], owner_identifiers: Sequence[str],
    *, max_characters: int = MAX_ASSESSMENT_RULE_CHARS,
) -> list[str]:
    remaining = max_characters
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


def expected_model_visible_fact_inputs(
    *,
    question: str,
    upload_context: Sequence[UploadContextSpan],
    owner_identifiers: Sequence[str] = (),
) -> dict[str, Any]:
    """Build the exact question/upload projection before a draft is generated."""

    visible_question = _bounded_text(
        scrub_pii(question, owner_identifiers), MAX_QUESTION_CHARS
    )
    uploads = _budgeted_upload_context(upload_context, owner_identifiers)
    visible = {
        "question": visible_question,
        "uploads": [
            {"context_id": item["context_id"], "text": item["text"]}
            for item in uploads
        ],
    }
    return {
        **visible,
        "provenance": _model_fact_provenance(
            visible,
            question=question,
            upload_context=upload_context,
            owner_identifiers=owner_identifiers,
        ),
    }


class ClientDisconnectedAfterGenerationError(RuntimeError):
    """The model ran, but the HTTP response was lost. That result is not VERIFIED."""


def model_visible_fact_inputs(projection: Mapping[str, Any]) -> dict[str, Any]:
    """Read only question/upload material from the exact host prompt projection.

    This is a byte-identity check, not independent custody or factual approval.
    In particular prior generated answers and legal evidence are not user facts.
    """
    if projection.get("schema") != "legalbot.actual-model-input-projection.v1":
        raise ValueError("actual model input projection is required")
    text = projection.get("user_message")
    if not isinstance(text, str) or hashlib.sha256(text.encode()).hexdigest() != projection.get("user_message_sha256"):
        raise ValueError("model input projection content changed")
    system_hash = hashlib.sha256(DRAFT_SYSTEM_PROMPT.encode()).hexdigest()
    if system_hash != projection.get("system_prompt_sha256"):
        raise ValueError("model input projection prompt changed")
    messages = [{"role": "system", "content": DRAFT_SYSTEM_PROMPT},
                {"role": "user", "content": text}]
    actual = hashlib.sha256(json.dumps(messages, ensure_ascii=False, sort_keys=True,
                                      separators=(",", ":")).encode()).hexdigest()
    if actual != projection.get("messages_sha256"):
        raise ValueError("model input projection messages changed")
    payload = json.loads(text)
    if not isinstance(payload, dict) or not isinstance(payload.get("question"), str):
        raise ValueError("model input projection question missing")
    uploads = payload.get("uploaded_context", [])
    if not isinstance(uploads, list) or any(not isinstance(item, dict)
        or not isinstance(item.get("context_id"), str)
        or not isinstance(item.get("text"), str) for item in uploads):
        raise ValueError("model input projection uploads invalid")
    return {"invocation_id": projection["invocation_id"], "question": payload["question"],
            "uploads": [{"context_id": item["context_id"], "text": item["text"]}
                        for item in uploads]}


def _model_fact_provenance(
    visible: Mapping[str, Any], *, question: str,
    upload_context: Sequence[UploadContextSpan], owner_identifiers: Sequence[str],
) -> dict[str, Any]:
    """Bind sent facts to original gateway inputs without retaining raw PII.

    Upload IDs identify extraction contexts, not source authority. The final
    review producer must bind these input hashes to the admitted request and
    extraction receipts; this mechanical projection does not approve facts.
    """
    expected_question = scrub_prompt_data(
        _bounded_text(scrub_pii(question, owner_identifiers), MAX_QUESTION_CHARS),
        owner_identifiers,
    )
    expected_uploads = scrub_prompt_data(
        _budgeted_upload_context(upload_context, owner_identifiers), owner_identifiers,
    )
    expected = [{"context_id": item["context_id"], "text": item["text"]}
                for item in expected_uploads]
    if visible["question"] != expected_question or visible["uploads"] != expected:
        raise ValueError("model-visible facts differ from host input transformation")
    sources = {item.id: item for item in upload_context}
    if len(sources) != len(upload_context):
        raise ValueError("duplicate upload context identity")

    def binding(original: str, sent: str) -> dict[str, Any]:
        return {
            "input_sha256": hashlib.sha256(original.encode("utf-8")).hexdigest(),
            "visible_sha256": hashlib.sha256(sent.encode("utf-8")).hexdigest(),
            "input_changed_by_projection": original != sent,
        }

    included = {item["context_id"] for item in expected}
    return {
        "schema": "legalbot.model-fact-input-provenance.v1",
        "transformation": "gateway-pii-scrub-and-context-budget-v1",
        "question": binding(question, str(expected_question)),
        "uploads": [{"context_id": item["context_id"],
                     **binding(sources[item["context_id"]].text, item["text"])}
                    for item in expected],
        "upload_input_inventory_sha256": hashlib.sha256(json.dumps(
            [{"context_id": item.id,
              "input_sha256": hashlib.sha256(item.text.encode("utf-8")).hexdigest()}
             for item in upload_context], sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest(),
        "omitted_upload_context_ids": [item.id for item in upload_context
                                       if item.id not in included],
        "semantic_facts_inferred": False,
    }


def verify_model_fact_provenance(
    projection: Mapping[str, Any], *, question: str,
    upload_context: Sequence[UploadContextSpan], owner_identifiers: Sequence[str],
) -> dict[str, Any]:
    """Replay the exact projection from caller-supplied original host inputs."""
    visible = model_visible_fact_inputs(projection)
    expected = _model_fact_provenance(
        visible, question=question, upload_context=upload_context,
        owner_identifiers=owner_identifiers,
    )
    if projection.get("fact_provenance") != expected:
        raise ValueError("model fact provenance differs from original inputs")
    return visible


class LoopbackModelGateway:
    max_question_chars = MAX_QUESTION_CHARS
    assessment_character_budget = MAX_ASSESSMENT_RULE_CHARS
    evidence_character_budget = EVIDENCE_PROMPT_CHAR_BUDGET
    evidence_token_budget = EVIDENCE_PROMPT_TOKEN_BUDGET
    repair_evidence_character_budget = REPAIR_EVIDENCE_CHAR_BUDGET
    repair_evidence_token_budget = REPAIR_EVIDENCE_TOKEN_BUDGET
    input_token_budget = MAX_INPUT_ESTIMATED_TOKENS
    output_token_budget = MODEL_OUTPUT_TOKENS

    def _generation_config_sha256(self) -> str:
        profile = dict(GENERATION_CONFIG)
        profile.update({
            "max_tokens": self.output_token_budget,
            "input_estimated_token_limit": self.input_token_budget,
            "context_tokens": self.input_token_budget + self.output_token_budget + PROMPT_SAFETY_TOKENS,
        })
        return hashlib.sha256(
            (json.dumps(profile, sort_keys=True, separators=(",", ":")) + "\n").encode()
        ).hexdigest()

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

    async def _generate(self, envelope: Mapping[str, Any]) -> dict[str, Any]:
        """Transport seam used by every model-dependent stage.

        Provider adapters override this method while retaining the exact
        prompt budgeting, fact projection, schema and evidence-ID checks.
        """
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
        return body

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
            evidence, self.owner_identifiers, as_of_date=as_of_date,
            char_budget=self.evidence_character_budget,
            token_budget=self.evidence_token_budget,
        )
        payload = {
            "mode": "draft",
            "question": _bounded_text(
                scrub_pii(question, self.owner_identifiers), self.max_question_chars
            ),
            "task_type": task_type,
            "jurisdiction": jurisdiction,
            "as_of_date": as_of_date.isoformat(),
            "word_target": word_target,
            "section_contract": section_contract(task_type),
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
            "assessment_rules": _bounded_rules(
                assessment_rules, self.owner_identifiers,
                max_characters=self.assessment_character_budget,
            ),
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
                    "characters": self.evidence_character_budget,
                    "estimated_tokens": self.evidence_token_budget,
                    "included": len(bundle.payloads),
                    "omitted_for_budget": len(bundle.omitted_budget_ids),
                    "excluded_for_document_safety": len(bundle.excluded_document_safety_ids),
                },
                "prompt_contract": {
                    "prompt_version": PROMPT_VERSION,
                    "prompt_sha256": DRAFT_SYSTEM_PROMPT_SHA256,
                    "structured_draft_schema_sha256": STRUCTURED_DRAFT_SCHEMA_SHA256,
                    "generation_config_sha256": self._generation_config_sha256(),
                    "silent_truncation_forbidden": True,
                },
            },
        }
        return await self._call(payload, mode="draft", question=question,
                                upload_context=upload_context)

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
        if _estimate_prompt_tokens(json.dumps(messages, ensure_ascii=False)) > self.input_token_budget:
            raise ValueError("verifier_prompt_exceeds_provider_input_budget")
        envelope = {
            "request_id": invocation_id,
            "mode": mode,
            "payload": {**safe_payload, "messages": messages},
            "messages": messages,
            "max_tokens": self.output_token_budget,
            "temperature": 0.0,
            "top_p": 1.0,
            "seed": 0,
            "stop": [],
        }
        try:
            body = await self._generate(envelope)
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
            char_budget=self.repair_evidence_character_budget,
            token_budget=self.repair_evidence_token_budget,
        )
        payload = {
            "mode": "repair",
            "question": _bounded_text(
                scrub_pii(question, self.owner_identifiers), self.max_question_chars
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
                    "generation_config_sha256": self._generation_config_sha256(),
                    "silent_truncation_forbidden": True,
                },
            },
        }
        return await self._call(payload, mode="repair", question=question,
                                upload_context=upload_context)

    async def _call(
        self, payload: dict[str, Any], *, mode: str, question: str,
        upload_context: Sequence[UploadContextSpan],
    ) -> ModelDraft:
        system_prompt = DRAFT_SYSTEM_PROMPT
        safe_payload = scrub_prompt_data(payload, self.owner_identifiers)
        if not isinstance(safe_payload, dict):  # pragma: no cover - fixed shape invariant
            raise TypeError("model payload must remain an object")
        fact_provenance = _model_fact_provenance(
            {"question": safe_payload["question"],
             "uploads": [{"context_id": item["context_id"], "text": item["text"]}
                         for item in safe_payload["uploaded_context"]]},
            question=question, upload_context=upload_context,
            owner_identifiers=self.owner_identifiers,
        )
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
        if estimated_input > self.input_token_budget:
            raise ValueError(
                "scrubbed model prompt exceeds the selected provider input budget"
            )
        envelope = {
            "request_id": str(uuid4()),
            "mode": mode,
            "payload": {**safe_payload, "messages": messages},
            "messages": messages,
            "max_tokens": self.output_token_budget,
            "temperature": GENERATION_CONFIG["temperature"],
            "top_p": GENERATION_CONFIG["top_p"],
            "seed": GENERATION_CONFIG["seed"],
            "stop": GENERATION_CONFIG["stop"],
        }
        body = await self._generate(envelope)
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
        transport_projection = body.get("transport_projection")
        if transport_projection is not None:
            if (
                not isinstance(transport_projection, dict)
                or not isinstance(transport_projection.get("sent_content"), str)
                or transport_projection.get("sent_content_sha256")
                != hashlib.sha256(transport_projection["sent_content"].encode("utf-8")).hexdigest()
                or transport_projection.get("source_messages_sha256")
                != hashlib.sha256(
                    json.dumps(messages, ensure_ascii=False, sort_keys=True,
                               separators=(",", ":")).encode("utf-8")
                ).hexdigest()
            ):
                raise ValueError("provider actual sent-input projection differs")
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
            input_projections=({
                "schema": "legalbot.actual-model-input-projection.v1",
                "fact_provenance": fact_provenance,
                "invocation_id": envelope["request_id"],
                "mode": mode,
                "messages_sha256": hashlib.sha256(
                    json.dumps(messages, ensure_ascii=False, sort_keys=True,
                               separators=(",", ":")).encode("utf-8")
                ).hexdigest(),
                "system_prompt_sha256": hashlib.sha256(system_prompt.encode("utf-8")).hexdigest(),
                "user_message": messages[1]["content"],
                "user_message_sha256": hashlib.sha256(
                    messages[1]["content"].encode("utf-8")
                ).hexdigest(),
                "transport_projection": transport_projection,
            },),
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
                "generation_config_sha256": self._generation_config_sha256(),
                "prompt_evidence_count": len(allowed_evidence_ids),
            },
        )
