#!/usr/bin/env python3
"""Plan bounded official-source research for the 364 unresolved issue rows.

This is an advisory planning pass, not legal qualification.  The pinned local
model sees the immutable scenario, the issue labels, and a bounded catalogue of
allowlisted authority *metadata*.  It may classify a row, propose one atomic
general proposition, select only supplied authority IDs, and provide a short
search query when the supplied catalogue is insufficient.

Find Case Law records are metadata/link-only.  No Find Case Law full text is
supplied to the model or used computationally.  The output cannot decide owner
approval or materiality, admit a source, change gold, mutate a candidate, or
authorize a later phase. Malformed output receives at most one targeted repair;
runtime or transport failure is held after one attempt. Diagnostics are
persisted before any retry that requires debugging.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import time
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

import httpx

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
for root in (PROJECT_ROOT, BACKEND_ROOT):
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

from app.evaluation.phase2a_research_packets import (  # noqa: E402
    _open_catalogue,
    _select_sources,
    subject_routes,
)
from app.retrieval.source_manifest import (  # noqa: E402
    approved_source_manifest_sha256,
)
from scripts import build_v111_phase2a_authority_plan_advisory as prior_planner  # noqa: E402

OWNER_REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
DEFAULT_TRIAGE = (
    OWNER_REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r71-gap-triage" / "ISSUE-GAP-TRIAGE-448.json"
)
DEFAULT_CASES = prior_planner.DEFAULT_CASES
DEFAULT_CATALOGUE = PROJECT_ROOT / "data/catalog.sqlite3"
DEFAULT_CANDIDATE_MANIFEST = (
    PROJECT_ROOT
    / "data/indexes/builds/current-law-ew-full-fp16-v111-20260818-a"
    / "approved-source-manifest.json"
)
DEFAULT_OUTPUT = (
    OWNER_REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r72-material-gap-research-advisory"
)

EXPECTED_TRIAGE_CONTENT_SHA256 = "d813a1fdc1b9b6f2d6c67b0ac2c113af696343cc8c619355c74ee8654beca475"
EXPECTED_CASES_FILE_SHA256 = prior_planner.EXPECTED_CASES_FILE_SHA256
EXPECTED_SELECTED_SOURCE_REGISTRY_SHA256 = (
    "65f304ac62ce67ac28ececa8f8d59adfe47e0141d9eeac0a53219e51267b93a4"
)
EXPECTED_CANDIDATE_MANIFEST_SHA256 = (
    "d2c1434fd5fc44d4f2f7e4f7629293f646bb28ed9b8466687feb6c470ea53ac0"
)
EXPECTED_MODEL_ID = prior_planner.EXPECTED_MODEL_ID
EXPECTED_MODEL_VERSION = prior_planner.EXPECTED_MODEL_VERSION
MODEL_BACKEND = prior_planner.MODEL_BACKEND
TARGET_CEILING_DATE = date(2026, 8, 14)
OUTPUT_SCHEMA = "p2a-gap-plan-v1"
EXPECTED_GAP_COUNT = 364
BATCH_SIZE = 4
MAX_AUTHORITIES = 48
MAX_SELECTIONS = 2
MAX_PROPOSITION_CHARACTERS = 240
MAX_LOCATOR_CHARACTERS = 120
MAX_SEARCH_QUERY_CHARACTERS = 180
MAX_OUTPUT_TOKENS = 900
MAX_PEAK_MEMORY_GB = 12.0
FCL_HOST = "caselaw.nationalarchives.gov.uk"
REVIEWER_EXECUTION_MODE = (
    "separate_advisory_gap_research_planner_same_model_adapter_as_drafting_not_model_independent"
)

SYSTEM_PROMPT = """/no_think
Advisory evidence-research planner only. Use the supplied immutable scenario only to disambiguate each terse issue label. Do not answer or apply law to the facts. Do not decide owner approval, legal materiality, source admission, qualification, or any gate.

For every row reproduce its supplied advisory_classification_hint exactly. The hint is deterministic routing for this advisory pass, not an owner decision. Apply the matching rule:
- LEGAL_PROPOSITION: use this for a named doctrine, test, duty, defence, remedy, statutory topic, or other legal issue whenever one central governing rule can be stated atomically. The existence of qualifications, exceptions, or missing supplied authority is not a reason to call the row composite. Give one single-sentence proposition of at most 240 characters. Select at most two supplied authority IDs likely to state that rule. If no supplied authority is adequate, use no selections and give one short official-source search query.
- ANALYTICAL_DIMENSION: use this only for a requested comparison, evidence assessment, litigation strategy, conclusion, strongest/weakest evaluation, missing-facts inquiry, policy evaluation, or presentation dimension rather than a standalone legal rule. Give an empty proposition, no selections, and an empty search query.
- COMPOSITE_REQUIRES_DECOMPOSITION: use this only when the label itself expressly joins materially distinct legal rules that cannot honestly be represented by one central rule, such as jurisdiction plus applicable law. Give an empty proposition, no selections, and a short decomposition/search query.

Never invent an authority ID. Find Case Law entries are metadata-only research leads; their text is unavailable and selecting one does not make it admissible. Do not state scenario facts, party conclusions, invented authorities, quotations, or unsupported numbers. Output compact JSON only with exactly: {"schema":"p2a-gap-plan-v1","case_id":"<supplied case id>","rows":[{"row_id":"<supplied row id>","classification":"LEGAL_PROPOSITION|ANALYTICAL_DIMENSION|COMPOSITE_REQUIRES_DECOMPOSITION","proposition":"<atomic general proposition or empty>","selections":[{"id":"<supplied authority id>","locator":"<short locator hint>"}],"search_query":"<short official-source query or empty>"}]}. Include every supplied row exactly once."""

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_CODE = re.compile(r"^[a-z0-9][a-z0-9_]{0,127}$")
_ROW_ID = re.compile(r"^(?:live30|live60)-q[0-9]{2}:issue-[0-9]{2}$")
_PROHIBITED_TEXT = re.compile(r"(?:/users/|file:|https?://|\x00)", re.IGNORECASE)
_TOKEN = re.compile(r"[a-z0-9]+(?:['’-][a-z0-9]+)?", re.IGNORECASE)
_TOKEN_SEPARATOR = re.compile(r"['-]")
_ISSUE_STOP_WORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "for",
        "in",
        "of",
        "on",
        "or",
        "the",
        "to",
        "with",
    }
)
_NON_REPAIRABLE_RUNTIME_FAILURES = frozenset(
    {
        "connect_error",
        "connect_timeout",
        "model_unavailable",
        "read_error",
        "read_timeout",
        "remote_protocol_error",
        "write_error",
        "write_timeout",
    }
)


def _is_repairable_model_output_failure(exc: BaseException, error_code: str) -> bool:
    """Allow one targeted repair only for malformed generated output.

    Transport, model-identity, resource-envelope and unexpected execution
    failures require diagnosis before another invocation.  Retrying those with
    a different prompt would not be a targeted repair and can conceal an
    unchanged failure fingerprint.
    """

    return isinstance(exc, GapPlanValidationError) and (
        error_code.startswith("structured_output_")
        or error_code in {"model_output_truncated", "model_response_not_object"}
    )


_ISSUE_TERM_ALIASES: dict[str, frozenset[str]] = {
    "breach": frozenset({"breach", "breached", "breaching", "repudiatory"}),
    "classification of contractual terms": frozenset(
        {
            "classification",
            "classify",
            "classified",
            "condition",
            "conditions",
            "contractual",
            "innominate",
            "term",
            "terms",
            "warranties",
            "warranty",
        }
    ),
    "termination": frozenset(
        {"discharge", "repudiation", "repudiatory", "terminate", "terminated", "termination"}
    ),
    "causation": frozenset({"causal", "causation", "cause", "caused", "causes"}),
    "mitigation": frozenset({"avoidable", "minimise", "minimize", "mitigate", "mitigation"}),
    "remoteness": frozenset(
        {"contemplation", "foreseeability", "foreseeable", "remote", "remoteness"}
    ),
    "causal relevance": frozenset({"causal", "causation", "cause", "relevance"}),
    "constitution and imperfect gifts": frozenset(
        {"constitution", "constituted", "gift", "gifts", "imperfect"}
    ),
    "corporate residence": frozenset({"company", "corporate", "residence", "resident"}),
    "interim relief": frozenset({"freezing", "injunction", "interim", "relief"}),
    "notification": frozenset({"notice", "notification", "notify"}),
    "remedies": frozenset({"relief", "remedies", "remedy"}),
    "suitability": frozenset({"suitability", "suitable"}),
    "testamentary capacity": frozenset(
        {"capacity", "mind", "sound", "testamentary", "testator", "understanding"}
    ),
    "tupe": frozenset(
        {"employment", "protection", "transfer", "tupe", "undertaking", "undertakings"}
    ),
}
_ANALYTICAL_LABEL = re.compile(
    r"(?:strongest\s+and\s+weakest|missing\s+factual\s+evidence|"
    r"litigation\s+and\s+settlement\s+strategy|project[- ]rescue\s+strategy|"
    r"comparison\s+with|reputational\s+risk|fairness\s+and\s+precedent|"
    r"legal\s+and\s+political\s+constitutionalism|constitutional\s+relationships|"
    r"operational[- ]contract\s+consequences|settlement\s+pressure\s+and\s+"
    r"speculative\s+litigation)",
    re.IGNORECASE,
)

Invoke = Callable[[dict[str, Any]], dict[str, Any]]


class GapPlanValidationError(ValueError):
    """One stable validation failure that is safe to persist."""

    def __init__(self, code: str, *, context: Mapping[str, Any] | None = None):
        if not _SAFE_CODE.fullmatch(code):
            raise ValueError("phase2a_gap_plan_error_code_invalid")
        self.code = code
        self.context = dict(context or {})
        super().__init__(code)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_gap_plan_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_gap_plan_input_must_be_object")
    return value


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or supplied != _sealed(material):
        raise ValueError(code)
    return supplied


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _load_cases(path: Path) -> dict[str, dict[str, Any]]:
    if _sha256_file(path) != EXPECTED_CASES_FILE_SHA256:
        raise ValueError("phase2a_gap_plan_cases_identity_invalid")
    cases: dict[str, dict[str, Any]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        case_id = str(row.get("case_id") or "")
        if not case_id or case_id in cases:
            raise ValueError("phase2a_gap_plan_case_registry_invalid")
        cases[case_id] = row
    if len(cases) != 60:
        raise ValueError("phase2a_gap_plan_case_count_invalid")
    return cases


def _load_gap_rows(path: Path) -> tuple[list[dict[str, Any]], str]:
    triage = _load_object(path)
    digest = _verify_seal(
        triage,
        "artifact_content_sha256",
        "phase2a_gap_plan_triage_seal_invalid",
    )
    rows = triage.get("rows")
    if (
        digest != EXPECTED_TRIAGE_CONTENT_SHA256
        or triage.get("row_count") != 448
        or triage.get("owner_decisions_applied") is not False
        or triage.get("source_admission_authorized") is not False
        or triage.get("candidate_mutated") is not False
        or not isinstance(rows, list)
    ):
        raise ValueError("phase2a_gap_plan_triage_boundary_invalid")
    gaps = [
        dict(row)
        for row in rows
        if isinstance(row, dict) and row.get("r70_assessment") == "MATERIAL_GAP_ADVISORY"
    ]
    row_ids = [str(row.get("row_id") or "") for row in gaps]
    if (
        len(gaps) != EXPECTED_GAP_COUNT
        or len(set(row_ids)) != EXPECTED_GAP_COUNT
        or any(not _ROW_ID.fullmatch(row_id) for row_id in row_ids)
    ):
        raise ValueError("phase2a_gap_plan_gap_inventory_invalid")
    return gaps, digest


def _candidate_authorities(path: Path) -> tuple[frozenset[str], str, str]:
    manifest = _load_object(path)
    digest = approved_source_manifest_sha256(manifest)
    sources = manifest.get("sources")
    if (
        digest != EXPECTED_CANDIDATE_MANIFEST_SHA256
        or manifest.get("manifest_sha256") != digest
        or manifest.get("exclude_find_case_law_full_text") is not True
        or not isinstance(sources, list)
    ):
        raise ValueError("phase2a_gap_plan_candidate_manifest_invalid")
    return (
        frozenset(str(source.get("authority_identity_id") or "") for source in sources),
        digest,
        _sha256_file(path),
    )


def _authority_catalogue(
    *,
    legal_domain: str,
    sources: Sequence[Any],
    candidate_authorities: frozenset[str],
) -> list[dict[str, Any]]:
    routes = subject_routes(legal_domain)
    routed = [source for source in sources if source.subject in routes]
    if len(routed) > MAX_AUTHORITIES:
        routed.sort(
            key=lambda source: (
                source.subject != "general",
                source.family == "case",
                source.authority_identity_id,
            ),
            reverse=True,
        )
        routed = routed[:MAX_AUTHORITIES]
    catalogue: list[dict[str, Any]] = []
    for source in sorted(routed, key=lambda item: item.authority_identity_id):
        host = (urlparse(source.canonical_url).hostname or "").casefold()
        catalogue.append(
            {
                "id": source.authority_identity_id,
                "title": source.title,
                "citation": source.canonical_citation,
                "family": source.family,
                "subject": source.subject,
                "in_exact_candidate": source.authority_identity_id in candidate_authorities,
                "metadata_only": host == FCL_HOST,
                "full_text_computational_use_permitted": host != FCL_HOST,
            }
        )
    return catalogue


def _selected_source_registry(sources: Sequence[Any]) -> list[dict[str, Any]]:
    """Return the evidence-relevant catalogue identity used by this planner.

    The live catalogue also contains operational tables and millions of chunk
    rows.  Their unrelated changes must not invalidate metadata-only planning,
    while any change to the selected official authority set must fail closed.
    """

    return [
        {
            "source_version_id": source.source_version_id,
            "authority_identity_id": source.authority_identity_id,
            "stable_identifier": source.stable_identifier,
            "version_sha256": source.version_sha256,
            "as_of_date": source.as_of_date,
            "currentness_status": source.currentness_status,
            "identity_verified": source.identity_verified,
            "currentness_verified": source.currentness_verified,
            "family": source.family,
            "catalogue_subject": source.subject,
        }
        for source in sources
    ]


def _batch_rows(rows: Sequence[Mapping[str, Any]]) -> list[list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    order: list[str] = []
    for row in rows:
        case_id = str(row["case_id"])
        if case_id not in grouped:
            order.append(case_id)
        grouped[case_id].append(dict(row))
    return [
        grouped[case_id][start : start + BATCH_SIZE]
        for case_id in order
        for start in range(0, len(grouped[case_id]), BATCH_SIZE)
    ]


def _classification_hint(issue_label: str) -> tuple[str, str]:
    """Return a conservative routing hint without deciding substantive merit."""

    if _ANALYTICAL_LABEL.search(issue_label):
        return "ANALYTICAL_DIMENSION", "EXPLICIT_ANALYSIS_EVIDENCE_OR_STRATEGY_LABEL"
    return "LEGAL_PROPOSITION", "NAMED_DOCTRINE_TEST_DUTY_DEFENCE_REMEDY_OR_TOPIC_DEFAULT"


def _lexical_tokens(text: str) -> set[str]:
    """Return whole and safe component tokens for linkage validation.

    The model may write ``public authority`` for ``public-authority`` or omit a
    possessive suffix.  Retaining the whole token while adding its components
    handles those forms without enabling fuzzy semantic matching.
    """

    observed: set[str] = set()
    for raw in _TOKEN.findall(text):
        token = raw.casefold().replace("’", "'")
        observed.add(token)
        parts = [part for part in _TOKEN_SEPARATOR.split(token) if part]
        if len(parts) > 1:
            observed.update(part for part in parts if part != "s")
    return observed


def _issue_topic_tokens(issue_label: str) -> set[str]:
    wanted = {token for token in _lexical_tokens(issue_label) if token not in _ISSUE_STOP_WORDS}
    for alias in _ISSUE_TERM_ALIASES.get(issue_label.casefold(), frozenset()):
        wanted.update(_lexical_tokens(alias))
    return wanted


def _light_stem(token: str) -> str:
    # Preserve the lexical identity of ordinary consonant+y plurals.  Blindly
    # stripping ``ies`` would turn ``remedies`` into ``remed`` while the
    # singular proposition token remains ``remedy``, creating a false
    # unsupported-topic rejection.
    current = token
    for _ in range(4):
        stem = current
        if current.endswith("ability") and len(current) > 7:
            stem = f"{current[:-7]}able"
        elif current.endswith(("ies", "ied")) and len(current) > 4:
            stem = f"{current[:-3]}y"
        elif current.endswith("ces") and len(current) > 4:
            stem = current[:-1]
        else:
            for suffix in (
                "ations",
                "ation",
                "ments",
                "ment",
                "ness",
                "ities",
                "ity",
                "ingly",
                "edly",
                "ing",
                "ed",
                "ate",
                "ion",
                "ly",
                "es",
                "s",
            ):
                if current.endswith(suffix) and len(current) - len(suffix) >= 4:
                    stem = current[: -len(suffix)]
                    break
        if stem == current:
            return current
        current = stem
    return current


def _issue_token_linked(issue_label: str, proposition: str) -> bool:
    wanted = _issue_topic_tokens(issue_label)
    observed = _lexical_tokens(proposition)
    if wanted & observed:
        return True
    wanted_stems = {_light_stem(token) for token in wanted}
    observed_stems = {_light_stem(token) for token in observed}
    return bool(wanted_stems & observed_stems)


def _fallback_official_source_query(issue_label: str) -> str:
    query = " ".join(f"England Wales official primary authority {issue_label}".split())
    if len(query) > MAX_SEARCH_QUERY_CHARACTERS:
        raise ValueError("phase2a_gap_plan_fallback_search_query_too_long")
    return query


def _failure_fingerprint(
    *,
    batch_ordinal: int,
    row_ids: Sequence[str],
    error_code: str,
    validation_context: Mapping[str, Any] | None,
    execution_plan_sha256: str | None = None,
) -> str:
    """Return a retry-stable material failure identity.

    Repair instructions and request IDs are deliberately excluded so the same
    validation failure cannot evade the two-attempt anti-loop rule merely
    because the second input envelope differs.
    """

    context = dict(validation_context or {})
    stable_context = {key: context[key] for key in ("row_id", "issue_label") if key in context}
    return _sealed(
        {
            "schema": "legalbot.v111.phase2a.gap-plan-failure-fingerprint.v2",
            "batch_ordinal": batch_ordinal,
            "row_ids": list(row_ids),
            "prompt_sha256": _sha256((SYSTEM_PROMPT + "\n").encode()),
            "model_version": EXPECTED_MODEL_VERSION,
            "error_code": error_code,
            "execution_plan_sha256": execution_plan_sha256,
            "stable_validation_context": stable_context,
        }
    )


def _build_input(
    *,
    ordinal: int,
    batch: Sequence[Mapping[str, Any]],
    case: Mapping[str, Any],
    sources: Sequence[Any],
    candidate_authorities: frozenset[str],
    repair_error: str | None,
    repair_context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    legal_domains = sorted({str(row["legal_domain"]) for row in batch})
    authorities_by_id: dict[str, dict[str, Any]] = {}
    for legal_domain in legal_domains:
        for authority in _authority_catalogue(
            legal_domain=legal_domain,
            sources=sources,
            candidate_authorities=candidate_authorities,
        ):
            authorities_by_id[str(authority["id"])] = authority
    value: dict[str, Any] = {
        "schema": "legalbot.v111.phase2a.material-gap-plan-input.v1",
        "batch_ordinal": ordinal,
        "case_id": case["case_id"],
        "subject": case["subject"],
        "scenario": case["question"],
        "rows": [],
        "authorities": list(authorities_by_id.values()),
        "find_case_law_metadata_only": True,
        "advisory_only": True,
        "owner_decision_required": True,
        "qualification_forbidden": True,
        "source_admission_forbidden": True,
        "gate_authorization_forbidden": True,
    }
    for row in batch:
        classification, basis = _classification_hint(str(row["issue_label"]))
        value["rows"].append(
            {
                "row_id": row["row_id"],
                "issue_label": row["issue_label"],
                "legal_domain": row["legal_domain"],
                "prior_triage_class": row["triage_class"],
                "advisory_classification_hint": classification,
                "classification_hint_basis": basis,
            }
        )
    if repair_error:
        value["repair_of_rejected_output"] = True
        value["deterministic_validation_error"] = repair_error
        context = dict(repair_context or {})
        safe_context = {
            key: context[key]
            for key in (
                "expected_classification",
                "issue_label",
                "maximum_characters",
                "observed_characters",
                "observed_classification",
                "output_index",
                "row_id",
            )
            if key in context
        }
        if safe_context:
            value["rejected_output_context"] = safe_context
        if repair_error == "structured_output_nonlegal_plan_invalid":
            value["repair_instruction"] = (
                'For ANALYTICAL_DIMENSION return proposition "", selections [], and '
                'search_query "". For COMPOSITE_REQUIRES_DECOMPOSITION return '
                'proposition "", selections [], and one short non-empty search_query. '
                "Do not attach a proposition or authority selection to either non-legal "
                "classification. Return only the exact compact JSON schema."
            )
        elif repair_error == "structured_output_legal_plan_incomplete":
            value["repair_instruction"] = (
                "For every LEGAL_PROPOSITION provide one non-empty atomic proposition "
                f"of no more than {MAX_PROPOSITION_CHARACTERS} characters "
                "and either at least one supplied authority selection or one non-empty "
                "official-source search_query. Return only the exact compact JSON schema."
            )
        elif repair_error == "structured_output_proposition_too_long":
            value["repair_instruction"] = (
                "Rewrite every LEGAL_PROPOSITION as one atomic sentence of no more than "
                f"{MAX_PROPOSITION_CHARACTERS} characters including spaces. Preserve the "
                "row's central rule and include a substantive issue-label term. Return "
                "only the exact compact JSON schema."
            )
        elif repair_error == "structured_output_proposition_not_linked_to_issue":
            value["repair_instruction"] = (
                "Rewrite each LEGAL_PROPOSITION so its atomic proposition expressly "
                "contains at least one substantive term from that row's issue_label. "
                f"Keep it to no more than {MAX_PROPOSITION_CHARACTERS} characters. Do not "
                "substitute a different doctrine from the wider scenario. Return only "
                "the exact compact JSON schema."
            )
        elif repair_error == "structured_output_invented_authority":
            value["repair_instruction"] = (
                "Every selection id must be copied character-for-character from an id "
                "in the supplied authorities array. Never infer or compose an authority "
                "id. If no supplied authority is adequate, return selections [] and a "
                "short non-empty official-source search_query for that row. Return only "
                "the exact compact JSON schema."
            )
        elif repair_error in {
            "structured_output_row_count_invalid",
            "structured_output_row_invalid",
            "structured_output_row_keys_invalid",
            "structured_output_row_set_invalid",
        }:
            value["repair_instruction"] = (
                "Return every supplied row_id exactly once, copy each row_id character-for-"
                "character, and reproduce that row's advisory_classification_hint exactly. "
                "Each row object must contain only row_id, classification, proposition, "
                "selections, and search_query. Return only the exact compact JSON schema."
            )
        elif repair_error == "model_output_truncated":
            value["repair_instruction"] = (
                "Return only compact JSON with no commentary. Keep every proposition at or "
                f"below {MAX_PROPOSITION_CHARACTERS} characters and every locator/search "
                "query minimal while retaining every supplied row exactly once."
            )
        else:
            value["repair_instruction"] = "Return only the exact compact JSON schema."
    return value


def _envelope(
    row_input: Mapping[str, Any], *, max_output_tokens: int = MAX_OUTPUT_TOKENS
) -> tuple[dict[str, Any], str]:
    if (
        isinstance(max_output_tokens, bool)
        or not isinstance(max_output_tokens, int)
        or not 1 <= max_output_tokens <= MAX_OUTPUT_TOKENS
    ):
        raise ValueError("phase2a_gap_plan_output_token_budget_invalid")
    request_id = str(uuid4())
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": json.dumps(row_input, ensure_ascii=False, separators=(",", ":")),
        },
    ]
    return (
        {
            "request_id": request_id,
            "mode": "semantic_verify",
            "payload": {**dict(row_input), "messages": messages},
            "messages": messages,
            "max_tokens": max_output_tokens,
            "temperature": 0.0,
            "top_p": 1.0,
            "seed": 0,
            "stop": [],
        },
        request_id,
    )


def _http_invoker(model_url: str, timeout_seconds: float) -> Invoke:
    parsed = urlparse(model_url)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("phase2a_gap_plan_model_url_must_be_literal_loopback")
    base = model_url.rstrip("/")
    with httpx.Client(
        timeout=httpx.Timeout(connect=5, read=timeout_seconds, write=30, pool=5),
        trust_env=False,
        follow_redirects=False,
    ) as client:
        response = client.get(f"{base}/api/v1/health")
        body = response.json()
    if (
        response.status_code != 200
        or not isinstance(body, dict)
        or body.get("backend") != MODEL_BACKEND
        or body.get("model_id") != EXPECTED_MODEL_ID
        or body.get("model_loaded") is not True
        or body.get("stub_mode") is not False
        or int(body.get("memory_profile", {}).get("max_output_tokens") or 0) < MAX_OUTPUT_TOKENS
    ):
        raise RuntimeError("phase2a_gap_plan_pinned_model_unavailable")

    def invoke(envelope: dict[str, Any]) -> dict[str, Any]:
        with httpx.Client(
            timeout=httpx.Timeout(connect=5, read=timeout_seconds, write=30, pool=5),
            trust_env=False,
            follow_redirects=False,
        ) as client:
            response = client.post(f"{base}/api/v1/generate", json=envelope)
            response.raise_for_status()
            value = response.json()
        if not isinstance(value, dict):
            raise GapPlanValidationError("model_response_not_object")
        return value

    return invoke


def _validate_model_response(
    *,
    body: Mapping[str, Any],
    row_input: Mapping[str, Any],
    request_id: str,
    allow_invented_authority_fallback: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if body.get("request_id") != request_id:
        raise GapPlanValidationError("model_request_identity_mismatch")
    if body.get("model_version") != EXPECTED_MODEL_VERSION:
        raise GapPlanValidationError("model_version_mismatch")
    if body.get("backend") != MODEL_BACKEND or body.get("deterministic") is not True:
        raise GapPlanValidationError("model_runtime_identity_invalid")
    finish_reason = str(body.get("finish_reason") or "").casefold()
    if finish_reason in {"length", "max_tokens", "token_limit", "truncated"}:
        raise GapPlanValidationError("model_output_truncated")
    warnings = body.get("warnings")
    if not isinstance(warnings, list) or "stub_mode" in warnings:
        raise GapPlanValidationError("model_warning_contract_invalid")
    peak = body.get("peak_memory_gb")
    if peak is not None and (
        isinstance(peak, bool)
        or not isinstance(peak, int | float)
        or float(peak) > MAX_PEAK_MEMORY_GB
    ):
        raise GapPlanValidationError("model_peak_memory_exceeded")
    usage = body.get("usage")
    if not isinstance(usage, dict) or any(
        isinstance(usage.get(field), bool)
        or not isinstance(usage.get(field), int)
        or int(usage[field]) < 0
        for field in ("input_tokens", "output_tokens", "total_tokens")
    ):
        raise GapPlanValidationError("model_usage_invalid")
    structured = body.get("structured")
    if not isinstance(structured, dict) or set(structured) != {
        "schema",
        "case_id",
        "rows",
    }:
        raise GapPlanValidationError("structured_output_keys_invalid")
    if structured.get("schema") != OUTPUT_SCHEMA or structured.get("case_id") != row_input.get(
        "case_id"
    ):
        raise GapPlanValidationError("structured_output_identity_invalid")
    supplied_rows = [str(row["row_id"]) for row in row_input["rows"]]
    supplied_row_records = {str(row["row_id"]): dict(row) for row in row_input["rows"]}
    supplied_classes = {
        str(row["row_id"]): str(row["advisory_classification_hint"]) for row in row_input["rows"]
    }
    supplied_authorities = {str(item["id"]) for item in row_input["authorities"]}
    output_rows = structured.get("rows")
    if not isinstance(output_rows, list) or len(output_rows) != len(supplied_rows):
        raise GapPlanValidationError(
            "structured_output_row_count_invalid",
            context={
                "expected_row_count": len(supplied_rows),
                "observed_row_count": len(output_rows) if isinstance(output_rows, list) else None,
                "observed_type": type(output_rows).__name__,
            },
        )
    normalized: list[dict[str, Any]] = []
    observed: list[str] = []
    deterministic_repairs: list[dict[str, Any]] = []
    classes = {
        "LEGAL_PROPOSITION",
        "ANALYTICAL_DIMENSION",
        "COMPOSITE_REQUIRES_DECOMPOSITION",
    }
    required_row_keys = {
        "row_id",
        "classification",
        "proposition",
        "selections",
        "search_query",
    }
    for output_index, output in enumerate(output_rows):
        if not isinstance(output, dict) or set(output) != required_row_keys:
            observed_keys = sorted(str(key) for key in output) if isinstance(output, dict) else []
            raise GapPlanValidationError(
                "structured_output_row_keys_invalid",
                context={
                    "output_index": output_index,
                    "observed_type": type(output).__name__,
                    "observed_keys": observed_keys,
                    "missing_keys": sorted(required_row_keys - set(observed_keys)),
                    "extra_keys": sorted(set(observed_keys) - required_row_keys),
                },
            )
        row_id = str(output.get("row_id") or "")
        classification = str(output.get("classification") or "")
        proposition = " ".join(str(output.get("proposition") or "").split())
        search_query = " ".join(str(output.get("search_query") or "").split())
        selections = output.get("selections")
        if (
            row_id not in supplied_rows
            or classification not in classes
            or classification != supplied_classes.get(row_id)
        ):
            supplied_row = supplied_row_records.get(row_id, {})
            raise GapPlanValidationError(
                "structured_output_row_invalid",
                context={
                    "output_index": output_index,
                    "row_id": row_id,
                    "issue_label": supplied_row.get("issue_label"),
                    "observed_classification": classification,
                    "expected_classification": supplied_classes.get(row_id),
                    "row_id_supplied": row_id in supplied_rows,
                    "classification_allowed": classification in classes,
                },
            )
        if not isinstance(selections, list) or len(selections) > MAX_SELECTIONS:
            raise GapPlanValidationError("structured_output_selections_invalid")
        issue_label = str(supplied_row_records[row_id]["issue_label"])
        if len(proposition) > MAX_PROPOSITION_CHARACTERS:
            raise GapPlanValidationError(
                "structured_output_proposition_too_long",
                context={
                    "output_index": output_index,
                    "row_id": row_id,
                    "issue_label": issue_label,
                    "observed_characters": len(proposition),
                    "maximum_characters": MAX_PROPOSITION_CHARACTERS,
                    "proposition_sha256": _sha256(proposition.encode()),
                },
            )
        if len(search_query) > MAX_SEARCH_QUERY_CHARACTERS or _PROHIBITED_TEXT.search(search_query):
            raise GapPlanValidationError("structured_output_search_query_invalid")
        if classification == "LEGAL_PROPOSITION":
            if not proposition:
                raise GapPlanValidationError(
                    "structured_output_legal_plan_incomplete",
                    context={
                        "output_index": output_index,
                        "row_id": row_id,
                        "issue_label": issue_label,
                        "missing_field": "proposition",
                    },
                )
            if not _issue_token_linked(issue_label, proposition):
                raise GapPlanValidationError(
                    "structured_output_proposition_not_linked_to_issue",
                    context={
                        "row_id": row_id,
                        "issue_label": issue_label,
                        "accepted_issue_topic_tokens": sorted(_issue_topic_tokens(issue_label)),
                        "observed_proposition_tokens": sorted(_lexical_tokens(proposition)),
                        "proposition_sha256": _sha256(proposition.encode()),
                    },
                )
        elif (
            proposition or selections or (classification == "ANALYTICAL_DIMENSION" and search_query)
        ):
            raise GapPlanValidationError("structured_output_nonlegal_plan_invalid")
        normalized_selections: list[dict[str, str]] = []
        for selection in selections:
            if not isinstance(selection, dict) or set(selection) != {"id", "locator"}:
                raise GapPlanValidationError("structured_output_selection_keys_invalid")
            authority_id = str(selection.get("id") or "")
            locator_hint = " ".join(str(selection.get("locator") or "").split())
            if authority_id not in supplied_authorities:
                if allow_invented_authority_fallback:
                    deterministic_repairs.append(
                        {
                            "row_id": row_id,
                            "reason_code": "INVENTED_AUTHORITY_SELECTION_DROPPED",
                            "rejected_authority_id": authority_id,
                            "rejected_authority_id_sha256": _sha256(authority_id.encode()),
                            "replacement": "BOUNDED_OFFICIAL_SOURCE_SEARCH_QUERY",
                        }
                    )
                    continue
                raise GapPlanValidationError(
                    "structured_output_invented_authority",
                    context={
                        "row_id": row_id,
                        "invented_authority_id": authority_id,
                        "supplied_authority_inventory_sha256": _sealed(
                            sorted(supplied_authorities)
                        ),
                    },
                )
            if (
                not locator_hint
                or len(locator_hint) > MAX_LOCATOR_CHARACTERS
                or _PROHIBITED_TEXT.search(locator_hint)
            ):
                raise GapPlanValidationError("structured_output_locator_invalid")
            normalized_selections.append(
                {"authority_identity_id": authority_id, "locator_hint": locator_hint}
            )
        if classification == "LEGAL_PROPOSITION" and not normalized_selections:
            if not search_query and allow_invented_authority_fallback:
                search_query = _fallback_official_source_query(issue_label)
            if not search_query:
                raise GapPlanValidationError("structured_output_legal_plan_incomplete")
        observed.append(row_id)
        normalized.append(
            {
                "row_id": row_id,
                "classification": classification,
                "advisory_atomic_proposition": proposition,
                "selections": normalized_selections,
                "official_source_search_query": search_query,
                "proposition_evidence_verified": False,
                "owner_outcome": None,
                "owner_decision_required": True,
                "technical_qualification_assigned": False,
            }
        )
    if len(set(observed)) != len(observed) or set(observed) != set(supplied_rows):
        duplicates = sorted(row_id for row_id, count in Counter(observed).items() if count > 1)
        raise GapPlanValidationError(
            "structured_output_row_set_invalid",
            context={
                "duplicate_row_ids": duplicates,
                "missing_row_ids": sorted(set(supplied_rows) - set(observed)),
                "unexpected_row_ids": sorted(set(observed) - set(supplied_rows)),
            },
        )
    normalized.sort(key=lambda row: supplied_rows.index(row["row_id"]))
    raw = str(body.get("raw_text") or "")
    return normalized, {
        "input_tokens": usage["input_tokens"],
        "output_tokens": usage["output_tokens"],
        "total_tokens": usage["total_tokens"],
        "generation_ms": body.get("generation_ms"),
        "time_to_first_token_ms": body.get("time_to_first_token_ms"),
        "peak_memory_gb": peak,
        "finish_reason": finish_reason,
        "raw_output_sha256": _sha256(raw.encode("utf-8")),
        "raw_output_character_count": len(raw),
        "deterministic_validation_repair_count": len(deterministic_repairs),
        "deterministic_validation_repairs": deterministic_repairs,
    }


def _error_code(exc: BaseException) -> str:
    if isinstance(exc, GapPlanValidationError):
        return exc.code
    if isinstance(exc, RuntimeError | ValueError) and exc.args:
        value = str(exc.args[0]).casefold().replace("-", "_")
        if _SAFE_CODE.fullmatch(value):
            return value
    value = re.sub(r"(?<!^)(?=[A-Z])", "_", type(exc).__name__).casefold()
    return value if _SAFE_CODE.fullmatch(value) else "phase2a_gap_plan_unknown_failure"


def _checkpoint_name(ordinal: int, batch: Sequence[Mapping[str, Any]]) -> str:
    row_ids = "\n".join(str(row["row_id"]) for row in batch)
    return f"{ordinal:03d}-{_sha256((row_ids + chr(10)).encode())[:24]}.json"


def _review_batch(
    *,
    ordinal: int,
    batch: Sequence[Mapping[str, Any]],
    case: Mapping[str, Any],
    sources: Sequence[Any],
    candidate_authorities: frozenset[str],
    invoke: Invoke,
    checkpoints_root: Path,
    diagnostics_root: Path,
    max_output_tokens: int = MAX_OUTPUT_TOKENS,
    debug_execution_context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    execution_context = dict(debug_execution_context or {})
    execution_plan_sha256 = _sealed(
        {
            "schema": "legalbot.v111.phase2a.gap-plan-execution-plan.v1",
            "prompt_sha256": _sha256((SYSTEM_PROMPT + "\n").encode()),
            "model_version": EXPECTED_MODEL_VERSION,
            "row_count": len(batch),
            "max_output_tokens": max_output_tokens,
            "debug_execution_context": execution_context,
        }
    )
    prior_error: str | None = None
    prior_context: dict[str, Any] | None = None
    fingerprints: list[str] = []
    for attempt in (1, 2):
        row_input = _build_input(
            ordinal=ordinal,
            batch=batch,
            case=case,
            sources=sources,
            candidate_authorities=candidate_authorities,
            repair_error=prior_error,
            repair_context=prior_context,
        )
        if execution_context:
            row_input["debug_execution_context"] = execution_context
        input_sha256 = _sealed(row_input)
        envelope, request_id = _envelope(row_input, max_output_tokens=max_output_tokens)
        started = time.perf_counter()
        body: dict[str, Any] | None = None
        try:
            body = invoke(envelope)
            plans, metrics = _validate_model_response(
                body=body,
                row_input=row_input,
                request_id=request_id,
                allow_invented_authority_fallback=(
                    attempt == 2
                    and prior_error == "structured_output_invented_authority"
                    and len(batch) == 1
                ),
            )
        except Exception as exc:
            error = _error_code(exc)
            repairable_output_failure = _is_repairable_model_output_failure(exc, error)
            validation_context = (
                dict(exc.context) if isinstance(exc, GapPlanValidationError) else {}
            )
            fingerprint = _failure_fingerprint(
                batch_ordinal=ordinal,
                row_ids=[str(row["row_id"]) for row in batch],
                error_code=error,
                validation_context=validation_context,
                execution_plan_sha256=execution_plan_sha256,
            )
            fingerprints.append(fingerprint)
            diagnostic_material = {
                "schema": "legalbot.v111.phase2a.gap-plan-rejected-attempt.v1",
                "batch_ordinal": ordinal,
                "row_ids": [str(row["row_id"]) for row in batch],
                "attempt": attempt,
                "input_content_sha256": input_sha256,
                "request_id": request_id,
                "error_code": error,
                "validation_context": validation_context,
                "failure_fingerprint": fingerprint,
                "execution_plan_sha256": execution_plan_sha256,
                "maximum_output_tokens": max_output_tokens,
                "same_failure_fingerprint_as_prior_attempt": len(fingerprints) == 2
                and fingerprints[0] == fingerprints[1],
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                "response_received": body is not None,
                "raw_output_sha256": _sha256(str((body or {}).get("raw_text") or "").encode())
                if body
                else None,
                "raw_output_persisted": False,
                "hidden_reasoning_persisted": False,
                "owner_decision_assigned": False,
                "source_admission_authorized": False,
                "candidate_mutated": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            }
            diagnostic = {
                **diagnostic_material,
                "diagnostic_content_sha256": _sealed(diagnostic_material),
            }
            stem = _checkpoint_name(ordinal, batch)[:-5]
            _write_exclusive(
                diagnostics_root / f"{stem}-a{attempt}.json",
                _pretty_json(diagnostic),
            )
            prior_error = error
            prior_context = validation_context
            if attempt == 1 and repairable_output_failure:
                continue
            same_failure_twice = len(fingerprints) == 2 and fingerprints[0] == fingerprints[1]
            debug_before_any_retry = attempt == 1
            held_material = {
                "schema": "legalbot.v111.phase2a.gap-plan-held-batch.v1",
                "batch_ordinal": ordinal,
                "case_id": case["case_id"],
                "row_ids": [str(row["row_id"]) for row in batch],
                "status": (
                    "HELD_FOR_DEBUG_BEFORE_ANY_RETRY"
                    if debug_before_any_retry
                    else "HELD_FOR_DEBUG_BEFORE_ANY_THIRD_ATTEMPT"
                ),
                "attempt_count": len(fingerprints),
                "failure_fingerprints": fingerprints,
                "execution_plan_sha256": execution_plan_sha256,
                "maximum_output_tokens": max_output_tokens,
                "same_failure_fingerprint_twice": same_failure_twice,
                "repairable_model_output_failure": repairable_output_failure,
                "nonrepairable_runtime_failure": (error in _NON_REPAIRABLE_RUNTIME_FAILURES),
                "debug_required_before_retry": debug_before_any_retry,
                "debug_required_before_third_attempt": attempt == 2,
                "owner_decision_assigned": False,
                "source_admission_authorized": False,
                "candidate_mutated": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            }
            held = {**held_material, "held_content_sha256": _sealed(held_material)}
            _write_exclusive(
                checkpoints_root / _checkpoint_name(ordinal, batch),
                _pretty_json(held),
            )
            return held
        checkpoint_material = {
            "schema": "legalbot.v111.phase2a.gap-plan-checkpoint.v1",
            "batch_ordinal": ordinal,
            "case_id": case["case_id"],
            "row_ids": [str(row["row_id"]) for row in batch],
            "input_content_sha256": input_sha256,
            "prompt_sha256": _sha256((SYSTEM_PROMPT + "\n").encode()),
            "model_version": EXPECTED_MODEL_VERSION,
            "reviewer_execution_mode": REVIEWER_EXECUTION_MODE,
            "attempt_count": attempt,
            "execution_plan_sha256": execution_plan_sha256,
            "maximum_output_tokens": max_output_tokens,
            "repaired_after_rejected_output": attempt == 2,
            "plans": plans,
            "model_metrics": metrics,
            "raw_model_output_persisted": False,
            "hidden_reasoning_persisted": False,
            "advisory_only": True,
            "owner_decision_required": True,
            "owner_decision_assigned": False,
            "source_admission_authorized": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        checkpoint = {
            **checkpoint_material,
            "checkpoint_content_sha256": _sealed(checkpoint_material),
        }
        _write_exclusive(
            checkpoints_root / _checkpoint_name(ordinal, batch),
            _pretty_json(checkpoint),
        )
        return checkpoint
    raise AssertionError("unreachable gap-plan attempt loop")


def _load_checkpoint(path: Path) -> dict[str, Any]:
    value = _load_object(path)
    if value.get("schema") == "legalbot.v111.phase2a.gap-plan-checkpoint.v1":
        _verify_seal(value, "checkpoint_content_sha256", "gap_plan_checkpoint_invalid")
    elif value.get("schema") == "legalbot.v111.phase2a.gap-plan-held-batch.v1":
        _verify_seal(value, "held_content_sha256", "gap_plan_held_invalid")
    else:
        raise ValueError("phase2a_gap_plan_checkpoint_schema_invalid")
    return value


def build_plans(
    *,
    triage_path: Path,
    cases_path: Path,
    catalogue_path: Path,
    candidate_manifest_path: Path,
    output_root: Path,
    invoke: Invoke,
    started_at: datetime,
    case_id: str | None,
    resume: bool,
) -> dict[str, Any]:
    if started_at.tzinfo is None:
        raise ValueError("phase2a_gap_plan_started_at_naive")
    gap_rows, triage_digest = _load_gap_rows(triage_path)
    cases = _load_cases(cases_path)
    if case_id:
        if case_id not in cases:
            raise ValueError("phase2a_gap_plan_case_filter_invalid")
        gap_rows = [row for row in gap_rows if row["case_id"] == case_id]
        if not gap_rows:
            raise ValueError("phase2a_gap_plan_case_filter_empty")
    candidate_authorities, candidate_digest, candidate_file_digest = _candidate_authorities(
        candidate_manifest_path
    )
    with _open_catalogue(catalogue_path) as connection:
        sources = _select_sources(connection, TARGET_CEILING_DATE)
    selected_source_registry_sha256 = _sealed(_selected_source_registry(sources))
    if selected_source_registry_sha256 != EXPECTED_SELECTED_SOURCE_REGISTRY_SHA256:
        raise ValueError("phase2a_gap_plan_selected_source_registry_changed")
    batches = _batch_rows(gap_rows)
    intent_path = output_root / "INTENT.json"
    code_digest = _sha256_file(Path(__file__).resolve())
    scope = case_id or "ALL_364"
    if output_root.exists() or output_root.is_symlink():
        if not resume or output_root.is_symlink() or not output_root.is_dir():
            raise ValueError("phase2a_gap_plan_output_already_exists")
        intent = _load_object(intent_path)
        _verify_seal(intent, "intent_content_sha256", "gap_plan_intent_invalid")
        if (
            intent.get("source_triage_content_sha256") != triage_digest
            or intent.get("prompt_sha256") != _sha256((SYSTEM_PROMPT + "\n").encode())
            or intent.get("builder_code_file_sha256") != code_digest
            or intent.get("scope") != scope
            or intent.get("source_selected_registry_sha256") != selected_source_registry_sha256
        ):
            raise ValueError("phase2a_gap_plan_resume_identity_mismatch")
    else:
        output_root.mkdir(parents=True, mode=0o700)
        if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
            raise ValueError("phase2a_gap_plan_output_mode_invalid")
        intent_material = {
            "schema": "legalbot.v111.phase2a.gap-plan-intent.v1",
            "status": "ADVISORY_GAP_RESEARCH_PLANNING_ONLY_NO_OWNER_DECISIONS",
            "started_at": started_at.astimezone(UTC).isoformat(timespec="seconds"),
            "scope": scope,
            "source_triage_content_sha256": triage_digest,
            "source_cases_file_sha256": EXPECTED_CASES_FILE_SHA256,
            "source_catalogue_identity_mode": ("SELECTED_OFFICIAL_SOURCE_REGISTRY_CONTENT_SHA256"),
            "source_selected_registry_sha256": selected_source_registry_sha256,
            "source_candidate_manifest_sha256": candidate_digest,
            "source_candidate_manifest_file_sha256": candidate_file_digest,
            "source_authority_count": len(sources),
            "prompt_sha256": _sha256((SYSTEM_PROMPT + "\n").encode()),
            "builder_code_file_sha256": code_digest,
            "model_id": EXPECTED_MODEL_ID,
            "model_version": EXPECTED_MODEL_VERSION,
            "reviewer_execution_mode": REVIEWER_EXECUTION_MODE,
            "model_independent_reviewer": False,
            "find_case_law_metadata_only": True,
            "find_case_law_full_text_supplied": False,
            "row_count": len(gap_rows),
            "batch_count": len(batches),
            "maximum_rows_per_batch": BATCH_SIZE,
            "maximum_attempts_per_batch": 2,
            "maximum_runtime_transport_attempts_per_batch": 1,
            "maximum_malformed_output_attempts_per_batch": 2,
            "runtime_transport_debug_required_before_retry": True,
            "debug_required_before_any_third_attempt": True,
            "raw_model_output_persisted": False,
            "hidden_reasoning_persisted": False,
            "owner_decisions_applied": False,
            "source_admission_authorized": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        intent = {**intent_material, "intent_content_sha256": _sealed(intent_material)}
        _write_exclusive(intent_path, _pretty_json(intent))

    checkpoints_root = output_root / "checkpoints"
    diagnostics_root = output_root / "diagnostics"
    checkpoints_root.mkdir(mode=0o700, exist_ok=True)
    diagnostics_root.mkdir(mode=0o700, exist_ok=True)
    final_path = output_root / "MATERIAL-GAP-RESEARCH-PLANS.json"
    if final_path.exists():
        raise ValueError("phase2a_gap_plan_already_finalized")
    results: list[dict[str, Any]] = []
    for ordinal, batch in enumerate(batches, start=1):
        checkpoint_path = checkpoints_root / _checkpoint_name(ordinal, batch)
        if checkpoint_path.exists():
            if not resume:
                raise ValueError("phase2a_gap_plan_checkpoint_exists_without_resume")
            results.append(_load_checkpoint(checkpoint_path))
            continue
        batch_case_id = str(batch[0]["case_id"])
        results.append(
            _review_batch(
                ordinal=ordinal,
                batch=batch,
                case=cases[batch_case_id],
                sources=sources,
                candidate_authorities=candidate_authorities,
                invoke=invoke,
                checkpoints_root=checkpoints_root,
                diagnostics_root=diagnostics_root,
            )
        )
    plans: list[dict[str, Any]] = []
    held_rows: list[str] = []
    for result in results:
        if result.get("schema") == "legalbot.v111.phase2a.gap-plan-held-batch.v1":
            held_rows.extend(str(row_id) for row_id in result["row_ids"])
        else:
            plans.extend(dict(plan) for plan in result["plans"])
    if len(plans) + len(held_rows) != len(gap_rows):
        raise ValueError("phase2a_gap_plan_final_coverage_invalid")
    classification_counts = Counter(str(plan["classification"]) for plan in plans)
    selected_ids = {
        str(selection["authority_identity_id"])
        for plan in plans
        for selection in plan["selections"]
    }
    fcl_ids = {
        source.authority_identity_id
        for source in sources
        if (urlparse(source.canonical_url).hostname or "").casefold() == FCL_HOST
    }
    final_material = {
        "schema": "legalbot.v111.phase2a.material-gap-research-plans.v1",
        "status": "ADVISORY_GAP_PLANS_COMPLETE_OWNER_DECISIONS_AND_EVIDENCE_REVIEW_REQUIRED"
        if not held_rows
        else "ADVISORY_GAP_PLANS_WITH_HELD_BATCHES_DEBUG_REQUIRED",
        "scope": scope,
        "source_intent_content_sha256": intent["intent_content_sha256"],
        "source_triage_content_sha256": triage_digest,
        "reviewer_execution_mode": REVIEWER_EXECUTION_MODE,
        "model_independent_reviewer": False,
        "find_case_law_metadata_only": True,
        "find_case_law_full_text_supplied": False,
        "row_count": len(gap_rows),
        "planned_row_count": len(plans),
        "held_row_count": len(held_rows),
        "held_row_ids": held_rows,
        "classification_counts": dict(sorted(classification_counts.items())),
        "selected_authority_count": len(selected_ids),
        "selected_find_case_law_metadata_authority_count": len(selected_ids & fcl_ids),
        "plans": plans,
        "proposition_evidence_verified": False,
        "owner_decisions_applied": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    final = {**final_material, "artifact_content_sha256": _sealed(final_material)}
    _write_exclusive(final_path, _pretty_json(final))
    outcome = (
        f"ADVISORY GAP PLANS: {len(plans)}/{len(gap_rows)} PLANNED; "
        f"{len(held_rows)} HELD. OWNER DECISIONS AND EVIDENCE VERIFICATION REMAIN REQUIRED.\n"
    ).encode()
    _write_exclusive(output_root / "OUTCOME.txt", outcome)
    names = ["INTENT.json", final_path.name, "OUTCOME.txt"]
    sums = "".join(f"{_sha256_file(output_root / name)}  {name}\n" for name in names).encode()
    _write_exclusive(output_root / "SHA256SUMS.txt", sums)
    return final


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--triage", type=Path, default=DEFAULT_TRIAGE)
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--catalogue", type=Path, default=DEFAULT_CATALOGUE)
    parser.add_argument("--candidate-manifest", type=Path, default=DEFAULT_CANDIDATE_MANIFEST)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--model-url", default="http://127.0.0.1:8779")
    parser.add_argument("--timeout-seconds", type=float, default=240.0)
    parser.add_argument("--case-id")
    parser.add_argument("--resume", action="store_true")
    return parser.parse_args()


def _persist_top_level_failure(output_root: Path, exc: BaseException) -> None:
    """Persist a fail-closed summary without mutating a completed run."""

    try:
        if output_root.is_symlink():
            return
        if output_root.exists():
            if (
                not output_root.is_dir()
                or (output_root / "MATERIAL-GAP-RESEARCH-PLANS.json").exists()
                or not (output_root / "INTENT.json").exists()
            ):
                return
        else:
            output_root.mkdir(parents=True, mode=0o700)
        failure_path = output_root / "FAILURE.json"
        if failure_path.exists() or failure_path.is_symlink():
            return
        error_code = _error_code(exc)
        fingerprint_material = {
            "affected_stage": "PHASE2A_MATERIAL_GAP_RESEARCH_PLANNING",
            "error_code": error_code,
            "expected_triage_content_sha256": EXPECTED_TRIAGE_CONTENT_SHA256,
            "expected_selected_source_registry_sha256": (EXPECTED_SELECTED_SOURCE_REGISTRY_SHA256),
            "prompt_sha256": _sha256((SYSTEM_PROMPT + "\n").encode()),
        }
        material = {
            "schema": "legalbot.v111.phase2a.gap-plan-top-level-failure.v1",
            "failure_fingerprint": _sealed(fingerprint_material),
            **fingerprint_material,
            "recorded_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "affected_rows": "REQUESTED_PLANNER_SCOPE",
            "completed_work": "PRESERVED_BEFORE_EXCEPTION",
            "root_cause_status": "DEBUG_REQUIRED",
            "required_execution_plan_change": (
                "INSPECT_THE_BOUND_INPUT_IDENTITY_OR_RUNTIME_FAILURE_BEFORE_RETRY"
            ),
            "debug_required_before_any_third_attempt": True,
            "owner_decisions_applied": False,
            "source_admission_authorized": False,
            "automatic_indexing": False,
            "automatic_embedding": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        _write_exclusive(
            failure_path,
            _pretty_json({**material, "failure_content_sha256": _sealed(material)}),
        )
    except BaseException:
        return


def main() -> None:
    args = _arguments()
    invoke = _http_invoker(args.model_url, args.timeout_seconds)
    output_root = args.output_root.resolve()
    try:
        result = build_plans(
            triage_path=args.triage.resolve(strict=True),
            cases_path=args.cases.resolve(strict=True),
            catalogue_path=args.catalogue.resolve(strict=True),
            candidate_manifest_path=args.candidate_manifest.resolve(strict=True),
            output_root=output_root,
            invoke=invoke,
            started_at=datetime.now(UTC),
            case_id=args.case_id,
            resume=args.resume,
        )
    except BaseException as exc:
        _persist_top_level_failure(output_root, exc)
        raise
    print(
        json.dumps(
            {
                "output_root": str(args.output_root),
                "status": result["status"],
                "row_count": result["row_count"],
                "planned_row_count": result["planned_row_count"],
                "held_row_count": result["held_row_count"],
                "classification_counts": result["classification_counts"],
                "artifact_content_sha256": result["artifact_content_sha256"],
                "phase2b_authorized": result["phase2b_authorized"],
                "development30_authorized": result["development30_authorized"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
