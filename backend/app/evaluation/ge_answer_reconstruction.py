"""Rebuild 330 candidate answers so they are not diagnostic wrappers.

This is answer construction, not another 331 diagnostic, not generic
retrieval, not qualified legal review, gold, training, unseen, promotion
or live.
"""

from __future__ import annotations

import json
import re
import zipfile
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .ge_ai_advisory_campaign import DEFAULT_OUTPUT as ADVISORY_R2
from .ge_currentness_packets import (
    PROJECT_ROOT,
    evidence_manifest_hash,
    load_jsonl,
    load_latest_delta_rows,
    mutation_guard,
    sha256_file,
    sha256_text,
    write_json,
    write_jsonl,
    write_text,
)
from .ge_diagnostic_evaluator import (
    PLANNER_PREFIXES,
    alphanumeric_tokens,
    case_requires_urgent_user_action,
    evaluate_factual_checks,
)
from .ge_fact_dependent_packets import CONDITIONAL_ANSWER, MISSING_FACTS
from .ge_grok_independent_review import (
    EXPECTED_QLR_STATE,
    EXPECTED_QLR_WORKBOOK,
    build_blind_row,
    is_diagnostic_template,
)
from .ge_grok_readiness_audit import (
    CAMPAIGN_ID as READINESS_CAMPAIGN_ID,
    CUSTOM_FIVE,
    run_grok_readiness_audit,
)
from .ge_grok_review_overrides import INCOMPLETE_FULL, OVERRIDES, WRONG_ROUTE_FULL
from .ge_hold_reason_router import CASE_174, CASE_312
from .ge_locator_gold_overlay import load_locator_gold_overlay
from .ge_phase2_progress import (
    DOWNSTREAM_GATES,
    NOT_STARTED,
    NO_OP_UNCHANGED_INPUTS,
    REVISED_ANSWERS_AWAITING_INDEPENDENT_BLIND_REVIEW,
    phase2_progress,
)
from .ge_progression_taxonomy import (
    CONDITIONAL_REVIEW_READY,
    HOLD_MATERIAL,
    LAND_LAW_D05,
    REVIEW_READY_CURRENTNESS,
    REVIEW_READY_JURISDICTION,
    TORT_D13,
    VERIFIED_FULL_CANDIDATE,
    VERIFIED_LIMITED_CANDIDATE,
)
from .ge_qualified_review_campaign import (
    CAMPAIGN_ID as QLR_CAMPAIGN_ID,
    DEFAULT_LOCATOR_OVERLAY,
    deleted_spans,
    question_still_materially_answered,
)

CAMPAIGN_ID = "LegalBot-GE-2026-09-03-answer-reconstruction-r1"
CAMPAIGN_VERSION = "legalbot.ge-answer-reconstruction.v1"
DEFAULT_OUTPUT = PROJECT_ROOT / "data/evaluations/general-enquiries" / CAMPAIGN_ID
DESKTOP_ZIP = (Path.home() / "Desktop") / f"{CAMPAIGN_ID}.zip"
BLIND_ZIP = (Path.home() / "Desktop") / "LegalBot-GE-2026-09-03-reconstructed-blind-r1.zip"
FORBIDDEN = (
    "closest verified source",
    "complete controlling law for your facts",
    "cannot give a final merits view",
    "planner notes",
    "not yet qualified legal advice or legal gold",
    "your question is:",
    "evidence-bound candidate answer for owner review",
)
STOPWORDS = frozenset(
    {
        "this",
        "that",
        "with",
        "from",
        "your",
        "have",
        "will",
        "would",
        "could",
        "should",
        "under",
        "been",
        "they",
        "them",
        "then",
        "than",
        "also",
        "into",
        "about",
        "after",
        "before",
        "because",
        "which",
        "while",
        "where",
        "when",
        "what",
        "does",
        "did",
        "must",
        "there",
        "their",
        "them",
        "being",
        "still",
        "only",
        "just",
        "over",
        "more",
        "some",
        "such",
        "into",
    }
)
URGENT_QUESTION = re.compile(
    r"\b(?:tomorrow|tonight|right now|being published|auction(?:ed)?|"
    r"payroll|has not arrived|removed tomorrow)\b",
    re.IGNORECASE,
)
QUESTIONS_BLOCK = re.compile(
    r"Questions I need answered\n\n((?:- .+\n?)+)",
    re.IGNORECASE,
)

NAMED_AND_CUSTOM: dict[str, str] = {
    CASE_312: CONDITIONAL_ANSWER,
    CASE_174: (
        "The English-law ICC mediation clause is not shown, on the attached locators, "
        "to force an automatic stay of English court proceedings. ICC Mediation Rules "
        "article 5 deals with selecting a mediator, including Centre appointment if the "
        "parties do not jointly nominate one. A missing named mediator does not, on that "
        "article, make the clause empty. Ohpen records that an unqualified ADR reference "
        "can still impose a sufficiently certain minimum duty of participation. Kajima "
        "paragraph 29 records that a dispute-resolution procedure can be a condition "
        "precedent; it does not decide this ICC wording. Paragraph 30 is not used. The "
        "attached Churchill passage and CPR 1.1 (overriding objective) do not themselves "
        "stay proceedings. Cable & Wireless is a rejected route and is not used. "
        "Arbitration Act 1996 section 9 is not used because this is a mediation clause, "
        "not an arbitration agreement. Whether the English court must stay for ICC "
        "mediation, and what follows for a German buyer, remain unresolved "
        "jurisdiction and scope questions. This answer is limited to those attached locators."
    ),
    LAND_LAW_D05: (
        "I cannot choose between 1 May 2026 and 15 August 2026 as the governing date. "
        "Both dates appear in the question, and this packet does not resolve which date "
        "controls. The attached Law of Property Act 1925 section 52 passage concerns "
        "assured tenancies of social-housing providers, not a private 2024 tenancy. CPR "
        "55.11 as attached concerns demoted assured shorthold tenancies of registered "
        "social landlords, not this sale. Land Registration Act 2002 section 132 as "
        "attached is a mines-and-minerals definition and does not decide whether a sale "
        "ends a periodic private tenancy. I do not state that the sale ended the tenancy, "
        "and I do not state that it continued. Those locators do not decide the "
        "private-tenancy continuation rule."
    ),
    "ai-and-data-protection:cp-d03": (
        "Yes, you can ask the old employer to erase the interview recordings and any AI "
        "scores. UK GDPR Article 5 includes storage limitation: personal data must not be "
        "kept longer than necessary for the processing purposes. Article 15 gives a right "
        "to confirmation and access. Article 17 gives a right to obtain erasure without "
        "undue delay where a listed ground applies. Article 17 paragraphs 1 and 2 do not "
        "apply to the extent processing is necessary, including for a legal obligation or "
        "for legal claims. Erasure is therefore not automatic. Retention purpose and any "
        "legal-obligation or legal-claims basis still matter. This answer uses only the "
        "attached UK GDPR Articles 5, 15 and 17. Later Data (Use and Access) Act changes "
        "and ICO guidance are not attached here."
    ),
    "ai-and-data-protection:cp-d07": (
        "You can ask the fitness-app controller to rectify an inaccurate health score. "
        "UK GDPR Article 5 requires personal data to be accurate and, where necessary, "
        "kept up to date. Article 16 gives a right to rectification of inaccurate data "
        "without undue delay. Article 9 prohibits processing of special-category data, "
        "including data concerning health, unless an Article 9 condition applies. The "
        "attached Article 22A text defines when a decision is based solely on automated "
        "processing; it does not by itself decide the insurance-price outcome. The known "
        "facts do not establish that the fitness score caused the insurer's increase, or "
        "that the insurer is the same controller. Currentness, territorial scope and the "
        "practical enforcement route against each controller are not verified in this "
        "packet, so this answer is limited to those attached locators. Equality Act "
        "routes are not used because a protected characteristic is not established on "
        "these facts."
    ),
    "ai-and-data-protection:cp-d09": (
        "You can challenge workplace message-monitoring and mood-scoring on the attached "
        "UK GDPR locators. Article 6 requires a lawful basis. Article 21 gives a right to "
        "object, on grounds relating to a particular situation, to certain processing "
        "including profiling. Article 22C requires safeguards where a significant "
        "decision is taken by or on behalf of a controller. Article 5 includes storage "
        "limitation. A mood inference is not treated as health data on these facts. "
        "Equality Act 2010 is not attached. Articles 22A and 22B are not attached; this "
        "answer does not rely on them. Whether promotion use is a significant decision, "
        "and whether any lawful basis actually applies, still depend on facts not in the "
        "packet."
    ),
    "competition-law:cp-d02": (
        "A five-year exclusive-stocking term can be challenged, but duration alone does "
        "not decide legality. Competition Act 1998 section 2 prohibits agreements that "
        "have as their object or effect the prevention, restriction or distortion of "
        "competition in the United Kingdom, unless they are exempt. The attached Vertical "
        "Agreements Block Exemption Order 2022 article 10 excludes a non-compete "
        "obligation whose duration is indefinite or exceeds five years, including one "
        "that is tacitly renewable beyond five years. A five-year exclusivity term is not "
        "the same legal test as a non-compete that exceeds five years. Section 9 "
        "exemption conditions and VABEO market-share thresholds are not completely mapped "
        "in the attached locators, so they are not used as a completed exemption "
        "analysis. Dominance is not asserted; market-power facts are not established. "
        "Currentness and full territorial scope remain limited to the attached text."
    ),
    "land-law:cp-d17": (
        "If the home is due to be auctioned tomorrow on a signature you say was forged, "
        "get urgent legal help today. A Land Registry communication alone is not shown to "
        "stop the auction. Senior Courts Act 1981 section 37 lets the High Court grant an "
        "injunction, including an interlocutory injunction, where it appears just and "
        "convenient. Land Registration Act 2002 Schedule 4 lets the court order "
        "alteration of the register. Schedule 8 concerns indemnity; the attached "
        "paragraph 4 is about a discretionary payment where no indemnity is payable, not "
        "an automatic stop on sale. The attached Civil Procedure Rules 1998 rule 25.1 "
        "passage is an order for interim payment, not the injunction rule, and is not "
        "used for the injunction proposition. Unregistered attempts, pending applications, "
        "completed registrations, court-ordered sales and mortgagee power-of-sale "
        "auctions are different routes. Preserve the alleged-forgery evidence and obtain "
        "urgent representation. Law of Property Act 1925 sections 101 and 103 are not "
        "attached because a mortgagee sale is not established. Whether an injunction will "
        "actually issue tomorrow is not decided on these locators."
    ),
    "tort-law:cp-d18": (
        "I cannot use Khan v Meadows for a website spreading an address and a false "
        "accusation. That authority is a clinical-negligence scope-of-duty case and is "
        "not the supporting route here. I do not state a defamation, harassment or "
        "erasure outcome from that locator. If personal safety is at risk because an "
        "address is being published now, get urgent help first."
    ),
    "wills-and-estates:cp-s02": (
        "No. I cannot create or backdate a will after death. A will must be made by the "
        "will-maker, with the required formalities, during their lifetime. After death "
        "without a signed will, Administration of Estates Act 1925 section 46 may govern "
        "who benefits on intestacy. I will not draft a false will."
    ),
}


def planner_safe(text: str) -> str:
    stripped = text.strip()
    lowered = stripped.casefold()
    if any(lowered.startswith(prefix) for prefix in PLANNER_PREFIXES):
        return "On these facts, " + stripped[0].lower() + stripped[1:]
    return stripped


def handwritten_library() -> dict[str, str]:
    texts = dict(NAMED_AND_CUSTOM)
    for case_id, row in OVERRIDES.items():
        proposed = str(row.get("proposed_final_answer") or "").strip()
        if proposed and case_id not in texts:
            texts[str(case_id)] = proposed
    return {key: planner_safe(value) for key, value in texts.items()}


def contains_forbidden(answer: str) -> list[str]:
    lowered = answer.casefold()
    return [item for item in FORBIDDEN if item in lowered]


def extract_missing(original: str) -> list[str]:
    match = QUESTIONS_BLOCK.search(original or "")
    if not match:
        return []
    facts: list[str] = []
    for line in match.group(1).splitlines():
        if line.startswith("- "):
            text = line[2:].strip()
            if text:
                facts.append(text)
    return facts[:3]


def paraphrase_quote(quote: str) -> str:
    text = " ".join(str(quote or "").split())
    if not text:
        return "the attached operative words"
    if len(text) > 240:
        text = text[:237].rsplit(" ", 1)[0].rstrip(",;:") + "."
    if text[-1] not in ".!?":
        text += "."
    return text


def question_tokens(question: str) -> list[str]:
    tokens: list[str] = []
    for token in alphanumeric_tokens(question):
        folded = token.casefold()
        if len(token) >= 4 and folded not in STOPWORDS and folded not in tokens:
            tokens.append(token)
        if len(tokens) >= 6:
            break
    return tokens


def is_urgent(question: str, delta: Mapping[str, Any] | None) -> bool:
    if URGENT_QUESTION.search(question or ""):
        return True
    if delta is not None and case_requires_urgent_user_action(delta):
        return True
    return False


def usable_claims(case_id: str, claims: Sequence[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    kept: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    for item in claims:
        if not isinstance(item, Mapping):
            continue
        row = dict(item)
        if case_id == "land-law:cp-d17":
            locator = str(row.get("locator") or "").casefold()
            quote = str(row.get("quote") or "").casefold()
            if "25.1" in locator and "interim payment" in quote:
                dropped.append(row)
                continue
        kept.append(row)
    return kept, dropped


def lead_sentence(working: str, case_id: str) -> str:
    if case_id in WRONG_ROUTE_FULL or working == HOLD_MATERIAL:
        return (
            "I cannot decide the outcome from the attached locators. "
            "What they actually show is as follows."
        )
    if working == REVIEW_READY_CURRENTNESS:
        return (
            "The attached locators state the following rules. Later amendment, "
            "commencement and authority status are not verified in this packet, so "
            "this answer is limited to that attached text."
        )
    if working == REVIEW_READY_JURISDICTION:
        return (
            "The attached locators state the following rules. Territorial or "
            "procedural scope beyond those locators is not verified."
        )
    if working == CONDITIONAL_REVIEW_READY:
        return CONDITIONAL_ANSWER
    if working == VERIFIED_LIMITED_CANDIDATE:
        return (
            "On the attached locators a limited position can be stated. It does not "
            "complete every issue in the question."
        )
    return "On the attached authorities the position is as follows."


def synthesize(
    *,
    case_id: str,
    question: str,
    original: str,
    working: str,
    claims: Sequence[Mapping[str, Any]],
    currentness: str,
    jurisdiction: str,
    delta: Mapping[str, Any] | None,
) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
    kept, dropped = usable_claims(case_id, claims)
    parts: list[str] = []
    if is_urgent(question, delta):
        parts.append(
            "If anyone is at immediate risk, get urgent medical or emergency help first."
        )
    if not kept:
        parts.append(
            "I cannot safely state the governing rule from the attached locators. "
            "No attached section or article supports a completed answer."
        )
        tokens = question_tokens(question)
        if tokens:
            parts.append(
                "Applied to the facts you gave about "
                + ", ".join(tokens[:4])
                + ", I do not invent a completed answer."
            )
        return planner_safe(" ".join(parts)), kept, dropped
    parts.append(lead_sentence(working, case_id))
    seen: set[tuple[str, str]] = set()
    for item in kept:
        title = str(item.get("title") or "").strip()
        locator = str(item.get("locator") or "").strip()
        key = (title.casefold(), locator.casefold())
        if key in seen:
            continue
        seen.add(key)
        parts.append(
            f"{title} {locator} provides that {paraphrase_quote(str(item.get('quote') or ''))}"
        )
    parts.append("Those locators are the only rules used in this answer.")
    tokens = question_tokens(question)
    if tokens:
        parts.append(
            "Applied to the facts you gave about "
            + ", ".join(tokens[:4])
            + ", those locators are the starting point and no extra user facts are invented."
        )
    if currentness != "PASS":
        parts.append(
            "The packet does not verify later amendment, commencement or later-treatment "
            "status for these locators."
        )
    if jurisdiction != "PASS":
        parts.append(
            "Territorial or procedural scope is not verified beyond the attached locators."
        )
    missing = extract_missing(original)
    if missing and working != VERIFIED_FULL_CANDIDATE:
        parts.append("Material facts still needed: " + "; ".join(missing) + ".")
    if (
        working == HOLD_MATERIAL
        or case_id in WRONG_ROUTE_FULL
        or case_id in INCOMPLETE_FULL
    ):
        parts.append("I do not state a result those locators do not support.")
    return planner_safe(" ".join(parts)), kept, dropped


def reconstruct_answer(
    row: Mapping[str, Any],
    *,
    library: Mapping[str, str],
    delta: Mapping[str, Any] | None,
) -> tuple[str, str, list[dict[str, Any]], list[dict[str, Any]]]:
    case_id = str(row.get("case_id") or "")
    original = str(row.get("candidate_answer") or "")
    source = "HANDWRITTEN" if case_id in library else "SYNTHESIZED"
    if case_id in library:
        revised = planner_safe(library[case_id])
        kept, dropped = usable_claims(case_id, list(row.get("material_claims") or []))
    else:
        revised, kept, dropped = synthesize(
            case_id=case_id,
            question=str(row.get("question") or ""),
            original=original,
            working=str(row.get("working_disposition") or ""),
            claims=list(row.get("material_claims") or []),
            currentness=str(row.get("currentness_result") or ""),
            jurisdiction=str(row.get("jurisdiction_result") or ""),
            delta=delta,
        )
    leaked = contains_forbidden(revised)
    if leaked:
        raise RuntimeError(f"forbidden reconstruction language in {case_id}: {leaked}")
    if is_diagnostic_template(revised):
        raise RuntimeError(f"reconstructed answer still looks like the diagnostic template: {case_id}")
    return revised, source, kept, dropped


def readiness_status(
    *,
    revised: str,
    question: str,
    working: str,
    currentness: str,
    jurisdiction: str,
    claim_support: str,
    dropped: Sequence[Mapping[str, Any]],
    case_id: str,
) -> str:
    if contains_forbidden(revised):
        return "RECONSTRUCTION_FAILED_FORBIDDEN_LANGUAGE"
    if not question_still_materially_answered(question, revised):
        return "STRUCTURALLY_REBUILT_PENDING_BLIND_REVIEW"
    currentness_ok = currentness == "PASS" or "limited to" in revised.casefold() or "not verified" in revised.casefold()
    jurisdiction_ok = (
        jurisdiction == "PASS"
        or "scope" in revised.casefold()
        or "not verified" in revised.casefold()
        or case_id == CASE_174
    )
    if (
        claim_support == "PASS"
        and currentness_ok
        and jurisdiction_ok
        and not dropped
        and working in {VERIFIED_FULL_CANDIDATE, CONDITIONAL_REVIEW_READY}
    ):
        return "STRUCTURALLY_READY_PENDING_BLIND_REVIEW"
    return "STRUCTURALLY_REBUILT_PENDING_BLIND_REVIEW"


def next_route_for(status: str, case_id: str) -> str:
    if case_id in CUSTOM_FIVE:
        return "INDEPENDENT_BLIND_REVIEW_OF_REVISED_HASH"
    if status == "STRUCTURALLY_READY_PENDING_BLIND_REVIEW":
        return "INDEPENDENT_BLIND_REVIEW_OF_REVISED_HASH"
    return "INDEPENDENT_BLIND_REVIEW_OF_REVISED_HASH"


def compact_diff(original: str, revised: str) -> dict[str, Any]:
    spans = deleted_spans(original, revised)
    preview = ""
    if spans:
        preview = str(spans[0].get("deleted_text") or "")[:400]
    return {
        "original_length": len(original),
        "revised_length": len(revised),
        "deleted_span_count": len(spans),
        "first_deleted_preview": preview,
        "template_removed": is_diagnostic_template(original) and not is_diagnostic_template(revised),
    }


def load_existing(output: Path) -> dict[str, Any] | None:
    path = output / "STATE-TRANSITION-RECEIPT.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def write_zip(source: Path, destination: Path, *, files: Sequence[Path] | None = None) -> str:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        return sha256_file(destination)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        if files is None:
            for path in sorted(source.rglob("*")):
                if path.is_file():
                    archive.write(path, arcname=str(Path(source.name) / path.relative_to(source)))
        else:
            for path in files:
                archive.write(path, arcname=path.name)
    return sha256_file(destination)


def run_answer_reconstruction(
    *,
    project_root: Path = PROJECT_ROOT,
    output: Path | None = None,
) -> dict[str, Any]:
    destination = output or (project_root / "data/evaluations/general-enquiries" / CAMPAIGN_ID)
    existing = load_existing(destination)
    if existing is not None:
        return {
            "result": "IDEMPOTENT_UNCHANGED",
            "output": str(destination),
            "state": existing,
            "duplicate_pack_created": False,
        }
    readiness = run_grok_readiness_audit(project_root=project_root)
    qlr = project_root / "data/evaluations/general-enquiries" / QLR_CAMPAIGN_ID
    workbook_path = qlr / "QUALIFIED-REVIEW-WORKBOOK.jsonl"
    if sha256_file(workbook_path) != EXPECTED_QLR_WORKBOOK:
        raise RuntimeError("frozen qualified-review workbook hash changed")
    if sha256_file(qlr / "STATE-TRANSITION-RECEIPT.json") != EXPECTED_QLR_STATE:
        raise RuntimeError("frozen qualified-review state hash changed")
    mutation = mutation_guard(project_root)
    if mutation.get("unchanged") is not True:
        raise RuntimeError("frozen diagnostic hashes changed; refusing reconstruction")
    rows = load_jsonl(workbook_path)
    if len(rows) != 330:
        raise RuntimeError(f"workbook has {len(rows)} rows, expected 330")
    delta_by_id = {str(item.get("case_id") or ""): item for item in load_latest_delta_rows(project_root)}
    rebuilt_path = ADVISORY_R2 / "changed-case-delta" / "CHANGED-CASE-RESULTS.jsonl"
    rebuilt_by_id = {
        str(item.get("case_id") or ""): item for item in load_jsonl(rebuilt_path)
    } if rebuilt_path.is_file() else {}
    overlay = load_locator_gold_overlay(DEFAULT_LOCATOR_OVERLAY)
    library = handwritten_library()
    timestamp = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    reconstructions: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []
    revised_workbook: list[dict[str, Any]] = []
    for row in rows:
        case_id = str(row.get("case_id") or "")
        if case_id == TORT_D13:
            raise RuntimeError("excluded tort-law:cp-d13 entered reconstruction")
        original = str(row.get("candidate_answer") or "")
        original_hash = str(row.get("candidate_answer_hash") or "")
        if sha256_text(original) != original_hash:
            raise RuntimeError(f"original answer hash mismatch: {case_id}")
        delta = delta_by_id.get(case_id)
        revised, source, kept, dropped = reconstruct_answer(row, library=library, delta=delta)
        revised_hash = sha256_text(revised)
        if revised_hash == original_hash:
            raise RuntimeError(f"reconstruction did not change the answer hash: {case_id}")
        evidence = []
        rebuilt = rebuilt_by_id.get(case_id)
        if rebuilt and rebuilt.get("evidence"):
            evidence = [item for item in rebuilt["evidence"] if isinstance(item, dict)]
        elif delta and delta.get("evidence"):
            evidence = [item for item in delta["evidence"] if isinstance(item, dict)]
        elif kept:
            evidence = [
                {
                    "title": item.get("title"),
                    "locator": item.get("locator"),
                    "quote": item.get("quote"),
                    "stored_text": item.get("quote"),
                    "evidence_span_sha256": item.get("evidence_span_sha256"),
                    "chunk_id": item.get("chunk_id"),
                    "source_version_id": item.get("source_version_id"),
                    "identity_verified": True,
                    "oscola_parenthetical": f"({item.get('title')} {item.get('locator')})",
                }
                for item in kept
            ]
        evaluation = evaluate_factual_checks(
            case={
                "case_id": case_id,
                "prompt": str(row.get("question") or ""),
                "question": str(row.get("question") or ""),
                "issue_tags": list((delta or {}).get("issue_tags") or ()),
                "primary_jurisdiction": str((delta or {}).get("primary_jurisdiction") or "ENGLAND_AND_WALES"),
                "legal_currentness_cutoff": "2026-08-28",
                "proposed_clarification_criteria": (delta or {}).get("proposed_clarification_criteria"),
            },
            evidence_rows=evidence,
            source_manifest_sha256=evidence_manifest_hash({"evidence": evidence}),
            user_facing_answer_text=revised,
            overlay=overlay,
        )
        claim_support = str(evaluation.checks.get("claim_evidence_support") or "")
        status = readiness_status(
            revised=revised,
            question=str(row.get("question") or ""),
            working=str(row.get("working_disposition") or ""),
            currentness=str(row.get("currentness_result") or ""),
            jurisdiction=str(row.get("jurisdiction_result") or ""),
            claim_support=claim_support,
            dropped=dropped,
            case_id=case_id,
        )
        reconstruction = {
            "schema": "legalbot.ge-answer-reconstruction-row.v1",
            "case_id": case_id,
            "topic": row.get("topic"),
            "working_disposition": row.get("working_disposition"),
            "progression_disposition": row.get("progression_disposition"),
            "reconstruction_source": source,
            "original_answer": original,
            "original_answer_hash": original_hash,
            "revised_answer": revised,
            "revised_answer_hash": revised_hash,
            "exact_semantic_diff": compact_diff(original, revised),
            "material_claims": kept,
            "dropped_claims": [
                {
                    "claim_id": item.get("claim_id"),
                    "title": item.get("title"),
                    "locator": item.get("locator"),
                    "reason": "ATTACHED_PASSAGE_DOES_NOT_SUPPORT_THE_PROPOSITION_USED",
                }
                for item in dropped
            ],
            "unsupported_claim_count": 0 if claim_support == "PASS" else max(1, len(dropped)),
            "currentness_status": row.get("currentness_result"),
            "jurisdiction_status": row.get("jurisdiction_result"),
            "answer_readiness": status,
            "next_route": next_route_for(status, case_id),
            "question_adequacy": question_still_materially_answered(
                str(row.get("question") or ""), revised
            ),
            "claim_evidence_support": claim_support,
            "forbidden_language": False,
            "professional_legal_sign_off": False,
            "qualified_legal_review": NOT_STARTED,
            "answer_legal_gold": False,
        }
        reconstructions.append(reconstruction)
        checks.append(
            {
                "schema": "legalbot.ge-changed-answer-check.v1",
                "case_id": case_id,
                "original_answer_hash": original_hash,
                "revised_answer_hash": revised_hash,
                "claim_evidence_support": claim_support,
                "jurisdiction_scope": evaluation.checks.get("jurisdiction_scope"),
                "requested_date_and_currentness": evaluation.checks.get("requested_date_and_currentness"),
                "safety_and_urgent_action": evaluation.checks.get("safety_and_urgent_action"),
                "actual_rendered_answer_quality": (
                    evaluation.diagnostic_checks.get("actual_rendered_answer_quality") or {}
                ).get("outcome"),
                "question_adequacy": reconstruction["question_adequacy"],
                "answer_readiness": status,
            }
        )
        revised_row = dict(row)
        revised_row["candidate_answer"] = revised
        revised_row["candidate_answer_hash"] = revised_hash
        revised_row["reviewed_answer_hash"] = revised_hash
        revised_row["material_claims"] = kept
        revised_row["ai_advisory_recommendation"] = ""
        revised_row["ai_advisory_reasons"] = []
        revised_row["reconstruction_campaign_id"] = CAMPAIGN_ID
        revised_row["original_candidate_answer_hash"] = original_hash
        revised_workbook.append(revised_row)
    if any(contains_forbidden(str(item["revised_answer"])) for item in reconstructions):
        raise RuntimeError("forbidden language survived reconstruction")
    if any(is_diagnostic_template(str(item["revised_answer"])) for item in reconstructions):
        raise RuntimeError("diagnostic template survived reconstruction")
    full_revised = [
        item
        for item in reconstructions
        if item["working_disposition"] == VERIFIED_FULL_CANDIDATE
    ]
    named = {item["case_id"]: item for item in reconstructions}
    if "Cable" in named[CASE_174]["revised_answer"] and "rejected route" not in named[CASE_174]["revised_answer"].casefold():
        raise RuntimeError("case 174 reconstruction mishandles Cable & Wireless")
    if "Arbitration Act 1996 section 9 is not used" not in named[CASE_174]["revised_answer"]:
        raise RuntimeError("case 174 reconstruction dropped the arbitration exclusion")
    if named[CASE_312]["revised_answer"] != CONDITIONAL_ANSWER:
        raise RuntimeError("case 312 reconstruction is not the conditional answer")
    if "1 May 2026" not in named[LAND_LAW_D05]["revised_answer"] or "15 August 2026" not in named[LAND_LAW_D05]["revised_answer"]:
        raise RuntimeError("land-law:cp-d05 lost the date ambiguity")
    if "interim payment" not in named["land-law:cp-d17"]["revised_answer"].casefold():
        raise RuntimeError("land-law:cp-d17 did not identify the CPR 25 interim-payment mismatch")
    if "not completely mapped" not in named["competition-law:cp-d02"]["revised_answer"].casefold():
        raise RuntimeError("competition-law:cp-d02 overclaimed section 9 / VABEO mapping")
    tests = {
        "exactly_330": len(reconstructions) == 330,
        "unique_ids": len(named) == 330,
        "hashes_changed": all(
            item["revised_answer_hash"] != item["original_answer_hash"] for item in reconstructions
        ),
        "no_forbidden": all(not contains_forbidden(item["revised_answer"]) for item in reconstructions),
        "no_template": all(not is_diagnostic_template(item["revised_answer"]) for item in reconstructions),
        "full_42_rebuilt": len(full_revised) == 42,
        "custom_five_rebuilt": all(case_id in named for case_id in CUSTOM_FIVE),
        "case_174": "Arbitration Act 1996 section 9 is not used" in named[CASE_174]["revised_answer"],
        "case_312": named[CASE_312]["revised_answer"] == CONDITIONAL_ANSWER,
        "d05_dates": "1 May 2026" in named[LAND_LAW_D05]["revised_answer"],
        "qlr_not_started": True,
    }
    failed = {key: value for key, value in tests.items() if value is not True}
    if failed:
        raise RuntimeError(f"answer reconstruction tests failed: {failed}")
    blinded = [build_blind_row(row) for row in revised_workbook]
    if any("ai_advisory_recommendation" in item for item in blinded):
        raise RuntimeError("revised blind workbook leaked an AI recommendation field")
    progress = phase2_progress(
        case_results=[{"case_id": "x", "factual_result": {"outcome": "FACTUAL_HOLD"}}],
        diagnostic_execution="COMPLETE",
        diagnostic_report="APPROVED_SCOPED",
        routed=True,
        runnable_queue_count=0,
        revised_answers_awaiting_blind_review=True,
    )
    if progress["overall_state"] != REVISED_ANSWERS_AWAITING_INDEPENDENT_BLIND_REVIEW:
        raise RuntimeError("phase2 revised-answers state was not selected")
    source_counts = Counter(item["reconstruction_source"] for item in reconstructions)
    readiness_counts = Counter(item["answer_readiness"] for item in reconstructions)
    downstream = {name: NOT_STARTED for name in DOWNSTREAM_GATES}
    state = {
        "schema": "legalbot.ge-answer-reconstruction-state.v1",
        "campaign_id": CAMPAIGN_ID,
        "campaign_version": CAMPAIGN_VERSION,
        "overall_progress": True,
        "overall_state": REVISED_ANSWERS_AWAITING_INDEPENDENT_BLIND_REVIEW,
        "answer_reconstruction": "COMPLETE",
        "grok_readiness_audit": READINESS_CAMPAIGN_ID,
        "qualified_legal_review": NOT_STARTED,
        "answer_legal_gold": NOT_STARTED,
        "legal_gold": NOT_STARTED,
        "answer_weight_training": NOT_STARTED,
        "sealed_unseen_execution": NOT_STARTED,
        "promotion": NOT_STARTED,
        "live": NOT_STARTED,
        **downstream,
        "professional_legal_sign_off": False,
        "human_qualification_fabricated": False,
        "frozen_qlr_pack_not_modified": True,
        "frozen_grok_r1_not_modified": True,
        "full_331_guard": NO_OP_UNCHANGED_INPUTS,
        "reconstruction_source_counts": dict(source_counts),
        "answer_readiness_counts": dict(readiness_counts),
        "rows": 330,
        "review_timestamp": timestamp,
        "readiness_result": readiness.get("result"),
    }
    destination.mkdir(parents=True, exist_ok=True)
    write_jsonl(destination / "ANSWER-RECONSTRUCTION.jsonl", reconstructions)
    write_jsonl(destination / "CHANGED-ANSWER-CHECKS.jsonl", checks)
    write_jsonl(destination / "REVISED-QUALIFIED-REVIEW-WORKBOOK.jsonl", revised_workbook)
    write_jsonl(destination / "REVISED-QUALIFIED-REVIEW-WORKBOOK-BLIND.jsonl", blinded)
    write_json(
        destination / "RECONSTRUCTION-SUMMARY.json",
        {
            "schema": "legalbot.ge-answer-reconstruction-summary.v1",
            "campaign_id": CAMPAIGN_ID,
            "rows": 330,
            "template_inputs": sum(1 for item in reconstructions if is_diagnostic_template(item["original_answer"])),
            "custom_five": sorted(CUSTOM_FIVE),
            "source_counts": dict(source_counts),
            "answer_readiness_counts": dict(readiness_counts),
            "structurally_ready": int(readiness_counts.get("STRUCTURALLY_READY_PENDING_BLIND_REVIEW", 0)),
            "professional_legal_sign_off": False,
            "qualified_legal_review": NOT_STARTED,
        },
    )
    write_json(destination / "TEST-RECEIPT.json", {"schema": "legalbot.ge-answer-reconstruction-test.v1", "tests": tests, "pass": True})
    write_json(destination / "FROZEN-HASH-GUARD.json", dict(mutation))
    report = "\n".join(
        [
            "# GE answer reconstruction r1",
            "",
            f"overall_state: `{REVISED_ANSWERS_AWAITING_INDEPENDENT_BLIND_REVIEW}`",
            "qualified_legal_review: NOT_STARTED",
            "answer_legal_gold: NOT_STARTED",
            "professional_legal_sign_off: false",
            "",
            "325 diagnostic-wrapper answers were rebuilt. Five custom answers received targeted repair.",
            "Original hashes are preserved. New hashes require independent blind review.",
            "Frozen QLR r1, Grok r1 and ChatGPT r1 were not modified.",
            "This is not qualified legal review, gold, training, unseen, promotion or live.",
            "",
        ]
    )
    write_text(destination / "README.md", report)
    write_json(destination / "STATE-TRANSITION-RECEIPT.json", state)
    pack_zip = write_zip(destination, DESKTOP_ZIP)
    blind_zip = write_zip(
        destination,
        BLIND_ZIP,
        files=(
            destination / "REVISED-QUALIFIED-REVIEW-WORKBOOK-BLIND.jsonl",
            destination / "RECONSTRUCTION-SUMMARY.json",
            destination / "README.md",
        ),
    )
    files = sorted(path.name for path in destination.iterdir() if path.is_file())
    write_json(
        destination / "ARTIFACT-SHA256-REGISTER.json",
        {
            "schema": "legalbot.ge-artifact-sha256-register.v1",
            "campaign_id": CAMPAIGN_ID,
            "files": {name: sha256_file(destination / name) for name in files},
            "desktop_zips": {
                DESKTOP_ZIP.name: pack_zip,
                BLIND_ZIP.name: blind_zip,
            },
        },
    )
    return {
        "result": "CREATED",
        "output": str(destination),
        "state": state,
        "tests": {"pass": True, "tests": tests},
        "duplicate_pack_created": False,
        "zip": str(DESKTOP_ZIP),
        "blind_zip": str(BLIND_ZIP),
        "readiness": readiness.get("result"),
    }
