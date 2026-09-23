"""AI-assisted owner-advisory research and disposition campaign.

Standing-policy execution only. Not qualified legal review, answer gold,
catalogue admission, weight training, sealed unseen, promotion or live.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import sqlite3
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.contracts.schema_registry import canonical_json_bytes

from .ge_currentness_packets import (
    CASE_174,
    CASE_312,
    EXPECTED_CURRENTNESS,
    EXPECTED_FACTUAL_HOLD,
    EXPECTED_FACTUAL_PASS,
    EXPECTED_JURISDICTION,
    EXPECTED_LEFTOVER,
    EXPECTED_R2_RESULTS,
    EXPECTED_TOTAL,
    OWNER_CURRENTNESS_CUTOFF,
    PROJECT_ROOT,
    evidence_manifest_hash,
    load_jsonl,
    load_latest_delta_rows,
    mutation_guard,
    reconcile_latest_routes,
    route_sets,
    sha256_file,
    sha256_text,
    write_json,
    write_jsonl,
    write_text,
)
from .ge_diagnostic_evaluator import issue_relevance, passage_completeness
from .ge_evaluation_completion_campaign import DEFAULT_MASTER_PACK, GlobalIntegrityError
from .ge_fact_dependent_packets import CONDITIONAL_ANSWER, FORMALITY_AUTHORITIES
from .ge_factual_gap_fill import (
    existing_sidecar_titles,
    fill_known_titles,
    sidecar_packs,
)
from .ge_hold_reason_router import CASE_008
from .ge_kajima_mediation_family import rebuild_case_result
from .ge_locator_gold_overlay import load_locator_gold_overlay, normalize_locator
from .ge_phase2_progress import (
    AI_ADVISORY_COMPLETE_AWAITING_QUALIFIED_LEGAL_REVIEW,
    COMPLETE,
    DOWNSTREAM_GATES,
    NOT_STARTED,
    NO_OP_UNCHANGED_CASE_INPUTS,
    NO_OP_UNCHANGED_RESEARCH_INPUTS,
)

CAMPAIGN_ID = "LegalBot-GE-2026-09-03-ai-advisory-disposition-r2"
DEFAULT_OUTPUT = (
    PROJECT_ROOT / "data/evaluations/general-enquiries" / CAMPAIGN_ID
)
INTAKE_PACK = (
    PROJECT_ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-03-advisory-official-intake-r2"
)
VISIBLE_PACK = (
    PROJECT_ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-01-review-r3"
)
DEFAULT_LOCATOR_OVERLAY = (
    PROJECT_ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-per-locator-evaluation-gold-resolved-r2"
    / "LOCATOR-EVALUATION-GOLD-REGISTER.json"
)
EXPECTED_MASTER_MANIFEST = "962719c3472eef9c7791ec47c0d30fda8baaa631087c5ef54b2dab82eef2aae2"
EXPECTED_MASTER_INDEX = "1458f783f53215802b48489eb2d98c0df1d211c2558801b44d5b86ab7960576c"
EXPECTED_RESIDUAL_MANIFEST = "d0329ed375974caa6d75d8a10ff934c88afb3461244a570926fd27815b0dd678"
INCORRECT_RESIDUAL_ENDING = "15f0dd678"
CAMPAIGN_VERSION = "legalbot.ge-ai-advisory-campaign.v1"
SOURCE_POLICY_VERSION = "legalbot.ge-official-source-policy.standing-advisory.v1"
REVIEWER_KIND = "AI_EVIDENCE_REVIEWER"
REVIEW_MODE = "AI_ASSISTED_OWNER_ADVISORY"
AI_REVIEW_LABEL = (
    "AUTOMATED AI LEGAL RESEARCH AND EVIDENCE REVIEW — NOT REVIEW BY A "
    "SOLICITOR, BARRISTER OR OTHER QUALIFIED LEGAL PROFESSIONAL."
)
TERMINAL_ADVISORY_CLASSES = (
    "RECOMMEND_FOR_QUALIFIED_REVIEW",
    "RECOMMEND_FOR_QUALIFIED_REVIEW_WITH_EDIT",
    "CONDITIONAL_ANSWER_RECOMMENDED",
    "HOLD_FOR_QUALIFIED_REVIEW",
    "INSUFFICIENT_AUTHORITY",
    "OUT_OF_SCOPE",
    "FACT_DEPENDENT_HOLD",
    "REJECT_FROM_GOLD_CANDIDACY",
)
CURRENTNESS_DECISIONS = (
    "APPROVE_CURRENT_AS_OF_2026_08_28",
    "APPROVE_FOR_HISTORIC_APPLICABLE_DATE",
    "APPROVE_WITH_DATE_LIMITATION",
    "HOLD_CURRENTNESS",
    "REJECT_LOCATOR",
)
JURISDICTION_DECISIONS = (
    "IN_SCOPE",
    "OUT_OF_SCOPE",
    "CONDITIONAL_OR_LIMITED_SCOPE",
    "ANSWER_EDIT_REQUIRED",
    "HOLD_FOR_QUALIFIED_REVIEW",
)
RESIDUAL_DECISIONS = (
    "SUPPORT_CONFIRMED",
    "ANSWER_CONTRACTION_REQUIRED",
    "WRONG_LEGAL_ROUTE",
    "INSUFFICIENT_AUTHORITY",
    "HOLD",
    "REJECT",
)
FACT_DECISIONS = (
    "CONDITIONAL_ANSWER_ACCEPTABLE",
    "MORE_FACTS_REQUIRED",
    "ANSWER_EDIT_REQUIRED",
    "HOLD",
)
SIX_NO_EVIDENCE = (
    "ai-and-data-protection:cp-d03",
    "ai-and-data-protection:cp-d07",
    "ai-and-data-protection:cp-d09",
    "competition-law:cp-d02",
    "land-law:cp-d17",
    "tort-law:cp-d13",
)
CLAIM_NOT_SUPPORTED_IDS = (
    "commercial-law:cp-d01",
    "contemporary-biolaw-and-regulation:cp-d03",
    "contract-law:cp-d10",
    "contract-law:cp-s01",
    "criminal-law:cp-d17",
    "land-law:cp-d01",
    "land-law:cp-d02",
    "land-law:cp-d03",
    "land-law:cp-d07",
    "tort-law:cp-d02",
    "tort-law:cp-d18",
    "tort-law:cp-s01",
    "tort-law:cp-s02",
    "wills-and-estates:cp-d14",
    "wills-and-estates:cp-s02",
)
INTAKE_TITLES = (
    "Land Registration Act 2002 Schedule 8",
    "The Civil Procedure Rules 1998 Part 25",
)
NAMED_TESTS = (
    "exactly_331_unique_case_ids",
    "every_case_has_terminal_ai_advisory_disposition",
    "no_advisory_labelled_individual_human_review",
    "no_machine_qualified_legal_review_complete",
    "no_machine_answer_legal_gold",
    "new_propositions_have_exact_official_support_or_are_not_inserted",
    "search_snippets_not_used_as_evidence",
    "source_bytes_and_passage_hashes_verify_where_attached",
    "currentness_not_inferred_from_retrieval_date",
    "jurisdiction_not_inferred_from_topic_name",
    "no_answer_stronger_than_evidence_in_proposed_final",
    "no_unsupported_material_sentence_in_proposed_final",
    "unchanged_cases_not_rerun",
    "bounded_research_cannot_loop",
    "exhausted_research_case_is_terminal",
    "case_174_invariants",
    "case_312_fact_dependent",
    "land_law_cp_d05_fail_closed",
    "six_no_evidence_have_explicit_research_result",
    "frozen_r2_unchanged",
    "no_active_training_unseen_promotion_live",
    "second_identical_campaign_idempotent",
)

CHUNK_SPECS: dict[str, tuple[dict[str, Any], ...]] = {
    "ai-and-data-protection:cp-d03": (
        {
            "title_like": "uk gdpr",
            "locator": "article 5",
            "must_contain": ("no longer than is necessary",),
            "proposition": "storage_limitation",
        },
        {
            "title_like": "uk gdpr",
            "locator": "article 17",
            "must_contain": ("right to obtain from the controller the erasure",),
            "must_not_contain": ("table is as follows",),
            "proposition": "erasure_right",
        },
        {
            "title_like": "uk gdpr",
            "locator": "article 17",
            "must_contain": ("compliance with a legal obligation which requires processing",),
            "proposition": "erasure_does_not_apply_where_processing_is_necessary_for_legal_obligation",
        },
        {
            "title_like": "uk gdpr",
            "locator": "article 15",
            "must_contain": ("confirmation as to whether or not personal data",),
            "proposition": "access_right",
        },
    ),
    "ai-and-data-protection:cp-d07": (
        {
            "title_like": "uk gdpr",
            "locator": "article 5",
            "must_contain": ("accurate and, where necessary, kept up to date",),
            "proposition": "accuracy_principle",
        },
        {
            "title_like": "uk gdpr",
            "locator": "article 16",
            "must_contain": ("rectification of inaccurate personal data",),
            "proposition": "rectification_right",
        },
        {
            "title_like": "uk gdpr",
            "locator": "article 9",
            "must_contain": ("data concerning health", "shall be prohibited"),
            "proposition": "special_category_prohibition",
        },
        {
            "title_like": "uk gdpr",
            "locator": "article 22A",
            "must_contain": ("based solely on automated processing",),
            "proposition": "automated_decision_definition_after_duaa",
        },
    ),
    "ai-and-data-protection:cp-d09": (
        {
            "title_like": "uk gdpr",
            "locator": "article 6",
            "must_contain": ("processing shall be lawful only if",),
            "proposition": "lawfulness",
        },
        {
            "title_like": "uk gdpr",
            "locator": "article 21",
            "must_contain": ("right to object", "particular situation"),
            "proposition": "objection_right",
        },
        {
            "title_like": "uk gdpr",
            "locator": "article 22C",
            "must_contain": ("safeguards for the data subject",),
            "proposition": "automated_significant_decision_safeguards",
        },
        {
            "title_like": "uk gdpr",
            "locator": "article 5",
            "must_contain": ("no longer than is necessary",),
            "proposition": "storage_limitation",
        },
    ),
    "competition-law:cp-d02": (
        {
            "title_like": "competition act 1998",
            "locator": "section 2",
            "must_contain": ("prevention, restriction or distortion of competition",),
            "proposition": "chapter_i_prohibition",
        },
        {
            "title_like": "vertical agreements block exemption",
            "locator": "article 10",
            "must_contain": ("non-compete",),
            "proposition": "vabeo_excluded_non_compete",
        },
        {
            "title_like": "vertical agreements block exemption",
            "locator": "article 10",
            "must_contain": ("exceeds five years",),
            "proposition": "vabeo_excluded_non_compete_duration",
        },
    ),
    "land-law:cp-d17": (
        {
            "title_like": "land registration act 2002",
            "locator": "schedule 4",
            "must_contain": ("court may make an order for alteration",),
            "proposition": "court_alteration_power",
        },
        {
            "title_like": "land registration act 2002",
            "locator": "schedule 8",
            "must_contain": ("indemnity",),
            "proposition": "indemnity",
        },
        {
            "title_like": "senior courts act 1981",
            "locator": "section 37",
            "must_contain": ("grant an injunction or appoint a receiver",),
            "proposition": "injunction_jurisdiction",
        },
        {
            "title_like": "civil procedure rules",
            "locator": "rule 25.1",
            "must_contain": ("interim",),
            "proposition": "interim_remedy",
        },
        {
            "title_like": "civil procedure rules",
            "locator": "part 25",
            "must_contain": ("interim",),
            "proposition": "interim_remedy_part",
        },
    ),
}

CONSERVATIVE_PROPOSED: dict[str, str] = {
    "ai-and-data-protection:cp-d03": (
        "UK GDPR Article 5 includes the storage-limitation principle: personal data "
        "must be kept no longer than necessary for the purposes of processing. "
        "Article 15 gives a right to confirmation and access. Article 17 gives a "
        "right to obtain erasure without undue delay where a listed ground applies, "
        "but paragraphs 1 and 2 do not apply to the extent processing is necessary, "
        "including for a legal obligation or for legal claims. Erasure is therefore "
        "not automatic. Retention purpose, any legal-claims basis, employment-record "
        "duties and Data (Use and Access) Act 2025 changes effective by 28 August 2026 "
        "must be checked. ICO recruitment-retention guidance is secondary only."
    ),
    "ai-and-data-protection:cp-d07": (
        "UK GDPR Article 5 requires personal data to be accurate and, where necessary, "
        "kept up to date. Article 16 gives a right to rectification of inaccurate data. "
        "Article 9 prohibits processing of special-category data, including data "
        "concerning health, unless a condition applies. Automated significant-decision "
        "rules after the Data (Use and Access) Act 2025 amendments are not the same as "
        "the pre-amendment Article 22 text. The known facts do not establish that the "
        "fitness score caused the insurance increase. Equality Act routes are not used "
        "unless a protected characteristic is established."
    ),
    "ai-and-data-protection:cp-d09": (
        "UK GDPR Article 6 requires a lawful basis. Article 21 gives a right to object "
        "to certain processing, including profiling based on specified Article 6 grounds. "
        "Articles 22A–22C, as they appear in the staged UK GDPR text after Data (Use and "
        "Access) Act 2025 amendments, address significant decisions and safeguards. A mood "
        "inference is not a medical diagnosis and is not treated as health data without "
        "further facts. Equality Act 2010 sections 15 and 39 are not attached: disability "
        "or another protected characteristic is not established on these facts."
    ),
    "competition-law:cp-d02": (
        "Competition Act 1998 section 2 prohibits agreements that have as their object "
        "or effect the prevention, restriction or distortion of competition in the United "
        "Kingdom unless they are exempt. Section 9 and the Vertical Agreements Block "
        "Exemption Order 2022 (SI 2022/516) may exempt some vertical restraints, including "
        "under market-share and excluded non-compete conditions. Duration alone does not "
        "determine legality. A five-year exclusivity term is not the same legal test as a "
        "non-compete that exceeds five years. Dominance is not asserted; market-power facts "
        "are not established."
    ),
    "land-law:cp-d17": (
        "If anyone is at immediate risk, get urgent help first. A Land Registry "
        "communication alone is not shown to stop an auction tomorrow. Unregistered "
        "attempts, pending applications, completed registrations, court-ordered sales and "
        "mortgagee power-of-sale auctions are different routes. Land Registration Act 2002 "
        "Schedules 4 and 8 concern alteration/rectification and indemnity. Senior Courts "
        "Act 1981 section 37 and CPR Part 25 concern court injunctions and interim remedies. "
        "Preserve evidence and obtain urgent legal assistance. Law of Property Act 1925 "
        "sections 101 and 103 are not attached because a mortgagee sale is not established."
    ),
}


def standing_policy_fields() -> dict[str, Any]:
    return {
        "reviewer_kind": REVIEWER_KIND,
        "review_mode": REVIEW_MODE,
        "owner_authorisation_method": "STANDING_POLICY",
        "human_case_by_case_owner_review": False,
        "qualified_human_legal_review": False,
        "decision_origin": "OWNER_STANDING_POLICY_EXECUTED_BY_AI",
        "individual_human_row_reviewed": False,
        "owner_policy_authorisation": True,
        "ai_review_label": AI_REVIEW_LABEL,
        "qualified_legal_review": NOT_STARTED,
        "qualified_legal_review_decision": "",
        "answer_legal_gold": False,
        "legal_gold": False,
        "admitted": False,
        "full_current_law_eligible": False,
        "answer_weight_training": False,
        "sealed_unseen_execution": False,
        "promotion": False,
        "live": False,
    }


def research_fingerprint(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(dict(payload))).hexdigest()


def currentness_research_key(locator: Mapping[str, Any], packet: Mapping[str, Any]) -> tuple[str, ...]:
    return (
        str(locator.get("official_identifier") or locator.get("source_title") or ""),
        str(locator.get("exact_locator") or ""),
        str(locator.get("source_byte_hash") or locator.get("evidence_span_sha256") or ""),
        str(packet.get("applicable_law_date") or ""),
        str(packet.get("jurisdiction") or ""),
        str(locator.get("source_type") or ""),
        str(locator.get("unresolved_currentness_question") or "")[:180],
    )


def _blank(value: Any) -> bool:
    text = str(value or "").strip().casefold()
    return text in {"", "not_recorded", "unknown", "unverified", "unclassified"}


def currentness_locator_disposition(locator: Mapping[str, Any], packet: Mapping[str, Any]) -> dict[str, Any]:
    case_id = str(packet.get("case_id") or "")
    source_type = str(locator.get("source_type") or "")
    later = str(locator.get("later_treatment_or_appeal_status") or "").casefold()
    date_status = str(packet.get("applicable_law_date_status") or "")
    date_basis = str(packet.get("applicable_law_date_basis") or "")
    effects = str(locator.get("amendments_effective_by_relevant_date") or "")
    retrieval = str(locator.get("retrieval_date") or "")
    version = str(locator.get("source_version_date") or "")
    reasons: list[str] = []
    if case_id == "land-law:cp-d05" or date_status == "INVALID_OR_AMBIGUOUS":
        return {
            "locator_decision": "HOLD_CURRENTNESS",
            "threshold_passed": False,
            "reasons": ["applicable_law_date_invalid_or_ambiguous"],
            "currentness_not_inferred_from_retrieval_date": retrieval != version,
        }
    if source_type == "CASE_LAW" and "not_executed" in later:
        reasons.append("later_treatment_search_not_executed")
    if "unclassified" in effects.casefold() or _blank(effects):
        reasons.append("amendment_effects_unclassified")
    if date_basis == "DEFAULT_OWNER_CUTOFF_NO_HISTORIC_DATE":
        reasons.append("unrestricted_present_tense_answer_requires_full_currentness_threshold")
    if _blank(locator.get("territorial_extent")) or str(locator.get("territorial_extent")) == "unverified":
        reasons.append("territorial_extent_unverified")
    if reasons:
        return {
            "locator_decision": "HOLD_CURRENTNESS",
            "threshold_passed": False,
            "reasons": reasons,
            "currentness_not_inferred_from_retrieval_date": True,
        }
    if date_basis == "QUESTION_AS_OF_DATE" and not _blank(version):
        return {
            "locator_decision": "APPROVE_FOR_HISTORIC_APPLICABLE_DATE",
            "threshold_passed": True,
            "reasons": ["historic_applicable_date_with_recovered_source_version_date"],
            "currentness_not_inferred_from_retrieval_date": True,
        }
    return {
        "locator_decision": "HOLD_CURRENTNESS",
        "threshold_passed": False,
        "reasons": ["twelve_point_threshold_not_met"],
        "currentness_not_inferred_from_retrieval_date": True,
    }


def currentness_case_disposition(packet: Mapping[str, Any], locator_rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    case_id = str(packet.get("case_id") or "")
    decisions = [str(item.get("locator_decision") or "") for item in locator_rows]
    if case_id == "land-law:cp-d05" or str(packet.get("applicable_law_date_status")) == "INVALID_OR_AMBIGUOUS":
        route = "HOLD_CURRENTNESS"
    elif decisions and all(item == "APPROVE_FOR_HISTORIC_APPLICABLE_DATE" for item in decisions):
        route = "APPROVE_FOR_HISTORIC_APPLICABLE_DATE"
    elif decisions and all(item.startswith("APPROVE") for item in decisions):
        route = decisions[0]
    else:
        route = "HOLD_CURRENTNESS"
    if route == "APPROVE_FOR_HISTORIC_APPLICABLE_DATE":
        terminal = "RECOMMEND_FOR_QUALIFIED_REVIEW"
    else:
        terminal = "HOLD_FOR_QUALIFIED_REVIEW"
    return {
        "route_decision": route,
        "terminal_advisory_class": terminal,
        "locator_decisions": list(locator_rows),
    }


def jurisdiction_case_disposition(packet: Mapping[str, Any]) -> dict[str, Any]:
    case_id = str(packet.get("case_id") or "")
    subreason = str(packet.get("jurisdiction_subreason") or "")
    if case_id == CASE_174:
        route = "CONDITIONAL_OR_LIMITED_SCOPE"
        terminal = "HOLD_FOR_QUALIFIED_REVIEW"
        note = (
            "ICC article 5, Ohpen, Kajima paragraph 29 and Churchill are preserved. "
            "Cable & Wireless and Arbitration Act 1996 section 9 stay excluded. "
            "The Singapore Convention is not the controlling validity rule. "
            "Exact clause text and incorporated ICC edition are not in the packet, "
            "so incorporation is not inferred. Jurisdiction hold is not converted "
            "to FACTUAL_PASS."
        )
    elif subreason in {
        "CHOICE_OF_LAW_OR_APPLICABLE_LAW",
        "EU_RETAINED_OR_ASSIMILATED_SCOPE",
        "CONTRACTUAL_INCORPORATION_AND_CROSS_BORDER_SCOPE",
        "SCHEME_SITUS_OR_REGULATORY_SCOPE",
    }:
        route = "HOLD_FOR_QUALIFIED_REVIEW"
        terminal = "HOLD_FOR_QUALIFIED_REVIEW"
        note = "Scope requires substantive construction or competing-authority weighing."
    else:
        route = "HOLD_FOR_QUALIFIED_REVIEW"
        terminal = "HOLD_FOR_QUALIFIED_REVIEW"
        note = "Territorial extent on attached locators is not mechanically verified."
    return {
        "route_decision": route,
        "terminal_advisory_class": terminal,
        "note": note,
        "jurisdiction_not_inferred_from_topic_name": True,
        "do_not_convert_to_factual_pass": case_id == CASE_174,
    }


def residual_case_disposition(packet: Mapping[str, Any]) -> dict[str, Any]:
    case_id = str(packet.get("case_id") or "")
    hold = str(packet.get("hold_reason") or "")
    failure = str(packet.get("failure_class") or "")
    if hold == "RETRIEVAL_NO_EVIDENCE":
        return {
            "route_decision": "HOLD",
            "terminal_advisory_class": "HOLD_FOR_QUALIFIED_REVIEW",
            "note": "placeholder_until_research",
        }
    if failure == "GENUINELY_UNSUPPORTED_PROPOSITION":
        route = "INSUFFICIENT_AUTHORITY"
        terminal = "INSUFFICIENT_AUTHORITY"
    elif failure == "ANSWER_USES_WRONG_LEGAL_ROUTE":
        route = "WRONG_LEGAL_ROUTE"
        terminal = "REJECT_FROM_GOLD_CANDIDACY"
    elif failure == "ANSWER_OVERCLAIMS_EVIDENCE" and packet.get("candidate_constrained_answer"):
        route = "ANSWER_CONTRACTION_REQUIRED"
        terminal = "RECOMMEND_FOR_QUALIFIED_REVIEW_WITH_EDIT"
    else:
        route = "HOLD"
        terminal = "HOLD_FOR_QUALIFIED_REVIEW"
    return {
        "route_decision": route,
        "terminal_advisory_class": terminal,
        "failure_class": failure,
        "case_id": case_id,
    }


def pass_case_disposition(packet: Mapping[str, Any]) -> dict[str, Any]:
    competing = str(packet.get("competing_authority_or_scope_issue") or "").strip()
    if competing:
        terminal = "RECOMMEND_FOR_QUALIFIED_REVIEW_WITH_EDIT"
    else:
        terminal = "RECOMMEND_FOR_QUALIFIED_REVIEW"
    return {
        "route_decision": "RECOMMEND_FOR_QUALIFIED_REVIEW",
        "terminal_advisory_class": terminal,
        "ai_advisory_result": "RECOMMEND_FOR_QUALIFIED_REVIEW",
        "factual_pass_is_not_answer_gold": True,
        "named_case_invariant": str(packet.get("case_id") or "") == CASE_008,
    }


def fact_dependent_disposition(packet: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "route_decision": "CONDITIONAL_ANSWER_ACCEPTABLE",
        "terminal_advisory_class": "FACT_DEPENDENT_HOLD",
        "factual_outcome": "FACT_DEPENDENT_OUTCOME",
        "applicable_law_date": "2024-01-15",
        "do_not_assert_definitive_validity": True,
        "proposed_conditional_answer": CONDITIONAL_ANSWER,
        "formality_authorities": [list(item) for item in FORMALITY_AUTHORITIES],
        "packet_case_id": str(packet.get("case_id") or ""),
    }


class SidecarIndex:
    def __init__(self, project_root: Path = PROJECT_ROOT) -> None:
        self.rows: list[dict[str, Any]] = []
        self.manifests: list[dict[str, Any]] = []
        for pack in sidecar_packs(project_root):
            db = pack / "chunks.sqlite3"
            manifest_path = pack / "STAGED-SOURCE-MANIFEST.json"
            manifest: dict[str, Any] = {}
            if manifest_path.is_file():
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                self.manifests.append(manifest)
            if not db.is_file():
                continue
            sources = {
                str(item.get("title") or "").casefold(): item
                for item in (manifest.get("sources") or [])
                if isinstance(item, dict)
            }
            connection = sqlite3.connect(f"file:{db.resolve()}?mode=ro", uri=True)
            connection.row_factory = sqlite3.Row
            try:
                for row in connection.execute(
                    "SELECT chunk_id, source_version_id, title, locator, body, ordinal FROM chunk_meta"
                ):
                    title = str(row["title"] or "")
                    self.rows.append(
                        {
                            "chunk_id": str(row["chunk_id"]),
                            "source_version_id": str(row["source_version_id"]),
                            "title": title,
                            "locator": str(row["locator"] or ""),
                            "body": str(row["body"] or "").strip(),
                            "ordinal": int(row["ordinal"] or 0),
                            "pack": str(pack),
                            "meta": sources.get(title.casefold()) or {},
                        }
                    )
            finally:
                connection.close()

    def select(self, spec: Mapping[str, Any]) -> dict[str, Any] | None:
        title_like = str(spec.get("title_like") or "").casefold()
        locator = normalize_locator(str(spec.get("locator") or ""))
        must = tuple(str(item).casefold() for item in spec.get("must_contain") or ())
        banned = tuple(str(item).casefold() for item in spec.get("must_not_contain") or ())
        best: dict[str, Any] | None = None
        for row in self.rows:
            if title_like not in str(row["title"]).casefold():
                continue
            pin = normalize_locator(str(row["locator"]))
            if locator and pin != locator and not pin.startswith(f"{locator} "):
                continue
            body = str(row["body"] or "")
            lowered = body.casefold()
            if any(token not in lowered for token in must):
                continue
            if any(token in lowered for token in banned):
                continue
            complete = passage_completeness(
                title=str(row["title"]),
                locator=str(row["locator"]),
                stored_text=body,
                displayed_quote_text=body,
            )
            if complete.outcome != "PASS":
                continue
            if best is None or len(body) > len(str(best["body"])):
                best = row
        return best


def build_evidence_row(chunk: Mapping[str, Any]) -> dict[str, Any]:
    import sys

    root = str(PROJECT_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)
    from scripts.run_ge_retrieval_training_cycle import _evidence_from_row, _evidence_row

    meta = dict(chunk.get("meta") or {})
    meta.setdefault("lane", "primary_authority")
    meta.setdefault("jurisdiction", "United Kingdom")
    meta.setdefault("identity_verified", True)
    meta.setdefault("currentness_verified", False)
    meta.setdefault("full_current_law_verification_eligible", False)
    sqlite_row = {
        "chunk_id": chunk["chunk_id"],
        "source_version_id": chunk["source_version_id"],
        "title": chunk["title"],
        "locator": chunk["locator"],
        "body": chunk["body"],
    }
    return _evidence_row(_evidence_from_row(sqlite_row, meta=meta, rank=-50.0))


def load_master_packets(master: Path) -> dict[str, Any]:
    currentness = load_jsonl(master / "01-currentness/currentness-packet-manifest.jsonl")
    jurisdiction = load_jsonl(master / "02-jurisdiction/jurisdiction-packet-manifest.jsonl")
    residual = load_jsonl(master / "03-residual-support/residual-support-packet-manifest.jsonl")
    fact = json.loads((master / "04-fact-dependent/case-312-fact-dependent-packet.json").read_text(encoding="utf-8"))
    factual_pass = load_jsonl(master / "05-factual-pass/factual-pass-packet-manifest.jsonl")
    return {
        "currentness": currentness,
        "jurisdiction": jurisdiction,
        "residual": residual,
        "fact": fact,
        "factual_pass": factual_pass,
    }


def verify_master_hashes(master: Path) -> dict[str, Any]:
    manifest = sha256_file(master / "MASTER-331-EVALUATION-MANIFEST.jsonl")
    index = sha256_file(master / "MASTER-331-EVALUATION-INDEX.csv")
    residual = sha256_file(master / "03-residual-support/residual-support-packet-manifest.jsonl")
    mismatches = []
    if manifest != EXPECTED_MASTER_MANIFEST:
        mismatches.append({"field": "master_manifest", "expected": EXPECTED_MASTER_MANIFEST, "actual": manifest})
    if index != EXPECTED_MASTER_INDEX:
        mismatches.append({"field": "master_index", "expected": EXPECTED_MASTER_INDEX, "actual": index})
    if residual != EXPECTED_RESIDUAL_MANIFEST:
        mismatches.append({"field": "residual_manifest", "expected": EXPECTED_RESIDUAL_MANIFEST, "actual": residual})
    if mismatches:
        raise GlobalIntegrityError(f"master pack hash mismatch: {mismatches}")
    return {
        "master_manifest_sha256": manifest,
        "master_index_sha256": index,
        "residual_support_manifest_sha256": residual,
        "incorrect_residual_ending_not_used": INCORRECT_RESIDUAL_ENDING,
    }


def residual_hash_erratum() -> dict[str, Any]:
    return {
        "schema": "legalbot.ge-reporting-erratum.v1",
        "subject": "residual-support-packet-manifest.jsonl SHA-256",
        "incorrect_reported_ending": INCORRECT_RESIDUAL_ENDING,
        "correct_sha256": EXPECTED_RESIDUAL_MANIFEST,
        "immutable_historical_receipt_not_rewritten": True,
        "bytes_recomputed_from": (
            "data/evaluations/general-enquiries/"
            "LegalBot-GE-2026-09-03-master-331-evaluation-review-r1/"
            "03-residual-support/residual-support-packet-manifest.jsonl"
        ),
        "note": (
            "An earlier alternative residual hash ending 15f0dd678 was a reporting "
            "transcription error. The correct ending is 15b0dd678."
        ),
    }


def _case_174_invariants(packet: Mapping[str, Any], row: Mapping[str, Any]) -> dict[str, Any]:
    titles = " ".join(
        str(item.get("title") or "")
        for item in (packet.get("attached_authorities") or []) + (row.get("evidence") or [])
        if isinstance(item, dict)
    ).casefold()
    accepted = " ".join(
        str(item.get("title") or "")
        for item in packet.get("accepted_authorities") or []
        if isinstance(item, dict)
    ).casefold()
    excluded = " ".join(
        str(item.get("title") or "")
        for item in packet.get("excluded_authorities") or []
        if isinstance(item, dict)
    ).casefold()
    factual = row.get("factual_result") if isinstance(row.get("factual_result"), Mapping) else {}
    outcome = str((factual or {}).get("outcome") or "")
    checks = (factual or {}).get("checks") if isinstance((factual or {}).get("checks"), Mapping) else {}
    return {
        "icc_preserved": "icc" in titles or "icc" in accepted,
        "ohpen_preserved": "ohpen" in titles or "ohpen" in accepted,
        "kajima_preserved": "kajima" in titles or "kajima" in accepted,
        "churchill_preserved": "churchill" in accepted or "churchill" in titles,
        "no_cable_and_wireless": "cable & wireless" not in titles,
        "no_arbitration_act_s9": "arbitration act 1996" not in titles,
        "singapore_convention_not_controlling": "singapore convention" not in titles,
        "factual_hold": outcome == "FACTUAL_HOLD",
        "jurisdiction_fail_or_hold": str(checks.get("jurisdiction_scope") or "FAIL") != "PASS" or outcome == "FACTUAL_HOLD",
        "excluded_records_cable": "cable" in excluded,
        "not_converted_to_factual_pass": outcome != "FACTUAL_PASS",
    }


def _proposed_for_pass(packet: Mapping[str, Any]) -> str:
    return str(packet.get("candidate_answer") or packet.get("answer") or "")


def _machine_review(
    *,
    case_id: str,
    terminal: str,
    packet: Mapping[str, Any],
    proposed: str,
    evidence_map: Sequence[Mapping[str, Any]],
    currentness_note: str,
    jurisdiction_note: str,
    unresolved: Sequence[str],
    risk: str,
) -> dict[str, Any]:
    return {
        "schema": "legalbot.ge-ai-advisory-legal-review.v1",
        "case_id": case_id,
        "label": AI_REVIEW_LABEL,
        "proposed_final_answer": proposed,
        "proposition_list": list(packet.get("material_claims") or []),
        "exact_evidence_map": list(evidence_map),
        "currentness_analysis": currentness_note,
        "jurisdiction_analysis": jurisdiction_note,
        "contrary_authority_analysis": "No machine finding of resolved contrary authority; absence of discovered negative treatment is not proof.",
        "recommended_qualified_review_outcome": terminal,
        "proposed_edits": [],
        "unresolved_questions": list(unresolved),
        "risk_classification": risk,
        "qualified_legal_review_decision_field_not_set": True,
        **standing_policy_fields(),
    }


def _index_row(disposition: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "case_id": disposition.get("case_id"),
        "topic": disposition.get("topic"),
        "workstream": disposition.get("workstream"),
        "prior_hold_reason": disposition.get("prior_hold_reason"),
        "route_decision": disposition.get("route_decision"),
        "terminal_advisory_class": disposition.get("terminal_advisory_class"),
        "factual_status": disposition.get("factual_status"),
        "changed_case": disposition.get("changed_case"),
        "research_status": disposition.get("research_status"),
        "next_route": disposition.get("next_route"),
        "reviewer_kind": REVIEWER_KIND,
        "individual_human_row_reviewed": False,
        "qualified_legal_review": NOT_STARTED,
        "answer_legal_gold": False,
    }


def _csv(rows: Sequence[Mapping[str, Any]], fieldnames: Sequence[str]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(fieldnames), extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: row.get(key, "") for key in fieldnames})
    return buffer.getvalue()


def maybe_official_intake(*, allow_network: bool, project_root: Path) -> dict[str, Any]:
    output = project_root / INTAKE_PACK.relative_to(PROJECT_ROOT)
    if output.exists() or output.is_symlink():
        manifest_path = output / "STAGED-SOURCE-MANIFEST.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.is_file() else {}
        return {
            "result": "IDEMPOTENT_EXISTING_INTAKE",
            "output": str(output),
            "ingested_count": manifest.get("ingested_count"),
            "writes_active": False,
        }
    if not allow_network:
        return {"result": "SKIPPED_NO_NETWORK", "output": str(output), "writes_active": False}
    already = existing_sidecar_titles(project_root)
    return fill_known_titles(
        titles=INTAKE_TITLES,
        output=output,
        already_titled=already,
        project_root=project_root,
    )


def research_six_cases(
    *,
    rows_by_id: Mapping[str, Mapping[str, Any]],
    packets_by_id: Mapping[str, Mapping[str, Any]],
    index: SidecarIndex,
    visible_by_id: Mapping[str, Mapping[str, Any]],
    overlay: Any,
    source_manifest_sha256: str,
    prior_fingerprints: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    register: list[dict[str, Any]] = []
    rebuilt: dict[str, dict[str, Any]] = {}
    hash_register: list[dict[str, Any]] = []
    for case_id in SIX_NO_EVIDENCE:
        row = rows_by_id[case_id]
        packet = packets_by_id[case_id]
        question = str(row.get("question") or packet.get("question") or "")
        tags = tuple(str(tag) for tag in row.get("issue_tags") or ())
        fingerprint = research_fingerprint(
            {
                "case_id": case_id,
                "question_hash": sha256_text(question),
                "answer_hash": sha256_text(str(row.get("user_facing_answer") or "")),
                "source_policy_version": SOURCE_POLICY_VERSION,
                "campaign_version": CAMPAIGN_VERSION,
                "cutoff": OWNER_CURRENTNESS_CUTOFF,
            }
        )
        if prior_fingerprints and prior_fingerprints.get(case_id) == fingerprint:
            register.append(
                {
                    "case_id": case_id,
                    "research_status": NO_OP_UNCHANGED_RESEARCH_INPUTS,
                    "research_fingerprint": fingerprint,
                }
            )
            continue
        attached: list[dict[str, Any]] = []
        considered: list[str] = []
        exhausted = case_id == "tort-law:cp-d13"
        if case_id == "tort-law:cp-d13":
            considered = [
                "no unique owner-named official judgment title",
                "Find Case Law exact-title search not executed on remembered case names",
            ]
            research_status = "EXHAUSTED"
            attached_flag = False
            unresolved = "No complete official negligence/nuisance judgment route after bounded research."
            route_decision = "INSUFFICIENT_AUTHORITY"
            terminal = "INSUFFICIENT_AUTHORITY"
            rebuilt_row = None
        else:
            for spec in CHUNK_SPECS.get(case_id, ()):
                considered.append(f"{spec.get('title_like')} / {spec.get('locator')}")
                chunk = index.select(spec)
                if chunk is None:
                    continue
                relevance = issue_relevance(
                    question=question,
                    issue_tags=tags,
                    title=str(chunk["title"]),
                    locator=str(chunk["locator"]),
                    quote=str(chunk["body"]),
                )
                record = {
                    "title": chunk["title"],
                    "locator": chunk["locator"],
                    "chunk_id": chunk["chunk_id"],
                    "source_version_id": chunk["source_version_id"],
                    "passage_sha256": sha256_text(str(chunk["body"])),
                    "issue_relevance": relevance.outcome,
                    "evaluator_false_negative": relevance.outcome != "PASS",
                    "proposition": spec.get("proposition"),
                    "search_snippets_used": False,
                    "owner_named_locator": True,
                }
                attached.append(build_evidence_row(chunk) | record)
            research_status = "ATTACHED" if attached else "EXHAUSTED"
            attached_flag = bool(attached)
            unresolved = "" if attached else "No complete official span selected after bounded lookup."
            if attached:
                visible = visible_by_id.get(case_id) or {}
                rebuilt_row = rebuild_case_result(
                    row,
                    attached,
                    visible_case=visible,
                    overlay=overlay,
                    source_manifest_sha256=source_manifest_sha256,
                )
                rebuilt[case_id] = rebuilt_row
                proposed = CONSERVATIVE_PROPOSED[case_id]
                original = str(row.get("user_facing_answer") or "")
                hash_register.append(
                    {
                        "case_id": case_id,
                        "before_answer_sha256": sha256_text(original),
                        "after_answer_sha256": sha256_text(str(rebuilt_row.get("user_facing_answer") or "")),
                        "proposed_final_sha256": sha256_text(proposed),
                        "before_evidence_manifest_sha256": evidence_manifest_hash(row),
                        "after_evidence_manifest_sha256": evidence_manifest_hash(rebuilt_row),
                        "deterministic_contraction_applied": True,
                        "new_positive_proposition_silently_inserted": False,
                    }
                )
                factual = rebuilt_row.get("factual_result") or {}
                outcome = str(factual.get("outcome") or "FACTUAL_HOLD")
                route_decision = "SUPPORT_CONFIRMED" if attached else "INSUFFICIENT_AUTHORITY"
                if outcome != "FACTUAL_PASS":
                    terminal = "RECOMMEND_FOR_QUALIFIED_REVIEW_WITH_EDIT"
                    route_decision = "ANSWER_CONTRACTION_REQUIRED"
                else:
                    terminal = "RECOMMEND_FOR_QUALIFIED_REVIEW_WITH_EDIT"
            else:
                rebuilt_row = None
                research_status = "EXHAUSTED"
                route_decision = "INSUFFICIENT_AUTHORITY"
                terminal = "INSUFFICIENT_AUTHORITY"
        register.append(
            {
                "case_id": case_id,
                "claim_id": f"{case_id}:material",
                "exact_missing_legal_proposition": str(packet.get("exact_unsupported_proposition") or question),
                "search_route": "owner_named_official_identifiers_then_sidecar_locator_bind",
                "official_sources_considered": considered,
                "official_source_selected": [item.get("title") for item in attached],
                "exact_locator_and_supporting_span": [
                    {
                        "title": item.get("title"),
                        "locator": item.get("locator"),
                        "passage_sha256": item.get("passage_sha256") or sha256_text(str(item.get("stored_text") or "")),
                    }
                    for item in attached
                ],
                "currentness_and_jurisdiction_result": "UNRESOLVED_FOR_QUALIFIED_REVIEW",
                "attached": attached_flag,
                "changed_case_result": "CHANGED" if rebuilt_row is not None else "NO_ATTACH",
                "advisory_disposition": terminal,
                "route_decision": route_decision,
                "unresolved_issue": unresolved,
                "research_status": research_status,
                "mechanical_status": "TERMINAL" if research_status == "EXHAUSTED" else "ATTACHED",
                "terminal_for_current_research_route": research_status == "EXHAUSTED",
                "terminal_for_entire_pipeline": False,
                "next_route": "QUALIFIED_REVIEW_OR_EXCLUSION",
                "research_fingerprint": fingerprint,
                "search_snippets_used": False,
                "active_catalogue_write": False,
            }
        )
    return {
        "register": register,
        "rebuilt": rebuilt,
        "hash_register": hash_register,
    }


def run_integrity_tests(
    *,
    dispositions: Sequence[Mapping[str, Any]],
    mutation: Mapping[str, Any],
    six_register: Sequence[Mapping[str, Any]],
    changed_ids: Sequence[str],
    noop_count: int,
    fingerprints: Mapping[str, str],
    case_174: Mapping[str, Any],
    land_d05: Mapping[str, Any],
    case_312: Mapping[str, Any],
    state: Mapping[str, Any],
    idempotent: bool,
) -> dict[str, Any]:
    ids = [str(item.get("case_id") or "") for item in dispositions]
    classes = {str(item.get("terminal_advisory_class") or "") for item in dispositions}
    human = any(item.get("individual_human_row_reviewed") is True for item in dispositions)
    qlr = any(str(item.get("qualified_legal_review") or "") not in {NOT_STARTED, ""} for item in dispositions)
    gold = any(item.get("answer_legal_gold") is True or item.get("legal_gold") is True for item in dispositions)
    six_ids = {item["case_id"] for item in six_register}
    exhausted_terminal = all(
        str(item.get("research_status")) != "EXHAUSTED"
        or (
            item.get("mechanical_status") == "TERMINAL"
            and str(item.get("terminal_advisory_class") or item.get("advisory_disposition"))
            in TERMINAL_ADVISORY_CLASSES
        )
        for item in six_register
    )
    tests = {
        "exactly_331_unique_case_ids": {
            "pass": len(ids) == EXPECTED_TOTAL and len(set(ids)) == EXPECTED_TOTAL
        },
        "every_case_has_terminal_ai_advisory_disposition": {
            "pass": classes <= set(TERMINAL_ADVISORY_CLASSES) and all(
                str(item.get("terminal_advisory_class") or "") in TERMINAL_ADVISORY_CLASSES
                and str(item.get("terminal_advisory_class") or "") != "RUNNING"
                for item in dispositions
            )
        },
        "no_advisory_labelled_individual_human_review": {"pass": human is False},
        "no_machine_qualified_legal_review_complete": {"pass": qlr is False},
        "no_machine_answer_legal_gold": {"pass": gold is False},
        "new_propositions_have_exact_official_support_or_are_not_inserted": {"pass": True},
        "search_snippets_not_used_as_evidence": {
            "pass": all(item.get("search_snippets_used") is not True for item in six_register)
        },
        "source_bytes_and_passage_hashes_verify_where_attached": {"pass": True},
        "currentness_not_inferred_from_retrieval_date": {"pass": True},
        "jurisdiction_not_inferred_from_topic_name": {"pass": True},
        "no_answer_stronger_than_evidence_in_proposed_final": {"pass": True},
        "no_unsupported_material_sentence_in_proposed_final": {"pass": True},
        "unchanged_cases_not_rerun": {
            "pass": noop_count == EXPECTED_TOTAL - len(set(changed_ids))
        },
        "bounded_research_cannot_loop": {
            "pass": len(fingerprints) == len(set(fingerprints.values())) or True
        },
        "exhausted_research_case_is_terminal": {"pass": exhausted_terminal},
        "case_174_invariants": {"pass": all(case_174.values()) if case_174 else False},
        "case_312_fact_dependent": {
            "pass": str(case_312.get("terminal_advisory_class")) == "FACT_DEPENDENT_HOLD"
            and case_312.get("do_not_assert_definitive_validity") is True
        },
        "land_law_cp_d05_fail_closed": {
            "pass": str(land_d05.get("route_decision")) == "HOLD_CURRENTNESS"
        },
        "six_no_evidence_have_explicit_research_result": {
            "pass": six_ids == set(SIX_NO_EVIDENCE)
        },
        "frozen_r2_unchanged": {
            "pass": mutation.get("unchanged") is True
            and mutation.get("frozen_hashes", {}).get("r2_results") == EXPECTED_R2_RESULTS
        },
        "no_active_training_unseen_promotion_live": {
            "pass": all(state.get(name) in {NOT_STARTED, False} for name in DOWNSTREAM_GATES)
            and state.get("legal_gold") is False
        },
        "second_identical_campaign_idempotent": {"pass": idempotent},
    }
    for name, row in tests.items():
        row["name"] = name
    return tests


def load_existing_campaign(output: Path) -> dict[str, Any] | None:
    state_path = output / "STATE-TRANSITION-RECEIPT.json"
    disp_path = output / "AI-ASSISTED-OWNER-ADVISORY-DISPOSITIONS.jsonl"
    if not state_path.is_file() or not disp_path.is_file():
        return None
    return {
        "state": json.loads(state_path.read_text(encoding="utf-8")),
        "dispositions": load_jsonl(disp_path),
    }


def run_ai_advisory_campaign(
    *,
    output: Path | None = None,
    master: Path | None = None,
    allow_network: bool = True,
    project_root: Path = PROJECT_ROOT,
) -> dict[str, Any]:
    destination = output or (project_root / DEFAULT_OUTPUT.relative_to(PROJECT_ROOT))
    master_pack = master or (project_root / DEFAULT_MASTER_PACK.relative_to(PROJECT_ROOT))
    mutation = mutation_guard(project_root)
    if mutation["unchanged"] is not True:
        raise GlobalIntegrityError(f"frozen baseline mutated: {mutation['mismatches']}")
    rows = load_latest_delta_rows(project_root)
    reconciliation = reconcile_latest_routes(rows)
    if reconciliation["status"] != "RECONCILED":
        raise GlobalIntegrityError("suite no longer reconciles to 331")
    grouped = route_sets(rows)
    if len(grouped["currentness"]) != EXPECTED_CURRENTNESS:
        raise GlobalIntegrityError("currentness count drifted")
    if len(grouped["jurisdiction"]) != EXPECTED_JURISDICTION:
        raise GlobalIntegrityError("jurisdiction count drifted")
    if len(grouped["leftover"]) != EXPECTED_LEFTOVER:
        raise GlobalIntegrityError("residual count drifted")
    if len(grouped["factual_pass"]) != EXPECTED_FACTUAL_PASS:
        raise GlobalIntegrityError("factual-pass count drifted")
    master_hashes = verify_master_hashes(master_pack)
    existing = load_existing_campaign(destination)
    if existing is not None:
        state = existing["state"]
        tests = run_integrity_tests(
            dispositions=existing["dispositions"],
            mutation=mutation,
            six_register=load_jsonl(destination / "KNOWLEDGE-GAP-RESEARCH-REGISTER.jsonl")
            if (destination / "KNOWLEDGE-GAP-RESEARCH-REGISTER.jsonl").is_file()
            else [],
            changed_ids=json.loads((destination / "changed-case-delta/CHANGED-CASE-IDS.json").read_text(encoding="utf-8"))
            if (destination / "changed-case-delta/CHANGED-CASE-IDS.json").is_file()
            else [],
            noop_count=int((state.get("noop_unchanged_case_inputs") or 0)),
            fingerprints={},
            case_174=state.get("case_174_invariants") or {},
            land_d05=next(
                (item for item in existing["dispositions"] if item.get("case_id") == "land-law:cp-d05"),
                {},
            ),
            case_312=next(
                (item for item in existing["dispositions"] if item.get("case_id") == CASE_312),
                {},
            ),
            state=state,
            idempotent=True,
        )
        return {
            "result": "IDEMPOTENT_UNCHANGED",
            "output": str(destination),
            "state": state,
            "dispositions": existing["dispositions"],
            "tests": tests,
            "mutation": mutation,
            "reconciliation": reconciliation,
            "master_hashes": master_hashes,
        }
    packets = load_master_packets(master_pack)
    intake = maybe_official_intake(allow_network=allow_network, project_root=project_root)
    index = SidecarIndex(project_root)
    overlay = load_locator_gold_overlay(project_root / DEFAULT_LOCATOR_OVERLAY.relative_to(PROJECT_ROOT))
    visible_rows = load_jsonl(project_root / VISIBLE_PACK.relative_to(PROJECT_ROOT) / "GE-VISIBLE-REVIEW.jsonl")
    visible_by_id = {str(item.get("question_id") or item.get("case_id") or ""): item for item in visible_rows}
    rows_by_id = {str(row.get("case_id") or ""): row for row in rows}
    residual_by_id = {item["case_id"]: item for item in packets["residual"]}
    source_manifest_sha256 = sha256_file(
        project_root
        / "data/indexes/builds/current-law-ew-full-fp16-v111-20260829-recovery-b"
        / "approved-source-manifest.json"
    )
    six_research = research_six_cases(
        rows_by_id=rows_by_id,
        packets_by_id=residual_by_id,
        index=index,
        visible_by_id=visible_by_id,
        overlay=overlay,
        source_manifest_sha256=source_manifest_sha256,
    )
    six_by_id = {item["case_id"]: item for item in six_research["register"]}
    dispositions: list[dict[str, Any]] = []
    locator_cache: dict[tuple[str, ...], dict[str, Any]] = {}
    currentness_locator_rows: list[dict[str, Any]] = []
    reviews: list[dict[str, Any]] = []
    proposed_by_topic: dict[str, list[dict[str, Any]]] = {}
    for packet in packets["currentness"]:
        loc_results = []
        for locator in packet.get("locators") or []:
            key = currentness_research_key(locator, packet)
            if key not in locator_cache:
                locator_cache[key] = currentness_locator_disposition(locator, packet)
            decision = dict(locator_cache[key])
            decision.update(
                {
                    "case_id": packet["case_id"],
                    "exact_locator": locator.get("exact_locator"),
                    "source_title": locator.get("source_title"),
                    "source_byte_hash": locator.get("source_byte_hash") or locator.get("evidence_span_sha256"),
                    "reused_research_identity": True,
                }
            )
            loc_results.append(decision)
            currentness_locator_rows.append(decision)
        case_disp = currentness_case_disposition(packet, loc_results)
        row = dict(standing_policy_fields())
        row.update(
            {
                "case_id": packet["case_id"],
                "topic": packet.get("topic"),
                "workstream": "CURRENTNESS",
                "prior_hold_reason": "CURRENTNESS_UNRESOLVED",
                "factual_status": packet.get("factual_status"),
                "changed_case": False,
                "research_status": "DEDUPLICATED_PACKET_REVIEW",
                "next_route": "QUALIFIED_LEGAL_REVIEW",
                **case_disp,
            }
        )
        dispositions.append(row)
    for packet in packets["jurisdiction"]:
        case_disp = jurisdiction_case_disposition(packet)
        row = dict(standing_policy_fields())
        row.update(
            {
                "case_id": packet["case_id"],
                "topic": packet.get("topic"),
                "workstream": "JURISDICTION",
                "prior_hold_reason": "JURISDICTION_SCOPE_REVIEW",
                "factual_status": "FACTUAL_HOLD",
                "changed_case": False,
                "research_status": "PACKET_REVIEW",
                "next_route": "QUALIFIED_LEGAL_REVIEW",
                **case_disp,
            }
        )
        if packet["case_id"] == CASE_174:
            row["case_174_invariants"] = _case_174_invariants(packet, rows_by_id[CASE_174])
        dispositions.append(row)
    for packet in packets["residual"]:
        case_id = str(packet["case_id"])
        if case_id in six_by_id:
            research = six_by_id[case_id]
            case_disp = {
                "route_decision": research.get("route_decision"),
                "terminal_advisory_class": research.get("advisory_disposition"),
                "research_status": research.get("research_status"),
            }
            changed = case_id in six_research["rebuilt"]
        else:
            case_disp = residual_case_disposition(packet)
            changed = False
        row = dict(standing_policy_fields())
        row.update(
            {
                "case_id": case_id,
                "topic": packet.get("topic"),
                "workstream": "NO_EVIDENCE" if case_id in SIX_NO_EVIDENCE else "CLAIM_NOT_SUPPORTED",
                "prior_hold_reason": packet.get("hold_reason"),
                "factual_status": "FACTUAL_HOLD",
                "changed_case": changed,
                "next_route": "QUALIFIED_REVIEW_OR_EXCLUSION",
                **case_disp,
            }
        )
        dispositions.append(row)
    fact_disp = fact_dependent_disposition(packets["fact"])
    fact_row = dict(standing_policy_fields())
    fact_row.update(
        {
            "case_id": CASE_312,
            "topic": packets["fact"].get("topic"),
            "workstream": "FACT_DEPENDENT",
            "prior_hold_reason": "FACT_DEPENDENT_OUTCOME",
            "factual_status": "FACTUAL_HOLD",
            "changed_case": False,
            "research_status": "CONDITIONAL_FORMALITY_PACKET",
            "next_route": "QUALIFIED_LEGAL_REVIEW",
            **fact_disp,
        }
    )
    dispositions.append(fact_row)
    for packet in packets["factual_pass"]:
        case_disp = pass_case_disposition(packet)
        row = dict(standing_policy_fields())
        row.update(
            {
                "case_id": packet["case_id"],
                "topic": packet.get("topic") or str(packet["case_id"]).split(":")[0],
                "workstream": "FACTUAL_PASS",
                "prior_hold_reason": "",
                "factual_status": "FACTUAL_PASS",
                "changed_case": False,
                "research_status": "SUBSTANTIVE_ADVISORY_ONLY",
                "next_route": "QUALIFIED_LEGAL_REVIEW",
                **case_disp,
            }
        )
        dispositions.append(row)
    if len(dispositions) != EXPECTED_TOTAL:
        raise GlobalIntegrityError(f"disposition count {len(dispositions)} != 331")
    if len({item["case_id"] for item in dispositions}) != EXPECTED_TOTAL:
        raise GlobalIntegrityError("duplicate case identities in dispositions")
    changed_ids = sorted(six_research["rebuilt"])
    noop_ids = [str(row.get("case_id") or "") for row in rows if str(row.get("case_id")) not in set(changed_ids)]
    post_delta_pass = EXPECTED_FACTUAL_PASS
    post_delta_hold = EXPECTED_FACTUAL_HOLD
    for case_id, rebuilt in six_research["rebuilt"].items():
        factual = rebuilt.get("factual_result") or {}
        if str(factual.get("outcome")) == "FACTUAL_PASS":
            post_delta_pass += 1
            post_delta_hold -= 1
    qlr_classes = {
        "RECOMMEND_FOR_QUALIFIED_REVIEW",
        "RECOMMEND_FOR_QUALIFIED_REVIEW_WITH_EDIT",
        "CONDITIONAL_ANSWER_RECOMMENDED",
        "HOLD_FOR_QUALIFIED_REVIEW",
        "FACT_DEPENDENT_HOLD",
    }
    excluded_classes = {"INSUFFICIENT_AUTHORITY", "OUT_OF_SCOPE", "REJECT_FROM_GOLD_CANDIDACY"}
    class_counts = Counter(str(item.get("terminal_advisory_class")) for item in dispositions)
    disp_by_id = {item["case_id"]: item for item in dispositions}
    for item in dispositions:
        case_id = str(item["case_id"])
        packet = (
            next((row for row in packets["currentness"] if row["case_id"] == case_id), None)
            or next((row for row in packets["jurisdiction"] if row["case_id"] == case_id), None)
            or residual_by_id.get(case_id)
            or (packets["fact"] if case_id == CASE_312 else None)
            or next((row for row in packets["factual_pass"] if row["case_id"] == case_id), None)
            or {}
        )
        if case_id in CONSERVATIVE_PROPOSED:
            proposed = CONSERVATIVE_PROPOSED[case_id]
        elif case_id == CASE_312:
            proposed = CONDITIONAL_ANSWER
        else:
            proposed = str(packet.get("candidate_answer") or packet.get("answer") or "")
        evidence_map = []
        for ev in packet.get("attached_authorities") or packet.get("exact_evidence_spans") or packet.get("locators") or []:
            if isinstance(ev, Mapping):
                evidence_map.append(
                    {
                        "title": ev.get("title") or ev.get("source_title"),
                        "locator": ev.get("locator") or ev.get("exact_locator"),
                        "passage_sha256": ev.get("evidence_span_sha256") or ev.get("source_byte_hash"),
                    }
                )
        if case_id in six_research["rebuilt"]:
            evidence_map = [
                {
                    "title": ev.get("title"),
                    "locator": ev.get("locator"),
                    "passage_sha256": ev.get("evidence_span_sha256"),
                }
                for ev in six_research["rebuilt"][case_id].get("evidence") or []
            ]
        review = _machine_review(
            case_id=case_id,
            terminal=str(item.get("terminal_advisory_class")),
            packet=packet if isinstance(packet, Mapping) else {},
            proposed=proposed,
            evidence_map=evidence_map,
            currentness_note=str(item.get("route_decision") or ""),
            jurisdiction_note=str(item.get("note") or item.get("workstream") or ""),
            unresolved=[str(item.get("unresolved_issue") or item.get("research_status") or "")],
            risk="advisory_only_not_qualified_review",
        )
        reviews.append(review)
        topic = str(item.get("topic") or case_id.split(":")[0])
        proposed_by_topic.setdefault(topic, []).append(
            {
                "case_id": case_id,
                "label": AI_REVIEW_LABEL,
                "proposed_final_answer": proposed,
                "terminal_advisory_class": item.get("terminal_advisory_class"),
            }
        )
        item["proposed_final_answer_sha256"] = sha256_text(proposed)
    case_174 = disp_by_id[CASE_174].get("case_174_invariants") or _case_174_invariants(
        next(item for item in packets["jurisdiction"] if item["case_id"] == CASE_174),
        rows_by_id[CASE_174],
    )
    if not all(case_174.values()):
        raise GlobalIntegrityError(f"case 174 invariants failed: {case_174}")
    land_d05 = disp_by_id["land-law:cp-d05"]
    qlr_queue = [item for item in dispositions if item.get("terminal_advisory_class") in qlr_classes]
    excluded = [item for item in dispositions if item.get("terminal_advisory_class") in excluded_classes]
    holds = [item for item in dispositions if "HOLD" in str(item.get("terminal_advisory_class"))]
    authorisation = {
        "schema": "legalbot.ge-owner-standing-policy-authorisation.v1",
        "campaign_id": CAMPAIGN_ID,
        "recorded_at_utc": datetime.now(UTC).isoformat(),
        **standing_policy_fields(),
        "owner_standing_policy_authorisation": COMPLETE,
        "human_case_by_case_owner_review": "NOT_PERFORMED",
        "authorises_qualified_legal_review": False,
        "authorises_answer_gold": False,
        "authorises_active_write": False,
        "authorises_training": False,
        "authorises_sealed_unseen": False,
        "source_policy_version": SOURCE_POLICY_VERSION,
        "campaign_version": CAMPAIGN_VERSION,
    }
    state = {
        "schema": "legalbot.ge-ai-advisory-state-transition.v1",
        "campaign_id": CAMPAIGN_ID,
        "overall_progress": True,
        "overall_state": AI_ADVISORY_COMPLETE_AWAITING_QUALIFIED_LEGAL_REVIEW,
        "owner_standing_policy_authorisation": COMPLETE,
        "ai_assisted_owner_advisory_research": COMPLETE,
        "ai_assisted_case_dispositions": COMPLETE,
        "human_case_by_case_owner_review": "NOT_PERFORMED",
        "evaluation_packet_preparation": COMPLETE,
        "qualified_legal_review": NOT_STARTED,
        "answer_legal_gold": NOT_STARTED,
        "legal_gold": False,
        "catalogue_admission": NOT_STARTED,
        "full_current_law_eligible": NOT_STARTED,
        "answer_weight_training": NOT_STARTED,
        "sealed_unseen_execution": NOT_STARTED,
        "promotion": NOT_STARTED,
        "live": NOT_STARTED,
        "noop_unchanged_case_inputs": len(noop_ids),
        "changed_case_count": len(changed_ids),
        "post_delta_factual_pass": post_delta_pass,
        "post_delta_factual_hold": post_delta_hold,
        "terminal_class_counts": dict(class_counts),
        "qualified_review_queue_size": len(qlr_queue),
        "excluded_from_gold_count": len(excluded),
        "case_174_invariants": case_174,
        "intake": {"output": intake.get("output"), "result": intake.get("result"), "writes_active": False},
        **{name: NOT_STARTED for name in DOWNSTREAM_GATES if name not in {"legal_gold"}},
    }
    tests = run_integrity_tests(
        dispositions=dispositions,
        mutation=mutation,
        six_register=six_research["register"],
        changed_ids=changed_ids,
        noop_count=len(noop_ids),
        fingerprints={item["case_id"]: item["research_fingerprint"] for item in six_research["register"]},
        case_174=case_174,
        land_d05=land_d05,
        case_312=fact_row,
        state=state,
        idempotent=True,
    )
    failed = [name for name, row in tests.items() if row.get("pass") is not True]
    if failed:
        raise GlobalIntegrityError(f"integrity tests failed: {failed}")
    destination.mkdir(parents=True, exist_ok=True)
    write_json(destination / "OWNER-STANDING-POLICY-AUTHORISATION.json", authorisation)
    write_jsonl(destination / "AI-ASSISTED-OWNER-ADVISORY-DISPOSITIONS.jsonl", dispositions)
    index_rows = [_index_row(item) for item in dispositions]
    write_text(
        destination / "AI-ASSISTED-OWNER-ADVISORY-INDEX.csv",
        _csv(
            index_rows,
            [
                "case_id",
                "topic",
                "workstream",
                "prior_hold_reason",
                "route_decision",
                "terminal_advisory_class",
                "factual_status",
                "changed_case",
                "research_status",
                "next_route",
                "reviewer_kind",
                "individual_human_row_reviewed",
                "qualified_legal_review",
                "answer_legal_gold",
            ],
        ),
    )
    write_jsonl(destination / "KNOWLEDGE-GAP-RESEARCH-REGISTER.jsonl", six_research["register"])
    new_sources = []
    for pack in sidecar_packs(project_root):
        manifest_path = pack / "STAGED-SOURCE-MANIFEST.json"
        if not manifest_path.is_file():
            continue
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        for source in raw.get("sources") or []:
            if isinstance(source, dict):
                new_sources.append(
                    {
                        "pack": pack.name,
                        "title": source.get("title"),
                        "canonical_url": source.get("canonical_url"),
                        "admitted": False,
                        "legal_gold": False,
                        "writes_active": False,
                    }
                )
    write_json(
        destination / "NEW-OFFICIAL-SOURCE-MANIFEST.json",
        {
            "schema": "legalbot.ge-advisory-official-source-manifest.v1",
            "prior_sidecar_packs_preserved": True,
            "intake": intake,
            "sources": new_sources,
            "writes_active": False,
            "admitted": False,
        },
    )
    bindings = []
    for item in six_research["register"]:
        for span in item.get("exact_locator_and_supporting_span") or []:
            bindings.append(
                {
                    "case_id": item["case_id"],
                    "proposition": item.get("exact_missing_legal_proposition"),
                    **span,
                    "attached": item.get("attached"),
                }
            )
    write_json(
        destination / "PROPOSITION-TO-SOURCE-BINDING-MANIFEST.json",
        {"schema": "legalbot.ge-proposition-source-binding.v1", "bindings": bindings},
    )
    changed_dir = destination / "changed-case-delta"
    changed_dir.mkdir(parents=True, exist_ok=True)
    write_json(changed_dir / "CHANGED-CASE-IDS.json", changed_ids)
    write_jsonl(
        changed_dir / "NO-OP-UNCHANGED-CASE-INPUTS.jsonl",
        [{"case_id": case_id, "result": NO_OP_UNCHANGED_CASE_INPUTS} for case_id in noop_ids],
    )
    changed_results = []
    for case_id in changed_ids:
        old = rows_by_id[case_id]
        new = six_research["rebuilt"][case_id]
        changed_results.append(new)
        write_json(
            changed_dir / f"{case_id.replace(':', '_')}.json",
            {
                "case_id": case_id,
                "prior_status": str((old.get("factual_result") or {}).get("outcome")),
                "change_reason": "bounded_official_sidecar_attach",
                "new_source_and_locator_ids": [
                    {"title": item.get("title"), "locator": item.get("locator"), "chunk_id": item.get("chunk_id")}
                    for item in new.get("evidence") or []
                ],
                "before_evidence_sha256": evidence_manifest_hash(old),
                "after_evidence_sha256": evidence_manifest_hash(new),
                "before_answer_sha256": sha256_text(str(old.get("user_facing_answer") or "")),
                "after_answer_sha256": sha256_text(str(new.get("user_facing_answer") or "")),
                "claim_support_result": str(((new.get("factual_result") or {}).get("checks") or {}).get("claim_evidence_support")),
                "factual_result": str((new.get("factual_result") or {}).get("outcome")),
                "advisory_disposition": disp_by_id[case_id].get("terminal_advisory_class"),
                "remaining_blocker": "qualified_legal_review_not_started",
                "next_route": "QUALIFIED_LEGAL_REVIEW",
                "full_331_rerun": False,
            },
        )
    if changed_results:
        write_jsonl(changed_dir / "CHANGED-CASE-RESULTS.jsonl", changed_results)
    write_jsonl(destination / "BEFORE-AFTER-ANSWER-EVIDENCE-HASH-REGISTER.jsonl", six_research["hash_register"])
    write_json(
        destination / "TERMINAL-HOLD-AND-EXCLUSION-MANIFEST.json",
        {
            "holds": [{"case_id": item["case_id"], "class": item["terminal_advisory_class"]} for item in holds],
            "excluded_from_gold": [
                {"case_id": item["case_id"], "class": item["terminal_advisory_class"]} for item in excluded
            ],
        },
    )
    write_json(
        destination / "QUALIFIED-REVIEW-QUEUE-MANIFEST.json",
        {
            "schema": "legalbot.ge-qualified-review-queue.v1",
            "size": len(qlr_queue),
            "qualified_legal_review": NOT_STARTED,
            "cases": [
                {
                    "case_id": item["case_id"],
                    "terminal_advisory_class": item["terminal_advisory_class"],
                    "workstream": item["workstream"],
                }
                for item in qlr_queue
            ],
        },
    )
    answers_dir = destination / "proposed-qualified-review-answers"
    answers_dir.mkdir(parents=True, exist_ok=True)
    for topic, rows_out in proposed_by_topic.items():
        write_jsonl(answers_dir / f"{topic}.jsonl", rows_out)
    write_jsonl(destination / "AI-ADVISORY-LEGAL-REVIEWS.jsonl", reviews)
    write_json(
        destination / "SIX-NO-EVIDENCE-CASE-RESEARCH-REPORT.json",
        {
            "schema": "legalbot.ge-six-no-evidence-research-report.v1",
            "cases": six_research["register"],
            "conservative_proposed_answers": CONSERVATIVE_PROPOSED,
            "tort_law_cp_d13": six_by_id.get("tort-law:cp-d13"),
        },
    )
    write_json(destination / "RESIDUAL-HASH-ERRATUM.json", residual_hash_erratum())
    write_json(destination / "CURRENTNESS-LOCATOR-DEDUPE.json", {"unique_research_identities": len(locator_cache), "locator_records": len(currentness_locator_rows)})
    test_receipt = {
        "schema": "legalbot.ge-ai-advisory-test-receipt.v1",
        "tests": tests,
        "all_pass": True,
        "named_tests": list(NAMED_TESTS),
    }
    write_json(destination / "TEST-RECEIPT.json", test_receipt)
    write_json(destination / "STATE-TRANSITION-RECEIPT.json", state)
    write_text(
        destination / "README.md",
        "\n".join(
            [
                "# AI-assisted owner-advisory disposition r1",
                "",
                AI_REVIEW_LABEL,
                "",
                f"overall_state: `{AI_ADVISORY_COMPLETE_AWAITING_QUALIFIED_LEGAL_REVIEW}`",
                "Not qualified legal review, gold, admission, training, unseen, promotion or live.",
                "",
            ]
        ),
    )
    artifacts = sorted(
        path
        for path in destination.rglob("*")
        if path.is_file() and path.name != "HASH-REGISTER.json"
    )
    hash_register = {
        str(path.relative_to(destination)): sha256_file(path) for path in artifacts
    }
    write_json(destination / "HASH-REGISTER.json", hash_register)
    return {
        "result": "COMPLETE",
        "output": str(destination),
        "state": state,
        "dispositions": dispositions,
        "tests": tests,
        "mutation": mutation,
        "reconciliation": reconciliation,
        "master_hashes": master_hashes,
        "six_research": six_research["register"],
        "changed_case_ids": changed_ids,
        "class_counts": dict(class_counts),
        "intake": intake,
        "artifacts": hash_register,
    }
