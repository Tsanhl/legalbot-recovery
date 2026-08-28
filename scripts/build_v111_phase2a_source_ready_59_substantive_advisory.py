#!/usr/bin/env python3
"""Build the create-only substantive r3 advisory for 59 source-ready rows.

This revision supersedes the unsafe r1 actions and uses the fail-closed r2 as
its immutable baseline.  Seventeen components are narrowed to proposition-
complete text that is present in already-bound official representations.  The
other 55 components remain material blockers.  Dated currentness and bounded
later-treatment recommendations are advisory owner inputs; retained release
holds remain fail-closed and no execution authority is created or consumed.

The builder does not fetch, materialize, scan, index, embed, qualify, release,
write pointers, or run Phase 2B.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import Counter
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from scripts import build_v111_phase2a_source_ready_59_remediation_advisory as r1
from scripts import build_v111_phase2a_source_ready_59_remediation_advisory_r2 as r2

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"

R2_ADVISORY_PATH = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-source-ready-59-remediation-advisory-r2/"
    "SOURCE-READY-59-REMEDIATION-ADVISORY-R2.json"
)
R2_CONTENT_SHA256 = "b1d5cb2d836cf75e7df65451a232b9a4a83730eb3dfda7cdc7aa9b3fb336e84d"
R2_FILE_SHA256 = "9dcb03e139dece7a3ce512f1e4479566905e775df3cd9af9ed00a8bcece6e2f0"

OUTPUT_ROOT = REVIEW_ROOT / ("LegalBot-Phase2A-2026-08-28-source-ready-59-substantive-advisory-r3")
ADVISORY_NAME = "SOURCE-READY-59-SUBSTANTIVE-REMEDIATION-ADVISORY-R3.json"
RESEARCH_NAME = "DATED-CURRENTNESS-LATER-TREATMENT-RESEARCH-LEDGER.json"
PACKAGE_NAME = "PACKAGE-MANIFEST.json"
CHECKSUMS_NAME = "SHA256SUMS.txt"


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _seal(value: dict[str, Any], field: str = "artifact_content_sha256") -> dict[str, Any]:
    material = dict(value)
    material.pop(field, None)
    return {**material, field: _sha256(_canonical_json(material))}


# These propositions deliberately state no more than the verified excerpts.
# In particular, absence-of-law and project-specific entitlement claims from
# r1 are removed because silence in one provision is not proposition-complete
# authority for those broader conclusions.
SAFE_AFTER: dict[tuple[str, int], str] = {
    ("live60-q34:issue-06", 1): (
        "Tas states that whether conduct was so distanced in time, place or "
        "circumstances is a question of fact and degree, and that if a defendant "
        "had withdrawn from the joint enterprise there was no relevant joint "
        "enterprise still operational."
    ),
    ("live60-q37:issue-05", 1): (
        "Section 5 states that an LLP's mutual member and LLP rights and duties are "
        "governed by agreement or, in the absence of agreement on a matter, by "
        "regulations; regulation 7 states that its default rules are subject to the "
        "general law and the LLP agreement."
    ),
    ("live60-q37:issue-07", 1): (
        "Regulation 5 states that the specified Insolvency Act 1986 provisions apply "
        "to LLPs subject to the modifications set out in Schedule 3."
    ),
    ("live60-q37:issue-08", 1): (
        "Regulation 5 states that the Insolvency Act 1986 provisions identified in "
        "regulation 5(1) apply to LLPs with the Schedule 3 modifications."
    ),
    ("live60-q37:issue-10", 1): (
        "The Limited Liability Partnerships Act 2000 states that an LLP is a body "
        "corporate with legal personality separate from its members and that every "
        "member is its agent; section 5 of the Partnership Act 1890 states that every "
        "partner is an agent of the firm and the other partners for partnership "
        "business."
    ),
    ("live60-q38:issue-05", 1): (
        "Sale of Goods Act 1979 section 19(1) states that a seller may, by the "
        "contract or appropriation terms, reserve the right of disposal of the goods "
        "until specified conditions are fulfilled."
    ),
    ("live60-q38:issue-06", 1): (
        "Sale of Goods Act 1979 sections 19 and 25 address reservation of disposal "
        "and a disposition by a buyer in possession to a recipient acting in good "
        "faith and without notice of the original seller's right."
    ),
    ("live60-q40:issue-01", 1): (
        "Article 15 of the 2015 Order requires the local planning authority to "
        "publicise a planning application. Regulation 3 of the 2017 Regulations "
        "prohibits permission for EIA development unless an EIA has been carried out, "
        "and regulation 18 requires an EIA application to be accompanied by an "
        "environmental statement, subject to regulation 9."
    ),
    ("live60-q45:issue-03", 1): (
        "Charity Commission CC9 states that a charity cannot have a political purpose "
        "and that political activity may support charitable purposes but cannot be "
        "the charity's continuing and sole activity."
    ),
    ("live60-q45:issue-04", 1): (
        "CC9 states that trustees considering political activity must decide whether "
        "there is a reasonable expectation that it will support the charity's "
        "purposes, and that political activity cannot be the continuing and sole "
        "activity."
    ),
    ("live60-q45:issue-04", 2): (
        "CC9 states that a charity must not support a political party or candidate "
        "and must guard and maintain its independence."
    ),
    ("live60-q45:issue-05", 1): (
        "CC3 states that trustees must decide for themselves what best enables the "
        "charity to carry out its purposes, make balanced and adequately informed "
        "decisions, and use reasonable care and skill with appropriate advice where "
        "necessary."
    ),
    ("live60-q45:issue-06", 1): (
        "Charity Commission guidance states that trustees considering refusal or "
        "return of a donation must have a legal power to do so and be satisfied that "
        "using it is in the charity's best interests; the applicable power depends on "
        "the circumstances."
    ),
    ("live60-q45:issue-09", 1): (
        "CC27 states that trustees must base decisions on sufficient relevant "
        "information, take all relevant factors into account, disregard irrelevant "
        "factors, and may treat reputational impact as a potentially relevant factor."
    ),
    ("live60-q51:issue-02", 1): (
        "Ingenious Media states that a recipient of personal or confidential "
        "information obtained under legal power or public duty generally owes a duty "
        "not to use it for other purposes, subject to statutory authority, and that an "
        "impermissible disclosure is not made permissible merely because it is passed "
        "on in confidence."
    ),
    ("live60-q58:issue-07", 1): (
        "Electricity Act 1989 section 9 states that a transmission licence holder has "
        "a duty to develop and maintain an efficient, co-ordinated and economical "
        "electricity transmission system."
    ),
    ("live60-q58:issue-11", 1): (
        "Contracts (Rights of Third Parties) Act 1999 section 1 states that a non-party "
        "may enforce a contract term where the contract expressly provides that the "
        "person may do so or the term purports to confer a benefit on that person."
    ),
}

SAFE_SPAN_LOCATOR_OVERRIDES = {
    ("live60-q37:issue-05", 1, "uksi:2001:1090"): "regulation 7",
}

LIVE_GUIDANCE_EVIDENCE = {
    "official-url:https://gov.uk/government/publications/speaking-out-guidance-on-campaigning-and-political-activity-by-charities-cc9/speaking-out-guidance-on-campaigning-and-political-activity-by-charities": {
        "official_url": "https://www.gov.uk/government/publications/speaking-out-guidance-on-campaigning-and-political-activity-by-charities-cc9/speaking-out-guidance-on-campaigning-and-political-activity-by-charities",
        "published_or_updated": "2022-11-07",
        "live_response_sha256": "ad4b069b8a7f57c8b019df08b788e4bb8be2922be9b48e693deb5a59a551b3ed",
        "jurisdiction": "England and Wales",
    },
    "official-url:https://gov.uk/government/publications/the-essential-trustee-what-you-need-to-know-what-you-need-to-do-cc3/the-essential-trustee-what-you-need-to-know-what-you-need-to-do": {
        "official_url": "https://www.gov.uk/government/publications/the-essential-trustee-what-you-need-to-know-what-you-need-to-do-cc3/the-essential-trustee-what-you-need-to-know-what-you-need-to-do",
        "published_or_updated": "2018-05-03",
        "live_response_sha256": "89afc6d83bf9d65aa40333eedfbe4641bbc5a0f313076c13be0eb461b0489be1",
        "jurisdiction": "England and Wales",
    },
    "official-url:https://gov.uk/guidance/accepting-refusing-and-returning-donations-to-your-charity": {
        "official_url": "https://www.gov.uk/guidance/accepting-refusing-and-returning-donations-to-your-charity",
        "published_or_updated": "2024-03-04",
        "live_response_sha256": "0d56fe0aca83727bec1075db06446e8efe6915acefca8c36a3643c55fd209cdd",
        "jurisdiction": "England and Wales",
    },
    "official-url:https://gov.uk/government/publications/decision-making-for-charity-trustees-cc27/decision-making-for-charity-trustees": {
        "official_url": "https://www.gov.uk/government/publications/decision-making-for-charity-trustees-cc27/decision-making-for-charity-trustees",
        "published_or_updated": "2013-07-01",
        "live_response_sha256": "7809c4b302c9749e58822db5dfa8a55ee4ab3c1e2697bc0b27b2265b5e53c466",
        "jurisdiction": "England and Wales",
    },
}

CASE_TREATMENT_EVIDENCE = {
    "neutral-citation:[2018] EWCA Crim 2603": {
        "exact_citation_query_url": "https://caselaw.nationalarchives.gov.uk/search?query=%22%5B2018%5D%20EWCA%20Crim%202603%22",
        "search_response_sha256": "cf0948adb742f8b777c59a4b80381bfa0ab98a2e0c113f28732187e91fac0e75",
        "result_count": 6,
        "later_treatments": [
            [
                "[2019] EWCA Crim 343",
                "paragraphs 30-32",
                "CONSISTENT_APPLICATION",
                "eee98a110d436feea938569b5de823218adb07137709887f1b2c0f454cb42b8c",
            ],
            [
                "[2021] EWCA Crim 450",
                "paragraphs 64-65",
                "CONSISTENT_APPLICATION",
                "94339f6abd67711563d75a7554b499c2361855e3735723face3e2a1b77f45672",
            ],
            [
                "[2022] EWCA Crim 1808",
                "paragraphs 12 and 28",
                "CONSISTENT_APPLICATION",
                "846ff5b15839604c2cd6108f16ec7746e1cc19983ba16df822a93b5dc7085d6c",
            ],
            [
                "[2023] EWCA Crim 845",
                "paragraph 11",
                "FACTUAL_HISTORY_REFERENCE_ONLY",
                "9aff9688e85be0c46069a66ff54528de2c90a63485ccadb74a7bbc593611d837",
            ],
            [
                "[2025] EWCA Crim 255",
                "paragraph 50",
                "CONSISTENT_APPLICATION",
                "459785b78b473b700196deb4105734ff97ebcda8874d710a83b5b218e64a6f32",
            ],
        ],
    },
    "neutral-citation:[2016] UKSC 54": {
        "exact_citation_query_url": "https://caselaw.nationalarchives.gov.uk/search?query=%22%5B2016%5D%20UKSC%2054%22",
        "search_response_sha256": "18ef5a34ef730a26944e3d6f69f96708d378ebfdd903103aa7240269c7cce981",
        "result_count": 13,
        "later_treatments": [
            [
                "[2023] EWCA Civ 261",
                "paragraphs 4 and 39",
                "CONSISTENT_APPLICATION",
                "d007616b862934cd3b5f429dec9d15a8e5111559ba37950eeb11d270c8ec0910",
            ],
            [
                "[2025] UKSC 11",
                "paragraph 69",
                "CONSISTENT_CITATION_DIFFERENT_POINT",
                "bd77e7472daf73e453d855a595780f71d63bbb44c1406849a78c1de5fb29ca24",
            ],
            [
                "[2026] EWHC 1001 (KB)",
                "paragraph 13",
                "CONSISTENT_APPLICATION",
                "8b9d33814e55afc1398795746004324e6a0f7ebf4922f09dc5f05bc3b8a02d7e",
            ],
            [
                "[2026] UKUT 146 (AAC)",
                "paragraph 64",
                "CONSISTENT_APPLICATION",
                "63c42c6e7ef7167cfe67db6f50df9d3662d902c4a29476b4023a93e4ec34620f",
            ],
        ],
    },
}


def _load_r2() -> dict[str, Any]:
    if R2_ADVISORY_PATH.is_symlink() or not R2_ADVISORY_PATH.is_file():
        raise ValueError("r2_advisory_not_regular")
    if _file_sha256(R2_ADVISORY_PATH) != R2_FILE_SHA256:
        raise ValueError("r2_file_digest_invalid")
    value = json.loads(R2_ADVISORY_PATH.read_bytes())
    material = dict(value)
    observed = material.pop("artifact_content_sha256", "")
    if observed != R2_CONTENT_SHA256 or _sha256(_canonical_json(material)) != observed:
        raise ValueError("r2_content_seal_invalid")
    return value


def _binding_path(binding: dict[str, Any]) -> Path:
    if binding["source_origin"] == "EXACT_OWNER_ADOPTED_MATERIALIZATION_PLAN":
        path = r2.QUARANTINE_ROOT / binding["representation_member"]
        if path.parent.resolve() != r2.QUARANTINE_ROOT.resolve():
            raise ValueError("quarantine_binding_escape")
        return path
    candidate = json.loads(r2.CANDIDATE_MANIFEST_PATH.read_bytes())
    source = next(
        row
        for row in candidate["sources"]
        if row["authority_identity_id"] == binding["authority_identity_id"]
    )
    return PROJECT_ROOT / source["canonical_markdown_path"]


def _bound_normalized_text(binding: dict[str, Any]) -> str:
    path = _binding_path(binding)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"bound_representation_not_regular:{binding['authority_identity_id']}")
    if _file_sha256(path) != binding["representation_file_sha256"]:
        raise ValueError(f"bound_representation_digest_invalid:{binding['authority_identity_id']}")
    text, _ = r2._representation_text(path)
    if _sha256(text.encode()) != binding["derived_normalized_representation_text_sha256"]:
        raise ValueError(
            f"bound_representation_text_digest_invalid:{binding['authority_identity_id']}"
        )
    return text


def _snapshot_evidence(binding: dict[str, Any]) -> dict[str, Any]:
    path = _binding_path(binding)
    identity = binding["authority_identity_id"]
    evidence: dict[str, Any] = {
        "authority_identity_id": identity,
        "source_binding_content_sha256": binding["record_content_sha256"],
        "representation_file_sha256": binding["representation_file_sha256"],
        "official_source_role": binding["official_source_role"],
    }
    if identity in LIVE_GUIDANCE_EVIDENCE:
        return {
            **evidence,
            **LIVE_GUIDANCE_EVIDENCE[identity],
            "snapshot_class": "LIVE_OFFICIAL_GUIDANCE_PAGE_CHECKED_2026_08_28",
            "currentness_owner_recommendation": (
                "ADOPT_AS_CURRENT_OFFICIAL_GUIDANCE_STATEMENT_ONLY_AT_CHECK_DATE"
            ),
            "later_treatment_owner_recommendation": (
                "NOT_APPLICABLE_TO_ATTRIBUTED_GUIDANCE_TEXT_UNDERLYING_LAW_NOT_INFERRED"
            ),
            "retained_release_hold_codes": [
                "NON_PRIMARY_REGULATOR_GUIDANCE",
                "UNDERLYING_CASE_AND_STATUTE_CURRENTNESS_NOT_ESTABLISHED_BY_GUIDANCE",
            ],
        }
    if identity in CASE_TREATMENT_EVIDENCE:
        treatment = CASE_TREATMENT_EVIDENCE[identity]
        return {
            **evidence,
            **treatment,
            "snapshot_class": "OFFICIAL_JUDGMENT_BYTES_AND_BOUNDED_EXACT_CITATION_SEARCH",
            "research_checked_date": "2026-08-28",
            "currentness_owner_recommendation": (
                "ADOPT_NARROW_HOLDING_WITH_BOUNDED_OFFICIAL_LATER_TREATMENT"
            ),
            "later_treatment_owner_recommendation": (
                "NO_CONTRARY_TREATMENT_IN_EXACT_CITATION_RESULT_SET"
            ),
            "retained_release_hold_codes": [
                "LATER_TREATMENT_SEARCH_BOUNDED_NOT_EXHAUSTIVE",
            ],
        }
    document_uri = None
    restrict_extent = None
    restrict_start_date = None
    if path.suffix.lower() == ".xml":
        root = ElementTree.fromstring(path.read_bytes())
        document_uri = root.attrib.get("DocumentURI")
        restrict_extent = root.attrib.get("RestrictExtent")
        restrict_start_date = root.attrib.get("RestrictStartDate")
    candidate = json.loads(r2.CANDIDATE_MANIFEST_PATH.read_bytes())
    candidate_source = next(
        (row for row in candidate["sources"] if row["authority_identity_id"] == identity),
        None,
    )
    return {
        **evidence,
        "snapshot_class": "OFFICIAL_REVISED_TEXT_SNAPSHOT_AS_AT_2026_08_14",
        "document_uri": document_uri,
        "document_restrict_extent": restrict_extent,
        "document_restrict_start_date": restrict_start_date,
        "candidate_currentness_status": (
            candidate_source.get("currentness_status") if candidate_source else None
        ),
        "candidate_currentness_verified": (
            candidate_source.get("currentness_verified") if candidate_source else None
        ),
        "candidate_unapplied_effect_count": (
            candidate_source.get("unapplied_effect_count") if candidate_source else None
        ),
        "currentness_owner_recommendation": (
            "ADOPT_EXACT_DATED_OFFICIAL_PROVISION_TEXT_ONLY_NOT_BROADER_CURRENT_LAW"
        ),
        "later_treatment_owner_recommendation": (
            "NOT_A_CASE_TREATMENT_QUESTION_RETAIN_PROVISION_EFFECTS_LIMITATION"
        ),
        "retained_release_hold_codes": [
            "PROVISION_EXTENT_EFFECTS_OR_TRANSITION_NOT_FULLY_REVIEWED",
            "DATED_SOURCE_TEXT_ONLY_NO_BROADER_CURRENT_LAW_INFERENCE",
        ],
    }


def build_research_ledger(r2_advisory: dict[str, Any]) -> dict[str, Any]:
    bindings = {row["authority_identity_id"]: row for row in r2_advisory["source_byte_bindings"]}
    used_ids = sorted(
        {
            span["authority_identity_id"]
            for rewrite in r1.REWRITES.values()
            for span in rewrite["spans"]
        }
    )
    records = [
        _seal(_snapshot_evidence(bindings[identity]), "record_content_sha256")
        for identity in used_ids
    ]
    return _seal(
        {
            "schema": "legalbot.v111.phase2a.source-ready-dated-currentness-treatment-ledger.v1",
            "research_date": "2026-08-28",
            "research_mode": "READ_ONLY_OFFICIAL_SOURCE_AND_SEALED_LOCAL_BYTES",
            "source_count": len(records),
            "records": records,
            "case_exact_citation_search_is_bounded_not_citator_complete": True,
            "owner_legal_judgment_required": True,
            **r2.NO_EXECUTION_FLAGS,
        }
    )


def build_advisory() -> tuple[dict[str, Any], dict[str, Any]]:
    baseline, topology, _ = r2.build_advisory()
    sealed_baseline = _load_r2()
    if baseline["artifact_content_sha256"] != sealed_baseline["artifact_content_sha256"]:
        raise ValueError("r2_rebuild_not_identical_to_sealed_artifact")
    if set(SAFE_AFTER) != set(r1.REWRITES) or len(SAFE_AFTER) != 17:
        raise ValueError("safe_rewrite_boundary_invalid")
    source_by_id = {row["authority_identity_id"]: row for row in baseline["source_byte_bindings"]}
    source_text = {
        identity: _bound_normalized_text(binding)
        for identity, binding in source_by_id.items()
        if identity
        in {
            span["authority_identity_id"]
            for rewrite in r1.REWRITES.values()
            for span in rewrite["spans"]
        }
    }
    research = build_research_ledger(baseline)
    research_by_id = {row["authority_identity_id"]: row for row in research["records"]}

    row_advisories = []
    action_counts: Counter[str] = Counter()
    residual_components = []
    support_complete_rows = []
    for row in baseline["row_advisories"]:
        recommendations = []
        for before in row["component_recommendations"]:
            key = (row["row_id"], before["component_ordinal"])
            rewrite = r1.REWRITES.get(key)
            if rewrite is None:
                recommendation = _seal(
                    {
                        "schema": "legalbot.v111.phase2a.source-ready-substantive-component-advisory.v3",
                        "row_id": row["row_id"],
                        "component_ordinal": before["component_ordinal"],
                        "before_proposition": before["before_proposition"],
                        "before_proposition_text_sha256": before["before_proposition_text_sha256"],
                        "upstream_support_fit": before["upstream_support_fit"],
                        "action": "RETAIN_BLOCKER_RESEARCH_REQUIRED",
                        "after_propositions": [],
                        "before_after_diff": None,
                        "frozen_evidence_span_proposals": [],
                        "component_support_complete_if_owner_adopted": False,
                        "material_gap_after_owner_adoption": True,
                        "row_specific_reason": before["rationale"],
                        "unsafe_r1_action_remains_revoked": True,
                        "r2_recommendation_content_sha256": before["recommendation_content_sha256"],
                        "owner_adopted": False,
                        "applied": False,
                    },
                    "recommendation_content_sha256",
                )
                residual_components.append(
                    {
                        "row_id": row["row_id"],
                        "component_ordinal": before["component_ordinal"],
                        "proposition_text_sha256": before["before_proposition_text_sha256"],
                        "reason": before["rationale"],
                    }
                )
            else:
                spans = []
                retained_codes: set[str] = set()
                for span_ordinal, span in enumerate(rewrite["spans"], start=1):
                    identity = span["authority_identity_id"]
                    binding = source_by_id[identity]
                    verified_excerpts = []
                    for excerpt in span["supporting_excerpts"]:
                        normalized = r2._normalise_text(excerpt)
                        if normalized not in source_text[identity]:
                            raise ValueError(
                                f"supporting_excerpt_not_in_bound_bytes:{row['row_id']}:{identity}"
                            )
                        verified_excerpts.append(
                            {
                                "text": excerpt,
                                "normalised_text_sha256": _sha256(normalized.encode()),
                                "verified_in_bound_source_bytes": True,
                            }
                        )
                    qualification = research_by_id[identity]
                    retained_codes.update(qualification["retained_release_hold_codes"])
                    locator = SAFE_SPAN_LOCATOR_OVERRIDES.get(
                        (row["row_id"], before["component_ordinal"], identity),
                        span["exact_locator"],
                    )
                    spans.append(
                        _seal(
                            {
                                "schema": "legalbot.v111.phase2a.frozen-evidence-span-proposal.v3",
                                "span_ordinal": span_ordinal,
                                "authority_identity_id": identity,
                                "exact_locator": locator,
                                "supporting_excerpts": verified_excerpts,
                                "source_binding_content_sha256": binding["record_content_sha256"],
                                "representation_file_sha256": binding["representation_file_sha256"],
                                "derived_normalized_representation_text_sha256": binding[
                                    "derived_normalized_representation_text_sha256"
                                ],
                                "official_source_role": binding["official_source_role"],
                                "dated_currentness_treatment_record_content_sha256": qualification[
                                    "record_content_sha256"
                                ],
                                "normalization": "UNICODE_NFKC_AND_COLLAPSE_WHITESPACE",
                                "proposal_payload_immutable": True,
                                "evidence_span_frozen_for_execution": False,
                                "owner_adopted": False,
                            },
                            "span_proposal_content_sha256",
                        )
                    )
                after = SAFE_AFTER[key]
                recommendation = _seal(
                    {
                        "schema": "legalbot.v111.phase2a.source-ready-substantive-component-advisory.v3",
                        "row_id": row["row_id"],
                        "component_ordinal": before["component_ordinal"],
                        "before_proposition": before["before_proposition"],
                        "before_proposition_text_sha256": before["before_proposition_text_sha256"],
                        "upstream_support_fit": before["upstream_support_fit"],
                        "action": "OWNER_REWRITE_TO_EXACT_BOUND_SOURCE_TEXT",
                        "after_propositions": [
                            {
                                "proposition": after,
                                "proposition_text_sha256": _sha256(after.encode()),
                                "proposed_support_fit": "FULL_IF_EXACT_OWNER_ADOPTED",
                            }
                        ],
                        "before_after_diff": {
                            "before_text_sha256": before["before_proposition_text_sha256"],
                            "after_text_sha256": _sha256(after.encode()),
                            "change_class": "NARROW_TO_VERIFIED_EXCERPT_ENTAILMENT",
                            "broader_absence_FACT_OR_APPLICATION_claims_removed": True,
                        },
                        "frozen_evidence_span_proposals": spans,
                        "component_support_complete_if_owner_adopted": True,
                        "material_gap_after_owner_adoption": False,
                        "retained_release_hold_codes": sorted(retained_codes),
                        "release_holds_do_not_convert_support_to_partial": True,
                        "answer_release_eligible": False,
                        "r1_rewrite_superseded_by_safer_r3_text": (after != rewrite["after"]),
                        "r2_recommendation_content_sha256": before["recommendation_content_sha256"],
                        "owner_adopted": False,
                        "applied": False,
                    },
                    "recommendation_content_sha256",
                )
            action_counts[recommendation["action"]] += 1
            recommendations.append(recommendation)
        row_complete = all(
            item["component_support_complete_if_owner_adopted"] for item in recommendations
        )
        if row_complete:
            support_complete_rows.append(row["row_id"])
        row_advisories.append(
            _seal(
                {
                    "schema": "legalbot.v111.phase2a.source-ready-substantive-row-advisory.v3",
                    "row_id": row["row_id"],
                    "r2_row_record_content_sha256": row["record_content_sha256"],
                    "component_recommendations": recommendations,
                    "component_count": len(recommendations),
                    "component_support_complete_if_owner_adopted": row_complete,
                    "material_gap_after_owner_adoption": not row_complete,
                    "qualification_eligible_if_owner_adopted": row_complete,
                    "answer_release_eligible": False,
                    "owner_decision_applied": False,
                },
                "record_content_sha256",
            )
        )

    if len(row_advisories) != 59 or sum(row["component_count"] for row in row_advisories) != 72:
        raise ValueError("source_ready_topology_invalid")
    if action_counts != {
        "OWNER_REWRITE_TO_EXACT_BOUND_SOURCE_TEXT": 17,
        "RETAIN_BLOCKER_RESEARCH_REQUIRED": 55,
    }:
        raise ValueError(f"substantive_action_counts_invalid:{dict(action_counts)}")
    if len(support_complete_rows) != 16 or len(residual_components) != 55:
        raise ValueError("substantive_residual_boundary_invalid")

    advisory = _seal(
        {
            "schema": "legalbot.v111.phase2a.source-ready-59-substantive-remediation-advisory.v3",
            "status": "SUBSTANTIVE_PARTIAL_PROGRESS_NOT_APPROVAL_READY_55_COMPONENT_BLOCKERS_REMAIN",
            "phase_scope": "PHASE2A_ONLY",
            "advisory_date": "2026-08-28",
            "advisory_effect": "NON_AUTHORIZING_OWNER_RECOMMENDATIONS_ONLY",
            "r2_baseline_content_sha256": R2_CONTENT_SHA256,
            "topology_partition_input_content_sha256": topology["artifact_content_sha256"],
            "dated_currentness_treatment_ledger_content_sha256": research[
                "artifact_content_sha256"
            ],
            "source_ready_row_id_set_sha256": topology["source_ready_row_id_set_sha256"],
            "source_ready_row_ids": topology["source_ready_row_ids"],
            "counts": {
                "row_count": 59,
                "blocking_component_input_count": 72,
                "exact_rewrite_recommendation_count": 17,
                "support_complete_row_if_owner_adopted_count": 16,
                "retained_blocking_component_count": 55,
                "residual_material_gap_row_count": 43,
                "source_binding_count": len(baseline["source_byte_bindings"]),
                "rewrite_support_source_count": research["source_count"],
                "no_execution_field_count": len(r2.NO_EXECUTION_FLAGS),
            },
            "support_complete_row_ids_if_owner_adopted": sorted(support_complete_rows),
            "residual_blocking_components": residual_components,
            "row_advisories": row_advisories,
            "source_byte_bindings": baseline["source_byte_bindings"],
            "decision_boundary": {
                "never_clear_due_to_other_full_component": True,
                "all_rewrites_bound_to_verified_source_bytes": True,
                "dated_or_historical_framing_required": True,
                "release_holds_remain_fail_closed": True,
                "not_approval_ready_because_residual_components_remain": True,
                "owner_adoption_required": True,
                "execution_chain_untouched": True,
            },
            "recursive_no_execution_control": {
                "authoritative_field_count": len(r2.NO_EXECUTION_FLAGS),
                "recursive_violations": [],
                "verified": True,
            },
            **r2.NO_EXECUTION_FLAGS,
        }
    )
    violations = r2._recursive_no_execution_violations(advisory)
    if violations:
        raise ValueError(f"recursive_no_execution_violation:{violations}")
    return advisory, research


def publish(output: Path = OUTPUT_ROOT) -> dict[str, Any]:
    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    advisory, research = build_advisory()
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    artifacts = {
        ADVISORY_NAME: _pretty_json(advisory),
        RESEARCH_NAME: _pretty_json(research),
    }
    package = _seal(
        {
            "schema": "legalbot.v111.phase2a.source-ready-substantive-package.v1",
            "status": advisory["status"],
            "artifact_count": len(artifacts),
            "artifacts": [
                {
                    "member": name,
                    "file_sha256": _sha256(raw),
                    "content_sha256": (
                        advisory["artifact_content_sha256"]
                        if name == ADVISORY_NAME
                        else research["artifact_content_sha256"]
                    ),
                }
                for name, raw in sorted(artifacts.items())
            ],
            **r2.NO_EXECUTION_FLAGS,
        },
        "manifest_content_sha256",
    )
    artifacts[PACKAGE_NAME] = _pretty_json(package)
    for name, raw in artifacts.items():
        path = output / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
    checksum_lines = [f"{_file_sha256(output / name)}  {name}" for name in sorted(artifacts)]
    checksums = output / CHECKSUMS_NAME
    fd = os.open(checksums, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(("\n".join(checksum_lines) + "\n").encode())
    return {
        "status": advisory["status"],
        "output": str(output),
        "advisory_content_sha256": advisory["artifact_content_sha256"],
        "research_content_sha256": research["artifact_content_sha256"],
        "package_content_sha256": package["manifest_content_sha256"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT_ROOT)
    args = parser.parse_args()
    print(json.dumps(publish(args.output), ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
