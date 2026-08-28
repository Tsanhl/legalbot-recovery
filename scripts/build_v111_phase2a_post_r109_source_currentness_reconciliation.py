#!/usr/bin/env python3
"""Build the deterministic 26-link source/currentness reconciliation.

The result is recommendation evidence only.  It binds exact official spans,
records same-adapter false negatives, proposes five source admissions and keeps
all owner, candidate and later-phase gates closed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
for root in (PROJECT_ROOT, BACKEND_ROOT):
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

from app.quality.evidence import (  # noqa: E402
    extract_material_facts,
    non_atomic_material_claim_reasons,
    substantive_tokens,
)

REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
R104_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-26-r104b-context-aware-source-review-packets"
    / "DETERMINISTIC-SOURCE-REVIEW-PACKETS-26.json"
)
R105_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-26-r105-independent-source-reranker"
    / "INDEPENDENT-SOURCE-RERANKER-26.json"
)
R108_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-26-r108-deterministic-held-source-resolution"
    / "DETERMINISTIC-HELD-SOURCE-RESOLUTION-26.json"
)
R103_ROOT = (
    PROJECT_ROOT
    / "data/quarantine/2026-08-26/phase2a-post-r101-official-source-research-r103"
)
R103_PATH = R103_ROOT / "QUARANTINE-MANIFEST.json"
R109_ROOT = (
    PROJECT_ROOT
    / "data/quarantine/2026-08-26/phase2a-post-r108-currentness-sources-r109c"
)
R109_PATH = R109_ROOT / "QUARANTINE-MANIFEST.json"
DEFAULT_OUTPUT_ROOT = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-26-r110-deterministic-source-currentness-reconciliation"
)
OUTPUT_NAME = "DETERMINISTIC-SOURCE-CURRENTNESS-RECONCILIATION-26.json"
TARGET_CEILING = "2026-08-14T23:59:59+01:00 Europe/London"
EXPECTED_INPUTS = {
    R104_PATH: (
        "artifact_content_sha256",
        "5fc1c6d1f8eebb1d7624abf3ca3249451f3e66873ae8826471a51fb11303318f",
        "a33a918d4f2e38573ad25f08e2f66490cf87a5c68ef21b0e26dde989c938fff2",
    ),
    R105_PATH: (
        "artifact_content_sha256",
        "984d16ad59325466340ab98e20c606712abf757f665d28692fe0b92f648186ce",
        "ad55174d421419981c332b0584d64b9eb17ebfa5fc1d1ab257b1106dbe039902",
    ),
    R108_PATH: (
        "artifact_content_sha256",
        "2c3f6f3bf9f9e862624065f884f6d59c745a74cc0dcc2ad2cb77254abe8037cd",
        "a1332b11d983fa45d7186e312184f60c29b2aad552df5854dacf40e33d6269c4",
    ),
    R103_PATH: (
        "manifest_content_sha256",
        "aee3cf90510f0b99d0885ddf0423a201cee25d03309096a05baeb3cbe82ae2ad",
        "af1b9ef8b9060497d4e4420edb313e6b7ce173aad817a515bdef1dfc4a892e53",
    ),
    R109_PATH: (
        "manifest_content_sha256",
        "cc4307ce981ebc931fdd9db557dffd62f81f163c4a9edeb80f74ba35a240078f",
        "c4867282297e5209858eb0a71f5b1b5d5ffe9b0ac84ef774cd5aa226c7cbe6d9",
    ),
}
_BOUNDARY_FIELDS = (
    "owner_decisions_applied",
    "source_admission_authorized",
    "automatic_indexing",
    "automatic_embedding",
    "candidate_mutated",
    "technical_qualification_assigned",
    "phase2b_authorized",
    "development30_authorized",
)

RECONCILIATION = {
    1: (
        "RECOMMEND_REJECT_MAPPING",
        "arbitration_governing_law_source_does_not_support_disclosure",
        "The judgment concerns arbitration governing law, forum and anti-suit relief; it does not state a disclosure proposition.",
    ),
    2: (
        "RECOMMEND_SUPERSEDE_WITH_CURRENT_AUTHORITY",
        "court_of_appeal_judgment_reversed_use_uksc_successor",
        "The paragraph is directly relevant, but the Court of Appeal judgment was reversed in the same proceedings; use the later Supreme Court mini-trial holding.",
    ),
    3: (
        "RECOMMEND_REJECT_MAPPING",
        "charge_priority_and_dishonest_assistance_not_payment_mandate",
        "The judgment addresses charge priority and dishonest assistance by solicitors, not a bank's payment-authority or Quincecare duties.",
    ),
    4: (
        "RECOMMEND_REJECT_MAPPING",
        "trespass_remedy_source_not_change_of_position",
        "The judgment addresses trespass and remedies, not the restitutionary defence of change of position.",
    ),
    5: (
        "RECOMMEND_REJECT_MAPPING",
        "bond_facts_do_not_establish_insurance_or_bond_merits",
        "The judgment mentions on-demand bonds as facts but decides arbitration and anti-suit issues, not insurance coverage or the merits of a bond call.",
    ),
    6: (
        "RECOMMEND_SUPERSEDE_WITH_CURRENT_AUTHORITY",
        "prefer_later_binding_uksc_undue_influence_authority",
        "The first-instance paragraph is relevant, but the 2025 Supreme Court judgment gives a later binding statement tailored to lender notice and undue influence.",
    ),
    7: (
        "RECOMMEND_REJECT_MAPPING",
        "proprietary_estoppel_source_not_undue_influence",
        "The judgment concerns proprietary estoppel and does not supply the required undue-influence rule.",
    ),
    8: (
        "RECOMMEND_PARTIAL_BINDING_AND_SOURCE_ADMISSION",
        "ai_output_substantial_part_comparison_directly_supported",
        "Paragraph 90 directly supports the individual comparison required for an AI-output copyright allegation, but not the whole intellectual-property issue.",
    ),
    9: (
        "RECOMMEND_PARTIAL_EXISTING_SOURCE_BINDING",
        "visitor_category_statute_partially_supports_driver_status",
        "The existing candidate statute supplies the visitor-category rule but cannot decide the delivery driver's status on the scenario facts.",
    ),
    10: (
        "RECOMMEND_REJECT_MAPPING",
        "1957_act_does_not_state_trespasser_duty",
        "The complete 1957 Act extraction contains no direct trespasser-duty proposition.",
    ),
    11: (
        "RECOMMEND_REJECT_MAPPING",
        "nuisance_case_not_occupiers_independent_contractor_rule",
        "The judgment concerns nuisance and negligence arising from piling works, not an occupier's liability for an independent contractor.",
    ),
    12: (
        "RECOMMEND_REJECT_MAPPING",
        "intoxication_mens_rea_case_not_complicity_intent",
        "The criminal appeal concerns intoxication and basic intent, not intention to assist or encourage secondary offending.",
    ),
    13: (
        "RECOMMEND_REJECT_MAPPING",
        "intoxication_mens_rea_case_not_complicity_knowledge",
        "The criminal appeal concerns intoxication and basic intent, not knowledge of essential circumstances for secondary liability.",
    ),
    14: (
        "RECOMMEND_REJECT_MAPPING",
        "intoxication_recklessness_case_not_complicity_foresight",
        "Its discussion of recklessness and foresight is not a rule about foresight as evidence in complicity.",
    ),
    15: (
        "RECOMMEND_REJECT_MAPPING",
        "commercial_lease_forfeiture_not_residential_retaliatory_action",
        "The judgment concerns forfeiture of a commercial lease and section 146 notice, not residential retaliatory eviction.",
    ),
    16: (
        "RECOMMEND_REJECT_MAPPING",
        "arbitration_governing_law_not_non_signatory_extension",
        "The judgment determines the governing law of an arbitration agreement, not whether a non-signatory is bound.",
    ),
    17: (
        "RECOMMEND_REJECT_MAPPING",
        "bill_of_lading_misdelivery_jurisdiction_not_deck_cargo",
        "The judgment concerns misdelivery, jurisdiction and time bars, not lawful deck stowage.",
    ),
    18: (
        "RECOMMEND_REJECT_MAPPING",
        "exclusive_jurisdiction_clause_not_deck_cargo",
        "The judgment concerns an exclusive English jurisdiction clause and foreign proceedings, not deck cargo.",
    ),
    19: (
        "RECOMMEND_REJECT_MAPPING",
        "insurance_arbitration_clause_not_policy_causation",
        "The insurance context is incidental to an arbitration-governing-law dispute and supplies no policy-causation rule.",
    ),
    20: (
        "RECOMMEND_REJECT_MAPPING",
        "bill_of_lading_jurisdiction_not_insurance_causation",
        "The judgment concerns bill-of-lading jurisdiction and supplies no insurance-causation proposition.",
    ),
    21: (
        "RECOMMEND_REJECT_MAPPING",
        "notice_of_arbitration_not_policy_notification",
        "A factual notice of arbitration is not a legal rule governing notification under an insurance policy.",
    ),
    22: (
        "RECOMMEND_REJECT_MAPPING",
        "bill_of_lading_jurisdiction_not_policy_notification",
        "The judgment supplies no insurance-policy notification proposition.",
    ),
    23: (
        "RECOMMEND_REJECT_MAPPING",
        "gmp_equalisation_case_not_regulatory_anti_avoidance",
        "The judgment addresses guaranteed-minimum-pension equalisation, not the Pensions Regulator's anti-avoidance powers.",
    ),
    24: (
        "RECOMMEND_PARTIAL_BINDING_AND_SOURCE_ADMISSION",
        "tupe_pension_entitlement_transfer_directly_supported",
        "The judgment directly supports transfer of some pension-related entitlements under TUPE, but current primary regulations are also required for the broader issue.",
    ),
    25: (
        "RECOMMEND_REJECT_MAPPING",
        "anti_suit_and_forum_case_not_foreign_judgment_recognition_rule",
        "The judgment addresses forum and anti-suit relief; incidental enforcement references do not establish a recognition-and-enforcement rule.",
    ),
    26: (
        "RECOMMEND_REJECT_MAPPING",
        "performance_bond_facts_not_bond_call_merits",
        "The existence of on-demand bonds is factual background; the court did not decide the merits of the performance-bond call.",
    ),
}

UKSC3_QUOTE = (
    "where, as in this case, the jurisdictional issue is whether there is a "
    "triable issue as against a defendant, it is important to observe judicial "
    "restraint and to avoid mini-trials"
)
UKSC3_PROPOSITION = (
    "Where the jurisdictional issue is whether a claim is triable, the court "
    "should exercise judicial restraint and avoid a mini-trial."
)
WALLER_CORE_QUOTE = (
    "the vulnerable party to such a relationship (say, a wife) who has been "
    "induced to enter into a financial transaction by the undue influence of "
    "her husband, is entitled to have it set aside as against the husband."
)
WALLER_CORE_PROPOSITION = (
    "A transaction induced by undue influence may be set aside against the "
    "person exerting that influence."
)
WALLER_LENDER_QUOTE = (
    "The bank is not expected to try to find out whether or not undue influence "
    "or misrepresentation is taking place"
)
WALLER_LENDER_PROPOSITION = (
    "A lender put on inquiry need not investigate whether undue influence "
    "actually occurred."
)
GETTY_QUOTE = (
    "The allegation (made in the text prompts claim) that an output from Stable "
    "Diffusion infringes copyright in a specifically identified Getty Copyright "
    "Work requires a comparison of the output obtained to the Copyright Work to "
    "determine whether the former reproduces a substantial part of the latter."
)
GETTY_PROPOSITION = (
    "An AI-output copyright claim requires comparison with the identified work "
    "to determine whether a substantial part was reproduced."
)
P_AND_G_QUOTE = (
    "The entitlement of the transferring employees, and its concomitant "
    "obligation, though discretionary, are such as to transfer by operation of "
    "TUPE accordingly."
)
P_AND_G_PROPOSITION = "A discretionary employment entitlement can transfer under TUPE."
TUPE_TRANSFER_QUOTE = (
    "any such contract shall have effect after the transfer as if originally "
    "made between the person so employed and the transferee."
)
TUPE_TRANSFER_PROPOSITION = (
    "An assigned employee's contract continues after a relevant transfer as if "
    "made with the transferee."
)
TUPE_PENSION_QUOTE = (
    "any provisions of an occupational pension scheme which do not relate to "
    "benefits for old age, invalidity or survivors shall not be treated as being "
    "part of the scheme."
)
TUPE_PENSION_PROPOSITION = (
    "For TUPE, pension provisions unrelated to old age, invalidity or survivor "
    "benefits are not treated as part of the occupational pension scheme."
)
TUPE_CONSULT_QUOTE = (
    "Long enough before a relevant transfer to enable the employer of any "
    "affected employees to consult the appropriate representatives of any "
    "affected employees, the employer shall inform those representatives"
)
TUPE_CONSULT_PROPOSITION = (
    "Before a relevant transfer, an employer must inform affected employees' "
    "representatives early enough to enable consultation."
)
GETTY_LATER_TREATMENT_QUOTE = (
    "following a successful challenge by Stability to this representative claim "
    "([2025] EWHC 38 (Ch)), Getty Images was instead permitted to proceed under "
    "CPR 19.3(1) and s.102(1) CDPA without joining any of the “Exclusive Licensors”"
)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


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


def _load_verified(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_r110_input_must_be_regular_file")
    field, expected_content, expected_file = EXPECTED_INPUTS[path]
    if _sha256_file(path) != expected_file:
        raise ValueError("phase2a_r110_input_file_digest_invalid")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_r110_input_must_be_object")
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if supplied != expected_content or supplied != _sealed(material):
        raise ValueError("phase2a_r110_input_content_seal_invalid")
    return value


def _load_extractions(
    manifest: Mapping[str, Any], root: Path
) -> dict[str, dict[str, Any]]:
    records = manifest.get("records")
    if not isinstance(records, list):
        raise ValueError("phase2a_r110_source_manifest_records_invalid")
    extractions: dict[str, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, Mapping):
            raise ValueError("phase2a_r110_source_record_invalid")
        member = str(record.get("extraction_member") or "")
        path = root / member
        if path.parent != root or _sha256_file(path) != record.get(
            "extraction_file_sha256"
        ):
            raise ValueError("phase2a_r110_extraction_file_digest_invalid")
        value = json.loads(path.read_bytes())
        if not isinstance(value, dict):
            raise ValueError("phase2a_r110_extraction_invalid")
        material = dict(value)
        supplied = str(material.pop("artifact_content_sha256", ""))
        if supplied != record.get("extraction_content_sha256") or supplied != _sealed(
            material
        ):
            raise ValueError("phase2a_r110_extraction_content_seal_invalid")
        authority = str(value.get("authority_identity_id") or "")
        if not authority or authority in extractions:
            raise ValueError("phase2a_r110_extraction_identity_collision")
        extractions[authority] = value
    return extractions


def _block(extraction: Mapping[str, Any], locator: str) -> Mapping[str, Any]:
    matches = [
        value
        for value in extraction.get("blocks", [])
        if isinstance(value, Mapping) and value.get("locator") == locator
    ]
    if len(matches) != 1:
        raise ValueError("phase2a_r110_exact_locator_invalid")
    return matches[0]


def _facts(value: str) -> list[dict[str, str]]:
    return [
        {
            "kind": fact.kind,
            "matched_text": fact.matched_text,
            "normalized_value": fact.normalized_value,
        }
        for fact in extract_material_facts(value)
    ]


def _binding(
    extraction: Mapping[str, Any],
    *,
    locator: str,
    quote: str,
    proposition: str,
) -> dict[str, Any]:
    reasons = non_atomic_material_claim_reasons(proposition)
    if reasons or len(proposition) > 220:
        raise ValueError("phase2a_r110_non_atomic_material_claim")
    block = _block(extraction, locator)
    text = str(block["text"])
    start = text.find(quote)
    if start < 0:
        raise ValueError("phase2a_r110_quote_not_contiguous")
    proposition_facts = {fact.identity for fact in extract_material_facts(proposition)}
    span_facts = {
        fact.identity for fact in extract_material_facts(f"{quote}\n{locator}")
    }
    if proposition_facts - span_facts:
        raise ValueError("phase2a_r110_unsupported_material_fact")
    overlap = set(substantive_tokens(proposition)) & set(substantive_tokens(quote))
    if len(overlap) < 2:
        raise ValueError("phase2a_r110_unrelated_evidence")
    full_sha256 = str(block.get("text_sha256") or block.get("exact_text_sha256") or "")
    if full_sha256 != _sha256(text.encode("utf-8")):
        raise ValueError("phase2a_r110_block_digest_invalid")
    return {
        "atomic_proposition": proposition,
        "authority_identity_id": extraction["authority_identity_id"],
        "block_id": block.get("block_id"),
        "element_id": block.get("element_id"),
        "full_text_sha256": full_sha256,
        "locator": locator,
        "proposition_material_facts": _facts(proposition),
        "quote": quote,
        "quote_end": start + len(quote),
        "quote_sha256": _sha256(quote.encode("utf-8")),
        "quote_start": start,
        "span_material_facts": _facts(f"{quote}\n{locator}"),
        "substantive_token_overlap": sorted(overlap),
    }


def _metadata_span(
    extraction: Mapping[str, Any], *, locator: str, quote: str
) -> dict[str, Any]:
    block = _block(extraction, locator)
    text = str(block["text"])
    start = text.find(quote)
    if start < 0:
        raise ValueError("phase2a_r110_metadata_quote_not_contiguous")
    return {
        "authority_identity_id": extraction["authority_identity_id"],
        "element_id": block.get("element_id"),
        "full_text_sha256": block["text_sha256"],
        "locator": locator,
        "quote": quote,
        "quote_end": start + len(quote),
        "quote_sha256": _sha256(quote.encode("utf-8")),
        "quote_start": start,
    }


def _source_proposal(
    extraction: Mapping[str, Any],
    *,
    affected_row_id: str,
    proposed_candidate_use: str,
    currentness_status: str,
    bindings: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "authority_identity_id": extraction["authority_identity_id"],
        "source_title": extraction["source_title"],
        "source_date": extraction["source_date"],
        "source_representation_sha256": extraction[
            "source_representation_sha256"
        ],
        "source_canonical_xml_sha256": extraction[
            "source_canonical_xml_sha256"
        ],
        "source_class": extraction["source_class"],
        "affected_row_ids": [affected_row_id],
        "proposed_candidate_use": proposed_candidate_use,
        "currentness_status": currentness_status,
        "exact_proposition_bindings": bindings,
        "owner_source_admission_required": True,
        "owner_source_admission_decision": None,
        "source_admission_authorized": False,
        "automatically_indexed": False,
        "automatically_embedded": False,
    }


def build_reconciliation(
    output_root: Path = DEFAULT_OUTPUT_ROOT,
) -> dict[str, Any]:
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_r110_output_already_exists")
    r104 = _load_verified(R104_PATH)
    r105 = _load_verified(R105_PATH)
    r108 = _load_verified(R108_PATH)
    r103_manifest = _load_verified(R103_PATH)
    r109_manifest = _load_verified(R109_PATH)
    packets = r104.get("rows")
    rankings = r105.get("rows")
    findings = r108.get("findings")
    if (
        not isinstance(packets, list)
        or len(packets) != 26
        or not isinstance(rankings, list)
        or len(rankings) != 26
        or not isinstance(findings, list)
        or len(findings) != 26
        or set(RECONCILIATION) != set(range(1, 27))
    ):
        raise ValueError("phase2a_r110_input_inventory_invalid")
    ranking_by_link = {
        str(row["row_source_link_id"]): row
        for row in rankings
        if isinstance(row, Mapping)
    }
    finding_by_link = {
        str(row["row_source_link_id"]): row
        for row in findings
        if isinstance(row, Mapping)
    }
    if len(ranking_by_link) != 26 or len(finding_by_link) != 26:
        raise ValueError("phase2a_r110_input_identity_collision")
    r103_sources = _load_extractions(r103_manifest, R103_ROOT)
    r109_sources = _load_extractions(r109_manifest, R109_ROOT)

    uksc3_binding = _binding(
        r109_sources["neutral-citation:[2021] UKSC 3"],
        locator="paragraph 21",
        quote=UKSC3_QUOTE,
        proposition=UKSC3_PROPOSITION,
    )
    waller_bindings = [
        _binding(
            r109_sources["neutral-citation:[2025] UKSC 22"],
            locator="paragraph 1",
            quote=WALLER_CORE_QUOTE,
            proposition=WALLER_CORE_PROPOSITION,
        ),
        _binding(
            r109_sources["neutral-citation:[2025] UKSC 22"],
            locator="paragraph 40",
            quote=WALLER_LENDER_QUOTE,
            proposition=WALLER_LENDER_PROPOSITION,
        ),
    ]
    getty_binding = _binding(
        r103_sources["neutral-citation:[2025] EWHC 38 (Ch)"],
        locator="paragraph 90",
        quote=GETTY_QUOTE,
        proposition=GETTY_PROPOSITION,
    )
    p_and_g_binding = _binding(
        r103_sources["neutral-citation:[2012] EWHC 1257 (Ch)"],
        locator="paragraph 68",
        quote=P_AND_G_QUOTE,
        proposition=P_AND_G_PROPOSITION,
    )
    tupe_source = r109_sources["uksi:2006:246"]
    tupe_bindings = [
        _binding(
            tupe_source,
            locator="regulation 4",
            quote=TUPE_TRANSFER_QUOTE,
            proposition=TUPE_TRANSFER_PROPOSITION,
        ),
        _binding(
            tupe_source,
            locator="regulation 10",
            quote=TUPE_PENSION_QUOTE,
            proposition=TUPE_PENSION_PROPOSITION,
        ),
        _binding(
            tupe_source,
            locator="regulation 13",
            quote=TUPE_CONSULT_QUOTE,
            proposition=TUPE_CONSULT_PROPOSITION,
        ),
    ]
    getty_later_treatment = _metadata_span(
        r109_sources["neutral-citation:[2025] EWHC 2863 (Ch)"],
        locator="paragraph 60",
        quote=GETTY_LATER_TREATMENT_QUOTE,
    )

    source_proposals = [
        _source_proposal(
            r109_sources["neutral-citation:[2021] UKSC 3"],
            affected_row_id="live30-q14:issue-06",
            proposed_candidate_use="REPLACE_REVERSED_EWCA_SOURCE",
            currentness_status="BINDING_SUCCESSOR_IN_SAME_PROCEEDINGS",
            bindings=[uksc3_binding],
        ),
        _source_proposal(
            r109_sources["neutral-citation:[2025] UKSC 22"],
            affected_row_id="live30-q28:issue-05",
            proposed_candidate_use="REPLACE_OLDER_FIRST_INSTANCE_SUMMARY",
            currentness_status="CURRENT_BINDING_SUPREME_COURT_AUTHORITY",
            bindings=waller_bindings,
        ),
        _source_proposal(
            r103_sources["neutral-citation:[2025] EWHC 38 (Ch)"],
            affected_row_id="live30-q30:issue-16",
            proposed_candidate_use="PARTIAL_AI_OUTPUT_COPYRIGHT_PROPOSITION",
            currentness_status=(
                "FIRST_INSTANCE_PROCEDURAL_PROPOSITION_NOT_DISPLACED_IN_REVIEWED_"
                "LATER_SAME_CASE_JUDGMENT"
            ),
            bindings=[getty_binding],
        ),
        _source_proposal(
            r103_sources["neutral-citation:[2012] EWHC 1257 (Ch)"],
            affected_row_id="live60-q54:issue-07",
            proposed_candidate_use="PARTIAL_TUPE_PENSION_PROPOSITION",
            currentness_status=(
                "PERSUASIVE_FIRST_INSTANCE_WITH_CURRENT_STATUTORY_CONFIRMATION"
            ),
            bindings=[p_and_g_binding],
        ),
        _source_proposal(
            tupe_source,
            affected_row_id="live60-q54:issue-07",
            proposed_candidate_use="CURRENT_PRIMARY_TUPE_RULES",
            currentness_status="POINT_IN_TIME_CURRENT_AT_TARGET_CEILING",
            bindings=tupe_bindings,
        ),
    ]
    if len({proposal["authority_identity_id"] for proposal in source_proposals}) != 5:
        raise ValueError("phase2a_r110_source_proposal_collision")

    exact_bindings_by_ordinal: dict[int, list[dict[str, Any]]] = {
        2: [uksc3_binding],
        6: waller_bindings,
        8: [getty_binding],
        9: [
            {
                **dict(finding_by_link[str(packets[8]["row_source_link_id"])][
                    "exact_span_binding"
                ]),
                "atomic_proposition": finding_by_link[
                    str(packets[8]["row_source_link_id"])
                ]["atomic_proposition"],
                "authority_identity_id": "ukpga:1957:31",
            }
        ],
        24: [p_and_g_binding, *tupe_bindings],
    }
    replacement_sources_by_ordinal = {
        2: ["neutral-citation:[2021] UKSC 3"],
        6: ["neutral-citation:[2025] UKSC 22"],
        24: ["uksi:2006:246"],
    }
    reconciled_links: list[dict[str, Any]] = []
    for ordinal, packet in enumerate(packets, start=1):
        if not isinstance(packet, Mapping):
            raise ValueError("phase2a_r110_packet_invalid")
        link_id = str(packet["row_source_link_id"])
        finding = finding_by_link[link_id]
        ranking = ranking_by_link[link_id]
        outcome, reason_code, rationale = RECONCILIATION[ordinal]
        false_negative = ordinal in {2, 6, 8, 24}
        if false_negative and finding.get("assessment") != "UNRELATED":
            raise ValueError("phase2a_r110_expected_model_false_negative_missing")
        record_material = {
            "ordinal": ordinal,
            "row_source_link_id": link_id,
            "row_id": packet["row_id"],
            "issue_label": packet["issue_label"],
            "authority_identity_id": packet["authority_identity_id"],
            "source_title": packet["source_title"],
            "research_route": packet["research_route"],
            "independent_reranker_top_locator": ranking["top_candidates"][0][
                "locator"
            ],
            "independent_reranker_top_score": ranking["top_candidates"][0][
                "reranker_score"
            ],
            "same_adapter_advisory_assessment": finding["assessment"],
            "same_adapter_false_negative": false_negative,
            "recommended_owner_outcome": outcome,
            "deterministic_reason_code": reason_code,
            "deterministic_rationale": rationale,
            "exact_proposition_bindings": exact_bindings_by_ordinal.get(ordinal, []),
            "replacement_authority_identity_ids": replacement_sources_by_ordinal.get(
                ordinal, []
            ),
            "owner_decision_required": True,
            "owner_outcome": None,
            "source_admission_authorized": False,
            "technical_qualification_assigned": False,
        }
        reconciled_links.append(
            {**record_material, "record_content_sha256": _sealed(record_material)}
        )

    outcome_counts = dict(
        sorted(Counter(row["recommended_owner_outcome"] for row in reconciled_links).items())
    )
    expected_counts = {
        "RECOMMEND_PARTIAL_BINDING_AND_SOURCE_ADMISSION": 2,
        "RECOMMEND_PARTIAL_EXISTING_SOURCE_BINDING": 1,
        "RECOMMEND_REJECT_MAPPING": 21,
        "RECOMMEND_SUPERSEDE_WITH_CURRENT_AUTHORITY": 2,
    }
    if outcome_counts != expected_counts:
        raise ValueError("phase2a_r110_outcome_inventory_invalid")

    artifact_material = {
        "schema": "legalbot.v111.phase2a.source-currentness-reconciliation.v1",
        "status": "DETERMINISTIC_RECOMMENDATIONS_READY_OWNER_DECISION_REQUIRED",
        "target_ceiling": TARGET_CEILING,
        "source_r104_content_sha256": r104["artifact_content_sha256"],
        "source_r105_content_sha256": r105["artifact_content_sha256"],
        "source_r108_content_sha256": r108["artifact_content_sha256"],
        "source_r103_manifest_content_sha256": r103_manifest[
            "manifest_content_sha256"
        ],
        "source_r109_manifest_content_sha256": r109_manifest[
            "manifest_content_sha256"
        ],
        "row_source_link_count": len(reconciled_links),
        "unique_row_count": len({row["row_id"] for row in reconciled_links}),
        "recommendation_counts": outcome_counts,
        "same_adapter_false_negative_count": sum(
            bool(row["same_adapter_false_negative"]) for row in reconciled_links
        ),
        "source_admission_proposal_count": len(source_proposals),
        "source_admission_proposals": source_proposals,
        "currentness_metadata_only_sources": [
            {
                "authority_identity_id": "neutral-citation:[2025] EWHC 2863 (Ch)",
                "affected_row_ids": ["live30-q30:issue-16"],
                "treatment_relationship": (
                    "LATER_SAME_CASE_CONFIRMS_SUCCESSFUL_REPRESENTATIVE_CLAIM_"
                    "CHALLENGE_AND_CHANGED_PROCEDURAL_ROUTE"
                ),
                "exact_span": getty_later_treatment,
                "candidate_source_admission_recommended": False,
                "owner_currentness_decision_required": True,
            }
        ],
        "existing_candidate_binding_count": 1,
        "reconciled_links": reconciled_links,
        "same_adapter_review_used_as_gate": False,
        "independent_reranker_used_as_qualification_threshold": False,
        "owner_decisions_applied": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    if any(artifact_material[field] is not False for field in _BOUNDARY_FIELDS):
        raise ValueError("phase2a_r110_boundary_invalid")
    artifact = {
        **artifact_material,
        "artifact_content_sha256": _sealed(artifact_material),
    }
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_r110_output_mode_invalid")
    _write_exclusive(output_root / OUTPUT_NAME, _pretty_json(artifact))
    _write_exclusive(
        output_root / "OUTCOME.txt",
        b"26 SOURCE LINKS RECONCILED; 5 SOURCE ADMISSIONS RECOMMENDED. "
        b"OWNER DIGEST APPROVAL REQUIRED. NOTHING ADMITTED, INDEXED, OR EMBEDDED.\n",
    )
    names = sorted(
        path.name
        for path in output_root.iterdir()
        if path.is_file() and path.name != "SHA256SUMS.txt"
    )
    sums = "".join(
        f"{_sha256_file(output_root / name)}  {name}\n" for name in names
    )
    _write_exclusive(output_root / "SHA256SUMS.txt", sums.encode("utf-8"))
    return artifact


def _persist_failure(output_root: Path, exc: BaseException) -> None:
    """Persist a fail-closed diagnostic before propagating a build failure."""

    try:
        output_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        path = output_root / "FAILURE.json"
        if path.exists() or path.is_symlink():
            return
        fingerprint_material = {
            "exception_type": type(exc).__name__,
            "error": str(exc),
            "affected_stage": "PHASE2A_POST_R109_SOURCE_CURRENTNESS_RECONCILIATION",
        }
        material = {
            "schema": "legalbot.v111.phase2a.post-r109-reconciliation-failure.v1",
            "failure_fingerprint": _sealed(fingerprint_material),
            **fingerprint_material,
            "affected_rows": "26_SOURCE_LINKS",
            "completed_work": "PRESERVED_BEFORE_EXCEPTION",
            "root_cause_status": "DEBUG_REQUIRED",
            "required_execution_plan_change": (
                "INSPECT_THE_PERSISTED_FAILURE_AND_INPUT_SEALS_BEFORE_RETRY"
            ),
            "owner_decisions_applied": False,
            "source_admission_authorized": False,
            "automatic_indexing": False,
            "automatic_embedding": False,
            "candidate_mutated": False,
            "technical_qualification_assigned": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        _write_exclusive(
            path,
            _pretty_json({**material, "failure_content_sha256": _sealed(material)}),
        )
    except Exception:
        # Diagnostic persistence must not replace the original exception.
        return


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    args = parser.parse_args(argv)
    output_root = args.output_root.resolve()
    try:
        artifact = build_reconciliation(output_root)
    except Exception as exc:
        _persist_failure(output_root, exc)
        raise
    print(
        json.dumps(
            {
                "artifact_content_sha256": artifact["artifact_content_sha256"],
                "row_source_link_count": artifact["row_source_link_count"],
                "recommendation_counts": artifact["recommendation_counts"],
                "source_admission_proposal_count": artifact[
                    "source_admission_proposal_count"
                ],
                "source_admission_authorized": False,
                "automatic_indexing": False,
                "automatic_embedding": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
