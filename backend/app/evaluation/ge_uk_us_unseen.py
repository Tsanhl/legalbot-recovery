"""Question-free UK/USA scope successor; pure functions, no bank or runtime IO.

Scope validation is a conservative authoring gate, not a legal/currentness review
or proof of semantic novelty. Authors must place the assigned location in the
question's facts (for example, ``My tenancy is in Wales``), not just its labels.
The original coverage module and its historical contracts remain independent.
"""

from __future__ import annotations

import re
import unicodedata
from collections import Counter
from collections.abc import Mapping, Sequence
from difflib import SequenceMatcher
from typing import Any

from .ge_everyday_unseen import DOMAIN_FAMILIES as _PREDECESSOR_DOMAINS
from .ge_everyday_unseen import SYSTEM_FAMILIES as _PREDECESSOR_SYSTEMS

__all__ = [
    "DOMAIN_FAMILIES",
    "SYSTEM_FAMILIES",
    "UK_JURISDICTIONS",
    "US_JURISDICTIONS",
    "UKUSScopeError",
    "coverage_slots",
    "scope_contract",
    "system_coverage_slots",
    "system_slots",
    "validate_author_scope",
]

UK_JURISDICTIONS = {
    "UK-ENG": "England", "UK-WLS": "Wales", "UK-SCT": "Scotland",
    "UK-NIR": "Northern Ireland",
}
# Alphabetical state cycle, followed by DC. These are geographic assignments,
# never a declaration that state law controls rather than federal law.
US_JURISDICTIONS = {
    "US-AL": "Alabama", "US-AK": "Alaska", "US-AZ": "Arizona", "US-AR": "Arkansas",
    "US-CA": "California", "US-CO": "Colorado", "US-CT": "Connecticut",
    "US-DE": "Delaware", "US-FL": "Florida", "US-GA": "Georgia", "US-HI": "Hawaii",
    "US-ID": "Idaho", "US-IL": "Illinois", "US-IN": "Indiana", "US-IA": "Iowa",
    "US-KS": "Kansas", "US-KY": "Kentucky", "US-LA": "Louisiana", "US-ME": "Maine",
    "US-MD": "Maryland", "US-MA": "Massachusetts", "US-MI": "Michigan",
    "US-MN": "Minnesota", "US-MS": "Mississippi", "US-MO": "Missouri",
    "US-MT": "Montana", "US-NE": "Nebraska", "US-NV": "Nevada",
    "US-NH": "New Hampshire", "US-NJ": "New Jersey", "US-NM": "New Mexico",
    "US-NY": "New York", "US-NC": "North Carolina", "US-ND": "North Dakota",
    "US-OH": "Ohio", "US-OK": "Oklahoma", "US-OR": "Oregon",
    "US-PA": "Pennsylvania", "US-RI": "Rhode Island", "US-SC": "South Carolina",
    "US-SD": "South Dakota", "US-TN": "Tennessee", "US-TX": "Texas", "US-UT": "Utah",
    "US-VT": "Vermont", "US-VA": "Virginia", "US-WA": "Washington",
    "US-WV": "West Virginia", "US-WI": "Wisconsin", "US-WY": "Wyoming",
    "US-DC": "Washington, DC",
}
_UK_ROTATION = ("UK-ENG", "UK-ENG", "UK-WLS", "UK-WLS", "UK-SCT", "UK-NIR")

# Retain topic identities except the explicitly renamed trade domain. Generalise
# England/Wales-only labels so all four UK assignments can be authored honestly.
_NEUTRAL_FAMILIES = {
    "post-exit-rights": "import-export-paperwork",
    "northern-ireland-scope": "border-arrangements",
    "nhs-complaints": "health-service-complaints",
    "england-wales-tenure": "housing-tenure",
    "england-wales-education-routes": "education-authority-routes",
    "council-tax": "local-household-tax",
    "council-service": "local-public-service",
    "grievance-and-tribunal": "employment-dispute-route",
}
DOMAIN_FAMILIES = {
    ("cross-border-trade-regulation" if domain == "eu-internal-market-law" else domain):
    tuple(_NEUTRAL_FAMILIES.get(family, family) for family in families)
    for domain, families in _PREDECESSOR_DOMAINS.items()
}
_US_FAMILIES = {
    "cross-border-trade-regulation": (
        "us-cross-border-goods", "us-cross-border-services", "us-import-export-paperwork",
        "us-border-and-customs-scope", "us-cross-border-consumers", "us-trade-regulatory-jurisdiction",
    ),
    "international-commercial-mediation": (
        "us-agreement-to-mediate", "us-mediator-impartiality", "us-mediation-confidentiality",
        "us-mediated-settlement-enforcement", "us-cross-border-mediated-settlement",
        "us-mediation-and-court-route",
    ),
    "pensions-law": (
        "workplace-retirement-plan-participation", "missing-retirement-contributions",
        "retirement-plan-benefits", "retirement-plan-rollover", "retirement-scam",
        "retirement-plan-complaint",
    ),
    "education-send": (
        "school-enrolment", "school-suspension-or-expulsion", "special-education-support",
        "school-discrimination", "college-dispute", "state-and-federal-education-routes",
    ),
    "social-care-mental-capacity": (
        "long-term-care-assessment", "care-funding-and-charges", "decision-making-capacity",
        "healthcare-proxy-and-power-of-attorney", "adult-protective-services",
        "guardianship-and-care-restrictions",
    ),
    "tax-personal-finance": (
        "federal-or-state-income-tax-decision", "tax-penalty-review", "local-property-tax",
        "self-employment-records", "estate-and-inheritance-tax-triage", "tax-debt-and-time-limits",
    ),
    "public-services-utilities": (
        "energy-billing", "water-service", "telecom-service", "municipal-service",
        "service-disconnection", "utility-provider-and-regulator-complaint",
    ),
}
_US_TERMS = {
    "enforcement-agents": "debt-enforcement-and-collection",
    "financial-ombudsman-route": "financial-provider-and-regulator-complaint",
    "redundancy": "layoff-and-job-loss",
    "package-holiday": "travel-package-dispute",
    "public-sector-equality": "public-agency-discrimination",
}

# Positional system IDs remain system:01 through system:23.
SYSTEM_FAMILIES = tuple(
    {11: "uk-devolved-jurisdiction-routing",
     12: "us-state-federal-and-deferred-jurisdiction-routing"}.get(number, family)
    for number, family in enumerate(_PREDECESSOR_SYSTEMS, 1)
)
_ROUTING_IDS = frozenset(("system:10", "system:11", "system:12"))


class UKUSScopeError(ValueError):
    """A draft or assignment fails the public UK/USA scope contract."""


def _jurisdiction(code: str) -> dict[str, str]:
    if code == "SYSTEM":
        return {"jurisdiction_code": code, "jurisdiction_name": "Unknown",
                "country": "SYSTEM", "location_name": "Unknown",
                "jurisdiction_instruction": "Ask for the missing jurisdiction; do not infer it from host location."}
    country = "UK" if code in UK_JURISDICTIONS else "USA"
    name = (UK_JURISDICTIONS if country == "UK" else US_JURISDICTIONS)[code]
    if country == "UK":
        instruction = (
            f"Explicitly locate a material part of the matter in {name} in the question's facts. "
            "Distinguish England, Wales, Scotland and Northern Ireland; assess relevant UK-wide "
            "and devolved law without assuming uniform rules. Keep a UK issue in cross-border cases."
        )
        if code in ("UK-ENG", "UK-WLS"):
            instruction += " England and Wales share a legal system; identify the nation for applicability."
    else:
        instruction = (
            f"Explicitly locate a material part of the matter in {name}, USA in the question's facts. "
            "Assess state/DC, local and federal law where applicable. A state location does not "
            "determine which law controls; no federal proposition is required in every case. "
            "Keep a US issue in cross-border cases."
        )
        if code == "US-WA":
            instruction += " Write Washington State or the state of Washington, distinct from Washington, DC."
        if code == "US-GA":
            instruction += " Identify the US state of Georgia, distinct from the country of Georgia."
    instruction += " Author an independently distinct scenario, not a country/location substitution."
    return {"jurisdiction_code": code, "jurisdiction_name": name, "country": country,
            "location_name": name, "jurisdiction_instruction": instruction}


def coverage_slots() -> list[dict[str, Any]]:
    """Return 420 fresh public assignments using the predecessor's slot keys/IDs.

    Each numbered family has one UK and one USA scenario. Alternating the country
    assigned to narrative/document yields three uploads per country per domain.
    UK locations rotate across family numbers; US assignments cycle all 51 places.
    """
    rows = []
    us_codes = tuple(US_JURISDICTIONS)
    for domain_index, (domain, families) in enumerate(DOMAIN_FAMILIES.items()):
        for family_index, family in enumerate(families):
            number = family_index + 1
            uk_code = _UK_ROTATION[(family_index + domain_index) % 6]
            us_code = us_codes[(domain_index * 6 + family_index) % len(us_codes)]
            for variant_index, variant in enumerate(("narrative", "document")):
                is_uk = variant_index == (domain_index + family_index) % 2
                local_family = family if is_uk else _US_FAMILIES.get(
                    domain, tuple(_US_TERMS.get(item, item) for item in families)
                )[family_index]
                rows.append({
                    "slot_id": f"{domain}:{number:02d}:{variant}", "domain": domain,
                    "family": local_family, "family_number": number, "variant": variant,
                    "synthetic_upload_required": variant == "document",
                    "multi_turn_required": number in (3, 6), "cross_issue_required": number == 6,
                    "private_case_created": False, "case_type": "legal", "jurisdiction_routing": False,
                    **_jurisdiction(uk_code if is_uk else us_code),
                })
    return rows


def system_slots() -> list[dict[str, Any]]:
    """Return the 23 separate behavior assignments, including three routing IDs.

    All nonrouting system cases still require an exact assigned location in their
    question, including malicious-upload/source and unsafe-request cases.
    """
    codes = ("UK-ENG", "US-CA", "UK-WLS", "US-NY", "UK-SCT", "US-WA", "UK-NIR", "US-DC")
    rows = []
    for number, family in enumerate(SYSTEM_FAMILIES, 1):
        slot_id = f"system:{number:02d}"
        code = {10: "SYSTEM", 11: "UK-ENG", 12: "US-WA"}.get(number, codes[(number - 1) % len(codes)])
        row = {"slot_id": slot_id, "domain": "SYSTEM", "family": family,
               "variant": "document" if number <= 7 else "narrative",
               "synthetic_upload_required": number <= 7,
               "multi_turn_required": number in (8, 20), "cross_issue_required": False,
               "private_case_created": False,
               "case_type": "system", "jurisdiction_routing": slot_id in _ROUTING_IDS,
               **_jurisdiction(code)}
        if number == 11:
            row["jurisdiction_instruction"] = (
                "Test distinguishing at least two of England, Wales, Scotland and Northern Ireland; "
                "do not assume one UK-wide legal route."
            )
        elif number == 12:
            row["jurisdiction_instruction"] = (
                "Test US state versus federal routing, or clarify/referral for territory, tribal "
                "or foreign law outside the initial scope. Distinguish Washington State from Washington, DC."
            )
        rows.append(row)
    return rows


def system_coverage_slots() -> list[dict[str, Any]]:
    """Descriptive alias for system_slots()."""
    return system_slots()


def scope_contract() -> dict[str, Any]:
    """Return a JSON-serialisable public scope specification, not a run receipt."""
    rows = coverage_slots()
    return {
        "schema": "legalbot.ge-uk-us-unseen-scope.v1", "countries": ["UK", "USA"],
        "language": "English", "legal_case_count": 420, "system_case_count": 23,
        "domain_count": 35, "cases_per_domain": 12, "families_per_domain": 6,
        "legal_cases_by_country": {"UK": 210, "USA": 210},
        "uk_cases_per_domain": {"UK-ENG": 2, "UK-WLS": 2, "UK-SCT": 1, "UK-NIR": 1},
        "jurisdiction_case_counts": dict(Counter(row["jurisdiction_code"] for row in rows)),
        "uk_jurisdictions": dict(UK_JURISDICTIONS), "us_locations": dict(US_JURISDICTIONS),
        "england_wales_applicability": "SHARED_LEGAL_SYSTEM_EXPLICIT_NATION_FOR_APPLICABILITY",
        "us_state_count": 50, "district_of_columbia_included": True,
        "us_cases_per_location_range": [4, 5],
        "minimum_upload_cases": 210, "minimum_multi_turn_cases": 140, "minimum_cross_issue_cases": 70,
        "coverage_by_country": {
            country: {"narrative": 105, "document": 105, "uploads": 105,
                      "followups": 70, "crossissues": 35} for country in ("UK", "USA")
        },
        "system_coverage": system_slots(),
        "system_routing_exemption_ids": sorted(_ROUTING_IDS),
        "pass_denominators": {"legal_factual": 420, "legal_quality": 420, "system": 23},
        "holds_and_errors_remain_in_denominator": True,
        "scenario_policy": "SCENARIO_FIRST_INDEPENDENT_UK_AND_US_SCENARIOS_PER_FAMILY",
        "source_before_case_construction": False,
        "federal_law_policy": "ASSESS_WHERE_APPLICABLE_LOCATION_DOES_NOT_DETERMINE_CONTROLLING_LAW",
        "federal_proposition_required_every_case": False,
        "deferred_scope": {
            "territories_and_dependencies": "CLARIFY_AND_REFER_SUBSTANTIVE_LAW_DEFERRED",
            "tribal_law": "CLARIFY_AND_REFER_SUBSTANTIVE_LAW_DEFERRED",
            "foreign_law": "REFER_OR_DEFER_RETAIN_EXPLICIT_UK_OR_US_ISSUE_IN_LEGAL_CASES",
            "non_english_languages": "SUPPORTED_LANGUAGE_OR_TRANSLATION_REFERRAL",
        },
        "coverage_limits": [
            "Finite experimental diagnostic; not all possible law or questions.",
            "Four to five cases per US location are not every domain in every state.",
            "English-language UK and 50 US states plus Washington, DC initial scope only.",
            "Location checks are conservative lexical checks; relevance, novelty and legal scope need preseal review.",
        ],
        "universal_correctness_claim": False, "professional_legal_sign_off": False,
        "training": "NOT_AUTHORIZED", "adapter": "INACTIVE_EXCLUDED",
        "retired_bank_access": "PROHIBITED", "artifact_kind": "PUBLIC_SCOPE_SPECIFICATION",
    }


def _normal(text: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


# Longest matches prevent West Virginia -> Virginia, Washington, DC -> Washington,
# and New England / New South Wales -> England / Wales. No two-letter abbreviations.
_LOCATION_CODES = {_normal(name): code for code, name in (UK_JURISDICTIONS | US_JURISDICTIONS).items()}
_LOCATION_CODES.update({"new england": "OUTSIDE", "new south wales": "OUTSIDE"})
_LOCATION_PATTERN = re.compile(
    r"(?<!\w)(?:" + "|".join(re.escape(name) for name in sorted(_LOCATION_CODES, key=len, reverse=True)) + r")(?!\w)"
)
_SPATIAL_PREFIX = re.compile(
    r"\b(?:in|within)\s+(?:the\s+)?(?:(?:(?:us|u\.s\.|united states)\s+)?state\s+of\s+)?"
    r"(?:upstate\s+)?"
    r"(?:[\w'-]+(?:\s+[\w'-]+){0,3},\s*)?$"
)
# 'Outside City, State' still names the state of the property/participant;
# 'outside State' does not. Keep the locality and comma mandatory.
_OUTSIDE_LOCALITY_PREFIX = re.compile(r"\boutside\s+[\w'-]+(?:\s+[\w'-]+){0,3},\s*$")
_POSSESSIVE_PREFIX = re.compile(r"\b(?:my|our|his|her|their|its|your)\s+$")
_HOME_DESTINATION_PREFIX = re.compile(
    r"\b(?:(?:flew|fly|flying|travelled|traveled|travel|returned|return|returning|"
    r"moved|move|moving|went|go|going|came|come|coming|drove|drive)\s+(?:back\s+)?"
    r"|(?:my|our)\s+(?:journey|trip)\s+)home\s+to\s+"
    r"(?:[\w'-]+(?:\s+[\w'-]+){0,3},\s*)?$"
)
_REFERENCE_NOUN = re.compile(r"\s+(?:law|legal|textbook|casebook|guide|citation|example|reference|code)\b")
_US_SUFFIX = re.compile(
    r",\s*(?:usa|us|united states|"
    + "|".join(re.escape(name.casefold()) for name in US_JURISDICTIONS.values()) + r")\b"
)
_UK_SUFFIX = re.compile(r",\s*(?:uk|united kingdom|england|wales|scotland|northern ireland)\b")


def _locations(question: str, *, relevant: bool) -> set[str]:
    text = _normal(question)
    found = set()
    for match in _LOCATION_PATTERN.finditer(text):
        code = _LOCATION_CODES[match.group()]
        if code == "OUTSIDE":
            continue
        before, after = text[:match.start()], text[match.end():]
        if (code in UK_JURISDICTIONS and _US_SUFFIX.match(after)) or (
            code in US_JURISDICTIONS and _UK_SUFFIX.match(after)
        ):
            continue
        # Explicit geographic qualifiers are mandatory for these ambiguous names.
        if code in ("US-WA", "US-GA") and not (
            re.search(r"\bstate of\s+$", before)
            or re.match(r"\s+state\b", after)
            or (code == "US-GA" and re.match(r",?\s+(?:usa|united states)\b", after))
        ):
            continue
        if relevant:
            prefix = (_SPATIAL_PREFIX.search(before) or _OUTSIDE_LOCALITY_PREFIX.search(before)
                      or _HOME_DESTINATION_PREFIX.search(before))
            if prefix is None and not _REFERENCE_NOUN.match(after):
                # Ordinary first-person facts such as 'my Michigan workshop'
                # explicitly locate a participant/property without using 'in'.
                prefix = _POSSESSIVE_PREFIX.search(before)
            if prefix is None:
                continue
            # Do not turn a negative, comparison or joint E&W label into a place.
            lead = before[max(0, prefix.start() - 40):prefix.start()]
            if re.search(r"\b(?:not|never)\b[^,;.!?]{0,32}$", lead) or re.search(
                r"\b(?:outside|rather than|instead of)\s+$", lead
            ):
                continue
            if code in UK_JURISDICTIONS and (
                re.match(r"\s*(?:and|or|/|&)\s*(?:england|wales|scotland|northern ireland)\b", after)
                or re.search(r"\b(?:england|wales|scotland|northern ireland)\s*(?:and|or|/|&)\s*$", before)
            ):
                continue
        found.add(code)
    return found


def _validate_routing(question: str, slot_id: str) -> None:
    text = _normal(question)
    if slot_id == "system:10":
        explicit_uncertainty = re.search(
            r"\b(?:which (?:jurisdiction|country|state)|"
            r"(?:jurisdiction|location|country|state) (?:is )?unknown|"
            r"unknown (?:jurisdiction|location|country|state))\b", text
        )
        # A personal fact plus a request can exercise missing-location routing
        # without legal vocabulary. Use raw location matches here so ambiguous
        # names (Washington/Georgia) cannot masquerade as an absent location.
        personal_fact = re.search(
            r"\b(?:(?:my|our)\s+\w+|(?:i|we)\s+(?:am|are|was|were|live|work|own|rent|have))\b", text
        )
        request = re.search(
            r"\b(?:what|where|how|which)\b|"
            r"\b(?:can|could|should|must|do|does|will|would|is|are)\s+(?:i|we|my|our|the)\b", text
        )
        valid = explicit_uncertainty or (
            not _LOCATION_PATTERN.search(text) and personal_fact and request
        )
    elif slot_id == "system:11":
        valid = len(_locations(question, relevant=False) & UK_JURISDICTIONS.keys()) >= 2
    else:
        state_federal = bool(_locations(question, relevant=False) & US_JURISDICTIONS.keys()) and (
            re.search(r"\bstate\b", text) and re.search(r"\bfederal\b", text)
        )
        # These are routing cues, not a finding about applicable law. Require a
        # relevant US fact, not a US name in a book or a negated location.
        foreign_party = re.search(
            r"\b(?:foreign|overseas)(?:-based)?\s+(?:employer|company|business|supplier)\b|"
            r"\b(?:employer|company|business|supplier)\s+(?:(?:is|was)\s+)?"
            r"(?:based|registered|located|headquartered)\s+"
            r"(?:abroad|overseas|outside\s+(?:the\s+)?(?:us|usa|united states))\b", text
        )
        named_base = re.search(
            r"\b(?:employer|company|business|supplier)\s+(?:(?:is|was)\s+)?"
            r"(?:based|registered|located|headquartered)\s+in\s+\w+", text
        )
        overseas_procedure = re.search(
            r"\b(?:complain|claim|file|start|bring|sue|proceed)\b[^.!?;]{0,60}\babroad\b", text
        )
        cross_border = bool(_locations(question, relevant=True) & US_JURISDICTIONS.keys()) and (
            foreign_party or (named_base and overseas_procedure)
        )
        deferred = re.search(
            r"\b(?:territory|territories|tribal|tribe|foreign|puerto rico|guam|american samoa|"
            r"northern mariana islands|us virgin islands)\b", text
        ) and re.search(r"\b(?:refer|referral|which jurisdiction|clarify|outside.*scope)\b", text)
        valid = state_federal or cross_border or deferred
    if not valid:
        raise UKUSScopeError("system routing question does not exercise its assigned routing boundary")


def _scenario_tokens(question: str) -> tuple[str, ...]:
    text = _LOCATION_PATTERN.sub(" location ", _normal(question))
    text = re.sub(r"\b(?:uk|usa|us|united kingdom|united states|state of|state)\b", " ", text)
    return tuple(re.findall(r"[^\W_]+", text))


def validate_author_scope(
    cases: Sequence[Mapping[str, Any]], slots: Sequence[Mapping[str, Any]]
) -> None:
    """Check an exact nonempty assigned batch (1..443); raise UKUSScopeError.

    Raw drafts require case_id/question and copy the exact slot
    jurisdiction_code into jurisdiction. jurisdiction_code is also accepted as an
    alias; if both are present both must match. Full-name jurisdiction labels are
    rejected. domain/family may be omitted until oracle enrichment: canonical slot
    identity binds them; if supplied they must match. Optional
    jurisdiction_name/country/location_name must agree. Optional
    slot metadata cannot override assignments. Slots must match canonical public
    assignments, so neither a case label nor edited slot can create an exemption.

    This supplements ge_codex_unseen_contracts.validate_cases: it does not inspect
    uploads, future turns, evidence or answers. Run both gates before preseal review.
    Relevance and independent authorship remain reviewer obligations; obvious
    location-only copies within the supplied batch are rejected mechanically.
    """
    if not isinstance(slots, list | tuple) or not 1 <= len(slots) <= 443:
        raise UKUSScopeError("slots must be a nonempty assigned batch of at most 443")
    if not isinstance(cases, list | tuple) or len(cases) != len(slots):
        raise UKUSScopeError("case count differs from assigned slots")
    canonical = {row["slot_id"]: row for row in coverage_slots() + system_slots()}
    assigned = {}
    for slot in slots:
        if not isinstance(slot, Mapping) or not isinstance(slot.get("slot_id"), str):
            raise UKUSScopeError("invalid assigned slot")
        slot_id = slot["slot_id"]
        expected = canonical.get(slot_id)
        if expected is None or slot_id in assigned:
            raise UKUSScopeError("unknown or duplicate assigned slot")
        for key, value in expected.items():
            if type(slot.get(key)) is not type(value) or slot.get(key) != value:
                raise UKUSScopeError(f"assigned slot changed canonical {key}")
        assigned[slot_id] = expected

    seen = set()
    scenarios: list[tuple[str, ...]] = []
    for case in cases:
        if not isinstance(case, Mapping) or not isinstance(case.get("case_id"), str):
            raise UKUSScopeError("invalid case_id")
        case_id = case["case_id"]
        if case_id not in assigned or case_id in seen:
            raise UKUSScopeError("unassigned or duplicate case_id")
        seen.add(case_id)
        slot = assigned[case_id]
        for key, value in slot.items():
            if key in case and (type(case[key]) is not type(value) or case[key] != value):
                raise UKUSScopeError(f"case changed assigned {key}")
        if not any(key in case for key in ("jurisdiction", "jurisdiction_code")):
            raise UKUSScopeError("case is missing assigned jurisdiction code")
        for key in ("jurisdiction", "jurisdiction_code"):
            if key in case and case[key] != slot["jurisdiction_code"]:
                raise UKUSScopeError(f"case changed assigned {key}")
        question = case.get("question")
        if not isinstance(question, str) or not question.strip():
            raise UKUSScopeError("question must be nonblank text")
        if case_id in _ROUTING_IDS:
            _validate_routing(question, case_id)
        elif slot["jurisdiction_code"] not in _locations(question, relevant=True):
            raise UKUSScopeError("question lacks an explicit relevant assigned location")
        if slot["case_type"] == "legal":
            tokens = _scenario_tokens(question)
            for other in scenarios:
                if tokens == other or (min(len(tokens), len(other)) >= 12 and
                        SequenceMatcher(None, tokens, other, autojunk=False).ratio() >= 0.94):
                    raise UKUSScopeError("scenario is a location-only copy or lightly duplicated question")
            scenarios.append(tokens)
