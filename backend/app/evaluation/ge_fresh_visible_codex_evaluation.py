"""Fresh visible base-versus-Codex evaluation after bounded answer repair.

This campaign tests a non-weight Codex evidence-bound answer route on new
questions and official locators. It keeps the private unseen bank sealed and
cannot activate the r2 adapter, create legal gold, or stand in for professional
legal review.
"""

from __future__ import annotations

import hashlib
import json
import statistics
from collections import Counter
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .ge_currentness_packets import PROJECT_ROOT, load_jsonl, sha256_file, sha256_text
from .ge_fresh_visible_adapter_evaluation import (
    Fetch,
    SourceSpec,
    _default_fetch,
    _parse_source,
)
from .ge_visible_answer_repair import surface_guard
from .ge_visible_harness import FACTUAL_CHECKS, QUALITY_CRITICAL_FLOORS, QUALITY_DIMENSION_MAX

CAMPAIGN_ID = "LegalBot-GE-2026-09-04-fresh-visible-codex-evaluation-r1"
CAMPAIGN_VERSION = "legalbot.ge-fresh-visible-codex-evaluation.v1"
DEFAULT_OUTPUT = PROJECT_ROOT / "data/evaluations/general-enquiries" / CAMPAIGN_ID
REPAIR_ROOT = (
    PROJECT_ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-04-visible-answer-repair-r1"
)
TRAINING_ROOT = (
    PROJECT_ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-04-answer-weight-training-r2"
)
SOURCE_REVIEW_ROOT = (
    PROJECT_ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-04-ai-auto-quality-review-r1"
)
PRIOR_VISIBLE_ROOT = (
    PROJECT_ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-04-fresh-visible-adapter-evaluation-r2"
)
EXPECTED_REPAIR_STATE_SHA256 = "0249fab59f2ebd9ec04d65e0da3e7d9ffb755333a6027c5d177ec7689fa82bd4"
EXPECTED_PRIVATE_CUSTODY_LEDGER_SHA256 = (
    "11f42c7fcd83dbb0299db31917663044515a574705472921e06fcc1e469af7b2"
)
OWNER_AUTHORIZATION_TEXT = (
    "Repair the 15 nonready visible answers: truncation, omissions, unsupported "
    "additions, arithmetic/logic errors, and the EU regression. Run changed-answer "
    "checks and another fresh visible evaluation. Consider one-pass unseen testing "
    "only after 23/23 factual and 70+/floor passes with no regressions."
)
SYSTEM_PROMPT = (
    "You are LegalBot's General Enquiry answer model for England and Wales. "
    "Use only the official evidence supplied with the question. Give a direct, "
    "complete plain-English answer. Separate law from unverified facts, state all "
    "material conditions and limits, and give a safe practical next step. Do not "
    "invent authority, remedies, deadlines, amounts, facts or professional sign-off. "
    "Name each supplied source and locator in ordinary prose. Return only the "
    "finished answer, without planning notes or source-dump language."
)
REGRESSION_CHECKS = (
    "truncation",
    "required_point_omission",
    "unsupported_addition",
    "arithmetic_or_logic_error",
    "eu_rule_regression",
)


class FreshVisibleCodexError(ValueError):
    """The fresh visible Codex route or its evidence is invalid."""


@dataclass(frozen=True, slots=True)
class CaseSpec:
    case_id: str
    topic: str
    coverage_kind: str
    question: str
    source_keys: tuple[str, ...]
    required_points: tuple[str, ...]
    material_limits: tuple[str, ...]
    prohibited_overclaims: tuple[str, ...]


SOURCES: tuple[SourceSpec, ...] = (
    SourceSpec(
        "foia10",
        "Freedom of Information Act 2000",
        "ukpga/2000/36/section/10",
        "section 10",
        tuple(range(1, 16)),
    ),
    SourceSpec(
        "ukgdpr22a",
        "Regulation (EU) 2016/679 of the European Parliament and of the Council of 27 April 2016 on the protection of natural persons with regard to the processing of personal data and on the free movement of such data (United Kingdom General Data Protection Regulation) (Text with EEA relevance)",
        "eur/2016/679/article/22A",
        "Article 22A",
        tuple(range(1, 7)),
    ),
    SourceSpec(
        "llp1",
        "Limited Liability Partnerships Act 2000",
        "ukpga/2000/12/section/1",
        "section 1",
        tuple(range(1, 10)),
    ),
    SourceSpec(
        "car17",
        "The Commercial Agents (Council Directive) Regulations 1993",
        "uksi/1993/3053/regulation/17",
        "regulation 17",
        tuple(range(1, 14)),
    ),
    SourceSpec(
        "enterprise188",
        "Enterprise Act 2002",
        "ukpga/2002/40/section/188",
        "section 188",
        tuple(range(1, 20)),
    ),
    SourceSpec(
        "hta1",
        "Human Tissue Act 2004",
        "ukpga/2004/30/section/1",
        "section 1",
        (1, 5, 28, 29, 30, 34, 35, 36),
    ),
    SourceSpec(
        "frustrated1",
        "Law Reform (Frustrated Contracts) Act 1943",
        "ukpga/1943/40/section/1",
        "section 1",
        tuple(range(1, 10)),
    ),
    SourceSpec("theft1", "Theft Act 1968", "ukpga/1968/60/section/1", "section 1", (1, 2, 3)),
    SourceSpec(
        "ukima2",
        "United Kingdom Internal Market Act 2020",
        "ukpga/2020/27/section/2",
        "section 2",
        tuple(range(1, 8)),
    ),
    SourceSpec(
        "arbitration2025_1",
        "Arbitration Act 2025",
        "ukpga/2025/4/section/1",
        "section 1",
        tuple(range(1, 13)),
    ),
    SourceSpec(
        "lra27",
        "Land Registration Act 2002",
        "ukpga/2002/9/section/27",
        "section 27",
        tuple(range(1, 27)),
    ),
    SourceSpec(
        "mha2", "Mental Health Act 1983", "ukpga/1983/20/section/2", "section 2", tuple(range(1, 7))
    ),
    SourceSpec(
        "pensions2014_1", "Pensions Act 2014", "ukpga/2014/19/section/1", "section 1", (1, 2)
    ),
    SourceSpec(
        "cjja32",
        "Civil Jurisdiction and Judgments Act 1982",
        "ukpga/1982/27/section/32",
        "section 32",
        tuple(range(1, 10)),
    ),
    SourceSpec(
        "ola2",
        "Occupiers’ Liability Act 1957",
        "ukpga/1957/31/section/2",
        "section 2",
        tuple(range(1, 11)),
    ),
    SourceSpec(
        "tolata6",
        "Trusts of Land and Appointment of Trustees Act 1996",
        "ukpga/1996/47/section/6",
        "section 6",
        tuple(range(1, 12)),
    ),
    SourceSpec(
        "pda1",
        "Presumption of Death Act 2013",
        "ukpga/2013/13/section/1",
        "section 1",
        tuple(range(1, 16)),
    ),
    SourceSpec(
        "pea3",
        "Protection from Eviction Act 1977",
        "ukpga/1977/43/section/3",
        "section 3",
        tuple(range(1, 16)),
    ),
    SourceSpec(
        "wtr13",
        "The Working Time Regulations 1998",
        "uksi/1998/1833/regulation/13",
        "regulation 13",
        (1, 2, 3, 4, 16, 17, 18),
    ),
    SourceSpec(
        "mca1973_25",
        "Matrimonial Causes Act 1973",
        "ukpga/1973/18/section/25",
        "section 25",
        tuple(range(1, 11)),
    ),
    SourceSpec(
        "bna1", "British Nationality Act 1981", "ukpga/1981/61/section/1", "section 1", (1, 2, 3, 4)
    ),
    SourceSpec(
        "cca87",
        "Consumer Credit Act 1974",
        "ukpga/1974/39/section/87",
        "section 87",
        tuple(range(1, 12)),
    ),
    SourceSpec(
        "ptr15",
        "The Package Travel and Linked Travel Arrangements Regulations 2018",
        "uksi/2018/634/regulation/15",
        "regulation 15",
        tuple(range(1, 15)),
    ),
)

CASES: tuple[CaseSpec, ...] = (
    CaseSpec(
        "administrative-law:fv-r2-01",
        "administrative-law",
        "LEGAL_TOPIC",
        "I sent a valid freedom-of-information request to a public authority. What ordinary response period does Freedom of Information Act 2000 section 10 require?",
        ("foia10",),
        (
            "The authority must comply promptly and ordinarily no later than the twentieth working day after receipt.",
            "The fees-notice period described in section 10 is disregarded when the fee is paid under section 9(2).",
            "The section contains a reasonable-time qualification for the stated public-interest conditions and defines receipt and working day.",
        ),
        ("Validity, section 1(3), fees and any section 2 public-interest issue must be checked.",),
        (
            "Twenty calendar days always applies.",
            "The section guarantees disclosure rather than a response under section 1(1).",
        ),
    ),
    CaseSpec(
        "ai-and-data-protection:fv-r2-01",
        "ai-and-data-protection",
        "LEGAL_TOPIC",
        "A lender says a person briefly glanced at an algorithmic score before the system refused my loan. What does UK GDPR Article 22A say counts as solely automated and significant?",
        ("ukgdpr22a",),
        (
            "Solely automated means no meaningful human involvement in taking the decision.",
            "A significant decision produces a legal or similarly significant effect for the data subject.",
            "The extent to which profiling reaches the decision is relevant to meaningful human involvement.",
        ),
        (
            "The excerpt defines terms for Articles 22B and 22C but does not decide whether the glance was meaningful or whether the refusal was lawful.",
        ),
        (
            "Any human glance is necessarily meaningful involvement.",
            "Article 22A alone proves compensation or unlawfulness.",
        ),
    ),
    CaseSpec(
        "business-and-company-law:fv-r2-01",
        "business-and-company-law",
        "LEGAL_TOPIC",
        "Is an English limited liability partnership legally separate from its members, and does it have limited business capacity?",
        ("llp1",),
        (
            "An LLP is a body corporate with legal personality separate from its members once incorporated under the Act.",
            "An LLP has unlimited capacity.",
            "Member contribution liability on winding up and other statutory exceptions remain governed by the Act.",
        ),
        ("The provision does not decide liability for a particular debt or misconduct.",),
        (
            "Unlimited capacity means members have unlimited personal liability.",
            "Every ordinary partnership rule applies to an LLP.",
        ),
    ),
    CaseSpec(
        "commercial-law:fv-r2-01",
        "commercial-law",
        "LEGAL_TOPIC",
        "My commercial agency contract is silent about indemnity or compensation and has ended. What does regulation 17 ordinarily provide, and is notice required?",
        ("car17",),
        (
            "Regulation 17 provides post-termination indemnity or compensation under its conditions.",
            "If the contract does not otherwise provide, compensation rather than indemnity is the default.",
            "Entitlement is lost if the agent does not notify the principal within one year after termination that it intends to pursue it.",
        ),
        (
            "Commercial-agent status, regulation 18 and the factual basis and amount remain unresolved.",
        ),
        (
            "Payment is automatic in a fixed amount.",
            "The one-year provision is stated as a court filing deadline.",
        ),
    ),
    CaseSpec(
        "competition-law:fv-r2-01",
        "competition-law",
        "LEGAL_TOPIC",
        "An individual agrees that two competing undertakings will fix their UK selling prices. Does Enterprise Act 2002 section 188 potentially describe a cartel-offence arrangement?",
        ("enterprise188",),
        (
            "Section 188 addresses an individual agreeing to make or implement specified arrangements concerning at least two undertakings.",
            "Direct or indirect UK price fixing is one listed arrangement when the statutory conditions are met.",
            "Section 188 is expressly subject to section 188A.",
        ),
        (
            "The excerpt does not establish every element, section 188A, section 189, defences or guilt.",
        ),
        (
            "Any price discussion automatically proves guilt.",
            "The Chapter I civil prohibition and criminal offence are interchangeable.",
        ),
    ),
    CaseSpec(
        "contemporary-biolaw-and-regulation:fv-r2-01",
        "contemporary-biolaw-and-regulation",
        "LEGAL_TOPIC",
        "A researcher has ethical approval to store living-person tissue for health research but holds the code that identifies the donor. Does Human Tissue Act 2004 section 1 show that ethical approval alone removes the consent requirement?",
        ("hta1",),
        (
            "Section 1 ordinarily makes the relevant storage lawful with appropriate consent.",
            "The living-person research exception requires ethical approval and circumstances in which the researcher neither possesses nor is likely to possess identifying information.",
            "Ethical approval alone is therefore insufficient on the stated identifying-code fact.",
        ),
        (
            "The Schedule 1 purpose, coding facts, other exceptions and wider licensing rules must be checked.",
        ),
        (
            "All ethically approved research is consent-free.",
            "Holding coded tissue can never involve identifying information.",
        ),
    ),
    CaseSpec(
        "contract-law:fv-r2-01",
        "contract-law",
        "LEGAL_TOPIC",
        "An English-law event contract was frustrated after I paid in advance. What does Law Reform (Frustrated Contracts) Act 1943 section 1 generally do with money paid and expenses?",
        ("frustrated1",),
        (
            "For a qualifying frustrated English-law contract, money already paid is recoverable and money payable before discharge ceases to be payable.",
            "The court may permit retention or recovery for pre-discharge expenses up to the statutory limit when just.",
            "A just sum may be recoverable for a non-money valuable benefit, subject to the section's conditions.",
        ),
        ("Frustration, section 2, expenses, benefits and insurance facts are unresolved.",),
        (
            "Every payment must be repaid in full regardless of expenses.",
            "The extract proves that the contract was frustrated.",
        ),
    ),
    CaseSpec(
        "criminal-law:fv-r2-01",
        "criminal-law",
        "LEGAL_TOPIC",
        "Someone took another person's phone intending never to return it. What elements does Theft Act 1968 section 1 require before that conduct is theft?",
        ("theft1",),
        (
            "Theft requires dishonest appropriation of property belonging to another with intent permanently to deprive.",
            "Gain or personal benefit is immaterial under section 1(2).",
            "Sections 2 to 6 govern interpretation and operation of the elements.",
        ),
        ("The facts and the statutory meanings in sections 2 to 6 must be proved.",),
        ("Taking alone is necessarily theft.", "The section establishes guilt on the short facts."),
    ),
    CaseSpec(
        "eu-internal-market-law:fv-r2-01",
        "eu-internal-market-law",
        "LEGAL_TOPIC",
        "Goods can lawfully be sold in one part of the UK. What basic mutual-recognition rule does United Kingdom Internal Market Act 2020 section 2 state for sale in another part?",
        ("ukima2",),
        (
            "The principle concerns goods produced in or imported into an originating UK part and lawfully saleable there under relevant requirements.",
            "Where the principle applies, relevant requirements in the other part do not apply to the sale.",
            "A particular method of sale must also be lawful in the originating part under the section's rule.",
        ),
        (
            "Whether the goods, sale and requirement qualify, and exclusions elsewhere in the Act, are not established.",
        ),
        (
            "All rules in the destination part are disapplied.",
            "EU free-movement law is the stated source of the rule.",
        ),
    ),
    CaseSpec(
        "international-commercial-mediation:fv-r2-01",
        "international-commercial-mediation",
        "LEGAL_TOPIC",
        "A cross-border contract chooses French law for the main contract, says nothing expressly about the arbitration agreement's law, and chooses London as the arbitral seat. What default does Arbitration Act 2025 section 1 state?",
        ("arbitration2025_1",),
        (
            "The law expressly chosen for the arbitration agreement applies.",
            "Without that express choice, the law of the arbitral seat applies.",
            "A choice of law for the wider contract alone is not an express choice for the arbitration agreement.",
        ),
        (
            "Commencement, transitional application, treaty exceptions and the exact clause must be checked.",
        ),
        (
            "French law necessarily governs the arbitration agreement.",
            "The provision decides validity or the result of arbitration.",
        ),
    ),
    CaseSpec(
        "land-law:fv-r2-01",
        "land-law",
        "LEGAL_TOPIC",
        "I signed a transfer of a registered English estate but registration is still pending. Does Land Registration Act 2002 section 27 say the transfer already operates at law?",
        ("lra27",),
        (
            "A registrable disposition of a registered estate does not operate at law until the registration requirements are met.",
            "A transfer is listed as requiring completion by registration.",
            "Section 27 contains specified exceptions and Schedule 2 supplies the registration requirements.",
        ),
        ("The estate, disposition, application and any exception must be checked.",),
        (
            "Signing alone completes the legal transfer.",
            "The section determines every equitable consequence while registration is pending.",
        ),
    ),
    CaseSpec(
        "law-and-medicine:fv-r2-01",
        "law-and-medicine",
        "LEGAL_TOPIC",
        "Can a patient be detained for assessment under Mental Health Act 1983 section 2 merely because one doctor thinks assessment would be useful?",
        ("mha2",),
        (
            "Section 2 requires mental disorder of a nature or degree warranting detention for assessment or assessment followed by treatment for a limited period.",
            "Detention must also be justified by the patient's health or safety or protection of others.",
            "The application requires prescribed written recommendations from two registered medical practitioners and ordinarily permits no more than 28 days under section 2.",
        ),
        (
            "The wider application procedure, section 29(4), later authority and facts are outside the excerpt.",
        ),
        ("One doctor's view alone satisfies section 2.", "Section 2 permits indefinite detention."),
    ),
    CaseSpec(
        "pensions-law:fv-r2-01",
        "pensions-law",
        "LEGAL_TOPIC",
        "I reached pensionable age in 2015. Does Pensions Act 2014 section 1 make me entitled to the new state pension created by Part 1?",
        ("pensions2014_1",),
        (
            "Part 1 creates the benefit called state pension.",
            "A person reaching pensionable age before 6 April 2016 is not entitled under Part 1.",
            "The provision says similar benefits may instead be available under Part 2 of the Contributions and Benefits Act.",
        ),
        (
            "Actual entitlement and amount under the alternative regime require further facts and provisions.",
        ),
        (
            "Reaching pensionable age in 2015 qualifies for the Part 1 benefit.",
            "The section proves no state-pension entitlement of any kind.",
        ),
    ),
    CaseSpec(
        "private-international-law:fv-r2-01",
        "private-international-law",
        "LEGAL_TOPIC",
        "A foreign court gave judgment after proceedings brought contrary to our agreement to litigate elsewhere. I did not agree, counterclaim or otherwise submit. What rule does Civil Jurisdiction and Judgments Act 1982 section 32 state?",
        ("cjja32",),
        (
            "Subject to section 32, the judgment is not recognised or enforced when proceedings breached the dispute-resolution agreement and the resisting person neither brought or agreed to them nor submitted.",
            "The rule does not apply if the agreement was illegal, void, unenforceable or incapable of performance for reasons not attributable to the claimant's fault.",
            "The section preserves judgments requiring recognition under the listed Conventions and enactments.",
        ),
        (
            "The agreement, proceedings, Convention routes and all statutory conditions require verification.",
        ),
        (
            "Every foreign judgment contrary to any clause is automatically void.",
            "The foreign court's view conclusively binds the UK court on section 32 matters.",
        ),
    ),
    CaseSpec(
        "tort-law:fv-r2-01",
        "tort-law",
        "LEGAL_TOPIC",
        "A shop displayed a warning about a floor hazard, but the warning did not enable visitors to avoid it safely. Does the warning automatically discharge the occupier's duty?",
        ("ola2",),
        (
            "The common duty is reasonable care in all circumstances to make the visitor reasonably safe for the permitted purpose.",
            "A warning does not by itself absolve the occupier unless it was enough in all circumstances to make the visitor reasonably safe.",
            "The visitor, hazard, accepted risk and all circumstances remain relevant.",
        ),
        (
            "Occupier status, visitor status, breach, causation, damage and any exclusion remain unresolved.",
        ),
        (
            "Any warning is a complete defence.",
            "An accident automatically proves breach and damages.",
        ),
    ),
    CaseSpec(
        "trusts-law:fv-r2-01",
        "trusts-law",
        "LEGAL_TOPIC",
        "Do trustees of land have exactly the powers of an absolute owner, free from beneficiaries' rights and other legal restrictions?",
        ("tolata6",),
        (
            "For their trustee functions, trustees of land have the powers of an absolute owner in relation to the trust land.",
            "They must have regard to beneficiaries' rights and cannot contravene other enactments, court orders, law or equity.",
            "Other statutory restrictions remain effective and the Trustee Act 2000 duty of care applies.",
        ),
        (
            "The trust instrument, beneficiaries, proposed transaction and other restrictions must be checked.",
        ),
        (
            "The powers are personal beneficial ownership.",
            "Trustees may ignore beneficiaries and all other legal limits.",
        ),
    ),
    CaseSpec(
        "wills-and-estates:fv-r2-01",
        "wills-and-estates",
        "LEGAL_TOPIC",
        "My sibling has been missing and not known to be alive for eight years. Does Presumption of Death Act 2013 section 1 permit an application to the High Court for a declaration?",
        ("pda1",),
        (
            "Section 1 applies where the missing person is thought to have died or has not been known alive for at least seven years.",
            "Any person may apply to the High Court for a declaration, subject to the section's jurisdiction and sufficient-interest rules.",
            "An eight-year absence satisfies the stated time limb, but domicile, habitual residence or spouse/civil-partner jurisdiction must still be shown.",
        ),
        (
            "The evidence of absence, jurisdiction, sufficient interest and section 21(2) remain to be checked.",
        ),
        (
            "Seven years makes death automatic without a court declaration.",
            "Any applicant always has sufficient interest and jurisdiction.",
        ),
    ),
    CaseSpec(
        "housing:fv-r2-01",
        "housing",
        "PUBLIC_ACCESS_DOMAIN",
        "My non-excluded residential tenancy has ended, but I still live in the home. Can the owner lawfully recover possession without court proceedings?",
        ("pea3",),
        (
            "For the stated qualifying former tenancy, the owner cannot enforce recovery of possession otherwise than through court proceedings while the occupier remains resident.",
            "Section 3 extends with modifications to specified residential licences other than excluded licences.",
            "Statutorily protected and excluded arrangements and the other stated limits must be considered.",
        ),
        (
            "The tenancy or licence classification and all possession facts require urgent verification.",
        ),
        (
            "Every occupier in every arrangement is covered.",
            "The section decides the merits or timing of a possession order.",
        ),
    ),
    CaseSpec(
        "employment:fv-r2-01",
        "employment",
        "PUBLIC_ACCESS_DOMAIN",
        "My employment continues and my employer wants to replace the four weeks of annual leave under Working Time Regulations 1998 regulation 13 with extra pay. Is that ordinarily allowed?",
        ("wtr13",),
        (
            "For a worker to whom regulation 13 applies, the regulation provides four weeks' annual leave in each leave year.",
            "The leave may be taken in instalments but ordinarily only in its leave year, subject to the stated exceptions.",
            "It may not be replaced by payment in lieu except when employment terminates.",
        ),
        (
            "Worker status, regulation 15B, the leave year, carry-over exceptions and other leave entitlements must be checked.",
        ),
        (
            "Extra pay may routinely replace the statutory leave during employment.",
            "Regulation 13 establishes every annual-leave entitlement and pay calculation.",
        ),
    ),
    CaseSpec(
        "family:fv-r2-01",
        "family",
        "PUBLIC_ACCESS_DOMAIN",
        "On divorce, does Matrimonial Causes Act 1973 section 25 require the court to divide all assets equally without considering anything else?",
        ("mca1973_25",),
        (
            "The court must consider all the circumstances and give first consideration to the welfare of a minor child of the family.",
            "The listed factors include resources, needs, living standard, age, marriage duration, disability, contributions, qualifying conduct and lost benefits.",
            "Section 25 does not state an automatic equal-division rule.",
        ),
        (
            "The assets, needs, children, contributions, orders sought and other law must be assessed.",
        ),
        (
            "Equal division is mandatory on every divorce.",
            "A single factor automatically determines the order.",
        ),
    ),
    CaseSpec(
        "immigration:fv-r2-01",
        "immigration",
        "PUBLIC_ACCESS_DOMAIN",
        "A child was born in the UK after the British Nationality Act 1981 commenced, but neither parent was British, settled or in the armed forces at the birth. Does UK birth alone confer citizenship under section 1(1) or (1A)?",
        ("bna1",),
        (
            "Post-commencement UK birth confers citizenship under section 1(1) if a parent was British or settled at birth.",
            "The armed-forces birth rule applies where a parent was a member of the armed forces at birth.",
            "On the stated facts, UK birth alone does not satisfy those automatic routes.",
        ),
        (
            "Other registration, adoption, statelessness and later-parent routes are outside the selected excerpt.",
        ),
        (
            "Every UK-born child is automatically British.",
            "The answer rules out every other route to citizenship.",
        ),
    ),
    CaseSpec(
        "benefits-and-debt:fv-r2-01",
        "benefits-and-debt",
        "PUBLIC_ACCESS_DOMAIN",
        "I missed payments under a regulated consumer-credit agreement. Before terminating for that breach or demanding earlier payment, does Consumer Credit Act 1974 section 87 generally require a default notice?",
        ("cca87",),
        (
            "A section 88-compliant default notice is generally necessary before the creditor becomes entitled by reason of breach to take the listed enforcement steps.",
            "The listed steps include termination, accelerated payment, recovery of goods or land, restriction of rights and enforcement of security.",
            "Section 87 contains stated exceptions, including regulatory exceptions and a deferred-payment-credit exclusion.",
        ),
        (
            "Agreement regulation, breach, notice compliance, cure and every exception must be checked.",
        ),
        (
            "Any missed payment permits immediate termination.",
            "A default notice guarantees that later enforcement succeeds.",
        ),
    ),
    CaseSpec(
        "consumer:fv-r2-01",
        "consumer",
        "PUBLIC_ACCESS_DOMAIN",
        "A hotel included in my package holiday did not provide the booked room. Can the organiser say only the hotel is responsible, and what immediate steps does regulation 15 contemplate?",
        ("ptr15",),
        (
            "The organiser is liable for performance of package travel services regardless of whether another provider performs them.",
            "The traveller must report perceived lack of conformity without undue delay, and the organiser generally must remedy it within a reasonable period set by the traveller.",
            "No period is required where the organiser refuses or immediate remedy is needed; the traveller may remedy and recover necessary expenses, subject to the regulation.",
        ),
        (
            "Package status, conformity, notice, possibility, proportionality, expenses and regulation 16 remain fact dependent.",
        ),
        (
            "Only the hotel can be liable.",
            "Every inconvenience guarantees termination and compensation.",
        ),
    ),
)


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _sealed(payload: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(payload)
    result["content_sha256"] = hashlib.sha256(_canonical_json(result)).hexdigest()
    return result


def _write_json_create(path: Path, payload: Mapping[str, Any]) -> None:
    with path.open("x", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


def _write_jsonl_create(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    with path.open("x", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _validate_static_contract() -> None:
    if len(SOURCES) != 23 or len({source.key for source in SOURCES}) != 23:
        raise FreshVisibleCodexError("expected 23 unique official locator sources")
    if len(CASES) != 23 or len({case.case_id for case in CASES}) != 23:
        raise FreshVisibleCodexError("expected 23 unique fresh visible cases")
    if len({case.topic for case in CASES}) != 23:
        raise FreshVisibleCodexError("fresh visible topics must be unique")
    if Counter(case.coverage_kind for case in CASES) != {
        "LEGAL_TOPIC": 17,
        "PUBLIC_ACCESS_DOMAIN": 6,
    }:
        raise FreshVisibleCodexError("expected 17 legal and six public-access cases")
    keys = {source.key for source in SOURCES}
    if any(not set(case.source_keys) <= keys for case in CASES):
        raise FreshVisibleCodexError("case references an unknown source")


def prepare_campaign(
    output: Path = DEFAULT_OUTPUT, *, fetch: Fetch = _default_fetch
) -> dict[str, Any]:
    """Create the new visible questions and immutable official-source captures."""

    _validate_static_contract()
    if output.exists():
        raise FreshVisibleCodexError(f"refusing to replace campaign: {output}")
    repair_state_path = REPAIR_ROOT / "STATE-TRANSITION-RECEIPT.json"
    if sha256_file(repair_state_path) != EXPECTED_REPAIR_STATE_SHA256:
        raise FreshVisibleCodexError("visible repair state identity changed")
    repair_state = json.loads(repair_state_path.read_text(encoding="utf-8"))
    if (
        repair_state.get("overall_state")
        != "VISIBLE_REPAIR_COMPLETE_AWAITING_NEW_FRESH_VISIBLE_EVALUATION"
        or repair_state.get("private_306_bank") != "SEALED_NOT_OPENED"
    ):
        raise FreshVisibleCodexError("visible repair predecessor is not ready and sealed")

    training_records = load_jsonl(TRAINING_ROOT / "TRAINING-RECORDS.jsonl")
    training_question_hashes = {str(row["question_hash"]) for row in training_records}
    training_answer_hashes = {str(row["target_answer_hash"]) for row in training_records}
    held_review = [
        row
        for row in load_jsonl(SOURCE_REVIEW_ROOT / "AI-AUTO-REVIEW.jsonl")
        if row.get("ai_auto_decision") != "AI_ACCEPT"
    ]
    held_routes = load_jsonl(SOURCE_REVIEW_ROOT / "AI-HOLD-ROUTING.jsonl")
    held_question_hashes = {str(row["question_hash"]) for row in held_review}
    held_answer_hashes = {str(row["candidate_answer_hash"]) for row in held_routes}
    held_case_ids = {str(row["case_id"]) for row in held_routes}
    if len(training_records) != 13 or len(held_review) != 7 or len(held_routes) != 7:
        raise FreshVisibleCodexError("predecessor training or hold counts changed")
    leakage = json.loads((TRAINING_ROOT / "LEAKAGE-REPORT.json").read_text(encoding="utf-8"))
    if (
        leakage.get("private_unseen_prompt_content_accessed") is not False
        or leakage.get("private_unseen_custody_ledger_sha256")
        != EXPECTED_PRIVATE_CUSTODY_LEDGER_SHA256
    ):
        raise FreshVisibleCodexError("private unseen custody changed")
    training_titles = {
        title for titles in leakage["source_titles_by_split"].values() for title in titles
    }
    prior_visible_titles = {
        str(row["title"])
        for row in load_jsonl(PRIOR_VISIBLE_ROOT / "OFFICIAL-SOURCE-MANIFEST.jsonl")
    }
    fresh_titles = {source.title for source in SOURCES}
    if overlap := fresh_titles & (training_titles | prior_visible_titles):
        raise FreshVisibleCodexError(f"fresh source title overlap: {sorted(overlap)}")

    output.mkdir(parents=True, exist_ok=False)
    snapshots = output / "official-source-snapshots"
    snapshots.mkdir()

    def capture(source: SourceSpec) -> tuple[dict[str, Any], bytes]:
        body, headers, final_url = fetch(source.url)
        return _parse_source(source, body, headers, final_url), body

    with ThreadPoolExecutor(max_workers=6) as executor:
        captured = list(executor.map(capture, SOURCES))
    sources: list[dict[str, Any]] = []
    for row, body in captured:
        with (output / row["snapshot_path"]).open("xb") as handle:
            handle.write(body)
        sources.append(row)
    source_by_key = {str(row["source_key"]): row for row in sources}

    cases: list[dict[str, Any]] = []
    inputs: list[dict[str, Any]] = []
    controls: list[dict[str, Any]] = []
    for ordinal, case in enumerate(CASES, 1):
        question_hash = sha256_text(case.question)
        if (
            question_hash in training_question_hashes
            or question_hash in held_question_hashes
            or case.case_id in held_case_ids
        ):
            raise FreshVisibleCodexError(f"fresh case overlaps predecessor: {case.case_id}")
        evidence = [source_by_key[key] for key in case.source_keys]
        evidence_refs = [
            {
                "source_key": row["source_key"],
                "title": row["title"],
                "locator": row["locator"],
                "evidence_span_sha256": row["evidence_span_sha256"],
                "raw_sha256": row["raw_sha256"],
            }
            for row in evidence
        ]
        prompt_parts = [f"Question:\n{case.question}", "Permitted official evidence:"]
        for index, row in enumerate(evidence, 1):
            prompt_parts.append(
                f"Evidence {index}\nSource: {row['title']}\nLocator: {row['locator']}\n"
                f"Verified excerpt: {row['evidence_excerpt']}"
            )
        prompt_parts.append(
            "Answer only from this evidence. Cover every material condition needed to "
            "answer the question and state what remains unresolved."
        )
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": "\n\n".join(prompt_parts)},
        ]
        input_hash = sha256_text(json.dumps(messages, ensure_ascii=False, sort_keys=True))
        cases.append(
            _sealed(
                {
                    "schema": "legalbot.ge-fresh-visible-codex-case.v1",
                    "ordinal": ordinal,
                    "case_id": case.case_id,
                    "topic": case.topic,
                    "coverage_kind": case.coverage_kind,
                    "question": case.question,
                    "question_hash": question_hash,
                    "evidence_references": evidence_refs,
                    "input_hash": input_hash,
                    "trained_exact_hash_excluded": True,
                    "held_exact_hash_excluded": True,
                    "prior_visible_source_title_excluded": True,
                    "private_unseen_source": False,
                }
            )
        )
        inputs.append(
            {
                "schema": "legalbot.ge-fresh-visible-codex-model-input.v1",
                "ordinal": ordinal,
                "case_id": case.case_id,
                "question_hash": question_hash,
                "input_hash": input_hash,
                "messages": messages,
            }
        )
        controls.append(
            _sealed(
                {
                    "schema": "legalbot.ge-fresh-visible-codex-control.v1",
                    "ordinal": ordinal,
                    "case_id": case.case_id,
                    "required_points": list(case.required_points),
                    "material_limits": list(case.material_limits),
                    "prohibited_overclaims": list(case.prohibited_overclaims),
                    "evidence_references": evidence_refs,
                }
            )
        )

    _write_json_create(
        output / "OWNER-AUTHORIZATION.json",
        _sealed(
            {
                "schema": "legalbot.ge-fresh-visible-codex-authorization.v1",
                "authorization_text": OWNER_AUTHORIZATION_TEXT,
                "authorized_action": "NEW_FRESH_VISIBLE_BASE_VS_CODEX_EVALUATION",
                "further_weight_training_authorized": False,
                "private_unseen_instruction": "KEEP_SEALED",
                "sealed_unseen_execution_authorized": False,
            }
        ),
    )
    _write_json_create(
        output / "EVALUATION-CONTRACT.json",
        _sealed(
            {
                "schema": "legalbot.ge-fresh-visible-codex-contract.v1",
                "campaign_id": CAMPAIGN_ID,
                "campaign_version": CAMPAIGN_VERSION,
                "case_count": 23,
                "candidate_variants": ["BASE", "CODEX_AUTO"],
                "codex_pass_requires_all_cases": True,
                "per_case_minimum_quality_score": 70.0,
                "quality_dimension_max": dict(QUALITY_DIMENSION_MAX),
                "quality_critical_floors": dict(QUALITY_CRITICAL_FLOORS),
                "regression_checks": list(REGRESSION_CHECKS),
                "no_factual_regression_required": True,
                "no_quality_regression_over_five_required": True,
                "private_unseen_prompt_content_accessed": False,
            }
        ),
    )
    _write_json_create(
        output / "LEAKAGE-REPORT.json",
        _sealed(
            {
                "schema": "legalbot.ge-fresh-visible-codex-leakage.v1",
                "status": "PASS_WITH_SEALED_UNSEEN_LIMITATION",
                "training_question_hash_count_excluded": len(training_question_hashes),
                "training_answer_hash_count_excluded": len(training_answer_hashes),
                "held_question_hash_count_excluded": len(held_question_hashes),
                "held_answer_hash_count_excluded": len(held_answer_hashes),
                "fresh_question_hash_count": len(cases),
                "source_title_overlap_with_training": [],
                "source_title_overlap_with_prior_visible": [],
                "private_unseen_case_count": 306,
                "private_unseen_custody_ledger_sha256": EXPECTED_PRIVATE_CUSTODY_LEDGER_SHA256,
                "private_unseen_prompt_content_accessed": False,
                "private_unseen_semantic_overlap_computed": False,
            }
        ),
    )
    _write_jsonl_create(output / "OFFICIAL-SOURCE-MANIFEST.jsonl", sources)
    _write_jsonl_create(output / "FRESH-VISIBLE-CASES.jsonl", cases)
    _write_jsonl_create(output / "MODEL-INPUTS.jsonl", inputs)
    _write_jsonl_create(output / "EXPECTED-CONTROLS.jsonl", controls)
    preparation = _sealed(
        {
            "schema": "legalbot.ge-fresh-visible-codex-preparation.v1",
            "campaign_id": CAMPAIGN_ID,
            "repair_state_sha256": EXPECTED_REPAIR_STATE_SHA256,
            "case_manifest_sha256": sha256_file(output / "FRESH-VISIBLE-CASES.jsonl"),
            "model_inputs_sha256": sha256_file(output / "MODEL-INPUTS.jsonl"),
            "expected_controls_sha256": sha256_file(output / "EXPECTED-CONTROLS.jsonl"),
            "official_source_manifest_sha256": sha256_file(
                output / "OFFICIAL-SOURCE-MANIFEST.jsonl"
            ),
            "official_source_snapshot_count": len(sources),
            "private_unseen_opened": False,
        }
    )
    _write_json_create(output / "PREPARATION-MANIFEST.json", preparation)
    return {"output": str(output), "case_count": len(cases), "source_count": len(sources)}


def record_codex_answers(
    answers: Mapping[str, str], output: Path = DEFAULT_OUTPUT
) -> dict[str, Any]:
    """Bind the exact Codex evidence-bound answers without changing weights."""

    path = output / "CODEX-AUTO-OUTPUTS.jsonl"
    if path.exists():
        raise FreshVisibleCodexError("refusing to replace Codex answer outputs")
    inputs = load_jsonl(output / "MODEL-INPUTS.jsonl")
    if set(answers) != {str(row["case_id"]) for row in inputs}:
        raise FreshVisibleCodexError("Codex answers must cover exactly 23 fresh cases")
    rows: list[dict[str, Any]] = []
    for record in inputs:
        answer = answers[str(record["case_id"])].strip()
        if defects := surface_guard(answer):
            raise FreshVisibleCodexError(
                f"Codex answer surface failure: {record['case_id']} {defects}"
            )
        rows.append(
            _sealed(
                {
                    "schema": "legalbot.ge-fresh-visible-codex-output.v1",
                    "ordinal": record["ordinal"],
                    "case_id": record["case_id"],
                    "question_hash": record["question_hash"],
                    "input_hash": record["input_hash"],
                    "candidate_variant": "CODEX_AUTO",
                    "candidate_answer": answer,
                    "candidate_answer_hash": sha256_text(answer),
                    "surface_word_count": len(answer.split()),
                    "surface_guard": "PASS",
                    "weight_training_performed": False,
                    "professional_legal_sign_off": False,
                }
            )
        )
    if len({row["candidate_answer_hash"] for row in rows}) != 23:
        raise FreshVisibleCodexError("Codex produced duplicate exact answers")
    _write_jsonl_create(path, rows)
    _write_json_create(
        output / "CODEX-AUTO-GENERATION-RECEIPT.json",
        _sealed(
            {
                "schema": "legalbot.ge-fresh-visible-codex-generation.v1",
                "candidate_variant": "CODEX_AUTO",
                "case_count": 23,
                "output_sha256": sha256_file(path),
                "weight_training_performed": False,
                "adapter_loaded": False,
                "adapter_runtime_activated": False,
                "private_unseen_prompt_content_accessed": False,
                "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            }
        ),
    )
    return {"output": str(path), "case_count": len(rows), "output_sha256": sha256_file(path)}


def build_blind_workbook(output: Path = DEFAULT_OUTPUT) -> dict[str, Any]:
    """Create a deterministic blind base-versus-Codex exact-hash workbook."""

    workbook_path = output / "BLIND-REVIEW-WORKBOOK.jsonl"
    map_path = output / "BLIND-MAP.jsonl"
    if workbook_path.exists() or map_path.exists():
        raise FreshVisibleCodexError("refusing to replace blind workbook")
    cases = {row["case_id"]: row for row in load_jsonl(output / "FRESH-VISIBLE-CASES.jsonl")}
    controls = {row["case_id"]: row for row in load_jsonl(output / "EXPECTED-CONTROLS.jsonl")}
    base = {row["case_id"]: row for row in load_jsonl(output / "BASE-OUTPUTS.jsonl")}
    codex = {row["case_id"]: row for row in load_jsonl(output / "CODEX-AUTO-OUTPUTS.jsonl")}
    if set(base) != set(cases) or set(codex) != set(cases):
        raise FreshVisibleCodexError("candidate output case sets do not reconcile")
    workbook: list[dict[str, Any]] = []
    mappings: list[dict[str, Any]] = []
    for case_id, case in sorted(cases.items(), key=lambda item: int(item[1]["ordinal"])):
        first_codex = int(hashlib.sha256(case_id.encode()).hexdigest(), 16) % 2 == 0
        variants = (
            [codex[case_id], base[case_id]] if first_codex else [base[case_id], codex[case_id]]
        )
        for label, candidate in zip(("A", "B"), variants, strict=True):
            workbook.append(
                {
                    "schema": "legalbot.ge-fresh-visible-codex-blind-row.v1",
                    "ordinal": case["ordinal"],
                    "case_id": case_id,
                    "topic": case["topic"],
                    "coverage_kind": case["coverage_kind"],
                    "blind_label": label,
                    "question": case["question"],
                    "question_hash": case["question_hash"],
                    "candidate_answer": candidate["candidate_answer"],
                    "candidate_answer_hash": candidate["candidate_answer_hash"],
                    "evidence_references": case["evidence_references"],
                    "required_points": controls[case_id]["required_points"],
                    "material_limits": controls[case_id]["material_limits"],
                    "prohibited_overclaims": controls[case_id]["prohibited_overclaims"],
                }
            )
            mappings.append(
                {
                    "schema": "legalbot.ge-fresh-visible-codex-blind-map.v1",
                    "case_id": case_id,
                    "blind_label": label,
                    "candidate_variant": candidate["candidate_variant"],
                    "candidate_answer_hash": candidate["candidate_answer_hash"],
                }
            )
    _write_jsonl_create(workbook_path, workbook)
    _write_jsonl_create(map_path, mappings)
    return {"row_count": len(workbook), "workbook_sha256": sha256_file(workbook_path)}


def _quality_pass(scores: Mapping[str, Any]) -> bool:
    if set(scores) != set(QUALITY_DIMENSION_MAX):
        return False
    if any(
        float(scores[name]) < 0 or float(scores[name]) > maximum
        for name, maximum in QUALITY_DIMENSION_MAX.items()
    ):
        return False
    return sum(float(value) for value in scores.values()) >= 70 and all(
        float(scores[name]) >= floor for name, floor in QUALITY_CRITICAL_FLOORS.items()
    )


def finalize_campaign(output: Path = DEFAULT_OUTPUT) -> dict[str, Any]:
    """Validate all 46 reviews and seal the fresh visible route decision."""

    if (output / "STATE-TRANSITION-RECEIPT.json").exists():
        raise FreshVisibleCodexError("refusing to replace finalized campaign")
    workbook = load_jsonl(output / "BLIND-REVIEW-WORKBOOK.jsonl")
    mappings = load_jsonl(output / "BLIND-MAP.jsonl")
    reviews = load_jsonl(output / "CODEX-BLIND-REVIEW.jsonl")
    expected = {
        (row["case_id"], row["blind_label"], row["candidate_answer_hash"]) for row in workbook
    }
    actual = {(row["case_id"], row["blind_label"], row["candidate_answer_hash"]) for row in reviews}
    if len(workbook) != 46 or len(reviews) != 46 or expected != actual:
        raise FreshVisibleCodexError("blind review must cover all 46 exact outputs")
    workbook_by_pair = {(row["case_id"], row["blind_label"]): row for row in workbook}
    map_by_pair = {(row["case_id"], row["blind_label"]): row for row in mappings}
    by_variant: dict[str, list[dict[str, Any]]] = {"BASE": [], "CODEX_AUTO": []}
    normalized: list[dict[str, Any]] = []
    claim_count = 0
    for review in reviews:
        pair = (review["case_id"], review["blind_label"])
        if review.get("reviewer_kind") != "AI_MODEL_REVIEWER":
            raise FreshVisibleCodexError("reviewer kind must remain AI_MODEL_REVIEWER")
        if review.get("professional_legal_sign_off") is not False:
            raise FreshVisibleCodexError("AI review cannot claim professional sign-off")
        claims = review.get("material_claims")
        if not isinstance(claims, list) or not claims:
            raise FreshVisibleCodexError(f"material claims missing: {pair}")
        allowed = {
            ref["evidence_span_sha256"] for ref in workbook_by_pair[pair]["evidence_references"]
        }
        for claim in claims:
            if claim.get("support_status") not in {"SUPPORTED", "UNSUPPORTED"}:
                raise FreshVisibleCodexError("invalid claim support status")
            hashes = claim.get("evidence_span_sha256")
            if not isinstance(hashes, list):
                raise FreshVisibleCodexError("claim evidence list missing")
            if claim["support_status"] == "SUPPORTED" and (
                not hashes or not set(hashes) <= allowed
            ):
                raise FreshVisibleCodexError("supported claim lacks allowed evidence")
            claim_count += 1
        checks = review.get("factual_checks", {})
        if set(checks) != set(FACTUAL_CHECKS):
            raise FreshVisibleCodexError("factual check set mismatch")
        factual_pass = (
            review.get("material_proposition_coverage_complete") is True
            and all(claim["support_status"] == "SUPPORTED" for claim in claims)
            and all(value in {"PASS", "NOT_APPLICABLE"} for value in checks.values())
        )
        expected_factual = "FACTUAL_PASS" if factual_pass else "FACTUAL_HOLD"
        if review.get("factual_outcome") != expected_factual:
            raise FreshVisibleCodexError(f"factual outcome mismatch: {pair}")
        scores = review.get("quality_dimensions", {})
        if factual_pass:
            if set(scores) != set(QUALITY_DIMENSION_MAX):
                raise FreshVisibleCodexError("quality dimensions missing")
            total = round(sum(float(value) for value in scores.values()), 2)
            if float(review.get("quality_score", -1)) != total:
                raise FreshVisibleCodexError("quality total mismatch")
            quality_pass = _quality_pass(scores)
            expected_quality = "MEETS_70_STANDARD" if quality_pass else "BELOW_70_OR_CRITICAL_FLOOR"
        else:
            if scores or review.get("quality_score") is not None:
                raise FreshVisibleCodexError("factual hold must not receive a quality score")
            quality_pass = False
            expected_quality = "NOT_SCORED_FACTUAL_HOLD"
        if review.get("quality_outcome") != expected_quality:
            raise FreshVisibleCodexError(f"quality outcome mismatch: {pair}")
        variant = map_by_pair[pair]["candidate_variant"]
        if variant == "CODEX_AUTO":
            regressions = review.get("regression_checks", {})
            if set(regressions) != set(REGRESSION_CHECKS) or any(
                value not in {"PASS", "FAIL"} for value in regressions.values()
            ):
                raise FreshVisibleCodexError("Codex regression check set mismatch")
        row = dict(review)
        row["candidate_variant"] = variant
        row["factual_gate_pass"] = factual_pass
        row["quality_gate_pass"] = quality_pass
        normalized.append(row)
        by_variant[variant].append(row)

    metrics: dict[str, dict[str, Any]] = {}
    for variant, rows in by_variant.items():
        scores = [float(row["quality_score"]) for row in rows if row["quality_score"] is not None]
        metrics[variant] = {
            "case_count": len(rows),
            "factual_pass_count": sum(bool(row["factual_gate_pass"]) for row in rows),
            "quality_pass_count": sum(bool(row["quality_gate_pass"]) for row in rows),
            "mean_quality_score_on_factual_pass": round(statistics.mean(scores), 2)
            if scores
            else None,
            "minimum_quality_score_on_factual_pass": min(scores) if scores else None,
        }
    base = {row["case_id"]: row for row in by_variant["BASE"]}
    codex = {row["case_id"]: row for row in by_variant["CODEX_AUTO"]}
    factual_regressions = 0
    quality_regressions = 0
    defect_regressions = 0
    comparisons: list[dict[str, Any]] = []
    for case in CASES:
        base_row = base[case.case_id]
        codex_row = codex[case.case_id]
        if base_row["factual_gate_pass"] and not codex_row["factual_gate_pass"]:
            factual_regressions += 1
        delta = None
        if base_row["quality_score"] is not None and codex_row["quality_score"] is not None:
            delta = round(float(codex_row["quality_score"]) - float(base_row["quality_score"]), 2)
            quality_regressions += int(delta < -5)
        failed_regressions = [
            name for name, value in codex_row["regression_checks"].items() if value == "FAIL"
        ]
        defect_regressions += len(failed_regressions)
        comparisons.append(
            {
                "schema": "legalbot.ge-fresh-visible-codex-comparison.v1",
                "case_id": case.case_id,
                "base_answer_hash": base_row["candidate_answer_hash"],
                "codex_answer_hash": codex_row["candidate_answer_hash"],
                "base_factual_outcome": base_row["factual_outcome"],
                "codex_factual_outcome": codex_row["factual_outcome"],
                "base_quality_score": base_row["quality_score"],
                "codex_quality_score": codex_row["quality_score"],
                "codex_minus_base_quality": delta,
                "failed_prior_defect_regressions": failed_regressions,
            }
        )
    route_pass = (
        metrics["CODEX_AUTO"]["factual_pass_count"] == 23
        and metrics["CODEX_AUTO"]["quality_pass_count"] == 23
        and factual_regressions == 0
        and quality_regressions == 0
        and defect_regressions == 0
    )
    state_name = (
        "FRESH_VISIBLE_CODEX_ROUTE_PASS_AWAITING_SEALED_UNSEEN_OWNER_AUTHORIZATION"
        if route_pass
        else "FRESH_VISIBLE_CODEX_ROUTE_HOLD_VISIBLE_REPAIR_REQUIRED"
    )
    next_gate = "SEALED_UNSEEN_ONE_PASS_AUTHORIZATION" if route_pass else "VISIBLE_REPAIR_ONLY"
    _write_jsonl_create(output / "CODEX-REVIEW-WITH-VARIANTS.jsonl", normalized)
    _write_jsonl_create(output / "CASE-COMPARISON.jsonl", comparisons)
    metric_report = _sealed(
        {
            "schema": "legalbot.ge-fresh-visible-codex-metrics.v1",
            "campaign_id": CAMPAIGN_ID,
            "metrics_by_variant": metrics,
            "codex_factual_regression_count": factual_regressions,
            "codex_quality_regression_over_five_count": quality_regressions,
            "prior_defect_regression_count": defect_regressions,
            "declared_material_claim_count": claim_count,
            "declared_material_claim_checked_count": claim_count,
            "declared_material_claim_review_coverage_pct": 100.0,
            "route_pass": route_pass,
            "pass_definition": "All 23 Codex answers must factually pass, score at least 70, meet every critical floor, and introduce no factual, greater-than-five-point quality, or prior-defect regression.",
        }
    )
    _write_json_create(output / "METRIC-REPORT.json", metric_report)
    state = _sealed(
        {
            "schema": "legalbot.ge-fresh-visible-codex-state.v1",
            "campaign_id": CAMPAIGN_ID,
            "overall_state": state_name,
            "fresh_visible_evaluation": "PASS" if route_pass else "HOLD",
            "private_306_bank": "SEALED_NOT_OPENED",
            "weight_training": "NOT_AUTHORIZED_NOT_PERFORMED",
            "r2_adapter_runtime_activation": "NOT_AUTHORIZED_NOT_PERFORMED",
            "qualified_legal_review": "NOT_STARTED",
            "answer_legal_gold": "NOT_STARTED",
            "sealed_unseen_execution": "NOT_STARTED",
            "promotion": "NOT_STARTED",
            "live": "NOT_STARTED",
            "next_owner_gate": next_gate,
            "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }
    )
    _write_json_create(output / "STATE-TRANSITION-RECEIPT.json", state)
    readme = f"""# {CAMPAIGN_ID}

This create-only campaign evaluates the non-weight Codex evidence-bound route
against the pinned base model on 23 new visible questions and 23 new official
locator sources. Source titles are disjoint from training and the prior visible
adapter evaluation.

## Result

- Base: {metrics["BASE"]["factual_pass_count"]}/23 factual and
  {metrics["BASE"]["quality_pass_count"]}/23 full 70+/floor passes.
- Codex route: {metrics["CODEX_AUTO"]["factual_pass_count"]}/23 factual and
  {metrics["CODEX_AUTO"]["quality_pass_count"]}/23 full 70+/floor passes.
- Factual regressions: {factual_regressions}; quality regressions over five:
  {quality_regressions}; prior-defect regressions: {defect_regressions}.
- State: `{state_name}`.

The 306-case private bank remained sealed. This AI-model review is not qualified
legal review or legal gold. An unseen run requires a separate exact owner gate.
"""
    with (output / "README.md").open("x", encoding="utf-8") as handle:
        handle.write(readme)
    manifest = _sealed(
        {
            "schema": "legalbot.ge-fresh-visible-codex-run.v1",
            "campaign_id": CAMPAIGN_ID,
            "campaign_version": CAMPAIGN_VERSION,
            "preparation_manifest_sha256": sha256_file(output / "PREPARATION-MANIFEST.json"),
            "base_outputs_sha256": sha256_file(output / "BASE-OUTPUTS.jsonl"),
            "codex_outputs_sha256": sha256_file(output / "CODEX-AUTO-OUTPUTS.jsonl"),
            "blind_workbook_sha256": sha256_file(output / "BLIND-REVIEW-WORKBOOK.jsonl"),
            "blind_review_sha256": sha256_file(output / "CODEX-BLIND-REVIEW.jsonl"),
            "metric_report_sha256": sha256_file(output / "METRIC-REPORT.json"),
            "state_transition_receipt_sha256": sha256_file(
                output / "STATE-TRANSITION-RECEIPT.json"
            ),
            "implementation_sha256": sha256_file(Path(__file__)),
            "private_unseen_opened": False,
            "weight_training_performed": False,
            "adapter_runtime_activated": False,
        }
    )
    _write_json_create(output / "RUN-MANIFEST.json", manifest)
    artifacts = {
        path.relative_to(output).as_posix(): sha256_file(path)
        for path in sorted(output.rglob("*"))
        if path.is_file() and path.name != "ARTIFACT-SHA256-REGISTER.json"
    }
    _write_json_create(
        output / "ARTIFACT-SHA256-REGISTER.json",
        {
            "schema": "legalbot.ge-fresh-visible-codex-artifact-hashes.v1",
            "campaign_id": CAMPAIGN_ID,
            "artifacts": artifacts,
        },
    )
    return {
        "output": str(output),
        "overall_state": state_name,
        "route_pass": route_pass,
        "metrics_by_variant": metrics,
        "state_transition_receipt_sha256": sha256_file(output / "STATE-TRANSITION-RECEIPT.json"),
    }


__all__ = [
    "CAMPAIGN_ID",
    "CASES",
    "DEFAULT_OUTPUT",
    "REGRESSION_CHECKS",
    "SOURCES",
    "FreshVisibleCodexError",
    "build_blind_workbook",
    "finalize_campaign",
    "prepare_campaign",
    "record_codex_answers",
]
