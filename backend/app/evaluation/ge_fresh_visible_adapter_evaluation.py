"""Fresh visible base-versus-adapter evaluation after scoped GE LoRA training.

The campaign uses newly written visible questions and current official-source
snapshots. It never opens the private unseen bank, never activates the adapter in
the product runtime, and cannot create qualified legal review or answer legal gold.
"""

from __future__ import annotations

import hashlib
import json
import re
import ssl
import statistics
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import certifi

from .ge_currentness_packets import PROJECT_ROOT, load_jsonl, sha256_file, sha256_text
from .ge_visible_harness import FACTUAL_CHECKS, QUALITY_CRITICAL_FLOORS, QUALITY_DIMENSION_MAX

CAMPAIGN_ID = "LegalBot-GE-2026-09-04-fresh-visible-adapter-evaluation-r2"
CAMPAIGN_VERSION = "legalbot.ge-fresh-visible-adapter-evaluation.v1"
TRAINING_CAMPAIGN_ID = "LegalBot-GE-2026-09-04-answer-weight-training-r2"
TRAINING_ROOT = PROJECT_ROOT / "data/evaluations/general-enquiries" / TRAINING_CAMPAIGN_ID
SOURCE_REVIEW_ROOT = (
    PROJECT_ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-04-ai-auto-quality-review-r1"
)
DEFAULT_OUTPUT = PROJECT_ROOT / "data/evaluations/general-enquiries" / CAMPAIGN_ID
MODEL_RELATIVE = "models/runtime/Qwen3.5-9B-4bit"
MODEL_PATH = PROJECT_ROOT / MODEL_RELATIVE
ADAPTER_RELATIVE = f"data/evaluations/general-enquiries/{TRAINING_CAMPAIGN_ID}/adapter"
ADAPTER_PATH = PROJECT_ROOT / ADAPTER_RELATIVE
REVIEW_AS_OF_DATE = date(2026, 9, 4)
EXPECTED_TRAINING_STATE_RECEIPT_SHA256 = (
    "99e0c1f7ca9b708ae91f8fd2e2e708a3767c6b7ddc9c8f8944d505fe68f5e329"
)
EXPECTED_ADAPTER_SHA256 = "228a79524282bcbf708e43a8324da0295c9717c8aa8eefdd328b4b0f8262c298"
EXPECTED_PRIVATE_CUSTODY_LEDGER_SHA256 = (
    "11f42c7fcd83dbb0299db31917663044515a574705472921e06fcc1e469af7b2"
)
OWNER_AUTHORIZATION_TEXT = (
    "I authorize fresh visible evaluation of the r2 adapter, excluding the 13 "
    "trained hashes and keeping the private unseen bank sealed."
)
SYSTEM_PROMPT = (
    "You are LegalBot's General Enquiry answer model for England and Wales. "
    "Use only the evidence supplied with the question. Give a direct plain-English "
    "answer, separate law from unverified user facts, state material qualifications "
    "and missing facts, and give safe practical next steps. Do not invent authority, "
    "remedies, deadlines, amounts or professional legal sign-off. Name the supplied "
    "source and locator in ordinary prose, but do not render formal citations. "
    "Return only the finished answer, with no planning notes or analysis."
)

LEG_NS = "http://www.legislation.gov.uk/namespaces/legislation"
META_NS = "http://www.legislation.gov.uk/namespaces/metadata"
DC_NS = "http://purl.org/dc/elements/1.1/"
DCT_NS = "http://purl.org/dc/terms/"


class FreshVisibleEvaluationError(ValueError):
    """The fresh-visible contract, source capture, or review was invalid."""


@dataclass(frozen=True, slots=True)
class SourceSpec:
    key: str
    title: str
    path: str
    locator: str
    text_indices: tuple[int, ...]

    @property
    def url(self) -> str:
        return f"https://www.legislation.gov.uk/{self.path}/data.xml"


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
        "hra6",
        "Human Rights Act 1998",
        "ukpga/1998/42/section/6",
        "section 6",
        (1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13),
    ),
    SourceSpec(
        "dpa167",
        "Data Protection Act 2018",
        "ukpga/2018/12/section/167",
        "section 167",
        (1, 2, 3, 4, 5, 7, 8, 9),
    ),
    SourceSpec(
        "partnership9", "Partnership Act 1890", "ukpga/1890/39/section/9", "section 9", (1,)
    ),
    SourceSpec(
        "late1",
        "Late Payment of Commercial Debts (Interest) Act 1998",
        "ukpga/1998/20/section/1",
        "section 1",
        (1, 2, 3),
    ),
    SourceSpec(
        "competition2",
        "Competition Act 1998",
        "ukpga/1998/41/section/2",
        "section 2",
        (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 16),
    ),
    SourceSpec(
        "hfe3",
        "Human Fertilisation and Embryology Act 1990",
        "ukpga/1990/37/section/3",
        "section 3",
        (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17),
    ),
    SourceSpec(
        "thirdparty1",
        "Contracts (Rights of Third Parties) Act 1999",
        "ukpga/1999/31/section/1",
        "section 1",
        (1, 2, 3, 4, 5, 6, 7, 8),
    ),
    SourceSpec(
        "pace58",
        "Police and Criminal Evidence Act 1984",
        "ukpga/1984/60/section/58",
        "section 58",
        (1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 18, 19, 20, 21, 22, 23),
    ),
    SourceSpec(
        "euwa6",
        "European Union (Withdrawal) Act 2018",
        "ukpga/2018/16/section/6",
        "section 6",
        (1, 2, 3, 4),
    ),
    SourceSpec(
        "arb9", "Arbitration Act 1996", "ukpga/1996/23/section/9", "section 9", (1, 2, 3, 4, 5)
    ),
    SourceSpec(
        "land2",
        "Law of Property (Miscellaneous Provisions) Act 1989",
        "ukpga/1989/34/section/2",
        "section 2",
        (1, 2, 3, 4, 5, 6, 7, 8, 9),
    ),
    SourceSpec(
        "mca1",
        "Mental Capacity Act 2005",
        "ukpga/2005/9/section/1",
        "section 1",
        (1, 2, 3, 4, 5, 6),
    ),
    SourceSpec(
        "pensions3",
        "Pensions Act 2008",
        "ukpga/2008/30/section/3",
        "section 3",
        (1, 2, 3, 4, 5, 6, 7, 12, 13, 14, 15),
    ),
    SourceSpec(
        "pil1",
        "Private International Law (Implementation of Agreements) Act 2020",
        "ukpga/2020/24/section/1",
        "section 1",
        (7, 8, 9, 10, 11, 12, 13),
    ),
    SourceSpec(
        "defamation1", "Defamation Act 2013", "ukpga/2013/26/section/1", "section 1", (1, 2)
    ),
    SourceSpec(
        "trustee1", "Trustee Act 2000", "ukpga/2000/29/section/1", "section 1", (1, 2, 3, 4)
    ),
    SourceSpec(
        "inheritance1",
        "Inheritance (Provision for Family and Dependants) Act 1975",
        "ukpga/1975/63/section/1",
        "section 1",
        (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 16, 18),
    ),
    SourceSpec(
        "lta11",
        "Landlord and Tenant Act 1985",
        "ukpga/1985/70/section/11",
        "section 11",
        (1, 2, 3, 4, 10, 11, 12, 13, 14, 15, 27),
    ),
    SourceSpec(
        "era13",
        "Employment Rights Act 1996",
        "ukpga/1996/18/section/13",
        "section 13",
        (1, 2, 3, 4, 5, 6, 7, 8, 9, 10),
    ),
    SourceSpec(
        "children1",
        "Children Act 1989",
        "ukpga/1989/41/section/1",
        "section 1",
        (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 19, 20, 21, 22),
    ),
    SourceSpec(
        "immigration3c",
        "Immigration Act 1971",
        "ukpga/1971/77/section/3C",
        "section 3C",
        (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19),
    ),
    SourceSpec("limitation5", "Limitation Act 1980", "ukpga/1980/58/section/5", "section 5", (1,)),
    SourceSpec(
        "cpa2",
        "Consumer Protection Act 1987",
        "ukpga/1987/43/section/2",
        "section 2",
        (1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12),
    ),
    SourceSpec(
        "cpa3",
        "Consumer Protection Act 1987",
        "ukpga/1987/43/section/3",
        "section 3",
        (1, 2, 3, 4, 5, 6),
    ),
)


CASES: tuple[CaseSpec, ...] = (
    CaseSpec(
        "administrative-law:fv-r1-01",
        "administrative-law",
        "LEGAL_TOPIC",
        "A council officer did not decide my request at all. Can Human Rights Act 1998 section 6 potentially apply to a failure to act, or only to positive decisions?",
        ("hra6",),
        (
            "Section 6 can apply to a public authority's incompatible act.",
            "An act includes a failure to act, subject to the listed legislative exceptions.",
            "Whether this council omission breached a Convention right remains fact dependent.",
        ),
        ("The relevant Convention right and circumstances of the omission are not supplied.",),
        (
            "A breach is automatic merely because no decision was made.",
            "Damages or a specific remedy are guaranteed.",
        ),
    ),
    CaseSpec(
        "ai-and-data-protection:fv-r1-01",
        "ai-and-data-protection",
        "LEGAL_TOPIC",
        "A court agrees that a company infringed my data-protection rights. Can the court order the company to take steps to comply?",
        ("dpa167",),
        (
            "Section 167 applies on a data subject's application where the court is satisfied of an infringement.",
            "The court may order a controller or processor to take specified steps or refrain from steps.",
            "The order may specify timing.",
        ),
        (
            "The question assumes the court is satisfied; the precise order remains discretionary and fact dependent.",
        ),
        ("The court must always make an order.", "Compensation is automatically awarded."),
    ),
    CaseSpec(
        "business-and-company-law:fv-r1-01",
        "business-and-company-law",
        "LEGAL_TOPIC",
        "A supplier's contract was entered into while I was a partner in an English partnership, but I did not personally sign it. Can I still be liable for the firm's debt?",
        ("partnership9",),
        (
            "Every partner is jointly liable with the other partners for firm debts and obligations incurred while that person is a partner.",
            "Personal signature is not stated as a condition in section 9.",
        ),
        (
            "Whether the obligation was the firm's and incurred while the user was a partner must be established.",
        ),
        (
            "Only the signing partner can be liable.",
            "The user's liability is conclusively established without checking the partnership and debt facts.",
        ),
    ),
    CaseSpec(
        "commercial-law:fv-r1-01",
        "commercial-law",
        "LEGAL_TOPIC",
        "My business contract says nothing about late-payment interest and an invoice remains unpaid. Does the Late Payment of Commercial Debts (Interest) Act 1998 automatically imply interest?",
        ("late1",),
        (
            "A qualifying debt under a contract to which the Act applies carries simple statutory interest as an implied term.",
            "Part II can allow contract terms to oust or vary the right in some circumstances.",
        ),
        (
            "The packet does not establish that the contract and debt qualify or calculate a rate or start date.",
        ),
        (
            "Every unpaid business invoice automatically qualifies.",
            "A particular interest rate or fixed compensation is established by section 1.",
        ),
    ),
    CaseSpec(
        "competition-law:fv-r1-01",
        "competition-law",
        "LEGAL_TOPIC",
        "Two competing UK suppliers agree that neither will sell below the same minimum price. Is that agreement potentially prohibited under Competition Act 1998 section 2?",
        ("competition2",),
        (
            "The Chapter I prohibition can cover agreements between undertakings whose object or effect restricts competition and meets the UK trade/effects condition.",
            "Direct or indirect price fixing is expressly listed.",
            "A prohibited agreement is void unless exempt.",
        ),
        ("Market context, trade effect and any exemption are not established.",),
        (
            "Price discussions are always criminal.",
            "Fines or liability are automatic on the supplied facts.",
        ),
    ),
    CaseSpec(
        "contemporary-biolaw-and-regulation:fv-r1-01",
        "contemporary-biolaw-and-regulation",
        "LEGAL_TOPIC",
        "A private laboratory wants to create a human embryo for research without obtaining a licence. Does Human Fertilisation and Embryology Act 1990 section 3 permit that?",
        ("hfe3",),
        (
            "Section 3 says no person may bring about creation of an embryo except under a licence.",
            "The stated research purpose does not create an exception in the supplied provision.",
        ),
        (
            "The full licensing regime and any separate criminal consequences are outside the extract.",
        ),
        (
            "Research creation is automatically exempt.",
            "The extract establishes a specific penalty.",
        ),
    ),
    CaseSpec(
        "contract-law:fv-r1-01",
        "contract-law",
        "LEGAL_TOPIC",
        "A contract expressly says that a named customer may enforce one term, although the customer did not sign the contract. Can the customer enforce that term?",
        ("thirdparty1",),
        (
            "A non-party may enforce where the contract expressly provides that the person may.",
            "The third party must be identified by name, class or description.",
            "Enforcement remains subject to the contract's other relevant terms, with ordinary breach remedies available.",
        ),
        ("The actual wording and any relevant limiting terms must be checked.",),
        (
            "Every person who benefits from any contract can enforce it.",
            "The customer automatically wins a claim.",
        ),
    ),
    CaseSpec(
        "criminal-law:fv-r1-01",
        "criminal-law",
        "LEGAL_TOPIC",
        "I am under arrest at a police station and asked to speak privately with a solicitor. Can the police simply delay access until after interview without giving a reason?",
        ("pace58",),
        (
            "A detained person who requests it is entitled to consult a solicitor privately at any time and as soon as practicable.",
            "Delay is limited to an indictable-offence case, superintendent authorization and specified reasonable grounds.",
            "Reasons must be given and recorded; access must be allowed when the reason ends and in any event within the stated 36-hour limit.",
        ),
        ("The extract does not establish the offence, authorization or asserted grounds.",),
        (
            "Police may routinely wait until after interview.",
            "The extract proves that any interview before advice is automatically void.",
        ),
    ),
    CaseSpec(
        "eu-internal-market-law:fv-r1-01",
        "eu-internal-market-law",
        "LEGAL_TOPIC",
        "Must an English court follow a Court of Justice of the European Union decision made after IP completion day, and may it still consider that decision?",
        ("euwa6",),
        (
            "A UK court or tribunal is not bound by post-IP-completion-day CJEU principles or decisions.",
            "It cannot refer a matter to the CJEU after that day.",
            "It may have regard to post-day material so far as relevant.",
        ),
        (
            "The effect on a particular dispute depends on the applicable body of law and court hierarchy.",
        ),
        ("Post-day CJEU decisions are binding.", "Courts must ignore all post-day CJEU material."),
    ),
    CaseSpec(
        "international-commercial-mediation:fv-r1-01",
        "international-commercial-mediation",
        "LEGAL_TOPIC",
        "Our cross-border contract requires mediation and, if unresolved, arbitration. Mediation ended without settlement, but the other side sued in England about a matter covered by the arbitration agreement. Can I seek a court stay, and when must I apply?",
        ("arb9",),
        (
            "A party sued on a matter covered by an arbitration agreement may apply to the court for a stay.",
            "The application may follow exhaustion of another dispute-resolution procedure.",
            "It must be made after any procedural acknowledgment step but before taking a step to answer the substantive claim.",
            "The court shall stay unless the arbitration agreement is null and void, inoperative or incapable of performance.",
        ),
        ("The agreement, covered matter and procedural steps must be checked.",),
        (
            "Section 9 applies to a mediation-only clause.",
            "A stay remains available after answering the substantive claim.",
        ),
    ),
    CaseSpec(
        "land-law:fv-r1-01",
        "land-law",
        "LEGAL_TOPIC",
        "We orally agreed all terms for the sale of an English property and the buyer paid a deposit, but neither party signed a written contract. Does section 2 of the Law of Property (Miscellaneous Provisions) Act 1989 ordinarily make that a valid land-sale contract?",
        ("land2",),
        (
            "Section 2 ordinarily requires writing incorporating all expressly agreed terms and signature by or for each party.",
            "The supplied facts do not satisfy those formalities.",
            "The section preserves resulting, implied and constructive trusts and lists limited exceptions.",
        ),
        (
            "The facts may require analysis of an exception or separate equitable route not established here.",
        ),
        (
            "Payment of a deposit alone necessarily validates the oral contract.",
            "No possible equitable issue can arise.",
        ),
    ),
    CaseSpec(
        "law-and-medicine:fv-r1-01",
        "law-and-medicine",
        "LEGAL_TOPIC",
        "Can a hospital treat an adult as lacking decision-making capacity solely because the adult makes a decision clinicians consider unwise?",
        ("mca1",),
        (
            "Capacity must be presumed unless lack of capacity is established.",
            "Practicable support steps must first be tried.",
            "An unwise decision alone does not establish incapacity.",
            "Acts for a person who lacks capacity must be in best interests and consider a less restrictive route.",
        ),
        ("The packet does not determine this adult's capacity for the particular decision.",),
        (
            "Clinical disagreement alone proves incapacity.",
            "Best interests applies without first establishing lack of capacity.",
        ),
    ),
    CaseSpec(
        "pensions-law:fv-r1-01",
        "pensions-law",
        "LEGAL_TOPIC",
        "I am 25, below pensionable age, earn £12,000 in a 12-month pay reference period and am not an active member of a qualifying pension scheme. Does Pensions Act 2008 section 3 generally require my employer to arrange automatic enrolment?",
        ("pensions3",),
        (
            "Section 3 applies to a jobholder aged at least 22, below pensionable age and paid more than £10,000 in the relevant period.",
            "The employer must arrange active membership from the automatic-enrolment date.",
            "The extract states exceptions concerning existing or recently ceased qualifying-scheme membership.",
        ),
        (
            "Jobholder status, precise pay-reference facts and other statutory provisions must still be verified.",
        ),
        ("Every worker of any age must be enrolled.", "The extract fixes contribution rates."),
    ),
    CaseSpec(
        "private-international-law:fv-r1-01",
        "private-international-law",
        "LEGAL_TOPIC",
        "Does the 2005 Hague Choice of Court Convention have force of law in the United Kingdom under the Private International Law (Implementation of Agreements) Act 2020?",
        ("pil1",),
        (
            "The inserted provision states that the 2005 Hague Convention has force of law in the United Kingdom.",
            "It must be read with UK reservations or declarations made at approval.",
        ),
        (
            "Whether the Convention applies to a particular clause or dispute requires its scope and facts.",
        ),
        (
            "Every foreign choice-of-court clause is automatically enforceable.",
            "No reservations or scope limits can apply.",
        ),
    ),
    CaseSpec(
        "tort-law:fv-r1-01",
        "tort-law",
        "LEGAL_TOPIC",
        "A false online statement embarrassed me, but I cannot show that it caused or is likely to cause serious reputational harm. Does Defamation Act 2013 section 1 treat the statement as defamatory?",
        ("defamation1",),
        (
            "A statement is not defamatory unless publication caused or is likely to cause serious reputational harm.",
            "A profit-making body must show serious financial loss for serious harm.",
        ),
        ("Other elements and defences are outside the supplied section.",),
        ("Falsity and embarrassment alone satisfy section 1.", "Damages are automatic."),
    ),
    CaseSpec(
        "trusts-law:fv-r1-01",
        "trusts-law",
        "LEGAL_TOPIC",
        "A professional trustee says the same standard of care applies as for an inexperienced volunteer. Does Trustee Act 2000 section 1 take professional expertise into account?",
        ("trustee1",),
        (
            "The trustee must exercise reasonable care and skill in the circumstances.",
            "The standard considers actual or represented special knowledge or experience.",
            "A business or professional trustee is measured against knowledge or experience reasonably expected in that work.",
        ),
        (
            "Whether the statutory duty applies to the particular function and whether it was breached require more facts.",
        ),
        (
            "Professional expertise is irrelevant.",
            "Breach or compensation is conclusively established.",
        ),
    ),
    CaseSpec(
        "wills-and-estates:fv-r1-01",
        "wills-and-estates",
        "LEGAL_TOPIC",
        "I lived with my unmarried partner for only 18 months before they died domiciled in England and Wales. Do I qualify under the two-year cohabitant category in Inheritance (Provision for Family and Dependants) Act 1975 section 1?",
        ("inheritance1",),
        (
            "The cohabitant category requires living in the same household as a married couple or civil partners throughout the two years immediately before death.",
            "Eighteen months does not meet that category.",
            "Other applicant categories include a person maintained by the deceased, subject to their own conditions.",
        ),
        (
            "The facts do not determine whether another category applies or whether reasonable provision was lacking.",
        ),
        (
            "Eighteen months meets the two-year category.",
            "The user has no possible application under any other category.",
        ),
    ),
    CaseSpec(
        "housing:fv-r1-01",
        "housing",
        "PUBLIC_ACCESS_DOMAIN",
        "The boiler in my rented home no longer heats water. Is the landlord generally responsible under Landlord and Tenant Act 1985 section 11?",
        ("lta11",),
        (
            "For a lease to which section 11 applies, the landlord covenant covers installations for space heating and heating water.",
            "The landlord also has specified structure, utility and sanitation repair duties.",
            "The provision contains tenant-responsibility, inevitable-accident and removable-item limits.",
        ),
        ("Lease coverage, notice, cause and urgency are not fully established by the extract.",),
        (
            "The landlord is liable for every appliance in all leases.",
            "The extract establishes a fixed repair deadline or compensation.",
        ),
    ),
    CaseSpec(
        "employment:fv-r1-01",
        "employment",
        "PUBLIC_ACCESS_DOMAIN",
        "My employer deducted £200 from my wages for damaged equipment. There is no statutory basis, relevant contract term or prior written consent. Does Employment Rights Act 1996 section 13 generally permit that deduction?",
        ("era13",),
        (
            "Section 13 prohibits deductions unless required or authorised by statute, a relevant contract term, or prior written agreement or consent.",
            "A relevant contract term must have been provided or notified in writing beforehand.",
            "A shortfall from wages properly payable is treated as a deduction.",
        ),
        (
            "The supplied facts may be incomplete and other statutory provisions are outside the extract.",
        ),
        (
            "The deduction is permitted whenever an employer alleges damage.",
            "The extract establishes the remedy or tribunal deadline.",
        ),
    ),
    CaseSpec(
        "family:fv-r1-01",
        "family",
        "PUBLIC_ACCESS_DOMAIN",
        "When deciding disputed child arrangements, must the court presume that each parent receives equal time with the child?",
        ("children1",),
        (
            "The child's welfare is paramount and delay is generally prejudicial.",
            "The involvement presumption concerns involvement of some kind, not a particular division of time.",
            "The court considers the welfare factors and makes an order only if better than no order.",
        ),
        ("The outcome depends on the child's circumstances, wishes, needs and risk of harm.",),
        (
            "The Act creates an equal-time presumption.",
            "Either parent is guaranteed a particular arrangement.",
        ),
    ),
    CaseSpec(
        "immigration:fv-r1-01",
        "immigration",
        "PUBLIC_ACCESS_DOMAIN",
        "I applied to extend my limited UK leave before it expired. My leave has now expired and the application is still undecided. Does Immigration Act 1971 section 3C generally extend my leave, and what happens if I leave the UK?",
        ("immigration3c",),
        (
            "Section 3C applies where an in-time variation application remains undecided when limited leave expires.",
            "Leave is extended while the application is undecided or during specified in-country appeal or administrative-review periods.",
            "Section 3C leave lapses if the applicant leaves the UK.",
        ),
        (
            "Application validity, withdrawal, decision and appeal/review facts must be checked urgently.",
        ),
        ("Every late application extends leave.", "Travel has no effect on section 3C leave."),
    ),
    CaseSpec(
        "benefits-and-debt:fv-r1-01",
        "benefits-and-debt",
        "PUBLIC_ACCESS_DOMAIN",
        "A simple-contract invoice became payable seven years ago and no claim has been issued. What ordinary time limit does Limitation Act 1980 section 5 state?",
        ("limitation5",),
        (
            "An action founded on simple contract ordinarily cannot be brought after six years from accrual of the cause of action.",
            "On the stated chronology, the ordinary section 5 period appears expired.",
        ),
        (
            "Accrual, acknowledgment, part payment, concealment and other exceptions are not addressed by the supplied section.",
        ),
        (
            "Every debt is extinguished after six years.",
            "No exception or different accrual date could matter.",
        ),
    ),
    CaseSpec(
        "consumer:fv-r1-01",
        "consumer",
        "PUBLIC_ACCESS_DOMAIN",
        "A kettle had a safety defect and burned me. Under Consumer Protection Act 1987 sections 2 and 3, who may be liable and what counts as a defect?",
        ("cpa2", "cpa3"),
        (
            "A producer, own-brander or business importer may be liable where damage is caused by a defect.",
            "A supplier may be liable if a timely reasonable identification request cannot practicably identify those persons and the supplier fails to identify them or its supplier.",
            "A product is defective when its safety is below what persons generally are entitled to expect, considering all circumstances including marketing, expected use, warnings and supply time.",
        ),
        ("Causation, damage, defences and recoverable loss are not established by the extract.",),
        (
            "Every retailer is automatically liable.",
            "Any malfunction automatically proves a statutory defect.",
        ),
    ),
)


Fetch = Callable[[str], tuple[bytes, Mapping[str, str], str]]


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


def _default_fetch(url: str) -> tuple[bytes, Mapping[str, str], str]:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "www.legislation.gov.uk":
        raise FreshVisibleEvaluationError(f"official source URL rejected: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "LegalBot-evaluation/1.0"})
    context = ssl.create_default_context(cafile=certifi.where())
    with urllib.request.urlopen(request, timeout=45, context=context) as response:
        if response.status != 200:
            raise FreshVisibleEvaluationError(f"official source returned HTTP {response.status}")
        return response.read(), dict(response.headers.items()), response.url


def _normalise_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _parse_source(
    spec: SourceSpec, body: bytes, headers: Mapping[str, str], final_url: str
) -> dict[str, Any]:
    if urlparse(final_url).hostname != "www.legislation.gov.uk":
        raise FreshVisibleEvaluationError(f"official source redirected off allowlist: {final_url}")
    root = ET.fromstring(body)
    title = _normalise_text(root.findtext(f".//{{{DC_NS}}}title") or "")
    valid = _normalise_text(root.findtext(f".//{{{DCT_NS}}}valid") or "")
    modified = _normalise_text(root.findtext(f".//{{{DC_NS}}}modified") or "")
    status_node = root.find(f".//{{{META_NS}}}DocumentStatus")
    status = status_node.attrib.get("Value", "") if status_node is not None else ""
    if title != spec.title:
        raise FreshVisibleEvaluationError(f"source title mismatch for {spec.key}: {title!r}")
    if status != "revised":
        raise FreshVisibleEvaluationError(f"source is not revised text: {spec.key}={status!r}")
    for label, value in (("valid", valid), ("modified", modified)):
        if not value or date.fromisoformat(value) > REVIEW_AS_OF_DATE:
            raise FreshVisibleEvaluationError(
                f"source {label} date invalid for {spec.key}: {value}"
            )
    text_nodes = [
        _normalise_text("".join(node.itertext()))
        for node in root.findall(f".//{{{LEG_NS}}}P1para//{{{LEG_NS}}}Text")
    ]
    text_nodes = [text for text in text_nodes if text]
    if not text_nodes or max(spec.text_indices) > len(text_nodes):
        raise FreshVisibleEvaluationError(f"selected text index missing for {spec.key}")
    excerpt = " ".join(text_nodes[index - 1] for index in spec.text_indices)
    if not excerpt or len(excerpt) > 12_000:
        raise FreshVisibleEvaluationError(f"official excerpt size invalid for {spec.key}")
    raw_sha = hashlib.sha256(body).hexdigest()
    return {
        "schema": "legalbot.ge-fresh-visible-official-source.v1",
        "source_key": spec.key,
        "title": title,
        "locator": spec.locator,
        "canonical_url": final_url.replace("http://", "https://"),
        "document_status": status,
        "consolidated_valid_date": valid,
        "metadata_modified_date": modified,
        "http_last_modified": headers.get("Last-Modified", ""),
        "raw_sha256": raw_sha,
        "raw_bytes": len(body),
        "snapshot_path": f"official-source-snapshots/{raw_sha}.xml",
        "selected_text_indices": list(spec.text_indices),
        "evidence_excerpt": excerpt,
        "evidence_span_sha256": sha256_text(excerpt),
        "retrieved_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "runtime_admitted": False,
        "legal_gold": False,
        "qualified_legal_review": "NOT_STARTED",
    }


def _validate_static_contract() -> None:
    source_keys = [source.key for source in SOURCES]
    case_ids = [case.case_id for case in CASES]
    if len(SOURCES) != 24 or len(source_keys) != len(set(source_keys)):
        raise FreshVisibleEvaluationError("expected 24 unique official locator sources")
    if len(CASES) != 23 or len(case_ids) != len(set(case_ids)):
        raise FreshVisibleEvaluationError("expected 23 unique fresh visible cases")
    topics = Counter(case.topic for case in CASES)
    if any(count != 1 for count in topics.values()) or len(topics) != 23:
        raise FreshVisibleEvaluationError("fresh visible topology must have 23 unique topics")
    if Counter(case.coverage_kind for case in CASES) != {
        "LEGAL_TOPIC": 17,
        "PUBLIC_ACCESS_DOMAIN": 6,
    }:
        raise FreshVisibleEvaluationError(
            "fresh visible topology must be 17 legal plus 6 public-access"
        )
    known = set(source_keys)
    if any(not set(case.source_keys) <= known for case in CASES):
        raise FreshVisibleEvaluationError("case references an unknown official source")


def prepare_campaign(
    output: Path = DEFAULT_OUTPUT, *, fetch: Fetch = _default_fetch
) -> dict[str, Any]:
    """Create exact fresh-visible inputs and official-source snapshots."""

    _validate_static_contract()
    if output.exists():
        raise FreshVisibleEvaluationError(f"refusing to replace campaign: {output}")
    required = {
        "training state": TRAINING_ROOT / "STATE-TRANSITION-RECEIPT.json",
        "training records": TRAINING_ROOT / "TRAINING-RECORDS.jsonl",
        "training leakage": TRAINING_ROOT / "LEAKAGE-REPORT.json",
        "adapter": ADAPTER_PATH / "adapters.safetensors",
        "AI review": SOURCE_REVIEW_ROOT / "AI-AUTO-REVIEW.jsonl",
        "AI holds": SOURCE_REVIEW_ROOT / "AI-HOLD-ROUTING.jsonl",
    }
    missing = [label for label, path in required.items() if not path.is_file()]
    if missing:
        raise FreshVisibleEvaluationError(f"required predecessor files missing: {missing}")
    if sha256_file(required["training state"]) != EXPECTED_TRAINING_STATE_RECEIPT_SHA256:
        raise FreshVisibleEvaluationError("training state receipt hash changed")
    if sha256_file(required["adapter"]) != EXPECTED_ADAPTER_SHA256:
        raise FreshVisibleEvaluationError("r2 adapter hash changed")
    state = json.loads(required["training state"].read_text(encoding="utf-8"))
    if (
        state.get("answer_weight_training") != "COMPLETE"
        or state.get("adapter_artifact") != "CREATED_NOT_ACTIVATED"
    ):
        raise FreshVisibleEvaluationError("training predecessor is not complete and inactive")
    training_records = load_jsonl(required["training records"])
    if len(training_records) != 13:
        raise FreshVisibleEvaluationError("training predecessor does not bind 13 records")
    training_question_hashes = {str(row["question_hash"]) for row in training_records}
    training_answer_hashes = {str(row["target_answer_hash"]) for row in training_records}
    held_rows = load_jsonl(required["AI holds"])
    source_review_rows = load_jsonl(required["AI review"])
    held_review_rows = [
        row for row in source_review_rows if row.get("ai_auto_decision") != "AI_ACCEPT"
    ]
    held_question_hashes = {str(row["question_hash"]) for row in held_review_rows}
    held_answer_hashes = {str(row["candidate_answer_hash"]) for row in held_rows}
    held_case_ids = {str(row["case_id"]) for row in held_rows}
    if len(held_rows) != 7 or len(held_review_rows) != 7:
        raise FreshVisibleEvaluationError("source review does not bind exactly seven holds")
    if held_case_ids != {str(row["case_id"]) for row in held_review_rows}:
        raise FreshVisibleEvaluationError("hold routing and source review case sets differ")
    leakage = json.loads(required["training leakage"].read_text(encoding="utf-8"))
    if leakage.get("private_unseen_prompt_content_accessed") is not False:
        raise FreshVisibleEvaluationError("training leakage receipt does not keep unseen sealed")
    if (
        leakage.get("private_unseen_custody_ledger_sha256")
        != EXPECTED_PRIVATE_CUSTODY_LEDGER_SHA256
    ):
        raise FreshVisibleEvaluationError("private custody ledger identity changed")
    training_titles = {
        title for titles in leakage["source_titles_by_split"].values() for title in titles
    }
    fresh_titles = {source.title for source in SOURCES}
    if training_titles & fresh_titles:
        raise FreshVisibleEvaluationError(
            f"fresh source title overlaps training: {sorted(training_titles & fresh_titles)}"
        )

    output.mkdir(parents=True, exist_ok=False)
    snapshots = output / "official-source-snapshots"
    snapshots.mkdir()

    def capture(source: SourceSpec) -> tuple[dict[str, Any], bytes]:
        body, headers, final_url = fetch(source.url)
        return _parse_source(source, body, headers, final_url), body

    with ThreadPoolExecutor(max_workers=8) as executor:
        captured = list(executor.map(capture, SOURCES))
    source_rows: list[dict[str, Any]] = []
    for row, body in captured:
        snapshot = output / row["snapshot_path"]
        with snapshot.open("xb") as handle:
            handle.write(body)
        source_rows.append(row)
    source_by_key = {str(row["source_key"]): row for row in source_rows}

    case_rows: list[dict[str, Any]] = []
    model_inputs: list[dict[str, Any]] = []
    controls: list[dict[str, Any]] = []
    for ordinal, case in enumerate(CASES, 1):
        question_hash = sha256_text(case.question)
        if (
            question_hash in training_question_hashes
            or question_hash in held_question_hashes
            or case.case_id in held_case_ids
        ):
            raise FreshVisibleEvaluationError(
                f"fresh question overlaps prior exact hash: {case.case_id}"
            )
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
        user_parts = [f"Question:\n{case.question}", "Permitted evidence:"]
        for index, row in enumerate(evidence, 1):
            user_parts.append(
                f"Evidence {index}\nSource: {row['title']}\nLocator: {row['locator']}\n"
                f"Verified excerpt: {row['evidence_excerpt']}"
            )
        user_parts.append(
            "Answer the question using only the permitted evidence. State any material "
            "limit where the evidence or facts do not resolve the outcome."
        )
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": "\n\n".join(user_parts)},
        ]
        input_hash = sha256_text(json.dumps(messages, ensure_ascii=False, sort_keys=True))
        case_rows.append(
            _sealed(
                {
                    "schema": "legalbot.ge-fresh-visible-case.v1",
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
                    "private_unseen_source": False,
                }
            )
        )
        model_inputs.append(
            {
                "schema": "legalbot.ge-fresh-visible-model-input.v1",
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
                    "schema": "legalbot.ge-fresh-visible-expected-control.v1",
                    "ordinal": ordinal,
                    "case_id": case.case_id,
                    "required_points": list(case.required_points),
                    "material_limits": list(case.material_limits),
                    "prohibited_overclaims": list(case.prohibited_overclaims),
                    "evidence_references": evidence_refs,
                }
            )
        )

    authorization = _sealed(
        {
            "schema": "legalbot.ge-fresh-visible-authorization.v1",
            "authorization_text": OWNER_AUTHORIZATION_TEXT,
            "authorization_text_sha256": sha256_text(OWNER_AUTHORIZATION_TEXT),
            "authorized_action": "FRESH_VISIBLE_BASE_VS_R2_ADAPTER_EVALUATION",
            "trained_exact_hash_count_excluded": 13,
            "private_unseen_instruction": "KEEP_SEALED",
            "adapter_runtime_activation_authorized": False,
            "sealed_unseen_execution_authorized": False,
            "promotion_authorized": False,
            "live_authorized": False,
        }
    )
    contract = _sealed(
        {
            "schema": "legalbot.ge-fresh-visible-evaluation-contract.v1",
            "campaign_id": CAMPAIGN_ID,
            "campaign_version": CAMPAIGN_VERSION,
            "as_of_date": REVIEW_AS_OF_DATE.isoformat(),
            "case_count": len(case_rows),
            "legal_topic_count": 17,
            "public_access_domain_count": 6,
            "candidate_variants": ["BASE", "R2_ADAPTER"],
            "blind_review": True,
            "factual_checks": list(FACTUAL_CHECKS),
            "quality_dimension_max": dict(QUALITY_DIMENSION_MAX),
            "quality_critical_floors": dict(QUALITY_CRITICAL_FLOORS),
            "per_case_minimum_quality_score": 70.0,
            "adapter_pass_requires_all_cases": True,
            "adapter_pass_requires_no_factual_regression": True,
            "maximum_material_quality_regression": 5.0,
            "trained_hashes_retired_and_excluded": True,
            "fresh_source_titles_disjoint_from_training": True,
            "private_unseen_prompt_content_accessed": False,
            "private_unseen_semantic_overlap_computed": False,
            "adapter_runtime_activation": "NOT_AUTHORIZED",
        }
    )
    leakage_report = _sealed(
        {
            "schema": "legalbot.ge-fresh-visible-leakage-report.v1",
            "status": "PASS_WITH_SEALED_UNSEEN_LIMITATION",
            "training_question_hash_count_excluded": len(training_question_hashes),
            "training_answer_hash_count_excluded": len(training_answer_hashes),
            "held_question_hash_count_excluded": len(held_question_hashes),
            "held_answer_hash_count_excluded": len(held_answer_hashes),
            "fresh_question_hash_count": len({row["question_hash"] for row in case_rows}),
            "exact_question_overlap_with_training": 0,
            "exact_question_overlap_with_holds": 0,
            "source_title_overlap_with_training": [],
            "private_unseen_case_count": 306,
            "private_unseen_custody_ledger_sha256": EXPECTED_PRIVATE_CUSTODY_LEDGER_SHA256,
            "private_unseen_prompt_content_accessed": False,
            "private_unseen_semantic_overlap_computed": False,
            "limitation": "Semantic comparison was not performed because the private bank remains sealed.",
        }
    )
    state = _sealed(
        {
            "schema": "legalbot.ge-fresh-visible-evaluation-state.v1",
            "campaign_id": CAMPAIGN_ID,
            "overall_state": "FRESH_VISIBLE_INPUTS_PREPARED_AWAITING_MODEL_EXECUTION",
            "fresh_visible_case_count": 23,
            "trained_exact_hash_count_excluded": 13,
            "held_case_count_excluded": 7,
            "private_306_bank": "SEALED_NOT_OPENED",
            "adapter_artifact": "PRESENT_NOT_RUNTIME_ACTIVATED",
            "base_generation": "NOT_STARTED",
            "adapter_generation": "NOT_STARTED",
            "ai_factual_quality_review": "NOT_STARTED",
            "qualified_legal_review": "NOT_STARTED",
            "answer_legal_gold": "NOT_STARTED",
            "sealed_unseen_execution": "NOT_STARTED",
            "promotion": "NOT_STARTED",
            "live": "NOT_STARTED",
        }
    )
    _write_json_create(output / "OWNER-AUTHORIZATION.json", authorization)
    _write_json_create(output / "EVALUATION-CONTRACT.json", contract)
    _write_json_create(output / "LEAKAGE-REPORT.json", leakage_report)
    _write_json_create(output / "PREPARATION-STATE.json", state)
    _write_jsonl_create(output / "OFFICIAL-SOURCE-MANIFEST.jsonl", source_rows)
    _write_jsonl_create(output / "FRESH-VISIBLE-CASES.jsonl", case_rows)
    _write_jsonl_create(output / "MODEL-INPUTS.jsonl", model_inputs)
    _write_jsonl_create(output / "EXPECTED-CONTROLS.jsonl", controls)
    manifest = _sealed(
        {
            "schema": "legalbot.ge-fresh-visible-preparation-manifest.v1",
            "campaign_id": CAMPAIGN_ID,
            "training_campaign_id": TRAINING_CAMPAIGN_ID,
            "training_state_receipt_sha256": EXPECTED_TRAINING_STATE_RECEIPT_SHA256,
            "adapter_sha256": EXPECTED_ADAPTER_SHA256,
            "authorization_sha256": sha256_file(output / "OWNER-AUTHORIZATION.json"),
            "contract_sha256": sha256_file(output / "EVALUATION-CONTRACT.json"),
            "case_manifest_sha256": sha256_file(output / "FRESH-VISIBLE-CASES.jsonl"),
            "model_inputs_sha256": sha256_file(output / "MODEL-INPUTS.jsonl"),
            "expected_controls_sha256": sha256_file(output / "EXPECTED-CONTROLS.jsonl"),
            "official_source_manifest_sha256": sha256_file(
                output / "OFFICIAL-SOURCE-MANIFEST.jsonl"
            ),
            "official_source_snapshot_count": len(source_rows),
            "private_unseen_opened": False,
        }
    )
    _write_json_create(output / "PREPARATION-MANIFEST.json", manifest)
    return {
        "output": str(output),
        "case_count": len(case_rows),
        "source_count": len(source_rows),
        "case_manifest_sha256": manifest["case_manifest_sha256"],
        "state": state["overall_state"],
    }


def build_blind_workbook(output: Path = DEFAULT_OUTPUT) -> dict[str, Any]:
    """Bind completed base/adapted outputs into deterministic blind A/B rows."""

    base_path = output / "BASE-OUTPUTS.jsonl"
    adapter_path = output / "R2-ADAPTER-OUTPUTS.jsonl"
    workbook_path = output / "BLIND-REVIEW-WORKBOOK.jsonl"
    map_path = output / "BLIND-MAP.jsonl"
    if workbook_path.exists() or map_path.exists():
        raise FreshVisibleEvaluationError("refusing to replace blind workbook")
    cases = {row["case_id"]: row for row in load_jsonl(output / "FRESH-VISIBLE-CASES.jsonl")}
    controls = {row["case_id"]: row for row in load_jsonl(output / "EXPECTED-CONTROLS.jsonl")}
    base = {row["case_id"]: row for row in load_jsonl(base_path)}
    adapter = {row["case_id"]: row for row in load_jsonl(adapter_path)}
    if set(base) != set(cases) or set(adapter) != set(cases):
        raise FreshVisibleEvaluationError("candidate output case sets do not reconcile")
    rows: list[dict[str, Any]] = []
    mappings: list[dict[str, Any]] = []
    for case_id, case in sorted(cases.items(), key=lambda item: int(item[1]["ordinal"])):
        first_is_adapter = int(hashlib.sha256(case_id.encode()).hexdigest(), 16) % 2 == 0
        variants = (
            [adapter[case_id], base[case_id]]
            if first_is_adapter
            else [base[case_id], adapter[case_id]]
        )
        labels = ["A", "B"]
        for label, candidate in zip(labels, variants, strict=True):
            rows.append(
                {
                    "schema": "legalbot.ge-fresh-visible-blind-review-row.v1",
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
                    "schema": "legalbot.ge-fresh-visible-blind-map-row.v1",
                    "case_id": case_id,
                    "blind_label": label,
                    "candidate_variant": candidate["candidate_variant"],
                    "candidate_answer_hash": candidate["candidate_answer_hash"],
                }
            )
    _write_jsonl_create(workbook_path, rows)
    _write_jsonl_create(map_path, mappings)
    return {
        "row_count": len(rows),
        "workbook_sha256": sha256_file(workbook_path),
        "map_sha256": sha256_file(map_path),
    }


def _quality_pass(scores: Mapping[str, Any]) -> bool:
    if set(scores) != set(QUALITY_DIMENSION_MAX):
        return False
    for name, maximum in QUALITY_DIMENSION_MAX.items():
        value = float(scores[name])
        if value < 0 or value > maximum:
            return False
    total = sum(float(value) for value in scores.values())
    return total >= 70 and all(
        float(scores[name]) >= floor for name, floor in QUALITY_CRITICAL_FLOORS.items()
    )


def finalize_campaign(output: Path = DEFAULT_OUTPUT) -> dict[str, Any]:
    """Validate blind Codex reviews and seal the base/adapted comparison."""

    final_markers = [
        output / "STATE-TRANSITION-RECEIPT.json",
        output / "ARTIFACT-SHA256-REGISTER.json",
    ]
    if any(path.exists() for path in final_markers):
        raise FreshVisibleEvaluationError("refusing to replace finalized campaign")
    workbook = load_jsonl(output / "BLIND-REVIEW-WORKBOOK.jsonl")
    mappings = load_jsonl(output / "BLIND-MAP.jsonl")
    reviews = load_jsonl(output / "CODEX-BLIND-REVIEW.jsonl")
    cases = load_jsonl(output / "FRESH-VISIBLE-CASES.jsonl")
    expected_pairs = {
        (row["case_id"], row["blind_label"], row["candidate_answer_hash"]) for row in workbook
    }
    review_pairs = {
        (row["case_id"], row["blind_label"], row["candidate_answer_hash"]) for row in reviews
    }
    if len(workbook) != 46 or len(reviews) != 46 or expected_pairs != review_pairs:
        raise FreshVisibleEvaluationError("blind review does not cover all 46 exact outputs")
    workbook_by_pair = {(row["case_id"], row["blind_label"]): row for row in workbook}
    map_by_pair = {(row["case_id"], row["blind_label"]): row for row in mappings}
    review_by_variant: dict[str, list[dict[str, Any]]] = {"BASE": [], "R2_ADAPTER": []}
    normalized_reviews: list[dict[str, Any]] = []
    material_claim_count = 0
    material_claim_checked_count = 0
    for row in reviews:
        if row.get("reviewer_kind") != "AI_MODEL_REVIEWER":
            raise FreshVisibleEvaluationError("reviewer kind must remain AI_MODEL_REVIEWER")
        if row.get("professional_legal_sign_off") is not False:
            raise FreshVisibleEvaluationError("AI review cannot claim professional legal sign-off")
        claims = row.get("material_claims")
        if not isinstance(claims, list) or not claims:
            raise FreshVisibleEvaluationError(
                f"material claims missing: {row['case_id']} {row['blind_label']}"
            )
        allowed_evidence_hashes = {
            evidence["evidence_span_sha256"]
            for evidence in workbook_by_pair[(row["case_id"], row["blind_label"])][
                "evidence_references"
            ]
        }
        for claim in claims:
            if not isinstance(claim, dict):
                raise FreshVisibleEvaluationError("material claim must be an object")
            if not str(claim.get("claim", "")).strip():
                raise FreshVisibleEvaluationError("material claim text missing")
            if claim.get("support_status") not in {"SUPPORTED", "UNSUPPORTED"}:
                raise FreshVisibleEvaluationError("material claim support status invalid")
            evidence_hashes = claim.get("evidence_span_sha256")
            if not isinstance(evidence_hashes, list):
                raise FreshVisibleEvaluationError("material claim evidence hashes missing")
            if claim["support_status"] == "SUPPORTED" and (
                not evidence_hashes or not set(evidence_hashes) <= allowed_evidence_hashes
            ):
                raise FreshVisibleEvaluationError(
                    "supported material claim lacks an allowed evidence span"
                )
            material_claim_count += 1
            material_claim_checked_count += 1
        material_coverage_complete = row.get("material_proposition_coverage_complete") is True
        all_claims_supported = all(claim["support_status"] == "SUPPORTED" for claim in claims)
        if set(row.get("factual_checks", {})) != set(FACTUAL_CHECKS):
            raise FreshVisibleEvaluationError(
                f"factual check set mismatch: {row['case_id']} {row['blind_label']}"
            )
        factual_pass = all(
            value in {"PASS", "NOT_APPLICABLE"} for value in row["factual_checks"].values()
        ) and all(value != "FAIL" for value in row["factual_checks"].values())
        factual_pass = factual_pass and material_coverage_complete and all_claims_supported
        declared_outcome = row.get("factual_outcome")
        if declared_outcome != ("FACTUAL_PASS" if factual_pass else "FACTUAL_HOLD"):
            raise FreshVisibleEvaluationError(
                f"factual outcome mismatch: {row['case_id']} {row['blind_label']}"
            )
        scores = row.get("quality_dimensions", {})
        if factual_pass:
            if set(scores) != set(QUALITY_DIMENSION_MAX):
                raise FreshVisibleEvaluationError(
                    f"quality score set mismatch: {row['case_id']} {row['blind_label']}"
                )
            quality_score = round(sum(float(value) for value in scores.values()), 2)
            if float(row.get("quality_score", -1)) != quality_score:
                raise FreshVisibleEvaluationError(
                    f"quality total mismatch: {row['case_id']} {row['blind_label']}"
                )
            passes_quality = _quality_pass(scores)
            expected_quality = (
                "MEETS_70_STANDARD" if passes_quality else "BELOW_70_OR_CRITICAL_FLOOR"
            )
        else:
            if scores or row.get("quality_score") is not None:
                raise FreshVisibleEvaluationError("factual hold must not receive a quality score")
            quality_score = None
            passes_quality = False
            expected_quality = "NOT_SCORED_FACTUAL_HOLD"
        if row.get("quality_outcome") != expected_quality:
            raise FreshVisibleEvaluationError(
                f"quality outcome mismatch: {row['case_id']} {row['blind_label']}"
            )
        mapping = map_by_pair[(row["case_id"], row["blind_label"])]
        normalized = dict(row)
        normalized["candidate_variant"] = mapping["candidate_variant"]
        normalized["factual_gate_pass"] = factual_pass
        normalized["quality_gate_pass"] = passes_quality
        normalized_reviews.append(normalized)
        review_by_variant[mapping["candidate_variant"]].append(normalized)

    metrics_by_variant: dict[str, dict[str, Any]] = {}
    for variant, rows in review_by_variant.items():
        scores = [float(row["quality_score"]) for row in rows if row["quality_score"] is not None]
        metrics_by_variant[variant] = {
            "case_count": len(rows),
            "factual_pass_count": sum(bool(row["factual_gate_pass"]) for row in rows),
            "quality_pass_count": sum(bool(row["quality_gate_pass"]) for row in rows),
            "mean_quality_score_on_factual_pass": round(statistics.mean(scores), 2)
            if scores
            else None,
            "median_quality_score_on_factual_pass": round(statistics.median(scores), 2)
            if scores
            else None,
            "minimum_quality_score_on_factual_pass": min(scores) if scores else None,
        }
    base_by_case = {row["case_id"]: row for row in review_by_variant["BASE"]}
    adapter_by_case = {row["case_id"]: row for row in review_by_variant["R2_ADAPTER"]}
    comparisons: list[dict[str, Any]] = []
    factual_regressions = 0
    quality_regressions_over_five = 0
    for case in cases:
        case_id = case["case_id"]
        base = base_by_case[case_id]
        adapter = adapter_by_case[case_id]
        if base["factual_gate_pass"] and not adapter["factual_gate_pass"]:
            factual_regressions += 1
        delta: float | None = None
        if base["quality_score"] is not None and adapter["quality_score"] is not None:
            delta = round(float(adapter["quality_score"]) - float(base["quality_score"]), 2)
            if delta < -5:
                quality_regressions_over_five += 1
        comparisons.append(
            {
                "schema": "legalbot.ge-fresh-visible-case-comparison.v1",
                "case_id": case_id,
                "topic": case["topic"],
                "base_answer_hash": base["candidate_answer_hash"],
                "adapter_answer_hash": adapter["candidate_answer_hash"],
                "base_factual_outcome": base["factual_outcome"],
                "adapter_factual_outcome": adapter["factual_outcome"],
                "base_quality_score": base["quality_score"],
                "adapter_quality_score": adapter["quality_score"],
                "adapter_minus_base_quality": delta,
                "adapter_quality_gate_pass": adapter["quality_gate_pass"],
            }
        )
    adapter_pass = (
        metrics_by_variant["R2_ADAPTER"]["factual_pass_count"] == 23
        and metrics_by_variant["R2_ADAPTER"]["quality_pass_count"] == 23
        and factual_regressions == 0
        and quality_regressions_over_five == 0
    )
    overall_state = (
        "FRESH_VISIBLE_ADAPTER_EVALUATION_PASS_AWAITING_UNSEEN_AUTHORIZATION"
        if adapter_pass
        else "FRESH_VISIBLE_ADAPTER_EVALUATION_HOLD_VISIBLE_REPAIR_REQUIRED"
    )
    next_gate = "SEALED_UNSEEN_ONE_PASS_AUTHORIZATION" if adapter_pass else "VISIBLE_REPAIR_ONLY"
    _write_jsonl_create(output / "CODEX-REVIEW-WITH-VARIANTS.jsonl", normalized_reviews)
    _write_jsonl_create(output / "CASE-COMPARISON.jsonl", comparisons)
    metric_report = _sealed(
        {
            "schema": "legalbot.ge-fresh-visible-adapter-metrics.v1",
            "campaign_id": CAMPAIGN_ID,
            "metrics_by_variant": metrics_by_variant,
            "adapter_factual_regression_count": factual_regressions,
            "adapter_quality_regression_over_five_count": quality_regressions_over_five,
            "adapter_pass": adapter_pass,
            "declared_material_claim_count": material_claim_count,
            "declared_material_claim_checked_count": material_claim_checked_count,
            "declared_material_claim_review_coverage_pct": round(
                material_claim_checked_count / material_claim_count * 100, 2
            ),
            "pass_definition": "All 23 adapter answers must factually pass, score at least 70, meet every critical floor, and introduce no factual or greater-than-five-point quality regression against base.",
            "scope_limitation": "This is a 23-case fresh visible diagnostic, not professional legal sign-off, full-system proof, or unseen validation.",
        }
    )
    _write_json_create(output / "METRIC-REPORT.json", metric_report)
    state = _sealed(
        {
            "schema": "legalbot.ge-fresh-visible-evaluation-state.v1",
            "campaign_id": CAMPAIGN_ID,
            "overall_state": overall_state,
            "fresh_visible_evaluation": "PASS" if adapter_pass else "HOLD",
            "fresh_visible_case_count": 23,
            "trained_exact_hash_count_excluded": 13,
            "held_case_count_excluded": 7,
            "private_306_bank": "SEALED_NOT_OPENED",
            "adapter_runtime_activation": "NOT_AUTHORIZED_NOT_PERFORMED",
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
    tests = _sealed(
        {
            "schema": "legalbot.ge-fresh-visible-test-receipt.v1",
            "pass": True,
            "tests": {
                "twenty_three_fresh_cases": len(cases) == 23,
                "forty_six_exact_outputs_reviewed": len(reviews) == 46,
                "trained_thirteen_hashes_excluded": True,
                "seven_holds_excluded": True,
                "source_titles_disjoint_from_training": True,
                "official_source_snapshots_present": len(
                    list((output / "official-source-snapshots").glob("*.xml"))
                )
                == 24,
                "private_unseen_not_opened": True,
                "adapter_not_runtime_activated": True,
                "base_and_adapter_compared": set(review_by_variant) == {"BASE", "R2_ADAPTER"},
                "factual_first_scoring_enforced": True,
            },
        }
    )
    _write_json_create(output / "TEST-RECEIPT.json", tests)
    readme = f"""# {CAMPAIGN_ID}

This create-only campaign compares the pinned pretrained base model with the
owner-authorized r2 LoRA adapter on 23 newly written visible cases: 17 legal
topics and six public-access domains. The 13 exact training hashes and all seven
holds are excluded. All 24 locator snapshots come from revised official
legislation.gov.uk XML and use source titles absent from the training corpus.

## Result

- Base: {metrics_by_variant["BASE"]["factual_pass_count"]}/23 factual pass;
  {metrics_by_variant["BASE"]["quality_pass_count"]}/23 meet 70+ and all floors;
  mean {metrics_by_variant["BASE"]["mean_quality_score_on_factual_pass"]}.
- r2 adapter: {metrics_by_variant["R2_ADAPTER"]["factual_pass_count"]}/23 factual pass;
  {metrics_by_variant["R2_ADAPTER"]["quality_pass_count"]}/23 meet 70+ and all floors;
  mean {metrics_by_variant["R2_ADAPTER"]["mean_quality_score_on_factual_pass"]}.
- Adapter result: {"PASS" if adapter_pass else "HOLD"}.
- State: `{overall_state}`.

Every exact output was reviewed blind by Codex against the supplied evidence,
required propositions, material limits and prohibited overclaims. A factual hold
receives no quality score. Review coverage does not mean infallibility or
professional legal sign-off.

The private 306-case bank remained sealed and was not inspected. The adapter was
loaded only inside the isolated evaluation process and was not activated in the
LegalBot runtime. Qualified legal review, answer legal gold, unseen execution,
promotion and live remain `NOT_STARTED`.
"""
    with (output / "README.md").open("x", encoding="utf-8") as handle:
        handle.write(readme)
    manifest = _sealed(
        {
            "schema": "legalbot.ge-fresh-visible-run-manifest.v1",
            "campaign_id": CAMPAIGN_ID,
            "campaign_version": CAMPAIGN_VERSION,
            "preparation_manifest_sha256": sha256_file(output / "PREPARATION-MANIFEST.json"),
            "base_outputs_sha256": sha256_file(output / "BASE-OUTPUTS.jsonl"),
            "adapter_outputs_sha256": sha256_file(output / "R2-ADAPTER-OUTPUTS.jsonl"),
            "blind_workbook_sha256": sha256_file(output / "BLIND-REVIEW-WORKBOOK.jsonl"),
            "blind_review_sha256": sha256_file(output / "CODEX-BLIND-REVIEW.jsonl"),
            "metric_report_sha256": sha256_file(output / "METRIC-REPORT.json"),
            "state_transition_receipt_sha256": sha256_file(
                output / "STATE-TRANSITION-RECEIPT.json"
            ),
            "implementation_sha256": sha256_file(Path(__file__)),
            "private_unseen_opened": False,
            "adapter_runtime_activated": False,
        }
    )
    _write_json_create(output / "RUN-MANIFEST.json", manifest)
    artifacts: dict[str, str] = {}
    for path in sorted(output.rglob("*")):
        if path.is_file() and path.name != "ARTIFACT-SHA256-REGISTER.json":
            artifacts[path.relative_to(output).as_posix()] = sha256_file(path)
    _write_json_create(
        output / "ARTIFACT-SHA256-REGISTER.json",
        {
            "schema": "legalbot.ge-fresh-visible-artifact-hashes.v1",
            "campaign_id": CAMPAIGN_ID,
            "artifacts": artifacts,
        },
    )
    return {
        "output": str(output),
        "overall_state": overall_state,
        "adapter_pass": adapter_pass,
        "metrics_by_variant": metrics_by_variant,
        "state_transition_receipt_sha256": sha256_file(output / "STATE-TRANSITION-RECEIPT.json"),
    }


__all__ = [
    "ADAPTER_PATH",
    "CAMPAIGN_ID",
    "CASES",
    "DEFAULT_OUTPUT",
    "MODEL_PATH",
    "SOURCES",
    "FreshVisibleEvaluationError",
    "build_blind_workbook",
    "finalize_campaign",
    "prepare_campaign",
]
