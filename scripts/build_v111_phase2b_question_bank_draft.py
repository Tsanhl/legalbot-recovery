#!/usr/bin/env python3
"""Build a non-authorizing Phase 2B topic question-bank draft.

This builder creates synthetic questions only.  It does not admit sources, run an
answer model, create a retrieval index, start Phase 2B, or create a validation set.
The visible questions it publishes are development/remediation candidates and are
therefore permanently ineligible for use as frozen unseen validation questions.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LAW_ROOT = Path("/Users/hltsang/Desktop/Law")
OUTPUT_PARENT = PROJECT_ROOT / "data/evaluations/phase2b-question-drafts"
RUN_NAME = "LegalBot-Phase2B-2026-08-28-question-bank-draft-r2"
OUTPUT_ROOT = OUTPUT_PARENT / RUN_NAME

QUESTION_SCHEMA = "legalbot.v111.phase2b.development-question-draft.v1"
TOPIC_SCHEMA = "legalbot.v111.phase2b.topic-question-set-draft.v1"
PACKAGE_SCHEMA = "legalbot.v111.phase2b.question-bank-draft-package.v1"

QUESTION_TYPES = ("ESSAY", "PROBLEM_BASED", "GENERAL_ENQUIRY")
ACADEMIC_DIFFICULTIES = ("SCHOOL_COMPARABLE", "HARDER", "EVEN_HARDER")
GENERAL_DIFFICULTIES = ("EVERYDAY", "EVERYDAY", "EVERYDAY", "EVERYDAY", "MULTI_ISSUE", "BOUNDARY_OR_URGENT")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(payload: dict[str, Any], *, field: str = "record_content_sha256") -> dict[str, Any]:
    value = dict(payload)
    value[field] = _sha256_bytes(_canonical_json(value))
    return value


def _q(
    question_type: str,
    difficulty: str,
    prompt: str,
    issue_tags: tuple[str, ...],
    *,
    clarification_targets: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "question_type": question_type,
        "difficulty": difficulty,
        "prompt": " ".join(prompt.split()),
        "issue_tags": list(issue_tags),
        "clarification_targets": list(clarification_targets),
    }


TOPICS: dict[str, dict[str, Any]] = {}


def _register(
    topic_id: str,
    display_name: str,
    source_scope: tuple[str, ...],
    coverage: tuple[str, ...],
    questions: list[dict[str, Any]],
) -> None:
    if topic_id in TOPICS:
        raise ValueError(f"duplicate topic: {topic_id}")
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", topic_id):
        raise ValueError(f"invalid topic id: {topic_id}")
    if len(questions) != 18:
        raise ValueError(f"{topic_id} must contain exactly 18 questions")
    type_counts = Counter(str(item["question_type"]) for item in questions)
    if type_counts != {kind: 6 for kind in QUESTION_TYPES}:
        raise ValueError(f"{topic_id} question type distribution changed: {type_counts}")
    for kind in ("ESSAY", "PROBLEM_BASED"):
        difficulties = Counter(
            str(item["difficulty"])
            for item in questions
            if item["question_type"] == kind
        )
        if difficulties != {level: 2 for level in ACADEMIC_DIFFICULTIES}:
            raise ValueError(f"{topic_id} {kind} difficulty distribution changed")
    general_difficulties = [
        str(item["difficulty"])
        for item in questions
        if item["question_type"] == "GENERAL_ENQUIRY"
    ]
    if Counter(general_difficulties) != Counter(GENERAL_DIFFICULTIES):
        raise ValueError(f"{topic_id} general enquiry distribution changed")
    TOPICS[topic_id] = {
        "display_name": display_name,
        "source_scope": list(source_scope),
        "coverage": list(coverage),
        "questions": questions,
    }


STYLE_REFERENCES = (
    (
        "competition-formative-question",
        LAW_ROOT / "Competition Law/Competitive law formative/Competition law formative question .docx",
        "academic_problem_question_style",
    ),
    (
        "competition-summative-question",
        LAW_ROOT / "Competition Law/Competitive law summative/QUESTION_LAW3011-Competition-Law_June2026.docx",
        "advanced_academic_problem_question_style",
    ),
    (
        "commercial-summative-question",
        LAW_ROOT / "Y2 Law/Commerical law revision/Summative/1. QUESTION_LAW2241_Commercial_JUNE 2025.pdf",
        "short_critical_essay_style",
    ),
    (
        "criminal-formative-question",
        LAW_ROOT / "Y2 Law/Criminal law /Formative /Formative Question.docx",
        "multi_actor_problem_question_style",
    ),
    (
        "criminal-examination-question",
        LAW_ROOT / "Y2 Law/Exam/Criminal law exam/2221 QUESTION_LAW2221_Criminal _Law June2025.pdf",
        "essay_and_problem_examination_style",
    ),
    (
        "international-commercial-mediation-handbook",
        LAW_ROOT / "International Commercial Mediation/International Commercial Mediation LLB Handbook 2025-2026.pdf",
        "topic_scope_and_learning_outcomes",
    ),
    (
        "law-and-medicine-examination-question",
        LAW_ROOT / "Law and medicine/Law and medicine exam/EXAM_213071-Law-Medicine_June2026.pdf",
        "cross_topic_problem_and_reform_essay_style",
    ),
    (
        "law-and-medicine-handbook",
        LAW_ROOT / "Law and medicine/Tutorial /Law and Medicine Module Handbook with tutorial questions.pdf",
        "topic_scope_and_tutorial_question_style",
    ),
    (
        "land-law-examination-question",
        LAW_ROOT / "Y2 Law/Exam/Land law exam/Land law question.docx",
        "essay_and_problem_examination_style",
    ),
    (
        "pensions-formative-question",
        LAW_ROOT / "Pensions Law/Pensions law formative/25FE102025-v1  PLM2025 Formative Essay Questions.docx",
        "dense_fact_pattern_and_structured_advice_style",
    ),
    (
        "pensions-general-feedback",
        LAW_ROOT / "Pensions Law/Pensions law formative/6A122025-V2 - PLM 2025 FE Gen Feedback.docx",
        "difficulty_and_assessment_quality_profile",
    ),
    (
        "private-international-law-formative",
        LAW_ROOT / "Private International Law/Formative/PrivIL - Formative Assessment 2025-26.pdf",
        "quotation_led_open_essay_style",
    ),
    (
        "trusts-formative-question-one",
        LAW_ROOT / "Y2 Law/Trusts law/Formative in comments/Formative 1 Question.docx",
        "testamentary_trust_problem_style",
    ),
    (
        "trusts-formative-question-two",
        LAW_ROOT / "Y2 Law/Trusts law/Formative in comments/Formative 2 Question.docx",
        "fiduciary_and_tracing_problem_style",
    ),
    (
        "biolaw-question-choice",
        LAW_ROOT / "Y2 Law/Biolaw/Summative 1/Choice of Biolaw Question for part A and B.docx",
        "emerging_technology_essay_and_briefing_style",
    ),
    (
        "business-law-enterprise-scope",
        LAW_ROOT / "Y2 Law/Business law/14. Legal Requirements when Establishing a Business Enterprise _ Law Trove.pdf",
        "business_organisation_topic_scope",
    ),
    (
        "business-law-management-scope",
        LAW_ROOT / "Y2 Law/Business law/17. The Management of Corporations _ Law Trove.pdf",
        "corporate_management_topic_scope",
    ),
)


_register(
    "commercial-law",
    "Commercial Law",
    ("commercial-law-course-materials", "commercial-assessment-style"),
    (
        "sale of goods and remedies",
        "property and risk in goods",
        "nemo dat and good-faith acquisition",
        "retention of title",
        "agency and documentary transfers",
        "digital trade documents and insolvency interfaces",
    ),
    [
        _q(
            "ESSAY",
            "SCHOOL_COMPARABLE",
            "‘The law governing retention-of-title clauses gives suppliers an appearance of security but no coherent account of ownership once goods are processed or proceeds are received.’ Discuss.",
            ("retention-of-title", "proceeds", "manufactured-goods", "insolvency"),
        ),
        _q(
            "ESSAY",
            "SCHOOL_COMPARABLE",
            "Critically evaluate whether the statutory rules governing the passing of property and risk in contracts for the sale of goods remain fit for modern commercial supply chains.",
            ("passing-of-property", "risk", "ascertainment", "sale-of-goods"),
        ),
        _q(
            "ESSAY",
            "HARDER",
            "‘The nemo dat principle protects ownership only by transferring unacceptable fraud risk to innocent buyers.’ To what extent should commercial law prefer transactional security over the original owner’s title?",
            ("nemo-dat", "buyer-in-good-faith", "voidable-title", "commercial-certainty"),
        ),
        _q(
            "ESSAY",
            "HARDER",
            "The remedial structure of sale-of-goods law is said to distinguish conditions from warranties while increasingly deciding disputes through ideas of substantial performance and proportionality. Critically assess whether that structure remains coherent for business-to-business transactions.",
            ("classification-of-terms", "rejection", "damages", "business-sales"),
        ),
        _q(
            "ESSAY",
            "EVEN_HARDER",
            "Critically assess whether electronic trade documents can reproduce the possession, transfer and priority functions traditionally performed by paper documents of title without creating new systemic risks for third parties and insolvency office-holders.",
            ("electronic-trade-documents", "possession", "priority", "insolvency"),
        ),
        _q(
            "ESSAY",
            "EVEN_HARDER",
            "‘Commercial law still treats ownership, security and contractual allocation of risk as separable concepts, even though platform commerce and automated fulfilment collapse them into a single transaction.’ Critically evaluate this claim and the case for reform.",
            ("platform-commerce", "ownership", "security-interests", "risk-allocation"),
        ),
        _q(
            "PROBLEM_BASED",
            "SCHOOL_COMPARABLE",
            "North Quay Foods agrees to buy 600 labelled cases of olive oil from Mercia Imports. Two hundred cases are placed in a segregated bay bearing North Quay’s name; the remainder stay mixed with identical stock. North Quay pays in full. Before collection, a leak damages 80 segregated cases and Mercia enters administration. A second buyer claims 150 cases under a later contract and has already collected them. Advise North Quay on property, risk and its position in the administration.",
            ("specific-goods", "unascertained-goods", "appropriation", "risk", "insolvency"),
        ),
        _q(
            "PROBLEM_BASED",
            "SCHOOL_COMPARABLE",
            "A fashion retailer orders 120 coats for delivery by 1 September before a major launch. Delivery occurs five days late; 20 coats are missing and 25 have defective fasteners. The supplier offers replacement fasteners in three weeks and relies on a term limiting all liability to the invoice price. The retailer lost launch sales and bought emergency stock at a higher price. Advise the retailer on rejection, cure, damages and the limitation term.",
            ("late-delivery", "short-delivery", "defective-goods", "rejection", "damages", "limitation"),
        ),
        _q(
            "PROBLEM_BASED",
            "HARDER",
            "Gallery A leaves a valuable sculpture with Broker B solely for exhibition. B sells it to Dealer C using convincing but forged authority documents. C resells it to Collector D. Before delivery, A discovers the transaction. Separately, B sells a second work that A had authorised B to sell, but A had revoked that authority in an email that B says went to spam. Advise A, C and D on title to both works and any personal claims.",
            ("agency", "nemo-dat", "mercantile-agent", "revocation", "conversion"),
        ),
        _q(
            "PROBLEM_BASED",
            "HARDER",
            "ResinCo supplies polymer to Maker Ltd under a clause reserving title to the polymer, all products made from it and all sale proceeds until every invoice is paid. Maker mixes the polymer with material from other suppliers, manufactures components and sells some through an online marketplace whose payment provider retains the proceeds. Maker then becomes insolvent. Classify each part of ResinCo’s clause and advise on the remaining material, components and platform-held money.",
            ("retention-of-title", "all-monies-clause", "manufacturing", "proceeds", "charge", "insolvency"),
        ),
        _q(
            "PROBLEM_BASED",
            "EVEN_HARDER",
            "An English buyer purchases machinery from a Dutch seller for shipment from Rotterdam to Newcastle. Their messages incorporate conflicting standard terms, different delivery rules and an electronic bill of lading recorded on a private platform. During transit the carrier redirects the cargo after receiving a fraudulent electronic instruction. The seller’s bank and the buyer’s inventory financier both claim the machinery. Advise on contract formation, risk, documentary transfer and competing proprietary claims, stating any conflicts questions that must be resolved first.",
            ("battle-of-forms", "international-sale", "risk", "electronic-bill-of-lading", "priority", "conflict-of-laws"),
        ),
        _q(
            "PROBLEM_BASED",
            "EVEN_HARDER",
            "A fulfilment platform stores indistinguishable consumer electronics for several merchants in pooled bins. Its ledger allocates units to each merchant and automatically transfers allocations when sales occur. A cyberattack alters the ledger, after which the platform grants security over all warehouse stock and enters administration. Some customers paid, some merchants retained title, and the lender inspected only aggregate stock reports. Advise the administrator on identification, title, tracing, priority and evidential uncertainty.",
            ("bulk-goods", "co-ownership", "digital-ledger", "retention-of-title", "security", "tracing"),
        ),
        _q(
            "GENERAL_ENQUIRY",
            "EVERYDAY",
            "I bought a new laptop from a shop last week. It shuts down every hour, but the shop says I must deal with the manufacturer and refuses a refund. What can I ask the shop to do?",
            ("consumer-sale", "faulty-goods", "short-term-remedy"),
            clarification_targets=("purchase_date", "seller_location", "fault_details", "payment_method"),
        ),
        _q(
            "GENERAL_ENQUIRY",
            "EVERYDAY",
            "A furniture company promised my made-to-order table before my wedding. It arrived three weeks late and is the wrong colour. Can I reject it even though it was made especially for me?",
            ("custom-goods", "late-delivery", "non-conformity", "rejection"),
            clarification_targets=("contract_terms", "agreed_deadline", "distance_or_in_store_sale"),
        ),
        _q(
            "GENERAL_ENQUIRY",
            "EVERYDAY",
            "My small business paid a supplier for 40 printers, but the supplier has gone into administration before delivery. The printers have our stickers on them in its warehouse. Do they belong to us?",
            ("appropriation", "property-in-goods", "supplier-insolvency"),
            clarification_targets=("contract_wording", "segregation", "payment_status", "administrator_notice"),
        ),
        _q(
            "GENERAL_ENQUIRY",
            "EVERYDAY",
            "I bought a used car from a trader and the police say it may have been stolen before the trader acquired it. Can the original owner take it back, and can I recover my money?",
            ("nemo-dat", "stolen-goods", "buyer-remedies"),
            clarification_targets=("jurisdiction", "seller_status", "vehicle_history", "finance"),
        ),
        _q(
            "GENERAL_ENQUIRY",
            "MULTI_ISSUE",
            "I sell handmade products through an online marketplace. A customer received the goods, the platform froze the payment after a fraud complaint, and the courier says the parcel was redirected through the customer’s account. Who bears the loss and what records should I preserve?",
            ("platform-contract", "delivery", "fraud", "risk", "evidence-preservation"),
            clarification_targets=("platform_terms", "delivery_terms", "tracking_records", "payment_route"),
        ),
        _q(
            "GENERAL_ENQUIRY",
            "BOUNDARY_OR_URGENT",
            "My main customer has stopped paying and may enter insolvency tomorrow. Our contract says we still own all unpaid stock, but some has been turned into finished products and some has been sold. What should we do immediately without unlawfully entering its premises?",
            ("retention-of-title", "insolvency", "finished-products", "proceeds", "urgent-preservation"),
            clarification_targets=("clause_text", "stock_identification", "insolvency_status", "site_access_rights"),
        ),
    ],
)


_register(
    "competition-law",
    "Competition Law",
    ("competition-law-course-materials", "competition-assessment-style"),
    (
        "goals and institutions of competition law",
        "market definition and dominance",
        "exclusionary and exploitative abuse",
        "horizontal and vertical agreements",
        "merger control",
        "data-driven and algorithmic markets",
    ),
    [
        _q(
            "ESSAY",
            "SCHOOL_COMPARABLE",
            "‘Competition law should protect the competitive process rather than individual competitors or any particular vision of consumer welfare.’ Discuss with reference to UK and EU competition law.",
            ("competition-goals", "consumer-welfare", "competitive-process", "uk-eu-comparison"),
        ),
        _q(
            "ESSAY",
            "SCHOOL_COMPARABLE",
            "Critically evaluate whether the concepts of relevant market and dominance provide a sufficiently predictable basis for identifying unilateral market power in digital markets.",
            ("market-definition", "dominance", "digital-markets", "market-power"),
        ),
        _q(
            "ESSAY",
            "HARDER",
            "‘The distinction between restrictions by object and by effect creates more litigation than legal certainty.’ To what extent is the distinction justified, and how should context and economic evidence shape it?",
            ("article-101", "chapter-i", "object-effect", "economic-context"),
        ),
        _q(
            "ESSAY",
            "HARDER",
            "Can the extraction, combination or discriminatory use of personal data by a dominant undertaking constitute an abuse even where consumers pay no monetary price? Critically assess the legal tests and institutional limits.",
            ("abuse-of-dominance", "personal-data", "zero-price-markets", "institutional-competence"),
        ),
        _q(
            "ESSAY",
            "EVEN_HARDER",
            "Pricing algorithms may learn to sustain supra-competitive outcomes without an express human agreement. Critically assess whether existing rules on coordination, attribution and evidence can distinguish unlawful collusion from lawful conscious parallelism.",
            ("algorithmic-collusion", "concerted-practice", "attribution", "evidence", "parallel-conduct"),
        ),
        _q(
            "ESSAY",
            "EVEN_HARDER",
            "‘Ex ante digital-market regulation and ex post competition enforcement pursue overlapping goals but apply incompatible theories of power and remedy.’ Critically evaluate this claim across the applicable UK and EU regimes at the frozen legal-currentness cutoff.",
            ("digital-market-regulation", "competition-enforcement", "uk-eu-comparison", "remedies", "currentness"),
        ),
        _q(
            "PROBLEM_BASED",
            "SCHOOL_COMPARABLE",
            "HomeSphere supplies voice-controlled home hubs and has a 64% share of UK hub sales. Manufacturers that use HomeSphere’s operating system must pre-install its shopping assistant and may not place rival assistants on the first screen. HomeSphere ranks its own services first and charges rivals a 32% commission. It says integration improves security and user experience. Advise HomeSphere and the CMA on dominance, tying, self-preferencing and objective justification.",
            ("dominance", "tying", "self-preferencing", "commission", "objective-justification"),
        ),
        _q(
            "PROBLEM_BASED",
            "SCHOOL_COMPARABLE",
            "Four regional building suppliers meet through a trade association. They exchange future price ranges, agree not to advertise outside their home counties and adopt identical environmental surcharges. One supplier later sends an email objecting but continues using the surcharge. Advise the suppliers on agreement, concerted practice, restriction by object or effect, distancing and possible exemption.",
            ("horizontal-agreement", "information-exchange", "market-sharing", "public-distancing", "exemption"),
        ),
        _q(
            "PROBLEM_BASED",
            "HARDER",
            "FitRoute operates a free fitness app funded by targeted advertising. It combines location, purchase and health-proxy data, blocks data portability to rival apps and offers advertisers lower prices if they buy exclusively. Its app share is 48%, but it controls 82% of compatible wearable-device data. Advise on market definition, dominance, exclusivity, data access and any privacy-related theory of abuse.",
            ("multi-sided-market", "data-market", "dominance", "exclusivity", "interoperability", "privacy"),
        ),
        _q(
            "PROBLEM_BASED",
            "HARDER",
            "A manufacturer requires online retailers to maintain a minimum advertised price, prohibits sales through third-party marketplaces and permits only retailers with trained staff to join its selective network. It terminates a retailer after an automated monitoring tool detects repeated discounts. Advise on resale-price maintenance, marketplace restrictions, selective distribution and the relevance of efficiencies.",
            ("vertical-agreements", "resale-price-maintenance", "marketplace-ban", "selective-distribution", "efficiencies"),
        ),
        _q(
            "PROBLEM_BASED",
            "EVEN_HARDER",
            "Two major cloud providers plan a joint venture to train a foundation model using pooled customer data. The venture will license the model to both parents, which will continue to compete downstream. Smaller rivals allege foreclosure because essential compute capacity and training data will be reserved for the venture. Analyse agreement, merger and abuse theories, information barriers, counterfactuals and possible remedies.",
            ("joint-venture", "merger-control", "information-exchange", "input-foreclosure", "data-access", "remedies"),
        ),
        _q(
            "PROBLEM_BASED",
            "EVEN_HARDER",
            "A global marketplace changes its ranking algorithm after acquiring a payment provider and logistics network. Sellers using both acquired services receive faster delivery labels and higher search placement; other sellers pay a new data-access fee. The platform has different shares in marketplace, advertising, payments and fulfilment services in the UK and EU. Prepare advice addressing jurisdiction, market definition, ecosystem power, leveraging, merger theories, regulatory overlap and defensible integration benefits.",
            ("ecosystem-power", "leveraging", "self-preferencing", "conglomerate-merger", "regulatory-overlap", "uk-eu"),
        ),
        _q(
            "GENERAL_ENQUIRY",
            "EVERYDAY",
            "Three plumbers in my town have started quoting exactly the same call-out fee and one told me they agreed a ‘fair local price’. Is that allowed, and where can I report it?",
            ("price-fixing", "horizontal-agreement", "complaint-route"),
            clarification_targets=("location", "evidence_of_contact", "business_relationships"),
        ),
        _q(
            "GENERAL_ENQUIRY",
            "EVERYDAY",
            "An online marketplace suspended my small shop because I also sell at a lower price on my own website. Can the marketplace force me to keep the same price everywhere?",
            ("platform-parity", "vertical-restraint", "market-power"),
            clarification_targets=("contract_term", "marketplace_location", "seller_status", "platform_share"),
        ),
        _q(
            "GENERAL_ENQUIRY",
            "EVERYDAY",
            "My café can buy a popular drink only if I promise not to stock a rival brand for five years. Is an exclusive supply contract automatically illegal?",
            ("exclusive-dealing", "vertical-agreement", "foreclosure"),
            clarification_targets=("supplier_market_position", "contract_duration", "available_alternatives", "territory"),
        ),
        _q(
            "GENERAL_ENQUIRY",
            "EVERYDAY",
            "The only pharmacy in my area charges much more for one medicine than pharmacies in nearby towns. Does a high price by itself break competition law?",
            ("excessive-pricing", "dominance", "market-definition"),
            clarification_targets=("medicine_and_regulation", "geographic_market", "price_comparison", "supply_constraints"),
        ),
        _q(
            "GENERAL_ENQUIRY",
            "MULTI_ISSUE",
            "A food-delivery app ranks restaurants lower unless they buy its delivery service, stops them offering cheaper prices elsewhere and uses their sales data to launch competing virtual restaurants. What competition issues could this raise?",
            ("self-preferencing", "tying", "parity-clause", "data-use", "platform-dominance"),
            clarification_targets=("jurisdiction", "contract_terms", "platform_market_share", "ranking_evidence"),
        ),
        _q(
            "GENERAL_ENQUIRY",
            "BOUNDARY_OR_URGENT",
            "Two competitors have invited me to a private chat tomorrow to discuss future prices and which customers each of us should serve. I have not agreed to anything. What should I do now and what records should I keep?",
            ("cartel-risk", "information-exchange", "market-sharing", "evidence-preservation"),
            clarification_targets=("business_role", "prior_contacts", "invitation_content", "jurisdiction"),
        ),
    ],
)


_register(
    "ai-and-data-protection",
    "Artificial Intelligence and Data Protection",
    ("ai-data-protection-dissertation-materials", "biolaw-ai-materials", "official-legislation-reference"),
    (
        "lawful processing and purpose limitation",
        "special-category and inferred data",
        "automated decision-making and explanation",
        "data subject rights and security incidents",
        "AI training, deployment and accountability",
        "neural, biometric and synthetic data",
    ),
    [
        _q(
            "ESSAY",
            "SCHOOL_COMPARABLE",
            "‘Data protection law regulates information about people, but modern AI systems exercise power through inferences that may never have been supplied by the individual.’ Critically discuss.",
            ("personal-data", "inferences", "profiling", "data-protection-principles"),
        ),
        _q(
            "ESSAY",
            "SCHOOL_COMPARABLE",
            "Critically evaluate whether the law governing solely automated decisions provides meaningful protection where a human reviewer formally approves, but rarely changes, an algorithmic recommendation.",
            ("automated-decision-making", "human-review", "profiling", "effective-safeguards"),
        ),
        _q(
            "ESSAY",
            "HARDER",
            "To what extent can transparency, access and explanation rights make high-dimensional machine-learning decisions contestable without disclosing trade secrets or creating misleading simplifications?",
            ("transparency", "access-rights", "explanation", "trade-secrets", "contestability"),
        ),
        _q(
            "ESSAY",
            "HARDER",
            "‘The boundary between ordinary personal data and special-category data collapses when AI can infer health, ethnicity, political belief or emotion from apparently innocuous inputs.’ Critically assess the doctrinal and regulatory consequences.",
            ("special-category-data", "inferred-data", "biometrics", "mental-privacy"),
        ),
        _q(
            "ESSAY",
            "EVEN_HARDER",
            "Critically assess how responsibility should be allocated among a foundation-model developer, fine-tuner, deployer and professional user when personal data are memorised, fabricated or used to make a harmful decision.",
            ("controller-processor", "joint-responsibility", "foundation-model", "memorisation", "fabricated-data"),
        ),
        _q(
            "ESSAY",
            "EVEN_HARDER",
            "‘A rights-based data-protection framework and a risk-based AI-regulation framework cannot be made coherent because they ask different questions about the same system.’ Evaluate this claim under the applicable UK and EU frameworks at the frozen currentness cutoff.",
            ("ai-regulation", "data-protection", "rights-based-regulation", "risk-based-regulation", "uk-eu", "currentness"),
        ),
        _q(
            "PROBLEM_BASED",
            "SCHOOL_COMPARABLE",
            "BrightHire uses a recruitment model trained on ten years of employee data. Applicants upload CVs and recorded interviews; the model scores voice, word choice and career gaps. Managers normally accept the ranking without seeing rejected applications. One applicant requests the data, logic and reasons for rejection after discovering that the system inferred a disability. Advise BrightHire and the applicant on lawful processing, transparency, inferred sensitive data and automated decision safeguards.",
            ("recruitment-ai", "lawful-basis", "special-category-inference", "automated-decision", "access"),
        ),
        _q(
            "PROBLEM_BASED",
            "SCHOOL_COMPARABLE",
            "A fitness app collects heart rate and sleep data to provide coaching. After a terms update, it shares risk scores with an insurer and advertising partners. The raw data stay with the app, but partners receive pseudonymous identifiers and predictions about anxiety and pregnancy. Advise on purpose limitation, transparency, special-category data, sharing and the status of the inferences.",
            ("health-data", "purpose-limitation", "data-sharing", "pseudonymisation", "inferences"),
        ),
        _q(
            "PROBLEM_BASED",
            "HARDER",
            "A local authority deploys facial recognition around a transport hub using a watchlist supplied by several agencies. The vendor periodically retrains the model on unmatched images. False alerts disproportionately affect one demographic group, and neither the authority nor vendor accepts responsibility for responding to access and deletion requests. Advise on legal basis, necessity, biometric data, fairness, governance and allocation of responsibility.",
            ("facial-recognition", "biometric-data", "public-authority", "fairness", "controller-allocation"),
        ),
        _q(
            "PROBLEM_BASED",
            "HARDER",
            "A bank uses an external AI service to summarise account activity and recommend whether fraud victims should be reimbursed. The service sends prompts to servers outside the UK, retains them for model improvement and occasionally invents transactions that never occurred. A customer is denied reimbursement on the basis of one invented transaction. Advise on international transfers, processor terms, accuracy, automated decision-making, security and redress.",
            ("banking-ai", "international-transfer", "processor", "accuracy", "hallucinated-data", "redress"),
        ),
        _q(
            "PROBLEM_BASED",
            "EVEN_HARDER",
            "A model developer trains a general-purpose system on a web-scale dataset containing public posts, leaked medical records and copyrighted news. A hospital fine-tunes it on patient notes and deploys it through a software integrator. The model later reproduces part of a patient record in response to an unrelated user and generates a false diagnosis that is copied into another patient’s file. Allocate data-protection roles and analyse lawful basis, research compatibility, security, accuracy, impact assessment and incident response.",
            ("foundation-model", "training-data", "health-data", "role-allocation", "data-breach", "accuracy"),
        ),
        _q(
            "PROBLEM_BASED",
            "EVEN_HARDER",
            "NeuroBand sells a consumer headset that estimates attention and emotional state. It markets only productivity feedback, but its on-device model creates embeddings from neural signals and synchronises them to a cloud account. An employer requires staff to use NeuroBand, a political consultancy buys audience segments derived from the embeddings, and a police force seeks voluntary access. Advise all parties on personal and special-category data, consent, employment imbalance, inferred mental data, joint control, law-enforcement disclosure and regulatory gaps.",
            ("neural-data", "mental-privacy", "employment-consent", "political-profiling", "law-enforcement", "regulatory-gap"),
        ),
        _q(
            "GENERAL_ENQUIRY",
            "EVERYDAY",
            "A company rejected my loan application instantly and says a computer made the decision. Can I ask for a person to review it and explain what data were used?",
            ("automated-credit-decision", "human-review", "access", "explanation"),
            clarification_targets=("decision_effect", "company_location", "notice_received", "human_involvement"),
        ),
        _q(
            "GENERAL_ENQUIRY",
            "EVERYDAY",
            "A shopping app seems to know that I am pregnant even though I never told it. Can I find out how it reached that conclusion and stop it using the prediction?",
            ("inferred-data", "profiling", "access", "objection", "special-category-data"),
            clarification_targets=("app_identity", "evidence_of_inference", "account_location", "privacy_notice"),
        ),
        _q(
            "GENERAL_ENQUIRY",
            "EVERYDAY",
            "My former employer still has recordings of my online interviews and says it may use them to improve its hiring AI. Can I ask for them to be deleted?",
            ("retention", "erasure", "recruitment-data", "ai-training"),
            clarification_targets=("employment_dates", "privacy_notice", "legal_claims", "controller_identity"),
        ),
        _q(
            "GENERAL_ENQUIRY",
            "EVERYDAY",
            "I uploaded family photos to an editing service and later saw an AI-generated advert using a face that looks exactly like my child. What information should I request from the company?",
            ("facial-data", "children-data", "ai-generation", "access", "transparency"),
            clarification_targets=("service_terms", "child_age", "advert_evidence", "company_location"),
        ),
        _q(
            "GENERAL_ENQUIRY",
            "MULTI_ISSUE",
            "My employer introduced software that reads emails, scores mood and predicts who may resign. Nobody was asked for consent, and managers use the score in promotion meetings. What rights might staff have and what documents should we collect?",
            ("workplace-monitoring", "emotion-inference", "profiling", "employment-imbalance", "automated-decision"),
            clarification_targets=("monitoring_notice", "decision_use", "workplace_location", "union_or_policy_documents"),
        ),
        _q(
            "GENERAL_ENQUIRY",
            "BOUNDARY_OR_URGENT",
            "A health app emailed me saying an attacker downloaded my medical and location history, but it has not explained when this happened or who received it. What should I do now, and when should the regulator or police be contacted?",
            ("data-breach", "health-data", "location-data", "urgent-mitigation", "notification"),
            clarification_targets=("breach_notice", "account_security", "financial_or_physical_risk", "jurisdiction"),
        ),
    ],
)


_register(
    "international-commercial-mediation",
    "International Commercial Mediation",
    ("international-commercial-mediation-course-materials", "mediation-handbook-style"),
    (
        "mediation agreements and clauses",
        "process models and professional roles",
        "confidentiality and without-prejudice protection",
        "costs, compulsion and access to justice",
        "cross-border settlement enforcement",
        "technology, culture and mediator accountability",
    ),
    [
        _q("ESSAY", "SCHOOL_COMPARABLE", "‘A contractual obligation to mediate is useful only when a court can identify exactly what performance requires.’ Critically discuss the enforceability and design of multi-tier dispute-resolution clauses.", ("mediation-clause", "certainty", "multi-tier-clause", "enforcement")),
        _q("ESSAY", "SCHOOL_COMPARABLE", "Critically evaluate whether confidentiality is an essential condition of effective commercial mediation or an overstated expectation that should yield more readily to justice and public-interest concerns.", ("confidentiality", "without-prejudice", "exceptions", "public-interest")),
        _q("ESSAY", "HARDER", "‘Encouraging parties to mediate through costs sanctions is legitimate; compelling participation is not.’ To what extent can that distinction be maintained in modern civil justice?", ("compulsory-mediation", "costs", "access-to-justice", "settlement")),
        _q("ESSAY", "HARDER", "Compare facilitative, evaluative and transformative approaches to commercial mediation. Should the legal duties and potential liability of a mediator differ according to the model adopted?", ("mediation-models", "mediator-duty", "professional-liability", "party-autonomy")),
        _q("ESSAY", "EVEN_HARDER", "Critically assess whether the international enforcement architecture for mediated settlement agreements achieves an appropriate balance among finality, consent, procedural fairness and state regulatory autonomy.", ("cross-border-enforcement", "singapore-convention", "consent", "public-policy")),
        _q("ESSAY", "EVEN_HARDER", "‘AI-assisted mediation may widen access and reduce cost, but it also converts a confidential human process into an opaque system of prediction and behavioural influence.’ Evaluate the regulatory implications for neutrality, data governance and informed consent.", ("ai-mediation", "neutrality", "data-governance", "informed-consent", "cross-border")),
        _q("PROBLEM_BASED", "SCHOOL_COMPARABLE", "A distribution contract requires senior negotiation, followed by mediation under named institutional rules, before proceedings may begin. After one short call, the buyer sues in England, saying delay will destroy its seasonal business. The seller seeks a stay, although it refused three proposed mediators. Advise both parties on the clause, compliance, urgency and available procedural responses.", ("multi-tier-clause", "condition-precedent", "stay", "urgency", "good-faith")),
        _q("PROBLEM_BASED", "SCHOOL_COMPARABLE", "During mediation of a construction dispute, the contractor admits that an invoice was altered and offers a reduced settlement. Negotiations fail. The employer wants to use the admission, the mediator's notes and an expert report prepared for the mediation in later proceedings. Advise on confidentiality, without-prejudice protection and possible exceptions.", ("confidentiality", "without-prejudice", "impropriety", "mediator-notes", "evidence")),
        _q("PROBLEM_BASED", "HARDER", "A mediator previously advised an affiliate of one party but discloses only that there was a ‘minor professional connection’. She later gives a strong private evaluation of the merits and drafts settlement wording that omits a tax contingency. Advise the parties and mediator on disclosure, impartiality, the chosen process model and potential responsibility for loss.", ("conflict-of-interest", "mediator-impartiality", "evaluative-mediation", "liability", "settlement-drafting")),
        _q("PROBLEM_BASED", "HARDER", "An English manufacturer and a Singaporean buyer sign a mediated settlement after an online process hosted by a French provider. Payment is due in instalments, but the buyer alleges duress, a forged electronic signature and mediator misconduct. Assets are located in three states. Advise on proof, governing instruments, enforcement routes and refusal grounds.", ("international-settlement", "electronic-signature", "duress", "enforcement", "refusal-grounds")),
        _q("PROBLEM_BASED", "EVEN_HARDER", "A platform supplies multilingual AI summaries, predicts each party's reservation price and privately recommends concessions to the mediator. One translation reverses a limitation clause; the provider retains transcripts to train its model, and the final settlement contains inconsistent language versions. Allocate the legal and professional issues among the parties, mediator and provider.", ("online-mediation", "ai-assistance", "translation", "confidentiality", "data-use", "settlement-interpretation")),
        _q("PROBLEM_BASED", "EVEN_HARDER", "A state-owned company settles a renewable-energy dispute through mediation. A new government argues that its negotiator lacked authority, that anti-corruption evidence was concealed and that enforcement would breach public policy. The investor alleges political repudiation and seeks enforcement in multiple jurisdictions. Advise on authority, confidentiality, public policy, enforcement and parallel proceedings.", ("state-owned-enterprise", "authority", "corruption", "public-policy", "parallel-enforcement")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "A customer contract says we must try mediation before going to court. The other business ignores my emails. Am I allowed to start a claim?", ("mediation-clause", "non-participation", "court-proceedings"), clarification_targets=("clause_wording", "steps_taken", "deadline", "jurisdiction")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "If I tell a mediator something privately, can the mediator repeat it to the other side or to a judge?", ("confidential-caucus", "mediator-duty", "disclosure"), clarification_targets=("mediation_terms", "what_was_said", "permission_given", "risk_of_harm_or_illegality")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "We agreed a payment plan at mediation, but the other company missed the first payment. How can I enforce the agreement?", ("settlement-agreement", "breach", "enforcement"), clarification_targets=("signed_terms", "mediation_location", "debtor_and_assets_location", "existing_proceedings")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "The mediator used to work with the other side and did not tell me until the meeting had started. Can I ask for a different mediator?", ("mediator-conflict", "disclosure", "impartiality"), clarification_targets=("nature_of_connection", "mediation_rules", "when_discovered", "consent_given")),
        _q("GENERAL_ENQUIRY", "MULTI_ISSUE", "My small business is in a dispute with an overseas supplier. Its lawyer proposes online mediation under foreign rules, in another language, with any settlement enforced abroad. What should I check before agreeing?", ("cross-border-mediation", "applicable-rules", "language", "cost", "enforcement"), clarification_targets=("contract_and_clause", "countries_involved", "asset_location", "proposed_rules")),
        _q("GENERAL_ENQUIRY", "BOUNDARY_OR_URGENT", "A mediation starts tomorrow and the other side says I must sign a confidentiality form that also destroys documents and prevents me reporting suspected fraud. Should I sign it?", ("confidentiality-agreement", "evidence-preservation", "fraud", "regulatory-reporting"), clarification_targets=("draft_terms", "suspected_conduct", "existing_duties", "legal_representation")),
    ],
)


_register(
    "law-and-medicine",
    "Law and Medicine",
    ("law-and-medicine-course-materials", "law-and-medicine-assessment-style"),
    (
        "consent, disclosure and capacity",
        "children and medical decision-making",
        "end-of-life decisions and advance planning",
        "organ donation and transplantation",
        "abortion and reproductive medicine",
        "clinical AI and responsibility",
    ),
    [
        _q("ESSAY", "SCHOOL_COMPARABLE", "‘Modern consent law protects a patient's right to decide, but leaves clinicians uncertain about how much information must be disclosed.’ Critically discuss.", ("consent", "material-risk", "therapeutic-exception", "clinical-judgment")),
        _q("ESSAY", "SCHOOL_COMPARABLE", "Critically evaluate whether the law gives sufficient weight to the autonomy of children and young people in medical treatment decisions.", ("minors", "capacity", "consent", "refusal", "best-interests")),
        _q("ESSAY", "HARDER", "‘Best interests is an indispensable standard for people lacking capacity, but its breadth permits value judgments to be disguised as welfare.’ To what extent is this criticism justified in end-of-life decision-making?", ("mental-capacity", "best-interests", "end-of-life", "autonomy")),
        _q("ESSAY", "HARDER", "Critically assess whether an opt-out system for deceased organ donation reconciles individual autonomy, family participation and the public need for transplants.", ("organ-donation", "deemed-consent", "family-role", "allocation")),
        _q("ESSAY", "EVEN_HARDER", "Evaluate whether the legal separation of abortion, assisted reproduction and embryo regulation can still be defended when genomic selection and novel reproductive technologies connect all three fields.", ("abortion", "assisted-reproduction", "embryo", "genomic-selection", "regulatory-coherence")),
        _q("ESSAY", "EVEN_HARDER", "‘When a clinician relies on an adaptive AI system, informed consent, negligence and product regulation each see only part of the risk.’ Critically assess how responsibility should be allocated when the system changes after deployment.", ("clinical-ai", "consent", "negligence", "product-regulation", "adaptive-system")),
        _q("PROBLEM_BASED", "SCHOOL_COMPARABLE", "Leah, aged 15, agrees to urgent surgery but refuses a blood transfusion for religious reasons. Her parents disagree with each other, and the surgeon believes delay materially increases the risk of death. Advise on Leah's decision-making status, parental involvement, best interests and the steps the hospital should take.", ("minor", "competence", "refusal", "parental-responsibility", "urgent-treatment")),
        _q("PROBLEM_BASED", "SCHOOL_COMPARABLE", "Mr Vale has advanced dementia and develops a treatable infection. His daughter produces a signed document refusing ‘all life-prolonging treatment’, while his partner says he later changed his mind. The clinical team also disputes whether treatment would be burdensome. Advise on capacity, the document's validity and applicability, best interests and consultation.", ("capacity", "advance-decision", "applicability", "best-interests", "consultation")),
        _q("PROBLEM_BASED", "HARDER", "A surgeon recommends a new procedure and describes its average success rate but not a small risk especially important to this patient's occupation. A manufacturer-funded decision tool understates the risk, and the patient suffers that complication. Advise on disclosure, causation, clinical negligence and the roles of the clinician, hospital and tool supplier.", ("material-risk", "patient-values", "causation", "clinical-ai", "responsibility")),
        _q("PROBLEM_BASED", "HARDER", "A deceased registered no objection to organ donation. His spouse strongly objects, a sibling says he privately opposed donation, and the transplant team discovers information suggesting the proposed recipient may not meet allocation criteria. Advise on consent, evidence of wishes, family participation and allocation governance.", ("organ-donation", "deemed-consent", "family-objection", "allocation", "governance")),
        _q("PROBLEM_BASED", "EVEN_HARDER", "A fertility clinic stores embryos created by a married couple. After separation, one partner withdraws consent while the other says treatment is their last chance for a genetically related child. A clinic error has also mixed parts of the records, and one embryo shows a disputed genomic finding. Advise on consent, storage, record integrity, testing and available remedies.", ("embryo", "withdrawal-of-consent", "storage", "record-error", "genomic-testing", "remedies")),
        _q("PROBLEM_BASED", "EVEN_HARDER", "An autonomous intensive-care system changes ventilator settings and recommends withdrawal of treatment. Its recommendation relies on incomplete records and a population model with unequal error rates. The patient lacks capacity; relatives disagree, and the vendor refuses to disclose model information. Advise on best interests, human oversight, discrimination, negligence, causation and disclosure.", ("critical-care-ai", "capacity", "best-interests", "bias", "negligence", "transparency")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "My doctor recommends an operation but did not tell me about an alternative treatment that another hospital offers. What information am I entitled to before deciding?", ("informed-consent", "alternatives", "material-information"), clarification_targets=("treatment", "risks_and_alternatives", "questions_asked", "urgency")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "My 16-year-old wants medical treatment that I oppose. Can the hospital go ahead without my permission?", ("young-person", "consent", "parental-responsibility"), clarification_targets=("treatment", "young_person_understanding", "country", "urgency")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "I wrote that I do not want certain treatment if I lose capacity. How do I make sure doctors will follow it?", ("advance-decision", "formalities", "applicability"), clarification_targets=("treatments_refused", "document_form", "witnessing", "healthcare_proxy")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "Can I require a donated organ to go only to a relative or to someone from my community?", ("directed-donation", "allocation", "consent"), clarification_targets=("living_or_deceased_donation", "relationship", "proposed_condition", "jurisdiction")),
        _q("GENERAL_ENQUIRY", "MULTI_ISSUE", "A fertility clinic says some of our embryos may have been labelled incorrectly and asks us to consent quickly to new genetic tests. What documents and decisions should we ask about first?", ("fertility-treatment", "embryo-identification", "genetic-testing", "consent", "incident-response"), clarification_targets=("clinic_notice", "existing_consents", "embryo_status", "deadline_reason")),
        _q("GENERAL_ENQUIRY", "BOUNDARY_OR_URGENT", "The hospital says it may stop life-sustaining treatment tonight, but close relatives disagree about what the unconscious patient wanted. What can the family do immediately?", ("life-sustaining-treatment", "best-interests", "family-dispute", "urgent-court-route"), clarification_targets=("clinical_plan", "patient_wishes_documents", "decision_maker", "time_and_location")),
    ],
)


_register(
    "pensions-law",
    "Pensions Law",
    ("pensions-law-course-materials", "pensions-assessment-and-feedback-style"),
    (
        "scheme powers and protected rights",
        "trustees, employers and conflicts",
        "equality and discrimination",
        "funding, investment and corporate events",
        "benefits, transfers and member communications",
        "regulatory, compensation and insolvency interfaces",
    ),
    [
        _q("ESSAY", "SCHOOL_COMPARABLE", "Critically evaluate the extent to which pension scheme amendment powers permit employers and trustees to respond to financial pressure without undermining members' accrued expectations.", ("amendment-power", "accrued-rights", "employer", "trustee", "member-expectation")),
        _q("ESSAY", "SCHOOL_COMPARABLE", "‘Pensions trustees are required to act in beneficiaries' interests, but that formula gives incomplete guidance on investment time horizons, risk and non-financial considerations.’ Discuss.", ("trustee-duty", "investment", "beneficiary-interest", "risk", "esg")),
        _q("ESSAY", "HARDER", "Critically assess whether the available ombudsman, regulatory and court routes provide a coherent and accessible system of redress for pension scheme maladministration and legal error.", ("pensions-ombudsman", "regulator", "court", "maladministration", "redress")),
        _q("ESSAY", "HARDER", "‘Equality law has corrected overt discrimination in pensions while leaving structural inequalities produced by pay, caring and longevity largely untouched.’ To what extent is this accurate?", ("pensions-equality", "indirect-discrimination", "part-time-work", "age", "sex")),
        _q("ESSAY", "EVEN_HARDER", "Critically evaluate whether the legal allocation of risk among employers, trustees, members, insurers and compensation arrangements remains defensible when a defined-benefit sponsor undergoes a major corporate transaction.", ("defined-benefit", "corporate-transaction", "funding", "employer-covenant", "compensation")),
        _q("ESSAY", "EVEN_HARDER", "‘The move from collective defined benefits to individualised retirement saving has outpaced the law's assumptions about informed choice.’ Assess the case for redesigning governance, defaults and responsibility across accumulation and decumulation.", ("defined-contribution", "automatic-enrolment", "defaults", "decumulation", "consumer-protection")),
        _q("PROBLEM_BASED", "SCHOOL_COMPARABLE", "The deed of the Northborough Scheme allows amendment by the employer with trustee consent but contains a proviso protecting benefits ‘already secured’. The employer proposes to increase normal pension age for past and future service and replace indexation with a discretionary uplift. Member communications describe all benefits as guaranteed. Advise on construction, protected rights, trustee decision-making and communications.", ("scheme-amendment", "protected-benefits", "pension-age", "indexation", "member-communications")),
        _q("PROBLEM_BASED", "SCHOOL_COMPARABLE", "A member dies after separating from a spouse but before updating an expression-of-wish form naming that spouse. The scheme rules give trustees discretion over a lump sum. One trustee is the deceased's business partner, and competing claims are made by the spouse, a cohabitant and an adult child. Advise the trustees on relevant considerations, conflicts, process and reasons.", ("death-benefit", "trustee-discretion", "expression-of-wish", "conflict", "reasons")),
        _q("PROBLEM_BASED", "HARDER", "A scheme closes to future accrual and offers enhanced transfer values for three months. Older members receive individual advice paid by the employer; younger part-time staff receive only a web link. An employee on maternity leave misses the deadline. Advise on equality, communications, advice boundaries and possible remedies.", ("scheme-closure", "transfer-value", "age-discrimination", "part-time", "maternity", "communications")),
        _q("PROBLEM_BASED", "HARDER", "Trustees allocate 35% of scheme assets to a renewable-infrastructure fund promoted by an adviser whose parent company earns transaction fees. The investment is illiquid, members have divergent ethical views and the employer covenant weakens soon after. Advise on powers, diversification, advice, conflicts, financial and non-financial factors, and record keeping.", ("trustee-investment", "diversification", "conflict", "esg", "employer-covenant", "records")),
        _q("PROBLEM_BASED", "EVEN_HARDER", "A corporate group sells its profitable subsidiary, grants security to a new lender and pays a large dividend while its pension scheme has a substantial deficit. The purchaser disclaims pension responsibility; internal papers show that directors expected the scheme to enter a compensation arrangement. Advise the employer, connected parties and trustees on funding, regulatory powers, transaction planning and evidence.", ("scheme-deficit", "corporate-sale", "security", "dividend", "regulatory-powers", "avoidance")),
        _q("PROBLEM_BASED", "EVEN_HARDER", "A cyberattack changes member bank details, deletes part of the administration history and causes some retirees to be underpaid and others overpaid. The administrator, trustees and software supplier each blame another. One member relied on an incorrect retirement quotation to resign. Advise on benefit entitlement, recovery, reliance loss, data duties, outsourcing and regulatory response.", ("pensions-administration", "cyberattack", "overpayment", "underpayment", "reliance", "outsourcing")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "My employer says my workplace pension will build up more slowly from next year. Can it change benefits I have already earned?", ("scheme-change", "accrued-benefits", "future-service"), clarification_targets=("scheme_type", "change_notice", "scheme_rules", "employment_status")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "My pension statement is missing several years of contributions even though they came out of my pay. What should I ask the employer and provider for?", ("missing-contributions", "records", "complaint"), clarification_targets=("payslips", "scheme_and_provider", "missing_period", "complaints_made")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "My late parent named me on a pension form years ago, but the trustees paid someone else. Can I challenge their decision?", ("death-benefit", "nomination", "trustee-discretion", "challenge"), clarification_targets=("decision_letter", "scheme_rules", "family_and_dependency", "date_of_death")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "A company has offered me cash to transfer my final-salary pension. How can I check whether the offer and advice are genuine?", ("pension-transfer", "defined-benefit", "regulated-advice", "scam-risk"), clarification_targets=("offer_source", "transfer_value", "scheme_type", "adviser_details")),
        _q("GENERAL_ENQUIRY", "MULTI_ISSUE", "I worked part-time, took maternity leave and later became full-time, but my pension is much lower than colleagues who started with me. Could the calculation or scheme rules be discriminatory?", ("part-time", "maternity", "pensions-equality", "benefit-calculation"), clarification_targets=("service_history", "scheme_membership_dates", "benefit_statement", "comparator_details")),
        _q("GENERAL_ENQUIRY", "BOUNDARY_OR_URGENT", "News says my former employer may become insolvent and its pension scheme has a large deficit. I am due to retire next month. Should I transfer or claim benefits now?", ("employer-insolvency", "scheme-deficit", "compensation", "retirement", "urgent-advice-boundary"), clarification_targets=("scheme_type", "formal_notices", "retirement_options", "regulated_advice_status")),
    ],
)


_register(
    "private-international-law",
    "Private International Law",
    ("private-international-law-course-materials", "private-international-law-assessment-style"),
    (
        "jurisdiction and parallel proceedings",
        "choice of law and party autonomy",
        "recognition and enforcement of judgments",
        "cross-border torts and digital activity",
        "interim relief and asset location",
        "post-exit and multilateral legal architecture",
    ),
    [
        _q("ESSAY", "SCHOOL_COMPARABLE", "‘Forum shopping is not an abuse of private international law but a predictable exercise of rights created by competing jurisdictional systems.’ Critically discuss.", ("forum-shopping", "jurisdiction", "access-to-justice", "comity")),
        _q("ESSAY", "SCHOOL_COMPARABLE", "Critically evaluate whether party autonomy provides a principled basis for choosing the law of an international contract or merely allows stronger parties to avoid mandatory protection.", ("choice-of-law", "party-autonomy", "mandatory-rules", "unequal-bargaining")),
        _q("ESSAY", "HARDER", "‘Recognition of foreign judgments should be routine; refusal should be exceptional.’ Assess whether the available jurisdiction, procedural fairness and public-policy controls justify that proposition.", ("foreign-judgment", "recognition", "procedural-fairness", "public-policy")),
        _q("ESSAY", "HARDER", "Critically assess the legal management of parallel proceedings and anti-suit relief where contractual expectations, comity and the risk of inconsistent judgments point in different directions.", ("parallel-proceedings", "anti-suit-injunction", "comity", "choice-of-court")),
        _q("ESSAY", "EVEN_HARDER", "Digital assets and decentralised transactions resist traditional connecting factors based on place, control and territorial acts. Critically evaluate whether existing choice-of-law methods can adapt without a new statutory situs rule.", ("digital-assets", "situs", "connecting-factor", "choice-of-law", "decentralisation")),
        _q("ESSAY", "EVEN_HARDER", "‘The fragmentation of UK–EU civil judicial cooperation demonstrates the limits of domestic common-law rules and the political limits of multilateral replacement.’ Evaluate this claim at the frozen currentness cutoff.", ("uk-eu", "civil-judicial-cooperation", "treaty", "common-law", "currentness")),
        _q("PROBLEM_BASED", "SCHOOL_COMPARABLE", "An English buyer orders machinery from an Italian seller through a German platform. The click-wrap terms choose French law and courts, while a later signed purchase order chooses English law but says nothing about jurisdiction. Delivery and injury occur in Wales. The seller sues for payment in Milan and the buyer sues for defects in London. Advise on jurisdiction, applicable law and parallel proceedings.", ("conflicting-clauses", "jurisdiction", "choice-of-law", "sale-of-goods", "parallel-proceedings")),
        _q("PROBLEM_BASED", "SCHOOL_COMPARABLE", "A Scottish tourist is injured in Spain by a bicycle hired from a Dutch company through an English-language app. The contract selects Dutch law; medical loss continues after the tourist returns home. Advise on characterisation, jurisdiction, contractual and non-contractual choice of law, and mandatory protections.", ("cross-border-injury", "consumer-contract", "tort", "choice-of-law", "jurisdiction")),
        _q("PROBLEM_BASED", "HARDER", "A Canadian court gives default judgment against an English director for fraud and punitive damages. Service was sent by social media after failed postal attempts. The claimant seeks enforcement against a London home; the director alleges no submission, defective notice and an inconsistent earlier English settlement. Advise on recognition, jurisdictional competence, fairness, finality and remedies.", ("foreign-default-judgment", "service", "fraud", "punitive-damages", "recognition")),
        _q("PROBLEM_BASED", "HARDER", "A celebrity living in England sues a US publisher over an online article written in New York, first uploaded on a global platform and most widely read in India. Reputational and economic loss is alleged in several states. The publisher has no UK office but targets subscriptions by location. Advise on jurisdiction, location of damage, applicable law and the scope of relief.", ("online-defamation", "jurisdiction", "place-of-damage", "applicable-law", "territorial-relief")),
        _q("PROBLEM_BASED", "EVEN_HARDER", "A crypto exchange incorporated offshore collapses after customer assets are transferred through wallets controlled from several countries. English liquidators, a foreign regulator and token holders each claim the same assets; one foreign court issues a worldwide freezing order. Advise on characterisation, situs, proprietary claims, jurisdiction, recognition and interim relief.", ("crypto-assets", "insolvency", "situs", "proprietary-claim", "freezing-order", "recognition")),
        _q("PROBLEM_BASED", "EVEN_HARDER", "A multinational group restructures debt through a foreign court process that releases claims against non-debtor affiliates. Some English creditors voted against it; finance documents select English law and exclusive English jurisdiction. Assets and proceedings span four states. Advise on recognition, contractual rights, public policy, insolvency cooperation and enforcement strategy.", ("cross-border-restructuring", "third-party-release", "choice-of-court", "recognition", "insolvency-cooperation")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "I bought goods from an overseas website and they never arrived. Can I sue the seller where I live, or must I use the country named in its terms?", ("consumer-contract", "jurisdiction-clause", "choice-of-law"), clarification_targets=("buyer_and_seller_locations", "terms", "purchase_date", "targeting_and_currency")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "A foreign court sent papers to an old address and has now entered judgment against me. Can that judgment be enforced here?", ("foreign-judgment", "service", "default", "enforcement"), clarification_targets=("issuing_country", "judgment_and_service_documents", "residence_history", "participation")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "I won a court case abroad and the losing company owns property in England. What do I need before I can enforce the judgment?", ("recognition", "enforcement", "foreign-judgment", "assets"), clarification_targets=("issuing_country", "judgment_status", "type_of_order", "asset_details")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "I was injured while on holiday but the travel company is based in another country. Which country's law decides my compensation?", ("cross-border-injury", "package-travel", "choice-of-law"), clarification_targets=("locations", "booking_contract", "cause_of_injury", "defendants")),
        _q("GENERAL_ENQUIRY", "MULTI_ISSUE", "Someone abroad posted a false video about my business. It is viewed worldwide, the platform is based overseas and customers in the UK have cancelled orders. Where could I bring a claim and which law might apply?", ("online-defamation", "platform", "jurisdiction", "applicable-law", "damage"), clarification_targets=("publisher_and_platform_locations", "viewership_evidence", "business_location", "content_and_dates")),
        _q("GENERAL_ENQUIRY", "BOUNDARY_OR_URGENT", "A former business partner is moving money through accounts and crypto wallets in several countries, and a foreign lawsuit starts next week. Can an English court freeze assets urgently?", ("interim-relief", "freezing-order", "crypto-assets", "parallel-proceedings"), clarification_targets=("claim_basis", "asset_evidence", "countries_and_proceedings", "risk_of_dissipation")),
    ],
)


_register(
    "tort-law",
    "Tort Law",
    ("tort-law-course-materials", "tort-assessment-style"),
    (
        "negligence, duty and causation",
        "occupiers and defective premises",
        "economic loss and negligent statements",
        "nuisance and land-based liability",
        "vicarious liability, privacy and reputation",
        "products, platforms and autonomous systems",
    ),
    [
        _q("ESSAY", "SCHOOL_COMPARABLE", "‘The modern duty-of-care framework is less a test than a vocabulary for expressing judicial policy.’ Critically discuss.", ("duty-of-care", "incrementalism", "policy", "negligence")),
        _q("ESSAY", "SCHOOL_COMPARABLE", "Critically evaluate whether the restrictions on recovery for psychiatric injury can be justified by principle rather than concerns about the scope of liability.", ("psychiatric-harm", "primary-victim", "secondary-victim", "policy")),
        _q("ESSAY", "HARDER", "‘The law of pure economic loss protects professional reliance inconsistently and physical property arbitrarily.’ Assess the coherence of the boundary between recoverable and unrecoverable loss.", ("pure-economic-loss", "negligent-misstatement", "defective-property", "reliance")),
        _q("ESSAY", "HARDER", "Critically assess whether vicarious liability remains a principled response to enterprise risk in a labour market organised through franchises, agencies, platforms and nominally independent contractors.", ("vicarious-liability", "employment-relationship", "close-connection", "platform-work")),
        _q("ESSAY", "EVEN_HARDER", "Privacy, misuse of private information and defamation protect overlapping but distinct interests. Critically evaluate whether online amplification and synthetic media require a more unified remedial framework.", ("privacy", "defamation", "synthetic-media", "platform-amplification", "remedies")),
        _q("ESSAY", "EVEN_HARDER", "‘Autonomous products expose the fiction that negligence, product liability and causation can identify a single human error behind every injury.’ Evaluate the case for enterprise or system-based liability.", ("autonomous-product", "product-liability", "negligence", "causation", "enterprise-liability")),
        _q("PROBLEM_BASED", "SCHOOL_COMPARABLE", "A bus driver brakes suddenly to avoid a cyclist who entered through a defective barrier. A standing passenger is injured; a witness develops severe psychiatric illness; and a nearby shop loses a day's trade while the road is closed. Advise the driver, operator, cyclist, barrier contractor and claimants on duty, breach, causation and recoverable loss.", ("negligence", "multiple-defendants", "psychiatric-harm", "economic-loss", "causation")),
        _q("PROBLEM_BASED", "SCHOOL_COMPARABLE", "A supermarket knows that a freezer leaks intermittently but places a warning sign around only part of the aisle. A customer slips while reading a phone, and a child enters a staff area through an unlocked door and touches damaged wiring installed by a contractor. Advise on occupiers' duties, warnings, children, contractors and contributory fault.", ("occupiers-liability", "warning", "children", "contractor", "contributory-negligence")),
        _q("PROBLEM_BASED", "HARDER", "A developer's drainage system repeatedly floods neighbouring homes during unusually heavy rain. Residents also complain of construction dust and night noise. The developer followed planning permission, blames a specialist engineer and says climate change made the rainfall unforeseeable. Advise on nuisance, negligence, causation, defences and remedies.", ("private-nuisance", "flooding", "planning-permission", "contractor", "foreseeability", "remedy")),
        _q("PROBLEM_BASED", "HARDER", "A delivery platform describes riders as independent businesses but fixes prices, assigns routes and penalises rejected jobs. A rider assaults a customer after an argument about a delivery and later causes a collision while using the app for a personal errand. Advise on relationship status, close connection, negligence and the platform's potential liability.", ("vicarious-liability", "platform-worker", "intentional-tort", "close-connection", "road-negligence")),
        _q("PROBLEM_BASED", "EVEN_HARDER", "An influencer publishes a video alleging that a surgeon falsified results, using an AI-generated audio clip supplied anonymously. A platform recommends the video to millions after receiving notice that the clip may be fake. The surgeon loses patients and private medical details appear in comments. Advise all parties on defamation, privacy, malicious falsehood, platform involvement and remedies.", ("defamation", "deepfake", "privacy", "platform", "economic-harm", "injunction")),
        _q("PROBLEM_BASED", "EVEN_HARDER", "A home robot receives an over-the-air learning update, mistakes a visitor for an intruder and causes injury while damaging a neighbour's property. The manufacturer blames the component supplier, the owner disabled one safety alert, and diagnostic logs were overwritten by the next update. Advise on product defect, negligence, causation, contributory fault and evidence.", ("autonomous-robot", "product-liability", "software-update", "causation", "contributory-negligence", "evidence")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "I tripped in a pothole and broke my wrist. Who should I contact, and what evidence should I collect?", ("highway-defect", "personal-injury", "evidence"), clarification_targets=("location_and_date", "photos_and_reports", "medical_loss", "road_authority")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "My neighbour's builder damaged my wall, but the neighbour says the builder is independent. Who might have to pay?", ("property-damage", "independent-contractor", "negligence"), clarification_targets=("work_and_damage", "contracts", "warnings", "expert_evidence")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "Someone posted an untrue accusation about me in a local group and people have shared it. Can I make them remove it?", ("defamation", "online-publication", "removal"), clarification_targets=("exact_words", "audience", "truth_and_evidence", "loss_and_threats")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "A nearby business makes noise every night and I cannot sleep. Is this a legal nuisance or just something I must tolerate?", ("private-nuisance", "noise", "local-authority"), clarification_targets=("frequency_and_duration", "neighbourhood", "complaints", "health_and_measurements")),
        _q("GENERAL_ENQUIRY", "MULTI_ISSUE", "A delivery rider knocked me over after looking at the app, and neither the platform nor rider accepts responsibility. The app also deleted the trip record. Who can I claim against and what evidence matters?", ("road-negligence", "vicarious-liability", "platform", "evidence-preservation"), clarification_targets=("police_and_medical_records", "rider_status", "witnesses", "platform_correspondence")),
        _q("GENERAL_ENQUIRY", "BOUNDARY_OR_URGENT", "A newly bought battery is overheating and has already burned furniture. The retailer refuses a refund and the manufacturer wants the product returned immediately. What should I do before evidence is lost or someone is hurt?", ("defective-product", "property-damage", "personal-safety", "evidence-preservation"), clarification_targets=("product_and_purchase", "injury_or_fire_risk", "photos_and_reports", "recall_notice")),
    ],
)


_register(
    "trusts-law",
    "Trusts Law",
    ("trusts-law-course-materials", "trusts-assessment-style"),
    (
        "three certainties and testamentary dispositions",
        "constitution and formalities",
        "trustee and fiduciary duties",
        "tracing and third-party liability",
        "charitable and purpose trusts",
        "co-ownership and digital trust property",
    ),
    [
        _q("ESSAY", "SCHOOL_COMPARABLE", "‘The three certainties provide an appearance of doctrinal order but conceal distinct judicial choices about intention, property and beneficiaries.’ Critically discuss.", ("certainty-of-intention", "certainty-of-subject", "certainty-of-object", "express-trust")),
        _q("ESSAY", "SCHOOL_COMPARABLE", "Critically evaluate whether the rules on constitution and formalities prevent fraud and careless dealing or merely defeat seriously intended gifts and trusts.", ("constitution", "formalities", "imperfect-gift", "fraud")),
        _q("ESSAY", "HARDER", "‘Fiduciary loyalty is strict in formulation but remedially flexible in operation.’ Assess this claim with reference to conflicts, profits, authorisation and relief.", ("fiduciary-duty", "conflict", "unauthorised-profit", "remedy")),
        _q("ESSAY", "HARDER", "Critically assess whether modern tracing and third-party liability preserve a principled distinction between vindicating property rights and imposing personal responsibility for wrongdoing.", ("tracing", "knowing-receipt", "dishonest-assistance", "proprietary-remedy")),
        _q("ESSAY", "EVEN_HARDER", "‘Charitable status privileges public benefit without a stable theory of what counts as public or beneficial.’ Evaluate the doctrine's capacity to address political, technological and transnational purposes.", ("charity", "public-benefit", "political-purpose", "technology", "cross-border")),
        _q("ESSAY", "EVEN_HARDER", "Critically evaluate whether trusts law can treat cryptoassets, tokenised interests and automatically executed governance rights as trust property without distorting certainty, control and fiduciary accountability.", ("digital-assets", "trust-property", "control", "smart-contract", "fiduciary")),
        _q("PROBLEM_BASED", "SCHOOL_COMPARABLE", "A will leaves ‘most of my reliable investments’ to trustees for ‘those loyal friends who need help’, £80,000 for maintaining a family memorial and the residue to whichever environmental organisation the executors select. Advise on certainty, beneficiary principle, purpose trusts, charity and resulting trusts.", ("will-trust", "three-certainties", "purpose-trust", "charity", "resulting-trust")),
        _q("PROBLEM_BASED", "SCHOOL_COMPARABLE", "Mira says she will give shares to her nephew, signs an incomplete transfer form and sends it to her accountant. She separately declares that she now holds one quarter of ‘my investment portfolio’ for her niece, then sells and replaces several assets. Advise on constitution, declaration, subject matter and possible perfection routes.", ("share-transfer", "imperfect-gift", "self-declaration", "certainty-of-subject", "constitution")),
        _q("PROBLEM_BASED", "HARDER", "Two trustees invest half a family trust in a start-up owned by one trustee's spouse, take no independent advice and exclude a beneficiary from information because of a family dispute. The investment first triples, then collapses. Advise on powers, care, diversification, conflicts, accounts, loss and remedies.", ("trustee-investment", "duty-of-care", "conflict", "information-rights", "equitable-compensation")),
        _q("PROBLEM_BASED", "HARDER", "A trustee transfers trust money through an overdrawn personal account, buys a painting, gives cryptocurrency to a partner and pays an innocent supplier. The partner suspects the trustee's financial difficulties and later swaps the tokens for land. Advise on tracing, mixing, change of position, knowing receipt and proprietary remedies.", ("tracing", "mixed-fund", "cryptoasset", "knowing-receipt", "change-of-position", "substitution")),
        _q("PROBLEM_BASED", "EVEN_HARDER", "A global online community contributes to a decentralised fund ‘for open knowledge and resistance to censorship’. Token holders vote on grants, anonymous developers control the key and an English company hosts the interface. Funds are diverted to political advertising and a developer's business. Characterise the arrangement and advise on trust, association, charity, fiduciary status and remedies.", ("decentralised-fund", "purpose", "charity", "political-activity", "fiduciary", "digital-assets")),
        _q("PROBLEM_BASED", "EVEN_HARDER", "A settlor creates an English-law trust of tokenised securities held through an offshore custodian and governed by code that automatically votes and distributes returns. A software exploit changes beneficiary addresses; the custodian enters insolvency and trustees propose a hard fork opposed by some beneficiaries. Advise on trust property, control, governing law, trustee powers, variation and insolvency claims.", ("tokenised-securities", "custody", "smart-contract", "beneficiary", "trustee-power", "insolvency")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "My parent repeatedly said a savings account was ‘for me’ but died without changing the account name or will. Does that make it a trust?", ("intention", "constitution", "estate"), clarification_targets=("exact_words_and_context", "account_records", "control_and_withdrawals", "will")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "A trustee will not tell me where the trust money is invested. As a beneficiary, can I ask for accounts and documents?", ("beneficiary-information", "trustee-accountability", "documents"), clarification_targets=("trust_terms", "beneficiary_status", "documents_requested", "reason_for_refusal")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "A will leaves money for ‘good causes in my town’ but names no charity. Is the gift valid?", ("charitable-purpose", "certainty", "selection"), clarification_targets=("will_wording", "amount_and_property", "named_decision_maker", "location")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "I paid toward a house owned only in my partner's name because we agreed it was our home. Do I have any share?", ("family-home", "beneficial-interest", "common-intention", "reliance"), clarification_targets=("ownership_and_relationship", "payments", "agreements", "occupation_and_children")),
        _q("GENERAL_ENQUIRY", "MULTI_ISSUE", "The family trustee moved money into personal accounts, bought crypto and now says some records are missing. What can beneficiaries do to trace the assets and stop further transfers?", ("breach-of-trust", "tracing", "cryptoasset", "accounts", "interim-relief"), clarification_targets=("trust_documents", "transactions", "wallet_or_bank_evidence", "current_control")),
        _q("GENERAL_ENQUIRY", "BOUNDARY_OR_URGENT", "Trustees plan to sell the family business tomorrow to a company connected with one trustee, without an independent valuation. Can a beneficiary seek an urgent court order?", ("trustee-conflict", "sale", "valuation", "injunction"), clarification_targets=("sale_documents", "trustee_connection", "trust_terms", "timing_and_notice")),
    ],
)


_register(
    "contract-law",
    "Contract Law",
    ("contract-law-course-materials", "contract-assessment-style"),
    (
        "formation, consideration and variation",
        "terms, interpretation and good faith",
        "misrepresentation, mistake, duress and undue influence",
        "breach, termination and remedies",
        "frustration, penalties and exclusion clauses",
        "consumer, platform and automated contracting",
    ),
    [
        _q("ESSAY", "SCHOOL_COMPARABLE", "‘The doctrine of consideration is neither a reliable test of bargains nor a convincing limit on enforcement.’ Critically discuss.", ("consideration", "bargain", "variation", "promissory-estoppel")),
        _q("ESSAY", "SCHOOL_COMPARABLE", "Critically evaluate whether the modern approach to contractual interpretation respects the parties' language or permits context to rewrite their bargain.", ("interpretation", "text", "context", "commercial-common-sense")),
        _q("ESSAY", "HARDER", "‘English contract law recognises good faith only in fragments because a general duty would create more uncertainty than fairness.’ To what extent is this justified?", ("good-faith", "relational-contract", "discretion", "certainty")),
        _q("ESSAY", "HARDER", "Critically assess whether the distinction among penalties, deposits, liquidated damages and primary price terms produces a coherent control of disproportionate contractual consequences.", ("penalty", "deposit", "liquidated-damages", "primary-obligation")),
        _q("ESSAY", "EVEN_HARDER", "‘Frustration is designed for unforeseen events but cannot allocate systemic risks such as pandemics, sanctions and climate disruption consistently.’ Evaluate the doctrine and the case for statutory reform.", ("frustration", "force-majeure", "systemic-risk", "reform")),
        _q("ESSAY", "EVEN_HARDER", "Critically evaluate how contract law should attribute intention, mistake and responsibility when autonomous agents negotiate terms that neither principal predicted or specifically approved.", ("automated-contracting", "agency", "intention", "mistake", "allocation-of-risk")),
        _q("PROBLEM_BASED", "SCHOOL_COMPARABLE", "A wholesaler emails a quotation ‘subject to our standard terms’. The buyer orders using a form containing different liability terms. The wholesaler acknowledges without attaching terms, delivers, and the buyer signs a receipt referring to a third set. Goods then fail. Advise on formation, incorporation, battle of forms and remedies.", ("formation", "battle-of-forms", "incorporation", "terms", "breach")),
        _q("PROBLEM_BASED", "SCHOOL_COMPARABLE", "A gym promises a discounted two-year membership after telling Sam that cancellation is possible at any time. The signed digital form contains an auto-renewal term and a large cancellation charge hidden behind a link. Sam relies on the oral statement, then needs to cancel after illness. Advise on terms, misrepresentation, consumer fairness and remedies.", ("pre-contract-statement", "incorporation", "misrepresentation", "consumer-term", "cancellation")),
        _q("PROBLEM_BASED", "HARDER", "A supplier demands a 35% price increase halfway through an urgent project, threatening to stop despite an existing fixed-price contract. The customer agrees because delay would trigger another contract's penalties, then pays two invoices before protesting. Advise on variation, consideration, economic duress, affirmation and restitution.", ("contract-variation", "consideration", "economic-duress", "affirmation", "restitution")),
        _q("PROBLEM_BASED", "HARDER", "A venue cancels a concert after a nearby emergency makes access difficult but not impossible. The promoter has prepaid, artists remain available, and the contract contains both a force-majeure clause and a non-refundable deposit. Advise on construction, frustration, termination, deposits and loss allocation.", ("force-majeure", "frustration", "deposit", "termination", "loss-allocation")),
        _q("PROBLEM_BASED", "EVEN_HARDER", "A retailer's purchasing bot accepts a supplier bot's dynamically generated price for 50,000 units after a data-feed error shifts a decimal point. Both systems depart from internal limits, but only the supplier notices before shipment and stays silent. Advise on formation, authority, mistake, knowledge, good faith and available relief.", ("contracting-bot", "authority", "unilateral-mistake", "knowledge", "relief")),
        _q("PROBLEM_BASED", "EVEN_HARDER", "A cloud provider suspends a hospital's records platform after an automated fraud alert. Its standard terms exclude data loss, cap liability at one month's fees and allow immediate suspension. The alert is wrong; backups also fail, surgeries are delayed and patients bring claims. Advise on incorporation, interpretation, exclusion control, remoteness, third-party loss and termination.", ("cloud-contract", "exclusion-clause", "liability-cap", "remoteness", "third-party", "termination")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "I paid a deposit for a service but cancelled before any work started. The business says every deposit is non-refundable. Is that always true?", ("deposit", "cancellation", "consumer-contract"), clarification_targets=("service_and_price", "terms", "cancellation_reason_and_date", "business_loss")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "A builder's final bill is much higher than the written quote. Do I have to pay the extra amount?", ("quote", "variation", "service-contract"), clarification_targets=("quote_wording", "agreed_changes", "work_completed", "consumer_or_business")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "An online subscription renewed for a year without warning. Can I cancel and get the payment back?", ("auto-renewal", "consumer-term", "notice"), clarification_targets=("sign_up_terms", "renewal_notice", "payment_date", "location")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "A seller promised delivery before my wedding, but the item arrived afterwards. Can I recover more than just the purchase price?", ("late-performance", "special-purpose", "damages", "remoteness"), clarification_targets=("promise_and_evidence", "seller_knowledge", "replacement_cost", "other_loss")),
        _q("GENERAL_ENQUIRY", "MULTI_ISSUE", "A software company changed its price and features halfway through our business contract, then locked us out when we disputed the invoice. Our data are still on its system. What contract issues and evidence should we check?", ("contract-variation", "termination", "data-access", "limitation", "business-contract"), clarification_targets=("contract_and_versions", "change_notices", "invoices_and_payments", "data_and_loss")),
        _q("GENERAL_ENQUIRY", "BOUNDARY_OR_URGENT", "A venue cancelled tomorrow's event but its terms exclude every refund and all consequential loss. Suppliers and guests are already travelling. What should I do now to reduce loss and preserve my claim?", ("cancellation", "exclusion-clause", "mitigation", "urgent-evidence"), clarification_targets=("contract_and_reason", "payments", "supplier_commitments", "replacement_options")),
    ],
)


_register(
    "criminal-law",
    "Criminal Law",
    ("criminal-law-course-materials", "criminal-law-assessment-style"),
    (
        "offences against the person and consent",
        "homicide and defences",
        "property offences and fraud",
        "secondary liability, attempts and inchoate offences",
        "self-defence, duress and necessity",
        "digital, corporate and autonomous harms",
    ),
    [
        _q("ESSAY", "SCHOOL_COMPARABLE", "‘The criminal law's treatment of mistaken belief in self-defence protects autonomy at the price of objective public safety.’ Critically discuss.", ("self-defence", "mistake", "reasonableness", "public-safety")),
        _q("ESSAY", "SCHOOL_COMPARABLE", "Critically evaluate whether consent provides a coherent boundary between lawful risk-taking and criminal injury.", ("consent", "assault", "bodily-harm", "public-policy")),
        _q("ESSAY", "HARDER", "‘Complicity doctrine risks punishing association and foresight rather than intentional participation.’ Assess the principles governing secondary liability and withdrawal.", ("secondary-liability", "intent", "assistance", "encouragement", "withdrawal")),
        _q("ESSAY", "HARDER", "Critically assess whether the law of attempts identifies a defensible point between criminal intention and conduct sufficiently proximate to a completed offence.", ("attempt", "intent", "more-than-preparatory", "impossibility")),
        _q("ESSAY", "EVEN_HARDER", "‘Dishonesty is presented as an objective standard but remains dependent on contested social expectations and incomplete facts.’ Evaluate its operation across theft, fraud and fiduciary wrongdoing.", ("dishonesty", "theft", "fraud", "social-standards", "fact-finding")),
        _q("ESSAY", "EVEN_HARDER", "Critically evaluate how criminal responsibility should be attributed when a corporation deploys an adaptive autonomous system that causes foreseeable harm without any individual possessing the complete actus reus and mens rea.", ("corporate-criminal-liability", "autonomous-system", "actus-reus", "mens-rea", "systemic-harm")),
        _q("PROBLEM_BASED", "SCHOOL_COMPARABLE", "During an amateur match, Ari tackles Ben after play has stopped. Ben punches Ari; Cara joins believing Ben is under attack, and a spectator is injured when Ari throws a bottle toward the group. Advise each person on offences against the person, consent to sporting contact, self-defence, transferred fault and causation.", ("assault", "consent", "sport", "self-defence", "transferred-malice", "causation")),
        _q("PROBLEM_BASED", "SCHOOL_COMPARABLE", "Dara secretly puts a sedative in Eli's drink intending only to frighten him. Eli becomes confused, walks into traffic and dies after a driver negligently fails to brake. Dara says she did not foresee death and acted after prolonged abuse by Eli. Advise on homicide, causation, mens rea and possible defences.", ("homicide", "unlawful-act", "causation", "mens-rea", "loss-of-control", "diminished-responsibility")),
        _q("PROBLEM_BASED", "HARDER", "Finn receives money transferred to his account by mistake, spends part after suspecting an error, and asks Gia to create an invoice explaining the payment. Gia agrees but later deletes the draft. Finn also returns a hired laptop after replacing valuable components. Advise on theft, fraud, appropriation, property, dishonesty, attempts and secondary liability.", ("theft", "mistaken-payment", "fraud", "dishonesty", "attempt", "secondary-liability")),
        _q("PROBLEM_BASED", "HARDER", "A gang pressures Hana to drive them to a warehouse by threatening her brother. She waits outside, hears breaking glass and then drives away with the group and unknown packages. Before arrest, she anonymously warns police about a second planned raid. Advise on participation, knowledge and intent, joint offending, duress and withdrawal.", ("complicity", "joint-offending", "duress", "withdrawal", "handling")),
        _q("PROBLEM_BASED", "EVEN_HARDER", "Employees use a generative system to create convincing messages that redirect supplier payments. One employee designs prompts, another supplies customer data believing the project is security testing, a manager ignores warnings, and an external mule receives cryptocurrency. Allocate potential fraud, conspiracy, attempt, money-laundering and corporate liability.", ("ai-enabled-fraud", "conspiracy", "attempt", "money-laundering", "secondary-liability", "corporate-liability")),
        _q("PROBLEM_BASED", "EVEN_HARDER", "A logistics company allows an autonomous truck to operate after safety alerts are downgraded to meet deadlines. A remote supervisor manages twenty vehicles and cannot intervene when the truck selects an unsafe route, killing a pedestrian. Software and sensor suppliers each contributed defects. Advise on homicide offences, gross negligence, corporate attribution, causation and evidential responsibility.", ("corporate-manslaughter", "gross-negligence", "autonomous-vehicle", "causation", "corporate-attribution", "evidence")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "Someone threatened me and I pushed them away, causing an injury. How does the law decide whether I acted in self-defence?", ("self-defence", "force", "assault"), clarification_targets=("immediate_threat", "force_used", "sequence_and_witnesses", "injury")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "My employer overpaid my wages and I spent the money before receiving an email about the mistake. Could this be a criminal matter?", ("mistaken-payment", "theft", "dishonesty"), clarification_targets=("payment_and_knowledge_dates", "communications", "amount_spent", "repayment_steps")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "A friend asked me to store a phone, and I later learned it may have been stolen. What matters for whether I have committed an offence?", ("handling-stolen-goods", "knowledge", "possession"), clarification_targets=("what_was_said", "when_suspicion_arose", "actions_taken", "phone_status")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "I sent angry messages saying I would hurt someone but never intended to do it. Can messages alone be criminal?", ("threats", "communications-offence", "intent"), clarification_targets=("exact_messages", "recipient_and_context", "timing", "subsequent_actions")),
        _q("GENERAL_ENQUIRY", "MULTI_ISSUE", "I drove friends to a shop, waited outside and only then realised they might be stealing. I drove away with them because I panicked. Could I be responsible for what they did?", ("secondary-liability", "knowledge", "assistance", "withdrawal", "duress"), clarification_targets=("knowledge_timeline", "agreement", "actions_during_and_after", "threats")),
        _q("GENERAL_ENQUIRY", "BOUNDARY_OR_URGENT", "Police want me to attend an interview today about online payments made through my account. They say it is voluntary. What should I do before answering questions or giving them my phone?", ("police-interview", "legal-advice", "digital-evidence", "self-incrimination"), clarification_targets=("police_request", "arrest_or_voluntary_status", "account_use", "legal_representation")),
    ],
)


_register(
    "eu-internal-market-law",
    "EU Internal Market and Citizenship Law",
    ("eu-law-course-materials", "eu-law-assessment-style"),
    (
        "free movement of goods",
        "workers, citizenship and family rights",
        "services and establishment",
        "justifications, proportionality and fundamental rights",
        "mutual recognition and national autonomy",
        "digital activity and changing UK-EU interfaces",
    ),
    [
        _q("ESSAY", "SCHOOL_COMPARABLE", "‘The distinction between distinctly and indistinctly applicable measures no longer explains the real structure of free movement of goods.’ Critically discuss.", ("free-movement-goods", "discrimination", "market-access", "article-34")),
        _q("ESSAY", "SCHOOL_COMPARABLE", "Critically evaluate whether EU citizenship has developed into a fundamental status or remains conditional on economic activity, resources and lawful residence.", ("eu-citizenship", "residence", "equal-treatment", "economic-activity")),
        _q("ESSAY", "HARDER", "‘Proportionality allows the Court to protect market integration while presenting contested policy choices as legal technique.’ Assess this claim in the context of national justifications.", ("proportionality", "justification", "market-integration", "national-autonomy")),
        _q("ESSAY", "HARDER", "Critically assess whether mutual recognition adequately reconciles cross-border trade in services with professional, consumer and public-interest regulation in the host state.", ("services", "mutual-recognition", "professional-qualification", "public-interest")),
        _q("ESSAY", "EVEN_HARDER", "‘Digital platforms are simultaneously service providers, market infrastructures and regulators of cross-border activity; classical internal-market freedoms cannot capture all three roles.’ Evaluate this proposition.", ("digital-platform", "services", "establishment", "market-access", "regulation")),
        _q("ESSAY", "EVEN_HARDER", "Critically evaluate how the applicable legal architecture after UK withdrawal mediates divergence, market access and individual rights across EU, UK and devolved regulatory spaces at the frozen currentness cutoff.", ("uk-eu", "withdrawal", "market-access", "divergence", "individual-rights", "currentness")),
        _q("PROBLEM_BASED", "SCHOOL_COMPARABLE", "A Portuguese worker moves to another Member State, works irregular hours for four months and then loses the job. Their non-EU spouse seeks residence, a child applies for study support and the authority refuses housing assistance because the family lacks five years' residence. Advise on worker status, retained status, family rights and equal treatment.", ("worker", "citizenship", "family-member", "social-assistance", "equal-treatment")),
        _q("PROBLEM_BASED", "SCHOOL_COMPARABLE", "A Member State requires imported energy drinks to use a different bottle shape, carry a national health label and be sold only through licensed pharmacies. Domestic herbal drinks with similar ingredients are exempt. Advise the importer on restrictions, discrimination, justifications and proportionality.", ("free-movement-goods", "product-requirement", "selling-arrangement", "discrimination", "public-health")),
        _q("PROBLEM_BASED", "HARDER", "An architect qualified in one Member State provides remote design services and opens a temporary studio in another. The host authority requires full requalification, local ownership and a permanent office, citing safety and professional independence. Advise on services, establishment, recognition, direct effect and justification.", ("professional-services", "establishment", "qualification", "ownership-restriction", "justification")),
        _q("PROBLEM_BASED", "HARDER", "A long-term EU resident is expelled after repeated minor offences. The decision relies on a predictive risk score, gives no individual reasons and also removes residence rights from a dependent parent. Advise on citizenship status, public-security grounds, proportionality, procedural protection and family rights.", ("expulsion", "public-security", "proportionality", "automated-score", "family-rights")),
        _q("PROBLEM_BASED", "EVEN_HARDER", "A Member State blocks an overseas telemedicine platform unless all patient data and clinicians are located nationally. The platform is established in one Member State, uses professionals licensed across three others and applies algorithmic triage. The state cites health, data protection and accountability. Advise on services, establishment, data measures, fundamental rights and proportionality.", ("telemedicine", "data-localisation", "services", "health-justification", "proportionality", "ai-triage")),
        _q("PROBLEM_BASED", "EVEN_HARDER", "A cross-border renewable-energy scheme gives priority grid access and consumer subsidies only to electricity certified under a national system. Foreign producers can qualify only by disclosing commercially sensitive data to a state-owned competitor. Advise on goods, services, state measures, environmental justification, proportionality and effective remedies.", ("renewable-energy", "market-access", "national-certification", "commercial-data", "environment", "remedy")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "I moved to another EU country for work and lost my job after three months. Can I stay and claim help while looking for work?", ("worker-status", "residence", "jobseeker", "benefits"), clarification_targets=("nationalities", "work_history", "reason_for_job_loss", "benefit_and_country")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "My small business wants to sell packaged food in another EU country, but it requires different labels and packaging. Can that country insist?", ("goods", "labelling", "packaging", "market-access"), clarification_targets=("product", "origin_and_destination", "national_rule", "health_or_consumer_reason")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "I am qualified as a nurse in one EU country, but another says I must repeat my full training. What can I ask the authority to recognise?", ("professional-qualification", "worker", "establishment"), clarification_targets=("qualification_and_country", "planned_work", "authority_decision", "training_differences")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "My spouse is not an EU citizen. If I move to work in another Member State, can they come and live with me?", ("family-member", "residence", "free-movement"), clarification_targets=("nationalities", "marriage_or_relationship", "movement_and_work", "prior_residence")),
        _q("GENERAL_ENQUIRY", "MULTI_ISSUE", "I run an online therapy service from one EU country. Another country says I need a local company, local servers and locally qualified therapists before serving its residents. Which restrictions should be checked?", ("online-service", "establishment", "data-localisation", "professional-qualification", "health"), clarification_targets=("countries", "service_and_profession", "requirements", "client_targeting")),
        _q("GENERAL_ENQUIRY", "BOUNDARY_OR_URGENT", "Border officials say an old conviction may lead to my removal from an EU country today, even though my children live there. What information and urgent review should I seek?", ("expulsion", "public-security", "family-life", "procedural-rights"), clarification_targets=("nationality_and_residence", "decision_document", "conviction", "family_and_deadline")),
    ],
)


_register(
    "land-law",
    "Land Law",
    ("land-law-course-materials", "land-law-assessment-style"),
    (
        "registered title and priority",
        "co-ownership and trusts of land",
        "actual occupation and mortgages",
        "easements and covenants",
        "proprietary estoppel and adverse possession",
        "leases, electronic conveyancing and fraud",
    ),
    [
        _q("ESSAY", "SCHOOL_COMPARABLE", "‘The law of severance converts personal communications and conduct into proprietary consequences with insufficient certainty for co-owners and purchasers.’ Critically discuss.", ("co-ownership", "joint-tenancy", "severance", "purchaser")),
        _q("ESSAY", "SCHOOL_COMPARABLE", "Critically evaluate whether the protection of interests arising from actual occupation strikes a fair balance among home occupiers, purchasers and mortgage lenders.", ("actual-occupation", "overriding-interest", "registered-land", "mortgage")),
        _q("ESSAY", "HARDER", "‘Proprietary estoppel has become a discretionary law of broken promises rather than a principled source of property rights.’ Assess this criticism.", ("proprietary-estoppel", "assurance", "reliance", "detriment", "remedy")),
        _q("ESSAY", "HARDER", "Critically assess whether the distinction between easements and restrictive covenants remains justified by coherent differences in use, benefit, registration and remedy.", ("easement", "restrictive-covenant", "benefit-and-burden", "registration", "remedy")),
        _q("ESSAY", "EVEN_HARDER", "‘Mortgage law formally protects consent and redemption while structurally prioritising the security and sale expectations of lenders.’ Evaluate this claim in domestic and commercial contexts.", ("mortgage", "undue-influence", "equity-of-redemption", "possession", "sale")),
        _q("ESSAY", "EVEN_HARDER", "Critically evaluate whether registered land can preserve title security when identity fraud, automated conveyancing and instant digital finance separate the register from human occupation and informed consent.", ("registered-title", "identity-fraud", "electronic-conveyancing", "rectification", "indemnity")),
        _q("PROBLEM_BASED", "SCHOOL_COMPARABLE", "Asha and Ben buy a house as joint registered proprietors, but Asha pays 80% and Ben later emails that he is giving ‘my share’ to his sister. Asha dies; Ben becomes bankrupt, and the sister seeks a sale while Asha's child claims the whole beneficial interest. Advise on co-ownership, beneficial shares, severance, survivorship and sale.", ("co-ownership", "beneficial-share", "severance", "survivorship", "bankruptcy", "sale")),
        _q("PROBLEM_BASED", "SCHOOL_COMPARABLE", "A bank takes a mortgage from the sole registered owner of a family home. His partner funded renovations and was away caring for a relative during the lender's inspection; belongings remained in the house. The owner defaults and the bank seeks possession. Advise on beneficial interest, actual occupation, inquiry, priority and remedies.", ("mortgage", "beneficial-interest", "actual-occupation", "priority", "possession")),
        _q("PROBLEM_BASED", "HARDER", "A farm is sold in three plots. One deed grants a right to use a track ‘for agricultural purposes’, another contains a promise not to build, and all owners have used a drainage pipe for twenty years. A developer proposes homes and blocks the track during construction. Advise on easements, prescription, covenants, construction and remedies.", ("easement", "prescription", "restrictive-covenant", "construction", "remedy")),
        _q("PROBLEM_BASED", "HARDER", "An aunt tells her niece that a cottage ‘will be yours’ if she leaves employment to provide care. The niece moves in, pays substantial repair costs and refuses another home. The aunt's will later leaves the cottage to a charity, and the executors offer only repayment of invoices. Advise on proprietary estoppel, constructive trust and remedy.", ("proprietary-estoppel", "assurance", "reliance", "detriment", "constructive-trust", "remedy")),
        _q("PROBLEM_BASED", "EVEN_HARDER", "A fraudster impersonates a registered proprietor and transfers land through an online conveyancing platform to a company that immediately grants a mortgage. The true owner is living abroad; a tenant in occupation has an unregistered purchase option. Advise on registration, validity, priority, alteration, indemnity and the positions of the company, lender, owner and tenant.", ("registration-fraud", "disposition", "mortgage", "purchase-option", "priority", "indemnity")),
        _q("PROBLEM_BASED", "EVEN_HARDER", "A mixed-use building is held through tokenised interests marketed as giving each buyer ‘direct ownership’. The registered proprietor leases flats, grants a lender security and enters insolvency; the token code allocates votes and rent but no transfer is registered. Characterise the interests and advise on trusts, co-ownership, leases, priority and insolvency.", ("tokenised-land", "registered-title", "trust", "lease", "mortgage", "insolvency")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "I paid most of the deposit for a home but only my partner is named as owner. Do I have any rights if we separate?", ("beneficial-interest", "family-home", "co-ownership"), clarification_targets=("purchase_and_title", "payments", "agreements", "later_contributions")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "My neighbour says I can no longer use a path that has provided access to my house for many years. Could I have a legal right of way?", ("easement", "right-of-way", "prescription"), clarification_targets=("title_documents", "years_and_manner_of_use", "permission", "alternative_access")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "A mortgage lender wants to repossess the home, but I live there and contributed money even though I did not sign the mortgage. Can my interest matter?", ("mortgage", "beneficial-interest", "actual-occupation"), clarification_targets=("ownership_and_mortgage", "contributions", "occupation", "lender_inquiry")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "The fence is not where the title plan seems to show, and both neighbours claim the strip of land. How is a boundary dispute decided?", ("boundary", "title-plan", "adverse-possession", "evidence"), clarification_targets=("titles_and_plans", "physical_history", "use_and_maintenance", "survey_or_correspondence")),
        _q("GENERAL_ENQUIRY", "MULTI_ISSUE", "My landlord sold the building. The new owner says my lease is invalid, removes access to parking and wants to change the locks. What land and tenancy documents should I check?", ("lease", "purchaser", "priority", "easement", "possession"), clarification_targets=("lease_and_registration", "occupation", "parking_terms", "notices_and_lock_threat")),
        _q("GENERAL_ENQUIRY", "BOUNDARY_OR_URGENT", "A jointly owned home is due to be sold tomorrow, but I believe my signature was forged and the buyer has never inspected the property. What urgent steps and evidence may matter?", ("forgery", "registered-disposition", "actual-occupation", "injunction", "evidence"), clarification_targets=("sale_and_title_documents", "occupation", "signature_evidence", "completion_timing")),
    ],
)


_register(
    "contemporary-biolaw-and-regulation",
    "Contemporary Biolaw and Regulation",
    ("biolaw-course-materials", "biolaw-assessment-style", "emerging-technology-materials"),
    (
        "neurotechnology and cognitive liberty",
        "AI in healthcare and research",
        "ectogestation and reproductive status",
        "genomics and human enhancement",
        "environmental technology and subsidy design",
        "evidence, responsibility and cross-regulatory gaps",
    ),
    [
        _q("ESSAY", "SCHOOL_COMPARABLE", "‘Existing privacy, bodily integrity and data-protection rights make separate neurorights unnecessary.’ Critically discuss.", ("neurorights", "mental-privacy", "bodily-integrity", "data-protection")),
        _q("ESSAY", "SCHOOL_COMPARABLE", "Critically evaluate whether the regulation of AI in healthcare should focus on the safety of the product, the quality of the clinical decision or the institutions that deploy it.", ("healthcare-ai", "medical-device", "clinical-governance", "institutional-responsibility")),
        _q("ESSAY", "HARDER", "‘Ectogestation destabilises legal categories of pregnancy, birth and parenthood but does not by itself determine how those categories should change.’ Assess the appropriate regulatory approach.", ("ectogestation", "pregnancy", "birth", "parenthood", "regulation")),
        _q("ESSAY", "HARDER", "Critically assess whether genomic selection can be regulated consistently when the same intervention may prevent disease, select traits and produce population-level inequality.", ("genomic-selection", "disease-prevention", "enhancement", "equality")),
        _q("ESSAY", "EVEN_HARDER", "‘The evidential use of brain data threatens criminal responsibility not because neuroscience eliminates agency, but because probabilistic inference may be mistaken for individual truth.’ Critically evaluate.", ("neuroscience-evidence", "criminal-responsibility", "probabilistic-inference", "agency")),
        _q("ESSAY", "EVEN_HARDER", "Evaluate how law should govern technologies that are simultaneously medical interventions, consumer products, data infrastructures and instruments of public policy. Is sector-specific regulation capable of controlling their combined effects?", ("cross-regulatory", "medical-device", "consumer-product", "data-infrastructure", "public-policy")),
        _q("PROBLEM_BASED", "SCHOOL_COMPARABLE", "A consumer headset marketed for focus records neural signals, gives mood advice and sends risk scores to the user's phone. After a software update it recommends stopping prescribed medication, and the user is harmed. Advise on product characterisation, consent, data use, safety claims and responsibility.", ("consumer-neurotechnology", "medical-advice", "product-safety", "neural-data", "responsibility")),
        _q("PROBLEM_BASED", "SCHOOL_COMPARABLE", "A hospital introduces an AI triage tool trained on overseas data. Nurses can override it but receive no explanation and are criticised for delays. It repeatedly assigns lower urgency to one patient group, and a patient suffers serious harm. Advise on validation, discrimination, professional duties, consent and liability.", ("ai-triage", "bias", "clinical-validation", "human-oversight", "liability")),
        _q("PROBLEM_BASED", "HARDER", "A research team transfers a fetus from a patient with life-threatening complications to an experimental artificial-womb system. The patient withdraws consent after transfer; the other genetic parent seeks continuation, and the system provider claims ownership of performance data. Advise on status, consent, parenthood, research governance and data.", ("ectogestation", "consent", "fetal-status", "parenthood", "research", "data")),
        _q("PROBLEM_BASED", "HARDER", "A clinic offers embryo screening for a serious condition, educational attainment and predicted height through one bundled service. Its model was trained on a narrow population and produces uncertain scores. Parents later allege they were not told about uncertainty or data sharing. Advise on consent, regulation, discrimination, information and remedies.", ("embryo-screening", "polygenic-score", "consent", "bias", "data-sharing", "remedy")),
        _q("PROBLEM_BASED", "EVEN_HARDER", "A government offers renewable-energy subsidies only to projects using an AI certification platform owned by an industry consortium. The platform's model is secret, disadvantages community projects and later misclassifies a polluting facility as low-carbon. Advise on public-law fairness, competition, environmental evidence, algorithmic accountability and subsidy recovery.", ("renewable-subsidy", "algorithmic-certification", "public-law", "competition", "environmental-evidence")),
        _q("PROBLEM_BASED", "EVEN_HARDER", "Police obtain a suspect's consumer brain-computer-interface history and use a commercial model to infer recognition of a crime scene. The provider cannot reproduce the score, the data were collected for gaming and the suspect has a neurological condition. Advise on privacy, data purpose, scientific validity, disclosure, admissibility and criminal responsibility.", ("brain-data", "law-enforcement", "purpose-limitation", "scientific-evidence", "admissibility", "responsibility")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "My fitness headset says it can detect stress from brain signals. Is that health data, and can the company sell the prediction?", ("neural-data", "health-inference", "data-sharing"), clarification_targets=("device_and_notice", "signals_and_inference", "company_location", "sharing_evidence")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "A hospital says an AI system helped decide my treatment. Can I ask whether a clinician checked its recommendation?", ("clinical-ai", "human-oversight", "explanation"), clarification_targets=("decision_and_effect", "hospital_notice", "clinician_involvement", "records_requested")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "Could a future artificial-womb treatment change who is legally treated as a parent or when a child is considered born?", ("ectogestation", "parenthood", "birth-status"), clarification_targets=("country", "treatment_or_hypothetical", "genetic_and_intended_parents", "stage")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "My employer wants everyone to wear a device that measures attention. Can I refuse, and who can see the results?", ("workplace-neurotechnology", "consent", "monitoring", "neural-data"), clarification_targets=("device_and_policy", "mandatory_consequences", "data_and_recipients", "workplace_location")),
        _q("GENERAL_ENQUIRY", "MULTI_ISSUE", "A genetic-testing service changed my health report, used my sample for research and shared family risk information with an insurer. What consent, accuracy and privacy questions should I raise?", ("genetic-testing", "biological-sample", "research", "accuracy", "family-data", "insurance"), clarification_targets=("terms_and_consents", "report_versions", "sample_status", "sharing_evidence")),
        _q("GENERAL_ENQUIRY", "BOUNDARY_OR_URGENT", "Police have asked me to unlock a brain-sensing device after an accident, while the manufacturer says its data may be overwritten tonight. What should be preserved and what advice should I obtain before agreeing?", ("neural-device", "police-access", "evidence-preservation", "self-incrimination", "privacy"), clarification_targets=("police_power_or_request", "device_and_data", "accident_role", "overwrite_notice")),
    ],
)


_register(
    "business-and-company-law",
    "Business and Company Law",
    ("business-law-course-materials", "business-organisation-and-management-scope"),
    (
        "business forms and separate legal personality",
        "corporate administration and shareholder rights",
        "company finance, capital and creditor protection",
        "directors, governance and conflicts",
        "agency and authority in business transactions",
        "employment, equality, intellectual property and data responsibilities",
    ),
    [
        _q("ESSAY", "SCHOOL_COMPARABLE", "‘Limited liability encourages enterprise by separating business risk from personal wealth, but permits those who control a business to externalise loss.’ Critically discuss across the principal forms of business organisation.", ("business-form", "separate-personality", "limited-liability", "creditor-risk")),
        _q("ESSAY", "SCHOOL_COMPARABLE", "Critically evaluate whether the division of power between shareholders and directors provides effective accountability without undermining efficient corporate management.", ("shareholder", "director", "corporate-administration", "accountability")),
        _q("ESSAY", "HARDER", "‘Capital maintenance rules protect creditors only indirectly and often after commercial risk has already shifted.’ Assess the coherence of rules governing shares, distributions and security.", ("capital-maintenance", "shares", "dividend", "security", "creditor-protection")),
        _q("ESSAY", "HARDER", "Critically assess whether directors' duties can accommodate employee, environmental and long-term interests while remaining enforceable duties owed to the company.", ("director-duty", "company-interest", "stakeholder", "long-term", "enforcement")),
        _q("ESSAY", "EVEN_HARDER", "‘Apparent authority is designed for human representations and cannot allocate transactional risk fairly when businesses communicate through platforms and autonomous agents.’ Evaluate this claim.", ("agency", "apparent-authority", "platform", "automated-agent", "transactional-risk")),
        _q("ESSAY", "EVEN_HARDER", "A growing business may simultaneously be a company, employer, data controller and owner of intangible assets. Critically evaluate whether fragmented legal regimes create accountability gaps that justify an integrated business-law approach.", ("corporate-law", "employment", "data-protection", "intellectual-property", "integrated-regulation")),
        _q("PROBLEM_BASED", "SCHOOL_COMPARABLE", "Three friends open a design studio without written terms. One contributes most of the capital, one signs a five-year lease in the studio's name, and one tells a supplier that a company will soon be formed. After losses arise, they incorporate but transfer only some contracts. Advise on business form, partnership, pre-incorporation obligations, authority and liability.", ("partnership", "business-form", "pre-incorporation-contract", "authority", "liability")),
        _q("PROBLEM_BASED", "SCHOOL_COMPARABLE", "The board of a small company approves a contract with a director's spouse, pays a dividend despite weak accounts and refuses a minority shareholder access to meeting information. The director did not vote but negotiated the price. Advise on board and member powers, conflicts, distributions, disclosure and remedies.", ("director-conflict", "board-power", "dividend", "minority-shareholder", "remedy")),
        _q("PROBLEM_BASED", "HARDER", "A sales manager regularly negotiates contracts up to £100,000. The board privately limits her authority to £40,000, but the website still calls her ‘Head of Commercial’. She agrees a £90,000 order containing an unusual guarantee, then takes a secret commission. Advise the company, supplier and manager on actual and apparent authority, ratification and fiduciary responsibility.", ("agency", "actual-authority", "apparent-authority", "ratification", "secret-commission")),
        _q("PROBLEM_BASED", "HARDER", "A company issues new shares selectively to dilute an activist member, grants a floating security interest to a connected lender and pays a large distribution shortly before cash-flow failure. Advise directors, shareholders, the lender and an insolvency office-holder on powers, purpose, capital, priority and potential challenge.", ("share-issue", "proper-purpose", "security", "distribution", "insolvency", "challenge")),
        _q("PROBLEM_BASED", "EVEN_HARDER", "A delivery business labels couriers self-employed, controls work through ratings and dismisses one after she reports safety defects and pregnancy discrimination. Customer software created by the courier is then reused after termination. Advise on employment status, dismissal, equality, whistleblowing, intellectual property and business responsibility.", ("employment-status", "dismissal", "pregnancy-discrimination", "whistleblowing", "intellectual-property")),
        _q("PROBLEM_BASED", "EVEN_HARDER", "A start-up trains a customer-service model on client records and a former employee's proprietary code. A director approves launch despite security warnings, the model discloses personal data and a reseller makes contracts outside written limits through the system. Allocate corporate, director, agency, employment, intellectual-property and data responsibilities.", ("corporate-governance", "director-duty", "agency", "trade-secret", "personal-data", "ai-system")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "I am starting a small business alone. What practical legal differences should I check before choosing sole trader or limited company status?", ("sole-trader", "company", "business-form", "liability"), clarification_targets=("business_activity", "co_owners", "risk_and_finance", "employees")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "My business partner signed an expensive contract without asking me. Is the business still bound?", ("partnership", "agency", "authority"), clarification_targets=("business_structure", "contract", "partner_role", "third_party_knowledge")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "I am a company director and the business cannot pay all its bills. Could I become personally liable if we keep trading?", ("director", "insolvency-risk", "personal-liability"), clarification_targets=("financial_position", "decisions_and_dates", "accounts_and_advice", "company_type")),
        _q("GENERAL_ENQUIRY", "EVERYDAY", "My employer dismissed me soon after I announced my pregnancy and says my role was redundant. What records should I collect?", ("dismissal", "pregnancy-discrimination", "redundancy", "evidence"), clarification_targets=("employment_dates", "dismissal_and_redundancy_process", "comparators", "messages_and_deadline")),
        _q("GENERAL_ENQUIRY", "MULTI_ISSUE", "A former worker copied our customer list, website design and brand name, then contacted clients through a competing company. What contract, intellectual-property, data and company issues should we examine?", ("confidential-information", "copyright", "trade-mark", "personal-data", "director-or-employee-duty"), clarification_targets=("worker_role_and_terms", "materials_copied", "data_and_clients", "new_business_connection")),
        _q("GENERAL_ENQUIRY", "BOUNDARY_OR_URGENT", "The directors plan to transfer the company's main asset tomorrow to another business they own, while staff and suppliers remain unpaid. As a minority shareholder, what urgent information and remedies should I seek?", ("director-conflict", "asset-transfer", "minority-shareholder", "creditor-risk", "urgent-relief"), clarification_targets=("company_and_shareholding", "transaction_documents", "director_connections", "financial_position_and_timing")),
    ],
)


def _build_style_profile() -> dict[str, Any]:
    references: list[dict[str, Any]] = []
    for alias, path, role in STYLE_REFERENCES:
        if not path.is_file() or path.is_symlink():
            raise FileNotFoundError(f"style reference unavailable: {alias}")
        references.append(
            {
                "alias": alias,
                "role": role,
                "file_sha256": _sha256_file(path),
                "legal_authority": False,
                "instructions_from_source_executed": False,
            }
        )
    return _sealed(
        {
            "schema": "legalbot.v111.phase2b.question-style-profile.v1",
            "status": "NON_AUTHORIZING_STYLE_REFERENCE_ONLY",
            "reference_count": len(references),
            "references": references,
            "observed_academic_features": [
                "quotation_or_proposition_led_critical_essay",
                "to_what_extent_and_reform_framing",
                "multi_actor_multi_event_problem_question",
                "realistic_dates_numbers_documents_and_relationships",
                "missing_or_ambiguous_facts_requiring_express_assumptions",
                "clear_advise_or_critically_discuss_command",
                "increased_difficulty_through_cross_doctrine_conflict_and_currentness",
            ],
            "general_enquiry_features": [
                "plain_first_person_language",
                "concrete_event_and_requested_outcome",
                "ordinary_user_does_not_name_the_legal_doctrine",
                "missing_jurisdiction_date_or_document_facts_trigger_clarification",
                "urgent_or_high_stakes_questions_trigger_safe_routing",
            ],
            "copyright_and_privacy_controls": {
                "student_answers_used_as_question_templates": False,
                "source_wording_reproduced": False,
                "personal_identifiers_in_output": False,
                "absolute_source_paths_in_output": False,
            },
        }
    )


def _build_source_scope_mapping() -> dict[str, Any]:
    return _sealed(
        {
            "schema": "legalbot.v111.phase2b.source-scope-mapping-draft.v1",
            "status": "NON_AUTHORIZING_SOURCE_SCOPE_MAP",
            "included_topic_ids": sorted(TOPICS),
            "supporting_material_mappings": [
                {
                    "source_alias": "assessment-guidance",
                    "treatment": "STYLE_AND_CITATION_GUIDANCE_ONLY",
                },
                {
                    "source_alias": "official-legislation-library",
                    "treatment": "FUTURE_OFFICIAL_RESEARCH_POOL_NOT_A_TOPIC",
                },
                {
                    "source_alias": "pensions-specialist-and-revision-folders",
                    "treatment": "MERGED_INTO_PENSIONS_LAW",
                },
                {
                    "source_alias": "year-two-course-and-exam-containers",
                    "treatment": "DISTRIBUTED_TO_NAMED_SUBJECT_TOPICS",
                },
                {
                    "source_alias": "year-three-exam-and-feedback-container",
                    "treatment": "STYLE_OR_FEEDBACK_ONLY_NO_STUDENT_ANSWER_USE",
                },
                {
                    "source_alias": "exam-archive",
                    "treatment": "NOT_USED_AS_AN_INSTRUCTION_OR_STUDENT_ANSWER_SOURCE",
                },
            ],
            "no_topic_created": [
                {
                    "source_alias": "administrative-law-empty-container",
                    "reason": "NO_SUBSTANTIVE_FILES_PRESENT_AT_DRAFTING",
                },
                {
                    "source_alias": "wills-and-estates-empty-container",
                    "reason": "NO_SUBSTANTIVE_FILES_PRESENT_AT_DRAFTING",
                },
                {
                    "source_alias": "year-three-law-empty-container",
                    "reason": "NO_SUBSTANTIVE_FILES_PRESENT_AT_DRAFTING",
                },
            ],
            "student_answers_used": False,
            "legal_authority_admitted": False,
            "phase2b_authorized": False,
        },
        field="scope_mapping_content_sha256",
    )


def _question_records(topic_id: str, topic: dict[str, Any]) -> list[dict[str, Any]]:
    counters: Counter[str] = Counter()
    records: list[dict[str, Any]] = []
    for ordinal, item in enumerate(topic["questions"], start=1):
        kind = str(item["question_type"])
        counters[kind] += 1
        prefix = {"ESSAY": "e", "PROBLEM_BASED": "p", "GENERAL_ENQUIRY": "g"}[kind]
        payload = {
            "schema": QUESTION_SCHEMA,
            "question_id": f"{topic_id}:{prefix}{counters[kind]:02d}",
            "ordinal_within_topic": ordinal,
            "topic_id": topic_id,
            "question_type": kind,
            "difficulty": item["difficulty"],
            "prompt": item["prompt"],
            "issue_tags": item["issue_tags"],
            "clarification_targets": item["clarification_targets"],
            "lane": "DEVELOPMENT_REMEDIATION_DRAFT",
            "visible_to_implementation_team": True,
            "frozen_validation_eligible": False,
            "requires_issue_decomposition_before_execution": True,
            "requires_official_source_research": True,
            "legal_currentness_cutoff": None,
            "answer_model_authorized": False,
            "answer_model_run": False,
            "phase2b_authorized": False,
            "phase2b_run": False,
        }
        records.append(_sealed(payload))
    return records


def _markdown(topic: dict[str, Any], records: list[dict[str, Any]]) -> str:
    lines = [
        f"# {topic['display_name']} - Phase 2B Development Question Draft",
        "",
        "> Non-authorizing visible question bank. These questions may be used for future development/remediation planning only and are permanently ineligible for frozen unseen validation.",
        "",
        "## Coverage",
        "",
    ]
    lines.extend(f"- {item}" for item in topic["coverage"])
    labels = {
        "ESSAY": "Essay questions",
        "PROBLEM_BASED": "Problem-based questions",
        "GENERAL_ENQUIRY": "General enquiries",
    }
    for kind in QUESTION_TYPES:
        lines.extend(["", f"## {labels[kind]}", ""])
        for record in (row for row in records if row["question_type"] == kind):
            lines.extend(
                [
                    f"### {record['question_id']} - {record['difficulty']}",
                    "",
                    str(record["prompt"]),
                    "",
                    "Issue tags: " + ", ".join(record["issue_tags"]),
                    "",
                ]
            )
            if record["clarification_targets"]:
                lines.extend(
                    [
                        "Clarification targets: "
                        + ", ".join(record["clarification_targets"]),
                        "",
                    ]
                )
    return "\n".join(lines).rstrip() + "\n"


def _run_checklist(topic: dict[str, Any]) -> str:
    return (
        f"# Future Phase 2B checklist — {topic['display_name']}\n\n"
        "Status: planning scaffold only. Completing this checklist requires a later owner gate and does not itself authorize Phase 2B.\n\n"
        "1. Owner selects this topic for a named development wave and approves its exact scope.\n"
        "2. Freeze the legal-currentness cutoff and decompose all 18 visible questions into proposition and issue rows.\n"
        "3. Run retrieval/evidence inspection against the then-authorized non-ACTIVE candidate.\n"
        "4. Classify every row as supported, weak, missing, currentness-held, or representation-held.\n"
        "5. Research gaps using official sources only; quarantine and verify substantive source bytes.\n"
        "6. Produce an exact source/evidence delta packet. The owner, not an automated monitor, decides whether to approve it.\n"
        "7. After approval, perform the bounded source scan and one versioned non-ACTIVE index/embedding build.\n"
        "8. Re-attest retrieval, rerun the 18-question development evaluation, and preserve all unresolved holds.\n"
        "9. Seal the topic report with question-level evidence coverage and root-cause findings; do not promote or activate.\n"
        "10. Create any frozen unseen validation set separately and only behind its own later custody and disclosure gate.\n\n"
        "Operational rule: up to two topics may be grouped into one administrative wave, but each topic keeps an independent folder, manifest, evidence ledger, result and pass/fail decision.\n"
    )


def _write_json(path: Path, value: Any) -> None:
    path.write_bytes(_canonical_json(value))


def _assert_generated_safety(root: Path) -> None:
    forbidden_patterns = (
        re.compile(rb"/Users/", re.IGNORECASE),
        re.compile(rb"hltsang", re.IGNORECASE),
        re.compile(rb"\bAgnes\b", re.IGNORECASE),
        re.compile(rb"\bZ\d{6,}\b", re.IGNORECASE),
    )
    seen_prompts: set[str] = set()
    for path in root.rglob("*"):
        if not path.is_file() or path.name == "SHA256SUMS.txt":
            continue
        raw = path.read_bytes()
        for pattern in forbidden_patterns:
            if pattern.search(raw):
                raise ValueError(f"private identifier or path leaked into {path.name}")
        if path.name == "QUESTION-SET.jsonl":
            for line in raw.decode("utf-8").splitlines():
                record = json.loads(line)
                normalized = re.sub(r"\W+", " ", record["prompt"].casefold()).strip()
                if normalized in seen_prompts:
                    raise ValueError("duplicate question prompt")
                seen_prompts.add(normalized)
                if (
                    record["frozen_validation_eligible"] is not False
                    or record["answer_model_authorized"] is not False
                    or record["phase2b_authorized"] is not False
                ):
                    raise ValueError("question draft became authorizing")
    if len(seen_prompts) != len(TOPICS) * 18:
        raise ValueError("question count changed")


def build() -> Path:
    if OUTPUT_ROOT.exists():
        raise FileExistsError(f"question-bank draft already exists: {RUN_NAME}")
    OUTPUT_PARENT.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{RUN_NAME}.staging-", dir=OUTPUT_PARENT))
    try:
        style_profile = _build_style_profile()
        _write_json(staging / "STYLE-PROFILE.json", style_profile)
        source_scope_mapping = _build_source_scope_mapping()
        _write_json(staging / "SOURCE-SCOPE-MAPPING.json", source_scope_mapping)
        topic_registry: list[dict[str, Any]] = []
        for topic_id in sorted(TOPICS):
            topic = TOPICS[topic_id]
            records = _question_records(topic_id, topic)
            topic_dir = staging / "topics" / topic_id
            topic_dir.mkdir(parents=True)
            jsonl = b"".join(_canonical_json(record) for record in records)
            (topic_dir / "QUESTION-SET.jsonl").write_bytes(jsonl)
            (topic_dir / "QUESTION-SET.md").write_text(
                _markdown(topic, records), encoding="utf-8"
            )
            (topic_dir / "FUTURE-RUN-CHECKLIST.md").write_text(
                _run_checklist(topic), encoding="utf-8"
            )
            type_counts = Counter(record["question_type"] for record in records)
            difficulty_counts = Counter(record["difficulty"] for record in records)
            topic_manifest = _sealed(
                {
                    "schema": TOPIC_SCHEMA,
                    "status": "DEVELOPMENT_QUESTION_DRAFT_ONLY",
                    "topic_id": topic_id,
                    "display_name": topic["display_name"],
                    "source_scope_aliases": topic["source_scope"],
                    "coverage": topic["coverage"],
                    "question_count": len(records),
                    "question_type_counts": dict(sorted(type_counts.items())),
                    "difficulty_counts": dict(sorted(difficulty_counts.items())),
                    "question_set_jsonl_sha256": _sha256_bytes(jsonl),
                    "question_set_markdown_sha256": _sha256_file(
                        topic_dir / "QUESTION-SET.md"
                    ),
                    "frozen_validation_set_created": False,
                    "source_admission_authorized": False,
                    "source_admitted": False,
                    "retrieval_run": False,
                    "answer_model_run": False,
                    "phase2b_authorized": False,
                    "phase2b_run": False,
                },
                field="topic_content_sha256",
            )
            _write_json(topic_dir / "TOPIC-MANIFEST.json", topic_manifest)
            topic_registry.append(
                {
                    "topic_id": topic_id,
                    "display_name": topic["display_name"],
                    "question_count": len(records),
                    "topic_content_sha256": topic_manifest["topic_content_sha256"],
                }
            )

        registry = _sealed(
            {
                "schema": "legalbot.v111.phase2b.topic-registry-draft.v1",
                "status": "NON_AUTHORIZING_DEVELOPMENT_DRAFT",
                "topic_count": len(topic_registry),
                "question_count": sum(item["question_count"] for item in topic_registry),
                "topics": topic_registry,
                "recommended_execution_wave_size": 2,
                "frozen_validation_questions_deferred": True,
            },
            field="registry_content_sha256",
        )
        _write_json(staging / "TOPIC-REGISTRY.json", registry)
        readme = (
            f"# {RUN_NAME}\n\n"
            "This package contains synthetic, non-authorizing Phase 2B development question drafts. "
            "It does not start Phase 2B and does not authorize source admission, retrieval, an answer-model run, qualification, promotion, or live use.\n\n"
            f"- Topics: {len(topic_registry)}\n"
            f"- Questions: {registry['question_count']}\n"
            "- Per topic: 6 essays, 6 problem-based questions, and 6 general enquiries\n"
            "- Academic difficulty: 2 school-comparable, 2 harder, and 2 even-harder questions per academic type\n"
            "- General enquiries: 4 everyday, 1 multi-issue, and 1 boundary-or-urgent question per topic\n"
            "- Frozen unseen validation: deliberately not created\n\n"
            "Each topic has its own folder, manifest and future-run checklist. Up to two topics may share one administrative wave, but their evidence and decisions remain independent. Each topic must be selected by the owner before a future development wave. At execution time, every question must be decomposed into issue rows, researched against official sources, bound to a currentness cutoff, and processed through the applicable owner gates.\n"
        )
        (staging / "README.md").write_text(readme, encoding="utf-8")
        package = _sealed(
            {
                "schema": PACKAGE_SCHEMA,
                "status": "QUESTION_BANK_DRAFT_READY_NOT_PHASE2B",
                "run_name": RUN_NAME,
                "revision": 2,
                "supersedes_run_name": "LegalBot-Phase2B-2026-08-28-question-bank-draft-r1",
                "revision_reason": "ADDED_PREVIOUSLY_OMITTED_BUSINESS_AND_COMPANY_LAW_TOPIC",
                "style_profile_content_sha256": style_profile["record_content_sha256"],
                "source_scope_mapping_content_sha256": source_scope_mapping[
                    "scope_mapping_content_sha256"
                ],
                "topic_registry_content_sha256": registry["registry_content_sha256"],
                "topic_count": len(topic_registry),
                "question_count": registry["question_count"],
                "development_question_count": registry["question_count"],
                "frozen_validation_question_count": 0,
                "owner_topic_selection_required": True,
                "owner_phase2b_gate_required": True,
                "source_admission_authorized": False,
                "source_admitted": False,
                "source_scan_run": False,
                "index_built": False,
                "embedding_run": False,
                "retrieval_run": False,
                "answer_model_authorized": False,
                "answer_model_run": False,
                "phase2b_authorized": False,
                "phase2b_run": False,
                "development30_authorized": False,
                "validation30_authorized": False,
                "promotion_authorized": False,
                "active_pointer_written": False,
                "previous_pointer_written": False,
                "live_activation_authorized": False,
                "live_activation_run": False,
            },
            field="package_content_sha256",
        )
        _write_json(staging / "PACKAGE-MANIFEST.json", package)
        _assert_generated_safety(staging)
        checksum_lines = []
        for path in sorted(item for item in staging.rglob("*") if item.is_file()):
            rel = path.relative_to(staging).as_posix()
            checksum_lines.append(f"{_sha256_file(path)}  {rel}")
        (staging / "SHA256SUMS.txt").write_text(
            "\n".join(checksum_lines) + "\n", encoding="utf-8"
        )
        os.replace(staging, OUTPUT_ROOT)
    except Exception:
        if staging.exists() and staging.parent == OUTPUT_PARENT:
            shutil.rmtree(staging)
        raise
    return OUTPUT_ROOT


def main() -> None:
    output = build()
    print(output)


if __name__ == "__main__":
    main()
