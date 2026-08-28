from __future__ import annotations

import re

from ..types import TaskType

CLASSIFIER_VERSION = "legalbot-subject-classifier-v3"

SUBJECT_MARKERS: dict[str, tuple[str, ...]] = {
    # Composite labels are deliberate retrieval families, not new physical
    # lanes.  The retrieval service expands them to the approved catalogue
    # subjects.  Requiring several distinctive phrases means a broad legal
    # question can be recognised without forcing every individual section
    # through one narrow filter.
    "multi-area artificial intelligence litigation": (
        "ai platform",
        "risk scores",
        "customer-uploaded documents",
        "systematically inaccurate information",
        "near-human professional accuracy",
        "overall litigation strategy",
    ),
    "corporate fraud regulation and litigation": (
        "internal whistleblower",
        "paid bribes",
        "financial sanctions",
        "internal investigation",
        "regulatory cooperation",
        "preservation of evidence",
    ),
    "land trusts family property and insolvency": (
        "actual occupation",
        "mortgage priority",
        "family occupation",
        "transactions defrauding creditors",
        "resulting and constructive trusts",
    ),
    "construction and commercial": (
        "design and construct",
        "extensions of time",
        "liquidated damages",
        "performance bond",
        "adjudication",
        "subcontractor",
    ),
    "insolvency and corporate transactions": (
        "transactions at an undervalue",
        "floating charge",
        "wrongful and fraudulent trading",
        "retention of title",
        "creditor priorities",
        "misfeasance",
    ),
    "legal ethics and artificial intelligence": (
        "generative ai by lawyers",
        "duties to clients",
        "duties to the court",
        "verification of authorities",
        "legal professional privilege",
        "misleading submissions",
        "responsibility for ai-generated work",
    ),
    "environmental and climate": (
        "climate litigation",
        "government climate policies",
        "scientific uncertainty",
        "intergenerational interests",
        "constitutional limits of judicial intervention",
    ),
    "public procurement and administrative": (
        "procurement obligations",
        "evaluation panel",
        "scoring criterion",
        "operational contract",
        "political criticism",
    ),
    "banking fraud and restitution": (
        "payment authority",
        "unjust enrichment",
        "change of position",
        "recipient banks",
        "freezing relief",
        "tracing",
    ),
    "data protection and privacy": (
        "special-category data",
        "automated decisions",
        "breach notification",
        "access rights",
        "profiling",
        "commercially confidential",
    ),
    "crypto exchange collapse": (
        "cryptocurrency exchange",
        "digital assets are held one-to-one",
        "stablecoin",
        "digital wallets",
        "cryptoassets",
        "foreign insolvency proceedings",
    ),
    "energy infrastructure and project finance": (
        "offshore wind project",
        "project finance",
        "grid connection",
        "lender step-in rights",
        "direct agreements",
        "project-rescue strategy",
    ),
    "pensions employment and corporate restructuring": (
        "defined-benefit pension scheme",
        "pension funding",
        "regulatory anti-avoidance powers",
        "tupe",
        "collective redundancy",
        "pension protection",
    ),
    "leasehold and building safety": (
        "long leases",
        "service charge",
        "cladding replacement",
        "building-safety law",
        "remediation liability",
        "forfeiture",
    ),
    "privacy media and confidential information": (
        "misuse of private information",
        "breach of confidence",
        "source protection",
        "covert recordings",
        "urgent injunction",
        "freedom of expression",
    ),
    "cross-border civil litigation": (
        "permission to serve proceedings abroad",
        "worldwide freezing order",
        "anti-suit injunction",
        "recognition and enforcement",
        "proper forum",
        "jurisdiction agreements",
    ),
    "international arbitration": (
        "arbitration agreement",
        "london-seated arbitration",
        "competence-competence",
        "separability",
        "challenges to awards",
        "non-signatories",
    ),
    "financial services investment mis-selling": (
        "investment mis-selling",
        "authorised financial adviser",
        "leveraged structured products",
        "suitability",
        "disclosure of commission",
        "compensation routes",
    ),
    "consumer credit and guarantees": (
        "personal guarantee",
        "unfair relationships",
        "independent legal advice",
        "default interest",
        "security documents",
        "regulated credit",
    ),
    "sale of goods and retention of title": (
        "retention of title",
        "passing of property and risk",
        "accession",
        "transformation",
        "unregistered charge",
        "innocent buyer",
    ),
    "agency and commercial contracts": (
        "actual authority",
        "apparent authority",
        "warranty of authority",
        "previous dealings",
        "ratification",
    ),
    "occupiers liability": (
        "occupiers’ liability",
        "occupiers' liability",
        "lawful visitors",
        "trespassers",
        "independent contractors",
        "warning barrier",
    ),
    "residential tenancies and housing": (
        "residential tenancy",
        "fitness for human habitation",
        "deposit protection",
        "retaliatory action",
        "rent withholding",
        "possession",
    ),
    "commercial insurance": (
        "fair presentation of risk",
        "business-interruption insurance",
        "commercial insurance disputes",
        "policy language",
        "conditions precedent",
        "fraudulent claims",
        "proportionate remedies",
        "broker liability",
        "non-disclosure",
    ),
    "partnership and llp": (
        "limited liability partnership",
        "ordinary partnerships",
        "member liability",
        "former members",
        "holding out",
    ),
    "product liability": (
        "product liability",
        "meaning of defect",
        "development risks",
        "component producers",
        "digital products",
    ),
    "planning and judicial review": (
        "planning permission",
        "planning committee",
        "environmental assessment",
        "apparent bias",
        "public consultation",
    ),
    "immigration asylum and human rights": (
        "refugee status",
        "internal relocation",
        "asylum",
        "trafficking",
        "home office",
    ),
    "legal professional privilege": (
        "legal-advice privilege",
        "litigation privilege",
        "dominant purpose",
        "corporate client",
        "inadvertent disclosure",
    ),
    "charity": (
        "charitable purposes",
        "public benefit",
        "political purposes",
        "charitable neutrality",
        "restricted donations",
    ),
    "education": (
        "university",
        "disciplinary panel",
        "academic misconduct",
        "external review",
        "generative ai to write",
    ),
    "cybercrime": (
        "computer misuse act",
        "unauthorised access",
        "ethical hacking",
        "ransomware",
        "security research",
    ),
    "shipping and carriage of goods": (
        "bill of lading",
        "seaworthiness",
        "deck cargo",
        "carrier",
        "charterer",
        "deviation",
    ),
    "sports law and arbitration": (
        "sports arbitration",
        "sporting rules",
        "doping proceedings",
        "sporting autonomy",
        "selection disputes",
    ),
    "surveillance and national security": (
        "state surveillance",
        "bulk interception",
        "equipment interference",
        "national-security claims",
        "closed material",
    ),
    "tax and professional advice": (
        "hmrc",
        "corporate residence",
        "employment income into capital gains",
        "anti-avoidance rules",
        "transfer pricing",
    ),
    "collective redress": (
        "group litigation orders",
        "representative proceedings",
        "collective proceedings",
        "opt-in and opt-out",
        "mass claims",
        "litigation funding",
    ),
    "defamation": (
        "defamation act 2013",
        "serious harm",
        "corporate claimants",
        "website operators",
        "strategic litigation",
    ),
    "criminal complicity": (
        "secondary participation",
        "parasitic accessory liability",
        "intention to assist or encourage",
        "spontaneous group violence",
        "mere presence or association",
    ),
    "consumer": (
        "consumer rights",
        "consumer law",
        "satisfactory quality",
        "fitness for purpose",
        "right to reject",
    ),
    "professional negligence": (
        "professional negligence",
        "solicitor",
        "scope of duty",
        "loss of a chance",
    ),
    "criminal evidence": (
        "criminal evidence",
        "improperly obtained evidence",
        "confessions",
        "oppression",
        "hearsay",
    ),
    "company": (
        "company law",
        "director's duty",
        "directors' duties",
        "derivative claim",
        "unfair prejudice",
        "secret profit",
    ),
    "family": (
        "family law",
        "matrimonial",
        "financial provision",
        "non-matrimonial",
        "children act",
    ),
    "public and constitutional": (
        "public law",
        "constitutional law",
        "judicial review",
        "ouster clause",
        "parliamentary sovereignty",
    ),
    "human rights": (
        "human rights act",
        "european court of human rights",
        "declaration of incompatibility",
        "positive obligation",
    ),
    "civil litigation": (
        "civil litigation",
        "overriding objective",
        "relief from sanctions",
        "part 36",
        "summary judgment",
    ),
    "intellectual property": (
        "intellectual property",
        "copyright",
        "substantial copying",
        "computer program",
        "training material",
    ),
    "financial services": (
        "financial services",
        "financial services and markets act",
        "fca",
        "pra",
        "capital requirements regulation",
    ),
    "mediation and adr": (
        "mediation",
        "alternative dispute resolution",
        "singapore convention",
        "mediated settlement",
    ),
    "wills and succession": (
        "wills and succession",
        "testamentary capacity",
        "knowledge and approval",
        "undue influence",
        "intestacy",
    ),
    "competition": ("competition act", "article 101", "article 102", "cartel", "dominance"),
    "data protection": ("uk gdpr", "gdpr", "data protection", "personal data"),
    "private international law": ("conflict of laws", "choice of law", "jurisdiction clause"),
    "pensions": ("pension", "trustee covenant"),
    "medical law": (
        "medical negligence",
        "informed consent",
        "mental capacity",
        "capacity assessment",
        "bolam",
    ),
    "trusts": ("trust", "trustee", "beneficiary", "three certainties"),
    "land": ("land registration", "easement", "lease", "proprietary estoppel"),
    "criminal": ("criminal", "mens rea", "actus reus", "homicide"),
    "eu": ("eu law", "tfeu", "direct effect", "free movement"),
    "commercial": ("sale of goods", "commercial", "agency", "secured transaction"),
    "contract": ("contract", "consideration", "misrepresentation", "breach"),
    "tort": (
        "tort",
        "negligence",
        "duty of care",
        "duties of care",
        "assumption of responsibility",
        "pure economic loss",
        "omissions",
        "nuisance",
    ),
    "employment": (
        "employment",
        "worker",
        "unfair dismissal",
        "redundancy",
        "discrimination",
        "reasonable adjustments",
        "victimisation",
    ),
}

# A single phrase such as ``tracing`` or ``risk scores`` is not enough to
# classify a question as a broad composite family.  Composite labels expand
# to several catalogue subjects, so require corroborating signals and retain
# broad per-section fallback when the signature is incomplete.
COMPOSITE_SUBJECT_MIN_MATCHES: dict[str, int] = {
    "multi-area artificial intelligence litigation": 2,
    "corporate fraud regulation and litigation": 2,
    "land trusts family property and insolvency": 2,
    "construction and commercial": 2,
    "insolvency and corporate transactions": 2,
    "legal ethics and artificial intelligence": 2,
    "environmental and climate": 2,
    "public procurement and administrative": 2,
    "banking fraud and restitution": 2,
    "data protection and privacy": 2,
    "crypto exchange collapse": 2,
    "energy infrastructure and project finance": 2,
    "pensions employment and corporate restructuring": 2,
    "leasehold and building safety": 2,
    "privacy media and confidential information": 2,
    "cross-border civil litigation": 2,
    "international arbitration": 2,
    "financial services investment mis-selling": 2,
    "consumer credit and guarantees": 2,
    "sale of goods and retention of title": 2,
    "agency and commercial contracts": 2,
    "occupiers liability": 2,
    "residential tenancies and housing": 2,
    "commercial insurance": 2,
    "partnership and llp": 2,
    "product liability": 2,
    "planning and judicial review": 2,
    "immigration asylum and human rights": 2,
    "legal professional privilege": 2,
    "charity": 2,
    "education": 2,
    "cybercrime": 2,
    "shipping and carriage of goods": 2,
    "sports law and arbitration": 2,
    "surveillance and national security": 2,
    "tax and professional advice": 2,
    "collective redress": 2,
    "defamation": 2,
    "criminal complicity": 2,
}


def _marker_matches(question: str, marker: str) -> bool:
    """Match a word or phrase without accidental substring collisions."""

    escaped = re.escape(marker).replace(r"\ ", r"\s+")
    return re.search(rf"(?<![\w]){escaped}(?![\w])", question) is not None


def _subject_scores(question: str) -> list[tuple[int, str]]:
    lowered = question.casefold()
    output: list[tuple[int, str]] = []
    for subject, markers in SUBJECT_MARKERS.items():
        score = sum(_marker_matches(lowered, marker.casefold()) for marker in markers)
        minimum = COMPOSITE_SUBJECT_MIN_MATCHES.get(subject, 1)
        output.append((score if score >= minimum else 0, subject))
    return output


def classify_task(question: str, requested: TaskType) -> TaskType:
    if requested != TaskType.AUTO:
        return requested
    lowered = question.casefold()
    if re.search(r"\b(advise|liability|remed(?:y|ies)|parties|scenario)\b", lowered):
        return TaskType.PROBLEM
    if re.search(r"\b(critically|evaluate|discuss|to what extent|essay)\b", lowered):
        return TaskType.ESSAY
    return TaskType.GENERAL


def classify_subject(question: str) -> str | None:
    scored = _subject_scores(question)
    score, subject = max(scored, default=(0, ""))
    return subject if score else None


def classify_subjects(question: str) -> tuple[str, ...]:
    """Return every safely recognised subject in deterministic score order.

    Long-form composite questions must not be collapsed to the single highest
    marker score before per-section retrieval.  The single-value helper above
    remains for backwards-compatible narrow routing.
    """

    scored = _subject_scores(question)
    return tuple(
        subject for score, subject in sorted(scored, key=lambda item: (-item[0], item[1])) if score
    )
