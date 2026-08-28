#!/usr/bin/env python3
"""Build a create-only remediation advisory for the 59-row NONE cohort.

The cohort label arose from 61 NONE components with empty authority lists.  A
full r3 topology check shows 63 NONE components in the same 59 rows: two more
components carry real statutory sources, but those sources are relevance-
insufficient for the case-specific conclusion.  The rows also contain 17
PARTIAL blockers.  This builder therefore dispositions all 80 r3 blockers
exactly once and records the 61/63 distinction instead of silently omitting the
two source-backed NONE components.

Every row already retains at least one FULL component in the sealed owner
packet.  The advisory never upgrades PARTIAL/NONE support.  It recommends
either exact exclusion from the legal-proposition set or replacement with a
strictly non-authoritative matter-information requirement.  It proposes no new
source, EvidenceSpan, fallback, execution, qualification, pointer write or
Phase-2B authority.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unicodedata
from collections import Counter
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from pypdf import PdfReader

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.apply_v111_phase2a_final_remediation import build_materialization_plan

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"

R3_PATH = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-prequalification-blockers-r3/PREQUALIFICATION-BLOCKER-REPORT.json"
)
WORKING_LEDGER_PATH = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-27-remediation-working-r1/"
    "PROPOSITION-RECONCILIATION-WORKING-LEDGER-361.json"
)
OWNER_PACKET_PATH = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-exact-remediation-owner-packet-r1/"
    "EXACT-REMEDIATION-OWNER-PACKET-361.json"
)
QUARANTINE_ROOT = REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-source-quarantine"
QUARANTINE_MANIFEST_PATH = QUARANTINE_ROOT / "QUARANTINE-MANIFEST.json"
CANDIDATE_MANIFEST_PATH = PROJECT_ROOT / (
    "data/indexes/builds/current-law-ew-full-fp16-v111-20260827-phase2a-a/"
    "approved-source-manifest.json"
)
EXECUTION_AUTHORITY_PATH = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-final-remediation-owner-approved-r1/"
    "PHASE2A-EXECUTION-AUTHORITY.json"
)
BASELINE_ADVISORY_PATH = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-146-row-superseding-remediation-advisory-r2/"
    "EXACT-146-ROW-SUPERSEDING-REMEDIATION-ADVISORY.json"
)
SUPERSEDED_R1_PATH = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-authorityless-cohort-59-remediation-advisory-r1/"
    "AUTHORITYLESS-COHORT-59-REMEDIATION-ADVISORY.json"
)

OUTPUT_ROOT = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-authorityless-cohort-59-remediation-advisory-r2"
)
ADVISORY_NAME = "AUTHORITYLESS-COHORT-59-REMEDIATION-ADVISORY.json"
PACKAGE_NAME = "PACKAGE-MANIFEST.json"
CHECKSUMS_NAME = "SHA256SUMS.txt"

R3_CONTENT_SHA256 = "5efc17b16adcae1ceb2ea1bbd7efcaba469ab0340c24b65c1e994132cb337980"
R3_FILE_SHA256 = "7cb044a4c9539162281e10ac41e5e0cb1f0cd846b0eb597a0443b0e67fb48899"
WORKING_LEDGER_CONTENT_SHA256 = "62d56c8b34d1fc964dca1a5920ee49b87499471c187dbe82aa58ebee191737ce"
WORKING_LEDGER_FILE_SHA256 = "bdc091b1a3b8de2febcbc14d86d8c88113ed112ca2bc28908eeb3e6d95ccc297"
OWNER_PACKET_CONTENT_SHA256 = "93ad9113af76896f0570a3666c446472af7587b7e3ff32b7464e670777ec6b6c"
OWNER_PACKET_FILE_SHA256 = "992770c04cb3e08de64bb98e80aa9801171d3e66e4b573b85919091a78b1db3b"
QUARANTINE_MANIFEST_CONTENT_SHA256 = (
    "b6d900b23232379a4d6c19d313f35c47e0758ce5e0bb6eb04008f9eba07a3819"
)
QUARANTINE_MANIFEST_FILE_SHA256 = "f482366a2ba0d9f636c56104d632767a8eadd6e9a9625d50ef5391a5f62995eb"
CANDIDATE_MANIFEST_CONTENT_SHA256 = (
    "b304ab1223987bf9b57d3e2560413b2f325c16213ae0071a45dface2e10dc206"
)
CANDIDATE_MANIFEST_FILE_SHA256 = "0bbb1edb169c84a26e5f1d42e367f9e2f83fcdd9c652a9061980652f15979b21"
EXECUTION_AUTHORITY_CONTENT_SHA256 = (
    "eb0eda2f34c8b261ea38fc9d697257cdd3bd6253c18c2d91355328c8cb78ef7b"
)
EXECUTION_AUTHORITY_FILE_SHA256 = "5171ce79007c68484f9854b5188bf7e7af8f880407b6fbad6e3f808d0c7630ad"
BASELINE_ADVISORY_CONTENT_SHA256 = (
    "6078e556e8ee3eb551bd48d310b2a89728e317dc8c240f22030799b54e595e1d"
)
BASELINE_ADVISORY_FILE_SHA256 = "81eebbe55d18d5257217d28760d136544523716adfb17746cd6cb34bceb27659"
MATERIALIZATION_PLAN_CONTENT_SHA256 = (
    "de7b8e8c0d5d4a6e1f99f0f338d623bb7e371222b8c0341b35515fe1d1567c7b"
)
SUPERSEDED_R1_CONTENT_SHA256 = "a3950fca2a66e623d08379955acd84c2cc0c61e71ce2af3fa4568f2a51161768"
SUPERSEDED_R1_FILE_SHA256 = "4d90676eae6ed0f312e5f72f8a9468b14ee392dbe36e4eb57484ba9e0ef5494a"

ROW_IDS = (
    "live30-q04:issue-01",
    "live30-q04:issue-06",
    "live30-q12:issue-05",
    "live30-q12:issue-06",
    "live30-q13:issue-01",
    "live30-q16:issue-06",
    "live30-q18:issue-08",
    "live30-q26:issue-01",
    "live30-q26:issue-08",
    "live30-q29:issue-05",
    "live30-q29:issue-07",
    "live30-q29:issue-09",
    "live30-q30:issue-02",
    "live30-q30:issue-08",
    "live30-q30:issue-11",
    "live30-q30:issue-12",
    "live30-q30:issue-14",
    "live30-q30:issue-15",
    "live60-q41:issue-02",
    "live60-q42:issue-02",
    "live60-q43:issue-04",
    "live60-q43:issue-06",
    "live60-q46:issue-01",
    "live60-q46:issue-03",
    "live60-q46:issue-04",
    "live60-q46:issue-09",
    "live60-q47:issue-01",
    "live60-q47:issue-06",
    "live60-q47:issue-09",
    "live60-q48:issue-08",
    "live60-q48:issue-10",
    "live60-q49:issue-08",
    "live60-q50:issue-04",
    "live60-q50:issue-07",
    "live60-q54:issue-10",
    "live60-q55:issue-09",
    "live60-q55:issue-10",
    "live60-q56:issue-04",
    "live60-q56:issue-06",
    "live60-q56:issue-09",
    "live60-q57:issue-01",
    "live60-q57:issue-04",
    "live60-q57:issue-05",
    "live60-q57:issue-07",
    "live60-q57:issue-09",
    "live60-q58:issue-06",
    "live60-q58:issue-10",
    "live60-q58:issue-12",
    "live60-q59:issue-18",
    "live60-q59:issue-20",
    "live60-q59:issue-21",
    "live60-q60:issue-08",
    "live60-q60:issue-16",
    "live60-q60:issue-18",
    "live60-q60:issue-23",
    "live60-q60:issue-27",
    "live60-q60:issue-28",
    "live60-q60:issue-29",
    "live60-q60:issue-31",
)
ROW_ID_SET_SHA256 = "45a35173be61cce0e472db89e979d9834125baa868bf96c78ae5e3f0fbb8f376"

# NONE components whose legal, policy or empirical content is removed without
# a replacement.  Every PARTIAL component is also removed, by deterministic
# rule, because relevance or incomplete support must never be upgraded.
EXCLUDE_NONE_KEYS = frozenset(
    {
        ("live30-q12:issue-05", 3),
        ("live30-q12:issue-06", 3),
        ("live30-q13:issue-01", 3),
        ("live30-q18:issue-08", 8),
        ("live60-q41:issue-02", 3),
        ("live60-q42:issue-02", 3),
        ("live60-q48:issue-08", 4),
        ("live60-q48:issue-10", 3),
        ("live60-q48:issue-10", 4),
        ("live60-q54:issue-10", 4),
        ("live60-q59:issue-20", 3),
        ("live60-q59:issue-21", 4),
    }
)

# These are operational intake requirements only.  They must never enter the
# legal-authority, EvidenceSpan or answer lanes.  The exact row/component key
# prevents a blanket or inferred reclassification.
MATTER_REQUIREMENTS: dict[tuple[str, int], str] = {
    ("live30-q04:issue-01", 2): (
        "Obtain authenticated medical and expert evidence establishing the time of "
        "death and whether the victim was alive when each alleged act occurred."
    ),
    ("live30-q04:issue-06", 2): (
        "Obtain authenticated medical and expert evidence attributing the fatal "
        "injury, fixing the time of death and identifying whether the victim was "
        "alive when Ben acted."
    ),
    ("live30-q16:issue-06", 3): (
        "Obtain the complete 2018 and 2025 testamentary documents, execution and "
        "revocation records, residuary provisions and surviving-relative facts."
    ),
    ("live30-q18:issue-08", 5): (
        "Obtain the complete bank-to-crypto transaction graph, wallet and key-control "
        "records, custody and exchange records, and evidence identifying every "
        "intermediary and recipient."
    ),
    ("live30-q18:issue-08", 7): (
        "Obtain the official title register, transfer and purchase-money records, "
        "mortgage records, recipient identity, value and notice evidence for the "
        "London property."
    ),
    ("live30-q26:issue-01", 3): (
        "Obtain the complete main contract, professional appointments, subcontract, "
        "technical scope, collateral warranties, third-party-rights terms, work "
        "records and claimed-loss evidence."
    ),
    ("live30-q26:issue-08", 3): (
        "Obtain the executed policy, exclusions, conditions and endorsements, the "
        "indemnification and payment record, and the insured's underlying claim, "
        "defence and recovery evidence."
    ),
    ("live30-q29:issue-05", 4): (
        "Obtain each disclosed document, its author and recipient, the legal notice "
        "or compulsion record, confidentiality terms, stated purpose and the exact "
        "scope and onward-use conditions of the disclosure."
    ),
    ("live30-q29:issue-07", 5): (
        "Identify each requesting authority and legal notice, the relevant "
        "jurisdictions, data subjects and data categories, transfer destinations, "
        "agreements, purposes and onward-use restrictions."
    ),
    ("live30-q29:issue-09", 3): (
        "Obtain every executed customer and finance agreement, governing-law clause, "
        "termination, default, acceleration, material-adverse-change, notice and cure "
        "term, and every notice, election, affirmation and loss record."
    ),
    ("live30-q30:issue-02", 1): (
        "Obtain claimant-specific contracts, representations, decision records, model "
        "outputs, party identities, dates, reliance, causation and loss evidence "
        "before any merits ranking is attempted."
    ),
    ("live30-q30:issue-08", 5): (
        "Classify each customer, identify the regulated activity, regulated person, "
        "decision-maker and outsourcing chain, and fix the date and rule set for each "
        "challenged decision."
    ),
    ("live30-q30:issue-11", 4): (
        "Obtain every contract, order form, service level, disclaimer, integration and "
        "non-reliance clause, sales presentation, recipient record and evidence of "
        "contemporaneous knowledge."
    ),
    ("live30-q30:issue-12", 4): (
        "Obtain the retainer, advice file, limitation calculation, review and warning "
        "records, the underlying claim file, causation and quantum evidence, and any "
        "contribution or mitigation material."
    ),
    ("live30-q30:issue-14", 4): (
        "Identify each item of information, its alleged confidential or private "
        "quality, the relevant contract or undertaking, every use and disclosure, "
        "claimant, recipient and asserted defence."
    ),
    ("live30-q30:issue-15", 3): (
        "Identify the exact benefit, statutory scheme, regulations, decision policy, "
        "suspension record, urgency basis, reasons, notice, representations and review "
        "or appeal documents."
    ),
    ("live60-q43:issue-04", 4): (
        "Obtain the agency appointment, assignment, novation, representation and "
        "reliance records, third-party-rights wording, party capacities and competent "
        "evidence of any relied-on Swiss law."
    ),
    ("live60-q43:issue-06", 3): (
        "Obtain the complete Italian-proceedings chronology and orders, the arbitration "
        "agreement and its temporal scope, the asserted jurisdictional basis and the "
        "dates needed to identify any transitional regime."
    ),
    ("live60-q46:issue-01", 3): (
        "Obtain the exact dated university offer, regulations, handbook, misconduct "
        "code, representations and documents said to apply those terms to Noah."
    ),
    ("live60-q46:issue-03", 4): (
        "Obtain the applicable hearing rules, the disputed allegations and evidence, "
        "the seriousness and possible consequences, each request to question a witness "
        "and the alternatives considered."
    ),
    ("live60-q46:issue-04", 1): (
        "Obtain the applicable institutional burden and standard wording, the complete "
        "detector report and methodology supplied to the decision-maker, and all other "
        "evidence used for the finding."
    ),
    ("live60-q46:issue-09", 1): (
        "Obtain the applicable internal-appeal rules, filing record, deadline, scope, "
        "decision and any provision addressing the appeal's effect."
    ),
    ("live60-q46:issue-09", 5): (
        "Identify each proposed claim, claimant and defendant, the decision or conduct "
        "challenged, relevant dates, requested remedy and any route already used."
    ),
    ("live60-q47:issue-01", 3): (
        "Obtain the executed loan, guarantee and charge, every amendment and notice, "
        "and the identity, status and capacity of each borrower, guarantor, lender and "
        "secured party."
    ),
    ("live60-q47:issue-06", 3): (
        "Obtain the solicitor's retainer, private-meeting and advice records, conflict "
        "analysis, information supplied by Hana and the written confirmation delivered "
        "to the bank."
    ),
    ("live60-q47:issue-09", 1): (
        "Obtain the executed default-interest and charge terms, the complete account, "
        "payment and default chronology, notices and a reproducible calculation of "
        "every claimed amount."
    ),
    ("live60-q49:issue-08", 6): (
        "Obtain the complete delay and voyage chronology, charterer instructions, "
        "compliance records, cargo-tranche damage evidence and the alleged causal route "
        "for each head of loss."
    ),
    ("live60-q50:issue-04", 5): (
        "Obtain the complete dated policy wording, the alleged attachment condition, "
        "event and compliance evidence, consumer status, contracting-out terms and the "
        "insurer's stated classification and consequence."
    ),
    ("live60-q50:issue-07", 3): (
        "Obtain the exact notice wording, required time and content, the notice given, "
        "the asserted consequence, and every insurer communication or act said to "
        "constitute waiver or demonstrate prejudice."
    ),
    ("live60-q55:issue-09", 3): (
        "Obtain the judgment's court, jurisdiction, date, proceeding date, finality, "
        "enforceability, amount, service and appeal record, the jurisdictional basis, "
        "identified Singapore assets and competent Singapore-law evidence."
    ),
    ("live60-q55:issue-10", 3): (
        "Identify the issued court and list, proposed defendants, governing-law and "
        "jurisdiction clauses, asset locations, data custodians and systems, privilege, "
        "retention, security and competent foreign-law evidence."
    ),
    ("live60-q56:issue-04", 3): (
        "Obtain the notice and authorisation, data categories, retention duration and "
        "purpose, review and renewal records, later-access records and the regulations "
        "and code invoked by the decision-maker."
    ),
    ("live60-q56:issue-06", 3): (
        "Obtain the communication, sender and recipient identities, client and lawyer "
        "roles, purpose, contemplated-litigation chronology, alleged iniquity, selector "
        "and handling records."
    ),
    ("live60-q56:issue-09", 3): (
        "Identify the exact surveillance power, issuer and reviewer, and obtain the "
        "authorisation, approval, urgency, renewal and modification records and the "
        "institutional review material relied upon."
    ),
    ("live60-q57:issue-01", 3): (
        "Fix each relevant tax year and obtain complete day-count, home, work, family "
        "and accommodation evidence, then identify the other jurisdiction and exact "
        "treaty said to apply for each period."
    ),
    ("live60-q57:issue-04", 3): (
        "Fix each accounting period and obtain incorporation records, board minutes, "
        "instructions, director evidence and locations of strategic decisions, then "
        "identify the foreign jurisdiction and exact treaty invoked."
    ),
    ("live60-q57:issue-05", 3): (
        "Obtain the controlled-party and participation records, IP ownership and "
        "valuation material, functions, assets, risks, contracts, payment terms, tax "
        "periods and enterprise-size information."
    ),
    ("live60-q57:issue-07", 4): (
        "Identify the arrangement, promoter and participants, alleged hallmarks, entity, "
        "jurisdiction, account and reporting regime, and obtain all relevant-period "
        "returns, notices, reference numbers and disclosures."
    ),
    ("live60-q57:issue-09", 3): (
        "Obtain the alleged document or return, tax-loss calculation, conduct, knowledge, "
        "concealment and adviser-instruction records, plus any exact charge, indictment "
        "or offence notice actually advanced."
    ),
    ("live60-q58:issue-06", 1): (
        "Obtain the support agreement, governing-law and change-in-law terms, baseline "
        "date, identified policy instrument, revenue model, causation evidence, notice, "
        "mitigation and claimed remedy."
    ),
    ("live60-q58:issue-10", 2): (
        "Obtain every direct agreement and protected contract, identify each third party, "
        "and extract the notice, cure, standstill, substitution, step-in, novation, "
        "termination and exclusion wording."
    ),
    ("live60-q58:issue-12", 2): (
        "Identify each fishing business and obtain its contracts, licences, quotas, "
        "proprietary or fishing-right records, physical-damage and reliance evidence, "
        "causation, quantified loss and the exact compensation regime invoked."
    ),
    ("live60-q59:issue-18", 4): (
        "Identify the affected market and conduct, regulator, respondent and operative "
        "scheme, and obtain the class, date, eligibility, causation, cap, deadline, "
        "acceptance, assignment, insolvency and parallel-proceeding records."
    ),
    ("live60-q60:issue-08", 3): (
        "Obtain every facility, security, custody, title-transfer, trust and collateral-"
        "control document, charged-asset definition, filing, wallet and key-control "
        "record, ownership evidence, insolvency dates and governing-law terms."
    ),
    ("live60-q60:issue-16", 3): (
        "Identify each token and instrument, venue, order and alleged price or volume "
        "effect, and obtain representations, reliance, accounting records, actor roles, "
        "mental-state and territorial evidence for each proposed route."
    ),
    ("live60-q60:issue-18", 3): (
        "Obtain the security architecture, vulnerability and notice chronology, board "
        "and penetration-test records, incident response, customer terms, regulated "
        "status, affected systems and data, and causal loss evidence."
    ),
    ("live60-q60:issue-23", 3): (
        "Obtain customer-asset ownership evidence, the complete wallet-to-fiat transfer "
        "chain, bank statements, conveyances, title and mortgage records, recipient "
        "identity, value, knowledge and dissipation evidence."
    ),
    ("live60-q60:issue-27", 3): (
        "Obtain every agency or regulator notice, warrant, interview request, restraint "
        "order and information request, identify each suspected person and power invoked, "
        "and fix the territorial and information-sharing facts."
    ),
    ("live60-q60:issue-28", 3): (
        "Obtain a document-level log of custodians, senders, recipients, client groups, "
        "instructions, purposes, anticipated proceedings, confidentiality, dissemination, "
        "alleged iniquity and every relevant foreign jurisdiction."
    ),
    ("live60-q60:issue-29", 3): (
        "Fix when proceedings or investigations were contemplated and obtain legal-hold "
        "notices, custodian, device and cloud records, retention settings, deletion logs, "
        "actor identities, recoverability, relevance and court or regulator notices."
    ),
    ("live60-q60:issue-31", 2): (
        "Obtain the live asset and ownership map, wallet and fiat control, property title, "
        "dissipation and limitation evidence, claim and defendant map, insurance, funding, "
        "security, foreign orders, restructuring and distribution proposals."
    ),
}

NO_EXECUTION_FLAGS = {
    "owner_approved": False,
    "owner_adoption_recorded": False,
    "owner_decision_application_authorized": False,
    "owner_decisions_applied": False,
    "owner_outcomes_applied": False,
    "source_delta_decisions_applied": False,
    "safe_fallback_decision_applied": False,
    "evaluation_contract_mutated": False,
    "source_admission_authorized": False,
    "source_admitted": False,
    "complete_source_scan_authorized": False,
    "source_scan_run": False,
    "successor_build_authorized": False,
    "successor_build_run": False,
    "index_build_authorized": False,
    "index_built": False,
    "embedding_authorized": False,
    "embedding_run": False,
    "automatic_indexing": False,
    "automatic_embedding": False,
    "candidate_mutated": False,
    "catalogue_mutated": False,
    "qualification_authorized": False,
    "qualification_run": False,
    "retrieval_reattestation_authorized": False,
    "retrieval_reattestation_run": False,
    "all585_qualification_authorized": False,
    "all585_qualification_run": False,
    "technical_qualification_assigned": False,
    "answer_model_authorized": False,
    "answer_model_run": False,
    "answer_eligible": False,
    "answer_release_authorized": False,
    "answer_release_run": False,
    "answer_released": False,
    "phase2b_authorized": False,
    "phase2b_run": False,
    "development30_authorized": False,
    "development30_run": False,
    "owner_certification60_authorized": False,
    "owner_certification60_run": False,
    "o04_authorized": False,
    "o04_run": False,
    "validation30_authorized": False,
    "validation30_run": False,
    "validation30_unsealed": False,
    "promotion_authorized": False,
    "promotion_run": False,
    "active_pointer_write_authorized": False,
    "active_pointer_written": False,
    "previous_pointer_write_authorized": False,
    "previous_pointer_written": False,
    "live_activation_authorized": False,
    "live_activation_run": False,
    "training_export_authorized": False,
    "training_export_run": False,
}


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


def _load(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"input_not_regular:{path.name}")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"input_not_object:{path.name}")
    return value


def _verify_seal(value: dict[str, Any], field: str, expected: str) -> None:
    material = dict(value)
    observed = str(material.pop(field, ""))
    if observed != expected or _sha256(_canonical_json(material)) != observed:
        raise ValueError(f"invalid_content_seal:{field}")


def _component_key(row_id: str, ordinal: int) -> str:
    return f"{row_id}#component-{ordinal}"


def _normalise_text(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).split())


def _representation_text(path: Path) -> tuple[str, str]:
    raw = path.read_bytes()
    suffix = path.suffix.lower()
    if suffix == ".xml":
        root = ElementTree.fromstring(raw)
        text = "".join(root.itertext())
        mode = "XML_ITERATION_TEXT"
    elif suffix in {".html", ".htm"}:
        text = raw.decode("utf-8", errors="strict")
        mode = "UTF8_OFFICIAL_HTML"
    elif suffix == ".pdf":
        reader = PdfReader(path)
        if not reader.pages:
            raise ValueError(f"empty_pdf:{path.name}")
        text = "\n".join(page.extract_text() or "" for page in reader.pages)
        mode = "PDF_TEXT_EXTRACTION"
    else:
        text = raw.decode("utf-8", errors="strict")
        mode = "UTF8_CANONICAL_MARKDOWN"
    if len(_normalise_text(text)) < 40:
        raise ValueError(f"empty_representation_text:{path.name}")
    return text, mode


def _source_bindings(
    r3_rows: list[dict[str, Any]],
    quarantine: dict[str, Any],
    candidate: dict[str, Any],
    plan: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    authority_metadata: dict[str, dict[str, Any]] = {}
    for row in r3_rows:
        for component in row["blocking_components"]:
            for authority in component["authorities"]:
                identity = authority["canonical_authority_identity_id"]
                existing = authority_metadata.setdefault(
                    identity,
                    {
                        "authority_identity_id": identity,
                        "citations": set(),
                        "official_urls": set(),
                        "original_exact_locators": set(),
                    },
                )
                existing["citations"].add(authority["citation"])
                existing["official_urls"].add(authority["official_url"])
                existing["original_exact_locators"].update(authority["exact_locators"])

    quarantine_records = {
        record["authority_identity_id"]: record
        for record in quarantine["records"]
        if record.get("selected_for_proposed_admission") is True
    }
    candidate_sources = {source["authority_identity_id"]: source for source in candidate["sources"]}
    plan_records = {
        record["authority_identity_id"]: record
        for record in plan["representations"]
        if record["index_eligible"] is True
    }

    bindings: list[dict[str, Any]] = []
    for identity in sorted(authority_metadata):
        metadata = authority_metadata[identity]
        if identity in plan_records:
            plan_record = plan_records[identity]
            quarantine_record = quarantine_records.get(identity)
            if quarantine_record is None:
                raise ValueError(f"planned_source_missing_quarantine_record:{identity}")
            member = quarantine_record["quarantine_member"]
            path = QUARANTINE_ROOT / member
            if (
                path.is_symlink()
                or not path.is_file()
                or path.parent.resolve() != QUARANTINE_ROOT.resolve()
                or _file_sha256(path) != quarantine_record["raw_sha256"]
                or plan_record["content_sha256"] != quarantine_record["raw_sha256"]
                or plan_record["input_member"] != member
            ):
                raise ValueError(f"quarantine_source_byte_mismatch:{identity}")
            _, mode = _representation_text(path)
            source = {
                "source_origin": "EXACT_OWNER_ADOPTED_MATERIALIZATION_PLAN",
                "proposed_source_version_id": quarantine_record["proposed_source_version_id"],
                "representation_member": member,
                "representation_file_sha256": quarantine_record["raw_sha256"],
                "canonical_content_sha256": quarantine_record.get("canonical_content_sha256"),
                "materialization_record_content_sha256": plan_record["record_content_sha256"],
                "materialization_target_relative_path": plan_record["target_relative_path"],
            }
        elif identity in candidate_sources:
            candidate_source = candidate_sources[identity]
            relative = Path(candidate_source["canonical_markdown_path"])
            path = PROJECT_ROOT / relative
            vault_root = (PROJECT_ROOT / "data/vault/objects/sha256").resolve()
            if (
                path.is_symlink()
                or not path.is_file()
                or vault_root not in path.resolve().parents
                or _file_sha256(path) != path.name
            ):
                raise ValueError(f"candidate_source_byte_mismatch:{identity}")
            _, mode = _representation_text(path)
            source = {
                "source_origin": "SEALED_251_SOURCE_CANDIDATE",
                "source_version_id": candidate_source["source_version_id"],
                "canonical_object_sha256": path.name,
                "catalogue_content_sha256": candidate_source["content_sha256"],
                "candidate_identity_verified": candidate_source["identity_verified"],
            }
        else:
            raise ValueError(f"source_identity_not_resolved:{identity}")

        bindings.append(
            _seal(
                {
                    "schema": (
                        "legalbot.v111.phase2a.authorityless-cohort-inspected-source-binding.v1"
                    ),
                    "authority_identity_id": identity,
                    "citations": sorted(metadata["citations"]),
                    "official_urls": sorted(metadata["official_urls"]),
                    "original_exact_locators": sorted(metadata["original_exact_locators"]),
                    "representation_parse_mode": mode,
                    "representation_byte_hash_verified": True,
                    "inspection_only": True,
                    "new_source_proposed": False,
                    "new_evidence_span_proposed": False,
                    "support_fit_not_upgraded": True,
                    **source,
                },
                "record_content_sha256",
            )
        )
    bindings.sort(key=lambda item: item["authority_identity_id"])
    return bindings, {item["authority_identity_id"]: item for item in bindings}


def build_advisory() -> dict[str, Any]:
    if _sha256(("\n".join(ROW_IDS) + "\n").encode()) != ROW_ID_SET_SHA256:
        raise ValueError("row_id_set_digest_invalid")

    input_files = (
        (R3_PATH, R3_FILE_SHA256),
        (WORKING_LEDGER_PATH, WORKING_LEDGER_FILE_SHA256),
        (OWNER_PACKET_PATH, OWNER_PACKET_FILE_SHA256),
        (QUARANTINE_MANIFEST_PATH, QUARANTINE_MANIFEST_FILE_SHA256),
        (CANDIDATE_MANIFEST_PATH, CANDIDATE_MANIFEST_FILE_SHA256),
        (EXECUTION_AUTHORITY_PATH, EXECUTION_AUTHORITY_FILE_SHA256),
        (BASELINE_ADVISORY_PATH, BASELINE_ADVISORY_FILE_SHA256),
        (SUPERSEDED_R1_PATH, SUPERSEDED_R1_FILE_SHA256),
    )
    for path, expected in input_files:
        if _file_sha256(path) != expected:
            raise ValueError(f"input_file_digest_invalid:{path.name}")

    r3 = _load(R3_PATH)
    ledger = _load(WORKING_LEDGER_PATH)
    owner_packet = _load(OWNER_PACKET_PATH)
    quarantine = _load(QUARANTINE_MANIFEST_PATH)
    candidate = _load(CANDIDATE_MANIFEST_PATH)
    execution_authority = _load(EXECUTION_AUTHORITY_PATH)
    baseline = _load(BASELINE_ADVISORY_PATH)
    superseded_r1 = _load(SUPERSEDED_R1_PATH)
    _verify_seal(r3, "artifact_content_sha256", R3_CONTENT_SHA256)
    _verify_seal(ledger, "artifact_content_sha256", WORKING_LEDGER_CONTENT_SHA256)
    _verify_seal(owner_packet, "artifact_content_sha256", OWNER_PACKET_CONTENT_SHA256)
    _verify_seal(quarantine, "manifest_content_sha256", QUARANTINE_MANIFEST_CONTENT_SHA256)
    _verify_seal(
        execution_authority,
        "artifact_content_sha256",
        EXECUTION_AUTHORITY_CONTENT_SHA256,
    )
    _verify_seal(baseline, "artifact_content_sha256", BASELINE_ADVISORY_CONTENT_SHA256)
    _verify_seal(superseded_r1, "artifact_content_sha256", SUPERSEDED_R1_CONTENT_SHA256)
    if (
        candidate.get("manifest_sha256") != CANDIDATE_MANIFEST_CONTENT_SHA256
        or candidate.get("source_count") != 251
    ):
        raise ValueError("candidate_manifest_identity_invalid")
    if (
        execution_authority.get("status") != "AVAILABLE_UNSPENT"
        or execution_authority.get("total_execution_chain_count") != 1
        or execution_authority.get("execution_chain_consumed_count") != 0
        or execution_authority.get("execution_chain_remaining_count") != 1
    ):
        raise ValueError("execution_chain_not_unspent")

    plan = build_materialization_plan()
    if (
        plan.get("artifact_content_sha256") != MATERIALIZATION_PLAN_CONTENT_SHA256
        or plan.get("source_materialized") is not False
        or plan.get("representation_count") != 254
        or plan.get("index_eligible_representation_count") != 250
    ):
        raise ValueError("materialization_plan_identity_invalid")

    r3_by_id = {row["row_id"]: row for row in r3["rows"]}
    ledger_by_id = {row["row_id"]: row for row in ledger["records"]}
    packet_by_id = {row["row_id"]: row for row in owner_packet["decisions"]}
    if (
        set(ROW_IDS) - r3_by_id.keys()
        or set(ROW_IDS) - ledger_by_id.keys()
        or set(ROW_IDS) - packet_by_id.keys()
    ):
        raise ValueError("cohort_row_missing_upstream")
    r3_rows = [r3_by_id[row_id] for row_id in ROW_IDS]

    blockers = [
        (row["row_id"], component) for row in r3_rows for component in row["blocking_components"]
    ]
    support_counts = Counter(component["support_fit"] for _, component in blockers)
    none_components = [component for _, component in blockers if component["support_fit"] == "NONE"]
    none_authority_empty = [
        component for component in none_components if not component["authorities"]
    ]
    none_authority_present = [
        component for component in none_components if component["authorities"]
    ]
    if (
        len(r3_rows) != 59
        or len(blockers) != 80
        or support_counts != {"NONE": 63, "PARTIAL": 17}
        or len(none_authority_empty) != 61
        or len(none_authority_present) != 2
    ):
        raise ValueError("cohort_topology_invalid")
    authority_present_keys = sorted(
        _component_key(row_id, component["component_ordinal"])
        for row_id, component in blockers
        if component["support_fit"] == "NONE" and component["authorities"]
    )
    expected_authority_present_keys = [
        "live30-q18:issue-08#component-5",
        "live30-q18:issue-08#component-7",
    ]
    if authority_present_keys != expected_authority_present_keys:
        raise ValueError("source_backed_none_topology_invalid")

    source_bindings, source_by_id = _source_bindings(r3_rows, quarantine, candidate, plan)
    source_origins = Counter(row["source_origin"] for row in source_bindings)
    if len(source_bindings) != 18 or source_origins != {
        "EXACT_OWNER_ADOPTED_MATERIALIZATION_PLAN": 14,
        "SEALED_251_SOURCE_CANDIDATE": 4,
    }:
        raise ValueError("inspected_source_topology_invalid")

    reclassified = 0
    excluded = 0
    retained_full_count = 0
    disposed_keys: list[str] = []
    row_advisories: list[dict[str, Any]] = []
    for row_id in ROW_IDS:
        r3_row = r3_by_id[row_id]
        ledger_row = ledger_by_id[row_id]
        packet_row = packet_by_id[row_id]
        atomic_components = packet_row["source_research_record"]["atomic_components"]
        retained_full = []
        for ordinal, component in enumerate(atomic_components, start=1):
            if component["support_fit"] != "FULL":
                continue
            proposition = component["proposition"]
            retained_full.append(
                {
                    "component_ordinal": ordinal,
                    "proposition": proposition,
                    "proposition_text_sha256": _sha256(proposition.encode()),
                    "support_fit": "FULL",
                    "authority_identity_ids": sorted(
                        authority.get("canonical_authority_identity_id")
                        or authority.get("authority_identity_id")
                        or authority.get("citation")
                        for authority in component["authorities"]
                    ),
                }
            )
        if not retained_full:
            raise ValueError(f"row_without_preexisting_full_component:{row_id}")
        retained_full_count += len(retained_full)

        recommendations = []
        for component in r3_row["blocking_components"]:
            ordinal = component["component_ordinal"]
            key = (row_id, ordinal)
            key_string = _component_key(row_id, ordinal)
            disposed_keys.append(key_string)
            before = {
                "component_ordinal": ordinal,
                "proposition": component["proposition"],
                "proposition_text_sha256": component["proposition_text_sha256"],
                "support_fit": component["support_fit"],
                "deterministic_blocker_reason_code": component["deterministic_blocker_reason_code"],
                "authority_list_empty": not component["authorities"],
            }
            inspections = []
            for authority in component["authorities"]:
                identity = authority["canonical_authority_identity_id"]
                inspections.append(
                    {
                        "authority_identity_id": identity,
                        "authority_content_sha256": authority["authority_content_sha256"],
                        "assessment_content_sha256": authority["assessment_content_sha256"],
                        "original_exact_locators": authority["exact_locators"],
                        "source_binding_content_sha256": source_by_id[identity][
                            "record_content_sha256"
                        ],
                        "representation_byte_hash_verified": True,
                        "support_fit_not_upgraded": True,
                    }
                )

            if component["support_fit"] == "PARTIAL" or key in EXCLUDE_NONE_KEYS:
                excluded += 1
                recommendation = {
                    "action": "EXCLUDE_EXACT_UNSUPPORTED_COMPONENT",
                    "before": before,
                    "after_legal_propositions": [],
                    "after_nonlegal_requirements": [],
                    "reason_code": (
                        "PARTIAL_SUPPORT_NOT_UPGRADED_ROW_RETAINS_FULL_COMPONENTS"
                        if component["support_fit"] == "PARTIAL"
                        else "UNSUPPORTED_OVERBROAD_POLICY_EMPIRICAL_OR_FOREIGN_LAW_CONTENT_EXCLUDED"
                    ),
                    "source_inspection": inspections,
                    "new_source_contracts": [],
                    "new_frozen_evidence_span_proposals": [],
                    "owner_adoption_required": True,
                    "applied": False,
                }
            else:
                requirement = MATTER_REQUIREMENTS.get(key)
                if requirement is None:
                    raise ValueError(f"matter_requirement_missing:{key_string}")
                reclassified += 1
                requirement_record = _seal(
                    {
                        "schema": (
                            "legalbot.v111.phase2a.nonlegal-matter-information-"
                            "requirement-proposal.v1"
                        ),
                        "requirement": requirement,
                        "requirement_text_sha256": _sha256(requirement.encode()),
                        "lane": "NONAUTHORITATIVE_MATTER_INTAKE_ONLY",
                        "may_enter_legal_authority_lane": False,
                        "may_create_evidence_span": False,
                        "may_be_cited_as_law": False,
                        "may_release_a_legal_claim": False,
                    },
                    "requirement_content_sha256",
                )
                recommendation = {
                    "action": "RECLASSIFY_AS_NONLEGAL_MATTER_INFORMATION_REQUIREMENT",
                    "before": before,
                    "after_legal_propositions": [],
                    "after_nonlegal_requirements": [requirement_record],
                    "reason_code": (
                        "SOURCE_PRESENT_BUT_RELEVANCE_INSUFFICIENT_FOR_CASE_SPECIFIC_OUTCOME"
                        if component["authorities"]
                        else "CASE_SPECIFIC_OUTCOME_DEPENDS_ON_MISSING_MATTER_INFORMATION"
                    ),
                    "source_inspection": inspections,
                    "new_source_contracts": [],
                    "new_frozen_evidence_span_proposals": [],
                    "owner_adoption_required": True,
                    "applied": False,
                }
            recommendations.append(_seal(recommendation, "recommendation_content_sha256"))

        row_advisories.append(
            _seal(
                {
                    "schema": (
                        "legalbot.v111.phase2a.authorityless-cohort-row-remediation-advisory.v1"
                    ),
                    "row_id": row_id,
                    "r3_row_record_content_sha256": r3_row["record_content_sha256"],
                    "working_ledger_record_content_sha256": ledger_row["record_content_sha256"],
                    "owner_decision_content_sha256": packet_row["decision_content_sha256"],
                    "original_blocking_component_count": len(r3_row["blocking_components"]),
                    "component_recommendations": recommendations,
                    "preexisting_full_components_retained": retained_full,
                    "all_unclassified_holds_retained": [
                        {
                            "record_content_sha256": hold["record_content_sha256"],
                            "hold_text_sha256": hold["hold_text_sha256"],
                            "hold_text": hold["hold_text"],
                            "classification_preserved": "UNCLASSIFIED_NON_OPERATIVE",
                        }
                        for hold in r3_row["unclassified_unresolved_holds"]
                    ],
                    "fallback_eligible": False,
                    "owner_adoption_required": True,
                    "owner_decision_applied": False,
                    "technical_success_not_predeclared": True,
                },
                "record_content_sha256",
            )
        )

    expected_keys = sorted(
        _component_key(row_id, component["component_ordinal"]) for row_id, component in blockers
    )
    if sorted(disposed_keys) != expected_keys or len(set(disposed_keys)) != 80:
        raise ValueError("blocker_disposition_not_exactly_once")
    if reclassified != 51 or excluded != 29 or retained_full_count != 127:
        raise ValueError("recommendation_counts_invalid")
    if set(MATTER_REQUIREMENTS) | EXCLUDE_NONE_KEYS != {
        (row_id, component["component_ordinal"])
        for row_id, component in blockers
        if component["support_fit"] == "NONE"
    }:
        raise ValueError("none_component_policy_not_exhaustive")

    advisory = {
        "schema": "legalbot.v111.phase2a.authorityless-cohort-59-remediation-advisory.v1",
        "status": "CREATE_ONLY_EXACT_REMEDIATION_READY_NOT_OWNER_ADOPTED",
        "phase_scope": "PHASE2A_ONLY",
        "advisory_date": "2026-08-28",
        "advisory_effect": "NON_AUTHORIZING_RECOMMENDATIONS_ONLY",
        "supersedes_advisory_content_sha256": SUPERSEDED_R1_CONTENT_SHA256,
        "supersession_reason": (
            "R2 removes the mutable private-helper dependency, completes the canonical "
            "no-execution boundary, and uses staged atomic no-replace publication. R1 "
            "is preserved as non-authoritative debug evidence."
        ),
        "row_id_set_sha256": ROW_ID_SET_SHA256,
        "row_ids": list(ROW_IDS),
        "topology_correction": {
            "assigned_authority_list_empty_none_component_count": 61,
            "observed_none_component_count": 63,
            "observed_partial_component_count": 17,
            "observed_total_blocking_component_count": 80,
            "authority_list_empty_none_component_count": 61,
            "authority_present_but_relevance_insufficient_none_component_count": 2,
            "authority_present_but_relevance_insufficient_component_keys": (authority_present_keys),
            "root_cause": (
                "The cohort name counted only NONE components with an empty authority "
                "list. Two additional NONE components cite real statutes, but those "
                "statutes do not support the claimed case-specific tracing or land-"
                "priority result. The row partition remains 59 and all 80 r3 blockers "
                "are dispositioned exactly once."
            ),
            "no_source_relevance_inference": True,
            "no_blocker_omitted": True,
        },
        "counts": {
            "row_count": len(row_advisories),
            "original_blocking_component_count": len(blockers),
            "original_none_component_count": support_counts["NONE"],
            "original_partial_component_count": support_counts["PARTIAL"],
            "authority_list_empty_none_component_count": len(none_authority_empty),
            "authority_present_none_component_count": len(none_authority_present),
            "nonlegal_matter_requirement_reclassification_count": reclassified,
            "exact_exclusion_component_count": excluded,
            "preexisting_full_component_retained_count": retained_full_count,
            "inspected_unique_source_count": len(source_bindings),
            "inspected_materialization_plan_source_count": source_origins[
                "EXACT_OWNER_ADOPTED_MATERIALIZATION_PLAN"
            ],
            "inspected_sealed_candidate_source_count": source_origins[
                "SEALED_251_SOURCE_CANDIDATE"
            ],
            "new_primary_authority_binding_count": 0,
            "new_source_admission_proposal_count": 0,
            "new_frozen_evidence_span_proposal_count": 0,
            "new_fallback_row_count": 0,
            "unresolved_blocker_count_if_exact_recommendations_owner_adopted": 0,
        },
        "input_bindings": [
            {
                "kind": "r3_prequalification_blocker_report",
                "content_sha256": R3_CONTENT_SHA256,
                "file_sha256": R3_FILE_SHA256,
            },
            {
                "kind": "proposition_reconciliation_working_ledger_361",
                "content_sha256": WORKING_LEDGER_CONTENT_SHA256,
                "file_sha256": WORKING_LEDGER_FILE_SHA256,
            },
            {
                "kind": "exact_remediation_owner_packet_361",
                "content_sha256": OWNER_PACKET_CONTENT_SHA256,
                "file_sha256": OWNER_PACKET_FILE_SHA256,
            },
            {
                "kind": "source_quarantine_manifest",
                "content_sha256": QUARANTINE_MANIFEST_CONTENT_SHA256,
                "file_sha256": QUARANTINE_MANIFEST_FILE_SHA256,
            },
            {
                "kind": "sealed_251_candidate_approved_source_manifest",
                "content_sha256": CANDIDATE_MANIFEST_CONTENT_SHA256,
                "file_sha256": CANDIDATE_MANIFEST_FILE_SHA256,
            },
            {
                "kind": "exact_owner_adopted_materialization_plan_read_only",
                "content_sha256": MATERIALIZATION_PLAN_CONTENT_SHA256,
            },
            {
                "kind": "single_unspent_phase2a_execution_authority",
                "content_sha256": EXECUTION_AUTHORITY_CONTENT_SHA256,
                "file_sha256": EXECUTION_AUTHORITY_FILE_SHA256,
            },
            {
                "kind": "authoritative_146_row_baseline_advisory_r2",
                "content_sha256": BASELINE_ADVISORY_CONTENT_SHA256,
                "file_sha256": BASELINE_ADVISORY_FILE_SHA256,
            },
            {
                "kind": "superseded_authorityless_cohort_advisory_r1",
                "content_sha256": SUPERSEDED_R1_CONTENT_SHA256,
                "file_sha256": SUPERSEDED_R1_FILE_SHA256,
            },
        ],
        "inspected_source_byte_bindings": source_bindings,
        "replacement_source_contract": {
            "new_primary_authority_bindings": [],
            "new_source_admission_proposals": [],
            "new_frozen_evidence_span_proposals": [],
            "reason": (
                "Every row retains pre-existing FULL legal components. Incomplete, "
                "irrelevant, unsupported, empirical, policy and case-specific outcome "
                "components are not upgraded by relevance or by additional authority."
            ),
        },
        "row_advisories": row_advisories,
        "decision_boundary": {
            "recommendations_are_not_owner_decisions": True,
            "owner_must_approve_exact_future_consolidated_digest": True,
            "no_blanket_fallback": True,
            "no_row_outside_exact_59_row_set": True,
            "one_execution_chain_total": 1,
            "execution_chain_consumed": 0,
            "execution_chain_remaining": 1,
            "technical_success_not_predeclared": True,
        },
        **NO_EXECUTION_FLAGS,
    }
    return _seal(advisory)


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


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_directory_noreplace(staging: Path, output: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    source = os.fsencode(staging)
    target = os.fsencode(output)
    if sys.platform == "darwin" and hasattr(libc, "renamex_np"):
        function = libc.renamex_np
        function.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        function.restype = ctypes.c_int
        result = function(source, target, 0x00000004)
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        function = libc.renameat2
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
        result = function(-100, source, -100, target, 0x00000001)
    else:
        raise RuntimeError("authorityless_cohort_atomic_noreplace_unavailable")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise FileExistsError("authorityless_cohort_output_already_exists")
    raise OSError(error_number, "authorityless_cohort_atomic_publish_failed")


def publish(output_root: Path = OUTPUT_ROOT) -> dict[str, str]:
    if output_root.exists() or output_root.is_symlink():
        raise FileExistsError("authorityless_cohort_output_already_exists")
    if not output_root.name or not output_root.parent.is_dir():
        raise ValueError("authorityless_cohort_output_parent_invalid")
    advisory = build_advisory()
    advisory_bytes = _pretty_json(advisory)
    package = _seal(
        {
            "schema": (
                "legalbot.v111.phase2a.authorityless-cohort-59-remediation-advisory-package.v1"
            ),
            "status": advisory["status"],
            "supersedes_advisory_content_sha256": SUPERSEDED_R1_CONTENT_SHA256,
            "advisory_content_sha256": advisory["artifact_content_sha256"],
            "advisory_file_sha256": _sha256(advisory_bytes),
            "row_id_set_sha256": ROW_ID_SET_SHA256,
            "row_count": advisory["counts"]["row_count"],
            "original_blocking_component_count": advisory["counts"][
                "original_blocking_component_count"
            ],
            "nonlegal_matter_requirement_reclassification_count": advisory["counts"][
                "nonlegal_matter_requirement_reclassification_count"
            ],
            "exact_exclusion_component_count": advisory["counts"][
                "exact_exclusion_component_count"
            ],
            "execution_chain_consumed": 0,
            **NO_EXECUTION_FLAGS,
        }
    )
    package_bytes = _pretty_json(package)
    checksums = (
        f"{_sha256(advisory_bytes)}  {ADVISORY_NAME}\n{_sha256(package_bytes)}  {PACKAGE_NAME}\n"
    ).encode()

    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.staging-", dir=output_root.parent))
    os.chmod(staging, 0o700)
    try:
        for name, raw in (
            (ADVISORY_NAME, advisory_bytes),
            (PACKAGE_NAME, package_bytes),
            (CHECKSUMS_NAME, checksums),
        ):
            _write_exclusive(staging / name, raw)
        for path in staging.iterdir():
            os.chmod(path, 0o600)
        _fsync_directory(staging)
        _publish_directory_noreplace(staging, output_root)
        _fsync_directory(output_root.parent)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    return {
        "output_root": output_root.name,
        "advisory_content_sha256": advisory["artifact_content_sha256"],
        "advisory_file_sha256": _sha256(advisory_bytes),
        "package_content_sha256": package["artifact_content_sha256"],
        "package_file_sha256": _sha256(package_bytes),
        "status": advisory["status"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("verify", "publish"))
    args = parser.parse_args()
    if args.command == "verify":
        advisory = build_advisory()
        print(
            json.dumps(
                {
                    "artifact_content_sha256": advisory["artifact_content_sha256"],
                    "counts": advisory["counts"],
                    "status": advisory["status"],
                },
                sort_keys=True,
            )
        )
    else:
        print(json.dumps(publish(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
