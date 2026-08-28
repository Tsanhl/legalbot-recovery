#!/usr/bin/env python3
"""Build the create-only substantive remediation advisory for the exact 28 rows.

The advisory is deliberately non-authorizing.  It binds each r3 blocker
ordinal/hash exactly once, narrows source-bearing propositions to historical
holdings or dated statutory/regulatory snapshots, and states exclusions for
unsupported legal or application claims.  It does not apply a decision, admit
or materialize a source, scan, build, embed, retrieve, qualify, invoke a model,
write ACTIVE/PREVIOUS, or start Phase 2B.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import io
import json
import os
import re
import shutil
import tempfile
import unicodedata
from collections import Counter
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from bs4 import BeautifulSoup
from pypdf import PdfReader

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LAW_ROOT = Path("/Users/hltsang/Desktop/Law")
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"

R3_PATH = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-prequalification-blockers-r3/PREQUALIFICATION-BLOCKER-REPORT.json"
)
OWNER_PACKET_PATH = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-exact-remediation-owner-packet-r1/"
    "EXACT-REMEDIATION-OWNER-PACKET-361.json"
)
BASELINE_ROOT = REVIEW_ROOT / ("LegalBot-Phase2A-2026-08-28-held-missing-source-advisory-r2")
BASELINE_ADVISORY_PATH = BASELINE_ROOT / "HELD-MISSING-SOURCE-ADVISORY-28.json"
BASELINE_SOURCE_MANIFEST_PATH = BASELINE_ROOT / "OFFICIAL-SOURCE-RESEARCH-MANIFEST.json"
SOURCE_QUARANTINE_ROOT = REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-source-quarantine"
SOURCE_QUARANTINE_MANIFEST_PATH = SOURCE_QUARANTINE_ROOT / "QUARANTINE-MANIFEST.json"
CANDIDATE_MANIFEST_PATH = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-27-final-owner-review-blocked/machine/candidate/"
    "approved-source-manifest.json"
)
EXECUTION_AUTHORITY_PATH = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-final-remediation-owner-approved-r1/"
    "PHASE2A-EXECUTION-AUTHORITY.json"
)

OUTPUT_ROOT = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-held-missing-28-substantive-remediation-advisory-r1"
)
ADVISORY_NAME = "EXACT-28-ROW-SUBSTANTIVE-REMEDIATION-ADVISORY.json"
SOURCE_MANIFEST_NAME = "NINE-PROPOSED-REPRESENTATION-BINDINGS.json"
PACKAGE_NAME = "PACKAGE-MANIFEST.json"
CHECKSUMS_NAME = "SHA256SUMS.txt"

R3_FILE_SHA256 = "7cb044a4c9539162281e10ac41e5e0cb1f0cd846b0eb597a0443b0e67fb48899"
R3_CONTENT_SHA256 = "5efc17b16adcae1ceb2ea1bbd7efcaba469ab0340c24b65c1e994132cb337980"
OWNER_PACKET_FILE_SHA256 = "992770c04cb3e08de64bb98e80aa9801171d3e66e4b573b85919091a78b1db3b"
OWNER_PACKET_CONTENT_SHA256 = "93ad9113af76896f0570a3666c446472af7587b7e3ff32b7464e670777ec6b6c"
BASELINE_ADVISORY_FILE_SHA256 = "50af9072af77e34acdd19fbaa8f59a45a7c675f8ce838a0ed95c38cb1c44b748"
BASELINE_ADVISORY_CONTENT_SHA256 = (
    "55142411a101f3c743e59f8548736d7cb3370f535b651466f0a69c63735cb6f8"
)
BASELINE_SOURCE_MANIFEST_FILE_SHA256 = (
    "fe7b4b28b4b1869d7c5058ed8f75ab4b654935b4200ab89eaa105c1a7de1ac3e"
)
BASELINE_SOURCE_MANIFEST_CONTENT_SHA256 = (
    "d0aa2aed911db9d47326072102bdfbfda8ef0c8326477ca48ab0eaf2f2b13ed4"
)
SOURCE_QUARANTINE_MANIFEST_FILE_SHA256 = (
    "f482366a2ba0d9f636c56104d632767a8eadd6e9a9625d50ef5391a5f62995eb"
)
SOURCE_QUARANTINE_MANIFEST_CONTENT_SHA256 = (
    "b6d900b23232379a4d6c19d313f35c47e0758ce5e0bb6eb04008f9eba07a3819"
)
CANDIDATE_MANIFEST_FILE_SHA256 = "0bbb1edb169c84a26e5f1d42e367f9e2f83fcdd9c652a9061980652f15979b21"
CANDIDATE_MANIFEST_CONTENT_SHA256 = (
    "b304ab1223987bf9b57d3e2560413b2f325c16213ae0071a45dface2e10dc206"
)
EXECUTION_AUTHORITY_FILE_SHA256 = "5171ce79007c68484f9854b5188bf7e7af8f880407b6fbad6e3f808d0c7630ad"
EXECUTION_AUTHORITY_CONTENT_SHA256 = (
    "eb0eda2f34c8b261ea38fc9d697257cdd3bd6253c18c2d91355328c8cb78ef7b"
)

STATUS_RESOLVED = "SOURCE_TOPOLOGY_RESOLVED_OWNER_ACTION_REQUIRED"
STATUS_REWRITE = "NO_VALID_MISSING_SOURCE_REQUIREMENT_OWNER_REWRITE_OR_EXCLUSION"
STATUS_RETAINED = "UNAVAILABLE_OR_INCOMPLETE_OFFICIAL_SOURCE_GAP_RETAINED"

STANDARD_NO_EXECUTION_FLAGS = {
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

# Additional names emitted by this advisory or used by adjacent Phase-2A
# builders.  Keeping them in the same recursive verifier closes aliases that
# could otherwise conceal a state change below a nested record.
NO_EXECUTION_EXTENSIONS = {
    "source_materialized": False,
    "index_build_run": False,
    "model_run": False,
    "retrieval_run": False,
    "owner_adopted": False,
    "applied": False,
    "materialized": False,
    "indexed": False,
    "embedded": False,
}
NO_EXECUTION = {**STANDARD_NO_EXECUTION_FLAGS, **NO_EXECUTION_EXTENSIONS}

_PRIVATE_PATH = re.compile(
    r"(?i)(?:/Users/|/home/|/private/|file://|[A-Z]:\\Users\\|LegalBot-New|hltsang)"
)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def _seal(value: dict[str, Any], field: str = "artifact_content_sha256") -> dict[str, Any]:
    material = dict(value)
    material.pop(field, None)
    return {**material, field: _sha256(_canonical_json(material))}


def _recursive_no_execution_violations(value: Any, path: str = "$") -> list[str]:
    violations: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key in NO_EXECUTION and child is not False:
                violations.append(child_path)
            violations.extend(_recursive_no_execution_violations(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            violations.extend(_recursive_no_execution_violations(child, f"{path}[{index}]"))
    return violations


def _recursive_no_execution_control() -> dict[str, Any]:
    return {
        "standard_authoritative_field_count": len(STANDARD_NO_EXECUTION_FLAGS),
        "additional_fail_closed_field_count": len(NO_EXECUTION_EXTENSIONS),
        "total_verified_field_count": len(NO_EXECUTION),
        "verified_field_names": sorted(NO_EXECUTION),
        "recursive_truthy_occurrence_rejected": True,
    }


def _load(path: Path, file_sha256: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or _file_sha256(path) != file_sha256:
        raise ValueError(f"sealed_input_file_invalid:{path.name}")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"sealed_input_not_object:{path.name}")
    return value


def _verify_content(value: dict[str, Any], field: str, expected: str) -> None:
    material = dict(value)
    observed = str(material.pop(field, ""))
    if observed != expected or _sha256(_canonical_json(material)) != observed:
        raise ValueError(f"sealed_input_content_invalid:{field}")


def _source(identity: str, *locators: str) -> dict[str, Any]:
    return {"authority_identity_id": identity, "exact_locators": list(locators)}


def _rewrite(
    proposition: str,
    sources: list[dict[str, Any]],
    excluded_scope: str,
    *,
    reason: str,
) -> dict[str, Any]:
    return {
        "action": "REPLACE_WITH_EXACT_NARROW_SOURCE_BOUND_PROPOSITION",
        "after_propositions": [proposition],
        "sources": sources,
        "excluded_scope": excluded_scope,
        "reason": reason,
    }


def _exclude(reason: str, coverage: str) -> dict[str, Any]:
    return {
        "action": "EXCLUDE_EXACT_UNSUPPORTED_COMPONENT",
        "after_propositions": [],
        "sources": [],
        "excluded_scope": "THE_EXACT_BASELINE_COMPONENT_IN_FULL",
        "reason": reason,
        "issue_coverage": coverage,
    }


# Every key is an exact (row_id, r3 component_ordinal) pair.  The builder
# verifies that this map equals the 41 blockers in the sealed r3 cohort.
RECOMMENDATIONS: dict[tuple[str, int], dict[str, Any]] = {
    ("live30-q01:issue-01", 1): _rewrite(
        "In Grand China [2016] EWCA Civ 982, the Court of Appeal treated the classification and consequences of non-performance of an express contractual obligation as questions of contractual construction; that holding does not prove the executed deadline or performance facts in this matter.",
        [
            _source(
                "neutral-citation:[2016] EWCA Civ 982",
                "paragraphs 16-20",
                "paragraph 47",
                "paragraphs 52 and 55",
            )
        ],
        "Any conclusion that the executed contract fixed 1 June, that delivery was late, or that termination or damages follows on the matter facts.",
        reason="Narrow the composite breach/application claim to the exact historical appellate holding.",
    ),
    ("live30-q01:issue-01", 2): _rewrite(
        "The sealed 2026-08-14 statutory snapshot of Supply of Goods and Services Act 1982 section 13 states that, where the statutory conditions apply, a supplier acting in the course of business carries an implied term to perform the service with reasonable care and skill; it does not establish this contract's specifications or breach.",
        [_source("ukpga:1982:29", "section 13")],
        "Contract characterization, exclusions, agreed specifications, defect evidence and application outcome.",
        reason="Separate the exact statutory term from contract and performance facts.",
    ),
    ("live30-q01:issue-03", 3): _exclude(
        "The distinct waiver-of-strict-compliance formulation exceeds the cited election authority.",
        "The row retains its two pre-existing FULL components on contractual termination and affirmation; waiver is not asserted.",
    ),
    ("live30-q04:issue-07", 1): _exclude(
        "No exact admitted Criminal Justice and Immigration Act 2008 section 76 representation is bound by this advisory.",
        "The row retains its pre-existing FULL statutory loss-of-control and diminished-responsibility components and gains the exact Johnson duress component; self-defence is not asserted.",
    ),
    ("live30-q04:issue-07", 4): _rewrite(
        "In R v Johnson [2022] EWCA Crim 832 at paragraphs 49-50, the Court of Appeal confirmed the Hasan duress framework, including a genuine and reasonable belief in an immediate or almost immediate threat of death or serious injury, absence of a reasonable evasive course, and the objective reasonable-person question; no duress outcome is inferred on the benchmark facts.",
        [_source("neutral-citation:[2022] EWCA Crim 832", "paragraphs 49-50")],
        "Any factual finding that threats existed, escape was unavailable, the objective test was met, or duress succeeds.",
        reason="Replace the source-free duress sentence with the exact historical Court of Appeal framework.",
    ),
    ("live30-q05:issue-06", 2): _exclude(
        "Perry does not itself supply every proposed costs or valuation deduction.",
        "The row retains its pre-existing FULL Perry component on the value of a lost claim and third-party contingencies; unproved deductions are not asserted.",
    ),
    ("live30-q05:issue-07", 1): _rewrite(
        "The sealed SRA Code page retrieved on 2026-08-28 states at paragraphs 3.2, 3.3 and 3.5 that regulated solicitors must provide competent and timely service, maintain competence, and effectively supervise work; this is a dated regulatory proposition, not a binding AI-specific negligence rule.",
        [
            _source(
                "official-url:https://www.sra.org.uk/solicitors/standards-regulations/code-conduct-solicitors",
                "paragraphs 3.2, 3.3 and 3.5",
            )
        ],
        "Any proposition that AI use transfers responsibility, establishes breach, or creates a freestanding negligence duty without the retainer, professional standard and facts.",
        reason="Use the exact regulatory duty and expressly reject an AI-specific common-law rule.",
    ),
    ("live30-q05:issue-07", 2): _exclude(
        "The post-ceiling SRA AI warning and matter-specific manual-verification conclusion cannot enter the qualification corpus.",
        "The narrowed Code proposition covers only competence and supervision; manual verification remains a professional-standard and matter-evidence question with no legal conclusion.",
    ),
    ("live30-q13:issue-04", 3): _exclude(
        "The partial component combines the conflict rule with unresolved authorization, profit, loss and remedy selection.",
        "The row retains its two pre-existing FULL components on strict no-conflict/no-profit duties and fully informed consent; no remedial outcome is asserted.",
    ),
    ("live30-q13:issue-08", 1): _exclude(
        "The Menelaou tracing/proprietary-versus-personal formulation remains later-treatment and mixed-account held.",
        "The row retains pre-existing FULL components on equitable compensation and knowing receipt; tracing and proprietary entitlement are not asserted.",
    ),
    ("live30-q13:issue-08", 4): _exclude(
        "The composite dishonest-assistance statement remains only partially supported in the sealed packet.",
        "The row retains the pre-existing FULL Byers knowing-receipt and AIB/Mitchell equitable-compensation components; dishonest assistance is not asserted.",
    ),
    ("live30-q19:issue-01", 1): _rewrite(
        "The official Competition Act 1998 section 18 representation states the Chapter II prohibition in terms of abuse by one or more undertakings of a dominant position in a market where the conduct may affect trade within the United Kingdom; section 18 alone does not provide a complete substitutability methodology or prove a relevant market.",
        [_source("ukpga:1998:41", "section 18(1)-(3)")],
        "Any market definition, substitutability, dominance, abuse, effect or justification conclusion on the matter facts.",
        reason="Narrow the market-definition component to the exact statutory gateway and its express limit.",
    ),
    ("live30-q19:issue-03", 2): _exclude(
        "The Competition Act application remains fact-specific and the statutory examples are not per se liability.",
        "The row retains its pre-existing FULL DMCC sections 19-20 component on permitted conduct requirements; no designation, requirement or breach is inferred.",
    ),
    ("live30-q19:issue-04", 2): _exclude(
        "The partial Competition Act component cannot prove an arrangement, foreclosure or objective justification.",
        "The row retains its pre-existing FULL DMCC sections 19-20 component on permitted discriminatory/access requirements; no designation or breach is inferred.",
    ),
    ("live30-q20:issue-08", 1): _rewrite(
        "In Montgomery v Lanarkshire Health Board [2015] UKSC 11 at paragraphs 82-83 and 87-89, the Supreme Court stated the clinician's duty to take reasonable care to ensure that a patient is aware of material risks and reasonable alternatives; the holding does not create an AI-specific verification duty or decide diagnosis, device status, breach or causation here.",
        [_source("neutral-citation:[2015] UKSC 11", "paragraphs 82-83 and 87-89")],
        "Any AI-specific duty, diagnostic-choice rule, device-status finding, accepted-practice finding, breach, causation or outcome.",
        reason="Replace the composite AI proposition with Montgomery's exact historical disclosure duty.",
    ),
    ("live30-q24:issue-01", 2): _exclude(
        "The Supply of Goods and Services Act route is partial and fact-dependent in this client-duties row.",
        "The row retains its pre-existing FULL SRA regulatory client-duty component; contract, tort and fiduciary application remain separate.",
    ),
    ("live30-q24:issue-08", 3): _exclude(
        "The costs-assessment route does not establish a categorical AI-billing or efficiency-pass-through rule.",
        "The row retains its two pre-existing FULL SRA pricing/information and Transparency Rules components; statutory assessment and billing facts remain separate.",
    ),
    ("live30-q28:issue-05", 4): _rewrite(
        "In Waller-Edwards v One Savings Bank Plc [2025] UKSC 22 at paragraphs 1-6, 25-40, 46-49 and 52-58, the Supreme Court treated the lender's inquiry obligation as a separate tripartite question and explained when a non-commercial surety or hybrid transaction puts the lender on inquiry; no Etridge representation or matter-level undue-influence result is asserted.",
        [_source("neutral-citation:[2025] UKSC 22", "paragraphs 1-6, 25-40, 46-49 and 52-58")],
        "All Etridge-only propositions and any finding about transaction, relationship, influence, suretyship, notice, lender knowledge or response on the facts.",
        reason="Use exact Waller-Edwards official bytes only and retain every fact hold.",
    ),
    ("live30-q30:issue-07", 2): _exclude(
        "No proposition-complete interim-relief merits test is bound for this component.",
        "The row retains its pre-existing FULL Senior Courts Act final-remedy, Equality Act, data-protection and copyright-remedy components; interim relief is not asserted.",
    ),
    ("live30-q30:issue-07", 6): _exclude(
        "A universal private-law remedy is not an atomic positive legal proposition.",
        "Each retained FULL statutory remedy remains separately scoped; contract, tort, misrepresentation, shareholder and insolvency remedies require a proved cause of action.",
    ),
    ("live30-q30:issue-10", 1): _exclude(
        "Strategic ranking is professional application judgment rather than a source-verifiable rule.",
        "The row retains FULL components on the overriding objective/case management, Churchill ADR and cause-specific limitation; claimant objectives and strategy remain facts/advice.",
    ),
    ("live30-q30:issue-10", 5): _exclude(
        "No universal Part 36 or interim-remedy tactical preference is legally supportable.",
        "The retained FULL procedural and limitation components preserve the legal framework; offer terms, timing, evidence and undertakings remain application matters.",
    ),
    ("live30-q30:issue-16", 4): _exclude(
        "The partial trade-secret component cannot establish that architecture, data or output is secret, protected or copied.",
        "The row retains FULL copyright authorship/ownership, infringement and database-right components; trade-secret outcome is not asserted.",
    ),
    ("live30-q30:issue-18", 5): _exclude(
        "The partial deletion component over-combines preservation duties with sanctions, inference and privilege consequences.",
        "The row retains four pre-existing FULL components on PD57AD preservation, CPR Part 31 disclosure, litigation privilege and legal-advice privilege; no spoliation tort or automatic consequence is asserted.",
    ),
    ("live60-q32:issue-04", 1): _rewrite(
        "In Dyson Technology Ltd v Channel Four Television Corp [2023] EWCA Civ 884 at paragraphs 33-47, the Court of Appeal held that reference is assessed through the hypothetical reasonable reader or viewer acquainted with the claimant, including attributes properly attributed to that acquaintance; actual subjective understanding is not the test.",
        [_source("neutral-citation:[2023] EWCA Civ 884", "paragraphs 33-47")],
        "Any conclusion that the words identify the claimant without the words, context, pleaded attributes and relevant acquaintance facts.",
        reason="Replace the regulatory analogy with direct England-and-Wales defamation authority.",
    ),
    ("live60-q32:issue-04", 2): _rewrite(
        "Simon v Lyder [2019] UKPC 38 at paragraphs 11-26 is a Privy Council appeal from Trinidad and Tobago and is proposed only as persuasive historical support that separate publications are not automatically aggregated and require a sufficient nexus in the reasonable reader's mind; it is not relabelled binding England-and-Wales authority.",
        [_source("neutral-citation:[2019] UKPC 38", "paragraphs 11-26")],
        "Any binding England-and-Wales cross-publication rule or application result.",
        reason="Preserve the exact persuasive source role and narrow the proposition to Simon's holding.",
    ),
    ("live60-q32:issue-04", 3): _exclude(
        "No categorical rule for every unnamed member of a criticised group was verified.",
        "Dyson supplies the direct fact-sensitive reference test and Simon is persuasive only for connected publications; group size alone yields no conclusion.",
    ),
    ("live60-q37:issue-06", 1): _rewrite(
        "SI 2024/234—not SI 2024/1377—is the Limited Liability Partnerships (Application of Company Law) Regulations 2024. The sealed as-made SI 2024/234 representation supplies that identity and its amendments to the 2009 LLP application regime; exact commencement, applied provisions, later effects, the LLP agreement and distribution or insolvency consequences remain outside this proposition.",
        [
            _source(
                "uksi:2024:234", "regulation 1", "regulation 5", "regulations 6-46 as relevant"
            ),
            _source("uksi:2009:1804", "Parts 4-8", "Parts 10-12", "Parts 13 and 15"),
        ],
        "The SI 2024/1377 mapping and every unverified commencement, application, disclosure, capital, distribution or insolvency conclusion.",
        reason="Correct the instrument identity, reject 2024/1377, and retain the effects/currentness boundary.",
    ),
    ("live60-q40:issue-09", 1): _rewrite(
        "The sealed 2026-08-14 Senior Courts Act 1981 snapshot provides final judicial-review remedies in sections 29A and 31, including quashing, mandatory and prohibiting orders and the statutory conditions on relief; damages require an independently available cause of action. No interim-relief merits test or entitlement is adopted.",
        [_source("ukpga:1981:54", "section 29A(1)-(9)", "section 31(1)-(2B)", "section 31(5)-(6)")],
        "The unsupported interim-relief test and all construction timing, delay, third-party prejudice, likely-outcome, damages-basis and undertaking conclusions.",
        reason="Narrow to exact Senior Courts Act final-remedy mechanics and exclude the unsupported interim test.",
    ),
    ("live60-q42:issue-03", 3): _rewrite(
        "In Aabar Holdings SARL v Glencore plc [2026] EWHC 877 (Comm) at paragraphs 34, 45-46 and 65-73, the Commercial Court treated the corporation as the client and the relevant human communicators as those authorised to seek and receive legal advice; the judgment is first-instance authority and does not establish that every employee can waive corporate privilege.",
        [_source("neutral-citation:[2026] EWHC 877 (Comm)", "paras 34 and 45-46", "paras 65-73")],
        "The unavailable Three Rivers No 6 employee-waiver formulation and any matter-level finding about authority, roles, purpose or disclosure.",
        reason="Use the exact available corporate-client source and exclude only the unsupported waiver proposition.",
    ),
    ("live60-q42:issue-08", 3): _exclude(
        "The partial component risks treating aligned interests as a freestanding privilege doctrine and a Bermuda appeal as binding England-and-Wales law.",
        "The row retains its FULL Berezovsky limited-waiver component and FULL Jardine joint-retainer component; common/aligned interest and shareholder status create no asserted automatic rule.",
    ),
    ("live60-q46:issue-05", 1): _rewrite(
        "In Osborn v Parole Board [2013] UKSC 61 at paragraph 2 and paragraphs 67-72, the Supreme Court treated procedural fairness as context-sensitive and directed attention to what fairness requires for effective participation and a fair decision; those passages do not create a blanket right to source code or decide this university process.",
        [_source("neutral-citation:[2013] UKSC 61", "paragraph 2", "paragraphs 67-72")],
        "Any blanket disclosure right, blanket confidentiality exception, or matter-level conclusion about what must be disclosed.",
        reason="Narrow commercial-confidentiality language to Osborn's exact historical fairness principle.",
    ),
    ("live60-q46:issue-05", 2): _rewrite(
        "The sealed Trade Secrets (Enforcement, etc.) Regulations 2018 snapshot at regulation 10 permits confidentiality-preserving measures in legal proceedings, including restricted access and redacted decisions; it is an exact procedural safeguard and is not asserted to govern an internal university hearing directly.",
        [_source("uksi:2018:597:made", "regulation 10(1)-(8)")],
        "Any direct application of regulation 10 to the internal hearing or conclusion that a particular safeguard is sufficient.",
        reason="Retain only the exact statutory safeguard as an expressly limited analogy.",
    ),
    ("live60-q46:issue-05", 3): _exclude(
        "Minimum disclosure is an application question that cannot be fixed without the detector, procedure and proposed safeguards.",
        "The two narrowed propositions supply the general fairness and confidentiality-safeguard framework; the exact disclosure package remains a matter-information decision.",
    ),
    ("live60-q50:issue-06", 5): {
        "action": "REPLACE_WITH_EXACT_NARROW_SOURCE_BOUND_PROPOSITION",
        "after_propositions": [
            "In AIG Europe Ltd v Woodman [2017] UKSC 18 at paragraphs 14-24, the Supreme Court held that a series-of-related-matters-or-transactions clause requires the matters or transactions to fit together rather than merely share similarity, and that application is acutely fact-sensitive.",
            "In Various Eateries Trading Ltd v Allianz Insurance Plc [2024] EWCA Civ 10 at paragraphs 27-28, 37-68 and 79-89, the Court of Appeal treated single-occurrence aggregation as dependent on the operative wording, causal connection, remoteness and relevant factual unities rather than a mechanical per-location or per-period rule.",
        ],
        "sources": [
            _source("neutral-citation:[2017] UKSC 18", "paragraphs 14-19", "paragraphs 20-24"),
            _source(
                "neutral-citation:[2024] EWCA Civ 10",
                "paragraphs 27-28",
                "paragraphs 37-68",
                "embedded aggregation summary at paragraphs 79-89",
            ),
        ],
        "excluded_scope": "Any aggregation outcome without the actual insuring clause, aggregation wording, schedule, limits, deductibles, retentions, locations, policy periods and event facts; Lloyds TSB bytes are not relied upon.",
        "reason": "Use exact AIG and Various Eateries propositions and preserve actual-wording dependence.",
    },
    ("live60-q59:issue-14", 3): _exclude(
        "The security/non-party-costs component is partial and route-specific.",
        "The row retains its FULL PACCAR/Sony enforceability and CAT representative/certification components; no general funder-security rule is asserted.",
    ),
    ("live60-q59:issue-14", 4): _exclude(
        "A route-independent universal control or full-disclosure rule was not verified.",
        "Control, disclosure, privilege and conflicts require the actual agreement, route and orders; no legal claim is released for this component.",
    ),
    ("live60-q59:issue-15", 2): _rewrite(
        "In Infinity Distribution Ltd v Khan Partnership LLP [2021] EWCA Civ 565 at paragraphs 26-37 and 59-74, the Court of Appeal treated the gateway, amount, manner and timing of security as distinct questions and assessed the proposed ATE-backed deed through the actual terms, consequences and evidence; an unidentified ATE policy is not automatically adequate security.",
        [_source("neutral-citation:[2021] EWCA Civ 565", "paragraphs 26-37", "paragraphs 59-74")],
        "Any conclusion about an unidentified policy's adequacy, recoverability, wording, insurer, rating, exclusions, deed or premium.",
        reason="Replace the unavailable Doyle proposition with the narrower exact Infinity security proposition.",
    ),
    ("live60-q59:issue-15", 3): _exclude(
        "No official legal source can prove the commercial terms or availability of an unidentified ATE product.",
        "The row retains its FULL statutory premium-recovery component and the narrowed Infinity security framework; product terms remain matter facts.",
    ),
    ("live60-q59:issue-17", 3): _rewrite(
        "In AXA Insurance UK plc v Commissioners for HMRC [2026] UKSC 24 at paragraphs 1-3, 14-21 and 185-188, the Supreme Court described a Group Litigation Order as case-management machinery for separately commenced claims placed on a group register and governed by common or related issues; it does not itself supply CAT aggregate-damages distribution rules.",
        [
            _source(
                "neutral-citation:[2026] UKSC 24",
                "paragraphs 1-3",
                "paragraphs 14-21",
                "paragraphs 185-188",
            )
        ],
        "Any distribution method, claimant entitlement, settlement term, unclaimed-sum destination or rule for a different procedural vehicle.",
        reason="Use exact AXA GLO mechanics and keep distribution routes separate.",
    ),
    ("live60-q59:issue-17", 4): _exclude(
        "No universal distribution rule exists across unidentified representative, GLO and regulatory routes.",
        "The row retains FULL CAT aggregate-damages and collective-settlement components plus the narrowed AXA GLO mechanics; route and order facts remain required.",
    ),
}


# Raw primary representations for source identities that otherwise resolve only
# to the sealed candidate's canonical derivative.  Paths are never emitted;
# artifacts contain only a root alias, relative member and byte hash.
RAW_OVERRIDES: dict[str, tuple[str, Path, str]] = {
    "ukpga:1982:29": (
        "PROJECT_RESEARCH_QUARANTINE",
        PROJECT_ROOT
        / "data/evaluations/phase2a-owner-review/LegalBot-Phase2AB-2026-08-24-r34-quarantine/candidate-legislation-760fe3f65b39e09e-7ec01025a80f84fd.xml",
        "7ec01025a80f84fdf93234d1a72db3d7e7b1631c9f701ced02fe78d6a39443a2",
    ),
    "neutral-citation:[2015] UKSC 11": (
        "LAW_SOURCE_ROOT",
        LAW_ROOT
        / "Official Legislation/seminar-gap-official-2026-08-26/uk-judgments-round2/United Kingdom/uksc-2015-11-data.xml",
        "32da4ee8711e404629f76884514b94054cfab2de862651c59633b6c06e4f087b",
    ),
    "neutral-citation:[2025] UKSC 22": (
        "PROJECT_APPROVED_SOURCE_ROOT",
        PROJECT_ROOT
        / "sources/phase2a-approved-2026-08-27/Official Judgments/068-neutral-citation-2025-uksc-22-ac8b04ef02769abf.xml",
        "ac8b04ef02769abfa455694e1271778403d30342ede0b96b706e91c003f6270b",
    ),
    "ukpga:1981:54": (
        "PROJECT_RESEARCH_QUARANTINE",
        PROJECT_ROOT
        / "data/evaluations/phase2a-owner-review/LegalBot-Phase2AB-2026-08-24-r34-quarantine/candidate-legislation-c13b082348582331-ac5ad88b8f5396cc.xml",
        "ac5ad88b8f5396cc63085bc86c2bd7a96ef37a30c92b0c90979725fd3f37dc2a",
    ),
    "uksi:2018:597:made": (
        "PROJECT_RESEARCH_QUARANTINE",
        PROJECT_ROOT
        / "data/evaluations/phase2a-owner-review/LegalBot-Phase2AB-2026-08-24-r34-quarantine/candidate-legislation-59d2e2ef3fe08226-7201e12a045b1036.xml",
        "7201e12a045b103674b4b9bc6cfec736b44a6bc49389ee677e9c55739533d4f9",
    ),
}


SOURCE_ASSESSMENTS: dict[str, dict[str, Any]] = {
    "neutral-citation:[2016] EWCA Civ 982": {
        "jurisdiction": "England and Wales",
        "source_role": "Court of Appeal (Civil Division); binding appellate historical holding subject to later treatment",
        "currentness_finding": "Official judgment identity and cited historical holding are byte-bound; present-law use is not asserted.",
        "later_treatment_finding": "Comprehensive later-treatment review remains an answer-release hold.",
    },
    "ukpga:1982:29": {
        "jurisdiction": "United Kingdom legislation; application and territorial effects remain contract-specific",
        "source_role": "Primary legislation snapshot",
        "currentness_finding": "Sealed candidate currentness verified at 2026-08-14; application, exclusions and effects remain held.",
        "later_treatment_finding": "Not a judgment; later amendment/effects review remains an answer-release hold.",
    },
    "neutral-citation:[2022] EWCA Crim 832": {
        "jurisdiction": "England and Wales",
        "source_role": "Court of Appeal (Criminal Division); binding appellate historical holding",
        "currentness_finding": "Official judgment identity and paragraphs 49-50 are byte-bound; current-law use remains release-held.",
        "later_treatment_finding": "Comprehensive later-treatment review remains an answer-release hold.",
    },
    "official-url:https://www.sra.org.uk/solicitors/standards-regulations/code-conduct-solicitors": {
        "jurisdiction": "Solicitors Regulation Authority regulatory jurisdiction",
        "source_role": "Official regulatory code; not independent legal authority",
        "currentness_finding": "Exact live-page bytes retrieved 2026-08-28; the 2026-08-14 source-ceiling version is not inferred.",
        "later_treatment_finding": "Regulatory-version/source-ceiling review remains an answer-release hold.",
    },
    "ukpga:1998:41": {
        "jurisdiction": "United Kingdom legislation",
        "source_role": "Primary legislation representation",
        "currentness_finding": "Official representation is byte-bound; currentness/effects beyond the exact section 18 text remain release-held.",
        "later_treatment_finding": "Not a judgment; amendment/effects review remains an answer-release hold.",
    },
    "neutral-citation:[2015] UKSC 11": {
        "jurisdiction": "United Kingdom Supreme Court; Scottish appeal",
        "source_role": "Supreme Court historical holding; binding subject to issue and later treatment",
        "currentness_finding": "Official judgment bytes and cited historical holding are exact; current-law use is not asserted.",
        "later_treatment_finding": "Comprehensive later-treatment review remains an answer-release hold.",
    },
    "neutral-citation:[2025] UKSC 22": {
        "jurisdiction": "United Kingdom Supreme Court; England and Wales appeal",
        "source_role": "Supreme Court historical holding; binding subject to issue and later treatment",
        "currentness_finding": "Official judgment bytes and exact Waller-Edwards holding are bound; Etridge is not relied upon.",
        "later_treatment_finding": "Post-decision later-treatment review remains an answer-release hold.",
    },
    "neutral-citation:[2023] EWCA Civ 884": {
        "jurisdiction": "England and Wales",
        "source_role": "Court of Appeal (Civil Division); binding appellate historical holding",
        "currentness_finding": "Official judgment identity and exact paragraphs are byte-bound; application facts remain held.",
        "later_treatment_finding": "Comprehensive later-treatment review remains an answer-release hold.",
    },
    "neutral-citation:[2019] UKPC 38": {
        "jurisdiction": "Privy Council appeal from Trinidad and Tobago",
        "source_role": "Persuasive only for the England-and-Wales target row; not relabelled binding",
        "currentness_finding": "Official JCPC judgment bytes and historical holding are exact.",
        "later_treatment_finding": "Later treatment and any England-and-Wales adoption remain answer-release holds.",
    },
    "uksi:2024:234": {
        "jurisdiction": "United Kingdom statutory instrument; extent/effects require provision-level review",
        "source_role": "Correct as-made LLP company-law amending instrument",
        "currentness_finding": "As-made identity is exact; commencement, application and later effects remain outside the narrowed proposition.",
        "later_treatment_finding": "Not a judgment; amendments/effects remain answer-release holds.",
    },
    "uksi:2009:1804": {
        "jurisdiction": "United Kingdom statutory instrument",
        "source_role": "LLP application regulations, subject to later amendments",
        "currentness_finding": "Official representation is byte-bound; applied-provision and later-effects review remains held.",
        "later_treatment_finding": "Not a judgment; amendment/effects review remains an answer-release hold.",
    },
    "ukpga:1981:54": {
        "jurisdiction": "England and Wales judicial-review jurisdiction",
        "source_role": "Primary legislation snapshot",
        "currentness_finding": "Sealed candidate currentness verified at 2026-08-14; the proposition is limited to exact sections 29A and 31.",
        "later_treatment_finding": "Not a judgment; unapplied effects, extent and current-law release remain held.",
    },
    "neutral-citation:[2026] EWHC 877 (Comm)": {
        "jurisdiction": "England and Wales",
        "source_role": "Commercial Court first-instance historical holding; not appellate authority",
        "currentness_finding": "Official judgment bytes and exact corporate-client passages are bound.",
        "later_treatment_finding": "Appeal/later-treatment review remains an answer-release hold.",
    },
    "neutral-citation:[2013] UKSC 61": {
        "jurisdiction": "United Kingdom Supreme Court",
        "source_role": "Supreme Court historical procedural-fairness holding",
        "currentness_finding": "Official judgment bytes and exact historical passages are bound; direct application to an internal university hearing is excluded.",
        "later_treatment_finding": "Comprehensive later-treatment review remains an answer-release hold.",
    },
    "uksi:2018:597:made": {
        "jurisdiction": "United Kingdom statutory instrument",
        "source_role": "Primary procedural safeguard in legal proceedings; analogy only outside its scope",
        "currentness_finding": "Sealed candidate currentness verified at 2026-08-14 for the exact snapshot; direct internal-hearing application is excluded.",
        "later_treatment_finding": "Not a judgment; later effects and current-law release remain held.",
    },
    "neutral-citation:[2017] UKSC 18": {
        "jurisdiction": "United Kingdom Supreme Court; England and Wales appeal",
        "source_role": "Supreme Court binding historical aggregation holding",
        "currentness_finding": "Official judgment bytes and exact historical holding are bound; policy wording and facts remain held.",
        "later_treatment_finding": "Comprehensive later-treatment review remains an answer-release hold.",
    },
    "neutral-citation:[2024] EWCA Civ 10": {
        "jurisdiction": "England and Wales",
        "source_role": "Court of Appeal (Civil Division) historical aggregation holding",
        "currentness_finding": "Official judgment bytes and exact historical holding are bound; present policy wording and facts remain held.",
        "later_treatment_finding": "Post-January-2024 later-treatment review remains an answer-release hold.",
    },
    "neutral-citation:[2021] EWCA Civ 565": {
        "jurisdiction": "England and Wales",
        "source_role": "Court of Appeal (Civil Division) historical security-for-costs holding",
        "currentness_finding": "Official judgment bytes and exact historical holding are bound; unidentified policy terms are excluded.",
        "later_treatment_finding": "Comprehensive later-treatment review remains an answer-release hold.",
    },
    "neutral-citation:[2026] UKSC 24": {
        "jurisdiction": "United Kingdom Supreme Court; England and Wales procedural context",
        "source_role": "Supreme Court historical description of GLO machinery",
        "currentness_finding": "Official judgment representation and exact passages are bound; other distribution regimes are excluded.",
        "later_treatment_finding": "Post-decision later treatment remains an answer-release hold.",
    },
}


# Short verbatim excerpts are sealed only to prove that each narrowed
# proposition is anchored in the hash-pinned official representation.  The
# builder verifies their normalized text against the primary bytes; they are
# not answer-release quotations and remain owner-unadopted proposals.
SOURCE_SUPPORTING_EXCERPTS: dict[str, tuple[str, ...]] = {
    "neutral-citation:[2016] EWCA Civ 982": (
        "the question was one of ascertaining the intentions of the parties and thus of the true construction of the contract",
    ),
    "ukpga:1982:29": (
        "there is an implied term that the supplier will carry out the service with reasonable care and skill.",
    ),
    "neutral-citation:[2022] EWCA Crim 832": (
        "she genuinely and reasonably believed that if she did not do so, she or a member of her immediate family would be killed or seriously injured, either immediately or almost immediately.",
        "immediacy and the inability to take evasive action is a key aspect of the defence.",
    ),
    "official-url:https://www.sra.org.uk/solicitors/standards-regulations/code-conduct-solicitors": (
        "You ensure that the service you provide to clients is competent and delivered in a timely manner.",
        "You maintain your competence to carry out your role and keep your professional knowledge and skills up to date.",
        "you effectively supervise work being done for clients",
    ),
    "ukpga:1998:41": (
        "any conduct on the part of one or more undertakings which amounts to the abuse of a dominant position in a market is prohibited if it may affect trade within the United Kingdom.",
    ),
    "neutral-citation:[2015] UKSC 11": (
        "The doctor is therefore under a duty to take reasonable care to ensure that the patient is aware of any material risks involved in any recommended treatment, and of any reasonable alternative or variant treatments.",
    ),
    "neutral-citation:[2025] UKSC 22": (
        "A tripartite non-commercial surety transaction carries with it an increased risk of undue influence having been exercised",
        "either there is, on the face of the non-commercial transaction, a surety element giving rise to a heightened risk of undue influence or there is not.",
    ),
    "neutral-citation:[2023] EWCA Civ 884": (
        "the law treats a given statement as having a single meaning, to be identified by a standard of the hypothetical reasonable reader or viewer.",
        "the words used are such as would reasonably lead persons acquainted with the claimant to believe that he was the person referred to",
    ),
    "neutral-citation:[2019] UKPC 38": (
        "for two statements made by the same person, but published at different times, to be aggregated for the purpose of giving rise in conjunction to a completed cause of action in defamation, there must in the mind of the reasonable reader be created a sufficient nexus, connection or association between the two of them",
    ),
    "uksi:2024:234": (
        "The Limited Liability Partnerships (Application of Companies Act 2006) Regulations 2009 are amended in accordance with regulations 6 to 46.",
    ),
    "uksi:2009:1804": (
        "The Limited Liability Partnerships (Application of Companies Act 2006) Regulations 2009",
        "PART 4 AN LLP'S REGISTERED OFFICE",
    ),
    "ukpga:1981:54": (
        "An application to the High Court for one or more of the following forms of relief, namely— a a mandatory, prohibiting or quashing order",
        "the High Court may award to the applicant damages, restitution or the recovery of a sum due if",
    ),
    "neutral-citation:[2026] EWHC 877 (Comm)": (
        "those employees of a company authorised to seek and receive legal advice on its behalf",
    ),
    "neutral-citation:[2013] UKSC 61": (
        "The question whether fairness requires a prisoner to be given an oral hearing is different from the question whether he has a particular likelihood of being released or transferred to open conditions",
    ),
    "uksi:2018:597:made": (
        "restrict access to any document containing a trade secret or alleged trade secret submitted by the parties or third parties, in whole or in part, to a limited number of persons",
        "a non-confidential version of any judicial decision, in which the passages containing trade secrets have been removed or redacted.",
    ),
    "neutral-citation:[2017] UKSC 18": (
        "there must be some inter-connection between the matters or transactions, or in other words that they must in some way fit together",
    ),
    "neutral-citation:[2024] EWCA Civ 10": (
        "The so-called 'unities' are not to be applied mechanistically",
        "Whether any and if so what causal link is required between the unifying factor and the losses must depend on the linking words used.",
    ),
    "neutral-citation:[2021] EWCA Civ 565": (
        "This is a pre-condition or gateway.",
        "the amount of security (r 25.12(3)(a)); the manner in which it is to be provided (r 25.12(3)(b)(i)); and the time within which it must be provided",
    ),
    "neutral-citation:[2026] UKSC 24": (
        "a GLO as an order made to provide for the case management of claims which give rise to common or related issues of fact or law",
        "they can join the rest of the group by being placed on the group register which is maintained by the court registry.",
    ),
}


def _logical_member(root_alias: str, path: Path) -> str:
    if root_alias == "LAW_SOURCE_ROOT":
        return path.relative_to(LAW_ROOT).as_posix()
    return path.relative_to(PROJECT_ROOT).as_posix()


def _normalise_evidence_text(value: str) -> str:
    value = html.unescape(unicodedata.normalize("NFKC", value))
    return re.sub(r"\s+", " ", value).strip()


def _binding_path(binding: dict[str, Any]) -> Path:
    member = Path(binding["representation_member"])
    if member.is_absolute() or ".." in member.parts:
        raise ValueError("source_binding_member_not_relative")
    if binding["root_alias"] == "LAW_SOURCE_ROOT":
        return LAW_ROOT / member
    if binding["root_alias"] in {
        "PROJECT_ROOT",
        "PROJECT_RESEARCH_QUARANTINE",
        "PROJECT_APPROVED_SOURCE_ROOT",
    }:
        return PROJECT_ROOT / member
    raise ValueError("unknown_source_binding_root_alias")


def _representation_text(binding: dict[str, Any]) -> tuple[str, str]:
    path = _binding_path(binding)
    raw = path.read_bytes()
    suffix = path.suffix.lower()
    if suffix == ".xml":
        text = " ".join(ElementTree.fromstring(raw).itertext())
        mode = "XML_ITERATION_TEXT"
    elif suffix in {".html", ".htm"}:
        text = BeautifulSoup(raw, "html.parser").get_text(" ")
        mode = "HTML_PARSER_VISIBLE_TEXT"
    elif suffix == ".pdf":
        reader = PdfReader(io.BytesIO(raw))
        if not reader.pages:
            raise ValueError("primary_representation_pdf_empty")
        text = "\n".join(page.extract_text() or "" for page in reader.pages)
        mode = "PDF_TEXT_EXTRACTION"
    else:
        text = raw.decode("utf-8", errors="strict")
        mode = "UTF8_TEXT"
    normalized = _normalise_evidence_text(text)
    if len(normalized) < 40:
        raise ValueError("primary_representation_text_empty")
    return normalized, mode


def _build_source_resolver(
    baseline_sources: dict[str, Any],
    quarantine: dict[str, Any],
    candidate: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    resolved: dict[str, dict[str, Any]] = {}

    for record in baseline_sources["records"]:
        member_path = PROJECT_ROOT / record["quarantine_path"]
        if member_path.is_symlink() or _file_sha256(member_path) != record["raw_sha256"]:
            raise ValueError(f"baseline_source_byte_mismatch:{record['member']}")
        identity = record["authority_identity_id"]
        resolved[identity] = {
            "authority_identity_id": identity,
            "source_origin": "SEALED_HELD_MISSING_R2_QUARANTINE",
            "root_alias": "PROJECT_ROOT",
            "representation_member": record["quarantine_path"],
            "representation_file_sha256": record["raw_sha256"],
            "media_type": record["media_type"],
            "official_url": record["official_url"],
            "baseline_source_record_content_sha256": record["record_content_sha256"],
            "primary_official_bytes_bound": record["evidence_role"]
            not in {
                "FAILED_ROUTE_DIAGNOSTIC_NOT_EVIDENCE",
                "MISIDENTIFIED_SOURCE_DIAGNOSTIC_NOT_ADMISSION",
            },
        }

    for record in quarantine["records"]:
        if record.get("result") != "DOWNLOADED_QUARANTINED_BOUND" or not record.get(
            "quarantine_member"
        ):
            continue
        path = SOURCE_QUARANTINE_ROOT / record["quarantine_member"]
        if path.is_symlink() or _file_sha256(path) != record["raw_sha256"]:
            raise ValueError(f"source_quarantine_byte_mismatch:{record['record_id']}")
        identity = record["authority_identity_id"]
        resolved[identity] = {
            "authority_identity_id": identity,
            "source_origin": "SEALED_142_SOURCE_QUARANTINE",
            "root_alias": "PROJECT_ROOT",
            "representation_member": path.relative_to(PROJECT_ROOT).as_posix(),
            "representation_file_sha256": record["raw_sha256"],
            "media_type": record["content_type"],
            "official_url": record["official_urls"][0],
            "quarantine_record_content_sha256": record["record_content_sha256"],
            "proposed_source_version_id": record.get("proposed_source_version_id"),
            "primary_official_bytes_bound": True,
        }

    candidate_by_id = {source["authority_identity_id"]: source for source in candidate["sources"]}
    for identity, (root_alias, path, expected_sha) in RAW_OVERRIDES.items():
        if path.is_symlink() or not path.is_file() or _file_sha256(path) != expected_sha:
            raise ValueError(f"raw_override_byte_mismatch:{identity}")
        candidate_source = candidate_by_id.get(identity)
        resolved[identity] = {
            "authority_identity_id": identity,
            "source_origin": "SEALED_CANDIDATE_PRIMARY_OFFICIAL_REPRESENTATION",
            "root_alias": root_alias,
            "representation_member": _logical_member(root_alias, path),
            "representation_file_sha256": expected_sha,
            "media_type": "application/xml",
            "official_url": candidate_source.get("canonical_url") if candidate_source else None,
            "source_version_id": candidate_source.get("source_version_id")
            if candidate_source
            else None,
            "candidate_catalogue_content_sha256": candidate_source.get("content_sha256")
            if candidate_source
            else None,
            "primary_official_bytes_bound": True,
        }

    return resolved


def _authority_identity_candidates(authority: dict[str, Any]) -> set[str]:
    candidates: set[str] = set()
    citation = str(authority.get("citation", ""))
    neutral = re.search(
        r"\[(\d{4})\]\s+(UKSC|UKPC|EWCA Civ|EWCA Crim|EWHC)\s+(\d+)(?:\s+\(([^)]+)\))?",
        citation,
    )
    if neutral:
        suffix = f" ({neutral.group(4)})" if neutral.group(4) else ""
        candidates.add(
            f"neutral-citation:[{neutral.group(1)}] {neutral.group(2)} {neutral.group(3)}{suffix}"
        )
    official_url = str(authority.get("official_url", "")).rstrip("/")
    if official_url:
        candidates.add(f"official-url:{official_url}")
        legislation = re.search(r"legislation\.gov\.uk/(ukpga|uksi)/(\d{4})/(\d+)", official_url)
        if legislation:
            identity = ":".join(legislation.groups())
            candidates.add(identity)
            if legislation.group(1) == "uksi":
                candidates.add(f"{identity}:made")
    return candidates


def _owner_authority_index(
    owner_packet: dict[str, Any], row_ids: set[str]
) -> dict[tuple[str, str], list[dict[str, Any]]]:
    output: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for decision in owner_packet["decisions"]:
        if decision["row_id"] not in row_ids:
            continue
        for component in decision["source_research_record"]["atomic_components"]:
            for authority in component["authorities"]:
                identities = _authority_identity_candidates(authority)
                explicit_identity = authority.get(
                    "canonical_authority_identity_id"
                ) or authority.get("authority_identity_id")
                if explicit_identity:
                    identities.add(explicit_identity)
                for identity in identities:
                    output.setdefault((decision["row_id"], identity), []).append(authority)
    return output


def _locator_attested(
    row_id: str,
    identity: str,
    locator: str,
    baseline_source_by_id: dict[str, dict[str, Any]],
    owner_authorities: dict[tuple[str, str], list[dict[str, Any]]],
) -> bool:
    upstream = []
    for authority in owner_authorities.get((row_id, identity), []):
        upstream.extend(authority.get("exact_locators", []))
    baseline_record = baseline_source_by_id.get(identity)
    if baseline_record:
        upstream.extend(baseline_record.get("exact_locators", []))

    def normalized(value: str) -> str:
        result = value.lower().replace("–", "-").replace("§", "section")
        result = re.sub(r"\b(?:para|paras|paragraph|paragraphs)\b", "paragraphs", result)
        result = re.sub(r"^ss?\s+", "section ", result)
        result = re.sub(r"^regs?\s+", "regulation ", result)
        return re.sub(r"\s+", " ", result).strip()

    wanted = normalized(locator)
    return any(wanted == normalized(item) for item in upstream)


def build_advisory() -> tuple[dict[str, Any], dict[str, Any]]:
    r3 = _load(R3_PATH, R3_FILE_SHA256)
    owner_packet = _load(OWNER_PACKET_PATH, OWNER_PACKET_FILE_SHA256)
    baseline = _load(BASELINE_ADVISORY_PATH, BASELINE_ADVISORY_FILE_SHA256)
    baseline_sources = _load(BASELINE_SOURCE_MANIFEST_PATH, BASELINE_SOURCE_MANIFEST_FILE_SHA256)
    quarantine = _load(SOURCE_QUARANTINE_MANIFEST_PATH, SOURCE_QUARANTINE_MANIFEST_FILE_SHA256)
    candidate = _load(CANDIDATE_MANIFEST_PATH, CANDIDATE_MANIFEST_FILE_SHA256)
    execution = _load(EXECUTION_AUTHORITY_PATH, EXECUTION_AUTHORITY_FILE_SHA256)

    _verify_content(r3, "artifact_content_sha256", R3_CONTENT_SHA256)
    _verify_content(owner_packet, "artifact_content_sha256", OWNER_PACKET_CONTENT_SHA256)
    _verify_content(baseline, "artifact_content_sha256", BASELINE_ADVISORY_CONTENT_SHA256)
    _verify_content(
        baseline_sources, "artifact_content_sha256", BASELINE_SOURCE_MANIFEST_CONTENT_SHA256
    )
    _verify_content(
        quarantine, "manifest_content_sha256", SOURCE_QUARANTINE_MANIFEST_CONTENT_SHA256
    )
    _verify_content(execution, "artifact_content_sha256", EXECUTION_AUTHORITY_CONTENT_SHA256)
    if (
        candidate.get("source_count") != 251
        or candidate.get("manifest_sha256") != CANDIDATE_MANIFEST_CONTENT_SHA256
    ):
        raise ValueError("candidate_source_count_invalid")
    if (
        execution.get("status") != "AVAILABLE_UNSPENT"
        or execution.get("total_execution_chain_count") != 1
        or execution.get("execution_chain_consumed_count") != 0
        or execution.get("execution_chain_remaining_count") != 1
    ):
        raise ValueError("execution_chain_not_unspent")

    row_ids = tuple(row["row_id"] for row in baseline["rows"])
    row_id_set = set(row_ids)
    if len(row_ids) != 28 or len(row_id_set) != 28:
        raise ValueError("baseline_28_row_cohort_invalid")
    r3_by_id = {row["row_id"]: row for row in r3["rows"]}
    owner_by_id = {row["row_id"]: row for row in owner_packet["decisions"]}
    if row_id_set - r3_by_id.keys() or row_id_set - owner_by_id.keys():
        raise ValueError("cohort_missing_from_sealed_inputs")

    blocker_keys = {
        (row_id, component["component_ordinal"])
        for row_id in row_ids
        for component in r3_by_id[row_id]["blocking_components"]
    }
    if blocker_keys != set(RECOMMENDATIONS) or len(blocker_keys) != 41:
        raise ValueError("recommendation_map_not_exact_41_blockers")

    source_resolver = _build_source_resolver(baseline_sources, quarantine, candidate)
    baseline_source_by_id = {
        row["authority_identity_id"]: row for row in baseline_sources["records"]
    }
    owner_authorities = _owner_authority_index(owner_packet, row_id_set)

    source_binding_cache: dict[str, dict[str, Any]] = {}
    source_text_cache: dict[str, str] = {}
    source_extraction_mode_cache: dict[str, str] = {}
    rows: list[dict[str, Any]] = []
    action_counts: Counter[str] = Counter()
    resolved_rows = 0
    rewrite_or_exclusion_rows = 0
    formerly_retained_rows = 0

    for row_id in row_ids:
        r3_row = r3_by_id[row_id]
        baseline_row = next(row for row in baseline["rows"] if row["row_id"] == row_id)
        owner_row = owner_by_id[row_id]
        topology = baseline_row["topology_disposition"]
        if topology == STATUS_RESOLVED:
            resolved_rows += 1
        elif topology == STATUS_REWRITE:
            rewrite_or_exclusion_rows += 1
        elif topology == STATUS_RETAINED:
            formerly_retained_rows += 1
        else:
            raise ValueError(f"unknown_baseline_topology:{row_id}")

        recommendations: list[dict[str, Any]] = []
        covered_keys: list[str] = []
        row_release_holds: set[str] = set()
        for component in r3_row["blocking_components"]:
            ordinal = component["component_ordinal"]
            spec = RECOMMENDATIONS[(row_id, ordinal)]
            action_counts[spec["action"]] += 1
            blocker_key = f"{row_id}#{ordinal}#{component['proposition_text_sha256']}"
            covered_keys.append(blocker_key)
            span_proposals: list[dict[str, Any]] = []
            for span_ordinal, source_spec in enumerate(spec["sources"], start=1):
                identity = source_spec["authority_identity_id"]
                if identity not in source_resolver or identity not in SOURCE_ASSESSMENTS:
                    raise ValueError(f"rewrite_source_unresolved:{row_id}:{identity}")
                binding = source_binding_cache.get(identity)
                if binding is None:
                    source_text, extraction_mode = _representation_text(source_resolver[identity])
                    source_text_cache[identity] = source_text
                    source_extraction_mode_cache[identity] = extraction_mode
                    binding = _seal(
                        {
                            "schema": "legalbot.v111.phase2a.held-missing-28-source-binding.v1",
                            **source_resolver[identity],
                            "normalized_representation_text_sha256": _sha256(source_text.encode()),
                            "representation_text_extraction_mode": extraction_mode,
                            "legal_assessment_recommendation": SOURCE_ASSESSMENTS[identity],
                            "assessment_owner_adoption_required": True,
                            "assessment_owner_adopted": False,
                            "qualification_scope": "EXACT_HISTORICAL_OR_DATED_SNAPSHOT_PROPOSITION_ONLY",
                            "answer_release_eligible": False,
                        },
                        "record_content_sha256",
                    )
                    source_binding_cache[identity] = binding
                excerpts = SOURCE_SUPPORTING_EXCERPTS.get(identity)
                if not excerpts:
                    raise ValueError(f"supporting_excerpt_missing:{row_id}:{identity}")
                excerpt_records = []
                for excerpt in excerpts:
                    normalized_excerpt = _normalise_evidence_text(excerpt)
                    if normalized_excerpt not in source_text_cache[identity]:
                        raise ValueError(
                            f"supporting_excerpt_not_in_source:{row_id}:{identity}:"
                            f"{_sha256(normalized_excerpt.encode())}"
                        )
                    excerpt_records.append(
                        {
                            "text": excerpt,
                            "normalized_text_sha256": _sha256(normalized_excerpt.encode()),
                            "verified_in_primary_official_bytes": True,
                        }
                    )
                for locator in source_spec["exact_locators"]:
                    if not _locator_attested(
                        row_id,
                        identity,
                        locator,
                        baseline_source_by_id,
                        owner_authorities,
                    ):
                        raise ValueError(f"locator_not_attested:{row_id}:{identity}:{locator}")
                assessment = SOURCE_ASSESSMENTS[identity]
                currentness_text = assessment["currentness_finding"].lower()
                later_text = assessment["later_treatment_finding"].lower()
                if (
                    "hold" in currentness_text
                    or "not asserted" in currentness_text
                    or "not inferred" in currentness_text
                ):
                    row_release_holds.add("CURRENT_LAW_CURRENTNESS_RELEASE_HOLD")
                if "hold" in later_text:
                    row_release_holds.add("LATER_TREATMENT_RELEASE_HOLD")
                span_proposals.append(
                    _seal(
                        {
                            "schema": "legalbot.v111.phase2a.held-missing-28-evidence-span-proposal.v1",
                            "span_ordinal": span_ordinal,
                            "authority_identity_id": identity,
                            "source_binding_content_sha256": binding["record_content_sha256"],
                            "exact_locators": source_spec["exact_locators"],
                            "locator_attested_by_sealed_upstream": True,
                            "primary_official_bytes_bound": binding["primary_official_bytes_bound"],
                            "supporting_excerpts": excerpt_records,
                            "normalization": "UNICODE_NFKC_HTML_UNESCAPE_COLLAPSE_WHITESPACE",
                            "normalized_representation_text_sha256": binding[
                                "normalized_representation_text_sha256"
                            ],
                            "jurisdiction": assessment["jurisdiction"],
                            "source_role": assessment["source_role"],
                            "currentness_finding": assessment["currentness_finding"],
                            "later_treatment_finding": assessment["later_treatment_finding"],
                            "owner_adoption_required": True,
                            "owner_adopted": False,
                            "proposal_payload_immutable": True,
                            "frozen_for_execution": False,
                        },
                        "span_proposal_content_sha256",
                    )
                )

            recommendation = _seal(
                {
                    "schema": "legalbot.v111.phase2a.held-missing-28-blocker-recommendation.v1",
                    "blocker_key": blocker_key,
                    "row_id": row_id,
                    "component_ordinal": ordinal,
                    "baseline_proposition": component["proposition"],
                    "baseline_proposition_text_sha256": component["proposition_text_sha256"],
                    "baseline_support_fit": component["support_fit"],
                    "baseline_deterministic_blocker_reason_code": component[
                        "deterministic_blocker_reason_code"
                    ],
                    "action": spec["action"],
                    "after_propositions": [
                        {
                            "proposition": proposition,
                            "proposition_text_sha256": _sha256(proposition.encode()),
                            "proposed_support_scope": "FULL_FOR_EXACT_HISTORICAL_OR_DATED_SNAPSHOT_PROPOSITION_IF_OWNER_ADOPTED",
                            "current_law_answer_release_eligible": False,
                        }
                        for proposition in spec["after_propositions"]
                    ],
                    "excluded_scope": spec["excluded_scope"],
                    "reason": spec["reason"],
                    "issue_coverage": spec.get("issue_coverage"),
                    "evidence_span_proposals": span_proposals,
                    "clears_exact_original_blocker_if_owner_adopted": True,
                    "owner_adoption_required": True,
                    "owner_adopted": False,
                    "applied": False,
                    "technical_success_not_predeclared": True,
                },
                "recommendation_content_sha256",
            )
            recommendations.append(recommendation)

        full_components = []
        for component_ordinal, component in enumerate(
            owner_row["source_research_record"]["atomic_components"], start=1
        ):
            if component["support_fit"] != "FULL":
                continue
            proposition = component["proposition"]
            full_components.append(
                {
                    "component_ordinal": component_ordinal,
                    "proposition": proposition,
                    "proposition_text_sha256": _sha256(proposition.encode()),
                    "support_fit": "FULL_UPSTREAM_OWNER_PACKET_RECOMMENDATION_NOT_YET_APPLIED",
                    "authority_identity_ids": sorted(
                        authority.get("canonical_authority_identity_id")
                        or authority.get("authority_identity_id")
                        or authority["citation"]
                        for authority in component["authorities"]
                    ),
                }
            )

        row_record = _seal(
            {
                "schema": "legalbot.v111.phase2a.held-missing-28-row-substantive-remediation.v1",
                "row_id": row_id,
                "issue_label": baseline_row["issue_label"],
                "baseline_topology_disposition": topology,
                "baseline_advisory_row_record_content_sha256": baseline_row[
                    "row_record_content_sha256"
                ],
                "r3_row_record_content_sha256": r3_row["record_content_sha256"],
                "owner_packet_decision_content_sha256": owner_row["decision_content_sha256"],
                "original_blocker_count": len(r3_row["blocking_components"]),
                "covered_blocker_keys": covered_keys,
                "blocker_recommendations": recommendations,
                "preexisting_full_components_preserved": full_components,
                "all_raw_holds_preserved": [
                    {
                        "record_content_sha256": hold["record_content_sha256"],
                        "hold_text_sha256": hold["hold_text_sha256"],
                        "classification": "UNCLASSIFIED_NON_OPERATIVE",
                    }
                    for hold in r3_row["unclassified_unresolved_holds"]
                ],
                "retained_release_hold_codes": sorted(row_release_holds),
                "qualification_effect_if_exactly_owner_adopted": "ORIGINAL_R3_SUPPORT_BLOCKERS_CLEARED_BY_EXACT_REWRITE_OR_EXCLUSION_ONLY; SUCCESSOR_ALL585_MUST_VERIFY",
                "residual_qualification_blocker_predeclared": False,
                "answer_release_eligible": False,
                "owner_adoption_required": True,
                "owner_adopted": False,
                "applied": False,
                "technical_success_not_predeclared": True,
            },
            "record_content_sha256",
        )
        rows.append(row_record)

    if (resolved_rows, rewrite_or_exclusion_rows, formerly_retained_rows) != (17, 7, 4):
        raise ValueError("baseline_topology_counts_invalid")
    if action_counts != {
        "REPLACE_WITH_EXACT_NARROW_SOURCE_BOUND_PROPOSITION": 17,
        "EXCLUDE_EXACT_UNSUPPORTED_COMPONENT": 24,
    }:
        raise ValueError("recommendation_action_counts_invalid")

    all_covered = [key for row in rows for key in row["covered_blocker_keys"]]
    if len(all_covered) != 41 or len(set(all_covered)) != 41:
        raise ValueError("blocker_coverage_not_exhaustive_unique")
    row_action_categories: Counter[str] = Counter()
    for row in rows:
        actions = {recommendation["action"] for recommendation in row["blocker_recommendations"]}
        if len(actions) == 2:
            row_action_categories["MIXED_REWRITE_AND_EXCLUSION"] += 1
        elif next(iter(actions)) == "REPLACE_WITH_EXACT_NARROW_SOURCE_BOUND_PROPOSITION":
            row_action_categories["REWRITE_ONLY"] += 1
        else:
            row_action_categories["EXCLUSION_ONLY"] += 1
    if row_action_categories != {
        "REWRITE_ONLY": 8,
        "EXCLUSION_ONLY": 14,
        "MIXED_REWRITE_AND_EXCLUSION": 6,
    }:
        raise ValueError("row_action_category_counts_invalid")

    nine_records = [
        record
        for record in baseline_sources["records"]
        if record["evidence_role"] == "PROPOSED_OWNER_ADMISSION_REPRESENTATION"
    ]
    if len(nine_records) != 9:
        raise ValueError("nine_proposed_representation_count_invalid")
    nine_bindings = []
    for record in sorted(nine_records, key=lambda value: value["member"]):
        identity = record["authority_identity_id"]
        binding_material = {
            "schema": "legalbot.v111.phase2a.held-missing-28-source-binding.v1",
            "authority_identity_id": identity,
            "source_origin": "SEALED_HELD_MISSING_R2_QUARANTINE",
            "root_alias": "PROJECT_ROOT",
            "representation_member": record["quarantine_path"],
            "representation_file_sha256": record["raw_sha256"],
            "media_type": record["media_type"],
            "official_url": record["official_url"],
            "baseline_source_record_content_sha256": record["record_content_sha256"],
            "primary_official_bytes_bound": True,
        }
        representation_text, extraction_mode = _representation_text(binding_material)
        exact_binding = _seal(
            {
                **binding_material,
                "normalized_representation_text_sha256": _sha256(representation_text.encode()),
                "representation_text_extraction_mode": extraction_mode,
                "legal_assessment_recommendation": SOURCE_ASSESSMENTS.get(
                    identity,
                    {
                        "jurisdiction": record["jurisdiction_finding"],
                        "source_role": record["source_role_finding"],
                        "currentness_finding": record["currentness_finding"],
                        "later_treatment_finding": record["later_treatment_finding"],
                    },
                ),
                "assessment_owner_adoption_required": True,
                "assessment_owner_adopted": False,
                "qualification_scope": "EXACT_HISTORICAL_OR_DATED_SNAPSHOT_PROPOSITION_ONLY",
                "answer_release_eligible": False,
            },
            "record_content_sha256",
        )
        nine_bindings.append(
            _seal(
                {
                    "schema": "legalbot.v111.phase2a.held-missing-nine-proposed-representation.v1",
                    "member": record["member"],
                    "authority_identity_id": identity,
                    "representation_file_sha256": record["raw_sha256"],
                    "representation_byte_identity_verified": True,
                    "source_binding": exact_binding,
                    "source_binding_content_sha256": exact_binding["record_content_sha256"],
                    "exact_locators": record["exact_locators"],
                    "affected_row_ids": record["affected_row_ids"],
                    "admission_recommended": True,
                    "owner_adoption_required": True,
                    "source_admitted": False,
                    "materialized": False,
                    "indexed": False,
                    "embedded": False,
                },
                "record_content_sha256",
            )
        )

    source_manifest = _seal(
        {
            "schema": "legalbot.v111.phase2a.held-missing-nine-proposed-representation-bindings.v1",
            "status": "CREATE_ONLY_EXACT_BINDINGS_NOT_ADMITTED_NOT_MATERIALIZED",
            "representation_count": 9,
            "representations": nine_bindings,
            "identity_correction": {
                "row_id": "live60-q37:issue-06",
                "accepted_identity_id": "uksi:2024:234",
                "accepted_title": "Limited Liability Partnerships (Application of Company Law) Regulations 2024",
                "rejected_identity_id": "uksi:2024:1377",
                "rejected_mapping": True,
                "automatic_substitution": False,
                "owner_adoption_required": True,
                "commencement_effects_release_hold_retained": True,
            },
            "recursive_no_execution_control": _recursive_no_execution_control(),
            **NO_EXECUTION,
        }
    )

    advisory = _seal(
        {
            "schema": "legalbot.v111.phase2a.held-missing-28-substantive-remediation-advisory.v1",
            "status": "CREATE_ONLY_EXACT_REMEDIATION_READY_FOR_OWNER_CONSOLIDATION_NOT_ADOPTED",
            "phase_scope": "PHASE2A_ONLY",
            "advisory_date": "2026-08-28",
            "input_bindings": {
                "r3_report_content_sha256": R3_CONTENT_SHA256,
                "owner_packet_content_sha256": OWNER_PACKET_CONTENT_SHA256,
                "baseline_held_missing_r2_content_sha256": BASELINE_ADVISORY_CONTENT_SHA256,
                "baseline_source_manifest_content_sha256": BASELINE_SOURCE_MANIFEST_CONTENT_SHA256,
                "source_quarantine_manifest_content_sha256": SOURCE_QUARANTINE_MANIFEST_CONTENT_SHA256,
                "execution_authority_content_sha256": EXECUTION_AUTHORITY_CONTENT_SHA256,
            },
            "counts": {
                "row_count": 28,
                "original_blocker_count": 41,
                "exact_source_bound_rewrite_count": 17,
                "exact_exclusion_count": 24,
                "source_topology_resolved_row_count": 17,
                "invalid_missing_source_requirement_row_count": 7,
                "formerly_retained_targeted_substitute_row_count": 4,
                "nine_proposed_representation_count": 9,
                "unique_rewrite_source_count": len(source_binding_cache),
                "residual_qualification_blocker_predeclared_count": 0,
                "row_action_category_counts": dict(sorted(row_action_categories.items())),
            },
            "formerly_retained_exact_treatments": {
                "live30-q28:issue-05": "WALLER_EDWARDS_ONLY_ETRIDGE_BYTES_NOT_CLAIMED_FACT_HOLDS_RETAINED",
                "live60-q40:issue-09": "SENIOR_COURTS_ACT_FINAL_REMEDIES_ONLY_INTERIM_TEST_EXCLUDED",
                "live60-q42:issue-03": "AABAR_CORPORATE_CLIENT_HISTORICAL_RULE_EMPLOYEE_WAIVER_FORMULATION_EXCLUDED",
                "live60-q50:issue-06": "AIG_AND_VARIOUS_EATERIES_EXACT_WORDING_DEPENDENT_AGGREGATION_LLOYDS_BYTES_NOT_CLAIMED",
            },
            "legal_accuracy_contract": {
                "historical_or_dated_snapshot_support_is_not_current_law_release": True,
                "jurisdiction_and_source_role_never_upgraded": True,
                "persuasive_source_never_relabelled_binding": True,
                "regulatory_material_never_relabelled_independent_legal_authority": True,
                "matter_facts_never_converted_to_source_support": True,
                "retained_release_holds_do_not_clear_answer_release": True,
                "technical_success_not_predeclared": True,
                "new_blanket_fallback_created": False,
                "only_original_two_fallback_rows_remain_fallback_eligible": True,
            },
            "source_bindings": sorted(
                source_binding_cache.values(), key=lambda value: value["authority_identity_id"]
            ),
            "rows": rows,
            "decision_boundary": {
                "owner_must_adopt_exact_future_consolidated_digest": True,
                "execution_chain_total": 1,
                "execution_chain_consumed": 0,
                "execution_chain_remaining": 1,
                "no_second_chain_created": True,
                "all585_must_recompute_after_any_adoption": True,
            },
            "recursive_no_execution_control": _recursive_no_execution_control(),
            **NO_EXECUTION,
        }
    )

    for artifact in (advisory, source_manifest):
        violations = _recursive_no_execution_violations(artifact)
        if violations:
            raise ValueError("recursive_no_execution_violation:" + ",".join(violations))
        rendered = json.dumps(artifact, ensure_ascii=False, sort_keys=True)
        if _PRIVATE_PATH.search(rendered):
            raise ValueError("review_artifact_contains_private_or_old_project_path")
    return advisory, source_manifest


def publish(output_root: Path = OUTPUT_ROOT) -> dict[str, str]:
    if output_root.exists():
        raise FileExistsError(f"create-only output already exists:{output_root}")
    advisory, source_manifest = build_advisory()
    output_root.parent.mkdir(parents=True, exist_ok=True)
    temp_root = Path(tempfile.mkdtemp(prefix=f".{output_root.name}-", dir=output_root.parent))
    try:
        artifacts = {
            ADVISORY_NAME: advisory,
            SOURCE_MANIFEST_NAME: source_manifest,
        }
        for name, value in artifacts.items():
            (temp_root / name).write_bytes(_pretty_json(value))
            os.chmod(temp_root / name, 0o600)
        package_records = [
            {
                "name": name,
                "file_sha256": _file_sha256(temp_root / name),
                "content_sha256": value["artifact_content_sha256"],
                "bytes": (temp_root / name).stat().st_size,
            }
            for name, value in sorted(artifacts.items())
        ]
        package = _seal(
            {
                "schema": "legalbot.v111.phase2a.held-missing-28-substantive-remediation-package.v1",
                "status": "CREATE_ONLY_NON_AUTHORIZING_NOT_EXECUTED",
                "artifact_count": len(package_records),
                "artifacts": package_records,
                "recursive_no_execution_control": _recursive_no_execution_control(),
                **NO_EXECUTION,
            },
            "package_content_sha256",
        )
        violations = _recursive_no_execution_violations(package)
        if violations:
            raise ValueError("recursive_no_execution_violation:" + ",".join(violations))
        (temp_root / PACKAGE_NAME).write_bytes(_pretty_json(package))
        os.chmod(temp_root / PACKAGE_NAME, 0o600)
        checksum_names = sorted([*artifacts, PACKAGE_NAME])
        (temp_root / CHECKSUMS_NAME).write_text(
            "".join(f"{_file_sha256(temp_root / name)}  {name}\n" for name in checksum_names),
            encoding="utf-8",
        )
        os.chmod(temp_root / CHECKSUMS_NAME, 0o600)
        os.chmod(temp_root, 0o700)
        temp_root.rename(output_root)
    except Exception:
        shutil.rmtree(temp_root, ignore_errors=True)
        raise
    return {
        "status": "CREATE_ONLY_NON_AUTHORIZING_NOT_EXECUTED",
        "advisory": str(output_root / ADVISORY_NAME),
        "source_manifest": str(output_root / SOURCE_MANIFEST_NAME),
        "package": str(output_root / PACKAGE_NAME),
        "checksums": str(output_root / CHECKSUMS_NAME),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=OUTPUT_ROOT)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    advisory, source_manifest = build_advisory()
    if args.dry_run:
        print(
            json.dumps(
                {
                    "advisory_content_sha256": advisory["artifact_content_sha256"],
                    "source_manifest_content_sha256": source_manifest["artifact_content_sha256"],
                    "counts": advisory["counts"],
                },
                sort_keys=True,
            )
        )
        return 0
    result = publish(args.output_root.resolve())
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
