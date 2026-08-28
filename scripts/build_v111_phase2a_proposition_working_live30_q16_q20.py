#!/usr/bin/env python3
"""Build the non-authorizing proposition draft for live30 q16-q20.

This is a conservative working ledger.  It freezes proposition questions and
research routes but deliberately selects no evidence, applies no owner outcome,
and does not change the candidate or any release gate.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OWNER_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
BLOCKED_ROOT = OWNER_ROOT / "LegalBot-Phase2A-2026-08-27-final-owner-review-blocked"
QUALIFICATION_PATH = BLOCKED_ROOT / (
    "machine/qualification/DETERMINISTIC-ALL585-QUALIFICATION.json"
)
CASES_PATH = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1/cases.jsonl"
CROSSWALK_PATH = BLOCKED_ROOT / (
    "machine/crosswalk/DETERMINISTIC-EXACT-SPAN-PACKETS-364.json"
)
R100_PATH = OWNER_ROOT / (
    "LegalBot-Phase2AB-2026-08-26-r100-debugged-held-exact-span-repair/"
    "REPAIRED-EXACT-SPAN-ADVISORY-361.json"
)
R117_PATH = OWNER_ROOT / (
    "LegalBot-Phase2AB-2026-08-26-r117-post-r116-stemmer-debug-gap-research-plans/"
    "MATERIAL-GAP-RESEARCH-PLANS.json"
)
SOURCE_MANIFEST_PATH = BLOCKED_ROOT / "machine/candidate/approved-source-manifest.json"
DEFAULT_OUTPUT = OWNER_ROOT / (
    "LegalBot-Phase2A-2026-08-27-remediation-working-r1/propositions/"
    "live30-q16-q20.json"
)

SCOPE_CASE_IDS = [f"live30-q{number:02d}" for number in range(16, 21)]


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(value: dict[str, Any], field: str) -> dict[str, Any]:
    result = dict(value)
    result[field] = hashlib.sha256(_canonical_json(result)).hexdigest()
    return result


def _record(
    proposition: str | None,
    status: str,
    research: list[str],
    *,
    rejected: list[str] | None = None,
    conflicts: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "canonical_atomic_proposition": proposition,
        "proposition_status": status,
        "local_evidence_fit": "UNASSESSED",
        "selected_local_evidence": [],
        "rejected_candidate_reasons": rejected or [],
        "required_research": research,
        "proposition_version_conflicts": conflicts or [],
    }


PROPOSITION_WORK: dict[str, dict[str, Any]] = {
    "live30-q16:issue-02": _record(
        "A testator has testamentary capacity only if they understand the nature and effect of making a will, the extent of the property disposed of, and the claims to which they ought to give effect, without a disorder of mind poisoning the disposition.",
        "READY_FOR_EVIDENCE_REVIEW",
        [
            "Bind the exact Banks v Goodfellow formulation and modern authority on applying it alongside the Mental Capacity Act 2005.",
            "Review fluctuating capacity and medication evidence at the time of execution.",
        ],
        rejected=["The six final lexical candidates do not state the testamentary-capacity test."],
    ),
    "live30-q16:issue-03": _record(
        None,
        "NEEDS_PROPOSITION_SPLIT",
        [
            "Separate the propounder's burden to prove knowledge and approval from the heightened scrutiny arising from suspicious circumstances.",
            "Bind exact probate authority for knowledge and approval; CPR 57.7 is pleading procedure only.",
        ],
        conflicts=[
            "The r100 proposition accurately describes CPR 57.7 particulars but does not state the substantive probate test."
        ],
    ),
    "live30-q16:issue-04": _record(
        "Testamentary undue influence requires proof that coercion overbore the testator's free will so that the will expressed another person's wishes rather than the testator's own.",
        "READY_FOR_EVIDENCE_REVIEW",
        [
            "Bind controlling testamentary-undue-influence authority and the applicable burden and standard of proof.",
            "Distinguish coercion from persuasion, dependency, opportunity, or suspicious circumstances alone.",
        ],
        rejected=["The final lexical candidates contain no substantive testamentary-undue-influence rule."],
    ),
    "live30-q16:issue-06": _record(
        None,
        "NEEDS_PROPOSITION_SPLIT",
        [
            "Determine whether invalidity of the 2025 document leaves the 2018 will operative or produces total or partial intestacy.",
            "Bind the statutory intestacy distribution only for property not effectively disposed of by a valid will.",
        ],
        rejected=[
            "The r100 Inheritance (Provision for Family and Dependants) Act 1975 span concerns family-provision applications, not intestate succession."
        ],
        conflicts=["The r100 proposition is assigned to the wrong issue."],
    ),
    "live30-q18:issue-01": _record(
        "A bank acts within its customer's mandate when it executes a clear payment instruction actually authorised by the customer, even if fraud induced the customer to give that instruction, subject to any distinct contractual, statutory, or restitutionary basis for withholding or reversing payment.",
        "NEEDS_LEGAL_RESEARCH",
        [
            "Bind Philipp v Barclays Bank UK plc and confirm its application to a corporate customer acting through an authorised finance director.",
            "Check the target-date statutory reimbursement regime and whether it applies to the payment rail and corporate customer in the facts.",
        ],
        rejected=["The final candidates do not state the customer-mandate rule."],
    ),
    "live30-q18:issue-02": _record(
        "A bank must exercise the care and skill required by its contract when executing its customer's mandate, but the common-law Quincecare duty does not ordinarily require a bank to second-guess a clear instruction given by the customer personally rather than by a dishonest agent.",
        "NEEDS_LEGAL_RESEARCH",
        [
            "Bind the precise majority holding and preserved issues in Philipp v Barclays Bank UK plc.",
            "Check whether the finance director acted as Orion's agent and whether notice of want of authority, rather than APP fraud alone, is realistically arguable.",
        ],
        rejected=["The final lexical candidates are unrelated to the bank mandate and Quincecare question."],
    ),
    "live30-q18:issue-03": _record(
        "A restitutionary claim for unjust enrichment requires the defendant to have been enriched at the claimant's expense in circumstances recognised by English law as unjust, subject to any applicable defence.",
        "READY_FOR_EVIDENCE_REVIEW",
        [
            "Bind current Supreme Court authority for the English-law elements and the mistake unjust factor.",
            "Analyse each recipient separately, including discharge of the supplier's genuine debt.",
        ],
        conflicts=[
            "The r117 draft incorrectly states that a claimant must prove a legal basis for the transfer rather than a recognised unjust factor."
        ],
    ),
    "live30-q18:issue-04": _record(
        "A good-faith recipient has a change-of-position defence to restitution to the extent that, because of the receipt, their position changed so that requiring full restitution would be inequitable.",
        "READY_FOR_EVIDENCE_REVIEW",
        [
            "Bind current authority on good faith, causal reliance, disenrichment, and the limits of the defence.",
            "Test whether payment of an existing genuine debt is enrichment, a defence, or a recipient-specific bar on recovery."
        ],
    ),
    "live30-q18:issue-05": _record(
        "Knowing receipt requires beneficial receipt of assets transferred in breach of trust or fiduciary duty and knowledge making it unconscionable for the recipient to retain the benefit.",
        "READY_FOR_EVIDENCE_REVIEW",
        [
            "Bind the controlling knowing-receipt formulation and verify that Orion can establish an antecedent trust or fiduciary disposition for each transfer.",
            "Separate knowing receipt from dishonest assistance and common-law restitution."
        ],
        conflicts=["The r117 notice formulation is broader than the unconscionability test."],
    ),
    "live30-q18:issue-07": _record(
        "A freezing injunction requires a good arguable case, a real risk that a judgment would be unsatisfied because of unjustified dissipation of assets, and that granting relief is just and convenient.",
        "READY_FOR_EVIDENCE_REVIEW",
        [
            "Bind current appellate authority and CPR/Senior Courts Act jurisdiction for domestic and third-party freezing relief.",
            "Separate a freezing injunction from a proprietary injunction over identified traceable assets."
        ],
        conflicts=[
            "The r117 serious-issue/balance-of-convenience formulation is not the complete freezing-order test."
        ],
    ),
    "live30-q18:issue-08": _record(
        None,
        "NEEDS_PROPOSITION_SPLIT",
        [
            "Split practical recovery into tracing into substitutes, proprietary remedies and priorities, bona fide purchaser/recipient defences, disclosure, freezing/proprietary interim relief, and enforcement against crypto and land.",
            "Bind only the legal propositions; keep operational recovery steps in a non-authority analytical lane."
        ],
        rejected=["The final lexical candidates do not support the proposed tracing and recovery analysis."],
    ),
    "live30-q19:issue-01": _record(
        None,
        "NEEDS_PROPOSITION_SPLIT",
        [
            "Separate the product/geographic substitutability test from digital-market adaptations for zero-price services, ecosystems, data, quality, and multi-sided platforms.",
            "Bind Competition Act/retained competition authority and current official CMA market-definition guidance without treating guidance as legislation."
        ],
        rejected=["DMCC Act sections 46, 77 and 116 do not state the general relevant-market definition test."],
    ),
    "live30-q19:issue-02": _record(
        "Dominance is a position of economic strength enabling an undertaking to prevent effective competition and behave to an appreciable extent independently of competitors, customers, and ultimately consumers in the relevant market.",
        "NEEDS_LEGAL_RESEARCH",
        [
            "Bind the current Competition Act 1998 section 18 framework and controlling retained/EU or domestic authority for the dominance formulation.",
            "Separate Competition Act dominance from the DMCC strategic-market-status designation tests."
        ],
        conflicts=["The r100 DMCC adverse-effect-on-competition proposition does not establish dominance."],
    ),
    "live30-q19:issue-03": _record(
        None,
        "NEEDS_PROPOSITION_SPLIT",
        [
            "Separate Competition Act 1998 abuse analysis for self-preferencing/tying from the DMCC conduct-requirement regime.",
            "Under DMCC sections 19-20, state conditionally that the CMA may impose specified conduct requirements on a designated undertaking; do not describe every listed practice as automatically prohibited."
        ],
        conflicts=["The r117 blanket-prohibition proposition overstates the DMCC statutory scheme."],
    ),
    "live30-q19:issue-04": _record(
        None,
        "NEEDS_PROPOSITION_SPLIT",
        [
            "Separate discriminatory access and exclusive arrangements under Competition Act abuse doctrine from DMCC sections 19-20 permitted conduct requirements.",
            "Identify the exact statutory language for fair terms, interoperability, access, and restrictions on use of competing products."
        ],
        conflicts=["The r117 blanket-prohibition proposition overstates the DMCC statutory scheme."],
    ),
    "live30-q19:issue-05": _record(
        "Section 18 of the Competition Act 1998 prohibits abuse of a dominant position, and pricing or other exclusionary conduct is predatory only where the applicable cost, exclusion, and recoupment or intent criteria established by authority are met.",
        "NEEDS_LEGAL_RESEARCH",
        [
            "Bind section 18 and current controlling authority for predatory pricing and non-price predation.",
            "Do not infer predation merely from low prices, free services, or vigorous competition."
        ],
        rejected=["The final DMCC and consumer-law candidates do not establish predatory-abuse doctrine."],
    ),
    "live30-q19:issue-06": _record(
        None,
        "NEEDS_PROPOSITION_SPLIT",
        [
            "Separate data as a barrier or source of market power from the DMCC conduct-requirement and pro-competition-intervention mechanisms.",
            "Reconcile DMCC sections 19-20 and 46 with the distinct evidence needed to establish competitive harm."
        ],
        conflicts=[
            "The r100 section 46 proposition concerns adverse effects on competition, while the final selected section 20 span addresses only a permitted conduct-requirement type."
        ],
    ),
    "live30-q19:issue-07": _record(
        None,
        "NEEDS_PROPOSITION_SPLIT",
        [
            "Identify the applicable Enterprise Act 2002 merger tests and the DMCC amendments/alternative thresholds current at the target date.",
            "Separate jurisdictional thresholds, substantial-lessening-of-competition assessment, and digital/SMS reporting duties."
        ],
        rejected=["The candidate schedule 21 excerpts are insufficient without exact amended Enterprise Act provisions."],
    ),
    "live30-q19:issue-08": _record(
        None,
        "NEEDS_PROPOSITION_SPLIT",
        [
            "Separate legal tests from economic analysis of price, quality, privacy, choice, innovation, and dynamic competition.",
            "Bind each statutory objective or adverse-effect test before treating a non-price effect as legally material."
        ],
        conflicts=["The r100 section 46 proposition is too narrow to establish the whole consumer-harm and innovation issue."],
    ),
    "live30-q19:issue-09": _record(
        None,
        "NEEDS_PROPOSITION_SPLIT",
        [
            "Separate CMA public enforcement under Competition Act/DMCC, CAT/private competition damages or injunctions, and consumer-enforcement routes.",
            "Identify exact standing, cause-of-action, forum, and remedy provisions for each private route."
        ],
        conflicts=[
            "The r100 schedule 18 proposition concerns designation of public consumer enforcers and does not establish a private right of action for digital-market abuses.",
            "The r117 combined public/private-right proposition is unsupported."
        ],
    ),
    "live30-q20:issue-02": _record(
        "A capacitous adult must give voluntary consent to medical treatment and may refuse treatment even where refusal risks death; absent valid consent, treatment requires another lawful basis such as the Mental Capacity Act 2005 or a genuine emergency.",
        "NEEDS_LEGAL_RESEARCH",
        [
            "Bind current authority on bodily autonomy and refusal, together with the exact Mental Capacity Act route if capacity is lacking.",
            "Separate consent, capacity, best interests, and emergency necessity."
        ],
        rejected=["The final lexical candidates do not state the medical-consent rule."],
    ),
    "live30-q20:issue-04": _record(
        "A clinician must take reasonable care to ensure that a patient is aware of material risks of the recommended treatment and reasonable alternative or variant treatments; a risk is material if a reasonable person in the patient's position would likely attach significance to it or the clinician knows that this patient would likely do so.",
        "READY_FOR_EVIDENCE_REVIEW",
        [
            "Bind the exact Montgomery material-risk and reasonable-alternatives passages and review later treatment.",
            "Determine whether the AI system's subgroup error rate was a material risk or information affecting reasonable alternatives."
        ],
        conflicts=["The r117 draft omits the patient-specific limb of materiality."],
    ),
    "live30-q20:issue-06": _record(
        None,
        "NEEDS_PROPOSITION_SPLIT",
        [
            "Separate ordinary but-for causation for negligent treatment from causation for failure to disclose material risks and alternatives.",
            "Bind the counterfactual choice and injury analysis, including the narrow status of any Chester v Afshar exception."
        ],
        conflicts=["The r117 substantial-factor formulation is not the ordinary English clinical-negligence test."],
    ),
    "live30-q20:issue-08": _record(
        None,
        "NEEDS_PROPOSITION_SPLIT",
        [
            "Treat AI reliance as an application of existing duties: independent clinical judgment, reasonable diagnosis/treatment, informed disclosure, governance and record-keeping.",
            "Research whether any target-date statute, medical-device rule, regulator standard, or binding authority creates an AI-specific duty relevant to these facts.",
            "Do not invent a free-standing AI verification rule."
        ],
        rejected=["The final lexical candidates contain no relevant AI-clinical-duty authority."],
    ),
}


def build(*, output_path: Path = DEFAULT_OUTPUT) -> dict[str, Any]:
    if output_path.exists():
        raise FileExistsError("working proposition draft already exists")
    qualification = json.loads(QUALIFICATION_PATH.read_text())
    pending = [
        row
        for row in qualification["rows"]
        if row["case_id"] in SCOPE_CASE_IDS
        and row["qualification_status"]
        in {"OWNER_DECISION_REQUIRED", "BLOCKED_MATERIAL_GAP"}
    ]
    pending_by_id = {row["row_id"]: row for row in pending}
    if set(pending_by_id) != set(PROPOSITION_WORK):
        raise ValueError("frozen pending scope changed for live30 q16-q20")

    records: list[dict[str, Any]] = []
    for frozen in sorted(pending, key=lambda row: int(row["ordinal"])):
        payload = {
            "row_id": frozen["row_id"],
            "case_id": frozen["case_id"],
            "issue_id": frozen["issue_id"],
            "issue_label": frozen["issue_label"],
            "qualification_status": frozen["qualification_status"],
            **PROPOSITION_WORK[frozen["row_id"]],
            "owner_outcome": None,
        }
        records.append(_sealed(payload, "record_content_sha256"))

    inputs = (
        QUALIFICATION_PATH,
        CASES_PATH,
        CROSSWALK_PATH,
        R100_PATH,
        R117_PATH,
        SOURCE_MANIFEST_PATH,
    )
    artifact = {
        "schema": "legalbot.v111.phase2a.proposition-reconciliation-working.v1",
        "scope_case_ids": SCOPE_CASE_IDS,
        "input_file_sha256s": {
            str(path.relative_to(PROJECT_ROOT)): _sha256_file(path) for path in inputs
        },
        "records": records,
        "repository_model_runtime_invoked": False,
        "codex_advisory_authorship": True,
        "automatic_source_admission": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "owner_decisions_applied": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
        "status": "WORKING_DRAFT_NON_AUTHORIZING",
    }
    artifact = _sealed(artifact, "artifact_content_sha256")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("xb") as handle:
        handle.write(_canonical_json(artifact))
    return artifact


def main() -> None:
    result = build()
    counts: dict[str, int] = {}
    for record in result["records"]:
        status = str(record["proposition_status"])
        counts[status] = counts.get(status, 0) + 1
    print(
        json.dumps(
            {
                "artifact_content_sha256": result["artifact_content_sha256"],
                "record_count": len(result["records"]),
                "status_counts": counts,
                "output": str(DEFAULT_OUTPUT.relative_to(PROJECT_ROOT)),
            },
            indent=2,
            sort_keys=True,
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
