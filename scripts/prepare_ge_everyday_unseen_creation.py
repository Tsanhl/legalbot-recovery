#!/usr/bin/env python3
"""Prepare or verify the authorized public handoff; no private-bank generation."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from app.evaluation.ge_everyday_unseen import (
    DOMAIN_FAMILIES,
    ORIGINAL_DOMAINS,
    PREDECESSOR_ID,
    PROJECT_ROOT,
    REQUEST_ID,
    REQUEST_ROOT,
    STATE,
    SYSTEM_FAMILIES,
    coverage_slots,
    creation_contract,
    seal,
    validate_coverage,
    verify_request,
)

OWNER_AUTHORIZATION = (
    "I authorize creation only of the new 92-case GE unseen bank and 23 separately "
    "scored system cases under LegalBot-GE-2026-09-04-new-unseen-bank-design-r1. "
    "Use a new independent custodian and private root. Keep the retired 306-case "
    "bank excluded. Do not execute the bank, train, activate the adapter, promote or go live."
)
OWNER_EXPANSION = (
    "and GE unseen set also upgrade to more i want all areas can be covered "
    "including what normal people will ask"
)


def write_json(path: Path, value: object) -> None:
    with path.open("x") as handle:
        handle.write(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n")


def prepare() -> dict[str, object]:
    if REQUEST_ROOT.exists():
        raise SystemExit("Request exists; use verify. Never overwrite the frozen handoff.")
    rows = coverage_slots()
    validate_coverage(rows)
    REQUEST_ROOT.mkdir()
    write_json(REQUEST_ROOT / "CREATION-CONTRACT.json", creation_contract())
    write_json(REQUEST_ROOT / "OWNER-AUTHORIZATION-RECEIPT.json", seal({
        "schema": "legalbot.owner-message-scope-receipt.v1",
        "request_id": REQUEST_ID,
        "recorded_at": datetime.now(UTC).isoformat(),
        "authorization_basis": "EXPLICIT_OWNER_MESSAGE_IN_CURRENT_CONVERSATION",
        "creation_scope_excerpt": OWNER_AUTHORIZATION,
        "expansion_scope_excerpt": OWNER_EXPANSION,
        "final_instruction_excerpt": "so improve + i authorise",
        "is_professional_or_cryptographic_signature": False,
        "previous_design": PREDECESSOR_ID,
        "resolved_expansion": {"legal_cases": 420, "domains": 35, "system_cases": 23},
        "resolution_kind": "IMPLEMENTATION_CHOICE_UNDER_AUTHORIZED_COVERAGE_EXPANSION",
        "creation_authorized": True,
        "execution_authorized": False,
    }))
    with (REQUEST_ROOT / "COVERAGE-SLOTS.jsonl").open("x") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    write_json(REQUEST_ROOT / "SYSTEM-COVERAGE.json", {
        "scenario_count": 23, "private_scenarios_created": False,
        "families": list(SYSTEM_FAMILIES), "scored_separately": True,
    })
    table = ["# Coverage obligations", "", "420 public slots; zero private cases created.", "",
        "Each row requires 12 cases in six families, with six upload cases and four follow-up cases.",
        "Counts overlap; they do not add to the denominator.", "",
        "| Domain | Status | Families | Cases |", "| --- | --- | --- | ---: |"]
    for domain, families in DOMAIN_FAMILIES.items():
        status = "Retained" if domain in ORIGINAL_DOMAINS else "Added everyday area"
        table.append(f"| {domain} | {status} | {'; '.join(families)} | 12 |")
    with (REQUEST_ROOT / "COVERAGE-MATRIX.md").open("x") as handle:
        handle.write("\n".join(table) + "\n")
    handoff = """# Independent custodian creation job — already authorized

Create and seal the expanded bank under CREATION-CONTRACT.json and COVERAGE-SLOTS.jsonl.
This job creates questions, synthetic uploaded documents and independently checked
oracle controls only. It must not run the LegalBot candidate or score model answers.

Before generating any private content, establish an authenticated independent
provider/custodian, a new restricted private root, encryption at rest and a
custodian-held decryption key. Enforce denial of development/candidate access and
all retired-bank access. Do not send private content into the development task,
tool output, public files, session history or logs. Return only aggregate counts,
encrypted artifact digests and independently verifiable custody evidence.

Author one independent case per coverage slot and 23 separate system scenarios.
Use realistic situations and synthetic documents. Do not turn this public coverage
matrix into repeated question templates. Do not copy the owner's consumer example
or historic visible/training cases. Check exact and semantic novelty independently
against permitted exclusions, while never opening the retired 306 bank. Do not
claim that an unperformed comparison against the retired bank passed.

Use current official primary evidence with exact spans, jurisdiction, commencement,
effects and relevant-date checks. Build a private case-law relevance record for
each case: MATERIAL with verified identity, holding and paragraphs, or NOT_REQUIRED
with a reason. Unverified or inaccessible controlling authority prevents sealing
that case; do not quietly substitute a narrower/easier question. Official guidance
must be identified separately from law. No source is admitted to runtime or gold.

Verify all synthetic uploads as actual files, trace their facts to pages/regions,
and mark the information as claimed, observed, disputed or missing. Design follow-up
turns, competing arguments, deadlines and practical remedies privately. An uploaded
claim is not automatically true. Use exact rule triggers for dates and arithmetic.

Preserve 420 legal cases, 35 domain denominators, 210 upload cases, 140 multi-turn
cases, 70 cross-issue cases and 23 separate system scenarios. Keep unresolved
coverage/currentness/source defects visible in aggregate; no fabricated completion.

Creation is complete only after the full private bank and all uploads/oracle
evidence are independently checked, encrypted, hash-bound and sealed. Publish a
question-free creation manifest and custody receipt. The development task must not
inspect the private bank. Candidate execution requires later explicit owner
authorization for the exact frozen bank and runtime hashes. No weights, adapter,
promotion, live activation or professional legal sign-off is authorized.
"""
    with (REQUEST_ROOT / "CUSTODIAN-HANDOFF.md").open("x") as handle:
        handle.write(handoff)
    write_json(REQUEST_ROOT / "STATE.json", seal({
        "schema": "legalbot.ge-expanded-bank-creation-state.v1",
        "request_id": REQUEST_ID, "overall_state": STATE,
        "creation_authorized": True, "scope_expansion_authorized": True,
        "coverage_preparation": "COMPLETE", "legal_coverage_slots": 420,
        "private_case_count_created": 0, "bank_created": False,
        "independent_custody_established": False, "private_root_created": False,
        "source_currentness_checked_for_bank": False,
        "execution_authorized": False, "sealed_bank_hash": None,
        "required_external_input": "AUTHENTICATED_INDEPENDENT_CUSTODIAN_CONNECTION",
        "connection_observation": "NO_INDEPENDENT_CUSTODIAN_CONNECTION_CONFIGURED",
        "retired_bank_accessed": False, "training_performed": False,
        "adapter_activated": False, "promotion": "NOT_STARTED", "live": "NOT_STARTED",
    }))
    with (REQUEST_ROOT / "README.md").open("x") as handle:
        handle.write(f"""# {REQUEST_ID}

Creation and expansion are authorized. This public package prepares 420 legal
coverage slots across 35 domains and 23 separate system-test obligations.
It contains zero private questions, answers or uploaded evidence files.

- Original 23 areas retained; 12 everyday areas added.
- At least 210 upload cases, 140 follow-up cases and 70 cross-issue cases.
- Scenario-first questions; candidate must find the law and process uploads.
- Verified legislation and relevant case law; all material claims and omissions checked.
- Every legal answer must pass factual review and the 70+/critical-floor standard.
- Scope is England and Wales with explicit jurisdiction checks, not all world law.

The independent custodian connection is unresolved. No particular vendor or
account is required by this project. No independent custody, encrypted bank or
bank hash has been fabricated. Same-provider sessions are not silently substituted.
Creation authorization need not be repeated.

Use [COVERAGE-MATRIX.md](COVERAGE-MATRIX.md) to review the scope and
[CUSTODIAN-HANDOFF.md](CUSTODIAN-HANDOFF.md) for the creation job.
State: `{STATE}`.

This is a creation request, not evidence of product capability or legal accuracy.
The historical 23/23 excerpt-based visible result does not prove end-to-end upload,
retrieval or case-law handling. No candidate evaluation, training, adapter
activation, promotion or live operation occurred.
""")
    design = PROJECT_ROOT / "docs/system-design/GE_EVERYDAY_UNSEEN.md"
    write_json(REQUEST_ROOT / "INPUT-DIGESTS.json", {
        "working_design_at_creation_sha256": hashlib.sha256(design.read_bytes()).hexdigest(),
        "coverage_module_sha256": hashlib.sha256(
            (PROJECT_ROOT / "backend/app/evaluation/ge_everyday_unseen.py").read_bytes()
        ).hexdigest(),
        "predecessor_design_sha256": hashlib.sha256(
            (REQUEST_ROOT.parent / PREDECESSOR_ID / "NEW-UNSEEN-BANK-DESIGN.json").read_bytes()
        ).hexdigest(),
    })
    artifacts = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in REQUEST_ROOT.iterdir() if p.is_file()}
    write_json(REQUEST_ROOT / "ARTIFACT-SHA256-REGISTER.json", {"artifacts": artifacts})
    return verify_request()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "verify"))
    args = parser.parse_args()
    print(json.dumps(prepare() if args.action == "prepare" else verify_request(), indent=2))


if __name__ == "__main__":
    main()
