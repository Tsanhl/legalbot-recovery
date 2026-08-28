#!/usr/bin/env python3
"""Seal the fail-closed source-ready-59 corrective advisory r4.

The artifact corrects the independent NO-GO audit of r3.  It carries all r2
holds, withdraws incomplete r3 rewrites, freezes parser-compatible canonical
derivatives for the four relied-on GOV.UK snapshots, and records the exact
residual component set.  It is advisory only: no source is admitted or
materialised and no scan, build, embedding, qualification, pointer write, or
answer operation is run.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.ingestion.markdown import CanonicalMarkdownConverter  # noqa: E402
from app.ingestion.models import (  # noqa: E402
    Jurisdiction,
    MaterialLane,
    ParseStatus,
    Provenance,
    SourceIdentity,
)
from app.ingestion.parsers import ParserRegistry  # noqa: E402
from scripts import build_v111_phase2a_source_ready_59_remediation_advisory_r2 as r2  # noqa: E402
from scripts import build_v111_phase2a_source_ready_59_substantive_advisory as r3  # noqa: E402

REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
R2_PATH = r2.OUTPUT_ROOT / r2.ADVISORY_NAME
R2_CONTENT_SHA256 = "b1d5cb2d836cf75e7df65451a232b9a4a83730eb3dfda7cdc7aa9b3fb336e84d"
R2_FILE_SHA256 = "9dcb03e139dece7a3ce512f1e4479566905e775df3cd9af9ed00a8bcece6e2f0"
R3_ROOT = REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-source-ready-59-substantive-advisory-r3"
R3_PATH = R3_ROOT / r3.ADVISORY_NAME
R3_CONTENT_SHA256 = "8166a486dc0385c44f8053351da5fde0a2cb57a6f0632433e38bcf3ac99440bb"
R3_FILE_SHA256 = "9c6484d8da46e252b4cd38c235149cf00cd34d83c673a72c5de80c4bd347d98c"
R3_RESEARCH_PATH = R3_ROOT / r3.RESEARCH_NAME
R3_RESEARCH_CONTENT_SHA256 = "23f04b93e2ce3d822afdee1a4d054e4b27a29ca7493809c9f9611fe55c99b639"
R3_RESEARCH_FILE_SHA256 = "c59e6cf9fe748b95a068fcaa00ca0a98929517c6cde0a5b0159931c1ee29ce9e"

OUTPUT_ROOT = REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-source-ready-59-corrective-advisory-r4"
ADVISORY_NAME = "SOURCE-READY-59-CORRECTIVE-REMEDIATION-ADVISORY-R4.json"
HOLD_LEDGER_NAME = "R2-HOLD-DISPOSITION-LEDGER.json"
DERIVATIVE_MANIFEST_NAME = "GOVUK-CANONICAL-DERIVATIVE-MANIFEST.json"
AUDIT_NAME = "R3-NO-GO-CORRECTIVE-AUDIT-R4.json"
RESIDUAL_NAME = "RESIDUAL-BLOCKER-LEDGER.json"
PACKAGE_NAME = "PACKAGE-MANIFEST.json"
CHECKSUMS_NAME = "SHA256SUMS.txt"

SOURCE_SNAPSHOT_DATE = "2026-08-14"
ADVISORY_DATE = "2026-08-28"


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


def _load_sealed(path: Path, *, field: str, content_sha: str, file_sha: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or _file_sha256(path) != file_sha:
        raise ValueError(f"sealed_input_file_invalid:{path.name}")
    value = json.loads(path.read_bytes())
    material = dict(value)
    observed = str(material.pop(field, ""))
    if observed != content_sha or _sha256(_canonical_json(material)) != observed:
        raise ValueError(f"sealed_input_content_invalid:{path.name}")
    return value


GOVUK_METADATA = {
    "official-url:https://gov.uk/government/publications/speaking-out-guidance-on-campaigning-and-political-activity-by-charities-cc9/speaking-out-guidance-on-campaigning-and-political-activity-by-charities": {
        "title": "Charity Commission, Speaking out (CC9)",
        "published_at": "2016-10-20T16:33:18+01:00",
        "modified_at": "2022-11-07T14:56:48+00:00",
    },
    "official-url:https://gov.uk/government/publications/the-essential-trustee-what-you-need-to-know-what-you-need-to-do-cc3/the-essential-trustee-what-you-need-to-know-what-you-need-to-do": {
        "title": "Charity Commission, The essential trustee (CC3)",
        "published_at": "2016-08-10T09:53:44+01:00",
        "modified_at": "2018-05-03T16:45:14+01:00",
    },
    "official-url:https://gov.uk/guidance/accepting-refusing-and-returning-donations-to-your-charity": {
        "title": "Charity Commission, Accepting, refusing and returning donations",
        "published_at": "2024-03-04T00:00:00+00:00",
        "modified_at": "2024-03-04T00:00:00+00:00",
    },
    "official-url:https://gov.uk/government/publications/decision-making-for-charity-trustees-cc27/decision-making-for-charity-trustees": {
        "title": "Charity Commission, Decision-making for charity trustees (CC27)",
        "published_at": "2024-09-09T06:00:07+01:00",
        "modified_at": "2024-09-09T06:00:06+01:00",
    },
}

CHARITY_AFTER = {
    ("live60-q45:issue-03", 1): (
        "In the Charity Commission CC9 official guidance snapshot last updated "
        "7 November 2022, CC9 states that a charity cannot have a political purpose "
        "and that political activity may support charitable purposes but cannot be "
        "the charity's continuing and sole activity."
    ),
    ("live60-q45:issue-04", 1): (
        "In the Charity Commission CC9 official guidance snapshot last updated "
        "7 November 2022, CC9 states that trustees considering political activity "
        "must decide whether there is a reasonable expectation that it will support "
        "the charity's purposes, and that political activity cannot be the charity's "
        "continuing and sole activity."
    ),
    ("live60-q45:issue-04", 2): (
        "In the Charity Commission CC9 official guidance snapshot last updated "
        "7 November 2022, CC9 states that a charity must not support a political "
        "party or candidate and must guard and maintain its independence."
    ),
    ("live60-q45:issue-05", 1): (
        "In the Charity Commission CC3 official guidance snapshot last updated "
        "3 May 2018, CC3 states that trustees must decide for themselves what best "
        "enables the charity to carry out its purposes, make balanced and adequately "
        "informed decisions, and use reasonable care and skill with appropriate "
        "advice where necessary."
    ),
    ("live60-q45:issue-06", 1): (
        "In the Charity Commission official guidance snapshot published and last "
        "updated 4 March 2024, the guidance states that trustees considering refusal "
        "or return of a donation must have a legal power to do so and be satisfied "
        "that using it is in the charity's best interests; the applicable power "
        "depends on the circumstances."
    ),
    ("live60-q45:issue-09", 1): (
        "In the Charity Commission CC27 official guidance snapshot published and "
        "last updated 9 September 2024, CC27 states that trustees must base decisions "
        "on sufficient relevant information, take all relevant factors into account, "
        "disregard irrelevant factors, and may treat reputational impact as a "
        "potentially relevant factor."
    ),
}

CHARITY_REMOVED_DIMENSIONS = {
    ("live60-q45:issue-03", 1): [
        "complete political-purposes doctrine as primary law",
        "court-authority conclusion",
        "application to the proposed purpose, governing document, duration, or activity mix",
    ],
    ("live60-q45:issue-04", 1): [
        "complete legality of the proposed campaign",
        "case- or statute-based rationality conclusion",
        "application to unproved campaign facts",
    ],
    ("live60-q45:issue-04", 2): [
        "whether a policy furthers the charity's purposes",
        "communication of independence beyond the quoted guidance",
        "election-period rules",
    ],
    ("live60-q45:issue-05", 1): [
        "complete best-interests doctrine",
        "conflict management and accountability",
        "Lehtimäki or other court-authority conclusions",
        "application to donor or campaigner influence",
    ],
    ("live60-q45:issue-06", 1): [
        "classification of the donation instrument",
        "special-trust or restriction effect",
        "donor influence",
        "variation, statutory scheme, Commission, or court routes",
    ],
    ("live60-q45:issue-09", 1): [
        "no-freestanding-prohibition conclusion",
        "nexus to purposes, assets, beneficiaries, independence, or public confidence",
        "application to the controversy facts",
    ],
}

MATTER_INTAKE = {
    ("live30-q16:issue-02", 3): [
        "the dates and circumstances of instructions and execution",
        "medical, medication, and capacity evidence at each relevant time",
        "the drafting solicitor's attendance notes and witness evidence",
    ],
    ("live30-q16:issue-03", 3): [
        "the drafting and explanation file",
        "George's understanding and approval evidence",
        "Nina's role, presence, benefit, and communications",
    ],
    ("live30-q16:issue-04", 3): [
        "the alleged pressure, threats, persistence, or manipulation",
        "George's will being overborne and the causal link to the document",
        "independent drafting and witness evidence",
    ],
    ("live30-q18:issue-01", 2): [
        "Orion's mandate, delegations, and authority matrix",
        "the finance director's role and communications",
        "the exact payment instruction and approval chain",
    ],
    ("live30-q18:issue-01", 4): [
        "the payment-service providers and account types",
        "payment date, amount, channel, destination, and consumer or business status",
        "the applicable reimbursement scheme scope and any exception facts",
    ],
    ("live30-q18:issue-02", 3): [
        "the mandate and authority limits",
        "the exact confirmation-call participants and contents",
        "the unusual-payment indicators known to the recipient at the time",
    ],
    ("live30-q18:issue-05", 3): [
        "the alleged antecedent trust or fiduciary relationship for each payment",
        "the asset disposed of, the alleged breach, and beneficial receipt",
        "the proprietary and tracing chain for each transfer",
    ],
    ("live30-q30:issue-04", 1): [
        "retainer, advice, attendance notes, procedural file, and deadline chronology",
        "underlying-claim and counterfactual-loss evidence",
    ],
    ("live30-q30:issue-04", 2): [
        "contracts, incorporated terms, marketing statements, warnings, and maker attribution",
        "model output, reliance, payment, loss, exclusion, and entire-agreement evidence",
    ],
    ("live30-q30:issue-04", 3): [
        "decision inputs and outputs, model and threshold versions, validation, and error rates",
        "protected-characteristic, comparator, human-review, notice, reason, safeguard, and controller allocation evidence",
    ],
    ("live30-q30:issue-04", 4): [
        "governing scheme, application, inputs, notice, reasons, and response opportunity",
        "review, appeal, equality assessment, system instruction, and decision-maker attribution records",
    ],
    ("live30-q30:issue-04", 5): [
        "code and training-data provenance, work, author, employment, licence, access, and output-comparison evidence",
        "board minutes, appointments, solvency accounts, creditor position, insurance, and benefit or loss allocation",
    ],
}

EXCLUSION_COVERAGE = {
    ("live30-q13:issue-02", 2): {
        "reason": (
            "The categorical inference is demonstrably overbroad: the upstream FULL "
            "component records deed, declaration-of-trust, or delivery routes, so lack "
            "of formal title transfer alone cannot establish failure."
        ),
        "coverage_component_ordinals": [1],
    }
}

DEFECT_DIMENSIONS = {
    ("live60-q34:issue-06", 1): [
        "private change of mind",
        "physical movement",
        "Jogee spent or overwhelmed assistance",
        "communication or neutralisation of prior assistance",
    ],
    ("live60-q37:issue-05", 1): ["LLP fiduciary duties", "no automatic company-director code"],
    ("live60-q37:issue-07", 1): [
        "distinct Insolvency Act routes",
        "CDDA section 6",
        "wrongful trading as civil not criminal",
    ],
    ("live60-q37:issue-08", 1): [
        "administration",
        "winding up",
        "office-holder claims",
        "priority",
        "member contribution",
        "dissolution",
    ],
    ("live60-q37:issue-10", 1): [
        "partnership liability and non-corporate structure",
        "company incorporation, ownership, directors, and capital",
        "governance, tax, disclosure, exit, and insolvency comparison",
    ],
    ("live60-q38:issue-05", 1): [
        "transformation and loss of identity",
        "new product",
        "charge registration",
        "Borden",
        "Peachdart",
    ],
    ("live60-q38:issue-06", 1): [
        "proceeds-clause trust, debt, or charge",
        "tracing",
        "bank receipt",
        "priority",
    ],
    ("live60-q40:issue-01", 1): [
        "consultation",
        "screening and category threshold",
        "delegation",
        "material considerations",
        "reasons",
    ],
    ("live60-q45:issue-03", 1): ["political-purpose court and matter dimensions"],
    ("live60-q45:issue-04", 1): ["election and campaign matter dimensions"],
    ("live60-q45:issue-04", 2): ["policy-furtherance", "election-period rules"],
    ("live60-q45:issue-05", 1): ["best interests", "conflicts", "accountability", "Lehtimäki"],
    ("live60-q45:issue-06", 1): [
        "donation classification",
        "donor influence",
        "variation or scheme",
        "court route",
    ],
    ("live60-q45:issue-09", 1): ["no-freestanding prohibition", "fact-specific nexus dimensions"],
    ("live60-q51:issue-02", 1): [
        "quality of confidence",
        "obligation",
        "use or threat",
        "detriment",
        "notice",
        "public interest",
        "remedies",
        "Bloomberg",
    ],
    ("live60-q58:issue-07", 1): ["private grid-delay entitlement", "damages"],
    ("live60-q58:issue-11", 1): ["lender step-in mechanics"],
}

LEGISLATION_DEFECT_KEYS = {
    ("live60-q37:issue-05", 1),
    ("live60-q37:issue-07", 1),
    ("live60-q37:issue-08", 1),
    ("live60-q37:issue-10", 1),
    ("live60-q38:issue-05", 1),
    ("live60-q38:issue-06", 1),
    ("live60-q40:issue-01", 1),
    ("live60-q58:issue-07", 1),
    ("live60-q58:issue-11", 1),
}


def _extract_date(raw: str, field: str) -> str:
    matches = re.findall(rf'"{field}"\s*:\s*"([^"]+)"', raw)
    if not matches:
        raise ValueError(f"govuk_{field}_missing")
    return matches[0]


def build_govuk_derivatives(
    baseline: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, bytes], dict[str, dict[str, Any]]]:
    bindings = {row["authority_identity_id"]: row for row in baseline["source_byte_bindings"]}
    records: list[dict[str, Any]] = []
    members: dict[str, bytes] = {}
    for ordinal, (identity, metadata) in enumerate(sorted(GOVUK_METADATA.items()), start=1):
        binding = bindings[identity]
        raw_path = r3._binding_path(binding)
        raw_bytes = raw_path.read_bytes()
        if _sha256(raw_bytes) != binding["representation_file_sha256"]:
            raise ValueError(f"govuk_raw_binding_invalid:{identity}")
        raw_text = raw_bytes.decode("utf-8", "strict")
        if _extract_date(raw_text, "datePublished") != metadata["published_at"]:
            raise ValueError(f"govuk_published_date_invalid:{identity}")
        if _extract_date(raw_text, "dateModified") != metadata["modified_at"]:
            raise ValueError(f"govuk_modified_date_invalid:{identity}")
        parsed = ParserRegistry.default().parse(raw_bytes, filename=raw_path.name)
        if parsed.status is not ParseStatus.READY or not parsed.body_blocks:
            raise ValueError(f"govuk_html_parse_invalid:{identity}")
        canonical_url = binding["official_urls"][0]
        provenance = Provenance(
            source_identity=SourceIdentity(
                "official-url",
                identity.removeprefix("official-url:"),
                version=binding["representation_file_sha256"],
            ),
            title=metadata["title"],
            source_kind="official_regulator_guidance_snapshot",
            jurisdiction=Jurisdiction.ENGLAND_WALES,
            material_lane=MaterialLane.OFFICIAL_GUIDANCE,
            content_sha256=binding["representation_file_sha256"],
            retrieved_at=f"{ADVISORY_DATE}T00:00:00+00:00",
            canonical_url=canonical_url,
            published_at=metadata["published_at"],
            modified_at=metadata["modified_at"],
            effective_as_at=metadata["modified_at"][:10],
            extra={
                "transform_schema": "legalbot.govuk-html-to-canonical-markdown.v1",
                "r2_source_binding_content_sha256": binding["record_content_sha256"],
            },
        )
        bundle = CanonicalMarkdownConverter().convert(parsed, provenance)
        body = bundle.body_markdown.encode("utf-8")
        body_sha = _sha256(body)
        parsed_again = ParserRegistry.default().parse(body, filename="official-guidance.md")
        if parsed_again.status is not ParseStatus.READY or not parsed_again.body_blocks:
            raise ValueError(f"govuk_canonical_parser_incompatible:{identity}")
        recanonical = CanonicalMarkdownConverter().convert(parsed_again, provenance)
        member = f"govuk-canonical-{ordinal:04d}-{body_sha[:20]}.md"
        record = _seal(
            {
                "schema": "legalbot.v111.phase2a.govuk-canonical-derivative-record.v1",
                "authority_identity_id": identity,
                "official_source_role": "OFFICIAL_REGULATOR_GUIDANCE_NON_PRIMARY",
                "jurisdiction": "England and Wales",
                "raw_source_binding_content_sha256": binding["record_content_sha256"],
                "raw_representation_member": binding["representation_member"],
                "raw_representation_file_sha256": binding["representation_file_sha256"],
                "raw_parse_status": parsed.status.value,
                "raw_body_block_count": len(parsed.body_blocks),
                "canonical_derivative_member": member,
                "canonical_derivative_file_sha256": body_sha,
                "canonical_content_identity_id": f"canonical-markdown-sha256:{body_sha}",
                "proposed_source_version_id": f"proposed-source-version-{body_sha[:40]}",
                "canonical_converter_schema": CanonicalMarkdownConverter.schema,
                "parser_registry_schema": ParserRegistry.schema,
                "parser_compatible": True,
                "reparsed_body_block_count": len(parsed_again.body_blocks),
                "recanonical_body_sha256": recanonical.body_sha256,
                "published_at": metadata["published_at"],
                "modified_at": metadata["modified_at"],
                "cc27_metadata_correction": (
                    "PUBLISHED_AND_LAST_UPDATED_2024_09_09"
                    if "decision-making-for-charity-trustees" in identity
                    else None
                ),
                "derivative_frozen_for_advisory_only": True,
                "source_admission_authorized": False,
                "source_admitted": False,
                "materialized": False,
            },
            "record_content_sha256",
        )
        records.append(record)
        members[member] = body
    manifest = _seal(
        {
            "schema": "legalbot.v111.phase2a.govuk-canonical-derivative-manifest.v1",
            "status": "FROZEN_PARSER_COMPATIBLE_DERIVATIVES_NOT_ADMITTED",
            "record_count": len(records),
            "records": records,
            "cc27_corrected_modified_date": "2024-09-09",
            **r2.NO_EXECUTION_FLAGS,
        }
    )
    return manifest, members, {row["authority_identity_id"]: row for row in records}


_LEGAL_HOLD_MARKERS = (
    "source",
    "authority",
    "currentness",
    "later-treatment",
    "later treatment",
    "extent",
    "effect",
    "commencement",
    "jurisdiction",
    "evidencespan",
    "official",
    "court",
    "statut",
    "legal",
    "proposition",
    "citation",
    "binding",
    "review",
)


def _hold_status(row_id: str, text: str) -> tuple[str, str]:
    lowered = text.casefold()
    if row_id.startswith("live60-q45:issue-") and any(
        marker in lowered for marker in _LEGAL_HOLD_MARKERS
    ):
        return (
            "OUTSIDE_EXPLICIT_SCOPE",
            "Operative unless the owner adopts the exact attributed-guidance scope supersession; it is not resolved.",
        )
    if any(marker in lowered for marker in _LEGAL_HOLD_MARKERS):
        return (
            "RETAINED_RELEASE",
            "Operative legal/source release hold; advisory scope changes do not resolve it.",
        )
    return (
        "MATTER_INFO",
        "Operative matter-information requirement; obtain the listed facts or documents before application.",
    )


def build_hold_ledger(baseline: dict[str, Any]) -> dict[str, Any]:
    records = []
    seen: set[str] = set()
    for row in baseline["row_advisories"]:
        for hold in row["all_raw_holds_retained"]:
            if hold["record_content_sha256"] in seen:
                raise ValueError("duplicate_r2_hold_record")
            seen.add(hold["record_content_sha256"])
            status, explanation = _hold_status(row["row_id"], hold["hold_text"])
            records.append(
                _seal(
                    {
                        "schema": "legalbot.v111.phase2a.r2-hold-disposition-record.v1",
                        "row_id": row["row_id"],
                        "r2_row_record_content_sha256": row["record_content_sha256"],
                        "r2_hold_record_content_sha256": hold["record_content_sha256"],
                        "hold_text_sha256": hold["hold_text_sha256"],
                        "hold_text": hold["hold_text"],
                        "disposition": status,
                        "disposition_explanation": explanation,
                        "operative": True,
                        "resolved": False,
                        "owner_adopted": False,
                        "applied": False,
                    },
                    "record_content_sha256",
                )
            )
    if len(records) != 180:
        raise ValueError(f"r2_hold_count_invalid:{len(records)}")
    counts = Counter(row["disposition"] for row in records)
    return _seal(
        {
            "schema": "legalbot.v111.phase2a.r2-hold-disposition-ledger.v1",
            "status": "ALL_R2_HOLDS_CARRIED_FORWARD_NONE_RESOLVED",
            "r2_baseline_content_sha256": R2_CONTENT_SHA256,
            "record_count": len(records),
            "unique_r2_hold_record_count": len(seen),
            "disposition_counts": dict(sorted(counts.items())),
            "allowed_dispositions": [
                "RESOLVED",
                "RETAINED_RELEASE",
                "MATTER_INFO",
                "OUTSIDE_EXPLICIT_SCOPE",
            ],
            "records": records,
            **r2.NO_EXECUTION_FLAGS,
        }
    )


def _unified_diff(before: str, after: str) -> list[str]:
    return list(
        difflib.unified_diff(
            [before + "\n"], [after + "\n"], fromfile="before", tofile="after", lineterm=""
        )
    )


def _r3_recommendations(r3_advisory: dict[str, Any]) -> dict[tuple[str, int], dict[str, Any]]:
    return {
        (row["row_id"], component["component_ordinal"]): component
        for row in r3_advisory["row_advisories"]
        for component in row["component_recommendations"]
    }


def _coverage_proof(
    *,
    row_id: str,
    component_ordinals: list[int],
    owner_by_id: dict[str, Any],
    source_by_id: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    decision = owner_by_id[row_id]
    components = decision["source_research_record"]["atomic_components"]
    assessments = decision["authority_assessments"]
    proof = []
    for component_ordinal in component_ordinals:
        component = components[component_ordinal - 1]
        if component["support_fit"] != "FULL":
            raise ValueError(f"coverage_component_not_full:{row_id}:{component_ordinal}")
        authority_bindings = []
        for authority_ordinal, authority in enumerate(component["authorities"], start=1):
            assessment = next(
                item
                for item in assessments
                if item["component_ordinal"] == component_ordinal
                and item["authority_ordinal"] == authority_ordinal
            )
            identity = assessment["canonical_authority_identity_id"]
            binding = source_by_id.get(identity)
            if binding is None:
                raise ValueError(f"coverage_source_not_byte_bound:{row_id}:{identity}")
            authority_bindings.append(
                {
                    "citation": authority["citation"],
                    "authority_identity_id": identity,
                    "exact_locators": authority["exact_locators"],
                    "authority_assessment_content_sha256": assessment["assessment_content_sha256"],
                    "source_binding_content_sha256": binding["record_content_sha256"],
                    "representation_file_sha256": binding["representation_file_sha256"],
                    "official_source_role": binding["official_source_role"],
                }
            )
        proof.append(
            _seal(
                {
                    "schema": "legalbot.v111.phase2a.preexisting-full-component-coverage-proof.v1",
                    "component_ordinal": component_ordinal,
                    "proposition": component["proposition"],
                    "proposition_text_sha256": _sha256(component["proposition"].encode()),
                    "upstream_support_fit": "FULL",
                    "owner_decision_content_sha256": decision["decision_content_sha256"],
                    "authority_bindings": authority_bindings,
                    "used_only_for_row_specific_overbreadth_proof": True,
                    "used_to_clear_unrelated_component": False,
                },
                "record_content_sha256",
            )
        )
    return proof


def _charity_recommendation(
    *,
    key: tuple[str, int],
    before: dict[str, Any],
    r3_prior: dict[str, Any],
    derivative_by_id: dict[str, dict[str, Any]],
    derivative_bytes: dict[str, bytes],
) -> dict[str, Any]:
    after = CHARITY_AFTER[key]
    spans = []
    for old_span in r3_prior["frozen_evidence_span_proposals"]:
        identity = old_span["authority_identity_id"]
        derivative = derivative_by_id[identity]
        canonical_text = r2._normalise_text(
            derivative_bytes[derivative["canonical_derivative_member"]].decode("utf-8")
        )
        excerpts = []
        for excerpt in old_span["supporting_excerpts"]:
            normalised = r2._normalise_text(excerpt["text"])
            if normalised not in canonical_text:
                raise ValueError(f"charity_excerpt_not_in_derivative:{key}:{identity}")
            excerpts.append(
                {
                    "text": excerpt["text"],
                    "normalised_text_sha256": _sha256(normalised.encode()),
                    "verified_in_parser_compatible_derivative": True,
                }
            )
        spans.append(
            _seal(
                {
                    "schema": "legalbot.v111.phase2a.frozen-evidence-span-proposal.v4",
                    "authority_identity_id": identity,
                    "exact_locator": old_span["exact_locator"],
                    "supporting_excerpts": excerpts,
                    "raw_source_binding_content_sha256": derivative[
                        "raw_source_binding_content_sha256"
                    ],
                    "raw_representation_file_sha256": derivative["raw_representation_file_sha256"],
                    "canonical_derivative_record_content_sha256": derivative[
                        "record_content_sha256"
                    ],
                    "canonical_derivative_file_sha256": derivative[
                        "canonical_derivative_file_sha256"
                    ],
                    "canonical_content_identity_id": derivative["canonical_content_identity_id"],
                    "official_source_role": "OFFICIAL_REGULATOR_GUIDANCE_NON_PRIMARY",
                    "jurisdiction": "England and Wales",
                    "currentness_snapshot_modified_at": derivative["modified_at"],
                    "later_treatment_disposition": (
                        "NOT_APPLICABLE_TO_ATTRIBUTED_GUIDANCE_TEXT; UNDERLYING_LAW_NOT_INFERRED"
                    ),
                    "proposal_payload_immutable": True,
                    "evidence_span_frozen_for_execution": False,
                    "owner_adopted": False,
                },
                "span_proposal_content_sha256",
            )
        )
    return _seal(
        {
            "schema": "legalbot.v111.phase2a.source-ready-corrective-component-advisory.v4",
            "row_id": key[0],
            "component_ordinal": key[1],
            "before_proposition": before["before_proposition"],
            "before_proposition_text_sha256": before["before_proposition_text_sha256"],
            "upstream_support_fit": before["upstream_support_fit"],
            "action": "OWNER_SCOPE_SUPERSESSION_TO_ATTRIBUTED_OFFICIAL_GUIDANCE",
            "after_propositions": [
                {
                    "proposition": after,
                    "proposition_text_sha256": _sha256(after.encode()),
                    "proposed_support_fit": "FULL_FOR_EXACT_ATTRIBUTED_GUIDANCE_SNAPSHOT_IF_OWNER_ADOPTS_SCOPE",
                }
            ],
            "before_after_diff": {
                "before_text_sha256": before["before_proposition_text_sha256"],
                "after_text_sha256": _sha256(after.encode()),
                "unified_diff": _unified_diff(before["before_proposition"], after),
            },
            "exact_owner_scope_supersession_recommendation": {
                "owner_action": "REPLACE_ORIGINAL_COMPONENT_SCOPE_WITH_EXACT_ATTRIBUTED_SNAPSHOT_STATEMENT_ONLY",
                "original_issue_preserved": False,
                "removed_dimensions": CHARITY_REMOVED_DIMENSIONS[key],
                "removed_dimensions_resolved": False,
                "removed_dimensions_outside_explicit_technical_scope_only_if_owner_adopts": True,
            },
            "frozen_evidence_span_proposals": spans,
            "component_support_complete_if_owner_adopted": True,
            "material_gap_after_exact_scope_adoption": False,
            "eligibility_pre_owner_adoption": False,
            "retained_release_hold_codes": [
                "NON_PRIMARY_REGULATOR_GUIDANCE",
                "UNDERLYING_PRIMARY_LAW_CURRENTNESS_NOT_ESTABLISHED",
                "ANSWER_RELEASE_REMAINS_HELD",
            ],
            "answer_release_eligible": False,
            "r2_recommendation_content_sha256": before["recommendation_content_sha256"],
            "r3_unsafe_recommendation_content_sha256": r3_prior["recommendation_content_sha256"],
            "owner_adopted": False,
            "applied": False,
        },
        "recommendation_content_sha256",
    )


def _matter_recommendation(key: tuple[str, int], before: dict[str, Any]) -> dict[str, Any]:
    requested = MATTER_INTAKE[key]
    return _seal(
        {
            "schema": "legalbot.v111.phase2a.source-ready-corrective-component-advisory.v4",
            "row_id": key[0],
            "component_ordinal": key[1],
            "before_proposition": before["before_proposition"],
            "before_proposition_text_sha256": before["before_proposition_text_sha256"],
            "upstream_support_fit": before["upstream_support_fit"],
            "action": "OWNER_SCOPE_SUPERSESSION_TO_NON_AUTHORITATIVE_MATTER_INTAKE",
            "after_propositions": [],
            "before_after_diff": {
                "before_text_sha256": before["before_proposition_text_sha256"],
                "after_legal_proposition_count": 0,
                "change_class": "REMOVE_UNPROVED_MATTER_CONCLUSION_AND_REQUEST_INPUTS",
            },
            "exact_owner_scope_supersession_recommendation": {
                "owner_action": "RECLASSIFY_COMPONENT_AS_NON_AUTHORITATIVE_MATTER_INTAKE_ONLY",
                "original_issue_preserved": False,
                "requested_facts_or_documents": requested,
                "intake_response": (
                    "The available matter information is insufficient to determine this point. "
                    "Please provide: " + "; ".join(requested) + "."
                ),
                "no_legal_rule_advice_citation_or_evidence_span": True,
            },
            "frozen_evidence_span_proposals": [],
            "component_support_complete_if_owner_adopted": True,
            "material_gap_after_exact_scope_adoption": False,
            "eligibility_pre_owner_adoption": False,
            "matter_information_gap_remains": True,
            "answer_release_eligible": False,
            "r2_recommendation_content_sha256": before["recommendation_content_sha256"],
            "owner_adopted": False,
            "applied": False,
        },
        "recommendation_content_sha256",
    )


def _exclusion_recommendation(
    key: tuple[str, int],
    before: dict[str, Any],
    *,
    owner_by_id: dict[str, Any],
    source_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    details = EXCLUSION_COVERAGE[key]
    proof = _coverage_proof(
        row_id=key[0],
        component_ordinals=details["coverage_component_ordinals"],
        owner_by_id=owner_by_id,
        source_by_id=source_by_id,
    )
    return _seal(
        {
            "schema": "legalbot.v111.phase2a.source-ready-corrective-component-advisory.v4",
            "row_id": key[0],
            "component_ordinal": key[1],
            "before_proposition": before["before_proposition"],
            "before_proposition_text_sha256": before["before_proposition_text_sha256"],
            "upstream_support_fit": before["upstream_support_fit"],
            "action": "OWNER_EXCLUDE_DEMONSTRABLY_OVERBROAD_PROPOSITION",
            "after_propositions": [],
            "before_after_diff": {
                "before_text_sha256": before["before_proposition_text_sha256"],
                "after_legal_proposition_count": 0,
                "change_class": "DELETE_CATEGORICAL_OVERBREADTH_NOT_DELETE_ROW_ISSUE",
            },
            "exact_owner_scope_supersession_recommendation": {
                "owner_action": "EXCLUDE_ONLY_THIS_EXACT_CATEGORICAL_PROPOSITION",
                "original_issue_preserved": False,
                "reason": details["reason"],
                "row_issue_remains_covered_by_bound_full_component": True,
            },
            "row_specific_redundancy_and_coverage_proof": proof,
            "frozen_evidence_span_proposals": [],
            "component_support_complete_if_owner_adopted": True,
            "material_gap_after_exact_scope_adoption": False,
            "eligibility_pre_owner_adoption": False,
            "answer_release_eligible": False,
            "r2_recommendation_content_sha256": before["recommendation_content_sha256"],
            "owner_adopted": False,
            "applied": False,
        },
        "recommendation_content_sha256",
    )


def _blocker_recommendation(key: tuple[str, int], before: dict[str, Any]) -> dict[str, Any]:
    missing = DEFECT_DIMENSIONS.get(key, [])
    schedule_control = None
    if key in {("live60-q37:issue-07", 1), ("live60-q37:issue-08", 1)}:
        schedule_control = {
            "r3_whole_schedule_3_locator_revoked": True,
            "whole_schedule_3_locator_carried_forward": False,
            "exact_schedule_3_paragraphs_adopted": [],
            "block_reason": "No proposition-complete exact paragraph set was safely established.",
        }
    return _seal(
        {
            "schema": "legalbot.v111.phase2a.source-ready-corrective-component-advisory.v4",
            "row_id": key[0],
            "component_ordinal": key[1],
            "before_proposition": before["before_proposition"],
            "before_proposition_text_sha256": before["before_proposition_text_sha256"],
            "upstream_support_fit": before["upstream_support_fit"],
            "action": "RETAIN_BLOCKER_PROPOSITION_COMPLETE_SUPPORT_REQUIRED",
            "after_propositions": [],
            "before_after_diff": None,
            "exact_owner_scope_supersession_recommendation": None,
            "original_issue_preserved": True,
            "missing_original_dimensions": missing,
            "legislation_proposition_control": (
                {
                    "r3_undated_legislation_proposition_revoked": True,
                    "r4_legislation_proposition_proposed": False,
                    "required_as_of_date_for_any_future_proposition": SOURCE_SNAPSHOT_DATE,
                }
                if key in LEGISLATION_DEFECT_KEYS
                else None
            ),
            "schedule_3_atomic_locator_control": schedule_control,
            "source_inspection": before["source_inspection"],
            "frozen_evidence_span_proposals": [],
            "component_support_complete_if_owner_adopted": False,
            "material_gap_after_exact_scope_adoption": True,
            "eligibility_pre_owner_adoption": False,
            "row_specific_reason": before["rationale"],
            "answer_release_eligible": False,
            "r2_recommendation_content_sha256": before["recommendation_content_sha256"],
            "owner_adopted": False,
            "applied": False,
        },
        "recommendation_content_sha256",
    )


def build_corrective_audit(
    *,
    r3_research: dict[str, Any],
    derivative_manifest: dict[str, Any],
) -> dict[str, Any]:
    unsealed = []
    for record in r3_research["records"]:
        if record.get("live_response_sha256"):
            unsealed.append({"kind": "LIVE_RESPONSE", "sha256": record["live_response_sha256"]})
        if record.get("search_response_sha256"):
            unsealed.append({"kind": "SEARCH_RESPONSE", "sha256": record["search_response_sha256"]})
        for treatment in record.get("later_treatments", []):
            unsealed.append({"kind": "JUDGMENT", "sha256": treatment[3]})
    if Counter(row["kind"] for row in unsealed) != {
        "LIVE_RESPONSE": 4,
        "SEARCH_RESPONSE": 2,
        "JUDGMENT": 9,
    }:
        raise ValueError("r3_unsealed_research_boundary_invalid")
    defect_records = []
    for key, dimensions in sorted(DEFECT_DIMENSIONS.items()):
        scope = key in CHARITY_AFTER
        defect_records.append(
            _seal(
                {
                    "schema": "legalbot.v111.phase2a.r3-no-go-defect-resolution.v1",
                    "row_id": key[0],
                    "component_ordinal": key[1],
                    "lost_or_unsupported_dimensions": dimensions,
                    "r4_disposition": (
                        "EXACT_OWNER_SCOPE_SUPERSESSION_RECOMMENDED_NOT_APPLIED"
                        if scope
                        else "RETAIN_BLOCKER_NO_INCOMPLETE_REWRITE"
                    ),
                    "qualification_eligible_pre_owner_adoption": False,
                    "owner_adopted": False,
                    "applied": False,
                },
                "record_content_sha256",
            )
        )
    return _seal(
        {
            "schema": "legalbot.v111.phase2a.r3-no-go-corrective-audit-r4.v1",
            "status": "R3_NO_GO_CORRECTED_FAIL_CLOSED_RESIDUALS_REMAIN",
            "r3_advisory_content_sha256": R3_CONTENT_SHA256,
            "r3_research_content_sha256": R3_RESEARCH_CONTENT_SHA256,
            "defect_record_count": len(defect_records),
            "defect_records": defect_records,
            "r3_unsealed_external_research": {
                "claim_reliance_removed": True,
                "hash_count": len(unsealed),
                "hash_kind_counts": dict(sorted(Counter(row["kind"] for row in unsealed).items())),
                "revoked_unsealed_hashes_for_identification_only": unsealed,
                "no_later_treatment_conclusion_carried_forward": True,
            },
            "legislation_date_control": {
                "required_exact_as_of_date": SOURCE_SNAPSHOT_DATE,
                "affected_components": [
                    {"row_id": row_id, "component_ordinal": ordinal}
                    for row_id, ordinal in sorted(LEGISLATION_DEFECT_KEYS)
                ],
                "r3_undated_propositions_revoked": True,
                "r4_legislation_propositions_proposed": 0,
            },
            "sale_of_goods_act_1979_effects_control": {
                "authority_identity_id": "ukpga:1979:54",
                "source_snapshot_as_of_date": SOURCE_SNAPSHOT_DATE,
                "candidate_unapplied_effect_count": 1,
                "effect_not_reviewed_or_applied": True,
                "affected_rows": ["live60-q38:issue-05", "live60-q38:issue-06"],
            },
            "schedule_3_control": {
                "affected_rows": ["live60-q37:issue-07", "live60-q37:issue-08"],
                "whole_schedule_locator_revoked": True,
                "whole_schedule_locator_carried_forward": False,
                "exact_paragraphs_adopted": [],
                "result": "BLOCK_RETAINED_UNTIL_EXACT_PARAGRAPH_SET_IS_PROPOSITION_COMPLETE",
            },
            "govuk_derivative_manifest_content_sha256": derivative_manifest[
                "artifact_content_sha256"
            ],
            "cc27_metadata_corrected_to": "2024-09-09",
            **r2.NO_EXECUTION_FLAGS,
        }
    )


def build_advisory() -> tuple[
    dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, bytes]
]:
    baseline_rebuilt, topology, _ = r2.build_advisory()
    baseline = _load_sealed(
        R2_PATH,
        field="artifact_content_sha256",
        content_sha=R2_CONTENT_SHA256,
        file_sha=R2_FILE_SHA256,
    )
    if baseline_rebuilt["artifact_content_sha256"] != baseline["artifact_content_sha256"]:
        raise ValueError("r2_rebuild_not_identical")
    r3_advisory = _load_sealed(
        R3_PATH,
        field="artifact_content_sha256",
        content_sha=R3_CONTENT_SHA256,
        file_sha=R3_FILE_SHA256,
    )
    r3_research = _load_sealed(
        R3_RESEARCH_PATH,
        field="artifact_content_sha256",
        content_sha=R3_RESEARCH_CONTENT_SHA256,
        file_sha=R3_RESEARCH_FILE_SHA256,
    )
    derivative_manifest, derivative_members, derivative_by_id = build_govuk_derivatives(baseline)
    hold_ledger = build_hold_ledger(baseline)
    audit = build_corrective_audit(r3_research=r3_research, derivative_manifest=derivative_manifest)
    r3_by_key = _r3_recommendations(r3_advisory)
    source_by_id = {row["authority_identity_id"]: row for row in baseline["source_byte_bindings"]}
    owner_packet = r2._load_inputs()[r2.OWNER_PACKET_PATH.name]
    owner_by_id = {row["row_id"]: row for row in owner_packet["decisions"]}

    row_advisories = []
    residual = []
    action_counts: Counter[str] = Counter()
    support_complete_rows = []
    for row in baseline["row_advisories"]:
        components = []
        for before in row["component_recommendations"]:
            key = (row["row_id"], before["component_ordinal"])
            if key in CHARITY_AFTER:
                recommendation = _charity_recommendation(
                    key=key,
                    before=before,
                    r3_prior=r3_by_key[key],
                    derivative_by_id=derivative_by_id,
                    derivative_bytes=derivative_members,
                )
            elif key in MATTER_INTAKE:
                recommendation = _matter_recommendation(key, before)
            elif key in EXCLUSION_COVERAGE:
                recommendation = _exclusion_recommendation(
                    key, before, owner_by_id=owner_by_id, source_by_id=source_by_id
                )
            else:
                recommendation = _blocker_recommendation(key, before)
                residual.append(
                    _seal(
                        {
                            "schema": "legalbot.v111.phase2a.source-ready-residual-blocker.v1",
                            "row_id": key[0],
                            "component_ordinal": key[1],
                            "proposition": before["before_proposition"],
                            "proposition_text_sha256": before["before_proposition_text_sha256"],
                            "upstream_support_fit": before["upstream_support_fit"],
                            "reason": before["rationale"],
                            "missing_original_dimensions": DEFECT_DIMENSIONS.get(key, []),
                            "r2_recommendation_content_sha256": before[
                                "recommendation_content_sha256"
                            ],
                            "owner_scope_supersession_recommended": False,
                            "material_gap": True,
                        },
                        "record_content_sha256",
                    )
                )
            action_counts[recommendation["action"]] += 1
            components.append(recommendation)
        complete = all(item["component_support_complete_if_owner_adopted"] for item in components)
        if complete:
            support_complete_rows.append(row["row_id"])
        row_advisories.append(
            _seal(
                {
                    "schema": "legalbot.v111.phase2a.source-ready-corrective-row-advisory.v4",
                    "row_id": row["row_id"],
                    "r2_row_record_content_sha256": row["record_content_sha256"],
                    "component_count": len(components),
                    "component_recommendations": components,
                    "component_support_complete_if_owner_adopted": complete,
                    "material_gap_after_exact_owner_adoption": not complete,
                    "qualification_eligible_pre_owner_adoption": False,
                    "qualification_eligible_if_owner_adopts_exact_scope_changes": complete,
                    "answer_release_eligible": False,
                    "owner_decision_applied": False,
                },
                "record_content_sha256",
            )
        )
    expected_actions = {
        "OWNER_SCOPE_SUPERSESSION_TO_ATTRIBUTED_OFFICIAL_GUIDANCE": 6,
        "OWNER_SCOPE_SUPERSESSION_TO_NON_AUTHORITATIVE_MATTER_INTAKE": 12,
        "OWNER_EXCLUDE_DEMONSTRABLY_OVERBROAD_PROPOSITION": 1,
        "RETAIN_BLOCKER_PROPOSITION_COMPLETE_SUPPORT_REQUIRED": 53,
    }
    if dict(action_counts) != expected_actions:
        raise ValueError(f"r4_action_counts_invalid:{dict(action_counts)}")
    if len(row_advisories) != 59 or sum(row["component_count"] for row in row_advisories) != 72:
        raise ValueError("r4_topology_invalid")
    if len(residual) != 53 or len(support_complete_rows) != 11:
        raise ValueError("r4_residual_boundary_invalid")
    residual_ledger = _seal(
        {
            "schema": "legalbot.v111.phase2a.source-ready-residual-blocker-ledger.v1",
            "status": "53_EXACT_COMPONENT_BLOCKERS_REMAIN",
            "record_count": len(residual),
            "residual_row_count": len({row["row_id"] for row in residual}),
            "records": residual,
            **r2.NO_EXECUTION_FLAGS,
        }
    )
    advisory = _seal(
        {
            "schema": "legalbot.v111.phase2a.source-ready-59-corrective-remediation-advisory.v4",
            "status": "NOT_APPROVAL_READY_53_PROPOSITION_COMPLETE_COMPONENT_BLOCKERS_REMAIN",
            "phase_scope": "PHASE2A_ADVISORY_ONLY",
            "advisory_date": ADVISORY_DATE,
            "advisory_effect": "NON_AUTHORIZING_OWNER_RECOMMENDATIONS_ONLY",
            "r2_baseline_content_sha256": R2_CONTENT_SHA256,
            "r3_no_go_content_sha256": R3_CONTENT_SHA256,
            "topology_partition_input_content_sha256": topology["artifact_content_sha256"],
            "hold_ledger_content_sha256": hold_ledger["artifact_content_sha256"],
            "govuk_derivative_manifest_content_sha256": derivative_manifest[
                "artifact_content_sha256"
            ],
            "corrective_audit_content_sha256": audit["artifact_content_sha256"],
            "residual_blocker_ledger_content_sha256": residual_ledger["artifact_content_sha256"],
            "counts": {
                "row_count": 59,
                "blocking_component_input_count": 72,
                "attributed_guidance_scope_supersession_count": 6,
                "matter_intake_scope_supersession_count": 12,
                "demonstrably_overbroad_exclusion_count": 1,
                "retained_blocker_count": 53,
                "residual_material_gap_row_count": residual_ledger["residual_row_count"],
                "support_complete_row_if_owner_adopts_exact_scope_count": 11,
                "r2_hold_record_count": 180,
                "source_byte_binding_count": len(baseline["source_byte_bindings"]),
                "govuk_canonical_derivative_count": 4,
                "no_execution_field_count": len(r2.NO_EXECUTION_FLAGS),
            },
            "action_counts": dict(sorted(action_counts.items())),
            "support_complete_row_ids_if_owner_adopts_exact_scope": sorted(support_complete_rows),
            "row_advisories": row_advisories,
            "source_byte_bindings": baseline["source_byte_bindings"],
            "decision_boundary": {
                "every_r2_hold_mapped": True,
                "no_component_cleared_because_another_full_component_exists": True,
                "only_one_overbroad_component_uses_row_specific_full_coverage_proof": True,
                "matter_facts_reclassified_only_by_exact_owner_scope_recommendation": True,
                "all_incomplete_r3_substantive_rewrites_withdrawn": True,
                "no_undated_legislation_proposition_proposed": True,
                "all_relied_on_guidance_bytes_and_derivatives_bound": True,
                "answer_release_remains_fail_closed": True,
                "not_approval_ready_because_residual_components_remain": True,
                "owner_adoption_required": True,
                "execution_chain_untouched": True,
            },
            **r2.NO_EXECUTION_FLAGS,
        }
    )
    for artifact in (advisory, hold_ledger, derivative_manifest, audit, residual_ledger):
        violations = r2._recursive_no_execution_violations(artifact)
        if violations:
            raise ValueError(f"recursive_no_execution_violation:{violations}")
    return advisory, hold_ledger, derivative_manifest, audit, residual_ledger, derivative_members


def publish(output: Path = OUTPUT_ROOT) -> dict[str, Any]:
    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    advisory, holds, derivatives, audit, residuals, derivative_members = build_advisory()
    artifacts: dict[str, bytes] = {
        ADVISORY_NAME: _pretty_json(advisory),
        HOLD_LEDGER_NAME: _pretty_json(holds),
        DERIVATIVE_MANIFEST_NAME: _pretty_json(derivatives),
        AUDIT_NAME: _pretty_json(audit),
        RESIDUAL_NAME: _pretty_json(residuals),
        **derivative_members,
    }
    package = _seal(
        {
            "schema": "legalbot.v111.phase2a.source-ready-corrective-package.v1",
            "status": advisory["status"],
            "artifact_count": len(artifacts),
            "artifacts": [
                {"member": name, "file_sha256": _sha256(raw)}
                for name, raw in sorted(artifacts.items())
            ],
            "advisory_content_sha256": advisory["artifact_content_sha256"],
            "hold_ledger_content_sha256": holds["artifact_content_sha256"],
            "derivative_manifest_content_sha256": derivatives["artifact_content_sha256"],
            "corrective_audit_content_sha256": audit["artifact_content_sha256"],
            "residual_ledger_content_sha256": residuals["artifact_content_sha256"],
            **r2.NO_EXECUTION_FLAGS,
        },
        "manifest_content_sha256",
    )
    artifacts[PACKAGE_NAME] = _pretty_json(package)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, raw in artifacts.items():
        path = output / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
    lines = [f"{_file_sha256(output / name)}  {name}" for name in sorted(artifacts)]
    checksum = output / CHECKSUMS_NAME
    fd = os.open(checksum, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(("\n".join(lines) + "\n").encode())
    return {
        "status": advisory["status"],
        "output": str(output),
        "advisory_content_sha256": advisory["artifact_content_sha256"],
        "hold_ledger_content_sha256": holds["artifact_content_sha256"],
        "derivative_manifest_content_sha256": derivatives["artifact_content_sha256"],
        "corrective_audit_content_sha256": audit["artifact_content_sha256"],
        "residual_ledger_content_sha256": residuals["artifact_content_sha256"],
        "package_content_sha256": package["manifest_content_sha256"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT_ROOT)
    args = parser.parse_args()
    print(json.dumps(publish(args.output), ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
