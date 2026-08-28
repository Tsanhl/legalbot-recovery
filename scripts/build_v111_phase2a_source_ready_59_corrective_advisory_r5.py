#!/usr/bin/env python3
"""Build the immutable source-ready-59 corrective advisory r5.

R5 preserves r4 and corrects its false row-eligibility boundary.  Matter
intake is non-answering and can only be proposed where every relied legal rule
has an exact official byte/span binding.  Attributed GOV.UK guidance remains
supplementary and cannot remove primary-law dimensions.  Missing PD31B and the
APP reimbursement scheme details remain blockers.  This builder is advisory
only and performs no production operation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import unicodedata
from collections import Counter
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
for entry in (str(BACKEND_ROOT), str(PROJECT_ROOT)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from app.ingestion.models import ParseStatus  # noqa: E402
from app.ingestion.parsers import ParserRegistry  # noqa: E402
from scripts import build_v111_phase2a_source_ready_59_corrective_advisory_r4 as r4  # noqa: E402
from scripts import build_v111_phase2a_source_ready_59_remediation_advisory_r2 as r2  # noqa: E402
from scripts import build_v111_phase2a_source_ready_59_substantive_advisory as r3  # noqa: E402

REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
R4_ROOT = REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-source-ready-59-corrective-advisory-r4"
R4_PATH = R4_ROOT / r4.ADVISORY_NAME
R4_CONTENT_SHA256 = "b9ba41f44ee0ffedcbd502491fe2288b73998786987537e1be28472f603743e0"
R4_FILE_SHA256 = "900a2f756f15c99bf93ed62923fcfc684c6ed4b62633199cc428f042dd28649d"
R4_DERIVATIVE_PATH = R4_ROOT / r4.DERIVATIVE_MANIFEST_NAME
R4_DERIVATIVE_CONTENT_SHA256 = "04e9433e85cd69c9cccfebc1bf81cb990a273cc245a6089a091697adecad9344"
R4_DERIVATIVE_FILE_SHA256 = "bc9e540d2348f77c6dc81663247487c361eaa15e958050a9ecd10ab50cfde00a"
R4_HOLD_PATH = R4_ROOT / r4.HOLD_LEDGER_NAME
R4_HOLD_CONTENT_SHA256 = "73d8ffc1d9645d3d50ca353cf6508c9227df49d1a322341579965d8e8da2eb29"
R4_HOLD_FILE_SHA256 = "b9e3c221f851f6bd225075819c32f68a5779e2374d17e0eeb70705a55162d394"

OUTPUT_ROOT = REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-source-ready-59-corrective-advisory-r5"
ADVISORY_NAME = "SOURCE-READY-59-CORRECTIVE-REMEDIATION-ADVISORY-R5.json"
HOLD_LEDGER_NAME = "R2-HOLD-DISPOSITION-LEDGER-R5.json"
COVERAGE_NAME = "RETAINED-FULL-BYTE-SPAN-COVERAGE-LEDGER.json"
AUDIT_NAME = "R4-NO-GO-CORRECTIVE-AUDIT-R5.json"
RESIDUAL_NAME = "RESIDUAL-BLOCKER-LEDGER-R5.json"
DERIVATIVE_MANIFEST_NAME = r4.DERIVATIVE_MANIFEST_NAME
PACKAGE_NAME = "PACKAGE-MANIFEST.json"
CHECKSUMS_NAME = "SHA256SUMS.txt"

QUARANTINE_MANIFEST_PATH = r2.QUARANTINE_MANIFEST_PATH
QUARANTINE_ROOT = r2.QUARANTINE_ROOT
OWNER_PACKET_PATH = r2.OWNER_PACKET_PATH

MATTER_COVERAGE_COMPONENTS = {
    ("live30-q16:issue-02", 3): [1, 2],
    ("live30-q16:issue-03", 3): [1, 2],
    ("live30-q16:issue-04", 3): [1, 2],
    ("live30-q18:issue-01", 2): [1, 3],
    ("live30-q18:issue-02", 3): [1, 2, 4],
    ("live30-q18:issue-05", 3): [1],
}
BLOCKED_MATTER_COMPONENTS = {
    (
        "live30-q18:issue-01",
        4,
    ): "PSR_APP_SCHEME_RULE_EFFECTIVE_DATE_CORPORATE_ELIGIBILITY_AND_EXCEPTIONS_NOT_BOUND",
    ("live30-q30:issue-04", 1): "NO_COMPONENT_SPECIFIC_INDEPENDENT_LEGAL_RULE_COVERAGE",
    ("live30-q30:issue-04", 2): "NO_COMPONENT_SPECIFIC_INDEPENDENT_LEGAL_RULE_COVERAGE",
    ("live30-q30:issue-04", 3): "NO_COMPONENT_SPECIFIC_INDEPENDENT_LEGAL_RULE_COVERAGE",
    ("live30-q30:issue-04", 4): "NO_COMPONENT_SPECIFIC_INDEPENDENT_LEGAL_RULE_COVERAGE",
    (
        "live30-q30:issue-04",
        5,
    ): "PD31B_OFFICIAL_REPRESENTATION_UNAVAILABLE_AND_NO_COMPONENT_SPECIFIC_RULE_COVERAGE",
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


def _load_sealed(path: Path, field: str, content_sha: str, file_sha: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or _file_sha256(path) != file_sha:
        raise ValueError(f"sealed_input_file_invalid:{path.name}")
    value = json.loads(path.read_bytes())
    material = dict(value)
    observed = str(material.pop(field, ""))
    if observed != content_sha or _sha256(_canonical_json(material)) != observed:
        raise ValueError(f"sealed_input_content_invalid:{path.name}")
    return value


def _normalise(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).split())


def _supplemental_simon_binding(quarantine: dict[str, Any]) -> tuple[dict[str, Any], Path]:
    identity = "neutral-citation:[2014] EWCA Civ 280"
    record = next(
        row
        for row in quarantine["records"]
        if row["authority_identity_id"] == identity
        and row.get("selected_for_proposed_admission") is True
    )
    path = QUARANTINE_ROOT / record["quarantine_member"]
    if (
        path.is_symlink()
        or not path.is_file()
        or path.parent.resolve() != QUARANTINE_ROOT.resolve()
        or _file_sha256(path) != record["raw_sha256"]
        or record["canonical_content_sha256"] is None
    ):
        raise ValueError("simon_official_byte_binding_invalid")
    text, mode = r2._representation_text(path)
    binding = _seal(
        {
            "schema": "legalbot.v111.phase2a.supplemental-full-authority-byte-binding.v1",
            "authority_identity_id": identity,
            "citation": "Simon v Byford [2014] EWCA Civ 280",
            "official_url": "https://caselaw.nationalarchives.gov.uk/ewca/civ/2014/280",
            "official_source_role": "PRIMARY_JUDGMENT_OFFICIAL",
            "quarantine_manifest_record_content_sha256": record["record_content_sha256"],
            "representation_member": record["quarantine_member"],
            "representation_file_sha256": record["raw_sha256"],
            "canonical_content_sha256": record["canonical_content_sha256"],
            "proposed_source_version_id": record["proposed_source_version_id"],
            "derived_normalized_representation_text_sha256": _sha256(text.encode()),
            "representation_parse_mode": mode,
            "representation_byte_hash_verified": True,
            "source_admission_authorized": False,
            "source_admitted": False,
        },
        "record_content_sha256",
    )
    return binding, path


def _paragraph_numbers(locator: str) -> list[int]:
    values: set[int] = set()
    for start, end in re.findall(r"(\d+)(?:\s*[-–]\s*(\d+))?", locator):
        first = int(start)
        last = int(end) if end else first
        if last < first or last - first > 100:
            raise ValueError(f"invalid_paragraph_range:{locator}")
        values.update(range(first, last + 1))
    return sorted(values)


def _parse_source(path: Path, parse_mode: str) -> tuple[Any, str]:
    filename = (
        "source.xml"
        if parse_mode == "XML_ITERATION_TEXT"
        else "source.md"
        if parse_mode == "UTF8_CANONICAL_MARKDOWN"
        else path.name
    )
    parsed = ParserRegistry.default().parse(path.read_bytes(), filename=filename)
    if parsed.status is not ParseStatus.READY or not parsed.body_blocks:
        raise ValueError(f"coverage_source_parse_invalid:{path.name}")
    return parsed, filename


def _locator_excerpt_texts(identity: str, locator: str, parsed: Any) -> list[str]:
    if identity.startswith("neutral-citation:"):
        numbers = _paragraph_numbers(locator)
        texts = []
        for number in numbers:
            prefix = f"paragraph {number} "
            block = next(
                (row for row in parsed.body_blocks if row.text.casefold().startswith(prefix)),
                None,
            )
            if block is None:
                numbered = re.compile(rf"(?:^|\s){number}\.\s")
                block = next(
                    (row for row in parsed.body_blocks if numbered.search(row.text)),
                    None,
                )
            if block is None:
                raise ValueError(f"coverage_paragraph_missing:{identity}:{number}")
            if block.text not in texts:
                texts.append(block.text)
        return texts
    if identity == "ukpga:2023:29":
        section = [row.text for row in parsed.body_blocks if row.text.startswith("section 72 ")]
        if locator == "section 72(1)-(2)":
            return section[:4]
        if locator == "section 72(5) and (9)-(11)":
            wanted = [section[8], *section[12:16]]
            definitions = [
                row.text
                for row in parsed.body_blocks
                if row.text.startswith(("“the Faster Payments Scheme”", "“relevant requirement”"))
            ]
            return [*wanted, *definitions]
    if identity == "ukpga:1986:45" and locator == "section 208(1)-(4)":
        return [row.text for row in parsed.body_blocks if row.text.startswith("section 208 ")][:11]
    raise ValueError(f"coverage_locator_extractor_missing:{identity}:{locator}")


def _source_binding_and_path(
    identity: str,
    baseline_by_id: dict[str, dict[str, Any]],
    simon_binding: dict[str, Any],
    simon_path: Path,
) -> tuple[dict[str, Any], Path]:
    if identity == simon_binding["authority_identity_id"]:
        return simon_binding, simon_path
    binding = baseline_by_id.get(identity)
    if binding is None:
        raise ValueError(f"retained_full_source_unbound:{identity}")
    return binding, r3._binding_path(binding)


def _full_component_proof(
    *,
    row_id: str,
    component_ordinal: int,
    owner_by_id: dict[str, Any],
    baseline_by_id: dict[str, dict[str, Any]],
    simon_binding: dict[str, Any],
    simon_path: Path,
) -> dict[str, Any]:
    decision = owner_by_id[row_id]
    component = decision["source_research_record"]["atomic_components"][component_ordinal - 1]
    if component["support_fit"] != "FULL":
        raise ValueError(f"relied_component_not_full:{row_id}:{component_ordinal}")
    source_spans = []
    for authority_ordinal, authority in enumerate(component["authorities"], start=1):
        assessment = next(
            item
            for item in decision["authority_assessments"]
            if item["component_ordinal"] == component_ordinal
            and item["authority_ordinal"] == authority_ordinal
        )
        identity = assessment["canonical_authority_identity_id"]
        binding, path = _source_binding_and_path(
            identity, baseline_by_id, simon_binding, simon_path
        )
        parsed, parser_filename = _parse_source(path, binding["representation_parse_mode"])
        locators = []
        for locator in authority["exact_locators"]:
            excerpts = _locator_excerpt_texts(identity, locator, parsed)
            if not excerpts:
                raise ValueError(f"retained_full_empty_span:{row_id}:{component_ordinal}")
            locators.append(
                _seal(
                    {
                        "schema": "legalbot.v111.phase2a.retained-full-frozen-span.v1",
                        "exact_locator": locator,
                        "supporting_excerpts": [
                            {
                                "text": text,
                                "normalised_text_sha256": _sha256(_normalise(text).encode()),
                            }
                            for text in excerpts
                        ],
                        "source_binding_content_sha256": binding["record_content_sha256"],
                        "representation_file_sha256": binding["representation_file_sha256"],
                        "parser_filename_class": parser_filename,
                        "owner_adopted": False,
                        "frozen_for_execution": False,
                    },
                    "span_content_sha256",
                )
            )
        source_spans.append(
            {
                "authority_ordinal": authority_ordinal,
                "citation": authority["citation"],
                "authority_identity_id": identity,
                "authority_assessment_content_sha256": assessment["assessment_content_sha256"],
                "source_binding_content_sha256": binding["record_content_sha256"],
                "representation_file_sha256": binding["representation_file_sha256"],
                "official_source_role": binding["official_source_role"],
                "frozen_spans": locators,
            }
        )
    return _seal(
        {
            "schema": "legalbot.v111.phase2a.retained-full-component-byte-span-proof.v1",
            "row_id": row_id,
            "component_ordinal": component_ordinal,
            "proposition": component["proposition"],
            "proposition_text_sha256": _sha256(component["proposition"].encode()),
            "upstream_support_fit": "FULL",
            "owner_decision_content_sha256": decision["decision_content_sha256"],
            "source_spans": source_spans,
            "exact_byte_and_span_binding_complete": True,
            "currentness_and_later_treatment_release_holds_retained": True,
            "answer_release_eligible": False,
            "owner_adopted": False,
        },
        "record_content_sha256",
    )


def build_coverage_ledger(
    *,
    baseline: dict[str, Any],
    owner_packet: dict[str, Any],
    quarantine: dict[str, Any],
) -> tuple[dict[str, Any], dict[tuple[str, int], list[str]], dict[str, Any], dict[str, Any]]:
    baseline_by_id = {row["authority_identity_id"]: row for row in baseline["source_byte_bindings"]}
    owner_by_id = {row["row_id"]: row for row in owner_packet["decisions"]}
    simon_binding, simon_path = _supplemental_simon_binding(quarantine)
    proofs = []
    action_bindings: dict[tuple[str, int], list[str]] = {}
    seen: set[tuple[str, int]] = set()
    for action_key, component_ordinals in MATTER_COVERAGE_COMPONENTS.items():
        hashes = []
        for component_ordinal in component_ordinals:
            proof_key = (action_key[0], component_ordinal)
            if proof_key in seen:
                raise ValueError(f"duplicate_retained_full_component:{proof_key}")
            seen.add(proof_key)
            proof = _full_component_proof(
                row_id=action_key[0],
                component_ordinal=component_ordinal,
                owner_by_id=owner_by_id,
                baseline_by_id=baseline_by_id,
                simon_binding=simon_binding,
                simon_path=simon_path,
            )
            proofs.append(proof)
            hashes.append(proof["record_content_sha256"])
        action_bindings[action_key] = hashes
    if len(proofs) != 12:
        raise ValueError(f"retained_full_coverage_count_invalid:{len(proofs)}")
    exclusion_proof = _full_component_proof(
        row_id="live30-q13:issue-02",
        component_ordinal=1,
        owner_by_id=owner_by_id,
        baseline_by_id=baseline_by_id,
        simon_binding=simon_binding,
        simon_path=simon_path,
    )
    pd31b = next(
        row
        for row in quarantine["records"]
        if row["authority_identity_id"]
        == "official-url:https://justice.gov.uk/courts/procedure-rules/civil/rules/part31/pd_part31b"
    )
    if pd31b.get("raw_sha256") is not None or pd31b.get("result") != "COLLECTION_FAILED_HELD":
        raise ValueError("pd31b_hold_boundary_changed")
    ledger = _seal(
        {
            "schema": "legalbot.v111.phase2a.retained-full-byte-span-coverage-ledger.v1",
            "status": "12_RELIED_FULL_COMPONENTS_EXACTLY_BYTE_AND_SPAN_BOUND",
            "record_count": len(proofs),
            "records": proofs,
            "additional_exact_exclusion_coverage_proof": exclusion_proof,
            "matter_action_count": len(action_bindings),
            "matter_action_bindings": [
                {
                    "row_id": key[0],
                    "component_ordinal": key[1],
                    "retained_full_component_proof_content_sha256s": hashes,
                }
                for key, hashes in sorted(action_bindings.items())
            ],
            "supplemental_source_bindings": [simon_binding],
            "pd31b_disposition": {
                "authority_identity_id": pd31b["authority_identity_id"],
                "quarantine_record_content_sha256": pd31b["record_content_sha256"],
                "hold_reason_codes": pd31b["hold_reason_codes"],
                "raw_representation_available": False,
                "affected_row_retained_blocked": "live30-q30:issue-04",
            },
            **r2.NO_EXECUTION_FLAGS,
        }
    )
    return ledger, action_bindings, simon_binding, exclusion_proof


def build_hold_ledger(r4_holds: dict[str, Any]) -> dict[str, Any]:
    records = []
    for old in r4_holds["records"]:
        disposition = old["disposition"]
        explanation = old["disposition_explanation"]
        if disposition == "OUTSIDE_EXPLICIT_SCOPE":
            disposition = "RETAINED_RELEASE"
            explanation = (
                "The primary-law, election, conflict, restricted-donation, or nexus "
                "dimension remains an operative blocker; supplementary guidance does not remove it."
            )
        material = {
            key: value
            for key, value in old.items()
            if key not in {"record_content_sha256", "disposition", "disposition_explanation"}
        }
        records.append(
            _seal(
                {
                    **material,
                    "schema": "legalbot.v111.phase2a.r2-hold-disposition-record.r5.v1",
                    "disposition": disposition,
                    "disposition_explanation": explanation,
                },
                "record_content_sha256",
            )
        )
    if len(records) != 180 or len({row["r2_hold_record_content_sha256"] for row in records}) != 180:
        raise ValueError("r5_hold_topology_invalid")
    return _seal(
        {
            "schema": "legalbot.v111.phase2a.r2-hold-disposition-ledger.r5.v1",
            "status": "ALL_180_R2_HOLDS_OPERATIVE_NONE_RESOLVED",
            "r2_baseline_content_sha256": r4.R2_CONTENT_SHA256,
            "r4_hold_ledger_content_sha256": R4_HOLD_CONTENT_SHA256,
            "record_count": 180,
            "disposition_counts": dict(
                sorted(Counter(row["disposition"] for row in records).items())
            ),
            "records": records,
            **r2.NO_EXECUTION_FLAGS,
        }
    )


def _non_answer_contract(requested: list[str]) -> dict[str, Any]:
    response = (
        "The available matter information is insufficient to determine this point. "
        "Please provide: "
        + "; ".join(requested)
        + ". I can then route the matter for qualified human legal review."
    )
    return {
        "schema": "legalbot.v111.phase2a.proposed-matter-information-gap-non-answer.v1",
        "reason_code": "MATTER_INFORMATION_INSUFFICIENT",
        "matter_information_gap_event": True,
        "knowledge_gap_event": False,
        "ui_cta_code": "PROVIDE_MISSING_INFORMATION_OR_REQUEST_HUMAN_REVIEW",
        "offer_qualified_human_legal_review": True,
        "requested_facts_or_documents": requested,
        "exact_non_answer_response": response,
        "exact_non_answer_response_sha256": _sha256(response.encode()),
        "legal_claim_released": False,
        "citation_released": False,
        "evidence_span_released": False,
        "answer_model_output_allowed": False,
        "owner_adopted": False,
        "applied": False,
        "evaluation_contract_mutated": False,
    }


def _recommendation(
    *,
    old: dict[str, Any],
    coverage_hashes: list[str] | None,
    exclusion_proof: dict[str, Any],
) -> dict[str, Any]:
    key = (old["row_id"], old["component_ordinal"])
    base = {
        "schema": "legalbot.v111.phase2a.source-ready-corrective-component-advisory.r5.v1",
        "row_id": old["row_id"],
        "component_ordinal": old["component_ordinal"],
        "before_proposition": old["before_proposition"],
        "before_proposition_text_sha256": old["before_proposition_text_sha256"],
        "upstream_support_fit": old["upstream_support_fit"],
        "r4_recommendation_content_sha256": old["recommendation_content_sha256"],
        "qualification_eligible": False,
        "answer_release_eligible": False,
        "owner_adopted": False,
        "applied": False,
    }
    if key in MATTER_COVERAGE_COMPONENTS:
        requested = r4.MATTER_INTAKE[key]
        return _seal(
            {
                **base,
                "action": "PROPOSE_MATTER_INFORMATION_GAP_NON_ANSWER_WITH_BOUND_LEGAL_RULES",
                "after_propositions": [],
                "retained_full_component_proof_content_sha256s": coverage_hashes,
                "retained_full_coverage_complete": True,
                "proposed_non_answer_contract": _non_answer_contract(requested),
                "component_disposition_ready_for_owner_consideration": True,
                "material_gap_if_exact_contract_adopted": False,
                "material_gap_now": True,
            },
            "recommendation_content_sha256",
        )
    if key in BLOCKED_MATTER_COMPONENTS:
        return _seal(
            {
                **base,
                "action": "RETAIN_BLOCKER_MATTER_SCOPE_CONTRACT_UNSUPPORTED",
                "after_propositions": [],
                "retained_full_component_proof_content_sha256s": [],
                "proposed_non_answer_contract": None,
                "blocker_reason_code": BLOCKED_MATTER_COMPONENTS[key],
                "component_disposition_ready_for_owner_consideration": False,
                "material_gap_now": True,
            },
            "recommendation_content_sha256",
        )
    if key in r4.CHARITY_AFTER:
        return _seal(
            {
                **base,
                "action": "RETAIN_BLOCKER_WITH_SUPPLEMENTARY_ATTRIBUTED_GUIDANCE_SNAPSHOT",
                "after_propositions": [],
                "supplementary_attributed_guidance_snapshot": old["after_propositions"],
                "supplementary_frozen_evidence_spans": old["frozen_evidence_span_proposals"],
                "removed_primary_dimensions": r4.CHARITY_REMOVED_DIMENSIONS[key],
                "removed_primary_dimensions_remain_blockers": True,
                "contract_or_scope_mutation_proposed": False,
                "component_disposition_ready_for_owner_consideration": False,
                "material_gap_now": True,
            },
            "recommendation_content_sha256",
        )
    if key in r4.EXCLUSION_COVERAGE:
        return _seal(
            {
                **base,
                "action": "OWNER_EXCLUDE_DEMONSTRABLY_OVERBROAD_PROPOSITION",
                "after_propositions": [],
                "row_specific_redundancy_and_coverage_proof": [exclusion_proof],
                "exact_owner_scope_supersession_recommendation": old[
                    "exact_owner_scope_supersession_recommendation"
                ],
                "component_disposition_ready_for_owner_consideration": True,
                "material_gap_if_exact_exclusion_adopted": False,
                "material_gap_now": True,
            },
            "recommendation_content_sha256",
        )
    return _seal(
        {
            **base,
            "action": "RETAIN_BLOCKER_PROPOSITION_COMPLETE_SUPPORT_REQUIRED",
            "after_propositions": [],
            "missing_original_dimensions": old.get("missing_original_dimensions", []),
            "source_inspection": old.get("source_inspection", []),
            "component_disposition_ready_for_owner_consideration": False,
            "material_gap_now": True,
        },
        "recommendation_content_sha256",
    )


def build_advisory() -> tuple[
    dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, bytes]
]:
    r4_advisory = _load_sealed(
        R4_PATH, "artifact_content_sha256", R4_CONTENT_SHA256, R4_FILE_SHA256
    )
    r4_holds = _load_sealed(
        R4_HOLD_PATH, "artifact_content_sha256", R4_HOLD_CONTENT_SHA256, R4_HOLD_FILE_SHA256
    )
    derivative_manifest = _load_sealed(
        R4_DERIVATIVE_PATH,
        "artifact_content_sha256",
        R4_DERIVATIVE_CONTENT_SHA256,
        R4_DERIVATIVE_FILE_SHA256,
    )
    derivative_members = {
        record["canonical_derivative_member"]: (
            R4_ROOT / record["canonical_derivative_member"]
        ).read_bytes()
        for record in derivative_manifest["records"]
    }
    for record in derivative_manifest["records"]:
        if (
            _sha256(derivative_members[record["canonical_derivative_member"]])
            != record["canonical_derivative_file_sha256"]
        ):
            raise ValueError("r4_derivative_member_invalid")
    baseline = _load_sealed(
        r4.R2_PATH,
        "artifact_content_sha256",
        r4.R2_CONTENT_SHA256,
        r4.R2_FILE_SHA256,
    )
    inputs = r2._load_inputs()
    owner_packet = inputs[OWNER_PACKET_PATH.name]
    quarantine = inputs[QUARANTINE_MANIFEST_PATH.name]
    coverage, action_bindings, simon_binding, exclusion_proof = build_coverage_ledger(
        baseline=baseline, owner_packet=owner_packet, quarantine=quarantine
    )
    holds = build_hold_ledger(r4_holds)

    rows = []
    residuals = []
    actions: Counter[str] = Counter()
    support_ready_rows = []
    for old_row in r4_advisory["row_advisories"]:
        recommendations = []
        for old in old_row["component_recommendations"]:
            key = (old["row_id"], old["component_ordinal"])
            rec = _recommendation(
                old=old,
                coverage_hashes=action_bindings.get(key),
                exclusion_proof=exclusion_proof,
            )
            recommendations.append(rec)
            actions[rec["action"]] += 1
            if not rec["component_disposition_ready_for_owner_consideration"]:
                residuals.append(
                    _seal(
                        {
                            "schema": "legalbot.v111.phase2a.source-ready-residual-blocker.r5.v1",
                            "row_id": key[0],
                            "component_ordinal": key[1],
                            "proposition": old["before_proposition"],
                            "proposition_text_sha256": old["before_proposition_text_sha256"],
                            "action": rec["action"],
                            "reason": rec.get(
                                "blocker_reason_code",
                                "PROPOSITION_COMPLETE_SUPPORT_OR_PRIMARY_DIMENSION_MISSING",
                            ),
                            "material_gap": True,
                        },
                        "record_content_sha256",
                    )
                )
        ready = all(
            rec["component_disposition_ready_for_owner_consideration"] for rec in recommendations
        )
        if ready:
            support_ready_rows.append(old_row["row_id"])
        rows.append(
            _seal(
                {
                    "schema": "legalbot.v111.phase2a.source-ready-corrective-row-advisory.r5.v1",
                    "row_id": old_row["row_id"],
                    "r4_row_record_content_sha256": old_row["record_content_sha256"],
                    "component_count": len(recommendations),
                    "component_recommendations": recommendations,
                    "whole_row_support_ready_for_owner_consideration": ready,
                    "qualification_eligible": False,
                    "qualification_eligibility_not_predeclared": True,
                    "material_gap_now": True,
                    "answer_release_eligible": False,
                    "owner_decision_applied": False,
                },
                "record_content_sha256",
            )
        )
    expected_actions = {
        "PROPOSE_MATTER_INFORMATION_GAP_NON_ANSWER_WITH_BOUND_LEGAL_RULES": 6,
        "RETAIN_BLOCKER_MATTER_SCOPE_CONTRACT_UNSUPPORTED": 6,
        "RETAIN_BLOCKER_WITH_SUPPLEMENTARY_ATTRIBUTED_GUIDANCE_SNAPSHOT": 6,
        "OWNER_EXCLUDE_DEMONSTRABLY_OVERBROAD_PROPOSITION": 1,
        "RETAIN_BLOCKER_PROPOSITION_COMPLETE_SUPPORT_REQUIRED": 53,
    }
    if dict(actions) != expected_actions:
        raise ValueError(f"r5_action_counts_invalid:{dict(actions)}")
    if len(rows) != 59 or sum(row["component_count"] for row in rows) != 72:
        raise ValueError("r5_topology_invalid")
    if len(residuals) != 65 or len({row["row_id"] for row in residuals}) != 55:
        raise ValueError("r5_residual_boundary_invalid")
    if sorted(support_ready_rows) != [
        "live30-q16:issue-02",
        "live30-q16:issue-03",
        "live30-q16:issue-04",
        "live30-q18:issue-02",
    ]:
        raise ValueError(f"r5_support_ready_rows_invalid:{support_ready_rows}")
    residual_ledger = _seal(
        {
            "schema": "legalbot.v111.phase2a.source-ready-residual-blocker-ledger.r5.v1",
            "status": "65_EXACT_COMPONENT_BLOCKERS_REMAIN_ACROSS_55_ROWS",
            "record_count": len(residuals),
            "residual_row_count": len({row["row_id"] for row in residuals}),
            "records": residuals,
            **r2.NO_EXECUTION_FLAGS,
        }
    )
    audit = _seal(
        {
            "schema": "legalbot.v111.phase2a.r4-no-go-corrective-audit.r5.v1",
            "status": "R4_NO_GO_CORRECTED_FAIL_CLOSED",
            "r4_advisory_content_sha256": R4_CONTENT_SHA256,
            "corrections": {
                "all_row_qualification_eligibility_false": True,
                "whole_row_support_ready_is_not_qualification_eligibility": True,
                "relied_full_component_byte_span_proof_count": coverage["record_count"],
                "simon_official_bytes_and_canonical_identity_bound": True,
                "pd31b_row_retained_because_official_representation_unavailable": True,
                "app_reimbursement_component_retained_for_missing_scheme_details": True,
                "charity_guidance_supplementary_only_primary_dimensions_retained": True,
                "matter_contracts_are_non_answering_unapplied_owner_proposals": True,
                "audit_only_whole_schedule_locator_removed": True,
            },
            "pd31b_quarantine_hold": coverage["pd31b_disposition"],
            "supplemental_simon_binding_content_sha256": simon_binding["record_content_sha256"],
            **r2.NO_EXECUTION_FLAGS,
        }
    )
    advisory = _seal(
        {
            "schema": "legalbot.v111.phase2a.source-ready-59-corrective-remediation-advisory.r5.v1",
            "status": "NOT_APPROVAL_READY_65_COMPONENT_BLOCKERS_REMAIN_ACROSS_55_ROWS",
            "phase_scope": "PHASE2A_ADVISORY_ONLY",
            "advisory_date": "2026-08-28",
            "advisory_effect": "NON_AUTHORIZING_OWNER_RECOMMENDATIONS_ONLY",
            "r4_advisory_content_sha256": R4_CONTENT_SHA256,
            "r2_baseline_content_sha256": r4.R2_CONTENT_SHA256,
            "hold_ledger_content_sha256": holds["artifact_content_sha256"],
            "coverage_ledger_content_sha256": coverage["artifact_content_sha256"],
            "govuk_derivative_manifest_content_sha256": derivative_manifest[
                "artifact_content_sha256"
            ],
            "corrective_audit_content_sha256": audit["artifact_content_sha256"],
            "residual_ledger_content_sha256": residual_ledger["artifact_content_sha256"],
            "counts": {
                "row_count": 59,
                "blocking_component_input_count": 72,
                "non_answer_matter_contract_proposal_count": 6,
                "blocked_matter_component_count": 6,
                "supplementary_guidance_blocked_component_count": 6,
                "exact_overbreadth_exclusion_count": 1,
                "retained_other_blocker_count": 53,
                "residual_blocker_count": 65,
                "residual_row_count": 55,
                "whole_row_support_ready_for_owner_consideration_count": 4,
                "qualification_eligible_row_count": 0,
                "r2_hold_record_count": 180,
                "retained_full_byte_span_proof_count": 12,
                "additional_exact_exclusion_byte_span_proof_count": 1,
                "baseline_source_binding_count": 77,
                "supplemental_source_binding_count": 1,
                "no_execution_field_count": len(r2.NO_EXECUTION_FLAGS),
            },
            "action_counts": dict(sorted(actions.items())),
            "whole_row_support_ready_for_owner_consideration_ids": sorted(support_ready_rows),
            "row_advisories": rows,
            "baseline_source_byte_bindings": baseline["source_byte_bindings"],
            "supplemental_source_byte_bindings": [simon_binding],
            "decision_boundary": {
                "no_row_qualification_eligibility_predeclared": True,
                "matter_non_answer_contract_requires_exact_owner_adoption": True,
                "supplementary_guidance_never_replaces_primary_law": True,
                "pd31b_not_retried_and_q30_remains_blocked": True,
                "app_reimbursement_scheme_details_remain_blocked": True,
                "all_180_holds_remain_operative": True,
                "no_audit_only_whole_schedule_locator": True,
                "not_approval_ready": True,
            },
            **r2.NO_EXECUTION_FLAGS,
        }
    )
    for artifact in (advisory, holds, coverage, audit, residual_ledger):
        violations = r2._recursive_no_execution_violations(artifact)
        if violations:
            raise ValueError(f"recursive_no_execution_violation:{violations}")
    return advisory, holds, coverage, audit, residual_ledger, derivative_members


def publish(output: Path = OUTPUT_ROOT) -> dict[str, Any]:
    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    advisory, holds, coverage, audit, residuals, derivative_members = build_advisory()
    derivative_manifest = _load_sealed(
        R4_DERIVATIVE_PATH,
        "artifact_content_sha256",
        R4_DERIVATIVE_CONTENT_SHA256,
        R4_DERIVATIVE_FILE_SHA256,
    )
    artifacts = {
        ADVISORY_NAME: _pretty_json(advisory),
        HOLD_LEDGER_NAME: _pretty_json(holds),
        COVERAGE_NAME: _pretty_json(coverage),
        AUDIT_NAME: _pretty_json(audit),
        RESIDUAL_NAME: _pretty_json(residuals),
        DERIVATIVE_MANIFEST_NAME: _pretty_json(derivative_manifest),
        **derivative_members,
    }
    package = _seal(
        {
            "schema": "legalbot.v111.phase2a.source-ready-corrective-package.r5.v1",
            "status": advisory["status"],
            "artifact_count": len(artifacts),
            "artifacts": [
                {"member": name, "file_sha256": _sha256(raw)}
                for name, raw in sorted(artifacts.items())
            ],
            "advisory_content_sha256": advisory["artifact_content_sha256"],
            "hold_ledger_content_sha256": holds["artifact_content_sha256"],
            "coverage_ledger_content_sha256": coverage["artifact_content_sha256"],
            "corrective_audit_content_sha256": audit["artifact_content_sha256"],
            "residual_ledger_content_sha256": residuals["artifact_content_sha256"],
            **r2.NO_EXECUTION_FLAGS,
        },
        "manifest_content_sha256",
    )
    artifacts[PACKAGE_NAME] = _pretty_json(package)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, raw in artifacts.items():
        fd = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
    lines = [f"{_file_sha256(output / name)}  {name}" for name in sorted(artifacts)]
    fd = os.open(output / CHECKSUMS_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(("\n".join(lines) + "\n").encode())
    return {
        "status": advisory["status"],
        "output": str(output),
        "advisory_content_sha256": advisory["artifact_content_sha256"],
        "coverage_content_sha256": coverage["artifact_content_sha256"],
        "hold_content_sha256": holds["artifact_content_sha256"],
        "audit_content_sha256": audit["artifact_content_sha256"],
        "residual_content_sha256": residuals["artifact_content_sha256"],
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
