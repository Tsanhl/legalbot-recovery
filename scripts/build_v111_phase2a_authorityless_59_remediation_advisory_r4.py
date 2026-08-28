#!/usr/bin/env python3
"""Build immutable authorityless-cohort r4 with exact span-bound repairs.

R4 supersedes the sealed r3 advisory.  It fixes two independently audited
FULL-component defects and reduces the residual material-gap rows from 55 to
52.  Every other residual is retained; no row is cleared merely because a
different FULL component exists.

The artifact is advisory-only.  It performs no source admission, scan, build,
embedding, qualification, pointer write, answer execution, or release.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import build_v111_phase2a_authorityless_59_remediation_advisory as r2
from scripts import build_v111_phase2a_authorityless_59_remediation_advisory_r3 as r3

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
R3_ROOT = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-authorityless-cohort-59-remediation-advisory-r3"
)
R3_ADVISORY_PATH = R3_ROOT / "AUTHORITYLESS-COHORT-59-REMEDIATION-ADVISORY-R3.json"
OUTPUT_ROOT = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-authorityless-cohort-59-remediation-advisory-r4"
)
ADVISORY_NAME = "AUTHORITYLESS-COHORT-59-REMEDIATION-ADVISORY-R4.json"
PACKAGE_NAME = "PACKAGE-MANIFEST.json"
CHECKSUMS_NAME = "SHA256SUMS.txt"

R3_BUILDER_FILE_SHA256 = "2f73394b0a8952623bc0a59d11368571215c260aa131c4f7d3d12134108f1bad"
R3_ADVISORY_CONTENT_SHA256 = "a3e4cdfc84db910a23a1c26b471c4febac82910f45f1b30a09c3d5256cf3a18a"
R3_ADVISORY_FILE_SHA256 = "6cb7696369ae2a509af91c5dc9fa08b610fcc09d0fc6f93c42ada07734aa54e4"

NO_EXECUTION_FLAGS = dict(r3.NO_EXECUTION_FLAGS)

RESOLVED_R3_RESIDUAL_ROWS = frozenset(
    {"live30-q12:issue-06", "live30-q16:issue-06", "live30-q30:issue-02"}
)
FUTURE_SUPPORT_READY_ROWS = frozenset(
    set(r3.FUTURE_SUPPORT_READY_ROWS) | set(RESOLVED_R3_RESIDUAL_ROWS)
)

Q12_AFTER = (
    "Bloomberg confirms that misuse of private information is a distinct cause of "
    "action from breach of confidence and records the integration of Articles 8 and "
    "10 values into that private-law development; it does not establish a freestanding "
    "direct Convention claim against every private person."
)
Q30_AFTER = (
    "Common-law procedural fairness protects meaningful participation by a person "
    "whose rights are significantly affected by an administrative or judicial "
    "decision, provided the person has something relevant to say; the procedure "
    "required remains context-specific."
)
Q58_CORRECTED = (
    "A non-party may enforce a term under the Contracts (Rights of Third Parties) Act "
    "1999 only if section 1 and the contract's contrary-intention and identification "
    "rules are satisfied. Section 7(1) preserves any third-party right or remedy that "
    "exists or is available apart from the Act, including any right arising under a "
    "separate signed direct agreement."
)
Q59_CORRECTED = (
    "Under Competition Act 1998 section 49C, a person may apply to the CMA for approval "
    "of a redress scheme and the CMA may consider the application before the related "
    "infringement decision. The CMA may approve only after that decision, or, for a CMA "
    "decision, at the same time as the decision. Sections 49D and 49E then govern the "
    "approved scheme's terms, statutory duty and specified civil enforcement routes."
)

Q16_INTAKE = (
    "Obtain the complete 2018 and 2025 testamentary documents, execution and revocation "
    "records, residuary provisions and surviving-relative facts."
)
Q30_INTAKE = (
    "Obtain the exact benefits statutory scheme, decision, reasons, notice, evidence "
    "supplied, opportunity to respond, internal review or appeal route and practical "
    "consequences."
)

SPAN_SPECS = {
    "q12-bloomberg": {
        "authority_identity_id": "neutral-citation:[2022] UKSC 5",
        "exact_locator": "paragraphs 45-49, especially paragraph 45",
        "supporting_excerpts": [
            (
                "In the seminal decision of the House of Lords in Campbell v MGN Ltd"
                "[2004] UKHL 22; [2004] 2 AC 457 it was recognised that the values "
                "enshrined in articles 8 and 10 had become part of the cause of action "
                "for breach of confidence"
            ),
            (
                "This is a distinct cause of action from breach of confidence. It rests "
                "on different legal foundations and protects different interests"
            ),
        ],
    },
    "q16-wills-s20": {
        "authority_identity_id": "ukpga:Will4and1Vict:7:26",
        "exact_locator": "section 20",
        "supporting_excerpts": [
            (
                "No will or codicil, or any part thereof, shall be revoked otherwise "
                "than as aforesaid, or by another will or codicil executed in manner "
                "herein-before required"
            )
        ],
    },
    "q16-aea-s49": {
        "authority_identity_id": "ukpga:Geo5:15-16:23",
        "exact_locator": "section 49(1)",
        "supporting_excerpts": [
            (
                "Where any person dies leaving a will effectively disposing of part of "
                "his property, this Part of this Act shall have effect as respects the "
                "part of his property not so disposed of"
            )
        ],
    },
    "q16-aea-s46": {
        "authority_identity_id": "ukpga:Geo5:15-16:23",
        "exact_locator": "section 46(1)",
        "supporting_excerpts": [
            "The residuary estate of an intestate shall be distributed in the manner or be held on the trusts mentioned in this section"
        ],
    },
    "q30-osborn": {
        "authority_identity_id": "neutral-citation:[2013] UKSC 61",
        "exact_locator": "paragraphs 67-72, especially paragraph 68",
        "supporting_excerpts": [
            (
                "justice is intuitively understood to require a procedure which pays "
                "due respect to persons whose rights are significantly affected by "
                "decisions taken in the exercise of administrative or judicial functions"
            ),
            (
                "such persons ought to be able to participate in the procedure by which "
                "the decision is made, provided they have something to say which is "
                "relevant to the decision to be taken"
            ),
        ],
    },
    "q58-crtpa-s7": {
        "authority_identity_id": "ukpga:1999:31",
        "exact_locator": "section 7(1)",
        "supporting_excerpts": [
            (
                "Section 1 does not affect any right or remedy of a third party that "
                "exists or is available apart from this Act."
            )
        ],
    },
    "q59-ca-s49c": {
        "authority_identity_id": "ukpga:1998:41",
        "exact_locator": "section 49C(1)-(2)",
        "supporting_excerpts": [
            "A person may apply to the CMA for approval of a redress scheme.",
            (
                "The CMA may consider an application before the infringement decision "
                "to which the redress scheme relates has been made, but may approve the "
                "scheme only—"
            ),
            "after that decision has been made",
            (
                "in the case of a decision of the CMA, at the same time as that decision "
                "is made."
            ),
        ],
    },
}

RELEASE_HOLD_CODES = {
    **r3.RELEASE_HOLD_CODES,
    "live30-q12:issue-06": [
        "BLOOMBERG_LATER_TREATMENT_REVIEW_PENDING",
        "PRIVATE_LAW_CAUSE_OF_ACTION_APPLICATION_PENDING",
    ],
    "live30-q16:issue-06": [
        "LEGISLATION_EFFECTS_CURRENTNESS_REVIEW_PENDING",
        "TESTAMENTARY_DOCUMENT_AND_FAMILY_FACTS_PENDING",
    ],
    "live30-q30:issue-02": [
        "MULTI_ROUTE_CURRENTNESS_LATER_TREATMENT_REVIEW_PENDING",
        "BENEFITS_SCHEME_AND_APPLICATION_FACTS_PENDING",
    ],
}


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _seal(value: dict[str, Any], field: str = "artifact_content_sha256") -> dict[str, Any]:
    material = dict(value)
    material.pop(field, None)
    return {**material, field: _sha(_canonical_json(material))}


def _recursive_no_execution_violations(
    value: Any, path: str = "$"
) -> list[str]:
    violations: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key in NO_EXECUTION_FLAGS and child is not False:
                violations.append(child_path)
            violations.extend(_recursive_no_execution_violations(child, child_path))
    elif isinstance(value, list):
        for ordinal, child in enumerate(value):
            violations.extend(
                _recursive_no_execution_violations(child, f"{path}[{ordinal}]")
            )
    return violations


def _component_key(row_id: str, ordinal: int) -> str:
    return f"{row_id}#component-{ordinal}"


def _matter_requirement(text: str) -> dict[str, Any]:
    return _seal(
        {
            "schema": "legalbot.v111.phase2a.nonlegal-matter-information-requirement-proposal-r4.v1",
            "requirement": text,
            "requirement_text_sha256": _sha(text.encode()),
            "lane": "NONAUTHORITATIVE_MATTER_INTAKE_ONLY",
            "may_enter_legal_authority_lane": False,
            "may_create_evidence_span": False,
            "may_be_cited_as_law": False,
            "may_release_a_legal_claim": False,
        },
        "requirement_content_sha256",
    )


def _binding_path(binding: dict[str, Any]) -> Path:
    if binding["source_origin"] == "EXACT_OWNER_ADOPTED_MATERIALIZATION_PLAN":
        return r2.QUARANTINE_ROOT / binding["representation_member"]
    digest = binding["canonical_object_sha256"]
    return PROJECT_ROOT / "data/vault/objects/sha256" / digest[:2] / digest


def _representation_file_sha(binding: dict[str, Any]) -> str:
    return binding.get("representation_file_sha256") or binding["canonical_object_sha256"]


def _span(
    spec_name: str, source_by_id: dict[str, dict[str, Any]], span_ordinal: int
) -> dict[str, Any]:
    spec = SPAN_SPECS[spec_name]
    binding = source_by_id[spec["authority_identity_id"]]
    path = _binding_path(binding)
    if path.is_symlink() or not path.is_file() or _file_sha(path) != _representation_file_sha(binding):
        raise ValueError(f"r4_span_source_byte_mismatch:{spec_name}")
    text, parse_mode = r2._representation_text(path)
    normalized_source = r2._normalise_text(text)
    verified = []
    for excerpt in spec["supporting_excerpts"]:
        normalized = r2._normalise_text(excerpt)
        if normalized not in normalized_source:
            raise ValueError(f"r4_supporting_excerpt_not_in_bound_bytes:{spec_name}")
        verified.append(
            {
                "text": excerpt,
                "normalised_text_sha256": _sha(normalized.encode()),
                "verified_in_bound_source_bytes": True,
            }
        )
    return _seal(
        {
            "schema": "legalbot.v111.phase2a.frozen-evidence-span-proposal.v4",
            "span_ordinal": span_ordinal,
            "authority_identity_id": spec["authority_identity_id"],
            "exact_locator": spec["exact_locator"],
            "supporting_excerpts": verified,
            "source_binding_content_sha256": binding["record_content_sha256"],
            "representation_file_sha256": _representation_file_sha(binding),
            "derived_normalized_representation_text_sha256": _sha(
                normalized_source.encode()
            ),
            "representation_parse_mode": parse_mode,
            "normalization": "UNICODE_NFKC_AND_COLLAPSE_WHITESPACE",
            "proposal_payload_immutable": True,
            "evidence_span_frozen_for_execution": False,
            "owner_adopted": False,
        },
        "span_proposal_content_sha256",
    )


def _packet_authorities(
    packet_row: dict[str, Any], component_ordinals: set[int]
) -> list[dict[str, Any]]:
    assessments = {
        (item["component_ordinal"], item["authority_ordinal"]): item
        for item in packet_row["authority_assessments"]
    }
    result = []
    for component_ordinal, component in enumerate(
        packet_row["source_research_record"]["atomic_components"], start=1
    ):
        if component_ordinal not in component_ordinals:
            continue
        authorities = []
        for authority_ordinal, authority in enumerate(component["authorities"], start=1):
            assessment = assessments[(component_ordinal, authority_ordinal)]
            authorities.append(
                {
                    **authority,
                    "canonical_authority_identity_id": assessment[
                        "canonical_authority_identity_id"
                    ],
                }
            )
        result.append({"authorities": authorities})
    return result


def _new_source_bindings(
    packet_rows: dict[str, dict[str, Any]],
    quarantine: dict[str, Any],
    candidate: dict[str, Any],
    plan: dict[str, Any],
) -> list[dict[str, Any]]:
    pseudo_rows = []
    # Every retained FULL component used for the three newly ready rows is
    # byte-bound.  q12 component 2 deliberately drops unavailable Campbell and
    # relies only on the narrower Bloomberg repair.
    for row_id in sorted(RESOLVED_R3_RESIDUAL_ROWS):
        row = packet_rows[row_id]
        ordinals = {
            ordinal
            for ordinal, component in enumerate(
                row["source_research_record"]["atomic_components"], start=1
            )
            if component["support_fit"] == "FULL"
        }
        if row_id == "live30-q30:issue-02":
            ordinals.add(5)
        components = _packet_authorities(row, ordinals)
        if row_id == "live30-q12:issue-06":
            for component in components:
                component["authorities"] = [
                    authority
                    for authority in component["authorities"]
                    if authority["canonical_authority_identity_id"]
                    != "neutral-citation:[2004] UKHL 22"
                ]
        pseudo_rows.append({"row_id": row_id, "blocking_components": components})
    bindings, _ = r2._source_bindings(pseudo_rows, quarantine, candidate, plan)
    return bindings


def _merge_bindings(
    r3_advisory: dict[str, Any], new_bindings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    new_ready_coverage_ids = {
        item["authority_identity_id"] for item in new_bindings
    }
    raw_by_id = {
        item["authority_identity_id"]: item
        for item in [*r3_advisory["source_byte_bindings"], *new_bindings]
    }
    role_map: dict[str, set[str]] = defaultdict(set)
    for item in r3_advisory["source_byte_bindings"]:
        role_map[item["authority_identity_id"]].update(item["source_roles"])
    for identity in {
        spec["authority_identity_id"] for spec in SPAN_SPECS.values()
    }:
        role_map[identity].add("R4_EXACT_FROZEN_SPAN_SUPPORT")
    for identity in new_ready_coverage_ids:
        role_map[identity].add("R4_NEW_READY_ROW_FULL_ISSUE_COVERAGE")
    role_map["ukpga:1999:31"].add("MANDATORY_Q58_SECTION_7_1_CORRECTION")
    role_map["ukpga:1998:41"].add("MANDATORY_Q59_SECTION_49C_TIMING_CORRECTION")

    merged = []
    for identity in sorted(raw_by_id):
        raw = dict(raw_by_id[identity])
        raw.pop("record_content_sha256", None)
        raw.update(
            {
                "schema": "legalbot.v111.phase2a.authorityless-cohort-r4-source-binding.v1",
                "source_roles": sorted(role_map[identity]),
                "relied_on_for_support": (
                    raw.get("relied_on_for_support", False)
                    or "R4_EXACT_FROZEN_SPAN_SUPPORT" in role_map[identity]
                    or identity in new_ready_coverage_ids
                ),
                "representation_byte_hash_verified": True,
                "inspection_does_not_upgrade_unrelated_partial_or_none": True,
                "source_admitted_by_r4": False,
                "answer_release_effect": "NONE",
            }
        )
        merged.append(_seal(raw, "record_content_sha256"))
    return merged


def _updated_full_inventory(
    row_id: str,
    inventory: list[dict[str, Any]],
    source_by_id: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    result = []
    for component in inventory:
        raw = dict(component)
        raw.pop("record_content_sha256", None)
        ordinal = raw["component_ordinal"]
        if row_id in FUTURE_SUPPORT_READY_ROWS:
            raw["coverage_role"] = "RELIED_ON_FOR_EXACT_ISSUE_DIMENSION_COVERAGE_R4"
        if (row_id, ordinal) == ("live30-q12:issue-06", 2):
            raw["proposition"] = Q12_AFTER
            raw["proposition_text_sha256"] = _sha(Q12_AFTER.encode())
            raw["authorities"] = [
                authority
                for authority in raw["authorities"]
                if authority["authority_identity_id"] == "neutral-citation:[2022] UKSC 5"
            ]
        elif (row_id, ordinal) == ("live60-q58:issue-10", 1):
            raw["proposition"] = Q58_CORRECTED
            raw["proposition_text_sha256"] = _sha(Q58_CORRECTED.encode())
            raw["authorities"][0]["exact_locators"] = ["sections 1-3", "section 7(1)"]
        elif (row_id, ordinal) == ("live60-q59:issue-18", 3):
            raw["proposition"] = Q59_CORRECTED
            raw["proposition_text_sha256"] = _sha(Q59_CORRECTED.encode())
            raw["authorities"][0]["exact_locators"] = [
                "section 49C(1)-(2)",
                "section 49D(1)-(5)",
                "section 49E(1)-(9)",
            ]
        authorities = []
        for authority in raw["authorities"]:
            authority = dict(authority)
            identity = authority["authority_identity_id"]
            if identity in source_by_id:
                authority["source_byte_binding_status"] = "EXACT_LOCAL_BYTE_BOUND_R4"
                authority["source_binding_content_sha256"] = source_by_id[identity][
                    "record_content_sha256"
                ]
            if row_id in FUTURE_SUPPORT_READY_ROWS and identity not in source_by_id:
                raise ValueError(f"future_ready_full_authority_not_bound:{row_id}:{identity}")
            authorities.append(authority)
        raw["authorities"] = authorities
        result.append(_seal(raw, "record_content_sha256"))
    return result


def build_advisory() -> dict[str, Any]:
    if len(NO_EXECUTION_FLAGS) != 56 or any(NO_EXECUTION_FLAGS.values()):
        raise ValueError("canonical_no_execution_flags_invalid")
    if _file_sha(Path(r3.__file__).resolve()) != R3_BUILDER_FILE_SHA256:
        raise ValueError("sealed_r3_builder_dependency_digest_invalid")
    if _file_sha(R3_ADVISORY_PATH) != R3_ADVISORY_FILE_SHA256:
        raise ValueError("r3_advisory_file_digest_invalid")
    sealed_r3 = json.loads(R3_ADVISORY_PATH.read_bytes())
    r2._verify_seal(sealed_r3, "artifact_content_sha256", R3_ADVISORY_CONTENT_SHA256)
    rebuilt_r3 = r3.build_advisory()
    if rebuilt_r3 != sealed_r3:
        raise ValueError("r3_rebuild_not_identical_to_sealed_artifact")

    packet = r2._load(r2.OWNER_PACKET_PATH)
    packet_rows = {row["row_id"]: row for row in packet["decisions"]}
    quarantine = r2._load(r2.QUARANTINE_MANIFEST_PATH)
    candidate = r2._load(r2.CANDIDATE_MANIFEST_PATH)
    plan = r2.build_materialization_plan()
    new_bindings = _new_source_bindings(packet_rows, quarantine, candidate, plan)
    source_bindings = _merge_bindings(sealed_r3, new_bindings)
    source_by_id = {item["authority_identity_id"]: item for item in source_bindings}

    spans = {
        name: _span(name, source_by_id, ordinal)
        for ordinal, name in enumerate(sorted(SPAN_SPECS), start=1)
    }
    mandatory_repairs = [
        _seal(
            {
                "schema": "legalbot.v111.phase2a.independent-audit-full-component-repair.v1",
                "row_id": "live60-q58:issue-10",
                "component_ordinal": 1,
                "defect_code": "CRTPA_APART_FROM_ACT_RIGHTS_REMEDIES_LOCATOR_OMITTED",
                "before_proposition": next(
                    component["proposition"]
                    for row in sealed_r3["row_advisories"]
                    if row["row_id"] == "live60-q58:issue-10"
                    for component in row["retained_full_component_inventory"]
                    if component["component_ordinal"] == 1
                ),
                "after_proposition": Q58_CORRECTED,
                "after_proposition_text_sha256": _sha(Q58_CORRECTED.encode()),
                "exact_locator_added": "section 7(1)",
                "frozen_evidence_span_proposals": [spans["q58-crtpa-s7"]],
                "owner_adoption_required": True,
                "applied": False,
                "answer_release_eligible": False,
            },
            "record_content_sha256",
        ),
        _seal(
            {
                "schema": "legalbot.v111.phase2a.independent-audit-full-component-repair.v1",
                "row_id": "live60-q59:issue-18",
                "component_ordinal": 3,
                "defect_code": "COMPETITION_ACT_1998_SECTION_49C_APPLICATION_APPROVAL_TIMING",
                "before_proposition": next(
                    component["proposition"]
                    for row in sealed_r3["row_advisories"]
                    if row["row_id"] == "live60-q59:issue-18"
                    for component in row["retained_full_component_inventory"]
                    if component["component_ordinal"] == 3
                ),
                "after_proposition": Q59_CORRECTED,
                "after_proposition_text_sha256": _sha(Q59_CORRECTED.encode()),
                "timing_contract": {
                    "application_may_be_considered_before_infringement_decision": True,
                    "approval_only_after_infringement_decision": True,
                    "cma_decision_same_time_approval_permitted": True,
                },
                "frozen_evidence_span_proposals": [spans["q59-ca-s49c"]],
                "owner_adoption_required": True,
                "applied": False,
                "answer_release_eligible": False,
            },
            "record_content_sha256",
        ),
    ]

    row_advisories = []
    residual_rows: set[str] = set()
    residual_components = []
    exact_rewrite_count = 0
    exact_exclusion_repair_count = 0
    full_inventory_total = 0
    for old_row in sealed_r3["row_advisories"]:
        row_id = old_row["row_id"]
        recommendations = []
        for old_rec in old_row["component_recommendations"]:
            ordinal = old_rec["before"]["component_ordinal"]
            if (row_id, ordinal) == ("live30-q16:issue-06", 3):
                exact_exclusion_repair_count += 1
                recommendation = _seal(
                    {
                        "schema": "legalbot.v111.phase2a.authorityless-component-remediation-r4.v1",
                        "before": old_rec["before"],
                        "action": "EXCLUDE_FALSE_NECESSARY_INTESTACY_AND_RETAIN_MATTER_INTAKE",
                        "after_legal_propositions": [],
                        "after_nonlegal_requirements": [_matter_requirement(Q16_INTAKE)],
                        "coverage_basis": {
                            "legal_rule": (
                                "Invalidity of the later document does not necessarily "
                                "produce intestacy: section 20 controls revocation, section "
                                "49 controls partial intestacy, and section 46 governs the "
                                "residuary estate of an intestate."
                            ),
                            "frozen_evidence_span_proposals": [
                                spans["q16-wills-s20"],
                                spans["q16-aea-s49"],
                                spans["q16-aea-s46"],
                            ],
                        },
                        "component_material_blocker_after_owner_adoption": False,
                        "owner_adoption_required": True,
                        "applied": False,
                        "answer_release_effect": "NONE",
                    },
                    "recommendation_content_sha256",
                )
            elif (row_id, ordinal) == ("live30-q30:issue-02", 5):
                exact_rewrite_count += 1
                recommendation = _seal(
                    {
                        "schema": "legalbot.v111.phase2a.authorityless-component-remediation-r4.v1",
                        "before": old_rec["before"],
                        "action": "OWNER_REWRITE_TO_EXACT_BOUND_SOURCE_TEXT_AND_SPLIT_MATTER_INTAKE",
                        "after_legal_propositions": [
                            {
                                "proposition": Q30_AFTER,
                                "proposition_text_sha256": _sha(Q30_AFTER.encode()),
                                "proposed_support_fit": "FULL_IF_EXACT_OWNER_ADOPTED",
                            }
                        ],
                        "after_nonlegal_requirements": [_matter_requirement(Q30_INTAKE)],
                        "frozen_evidence_span_proposals": [spans["q30-osborn"]],
                        "component_material_blocker_after_owner_adoption": False,
                        "owner_adoption_required": True,
                        "applied": False,
                        "answer_release_effect": "NONE",
                    },
                    "recommendation_content_sha256",
                )
            else:
                raw = dict(old_rec)
                raw.pop("recommendation_content_sha256", None)
                raw["schema"] = "legalbot.v111.phase2a.authorityless-component-remediation-r4.v1"
                raw["r3_recommendation_content_sha256"] = old_rec[
                    "recommendation_content_sha256"
                ]
                recommendation = _seal(raw, "recommendation_content_sha256")
            recommendations.append(recommendation)
            if recommendation["component_material_blocker_after_owner_adoption"]:
                residual_components.append(
                    {
                        "row_id": row_id,
                        "component_ordinal": ordinal,
                        "proposition_text_sha256": old_rec["before"][
                            "proposition_text_sha256"
                        ],
                        "upstream_support_fit": old_rec["before"]["support_fit"],
                    }
                )

        full_inventory = _updated_full_inventory(
            row_id, old_row["retained_full_component_inventory"], source_by_id
        )
        full_inventory_total += len(full_inventory)
        issue_holds = list(old_row["row_issue_dimension_coverage_holds"])
        source_holds = list(old_row["source_binding_material_holds"])
        full_repairs = []
        if row_id == "live30-q12:issue-06":
            source_holds = []
            full_repairs.append(
                _seal(
                    {
                        "schema": "legalbot.v111.phase2a.retained-full-component-source-repair.v1",
                        "component_ordinal": 2,
                        "repair": "NARROW_TO_BLOOMBERG_ONLY_REMOVE_UNAVAILABLE_CAMPBELL_DEPENDENCY",
                        "after_proposition": Q12_AFTER,
                        "after_proposition_text_sha256": _sha(Q12_AFTER.encode()),
                        "frozen_evidence_span_proposals": [spans["q12-bloomberg"]],
                        "owner_adoption_required": True,
                        "applied": False,
                    },
                    "record_content_sha256",
                )
            )
        if row_id in {"live60-q58:issue-10", "live60-q59:issue-18"}:
            full_repairs.extend(
                repair for repair in mandatory_repairs if repair["row_id"] == row_id
            )

        material_gap = row_id not in FUTURE_SUPPORT_READY_ROWS
        coverage_ready = not material_gap
        if material_gap:
            residual_rows.add(row_id)
        if coverage_ready and any(
            item["component_material_blocker_after_owner_adoption"]
            for item in recommendations
        ):
            raise ValueError(f"ready_row_retains_component_blocker:{row_id}")
        if coverage_ready and (issue_holds or source_holds):
            raise ValueError(f"ready_row_retains_material_hold:{row_id}")
        row_advisories.append(
            _seal(
                {
                    "schema": "legalbot.v111.phase2a.authorityless-cohort-row-remediation-advisory-r4.v1",
                    "row_id": row_id,
                    "r3_row_record_content_sha256": old_row["record_content_sha256"],
                    "original_blocking_component_count": old_row[
                        "original_blocking_component_count"
                    ],
                    "component_recommendations": recommendations,
                    "retained_full_component_inventory": full_inventory,
                    "retained_full_component_repairs": full_repairs,
                    "row_issue_dimension_coverage_holds": issue_holds,
                    "source_binding_material_holds": source_holds,
                    "all_unclassified_upstream_holds_retained": old_row[
                        "all_unclassified_upstream_holds_retained"
                    ],
                    "retained_release_hold_codes": RELEASE_HOLD_CODES.get(row_id, []),
                    "material_legal_support_gap": material_gap,
                    "legal_component_coverage_complete_after_exact_action_if_owner_adopted": coverage_ready,
                    "qualification_eligible": False,
                    "answer_eligible": False,
                    "answer_release_eligible": False,
                    "owner_adoption_required": True,
                    "owner_decision_applied": False,
                },
                "record_content_sha256",
            )
        )

    if (
        len(row_advisories) != 59
        or sum(len(row["component_recommendations"]) for row in row_advisories) != 80
        or full_inventory_total != 127
        or len(residual_rows) != 52
        or len(residual_components) != 65
        or exact_rewrite_count != 1
        or exact_exclusion_repair_count != 1
    ):
        raise ValueError("r4_topology_or_residual_arithmetic_invalid")
    expected_residual = {
        row["row_id"]
        for row in sealed_r3["row_advisories"]
        if row["material_legal_support_gap"]
    } - RESOLVED_R3_RESIDUAL_ROWS
    if residual_rows != expected_residual:
        raise ValueError("r4_residual_row_set_invalid")

    source_origins = Counter(item["source_origin"] for item in source_bindings)
    relied = [item for item in source_bindings if item["relied_on_for_support"]]
    advisory = {
        "schema": "legalbot.v111.phase2a.authorityless-cohort-59-remediation-advisory-r4.v1",
        "status": "IMMUTABLE_NO_GO_52_RESIDUAL_MATERIAL_GAP_ROWS_NOT_OWNER_ADOPTED",
        "phase_scope": "PHASE2A_ONLY",
        "advisory_date": "2026-08-28",
        "advisory_effect": "NON_AUTHORIZING_FAIL_CLOSED_RECOMMENDATIONS_ONLY",
        "supersedes_advisory_content_sha256": R3_ADVISORY_CONTENT_SHA256,
        "supersession_reason": (
            "R4 corrects the q58 section 7(1) omission and q59 section 49C timing "
            "error, then uses exact local official bytes and verified excerpts to "
            "resolve three of r3's 55 residual rows."
        ),
        "row_id_set_sha256": sealed_r3["row_id_set_sha256"],
        "row_ids": sealed_r3["row_ids"],
        "topology_derivation": {
            "method": "SEALED_R3_EXACT_59_ROW_SET_PLUS_EXACT_R4_REPAIR_DELTA",
            "row_count": 59,
            "original_blocking_component_count": 80,
            "original_none_component_count": 63,
            "original_partial_component_count": 17,
            "r3_residual_material_gap_row_count": 55,
            "r4_resolved_r3_residual_row_count": 3,
            "r4_residual_material_gap_row_count": 52,
            "no_blocker_omitted": True,
            "blockers_dispositioned_exactly_once": True,
        },
        "counts": {
            "row_count": 59,
            "original_blocking_component_count": 80,
            "original_none_component_count": 63,
            "original_partial_component_count": 17,
            "preserved_r3_safe_exact_exclusion_count": 4,
            "preserved_r3_safe_matter_application_split_count": 9,
            "r4_exact_source_rewrite_count": exact_rewrite_count,
            "r4_exact_false_overbroad_exclusion_repair_count": exact_exclusion_repair_count,
            "r4_full_component_source_narrowing_repair_count": 1,
            "independent_audit_mandatory_full_component_repair_count": len(
                mandatory_repairs
            ),
            "retained_original_component_blocker_count": len(residual_components),
            "retained_partial_component_blocker_count": sum(
                item["upstream_support_fit"] == "PARTIAL"
                for item in residual_components
            ),
            "retained_none_component_blocker_count": sum(
                item["upstream_support_fit"] == "NONE"
                for item in residual_components
            ),
            "residual_material_gap_row_count": len(residual_rows),
            "future_owner_consideration_support_ready_row_count": len(
                FUTURE_SUPPORT_READY_ROWS
            ),
            "retained_full_component_inventory_count": full_inventory_total,
            "source_byte_binding_count": len(source_bindings),
            "relied_source_byte_binding_count": len(relied),
            "materialization_plan_source_binding_count": source_origins[
                "EXACT_OWNER_ADOPTED_MATERIALIZATION_PLAN"
            ],
            "sealed_candidate_source_binding_count": source_origins[
                "SEALED_251_SOURCE_CANDIDATE"
            ],
            "frozen_evidence_span_proposal_count": len(spans),
            "new_source_admission_count": 0,
            "qualification_run_count": 0,
            "answer_release_count": 0,
        },
        "resolved_r3_residual_row_ids": sorted(RESOLVED_R3_RESIDUAL_ROWS),
        "residual_material_gap_row_ids": sorted(residual_rows),
        "residual_blocking_components": sorted(
            residual_components, key=lambda item: (item["row_id"], item["component_ordinal"])
        ),
        "mandatory_independent_audit_repairs": mandatory_repairs,
        "input_lineage": [
            {
                "kind": "superseded_authorityless_cohort_advisory_r3",
                "content_sha256": R3_ADVISORY_CONTENT_SHA256,
                "file_sha256": R3_ADVISORY_FILE_SHA256,
            },
            {
                "kind": "sealed_r3_builder_dependency",
                "file_sha256": R3_BUILDER_FILE_SHA256,
            },
            *sealed_r3["input_lineage"],
        ],
        "source_byte_bindings": source_bindings,
        "row_advisories": row_advisories,
        "decision_boundary": {
            "recommendations_are_not_owner_decisions": True,
            "owner_adoption_not_recorded": True,
            "material_gap_rows_remain_blocked_after_owner_adoption_of_safe_actions": True,
            "release_only_holds_do_not_replace_material_support_analysis": True,
            "future_support_ready_does_not_mean_qualification_or_release": True,
            "all_rewrite_excerpts_verified_in_exact_bound_local_bytes": True,
            "one_execution_chain_total": 1,
            "execution_chain_consumed": 0,
            "execution_chain_remaining": 1,
        },
        "answer_release_eligible": False,
        "recursive_no_execution_control": {
            "authoritative_field_count": len(NO_EXECUTION_FLAGS),
            "recursive_violations": [],
            "verified": True,
        },
        **NO_EXECUTION_FLAGS,
    }
    sealed = _seal(advisory)
    violations = _recursive_no_execution_violations(sealed)
    if violations:
        raise ValueError(f"recursive_no_execution_violation:{violations}")
    return sealed


def publish(output_root: Path = OUTPUT_ROOT) -> dict[str, str]:
    if output_root.exists() or output_root.is_symlink():
        raise FileExistsError("authorityless_cohort_r4_output_already_exists")
    if not output_root.name or not output_root.parent.is_dir():
        raise ValueError("authorityless_cohort_r4_output_parent_invalid")
    advisory = build_advisory()
    advisory_bytes = _pretty_json(advisory)
    package = _seal(
        {
            "schema": "legalbot.v111.phase2a.authorityless-cohort-59-remediation-advisory-r4-package.v1",
            "status": advisory["status"],
            "supersedes_advisory_content_sha256": R3_ADVISORY_CONTENT_SHA256,
            "advisory_content_sha256": advisory["artifact_content_sha256"],
            "advisory_file_sha256": _sha(advisory_bytes),
            "row_id_set_sha256": advisory["row_id_set_sha256"],
            "row_count": 59,
            "original_blocking_component_count": 80,
            "residual_material_gap_row_count": 52,
            "retained_original_component_blocker_count": 65,
            **NO_EXECUTION_FLAGS,
        }
    )
    package_bytes = _pretty_json(package)
    checksums = (
        f"{_sha(advisory_bytes)}  {ADVISORY_NAME}\n"
        f"{_sha(package_bytes)}  {PACKAGE_NAME}\n"
    ).encode()
    staging = Path(
        tempfile.mkdtemp(prefix=f".{output_root.name}.staging-", dir=output_root.parent)
    )
    os.chmod(staging, 0o700)
    try:
        for name, raw in (
            (ADVISORY_NAME, advisory_bytes),
            (PACKAGE_NAME, package_bytes),
            (CHECKSUMS_NAME, checksums),
        ):
            r2._write_exclusive(staging / name, raw)
        for path in staging.iterdir():
            os.chmod(path, 0o600)
        r2._fsync_directory(staging)
        r2._publish_directory_noreplace(staging, output_root)
        r2._fsync_directory(output_root.parent)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    return {
        "output_root": output_root.name,
        "advisory_content_sha256": advisory["artifact_content_sha256"],
        "advisory_file_sha256": _sha(advisory_bytes),
        "package_content_sha256": package["artifact_content_sha256"],
        "package_file_sha256": _sha(package_bytes),
        "status": advisory["status"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("verify", "publish"))
    args = parser.parse_args()
    result = build_advisory() if args.command == "verify" else publish()
    if args.command == "verify":
        result = {
            "artifact_content_sha256": result["artifact_content_sha256"],
            "counts": result["counts"],
            "status": result["status"],
        }
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
