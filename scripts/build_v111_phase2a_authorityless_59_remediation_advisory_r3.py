#!/usr/bin/env python3
"""Build the immutable, fail-closed r3 authorityless-cohort advisory.

R2 is preserved as evidence but is substantively superseded: it treated the
mere presence of some FULL components as permission to erase different legal
rules.  This revision clears only four exact false/overbroad components and
nine genuinely fact/application-only components.  It retains every other
PARTIAL/NONE component, splits mixed law/fact components from their useful
matter-intake requirements, and records four row-level issue-dimension gaps.

This is advisory construction only.  It does not admit a source, apply an
owner decision, run a scan/build/embedding/qualification, write a pointer, or
release an answer.
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

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
R2_ROOT = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-authorityless-cohort-59-remediation-advisory-r2"
)
R2_ADVISORY_PATH = R2_ROOT / "AUTHORITYLESS-COHORT-59-REMEDIATION-ADVISORY.json"
OUTPUT_ROOT = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-authorityless-cohort-59-remediation-advisory-r3"
)
ADVISORY_NAME = "AUTHORITYLESS-COHORT-59-REMEDIATION-ADVISORY-R3.json"
PACKAGE_NAME = "PACKAGE-MANIFEST.json"
CHECKSUMS_NAME = "SHA256SUMS.txt"

R2_BUILDER_FILE_SHA256 = "29088b4dc55d53c3e19198a6cb2b90ae7b576e339d354c9c2d597b12e42ffd93"
R2_ADVISORY_FILE_SHA256 = "96c8b664d185ad5b382eac962388c27194b6801c926e184659d1c969e574bc99"
R2_ADVISORY_CONTENT_SHA256 = "69e12e09f5d060049fa3ecd939ec2f82fa66fa65cbbe6c56addeb4478dc4ba50"

NO_EXECUTION_FLAGS = dict(r2.NO_EXECUTION_FLAGS)

SAFE_EXCLUSION_KEYS = frozenset(
    {
        ("live30-q12:issue-05", 3),
        ("live30-q12:issue-06", 3),
        ("live30-q13:issue-01", 3),
        ("live30-q18:issue-08", 8),
    }
)

SAFE_MATTER_KEYS = frozenset(
    {
        ("live30-q18:issue-08", 7),
        ("live30-q30:issue-02", 1),
        ("live60-q46:issue-09", 1),
        ("live60-q47:issue-06", 3),
        ("live60-q47:issue-09", 1),
        ("live60-q57:issue-05", 3),
        ("live60-q58:issue-10", 2),
        ("live60-q59:issue-18", 4),
        ("live60-q60:issue-31", 2),
    }
)

MIXED_LAW_FACT_KEYS = frozenset(
    {
        ("live30-q04:issue-01", 2),
        ("live30-q04:issue-06", 2),
        ("live30-q16:issue-06", 3),
        ("live30-q18:issue-08", 5),
        ("live30-q26:issue-01", 3),
        ("live30-q26:issue-08", 3),
        ("live30-q29:issue-05", 4),
        ("live30-q29:issue-07", 5),
        ("live30-q29:issue-09", 3),
        ("live30-q30:issue-08", 5),
        ("live30-q30:issue-11", 4),
        ("live30-q30:issue-12", 4),
        ("live30-q30:issue-14", 4),
        ("live30-q30:issue-15", 3),
        ("live60-q43:issue-04", 4),
        ("live60-q43:issue-06", 3),
        ("live60-q46:issue-01", 3),
        ("live60-q46:issue-03", 4),
        ("live60-q46:issue-04", 1),
        ("live60-q46:issue-09", 5),
        ("live60-q47:issue-01", 3),
        ("live60-q49:issue-08", 6),
        ("live60-q50:issue-04", 5),
        ("live60-q50:issue-07", 3),
        ("live60-q55:issue-09", 3),
        ("live60-q55:issue-10", 3),
        ("live60-q56:issue-04", 3),
        ("live60-q56:issue-06", 3),
        ("live60-q56:issue-09", 3),
        ("live60-q57:issue-01", 3),
        ("live60-q57:issue-04", 3),
        ("live60-q57:issue-07", 4),
        ("live60-q57:issue-09", 3),
        ("live60-q58:issue-06", 1),
        ("live60-q58:issue-12", 2),
        ("live60-q60:issue-08", 3),
        ("live60-q60:issue-16", 3),
        ("live60-q60:issue-18", 3),
        ("live60-q60:issue-23", 3),
        ("live60-q60:issue-27", 3),
        ("live60-q60:issue-28", 3),
        ("live60-q60:issue-29", 3),
    }
)

ISSUE_COVERAGE_GAPS = {
    "live30-q12:issue-05": (
        "ARTICLE_SPECIFIC_POSITIVE_OBLIGATIONS_OUTSIDE_ARTICLE_2",
        "Removing the false generic real-and-immediate-risk rule leaves any other "
        "Convention article's distinct positive-obligation test unsupported.",
    ),
    "live30-q13:issue-01": (
        "CERTAINTY_OF_OBJECTS_APPLIED_TO_LOYAL_EMPLOYEES_CLASS",
        "Generic trust-certainty rules do not decide whether the actual class of "
        "'most loyal employees' is sufficiently certain on the will and facts.",
    ),
    "live60-q47:issue-09": (
        "CONTRACTUAL_INCORPORATION_CONSTRUCTION_AND_ACCRUAL_OF_CHARGES",
        "The executed terms and account are matter intake, but the legal rules for "
        "incorporation, construction and accrual of default interest and charges "
        "are not independently covered by the retained FULL components.",
    ),
    "live60-q60:issue-31": (
        "LEGAL_ROUTE_COVERAGE_FOR_PRIORITISED_RECOVERY_PLAN",
        "The matter map is nonlegal intake, but the distinct proprietary, personal, "
        "cross-border recognition, insolvency, rescue and distribution routes are "
        "not proposition-completely supported by the single retained procedural component.",
    ),
}

# These are the only rows where the safe action leaves every scoped legal issue
# dimension covered by exact retained FULL components whose relied-on official
# bytes can be bound in this revision.  This is not qualification or release.
FUTURE_SUPPORT_READY_ROWS = frozenset(
    {
        "live60-q47:issue-06",
        "live60-q57:issue-05",
        "live60-q58:issue-10",
        "live60-q59:issue-18",
    }
)

SOURCE_BINDING_HOLDS = {
    "live30-q12:issue-06": [
        {
            "code": "RETAINED_FULL_SOURCE_BYTE_NOT_RESOLVED",
            "authority_identity_id": "neutral-citation:[2004] UKHL 22",
            "effect": "MATERIAL_SUPPORT_CLEARANCE_BLOCKED",
        }
    ]
}

RELEASE_HOLD_CODES = {
    "live60-q47:issue-06": [
        "CANDIDATE_CURRENTNESS_REVIEW_PENDING",
        "LATER_TREATMENT_REVIEW_PENDING",
        "APPLICATION_FACTS_PENDING",
    ],
    "live60-q57:issue-05": [
        "SOURCE_ADMISSION_OWNER_GATE_PENDING",
        "CURRENTNESS_EFFECTS_REVIEW_PENDING",
        "TAX_YEAR_AND_APPLICATION_FACTS_PENDING",
    ],
    "live60-q58:issue-10": [
        "EXTENT_EFFECTS_APPLICABILITY_REVIEW_PENDING",
        "CONTRACT_AND_APPLICATION_FACTS_PENDING",
    ],
    "live60-q59:issue-18": [
        "SOURCE_ADMISSION_OWNER_GATE_PENDING",
        "EXTENT_EFFECTS_AND_SCHEME_INSTRUMENT_REVIEW_PENDING",
        "REGULATORY_ROUTE_APPLICATION_FACTS_PENDING",
    ],
}


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
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


def _component_key(row_id: str, ordinal: int) -> str:
    return f"{row_id}#component-{ordinal}"


def _retained_proposition(before: dict[str, Any]) -> dict[str, Any]:
    return _seal(
        {
            "schema": "legalbot.v111.phase2a.retained-legal-proposition-blocker.v1",
            "component_ordinal": before["component_ordinal"],
            "proposition": before["proposition"],
            "proposition_text_sha256": before["proposition_text_sha256"],
            "upstream_support_fit": before["support_fit"],
            "status": "RETAINED_BLOCKER_EXACT_PROPOSITION_SUPPORT_REQUIRED",
            "may_be_cleared_by_unrelated_full_component": False,
            "may_release_a_legal_claim": False,
        },
        "record_content_sha256",
    )


def _full_component_inventory(
    packet_rows: dict[str, dict[str, Any]], source_by_id: dict[str, dict[str, Any]]
) -> tuple[dict[str, list[dict[str, Any]]], int, set[str]]:
    result: dict[str, list[dict[str, Any]]] = {}
    total = 0
    unresolved: set[str] = set()
    for row_id in r2.ROW_IDS:
        row = packet_rows[row_id]
        assessments = {
            (item["component_ordinal"], item["authority_ordinal"]): item
            for item in row["authority_assessments"]
        }
        components: list[dict[str, Any]] = []
        for component_ordinal, component in enumerate(
            row["source_research_record"]["atomic_components"], start=1
        ):
            if component["support_fit"] != "FULL":
                continue
            authorities = []
            for authority_ordinal, authority in enumerate(component["authorities"], start=1):
                assessment = assessments[(component_ordinal, authority_ordinal)]
                identity = assessment["canonical_authority_identity_id"]
                bound = identity in source_by_id
                if row_id in FUTURE_SUPPORT_READY_ROWS and not bound:
                    raise ValueError(f"relied_full_source_not_byte_bound:{row_id}:{identity}")
                if not bound:
                    unresolved.add(identity)
                authorities.append(
                    {
                        "authority_ordinal": authority_ordinal,
                        "authority_identity_id": identity,
                        "authority_content_sha256": assessment["authority_content_sha256"],
                        "assessment_content_sha256": assessment["assessment_content_sha256"],
                        "citation": authority["citation"],
                        "exact_locators": authority["exact_locators"],
                        "source_byte_binding_status": (
                            "EXACT_LOCAL_BYTE_BOUND"
                            if bound
                            else "INVENTORY_ONLY_NOT_REATTESTED_OR_UNRESOLVED"
                        ),
                        "source_binding_content_sha256": (
                            source_by_id[identity]["record_content_sha256"] if bound else None
                        ),
                    }
                )
            proposition = component["proposition"]
            components.append(
                _seal(
                    {
                        "schema": "legalbot.v111.phase2a.retained-full-component-inventory.v1",
                        "component_ordinal": component_ordinal,
                        "proposition": proposition,
                        "proposition_text_sha256": _sha(proposition.encode()),
                        "support_fit": "FULL",
                        "coverage_role": (
                            "RELIED_ON_FOR_EXACT_ISSUE_DIMENSION_COVERAGE"
                            if row_id in FUTURE_SUPPORT_READY_ROWS
                            else "INVENTORY_ONLY_NOT_USED_TO_CLEAR_A_BLOCKER"
                        ),
                        "authorities": authorities,
                        "does_not_clear_different_component": True,
                    },
                    "record_content_sha256",
                )
            )
            total += 1
        if not components:
            raise ValueError(f"row_without_retained_full_component:{row_id}")
        result[row_id] = components
    return result, total, unresolved


def _build_full_source_bindings(
    packet_rows: dict[str, dict[str, Any]],
    quarantine: dict[str, Any],
    candidate: dict[str, Any],
    plan: dict[str, Any],
) -> list[dict[str, Any]]:
    pseudo_rows = []
    for row_id in sorted(FUTURE_SUPPORT_READY_ROWS):
        packet_row = packet_rows[row_id]
        assessments = {
            (item["component_ordinal"], item["authority_ordinal"]): item
            for item in packet_row["authority_assessments"]
        }
        components = []
        for component_ordinal, component in enumerate(
            packet_row["source_research_record"]["atomic_components"], start=1
        ):
            if component["support_fit"] != "FULL":
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
            components.append({"authorities": authorities})
        pseudo_rows.append({"row_id": row_id, "blocking_components": components})
    bindings, _ = r2._source_bindings(pseudo_rows, quarantine, candidate, plan)
    return bindings


def _merge_source_bindings(
    r2_advisory: dict[str, Any],
    full_bindings: list[dict[str, Any]],
    packet_rows: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    blocker_usage: dict[str, set[str]] = defaultdict(set)
    for row in r2_advisory["row_advisories"]:
        for recommendation in row["component_recommendations"]:
            key = _component_key(row["row_id"], recommendation["before"]["component_ordinal"])
            for inspection in recommendation["source_inspection"]:
                blocker_usage[inspection["authority_identity_id"]].add(key)
    full_usage: dict[str, set[str]] = defaultdict(set)
    for row_id in FUTURE_SUPPORT_READY_ROWS:
        packet_row = packet_rows[row_id]
        assessments = {
            (item["component_ordinal"], item["authority_ordinal"]): item
            for item in packet_row["authority_assessments"]
        }
        for component_ordinal, component in enumerate(
            packet_row["source_research_record"]["atomic_components"], start=1
        ):
            if component["support_fit"] != "FULL":
                continue
            for authority_ordinal, _ in enumerate(component["authorities"], start=1):
                identity = assessments[(component_ordinal, authority_ordinal)][
                    "canonical_authority_identity_id"
                ]
                full_usage[identity].add(_component_key(row_id, component_ordinal))

    raw_by_id = {
        item["authority_identity_id"]: item
        for item in [*r2_advisory["inspected_source_byte_bindings"], *full_bindings]
    }
    merged = []
    for identity in sorted(raw_by_id):
        raw = dict(raw_by_id[identity])
        raw.pop("record_content_sha256", None)
        roles = []
        if blocker_usage.get(identity):
            roles.append("RETAINED_BLOCKER_OR_SAFE_ACTION_INSPECTION_ONLY")
        if full_usage.get(identity):
            roles.append("RETAINED_FULL_EXACT_ISSUE_COVERAGE")
        raw.update(
            {
                "schema": "legalbot.v111.phase2a.authorityless-cohort-r3-source-binding.v1",
                "source_roles": roles,
                "related_blocker_component_keys": sorted(blocker_usage.get(identity, set())),
                "relied_full_component_keys": sorted(full_usage.get(identity, set())),
                "relied_on_for_support": bool(full_usage.get(identity)),
                "representation_byte_hash_verified": True,
                "inspection_does_not_upgrade_partial_or_none": True,
                "source_admitted_by_r3": False,
                "answer_release_effect": "NONE",
            }
        )
        merged.append(_seal(raw, "record_content_sha256"))
    return merged


def build_advisory() -> dict[str, Any]:
    if len(NO_EXECUTION_FLAGS) != 56 or any(NO_EXECUTION_FLAGS.values()):
        raise ValueError("canonical_no_execution_flags_invalid")
    if _file_sha(Path(r2.__file__).resolve()) != R2_BUILDER_FILE_SHA256:
        raise ValueError("sealed_r2_builder_dependency_digest_invalid")
    if _file_sha(R2_ADVISORY_PATH) != R2_ADVISORY_FILE_SHA256:
        raise ValueError("r2_advisory_file_digest_invalid")
    r2_disk = json.loads(R2_ADVISORY_PATH.read_bytes())
    r2._verify_seal(r2_disk, "artifact_content_sha256", R2_ADVISORY_CONTENT_SHA256)
    r2_advisory = r2.build_advisory()
    if r2_advisory != r2_disk:
        raise ValueError("r2_rebuild_not_byte_equivalent_to_sealed_input")

    r3_report = r2._load(r2.R3_PATH)
    packet = r2._load(r2.OWNER_PACKET_PATH)
    quarantine = r2._load(r2.QUARANTINE_MANIFEST_PATH)
    candidate = r2._load(r2.CANDIDATE_MANIFEST_PATH)
    plan = r2.build_materialization_plan()
    packet_rows = {row["row_id"]: row for row in packet["decisions"]}
    r3_rows = {row["row_id"]: row for row in r3_report["rows"]}

    # Empty-authority NONE is not, by itself, a unique cohort selector: eight
    # held/source-repair rows also have that property.  Membership therefore
    # comes from the sealed r2 59-row identity set and is independently
    # revalidated against the exact r3 component topology below.
    derived_row_ids = tuple(r2.ROW_IDS)
    if any(
        row_id not in r3_rows
        or not any(
            item["support_fit"] == "NONE" and not item["authorities"]
            for item in r3_rows[row_id]["blocking_components"]
        )
        for row_id in derived_row_ids
    ):
        raise ValueError("authorityless_row_topology_revalidation_invalid")
    if _sha(("\n".join(derived_row_ids) + "\n").encode()) != r2.ROW_ID_SET_SHA256:
        raise ValueError("authorityless_row_set_digest_invalid")

    base_recommendations: dict[tuple[str, int], dict[str, Any]] = {}
    for row in r2_advisory["row_advisories"]:
        for recommendation in row["component_recommendations"]:
            key = (row["row_id"], recommendation["before"]["component_ordinal"])
            base_recommendations[key] = recommendation
    all_keys = set(base_recommendations)
    base_matter = {
        key
        for key, item in base_recommendations.items()
        if item["action"] == "RECLASSIFY_AS_NONLEGAL_MATTER_INFORMATION_REQUIREMENT"
    }
    base_exclusions = all_keys - base_matter
    retained_exclusion_keys = base_exclusions - SAFE_EXCLUSION_KEYS
    if (
        len(all_keys) != 80
        or len(base_matter) != 51
        or len(base_exclusions) != 29
        or base_matter != SAFE_MATTER_KEYS | MIXED_LAW_FACT_KEYS
        or len(SAFE_EXCLUSION_KEYS) != 4
        or len(SAFE_MATTER_KEYS) != 9
        or len(MIXED_LAW_FACT_KEYS) != 42
        or len(retained_exclusion_keys) != 25
    ):
        raise ValueError("r3_semantic_action_partition_invalid")
    if Counter(
        base_recommendations[key]["before"]["support_fit"] for key in retained_exclusion_keys
    ) != {"PARTIAL": 17, "NONE": 8}:
        raise ValueError("retained_exclusion_support_topology_invalid")

    full_bindings = _build_full_source_bindings(packet_rows, quarantine, candidate, plan)
    source_bindings = _merge_source_bindings(r2_advisory, full_bindings, packet_rows)
    source_by_id = {item["authority_identity_id"]: item for item in source_bindings}
    full_inventory, full_count, unresolved_full_identities = _full_component_inventory(
        packet_rows, source_by_id
    )
    if full_count != 127:
        raise ValueError("retained_full_component_count_invalid")

    row_advisories = []
    retained_component_count = 0
    safe_exclusion_count = 0
    safe_matter_count = 0
    mixed_split_count = 0
    material_blocker_rows: set[str] = set()
    for row_id in derived_row_ids:
        recommendations = []
        for component in r3_rows[row_id]["blocking_components"]:
            key = (row_id, component["component_ordinal"])
            prior = base_recommendations[key]
            before = prior["before"]
            common = {
                "before": before,
                "source_inspection": prior["source_inspection"],
                "new_source_contracts": [],
                "new_frozen_evidence_span_proposals": [],
                "owner_adoption_required": True,
                "applied": False,
                "answer_release_effect": "NONE",
            }
            if key in SAFE_EXCLUSION_KEYS:
                safe_exclusion_count += 1
                body = {
                    "action": "EXCLUDE_EXACT_FALSE_OR_OVERBROAD_COMPONENT",
                    "after_legal_propositions": [],
                    "after_nonlegal_requirements": [],
                    "reason_code": "EXACT_FALSE_OR_OVERBROAD_ASSERTION_REMOVED_NOT_A_LEGAL_ROUTE",
                    "component_material_blocker_after_owner_adoption": False,
                    **common,
                }
            elif key in SAFE_MATTER_KEYS:
                safe_matter_count += 1
                body = {
                    "action": "SPLIT_REMOVE_CASE_FACT_APPLICATION_TO_MATTER_INTAKE",
                    "after_legal_propositions": [],
                    "after_nonlegal_requirements": prior["after_nonlegal_requirements"],
                    "reason_code": "FACT_OR_APPLICATION_REQUIREMENT_ONLY_LEGAL_DIMENSION_CHECKED_SEPARATELY",
                    "component_material_blocker_after_owner_adoption": False,
                    **common,
                }
            elif key in MIXED_LAW_FACT_KEYS:
                retained_component_count += 1
                mixed_split_count += 1
                material_blocker_rows.add(row_id)
                body = {
                    "action": "SPLIT_MATTER_INTAKE_AND_RETAIN_LEGAL_RULE_BLOCKER",
                    "after_legal_propositions": [_retained_proposition(before)],
                    "after_nonlegal_requirements": prior["after_nonlegal_requirements"],
                    "reason_code": "MIXED_LAW_AND_FACT_COMPONENT_LEGAL_RULE_NOT_ERASED",
                    "component_material_blocker_after_owner_adoption": True,
                    **common,
                }
            else:
                retained_component_count += 1
                material_blocker_rows.add(row_id)
                body = {
                    "action": "RETAIN_COMPONENT_BLOCKER_EXACT_PROPOSITION_SUPPORT_REQUIRED",
                    "after_legal_propositions": [_retained_proposition(before)],
                    "after_nonlegal_requirements": [],
                    "reason_code": (
                        "PARTIAL_SUPPORT_CANNOT_BE_DELETED_OR_CLEARED_BY_DIFFERENT_FULL_COMPONENT"
                        if before["support_fit"] == "PARTIAL"
                        else "UNSUPPORTED_LEGAL_OR_MATERIAL_ISSUE_DIMENSION_REMAINS_BLOCKED"
                    ),
                    "component_material_blocker_after_owner_adoption": True,
                    **common,
                }
            recommendations.append(_seal(body, "recommendation_content_sha256"))

        issue_holds = []
        if row_id in ISSUE_COVERAGE_GAPS:
            code, reason = ISSUE_COVERAGE_GAPS[row_id]
            material_blocker_rows.add(row_id)
            issue_holds.append(
                _seal(
                    {
                        "schema": "legalbot.v111.phase2a.row-issue-dimension-coverage-hold.v1",
                        "code": code,
                        "reason": reason,
                        "effect": "MATERIAL_SUPPORT_CLEARANCE_BLOCKED",
                        "may_be_cleared_by_unrelated_full_component": False,
                    },
                    "record_content_sha256",
                )
            )
        source_holds = SOURCE_BINDING_HOLDS.get(row_id, [])
        if source_holds:
            material_blocker_rows.add(row_id)
        material_gap = row_id in material_blocker_rows
        coverage_ready = row_id in FUTURE_SUPPORT_READY_ROWS
        if coverage_ready == material_gap:
            raise ValueError(f"row_readiness_partition_invalid:{row_id}")
        row_advisories.append(
            _seal(
                {
                    "schema": "legalbot.v111.phase2a.authorityless-cohort-row-remediation-advisory-r3.v1",
                    "row_id": row_id,
                    "r3_row_record_content_sha256": r3_rows[row_id]["record_content_sha256"],
                    "owner_decision_content_sha256": packet_rows[row_id]["decision_content_sha256"],
                    "original_blocking_component_count": len(
                        r3_rows[row_id]["blocking_components"]
                    ),
                    "component_recommendations": recommendations,
                    "retained_full_component_inventory": full_inventory[row_id],
                    "row_issue_dimension_coverage_holds": issue_holds,
                    "source_binding_material_holds": source_holds,
                    "all_unclassified_upstream_holds_retained": [
                        {
                            "record_content_sha256": hold["record_content_sha256"],
                            "hold_text_sha256": hold["hold_text_sha256"],
                            "hold_text": hold["hold_text"],
                            "classification_preserved": "UNCLASSIFIED_NON_OPERATIVE",
                        }
                        for hold in r3_rows[row_id]["unclassified_unresolved_holds"]
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
        retained_component_count != 67
        or safe_exclusion_count != 4
        or safe_matter_count != 9
        or mixed_split_count != 42
        or len(material_blocker_rows) != 55
        or {row["row_id"] for row in row_advisories if not row["material_legal_support_gap"]}
        != FUTURE_SUPPORT_READY_ROWS
    ):
        raise ValueError("residual_blocker_arithmetic_invalid")

    source_origins = Counter(item["source_origin"] for item in source_bindings)
    relied_sources = [item for item in source_bindings if item["relied_on_for_support"]]
    advisory = {
        "schema": "legalbot.v111.phase2a.authorityless-cohort-59-remediation-advisory-r3.v1",
        "status": "IMMUTABLE_NO_GO_RESIDUAL_MATERIAL_BLOCKERS_NOT_OWNER_ADOPTED",
        "phase_scope": "PHASE2A_ONLY",
        "advisory_date": "2026-08-28",
        "advisory_effect": "NON_AUTHORIZING_FAIL_CLOSED_RECOMMENDATIONS_ONLY",
        "supersedes_advisory_content_sha256": R2_ADVISORY_CONTENT_SHA256,
        "supersession_reason": (
            "R2 erased mixed legal rules and PARTIAL propositions because unrelated FULL "
            "components existed. R3 permits only 13 exact defensible actions, retains 67 "
            "component blockers, and adds four row-level issue-dimension holds."
        ),
        "row_id_set_sha256": r2.ROW_ID_SET_SHA256,
        "row_ids": list(derived_row_ids),
        "topology_derivation": {
            "method": (
                "SEALED_R2_EXACT_59_ROW_MEMBERSHIP_REVALIDATED_AGAINST_R3_BLOCKER_COMPONENTS"
            ),
            "derived_row_count": len(derived_row_ids),
            "original_none_component_count": 63,
            "original_partial_component_count": 17,
            "original_blocking_component_count": 80,
            "authority_list_empty_none_component_count": 61,
            "authority_present_none_component_count": 2,
            "no_blocker_omitted": True,
            "blockers_dispositioned_exactly_once": True,
        },
        "counts": {
            "row_count": 59,
            "original_blocking_component_count": 80,
            "original_none_component_count": 63,
            "original_partial_component_count": 17,
            "safe_exact_exclusion_count": safe_exclusion_count,
            "safe_matter_application_split_count": safe_matter_count,
            "mixed_law_fact_split_retained_blocker_count": mixed_split_count,
            "retained_original_component_blocker_count": retained_component_count,
            "retained_partial_component_blocker_count": 17,
            "retained_none_component_blocker_count": 50,
            "row_issue_dimension_coverage_hold_count": len(ISSUE_COVERAGE_GAPS),
            "source_binding_material_hold_row_count": len(SOURCE_BINDING_HOLDS),
            "residual_material_blocker_row_count": len(material_blocker_rows),
            "future_owner_consideration_support_ready_row_count": len(FUTURE_SUPPORT_READY_ROWS),
            "retained_full_component_inventory_count": full_count,
            "source_byte_binding_count": len(source_bindings),
            "relied_source_byte_binding_count": len(relied_sources),
            "inspection_only_nonrelied_source_byte_binding_count": len(source_bindings)
            - len(relied_sources),
            "materialization_plan_source_binding_count": source_origins[
                "EXACT_OWNER_ADOPTED_MATERIALIZATION_PLAN"
            ],
            "sealed_candidate_source_binding_count": source_origins["SEALED_251_SOURCE_CANDIDATE"],
            "unresolved_full_authority_identity_inventory_count": len(unresolved_full_identities),
            "new_source_admission_count": 0,
            "qualification_run_count": 0,
            "answer_release_count": 0,
        },
        "input_lineage": [
            {
                "kind": "superseded_authorityless_cohort_advisory_r2",
                "content_sha256": R2_ADVISORY_CONTENT_SHA256,
                "file_sha256": R2_ADVISORY_FILE_SHA256,
            },
            {
                "kind": "sealed_r2_builder_dependency",
                "file_sha256": R2_BUILDER_FILE_SHA256,
            },
            *r2_advisory["input_bindings"],
        ],
        "semantic_policy": {
            "safe_exclusion_component_keys": sorted(
                _component_key(*key) for key in SAFE_EXCLUSION_KEYS
            ),
            "safe_matter_application_component_keys": sorted(
                _component_key(*key) for key in SAFE_MATTER_KEYS
            ),
            "mixed_law_fact_retained_component_keys": sorted(
                _component_key(*key) for key in MIXED_LAW_FACT_KEYS
            ),
            "retained_partial_and_other_none_component_keys": sorted(
                _component_key(*key) for key in retained_exclusion_keys
            ),
            "row_issue_dimension_coverage_hold_rows": sorted(ISSUE_COVERAGE_GAPS),
            "no_clearance_from_unrelated_full_component": True,
            "owner_adoption_cannot_clear_residual_material_gap": True,
        },
        "source_byte_bindings": source_bindings,
        "unresolved_full_authority_identity_inventory": sorted(unresolved_full_identities),
        "row_advisories": row_advisories,
        "decision_boundary": {
            "recommendations_are_not_owner_decisions": True,
            "owner_adoption_not_recorded": True,
            "material_gap_rows_remain_blocked_after_owner_adoption_of_safe_actions": True,
            "release_only_holds_do_not_replace_material_support_analysis": True,
            "future_support_ready_does_not_mean_qualification_or_release": True,
            "one_execution_chain_total": 1,
            "execution_chain_consumed": 0,
            "execution_chain_remaining": 1,
        },
        **NO_EXECUTION_FLAGS,
    }
    return _seal(advisory)


def publish(output_root: Path = OUTPUT_ROOT) -> dict[str, str]:
    if output_root.exists() or output_root.is_symlink():
        raise FileExistsError("authorityless_cohort_r3_output_already_exists")
    if not output_root.name or not output_root.parent.is_dir():
        raise ValueError("authorityless_cohort_r3_output_parent_invalid")
    advisory = build_advisory()
    advisory_bytes = _pretty_json(advisory)
    package = _seal(
        {
            "schema": "legalbot.v111.phase2a.authorityless-cohort-59-remediation-advisory-r3-package.v1",
            "status": advisory["status"],
            "supersedes_advisory_content_sha256": R2_ADVISORY_CONTENT_SHA256,
            "advisory_content_sha256": advisory["artifact_content_sha256"],
            "advisory_file_sha256": _sha(advisory_bytes),
            "row_id_set_sha256": advisory["row_id_set_sha256"],
            "row_count": advisory["counts"]["row_count"],
            "original_blocking_component_count": 80,
            "retained_original_component_blocker_count": 67,
            "residual_material_blocker_row_count": 55,
            "future_owner_consideration_support_ready_row_count": 4,
            **NO_EXECUTION_FLAGS,
        }
    )
    package_bytes = _pretty_json(package)
    checksums = (
        f"{_sha(advisory_bytes)}  {ADVISORY_NAME}\n{_sha(package_bytes)}  {PACKAGE_NAME}\n"
    ).encode()
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.staging-", dir=output_root.parent))
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
