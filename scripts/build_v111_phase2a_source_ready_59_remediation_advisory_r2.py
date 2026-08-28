#!/usr/bin/env python3
"""Build the fail-closed r2 advisory for the source-resolved Phase-2A cohort.

The cohort is derived from the sealed r3 blocker set and two explicit,
disjoint topology-partition inputs.  This revision supersedes the rejected r1
advisory.  It retains every PARTIAL/NONE component as a blocker: no component
is removed merely because the row contains some other FULL component.

This builder is create-only and non-authorizing.  It cannot materialize a
source, scan, build, embed, qualify, release an answer, write a pointer, or run
Phase 2B.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from xml.etree import ElementTree

from pypdf import PdfReader

from scripts.apply_v111_phase2a_final_remediation import build_materialization_plan

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"

R3_PATH = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-prequalification-blockers-r3/PREQUALIFICATION-BLOCKER-REPORT.json"
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
AUTHORITYLESS_PARTITION_PATH = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-authorityless-cohort-59-remediation-advisory-r1/"
    "AUTHORITYLESS-COHORT-59-REMEDIATION-ADVISORY.json"
)
HELD_PARTITION_PATH = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-held-missing-source-advisory-r2/"
    "HELD-MISSING-SOURCE-ADVISORY-28.json"
)
REJECTED_R1_PATH = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-source-ready-59-remediation-advisory-r1/"
    "SOURCE-READY-59-REMEDIATION-ADVISORY.json"
)

OUTPUT_ROOT = REVIEW_ROOT / ("LegalBot-Phase2A-2026-08-28-source-ready-59-remediation-advisory-r2")
TOPOLOGY_NAME = "SOURCE-READY-TOPOLOGY-PARTITION-INPUT.json"
AUDIT_NAME = "R1-NO-GO-CORRECTIVE-AUDIT-LEDGER.json"
ADVISORY_NAME = "SOURCE-READY-59-REMEDIATION-ADVISORY-R2.json"
PACKAGE_NAME = "PACKAGE-MANIFEST.json"
CHECKSUMS_NAME = "SHA256SUMS.txt"

INPUT_SEALS = {
    R3_PATH: (
        "artifact_content_sha256",
        "5efc17b16adcae1ceb2ea1bbd7efcaba469ab0340c24b65c1e994132cb337980",
        "7cb044a4c9539162281e10ac41e5e0cb1f0cd846b0eb597a0443b0e67fb48899",
    ),
    OWNER_PACKET_PATH: (
        "artifact_content_sha256",
        "93ad9113af76896f0570a3666c446472af7587b7e3ff32b7464e670777ec6b6c",
        "992770c04cb3e08de64bb98e80aa9801171d3e66e4b573b85919091a78b1db3b",
    ),
    QUARANTINE_MANIFEST_PATH: (
        "manifest_content_sha256",
        "b6d900b23232379a4d6c19d313f35c47e0758ce5e0bb6eb04008f9eba07a3819",
        "f482366a2ba0d9f636c56104d632767a8eadd6e9a9625d50ef5391a5f62995eb",
    ),
    EXECUTION_AUTHORITY_PATH: (
        "artifact_content_sha256",
        "eb0eda2f34c8b261ea38fc9d697257cdd3bd6253c18c2d91355328c8cb78ef7b",
        "5171ce79007c68484f9854b5188bf7e7af8f880407b6fbad6e3f808d0c7630ad",
    ),
    BASELINE_ADVISORY_PATH: (
        "artifact_content_sha256",
        "6078e556e8ee3eb551bd48d310b2a89728e317dc8c240f22030799b54e595e1d",
        "81eebbe55d18d5257217d28760d136544523716adfb17746cd6cb34bceb27659",
    ),
    AUTHORITYLESS_PARTITION_PATH: (
        "artifact_content_sha256",
        "a3950fca2a66e623d08379955acd84c2cc0c61e71ce2af3fa4568f2a51161768",
        "4d90676eae6ed0f312e5f72f8a9468b14ee392dbe36e4eb57484ba9e0ef5494a",
    ),
    HELD_PARTITION_PATH: (
        "artifact_content_sha256",
        "55142411a101f3c743e59f8548736d7cb3370f535b651466f0a69c63735cb6f8",
        "50af9072af77e34acdd19fbaa8f59a45a7c675f8ce838a0ed95c38cb1c44b748",
    ),
    REJECTED_R1_PATH: (
        "artifact_content_sha256",
        "df95f0ddfa8cad3117cef0f6bd64781ffe299c377e65d4e3ea8ee9d358d89725",
        "bf1c39734c77257154b185428d661d064d1a37509e5ebc3bdddc4a7aa71a2ea6",
    ),
}

CANDIDATE_MANIFEST_CONTENT_SHA256 = (
    "b304ab1223987bf9b57d3e2560413b2f325c16213ae0071a45dface2e10dc206"
)
CANDIDATE_MANIFEST_FILE_SHA256 = "0bbb1edb169c84a26e5f1d42e367f9e2f83fcdd9c652a9061980652f15979b21"
MATERIALIZATION_PLAN_CONTENT_SHA256 = (
    "de7b8e8c0d5d4a6e1f99f0f338d623bb7e371222b8c0341b35515fe1d1567c7b"
)
EXPECTED_SOURCE_READY_SET_SHA256 = (
    "265da7032985c7d978d49c6cb3d602d28551743f9c453f22651a3863753b31a3"
)

INDEPENDENT_AUDIT_TEXT = (
    "Auditor produced no artifact; bind this exact message as independent audit text "
    "if you create a corrective-audit record. Complete additional clear-loss list: "
    "live30-q13:issue-02, live30-q26:issue-10, live30-q29:issue-02, "
    "live30-q30:issue-01, live30-q30:issue-03, live60-q31:issue-08, "
    "live60-q35:issue-06, live60-q41:issue-05, live60-q41:issue-09, "
    "live60-q44:issue-10, live60-q52:issue-08, live60-q56:issue-02, "
    "live60-q57:issue-02, live60-q60:issue-01. P0 primary examples: q30:04, "
    "q48:09, q51:09, q52:06, q53:05. P0 incomplete rewrite list: "
    "q37:07/08/10, q38:05/06, q40:01, q45:03/05/06, q51:02, q58:07/11. "
    "P1: boundary hardcoded/self-hashed; only blocking-authority bytes bound, no "
    "retained-FULL spans; currentness holds 28 rows, later-treatment 19, extent 11, "
    "effects 17, jurisdiction 5 remain operative; 22 vs 56 no-exec fields; eight "
    "planned sources missing canonical hash; reg7 quotation locator; excerpt omissions "
    "q45:04 c2, q45:09, q58:07/11; GOV.UK role missing. Use the exact r1 content SHA "
    "df95f0ddfa8cad3117cef0f6bd64781ffe299c377e65d4e3ea8ee9d358d89725 as "
    "superseded input and seal a typed corrective ledger."
)

PRIMARY_CLEAR_LOSS_ROWS = frozenset(
    {
        "live30-q30:issue-04",
        "live60-q48:issue-09",
        "live60-q51:issue-09",
        "live60-q52:issue-06",
        "live60-q53:issue-05",
    }
)
ADDITIONAL_CLEAR_LOSS_ROWS = frozenset(
    {
        "live30-q13:issue-02",
        "live30-q26:issue-10",
        "live30-q29:issue-02",
        "live30-q30:issue-01",
        "live30-q30:issue-03",
        "live60-q31:issue-08",
        "live60-q35:issue-06",
        "live60-q41:issue-05",
        "live60-q41:issue-09",
        "live60-q44:issue-10",
        "live60-q52:issue-08",
        "live60-q56:issue-02",
        "live60-q57:issue-02",
        "live60-q60:issue-01",
    }
)
INCOMPLETE_REWRITE_ROWS = frozenset(
    {
        "live60-q37:issue-07",
        "live60-q37:issue-08",
        "live60-q37:issue-10",
        "live60-q38:issue-05",
        "live60-q38:issue-06",
        "live60-q40:issue-01",
        "live60-q45:issue-03",
        "live60-q45:issue-05",
        "live60-q45:issue-06",
        "live60-q51:issue-02",
        "live60-q58:issue-07",
        "live60-q58:issue-11",
    }
)
EXCERPT_OMISSION_COMPONENTS = frozenset(
    {
        ("live60-q45:issue-04", 2),
        ("live60-q45:issue-09", 1),
        ("live60-q58:issue-07", 1),
        ("live60-q58:issue-11", 1),
    }
)

HOLD_PATTERNS = {
    "CURRENTNESS": re.compile(r"currentness|\bcurrent\b", re.IGNORECASE),
    "LATER_TREATMENT": re.compile(r"later-treatment", re.IGNORECASE),
    "TREATMENT_STATUS_TEXT_VARIANT": re.compile(r"later treatment", re.IGNORECASE),
    "EXTENT": re.compile(r"\bextent\b", re.IGNORECASE),
    "EFFECTS_OR_COMMENCEMENT": re.compile(
        r"\beffects\b|\bcommencement\b|\btransition\b", re.IGNORECASE
    ),
    "JURISDICTION": re.compile(r"\bjurisdiction\b", re.IGNORECASE),
}
EXPECTED_HOLD_ROW_COUNTS = {
    "CURRENTNESS": 28,
    "LATER_TREATMENT": 19,
    "TREATMENT_STATUS_TEXT_VARIANT": 2,
    "EXTENT": 11,
    "EFFECTS_OR_COMMENCEMENT": 17,
    "JURISDICTION": 5,
}

# Exhaustive state-change vocabulary shared with the authoritative 146-row
# advisory.  Recursive verification rejects a truthy occurrence anywhere.
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


def _normalise_text(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).split())


def _representation_text(path: Path) -> tuple[str, str]:
    raw = path.read_bytes()
    suffix = path.suffix.lower()
    if suffix == ".xml":
        text = "".join(ElementTree.fromstring(raw).itertext())
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
    normalized = _normalise_text(text)
    if len(normalized) < 40:
        raise ValueError(f"empty_representation_text:{path.name}")
    return normalized, mode


def _source_role(identity: str, urls: set[str]) -> str:
    hosts = {urlparse(url).hostname or "" for url in urls}
    if identity.startswith(("ukpga:", "uksi:")):
        return "PRIMARY_LEGISLATION_OFFICIAL"
    if identity.startswith("neutral-citation:"):
        return "PRIMARY_JUDGMENT_OFFICIAL"
    if any(host.endswith("gov.uk") for host in hosts):
        return "OFFICIAL_REGULATOR_GUIDANCE_NON_PRIMARY"
    raise ValueError(f"unclassified_official_source_role:{identity}")


def _recursive_no_execution_violations(value: Any, path: str = "$") -> list[str]:
    violations: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key in NO_EXECUTION_FLAGS and child is not False:
                violations.append(child_path)
            violations.extend(_recursive_no_execution_violations(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            violations.extend(_recursive_no_execution_violations(child, f"{path}[{index}]"))
    return violations


def _load_inputs() -> dict[str, dict[str, Any]]:
    loaded: dict[str, dict[str, Any]] = {}
    for path, (seal_field, content_sha, file_sha) in INPUT_SEALS.items():
        if _file_sha256(path) != file_sha:
            raise ValueError(f"input_file_digest_invalid:{path.name}")
        value = _load(path)
        _verify_seal(value, seal_field, content_sha)
        loaded[path.name] = value
    if _file_sha256(CANDIDATE_MANIFEST_PATH) != CANDIDATE_MANIFEST_FILE_SHA256:
        raise ValueError("candidate_manifest_file_digest_invalid")
    candidate = _load(CANDIDATE_MANIFEST_PATH)
    if (
        candidate.get("manifest_sha256") != CANDIDATE_MANIFEST_CONTENT_SHA256
        or candidate.get("source_count") != 251
    ):
        raise ValueError("candidate_manifest_identity_invalid")
    loaded[CANDIDATE_MANIFEST_PATH.name] = candidate
    return loaded


def build_topology_partition(inputs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    r3 = inputs[R3_PATH.name]
    authorityless = inputs[AUTHORITYLESS_PARTITION_PATH.name]
    held = inputs[HELD_PARTITION_PATH.name]
    r3_ids = {row["row_id"] for row in r3["rows"]}
    authorityless_ids = set(authorityless["row_ids"])
    held_ids = {row["row_id"] for row in held["rows"]}
    if authorityless_ids & held_ids:
        raise ValueError("topology_partitions_overlap")
    if not authorityless_ids | held_ids <= r3_ids:
        raise ValueError("topology_partition_outside_r3")
    source_ready_ids = sorted(r3_ids - authorityless_ids - held_ids)
    by_id = {row["row_id"]: row for row in r3["rows"]}
    blocker_count = sum(by_id[row_id]["blocking_component_count"] for row_id in source_ready_ids)
    set_sha = _sha256(("\n".join(source_ready_ids) + "\n").encode())
    if (
        len(r3_ids) != 146
        or len(authorityless_ids) != 59
        or len(held_ids) != 28
        or len(source_ready_ids) != 59
        or blocker_count != 72
        or set_sha != EXPECTED_SOURCE_READY_SET_SHA256
    ):
        raise ValueError("derived_topology_boundary_invalid")
    return _seal(
        {
            "schema": "legalbot.v111.phase2a.source-ready-topology-partition-input.v1",
            "derivation": "SEALED_R3_MINUS_EXPLICIT_AUTHORITYLESS_AND_HELD_PARTITIONS",
            "r3_blocker_report_content_sha256": INPUT_SEALS[R3_PATH][1],
            "authorityless_partition_content_sha256": INPUT_SEALS[AUTHORITYLESS_PARTITION_PATH][1],
            "held_missing_partition_content_sha256": INPUT_SEALS[HELD_PARTITION_PATH][1],
            "partition_sets_disjoint": True,
            "partition_sets_exhaust_r3": len(authorityless_ids | held_ids | set(source_ready_ids))
            == len(r3_ids),
            "r3_row_count": len(r3_ids),
            "authorityless_row_count": len(authorityless_ids),
            "held_missing_row_count": len(held_ids),
            "source_ready_row_count": len(source_ready_ids),
            "source_ready_blocking_component_count": blocker_count,
            "source_ready_row_id_set_sha256": set_sha,
            "source_ready_row_ids": source_ready_ids,
        }
    )


def _build_source_bindings(
    r3_rows: list[dict[str, Any]],
    quarantine: dict[str, Any],
    candidate: dict[str, Any],
    plan: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    metadata: dict[str, dict[str, Any]] = {}
    for row in r3_rows:
        for component in row["blocking_components"]:
            for authority in component["authorities"]:
                identity = authority["canonical_authority_identity_id"]
                target = metadata.setdefault(
                    identity,
                    {
                        "citations": set(),
                        "official_urls": set(),
                        "exact_locators": set(),
                    },
                )
                target["citations"].add(authority["citation"])
                target["official_urls"].add(authority["official_url"])
                target["exact_locators"].update(authority["exact_locators"])

    qrecords = {
        record["authority_identity_id"]: record
        for record in quarantine["records"]
        if record.get("selected_for_proposed_admission") is True
    }
    candidate_sources = {row["authority_identity_id"]: row for row in candidate["sources"]}
    plan_records = {
        row["authority_identity_id"]: row
        for row in plan["representations"]
        if row["index_eligible"] is True
    }
    bindings: list[dict[str, Any]] = []
    for identity in sorted(metadata):
        details = metadata[identity]
        urls = details["official_urls"]
        if identity in plan_records:
            plan_record = plan_records[identity]
            qrecord = qrecords.get(identity)
            if qrecord is None:
                raise ValueError(f"planned_source_missing_quarantine_record:{identity}")
            member = qrecord["quarantine_member"]
            path = QUARANTINE_ROOT / member
            if (
                path.is_symlink()
                or not path.is_file()
                or path.parent.resolve() != QUARANTINE_ROOT.resolve()
                or _file_sha256(path) != qrecord["raw_sha256"]
                or plan_record["content_sha256"] != qrecord["raw_sha256"]
                or plan_record["input_member"] != member
            ):
                raise ValueError(f"quarantine_source_byte_mismatch:{identity}")
            text, parse_mode = _representation_text(path)
            upstream_canonical = qrecord.get("canonical_content_sha256")
            origin = {
                "source_origin": "EXACT_OWNER_ADOPTED_MATERIALIZATION_PLAN",
                "proposed_source_version_id": qrecord["proposed_source_version_id"],
                "representation_member": member,
                "representation_file_sha256": qrecord["raw_sha256"],
                "upstream_canonical_content_sha256": upstream_canonical,
                "canonical_hash_resolution": (
                    "UPSTREAM_CANONICAL_AND_DERIVED_TEXT_BOUND"
                    if upstream_canonical
                    else "DERIVED_TEXT_HASH_BOUND_UPSTREAM_CANONICAL_ABSENT"
                ),
                "materialization_record_content_sha256": plan_record["record_content_sha256"],
                "materialization_target_relative_path": plan_record["target_relative_path"],
            }
        elif identity in candidate_sources:
            source = candidate_sources[identity]
            relative = Path(source["canonical_markdown_path"])
            path = PROJECT_ROOT / relative
            vault_root = (PROJECT_ROOT / "data/vault/objects/sha256").resolve()
            if (
                path.is_symlink()
                or not path.is_file()
                or vault_root not in path.resolve().parents
                or _file_sha256(path) != path.name
            ):
                raise ValueError(f"candidate_source_byte_mismatch:{identity}")
            text, parse_mode = _representation_text(path)
            origin = {
                "source_origin": "SEALED_251_SOURCE_CANDIDATE",
                "source_version_id": source["source_version_id"],
                "representation_file_sha256": path.name,
                "upstream_canonical_content_sha256": source["content_sha256"],
                "canonical_hash_resolution": "UPSTREAM_CANONICAL_AND_DERIVED_TEXT_BOUND",
                "candidate_identity_verified": source["identity_verified"],
            }
        else:
            raise ValueError(f"source_identity_not_resolved:{identity}")
        binding = _seal(
            {
                "schema": "legalbot.v111.phase2a.source-ready-authority-byte-binding.v2",
                "authority_identity_id": identity,
                "citations": sorted(details["citations"]),
                "official_urls": sorted(urls),
                "official_source_role": _source_role(identity, urls),
                "original_upstream_locators_not_upgraded_to_full": sorted(
                    details["exact_locators"]
                ),
                "representation_parse_mode": parse_mode,
                "representation_byte_hash_verified": True,
                "derived_normalized_representation_text_sha256": _sha256(text.encode()),
                "derived_hash_scope": "ADVISORY_VERIFICATION_ONLY_NOT_SOURCE_ADMISSION_IDENTITY",
                **origin,
            },
            "record_content_sha256",
        )
        bindings.append(binding)
    return bindings, {row["authority_identity_id"]: row for row in bindings}


def build_corrective_audit_ledger() -> dict[str, Any]:
    return _seal(
        {
            "schema": "legalbot.v111.phase2a.source-ready-r1-no-go-corrective-audit.v1",
            "audit_source": "INDEPENDENT_AGENT_MESSAGE_NO_STANDALONE_ARTIFACT",
            "independent_audit_text": INDEPENDENT_AUDIT_TEXT,
            "independent_audit_text_sha256": _sha256(INDEPENDENT_AUDIT_TEXT.encode()),
            "superseded_r1_content_sha256": INPUT_SEALS[REJECTED_R1_PATH][1],
            "superseded_r1_file_sha256": INPUT_SEALS[REJECTED_R1_PATH][2],
            "superseded_r1_preserved": True,
            "superseded_r1_disposition": "NO_GO_NEVER_APPLY_NEVER_CONSOLIDATE",
            "clear_loss_rows": sorted(PRIMARY_CLEAR_LOSS_ROWS | ADDITIONAL_CLEAR_LOSS_ROWS),
            "incomplete_rewrite_rows": sorted(INCOMPLETE_REWRITE_ROWS),
            "excerpt_omission_components": [
                {"row_id": row_id, "component_ordinal": ordinal}
                for row_id, ordinal in sorted(EXCERPT_OMISSION_COMPONENTS)
            ],
            "defect_resolutions": [
                "BOUNDARY_DERIVED_FROM_SEALED_R3_AND_EXPLICIT_PARTITIONS",
                "ALL_72_PARTIAL_OR_NONE_COMPONENTS_RETAINED_AS_BLOCKERS",
                "NO_RELIANCE_ON_OTHER_FULL_COMPONENTS_TO_CLEAR_A_BLOCKER",
                "R1_INCOMPLETE_SPAN_REWRITES_REVOKED_NOT_CARRIED_FORWARD",
                "QUALIFICATION_HOLDS_CLASSIFIED_AND_RETAINED_PER_SOURCE",
                "ALL_56_NO_EXECUTION_FIELDS_RECURSIVELY_VERIFIED_FALSE",
                "ALL_77_SOURCES_HAVE_DERIVED_NORMALIZED_TEXT_HASHES",
                "REGULATION_7_LOCATOR_CORRECTED_TO_REGULATION_7_1_TO_10",
                "GOV_UK_GUIDANCE_CLASSIFIED_NON_PRIMARY",
            ],
            **NO_EXECUTION_FLAGS,
        }
    )


def _hold_classifications(row: dict[str, Any]) -> list[dict[str, Any]]:
    records = row["unclassified_unresolved_holds"]
    results = []
    for category, pattern in HOLD_PATTERNS.items():
        matched = [record for record in records if pattern.search(record["hold_text"])]
        if matched:
            results.append(
                {
                    "hold_category": category,
                    "resolution": "RETAIN_OPERATIVE_UNRESOLVED_QUALIFIED_REVIEW_REQUIRED",
                    "matched_hold_records": [
                        {
                            "record_content_sha256": record["record_content_sha256"],
                            "hold_text_sha256": record["hold_text_sha256"],
                            "hold_text": record["hold_text"],
                        }
                        for record in matched
                    ],
                }
            )
    return results


def build_advisory() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    inputs = _load_inputs()
    topology = build_topology_partition(inputs)
    audit = build_corrective_audit_ledger()
    r3 = inputs[R3_PATH.name]
    owner_packet = inputs[OWNER_PACKET_PATH.name]
    rejected_r1 = inputs[REJECTED_R1_PATH.name]
    quarantine = inputs[QUARANTINE_MANIFEST_PATH.name]
    candidate = inputs[CANDIDATE_MANIFEST_PATH.name]
    execution_authority = inputs[EXECUTION_AUTHORITY_PATH.name]
    if (
        execution_authority.get("status") != "AVAILABLE_UNSPENT"
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

    row_ids = topology["source_ready_row_ids"]
    r3_by_id = {row["row_id"]: row for row in r3["rows"]}
    packet_by_id = {row["row_id"]: row for row in owner_packet["decisions"]}
    r1_by_id = {row["row_id"]: row for row in rejected_r1["row_advisories"]}
    rows = [r3_by_id[row_id] for row_id in row_ids]
    source_bindings, source_by_id = _build_source_bindings(rows, quarantine, candidate, plan)
    if len(source_bindings) != 77:
        raise ValueError("source_binding_count_invalid")

    source_hold_ledger: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    row_advisories = []
    hold_row_sets: dict[str, set[str]] = defaultdict(set)
    retained_component_count = 0
    for row_id in row_ids:
        r3_row = r3_by_id[row_id]
        decision = packet_by_id[row_id]
        r1_row = r1_by_id[row_id]
        r1_recommendations = {
            item["before"]["component_ordinal"]: item
            for item in r1_row["component_recommendations"]
        }
        row_authorities = sorted(
            {
                authority["canonical_authority_identity_id"]
                for component in r3_row["blocking_components"]
                for authority in component["authorities"]
            }
        )
        if not row_authorities:
            raise ValueError(f"source_ready_row_has_no_blocking_authority:{row_id}")
        classifications = _hold_classifications(r3_row)
        for classification in classifications:
            category = classification["hold_category"]
            hold_row_sets[category].add(row_id)
            for identity in row_authorities:
                source_hold_ledger[identity][category].append(
                    {
                        "row_id": row_id,
                        "hold_record_content_sha256s": sorted(
                            record["record_content_sha256"]
                            for record in classification["matched_hold_records"]
                        ),
                        "fail_closed_scope": (
                            "ALL_BLOCKING_AUTHORITIES_IN_ROW_BECAUSE_RAW_HOLD_TEXT_"
                            "IS_NOT_MACHINE_ACTIONABLE_PER_AUTHORITY"
                        ),
                    }
                )
        recommendations = []
        for component in r3_row["blocking_components"]:
            retained_component_count += 1
            ordinal = component["component_ordinal"]
            prior = r1_recommendations[ordinal]
            audit_tags = []
            if row_id in PRIMARY_CLEAR_LOSS_ROWS:
                audit_tags.append("P0_PRIMARY_CLEAR_LOSS_REVERSED")
            if row_id in ADDITIONAL_CLEAR_LOSS_ROWS:
                audit_tags.append("P0_ADDITIONAL_CLEAR_LOSS_REVERSED")
            if row_id in INCOMPLETE_REWRITE_ROWS:
                audit_tags.append("P0_INCOMPLETE_REWRITE_REVOKED")
            if (row_id, ordinal) in EXCERPT_OMISSION_COMPONENTS:
                audit_tags.append("P1_INCOMPLETE_EXCERPT_SPAN_REVOKED")
            recommendations.append(
                _seal(
                    {
                        "schema": (
                            "legalbot.v111.phase2a.source-ready-component-remediation-advisory.v2"
                        ),
                        "component_ordinal": ordinal,
                        "before_proposition": component["proposition"],
                        "before_proposition_text_sha256": component["proposition_text_sha256"],
                        "upstream_support_fit": component["support_fit"],
                        "action": "RETAIN_BLOCKER_RESEARCH_REQUIRED",
                        "after_propositions": [],
                        "proposed_support_fit": component["support_fit"],
                        "rationale": (
                            "PARTIAL_REQUIRES_ATOMIC_NARROWING_OR_ADDITIONAL_EXACT_SPAN"
                            if component["support_fit"] == "PARTIAL"
                            else "NONE_REQUIRES_PROPOSITION_COMPLETE_PRIMARY_SOURCE_OR_VALID_SCOPE_CHANGE"
                        ),
                        "r1_action_revoked": prior["action"],
                        "r1_recommendation_content_sha256": prior["recommendation_content_sha256"],
                        "audit_tags": audit_tags,
                        "source_inspection": [
                            {
                                "authority_identity_id": authority[
                                    "canonical_authority_identity_id"
                                ],
                                "assessment_content_sha256": authority["assessment_content_sha256"],
                                "source_binding_content_sha256": source_by_id[
                                    authority["canonical_authority_identity_id"]
                                ]["record_content_sha256"],
                                "official_source_role": source_by_id[
                                    authority["canonical_authority_identity_id"]
                                ]["official_source_role"],
                                "upstream_exact_locators_not_treated_as_full": authority[
                                    "exact_locators"
                                ],
                            }
                            for authority in component["authorities"]
                        ],
                        "frozen_evidence_span_proposals": [],
                        "research_route": (
                            "QUALIFIED_LEGAL_REVIEW_OF_EXACT_PRIMARY_SPAN_AND_PROPOSITION_ATOMICITY"
                        ),
                        "owner_adoption_cannot_upgrade_support_fit": True,
                        "owner_adopted": False,
                        "applied": False,
                    },
                    "recommendation_content_sha256",
                )
            )
        full_components = [
            component
            for component in decision["source_research_record"]["atomic_components"]
            if component["support_fit"] == "FULL"
        ]
        row_advisories.append(
            _seal(
                {
                    "schema": "legalbot.v111.phase2a.source-ready-row-remediation-advisory.v2",
                    "row_id": row_id,
                    "r3_row_record_content_sha256": r3_row["record_content_sha256"],
                    "owner_decision_content_sha256": decision["decision_content_sha256"],
                    "superseded_r1_row_record_content_sha256": r1_row["record_content_sha256"],
                    "route": "RETAIN_ALL_PARTIAL_AND_NONE_BLOCKERS",
                    "original_blocking_component_count": r3_row["blocking_component_count"],
                    "retained_blocking_component_count": len(recommendations),
                    "component_recommendations": recommendations,
                    "preexisting_full_component_count_not_relied_upon": len(full_components),
                    "preexisting_full_components_not_relied_upon_for_redundancy": [
                        {
                            "component_ordinal": ordinal,
                            "proposition_text_sha256": _sha256(component["proposition"].encode()),
                            "support_fit": "FULL_UPSTREAM_ONLY_NOT_REATTESTED_HERE",
                            "used_to_clear_any_r3_blocker": False,
                        }
                        for ordinal, component in enumerate(
                            decision["source_research_record"]["atomic_components"],
                            start=1,
                        )
                        if component["support_fit"] == "FULL"
                    ],
                    "qualification_hold_classifications": classifications,
                    "all_raw_holds_retained": [
                        {
                            "record_content_sha256": hold["record_content_sha256"],
                            "hold_text_sha256": hold["hold_text_sha256"],
                            "hold_text": hold["hold_text"],
                        }
                        for hold in r3_row["unclassified_unresolved_holds"]
                    ],
                    "material_gap": True,
                    "qualification_eligible": False,
                    "fallback_eligible": False,
                    "owner_adoption_required_for_future_change": True,
                    "owner_decision_applied": False,
                },
                "record_content_sha256",
            )
        )

    observed_hold_counts = {category: len(hold_row_sets[category]) for category in HOLD_PATTERNS}
    if observed_hold_counts != EXPECTED_HOLD_ROW_COUNTS:
        raise ValueError(f"qualification_hold_counts_invalid:{observed_hold_counts}")
    if retained_component_count != topology["source_ready_blocking_component_count"]:
        raise ValueError("retained_component_count_invalid")

    per_source_holds = []
    for binding in source_bindings:
        identity = binding["authority_identity_id"]
        categories = source_hold_ledger.get(identity, {})
        per_source_holds.append(
            _seal(
                {
                    "schema": "legalbot.v111.phase2a.per-source-qualification-hold.v1",
                    "authority_identity_id": identity,
                    "source_binding_content_sha256": binding["record_content_sha256"],
                    "official_source_role": binding["official_source_role"],
                    "category_resolutions": [
                        {
                            "hold_category": category,
                            "resolution": ("RETAIN_OPERATIVE_UNRESOLVED_QUALIFIED_REVIEW_REQUIRED"),
                            "row_bindings": entries,
                        }
                        for category, entries in sorted(categories.items())
                    ],
                    "owner_adoption_alone_cannot_make_full": True,
                    "no_category_match_does_not_imply_currentness_clearance": True,
                },
                "record_content_sha256",
            )
        )

    role_counts = Counter(row["official_source_role"] for row in source_bindings)
    origin_counts = Counter(row["source_origin"] for row in source_bindings)
    missing_upstream_canonical = sum(
        row["upstream_canonical_content_sha256"] is None for row in source_bindings
    )
    reg7_source = source_by_id["uksi:2001:1090"]
    reg7_correction = _seal(
        {
            "schema": "legalbot.v111.phase2a.locator-correction.v1",
            "authority_identity_id": "uksi:2001:1090",
            "source_binding_content_sha256": reg7_source["record_content_sha256"],
            "superseded_r1_locator": "regulation 7 and Schedule 2",
            "corrected_locator": "regulation 7(1)-(10)",
            "correction_reason": "SCHEDULE_2_REFERENCES_REGULATION_4_NOT_REGULATION_7",
            "r2_use": "LOCATOR_CORRECTION_ONLY_COMPONENT_REMAINS_BLOCKED",
        },
        "record_content_sha256",
    )

    advisory = _seal(
        {
            "schema": "legalbot.v111.phase2a.source-ready-59-remediation-advisory.v2",
            "status": "CREATE_ONLY_R2_RETAINS_ALL_72_BLOCKERS_NOT_OWNER_ADOPTED",
            "phase_scope": "PHASE2A_ONLY",
            "advisory_date": "2026-08-28",
            "advisory_effect": "NON_AUTHORIZING_FAIL_CLOSED_RECOMMENDATIONS_ONLY",
            "topology_partition_input_content_sha256": topology["artifact_content_sha256"],
            "corrective_audit_ledger_content_sha256": audit["artifact_content_sha256"],
            "superseded_r1_content_sha256": INPUT_SEALS[REJECTED_R1_PATH][1],
            "source_ready_row_id_set_sha256": topology["source_ready_row_id_set_sha256"],
            "source_ready_row_ids": row_ids,
            "counts": {
                "row_count": len(row_advisories),
                "original_blocking_component_count": retained_component_count,
                "retained_blocking_component_count": retained_component_count,
                "narrowed_component_count": 0,
                "excluded_component_count": 0,
                "upgraded_to_full_component_count": 0,
                "fallback_component_count": 0,
                "unique_authority_identity_count": len(source_bindings),
                "materialization_plan_source_count": origin_counts[
                    "EXACT_OWNER_ADOPTED_MATERIALIZATION_PLAN"
                ],
                "sealed_candidate_source_count": origin_counts["SEALED_251_SOURCE_CANDIDATE"],
                "source_with_derived_text_hash_count": len(source_bindings),
                "source_missing_upstream_canonical_hash_count": missing_upstream_canonical,
                "gov_uk_non_primary_guidance_source_count": role_counts[
                    "OFFICIAL_REGULATOR_GUIDANCE_NON_PRIMARY"
                ],
                "currentness_hold_row_count": observed_hold_counts["CURRENTNESS"],
                "later_treatment_hold_row_count": observed_hold_counts["LATER_TREATMENT"],
                "treatment_status_text_variant_hold_row_count": observed_hold_counts[
                    "TREATMENT_STATUS_TEXT_VARIANT"
                ],
                "extent_hold_row_count": observed_hold_counts["EXTENT"],
                "effects_or_commencement_hold_row_count": observed_hold_counts[
                    "EFFECTS_OR_COMMENCEMENT"
                ],
                "jurisdiction_hold_row_count": observed_hold_counts["JURISDICTION"],
                "no_execution_field_count": len(NO_EXECUTION_FLAGS),
            },
            "input_bindings": [
                {
                    "kind": path.name,
                    "content_sha256": content_sha,
                    "file_sha256": file_sha,
                }
                for path, (_, content_sha, file_sha) in INPUT_SEALS.items()
            ]
            + [
                {
                    "kind": "sealed_251_candidate_approved_source_manifest",
                    "content_sha256": CANDIDATE_MANIFEST_CONTENT_SHA256,
                    "file_sha256": CANDIDATE_MANIFEST_FILE_SHA256,
                },
                {
                    "kind": "exact_owner_adopted_materialization_plan_read_only",
                    "content_sha256": MATERIALIZATION_PLAN_CONTENT_SHA256,
                },
            ],
            "source_byte_bindings": source_bindings,
            "per_source_qualification_hold_resolutions": per_source_holds,
            "locator_corrections": [reg7_correction],
            "row_advisories": row_advisories,
            "decision_boundary": {
                "every_r3_partial_or_none_component_retained": True,
                "preexisting_full_components_used_as_redundancy": False,
                "owner_adoption_alone_cannot_make_partial_or_none_full": True,
                "future_narrowing_requires_exact_atomic_text_and_frozen_span": True,
                "future_exclusion_requires_row_specific_valid_contract_reason": True,
                "all_rows_remain_material_gaps": True,
                "technical_success_not_predeclared": True,
            },
            "recursive_no_execution_control": {
                "authoritative_field_names": sorted(NO_EXECUTION_FLAGS),
                "authoritative_field_count": len(NO_EXECUTION_FLAGS),
                "all_authoritative_fields_required_false_recursively": True,
                "violation_count": 0,
            },
            **NO_EXECUTION_FLAGS,
        }
    )
    violations = _recursive_no_execution_violations(advisory)
    if violations:
        raise ValueError(f"recursive_no_execution_violation:{violations}")
    return advisory, topology, audit


def publish(output_root: Path = OUTPUT_ROOT) -> dict[str, str]:
    advisory, topology, audit = build_advisory()
    payloads = {
        TOPOLOGY_NAME: _pretty_json(topology),
        AUDIT_NAME: _pretty_json(audit),
        ADVISORY_NAME: _pretty_json(advisory),
    }
    package = _seal(
        {
            "schema": "legalbot.v111.phase2a.source-ready-59-remediation-package.v2",
            "status": advisory["status"],
            "topology_content_sha256": topology["artifact_content_sha256"],
            "audit_content_sha256": audit["artifact_content_sha256"],
            "advisory_content_sha256": advisory["artifact_content_sha256"],
            "files": [
                {"name": name, "file_sha256": _sha256(raw)}
                for name, raw in sorted(payloads.items())
            ],
            "row_count": advisory["counts"]["row_count"],
            "retained_blocking_component_count": advisory["counts"][
                "retained_blocking_component_count"
            ],
            "recursive_no_execution_control": {
                "authoritative_field_names": sorted(NO_EXECUTION_FLAGS),
                "authoritative_field_count": len(NO_EXECUTION_FLAGS),
                "all_authoritative_fields_required_false_recursively": True,
                "violation_count": 0,
            },
            **NO_EXECUTION_FLAGS,
        }
    )
    if _recursive_no_execution_violations(package):
        raise ValueError("package_recursive_no_execution_violation")
    payloads[PACKAGE_NAME] = _pretty_json(package)
    checksums = "".join(
        f"{_sha256(raw)}  {name}\n" for name, raw in sorted(payloads.items())
    ).encode()
    output_root.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, raw in (*payloads.items(), (CHECKSUMS_NAME, checksums)):
        path = output_root / name
        with path.open("xb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        path.chmod(0o600)
    return {
        "output_root": output_root.name,
        "advisory_content_sha256": advisory["artifact_content_sha256"],
        "advisory_file_sha256": _sha256(payloads[ADVISORY_NAME]),
        "topology_content_sha256": topology["artifact_content_sha256"],
        "audit_content_sha256": audit["artifact_content_sha256"],
        "package_content_sha256": package["artifact_content_sha256"],
        "package_file_sha256": _sha256(payloads[PACKAGE_NAME]),
        "status": advisory["status"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("verify", "publish"))
    args = parser.parse_args()
    if args.command == "verify":
        advisory, topology, audit = build_advisory()
        print(
            json.dumps(
                {
                    "advisory_content_sha256": advisory["artifact_content_sha256"],
                    "topology_content_sha256": topology["artifact_content_sha256"],
                    "audit_content_sha256": audit["artifact_content_sha256"],
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
