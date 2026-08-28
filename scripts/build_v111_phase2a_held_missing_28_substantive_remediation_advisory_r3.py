#!/usr/bin/env python3
"""Create the immutable held/missing-28 r3 targeted span correction.

R3 changes only the q04 self-defence proposal rejected by the independent r2
audit.  It adds the exact CJIA 2008 section 76(2)(a) identity provision and
section 76(6) non-householder proportionality provision, then reseals every
dependent record.  It cannot apply an owner decision or run any production
operation.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts import (  # noqa: E402
    build_v111_phase2a_held_missing_28_substantive_remediation_advisory as r1,
)

REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
R2_ROOT = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-held-missing-28-substantive-remediation-advisory-r2"
)
R2_ADVISORY_NAME = "EXACT-28-ROW-SUBSTANTIVE-REMEDIATION-ADVISORY-R2.json"
R2_SOURCE_MANIFEST_NAME = "NINE-PROPOSED-REPRESENTATION-BINDINGS-R2.json"
R2_PACKAGE_NAME = "PACKAGE-MANIFEST.json"
R2_ADVISORY_FILE_SHA256 = "a309a5020bf3031a97d6177e1aaef76401966a2271a767a5e17b660b1a1adafa"
R2_ADVISORY_CONTENT_SHA256 = "208b5250147ca26e1ec49ac8624b1866ec762dbbc95b285600c17962d6beefbf"
R2_SOURCE_MANIFEST_FILE_SHA256 = "29b90ae9c94439324ea8e12e44d72313ff57f4aa6de797398e4bd954435447d2"
R2_SOURCE_MANIFEST_CONTENT_SHA256 = (
    "f5014e112eec9962b654811f7958ae041daf938c517c22c72ed7ef5f00a10ab4"
)
R2_PACKAGE_FILE_SHA256 = "a0d8cc6ea87b9383a3ea70348d2d608202567ac2706bf45a076bc3ba0efe763d"
R2_PACKAGE_CONTENT_SHA256 = "b30770710079290d89f59d903267d72b260b0aab7b67d933602d59cecf513220"

OUTPUT_ROOT = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-held-missing-28-substantive-remediation-advisory-r3"
)
ADVISORY_NAME = "EXACT-28-ROW-SUBSTANTIVE-REMEDIATION-ADVISORY-R3.json"
SOURCE_MANIFEST_NAME = "NINE-PROPOSED-REPRESENTATION-BINDINGS-R3.json"
AUDIT_NAME = "R2-TARGETED-AUDIT-NO-GO.json"
PACKAGE_NAME = "PACKAGE-MANIFEST.json"
CHECKSUMS_NAME = "SHA256SUMS.txt"

TARGET_ROW_ID = "live30-q04:issue-07"
TARGET_COMPONENT_ORDINAL = 1
TARGET_SOURCE_ID = "ukpga:2008:4"
TARGET_FINGERPRINT = "R2_Q04_C1_CJIA_S76_INCOMPLETE_EXACT_SPAN"
R2_RECOMMENDATION_SHA256 = "7c293616d261ea9a0f7adc607c15d4870d97f0363d16e0adfeac0ab93ac0e9d4"
R2_SPAN_SHA256 = "8827a44a4317f0a7e671bcffc14df347c90434a6b60d7dcaeb06aaaa0982aa11"
TARGET_SOURCE_BINDING_SHA256 = "b02cde2627fc442f049541fad177b2a2206bf09065ea3bf45e6a7f05e2ac7bfd"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _load(path: Path, file_sha256: str, content_sha256: str, field: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or _file_sha256(path) != file_sha256:
        raise ValueError(f"{field}_file_identity_invalid")
    value = json.loads(path.read_bytes())
    if value.get(field) != content_sha256:
        raise ValueError(f"{field}_content_identity_invalid")
    material = dict(value)
    material.pop(field, None)
    if r1._sha256(r1._canonical_json(material)) != content_sha256:
        raise ValueError(f"{field}_seal_invalid")
    return value


def _load_r2() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    advisory = _load(
        R2_ROOT / R2_ADVISORY_NAME,
        R2_ADVISORY_FILE_SHA256,
        R2_ADVISORY_CONTENT_SHA256,
        "artifact_content_sha256",
    )
    source_manifest = _load(
        R2_ROOT / R2_SOURCE_MANIFEST_NAME,
        R2_SOURCE_MANIFEST_FILE_SHA256,
        R2_SOURCE_MANIFEST_CONTENT_SHA256,
        "artifact_content_sha256",
    )
    package = _load(
        R2_ROOT / R2_PACKAGE_NAME,
        R2_PACKAGE_FILE_SHA256,
        R2_PACKAGE_CONTENT_SHA256,
        "package_content_sha256",
    )
    package_by_name = {item["name"]: item for item in package["artifacts"]}
    expected = {
        R2_ADVISORY_NAME: R2_ADVISORY_FILE_SHA256,
        R2_SOURCE_MANIFEST_NAME: R2_SOURCE_MANIFEST_FILE_SHA256,
    }
    if any(package_by_name[name]["file_sha256"] != digest for name, digest in expected.items()):
        raise ValueError("r2_package_binding_invalid")
    return advisory, source_manifest, package


def _reseal(value: dict[str, Any], field: str, **updates: Any) -> dict[str, Any]:
    material = copy.deepcopy(value)
    material.pop(field, None)
    material.update(updates)
    return r1._seal(material, field)


def _patched_span(span: dict[str, Any], source_binding: dict[str, Any]) -> dict[str, Any]:
    if (
        span["span_proposal_content_sha256"] != R2_SPAN_SHA256
        or span["source_binding_content_sha256"] != TARGET_SOURCE_BINDING_SHA256
    ):
        raise ValueError("target_r2_span_identity_invalid")
    source_text, _ = r1._representation_text(source_binding)
    new_excerpts = [
        "the common law defence of self-defence;",
        (
            "In a case other than a householder case, the degree of force used by D is not "
            "to be regarded as having been reasonable in the circumstances as D believed them "
            "to be if it was disproportionate in those circumstances."
        ),
    ]
    excerpt_records = copy.deepcopy(span["supporting_excerpts"])
    for text in new_excerpts:
        normalized = r1._normalise_evidence_text(text)
        if normalized not in source_text:
            raise ValueError(f"target_excerpt_missing:{_sha256(normalized.encode())}")
        excerpt_records.append(
            {
                "text": text,
                "normalized_text_sha256": _sha256(normalized.encode()),
                "verified_in_primary_official_bytes": True,
            }
        )
    return _reseal(
        span,
        "span_proposal_content_sha256",
        schema="legalbot.v111.phase2a.held-missing-28-evidence-span-proposal.r3.v1",
        supersedes_r2_span_proposal_content_sha256=R2_SPAN_SHA256,
        exact_locators=[
            "section 76(1)",
            "section 76(2)(a)",
            "section 76(3)-(6)",
            "section 76(6A)-(9)",
        ],
        supporting_excerpts=excerpt_records,
    )


def build_artifacts() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    r2_advisory, r2_manifest, _ = _load_r2()
    advisory = copy.deepcopy(r2_advisory)
    rows = advisory["rows"]
    row = next(item for item in rows if item["row_id"] == TARGET_ROW_ID)
    recommendation = next(
        item
        for item in row["blocker_recommendations"]
        if item["component_ordinal"] == TARGET_COMPONENT_ORDINAL
    )
    if recommendation["recommendation_content_sha256"] != R2_RECOMMENDATION_SHA256:
        raise ValueError("target_r2_recommendation_identity_invalid")
    source_binding = next(
        item
        for item in advisory["source_bindings"]
        if item["authority_identity_id"] == TARGET_SOURCE_ID
    )
    if source_binding["record_content_sha256"] != TARGET_SOURCE_BINDING_SHA256:
        raise ValueError("target_source_binding_identity_invalid")
    spans = copy.deepcopy(recommendation["evidence_span_proposals"])
    span_index = next(
        index
        for index, item in enumerate(spans)
        if item["authority_identity_id"] == TARGET_SOURCE_ID
    )
    spans[span_index] = _patched_span(spans[span_index], source_binding)
    proposition = (
        "Criminal Law Act 1967 section 3(1)-(2) permits reasonable force only for "
        "preventing crime or effecting or assisting lawful arrest and replaces the common-law "
        "rules only for those purposes. Criminal Justice and Immigration Act 2008 section 76(1), "
        "(2)(a), (3)-(6) and (6A)-(9) separately identifies the common-law defence of "
        "self-defence, records that force is judged by the circumstances D genuinely believed, "
        "and provides that, outside a householder case, disproportionate force is not reasonable. "
        "No defence or factual outcome is inferred."
    )
    after = copy.deepcopy(recommendation["after_propositions"])
    after[0]["proposition"] = proposition
    after[0]["proposition_text_sha256"] = _sha256(proposition.encode())
    patched_recommendation = _reseal(
        recommendation,
        "recommendation_content_sha256",
        schema="legalbot.v111.phase2a.held-missing-28-blocker-recommendation.r3.v1",
        supersedes_r2_recommendation_content_sha256=R2_RECOMMENDATION_SHA256,
        after_propositions=after,
        evidence_span_proposals=spans,
        r3_targeted_span_fingerprint=TARGET_FINGERPRINT,
    )
    recommendations = copy.deepcopy(row["blocker_recommendations"])
    recommendation_index = next(
        index
        for index, item in enumerate(recommendations)
        if item["component_ordinal"] == TARGET_COMPONENT_ORDINAL
    )
    recommendations[recommendation_index] = patched_recommendation
    patched_row = _reseal(
        row,
        "record_content_sha256",
        schema="legalbot.v111.phase2a.held-missing-28-row-substantive-remediation.r3.v1",
        supersedes_r2_row_record_content_sha256=row["record_content_sha256"],
        blocker_recommendations=recommendations,
    )
    row_index = next(index for index, item in enumerate(rows) if item["row_id"] == TARGET_ROW_ID)
    rows[row_index] = patched_row
    advisory = _reseal(
        advisory,
        "artifact_content_sha256",
        schema="legalbot.v111.phase2a.held-missing-28-substantive-remediation-advisory.r3.v1",
        status="CREATE_ONLY_R3_TARGETED_SPAN_REPAIR_WITH_HONEST_RESIDUALS_NOT_ADOPTED",
        supersedes_r2_advisory_content_sha256=R2_ADVISORY_CONTENT_SHA256,
        rows=rows,
        r2_audit_targeted_fingerprint=TARGET_FINGERPRINT,
    )

    source_manifest = copy.deepcopy(r2_manifest)
    component_binding = source_manifest["additional_q04_official_representation"][
        "component_binding"
    ]
    component_binding.update(
        {
            "after_proposition_text_sha256s": [after[0]["proposition_text_sha256"]],
            "exact_locators": spans[span_index]["exact_locators"],
            "recommendation_content_sha256": patched_recommendation[
                "recommendation_content_sha256"
            ],
            "span_proposal_content_sha256": spans[span_index]["span_proposal_content_sha256"],
        }
    )
    source_manifest = _reseal(
        source_manifest,
        "artifact_content_sha256",
        schema="legalbot.v111.phase2a.held-missing-nine-proposed-representation-bindings.r3.v1",
        status="CREATE_ONLY_R3_TARGETED_SPAN_REPAIR_NOT_ADMITTED_NOT_MATERIALIZED",
        supersedes_r2_manifest_content_sha256=R2_SOURCE_MANIFEST_CONTENT_SHA256,
        r2_audit_targeted_fingerprint=TARGET_FINGERPRINT,
    )

    audit = r1._seal(
        {
            "schema": "legalbot.v111.phase2a.held-missing-28-r2-targeted-audit-no-go.v1",
            "status": "R2_NO_GO_TARGETED_SPAN_DEFECT_R3_REPAIR_PROPOSED_NOT_ADOPTED",
            "fingerprint": TARGET_FINGERPRINT,
            "r2_advisory_content_sha256": R2_ADVISORY_CONTENT_SHA256,
            "r2_source_manifest_content_sha256": R2_SOURCE_MANIFEST_CONTENT_SHA256,
            "r2_package_content_sha256": R2_PACKAGE_CONTENT_SHA256,
            "r2_recommendation_content_sha256": R2_RECOMMENDATION_SHA256,
            "r2_span_proposal_content_sha256": R2_SPAN_SHA256,
            "r3_advisory_content_sha256": advisory["artifact_content_sha256"],
            "r3_source_manifest_content_sha256": source_manifest["artifact_content_sha256"],
            "exact_repair": {
                "added_locators": ["section 76(2)(a)", "section 76(6)"],
                "target_row_id": TARGET_ROW_ID,
                "target_component_ordinal": TARGET_COMPONENT_ORDINAL,
                "residual_blocker_count_unchanged": 24,
                "residual_row_count_unchanged": 22,
            },
            "owner_adoption_required": True,
            "owner_adopted": False,
            "recursive_no_execution_control": r1._recursive_no_execution_control(),
            **r1.NO_EXECUTION,
        }
    )
    for artifact in (advisory, source_manifest, audit):
        violations = r1._recursive_no_execution_violations(artifact)
        if violations:
            raise ValueError("recursive_no_execution_violation:" + ",".join(violations))
    if (
        advisory["counts"]["residual_blocker_count"] != 24
        or len(advisory["residual_row_ids"]) != 22
    ):
        raise ValueError("r3_residual_boundary_changed")
    return advisory, source_manifest, audit


def publish(output_root: Path = OUTPUT_ROOT) -> dict[str, str]:
    if output_root.exists():
        raise FileExistsError(f"create-only output already exists:{output_root}")
    advisory, source_manifest, audit = build_artifacts()
    output_root.parent.mkdir(parents=True, exist_ok=True)
    temp_root = Path(tempfile.mkdtemp(prefix=f".{output_root.name}-", dir=output_root.parent))
    try:
        artifacts = {
            ADVISORY_NAME: advisory,
            SOURCE_MANIFEST_NAME: source_manifest,
            AUDIT_NAME: audit,
        }
        for name, value in artifacts.items():
            (temp_root / name).write_bytes(r1._pretty_json(value))
            os.chmod(temp_root / name, 0o600)
        records = [
            {
                "name": name,
                "file_sha256": _file_sha256(temp_root / name),
                "content_sha256": value["artifact_content_sha256"],
                "bytes": (temp_root / name).stat().st_size,
            }
            for name, value in sorted(artifacts.items())
        ]
        package = r1._seal(
            {
                "schema": "legalbot.v111.phase2a.held-missing-28-substantive-remediation-package.r3.v1",
                "status": "CREATE_ONLY_NON_AUTHORIZING_NOT_EXECUTED",
                "supersedes_r2_package_content_sha256": R2_PACKAGE_CONTENT_SHA256,
                "artifact_count": len(records),
                "artifacts": records,
                "recursive_no_execution_control": r1._recursive_no_execution_control(),
                **r1.NO_EXECUTION,
            },
            "package_content_sha256",
        )
        (temp_root / PACKAGE_NAME).write_bytes(r1._pretty_json(package))
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
        "advisory": str(output_root / ADVISORY_NAME),
        "source_manifest": str(output_root / SOURCE_MANIFEST_NAME),
        "audit": str(output_root / AUDIT_NAME),
        "package": str(output_root / PACKAGE_NAME),
        "checksums": str(output_root / CHECKSUMS_NAME),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=OUTPUT_ROOT)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    advisory, source_manifest, audit = build_artifacts()
    if args.dry_run:
        print(
            json.dumps(
                {
                    "advisory_content_sha256": advisory["artifact_content_sha256"],
                    "source_manifest_content_sha256": source_manifest["artifact_content_sha256"],
                    "audit_content_sha256": audit["artifact_content_sha256"],
                },
                sort_keys=True,
            )
        )
        return 0
    print(json.dumps(publish(args.output_root), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
