#!/usr/bin/env python3
"""Create the owner-input ZIP for currentness/source decisions.

Does not mutate the RETURN_FOR_REVISION overlay. Does not open unseen,
train, promote, or mark qualified legal review.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import zipfile
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OVERLAY = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-pack-return-for-revision-r1"
)
PACK = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-owner-advisory-source-matrix-input-r1"
)
MANIFEST = (
    ROOT
    / "data/indexes/builds/current-law-ew-full-fp16-v111-20260829-recovery-b"
    / "approved-source-manifest.json"
)
PROVISION = ROOT / "config/provision_verification.v1.json"
CURRENT_PACK = ROOT / "config/current_legislation_pack.json"
VISIBLE = (
    ROOT
    / "data/evaluations/general-enquiries/LegalBot-GE-2026-09-01-review-r3"
    / "GE-VISIBLE-REVIEW.jsonl"
)
RESULTS = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-01-improvement-training-unseen-r3"
    / "visible/RESULTS.jsonl"
)
DESKTOP_ZIP = Path.home() / "Desktop" / (
    "LegalBot-GE-2026-09-02-pack-return-for-revision-r1-owner-input.zip"
)
WANTED_ORDINALS = {8, 174, 312}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _sealed(value: dict[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result["content_sha256"] = hashlib.sha256(_canonical_bytes(result)).hexdigest()
    return result


def _write_text(path: Path, text: str) -> None:
    data = text.encode("utf-8")
    if not data.endswith(b"\n"):
        data += b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _write_json(path: Path, value: Any) -> None:
    _write_text(path, json.dumps(value, ensure_ascii=False, indent=2))


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    data = b"".join(_canonical_bytes(row) for row in rows)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _copy_file(src: Path, dest: Path) -> None:
    data = src.read_bytes()
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _source_class(row: dict[str, Any]) -> str:
    if row.get("subsequent_treatment_check_required") is True:
        return "judgment"
    if str(row.get("currentness_status") or "") == "historical":
        return "judgment"
    return "legislation"


def _matrix_row(
    index: int,
    row: dict[str, Any],
    provision_by_hash: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    kind = _source_class(row)
    effects = row.get("unapplied_effect_count")
    proposed = (
        "HOLD_PROPOSITION_CURRENTNESS_LATER_TREATMENT_REVIEW"
        if kind == "judgment"
        else "CURRENT_TO_2026-08-14_ONLY_AND_HOLD_FOR_2026-08-28"
    )
    if kind == "legislation" and isinstance(effects, int) and effects > 0:
        proposed = "SEND_FOR_QUALIFIED_LEGAL_REVIEW_IF_EFFECTS_MATERIAL"
    content_hash = str(row.get("content_sha256") or "")
    provision_rows = provision_by_hash.get(content_hash, [])
    return {
        "ordinal": index,
        "source_version_id": row.get("source_version_id"),
        "document_id": row.get("document_id"),
        "title": row.get("title"),
        "source_class": kind,
        "source_type": row.get("lane"),
        "authority_identity_id": row.get("authority_identity_id"),
        "stable_identifier": row.get("stable_identifier"),
        "canonical_url": row.get("canonical_url"),
        "official_representation_id": row.get("official_representation_id"),
        "jurisdiction": row.get("jurisdiction"),
        "provision_extent_status": row.get("provision_extent_status"),
        "as_of_date": row.get("as_of_date"),
        "source_date": row.get("source_date"),
        "snapshot_or_version_date": row.get("as_of_date") or row.get("source_date"),
        "content_sha256": row.get("content_sha256"),
        "version_sha256": row.get("version_sha256"),
        "currentness_reviewed_as_of_date": row.get("currentness_reviewed_as_of_date"),
        "currentness_status": row.get("currentness_status"),
        "currentness_verified": row.get("currentness_verified"),
        "catalogue_currentness_status": row.get("catalogue_currentness_status"),
        "full_current_law_verification_eligible": row.get(
            "full_current_law_verification_eligible"
        ),
        "identity_verified": row.get("identity_verified"),
        "unapplied_effect_count": effects,
        "subsequent_treatment_check_required": row.get("subsequent_treatment_check_required"),
        "subsequent_treatment_verified": row.get("subsequent_treatment_verified"),
        "document_status": row.get("document_status"),
        "licence_name": row.get("licence_name"),
        "body_chunk_count": row.get("body_chunk_count"),
        "existing_reviewer_decision": {
            "currentness_reviewed_as_of_date": row.get("currentness_reviewed_as_of_date"),
            "currentness_status": row.get("currentness_status"),
            "currentness_verified": row.get("currentness_verified"),
            "full_current_law_verification_eligible": row.get(
                "full_current_law_verification_eligible"
            ),
            "provision_extent_status": row.get("provision_extent_status"),
            "subsequent_treatment_verified": row.get("subsequent_treatment_verified"),
            "qualified_legal_review": False,
            "named_human_reviewer": None,
        },
        "provision_verification_records": provision_rows,
        "commencement_amendment_repeal_applied_unapplied_effects": {
            "unapplied_effect_count": effects,
            "provision_records_present": bool(provision_rows),
            "note": (
                "The approved-source-manifest records source-level unapplied_effect_count. "
                "config/provision_verification.v1.json currently holds 14 inherited "
                "locator records as of 2026-08-14; it is not a complete effects register "
                "for all 65 legislation sources."
            ),
        },
        "proposed_batch_decision": proposed,
        "owner_decision": None,
        "owner_reason": None,
        "full_current_law_eligible_2026_08_28": False,
        "qualified_legal_review": False,
    }


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _case_extract(visible: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    return {
        "question_id": visible.get("question_id") or result.get("case_id"),
        "case_id": result.get("case_id"),
        "case_version_id": result.get("case_version_id"),
        "source_review_ordinal": visible.get("source_review_ordinal") or result.get("ordinal"),
        "ids_must_remain_unchanged": True,
        "visible_record": visible,
        "r3_result": result,
    }


def main() -> int:
    if PACK.exists() or PACK.is_symlink():
        raise FileExistsError(f"create-only pack exists: {PACK}")
    if DESKTOP_ZIP.exists() or DESKTOP_ZIP.is_symlink():
        raise FileExistsError(f"create-only zip exists: {DESKTOP_ZIP}")
    PACK.mkdir(parents=True, mode=0o700)
    os.chmod(PACK, stat.S_IRWXU)
    recorded_at = datetime.now(UTC).isoformat()

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    sources = list(manifest["sources"])
    if len(sources) != 85:
        raise RuntimeError("approved source manifest is not 85 rows")
    provision = json.loads(PROVISION.read_text(encoding="utf-8"))
    provision_by_hash: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in provision.get("records") or []:
        slim = {
            "legal_locator": record.get("legal_locator"),
            "official_source_url": record.get("official_source_url"),
            "stable_source_id": record.get("stable_source_id"),
            "verified_extent": record.get("verified_extent"),
            "section_unapplied_effect_count": record.get("section_unapplied_effect_count"),
            "unapplied_effect_materiality": record.get("unapplied_effect_materiality"),
            "qualification_provenance": record.get("qualification_provenance"),
            "official_version": record.get("official_version"),
            "source_content_sha256": record.get("source_content_sha256"),
            "source_version_sha256": record.get("source_version_sha256"),
        }
        provision_by_hash[str(record.get("source_content_sha256") or "")].append(slim)
    matrix = [
        _matrix_row(index, row, provision_by_hash)
        for index, row in enumerate(sources, start=1)
    ]
    kind_counts = Counter(row["source_class"] for row in matrix)
    effect_sum = sum(
        int(row["unapplied_effect_count"])
        for row in matrix
        if isinstance(row["unapplied_effect_count"], int)
    )

    visible_rows = {
        int(row["source_review_ordinal"]): row
        for row in _load_jsonl(VISIBLE)
        if int(row["source_review_ordinal"]) in WANTED_ORDINALS
    }
    result_rows = {
        int(row["ordinal"]): row
        for row in _load_jsonl(RESULTS)
        if int(row["ordinal"]) in WANTED_ORDINALS
    }
    cases = {
        f"case_{ordinal:03d}": _case_extract(visible_rows[ordinal], result_rows[ordinal])
        for ordinal in sorted(WANTED_ORDINALS)
    }

    overlay_dest = PACK / OVERLAY.name
    overlay_dest.mkdir(mode=0o700)
    for path in sorted(OVERLAY.iterdir()):
        if path.is_file():
            _copy_file(path, overlay_dest / path.name)

    _copy_file(MANIFEST, PACK / "approved-source-manifest.json")
    _copy_file(PROVISION, PACK / "provision_verification.v1.json")
    _copy_file(CURRENT_PACK, PACK / "current_legislation_pack.json")
    _copy_file(
        ROOT / "docs/system-design/schemas/knowledge-generation-manifest.v1.schema.json",
        PACK / "knowledge-generation-manifest.v1.schema.json",
    )
    _write_json(PACK / "85-SOURCE-MATRIX.json", _sealed({"schema": "legalbot.ge-85-source-currentness-matrix.v1", "source_count": 85, "kind_counts": dict(kind_counts), "unapplied_effect_sum": effect_sum, "reviewed_through": "2026-08-14", "hold_for": "2026-08-28", "full_current_law_eligible": False, "rows": matrix}))
    _write_jsonl(PACK / "85-SOURCE-MATRIX.jsonl", matrix)
    _write_json(
        PACK / "CASES-008-174-312.json",
        _sealed(
            {
                "schema": "legalbot.ge-owner-advisory-case-records.v1",
                "ids_must_remain_unchanged": True,
                "includes_unseen": False,
                "includes_training": False,
                "cases": cases,
                "writeback_stubs": {
                    "case_008": {
                        "case_id": cases["case_008"]["case_id"],
                        "source_review_ordinal": 8,
                        "route": "CONFIRMED",
                        "primary_route": "EqA_2010_s29_s20_Sch2",
                        "specific_route": "PSB_Accessibility_Regulations_2018",
                        "reject": "EqA_2010_s174",
                        "gold": False,
                    },
                    "case_174": {
                        "case_id": cases["case_174"]["case_id"],
                        "source_review_ordinal": 174,
                        "arbitration_act_s9": "REJECTED",
                        "singapore_convention": "NOT_CONTROLLING_THIS_ISSUE",
                        "authority_route": [
                            "exact_clause",
                            "incorporated_ICC_Mediation_Rules",
                            "Cable_and_Wireless",
                            "Ohpen",
                            "Kajima",
                            "CPR_stay_power",
                        ],
                        "status": "FAIL_CLOSED_PENDING_ADMISSION_AND_REVIEW",
                        "gold": False,
                    },
                    "case_312": {
                        "case_id": cases["case_312"]["case_id"],
                        "source_review_ordinal": 312,
                        "legal_date": "2024-01-15",
                        "temporal_method": "POINT_IN_TIME",
                        "video_will_window": "IN_SCOPE",
                        "latest_2026_text_only": "PROHIBITED",
                        "validity_conclusion": "HOLD_PENDING_FACTS_AND_EXACT_SPANS",
                        "gold": False,
                    },
                },
            }
        ),
    )

    decisions = _sealed(
        {
            "schema": "legalbot.ge-owner-advisory-research-decision.v1",
            "recorded_at_utc": recorded_at,
            "classification": "OWNER_ADVISORY_RESEARCH_DECISION",
            "qualified_legal_review": False,
            "qualified_england_and_wales_legal_reviewer": None,
            "ai_may_not_be_recorded_as_qualified_legal_reviewer": True,
            "grok_or_chatgpt_are_not_the_legal_reviewer": True,
            "legal_gold": False,
            "full_current_law_eligible": False,
            "runtime_admission": False,
            "answer_weight_training": False,
            "sealed_unseen": False,
            "promotion": False,
            "live": False,
            "decisions": {
                "CURRENTNESS_85": {
                    "decision": "HOLD_FOR_2026-08-28",
                    "reviewed_through": "2026-08-14",
                    "current_to_2026_08_28": "unconfirmed",
                    "full_current_law_eligible": False,
                    "legislation_rule": "CURRENT_TO_2026-08-14_ONLY and HOLD_FOR_2026-08-28 until point-in-time/effects review",
                    "judgment_rule": "identity may remain fixed; proposition currentness HOLD pending later-treatment review through 2026-08-28",
                    "note": "A later finding of no relevant statutory change does not automatically approve extracted chunks, propositions or answers.",
                },
                "MISSING_PRIMARY_AUTHORITIES": {
                    "decision": "ADMIT_VIA_OFFICIAL_STAGING_INTAKE",
                    "runtime": "FAIL_CLOSED_UNTIL_VALIDATED_AND_QUALIFIED",
                    "core_source_deferral": False,
                    "do_not_admit_unidentified_title": ["Mediation Act 2025"],
                    "do_not_set_on_download": ["admitted=true", "full_current_law_eligible=true"],
                    "bundles": {
                        "ai-and-data-protection": [
                            "Data Protection Act 2018",
                            "UK GDPR",
                            "Data (Use and Access) Act 2025",
                        ],
                        "competition-law": [
                            "Competition Act 1998",
                            "Enterprise Act 2002",
                            "Digital Markets, Competition and Consumers Act 2024",
                        ],
                        "mental_capacity_and_fertility": [
                            "Mental Capacity Act 2005",
                            "Human Fertilisation and Embryology Act 1990 including 2008 amendments",
                            "Medical Devices Regulations 2002 where the issue family requires them",
                            "Abortion Act 1967 where the issue family requires them",
                        ],
                        "pensions-law": [
                            "Pension Schemes Act 1993",
                            "Pensions Act 1995",
                            "Pensions Act 2004",
                            "Pensions Act 2008",
                            "Pension Schemes Act 2021",
                            "Pensions Dashboards Regulations 2022",
                            "Occupational and Personal Pension Schemes (Conditions for Transfers) Regulations 2021",
                        ],
                        "eu_and_withdrawal": [
                            "European Union (Withdrawal) Act 2018",
                            "TFEU",
                            "Withdrawal Agreement",
                            "relevant EU measures with jurisdiction limits",
                        ],
                    },
                },
                "CASE_008": {
                    "case_id": cases["case_008"]["case_id"],
                    "ordinal": 8,
                    "route": "CONFIRMED",
                    "primary_route": "EqA_2010_s29_s20_Sch2",
                    "specific_route": "PSB_Accessibility_Regulations_2018",
                    "reject": "EqA_2010_s174",
                    "gold": False,
                },
                "CASE_174": {
                    "case_id": cases["case_174"]["case_id"],
                    "ordinal": 174,
                    "arbitration_act_s9": "REJECTED",
                    "singapore_convention": "NOT_CONTROLLING_THIS_ISSUE",
                    "authority_route": [
                        "exact_clause",
                        "incorporated_ICC_Mediation_Rules",
                        "Cable_and_Wireless",
                        "Ohpen",
                        "Kajima",
                        "CPR_stay_power",
                    ],
                    "status": "FAIL_CLOSED_PENDING_ADMISSION_AND_REVIEW",
                    "gold": False,
                    "retain_s9_as_negative_retrieval_regression": True,
                },
                "CASE_312": {
                    "case_id": cases["case_312"]["case_id"],
                    "ordinal": 312,
                    "legal_date": "2024-01-15",
                    "temporal_method": "POINT_IN_TIME",
                    "video_will_window": "IN_SCOPE",
                    "latest_2026_text_only": "PROHIBITED",
                    "validity_conclusion": "HOLD_PENDING_FACTS_AND_EXACT_SPANS",
                    "gold": False,
                },
            },
        }
    )
    _write_json(PACK / "OWNER-ADVISORY-DECISIONS.json", decisions)

    policy = _sealed(
        {
            "schema": "legalbot.ge-source-intake-policy-excerpt.v1",
            "qualified_legal_review": False,
            "intake_bridge_schema": "legalbot.research-source-intake-bridge.v1",
            "create_only_intake_schema": "legalbot.research-source-create-only-ingestion.v1",
            "knowledge_generation_schema": "knowledge-generation-manifest.v1.schema.json",
            "permitted_sequence": [
                "official fetch",
                "immutable raw capture and hash",
                "point-in-time/version verification",
                "extent/commencement/effects review",
                "proposition mapping",
                "qualified/adopted decision",
                "runtime admission",
            ],
            "forbidden": [
                "download-to-active-index shortcut",
                "set admitted=true on fetch",
                "set full_current_law_eligible=true on fetch",
                "record Grok or ChatGPT as qualified England-and-Wales legal reviewer",
            ],
            "policy_documents": [
                "docs/system-design/EVALUATION_AND_TRAINING.md",
                "docs/system-design/ARCHITECTURE.md",
                "docs/system-design/FAILURE_MODES.md",
                "backend/app/research/source_intake_bridge.py",
                "backend/app/research/source_intake_create_only.py",
            ],
        }
    )
    _write_json(PACK / "SOURCE-INTAKE-POLICY.json", policy)

    readme = """# Owner currentness/source-matrix input pack

This ZIP is for source-by-source currentness and official-intake decisions.

It is **not** on GitHub `main`. The overlay lived only in the local recovery
workspace until this pack was created.

## Contents

1. `LegalBot-GE-2026-09-02-pack-return-for-revision-r1/` — exact RETURN_FOR_REVISION overlay.
2. `approved-source-manifest.json` — the exact 85-source recovery-b manifest.
3. `85-SOURCE-MATRIX.json` / `.jsonl` — one row per source, with IDs, titles,
   URLs, hashes, jurisdiction, extent, currentness, later-treatment and
   unapplied-effect counts. `owner_decision` is blank for you to complete.
4. `CASES-008-174-312.json` — visible-pack plus r3 result records. IDs must
   stay unchanged.
5. `provision_verification.v1.json` and `current_legislation_pack.json` —
   provision-level inherited snapshot records (14 locators, as_of 2026-08-14).
6. `SOURCE-INTAKE-POLICY.json` — staging-intake sequence and forbidden shortcuts.
7. `OWNER-ADVISORY-DECISIONS.json` — the five batch decisions as
   **owner-advisory research**, not qualified legal review and not gold.

Excluded: unseen questions, training examples, model weights, catalogue bytes,
vault objects and the 152 MiB FTS index.

## Status of the five decisions

They may be used as an owner-advisory research decision. They must not be
recorded as `qualified_legal_review=true` merely because an AI produced
supporting research. Runtime routes stay fail-closed until intake validation
and human/second-review qualification.
"""
    _write_text(PACK / "README.md", readme)

    artifacts = []
    for path in sorted(PACK.rglob("*")):
        if path.is_file():
            artifacts.append(
                {
                    "path": path.relative_to(PACK).as_posix(),
                    "bytes": path.stat().st_size,
                    "sha256": _sha256_file(path),
                }
            )
    _write_text(
        PACK / "SHA256SUMS.txt",
        "\n".join(f"{item['sha256']}  {item['path']}" for item in artifacts) + "\n",
    )
    package = _sealed(
        {
            "schema": "legalbot.ge-owner-advisory-source-matrix-input.v1",
            "authorizing": False,
            "qualified_legal_review": False,
            "legal_gold": False,
            "overlay_run_id": OVERLAY.name,
            "source_manifest_sha256": manifest["manifest_sha256"],
            "source_count": 85,
            "kind_counts": dict(kind_counts),
            "unapplied_effect_sum": effect_sum,
            "desktop_zip": str(DESKTOP_ZIP),
            "artifacts": artifacts
            + [
                {
                    "path": "SHA256SUMS.txt",
                    "bytes": (PACK / "SHA256SUMS.txt").stat().st_size,
                    "sha256": _sha256_file(PACK / "SHA256SUMS.txt"),
                }
            ],
        }
    )
    _write_json(PACK / "PACKAGE-MANIFEST.json", package)

    with zipfile.ZipFile(DESKTOP_ZIP, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(PACK.rglob("*")):
            if path.is_file():
                archive.write(path, arcname=f"{PACK.name}/{path.relative_to(PACK).as_posix()}")
    os.chmod(DESKTOP_ZIP, 0o600)
    print(
        json.dumps(
            {
                "pack": str(PACK),
                "zip": str(DESKTOP_ZIP),
                "zip_sha256": _sha256_file(DESKTOP_ZIP),
                "zip_bytes": DESKTOP_ZIP.stat().st_size,
                "source_count": 85,
                "cases": sorted(cases),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
