#!/usr/bin/env python3
"""Record the owner's RETURN_FOR_REVISION disposition without mutating historical runs."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (
    ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-pack-return-for-revision-r1"
)
R3 = ROOT / (
    "data/evaluations/general-enquiries/LegalBot-GE-2026-09-01-improvement-training-unseen-r3"
)
R2_DOCX = ROOT / "output/docx/LegalBot-GE-331-Training-and-60-Unseen-Full-Review-r2.docx"
SOURCE_MANIFEST = (
    ROOT
    / "data/indexes/builds/current-law-ew-full-fp16-v111-20260829-recovery-b"
    / "approved-source-manifest.json"
)


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
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        if not data.endswith(b"\n"):
            handle.write(b"\n")
        handle.flush()
        os.fsync(handle.fileno())


def _write_json(path: Path, value: dict[str, Any]) -> None:
    _write_text(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"expected object: {path}")
    return value


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def main() -> int:
    if OUTPUT.exists() or OUTPUT.is_symlink():
        raise FileExistsError(f"create-only overlay already exists: {OUTPUT}")
    OUTPUT.mkdir(parents=True, mode=0o700)
    os.chmod(OUTPUT, stat.S_IRWXU)

    r3_manifest = _load_json(R3 / "RUN-MANIFEST.json")
    source_manifest = _load_json(SOURCE_MANIFEST)
    unseen_questions = _load_jsonl(R3 / "unseen/PRIVATE-QUESTIONS.jsonl")
    unseen_results = _load_jsonl(R3 / "unseen/RESULTS.jsonl")
    recorded_at = datetime.now(UTC).isoformat()

    historical = {
        "schema": "legalbot.ge-historical-artifact-bind.v1",
        "preserved": True,
        "mutated": False,
        "run_id": r3_manifest["run_id"],
        "run_content_sha256": r3_manifest["content_sha256"],
        "visible_results_sha256": _sha256_file(R3 / "visible/RESULTS.jsonl"),
        "unseen_questions_sha256": _sha256_file(R3 / "unseen/PRIVATE-QUESTIONS.jsonl"),
        "unseen_results_sha256": _sha256_file(R3 / "unseen/RESULTS.jsonl"),
        "training_candidates_sha256": _sha256_file(
            R3 / "training/RETRIEVAL-TRAINING-CANDIDATES.jsonl"
        ),
        "docx_path": "output/docx/LegalBot-GE-331-Training-and-60-Unseen-Full-Review-r2.docx",
        "docx_sha256": _sha256_file(R2_DOCX),
        "source_manifest_sha256": source_manifest["manifest_sha256"],
        "visible_pack_content_sha256": r3_manifest["visible_pack_manifest_sha256"],
    }

    owner_review = _sealed(
        {
            "schema": "legalbot.ge-owner-review-acknowledgement.v1",
            "authorizing": False,
            "recorded_at_utc": recorded_at,
            "owner_statement_date": "2026-09-02",
            "disposition": "RETURN_FOR_REVISION",
            "owner_statement": (
                "Return this pack for revision. Keep it as a diagnostic record, but do not "
                "approve its answers for weight training, claim 70+ performance, or use it to "
                "justify release. Proceed with the recommended repair plan."
            ),
            "statement_classification": "ACKNOWLEDGED_IN_THREAD_NOT_CRYPTOGRAPHICALLY_SIGNED",
            "interpreted_review_object": {
                "run_id": r3_manifest["run_id"],
                "docx": historical["docx_path"],
                "docx_sha256": historical["docx_sha256"],
                "run_content_sha256": r3_manifest["content_sha256"],
            },
            "accepted_scope": {
                "pack_as_diagnostic_record": True,
                "preserve_historical_artifacts": True,
                "classify_60_as_exposed_regression": True,
                "evaluator_retrieval_answer_and_non_weight_planner_repair": True,
                "official_source_and_currentness_packets": True,
            },
            "explicit_limits": {
                "answer_weight_training": False,
                "claim_70_plus_performance": False,
                "legal_gold_approved": False,
                "source_currentness_approved": False,
                "sealed_validation": False,
                "fresh_unseen": False,
                "private_306_disclosure": False,
                "promotion": False,
                "live": False,
                "deletion": False,
                "git_mutation": False,
            },
            "source_package_remains_immutable": True,
            "deletion_performed": False,
        }
    )
    _write_json(OUTPUT / "OWNER-REVIEW.json", owner_review)

    defect_cases = [
        {
            "ordinal": 8,
            "case_id": "administrative-law:cp-d08",
            "defect": "Equality Act 2010 s174 (PSV accessibility) selected for an inaccessible online form",
            "required_correction": "Relevance at issue/proposition level, not Act-level subject match",
        },
        {
            "ordinal": 174,
            "case_id": "international-commercial-mediation:cp-d01",
            "defect": "Arbitration Act 1996 s9 selected for an ICC mediation clause",
            "required_correction": "Reject mediation-to-arbitration substitution",
        },
        {
            "ordinal": 279,
            "case_id": "tort-law:cp-d09",
            "defect": "Punctuation-only Contributory Negligence s1 fragment marked claim-support PASS",
            "required_correction": "Punctuation-only passages cannot count as legal support",
        },
        {
            "ordinal": 312,
            "case_id": "wills-and-estates:cp-d02",
            "defect": "Collapsed Wills Act 1837 s9 quotation omitted writing/signature/witness conditions; 15 January 2024 temporal issue ignored",
            "required_correction": "Assemble complete operative passage and check the specified historical date",
        },
    ]
    defect_ledger = _sealed(
        {
            "schema": "legalbot.ge-return-for-revision-defect-ledger.v1",
            "historical_run_id": r3_manifest["run_id"],
            "historical_results_not_rewritten": True,
            "defective_pass_examples": defect_cases,
            "evaluator_defects": [
                "claim_evidence_support passed whenever any chunk was selected",
                "citation identity passed from chunk SHA without completeness or issue relevance",
                "jurisdiction_scope passed from UK/E&W origin while extent remained unverified",
                "no-evidence currentness used 'selected provision' wording",
                "safety passed from planner intent rather than rendered user-facing answer",
                "unseen rows inherited retrieval_planner_tuning=true",
            ],
        }
    )
    _write_json(OUTPUT / "DEFECT-LEDGER.json", defect_ledger)

    bases = []
    for row in unseen_questions:
        base = str(row.get("scenario_family_id") or "").split(":", 1)[0]
        if base and base not in bases:
            bases.append(base)
    exposed = _sealed(
        {
            "schema": "legalbot.ge-exposed-diagnostic-unseen.v1",
            "historical_run_id": r3_manifest["run_id"],
            "usage_role": "EXPOSED_DIAGNOSTIC_REGRESSION",
            "fresh_unseen": False,
            "sealed_validation": False,
            "question_record_count": len(unseen_questions),
            "result_count": len(unseen_results),
            "scenario_family_base_count": len(bases),
            "scenario_family_base_ids": bases,
            "private_questions_sha256": historical["unseen_questions_sha256"],
            "unseen_results_sha256": historical["unseen_results_sha256"],
            "official_306_private_bank_opened": False,
            "reuse_policy": (
                "These 60 records may be used as labelled regression tests. They cannot be "
                "described as fresh unseen or sealed Validation."
            ),
        }
    )
    _write_json(OUTPUT / "EXPOSED-DIAGNOSTIC-UNSEEN.json", exposed)

    topic_zero = sorted(
        topic
        for topic, bucket in r3_manifest["visible_summary"]["topics"].items()
        if bucket.get("evidence_present") == 0
    )
    currentness_counter = Counter()
    work_items = []
    for source in source_manifest["sources"]:
        reviewed = source.get("currentness_reviewed_as_of_date")
        status = source.get("currentness_status")
        eligible = source.get("full_current_law_verification_eligible") is True
        extent = source.get("provision_extent_status")
        currentness_counter[(reviewed, status, eligible, extent)] += 1
        work_items.append(
            {
                "source_version_id": source.get("source_version_id"),
                "title": source.get("title"),
                "currentness_reviewed_as_of_date": reviewed,
                "currentness_status": status,
                "full_current_law_verification_eligible": eligible,
                "provision_extent_status": extent,
                "owner_action_required": "currentness_extent_and_effects_review",
                "do_not": [
                    "advance the date field without review",
                    "set full_current_law_verification_eligible=true without review",
                ],
            }
        )
    currentness = _sealed(
        {
            "schema": "legalbot.ge-currentness-and-source-work-order.v1",
            "authorizing": False,
            "legal_cutoff_in_pack": "2026-08-28",
            "admitted_source_review_date": "2026-08-14",
            "gap_days_are_incomplete_assurance_not_proof_every_rule_changed": True,
            "source_count": len(source_manifest["sources"]),
            "currentness_tuples": [
                {
                    "count": count,
                    "currentness_reviewed_as_of_date": key[0],
                    "currentness_status": key[1],
                    "full_current_law_verification_eligible": key[2],
                    "provision_extent_status": key[3],
                }
                for key, count in currentness_counter.most_common()
            ],
            "visible_topics_with_zero_recorded_evidence": topic_zero,
            "zero_evidence_visible_case_count": sum(
                r3_manifest["visible_summary"]["topics"][topic]["total"] for topic in topic_zero
            ),
            "missing_primary_authorities_not_in_admitted_corpus": [
                "Data Protection Act 2018",
                "UK GDPR",
                "Data (Use and Access) Act 2025",
                "Competition Act 1998",
                "Enterprise Act 2002",
                "Mental Capacity Act 2005",
                "Human Fertilisation and Embryology Act 1990",
                "Pension Schemes Act 1993",
                "Pensions Act 1995",
                "Pensions Act 2004",
                "Pensions Act 2008",
                "European Union (Withdrawal) Act 2018",
                "Treaty on the Functioning of the European Union",
                "Singapore Convention on Mediation",
                "Mediation Act 2025",
            ],
            "gap_classes": [
                "authority_absent_from_admitted_corpus",
                "authority_present_but_not_retrieved",
                "wrong_passage_selected",
                "passage_incomplete",
                "jurisdiction_unresolved",
                "currentness_unresolved",
                "required_legal_review_missing",
            ],
            "historical_date_example": {
                "case_id": "wills-and-estates:cp-d02",
                "specified_date": "15 January 2024",
                "note": "Retrieving the newest stored text is not an adequate temporal check.",
            },
            "sources": work_items,
        }
    )
    _write_json(OUTPUT / "CURRENTNESS-AND-SOURCE-WORK-ORDER.json", currentness)

    packets = _sealed(
        {
            "schema": "legalbot.ge-official-source-candidate-packets.v1",
            "authorizing": False,
            "gold": False,
            "catalogue_ingest_performed": False,
            "fetched_at_utc": "2026-09-02T00:00:00+00:00",
            "note": (
                "Official pages are candidates for owner legal/currentness review. "
                "They are not gold until catalogue or accepted v2-repair hashes match "
                "and the owner or qualified legal reviewer decides."
            ),
            "defect_comparisons": [
                {
                    "case_id": "administrative-law:cp-d08",
                    "r3_selected": "Equality Act 2010 s174",
                    "official_url": "https://www.legislation.gov.uk/ukpga/2010/15/section/174",
                    "official_heading": "PSV accessibility regulations",
                    "official_excerpt": (
                        "The Secretary of State may make regulations (in this Chapter referred to as "
                        "“PSV accessibility regulations”) for securing that it is possible for disabled "
                        "persons to get on to and off regulated public service vehicles"
                    ),
                    "sld_revised_header": "2026-08-14 / Expert Participation 2026-07-15",
                    "candidate_issue_routes_not_gold": [
                        {
                            "url": "https://www.legislation.gov.uk/ukpga/2010/15/section/20",
                            "heading": "Duty to make adjustments",
                        },
                        {
                            "url": "https://www.legislation.gov.uk/ukpga/2010/15/section/29",
                            "heading": "Provision of services, etc.",
                        },
                    ],
                    "owner_decision_needed": "Whether s20/s29 or another admitted provision is the correct issue route for an inaccessible public-authority online form.",
                },
                {
                    "case_id": "international-commercial-mediation:cp-d01",
                    "r3_selected": "Arbitration Act 1996 s9",
                    "official_url": "https://www.legislation.gov.uk/ukpga/1996/23/section/9",
                    "official_heading": "Stay of legal proceedings",
                    "official_excerpt": (
                        "A party to an arbitration agreement against whom legal proceedings are brought "
                        "... may apply to the court ... to stay the proceedings"
                    ),
                    "sld_revised_header": "2025-08-05 / Expert Participation 2025-08-01",
                    "owner_decision_needed": "Whether to admit Singapore Convention / Mediation Act material or keep fail-closed missing-primary for mediation-only questions.",
                },
                {
                    "case_id": "tort-law:cp-d09",
                    "r3_selected": "Law Reform (Contributory Negligence) Act 1945 s1 punctuation-only fragment",
                    "official_url": "https://www.legislation.gov.uk/ukpga/Geo6/8-9/28/section/1",
                    "official_heading": "Apportionment of liability in case of contributory negligence",
                    "official_excerpt": (
                        "Where any person suffers damage as the result partly of his own fault and partly "
                        "of the fault of any other person or persons, a claim in respect of that damage "
                        "shall not be defeated by reason of the fault of the person suffering the damage"
                    ),
                    "note": "Official XML shows repealed subsections 1(3), 1(4) and 1(7) as dots. Those fragments must not be selected as the operative rule.",
                    "sld_revised_header": "2021-06-25 / Expert Participation 2021-04-21",
                },
                {
                    "case_id": "wills-and-estates:cp-d02",
                    "r3_selected": "Collapsed Wills Act 1837 s9 quotation",
                    "official_url": "https://www.legislation.gov.uk/ukpga/Will4and1Vict/7/26/section/9",
                    "official_heading": "Signing and attestation of wills",
                    "official_excerpt": (
                        "No will shall be valid unless—(a) it is in writing, and signed by the testator, "
                        "or by some other person in his presence and by his direction; and (b) it appears "
                        "that the testator intended by his signature to give effect to the will; and "
                        "(c) the signature is made or acknowledged by the testator in the presence of two "
                        "or more witnesses present at the same time; and (d) each witness either attests "
                        "and signs the will or acknowledges his signature ... but no form of attestation "
                        "shall be necessary. (2) For wills made on or after 31 January 2020 and on or "
                        "before 31 January 2024, “presence” includes presence by means of videoconference "
                        "or other visual transmission."
                    ),
                    "sld_revised_header": "2022-05-30 / Expert Participation 2022-04-06",
                    "temporal_note": "The question date is 15 January 2024, inside the video-presence window. Latest-text retrieval is not a temporal check.",
                },
            ],
            "missing_primary_official_urls_candidates_only": [
                {"title": "Data Protection Act 2018", "url": "https://www.legislation.gov.uk/ukpga/2018/12"},
                {"title": "UK GDPR", "url": "https://www.legislation.gov.uk/eur/2016/679"},
                {"title": "Competition Act 1998", "url": "https://www.legislation.gov.uk/ukpga/1998/41"},
                {"title": "Mental Capacity Act 2005", "url": "https://www.legislation.gov.uk/ukpga/2005/9"},
                {
                    "title": "Human Fertilisation and Embryology Act 1990",
                    "url": "https://www.legislation.gov.uk/ukpga/1990/37",
                },
                {"title": "Pension Schemes Act 1993", "url": "https://www.legislation.gov.uk/ukpga/1993/48"},
                {"title": "Pensions Act 1995", "url": "https://www.legislation.gov.uk/ukpga/1995/26"},
                {"title": "Pensions Act 2004", "url": "https://www.legislation.gov.uk/ukpga/2004/35"},
                {"title": "Pensions Act 2008", "url": "https://www.legislation.gov.uk/ukpga/2008/30"},
                {
                    "title": "European Union (Withdrawal) Act 2018",
                    "url": "https://www.legislation.gov.uk/ukpga/2018/16",
                },
            ],
        }
    )
    _write_json(OUTPUT / "OFFICIAL-SOURCE-CANDIDATE-PACKETS.json", packets)

    readme = """# GE pack returned for revision

The owner reviewed `LegalBot-GE-331-Training-and-60-Unseen-Full-Review-r2.docx` on
2 September 2026 and recorded **RETURN_FOR_REVISION**.

This overlay does not rewrite the r3 run or the r2 DOCX. Those artifacts remain
the diagnostic record.

## Bound identities

- Run: `LegalBot-GE-2026-09-01-improvement-training-unseen-r3`
- DOCX: `output/docx/LegalBot-GE-331-Training-and-60-Unseen-Full-Review-r2.docx`

## What this overlay records

- Pack-level disposition: return for revision; do not approve answers, 70+, weight
  training, or release.
- The 60 diagnostic cases are **exposed regression material**, not fresh unseen and
  not sealed Validation. The official 306 private bank remains unopened.
- Defective PASS examples: visible cases 008, 174, 279 and Wills Act s9 quotations.
- Official-source and currentness packets for owner review. Downloaded official
  text is a candidate only.

## What remains unauthorized

Answer-weight training, qualified legal gold, currentness approval, sealed
Validation, promotion, live activation, Git mutation and deletion.
"""
    _write_text(OUTPUT / "README.md", readme)

    bind = _sealed({"schema": "legalbot.ge-historical-artifact-bind.v1", **historical})
    _write_json(OUTPUT / "HISTORICAL-BIND.json", bind)

    artifacts = []
    for path in sorted(OUTPUT.iterdir()):
        if path.is_file() and path.name not in {"PACKAGE-MANIFEST.json", "SHA256SUMS.txt"}:
            artifacts.append(
                {
                    "path": path.name,
                    "bytes": path.stat().st_size,
                    "sha256": _sha256_file(path),
                }
            )
    sums = "\n".join(f"{item['sha256']}  {item['path']}" for item in artifacts) + "\n"
    _write_text(OUTPUT / "SHA256SUMS.txt", sums)
    sha256sums = _sha256_file(OUTPUT / "SHA256SUMS.txt")
    package = _sealed(
        {
            "schema": "legalbot.ge-owner-review-package.v1",
            "authorizing": False,
            "run_id": OUTPUT.name,
            "disposition": "RETURN_FOR_REVISION",
            "source_run_id": r3_manifest["run_id"],
            "source_run_content_sha256": r3_manifest["content_sha256"],
            "docx_sha256": historical["docx_sha256"],
            "owner_review_content_sha256": owner_review["content_sha256"],
            "visible_case_count": 331,
            "exposed_diagnostic_unseen_count": 60,
            "system_case_count_separate": 32,
            "legal_gold_approved": False,
            "evaluation_authorized": False,
            "training_authorized": False,
            "answer_weight_training_authorized": False,
            "unseen_authorized": False,
            "live_authorized": False,
            "deletion_performed": False,
            "artifacts": [
                *artifacts,
                {
                    "path": "SHA256SUMS.txt",
                    "sha256": sha256sums,
                    "bytes": (OUTPUT / "SHA256SUMS.txt").stat().st_size,
                },
            ],
        }
    )
    _write_json(OUTPUT / "PACKAGE-MANIFEST.json", package)
    print(json.dumps({"path": str(OUTPUT), "content_sha256": package["content_sha256"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
