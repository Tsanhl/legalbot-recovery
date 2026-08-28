#!/usr/bin/env python3
"""Create immutable r2 research waves for deterministic authority repairs.

This is a representation-only repair.  It splits composite authority objects
and corrects three candidate-membership flags already proved by the bound
251-source manifest.  It cannot admit sources, mutate a candidate, embed,
promote, or apply an owner outcome.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from scripts import validate_v111_phase2a_official_research_waves as validator

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKING_ROOT = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review"
    / "LegalBot-Phase2A-2026-08-27-remediation-working-r1"
)
DEFAULT_MANIFEST = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review"
    / "LegalBot-Phase2A-2026-08-27-final-owner-review-blocked"
    / "machine/candidate/approved-source-manifest.json"
)
EXPECTED_MANIFEST_FILE_SHA256 = "0bbb1edb169c84a26e5f1d42e367f9e2f83fcdd9c652a9061980652f15979b21"
EXPECTED_MANIFEST_CONTENT_SHA256 = (
    "b304ab1223987bf9b57d3e2560413b2f325c16213ae0071a45dface2e10dc206"
)
EXPECTED_QUEUE_FILE_SHA256 = "7cdfaf81dab005dea418510884e741173f16ad378e64b026e3f52b7de9095391"
CANONICAL_BINDING_FILE_NAME = "CANONICAL-RESEARCH-WAVE-BINDINGS-32.json"
CANONICAL_BINDING_SCHEMA = "legalbot.v111.phase2a.canonical-research-wave-set.v1"

# (successor filename, embedded content seal, whole-file SHA-256)
BASE_BINDINGS: dict[str, tuple[str, str, str]] = {
    "research-live30-q24-q25.json": (
        "research-live30-q24-q25-r2.json",
        "9187c2d444c49ae074355da6b96d6f32da6e61136c24e51e086eb150af182906",
        "39258479f49a559bf4248f86607824c3e384124da597798bfc91224bca880696",
    ),
    "research-live30-q28.json": (
        "research-live30-q28-r2.json",
        "4c6a5d2b371b75727e8fdbcbeba9f36fc9fb47c48b663a8c663c1b000bef697a",
        "c3e25445a037f7891b1c1e0decd329b1fa87fac9b451b4b07cfbe851fc7e45ae",
    ),
    "research-live30-q30.json": (
        "research-live30-q30-r2.json",
        "d8b0294300da0f706d4c0ed00b57e82439f3555996cad69b366d039dcc0aad15",
        "cf1db2959afb8f79baf22543d60c684f31550f1b3e3e639c42dc10ebdce45417",
    ),
    "research-live60-q31-q35.json": (
        "research-live60-q31-q35-r2.json",
        "41ade46af9f2a4c7cf72a0792e8e80368b2a76e26fdaaa31ad9075bcda259826",
        "45ab27763dd09b51e9e96d963964911602156858d1b7508eba9f3b444d6e36c0",
    ),
    "research-live60-q37.json": (
        "research-live60-q37-r2.json",
        "28e028e83ea2cada8fa014b8db44013df6e835e5723d726f28d21d2a0282a7d9",
        "fd7fc897fd1177edc363cd7003c776c16885559830bf7585a2e26d68c57b356d",
    ),
    "research-live60-q40.json": (
        "research-live60-q40-r2.json",
        "9854dd1cdaf2f453719a82a4b5eab08516243d2dd1771617a4a4395e538eb177",
        "74a1f2750f9a688d6868fe4eab7ddc1e8fcb3bd3e25311f776b4701132d451bc",
    ),
    "research-live60-q41-q43.json": (
        "research-live60-q41-q43-r2.json",
        "349b07ede99dd1744667a8ce860fa62a248c9aa1c4cc8d4118979fa5aea88b74",
        "97992b1e8030a16e90bc37a1d0292cfd912dcc3c87c20ef60a62b1bfa2730aa7",
    ),
    "research-live60-q44.json": (
        "research-live60-q44-r2.json",
        "c358f858f546f8950523cd26209f875f13fd26c04776cab5cd32450291ec6c03",
        "dbaa9fb6392d490fb70f9ebf18e4bbb0175bb8c0bd6c1ec0594e943a205f7b5d",
    ),
    "research-live60-q52.json": (
        "research-live60-q52-r2.json",
        "e1b0cac7c885923cd0b0fdd0983d1369833533797ed31081e20bad2c7712822e",
        "8430d7cff301fc5731fef8ab11a66a9ecf136caed96e81615775720519cb5c7a",
    ),
}

CANONICAL_BASE_WAVES = (
    "research-live30-q01-q05.json",
    "research-live30-q06-q10.json",
    "research-live30-q11-q15.json",
    "research-live30-q16-q18.json",
    "research-live30-q19-q20.json",
    "research-live30-q21-q22.json",
    "research-live30-q24-q25.json",
    "research-live30-q26.json",
    "research-live30-q27.json",
    "research-live30-q28.json",
    "research-live30-q29.json",
    "research-live30-q30.json",
    "research-live60-q31-q35.json",
    "research-live60-q36.json",
    "research-live60-q37.json",
    "research-live60-q38.json",
    "research-live60-q39.json",
    "research-live60-q40.json",
    "research-live60-q41-q43.json",
    "research-live60-q44.json",
    "research-live60-q45.json",
    "research-live60-q46-q47.json",
    "research-live60-q48-q50-r3.json",
    "research-live60-q51.json",
    "research-live60-q52.json",
    "research-live60-q53.json",
    "research-live60-q54.json",
    "research-live60-q55.json",
    "research-live60-q56-q57.json",
    "research-live60-q58.json",
    "research-live60-q59.json",
    "research-live60-q60.json",
)

OBSOLETE_CANONICAL_WAVE_NAMES = frozenset(
    {
        *BASE_BINDINGS,
        "research-live60-q48-q50.json",
        "research-live60-q48-q50-r1.json",
        "research-live60-q48-q50-r2.json",
    }
)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _approved_manifest_digest(manifest: Mapping[str, Any]) -> str:
    identity = {
        key: value
        for key, value in manifest.items()
        if key not in {"created_at", "manifest_sha256"}
    }
    raw = (json.dumps(identity, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(
        "utf-8"
    )
    return _sha256(raw)


def _replacement(
    *,
    title: str,
    citation: str,
    official_url: str,
    exact_locators: Sequence[str],
    manifest_identity: str,
    candidate_existing: bool = False,
    candidate_source_version_ids: Sequence[str] = (),
    source_admission_required: bool = True,
    **overrides: str,
) -> dict[str, Any]:
    return {
        "title": title,
        "citation": citation,
        "official_url": official_url,
        "exact_locators": list(exact_locators),
        "manifest_identity": manifest_identity,
        "candidate_existing": candidate_existing,
        "candidate_source_version_ids": list(candidate_source_version_ids),
        "source_admission_required": source_admission_required,
        "overrides": overrides,
    }


def _split(
    row_id: str,
    component: int,
    authority: int,
    *,
    expected_citation: str,
    expected_url: str,
    expected_locators: Sequence[str],
    replacements: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "row_id": row_id,
        "component": component,
        "authority": authority,
        "expected": {
            "citation": expected_citation,
            "official_url": expected_url,
            "exact_locators": list(expected_locators),
        },
        "replacements": list(replacements),
    }


SPLIT_EDITS: dict[str, list[dict[str, Any]]] = {
    "research-live30-q28.json": [
        _split(
            "live30-q28:issue-05",
            4,
            1,
            expected_citation=(
                "Royal Bank of Scotland plc v Etridge (No 2) [2001] UKHL 44; "
                "Waller-Edwards v One Savings Bank Plc [2025] UKSC 22"
            ),
            expected_url="https://caselaw.nationalarchives.gov.uk/uksc/2025/22",
            expected_locators=[
                "Waller-Edwards paragraphs 1-6, 39-41 and 46-58; Etridge paragraphs 6-21"
            ],
            replacements=[
                _replacement(
                    title="Royal Bank of Scotland plc v Etridge (No 2)",
                    citation=("Royal Bank of Scotland plc v Etridge (No 2) [2001] UKHL 44"),
                    official_url=(
                        "https://publications.parliament.uk/pa/ld200102/"
                        "ldjudgmt/jd011011/etridg-1.htm"
                    ),
                    exact_locators=["paragraphs 6-21"],
                    manifest_identity="neutral-citation:[2001] UKHL 44",
                    jurisdiction=(
                        "House of Lords; binding for England and Wales on the "
                        "relevant equitable doctrine"
                    ),
                    currentness_finding=(
                        "The official judgment supplies the evidential-burden "
                        "formulation and rejects manifest disadvantage as a "
                        "misleading universal label."
                    ),
                    later_treatment_finding=(
                        "The Supreme Court in Waller-Edwards continues to treat "
                        "Etridge as authoritative; no proposition here treats the "
                        "2025 lender-notice refinement as replacing the underlying "
                        "inference test."
                    ),
                    verification_status=("VERIFIED_OFFICIAL_PARLIAMENTARY_ARCHIVE_AND_LOCATORS"),
                ),
                _replacement(
                    title="Waller-Edwards v One Savings Bank Plc",
                    citation=("Waller-Edwards v One Savings Bank Plc [2025] UKSC 22"),
                    official_url=("https://caselaw.nationalarchives.gov.uk/uksc/2025/22"),
                    exact_locators=["paragraphs 1-6, 39-41 and 46-58"],
                    manifest_identity="neutral-citation:[2025] UKSC 22",
                    candidate_existing=True,
                    candidate_source_version_ids=[
                        "source-version-adb3867a9d3850728daeb55a19c9cb4fc0c30e9b"
                    ],
                    source_admission_required=False,
                    jurisdiction="UK Supreme Court; appeal from England and Wales",
                    currentness_finding=(
                        "The 2025 Supreme Court judgment is present in the sealed "
                        "candidate but its manifest record has no as-of date or "
                        "canonical URL and retains currentness and later-treatment "
                        "holds."
                    ),
                    later_treatment_finding=(
                        "No later Supreme Court reversal was identified in the "
                        "bounded official-source search, but no comprehensive "
                        "commercial-citator review was performed."
                    ),
                    verification_status="VERIFIED_OFFICIAL_XML_AND_LOCATORS",
                ),
            ],
        ),
        _split(
            "live30-q28:issue-10",
            5,
            1,
            expected_citation=(
                "Insolvency Act 1986, s 335A; Trusts of Land and Appointment "
                "of Trustees Act 1996, s 15(4)"
            ),
            expected_url=("https://www.legislation.gov.uk/ukpga/1986/45/section/335A/2026-08-14"),
            expected_locators=[
                "Insolvency Act 1986 section 335A(1)-(4); TOLATA 1996 section 15(4)"
            ],
            replacements=[
                _replacement(
                    title="Insolvency Act 1986",
                    citation="Insolvency Act 1986, s 335A",
                    official_url=(
                        "https://www.legislation.gov.uk/ukpga/1986/45/section/335A/2026-08-14"
                    ),
                    exact_locators=["section 335A(1)-(4)"],
                    manifest_identity="ukpga:1986:45",
                    candidate_existing=True,
                    candidate_source_version_ids=[
                        "source-version-c5a87b369f1425926f022fcd9d684ab2d4525839"
                    ],
                    source_admission_required=False,
                    currentness_finding=(
                        "The point-in-time candidate source is marked currentness "
                        "verified, but the Insolvency Act source retains unverified "
                        "extent and 21 unapplied effects that require reconciliation."
                    ),
                ),
                _replacement(
                    title="Trusts of Land and Appointment of Trustees Act 1996",
                    citation=("Trusts of Land and Appointment of Trustees Act 1996, s 15(4)"),
                    official_url=("https://www.legislation.gov.uk/ukpga/1996/47/2026-08-14"),
                    exact_locators=["section 15(4)"],
                    manifest_identity="ukpga:1996:47",
                    candidate_existing=True,
                    candidate_source_version_ids=[
                        "source-version-e4b9da65ccd473b2a7f0996ede07d4085fa1d34f"
                    ],
                    source_admission_required=False,
                    currentness_finding=(
                        "The 2026-08-14 candidate representation is marked "
                        "currentness verified with no unapplied effects; provision "
                        "extent remains unverified."
                    ),
                ),
            ],
        ),
    ],
    "research-live60-q31-q35.json": [
        _split(
            "live60-q32:issue-11",
            2,
            1,
            expected_citation=(
                "Civil Procedure Rules 1998, rr 3.4 and 44.2; Civil Procedure "
                "(Amendment) Rules 2025, SI 2025/106"
            ),
            expected_url="https://www.legislation.gov.uk/uksi/2025/106/made",
            expected_locators=["SI 2025/106 rules 3 and 9; CPR 3.4(2)(a)-(d) and 44.2(9)-(10)"],
            replacements=[
                _replacement(
                    title="Civil Procedure Rules 1998",
                    citation="Civil Procedure Rules 1998, rr 3.4 and 44.2",
                    official_url=("https://www.legislation.gov.uk/uksi/1998/3132"),
                    exact_locators=["r 3.4(2)(a)-(d)", "r 44.2(9)-(10)"],
                    manifest_identity="uksi:1998:3132",
                    candidate_existing=True,
                    candidate_source_version_ids=[
                        "source-version-0dd74a37a139ea09afedbb95ac8e4b180b7cb95f"
                    ],
                    source_admission_required=False,
                    currentness_finding=(
                        "The candidate CPR source is currentness verified as of "
                        "2026-08-14 but has unverified extent and 175 unapplied "
                        "effects."
                    ),
                ),
                _replacement(
                    title="Civil Procedure (Amendment) Rules 2025",
                    citation=("Civil Procedure (Amendment) Rules 2025, SI 2025/106"),
                    official_url=("https://www.legislation.gov.uk/uksi/2025/106/made"),
                    exact_locators=["rules 3 and 9"],
                    manifest_identity="uksi:2025:106:made",
                    currentness_finding=(
                        "The specific 2025 amending instrument is not separately "
                        "confirmed in the candidate manifest."
                    ),
                ),
            ],
        ),
        _split(
            "live60-q34:issue-03",
            1,
            1,
            expected_citation=(
                "R v Jogee; Ruddock v The Queen [2016] UKSC 8; Odunewu and "
                "others v R [2026] EWCA Crim 444"
            ),
            expected_url=("https://caselaw.nationalarchives.gov.uk/ewca/crim/2026/444"),
            expected_locators=["Jogee paragraphs 90 and 92-95; Odunewu paragraphs 54-55"],
            replacements=[],
        ),
        _split(
            "live60-q34:issue-08",
            1,
            1,
            expected_citation=(
                "R v Jogee; Ruddock v The Queen [2016] UKSC 8; Odunewu and "
                "others v R [2026] EWCA Crim 444"
            ),
            expected_url=("https://caselaw.nationalarchives.gov.uk/ewca/crim/2026/444"),
            expected_locators=["Jogee paragraphs 11 and 77-78; Odunewu paragraphs 54-55"],
            replacements=[],
        ),
        _split(
            "live60-q34:issue-05",
            1,
            1,
            expected_citation=(
                "R v Jogee; Ruddock v The Queen [2016] UKSC 8; Tas v R [2018] EWCA Crim 2603"
            ),
            expected_url=("https://caselaw.nationalarchives.gov.uk/ewca/crim/2018/2603"),
            expected_locators=["Jogee paragraphs 95-98; Tas paragraphs 31-45"],
            replacements=[],
        ),
        _split(
            "live60-q34:issue-06",
            1,
            1,
            expected_citation=(
                "R v Jogee; Ruddock v The Queen [2016] UKSC 8; Tas v R [2018] EWCA Crim 2603"
            ),
            expected_url=("https://caselaw.nationalarchives.gov.uk/ewca/crim/2018/2603"),
            expected_locators=["Jogee paragraphs 12-13; Tas paragraphs 31-32, 41 and 44"],
            replacements=[],
        ),
        _split(
            "live60-q34:issue-07",
            1,
            1,
            expected_citation=(
                "R v Jogee; Ruddock v The Queen [2016] UKSC 8; Tas v R [2018] EWCA Crim 2603"
            ),
            expected_url=("https://caselaw.nationalarchives.gov.uk/ewca/crim/2018/2603"),
            expected_locators=["Jogee paragraphs 12-13; Tas paragraphs 31-32 and 40-44"],
            replacements=[],
        ),
        _split(
            "live60-q35:issue-05",
            2,
            1,
            expected_citation=(
                "Renters' Rights Act 2025, ss 2 and 146, Schedules 2 and 6; "
                "Renters' Rights Act 2025 (Commencement No 2 and Transitional "
                "and Saving Provisions) Regulations 2026, SI 2026/421"
            ),
            expected_url="https://www.legislation.gov.uk/uksi/2026/421/made",
            expected_locators=[
                "SI 2026/421 regulations 1-2; 2025 Act section 2, section 146(3), "
                "Schedule 2 paragraph 73 and Schedule 6 paragraphs 3-4"
            ],
            replacements=[
                _replacement(
                    title="Renters' Rights Act 2025",
                    citation=("Renters' Rights Act 2025, ss 2 and 146, Schedules 2 and 6"),
                    official_url=("https://www.legislation.gov.uk/ukpga/2025/26/2026-08-14"),
                    exact_locators=[
                        "section 2",
                        "section 146(3)",
                        "Schedule 2 paragraph 73",
                        "Schedule 6 paragraphs 3-4",
                    ],
                    manifest_identity="ukpga:2025:26",
                ),
                _replacement(
                    title=(
                        "Renters' Rights Act 2025 (Commencement No 2 and "
                        "Transitional and Saving Provisions) Regulations 2026"
                    ),
                    citation=(
                        "Renters' Rights Act 2025 (Commencement No 2 and "
                        "Transitional and Saving Provisions) Regulations 2026, "
                        "SI 2026/421"
                    ),
                    official_url=("https://www.legislation.gov.uk/uksi/2026/421/made"),
                    exact_locators=["regulations 1-2"],
                    manifest_identity="uksi:2026:421:made",
                ),
            ],
        ),
        _split(
            "live60-q35:issue-06",
            2,
            1,
            expected_citation=(
                "Housing Act 1988, ss 7-8 and Schedule 2; Landlord and Tenant "
                "Act 1985, ss 9A, 11 and 17"
            ),
            expected_url=("https://www.legislation.gov.uk/ukpga/1988/50/2026-08-14"),
            expected_locators=[
                "Housing Act 1988 sections 7-8 and Schedule 2; Landlord and "
                "Tenant Act 1985 sections 9A, 11 and 17"
            ],
            replacements=[
                _replacement(
                    title="Housing Act 1988",
                    citation="Housing Act 1988, ss 7-8 and Schedule 2",
                    official_url=("https://www.legislation.gov.uk/ukpga/1988/50/2026-08-14"),
                    exact_locators=["sections 7-8", "Schedule 2"],
                    manifest_identity="ukpga:1988:50",
                ),
                _replacement(
                    title="Landlord and Tenant Act 1985",
                    citation="Landlord and Tenant Act 1985, ss 9A, 11 and 17",
                    official_url=("https://www.legislation.gov.uk/ukpga/1985/70/2026-08-14"),
                    exact_locators=["sections 9A, 11 and 17"],
                    manifest_identity="ukpga:1985:70",
                ),
            ],
        ),
    ],
    "research-live60-q37.json": [
        _split(
            "live60-q37:issue-05",
            1,
            1,
            expected_citation=(
                "Limited Liability Partnerships Act 2000, s 5; Limited "
                "Liability Partnerships Regulations 2001, reg 7 and sch 2"
            ),
            expected_url="https://www.legislation.gov.uk/uksi/2001/1090",
            expected_locators=[
                "LLP Act 2000 s 5(1)-(2)",
                "SI 2001/1090 reg 7",
                "SI 2001/1090 sch 2 paras 1-8",
            ],
            replacements=[
                _replacement(
                    title="Limited Liability Partnerships Act 2000",
                    citation="Limited Liability Partnerships Act 2000, s 5",
                    official_url="https://www.legislation.gov.uk/ukpga/2000/12",
                    exact_locators=["s 5(1)-(2)"],
                    manifest_identity="ukpga:2000:12",
                ),
                _replacement(
                    title="Limited Liability Partnerships Regulations 2001",
                    citation=("Limited Liability Partnerships Regulations 2001, reg 7 and sch 2"),
                    official_url="https://www.legislation.gov.uk/uksi/2001/1090",
                    exact_locators=["regulation 7", "Schedule 2 paragraphs 1-8"],
                    manifest_identity="uksi:2001:1090",
                ),
            ],
        )
    ],
    "research-live60-q40.json": [
        _split(
            "live60-q40:issue-03",
            1,
            2,
            expected_citation=(
                "Localism Act 2011, ss 29-34; Relevant Authorities "
                "(Disclosable Pecuniary Interests) Regulations 2012, SI 2012/1464"
            ),
            expected_url=("https://www.legislation.gov.uk/ukpga/2011/20/part/1/chapter/7"),
            expected_locators=[
                "Localism Act 2011 ss 29-34",
                "SI 2012/1464 regs 2-3 and Schedule",
            ],
            replacements=[
                _replacement(
                    title="Localism Act 2011",
                    citation="Localism Act 2011, ss 29-34",
                    official_url=("https://www.legislation.gov.uk/ukpga/2011/20/part/1/chapter/7"),
                    exact_locators=["ss 29-34"],
                    manifest_identity="ukpga:2011:20",
                ),
                _replacement(
                    title=(
                        "Relevant Authorities (Disclosable Pecuniary Interests) Regulations 2012"
                    ),
                    citation=(
                        "Relevant Authorities (Disclosable Pecuniary Interests) "
                        "Regulations 2012, SI 2012/1464"
                    ),
                    official_url=("https://www.legislation.gov.uk/uksi/2012/1464/2026-08-14"),
                    exact_locators=["regs 2-3 and Schedule"],
                    manifest_identity="uksi:2012:1464",
                ),
            ],
        )
    ],
    "research-live60-q41-q43.json": [
        _split(
            "live60-q41:issue-06",
            1,
            1,
            expected_citation=(
                "Nationality and Borders Act 2022, s 60; Modern Slavery Act 2015, ss 49-51"
            ),
            expected_url=("https://www.legislation.gov.uk/ukpga/2022/36/section/60/2026-08-14"),
            expected_locators=[
                "s 60(1)-(7)",
                "Modern Slavery Act 2015 s 49(1)-(1A)",
                "Modern Slavery Act 2015 s 50(1)-(4)",
            ],
            replacements=[
                _replacement(
                    title="Nationality and Borders Act 2022",
                    citation="Nationality and Borders Act 2022, s 60",
                    official_url=(
                        "https://www.legislation.gov.uk/ukpga/2022/36/section/60/2026-08-14"
                    ),
                    exact_locators=["s 60(1)-(7)"],
                    manifest_identity="ukpga:2022:36",
                ),
                _replacement(
                    title="Modern Slavery Act 2015",
                    citation="Modern Slavery Act 2015, ss 49-50",
                    official_url=("https://www.legislation.gov.uk/ukpga/2015/30/2026-08-14"),
                    exact_locators=["s 49(1)-(1A)", "s 50(1)-(4)"],
                    manifest_identity="ukpga:2015:30",
                ),
            ],
        )
    ],
    "research-live60-q44.json": [
        _split(
            "live60-q44:issue-04",
            3,
            1,
            expected_citation=("FCA Handbook, COBS 2.2A.2R-2.2A.3R and 14.3A.7R-14.3A.9R"),
            expected_url=(
                "https://handbook.fca.org.uk/handbook/cobs2/cobs2s2?date=2026-08-14&timeline=true"
            ),
            expected_locators=["COBS 2.2A.1R-2.2A.3R; COBS 14.3A.7R and 14.3A.9R"],
            replacements=[
                _replacement(
                    title="FCA Handbook COBS 2.2A",
                    citation="FCA Handbook, COBS 2.2A.1R-2.2A.3R",
                    official_url=(
                        "https://handbook.fca.org.uk/handbook/cobs2/cobs2s2?"
                        "date=2026-08-14&timeline=true"
                    ),
                    exact_locators=["COBS 2.2A.1R-2.2A.3R"],
                    manifest_identity="fca:cobs:2.2A",
                ),
                _replacement(
                    title="FCA Handbook COBS 14.3A",
                    citation="FCA Handbook, COBS 14.3A.7R-14.3A.9R",
                    official_url=(
                        "https://handbook.fca.org.uk/handbook/cobs14/"
                        "cobs14s3a?date=2026-08-14&timeline=true"
                    ),
                    exact_locators=["COBS 14.3A.7R", "COBS 14.3A.9R"],
                    manifest_identity="fca:cobs:14.3A",
                ),
            ],
        )
    ],
}


def _jogee_replacement(locators: Sequence[str]) -> dict[str, Any]:
    return _replacement(
        title="R v Jogee; Ruddock v The Queen",
        citation="R v Jogee; Ruddock v The Queen [2016] UKSC 8",
        official_url=("https://supremecourt.uk/uploads/uksc_2015_0015_judgment_e9dab4a097.pdf"),
        exact_locators=locators,
        manifest_identity="neutral-citation:[2016] UKSC 8",
        jurisdiction="UK Supreme Court",
        verification_status="VERIFIED_OFFICIAL_SUPREME_COURT_LOCATORS",
    )


def _later_case_replacement(
    *, title: str, citation: str, url: str, locators: Sequence[str]
) -> dict[str, Any]:
    return _replacement(
        title=title,
        citation=citation,
        official_url=url,
        exact_locators=locators,
        manifest_identity=f"neutral-citation:{citation.rsplit('[', 1)[-1].join(['[', ''])}",
        jurisdiction="Court of Appeal of England and Wales, Criminal Division",
        verification_status="VERIFIED_OFFICIAL_COURT_OF_APPEAL_LOCATORS",
    )


def _install_criminal_splits() -> None:
    edits = SPLIT_EDITS["research-live60-q31-q35.json"]
    plans = (
        (1, ["paragraphs 90 and 92-95"], "Odunewu", ["paragraphs 54-55"]),
        (2, ["paragraphs 11 and 77-78"], "Odunewu", ["paragraphs 54-55"]),
        (3, ["paragraphs 95-98"], "Tas", ["paragraphs 31-45"]),
        (
            4,
            ["paragraphs 12-13"],
            "Tas",
            ["paragraphs 31-32, 41 and 44"],
        ),
        (
            5,
            ["paragraphs 12-13"],
            "Tas",
            ["paragraphs 31-32 and 40-44"],
        ),
    )
    later = {
        "Odunewu": (
            "Odunewu and others v R",
            "Odunewu and others v R [2026] EWCA Crim 444",
            "https://caselaw.nationalarchives.gov.uk/ewca/crim/2026/444",
        ),
        "Tas": (
            "Tas v R",
            "Tas v R [2018] EWCA Crim 2603",
            "https://caselaw.nationalarchives.gov.uk/ewca/crim/2018/2603",
        ),
    }
    for edit_index, jogee_locators, case_key, later_locators in plans:
        title, citation, url = later[case_key]
        edits[edit_index]["replacements"] = [
            _jogee_replacement(jogee_locators),
            _later_case_replacement(
                title=title,
                citation=citation,
                url=url,
                locators=later_locators,
            ),
        ]


_install_criminal_splits()

MEMBERSHIP_EDITS: dict[str, list[dict[str, str]]] = {
    "research-live30-q24-q25.json": [
        {
            "row_id": "live30-q24:issue-01",
            "citation": "Supply of Goods and Services Act 1982, s 13",
            "manifest_identity": "ukpga:1982:29",
            "source_version_id": ("source-version-16a9bcb428d17e0126ba147b0903bece7823d595"),
            "expected_currentness_finding": (
                "The official point-in-time page was selected to the 2026-08-14 "
                "ceiling; the Act is not in the candidate."
            ),
            "currentness_finding": (
                "The official point-in-time page was selected to the 2026-08-14 "
                "ceiling; the candidate manifest contains the Act's bound source "
                "version."
            ),
            "expected_hold": (
                "The SRA and 1982 Act sources are outside the candidate and require "
                "owner admission and frozen EvidenceSpans before use."
            ),
            "replacement_hold": (
                "The SRA sources remain outside the candidate and require owner "
                "admission and frozen EvidenceSpans before use; the 1982 Act source "
                "is candidate-bound but still requires frozen EvidenceSpans before "
                "use."
            ),
        }
    ],
    "research-live30-q30.json": [
        {
            "row_id": "live30-q30:issue-16",
            "citation": "Trade Secrets (Enforcement, etc.) Regulations 2018",
            "manifest_identity": "uksi:2018:597:made",
            "source_version_id": ("source-version-f1d2fba5d67d7ecbb060841435513960b9bb861c"),
            "expected_currentness_finding": (
                "The point-in-time preservation, confidentiality and remedy "
                "provisions were inspected; the source is outside the candidate."
            ),
            "currentness_finding": (
                "The point-in-time preservation, confidentiality and remedy "
                "provisions were inspected; the candidate manifest contains the "
                "instrument's bound source version."
            ),
            "expected_hold": (
                "The Database Regulations and Trade Secrets Regulations are "
                "outside the candidate and require owner admission and frozen "
                "EvidenceSpans."
            ),
            "replacement_hold": (
                "The Database Regulations remain outside the candidate and require "
                "owner admission and frozen EvidenceSpans; the Trade Secrets "
                "Regulations are candidate-bound but still require frozen "
                "EvidenceSpans."
            ),
        }
    ],
    "research-live60-q52.json": [
        {
            "row_id": "live60-q52:issue-01",
            "citation": "Arnold v Britton [2015] UKSC 36",
            "manifest_identity": "neutral-citation:[2015] UKSC 36",
            "source_version_id": ("source-version-77233fd6c2c5ba582c1599a1e9df520c01b134ac"),
            "expected_currentness_finding": (
                "Official judgment and contractual-interpretation passages were "
                "verified on 2026-08-27; the judgment is outside the sealed "
                "candidate."
            ),
            "currentness_finding": (
                "Official judgment and contractual-interpretation passages were "
                "verified on 2026-08-27; the candidate manifest contains the "
                "judgment's bound source version."
            ),
            "expected_hold": (
                "Both judgments require source admission and later-treatment review."
            ),
            "replacement_hold": (
                "Waaler remains outside the candidate and requires source admission; "
                "Arnold is candidate-bound. Both judgments retain later-treatment "
                "and frozen EvidenceSpan requirements."
            ),
        }
    ],
}


def _load_manifest(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_wave_authority_repair_manifest_invalid")
    raw = path.read_bytes()
    if _sha256(raw) != EXPECTED_MANIFEST_FILE_SHA256:
        raise ValueError("phase2a_wave_authority_repair_manifest_file_digest_mismatch")
    value = json.loads(raw)
    if (
        not isinstance(value, dict)
        or value.get("source_count") != 251
        or len(value.get("sources", [])) != 251
        or value.get("manifest_sha256") != EXPECTED_MANIFEST_CONTENT_SHA256
        or _approved_manifest_digest(value) != EXPECTED_MANIFEST_CONTENT_SHA256
    ):
        raise ValueError("phase2a_wave_authority_repair_manifest_content_mismatch")
    return value


def _load_bound_wave(path: Path, *, content_sha: str, file_sha: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_wave_authority_repair_base_invalid")
    raw = path.read_bytes()
    if _sha256(raw) != file_sha:
        raise ValueError("phase2a_wave_authority_repair_base_file_digest_mismatch")
    value = json.loads(raw)
    if not isinstance(value, dict) or value.get("artifact_content_sha256") != content_sha:
        raise ValueError("phase2a_wave_authority_repair_base_content_digest_mismatch")
    material = dict(value)
    material.pop("artifact_content_sha256", None)
    if _sealed(material) != content_sha:
        raise ValueError("phase2a_wave_authority_repair_base_seal_invalid")
    return value


def _manifest_maps(
    manifest: Mapping[str, Any],
) -> tuple[dict[str, Mapping[str, Any]], set[str]]:
    sources = manifest.get("sources")
    if not isinstance(sources, list):
        raise ValueError("phase2a_wave_authority_repair_manifest_sources_invalid")
    by_version: dict[str, Mapping[str, Any]] = {}
    identities: set[str] = set()
    for source in sources:
        if not isinstance(source, Mapping):
            raise ValueError("phase2a_wave_authority_repair_manifest_source_invalid")
        source_version_id = str(source.get("source_version_id") or "")
        identity = str(source.get("authority_identity_id") or "")
        if not source_version_id or source_version_id in by_version or not identity:
            raise ValueError("phase2a_wave_authority_repair_manifest_source_invalid")
        by_version[source_version_id] = source
        identities.add(identity.casefold())
    return by_version, identities


def _assert_manifest_membership(
    spec: Mapping[str, Any],
    *,
    by_version: Mapping[str, Mapping[str, Any]],
    identities: set[str],
) -> None:
    identity = str(spec["manifest_identity"])
    expected_existing = bool(spec["candidate_existing"])
    version_ids = list(spec["candidate_source_version_ids"])
    admission = bool(spec["source_admission_required"])
    if expected_existing:
        if admission or len(version_ids) != 1:
            raise ValueError("phase2a_wave_authority_repair_existing_spec_invalid")
        source = by_version.get(str(version_ids[0]))
        if source is None or str(source.get("authority_identity_id")) != identity:
            raise ValueError("phase2a_wave_authority_repair_existing_manifest_mismatch")
    elif version_ids or not admission or identity.casefold() in identities:
        raise ValueError("phase2a_wave_authority_repair_new_manifest_conflict")


def _row(wave: Mapping[str, Any], row_id: str) -> dict[str, Any]:
    records = wave.get("records")
    matches = (
        [
            record
            for record in records
            if isinstance(record, dict) and record.get("row_id") == row_id
        ]
        if isinstance(records, list)
        else []
    )
    if len(matches) != 1:
        raise ValueError("phase2a_wave_authority_repair_row_identity_mismatch")
    return matches[0]


def _authority_at(
    wave: Mapping[str, Any], *, row_id: str, component: int, authority: int
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    row = _row(wave, row_id)
    components = row.get("atomic_components")
    if not isinstance(components, list) or not 0 < component <= len(components):
        raise ValueError("phase2a_wave_authority_repair_component_mismatch")
    component_value = components[component - 1]
    authorities = (
        component_value.get("authorities") if isinstance(component_value, Mapping) else None
    )
    if not isinstance(authorities, list) or not 0 < authority <= len(authorities):
        raise ValueError("phase2a_wave_authority_repair_authority_mismatch")
    selected = authorities[authority - 1]
    if not isinstance(selected, dict):
        raise ValueError("phase2a_wave_authority_repair_authority_mismatch")
    return authorities, selected


def _apply_split(
    wave: dict[str, Any],
    edit: Mapping[str, Any],
    *,
    by_version: Mapping[str, Mapping[str, Any]],
    identities: set[str],
) -> None:
    authorities, base = _authority_at(
        wave,
        row_id=str(edit["row_id"]),
        component=int(edit["component"]),
        authority=int(edit["authority"]),
    )
    expected = edit["expected"]
    if not isinstance(expected, Mapping) or any(
        base.get(key) != expected.get(key) for key in ("citation", "official_url", "exact_locators")
    ):
        raise ValueError("phase2a_wave_authority_repair_composite_fingerprint_mismatch")
    replacement_values: list[dict[str, Any]] = []
    for raw_spec in edit["replacements"]:
        if not isinstance(raw_spec, Mapping):
            raise ValueError("phase2a_wave_authority_repair_replacement_invalid")
        _assert_manifest_membership(raw_spec, by_version=by_version, identities=identities)
        authority_value = copy.deepcopy(base)
        authority_value.update(
            {
                "title": raw_spec["title"],
                "citation": raw_spec["citation"],
                "official_url": raw_spec["official_url"],
                "exact_locators": list(raw_spec["exact_locators"]),
                "candidate_existing": raw_spec["candidate_existing"],
                "candidate_source_version_ids": list(raw_spec["candidate_source_version_ids"]),
                "source_admission_required": raw_spec["source_admission_required"],
            }
        )
        authority_value.update(raw_spec["overrides"])
        validator._validate_authority(authority_value)
        replacement_values.append(authority_value)
    index = int(edit["authority"]) - 1
    authorities[index : index + 1] = replacement_values


def _apply_membership_edit(
    wave: dict[str, Any],
    edit: Mapping[str, str],
    *,
    by_version: Mapping[str, Mapping[str, Any]],
) -> None:
    row = _row(wave, edit["row_id"])
    matches: list[dict[str, Any]] = []
    for component in row["atomic_components"]:
        for authority in component["authorities"]:
            if authority.get("citation") == edit["citation"]:
                matches.append(authority)
    if len(matches) != 1:
        raise ValueError("phase2a_wave_authority_repair_membership_fingerprint_mismatch")
    authority = matches[0]
    if (
        authority.get("candidate_existing") is not False
        or authority.get("candidate_source_version_ids") != []
        or authority.get("source_admission_required") is not True
    ):
        raise ValueError("phase2a_wave_authority_repair_false_new_state_mismatch")
    source = by_version.get(edit["source_version_id"])
    if source is None or source.get("authority_identity_id") != edit["manifest_identity"]:
        raise ValueError("phase2a_wave_authority_repair_false_new_manifest_mismatch")
    if authority.get("currentness_finding") != edit["expected_currentness_finding"]:
        raise ValueError("phase2a_wave_authority_repair_false_new_text_mismatch")
    holds = row.get("unresolved_holds")
    if (
        not isinstance(holds, list)
        or holds.count(edit["expected_hold"]) != 1
        or edit["replacement_hold"] in holds
    ):
        raise ValueError("phase2a_wave_authority_repair_false_new_hold_mismatch")
    authority["candidate_existing"] = True
    authority["candidate_source_version_ids"] = [edit["source_version_id"]]
    authority["source_admission_required"] = False
    authority["currentness_finding"] = edit["currentness_finding"]
    holds[holds.index(edit["expected_hold"])] = edit["replacement_hold"]


def _add_exact_hold(wave: dict[str, Any], *, row_id: str, hold: str) -> None:
    row = _row(wave, row_id)
    holds = row.get("unresolved_holds")
    if not isinstance(holds, list):
        raise ValueError("phase2a_wave_authority_repair_holds_invalid")
    if hold not in holds:
        holds.append(hold)


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def canonical_wave_paths(*, input_root: Path, output_root: Path) -> list[Path]:
    paths: list[Path] = []
    for base_name in CANONICAL_BASE_WAVES:
        replacement = BASE_BINDINGS.get(base_name)
        paths.append(
            output_root / replacement[0] if replacement is not None else input_root / base_name
        )
    return paths


def _record_sealed(material: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(material)
    return {**value, "record_content_sha256": _sealed(value)}


def _assert_binding_privacy_safe(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if str(key).casefold() in {
                "absolute_path",
                "local_path",
                "owner_id",
                "owner_identifier",
                "personal_filename",
                "source_path",
            }:
                raise ValueError("phase2a_canonical_wave_binding_privacy_invalid")
            _assert_binding_privacy_safe(nested)
        return
    if isinstance(value, list):
        for nested in value:
            _assert_binding_privacy_safe(nested)
        return
    if isinstance(value, str) and (
        value.startswith(("/", "~", "file://"))
        or "/Users/" in value
        or "/home/" in value
        or "\\Users\\" in value
    ):
        raise ValueError("phase2a_canonical_wave_binding_privacy_invalid")


def _canonical_binding_material(*, queue_path: Path, wave_root: Path) -> dict[str, Any]:
    queue = validator._load_queue(queue_path)
    queue_raw = queue_path.read_bytes()
    if (
        _sha256(queue_raw) != EXPECTED_QUEUE_FILE_SHA256
        or queue.get("artifact_content_sha256") != validator.EXPECTED_QUEUE_CONTENT_SHA256
        or len(queue.get("records", [])) != 316
    ):
        raise ValueError("phase2a_canonical_wave_binding_queue_mismatch")
    paths = canonical_wave_paths(input_root=wave_root, output_root=wave_root)
    validation = validator.validate_waves(queue_path=queue_path, wave_paths=paths)
    if (
        validation.get("status") != "PASS_COMPLETE"
        or validation.get("wave_count") != 32
        or validation.get("covered_row_count") != 316
        or validation.get("missing_row_count") != 0
    ):
        raise ValueError("phase2a_canonical_wave_binding_validation_failed")
    expected_names = {BASE_BINDINGS.get(name, (name, "", ""))[0] for name in CANONICAL_BASE_WAVES}
    names = {path.name for path in paths}
    if (
        len(paths) != 32
        or len(names) != 32
        or names != expected_names
        or names & OBSOLETE_CANONICAL_WAVE_NAMES
        or "research-live60-q48-q50-r3.json" not in names
    ):
        raise ValueError("phase2a_canonical_wave_binding_exact_set_invalid")
    waves: list[dict[str, Any]] = []
    total_rows = 0
    for path in sorted(paths, key=lambda item: item.name):
        if path.is_symlink() or not path.is_file() or path.name != Path(path.name).name:
            raise ValueError("phase2a_canonical_wave_binding_wave_invalid")
        raw = path.read_bytes()
        wave = json.loads(raw)
        if not isinstance(wave, dict):
            raise ValueError("phase2a_canonical_wave_binding_wave_invalid")
        material = dict(wave)
        content_sha256 = str(material.pop("artifact_content_sha256", ""))
        records = wave.get("records")
        if content_sha256 != _sealed(material) or not isinstance(records, list):
            raise ValueError("phase2a_canonical_wave_binding_wave_seal_invalid")
        record_count = len(records)
        total_rows += record_count
        waves.append(
            _record_sealed(
                {
                    "file_name": path.name,
                    "record_count": record_count,
                    "content_sha256": content_sha256,
                    "file_sha256": _sha256(raw),
                }
            )
        )
    if total_rows != 316:
        raise ValueError("phase2a_canonical_wave_binding_row_count_invalid")
    queue_binding = _record_sealed(
        {
            "file_name": queue_path.name,
            "row_count": 316,
            "content_sha256": validator.EXPECTED_QUEUE_CONTENT_SHA256,
            "file_sha256": EXPECTED_QUEUE_FILE_SHA256,
        }
    )
    result = {
        "schema": CANONICAL_BINDING_SCHEMA,
        "status": "CANONICAL_32_WAVES_BOUND_NOT_AUTHORIZING",
        "source_queue_content_sha256": validator.EXPECTED_QUEUE_CONTENT_SHA256,
        "source_queue_file_sha256": EXPECTED_QUEUE_FILE_SHA256,
        "queue_binding": queue_binding,
        "exact_set_count": 32,
        "wave_count": 32,
        "total_row_count": 316,
        "waves": waves,
        "excluded_obsolete_wave_files": sorted(OBSOLETE_CANONICAL_WAVE_NAMES),
        "advisory_only": True,
        "owner_decisions_applied": False,
        "owner_outcomes_applied": False,
        "source_collection_authorized": False,
        "source_collected": False,
        "source_admitted": False,
        "catalogue_mutated": False,
        "candidate_mutated": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "embedding_run": False,
        "active_or_previous_write_authorized": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
        "validation30_authorized": False,
        "live_activation_authorized": False,
    }
    _assert_binding_privacy_safe(result)
    return result


def verify_canonical_bindings(
    *, queue_path: Path, wave_root: Path, binding_path: Path
) -> dict[str, Any]:
    if binding_path.is_symlink() or not binding_path.is_file():
        raise ValueError("phase2a_canonical_wave_binding_artifact_invalid")
    raw = binding_path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("phase2a_canonical_wave_binding_artifact_invalid")
    material = dict(value)
    content_sha256 = str(material.pop("artifact_content_sha256", ""))
    if content_sha256 != _sealed(material):
        raise ValueError("phase2a_canonical_wave_binding_artifact_seal_invalid")
    expected = _canonical_binding_material(queue_path=queue_path, wave_root=wave_root)
    if material != expected:
        raise ValueError("phase2a_canonical_wave_binding_artifact_drift")
    for record in [material["queue_binding"], *material["waves"]]:
        record_material = dict(record)
        record_seal = str(record_material.pop("record_content_sha256", ""))
        if record_seal != _sealed(record_material):
            raise ValueError("phase2a_canonical_wave_binding_record_seal_invalid")
    _assert_binding_privacy_safe(value)
    return {
        "schema": "legalbot.v111.phase2a.canonical-research-wave-set-verification.v1",
        "status": "PASS",
        "file_name": binding_path.name,
        "artifact_content_sha256": content_sha256,
        "file_sha256": _sha256(raw),
        "exact_set_count": material["exact_set_count"],
        "total_row_count": material["total_row_count"],
        "owner_outcomes_applied": False,
        "source_collected": False,
        "source_admitted": False,
        "candidate_mutated": False,
        "embedding_run": False,
        "phase2b_authorized": False,
    }


def emit_canonical_bindings(
    *, queue_path: Path, wave_root: Path, binding_path: Path
) -> dict[str, Any]:
    if binding_path.exists() or binding_path.is_symlink():
        raise ValueError("phase2a_canonical_wave_binding_output_already_exists")
    material = _canonical_binding_material(queue_path=queue_path, wave_root=wave_root)
    value = {**material, "artifact_content_sha256": _sealed(material)}
    binding_path.parent.mkdir(parents=True, exist_ok=True)
    _write_exclusive(binding_path, _pretty_json(value))
    return verify_canonical_bindings(
        queue_path=queue_path,
        wave_root=wave_root,
        binding_path=binding_path,
    )


def repair_all(
    *,
    queue_path: Path,
    manifest_path: Path,
    input_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    manifest = _load_manifest(manifest_path)
    by_version, identities = _manifest_maps(manifest)
    outputs: list[tuple[Path, dict[str, Any]]] = []
    split_count = 0
    membership_count = 0
    for base_name, (output_name, content_sha, file_sha) in BASE_BINDINGS.items():
        output_path = output_root / output_name
        if output_path.exists() or output_path.is_symlink():
            raise ValueError("phase2a_wave_authority_repair_output_already_exists")
        base_path = input_root / base_name
        source = _load_bound_wave(base_path, content_sha=content_sha, file_sha=file_sha)
        wave = copy.deepcopy(source)
        for edit in SPLIT_EDITS.get(base_name, []):
            _apply_split(wave, edit, by_version=by_version, identities=identities)
            split_count += 1
        for edit in MEMBERSHIP_EDITS.get(base_name, []):
            _apply_membership_edit(wave, edit, by_version=by_version)
            membership_count += 1
        if base_name == "research-live60-q41-q43.json":
            _add_exact_hold(
                wave,
                row_id="live60-q41:issue-06",
                hold=(
                    "Modern Slavery Act 2015 section 51 remains unbound in this "
                    "wave because the researched composite authority supplied exact "
                    "locators only for sections 49 and 50."
                ),
            )
        wave.pop("artifact_content_sha256", None)
        wave["deterministic_authority_repair"] = {
            "schema": ("legalbot.v111.phase2a.deterministic-wave-authority-repair.v1"),
            "source_file": base_name,
            "source_file_sha256": file_sha,
            "source_content_sha256": content_sha,
            "approved_source_manifest_file_sha256": (EXPECTED_MANIFEST_FILE_SHA256),
            "approved_source_manifest_content_sha256": (EXPECTED_MANIFEST_CONTENT_SHA256),
            "authority_split_count": len(SPLIT_EDITS.get(base_name, [])),
            "false_new_membership_correction_count": len(MEMBERSHIP_EDITS.get(base_name, [])),
            "repair_scope": (
                "Split composite authority representations into one official source "
                "per authority object and correct only manifest-proven false-new "
                "candidate flags."
            ),
            "substantive_owner_judgment_added": False,
            "owner_outcomes_applied": False,
            "source_collected": False,
            "source_admitted": False,
            "candidate_mutated": False,
            "embedding_run": False,
            "phase2b_authorized": False,
        }
        result = {**wave, "artifact_content_sha256": _sealed(wave)}
        if validator._contains_exact_text(result):
            raise ValueError("phase2a_wave_authority_repair_exact_text_forbidden")
        if validator._safety_flag(result, "advisory_only") is not True or any(
            validator._safety_flag(result, flag) is not False
            for flag in validator.REQUIRED_FALSE_FLAGS
        ):
            raise ValueError("phase2a_wave_authority_repair_boundary_invalid")
        outputs.append((output_path, result))
    if split_count != 14 or membership_count != 3 or len(outputs) != 9:
        raise ValueError("phase2a_wave_authority_repair_scope_count_mismatch")
    output_root.mkdir(parents=True, exist_ok=True)
    for output_path, value in outputs:
        _write_exclusive(output_path, _pretty_json(value))
    validation = validator.validate_waves(
        queue_path=queue_path,
        wave_paths=canonical_wave_paths(input_root=input_root, output_root=output_root),
    )
    if (
        validation.get("status") != "PASS_COMPLETE"
        or validation.get("covered_row_count") != 316
        or validation.get("missing_row_count") != 0
    ):
        raise ValueError("phase2a_wave_authority_repair_full_validation_failed")
    return {
        "schema": "legalbot.v111.phase2a.deterministic-wave-authority-repair-run.v1",
        "status": "PASS",
        "output_count": len(outputs),
        "authority_split_count": split_count,
        "false_new_membership_correction_count": membership_count,
        "covered_row_count": validation["covered_row_count"],
        "wave_count": validation["wave_count"],
        "outputs": [
            {
                "path": path.name,
                "artifact_content_sha256": value["artifact_content_sha256"],
                "file_sha256": _sha256(path.read_bytes()),
            }
            for path, value in outputs
        ],
        "owner_outcomes_applied": False,
        "source_collected": False,
        "source_admitted": False,
        "candidate_mutated": False,
        "embedding_run": False,
        "phase2b_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--queue", type=Path, default=validator.DEFAULT_QUEUE)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--input-root", type=Path, default=WORKING_ROOT)
    parser.add_argument("--output-root", type=Path, default=WORKING_ROOT)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--emit-canonical-bindings", action="store_true")
    modes.add_argument("--verify-canonical-bindings", action="store_true")
    parser.add_argument("--binding-output", type=Path)
    args = parser.parse_args()
    binding_path = args.binding_output or (args.output_root / CANONICAL_BINDING_FILE_NAME)
    if args.emit_canonical_bindings:
        result = emit_canonical_bindings(
            queue_path=args.queue,
            wave_root=args.input_root,
            binding_path=binding_path,
        )
    elif args.verify_canonical_bindings:
        result = verify_canonical_bindings(
            queue_path=args.queue,
            wave_root=args.input_root,
            binding_path=binding_path,
        )
    else:
        result = repair_all(
            queue_path=args.queue,
            manifest_path=args.manifest,
            input_root=args.input_root,
            output_root=args.output_root,
        )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
