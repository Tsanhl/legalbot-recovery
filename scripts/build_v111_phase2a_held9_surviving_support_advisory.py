#!/usr/bin/env python3
"""Build the sealed Phase-2A held-nine surviving-support advisory.

This create-only builder verifies the exact remediation packet, substantive
content audit, source-binding delta packet and existing candidate manifest.  It
then records which support survives for nine rows affected by five unresolved
official-source holds.  The output is advisory evidence only: it cannot apply
an owner decision, admit a source, scan, build, embed, qualify, release an
answer, write a pointer or authorize Phase 2B.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
OUTPUT_REVIEW_ROOT = REVIEW_ROOT

ORIGINAL_ROOT_NAME = "LegalBot-Phase2A-2026-08-28-exact-remediation-owner-packet-r1"
ORIGINAL_NAME = "EXACT-REMEDIATION-OWNER-PACKET-361.json"
ORIGINAL_PATH = REVIEW_ROOT / ORIGINAL_ROOT_NAME / ORIGINAL_NAME
AUDIT_ROOT_NAME = "LegalBot-Phase2A-2026-08-28-admission-content-audit-r1"
AUDIT_NAME = "ADMISSION-CONTENT-AUDIT-247.json"
AUDIT_PATH = REVIEW_ROOT / AUDIT_ROOT_NAME / AUDIT_NAME
DELTA_ROOT_NAME = "LegalBot-Phase2A-2026-08-28-source-binding-delta-owner-packet-r1"
DELTA_NAME = "EXACT-SOURCE-BINDING-DELTA-OWNER-PACKET.json"
DELTA_PATH = REVIEW_ROOT / DELTA_ROOT_NAME / DELTA_NAME
CANDIDATE_ROOT_NAME = "current-law-ew-full-fp16-v111-20260827-phase2a-a"
CANDIDATE_NAME = "approved-source-manifest.json"
CANDIDATE_PATH = PROJECT_ROOT / "data/indexes/builds" / CANDIDATE_ROOT_NAME / CANDIDATE_NAME

DEFAULT_OUTPUT_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-held9-surviving-support-advisory-r1"
)
ADVISORY_NAME = "HELD9-SURVIVING-SUPPORT-ADVISORY.json"
PACKAGE_NAME = "PACKAGE-MANIFEST.json"
CHECKSUMS_NAME = "SHA256SUMS.txt"

EXPECTED_INPUTS = {
    "original": {
        "content_sha256": "93ad9113af76896f0570a3666c446472af7587b7e3ff32b7464e670777ec6b6c",
        "file_sha256": "992770c04cb3e08de64bb98e80aa9801171d3e66e4b573b85919091a78b1db3b",
    },
    "audit": {
        "content_sha256": "fdb0fc0f6233e41da7088304323930cb1edd20ad4a4610774db2d77f056a8e5b",
        "file_sha256": "cdd7e3a8e2dd3bafba07271a74af4a7fa59a9a7a97d2daf957575d12b30225bc",
    },
    "delta": {
        "content_sha256": "01312e142dd084271aa005b3d2a5ba8b93564bf3a841e1f5a4ec68c06a604ac0",
        "file_sha256": "a3498ce36e0782d941b9c167dd9ab3e78da1a7df2537e590946b1ccea666ca3a",
    },
    "candidate": {
        "content_sha256": "b304ab1223987bf9b57d3e2560413b2f325c16213ae0071a45dface2e10dc206",
        "file_sha256": "0bbb1edb169c84a26e5f1d42e367f9e2f83fcdd9c652a9061980652f15979b21",
    },
}

HELD_SPECS = (
    {
        "label": "Verein Klimaseniorinnen Schweiz v Switzerland",
        "proposal_id": "proposed-source-4e8af055532a8bb2c56f2bd8",
        "proposal_content_sha256": (
            "b4fbf58b064362902fb086d426edb9ffb9d51065ae6096525786133b16775130"
        ),
        "old_record_id": "quarantine-binding-0a370f8e41122c812c5f26d2",
        "repair_hold_content_sha256": (
            "e9370cadc743674906f33b68d8e2e320fa5e4a02dd60e1ed8aa63c7ff6c3f99f"
        ),
        "affected_rows": {
            "live30-q22:issue-02": ["paragraphs 487-488, 502, 519-527 and 622-623"],
            "live30-q22:issue-04": ["paragraphs 519-520, 545, 548-551 and 572-574"],
            "live30-q22:issue-06": ["paragraphs 497-502 and 519-527"],
        },
    },
    {
        "label": "Mutu and Pechstein v Switzerland",
        "proposal_id": "proposed-source-78183f51ee77b79b9410687b",
        "proposal_content_sha256": (
            "f2069984901ebe5a25e50d459228ab8b4b4bf72c3f7580a881112f9a6779a968"
        ),
        "old_record_id": "quarantine-binding-3688eea8275753b9dcabf559",
        "repair_hold_content_sha256": (
            "340880903c2d176a4a8f59e69de3abdac0d2eb18f6b153b9c0f1f448cf088598"
        ),
        "affected_rows": {
            "live60-q53:issue-04": ["paras 95-123", "paras 138-168", "paras 169-184"],
            "live60-q53:issue-11": ["paras 95-123", "paras 138-168", "paras 172-184"],
        },
    },
    {
        "label": "Big Brother Watch and Others v United Kingdom",
        "proposal_id": "proposed-source-4ccedf903597d1aea5391919",
        "proposal_content_sha256": (
            "2f8d89044540f0bdae8e8466190c0d7c16a559639ba3effa54c6a3db591b2f67"
        ),
        "old_record_id": "quarantine-binding-678af407a5abea67aa817bee",
        "repair_hold_content_sha256": (
            "d307bfa43e9c87ee561bcfb19ff82c2cb1fcc9b429bc5d66f8391ba99b9c7773"
        ),
        "affected_rows": {
            "live60-q56:issue-01": ["paras 332-347", "paras 356-364", "paras 425-426"],
            "live60-q56:issue-05": ["paras 442-450"],
        },
    },
    {
        "label": "Shanghai Shipyard Co Ltd v Reignwood International Investment",
        "proposal_id": "proposed-source-9806b3f299403ca5fded06ef",
        "proposal_content_sha256": (
            "dff15556dfb22001557070900c7f549d8b8d998b17ad57e774e96b94b662b5d7"
        ),
        "old_record_id": "quarantine-binding-caeef16146c2eea1e2b03d09",
        "repair_hold_content_sha256": (
            "415224b809a0df8cccc32fa4c4e3af630e66ac876743a038c648750d82c511e4"
        ),
        "affected_rows": {"live60-q58:issue-09": ["paras 21-52"]},
    },
    {
        "label": "Goodwin v United Kingdom",
        "proposal_id": "proposed-source-74cac9763ab311805522f648",
        "proposal_content_sha256": (
            "f243f9a6054977d0b2790a400c3bafddec6a4dc6150e8b383fab841b63f59daa"
        ),
        "old_record_id": "quarantine-binding-d07fad39256d15a7c6a25893",
        "repair_hold_content_sha256": (
            "53878fbfdc8ed554c4e1837df0207e90189e2ee64e02c84f3b8a1ee087c01cd9"
        ),
        "affected_rows": {"live60-q51:issue-05": ["paras 20-22", "paras 39-46"]},
    },
)

SURVIVOR_SPECS = (
    {
        "label": "Walton v Scottish Ministers",
        "proposal_id": "proposed-source-b6a333632ad4e80c6c841d99",
        "proposal_content_sha256": (
            "bbccd6d9d96e76a1772181009bcd2e01103f49aff9c890c58f38906df89934e5"
        ),
        "source_version_id": "proposed-source-version-3ce050f9ccc130075638b9392c27243d9804d936",
        "raw_sha256": "bdcb223d762325d544fe0a58baa35020cd7c26b7e22bd02dee4d6b2f73f957b7",
        "canonical_content_sha256": (
            "a2fafc0906317b900b73e6726da96088659b54f3f31bfbd25c6441bf2ee2e4c0"
        ),
        "binding_record_content_sha256": (
            "975839776bfef710aa0e596acc9e5fcb64981f45b3f5a47d0902f0f4a596de3e"
        ),
        "audit_record_content_sha256": (
            "2b8841642cc96d2693f0d071f8b25b696736b544dd85cde4d523a8180913395d"
        ),
        "audit_verdict": "PASS",
        "audit_warning_reason_codes": [],
        "row_locators": {
            "live30-q22:issue-02": ["paragraphs 90-95"],
            "live30-q22:issue-06": ["paragraphs 90-95"],
        },
    },
    {
        "label": "Friends of the Earth Ltd v Secretary of State for BEIS",
        "proposal_id": "proposed-source-33b828b53fbcbab0fab88781",
        "proposal_content_sha256": (
            "4480b0e3e62a88d5ac0123c8ea125a661503473963a9794fb55be805d88e60de"
        ),
        "source_version_id": "proposed-source-version-f8afed921e2e44f103dbd69ed23c15fed79d6af0",
        "raw_sha256": "d0a3f1eef5d77ef634b34ec7e1171f86bc59f694bf0d0d8ff5f0c313cd5684ec",
        "canonical_content_sha256": (
            "39e44c7926042c2f0031f551a2d216e3308792d2a690c9842ebdd6aaadc3b6a6"
        ),
        "binding_record_content_sha256": (
            "e7939bd3af6b9a73cccc22160316a77ac6ece9d6a67648a11c75b33b8aa1fe09"
        ),
        "audit_record_content_sha256": (
            "4cae90df3d4c58d6995e6b65c80b426e5239fdec51919a94639b8c11e2a6f151"
        ),
        "audit_verdict": "PASS",
        "audit_warning_reason_codes": [],
        "row_locators": {
            "live30-q22:issue-02": ["paragraphs 22 and 192-195"],
        },
    },
    {
        "label": "Plan B Earth v Prime Minister",
        "proposal_id": "proposed-source-8b5cbaebf2071864a339c12b",
        "proposal_content_sha256": (
            "4816bc728de445d4c98c183e6dcf4ca1492f20dd64d5b4d980ade36176de5e3c"
        ),
        "source_version_id": "proposed-source-version-dbb4e855240287db5d4ea79b47012894f5611ffc",
        "raw_sha256": "3ef440a12952e05a8861257d12ab2cbdbcd502ee49fa6a545d9b0c4e44ad9ead",
        "canonical_content_sha256": (
            "3fe2e5bc4413d8cdf4360b3e5928d32eb1bcf112e0857783596cbe181662fc88"
        ),
        "binding_record_content_sha256": (
            "bb5e68c343ff1e7e5f545d53971fa70199430013d9cef7dc26d7592bc4c66d63"
        ),
        "audit_record_content_sha256": (
            "b1790199aab9b7d8134542e14e145ac99b86046cf2bda765cc1c0f3ae95cb78c"
        ),
        "audit_verdict": "PASS",
        "audit_warning_reason_codes": [],
        "row_locators": {
            "live30-q22:issue-04": ["paragraphs 19-25, 39-60 and 61-79"],
        },
    },
    {
        "label": "Climate Change Act 2008",
        "proposal_id": "proposed-source-ae7350466ccf4faaf5ea0638",
        "proposal_content_sha256": (
            "40e2e383ffb654b5d2a8b20af487cc59230ede54da33183d3d640b720dc2958a"
        ),
        "source_version_id": "proposed-source-version-f44b4c8f6d88bc26329b809c2593b84a4f610a28",
        "raw_sha256": "9e1191acf137ef7d968f71c11980ebbed75c855ca28d671919d806d051a84ff5",
        "canonical_content_sha256": (
            "fc71609e1ff00791a447a4a1e812795bf8c3a8c991f25fc41ea7bf78a7686308"
        ),
        "binding_record_content_sha256": (
            "f336cb71e9a3c7c16230be94d7d760ca3215801cd1b445cd9812a34e28ecb8eb"
        ),
        "audit_record_content_sha256": (
            "431a15b7f076b7265a11ee7e4e8f4aa40c0164e66424d634e675f6627a953772"
        ),
        "audit_verdict": "PASS",
        "audit_warning_reason_codes": [],
        "row_locators": {
            "live30-q22:issue-06": ["sections 1, 4-8, 13 and 56-58"],
        },
    },
    {
        "label": "Contempt of Court Act 1981",
        "proposal_id": "proposed-source-a3f8704a19a6d34660f952cf",
        "proposal_content_sha256": (
            "66a9832122cbd21d471d9c32fd047ea82dcd0e3d686f686cd859b8e1468fbb57"
        ),
        "source_version_id": "proposed-source-version-d99cd007137fb91f82e52dec10101806b540506c",
        "raw_sha256": "795ca24ecf121f3b6323d8d913fdc96295e68be98c2947da99d5d0b83ba44e69",
        "canonical_content_sha256": (
            "30c3e6217eba0fd6b7c29ae2c431e3bc54d1964088754171a39543d92ea7a2c1"
        ),
        "binding_record_content_sha256": (
            "90dd9eb9cb99c65adb21fc28f1b05a3d1cacfeae5376857ddc6d5815465c1f39"
        ),
        "audit_record_content_sha256": (
            "663526cd0a001dc909d3f1fbb182b8580da2fc977bd16c34c941dc34fc213a1e"
        ),
        "audit_verdict": "PASS",
        "audit_warning_reason_codes": [],
        "row_locators": {"live60-q51:issue-05": ["s 10"]},
    },
    {
        "label": "Braganza v BP Shipping Ltd",
        "proposal_id": "proposed-source-6b90251a996f47b9ea01de9e",
        "proposal_content_sha256": (
            "b4916ddbae86960cdc7ac812a699da87965b452bea69ecb73369f7f20a76dd29"
        ),
        "source_version_id": "proposed-source-version-151fdfa5f1531448bb97d8f9301485e00fb2325b",
        "raw_sha256": "ba331e1b8dd0fe70587cfb25bf3c260ca026f8a7083385ce81558d4057abec3b",
        "canonical_content_sha256": (
            "d26bfa60fc499bb7c66510c2e9370be66144bc1af1c726d6e81a60ec92b46852"
        ),
        "binding_record_content_sha256": (
            "a54c9dff7ea9dea47f87abef3ddf9960d8057545abca2b899a110c64f67a12f2"
        ),
        "audit_record_content_sha256": (
            "eb33d93208b934dae293c64b05a0a8c6db08fee70f3470d2142e2c3e451eb0d9"
        ),
        "audit_verdict": "PASS",
        "audit_warning_reason_codes": [],
        "row_locators": {"live60-q53:issue-04": ["paras 18-31"]},
    },
    {
        "label": "Code of Sports-related Arbitration",
        "proposal_id": "proposed-source-22c1a06353633c217c79b349",
        "proposal_content_sha256": (
            "31509f391d485615ba067b614518fdb5296c2386c38597a2bd1cdf2117714339"
        ),
        "source_version_id": "proposed-source-version-f751237a1139e758734534c7c8fc8e265cbc8e00",
        "raw_sha256": "af50463d8ee72e5de91bae081a66cb4b809754229f8ab81894c0df83627f9855",
        "canonical_content_sha256": None,
        "binding_record_content_sha256": (
            "be886d6598acdbbb5c1b32b1fb248cd15543c5ca99cca77304074330f97ddc52"
        ),
        "audit_record_content_sha256": (
            "4777ca55ee140740777925e38a3cc0c478f3deb1aef8e9802c19e310d34fa72a"
        ),
        "audit_verdict": "PASS_WITH_WARNING",
        "audit_warning_reason_codes": ["TAS_NOISY_SEARCH_OVERLAY_RULE_BODY_PRESENT"],
        "row_locators": {
            "live60-q53:issue-04": ["R47", "R57"],
            "live60-q53:issue-11": ["R27", "R47", "R57", "R59"],
        },
    },
    {
        "label": "Investigatory Powers Act 2016",
        "proposal_id": "proposed-source-9f608bba79f11c1e5b227169",
        "proposal_content_sha256": (
            "615282396df0d39056bf85894f3b3a9f4003194d530764b169a22ded3fb7c678"
        ),
        "source_version_id": "proposed-source-version-cef92c5e744abf015d99fcd368955b097f1b1704",
        "raw_sha256": "2e0dbbb9fdd832766efcdfc8e7e95b56be1a44ad073b2a8cce7b1c9f29f07faa",
        "canonical_content_sha256": (
            "c2eab1002c405e9fffce340ed605c92acd54cdfed6a1e65dfc00d8177d0f9141"
        ),
        "binding_record_content_sha256": (
            "b8691e05289b6ba8bace9f671211742d075d3537fc76fc2fcb4f95b3c1bdf4a7"
        ),
        "audit_record_content_sha256": (
            "50e0208b1c0082934f0416fd3a45db831337d780ca138f98481e7af73dd28ec6"
        ),
        "audit_verdict": "PASS",
        "audit_warning_reason_codes": [],
        "row_locators": {
            "live60-q56:issue-01": [
                "sections 15 and 18-25",
                "sections 30-39",
                "sections 136-142",
                "sections 143-157",
            ],
            "live60-q56:issue-05": [
                "sections 28-29",
                "section 77",
                "sections 113-114",
                "sections 154 and 195",
            ],
        },
    },
    {
        "label": "Wuhan Guoyu Logistics Group Co Ltd v Emporiki Bank of Greece SA",
        "proposal_id": "proposed-source-4454eee65cc76c0a988198a1",
        "proposal_content_sha256": (
            "0e0b4015fe6e2fecd4e9fadf43370dad28d9313e64fda6c7ed5f09bfa61a98b4"
        ),
        "source_version_id": "proposed-source-version-073ac54538f550bec187276a8a8188a0333da522",
        "raw_sha256": "0ec6a2772991918657155ce9402bb557aaccc9e97f6e35c59b76e6bbf2a35ef5",
        "canonical_content_sha256": (
            "95e87b187b56fa0851a8258244510d198bdced6690700645d64ecde5cc6fa603"
        ),
        "binding_record_content_sha256": (
            "7f089f7b05a87a72129ac5bf936d8976bd33cec3ccb478f497f927aa2a5b29fc"
        ),
        "audit_record_content_sha256": (
            "b36c366b1d180f69a85239e17dc5cdfffabfdb1d0a1e4875150e7601e194131e"
        ),
        "audit_verdict": "PASS",
        "audit_warning_reason_codes": [],
        "row_locators": {"live60-q58:issue-09": ["paragraphs 25-33"]},
        "original_approved_packet_row_id": "live30-q26:issue-08",
        "cross_row_candidate_only": True,
    },
)

CANDIDATE_SOURCE_SPECS = (
    {
        "label": "Senior Courts Act 1981",
        "authority_identity_id": "ukpga:1981:54",
        "source_version_id": "source-version-bd7651ddaa9a8043ff57dfd1bf71c707d5af9f68",
        "content_sha256": "500993e5639d31664634b8408c2bc01530126f7a3510d8a4a57f81f57ea5c499",
        "row_locators": {"live30-q22:issue-02": ["section 31(3)"]},
    },
    {
        "label": "Human Rights Act 1998",
        "authority_identity_id": "ukpga:1998:42",
        "source_version_id": "source-version-a7765ef20ffc9826c4dddc430c61d9077e85b4f1",
        "content_sha256": "3dd5c55b447935d62c359180f34a0a2932272554c5c62d27dc27aec17e1f01c8",
        "row_locators": {
            "live30-q22:issue-02": ["sections 2(1) and 7(1)-(7), especially 7(3)"],
            "live30-q22:issue-04": [
                "sections 2(1), 6(1)-(3), 7(1)-(7) and 8(1)-(4)",
                "Schedule 1 Articles 2 and 8",
            ],
        },
    },
    {
        "label": "Arbitration Act 1996",
        "authority_identity_id": "ukpga:1996:23",
        "source_version_id": "source-version-59a8ac0ed35ad09bb4ea9520c6bddd3110a78cf8",
        "content_sha256": "2d395c8b88c15104758839b7e586816c67b344fda9def5e091384d4cb1a96eea",
        "row_locators": {
            "live60-q53:issue-04": ["sections 33 and 68"],
            "live60-q53:issue-11": ["sections 1, 33, 67-70, 81(1)(a) and 103(3)"],
        },
    },
)

ROW_OUTCOMES = (
    {
        "row_id": "live30-q22:issue-02",
        "question_kind": "ESSAY",
        "outcome": "SUPPORTED_SUBSET_WITH_GENUINE_LEGAL_AUTHORITY_GAP",
        "supported_subset": [
            "Ordinary sufficient-interest and public-interest standing under section 31(3).",
            "Climate-legality review remains distinct from policy-merits substitution.",
            "Human Rights Act victim status is a distinct statutory test.",
        ],
        "excluded_unsupported_components": [
            "Klimaseniorinnen association and individual-applicant criteria.",
            "CPR Part 54 is a separate unadmitted identity and is not supplied by this audit.",
        ],
        "safe_fallback_eligible": False,
        "safe_fallback_prohibited": True,
        "blocker_class": "LEGAL_AUTHORITY_GAP",
    },
    {
        "row_id": "live30-q22:issue-04",
        "question_kind": "ESSAY",
        "outcome": "SUPPORTED_SUBSET_WITH_GENUINE_LEGAL_AUTHORITY_GAP",
        "supported_subset": [
            "Human Rights Act sections 2 and 6-8 framework.",
            "Plan B historical refusal and the supported judicial-review analysis.",
        ],
        "excluded_unsupported_components": [
            "Klimaseniorinnen 2024 Article 8 positive obligation and current reconciliation."
        ],
        "safe_fallback_eligible": False,
        "safe_fallback_prohibited": True,
        "blocker_class": "LEGAL_AUTHORITY_GAP",
    },
    {
        "row_id": "live30-q22:issue-06",
        "question_kind": "ESSAY",
        "outcome": "NARROW_SUPPORTED_SUBSET_ONLY",
        "supported_subset": [
            "Climate Change Act long-term statutory duties.",
            "Walton public-interest standing.",
            "Those materials do not themselves create a freestanding future-generations right.",
        ],
        "excluded_unsupported_components": [
            "Klimaseniorinnen future-facing Strasbourg association component."
        ],
        "safe_fallback_eligible": False,
        "safe_fallback_prohibited": True,
        "blocker_class": "LEGAL_AUTHORITY_GAP",
        "future_owner_choice_required_for_narrow_proposition": True,
    },
    {
        "row_id": "live60-q53:issue-04",
        "question_kind": "ESSAY",
        "outcome": "SUPPORTED_SUBSET_WITH_GENUINE_LEGAL_AUTHORITY_GAP",
        "supported_subset": [
            "Contractual-discretion control under Braganza.",
            "Arbitration Act sections 33 and 68.",
            "CAS Code R47 and R57 procedural text.",
        ],
        "excluded_unsupported_components": [
            "Mutu and Pechstein compulsory arbitration, independence and Article 6 hearing analysis."
        ],
        "safe_fallback_eligible": False,
        "safe_fallback_prohibited": True,
        "blocker_class": "LEGAL_AUTHORITY_GAP",
    },
    {
        "row_id": "live60-q53:issue-11",
        "question_kind": "ESSAY",
        "outcome": "SUPPORTED_SUBSET_WITH_GENUINE_LEGAL_AUTHORITY_GAP",
        "supported_subset": [
            "CAS Code R27, R47, R57 and R59 procedural text.",
            "Arbitration Act challenge, seat and enforcement provisions listed in this advisory.",
        ],
        "excluded_unsupported_components": [
            "Mutu and Pechstein Convention compulsion and fairness analysis.",
            "Swiss supervisory and enforcement law is not established by the surviving sources.",
        ],
        "safe_fallback_eligible": False,
        "safe_fallback_prohibited": True,
        "blocker_class": "LEGAL_AUTHORITY_GAP",
    },
    {
        "row_id": "live60-q56:issue-01",
        "question_kind": "ESSAY",
        "outcome": "SUPPORTED_SUBSET_WITH_GENUINE_LEGAL_AUTHORITY_GAP",
        "supported_subset": ["Investigatory Powers Act targeted and bulk mechanics."],
        "excluded_unsupported_components": [
            "Big Brother Watch Article 8 global and end-to-end safeguards analysis."
        ],
        "safe_fallback_eligible": False,
        "safe_fallback_prohibited": True,
        "blocker_class": "LEGAL_AUTHORITY_GAP",
    },
    {
        "row_id": "live60-q56:issue-05",
        "question_kind": "ESSAY",
        "outcome": "SUPPORTED_SUBSET_WITH_GENUINE_LEGAL_AUTHORITY_GAP",
        "supported_subset": ["Investigatory Powers Act statutory journalistic safeguards."],
        "excluded_unsupported_components": [
            "Big Brother Watch Article 10 prior-independent-review analysis."
        ],
        "safe_fallback_eligible": False,
        "safe_fallback_prohibited": True,
        "blocker_class": "LEGAL_AUTHORITY_GAP",
    },
    {
        "row_id": "live60-q51:issue-05",
        "question_kind": "PROBLEM",
        "outcome": "DUAL_LEGAL_SOURCE_AND_MATTER_FACT_HOLD",
        "supported_subset": ["Contempt of Court Act 1981 section 10 statutory gateway."],
        "excluded_unsupported_components": [
            "Goodwin Article 10 pressing-need and proportionality analysis."
        ],
        "missing_matter_facts": [
            "The requested material and relevant proceedings.",
            "Alternative evidence, safeguards and the asserted statutory ground.",
        ],
        "safe_fallback_eligible": False,
        "safe_fallback_prohibited": True,
        "blocker_class": "DUAL_LEGAL_SOURCE_AND_MATTER_FACT_HOLD",
        "reason": "A fact fallback cannot hide the unresolved Goodwin legal-source gap.",
    },
    {
        "row_id": "live60-q58:issue-09",
        "question_kind": "PROBLEM",
        "outcome": "NO_LEGAL_CLAIM_MATTER_FACT_SUPPLEMENTATION_FALLBACK_ADVISORY",
        "supported_subset": [],
        "excluded_unsupported_components": [
            "Shanghai Shipyard performance-bond classification and injunction analysis.",
            "Any Wuhan legal rule until an exact cross-row owner decision and retained-hold review.",
        ],
        "safe_fallback_eligible": True,
        "safe_fallback_prohibited": False,
        "blocker_class": "MISSING_MATTER_FACTS",
        "reason_code": "INSUFFICIENT_MATTER_FACTS_FOR_PERFORMANCE_BOND_ADVICE",
        "ui_cta": "SUPPLY_BOND_AND_DEMAND_DOCUMENTS_AND_ESCALATE_QUALIFIED_HUMAN",
        "knowledge_gap_event": False,
        "matter_information_gap_event": True,
        "requested_material": [
            "Bond instrument and amendments.",
            "Demand, service records and evidence of compliance with demand conditions.",
            "Expiry information.",
            "Underlying contract and termination notices.",
            "Governing-law material.",
            "Fraud evidence.",
            "Urgency and injunction evidence.",
        ],
        "safe_fallback_text": (
            "現有資料不足以安全判斷該履約保證是見索即付保證還是從屬保證、索款是否合規，"
            "或是否有基礎申請禁制令。請提供保證書及修訂、索款文件與送達紀錄、到期日、"
            "基礎合約及終止通知、準據法、欺詐證據及緊急救濟材料，並交由合資格律師審核。"
        ),
        "fallback_releases_material_legal_claim": False,
        "cross_row_owner_decision_required": True,
        "wuhan_source_admission_authorized": False,
        "currentness_hold_retained": True,
        "later_treatment_hold_retained": True,
        "legal_rule_release_prohibited": True,
        "citation_release_prohibited": True,
        "evidence_span_release_prohibited": True,
    },
)

_NO_EXECUTION_FLAG_NAMES = (
    "owner_approved",
    "owner_decisions_applied",
    "owner_outcomes_applied",
    "source_admission_authorized",
    "source_admitted",
    "source_scan_authorized",
    "source_scan_run",
    "catalogue_mutated",
    "candidate_mutated",
    "index_build_authorized",
    "index_built",
    "embedding_authorized",
    "embedding_run",
    "successor_build_authorized",
    "successor_build_run",
    "retrieval_reattestation_authorized",
    "retrieval_reattestation_run",
    "qualification_authorized",
    "qualification_run",
    "all585_qualification_authorized",
    "all585_qualification_run",
    "technical_qualification_assigned",
    "answer_model_authorized",
    "answer_model_run",
    "answer_release_authorized",
    "answer_released",
    "phase2b_authorized",
    "phase2b_run",
    "development30_authorized",
    "development30_run",
    "validation30_authorized",
    "validation30_run",
    "promotion_authorized",
    "promotion_run",
    "active_pointer_write_authorized",
    "active_pointer_written",
    "previous_pointer_write_authorized",
    "previous_pointer_written",
    "live_activation_authorized",
    "live_activation_run",
    "training_export_authorized",
    "training_export_run",
    "automatic_indexing",
    "automatic_embedding",
    "network_used",
)

_SHA256 = re.compile(r"[0-9a-f]{64}")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _verify_seal(value: Mapping[str, Any], field: str, expected: str, code: str) -> None:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if supplied != expected or supplied != _sealed(material):
        raise ValueError(code)


def _load_exact(
    path: Path,
    *,
    expected_file_sha256: str,
    seal_field: str,
    expected_content_sha256: str,
    code: str,
    source_manifest_identity_mode: bool = False,
) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{code}_missing")
    if _sha256_file(path) != expected_file_sha256:
        raise ValueError(f"{code}_file_digest_mismatch")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"{code}_not_object")
    if source_manifest_identity_mode:
        supplied = str(value.get(seal_field, ""))
        identity = {
            key: item for key, item in value.items() if key not in {"created_at", seal_field}
        }
        computed = _sha256(_pretty_json(identity))
        if supplied != expected_content_sha256 or supplied != computed:
            raise ValueError(f"{code}_seal_mismatch")
    else:
        _verify_seal(value, seal_field, expected_content_sha256, f"{code}_seal_mismatch")
    return value


def _verify_inputs() -> tuple[dict[str, Any], ...]:
    original = _load_exact(
        ORIGINAL_PATH,
        expected_file_sha256=EXPECTED_INPUTS["original"]["file_sha256"],
        seal_field="artifact_content_sha256",
        expected_content_sha256=EXPECTED_INPUTS["original"]["content_sha256"],
        code="held9_original",
    )
    audit = _load_exact(
        AUDIT_PATH,
        expected_file_sha256=EXPECTED_INPUTS["audit"]["file_sha256"],
        seal_field="artifact_content_sha256",
        expected_content_sha256=EXPECTED_INPUTS["audit"]["content_sha256"],
        code="held9_audit",
    )
    delta = _load_exact(
        DELTA_PATH,
        expected_file_sha256=EXPECTED_INPUTS["delta"]["file_sha256"],
        seal_field="artifact_content_sha256",
        expected_content_sha256=EXPECTED_INPUTS["delta"]["content_sha256"],
        code="held9_delta",
    )
    candidate = _load_exact(
        CANDIDATE_PATH,
        expected_file_sha256=EXPECTED_INPUTS["candidate"]["file_sha256"],
        seal_field="manifest_sha256",
        expected_content_sha256=EXPECTED_INPUTS["candidate"]["content_sha256"],
        code="held9_candidate",
        source_manifest_identity_mode=True,
    )
    return original, audit, delta, candidate


def _exact_index(
    values: Sequence[Mapping[str, Any]], key: str, *, code: str
) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for value in values:
        identity = str(value.get(key, ""))
        if not identity or identity in result:
            raise ValueError(code)
        result[identity] = value
    return result


def _verify_and_make_holds(
    original: Mapping[str, Any], delta: Mapping[str, Any]
) -> list[dict[str, Any]]:
    proposals = _exact_index(
        original["proposed_new_source_admissions"], "proposal_id", code="held9_proposals"
    )
    holds = _exact_index(delta["unresolved_repair_holds"], "old_proposal_id", code="held9_holds")
    if len(holds) != 5:
        raise ValueError("held9_hold_count_mismatch")
    result: list[dict[str, Any]] = []
    for spec in HELD_SPECS:
        proposal = proposals[str(spec["proposal_id"])]
        hold = holds[str(spec["proposal_id"])]
        expected = {
            "old_proposal_content_sha256": spec["proposal_content_sha256"],
            "old_record_id": spec["old_record_id"],
            "repair_hold_content_sha256": spec["repair_hold_content_sha256"],
            "currentness_hold_retained": True,
            "later_treatment_hold_retained": True,
        }
        if any(hold.get(key) != value for key, value in expected.items()):
            raise ValueError("held9_hold_binding_mismatch")
        if proposal.get("proposal_content_sha256") != spec["proposal_content_sha256"]:
            raise ValueError("held9_held_proposal_digest_mismatch")
        uses = {str(item["row_id"]): item for item in proposal["uses"]}
        for row_id, locators in spec["affected_rows"].items():
            if row_id not in uses or uses[row_id]["authority"]["exact_locators"] != locators:
                raise ValueError("held9_held_locator_mismatch")
        result.append(
            {
                "label": spec["label"],
                "proposal_id": spec["proposal_id"],
                "proposal_content_sha256": spec["proposal_content_sha256"],
                "old_record_id": spec["old_record_id"],
                "repair_hold_content_sha256": spec["repair_hold_content_sha256"],
                "affected_rows_and_excluded_locators": spec["affected_rows"],
                "representation_excluded": True,
                "source_admission_authorized": False,
                "source_admitted": False,
                "currentness_hold_retained": True,
                "later_treatment_hold_retained": True,
                "legal_rule_release_prohibited": True,
            }
        )
    return sorted(result, key=lambda item: str(item["proposal_id"]))


def _verify_and_make_survivors(
    original: Mapping[str, Any], audit: Mapping[str, Any], delta: Mapping[str, Any]
) -> list[dict[str, Any]]:
    proposals = _exact_index(
        original["proposed_new_source_admissions"], "proposal_id", code="held9_proposals"
    )
    audits = _exact_index(audit["records"], "proposal_id", code="held9_audits")
    retained = _exact_index(
        delta["retained_original_passing_representations"],
        "original_proposal_id",
        code="held9_retained",
    )
    result: list[dict[str, Any]] = []
    for spec in SURVIVOR_SPECS:
        proposal = proposals[str(spec["proposal_id"])]
        audit_record = audits[str(spec["proposal_id"])]
        retained_record = retained[str(spec["proposal_id"])]
        binding = proposal["quarantine_representation_binding"]["selected_admission_binding"]
        expected_binding = {
            "proposed_source_version_id": spec["source_version_id"],
            "raw_sha256": spec["raw_sha256"],
            "canonical_content_sha256": spec["canonical_content_sha256"],
            "record_content_sha256": spec["binding_record_content_sha256"],
        }
        if proposal.get("proposal_content_sha256") != spec["proposal_content_sha256"]:
            raise ValueError("held9_survivor_proposal_digest_mismatch")
        if any(binding.get(key) != value for key, value in expected_binding.items()):
            raise ValueError("held9_survivor_binding_mismatch")
        expected_audit = {
            "record_content_sha256": spec["audit_record_content_sha256"],
            "substantive_content_verdict": spec["audit_verdict"],
            "warning_reason_codes": spec["audit_warning_reason_codes"],
            "raw_sha256": spec["raw_sha256"],
            "proposed_source_version_id": spec["source_version_id"],
        }
        if any(audit_record.get(key) != value for key, value in expected_audit.items()):
            raise ValueError("held9_survivor_audit_mismatch")
        expected_retained = {
            "original_proposal_content_sha256": spec["proposal_content_sha256"],
            "original_proposed_source_version_id": spec["source_version_id"],
            "original_raw_sha256": spec["raw_sha256"],
            "original_record_content_sha256": spec["binding_record_content_sha256"],
            "audit_record_content_sha256": spec["audit_record_content_sha256"],
            "audit_verdict": spec["audit_verdict"],
        }
        if any(retained_record.get(key) != value for key, value in expected_retained.items()):
            raise ValueError("held9_survivor_delta_mismatch")
        uses = {}
        for use in proposal["uses"]:
            uses.setdefault(str(use["row_id"]), []).append(use)
        for row_id, locators in spec["row_locators"].items():
            if spec.get("cross_row_candidate_only"):
                original_row = str(spec["original_approved_packet_row_id"])
                matches = uses.get(original_row, [])
            else:
                matches = uses.get(row_id, [])
            exact = [locator for item in matches for locator in item["authority"]["exact_locators"]]
            if locators != exact:
                raise ValueError("held9_survivor_locator_mismatch")
        item = {
            "label": spec["label"],
            "proposal_id": spec["proposal_id"],
            "proposal_content_sha256": spec["proposal_content_sha256"],
            "proposed_source_version_id": spec["source_version_id"],
            "raw_sha256": spec["raw_sha256"],
            "canonical_content_sha256": spec["canonical_content_sha256"],
            "binding_record_content_sha256": spec["binding_record_content_sha256"],
            "audit_record_content_sha256": spec["audit_record_content_sha256"],
            "audit_verdict": spec["audit_verdict"],
            "audit_warning_reason_codes": spec["audit_warning_reason_codes"],
            "row_locator_bindings": spec["row_locators"],
            "source_admission_authorized": False,
            "source_admitted": False,
        }
        if spec.get("cross_row_candidate_only"):
            item.update(
                {
                    "original_approved_packet_row_id": spec["original_approved_packet_row_id"],
                    "cross_row_candidate_only": True,
                    "cross_row_owner_decision_required": True,
                    "currentness_hold_retained": True,
                    "later_treatment_hold_retained": True,
                    "legal_rule_release_prohibited": True,
                }
            )
        result.append(item)
    return sorted(result, key=lambda item: str(item["proposal_id"]))


def _verify_and_make_candidate_sources(candidate: Mapping[str, Any]) -> list[dict[str, Any]]:
    sources = _exact_index(
        candidate["sources"], "source_version_id", code="held9_candidate_sources"
    )
    result: list[dict[str, Any]] = []
    for spec in CANDIDATE_SOURCE_SPECS:
        source = sources[str(spec["source_version_id"])]
        expected = {
            "authority_identity_id": spec["authority_identity_id"],
            "content_sha256": spec["content_sha256"],
            "version_sha256": spec["content_sha256"],
            "title": spec["label"],
        }
        if any(source.get(key) != value for key, value in expected.items()):
            raise ValueError("held9_candidate_source_mismatch")
        result.append(
            {
                **spec,
                "candidate_manifest_sha256": EXPECTED_INPUTS["candidate"]["content_sha256"],
                "candidate_existing": True,
            }
        )
    return sorted(result, key=lambda item: str(item["source_version_id"]))


def _make_defective_exclusions(delta: Mapping[str, Any]) -> list[dict[str, Any]]:
    rejected = delta["rejected_defective_original_representations"]
    if len(rejected) != 16:
        raise ValueError("held9_defective_representation_count_mismatch")
    result = []
    for item in rejected:
        if item.get("audit_verdict") != "FAIL":
            raise ValueError("held9_defective_representation_not_fail")
        result.append(
            {
                "original_proposal_id": item["original_proposal_id"],
                "original_proposal_content_sha256": item["original_proposal_content_sha256"],
                "original_source_version_id": item["original_proposed_source_version_id"],
                "original_raw_sha256": item["original_raw_sha256"],
                "original_binding_record_content_sha256": item["original_record_content_sha256"],
                "audit_record_content_sha256": item["audit_record_content_sha256"],
                "audit_failure_reason_codes": item["audit_failure_reason_codes"],
                "excluded": True,
                "source_admission_authorized": False,
                "source_admitted": False,
            }
        )
    return sorted(result, key=lambda item: str(item["original_proposal_id"]))


def _privacy_check(values: Sequence[Any]) -> None:
    def walk(value: Any) -> None:
        if isinstance(value, Mapping):
            for key, nested in value.items():
                walk(str(key))
                walk(nested)
        elif isinstance(value, list | tuple):
            for nested in value:
                walk(nested)
        elif isinstance(value, str):
            lowered = value.casefold()
            if (
                "/users/" in lowered
                or "hltsang" in lowered
                or "legalbot-new" in lowered
                or "file://" in lowered
                or value.startswith(("~/", "~\\"))
                or _EMAIL.search(value)
            ):
                raise ValueError("held9_privacy_violation")

    walk(list(values))


def _verify_no_execution_flags(value: Any) -> None:
    def walk(nested: Any) -> None:
        if isinstance(nested, Mapping):
            for key, item in nested.items():
                if key in _NO_EXECUTION_FLAG_NAMES and item is not False:
                    raise ValueError("held9_execution_flag_not_false")
                walk(item)
        elif isinstance(nested, list | tuple):
            for item in nested:
                walk(item)

    walk(value)


def _input_bindings() -> list[dict[str, str]]:
    rows = (
        ("original", ORIGINAL_ROOT_NAME, ORIGINAL_NAME),
        ("audit", AUDIT_ROOT_NAME, AUDIT_NAME),
        ("delta", DELTA_ROOT_NAME, DELTA_NAME),
        ("candidate", CANDIDATE_ROOT_NAME, CANDIDATE_NAME),
    )
    return [
        {
            "kind": kind,
            "root_name": root_name,
            "file_name": file_name,
            "content_sha256": EXPECTED_INPUTS[kind]["content_sha256"],
            "file_sha256": EXPECTED_INPUTS[kind]["file_sha256"],
        }
        for kind, root_name, file_name in rows
    ]


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


def _publish_directory_noreplace(staging: Path, output: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    source = os.fsencode(staging)
    target = os.fsencode(output)
    if sys.platform == "darwin" and hasattr(libc, "renamex_np"):
        function = libc.renamex_np
        function.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        function.restype = ctypes.c_int
        result = function(source, target, 0x00000004)  # RENAME_EXCL
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        function = libc.renameat2
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
        result = function(-100, source, -100, target, 0x00000001)  # RENAME_NOREPLACE
    else:
        raise RuntimeError("held9_atomic_noreplace_unavailable")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise ValueError("held9_output_already_exists")
    raise OSError(error_number, "held9_atomic_publish_failed")


def _ensure_output_path(output_root: Path) -> Path:
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("held9_output_already_exists")
    review = OUTPUT_REVIEW_ROOT.resolve(strict=True)
    parent = output_root.parent.resolve(strict=True)
    resolved = parent / output_root.name
    if not output_root.name or not resolved.is_relative_to(review):
        raise ValueError("held9_output_outside_review_root")
    return resolved


def build_advisory(*, output_root: Path, created_at: datetime | None = None) -> dict[str, Any]:
    """Create and atomically publish one immutable advisory package."""

    output = _ensure_output_path(output_root)
    timestamp = created_at or datetime.now(UTC)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("held9_created_at_must_be_aware")
    original, audit, delta, candidate = _verify_inputs()
    held_sources = _verify_and_make_holds(original, delta)
    survivors = _verify_and_make_survivors(original, audit, delta)
    candidate_sources = _verify_and_make_candidate_sources(candidate)
    defective = _make_defective_exclusions(delta)
    row_ids = [str(item["row_id"]) for item in ROW_OUTCOMES]
    if len(row_ids) != 9 or len(set(row_ids)) != 9:
        raise ValueError("held9_row_set_invalid")
    if sum(item["question_kind"] == "ESSAY" for item in ROW_OUTCOMES) != 7:
        raise ValueError("held9_essay_count_invalid")
    if any(
        not item["safe_fallback_prohibited"]
        for item in ROW_OUTCOMES
        if item["question_kind"] == "ESSAY"
    ):
        raise ValueError("held9_essay_fallback_not_prohibited")

    no_execution_flags = {name: False for name in _NO_EXECUTION_FLAG_NAMES}
    advisory: dict[str, Any] = {
        "schema": "legalbot.v111.phase2a.held9-surviving-support-advisory.v1",
        "status": "SEALED_ADVISORY_ONLY_NO_PRODUCTION_STATE",
        "route": "OWNER_REVIEW_ONLY_NO_DECISION_NO_EXECUTION",
        "created_at": timestamp.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "input_bindings": _input_bindings(),
        "scope": {
            "exact_row_count": 9,
            "exact_row_ids": sorted(row_ids),
            "held_proposal_count": 5,
            "defective_representation_count": 16,
            "surviving_audit_pass_or_warning_proposal_count": len(survivors),
            "existing_candidate_source_count": len(candidate_sources),
            "audit_pass_original_universe_count": 231,
        },
        "five_unresolved_held_proposals": held_sources,
        "sixteen_defective_original_representations_excluded": defective,
        "surviving_pass_or_pass_with_warning_representations": survivors,
        "surviving_existing_candidate_sources": candidate_sources,
        "row_outcomes": sorted(ROW_OUTCOMES, key=lambda item: str(item["row_id"])),
        "interpretation_contract": {
            "supported_subset_is_not_a_pass": True,
            "essay_safe_fallback_prohibited": True,
            "fact_fallback_must_release_no_material_legal_claim": True,
            "fallback_must_not_hide_legal_knowledge_or_source_gap": True,
            "wuhan_cross_row_candidate_is_not_an_owner_decision": True,
            "wuhan_currentness_and_later_treatment_holds_retained": True,
            "no_source_or_span_becomes_releasable_by_this_advisory": True,
        },
        "no_execution_flags": no_execution_flags,
        "no_replace_contract": {
            "create_only": True,
            "atomic_directory_publish": True,
            "existing_output_refused": True,
            "earlier_artifacts_unchanged": True,
        },
        "privacy_contract": {
            "absolute_source_paths_in_output": False,
            "owner_identifiers_in_output": False,
            "personal_filenames_in_output": False,
            "source_bytes_in_output": False,
            "source_text_in_output": False,
        },
        "not_owner_decision": True,
        "not_source_admission": True,
        "not_legal_currentness_certification": True,
        "not_later_treatment_certification": True,
        "not_qualification_result": True,
    }
    _verify_no_execution_flags(advisory)
    _privacy_check([advisory])
    advisory["artifact_content_sha256"] = _sealed(advisory)
    advisory_raw = _pretty_json(advisory)
    advisory_file_sha256 = _sha256(advisory_raw)

    package: dict[str, Any] = {
        "schema": "legalbot.v111.phase2a.held9-surviving-support-package.v1",
        "status": "SEALED_ADVISORY_ONLY_NO_PRODUCTION_STATE",
        "created_at": advisory["created_at"],
        "advisory": {
            "file_name": ADVISORY_NAME,
            "artifact_content_sha256": advisory["artifact_content_sha256"],
            "file_sha256": advisory_file_sha256,
        },
        "checksums_file_name": CHECKSUMS_NAME,
        "no_execution_flags": no_execution_flags,
        "no_replace_contract": advisory["no_replace_contract"],
        "privacy_contract": advisory["privacy_contract"],
    }
    _verify_no_execution_flags(package)
    _privacy_check([package])
    package["package_content_sha256"] = _sealed(package)
    package_raw = _pretty_json(package)
    package_file_sha256 = _sha256(package_raw)
    checksums_raw = (
        f"{advisory_file_sha256}  {ADVISORY_NAME}\n{package_file_sha256}  {PACKAGE_NAME}\n"
    ).encode()

    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    os.chmod(staging, 0o700)
    try:
        _write_exclusive(staging / ADVISORY_NAME, advisory_raw)
        _write_exclusive(staging / PACKAGE_NAME, package_raw)
        _write_exclusive(staging / CHECKSUMS_NAME, checksums_raw)
        directory_fd = os.open(staging, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        _publish_directory_noreplace(staging, output)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return {
        "output_root": output,
        "advisory_content_sha256": advisory["artifact_content_sha256"],
        "advisory_file_sha256": advisory_file_sha256,
        "package_content_sha256": package["package_content_sha256"],
        "package_file_sha256": package_file_sha256,
        "checksums_file_sha256": _sha256(checksums_raw),
    }


def _parse_created_at(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise argparse.ArgumentTypeError("--created-at must include a UTC offset")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--created-at", type=str)
    args = parser.parse_args()
    result = build_advisory(
        output_root=args.output_root,
        created_at=_parse_created_at(args.created_at),
    )
    print(
        json.dumps(
            {
                key: str(value) if isinstance(value, Path) else value
                for key, value in result.items()
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
