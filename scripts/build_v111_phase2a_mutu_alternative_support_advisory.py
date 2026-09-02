#!/usr/bin/env python3
"""Build the fail-closed Mutu/Pechstein alternative-support advisory.

The builder performs a read-only, deterministic audit of the two Phase-2A
essay rows affected by the final Mutu/Pechstein transport hold.  It verifies
the three changed single-attempt recovery holds, the original exact owner
packet, audited local representations, the held-nine advisory and exact
candidate chunks.  It does not fetch, retry, admit, scan, build, embed,
qualify, invoke a model, write a pointer or authorize any later phase.
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

import lancedb

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.retrieval.ge_generic_read_guard import (  # noqa: E402
    require_generic_index_read_allowed,
)

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
HELD9_ROOT_NAME = "LegalBot-Phase2A-2026-08-28-held9-surviving-support-advisory-r1"
HELD9_NAME = "HELD9-SURVIVING-SUPPORT-ADVISORY.json"
HELD9_PATH = REVIEW_ROOT / HELD9_ROOT_NAME / HELD9_NAME
CANDIDATE_ROOT_NAME = "current-law-ew-full-fp16-v111-20260827-phase2a-a"
CANDIDATE_ROOT = PROJECT_ROOT / "data/indexes/builds" / CANDIDATE_ROOT_NAME
CANDIDATE_NAME = "approved-source-manifest.json"
CANDIDATE_PATH = CANDIDATE_ROOT / CANDIDATE_NAME

RECOVERY_ROOT_NAMES = {
    revision: f"LegalBot-Phase2A-2026-08-28-echr-held-source-recovery-quarantine-{revision}"
    for revision in ("r1", "r2", "r3")
}
RECOVERY_NAME = "ECHR-RECOVERY-QUARANTINE-MANIFEST.json"
RECOVERY_PATHS = {
    revision: REVIEW_ROOT / root_name / RECOVERY_NAME
    for revision, root_name in RECOVERY_ROOT_NAMES.items()
}

DEFAULT_OUTPUT_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-mutu-alternative-support-advisory-r1"
)
ADVISORY_NAME = "MUTU-ALTERNATIVE-SUPPORT-ADVISORY.json"
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
    "held9": {
        "content_sha256": "599d7175005c8978757611be0ce837299845c142147ec02828f53ee7620e75fd",
        "file_sha256": "2fe8eb506bce8ba455b7dea69d21927bba8fb54e242dba81c4287096a6535ef1",
    },
    "candidate": {
        "content_sha256": "b304ab1223987bf9b57d3e2560413b2f325c16213ae0071a45dface2e10dc206",
        "file_sha256": "0bbb1edb169c84a26e5f1d42e367f9e2f83fcdd9c652a9061980652f15979b21",
    },
    "recovery_r1": {
        "content_sha256": "9c69a31c27e5b8b1e6c915d354ee921417d0a439b62047cb1c2bf4f02a2458b4",
        "file_sha256": "858f08d5a7d2858f8b1895451b06c41be4e04a0f2a936f0009ccfe3f68505c1d",
    },
    "recovery_r2": {
        "content_sha256": "c6672a3f227b9a518ac628861bc1bcaf361d9c29968f20c490f27d3f34592145",
        "file_sha256": "e7f23bbe8219370f24ae86e3dab7356bab6ad90fc8a405c92ee1b06f8bd74879",
    },
    "recovery_r3": {
        "content_sha256": "f5beba682a629d3a6e0e79be374c0d2a3d6690d45abe467fa40f67879dcb0142",
        "file_sha256": "c2682917d3f2dbc7cc701ad63ff98552eeb0e0398a85503b4b55a12c72b78471",
    },
}

ROW_SPECS = {
    "live60-q53:issue-04": {
        "decision_content_sha256": (
            "592cdc175782d002c0fb3ba96c51ade615790a6df83d7ab781eec610b8fdf8d2"
        ),
        "proposition_record_content_sha256": (
            "da5c30e78778d03275cb1bc8c5e4fa3e827491cd81826d030d4883166e502d12"
        ),
        "queue_record_content_sha256": (
            "db0662b93814e4b06e21498685ee11d84dde3d13ddff3691a434e71802546787"
        ),
        "components": (
            {
                "component_ordinal": 1,
                "proposition": (
                    "An internal sporting sanction must first comply with the governing "
                    "contract and incorporated rules. Where those rules confer a contractual "
                    "discretion, good faith, contractual purpose and rational consideration of "
                    "relevant matters may constrain its exercise; that does not by itself "
                    "establish a free-standing proportionality jurisdiction or permit the court "
                    "to substitute the merits decision."
                ),
                "original_support_fit": "PARTIAL",
                "alternative_support_outcome": "SUPPORTED_ONLY_TO_ORIGINAL_PARTIAL_SCOPE",
                "support_refs": ("braganza",),
                "unsupported_claims": (
                    "A free-standing proportionality test for every internal sporting sanction.",
                ),
            },
            {
                "component_ordinal": 2,
                "proposition": (
                    "For arbitration governed by the 1996 Act, the tribunal must act fairly and "
                    "impartially, give each party a reasonable opportunity to put its case and "
                    "deal with the opponent's case, and adopt procedures avoiding unnecessary "
                    "delay or expense. A section 68 challenge additionally requires a listed "
                    "serious irregularity causing substantial injustice."
                ),
                "original_support_fit": "FULL",
                "alternative_support_outcome": "FULLY_SUPPORTED_WITHIN_ENGLISH_ACT_SCOPE",
                "support_refs": ("arbitration_act_1996",),
                "unsupported_claims": (),
            },
            {
                "component_ordinal": 3,
                "proposition": (
                    "CAS appeal panels have full power to review facts and law and may replace, "
                    "annul or remit the challenged decision. Convention scrutiny remains "
                    "distinct: Mutu and Pechstein treated Pechstein's arbitration as compulsory, "
                    "found no majority-established structural independence violation on the "
                    "evidence, but found an Article 6 violation because her fact-heavy, stigmatic "
                    "doping case was not heard in public despite her request."
                ),
                "original_support_fit": "FULL",
                "alternative_support_outcome": "PARTIAL_MECHANICS_ONLY_IRREDUCIBLE_ECHR_GAP",
                "support_refs": ("cas_code",),
                "unsupported_claims": (
                    "Pechstein's submission was compulsory for Convention-waiver analysis.",
                    "The majority finding on CAS structural independence in that case.",
                    "The Article 6 public-hearing violation on the Pechstein facts.",
                ),
            },
        ),
    },
    "live60-q53:issue-11": {
        "decision_content_sha256": (
            "efac2d0ba6e06f8db30643f041bc080526ec1ffe56d970315c489faf5de35bc6"
        ),
        "proposition_record_content_sha256": (
            "64f61f27c6707837279bbf8256e10a6196619ae65493d110e928de1718ebf2f3"
        ),
        "queue_record_content_sha256": (
            "cee5e1243d421d2b15425a9ba743316f850abbd44f029094deadd341d01a2e89"
        ),
        "components": (
            {
                "component_ordinal": 1,
                "proposition": (
                    "Sporting autonomy through CAS is agreement- and rules-based: the Code "
                    "defines jurisdiction, internal-remedy exhaustion, merits review and finality, "
                    "while expressly locating CAS at a Swiss seat and preserving the limited "
                    "recourse available under Swiss law. Expertise and consistency therefore "
                    "coexist with externally defined procedural limits."
                ),
                "original_support_fit": "FULL",
                "alternative_support_outcome": "FULLY_SUPPORTED_AS_RULE_TEXT_NOT_SWISS_LAW_DETAIL",
                "support_refs": ("cas_code",),
                "unsupported_claims": (
                    "The content of Swiss supervisory law beyond the recourse preserved by R59.",
                ),
            },
            {
                "component_ordinal": 2,
                "proposition": (
                    "Within the 1996 Act's scope, party autonomy and limited court intervention "
                    "operate alongside the tribunal's mandatory fairness duty and defined court "
                    "controls for jurisdiction, serious irregularity and qualifying points of law. "
                    "The Act also preserves non-arbitrability rules and permits refusal to enforce "
                    "a Convention award where the subject matter is non-arbitrable or enforcement "
                    "would offend public policy."
                ),
                "original_support_fit": "FULL",
                "alternative_support_outcome": "FULLY_SUPPORTED_WITHIN_ENGLISH_ACT_SCOPE",
                "support_refs": ("arbitration_act_1996",),
                "unsupported_claims": (),
            },
            {
                "component_ordinal": 3,
                "proposition": (
                    "Sporting autonomy does not itself answer procedural-rights questions. Where "
                    "submission is effectively compulsory rather than a free and unequivocal "
                    "waiver, Convention safeguards may apply to the arbitral process and the "
                    "adequacy of state-court supervision; the required safeguard remains issue- "
                    "and fact-specific."
                ),
                "original_support_fit": "FULL",
                "alternative_support_outcome": "IRREDUCIBLE_ECHR_AND_SWISS_SUPERVISION_GAP",
                "support_refs": (),
                "unsupported_claims": (
                    "Compulsory submission versus free and unequivocal Convention waiver.",
                    "Convention safeguards applicable to the CAS process.",
                    "Adequacy of Swiss state-court supervision on the relevant facts.",
                ),
            },
        ),
    },
}

PROPOSAL_SOURCE_SPECS = {
    "braganza": {
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
        "warning_reason_codes": (),
        "row_locators": {"live60-q53:issue-04": ("paras 18-31",)},
    },
    "cas_code": {
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
        "warning_reason_codes": ("TAS_NOISY_SEARCH_OVERLAY_RULE_BODY_PRESENT",),
        "row_locators": {
            "live60-q53:issue-04": ("R47", "R57"),
            "live60-q53:issue-11": ("R27", "R47", "R57", "R59"),
        },
    },
}

CANDIDATE_SOURCE_SPECS = {
    "arbitration_act_1996": {
        "label": "Arbitration Act 1996",
        "authority_identity_id": "ukpga:1996:23",
        "source_version_id": "source-version-59a8ac0ed35ad09bb4ea9520c6bddd3110a78cf8",
        "content_sha256": "2d395c8b88c15104758839b7e586816c67b344fda9def5e091384d4cb1a96eea",
        "row_locators": {
            "live60-q53:issue-04": ("section 33", "section 68"),
            "live60-q53:issue-11": (
                "section 1",
                "section 33",
                "sections 67-70",
                "section 81(1)(a)",
                "section 103(3)",
            ),
        },
    },
    "human_rights_act_1998": {
        "label": "Human Rights Act 1998",
        "authority_identity_id": "ukpga:1998:42",
        "source_version_id": "source-version-a7765ef20ffc9826c4dddc430c61d9077e85b4f1",
        "content_sha256": "3dd5c55b447935d62c359180f34a0a2932272554c5c62d27dc27aec17e1f01c8",
        "row_locators": {},
    },
}

ARBITRATION_ACT_CHUNKS = (
    (
        "chunk-881a7c9fd26cb763d4446f8ee9939d6b02d00f21",
        "section 33",
        "13122f0d261e21b439db31b9fcc07527db1ccae20e3722fd8ae3dcf4503e3820",
    ),
    (
        "chunk-2d153ea8c4d66d9ba278d28d0b5e8cffe138719f",
        "section 33",
        "23397585762b9f940485e17e6636d9e04ad8920f23fd98aa23a8a5936e616b6f",
    ),
    (
        "chunk-cd659e5b74c2e8ca96cfaab6c16a534cb315c348",
        "section 33",
        "0a30df8435ee48f85fa9c996a60111a2f10ba72aaab641c3e2a82b9a135a924b",
    ),
    (
        "chunk-dbbbdb902c3b57efd830df7cd18495fd34458cad",
        "section 68",
        "0b02dde2ae755661ec82b20e8c52ede249f413fc9b57a3dbf58be1e29f291b53",
    ),
    (
        "chunk-7a6d54fcac9cd7853927523bb814f8cd265082c0",
        "section 68",
        "55846d5cafb4dd656edc177167dc3c41463717980249a14a0925fa912188c68c",
    ),
    (
        "chunk-2e21c6d22243c49088e02a0ad594d705a8450feb",
        "section 68",
        "870cd5bcbb4ecf371ecd05dc50853aa5840f30fa0c140a176c018496d216e00d",
    ),
    (
        "chunk-c18339963e6c84c4ca35b487600679bc31ad9b54",
        "section 1",
        "af44aa36cbf7031b0d83bda921ef3ba84e6ccc25b3e3a08fa87a6f893201f0d4",
    ),
    (
        "chunk-f8a32419cd15e1430e3d3124f0a1964268be0c15",
        "section 1",
        "fa17850343e0e53a66c414f1beb6cf1cabcec80a0074abaedb664ce3270a7f9c",
    ),
    (
        "chunk-006d307618137dcb0389ae77ec0416a2aa767111",
        "section 1",
        "c9472a1ee7c2585be3f133f1b8c41edad347a2477ff5525bd6100fe2814db943",
    ),
    (
        "chunk-c93bfc672aee57a04eb11bef3451af7d83bade78",
        "section 67",
        "d45a04731515cf1bd26a6d865fd05dd3c09ac4f7d12fbb01f06ca4c3128f4258",
    ),
    (
        "chunk-19067e2106a9448964bae359419676af320791bf",
        "section 67",
        "9bdb9c9960496e74ec9347e2600cf6a20eaffa0e36ff3995bd9ab97f39bd73cf",
    ),
    (
        "chunk-81e321df469cdd6b2168dd0bc71555cbd72b6794",
        "section 69",
        "85c7cbba5451e7aea82579a94dfa464b651bef6c0457eba557a9cba8e6f0ac03",
    ),
    (
        "chunk-3e584b2004a4e9c3c7b016bcf1add9b706a59e5e",
        "section 70",
        "ccfab663b6b619369be62cbc552557a7fcc5978b72138f7fd95f2a1ac4718157",
    ),
    (
        "chunk-dce34b435d40bc64046252b9fb7b60c129db012a",
        "section 70",
        "221794c0cfc6cbb01c1bce502914e093eef37be23ad81fec2bb4a5c69bfd8f84",
    ),
    (
        "chunk-ecb4169db58310edb2cee41441d49de8170e96db",
        "section 81",
        "73c5f543a8a156a86e91205ff6b48022552c18f203c4219e866ed2a9808f87f8",
    ),
    (
        "chunk-339dcbaef77319258af054401d502cc810584978",
        "section 81",
        "8cb3ce046b6682aaaf7e2c5cc41f1219c92eb1ad3e76140fd9b963f04eef6c28",
    ),
    (
        "chunk-36641f827701f78884b7af2d8abebf3a635b3733",
        "section 81",
        "414c56dbbba63c6d34893ef38ef532bf7106193cac1335d7a22f29389408b358",
    ),
    (
        "chunk-8631cd562827633f09926dc61d58fae81fb9548e",
        "section 103",
        "06c69374e9453b73e7285be71a7674055fb1f873e5094db53182adebd1880097",
    ),
    (
        "chunk-1344449eecdbad197da3d9014ed252751bc69b4b",
        "section 103",
        "b922ba00de163d3d21e6b985b7a71614e8f6adac5cf0165550057777a9cb368b",
    ),
)

RECOVERY_HOLD_SPECS = {
    "r1": {
        "attempt_identity_sha256": "5bbbd361f020fbf6d9099e6d5c32b24b10292837c44cae1c40e94ab61518c24d",
        "failure_fingerprint": "c69cbd8cb04b90c507d8346606c8adb06532e26731dea997fc92f50cd7f88312",
        "hold_content_sha256": "51eb5fb20986775c11dc49cb9ed9e385cecd334d502baa2ecdc7fa44880dee94",
        "exception_type": "RemoteDisconnected",
        "error": "Remote end closed connection without response",
    },
    "r2": {
        "attempt_identity_sha256": "113c516e044e77ccd78cd6c61dcec75a7369a841fab34a7ddb023de9bc0a889a",
        "failure_fingerprint": "7b58dd60d56491eee1547e5de83b88e028248ad74d167adb7cadd13937a94180",
        "hold_content_sha256": "0b04d291cda5d468f9d31f7ea1da8aa0cda6d4488bfe2894464eb70879615fcf",
        "exception_type": "RemoteDisconnected",
        "error": "Remote end closed connection without response",
    },
    "r3": {
        "attempt_identity_sha256": "86517dd2d35137e5dfd3ed7918161efaa26174e9231806b2cf14df3452443c61",
        "failure_fingerprint": "cd73206a613336d1790a6b8c2db5aab2e621dda9206ed3decf20f22a9034924c",
        "hold_content_sha256": "9bce887cef120efcc310aafe157261d1c7f62b6ca52d2d6d77cb5dc4b62f13f6",
        "exception_type": "RuntimeError",
        "error": "phase2a_echr_curl_exit_52:curl: (52) Empty reply from server",
    },
}

MUTU_PROPOSAL_SPEC = {
    "proposal_id": "proposed-source-78183f51ee77b79b9410687b",
    "proposal_content_sha256": "f2069984901ebe5a25e50d459228ab8b4b4bf72c3f7580a881112f9a6779a968",
    "source_version_id": "proposed-source-version-453931559c06d9a4854464f50247caf6b2ecd9d4",
    "raw_sha256": "1a216c3bea23ac75585b5815abe65bdfce0cffa9e1cd06db4a8d73935c3447fa",
    "binding_record_content_sha256": "06f24cd7da8767dc09366a11da903cfc6d291548c2c4e370dda6a71c5785c980",
    "audit_record_content_sha256": "f0e5e4d6eea18a10613a52bdee75bda6c6dda4c1b1cd8442b7c0f0c7a2475179",
    "old_record_id": "quarantine-binding-3688eea8275753b9dcabf559",
    "delta_repair_hold_content_sha256": "340880903c2d176a4a8f59e69de3abdac0d2eb18f6b153b9c0f1f448cf088598",
    "exact_locators": ("paras 95-123", "paras 138-168", "paras 169-184", "paras 172-184"),
}

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
    "mutu_fetch_run",
    "mutu_retry_run",
    "transport_call_run",
)

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


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
    supplied = str(value.get(seal_field, ""))
    if source_manifest_identity_mode:
        material = {
            key: item for key, item in value.items() if key not in {"created_at", seal_field}
        }
        computed = _sha256(_pretty_json(material))
    else:
        material = dict(value)
        material.pop(seal_field, None)
        computed = _sealed(material)
    if supplied != expected_content_sha256 or supplied != computed:
        raise ValueError(f"{code}_seal_mismatch")
    return value


def _verify_inputs() -> dict[str, dict[str, Any]]:
    inputs = {
        "original": _load_exact(
            ORIGINAL_PATH,
            expected_file_sha256=EXPECTED_INPUTS["original"]["file_sha256"],
            seal_field="artifact_content_sha256",
            expected_content_sha256=EXPECTED_INPUTS["original"]["content_sha256"],
            code="mutu_original",
        ),
        "audit": _load_exact(
            AUDIT_PATH,
            expected_file_sha256=EXPECTED_INPUTS["audit"]["file_sha256"],
            seal_field="artifact_content_sha256",
            expected_content_sha256=EXPECTED_INPUTS["audit"]["content_sha256"],
            code="mutu_audit",
        ),
        "delta": _load_exact(
            DELTA_PATH,
            expected_file_sha256=EXPECTED_INPUTS["delta"]["file_sha256"],
            seal_field="artifact_content_sha256",
            expected_content_sha256=EXPECTED_INPUTS["delta"]["content_sha256"],
            code="mutu_delta",
        ),
        "held9": _load_exact(
            HELD9_PATH,
            expected_file_sha256=EXPECTED_INPUTS["held9"]["file_sha256"],
            seal_field="artifact_content_sha256",
            expected_content_sha256=EXPECTED_INPUTS["held9"]["content_sha256"],
            code="mutu_held9",
        ),
        "candidate": _load_exact(
            CANDIDATE_PATH,
            expected_file_sha256=EXPECTED_INPUTS["candidate"]["file_sha256"],
            seal_field="manifest_sha256",
            expected_content_sha256=EXPECTED_INPUTS["candidate"]["content_sha256"],
            code="mutu_candidate",
            source_manifest_identity_mode=True,
        ),
    }
    for revision in ("r1", "r2", "r3"):
        key = f"recovery_{revision}"
        inputs[key] = _load_exact(
            RECOVERY_PATHS[revision],
            expected_file_sha256=EXPECTED_INPUTS[key]["file_sha256"],
            seal_field="manifest_content_sha256",
            expected_content_sha256=EXPECTED_INPUTS[key]["content_sha256"],
            code=f"mutu_{key}",
        )
    return inputs


def _index(
    values: Sequence[Mapping[str, Any]], key: str, code: str
) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for value in values:
        identity = str(value.get(key, ""))
        if not identity or identity in result:
            raise ValueError(code)
        result[identity] = value
    return result


def _verify_recovery_holds(inputs: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for revision in ("r1", "r2", "r3"):
        manifest = inputs[f"recovery_{revision}"]
        matches = [
            item
            for item in manifest["holds"]
            if item.get("old_record_id") == MUTU_PROPOSAL_SPEC["old_record_id"]
        ]
        if len(matches) != 1:
            raise ValueError("mutu_recovery_hold_missing")
        hold = matches[0]
        spec = RECOVERY_HOLD_SPECS[revision]
        expected = {
            **spec,
            "attempt_count": 1,
            "retry_run": False,
            "hold_retained": True,
            "affected_row_ids": sorted(ROW_SPECS),
            "reason_code": "OFFICIAL_HUDOC_RECOVERY_SINGLE_CHANGED_PATH_ATTEMPT_FAILED",
        }
        if any(hold.get(key) != value for key, value in expected.items()):
            raise ValueError("mutu_recovery_hold_mismatch")
        result.append(
            {
                "revision": revision,
                "manifest_content_sha256": EXPECTED_INPUTS[f"recovery_{revision}"][
                    "content_sha256"
                ],
                "manifest_file_sha256": EXPECTED_INPUTS[f"recovery_{revision}"]["file_sha256"],
                **spec,
                "attempt_count": 1,
                "retry_run": False,
                "hold_retained": True,
            }
        )
    if len({item["attempt_identity_sha256"] for item in result}) != 3:
        raise ValueError("mutu_recovery_attempt_identity_not_distinct")
    return result


def _verify_rows(original: Mapping[str, Any]) -> list[dict[str, Any]]:
    decisions = _index(original["decisions"], "row_id", "mutu_duplicate_row")
    result = []
    for row_id, spec in ROW_SPECS.items():
        decision = decisions[row_id]
        research = decision["source_research_record"]
        expected = {
            "decision_content_sha256": spec["decision_content_sha256"],
            "owner_decision_required": True,
            "owner_outcome": None,
            "source_admission_authorized": False,
            "source_admitted": False,
            "technical_qualification_assigned": False,
        }
        if any(decision.get(key) != value for key, value in expected.items()):
            raise ValueError("mutu_row_decision_mismatch")
        if (
            research.get("proposition_record_content_sha256")
            != spec["proposition_record_content_sha256"]
            or research.get("queue_record_content_sha256") != spec["queue_record_content_sha256"]
        ):
            raise ValueError("mutu_row_record_digest_mismatch")
        original_components = research["atomic_components"]
        if len(original_components) != len(spec["components"]):
            raise ValueError("mutu_component_count_mismatch")
        components = []
        for expected_component, actual_component in zip(
            spec["components"], original_components, strict=True
        ):
            if (
                actual_component.get("proposition") != expected_component["proposition"]
                or actual_component.get("support_fit") != expected_component["original_support_fit"]
            ):
                raise ValueError("mutu_component_identity_mismatch")
            components.append(
                {
                    **expected_component,
                    "support_refs": list(expected_component["support_refs"]),
                    "unsupported_claims": list(expected_component["unsupported_claims"]),
                    "proposition_content_sha256": _sealed(
                        {"proposition": expected_component["proposition"]}
                    ),
                }
            )
        result.append(
            {
                "row_id": row_id,
                "question_kind": "ESSAY",
                "decision_content_sha256": spec["decision_content_sha256"],
                "proposition_record_content_sha256": spec["proposition_record_content_sha256"],
                "queue_record_content_sha256": spec["queue_record_content_sha256"],
                "row_outcome": "IRREDUCIBLE_LEGAL_AUTHORITY_BLOCKER",
                "row_proposition_complete": False,
                "safe_fallback_eligible": False,
                "safe_fallback_prohibited": True,
                "owner_decision_required": True,
                "technical_qualification_assigned": False,
                "components": components,
            }
        )
    return result


def _verify_proposal_sources(
    original: Mapping[str, Any], audit: Mapping[str, Any], delta: Mapping[str, Any]
) -> list[dict[str, Any]]:
    proposals = _index(
        original["proposed_new_source_admissions"], "proposal_id", "mutu_duplicate_proposal"
    )
    audits = _index(audit["records"], "proposal_id", "mutu_duplicate_audit")
    retained = _index(
        delta["retained_original_passing_representations"],
        "original_proposal_id",
        "mutu_duplicate_retained",
    )
    result = []
    for source_ref, spec in PROPOSAL_SOURCE_SPECS.items():
        proposal = proposals[spec["proposal_id"]]
        audit_record = audits[spec["proposal_id"]]
        retained_record = retained[spec["proposal_id"]]
        binding = proposal["quarantine_representation_binding"]["selected_admission_binding"]
        expected_binding = {
            "proposed_source_version_id": spec["source_version_id"],
            "raw_sha256": spec["raw_sha256"],
            "canonical_content_sha256": spec["canonical_content_sha256"],
            "record_content_sha256": spec["binding_record_content_sha256"],
        }
        if proposal.get("proposal_content_sha256") != spec["proposal_content_sha256"]:
            raise ValueError("mutu_support_proposal_digest_mismatch")
        if any(binding.get(key) != value for key, value in expected_binding.items()):
            raise ValueError("mutu_support_binding_mismatch")
        if (
            audit_record.get("record_content_sha256") != spec["audit_record_content_sha256"]
            or audit_record.get("substantive_content_verdict") != spec["audit_verdict"]
            or audit_record.get("warning_reason_codes") != list(spec["warning_reason_codes"])
        ):
            raise ValueError("mutu_support_audit_mismatch")
        if (
            retained_record.get("original_record_content_sha256")
            != spec["binding_record_content_sha256"]
            or retained_record.get("audit_record_content_sha256")
            != spec["audit_record_content_sha256"]
        ):
            raise ValueError("mutu_support_delta_mismatch")
        uses: dict[str, list[Mapping[str, Any]]] = {}
        for use in proposal["uses"]:
            uses.setdefault(str(use["row_id"]), []).append(use)
        for row_id, locators in spec["row_locators"].items():
            actual = [
                locator
                for use in uses.get(row_id, [])
                for locator in use["authority"]["exact_locators"]
            ]
            if list(locators) != actual:
                raise ValueError("mutu_support_locator_mismatch")
        result.append(
            {
                "source_ref": source_ref,
                "label": spec["label"],
                "proposal_id": spec["proposal_id"],
                "proposal_content_sha256": spec["proposal_content_sha256"],
                "proposed_source_version_id": spec["source_version_id"],
                "raw_sha256": spec["raw_sha256"],
                "canonical_content_sha256": spec["canonical_content_sha256"],
                "binding_record_content_sha256": spec["binding_record_content_sha256"],
                "audit_record_content_sha256": spec["audit_record_content_sha256"],
                "audit_verdict": spec["audit_verdict"],
                "audit_warning_reason_codes": list(spec["warning_reason_codes"]),
                "row_locator_bindings": {
                    row_id: list(locators) for row_id, locators in spec["row_locators"].items()
                },
                "source_admission_authorized": False,
                "source_admitted": False,
            }
        )
    return sorted(result, key=lambda item: str(item["source_ref"]))


def _verify_candidate_sources(candidate: Mapping[str, Any]) -> list[dict[str, Any]]:
    sources = _index(candidate["sources"], "source_version_id", "mutu_candidate_duplicate")
    result = []
    for source_ref, spec in CANDIDATE_SOURCE_SPECS.items():
        source = sources[spec["source_version_id"]]
        expected = {
            "title": spec["label"],
            "authority_identity_id": spec["authority_identity_id"],
            "content_sha256": spec["content_sha256"],
            "version_sha256": spec["content_sha256"],
        }
        if any(source.get(key) != value for key, value in expected.items()):
            raise ValueError("mutu_candidate_source_mismatch")
        result.append(
            {
                "source_ref": source_ref,
                **spec,
                "row_locators": {
                    row_id: list(locators) for row_id, locators in spec["row_locators"].items()
                },
                "candidate_existing": True,
                "candidate_manifest_sha256": EXPECTED_INPUTS["candidate"]["content_sha256"],
            }
        )
    return sorted(result, key=lambda item: str(item["source_ref"]))


def _verify_candidate_chunks() -> list[dict[str, Any]]:
    require_generic_index_read_allowed(CANDIDATE_ROOT, expected_build_id=CANDIDATE_ROOT_NAME)
    table = lancedb.connect(str(CANDIDATE_ROOT / "lance/authority")).open_table("chunks")
    source_version_id = CANDIDATE_SOURCE_SPECS["arbitration_act_1996"]["source_version_id"]
    rows = (
        table.search()
        .where(f"source_version_id = '{source_version_id}'")
        .select(
            [
                "chunk_id",
                "locator",
                "content_sha256",
                "canonical_chunk_sha256",
                "canonical_chunk_sha256_binding",
                "currentness_verified",
                "retrieval_eligible",
            ]
        )
        .limit(1000)
        .to_list()
    )
    by_id = _index(rows, "chunk_id", "mutu_candidate_chunk_duplicate")
    result = []
    for chunk_id, locator, content_sha256 in ARBITRATION_ACT_CHUNKS:
        row = by_id.get(chunk_id)
        if row is None:
            raise ValueError("mutu_candidate_chunk_missing")
        expected = {
            "locator": locator,
            "content_sha256": content_sha256,
            "canonical_chunk_sha256": content_sha256,
            "canonical_chunk_sha256_binding": "bound",
            "currentness_verified": True,
            "retrieval_eligible": True,
        }
        if any(row.get(key) != value for key, value in expected.items()):
            raise ValueError("mutu_candidate_chunk_mismatch")
        result.append(
            {
                "chunk_id": chunk_id,
                "source_version_id": source_version_id,
                **expected,
            }
        )
    return result


def _verify_mutu_exclusion(
    original: Mapping[str, Any], audit: Mapping[str, Any], delta: Mapping[str, Any]
) -> dict[str, Any]:
    spec = MUTU_PROPOSAL_SPEC
    proposals = _index(original["proposed_new_source_admissions"], "proposal_id", "mutu_proposals")
    audits = _index(audit["records"], "proposal_id", "mutu_audits")
    proposal = proposals[spec["proposal_id"]]
    audit_record = audits[spec["proposal_id"]]
    binding = proposal["quarantine_representation_binding"]["selected_admission_binding"]
    delta_holds = [
        item
        for item in delta["unresolved_repair_holds"]
        if item.get("old_proposal_id") == spec["proposal_id"]
    ]
    if len(delta_holds) != 1:
        raise ValueError("mutu_delta_hold_missing")
    if (
        proposal.get("proposal_content_sha256") != spec["proposal_content_sha256"]
        or binding.get("proposed_source_version_id") != spec["source_version_id"]
        or binding.get("raw_sha256") != spec["raw_sha256"]
        or binding.get("record_content_sha256") != spec["binding_record_content_sha256"]
        or sorted(binding.get("exact_locators", [])) != sorted(spec["exact_locators"])
        or audit_record.get("record_content_sha256") != spec["audit_record_content_sha256"]
        or audit_record.get("substantive_content_verdict") != "FAIL"
        or audit_record.get("failure_reason_codes") != ["HUDOC_GENERIC_APP_SHELL_NO_CASE_DOCUMENT"]
        or delta_holds[0].get("repair_hold_content_sha256")
        != spec["delta_repair_hold_content_sha256"]
    ):
        raise ValueError("mutu_exclusion_binding_mismatch")
    return {
        **spec,
        "exact_locators": list(spec["exact_locators"]),
        "audit_verdict": "FAIL",
        "audit_failure_reason_codes": ["HUDOC_GENERIC_APP_SHELL_NO_CASE_DOCUMENT"],
        "representation_excluded": True,
        "final_transport_hold": True,
        "retry_prohibited": True,
        "fetch_prohibited": True,
        "source_admission_authorized": False,
        "source_admitted": False,
        "legal_claim_release_prohibited": True,
    }


def _verify_local_universe(
    original: Mapping[str, Any], candidate: Mapping[str, Any]
) -> dict[str, Any]:
    proposals = original["proposed_new_source_admissions"]
    relevant_terms = ("sporting autonomy", "cas appeal", "cas jurisdiction")
    term_matches: dict[str, list[str]] = {}
    for term in relevant_terms:
        term_matches[term] = sorted(
            proposal["proposal_id"]
            for proposal in proposals
            if term
            in " ".join(
                str(use.get("atomic_proposition", "")) for use in proposal.get("uses", [])
            ).casefold()
        )
    expected = {
        "sporting autonomy": [
            MUTU_PROPOSAL_SPEC["proposal_id"],
            PROPOSAL_SOURCE_SPECS["cas_code"]["proposal_id"],
        ],
        "cas appeal": [
            MUTU_PROPOSAL_SPEC["proposal_id"],
            PROPOSAL_SOURCE_SPECS["cas_code"]["proposal_id"],
        ],
        "cas jurisdiction": [PROPOSAL_SOURCE_SPECS["cas_code"]["proposal_id"]],
    }
    expected = {key: sorted(value) for key, value in expected.items()}
    if term_matches != expected:
        raise ValueError("mutu_local_universe_term_match_changed")
    candidate_titles = {str(source.get("title", "")).casefold() for source in candidate["sources"]}
    exact_party_name = re.compile(r"\b(?:mutu|pechstein)\b", re.IGNORECASE)
    if any(exact_party_name.search(title) for title in candidate_titles):
        raise ValueError("mutu_unexpected_candidate_representation")
    return {
        "original_proposal_count": len(proposals),
        "candidate_source_count": len(candidate["sources"]),
        "exact_term_matches": term_matches,
        "mutu_or_pechstein_candidate_title_match_count": 0,
        "interpretation": (
            "The deterministic inventory scan identifies CAS Code mechanics but no independent "
            "already-local verified authority for the missing Convention holdings."
        ),
    }


def _verify_no_execution_flags(value: Any) -> None:
    def walk(nested: Any) -> None:
        if isinstance(nested, Mapping):
            for key, item in nested.items():
                if key in _NO_EXECUTION_FLAG_NAMES and item is not False:
                    raise ValueError("mutu_execution_flag_not_false")
                walk(item)
        elif isinstance(nested, list | tuple):
            for item in nested:
                walk(item)

    walk(value)


def _privacy_check(value: Any) -> None:
    def walk(nested: Any) -> None:
        if isinstance(nested, Mapping):
            for key, item in nested.items():
                walk(str(key))
                walk(item)
        elif isinstance(nested, list | tuple):
            for item in nested:
                walk(item)
        elif isinstance(nested, str):
            lowered = nested.casefold()
            if (
                "/users/" in lowered
                or "hltsang" in lowered
                or "legalbot-new" in lowered
                or "file://" in lowered
                or nested.startswith(("~/", "~\\"))
                or _EMAIL.search(nested)
            ):
                raise ValueError("mutu_privacy_violation")

    walk(value)


def _input_bindings() -> list[dict[str, str]]:
    rows = [
        ("original", ORIGINAL_ROOT_NAME, ORIGINAL_NAME),
        ("audit", AUDIT_ROOT_NAME, AUDIT_NAME),
        ("delta", DELTA_ROOT_NAME, DELTA_NAME),
        ("held9", HELD9_ROOT_NAME, HELD9_NAME),
        ("candidate", CANDIDATE_ROOT_NAME, CANDIDATE_NAME),
    ]
    rows.extend(
        (f"recovery_{revision}", RECOVERY_ROOT_NAMES[revision], RECOVERY_NAME)
        for revision in ("r1", "r2", "r3")
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
        result = function(source, target, 0x00000004)
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
        result = function(-100, source, -100, target, 0x00000001)
    else:
        raise RuntimeError("mutu_atomic_noreplace_unavailable")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise ValueError("mutu_output_already_exists")
    raise OSError(error_number, "mutu_atomic_publish_failed")


def _ensure_output_path(output_root: Path) -> Path:
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("mutu_output_already_exists")
    review = OUTPUT_REVIEW_ROOT.resolve(strict=True)
    parent = output_root.parent.resolve(strict=True)
    resolved = parent / output_root.name
    if not output_root.name or not resolved.is_relative_to(review):
        raise ValueError("mutu_output_outside_review_root")
    return resolved


def build_advisory(*, output_root: Path, created_at: datetime | None = None) -> dict[str, Any]:
    """Create and atomically publish one immutable fail-closed advisory."""

    output = _ensure_output_path(output_root)
    timestamp = created_at or datetime.now(UTC)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("mutu_created_at_must_be_aware")
    inputs = _verify_inputs()
    recovery_holds = _verify_recovery_holds(inputs)
    row_outcomes = _verify_rows(inputs["original"])
    proposal_sources = _verify_proposal_sources(
        inputs["original"], inputs["audit"], inputs["delta"]
    )
    candidate_sources = _verify_candidate_sources(inputs["candidate"])
    candidate_chunks = _verify_candidate_chunks()
    mutu_exclusion = _verify_mutu_exclusion(inputs["original"], inputs["audit"], inputs["delta"])
    local_universe = _verify_local_universe(inputs["original"], inputs["candidate"])
    no_execution_flags = {name: False for name in _NO_EXECUTION_FLAG_NAMES}

    advisory: dict[str, Any] = {
        "schema": "legalbot.v111.phase2a.mutu-alternative-support-advisory.v1",
        "status": "SEALED_IRREDUCIBLE_LEGAL_AUTHORITY_BLOCKER",
        "route": "OWNER_REVIEW_ONLY_NO_DECISION_NO_EXECUTION",
        "created_at": timestamp.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "input_bindings": _input_bindings(),
        "exact_scope": {
            "row_count": 2,
            "row_ids": sorted(ROW_SPECS),
            "question_kind": "ESSAY",
            "mutu_document_id": "001-186828",
            "changed_single_attempt_path_count": 3,
        },
        "mutu_defective_representation_and_final_hold": mutu_exclusion,
        "changed_single_attempt_transport_holds": recovery_holds,
        "verified_local_support_sources": proposal_sources,
        "verified_existing_candidate_sources": candidate_sources,
        "exact_arbitration_act_candidate_spans": candidate_chunks,
        "deterministic_local_universe_scan": local_universe,
        "semantically_insufficient_local_sources": [
            {
                "source_ref": "human_rights_act_1998",
                "reason": (
                    "The domestic Act supplies United Kingdom interpretive and remedial machinery; "
                    "it does not prove the compulsory-submission, CAS-independence, public-hearing "
                    "or Swiss-supervisory findings required by these propositions."
                ),
            },
            {
                "source_ref": "arbitration_act_1996",
                "reason": (
                    "The Act supports only arbitration within its statutory scope and English "
                    "recognition or court-control rules; it is not evidence of the relevant CAS "
                    "facts, Convention findings or Swiss supervisory law."
                ),
            },
            {
                "source_ref": "braganza",
                "reason": (
                    "Braganza controls contractual discretion only to its stated scope and does "
                    "not establish Convention safeguards or a free-standing proportionality rule."
                ),
            },
        ],
        "row_outcomes": row_outcomes,
        "irreducible_blocker": {
            "blocker_class": "GENUINELY_DIFFERENT_OFFICIAL_LEGAL_AUTHORITY_REQUIRED",
            "material_legal_claim_release_prohibited": True,
            "required_source_characteristics": [
                "A technically verified official representation independent of the held Mutu/Pechstein transport path.",
                "Exact spans supporting compulsory versus voluntary Convention waiver in sports arbitration.",
                "Exact spans supporting the applicable Article 6 hearing and institutional-independence analysis.",
                "For the state-supervision limb, exact authority for the relevant Convention and Swiss-supervisory relationship.",
            ],
            "alternative_source_selected": False,
            "alternative_source_admission_authorized": False,
            "owner_decision_required": True,
            "qualification_eligible": False,
        },
        "fallback_contract": {
            "essay_safe_fallback_prohibited": True,
            "fallback_used": False,
            "missing_matter_facts_reclassification_prohibited": True,
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
    _privacy_check(advisory)
    advisory["artifact_content_sha256"] = _sealed(advisory)
    advisory_raw = _pretty_json(advisory)
    advisory_file_sha256 = _sha256(advisory_raw)

    package: dict[str, Any] = {
        "schema": "legalbot.v111.phase2a.mutu-alternative-support-package.v1",
        "status": advisory["status"],
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
    _privacy_check(package)
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
