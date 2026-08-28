#!/usr/bin/env python3
"""Seal the Semenya substitute-source advisory for two Phase-2A q53 rows.

The Mutu/Pechstein transport path is permanently stopped.  This create-only
builder accepts the one successfully fetched official HUDOC representation of
Semenya v Switzerland [GC], validates the full judgment and exact paragraph
anchors, and binds it to already-sealed CAS Code and Arbitration Act support.

The result is quarantine/advisory evidence only.  It does not apply an owner
decision, admit a source, scan, build, embed, qualify, release an answer, write
a pointer, activate Phase 2B, or export training material.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import tempfile
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"

HELD9_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2A-2026-08-28-held9-surviving-support-advisory-r1"
    / "HELD9-SURVIVING-SUPPORT-ADVISORY.json"
)
RECOVERY_R3_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2A-2026-08-28-echr-held-source-recovery-quarantine-r3"
    / "ECHR-RECOVERY-QUARANTINE-MANIFEST.json"
)
DEFAULT_OUTPUT_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-q53-semenya-substitute-quarantine-r1"
)

ADVISORY_NAME = "Q53-SEMENYA-SUBSTITUTE-SOURCE-ADVISORY.json"
PACKAGE_NAME = "PACKAGE-MANIFEST.json"
CHECKSUMS_NAME = "SHA256SUMS.txt"

EXPECTED_HELD9_FILE_SHA256 = "2fe8eb506bce8ba455b7dea69d21927bba8fb54e242dba81c4287096a6535ef1"
EXPECTED_HELD9_CONTENT_SHA256 = "599d7175005c8978757611be0ce837299845c142147ec02828f53ee7620e75fd"
EXPECTED_RECOVERY_R3_FILE_SHA256 = (
    "c2682917d3f2dbc7cc701ad63ff98552eeb0e0398a85503b4b55a12c72b78471"
)
EXPECTED_RECOVERY_R3_CONTENT_SHA256 = (
    "f5beba682a629d3a6e0e79be374c0d2a3d6690d45abe467fa40f67879dcb0142"
)
EXPECTED_SEMENYA_RAW_SHA256 = "52f5485626ffd7235993db907a3051010af8f8104804db551e11d58648455d62"
EXPECTED_SEMENYA_BYTES = 624_549

SEMYA_DOCUMENT_ID = "001-244348"
SEMYA_CANONICAL_URL = "https://hudoc.echr.coe.int/eng?i=001-244348"
SEMYA_REPRESENTATION_URL = (
    "https://hudoc.echr.coe.int/app/conversion/docx/html/body?id=001-244348&library=ECHR"
)
ALI_RIZA_DOCUMENT_ID = "001-200548"
ALI_RIZA_REPRESENTATION_URL = (
    "https://hudoc.echr.coe.int/app/conversion/docx/html/body?id=001-200548&library=ECHR"
)

CAS_BINDING = {
    "proposal_id": "proposed-source-22c1a06353633c217c79b349",
    "proposal_content_sha256": ("31509f391d485615ba067b614518fdb5296c2386c38597a2bd1cdf2117714339"),
    "proposed_source_version_id": (
        "proposed-source-version-f751237a1139e758734534c7c8fc8e265cbc8e00"
    ),
    "raw_sha256": "af50463d8ee72e5de91bae081a66cb4b809754229f8ab81894c0df83627f9855",
    "binding_record_content_sha256": (
        "be886d6598acdbbb5c1b32b1fb248cd15543c5ca99cca77304074330f97ddc52"
    ),
    "audit_record_content_sha256": (
        "4777ca55ee140740777925e38a3cc0c478f3deb1aef8e9802c19e310d34fa72a"
    ),
    "audit_verdict": "PASS_WITH_WARNING",
    "audit_warning_reason_codes": ["TAS_NOISY_SEARCH_OVERLAY_RULE_BODY_PRESENT"],
}

ARBITRATION_ACT_BINDING = {
    "authority_identity_id": "ukpga:1996:23",
    "source_version_id": "source-version-59a8ac0ed35ad09bb4ea9520c6bddd3110a78cf8",
    "content_sha256": "2d395c8b88c15104758839b7e586816c67b344fda9def5e091384d4cb1a96eea",
    "candidate_manifest_sha256": (
        "b304ab1223987bf9b57d3e2560413b2f325c16213ae0071a45dface2e10dc206"
    ),
}

REQUIRED_PARAGRAPHS = tuple(range(193, 219)) + tuple(range(226, 240))
PARAGRAPH_MARKERS = {
    195: ("arbitration clauses",),
    196: ("loss of certain of the rights and guarantees",),
    197: ("free, lawful and unequivocal", "independent and impartial tribunal"),
    198: ("safeguards provided for by Article 6",),
    199: ("imposed by a private entity", "specialised body"),
    200: ("structural imbalance",),
    204: ("structural control",),
    205: ("safeguards provided for by Article 6",),
    209: ("particularly rigorous examination",),
    211: ("left the applicant no choice other than to appeal to the CAS",),
    214: ("the arbitration was compulsory",),
    216: ("particularly rigorous examination",),
    218: ("review the compatibility of the award with substantive public policy",),
    226: ("incompatible with public policy",),
    230: ("not subjected to the particularly rigorous examination",),
    238: ("required an in-depth judicial review", "did not satisfy"),
    239: ("violation of Article 6",),
}

FALSE_BOUNDARIES = (
    "owner_approved",
    "owner_decisions_applied",
    "source_admission_authorized",
    "source_admitted",
    "catalogue_mutated",
    "complete_source_scan_authorized",
    "source_scan_run",
    "successor_build_authorized",
    "successor_build_run",
    "index_build_authorized",
    "index_built",
    "automatic_indexing",
    "embedding_authorized",
    "embedding_run",
    "automatic_embedding",
    "candidate_mutated",
    "qualification_authorized",
    "technical_qualification_assigned",
    "retrieval_reattestation_run",
    "all585_qualification_run",
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
)


class JudgmentParser(HTMLParser):
    """Extract visible HUDOC converter paragraphs without trusting CSS names."""

    _EXCLUDED = frozenset(
        {
            "script",
            "style",
            "noscript",
            "template",
            "nav",
            "header",
            "footer",
            "aside",
            "form",
            "iframe",
        }
    )
    _VOID = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._open: list[str] = []
        self._excluded_depth = 0
        self._footnote_stack_indexes: list[int] = []
        self._paragraph_depth: int | None = None
        self._paragraph_parts: list[str] = []
        self._paragraph_is_toc = False
        self.paragraphs: list[str] = []
        self.visible_parts: list[str] = []
        self.element_count = 0
        self.paragraph_element_count = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.casefold()
        attr_map = {key.casefold(): value or "" for key, value in attrs}
        depth = len(self._open)
        self.element_count += 1
        if tag in self._EXCLUDED:
            self._excluded_depth += 1
        if tag == "div" and attr_map.get("id", "").casefold().startswith("_ftn"):
            self._footnote_stack_indexes.append(depth)
        if tag == "p" and not self._excluded_depth and not self._footnote_stack_indexes:
            if self._paragraph_depth is not None:
                raise ValueError("q53_semenya_nested_paragraph")
            self._paragraph_depth = depth
            self._paragraph_parts = []
            self._paragraph_is_toc = False
            self.paragraph_element_count += 1
        if (
            self._paragraph_depth is not None
            and tag == "a"
            and attr_map.get("href", "").casefold().startswith("#_toc")
        ):
            self._paragraph_is_toc = True
        if tag not in self._VOID:
            self._open.append(tag)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.casefold()
        if tag in self._VOID:
            return
        if not self._open or self._open[-1] != tag:
            raise ValueError("q53_semenya_html_tag_nesting_invalid")
        depth = len(self._open) - 1
        if tag == "p" and self._paragraph_depth == depth:
            text = " ".join(" ".join(self._paragraph_parts).split())
            if text and not self._paragraph_is_toc:
                self.paragraphs.append(text)
            self._paragraph_depth = None
            self._paragraph_parts = []
            self._paragraph_is_toc = False
        if self._footnote_stack_indexes and self._footnote_stack_indexes[-1] == depth:
            self._footnote_stack_indexes.pop()
        if tag in self._EXCLUDED and self._excluded_depth:
            self._excluded_depth -= 1
        self._open.pop()

    def handle_data(self, data: str) -> None:
        if not self._excluded_depth and not self._footnote_stack_indexes:
            self.visible_parts.append(data)
            if self._paragraph_depth is not None:
                self._paragraph_parts.append(data)

    def close(self) -> None:
        super().close()
        if self._open or self._paragraph_depth is not None:
            raise ValueError("q53_semenya_unclosed_html_element")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError("q53_semenya_input_not_regular")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _false_boundaries() -> dict[str, bool]:
    return {field: False for field in FALSE_BOUNDARIES}


def _load_sealed(path: Path, file_sha: str, content_sha: str, field: str) -> dict[str, Any]:
    if _sha256_file(path) != file_sha:
        raise ValueError("q53_semenya_input_file_digest_invalid")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("q53_semenya_input_not_object")
    material = dict(value)
    supplied = material.pop(field, None)
    if supplied != content_sha or supplied != _sealed(material):
        raise ValueError("q53_semenya_input_content_digest_invalid")
    return value


def _verify_lineage() -> tuple[dict[str, Any], dict[str, Any]]:
    held9 = _load_sealed(
        HELD9_PATH,
        EXPECTED_HELD9_FILE_SHA256,
        EXPECTED_HELD9_CONTENT_SHA256,
        "artifact_content_sha256",
    )
    recovery = _load_sealed(
        RECOVERY_R3_PATH,
        EXPECTED_RECOVERY_R3_FILE_SHA256,
        EXPECTED_RECOVERY_R3_CONTENT_SHA256,
        "manifest_content_sha256",
    )
    survivors = held9.get("surviving_pass_or_pass_with_warning_representations", [])
    cas = next(
        (
            item
            for item in survivors
            if isinstance(item, dict) and item.get("label") == "Code of Sports-related Arbitration"
        ),
        None,
    )
    if not isinstance(cas, dict):
        raise ValueError("q53_semenya_cas_binding_missing")
    for field, expected in CAS_BINDING.items():
        if cas.get(field) != expected:
            raise ValueError(f"q53_semenya_cas_binding_mismatch:{field}")
    if cas.get("row_locator_bindings") != {
        "live60-q53:issue-04": ["R47", "R57"],
        "live60-q53:issue-11": ["R27", "R47", "R57", "R59"],
    }:
        raise ValueError("q53_semenya_cas_locator_binding_mismatch")
    existing = held9.get("surviving_existing_candidate_sources", [])
    act = next(
        (
            item
            for item in existing
            if isinstance(item, dict) and item.get("label") == "Arbitration Act 1996"
        ),
        None,
    )
    if not isinstance(act, dict):
        raise ValueError("q53_semenya_arbitration_act_binding_missing")
    for field, expected in ARBITRATION_ACT_BINDING.items():
        if act.get(field) != expected:
            raise ValueError(f"q53_semenya_arbitration_act_mismatch:{field}")
    holds = recovery.get("holds", [])
    mutu = next(
        (
            item
            for item in holds
            if isinstance(item, dict) and item.get("document_id") == "001-186828"
        ),
        None,
    )
    if (
        not isinstance(mutu, dict)
        or mutu.get("failure_fingerprint")
        != "cd73206a613336d1790a6b8c2db5aab2e621dda9206ed3decf20f22a9034924c"
        or mutu.get("hold_retained") is not True
        or mutu.get("attempt_count") != 1
    ):
        raise ValueError("q53_semenya_stopped_mutu_lineage_invalid")
    if any(
        isinstance(item, dict) and item.get("document_id") == "001-186828"
        for item in recovery.get("records", [])
    ):
        raise ValueError("q53_semenya_mutu_record_must_not_exist")
    return held9, recovery


def _validate_semenya(raw: bytes) -> tuple[dict[str, Any], bytes, dict[int, str]]:
    if len(raw) != EXPECTED_SEMENYA_BYTES or _sha256(raw) != EXPECTED_SEMENYA_RAW_SHA256:
        raise ValueError("q53_semenya_raw_identity_invalid")
    parser = JudgmentParser()
    try:
        parser.feed(raw.decode("utf-8", "strict"))
        parser.close()
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("q53_semenya_html_invalid") from exc
    if len(parser.paragraphs) < 800:
        raise ValueError("q53_semenya_full_body_too_short")
    front = " ".join(parser.paragraphs[:16]).casefold()
    for marker in (
        "grand chamber",
        "case of semenya v. switzerland",
        "application no. 10934/21",
        "judgment",
        "10 july 2025",
        "this judgment is final",
    ):
        if marker not in front:
            raise ValueError(f"q53_semenya_front_identity_missing:{marker}")
    leading = re.compile(r"^\s*(\d{1,4})\s*[.)]?\s+")
    numbered = [
        (index, int(match.group(1)), text)
        for index, text in enumerate(parser.paragraphs)
        if (match := leading.match(text)) is not None and len(text) >= 15
    ]
    runs: list[list[tuple[int, int, str]]] = []
    for item in numbered:
        if not runs or item[1] != runs[-1][-1][1] + 1:
            runs.append([item])
        else:
            runs[-1].append(item)
    matching_runs = [
        run for run in runs if {number for _, number, _ in run}.issuperset(REQUIRED_PARAGRAPHS)
    ]
    if len(matching_runs) != 1:
        raise ValueError("q53_semenya_unique_main_paragraph_run_missing")
    run = matching_runs[0]
    paragraphs = {number: text for _, number, text in run if number in REQUIRED_PARAGRAPHS}
    if tuple(sorted(paragraphs)) != REQUIRED_PARAGRAPHS:
        raise ValueError("q53_semenya_required_paragraphs_missing")
    for number, markers in PARAGRAPH_MARKERS.items():
        normalized = paragraphs[number].casefold()
        if any(marker.casefold() not in normalized for marker in markers):
            raise ValueError(f"q53_semenya_paragraph_semantic_marker_missing:{number}")
    visible = " ".join(" ".join(parser.visible_parts).split())
    canonical_lines = [
        "# Semenya v Switzerland [GC]",
        "",
        f"HUDOC document: {SEMYA_DOCUMENT_ID}",
        "",
        *parser.paragraphs,
    ]
    canonical = ("\n\n".join(canonical_lines) + "\n").encode()
    validation = {
        "content_fitness_status": "OFFICIAL_FULL_JUDGMENT_BODY_AND_EXACT_SUBSTITUTE_SPANS_VERIFIED",
        "parser_profile": "hudoc-visible-paragraphs-q53-semenya-v1",
        "html_element_count": parser.element_count,
        "html_paragraph_element_count": parser.paragraph_element_count,
        "extracted_paragraph_count": len(parser.paragraphs),
        "extracted_text_characters": len(visible),
        "extracted_text_sha256": _sha256(visible.encode()),
        "required_paragraphs_verified": list(REQUIRED_PARAGRAPHS),
        "required_paragraph_count": len(REQUIRED_PARAGRAPHS),
        "main_run_first": run[0][1],
        "main_run_last": run[-1][1],
        "main_run_count": len(run),
        "main_run_paragraph_positions": {
            str(number): index for index, number, _ in run if number in REQUIRED_PARAGRAPHS
        },
        "identity_markers_verified": [
            "GRAND CHAMBER",
            "CASE OF SEMENYA v. SWITZERLAND",
            "Application no. 10934/21",
            "JUDGMENT",
            "10 July 2025",
            "This judgment is final",
        ],
        "canonical_markdown_bytes": len(canonical),
        "canonical_markdown_sha256": _sha256(canonical),
    }
    return validation, canonical, paragraphs


def _ali_riza_hold() -> dict[str, Any]:
    attempt = {
        "document_id": ALI_RIZA_DOCUMENT_ID,
        "representation_url": ALI_RIZA_REPRESENTATION_URL,
        "transport": "curl-default-http-negotiation-location-max-time-180-connect-timeout-20",
        "attempt_count": 1,
        "curl_exit_code": 16,
        "error": "curl: (16) Error in the HTTP2 framing layer",
        "retry_run": False,
    }
    attempt["attempt_identity_sha256"] = _sealed(attempt)
    fingerprint_material = {
        "stage": "OFFICIAL_HUDOC_SUBSTITUTE_FETCH",
        "document_id": ALI_RIZA_DOCUMENT_ID,
        "endpoint": ALI_RIZA_REPRESENTATION_URL,
        "exception_code": "CURL_EXIT_16_HTTP2_FRAMING",
        "attempt_identity_sha256": attempt["attempt_identity_sha256"],
    }
    hold = {
        **attempt,
        "failure_fingerprint": _sealed(fingerprint_material),
        "reason_code": "OFFICIAL_HUDOC_SUBSTITUTE_SINGLE_ATTEMPT_FAILED_NO_RETRY",
        "path_stopped": True,
        "hold_retained": True,
        "required_for_revised_substitute_set": False,
        "disposition": "NOT_REQUIRED_BECAUSE_SEMENYA_PLUS_EXISTING_SEALED_SOURCES_IS_PROPOSITION_COMPLETE",
        **_false_boundaries(),
    }
    hold["hold_content_sha256"] = _sealed(hold)
    return hold


def _build_advisory(raw: bytes, canonical: bytes, validation: dict[str, Any]) -> dict[str, Any]:
    raw_sha = _sha256(raw)
    canonical_sha = _sha256(canonical)
    source_identity_material = {
        "authority_identity_id": f"official-url:{SEMYA_CANONICAL_URL}",
        "raw_sha256": raw_sha,
        "canonical_markdown_sha256": canonical_sha,
        "document_id": SEMYA_DOCUMENT_ID,
    }
    identity_sha = _sealed(source_identity_material)
    source_record = {
        "record_id": f"q53-semenya-substitute-{identity_sha[:24]}",
        "proposed_source_version_id": f"proposed-source-version-{identity_sha[:40]}",
        "title": "Semenya v Switzerland [GC]",
        "document_id": SEMYA_DOCUMENT_ID,
        "authority_identity_id": f"official-url:{SEMYA_CANONICAL_URL}",
        "canonical_url": SEMYA_CANONICAL_URL,
        "representation_url": SEMYA_REPRESENTATION_URL,
        "raw_member": f"echr-{SEMYA_DOCUMENT_ID}-{raw_sha[:20]}.html",
        "raw_sha256": raw_sha,
        "bytes": len(raw),
        "canonical_markdown_member": f"echr-{SEMYA_DOCUMENT_ID}-{canonical_sha[:20]}.md",
        "canonical_markdown_sha256": canonical_sha,
        "canonical_markdown_bytes": len(canonical),
        "retrieval_attempt_count": 1,
        "retry_run": False,
        "official_judgment_date": "2025-07-10",
        "official_front_matter_finality_statement_verified": True,
        "source_version_mode": "OFFICIAL_FINAL_GRAND_CHAMBER_JUDGMENT_RETRIEVED_2026_08_28",
        "currentness_hold_retained": True,
        "later_treatment_hold_retained": True,
        "currentness_finding": "No comprehensive proposition-level currentness review through the 2026-08-14 source ceiling was completed.",
        "later_treatment_finding": "No comprehensive ECtHR, Swiss, CAS or related later-treatment sweep through the 2026-08-14 source ceiling was completed.",
        "answer_eligible": False,
        "owner_delta_decision_required": True,
        "source_admission_recommendation": "ADMIT_ONLY_THIS_EXACT_SEALED_REPRESENTATION_IF_OWNER_ADOPTS_THE_FINAL_EXACT_PACKET",
        **validation,
        **_false_boundaries(),
    }
    source_record["record_content_sha256"] = _sealed(source_record)
    row_outcomes = [
        {
            "row_id": "live60-q53:issue-04",
            "question_kind": "ESSAY",
            "outcome": "PROPOSITION_COMPLETE_SUBSTITUTE_SET_ADVISORY_OWNER_DELTA_REQUIRED",
            "support_set": [
                {
                    "source": "Code of Sports-related Arbitration 2025",
                    "locators": ["R47", "R57"],
                    "supports": "CAS appeal jurisdiction and merits-review mechanics, including R57's disciplinary-proceedings public-hearing rule and stated exceptions/mechanics.",
                    **CAS_BINDING,
                },
                {
                    "source": "Semenya v Switzerland [GC]",
                    "locators": ["paras 195-218", "paras 226-239"],
                    "supports": "Voluntary waiver requirements; express waiver needed for an independent and impartial tribunal; Article 6 safeguards in compulsory private sports arbitration; structural imbalance; and particularly rigorous state-court supervision.",
                    "record_id": source_record["record_id"],
                    "record_content_sha256": source_record["record_content_sha256"],
                },
                {
                    "source": "Arbitration Act 1996",
                    "locators": ["sections 33 and 68"],
                    "supports": "Fair and impartial procedure and serious-irregularity control only where Part I applies; not Swiss CAS supervisory law.",
                    **ARBITRATION_ACT_BINDING,
                },
            ],
            "superseded_old_mutu_specific_wording": [
                "The earlier proposal's historical statement that Mutu and Pechstein found no majority-established structural independence violation is not carried forward.",
                "The earlier proposal's historical statement that Pechstein obtained an Article 6 violation because CAS did not hold a public hearing is not carried forward.",
            ],
            "replacement_boundary": "The CAS Code supplies the current R57 public-hearing rule/mechanics; Semenya supplies the Convention principles. Semenya is not described as a disciplinary-sanctions case and does not prove the excluded Mutu historical outcomes.",
            "safe_fallback_eligible": False,
            "safe_fallback_prohibited": True,
            "currentness_hold_retained": True,
            "later_treatment_hold_retained": True,
            "answer_eligible": False,
        },
        {
            "row_id": "live60-q53:issue-11",
            "question_kind": "ESSAY",
            "outcome": "PROPOSITION_COMPLETE_SUBSTITUTE_SET_ADVISORY_OWNER_DELTA_REQUIRED",
            "support_set": [
                {
                    "source": "Code of Sports-related Arbitration 2025",
                    "locators": ["R27", "R47", "R57", "R59"],
                    "supports": "Rules-based jurisdiction, internal-remedy exhaustion, merits review, Swiss seat and stated finality/recourse mechanics.",
                    **CAS_BINDING,
                },
                {
                    "source": "Semenya v Switzerland [GC]",
                    "locators": ["paras 195-218", "paras 226-239"],
                    "supports": "The boundary between free waiver and compulsory sports arbitration, Article 6 safeguards, and the adequacy and rigour required of Swiss state-court supervision.",
                    "record_id": source_record["record_id"],
                    "record_content_sha256": source_record["record_content_sha256"],
                },
                {
                    "source": "Arbitration Act 1996",
                    "locators": ["sections 1, 33, 67-70, 81(1)(a) and 103(3)"],
                    "supports": "English statutory autonomy, mandatory fairness and defined court controls within the Act's scope; not Swiss setting-aside law.",
                    **ARBITRATION_ACT_BINDING,
                },
            ],
            "superseded_old_mutu_specific_wording": [
                "The unavailable Mutu/Pechstein representation is not used, fetched, retried, cited as an admitted source or silently retained.",
                "Any case-specific historical result about CAS independence or Pechstein's public hearing is excluded from this revised proposition.",
            ],
            "replacement_boundary": "Semenya supports only the identified compulsory-arbitration, waiver, Article 6 and state-supervision propositions; Swiss substantive setting-aside and enforcement law remains outside this substitute set.",
            "safe_fallback_eligible": False,
            "safe_fallback_prohibited": True,
            "currentness_hold_retained": True,
            "later_treatment_hold_retained": True,
            "answer_eligible": False,
        },
    ]
    advisory = {
        "schema": "legalbot.v111.phase2a.q53-semenya-substitute-source-advisory.v1",
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "status": "PROPOSITION_COMPLETE_SUBSTITUTE_QUARANTINED_OWNER_DELTA_REQUIRED",
        "scope": {
            "row_ids": ["live60-q53:issue-04", "live60-q53:issue-11"],
            "mutu_pechstein_path_permanently_stopped": True,
            "mutu_pechstein_fetched_or_retried_here": False,
            "official_source_hosts": ["hudoc.echr.coe.int"],
        },
        "input_bindings": {
            "held9_advisory": {
                "path": str(HELD9_PATH.relative_to(PROJECT_ROOT)),
                "content_sha256": EXPECTED_HELD9_CONTENT_SHA256,
                "file_sha256": EXPECTED_HELD9_FILE_SHA256,
            },
            "echr_recovery_r3": {
                "path": str(RECOVERY_R3_PATH.relative_to(PROJECT_ROOT)),
                "content_sha256": EXPECTED_RECOVERY_R3_CONTENT_SHA256,
                "file_sha256": EXPECTED_RECOVERY_R3_FILE_SHA256,
                "mutu_failure_fingerprint": "cd73206a613336d1790a6b8c2db5aab2e621dda9206ed3decf20f22a9034924c",
            },
        },
        "semenya_source_record": source_record,
        "ali_riza_single_attempt_hold": _ali_riza_hold(),
        "row_outcomes": row_outcomes,
        "interpretation_contract": {
            "proposition_complete_means": "The revised, explicitly bounded source sets cover the listed Phase-2A propositions; it is not an answer-release, currentness or later-treatment certification.",
            "public_hearing_boundary": "R57 is used for the current CAS disciplinary public-hearing rule/mechanics. No claim is made here about Mutu/Pechstein's historical public-hearing outcome.",
            "semenya_case_boundary": "Semenya is a compulsory sports-arbitration and state-supervision authority, not a disciplinary-sanctions case.",
            "no_claim_from_party_submission": True,
            "no_claim_from_press_release_or_case_law_note": True,
        },
        "not_owner_decision": True,
        "not_source_admission": True,
        "not_qualification_result": True,
        "not_legal_currentness_certification": True,
        "not_later_treatment_certification": True,
        **_false_boundaries(),
    }
    advisory["artifact_content_sha256"] = _sealed(advisory)
    return advisory


def build(input_path: Path, output_root: Path) -> dict[str, Any]:
    _verify_lineage()
    if input_path.is_symlink() or not input_path.is_file():
        raise ValueError("q53_semenya_raw_input_not_regular")
    raw = input_path.read_bytes()
    validation, canonical, _ = _validate_semenya(raw)
    advisory = _build_advisory(raw, canonical, validation)
    advisory_bytes = _pretty_json(advisory)
    raw_member = advisory["semenya_source_record"]["raw_member"]
    canonical_member = advisory["semenya_source_record"]["canonical_markdown_member"]
    if output_root.exists() or output_root.is_symlink():
        raise FileExistsError("q53_semenya_output_exists")
    output_root.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output_root.name}-", dir=output_root.parent))
    try:
        (temporary / raw_member).write_bytes(raw)
        (temporary / canonical_member).write_bytes(canonical)
        (temporary / ADVISORY_NAME).write_bytes(advisory_bytes)
        package = {
            "schema": "legalbot.v111.phase2a.q53-semenya-substitute-package-manifest.v1",
            "advisory_content_sha256": advisory["artifact_content_sha256"],
            "advisory_file_sha256": _sha256(advisory_bytes),
            "raw_member": raw_member,
            "raw_sha256": _sha256(raw),
            "canonical_markdown_member": canonical_member,
            "canonical_markdown_sha256": _sha256(canonical),
            "ali_riza_failure_fingerprint": advisory["ali_riza_single_attempt_hold"][
                "failure_fingerprint"
            ],
            "owner_delta_decision_required": True,
            **_false_boundaries(),
        }
        package["package_content_sha256"] = _sealed(package)
        package_bytes = _pretty_json(package)
        (temporary / PACKAGE_NAME).write_bytes(package_bytes)
        checksum_names = [raw_member, canonical_member, ADVISORY_NAME, PACKAGE_NAME]
        checksums = "".join(
            f"{_sha256_file(temporary / name)}  {name}\n" for name in checksum_names
        )
        (temporary / CHECKSUMS_NAME).write_text(checksums, encoding="utf-8")
        for member in temporary.iterdir():
            os.chmod(member, 0o444)
        os.rename(temporary, output_root)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return {
        "output_root": str(output_root),
        "advisory_content_sha256": advisory["artifact_content_sha256"],
        "advisory_file_sha256": _sha256(advisory_bytes),
        "package_content_sha256": package["package_content_sha256"],
        "package_file_sha256": _sha256(package_bytes),
        "raw_sha256": _sha256(raw),
        "canonical_markdown_sha256": _sha256(canonical),
        "checksums_file_sha256": _sha256_file(output_root / CHECKSUMS_NAME),
        "row_count": len(advisory["row_outcomes"]),
        "status": advisory["status"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    args = parser.parse_args()
    print(json.dumps(build(args.input, args.output_root), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
