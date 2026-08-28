#!/usr/bin/env python3
"""Create a sealed, read-only content audit of the 247 proposed admissions.

The audit is intentionally narrower than source admission.  It verifies the
exact owner-packet and quarantine seals, re-reads every selected quarantine
member without following symlinks, and determines whether the sealed bytes
contain an inspectable legal document rather than a landing page or JavaScript
application shell.  It never uses the network and never admits a source,
scans/builds/embeds an index, mutates a candidate, or writes a release pointer.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import stat
import tempfile
import xml.etree.ElementTree as ET
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from pypdf import PdfReader

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
DEFAULT_PACKET_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2A-2026-08-28-exact-remediation-owner-packet-r1"
    / "EXACT-REMEDIATION-OWNER-PACKET-361.json"
)
DEFAULT_QUARANTINE_MANIFEST_PATH = (
    REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-source-quarantine" / "QUARANTINE-MANIFEST.json"
)
DEFAULT_OUTPUT_ROOT = REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-admission-content-audit-r1"

PACKET_CONTENT_SHA256 = "93ad9113af76896f0570a3666c446472af7587b7e3ff32b7464e670777ec6b6c"
PACKET_FILE_SHA256 = "992770c04cb3e08de64bb98e80aa9801171d3e66e4b573b85919091a78b1db3b"
QUARANTINE_CONTENT_SHA256 = "b6d900b23232379a4d6c19d313f35c47e0758ce5e0bb6eb04008f9eba07a3819"
QUARANTINE_FILE_SHA256 = "f482366a2ba0d9f636c56104d632767a8eadd6e9a9625d50ef5391a5f62995eb"
PACKET_SCHEMA = "legalbot.v111.phase2a.exact-remediation-owner-packet.v1"
QUARANTINE_SCHEMA = "legalbot.v111.phase2a.research-wave-quarantine-binding.v2"
EXPECTED_PROPOSAL_COUNT = 247
EXPECTED_FAILURE_COUNT = 16
EXPECTED_PASS_COUNT = 231

AUDIT_NAME = "ADMISSION-CONTENT-AUDIT-247.json"
OUTCOME_NAME = "AUDIT-OUTCOME.json"
PACKAGE_NAME = "PACKAGE-MANIFEST.json"
CHECKSUM_NAME = "SHA256SUMS.txt"

FCA_FAILURE = "FCA_DYNAMIC_APP_SHELL_NO_RULE_BODY"
HUDOC_FAILURE = "HUDOC_GENERIC_APP_SHELL_NO_CASE_DOCUMENT"
JUDICIARY_FAILURE = "JUDICIARY_LANDING_METADATA_NO_JUDGMENT_BODY"

EXPECTED_FAILURE_CATEGORY_BY_RECORD_ID = {
    "quarantine-binding-caeef16146c2eea1e2b03d09": JUDICIARY_FAILURE,
    "quarantine-binding-f8a3307ef69293278c5531e9": FCA_FAILURE,
    "quarantine-binding-d0474e100e630e772055180c": FCA_FAILURE,
    "quarantine-binding-87f163e3509d14d6a37a62b6": FCA_FAILURE,
    "quarantine-binding-87f560afff24458a4860fe7d": FCA_FAILURE,
    "quarantine-binding-5250c824665dd618ee8ca7b4": FCA_FAILURE,
    "quarantine-binding-80a78f6ef29e6748d869b850": FCA_FAILURE,
    "quarantine-binding-035155a0fd7eb9b7d85ac164": FCA_FAILURE,
    "quarantine-binding-4182da970c521667c7a18423": FCA_FAILURE,
    "quarantine-binding-e47c5df0358c13f249834f73": FCA_FAILURE,
    "quarantine-binding-c77651e23cb2156c65e9c850": FCA_FAILURE,
    "quarantine-binding-1c53d8ee4bfc4e3cdf174423": FCA_FAILURE,
    "quarantine-binding-3688eea8275753b9dcabf559": HUDOC_FAILURE,
    "quarantine-binding-678af407a5abea67aa817bee": HUDOC_FAILURE,
    "quarantine-binding-0a370f8e41122c812c5f26d2": HUDOC_FAILURE,
    "quarantine-binding-d07fad39256d15a7c6a25893": HUDOC_FAILURE,
}
EXPECTED_WARNING_CATEGORY_BY_RECORD_ID = {
    "quarantine-binding-d31c75cc95a825afac363e91": ("TAS_NOISY_SEARCH_OVERLAY_RULE_BODY_PRESENT")
}

FCA_VISIBLE_FINGERPRINTS = {
    (1675, "0b300aba64ca49887befa8585c1df1cd0e040bd715823fd01a9a64eafd2dc170"),
    (1695, "9ec027ee7391f3a4e7e9c1b230e0690ccc81e9ce35ca19eca8f29709a8027cda"),
}
HUDOC_VISIBLE_TEXT = "HUDOC - European Court of Human Rights"
HUDOC_VISIBLE_SHA256 = "8730b663b09d32788d683e190fd85d824eaebd6c5ac439741fb87164683c6243"
TAS_NO_RESULTS_MARKER = "No documents match the specified search terms"
TAS_REQUIRED_RULE_MARKERS = ("R27", "R47", "R57", "R59")

_SHA256 = re.compile(r"[0-9a-f]{64}")
_PROPOSAL_ID = re.compile(r"proposed-source-[0-9a-f]{24}")
_SOURCE_VERSION_ID = re.compile(r"proposed-source-version-[0-9a-f]{40}")
_RECORD_ID = re.compile(r"quarantine-binding-[0-9a-f]{24}")
_FCA_LOCATOR = re.compile(
    r"\b(?:(?:COBS|COMP|DISP)\s+)?\d+[A-Z]?(?:\.\d+[A-Z]?){1,2}[A-Z]?\b",
    re.IGNORECASE,
)
_PARAGRAPH_MARKER = re.compile(r"(?:\[(?P<bracket>\d{1,3})\]|(?<!\d)(?P<dot>\d{1,3})\.(?=\s))")

_TOP_LEVEL_FALSE_FIELDS = (
    "source_admission_authorized",
    "source_admitted",
    "source_scan_run",
    "index_built",
    "embedding_run",
    "candidate_mutated",
    "retrieval_reattestation_run",
    "all585_qualification_run",
    "answer_model_run",
    "answer_released",
    "phase2b_run",
    "development30_run",
    "validation30_run",
    "promotion_run",
    "active_pointer_written",
    "previous_pointer_written",
    "live_activation_run",
    "training_export_run",
)


@dataclass(frozen=True)
class BoundArtifact:
    path: Path
    content_sha256: str
    file_sha256: str
    content_seal_field: str


@dataclass(frozen=True)
class HtmlProjection:
    title: str
    visible_text: str
    identifiers: frozenset[str]


class _VisibleHtmlParser(HTMLParser):
    """Project deterministic visible text while omitting executable/style bytes."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._suppressed = 0
        self._in_title = False
        self._visible_parts: list[str] = []
        self._title_parts: list[str] = []
        self.identifiers: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.casefold()
        self.identifiers.add(f"tag:{tag}")
        if tag in {"script", "style", "noscript"}:
            self._suppressed += 1
        if tag == "title":
            self._in_title = True
        for key, value in attrs:
            if value is None or key.casefold() not in {"id", "class", "role"}:
                continue
            self.identifiers.update(part.casefold() for part in re.split(r"\s+", value) if part)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.casefold()
        if tag == "title":
            self._in_title = False
        if tag in {"script", "style", "noscript"} and self._suppressed:
            self._suppressed -= 1

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_parts.append(data)
        if not self._suppressed:
            self._visible_parts.append(data)

    def projection(self) -> HtmlProjection:
        return HtmlProjection(
            title=" ".join(" ".join(self._title_parts).split()),
            visible_text=" ".join(" ".join(self._visible_parts).split()),
            identifiers=frozenset(self.identifiers),
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


def _portable_path(path: Path) -> str:
    resolved = path.resolve()
    if not resolved.is_relative_to(PROJECT_ROOT.resolve()):
        raise ValueError("phase2a_admission_content_audit_path_outside_project")
    return resolved.relative_to(PROJECT_ROOT.resolve()).as_posix()


def _read_regular_no_follow(path: Path, *, within: Path | None = None) -> bytes:
    if within is not None:
        root = within.resolve()
        if within.is_symlink() or not within.is_dir():
            raise ValueError("phase2a_admission_content_audit_root_invalid")
        resolved = path.resolve()
        if resolved == root or not resolved.is_relative_to(root):
            raise ValueError("phase2a_admission_content_audit_member_outside_quarantine")
    if path.is_symlink():
        raise ValueError("phase2a_admission_content_audit_symlink_rejected")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise ValueError("phase2a_admission_content_audit_regular_file_required") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("phase2a_admission_content_audit_regular_file_required")
        blocks: list[bytes] = []
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            blocks.append(block)
        raw = b"".join(blocks)
        if len(raw) != info.st_size:
            raise ValueError("phase2a_admission_content_audit_file_changed_during_read")
        return raw
    finally:
        os.close(descriptor)


def _load_bound_json(binding: BoundArtifact, *, schema: str, role: str) -> dict[str, Any]:
    raw = _read_regular_no_follow(binding.path, within=REVIEW_ROOT)
    if _sha256(raw) != binding.file_sha256:
        raise ValueError(f"phase2a_admission_content_audit_{role}_file_sha256_mismatch")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"phase2a_admission_content_audit_{role}_json_invalid") from exc
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise ValueError(f"phase2a_admission_content_audit_{role}_schema_invalid")
    material = dict(value)
    supplied = material.pop(binding.content_seal_field, None)
    if (
        supplied != binding.content_sha256
        or not _SHA256.fullmatch(str(supplied))
        or _sealed(material) != supplied
    ):
        raise ValueError(f"phase2a_admission_content_audit_{role}_content_sha256_mismatch")
    return value


def _record_seal_valid(record: Mapping[str, Any]) -> bool:
    material = dict(record)
    supplied = material.pop("record_content_sha256", None)
    return bool(
        isinstance(supplied, str) and _SHA256.fullmatch(supplied) and _sealed(material) == supplied
    )


def _proposal_seal_valid(proposal: Mapping[str, Any]) -> bool:
    material = dict(proposal)
    supplied = material.pop("proposal_content_sha256", None)
    return bool(
        isinstance(supplied, str) and _SHA256.fullmatch(supplied) and _sealed(material) == supplied
    )


def _validate_false_boundaries(value: Mapping[str, Any], *, role: str) -> None:
    for field in _TOP_LEVEL_FALSE_FIELDS:
        if field in value and value[field] is not False:
            raise ValueError(f"phase2a_admission_content_audit_{role}_{field}_must_remain_false")


def _validate_and_join_inputs(
    packet: Mapping[str, Any],
    quarantine: Mapping[str, Any],
    *,
    quarantine_binding: BoundArtifact,
) -> list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]]:
    _validate_false_boundaries(packet, role="packet")
    _validate_false_boundaries(quarantine, role="quarantine")
    proposals = packet.get("proposed_new_source_admissions")
    selected = quarantine.get("selected_admission_bindings")
    records = quarantine.get("records")
    if not isinstance(proposals, list) or len(proposals) != EXPECTED_PROPOSAL_COUNT:
        raise ValueError("phase2a_admission_content_audit_proposal_count_invalid")
    if not isinstance(selected, list) or len(selected) != EXPECTED_PROPOSAL_COUNT:
        raise ValueError("phase2a_admission_content_audit_selected_count_invalid")
    if not isinstance(records, list):
        raise ValueError("phase2a_admission_content_audit_records_invalid")
    if packet.get("decision_summary", {}).get("proposed_new_source_admission_count") != (
        EXPECTED_PROPOSAL_COUNT
    ):
        raise ValueError("phase2a_admission_content_audit_packet_summary_invalid")
    records_by_id: dict[str, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict) or not _record_seal_valid(record):
            raise ValueError("phase2a_admission_content_audit_quarantine_record_seal_invalid")
        record_id = str(record.get("record_id"))
        if not _RECORD_ID.fullmatch(record_id) or record_id in records_by_id:
            raise ValueError("phase2a_admission_content_audit_quarantine_record_id_invalid")
        records_by_id[record_id] = record

    selected_by_id: dict[str, dict[str, Any]] = {}
    for item in selected:
        if not isinstance(item, dict):
            raise ValueError("phase2a_admission_content_audit_selected_binding_invalid")
        record_id = str(item.get("record_id"))
        record = records_by_id.get(record_id)
        if (
            record is None
            or record_id in selected_by_id
            or item.get("selected_for_proposed_admission") is not True
            or item.get("representation_role") != "PROPOSED_ADMISSION_REPRESENTATION"
            or item.get("eligible_for_owner_packet") is not True
            or item.get("record_content_sha256") != record["record_content_sha256"]
        ):
            raise ValueError("phase2a_admission_content_audit_selected_binding_invalid")
        selected_by_id[record_id] = item

    manifest_portable_path = _portable_path(quarantine_binding.path)
    joined: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = []
    joined_ids: set[str] = set()
    proposal_ids: set[str] = set()
    for proposal in proposals:
        if not isinstance(proposal, dict) or not _proposal_seal_valid(proposal):
            raise ValueError("phase2a_admission_content_audit_proposal_seal_invalid")
        proposal_id = str(proposal.get("proposal_id"))
        if not _PROPOSAL_ID.fullmatch(proposal_id) or proposal_id in proposal_ids:
            raise ValueError("phase2a_admission_content_audit_proposal_id_invalid")
        proposal_ids.add(proposal_id)
        binding = proposal.get("quarantine_representation_binding")
        if not isinstance(binding, dict):
            raise ValueError("phase2a_admission_content_audit_proposal_binding_invalid")
        selected_item = binding.get("selected_admission_binding")
        if not isinstance(selected_item, dict):
            raise ValueError("phase2a_admission_content_audit_proposal_binding_invalid")
        record_id = str(selected_item.get("record_id"))
        manifest_item = selected_by_id.get(record_id)
        record = records_by_id.get(record_id)
        authority_identity_id = str(selected_item.get("authority_identity_id"))
        if (
            manifest_item is None
            or record is None
            or selected_item != manifest_item
            or record_id in joined_ids
            or binding.get("manifest_path") != manifest_portable_path
            or binding.get("manifest_content_sha256") != quarantine_binding.content_sha256
            or binding.get("manifest_file_sha256") != quarantine_binding.file_sha256
            or binding.get("representation_equivalence_assumed") is not False
            or proposal.get("canonical_authority_identity_key")
            != f"identity:{authority_identity_id}".casefold()
            or proposal.get("recommended_owner_outcome")
            != "ADMIT_PROPOSITION_LEVEL_OFFICIAL_SOURCE_WITH_ALL_LISTED_HOLDS_RETAINED"
            or proposal.get("owner_source_admission_required") is not True
            or proposal.get("source_admission_authorized") is not False
            or proposal.get("source_admitted") is not False
            or proposal.get("automatic_indexing") is not False
            or proposal.get("automatic_embedding") is not False
            or proposal.get("candidate_mutated") is not False
        ):
            raise ValueError("phase2a_admission_content_audit_proposal_binding_invalid")
        if (
            record.get("authority_identity_id") != authority_identity_id
            or record.get("result") != "DOWNLOADED_QUARANTINED_BOUND"
            or record.get("representation_role") != "PROPOSED_ADMISSION_REPRESENTATION"
            or record.get("selected_for_proposed_admission") is not True
            or record.get("source_admission_authorized") is not False
            or record.get("source_admitted") is not False
            or record.get("automatic_indexing") is not False
            or record.get("automatic_embedding") is not False
            or record.get("candidate_mutated") is not False
            or not _SOURCE_VERSION_ID.fullmatch(str(record.get("proposed_source_version_id")))
        ):
            raise ValueError("phase2a_admission_content_audit_selected_record_invalid")
        joined_ids.add(record_id)
        joined.append((proposal, selected_item, record))
    if joined_ids != set(selected_by_id):
        raise ValueError("phase2a_admission_content_audit_proposal_coverage_invalid")
    return sorted(joined, key=lambda item: str(item[1]["record_id"]))


def _html_projection(raw: bytes) -> HtmlProjection:
    parser = _VisibleHtmlParser()
    try:
        parser.feed(raw.decode("utf-8", errors="strict"))
        parser.close()
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("phase2a_admission_content_audit_html_invalid") from exc
    return parser.projection()


def _locator_tokens(locators: Sequence[Any]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                match.group(0).upper().replace("  ", " ")
                for locator in locators
                for match in _FCA_LOCATOR.finditer(str(locator))
            }
        )
    )


def _numbered_paragraphs(text: str) -> frozenset[int]:
    return frozenset(
        int(match.group("bracket") or match.group("dot"))
        for match in _PARAGRAPH_MARKER.finditer(text)
    )


def _audit_html(
    raw: bytes,
    *,
    selected: Mapping[str, Any],
    record: Mapping[str, Any],
) -> tuple[str, list[str], list[str], dict[str, Any]]:
    projection = _html_projection(raw)
    visible = projection.visible_text
    visible_sha256 = _sha256(visible.encode("utf-8"))
    host = (urlsplit(str(record["final_url"])).hostname or "").casefold()
    evidence: dict[str, Any] = {
        "html_title": projection.title,
        "normalized_visible_text_length": len(visible),
        "normalized_visible_text_sha256": visible_sha256,
        "official_host": host,
    }

    if host == "handbook.fca.org.uk":
        locator_tokens = _locator_tokens(selected.get("exact_locators") or [])
        present_tokens = tuple(token for token in locator_tokens if token in visible.upper())
        loader_markers = tuple(
            marker
            for marker in ("p-progressspinner", "Page_loader")
            if marker in raw.decode("utf-8", errors="replace")
        )
        evidence.update(
            {
                "claimed_locator_tokens": list(locator_tokens),
                "present_claimed_locator_tokens": list(present_tokens),
                "loader_markers": list(loader_markers),
                "exact_shell_fingerprint": (
                    (len(visible), visible_sha256) in FCA_VISIBLE_FINGERPRINTS
                ),
            }
        )
        if (
            projection.title == "FCA Handbook"
            and bool(loader_markers)
            and (len(visible), visible_sha256) in FCA_VISIBLE_FINGERPRINTS
            and not present_tokens
        ):
            return "FAIL", [FCA_FAILURE], [], evidence
        if len(visible) >= 5000 and present_tokens:
            return "PASS", [], [], evidence
        return "FAIL", ["FCA_RULE_BODY_NOT_DETERMINISTICALLY_VERIFIED"], [], evidence

    if host == "hudoc.echr.coe.int":
        requested_ids = tuple(
            sorted(parse_qs(urlsplit(str(record["final_url"])).query).get("i", []))
        )
        requested_id_present = any(identifier in visible for identifier in requested_ids)
        paragraph_numbers = sorted(_numbered_paragraphs(visible))
        evidence.update(
            {
                "requested_document_ids": list(requested_ids),
                "requested_document_id_present": requested_id_present,
                "numbered_paragraph_marker_count": len(paragraph_numbers),
                "exact_shell_fingerprint": (
                    projection.title == HUDOC_VISIBLE_TEXT
                    and visible == HUDOC_VISIBLE_TEXT
                    and visible_sha256 == HUDOC_VISIBLE_SHA256
                ),
            }
        )
        if (
            projection.title == HUDOC_VISIBLE_TEXT
            and visible == HUDOC_VISIBLE_TEXT
            and visible_sha256 == HUDOC_VISIBLE_SHA256
            and not requested_id_present
            and not paragraph_numbers
        ):
            return "FAIL", [HUDOC_FAILURE], [], evidence
        if len(visible) >= 5000 and requested_id_present and paragraph_numbers:
            return "PASS", [], [], evidence
        return "FAIL", ["HUDOC_CASE_DOCUMENT_NOT_DETERMINISTICALLY_VERIFIED"], [], evidence

    if host in {"www.judiciary.uk", "judiciary.uk"}:
        citation = str(record["authority_identity_id"]).removeprefix("neutral-citation:")
        paragraph_numbers = _numbered_paragraphs(visible)
        body_node_present = bool(
            projection.identifiers
            & {
                "judgment-body",
                "judgment_body",
                "judgment-content",
                "judgment__body",
            }
        )
        range_21_52_count = len(paragraph_numbers & set(range(21, 53)))
        evidence.update(
            {
                "neutral_citation_present": citation.casefold() in visible.casefold(),
                "judgment_body_node_present": body_node_present,
                "numbered_paragraph_marker_count": len(paragraph_numbers),
                "paragraph_21_52_marker_count": range_21_52_count,
            }
        )
        if (
            citation.casefold() in visible.casefold()
            and not body_node_present
            and range_21_52_count == 0
        ):
            return "FAIL", [JUDICIARY_FAILURE], [], evidence
        if body_node_present and range_21_52_count >= 2 and len(visible) >= 5000:
            return "PASS", [], [], evidence
        return "FAIL", ["JUDICIARY_JUDGMENT_BODY_NOT_DETERMINISTICALLY_VERIFIED"], [], evidence

    if host in {"www.tas-cas.org", "tas-cas.org"}:
        present = tuple(marker for marker in TAS_REQUIRED_RULE_MARKERS if marker in visible)
        noisy_overlay = TAS_NO_RESULTS_MARKER in visible
        evidence.update(
            {
                "required_rule_markers": list(TAS_REQUIRED_RULE_MARKERS),
                "present_rule_markers": list(present),
                "noisy_search_overlay_present": noisy_overlay,
            }
        )
        if present == TAS_REQUIRED_RULE_MARKERS and len(visible) >= 10000:
            warnings = ["TAS_NOISY_SEARCH_OVERLAY_RULE_BODY_PRESENT"] if noisy_overlay else []
            return ("PASS_WITH_WARNING" if warnings else "PASS"), [], warnings, evidence
        return "FAIL", ["TAS_RULE_BODY_NOT_DETERMINISTICALLY_VERIFIED"], [], evidence

    if host in {"www.gov.uk", "gov.uk", "www.sra.org.uk", "sra.org.uk"}:
        main_or_article = bool(
            projection.identifiers & {"tag:main", "tag:article", "main", "main-content", "content"}
        )
        title_present = bool(projection.title) and projection.title.split(" - ")[0] in visible
        evidence.update(
            {
                "main_content_identifier_present": main_or_article,
                "document_title_present_in_visible_text": title_present,
            }
        )
        if len(visible) >= 10000 and title_present and main_or_article:
            return "PASS", [], [], evidence
        return "FAIL", ["OFFICIAL_HTML_BODY_NOT_DETERMINISTICALLY_VERIFIED"], [], evidence

    return "FAIL", ["UNSUPPORTED_HTML_SOURCE_FOR_SUBSTANTIVE_AUDIT"], [], evidence


def _audit_xml(raw: bytes) -> tuple[str, list[str], list[str], dict[str, Any]]:
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return "FAIL", ["XML_DOCUMENT_NOT_WELL_FORMED"], [], {}
    root_name = root.tag.rsplit("}", 1)[-1]
    element_names = Counter(element.tag.rsplit("}", 1)[-1] for element in root.iter())
    text = " ".join(" ".join(root.itertext()).split())
    evidence = {
        "xml_root_local_name": root_name,
        "normalized_document_text_length": len(text),
        "normalized_document_text_sha256": _sha256(text.encode("utf-8")),
    }
    if root_name == "akomaNtoso":
        substantive = element_names["judgment"] == 1 and element_names["judgmentBody"] == 1
    elif root_name == "Legislation":
        substantive = any(
            element_names[name] > 0
            for name in ("EURetained", "Primary", "Secondary", "P1group", "P1", "Text")
        )
    else:
        substantive = False
    if substantive and len(text) >= 1000:
        return "PASS", [], [], evidence
    return "FAIL", ["XML_LEGAL_BODY_NOT_DETERMINISTICALLY_VERIFIED"], [], evidence


def _audit_pdf(raw: bytes) -> tuple[str, list[str], list[str], dict[str, Any]]:
    envelope_valid = raw.startswith(b"%PDF-") and raw.rstrip().endswith(b"%%EOF")
    try:
        reader = PdfReader(io.BytesIO(raw), strict=True)
        if reader.is_encrypted:
            raise ValueError("encrypted")
        text = " ".join(" ".join((page.extract_text() or "") for page in reader.pages).split())
        page_count = len(reader.pages)
    except Exception:  # pypdf exposes several parser exception subtypes.
        text = ""
        page_count = 0
    evidence = {
        "pdf_envelope_valid": envelope_valid,
        "pdf_page_count": page_count,
        "normalized_document_text_length": len(text),
        "normalized_document_text_sha256": _sha256(text.encode("utf-8")),
    }
    if envelope_valid and page_count > 0 and len(text) >= 1000:
        return "PASS", [], [], evidence
    return "FAIL", ["PDF_LEGAL_BODY_NOT_DETERMINISTICALLY_VERIFIED"], [], evidence


def _audit_representation(
    raw: bytes,
    *,
    proposal: Mapping[str, Any],
    selected: Mapping[str, Any],
    record: Mapping[str, Any],
) -> dict[str, Any]:
    content_type = str(record["content_type"])
    if content_type == "text/html":
        verdict, failures, warnings, evidence = _audit_html(raw, selected=selected, record=record)
    elif content_type == "application/xml":
        verdict, failures, warnings, evidence = _audit_xml(raw)
    elif content_type == "application/pdf":
        verdict, failures, warnings, evidence = _audit_pdf(raw)
    else:
        verdict = "FAIL"
        failures = ["UNSUPPORTED_CONTENT_TYPE_FOR_SUBSTANTIVE_AUDIT"]
        warnings = []
        evidence = {}
    material = {
        "audit_record_id": (
            "admission-content-audit-" + _sha256(str(record["record_id"]).encode("utf-8"))[:24]
        ),
        "proposal_id": proposal["proposal_id"],
        "record_id": record["record_id"],
        "authority_identity_id": record["authority_identity_id"],
        "proposed_source_version_id": record["proposed_source_version_id"],
        "quarantine_member": record["quarantine_member"],
        "raw_sha256": record["raw_sha256"],
        "bytes": record["bytes"],
        "content_type": content_type,
        "substantive_content_verdict": verdict,
        "failure_reason_codes": failures,
        "warning_reason_codes": warnings,
        "substantive_content_eligible": verdict in {"PASS", "PASS_WITH_WARNING"},
        "audit_evidence": evidence,
        "source_admission_authorized": False,
        "source_admitted": False,
        "source_scan_run": False,
        "index_built": False,
        "embedding_run": False,
        "candidate_mutated": False,
    }
    return {**material, "record_content_sha256": _sealed(material)}


def _audit_all(
    joined: Sequence[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]],
    *,
    quarantine_root: Path,
) -> list[dict[str, Any]]:
    audited: list[dict[str, Any]] = []
    for proposal, selected, record in joined:
        member = str(record.get("quarantine_member"))
        if Path(member).name != member or member in {"", ".", ".."}:
            raise ValueError("phase2a_admission_content_audit_member_name_invalid")
        member_path = quarantine_root / member
        raw = _read_regular_no_follow(member_path, within=quarantine_root)
        if (
            len(raw) != record.get("bytes")
            or _sha256(raw) != record.get("raw_sha256")
            or record.get("raw_sha256") != selected.get("raw_sha256")
            or record.get("bytes") != selected.get("bytes")
        ):
            raise ValueError("phase2a_admission_content_audit_member_byte_binding_mismatch")
        audited.append(
            _audit_representation(
                raw,
                proposal=proposal,
                selected=selected,
                record=record,
            )
        )
    return audited


def _summarize(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    failures = {
        str(record["record_id"]): str(record["failure_reason_codes"][0])
        for record in records
        if record["substantive_content_verdict"] == "FAIL"
    }
    warnings = {
        str(record["record_id"]): str(record["warning_reason_codes"][0])
        for record in records
        if record["warning_reason_codes"]
    }
    pass_count = sum(
        record["substantive_content_verdict"] in {"PASS", "PASS_WITH_WARNING"} for record in records
    )
    exact_expected = (
        len(records) == EXPECTED_PROPOSAL_COUNT
        and pass_count == EXPECTED_PASS_COUNT
        and failures == EXPECTED_FAILURE_CATEGORY_BY_RECORD_ID
        and warnings == EXPECTED_WARNING_CATEGORY_BY_RECORD_ID
    )
    return {
        "audited_representation_count": len(records),
        "pass_count": pass_count,
        "fail_count": len(failures),
        "pass_with_warning_count": sum(
            record["substantive_content_verdict"] == "PASS_WITH_WARNING" for record in records
        ),
        "failure_reason_counts": dict(
            sorted(
                Counter(failures.values()).items(),
            )
        ),
        "failure_record_ids": sorted(failures),
        "warning_reason_counts": dict(sorted(Counter(warnings.values()).items())),
        "warning_record_ids": sorted(warnings),
        "expected_failure_count": EXPECTED_FAILURE_COUNT,
        "expected_pass_count": EXPECTED_PASS_COUNT,
        "exact_expected_result": exact_expected,
    }


def _false_boundaries() -> dict[str, bool]:
    return {field: False for field in _TOP_LEVEL_FALSE_FIELDS}


def _package_artifacts(
    records: list[dict[str, Any]],
    *,
    packet_binding: BoundArtifact,
    quarantine_binding: BoundArtifact,
) -> tuple[dict[str, bytes], dict[str, Any]]:
    summary = _summarize(records)
    status = (
        "BLOCKED_EXACT_SUBSTANTIVE_CONTENT_FAILURE_SET"
        if summary["exact_expected_result"]
        else "FAIL_CLOSED_UNEXPECTED_SUBSTANTIVE_CONTENT_RESULT"
    )
    audit_material = {
        "schema": "legalbot.v111.phase2a.admission-content-audit.v1",
        "status": status,
        "route": "READ_ONLY_CREATE_ONLY_SUBSTANTIVE_CONTENT_AUDIT",
        "input_bindings": {
            "exact_remediation_owner_packet": {
                "path": _portable_path(packet_binding.path),
                "content_sha256": packet_binding.content_sha256,
                "file_sha256": packet_binding.file_sha256,
                "proposed_source_admission_count": EXPECTED_PROPOSAL_COUNT,
            },
            "research_wave_quarantine_manifest": {
                "path": _portable_path(quarantine_binding.path),
                "content_sha256": quarantine_binding.content_sha256,
                "file_sha256": quarantine_binding.file_sha256,
                "selected_admission_binding_count": EXPECTED_PROPOSAL_COUNT,
            },
        },
        "summary": summary,
        "records": records,
        "network_used": False,
        "noisy_search_overlay_is_not_itself_a_content_failure": True,
        **_false_boundaries(),
    }
    audit = {**audit_material, "artifact_content_sha256": _sealed(audit_material)}
    audit_raw = _pretty_json(audit)

    outcome_material = {
        "schema": "legalbot.v111.phase2a.admission-content-audit-outcome.v1",
        "status": status,
        "audit_artifact": {
            "name": AUDIT_NAME,
            "content_sha256": audit["artifact_content_sha256"],
            "file_sha256": _sha256(audit_raw),
            "record_count": len(records),
        },
        "summary": summary,
        "safe_next_state": "HOLD_FAILED_REPRESENTATIONS_AND_PREPARE_EXACT_REPLACEMENT_PACKET",
        "successor_scan_or_build_allowed_by_this_audit": False,
        **_false_boundaries(),
    }
    outcome = {**outcome_material, "outcome_content_sha256": _sealed(outcome_material)}
    outcome_raw = _pretty_json(outcome)

    package_material = {
        "schema": "legalbot.v111.phase2a.admission-content-audit-package.v1",
        "status": status,
        "artifacts": [
            {
                "name": AUDIT_NAME,
                "content_sha256": audit["artifact_content_sha256"],
                "file_sha256": _sha256(audit_raw),
            },
            {
                "name": OUTCOME_NAME,
                "content_sha256": outcome["outcome_content_sha256"],
                "file_sha256": _sha256(outcome_raw),
            },
        ],
        "input_content_sha256": {
            "exact_remediation_owner_packet": packet_binding.content_sha256,
            "research_wave_quarantine_manifest": quarantine_binding.content_sha256,
        },
        **_false_boundaries(),
    }
    package = {**package_material, "package_content_sha256": _sealed(package_material)}
    package_raw = _pretty_json(package)
    checksum_raw = (
        f"{_sha256(audit_raw)}  {AUDIT_NAME}\n"
        f"{_sha256(outcome_raw)}  {OUTCOME_NAME}\n"
        f"{_sha256(package_raw)}  {PACKAGE_NAME}\n"
    ).encode("ascii")
    artifacts = {
        AUDIT_NAME: audit_raw,
        OUTCOME_NAME: outcome_raw,
        PACKAGE_NAME: package_raw,
        CHECKSUM_NAME: checksum_raw,
    }
    return artifacts, outcome


def _validated_output_root(output_root: Path) -> Path:
    if REVIEW_ROOT.is_symlink() or not REVIEW_ROOT.is_dir():
        raise ValueError("phase2a_admission_content_audit_review_root_invalid")
    review = REVIEW_ROOT.resolve()
    resolved = output_root.resolve()
    if resolved == review or not resolved.is_relative_to(review):
        raise ValueError("phase2a_admission_content_audit_output_outside_review_root")
    if resolved.parent.is_symlink() or not resolved.parent.is_dir():
        raise ValueError("phase2a_admission_content_audit_output_parent_invalid")
    if resolved.exists() or resolved.is_symlink():
        raise ValueError("phase2a_admission_content_audit_output_already_exists")
    return resolved


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


def _write_transactional_package(output_root: Path, artifacts: Mapping[str, bytes]) -> None:
    staging_root = Path(
        tempfile.mkdtemp(prefix=f".{output_root.name}.staging-", dir=output_root.parent)
    )
    try:
        staging_root.chmod(0o700)
        for name, raw in sorted(artifacts.items()):
            _write_exclusive(staging_root / name, raw)
        descriptor = os.open(staging_root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if output_root.exists() or output_root.is_symlink():
            raise ValueError("phase2a_admission_content_audit_output_already_exists")
        os.rename(staging_root, output_root)
        parent_descriptor = os.open(output_root.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    finally:
        if staging_root.exists():
            shutil.rmtree(staging_root)


def build(
    output_root: Path,
    *,
    packet_binding: BoundArtifact | None = None,
    quarantine_binding: BoundArtifact | None = None,
) -> dict[str, Any]:
    """Audit the exact sealed inputs and atomically publish one immutable package."""

    output_root = _validated_output_root(output_root)
    packet_binding = packet_binding or BoundArtifact(
        DEFAULT_PACKET_PATH,
        PACKET_CONTENT_SHA256,
        PACKET_FILE_SHA256,
        "artifact_content_sha256",
    )
    quarantine_binding = quarantine_binding or BoundArtifact(
        DEFAULT_QUARANTINE_MANIFEST_PATH,
        QUARANTINE_CONTENT_SHA256,
        QUARANTINE_FILE_SHA256,
        "manifest_content_sha256",
    )
    packet = _load_bound_json(packet_binding, schema=PACKET_SCHEMA, role="packet")
    quarantine = _load_bound_json(
        quarantine_binding,
        schema=QUARANTINE_SCHEMA,
        role="quarantine",
    )
    joined = _validate_and_join_inputs(
        packet,
        quarantine,
        quarantine_binding=quarantine_binding,
    )
    records = _audit_all(joined, quarantine_root=quarantine_binding.path.parent)
    artifacts, outcome = _package_artifacts(
        records,
        packet_binding=packet_binding,
        quarantine_binding=quarantine_binding,
    )
    _write_transactional_package(output_root, artifacts)
    return outcome


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--packet", type=Path, default=DEFAULT_PACKET_PATH)
    parser.add_argument(
        "--quarantine-manifest",
        type=Path,
        default=DEFAULT_QUARANTINE_MANIFEST_PATH,
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    outcome = build(
        args.output_root,
        packet_binding=BoundArtifact(
            args.packet,
            PACKET_CONTENT_SHA256,
            PACKET_FILE_SHA256,
            "artifact_content_sha256",
        ),
        quarantine_binding=BoundArtifact(
            args.quarantine_manifest,
            QUARANTINE_CONTENT_SHA256,
            QUARANTINE_FILE_SHA256,
            "manifest_content_sha256",
        ),
    )
    print(json.dumps(outcome["summary"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
