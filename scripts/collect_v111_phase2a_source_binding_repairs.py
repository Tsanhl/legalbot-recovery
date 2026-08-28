#!/usr/bin/env python3
"""Collect exact substantive replacements for defective Phase-2A bindings.

The approved 2026-08-28 packet bound sixteen official-site representations that
preserve the requested URLs and bytes but do not contain the claimed legal body.
This create-only collector verifies those old bindings, downloads one bounded
set of official replacements for eleven repairable bindings into quarantine,
and proves that every replacement contains its claimed title and locator
markers.  The unavailable EWCA and all four defective HUDOC judgment
representations remain explicit holds.

Nothing produced here is admitted, scanned, indexed, embedded, qualified, or
eligible for answers.  Replacement bytes require a new exact owner decision.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import Request, urlopen

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
PACKET_ROOT = REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-exact-remediation-owner-packet-r1"
PACKET_PATH = PACKET_ROOT / "EXACT-REMEDIATION-OWNER-PACKET-361.json"
QUARANTINE_ROOT = REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-source-quarantine"
QUARANTINE_MANIFEST_PATH = QUARANTINE_ROOT / "QUARANTINE-MANIFEST.json"
DEFAULT_OUTPUT_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-source-binding-repair-quarantine-r7"
)

EXPECTED_PACKET_CONTENT_SHA256 = "93ad9113af76896f0570a3666c446472af7587b7e3ff32b7464e670777ec6b6c"
EXPECTED_PACKET_FILE_SHA256 = "992770c04cb3e08de64bb98e80aa9801171d3e66e4b573b85919091a78b1db3b"
EXPECTED_QUARANTINE_CONTENT_SHA256 = (
    "b6d900b23232379a4d6c19d313f35c47e0758ce5e0bb6eb04008f9eba07a3819"
)
EXPECTED_QUARANTINE_FILE_SHA256 = "f482366a2ba0d9f636c56104d632767a8eadd6e9a9625d50ef5391a5f62995eb"

ALLOWED_HOSTS = frozenset(
    {
        "api-handbook.fca.org.uk",
        "hudoc.echr.coe.int",
    }
)
USER_AGENT = "LegalBot-v1.11-source-binding-repair/1.0"
FCA_POINT_IN_TIME_DATE = "14-08-2026"
MAX_RESPONSE_BYTES = 25 * 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

_FALSE_BOUNDARY_FIELDS = (
    "owner_approved",
    "owner_decisions_applied",
    "owner_outcomes_applied",
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


@dataclass(frozen=True)
class Replacement:
    replacement_key: str
    old_record_id: str
    canonical_url: str
    representation_url: str
    suffix: str
    expected_media_type: str
    title_markers: tuple[str, ...]
    locator_markers: tuple[str, ...]
    identity_front_matter_markers: tuple[str, ...] = ()
    paragraph_markers: tuple[int, ...] = ()
    minimum_bytes: int = 8_000
    minimum_text_characters: int = 1_000
    expected_json_chapter: str | None = None
    expected_json_section: str | None = None
    source_version_mode: str = "OFFICIAL_CURRENT_AT_RETRIEVAL_NOT_POINT_IN_TIME"


def _fca_json_url(chapter: str, section: str = "") -> str:
    params = {"Date": FCA_POINT_IN_TIME_DATE}
    if section:
        params["sectionId"] = section
    return (
        "https://api-handbook.fca.org.uk/Handbook/"
        f"GetAllHandBookProvisionsSortedOrderByChapter/{chapter}?" + urlencode(params)
    )


def _fca_replacement(
    replacement_key: str,
    old_record_id: str,
    canonical_url: str,
    chapter: str,
    section: str,
    title_markers: tuple[str, ...],
    locator_markers: tuple[str, ...],
) -> Replacement:
    return Replacement(
        replacement_key=replacement_key,
        old_record_id=old_record_id,
        canonical_url=canonical_url,
        representation_url=_fca_json_url(chapter, section),
        suffix=".json",
        expected_media_type="application/json",
        title_markers=title_markers,
        locator_markers=locator_markers,
        expected_json_chapter=chapter,
        expected_json_section=section or None,
        source_version_mode="OFFICIAL_POINT_IN_TIME_2026-08-14",
    )


REPLACEMENTS = (
    _fca_replacement(
        "fca-cobs10-2026-08-14-json",
        "quarantine-binding-f8a3307ef69293278c5531e9",
        "https://handbook.fca.org.uk/handbook/cobs10?date=2026-08-14&timeline=true",
        "cobs10",
        "",
        ("COBS 10", "Appropriateness"),
        ("10.2.1", "10.2.2"),
    ),
    _fca_replacement(
        "fca-cobs10a-2026-08-14-json",
        "quarantine-binding-d0474e100e630e772055180c",
        "https://handbook.fca.org.uk/handbook/cobs10a?date=2026-08-14&timeline=true",
        "cobs10a",
        "",
        ("COBS 10A", "Appropriateness"),
        ("10A.1.1", "10A.2.1", "10A.3.1", "10A.4.1"),
    ),
    _fca_replacement(
        "fca-cobs14-3-2026-08-14-json",
        "quarantine-binding-87f163e3509d14d6a37a62b6",
        "https://handbook.fca.org.uk/handbook/cobs14/cobs14s3?date=2026-08-14&timeline=true",
        "cobs14",
        "cobs14s3",
        ("COBS 14.3", "designated investments"),
        ("14.3.1", "14.3.2", "14.3.4", "14.3.5"),
    ),
    _fca_replacement(
        "fca-cobs14-3a-2026-08-14-json",
        "quarantine-binding-87f560afff24458a4860fe7d",
        "https://handbook.fca.org.uk/handbook/cobs14/cobs14s6?date=2026-08-14&timeline=true",
        "cobs14",
        "cobs14s6",
        ("COBS 14.3A", "financial instruments"),
        ("14.3A.1", "14.3A.3", "14.3A.5", "14.3A.7", "14.3A.9"),
    ),
    _fca_replacement(
        "fca-cobs2-2a-2026-08-14-json",
        "quarantine-binding-5250c824665dd618ee8ca7b4",
        "https://handbook.fca.org.uk/handbook/cobs2/cobs2s6?date=2026-08-14&timeline=true",
        "cobs2",
        "cobs2s6",
        ("COBS 2.2A", "Information disclosure"),
        ("2.2A.1", "2.2A.2", "2.2A.3"),
    ),
    _fca_replacement(
        "fca-cobs2-3-2026-08-14-json",
        "quarantine-binding-80a78f6ef29e6748d869b850",
        "https://handbook.fca.org.uk/handbook/cobs2/cobs2s3?date=2026-08-14&timeline=true",
        "cobs2",
        "cobs2s3",
        ("COBS 2.3", "Inducements"),
        ("2.3.1",),
    ),
    _fca_replacement(
        "fca-cobs2-3a-2026-08-14-json",
        "quarantine-binding-80a78f6ef29e6748d869b850",
        "https://handbook.fca.org.uk/handbook/cobs2/cobs2s7?date=2026-08-14&timeline=true",
        "cobs2",
        "cobs2s7",
        ("COBS 2.3A", "Inducements"),
        ("2.3A.5", "2.3A.10", "2.3A.13"),
    ),
    _fca_replacement(
        "fca-cobs4-2-2026-08-14-json",
        "quarantine-binding-035155a0fd7eb9b7d85ac164",
        "https://handbook.fca.org.uk/handbook/cobs4/cobs4s2?date=2026-08-14&timeline=true",
        "cobs4",
        "cobs4s2",
        ("COBS 4.2", "fair, clear and not misleading"),
        ("4.2.1", "4.2.2", "4.2.4", "4.2.5"),
    ),
    _fca_replacement(
        "fca-cobs9-2-2026-08-14-json",
        "quarantine-binding-4182da970c521667c7a18423",
        "https://handbook.fca.org.uk/handbook/cobs9/cobs9s2?date=2026-08-14&timeline=true",
        "cobs9",
        "cobs9s2",
        ("COBS 9.2", "Assessing suitability"),
        ("9.2.1", "9.2.2", "9.2.3", "9.2.6"),
    ),
    _fca_replacement(
        "fca-cobs9a-2-2026-08-14-json",
        "quarantine-binding-e47c5df0358c13f249834f73",
        "https://handbook.fca.org.uk/handbook/cobs9a/cobs9as2?date=2026-08-14&timeline=true",
        "cobs9a",
        "cobs9as2",
        ("COBS 9A.2", "Assessing suitability"),
        ("9A.2.1",),
    ),
    _fca_replacement(
        "fca-comp3-2026-08-14-json",
        "quarantine-binding-c77651e23cb2156c65e9c850",
        "https://handbook.fca.org.uk/handbook/comp3?date=2026-08-14&timeline=true",
        "comp3",
        "",
        ("COMP 3", "qualifying conditions"),
        ("3.2.1",),
    ),
    _fca_replacement(
        "fca-comp5-2026-08-14-json",
        "quarantine-binding-c77651e23cb2156c65e9c850",
        "https://handbook.fca.org.uk/handbook/comp5?date=2026-08-14&timeline=true",
        "comp5",
        "",
        ("COMP 5",),
        ("5.5.1", "5.5.3"),
    ),
    _fca_replacement(
        "fca-comp6-2026-08-14-json",
        "quarantine-binding-c77651e23cb2156c65e9c850",
        "https://handbook.fca.org.uk/handbook/comp6?date=2026-08-14&timeline=true",
        "comp6",
        "",
        ("COMP 6",),
        ("6.3.1", "6.3.3"),
    ),
    _fca_replacement(
        "fca-comp10-2026-08-14-json",
        "quarantine-binding-c77651e23cb2156c65e9c850",
        "https://handbook.fca.org.uk/handbook/comp10?date=2026-08-14&timeline=true",
        "comp10",
        "",
        ("COMP 10", "compensation"),
        ("10.2.1", "10.2.3"),
    ),
    _fca_replacement(
        "fca-disp2-8-2026-08-14-json",
        "quarantine-binding-1c53d8ee4bfc4e3cdf174423",
        "https://handbook.fca.org.uk/handbook/disp2/disp2s8?date=2026-08-14&timeline=true",
        "disp2",
        "disp2s8",
        ("DISP 2.8", "complaint"),
        ("2.8.2", "2.8.2A", "2.8.3"),
    ),
)

DEFECTIVE_OLD_RECORD_IDS = frozenset(
    {
        *(item.old_record_id for item in REPLACEMENTS),
        "quarantine-binding-caeef16146c2eea1e2b03d09",
        "quarantine-binding-678af407a5abea67aa817bee",
        "quarantine-binding-3688eea8275753b9dcabf559",
        "quarantine-binding-0a370f8e41122c812c5f26d2",
        "quarantine-binding-d07fad39256d15a7c6a25893",
    }
)
UNRESOLVED_REPAIR_HOLDS = (
    {
        "old_record_id": "quarantine-binding-caeef16146c2eea1e2b03d09",
        "category": "JUDICIARY_LANDING_METADATA_NO_JUDGMENT_BODY",
        "reason_code": "OFFICIAL_SUBSTANTIVE_BYTES_CURRENTLY_UNAVAILABLE",
        "checked_official_endpoints": [
            "https://www.judiciary.uk/wp-content/uploads/2022/07/"
            "Shanghai-Shipyard-v-Reignwood-International-Investment-judgment.pdf",
            "https://caselaw.nationalarchives.gov.uk/ewca/civ/2021/1147",
            "https://www.judiciary.uk/wp-json/wp/v2/media?parent=22952&per_page=100",
        ],
        "observed_results": ["HTTP_404", "HTTP_404", "EMPTY_MEDIA_LIST"],
        "source_admission_authorized": False,
        "source_admitted": False,
        "currentness_hold_retained": True,
        "later_treatment_hold_retained": True,
    },
    {
        "old_record_id": "quarantine-binding-3688eea8275753b9dcabf559",
        "category": "HUDOC_GENERIC_APP_SHELL_NO_CASE_DOCUMENT",
        "reason_code": "OFFICIAL_SUBSTANTIVE_BYTES_SINGLE_TRANSPORT_FAILURE_SCHEMA_UNVERIFIED",
        "checked_official_endpoints": [
            "https://hudoc.echr.coe.int/app/conversion/docx/html/body?"
            "library=ECHR&id=001-186828&logEvent=False",
            "https://hudoc.echr.coe.int/eng?i=001-186828",
        ],
        "observed_results": [
            "REMOTE_DISCONNECTED_FIRST_BOUNDED_ATTEMPT_NOT_RETRIED",
            "GENERIC_HUDOC_APPLICATION_SHELL",
        ],
        "source_admission_authorized": False,
        "source_admitted": False,
        "currentness_hold_retained": True,
        "later_treatment_hold_retained": True,
    },
    {
        "old_record_id": "quarantine-binding-678af407a5abea67aa817bee",
        "category": "HUDOC_GENERIC_APP_SHELL_NO_CASE_DOCUMENT",
        "reason_code": "OFFICIAL_SUBSTANTIVE_BYTES_TRANSPORT_UNAVAILABLE",
        "checked_official_endpoints": [
            "https://hudoc.echr.coe.int/app/conversion/docx/html/body?"
            "library=ECHR&id=001-210077&logEvent=False",
            "https://hudoc.echr.coe.int/eng?i=001-210077",
            "https://www.echr.coe.int/w/big-brother-watch-and-others-v.-the-"
            "united-kingdom-nos.-58170/13-62322/14-and-24960/15-",
        ],
        "observed_results": [
            "REPEATED_TIMEOUT_OR_EMPTY_RESPONSE",
            "GENERIC_HUDOC_APPLICATION_SHELL",
            "CASE_IDENTITY_PAGE_ONLY_NO_JUDGMENT_BYTES",
        ],
        "source_admission_authorized": False,
        "source_admitted": False,
        "currentness_hold_retained": True,
        "later_treatment_hold_retained": True,
    },
    {
        "old_record_id": "quarantine-binding-0a370f8e41122c812c5f26d2",
        "category": "HUDOC_GENERIC_APP_SHELL_NO_CASE_DOCUMENT",
        "reason_code": "HUDOC_STRUCTURAL_VALIDATION_REPEAT_FINGERPRINT_PATH_STOPPED",
        "checked_official_endpoints": [
            "https://hudoc.echr.coe.int/app/conversion/docx/html/body?"
            "library=ECHR&id=001-233206&logEvent=False",
            "https://hudoc.echr.coe.int/eng?i=001-233206",
        ],
        "observed_results": [
            "SUBSTANTIVE_BYTES_FETCHED_BUT_STRICT_STRUCTURE_NOT_ATTESTED",
            "SAME_VALIDATOR_FINGERPRINT_TWICE_STOPPED_BEFORE_THIRD_ATTEMPT",
        ],
        "source_admission_authorized": False,
        "source_admitted": False,
        "currentness_hold_retained": True,
        "later_treatment_hold_retained": True,
    },
    {
        "old_record_id": "quarantine-binding-d07fad39256d15a7c6a25893",
        "category": "HUDOC_GENERIC_APP_SHELL_NO_CASE_DOCUMENT",
        "reason_code": "HUDOC_COLLECTION_NOT_RUN_AFTER_PATH_STOP",
        "checked_official_endpoints": [
            "https://hudoc.echr.coe.int/app/conversion/docx/html/body?"
            "library=ECHR&id=001-57974&logEvent=False",
            "https://hudoc.echr.coe.int/eng?i=001-57974",
        ],
        "observed_results": [
            "READ_ONLY_DOM_RESEARCH_NOT_ADMISSIBLE_BYTES",
            "COLLECTOR_PATH_STOPPED_BEFORE_THIS_ITEM",
        ],
        "source_admission_authorized": False,
        "source_admitted": False,
        "currentness_hold_retained": True,
        "later_treatment_hold_retained": True,
    },
)


class _VisibleTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._skip_depth = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.casefold() in {"script", "style", "noscript"}:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() in {"script", "style", "noscript"} and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            self.parts.append(data)


class _JudgmentBodyParser(HTMLParser):
    """Extract converter-body paragraphs while excluding navigation and footnotes."""

    _EXCLUDED = frozenset(
        {
            "script",
            "noscript",
            "template",
            "nav",
            "header",
            "footer",
            "aside",
            "form",
            "input",
            "button",
            "iframe",
        }
    )
    _VOID = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.body_seen = False
        self._open_tags: list[str] = []
        self._body_stack_index: int | None = None
        self._wrapper_stack_index: int | None = None
        self.body_direct_div_count = 0
        self.body_direct_other_element_count = 0
        self.fragment_direct_div_count = 0
        self.fragment_direct_other_element_count = 0
        self.wrapper_classes: tuple[str, ...] = ()
        self.forbidden_tag_seen = False
        self._excluded_depth = 0
        self._footnote_stack_index: int | None = None
        self._paragraph_stack_index: int | None = None
        self._paragraph_parts: list[str] = []
        self._paragraph_is_toc = False
        self.paragraphs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.casefold()
        attr_map = {key.casefold(): value or "" for key, value in attrs}
        stack_index = len(self._open_tags)
        if tag == "body":
            if self.body_seen or self._body_stack_index is not None:
                raise ValueError("phase2a_binding_repair_multiple_html_bodies")
            self.body_seen = True
            self._body_stack_index = stack_index
        elif self._body_stack_index is not None:
            if stack_index == self._body_stack_index + 1:
                if tag == "div":
                    self.body_direct_div_count += 1
                    if self._wrapper_stack_index is None:
                        self._wrapper_stack_index = stack_index
                        self.wrapper_classes = tuple(
                            part for part in re.split(r"\s+", attr_map.get("class", "")) if part
                        )
                elif tag not in self._VOID:
                    self.body_direct_other_element_count += 1
            if tag in self._EXCLUDED:
                self.forbidden_tag_seen = True
        elif not self.body_seen and stack_index == 0:
            if tag == "div":
                self.fragment_direct_div_count += 1
                if self._wrapper_stack_index is None:
                    self._wrapper_stack_index = stack_index
                    self.wrapper_classes = tuple(
                        part for part in re.split(r"\s+", attr_map.get("class", "")) if part
                    )
            elif tag not in self._VOID:
                self.fragment_direct_other_element_count += 1
        if tag in self._EXCLUDED:
            self.forbidden_tag_seen = True
        if self._body_stack_index is not None and tag in self._EXCLUDED:
            self._excluded_depth += 1
        if (
            self._wrapper_stack_index is not None
            and self._footnote_stack_index is None
            and tag == "div"
            and attr_map.get("id", "").casefold().startswith("_ftn")
        ):
            self._footnote_stack_index = stack_index
        if (
            self._wrapper_stack_index is not None
            and self._footnote_stack_index is None
            and tag == "p"
            and not self._excluded_depth
        ):
            if self._paragraph_stack_index is not None:
                raise ValueError("phase2a_binding_repair_nested_html_paragraph")
            self._paragraph_stack_index = stack_index
            self._paragraph_parts = []
            self._paragraph_is_toc = False
        if (
            self._paragraph_stack_index is not None
            and tag == "a"
            and attr_map.get("href", "").casefold().startswith("#_toc")
        ):
            self._paragraph_is_toc = True
        if tag not in self._VOID:
            self._open_tags.append(tag)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.casefold()
        if tag in self._VOID:
            return
        if not self._open_tags or self._open_tags[-1] != tag:
            raise ValueError("phase2a_binding_repair_html_tag_nesting_invalid")
        stack_index = len(self._open_tags) - 1
        if tag == "p" and self._paragraph_stack_index == stack_index:
            paragraph = " ".join(" ".join(self._paragraph_parts).split())
            if paragraph and not self._paragraph_is_toc:
                self.paragraphs.append(paragraph)
            self._paragraph_parts = []
            self._paragraph_is_toc = False
            self._paragraph_stack_index = None
        if self._footnote_stack_index == stack_index:
            self._footnote_stack_index = None
        if tag in self._EXCLUDED and self._excluded_depth:
            self._excluded_depth -= 1
        if self._wrapper_stack_index == stack_index:
            self._wrapper_stack_index = None
        if self._body_stack_index == stack_index:
            self._body_stack_index = None
        self._open_tags.pop()

    def handle_data(self, data: str) -> None:
        if (
            self._paragraph_stack_index is not None
            and self._footnote_stack_index is None
            and not self._excluded_depth
        ):
            self._paragraph_parts.append(data)

    def close(self) -> None:
        super().close()
        if self._open_tags or self._paragraph_stack_index is not None:
            raise ValueError("phase2a_binding_repair_unclosed_html_element")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(file_path: Path) -> str:
    if file_path.is_symlink() or not file_path.is_file():
        raise ValueError("phase2a_binding_repair_input_not_regular")
    digest = hashlib.sha256()
    with file_path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(material: Any) -> str:
    return _sha256(_canonical_json(material))


def _false_boundaries() -> dict[str, bool]:
    return {field: False for field in _FALSE_BOUNDARY_FIELDS}


def _load_object(file_path: Path) -> dict[str, Any]:
    if file_path.is_symlink() or not file_path.is_file():
        raise ValueError("phase2a_binding_repair_input_not_regular")
    value = json.loads(file_path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_binding_repair_input_not_object")
    return value


def _verify_seal(value: dict[str, Any], field: str, expected: str) -> None:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if supplied != expected or not _SHA256.fullmatch(supplied):
        raise ValueError("phase2a_binding_repair_input_digest_mismatch")
    if supplied != _sealed(material):
        raise ValueError("phase2a_binding_repair_input_seal_invalid")


def _write_exclusive(file_path: Path, raw: bytes) -> None:
    descriptor = os.open(
        file_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        file_path.unlink(missing_ok=True)
        raise


def _normalized_marker_text(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def _is_allowlisted_https_url(url: str) -> bool:
    parsed = urlparse(url)
    try:
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme.casefold() == "https"
        and parsed.hostname in ALLOWED_HOSTS
        and parsed.username is None
        and parsed.password is None
        and port in (None, 443)
    )


def _visible_html(raw: bytes) -> str:
    parser = _VisibleTextParser()
    try:
        parser.feed(raw.decode("utf-8", "strict"))
        parser.close()
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("phase2a_binding_repair_html_invalid") from exc
    return " ".join(" ".join(parser.parts).split())


def _validate_fca_point_in_time_url(replacement: Replacement, url: str) -> None:
    parsed = urlparse(url)
    expected = urlparse(replacement.representation_url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    expected_query = {"Date": [FCA_POINT_IN_TIME_DATE]}
    if replacement.expected_json_section is not None:
        expected_query["sectionId"] = [replacement.expected_json_section]
    if (
        not _is_allowlisted_https_url(url)
        or parsed.hostname != "api-handbook.fca.org.uk"
        or parsed.path != expected.path
        or parsed.params
        or parsed.fragment
        or query != expected_query
    ):
        raise ValueError("phase2a_binding_repair_fca_point_in_time_url_invalid")


def _fca_substantive_text(
    replacement: Replacement,
    result: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    provisions = result.get("provisions")
    if not isinstance(provisions, list) or not provisions:
        raise ValueError("phase2a_binding_repair_json_provisions_missing")
    substantive_parts: list[str] = []
    entity_ids: list[str] = []
    for provision in provisions:
        if not isinstance(provision, dict):
            raise ValueError("phase2a_binding_repair_json_provision_not_object")
        entity_id = provision.get("entityId")
        provision_name = provision.get("provisionName")
        content_text = provision.get("contentText")
        if not isinstance(entity_id, str) or not entity_id.startswith(
            f"{replacement.expected_json_chapter}-"
        ):
            raise ValueError("phase2a_binding_repair_json_entity_id_invalid")
        if replacement.expected_json_section is not None and (
            not entity_id.startswith(
                f"{replacement.expected_json_chapter}-{replacement.expected_json_section}-"
            )
            or provision.get("sectionId") != replacement.expected_json_section
        ):
            raise ValueError("phase2a_binding_repair_json_provision_section_mismatch")
        if provision.get("isDeleted") is not False:
            raise ValueError("phase2a_binding_repair_json_deleted_or_unknown_provision")
        if not isinstance(provision_name, str) or not provision_name.strip():
            raise ValueError("phase2a_binding_repair_json_provision_name_invalid")
        if not isinstance(content_text, str) or not content_text.strip():
            raise ValueError("phase2a_binding_repair_json_content_text_invalid")
        visible_content = _visible_html(content_text.encode("utf-8"))
        if not visible_content:
            raise ValueError("phase2a_binding_repair_json_content_text_invalid")
        entity_ids.append(entity_id)
        substantive_parts.extend((provision_name, visible_content))
    if len(entity_ids) != len(set(entity_ids)):
        raise ValueError("phase2a_binding_repair_json_duplicate_entity_id")
    return " ".join(substantive_parts), {
        "json_provision_count": len(provisions),
        "json_entity_id_set_sha256": _sealed(sorted(entity_ids)),
        "json_all_provisions_typed_and_live": True,
        "json_substantive_fields": ["provisionName", "contentText"],
    }


def _judgment_body_text_and_anchors(
    raw: bytes,
    replacement: Replacement,
) -> tuple[str, dict[str, Any]]:
    parser = _JudgmentBodyParser()
    try:
        parser.feed(raw.decode("utf-8", "strict"))
        parser.close()
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("phase2a_binding_repair_html_invalid") from exc
    body_shell_verified = (
        parser.body_seen
        and parser.body_direct_div_count == 1
        and parser.body_direct_other_element_count == 0
    )
    fragment_shell_verified = (
        not parser.body_seen
        and parser.fragment_direct_div_count == 1
        and parser.fragment_direct_other_element_count == 0
    )
    if not (body_shell_verified or fragment_shell_verified) or (
        parser.wrapper_classes != ("s800EAC49",)
        or parser.forbidden_tag_seen
        or len(parser.paragraphs) < 100
    ):
        raise ValueError("phase2a_binding_repair_judgment_body_missing")
    if tuple(sorted(set(replacement.paragraph_markers))) != replacement.paragraph_markers:
        raise ValueError("phase2a_binding_repair_paragraph_marker_plan_invalid")
    front_15 = " ".join(parser.paragraphs[:15])
    normalized_front_15 = _normalized_marker_text(front_15)
    missing_front_markers = [
        marker
        for marker in (
            *replacement.title_markers,
            *replacement.identity_front_matter_markers,
        )
        if _normalized_marker_text(marker) not in normalized_front_15
    ]
    if missing_front_markers:
        raise ValueError("phase2a_binding_repair_judgment_front_matter_identity_missing")
    normalized_front_20 = _normalized_marker_text(" ".join(parser.paragraphs[:20]))
    if any(
        _normalized_marker_text(marker) not in normalized_front_20
        for marker in ("JUDGMENT", "STRASBOURG")
    ):
        raise ValueError("phase2a_binding_repair_judgment_front_matter_status_missing")

    leading_number = re.compile(r"^\s*(?:\[\s*)?(\d{1,4})(?:\s*\])?\s*[.)]?\s+")
    numbered_paragraphs = [
        (index, int(match.group(1)))
        for index, paragraph in enumerate(parser.paragraphs)
        if (match := leading_number.search(paragraph)) is not None and len(paragraph) >= 20
    ]
    longest_consecutive_run = 0
    current_run = 0
    previous_number: int | None = None
    for _, number in numbered_paragraphs:
        current_run = (
            current_run + 1 if previous_number is not None and number == previous_number + 1 else 1
        )
        longest_consecutive_run = max(longest_consecutive_run, current_run)
        previous_number = number
    if longest_consecutive_run < 20:
        raise ValueError("phase2a_binding_repair_judgment_numbered_run_missing")

    positions: list[int] = []
    search_from = 0
    for number in replacement.paragraph_markers:
        match_index = next(
            (
                index
                for index, candidate_number in numbered_paragraphs
                if index >= search_from and candidate_number == number
            ),
            None,
        )
        if match_index is None:
            raise ValueError("phase2a_binding_repair_paragraph_marker_missing_or_unordered")
        positions.append(match_index)
        search_from = match_index + 1
    return " ".join(parser.paragraphs), {
        "html_body_verified": True,
        "html_shell_mode": "BODY" if body_shell_verified else "BODY_FRAGMENT",
        "html_body_direct_div_count": (
            parser.body_direct_div_count
            if body_shell_verified
            else parser.fragment_direct_div_count
        ),
        "html_body_wrapper_classes": list(parser.wrapper_classes),
        "html_paragraph_count": len(parser.paragraphs),
        "html_numbered_paragraph_count": len(numbered_paragraphs),
        "html_longest_consecutive_numbered_run": longest_consecutive_run,
        "identity_front_matter_markers_verified": list(replacement.identity_front_matter_markers),
        "judgment_status_front_matter_markers_verified": ["JUDGMENT", "STRASBOURG"],
        "ordered_paragraph_anchor_positions": positions,
    }


def _verify_old_bindings(
    packet: dict[str, Any], quarantine: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    if QUARANTINE_ROOT.is_symlink() or not QUARANTINE_ROOT.is_dir():
        raise ValueError("phase2a_binding_repair_quarantine_root_invalid")
    quarantine_root_resolved = QUARANTINE_ROOT.resolve()
    records = {str(item["record_id"]): item for item in quarantine["records"]}
    selected: dict[str, dict[str, Any]] = {}
    for proposal in packet["proposed_new_source_admissions"]:
        binding = proposal["quarantine_representation_binding"]["selected_admission_binding"]
        selected[str(binding["record_id"])] = proposal
    expected_ids = set(DEFECTIVE_OLD_RECORD_IDS)
    if len(expected_ids) != 16 or not expected_ids <= selected.keys():
        raise ValueError("phase2a_binding_repair_defect_set_invalid")
    for record_id in sorted(expected_ids):
        record = records.get(record_id)
        proposal = selected[record_id]
        if not record or not record.get("selected_for_proposed_admission"):
            raise ValueError("phase2a_binding_repair_old_record_not_selected")
        binding = proposal["quarantine_representation_binding"]["selected_admission_binding"]
        for key in ("raw_sha256", "quarantine_member", "record_content_sha256"):
            if binding.get(key) != record.get(key):
                raise ValueError("phase2a_binding_repair_old_binding_mismatch")
        member_name = str(record["quarantine_member"])
        if (
            not member_name
            or Path(member_name).is_absolute()
            or Path(member_name).name != member_name
        ):
            raise ValueError("phase2a_binding_repair_old_member_path_invalid")
        member = QUARANTINE_ROOT / member_name
        if (
            member.parent.resolve() != quarantine_root_resolved
            or member.is_symlink()
            or not member.is_file()
        ):
            raise ValueError("phase2a_binding_repair_old_member_not_regular")
        raw = member.read_bytes()
        if len(raw) != int(record["bytes"]) or _sha256(raw) != record["raw_sha256"]:
            raise ValueError("phase2a_binding_repair_old_member_digest_mismatch")
    return selected


def _validate_repair_scope() -> None:
    repaired_ids = {item.old_record_id for item in REPLACEMENTS}
    hold_ids = {str(item["old_record_id"]) for item in UNRESOLVED_REPAIR_HOLDS}
    defect_ids = set(DEFECTIVE_OLD_RECORD_IDS)
    if (
        len(REPLACEMENTS) != 15
        or len(repaired_ids) != 11
        or len(hold_ids) != 5
        or len(defect_ids) != 16
        or repaired_ids & hold_ids
        or repaired_ids | hold_ids != defect_ids
        or len({item.replacement_key for item in REPLACEMENTS}) != len(REPLACEMENTS)
        or len({item.representation_url for item in REPLACEMENTS}) != len(REPLACEMENTS)
        or any(item.suffix != ".json" for item in REPLACEMENTS)
    ):
        raise ValueError("phase2a_binding_repair_scope_invalid")
    for replacement in REPLACEMENTS:
        if replacement.suffix == ".json":
            _validate_fca_point_in_time_url(replacement, replacement.representation_url)
        elif (
            not replacement.paragraph_markers
            or tuple(sorted(set(replacement.paragraph_markers))) != replacement.paragraph_markers
        ):
            raise ValueError("phase2a_binding_repair_scope_invalid")


def _fetch(replacement: Replacement, timeout_seconds: float) -> tuple[bytes, str]:
    if not _is_allowlisted_https_url(replacement.representation_url):
        raise ValueError("phase2a_binding_repair_url_not_allowlisted")
    if replacement.suffix == ".json":
        _validate_fca_point_in_time_url(replacement, replacement.representation_url)
    request = Request(
        replacement.representation_url,
        headers={"Accept": replacement.expected_media_type, "User-Agent": USER_AGENT},
    )
    with urlopen(request, timeout=timeout_seconds) as response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        media_type = (
            str(response.headers.get("Content-Type", "")).split(";", 1)[0].strip().casefold()
        )
        final_url = response.geturl()
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("phase2a_binding_repair_payload_too_large")
    if not _is_allowlisted_https_url(final_url):
        raise ValueError("phase2a_binding_repair_redirect_not_allowlisted")
    if media_type != replacement.expected_media_type.casefold():
        raise ValueError("phase2a_binding_repair_media_type_invalid")
    if replacement.suffix == ".json":
        _validate_fca_point_in_time_url(replacement, final_url)
    return raw, final_url


def _validate_replacement(replacement: Replacement, raw: bytes) -> dict[str, Any]:
    if len(raw) < replacement.minimum_bytes:
        raise ValueError("phase2a_binding_repair_payload_too_small")
    structural_validation: dict[str, Any] = {}
    title_text: str
    if replacement.suffix == ".json":
        _validate_fca_point_in_time_url(replacement, replacement.representation_url)
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("phase2a_binding_repair_json_invalid") from exc
        if not isinstance(payload, dict) or payload.get("Success") is not True:
            raise ValueError("phase2a_binding_repair_json_success_invalid")
        result = payload.get("Result")
        if not isinstance(result, dict):
            raise ValueError("phase2a_binding_repair_json_result_invalid")
        if result.get("chapterId") != replacement.expected_json_chapter:
            raise ValueError("phase2a_binding_repair_json_chapter_mismatch")
        actual_section = result.get("sectionId")
        if replacement.expected_json_section is None:
            if actual_section not in (None, ""):
                raise ValueError("phase2a_binding_repair_json_section_mismatch")
        elif actual_section != replacement.expected_json_section:
            raise ValueError("phase2a_binding_repair_json_section_mismatch")
        text, provision_validation = _fca_substantive_text(replacement, result)
        typed_identity_fields = []
        for field in ("chapterName", "sectionName"):
            value = result.get(field)
            if value is not None and not isinstance(value, str):
                raise ValueError("phase2a_binding_repair_json_identity_field_invalid")
            if isinstance(value, str) and value.strip():
                typed_identity_fields.append(value)
        title_text = " ".join((*typed_identity_fields, text))
        page_count = None
        extraction_method = "official-fca-json-v1"
        structural_validation = {
            "json_success_verified": True,
            "json_chapter_id_verified": replacement.expected_json_chapter,
            "json_section_id_verified": replacement.expected_json_section,
            "json_point_in_time_date_verified": FCA_POINT_IN_TIME_DATE,
            **provision_validation,
        }
    else:
        text, judgment_validation = _judgment_body_text_and_anchors(
            raw,
            replacement,
        )
        title_text = text
        page_count = None
        extraction_method = "html.parser-judgment-body-paragraphs-v2"
        structural_validation = judgment_validation
    if len(text) < replacement.minimum_text_characters:
        raise ValueError("phase2a_binding_repair_extracted_text_too_small")
    normalized = _normalized_marker_text(text)
    normalized_title_text = _normalized_marker_text(title_text)
    missing_titles = [
        marker
        for marker in replacement.title_markers
        if _normalized_marker_text(marker) not in normalized_title_text
    ]
    missing_locators = [
        marker
        for marker in replacement.locator_markers
        if _normalized_marker_text(marker) not in normalized
    ]
    if missing_titles:
        raise ValueError("phase2a_binding_repair_title_marker_missing")
    if missing_locators:
        raise ValueError("phase2a_binding_repair_locator_marker_missing")
    return {
        "extraction_method": extraction_method,
        "extracted_text_characters": len(text),
        "extracted_text_sha256": _sha256(text.encode("utf-8")),
        "normalized_text_sha256": _sha256(normalized.encode("utf-8")),
        "page_count": page_count,
        "title_markers_verified": list(replacement.title_markers),
        "locator_markers_verified": list(replacement.locator_markers),
        "paragraph_markers_verified": list(replacement.paragraph_markers),
        **structural_validation,
        "content_fitness_status": "SUBSTANTIVE_BODY_AND_LOCATORS_VERIFIED",
    }


def _package_files(output_root: Path, files: dict[str, bytes]) -> str:
    entries: list[dict[str, Any]] = []
    for name, raw in sorted(files.items()):
        if not name or Path(name).is_absolute() or Path(name).name != name:
            raise ValueError("phase2a_binding_repair_output_member_path_invalid")
        _write_exclusive(output_root / name, raw)
        entries.append({"path": name, "bytes": len(raw), "sha256": _sha256(raw)})
    material = {
        "schema": "legalbot.v111.phase2a.source-binding-repair-package.v1",
        "status": "QUARANTINED_NOT_OWNER_ADOPTED",
        "files": entries,
        "file_count": len(entries),
        "owner_delta_decision_required": True,
        "answer_eligible": False,
        **_false_boundaries(),
    }
    package = {**material, "package_content_sha256": _sealed(material)}
    package_raw = _pretty_json(package)
    _write_exclusive(output_root / "PACKAGE-MANIFEST.json", package_raw)
    checksum_lines = [f"{entry['sha256']}  {entry['path']}" for entry in entries]
    checksum_lines.append(f"{_sha256(package_raw)}  PACKAGE-MANIFEST.json")
    _write_exclusive(
        output_root / "SHA256SUMS.txt",
        ("\n".join(checksum_lines) + "\n").encode("utf-8"),
    )
    return str(package["package_content_sha256"])


def _validated_output_root(
    output_root: Path,
    *,
    review_root: Path = REVIEW_ROOT,
) -> Path:
    if review_root.is_symlink() or not review_root.is_dir():
        raise ValueError("phase2a_binding_repair_review_root_invalid")
    review_resolved = review_root.resolve()
    output_absolute = output_root.absolute()
    if output_absolute.exists() or output_absolute.is_symlink():
        raise ValueError("phase2a_binding_repair_output_exists")
    parent = output_absolute.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError("phase2a_binding_repair_output_parent_invalid")
    parent_resolved = parent.resolve()
    output_resolved = parent_resolved / output_absolute.name
    if (
        output_resolved == review_resolved
        or not output_resolved.is_relative_to(review_resolved)
        or output_resolved.parent != review_resolved
    ):
        raise ValueError("phase2a_binding_repair_output_outside_review_root")
    return output_resolved


def _publish_transactionally(
    output_root: Path,
    files: dict[str, bytes],
    *,
    include_package: bool,
) -> str | None:
    staging_root = Path(
        tempfile.mkdtemp(prefix=f".{output_root.name}.staging-", dir=output_root.parent)
    )
    try:
        staging_root.chmod(0o700)
        if stat.S_IMODE(staging_root.stat().st_mode) != 0o700:
            raise ValueError("phase2a_binding_repair_staging_mode_invalid")
        package_digest = _package_files(staging_root, files) if include_package else None
        if not include_package:
            for name, raw in sorted(files.items()):
                _write_exclusive(staging_root / name, raw)
        directory_descriptor = os.open(staging_root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        if output_root.exists() or output_root.is_symlink():
            raise ValueError("phase2a_binding_repair_output_exists")
        os.rename(staging_root, output_root)
        try:
            parent_descriptor = os.open(output_root.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)
        except BaseException:
            if output_root.exists() and not staging_root.exists():
                os.rename(output_root, staging_root)
            raise
        return package_digest
    finally:
        if staging_root.exists():
            shutil.rmtree(staging_root)


def collect(
    *,
    output_root: Path,
    retrieved_at: datetime,
    timeout_seconds: float,
    review_root: Path = REVIEW_ROOT,
) -> dict[str, Any]:
    output_root = _validated_output_root(output_root, review_root=review_root)
    _validate_repair_scope()
    if retrieved_at.tzinfo is None:
        raise ValueError("phase2a_binding_repair_retrieved_at_naive")
    if not 0 < timeout_seconds <= 120:
        raise ValueError("phase2a_binding_repair_timeout_invalid")
    if _sha256_file(PACKET_PATH) != EXPECTED_PACKET_FILE_SHA256:
        raise ValueError("phase2a_binding_repair_packet_file_digest_invalid")
    if _sha256_file(QUARANTINE_MANIFEST_PATH) != EXPECTED_QUARANTINE_FILE_SHA256:
        raise ValueError("phase2a_binding_repair_quarantine_file_digest_invalid")
    packet = _load_object(PACKET_PATH)
    quarantine = _load_object(QUARANTINE_MANIFEST_PATH)
    _verify_seal(packet, "artifact_content_sha256", EXPECTED_PACKET_CONTENT_SHA256)
    _verify_seal(
        quarantine,
        "manifest_content_sha256",
        EXPECTED_QUARANTINE_CONTENT_SHA256,
    )
    selected = _verify_old_bindings(packet, quarantine)

    timestamp = retrieved_at.astimezone(UTC).isoformat(timespec="seconds")
    records: list[dict[str, Any]] = []
    payloads: dict[str, bytes] = {}
    for ordinal, replacement in enumerate(REPLACEMENTS, start=1):
        try:
            raw, final_url = _fetch(replacement, timeout_seconds)
            validation = _validate_replacement(replacement, raw)
        except BaseException as exc:
            raise RuntimeError(
                "phase2a_binding_repair_item_failed:"
                f"{replacement.replacement_key}:{type(exc).__name__}:{exc}"
            ) from exc
        raw_sha = _sha256(raw)
        member = f"repair-representation-{ordinal:04d}-{raw_sha[:20]}{replacement.suffix}"
        if member in payloads:
            raise ValueError("phase2a_binding_repair_member_collision")
        payloads[member] = raw
        old_proposal = selected[replacement.old_record_id]
        old_binding = old_proposal["quarantine_representation_binding"][
            "selected_admission_binding"
        ]
        identity_material = {
            "canonical_url": replacement.canonical_url,
            "final_url": final_url,
            "raw_sha256": raw_sha,
            "retrieved_at": timestamp,
        }
        proposed_source_version_id = (
            "proposed-repair-source-version-" + _sealed(identity_material)[:40]
        )
        record_material = {
            "record_id": "binding-repair-" + _sealed(identity_material)[:24],
            "replacement_key": replacement.replacement_key,
            "old_proposal_id": old_proposal["proposal_id"],
            "old_proposed_source_version_id": old_binding["proposed_source_version_id"],
            "old_record_id": replacement.old_record_id,
            "old_raw_sha256": old_binding["raw_sha256"],
            "old_official_urls": old_proposal["official_urls"],
            "affected_row_ids": old_proposal["affected_row_ids"],
            "citations": old_proposal["citations"],
            "titles": old_proposal["titles"],
            "canonical_url": replacement.canonical_url,
            "representation_url": replacement.representation_url,
            "final_url": final_url,
            "retrieved_at": timestamp,
            "content_type": replacement.expected_media_type,
            "bytes": len(raw),
            "raw_sha256": raw_sha,
            "quarantine_member": member,
            "proposed_source_version_id": proposed_source_version_id,
            **validation,
            "source_version_mode": replacement.source_version_mode,
            "currentness_hold_retained": True,
            "later_treatment_hold_retained": True,
            "owner_delta_decision_required": True,
            "answer_eligible": False,
            **_false_boundaries(),
        }
        records.append(
            {
                **record_material,
                "record_content_sha256": _sealed(record_material),
            }
        )

    old_ids = sorted(DEFECTIVE_OLD_RECORD_IDS)
    repaired_old_ids = sorted({item.old_record_id for item in REPLACEMENTS})
    unresolved_holds = []
    for hold in UNRESOLVED_REPAIR_HOLDS:
        hold_material = {
            **hold,
            "owner_delta_decision_required": True,
            "answer_eligible": False,
            **_false_boundaries(),
        }
        unresolved_holds.append({**hold_material, "hold_content_sha256": _sealed(hold_material)})
    material = {
        "schema": "legalbot.v111.phase2a.source-binding-repair-quarantine.v1",
        "status": "EXACT_REPLACEMENTS_QUARANTINED_OWNER_DELTA_REQUIRED",
        "created_at": timestamp,
        "source_owner_packet_content_sha256": EXPECTED_PACKET_CONTENT_SHA256,
        "source_owner_packet_file_sha256": EXPECTED_PACKET_FILE_SHA256,
        "source_quarantine_manifest_content_sha256": (EXPECTED_QUARANTINE_CONTENT_SHA256),
        "source_quarantine_manifest_file_sha256": EXPECTED_QUARANTINE_FILE_SHA256,
        "defective_old_binding_count": len(old_ids),
        "defective_old_record_ids": old_ids,
        "repaired_old_binding_count": len(repaired_old_ids),
        "repaired_old_record_ids": repaired_old_ids,
        "unresolved_repair_hold_count": len(unresolved_holds),
        "unresolved_repair_holds": unresolved_holds,
        "replacement_representation_count": len(records),
        "records": records,
        "all_substantive_body_and_locator_checks_passed": True,
        "owner_delta_decision_required": True,
        "answer_eligible": False,
        **_false_boundaries(),
    }
    manifest = {**material, "manifest_content_sha256": _sealed(material)}
    manifest_raw = _pretty_json(manifest)
    files = {
        **payloads,
        "REPAIR-QUARANTINE-MANIFEST.json": manifest_raw,
        "OUTCOME.txt": (
            b"15 substantive official FCA replacement representations quarantined "
            b"for 11 defective bindings; the EWCA and all four defective HUDOC "
            b"bindings remain held; exact owner delta approval required.\n"
        ),
    }
    package_digest = _publish_transactionally(
        output_root,
        files,
        include_package=True,
    )
    if package_digest is None:
        raise RuntimeError("phase2a_binding_repair_package_digest_missing")
    return {
        "output_root": str(output_root),
        "defective_old_binding_count": len(old_ids),
        "repaired_old_binding_count": len(repaired_old_ids),
        "unresolved_repair_hold_count": len(unresolved_holds),
        "replacement_representation_count": len(records),
        "manifest_content_sha256": manifest["manifest_content_sha256"],
        "manifest_file_sha256": _sha256(manifest_raw),
        "package_content_sha256": package_digest,
        "owner_delta_decision_required": True,
        "answer_eligible": False,
        **_false_boundaries(),
    }


def _persist_failure(
    output_root: Path,
    exc: BaseException,
    *,
    review_root: Path = REVIEW_ROOT,
) -> None:
    try:
        if output_root.exists() or output_root.is_symlink():
            return
        output_root = _validated_output_root(output_root, review_root=review_root)
        fingerprint = {
            "stage": "PHASE2A_SOURCE_BINDING_REPAIR_COLLECTION",
            "exception_type": type(exc).__name__,
            "error": str(exc),
        }
        material = {
            "schema": "legalbot.v111.phase2a.source-binding-repair-failure.v1",
            **fingerprint,
            "failure_fingerprint": _sealed(fingerprint),
            "unchanged_retry_authorized": False,
            "debug_required_before_retry": True,
            "owner_delta_decision_required": True,
            "answer_eligible": False,
            **_false_boundaries(),
        }
        _publish_transactionally(
            output_root,
            {
                "FAILURE.json": _pretty_json(
                    {**material, "failure_content_sha256": _sealed(material)}
                )
            },
            include_package=False,
        )
    except BaseException:
        return


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--timeout-seconds", type=float, default=45.0)
    args = parser.parse_args()
    output_root = args.output_root
    try:
        result = collect(
            output_root=output_root,
            retrieved_at=datetime.now(UTC),
            timeout_seconds=args.timeout_seconds,
        )
    except BaseException as exc:
        _persist_failure(output_root, exc)
        raise
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
