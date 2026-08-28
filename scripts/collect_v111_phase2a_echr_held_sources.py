#!/usr/bin/env python3
"""Recover four held ECtHR judgments into a create-only Phase-2A quarantine.

This is a targeted successor to the stopped r5/r6 HUDOC path.  Those runs
fetched the official converter body but rejected it because the validator
required one document-specific CSS wrapper.  This collector instead proves
the official HUDOC identity, judgment front matter, a long ordered run of
numbered judgment paragraphs, and every paragraph required by the sealed
owner packet.  It makes one bounded request per document and never retries.

The output is evidence for a later exact owner decision.  It does not admit a
source, mutate the catalogue, scan, index, embed, qualify, release answers,
write pointers, promote, activate Phase 2B, or export training material.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from html.parser import HTMLParser
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
PACKET_ROOT = REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-exact-remediation-owner-packet-r1"
PACKET_PATH = PACKET_ROOT / "EXACT-REMEDIATION-OWNER-PACKET-361.json"
SOURCE_QUARANTINE_ROOT = REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-source-quarantine"
SOURCE_QUARANTINE_MANIFEST = SOURCE_QUARANTINE_ROOT / "QUARANTINE-MANIFEST.json"
R7_ROOT = REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-source-binding-repair-quarantine-r7"
R7_MANIFEST = R7_ROOT / "REPAIR-QUARANTINE-MANIFEST.json"
RECOVERY_R1_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-echr-held-source-recovery-quarantine-r1"
)
RECOVERY_R1_MANIFEST = RECOVERY_R1_ROOT / "ECHR-RECOVERY-QUARANTINE-MANIFEST.json"
RECOVERY_R2_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-echr-held-source-recovery-quarantine-r2"
)
RECOVERY_R2_MANIFEST = RECOVERY_R2_ROOT / "ECHR-RECOVERY-QUARANTINE-MANIFEST.json"
DEFAULT_OUTPUT_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-echr-held-source-recovery-quarantine-r3"
)

EXPECTED_PACKET_FILE_SHA256 = "992770c04cb3e08de64bb98e80aa9801171d3e66e4b573b85919091a78b1db3b"
EXPECTED_PACKET_CONTENT_SHA256 = "93ad9113af76896f0570a3666c446472af7587b7e3ff32b7464e670777ec6b6c"
EXPECTED_SOURCE_QUARANTINE_FILE_SHA256 = (
    "f482366a2ba0d9f636c56104d632767a8eadd6e9a9625d50ef5391a5f62995eb"
)
EXPECTED_SOURCE_QUARANTINE_CONTENT_SHA256 = (
    "b6d900b23232379a4d6c19d313f35c47e0758ce5e0bb6eb04008f9eba07a3819"
)
EXPECTED_R7_FILE_SHA256 = "955503ce1d3d79602f7fe90f1c6330c63c0aea2dea6588e87f0d821eac129639"
EXPECTED_R7_CONTENT_SHA256 = "8c6c7c926b8612208287ae1c15af4d64b7f47829e9a2ff988fd4a95e9879c817"
EXPECTED_RECOVERY_R1_FILE_SHA256 = (
    "858f08d5a7d2858f8b1895451b06c41be4e04a0f2a936f0009ccfe3f68505c1d"
)
EXPECTED_RECOVERY_R1_CONTENT_SHA256 = (
    "9c69a31c27e5b8b1e6c915d354ee921417d0a439b62047cb1c2bf4f02a2458b4"
)
EXPECTED_RECOVERY_R2_FILE_SHA256 = (
    "e7f23bbe8219370f24ae86e3dab7356bab6ad90fc8a405c92ee1b06f8bd74879"
)
EXPECTED_RECOVERY_R2_CONTENT_SHA256 = (
    "c6672a3f227b9a518ac628861bc1bcaf361d9c29968f20c490f27d3f34592145"
)
EXPECTED_GOODWIN_R2_RAW_SHA256 = "49074fe49a3280239806d86233f2a4be081777859467fa7df723adc1590d4441"
EXPECTED_GOODWIN_R2_RECORD_SHA256 = (
    "be390e6a0f1def7c073f0fae329b56d3e7c4e6acf7610ce6fffef8d15b7da145"
)

FAILED_LINEAGE = (
    {
        "revision": "r2",
        "file": "LegalBot-Phase2A-2026-08-28-source-binding-repair-quarantine-r2/FAILURE.json",
        "file_sha256": "52253805eeea3efe881809e86d3bac09a153d1548589a390e897cce802d220bf",
        "failure_fingerprint": "f0f768b3f807de15f99d33fc8c021d181ec6c0f9dd50e6febc6a98e6e54cd362",
        "finding": "PDF transport timeout; not retried here",
    },
    {
        "revision": "r5",
        "file": "LegalBot-Phase2A-2026-08-28-source-binding-repair-quarantine-r5/FAILURE.json",
        "file_sha256": "4c155f6eeeab57a9fb6569e144b0e9b409fd2e1601b7eb8c48d7e9575b55ef6b",
        "failure_fingerprint": "682392ef9bc42f28072c29368b7a35e2f9e527d4e1699d19597ae9af56734421",
        "finding": "official HTML rejected by document-specific wrapper validator",
    },
    {
        "revision": "r6",
        "file": "LegalBot-Phase2A-2026-08-28-source-binding-repair-quarantine-r6/FAILURE.json",
        "file_sha256": "4c155f6eeeab57a9fb6569e144b0e9b409fd2e1601b7eb8c48d7e9575b55ef6b",
        "failure_fingerprint": "682392ef9bc42f28072c29368b7a35e2f9e527d4e1699d19597ae9af56734421",
        "finding": "second identical wrapper-validator failure; old path stopped",
    },
)

ALLOWED_HOST = "hudoc.echr.coe.int"
HTML_CONVERTER_PATH = "/app/conversion/docx/html/body"
PDF_CONVERTER_PATH = "/app/conversion/docx/pdf"
USER_AGENT = "LegalBot-v1.11-echr-held-source-recovery/1.0"
MAX_RESPONSE_BYTES = 30 * 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

_FALSE_BOUNDARIES = (
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


def _numbers(*ranges: tuple[int, int]) -> tuple[int, ...]:
    return tuple(number for start, end in ranges for number in range(start, end + 1))


@dataclass(frozen=True)
class JudgmentPlan:
    key: str
    document_id: str
    old_record_id: str
    title: str
    identity_title_marker: str
    application_markers: tuple[str, ...]
    affected_row_ids: tuple[str, ...]
    exact_locators: tuple[str, ...]
    required_paragraphs: tuple[int, ...]
    minimum_bytes: int
    minimum_paragraph_count: int
    minimum_text_characters: int
    representation_mode: str = "html"
    pdf_filename: str | None = None

    @property
    def canonical_url(self) -> str:
        return f"https://hudoc.echr.coe.int/eng?i={self.document_id}"

    @property
    def representation_url(self) -> str:
        if self.representation_mode == "html":
            path = HTML_CONVERTER_PATH
            params = {"id": self.document_id, "library": "ECHR"}
        elif self.representation_mode == "pdf" and self.pdf_filename:
            path = PDF_CONVERTER_PATH
            params = {
                "filename": self.pdf_filename,
                "id": self.document_id,
                "library": "ECHR",
                "logEvent": "False",
            }
        else:
            raise ValueError("phase2a_echr_representation_mode_invalid")
        return f"https://{ALLOWED_HOST}{path}?" + urlencode(params)


PLANS = (
    JudgmentPlan(
        key="hudoc-001-233206-klimaseniorinnen-html-body-v2",
        document_id="001-233206",
        old_record_id="quarantine-binding-0a370f8e41122c812c5f26d2",
        title="Verein KlimaSeniorinnen Schweiz and Others v Switzerland",
        identity_title_marker="VEREIN KLIMASENIORINNEN SCHWEIZ AND OTHERS v. SWITZERLAND",
        application_markers=("53600/20", "GRAND CHAMBER"),
        affected_row_ids=("live30-q22:issue-02", "live30-q22:issue-04", "live30-q22:issue-06"),
        exact_locators=(
            "paragraphs 487-488, 502, 519-527 and 622-623",
            "paragraphs 497-502 and 519-527",
            "paragraphs 519-520, 545, 548-551 and 572-574",
        ),
        required_paragraphs=tuple(
            sorted(
                set(
                    _numbers(
                        (487, 488),
                        (497, 502),
                        (519, 527),
                        (545, 545),
                        (548, 551),
                        (572, 574),
                        (622, 623),
                    )
                )
            )
        ),
        minimum_bytes=300_000,
        minimum_paragraph_count=650,
        minimum_text_characters=300_000,
    ),
    JudgmentPlan(
        key="hudoc-001-186828-mutu-pechstein-html-body-v2",
        document_id="001-186828",
        old_record_id="quarantine-binding-3688eea8275753b9dcabf559",
        title="Mutu and Pechstein v Switzerland",
        identity_title_marker="MUTU AND PECHSTEIN v. SWITZERLAND",
        application_markers=("40575/10", "67474/10"),
        affected_row_ids=("live60-q53:issue-04", "live60-q53:issue-11"),
        exact_locators=("paras 138-168", "paras 169-184", "paras 172-184", "paras 95-123"),
        required_paragraphs=tuple(sorted(set(_numbers((95, 123), (138, 184))))),
        minimum_bytes=100_000,
        minimum_paragraph_count=180,
        minimum_text_characters=90_000,
        representation_mode="pdf",
        pdf_filename="CASE OF MUTU AND PECHSTEIN v. SWITZERLAND.pdf",
    ),
    JudgmentPlan(
        key="hudoc-001-210077-big-brother-watch-html-body-v2",
        document_id="001-210077",
        old_record_id="quarantine-binding-678af407a5abea67aa817bee",
        title="Big Brother Watch and Others v United Kingdom",
        identity_title_marker="BIG BROTHER WATCH AND OTHERS v. THE UNITED KINGDOM",
        application_markers=("58170/13", "62322/14", "24960/15", "GRAND CHAMBER"),
        affected_row_ids=("live60-q56:issue-01", "live60-q56:issue-05"),
        exact_locators=("paras 332-347", "paras 356-364", "paras 425-426", "paras 442-450"),
        required_paragraphs=tuple(
            sorted(set(_numbers((332, 347), (356, 364), (425, 426), (442, 450))))
        ),
        minimum_bytes=250_000,
        minimum_paragraph_count=450,
        minimum_text_characters=250_000,
    ),
    JudgmentPlan(
        key="hudoc-001-57974-goodwin-html-body-v2",
        document_id="001-57974",
        old_record_id="quarantine-binding-d07fad39256d15a7c6a25893",
        title="Goodwin v United Kingdom",
        identity_title_marker="GOODWIN v. THE UNITED KINGDOM",
        application_markers=("17488/90",),
        affected_row_ids=("live60-q51:issue-05",),
        exact_locators=("paras 20-22", "paras 39-46"),
        required_paragraphs=tuple(sorted(set(_numbers((20, 22), (39, 46))))),
        minimum_bytes=25_000,
        minimum_paragraph_count=45,
        minimum_text_characters=25_000,
    ),
)

ATTEMPT_PLANS = tuple(plan for plan in PLANS if plan.document_id != "001-57974")


class _JudgmentParser(HTMLParser):
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
                raise ValueError("phase2a_echr_nested_paragraph")
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
            raise ValueError("phase2a_echr_html_tag_nesting_invalid")
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
            raise ValueError("phase2a_echr_unclosed_html_element")


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
        raise ValueError("phase2a_echr_input_not_regular")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _false_boundaries() -> dict[str, bool]:
    return {field: False for field in _FALSE_BOUNDARIES}


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_echr_input_not_regular")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_echr_input_not_object")
    return value


def _verify_seal(value: dict[str, Any], field: str, expected: str) -> None:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if supplied != expected or not _SHA256.fullmatch(supplied) or supplied != _sealed(material):
        raise ValueError("phase2a_echr_input_seal_invalid")


def _normalized(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def _is_exact_representation_url(url: str, plan: JudgmentPlan) -> bool:
    parsed = urlparse(url)
    try:
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme.casefold() == "https"
        and parsed.hostname == ALLOWED_HOST
        and parsed.username is None
        and parsed.password is None
        and port in (None, 443)
        and parsed.path
        == (HTML_CONVERTER_PATH if plan.representation_mode == "html" else PDF_CONVERTER_PATH)
        and not parsed.params
        and not parsed.fragment
        and parse_qs(parsed.query, keep_blank_values=True)
        == (
            {"id": [plan.document_id], "library": ["ECHR"]}
            if plan.representation_mode == "html"
            else {
                "filename": [str(plan.pdf_filename)],
                "id": [plan.document_id],
                "library": ["ECHR"],
                "logEvent": ["False"],
            }
        )
    )


def _verify_inputs() -> dict[str, dict[str, Any]]:
    if _sha256_file(PACKET_PATH) != EXPECTED_PACKET_FILE_SHA256:
        raise ValueError("phase2a_echr_packet_file_digest_invalid")
    if _sha256_file(SOURCE_QUARANTINE_MANIFEST) != EXPECTED_SOURCE_QUARANTINE_FILE_SHA256:
        raise ValueError("phase2a_echr_quarantine_file_digest_invalid")
    if _sha256_file(R7_MANIFEST) != EXPECTED_R7_FILE_SHA256:
        raise ValueError("phase2a_echr_r7_file_digest_invalid")
    if _sha256_file(RECOVERY_R1_MANIFEST) != EXPECTED_RECOVERY_R1_FILE_SHA256:
        raise ValueError("phase2a_echr_recovery_r1_file_digest_invalid")
    if _sha256_file(RECOVERY_R2_MANIFEST) != EXPECTED_RECOVERY_R2_FILE_SHA256:
        raise ValueError("phase2a_echr_recovery_r2_file_digest_invalid")
    packet = _load_object(PACKET_PATH)
    source_quarantine = _load_object(SOURCE_QUARANTINE_MANIFEST)
    r7 = _load_object(R7_MANIFEST)
    recovery_r1 = _load_object(RECOVERY_R1_MANIFEST)
    recovery_r2 = _load_object(RECOVERY_R2_MANIFEST)
    _verify_seal(packet, "artifact_content_sha256", EXPECTED_PACKET_CONTENT_SHA256)
    _verify_seal(
        source_quarantine,
        "manifest_content_sha256",
        EXPECTED_SOURCE_QUARANTINE_CONTENT_SHA256,
    )
    _verify_seal(r7, "manifest_content_sha256", EXPECTED_R7_CONTENT_SHA256)
    _verify_seal(
        recovery_r1,
        "manifest_content_sha256",
        EXPECTED_RECOVERY_R1_CONTENT_SHA256,
    )
    _verify_seal(
        recovery_r2,
        "manifest_content_sha256",
        EXPECTED_RECOVERY_R2_CONTENT_SHA256,
    )
    if recovery_r1.get("successful_document_count") != 0 or recovery_r1.get(
        "held_document_count"
    ) != len(PLANS):
        raise ValueError("phase2a_echr_recovery_r1_scope_invalid")
    r2_records = recovery_r2.get("records")
    if not isinstance(r2_records, list) or len(r2_records) != 1:
        raise ValueError("phase2a_echr_recovery_r2_scope_invalid")
    goodwin = r2_records[0]
    if (
        not isinstance(goodwin, dict)
        or goodwin.get("old_record_id") != "quarantine-binding-d07fad39256d15a7c6a25893"
        or goodwin.get("raw_sha256") != EXPECTED_GOODWIN_R2_RAW_SHA256
        or goodwin.get("record_content_sha256") != EXPECTED_GOODWIN_R2_RECORD_SHA256
        or goodwin.get("content_fitness_status")
        != "OFFICIAL_FULL_JUDGMENT_BODY_AND_REQUIRED_SPANS_VERIFIED"
    ):
        raise ValueError("phase2a_echr_recovery_r2_goodwin_binding_invalid")

    selected = {
        str(record["record_id"]): record
        for record in source_quarantine.get("selected_admission_bindings", [])
        if isinstance(record, dict) and isinstance(record.get("record_id"), str)
    }
    r7_holds = {
        str(hold["old_record_id"]): hold
        for hold in r7.get("unresolved_repair_holds", [])
        if isinstance(hold, dict) and isinstance(hold.get("old_record_id"), str)
    }
    for plan in PLANS:
        old = selected.get(plan.old_record_id)
        if old is None or r7_holds.get(plan.old_record_id) is None:
            raise ValueError("phase2a_echr_expected_held_binding_missing")
        member_name = str(old.get("quarantine_member", ""))
        member = SOURCE_QUARANTINE_ROOT / member_name
        if not member_name or Path(member_name).name != member_name or member.is_symlink():
            raise ValueError("phase2a_echr_old_member_invalid")
        raw = member.read_bytes()
        if len(raw) != old.get("bytes") or _sha256(raw) != old.get("raw_sha256"):
            raise ValueError("phase2a_echr_old_member_digest_mismatch")
        if old.get("affected_row_ids") is None or old.get("exact_locators") is None:
            raise ValueError("phase2a_echr_old_binding_incomplete")
        if tuple(old["affected_row_ids"]) != plan.affected_row_ids:
            raise ValueError("phase2a_echr_affected_rows_mismatch")
        if tuple(old["exact_locators"]) != plan.exact_locators:
            raise ValueError("phase2a_echr_exact_locators_mismatch")
        if old.get("authority_identity_id") != f"official-url:{plan.canonical_url}":
            raise ValueError("phase2a_echr_authority_identity_mismatch")
    for lineage in FAILED_LINEAGE:
        path = REVIEW_ROOT / str(lineage["file"])
        if _sha256_file(path) != lineage["file_sha256"]:
            raise ValueError("phase2a_echr_failed_lineage_digest_invalid")
        failure = _load_object(path)
        if failure.get("failure_fingerprint") != lineage["failure_fingerprint"]:
            raise ValueError("phase2a_echr_failed_lineage_fingerprint_invalid")
    return selected


def _fetch_once(plan: JudgmentPlan, timeout_seconds: float) -> tuple[bytes, str, str]:
    if not _is_exact_representation_url(plan.representation_url, plan):
        raise ValueError("phase2a_echr_url_invalid")
    expected_media_types = (
        {"text/html", "application/xhtml+xml"}
        if plan.representation_mode == "html"
        else {"application/pdf"}
    )
    with tempfile.TemporaryDirectory(prefix="legalbot-echr-curl-") as temporary:
        payload_path = Path(temporary) / "payload"
        command = [
            "/usr/bin/curl",
            "--http1.1",
            "--proto",
            "=https",
            "--location",
            "--max-redirs",
            "2",
            "--connect-timeout",
            str(min(20.0, timeout_seconds)),
            "--max-time",
            str(timeout_seconds),
            "--fail-with-body",
            "--silent",
            "--show-error",
            "--header",
            "Connection: close",
            "--header",
            "Accept-Encoding: identity",
            "--header",
            "Accept: " + ", ".join(sorted(expected_media_types)),
            "--user-agent",
            USER_AGENT,
            "--output",
            str(payload_path),
            "--write-out",
            "%{url_effective}\n%{content_type}\n%{http_code}\n",
            plan.representation_url,
        ]
        try:
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds + 5,
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("phase2a_echr_curl_process_timeout") from exc
        if result.returncode != 0:
            safe_error = " ".join(result.stderr.split())[:500]
            raise RuntimeError(f"phase2a_echr_curl_exit_{result.returncode}:{safe_error}")
        metadata = result.stdout.splitlines()
        if len(metadata) != 3 or metadata[2] != "200":
            raise ValueError("phase2a_echr_curl_response_metadata_invalid")
        final_url = metadata[0]
        media_type = metadata[1].split(";", 1)[0].strip().casefold()
        if payload_path.is_symlink() or not payload_path.is_file():
            raise ValueError("phase2a_echr_curl_payload_missing")
        raw = payload_path.read_bytes()
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("phase2a_echr_payload_too_large")
    if not _is_exact_representation_url(final_url, plan):
        raise ValueError("phase2a_echr_redirect_invalid")
    if media_type not in expected_media_types:
        raise ValueError("phase2a_echr_media_type_invalid")
    return raw, final_url, media_type


def _numbered_runs(paragraphs: list[str]) -> list[list[tuple[int, int, str]]]:
    leading = re.compile(r"^\s*(?:\[\s*)?(\d{1,4})(?:\s*\])?\s*[.)]?\s+")
    numbered = [
        (index, int(match.group(1)), paragraph)
        for index, paragraph in enumerate(paragraphs)
        if (match := leading.search(paragraph)) is not None and len(paragraph) >= 15
    ]
    runs: list[list[tuple[int, int, str]]] = []
    for item in numbered:
        if not runs or item[1] != runs[-1][-1][1] + 1:
            runs.append([item])
        else:
            runs[-1].append(item)
    return runs


def _ordered_required_positions(
    numbered: list[tuple[int, int, str]], required_paragraphs: tuple[int, ...]
) -> list[int]:
    positions: list[int] = []
    search_from = 0
    for required in required_paragraphs:
        match = next(
            (
                (ordinal, index)
                for ordinal, (index, number, _) in enumerate(
                    numbered[search_from:], start=search_from
                )
                if number == required
            ),
            None,
        )
        if match is None:
            raise ValueError("phase2a_echr_required_paragraph_run_missing")
        ordinal, index = match
        positions.append(index)
        search_from = ordinal + 1
    return positions


def _validate_html(plan: JudgmentPlan, raw: bytes) -> tuple[dict[str, Any], bytes]:
    if len(raw) < plan.minimum_bytes:
        raise ValueError("phase2a_echr_payload_too_small")
    parser = _JudgmentParser()
    try:
        parser.feed(raw.decode("utf-8", "strict"))
        parser.close()
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("phase2a_echr_html_invalid") from exc
    visible = " ".join(" ".join(parser.visible_parts).split())
    if len(visible) < plan.minimum_text_characters:
        raise ValueError("phase2a_echr_substantive_text_too_small")
    normalized_front = _normalized(" ".join(parser.paragraphs[:30]))
    identity_markers = (
        plan.identity_title_marker,
        *plan.application_markers,
        "JUDGMENT",
        "STRASBOURG",
    )
    missing_identity = [
        marker for marker in identity_markers if _normalized(marker) not in normalized_front
    ]
    if missing_identity:
        raise ValueError("phase2a_echr_front_matter_identity_missing:" + ",".join(missing_identity))
    if len(parser.paragraphs) < plan.minimum_paragraph_count:
        raise ValueError("phase2a_echr_paragraph_count_too_small")

    runs = _numbered_runs(parser.paragraphs)
    longest_run = max(runs, key=len, default=[])
    if len(longest_run) < 20:
        raise ValueError("phase2a_echr_consecutive_numbered_run_too_short")
    numbered = [item for run in runs for item in run]
    positions = _ordered_required_positions(numbered, plan.required_paragraphs)
    required_text = {
        number: next(
            text for index, candidate, text in numbered if index == position and candidate == number
        )
        for number, position in zip(plan.required_paragraphs, positions, strict=True)
    }
    if any(len(text) < 15 for text in required_text.values()):
        raise ValueError("phase2a_echr_required_paragraph_empty")

    canonical_lines = [f"# {plan.title}", "", f"HUDOC document: {plan.document_id}", ""]
    canonical_lines.extend(parser.paragraphs)
    canonical = ("\n\n".join(canonical_lines) + "\n").encode("utf-8")
    validation = {
        "content_fitness_status": "OFFICIAL_FULL_JUDGMENT_BODY_AND_REQUIRED_SPANS_VERIFIED",
        "parser_profile": "hudoc-converter-visible-paragraphs-v4-ordered-required-anchors",
        "html_element_count": parser.element_count,
        "html_paragraph_element_count": parser.paragraph_element_count,
        "extracted_paragraph_count": len(parser.paragraphs),
        "extracted_text_characters": len(visible),
        "extracted_text_sha256": _sha256(visible.encode("utf-8")),
        "identity_markers_verified": list(identity_markers),
        "required_paragraphs_verified": list(plan.required_paragraphs),
        "required_paragraph_count": len(plan.required_paragraphs),
        "numbered_paragraph_count": len(numbered),
        "longest_consecutive_numbered_run_first": longest_run[0][1],
        "longest_consecutive_numbered_run_last": longest_run[-1][1],
        "longest_consecutive_numbered_run_count": len(longest_run),
        "ordered_required_paragraph_positions": positions,
        "canonical_markdown_bytes": len(canonical),
        "canonical_markdown_sha256": _sha256(canonical),
    }
    return validation, canonical


def _validate_pdf(plan: JudgmentPlan, raw: bytes) -> tuple[dict[str, Any], bytes]:
    if len(raw) < plan.minimum_bytes or not raw.startswith(b"%PDF-"):
        raise ValueError("phase2a_echr_pdf_payload_invalid")
    try:
        from pypdf import PdfReader

        reader = PdfReader(BytesIO(raw), strict=True)
        pages = [page.extract_text() or "" for page in reader.pages]
    except Exception as exc:
        raise ValueError("phase2a_echr_pdf_parse_invalid") from exc
    if len(pages) < 20:
        raise ValueError("phase2a_echr_pdf_page_count_too_small")
    text = "\n\f\n".join(pages)
    if len(text) < plan.minimum_text_characters:
        raise ValueError("phase2a_echr_substantive_text_too_small")
    normalized_front = _normalized(" ".join(pages[:8]))
    identity_markers = (
        plan.identity_title_marker,
        *plan.application_markers,
        "JUDGMENT",
        "STRASBOURG",
    )
    missing_identity = [
        marker for marker in identity_markers if _normalized(marker) not in normalized_front
    ]
    if missing_identity:
        raise ValueError("phase2a_echr_front_matter_identity_missing:" + ",".join(missing_identity))
    leading = re.compile(r"(?m)^\s*(?:\[\s*)?(\d{1,4})(?:\s*\])?\s*[.)]?\s+")
    matches = list(leading.finditer(text))
    numbered = []
    for ordinal, match in enumerate(matches):
        end = matches[ordinal + 1].start() if ordinal + 1 < len(matches) else len(text)
        paragraph = " ".join(text[match.start() : end].split())
        if len(paragraph) >= 15:
            numbered.append((match.start(), int(match.group(1)), paragraph))
    positions = _ordered_required_positions(numbered, plan.required_paragraphs)
    canonical_lines = [f"# {plan.title}", "", f"HUDOC document: {plan.document_id}", ""]
    canonical_lines.extend(
        f"## Page {number}\n\n{page.strip()}" for number, page in enumerate(pages, start=1)
    )
    canonical = ("\n\n".join(canonical_lines) + "\n").encode("utf-8")
    validation = {
        "content_fitness_status": "OFFICIAL_FULL_JUDGMENT_BODY_AND_REQUIRED_SPANS_VERIFIED",
        "parser_profile": "pypdf-5.9.0-full-page-text-ordered-required-anchors-v1",
        "pdf_header_verified": True,
        "pdf_page_count": len(pages),
        "extracted_text_characters": len(text),
        "extracted_text_sha256": _sha256(text.encode("utf-8")),
        "identity_markers_verified": list(identity_markers),
        "required_paragraphs_verified": list(plan.required_paragraphs),
        "required_paragraph_count": len(plan.required_paragraphs),
        "numbered_paragraph_count": len(numbered),
        "ordered_required_paragraph_positions": positions,
        "canonical_markdown_bytes": len(canonical),
        "canonical_markdown_sha256": _sha256(canonical),
    }
    return validation, canonical


def _validate(plan: JudgmentPlan, raw: bytes) -> tuple[dict[str, Any], bytes]:
    if plan.representation_mode == "html":
        return _validate_html(plan, raw)
    if plan.representation_mode == "pdf":
        return _validate_pdf(plan, raw)
    raise ValueError("phase2a_echr_representation_mode_invalid")


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _validated_output_root(output_root: Path) -> Path:
    if REVIEW_ROOT.is_symlink() or not REVIEW_ROOT.is_dir():
        raise ValueError("phase2a_echr_review_root_invalid")
    output = output_root.absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("phase2a_echr_output_exists")
    parent = output.parent
    if parent.is_symlink() or parent.resolve() != REVIEW_ROOT.resolve():
        raise ValueError("phase2a_echr_output_parent_invalid")
    return parent.resolve() / output.name


def _publish(output_root: Path, files: dict[str, bytes]) -> str:
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.staging-", dir=output_root.parent))
    try:
        staging.chmod(0o700)
        if stat.S_IMODE(staging.stat().st_mode) != 0o700:
            raise ValueError("phase2a_echr_staging_mode_invalid")
        entries = []
        for name, raw in sorted(files.items()):
            if Path(name).name != name or Path(name).is_absolute():
                raise ValueError("phase2a_echr_member_name_invalid")
            _write_exclusive(staging / name, raw)
            entries.append({"path": name, "bytes": len(raw), "sha256": _sha256(raw)})
        package_material = {
            "schema": "legalbot.v111.phase2a.echr-held-source-recovery-package.v1",
            "status": "QUARANTINED_NOT_OWNER_ADOPTED",
            "file_count": len(entries),
            "files": entries,
            "owner_delta_decision_required": True,
            "answer_eligible": False,
            **_false_boundaries(),
        }
        package = {**package_material, "package_content_sha256": _sealed(package_material)}
        package_raw = _pretty_json(package)
        _write_exclusive(staging / "PACKAGE-MANIFEST.json", package_raw)
        checksums = [f"{entry['sha256']}  {entry['path']}" for entry in entries]
        checksums.append(f"{_sha256(package_raw)}  PACKAGE-MANIFEST.json")
        _write_exclusive(staging / "SHA256SUMS.txt", ("\n".join(checksums) + "\n").encode())
        descriptor = os.open(staging, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.rename(staging, output_root)
        return str(package["package_content_sha256"])
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def collect(*, output_root: Path, retrieved_at: datetime, timeout_seconds: float) -> dict[str, Any]:
    output_root = _validated_output_root(output_root)
    if retrieved_at.tzinfo is None:
        raise ValueError("phase2a_echr_retrieved_at_naive")
    if not 0 < timeout_seconds <= 120:
        raise ValueError("phase2a_echr_timeout_invalid")
    selected = _verify_inputs()
    timestamp = retrieved_at.astimezone(UTC).isoformat(timespec="seconds")
    records: list[dict[str, Any]] = []
    holds: list[dict[str, Any]] = []
    files: dict[str, bytes] = {}

    for ordinal, plan in enumerate(ATTEMPT_PLANS, start=1):
        old = selected[plan.old_record_id]
        parser_profile = (
            "hudoc-converter-visible-paragraphs-v4-ordered-required-anchors"
            if plan.representation_mode == "html"
            else "pypdf-5.9.0-full-page-text-ordered-required-anchors-v1"
        )
        attempt_identity = {
            "collector_profile": parser_profile,
            "transport_profile": "curl-http1.1-connection-close-no-retry-v1",
            "document_id": plan.document_id,
            "representation_url": plan.representation_url,
            "representation_mode": plan.representation_mode,
            "attempt_limit": 1,
        }
        try:
            raw, final_url, media_type = _fetch_once(plan, timeout_seconds)
            validation, canonical = _validate(plan, raw)
        except BaseException as exc:
            failure = {
                "old_record_id": plan.old_record_id,
                "document_id": plan.document_id,
                "attempt_identity_sha256": _sealed(attempt_identity),
                "attempt_count": 1,
                "retry_run": False,
                "reason_code": "OFFICIAL_HUDOC_RECOVERY_SINGLE_CHANGED_PATH_ATTEMPT_FAILED",
                "exception_type": type(exc).__name__,
                "error": str(exc),
                "failure_fingerprint": _sealed(
                    {
                        "stage": "PHASE2A_ECHR_HELD_SOURCE_RECOVERY",
                        "document_id": plan.document_id,
                        "exception_type": type(exc).__name__,
                        "error": str(exc),
                        "attempt_identity_sha256": _sealed(attempt_identity),
                    }
                ),
                "affected_row_ids": old["affected_row_ids"],
                "exact_locators": old["exact_locators"],
                "hold_retained": True,
                "owner_delta_decision_required": True,
                **_false_boundaries(),
            }
            holds.append({**failure, "hold_content_sha256": _sealed(failure)})
            continue

        raw_sha = _sha256(raw)
        canonical_sha = _sha256(canonical)
        raw_suffix = ".html" if plan.representation_mode == "html" else ".pdf"
        raw_member = f"echr-representation-{ordinal:04d}-{raw_sha[:20]}{raw_suffix}"
        canonical_member = f"echr-canonical-{ordinal:04d}-{canonical_sha[:20]}.md"
        files[raw_member] = raw
        files[canonical_member] = canonical
        identity_material = {
            "canonical_url": plan.canonical_url,
            "final_url": final_url,
            "raw_sha256": raw_sha,
            "canonical_markdown_sha256": canonical_sha,
            "retrieved_at": timestamp,
        }
        record_material = {
            "record_id": "echr-held-recovery-" + _sealed(identity_material)[:24],
            "replacement_key": plan.key,
            "old_record_id": plan.old_record_id,
            "old_proposed_source_version_id": old["proposed_source_version_id"],
            "old_raw_sha256": old["raw_sha256"],
            "authority_identity_id": old["authority_identity_id"],
            "affected_row_ids": old["affected_row_ids"],
            "exact_locators": old["exact_locators"],
            "title": plan.title,
            "canonical_url": plan.canonical_url,
            "representation_url": plan.representation_url,
            "final_url": final_url,
            "retrieved_at": timestamp,
            "content_type": media_type,
            "bytes": len(raw),
            "raw_sha256": raw_sha,
            "quarantine_member": raw_member,
            "canonical_markdown_member": canonical_member,
            "canonical_markdown_sha256": canonical_sha,
            "proposed_source_version_id": "proposed-echr-repair-source-version-"
            + _sealed(identity_material)[:40],
            "source_version_mode": "OFFICIAL_FINAL_JUDGMENT_DOCUMENT_RETRIEVED_2026_08_28",
            "representation_mode": plan.representation_mode,
            "attempt_identity_sha256": _sealed(attempt_identity),
            "attempt_count": 1,
            "retry_run": False,
            **validation,
            "currentness_hold_retained": True,
            "later_treatment_hold_retained": True,
            "owner_delta_decision_required": True,
            "answer_eligible": False,
            **_false_boundaries(),
        }
        records.append({**record_material, "record_content_sha256": _sealed(record_material)})

    manifest_material = {
        "schema": "legalbot.v111.phase2a.echr-held-source-recovery-quarantine.v1",
        "status": "EXACT_ECHR_REPRESENTATIONS_QUARANTINED_OWNER_DELTA_REQUIRED",
        "created_at": timestamp,
        "source_owner_packet_content_sha256": EXPECTED_PACKET_CONTENT_SHA256,
        "source_owner_packet_file_sha256": EXPECTED_PACKET_FILE_SHA256,
        "source_quarantine_manifest_content_sha256": EXPECTED_SOURCE_QUARANTINE_CONTENT_SHA256,
        "source_quarantine_manifest_file_sha256": EXPECTED_SOURCE_QUARANTINE_FILE_SHA256,
        "source_r7_manifest_content_sha256": EXPECTED_R7_CONTENT_SHA256,
        "source_r7_manifest_file_sha256": EXPECTED_R7_FILE_SHA256,
        "source_recovery_r1_manifest_content_sha256": EXPECTED_RECOVERY_R1_CONTENT_SHA256,
        "source_recovery_r1_manifest_file_sha256": EXPECTED_RECOVERY_R1_FILE_SHA256,
        "source_recovery_r2_manifest_content_sha256": EXPECTED_RECOVERY_R2_CONTENT_SHA256,
        "source_recovery_r2_manifest_file_sha256": EXPECTED_RECOVERY_R2_FILE_SHA256,
        "changed_path_basis": (
            "Three targeted HTML validator repairs for sealed r1 fingerprints plus one distinct "
            "official HUDOC PDF path for Mutu and Pechstein; no unchanged r1 or r5/r6 retry"
        ),
        "failed_lineage": list(FAILED_LINEAGE),
        "planned_document_count": len(PLANS),
        "attempted_document_count": len(ATTEMPT_PLANS),
        "new_successful_document_count": len(records),
        "carried_forward_document_count": 1,
        "successful_document_count": len(records) + 1,
        "held_document_count": len(holds),
        "affected_row_ids": sorted(
            {
                row_id
                for plan in ATTEMPT_PLANS
                for row_id in selected[plan.old_record_id]["affected_row_ids"]
            }
        ),
        "carried_forward_records": [
            {
                "document_id": "001-57974",
                "old_record_id": "quarantine-binding-d07fad39256d15a7c6a25893",
                "source_manifest_content_sha256": EXPECTED_RECOVERY_R2_CONTENT_SHA256,
                "source_manifest_file_sha256": EXPECTED_RECOVERY_R2_FILE_SHA256,
                "raw_sha256": EXPECTED_GOODWIN_R2_RAW_SHA256,
                "record_content_sha256": EXPECTED_GOODWIN_R2_RECORD_SHA256,
                "carry_mode": "SEALED_REFERENCE_NO_NETWORK_NO_BYTE_COPY",
                "owner_delta_decision_required": True,
                "answer_eligible": False,
                **_false_boundaries(),
            }
        ],
        "records": records,
        "holds": holds,
        "all_successful_documents_have_full_judgment_and_required_spans": not holds,
        "single_attempt_per_document_enforced": True,
        "owner_delta_decision_required": True,
        "answer_eligible": False,
        **_false_boundaries(),
    }
    manifest = {**manifest_material, "manifest_content_sha256": _sealed(manifest_material)}
    files["ECHR-RECOVERY-QUARANTINE-MANIFEST.json"] = _pretty_json(manifest)
    files["OUTCOME.txt"] = (
        f"{len(records)} new plus 1 sealed r2 ECtHR judgment body available; "
        f"{len(holds)} exact holds retained; owner delta decision required.\n"
    ).encode()
    package_content_sha256 = _publish(output_root, files)
    return {
        "output_root": str(output_root),
        "new_successful_document_count": len(records),
        "carried_forward_document_count": 1,
        "successful_document_count": len(records) + 1,
        "held_document_count": len(holds),
        "manifest_content_sha256": manifest["manifest_content_sha256"],
        "manifest_file_sha256": _sha256(files["ECHR-RECOVERY-QUARANTINE-MANIFEST.json"]),
        "package_content_sha256": package_content_sha256,
        "owner_delta_decision_required": True,
        "answer_eligible": False,
        **_false_boundaries(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--timeout-seconds", type=float, default=90.0)
    args = parser.parse_args()
    result = collect(
        output_root=args.output_root,
        retrieved_at=datetime.now(UTC),
        timeout_seconds=args.timeout_seconds,
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
