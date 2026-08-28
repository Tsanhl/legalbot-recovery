#!/usr/bin/env python3
"""Bind and classify five additional official later-treatment contexts.

The classifications are deterministic advisory screens over exact, hash-bound
official-source representations.  They do not decide owner outcomes, admit or
index sources, mutate a candidate, qualify an issue, or authorize a later gate.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from bs4 import BeautifulSoup
from pypdf import PdfReader

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SEQUANA_ROOT = (
    PROJECT_ROOT / "data/quarantine/2026-08-25/phase2a-targeted-later-treatment-sequana-r56"
)
SEQUANA_MANIFEST = SEQUANA_ROOT / "SEQUANA-LATER-TREATMENT-LEAD.json"
ADDITIONAL_ROOT = (
    PROJECT_ROOT / "data/quarantine/2026-08-25/phase2a-targeted-later-treatment-additional-r57"
)
ADDITIONAL_MANIFEST = ADDITIONAL_ROOT / "TARGETED-LATER-TREATMENT-LEADS-3.json"
ORIGINAL_ROOT = PROJECT_ROOT / "data/quarantine/2026-08-24/phase2a-targeted-later-treatment-r42"
ORIGINAL_MANIFEST = ORIGINAL_ROOT / "TARGETED-LATER-TREATMENT-LEADS-9.json"
DEFAULT_OUTPUT = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review"
    / "LegalBot-Phase2AB-2026-08-25-r58-additional-treatment-advisory"
)

EXPECTED_SEQUANA_SHA256 = "453acccb05c3c8f87c91ce06357b6b5c13eae4e8d4fc8347ab9d8f0fa041980a"
EXPECTED_ADDITIONAL_SHA256 = "f3fd36654c391c74c5167ce40a5681c562d42abaf916198c382a0c4b533169cc"
EXPECTED_ORIGINAL_SHA256 = "ad887ac1d18b06ed459b05471188cd6f999fa6b0580589edc4bbacc46cd902a9"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PARAGRAPH_MARKER = re.compile(r"(?<!\d)(?P<number>\d{1,3})\.\s")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _normal_text(value: str) -> str:
    return " ".join(value.replace("\u00a0", " ").split())


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_additional_treatment_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_additional_treatment_input_must_be_object")
    return value


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or supplied != _sealed(material):
        raise ValueError(code)
    return supplied


def _regular_bound_file(
    record: Mapping[str, Any],
    *,
    root: Path,
) -> Path:
    path = (PROJECT_ROOT / str(record.get("relative_path") or "")).resolve(strict=True)
    if (
        not path.is_relative_to(root)
        or path.is_symlink()
        or not path.is_file()
        or _sha256_file(path) != record.get("sha256")
        or path.stat().st_size != record.get("bytes")
    ):
        raise ValueError("phase2a_additional_treatment_source_integrity_invalid")
    return path


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


def _sealed_span(
    *,
    representation: str,
    exact_text: str,
    source_sha256: str,
    page_number: int | None = None,
) -> dict[str, Any]:
    material = {
        "schema": "legalbot.v111.phase2a.additional-treatment-exact-span.v1",
        "representation": representation,
        "source_sha256": source_sha256,
        "page_number": page_number,
        "exact_text": exact_text,
        "exact_text_sha256": _sha256(exact_text.encode("utf-8")),
        "exact_text_is_contiguous_in_representation": True,
    }
    return {**material, "span_content_sha256": _sealed(material)}


def _citation_paragraph(text: str, citation: str) -> str:
    occurrences = [match.start() for match in re.finditer(re.escape(citation), text)]
    if len(occurrences) != 1:
        raise ValueError("phase2a_additional_treatment_citation_occurrence_invalid")
    position = occurrences[0]
    markers = list(_PARAGRAPH_MARKER.finditer(text))
    prior = [marker for marker in markers if marker.start() < position]
    following = [marker for marker in markers if marker.start() > position]
    if not prior or not following:
        raise ValueError("phase2a_additional_treatment_paragraph_boundary_missing")
    paragraph = text[prior[-1].start() : following[0].start()].strip()
    if citation not in paragraph or not 40 <= len(paragraph) <= 5_000:
        raise ValueError("phase2a_additional_treatment_paragraph_invalid")
    return paragraph


def _html_paragraph_group(
    path: Path,
    *,
    citation: str,
    required_phrases: tuple[str, ...],
    maximum_paragraphs: int = 4,
) -> list[str]:
    paragraphs = [
        _normal_text(paragraph.get_text(" ", strip=True))
        for paragraph in BeautifulSoup(path.read_bytes(), "html.parser").find_all("p")
    ]
    indices = [index for index, text in enumerate(paragraphs) if citation in text]
    if len(indices) != 1:
        raise ValueError("phase2a_additional_treatment_html_citation_occurrence_invalid")
    start = indices[0]
    for count in range(1, maximum_paragraphs + 1):
        selected = paragraphs[start : start + count]
        combined = "\n".join(selected)
        if all(phrase in combined for phrase in required_phrases):
            return selected
    raise ValueError("phase2a_additional_treatment_html_phrase_fingerprint_invalid")


def _pdf_page_with_phrases(path: Path, phrases: tuple[str, ...]) -> tuple[int, str]:
    reader = PdfReader(io.BytesIO(path.read_bytes()))
    if reader.is_encrypted:
        raise ValueError("phase2a_additional_treatment_pdf_encrypted")
    matches: list[tuple[int, str]] = []
    for page_number, page in enumerate(reader.pages, start=1):
        text = _normal_text(page.extract_text() or "")
        if all(phrase in text for phrase in phrases):
            matches.append((page_number, text))
    if len(matches) != 1:
        raise ValueError("phase2a_additional_treatment_pdf_phrase_page_invalid")
    return matches[0]


def _lead_by_id(manifest: Mapping[str, Any], lead_id: str) -> dict[str, Any]:
    records = manifest.get("records")
    if not isinstance(records, list):
        raise ValueError("phase2a_additional_treatment_records_invalid")
    matches = [record for record in records if record.get("lead_id") == lead_id]
    if len(matches) != 1 or not isinstance(matches[0], dict):
        raise ValueError("phase2a_additional_treatment_lead_identity_invalid")
    _verify_seal(
        matches[0],
        "lead_content_sha256",
        "phase2a_additional_treatment_lead_seal_invalid",
    )
    return matches[0]


def _advisory_row(
    *,
    lead_id: str,
    target: str,
    candidate: str,
    candidate_name: str,
    candidate_date: str,
    court_weight: str,
    source_lead_sha256: str,
    exact_spans: list[dict[str, Any]],
    required_phrases: tuple[str, ...],
    relationship: str,
    owner_recommendation: str,
    note: str,
) -> dict[str, Any]:
    combined = "\n".join(str(span["exact_text"]) for span in exact_spans)
    if target not in combined or any(phrase not in combined for phrase in required_phrases):
        raise ValueError("phase2a_additional_treatment_row_evidence_invalid")
    material = {
        "schema": "legalbot.v111.phase2a.additional-treatment-advisory-row.v1",
        "source_lead_content_sha256": source_lead_sha256,
        "lead_id": lead_id,
        "target_neutral_citation": target,
        "candidate_neutral_citation": candidate,
        "candidate_case_name": candidate_name,
        "candidate_judgment_date": candidate_date,
        "court_weight": court_weight,
        "exact_treatment_spans": exact_spans,
        "explicit_required_phrases": list(required_phrases),
        "advisory_relationship": relationship,
        "recommended_owner_outcome": owner_recommendation,
        "advisory_note": note,
        "advisory_method": ("DETERMINISTIC_EXPLICIT_TREATMENT_PHRASE_SCREEN_NOT_LEGAL_DECISION"),
        "targeted_search_is_exhaustive": False,
        "absence_of_other_hits_proves_no_later_treatment": False,
        "final_relationship_depends_on_exact_proposition_scope": True,
        "owner_outcome": None,
        "owner_decision_required": True,
        "proposition_level_materiality_approved": False,
        "source_admitted": False,
        "indexed": False,
        "embedded": False,
        "candidate_mutated": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    return {**material, "record_content_sha256": _sealed(material)}


def build_additional_relationships(
    *,
    sequana_manifest_path: Path,
    additional_manifest_path: Path,
    original_manifest_path: Path,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_additional_treatment_output_already_exists")

    sequana = _load_object(sequana_manifest_path)
    sequana_sha256 = _verify_seal(
        sequana,
        "artifact_content_sha256",
        "phase2a_additional_treatment_sequana_seal_invalid",
    )
    additional = _load_object(additional_manifest_path)
    additional_sha256 = _verify_seal(
        additional,
        "artifact_content_sha256",
        "phase2a_additional_treatment_additional_seal_invalid",
    )
    original = _load_object(original_manifest_path)
    original_sha256 = _verify_seal(
        original,
        "artifact_content_sha256",
        "phase2a_additional_treatment_original_seal_invalid",
    )
    if (
        sequana_sha256 != EXPECTED_SEQUANA_SHA256
        or additional_sha256 != EXPECTED_ADDITIONAL_SHA256
        or original_sha256 != EXPECTED_ORIGINAL_SHA256
        or sequana.get("source_admitted") is not False
        or sequana.get("candidate_mutated") is not False
        or sequana.get("phase2b_authorized") is not False
        or additional.get("source_admission_authorized") is not False
        or additional.get("candidate_mutated") is not False
        or additional.get("phase2b_authorized") is not False
        or original.get("source_admission_authorized") is not False
        or original.get("candidate_mutated") is not False
        or original.get("phase2b_authorized") is not False
    ):
        raise ValueError("phase2a_additional_treatment_source_boundary_invalid")

    recommendations: list[dict[str, Any]] = []

    sequana_spans_record = sequana.get("exact_review_spans")
    if not isinstance(sequana_spans_record, dict):
        raise ValueError("phase2a_additional_treatment_sequana_spans_invalid")
    sequana_spans_path = (
        PROJECT_ROOT / str(sequana_spans_record.get("relative_path") or "")
    ).resolve(strict=True)
    if not sequana_spans_path.is_relative_to(SEQUANA_ROOT) or sequana_spans_path.is_symlink():
        raise ValueError("phase2a_additional_treatment_sequana_spans_path_invalid")
    sequana_spans = _load_object(sequana_spans_path)
    if _verify_seal(
        sequana_spans,
        "artifact_content_sha256",
        "phase2a_additional_treatment_sequana_spans_seal_invalid",
    ) != sequana_spans_record.get("artifact_content_sha256"):
        raise ValueError("phase2a_additional_treatment_sequana_spans_identity_invalid")
    exact_paragraphs = sequana_spans.get("exact_paragraphs")
    if not isinstance(exact_paragraphs, list) or len(exact_paragraphs) != 1:
        raise ValueError("phase2a_additional_treatment_sequana_paragraph_invalid")
    sequana_source = sequana.get("official_case_page")
    if not isinstance(sequana_source, dict):
        raise ValueError("phase2a_additional_treatment_sequana_source_invalid")
    _regular_bound_file(sequana_source, root=SEQUANA_ROOT)
    sequana_text = str(exact_paragraphs[0].get("exact_text") or "")
    sequana_exact = [
        _sealed_span(
            representation="OFFICIAL_CASE_PAGE_PARAGRAPH",
            exact_text=sequana_text,
            source_sha256=str(sequana_source["sha256"]),
        )
    ]
    recommendations.append(
        _advisory_row(
            lead_id="later-treatment-lead-010",
            target="[2022] UKSC 25",
            candidate="[2025] UKPC 34",
            candidate_name=str(sequana["candidate_case_name"]),
            candidate_date=str(sequana["candidate_judgment_date"]),
            court_weight=str(sequana["court_weight"]),
            source_lead_sha256=sequana_sha256,
            exact_spans=sequana_exact,
            required_phrases=(
                "It was confirmed most recently",
                "directors owe their fiduciary duties to the company alone",
            ),
            relationship="AFFIRMED_PERSUASIVE_CONFIRMATION",
            owner_recommendation="AFFIRMED",
            note="The JCPC expressly treats Sequana as confirming the company-property and directors-duty propositions.",
        )
    )

    urs = _lead_by_id(additional, "later-treatment-lead-011")
    urs_source = urs.get("official_case_page")
    urs_raw_spans = urs.get("exact_citation_spans")
    if not isinstance(urs_source, dict) or not isinstance(urs_raw_spans, list):
        raise ValueError("phase2a_additional_treatment_urs_source_invalid")
    _regular_bound_file(urs_source, root=ADDITIONAL_ROOT)
    urs_texts = [str(span.get("exact_text") or "") for span in urs_raw_spans]
    urs_exact = [
        _sealed_span(
            representation="OFFICIAL_CASE_PAGE_PARAGRAPH",
            exact_text=text,
            source_sha256=str(urs_source["sha256"]),
        )
        for text in urs_texts
    ]
    recommendations.append(
        _advisory_row(
            lead_id="later-treatment-lead-011",
            target="[2021] UKSC 20",
            candidate="[2025] UKSC 21",
            candidate_name=str(urs["candidate_case_name"]),
            candidate_date=str(urs["candidate_judgment_date"]),
            court_weight=str(urs["court_weight"]),
            source_lead_sha256=str(urs["lead_content_sha256"]),
            exact_spans=urs_exact,
            required_phrases=(
                "it was explained",
                "scope of duty enquiry essentially depends on the purpose of the duty",
                "the loss here was within the scope",
            ),
            relationship="AFFIRMED_OR_APPLIED",
            owner_recommendation="AFFIRMED",
            note="The later UKSC judgment states and applies Manchester's purpose-of-duty principle.",
        )
    )

    primeo = _lead_by_id(additional, "later-treatment-lead-012")
    primeo_source = primeo.get("official_judgment_pdf")
    primeo_raw_spans = primeo.get("exact_citation_spans")
    if not isinstance(primeo_source, dict) or not isinstance(primeo_raw_spans, list):
        raise ValueError("phase2a_additional_treatment_primeo_source_invalid")
    primeo_pdf = _regular_bound_file(primeo_source, root=ADDITIONAL_ROOT)
    citation_span = next(
        (
            str(span.get("exact_text") or "")
            for span in primeo_raw_spans
            if "[2020] UKSC 31" in str(span.get("exact_text") or "")
        ),
        "",
    )
    application_phrases = (
        "In the Board’s judgment, on proper application",
        "reflective loss rule has no application",
        "losses it suffered each time it made a direct investment",
    )
    application_page, application_text = _pdf_page_with_phrases(
        primeo_pdf,
        application_phrases,
    )
    primeo_exact = [
        _sealed_span(
            representation="OFFICIAL_JUDGMENT_PDF_PAGE_EXTRACTION",
            exact_text=citation_span,
            source_sha256=str(primeo_source["sha256"]),
            page_number=3,
        ),
        _sealed_span(
            representation="OFFICIAL_JUDGMENT_PDF_PAGE_EXTRACTION",
            exact_text=application_text,
            source_sha256=str(primeo_source["sha256"]),
            page_number=application_page,
        ),
    ]
    recommendations.append(
        _advisory_row(
            lead_id="later-treatment-lead-012",
            target="[2020] UKSC 31",
            candidate="[2021] UKPC 22",
            candidate_name=str(primeo["candidate_case_name"]),
            candidate_date=str(primeo["candidate_judgment_date"]),
            court_weight=str(primeo["court_weight"]),
            source_lead_sha256=str(primeo["lead_content_sha256"]),
            exact_spans=primeo_exact,
            required_phrases=(
                "law as determined by the majority in Marex",
                *application_phrases,
            ),
            relationship="AFFIRMED_AND_APPLIED_PERSUASIVELY_WITH_NARROW_SCOPE",
            owner_recommendation="AFFIRMED",
            note="The Board adopts Marex as governing law and applies its deliberately narrow reflective-loss rule.",
        )
    )

    spain = _lead_by_id(additional, "later-treatment-lead-013")
    spain_source = spain.get("official_case_page")
    if not isinstance(spain_source, dict):
        raise ValueError("phase2a_additional_treatment_spain_source_invalid")
    spain_page = _regular_bound_file(spain_source, root=ADDITIONAL_ROOT)
    spain_phrases = (
        "Triple Point Technology Inc v PTT Public Co Ltd [2021] UKSC 29",
        "We agree with the reasoning and conclusion of Phillips LJ",
        "requires a clear and unequivocal expression of the state’s consent",
    )
    spain_texts = _html_paragraph_group(
        spain_page,
        citation="[2021] UKSC 29",
        required_phrases=spain_phrases,
        maximum_paragraphs=8,
    )
    spain_exact = [
        _sealed_span(
            representation="OFFICIAL_CASE_PAGE_PARAGRAPH",
            exact_text=text,
            source_sha256=str(spain_source["sha256"]),
        )
        for text in spain_texts
    ]
    recommendations.append(
        _advisory_row(
            lead_id="later-treatment-lead-013",
            target="[2021] UKSC 29",
            candidate="[2026] UKSC 9",
            candidate_name=str(spain["candidate_case_name"]),
            candidate_date=str(spain["candidate_judgment_date"]),
            court_weight=str(spain["court_weight"]),
            source_lead_sha256=str(spain["lead_content_sha256"]),
            exact_spans=spain_exact,
            required_phrases=spain_phrases,
            relationship="DISTINGUISHED_OR_NOT_APPLIED_AS_ADDITIONAL_GLOSS",
            owner_recommendation="DISTINGUISHED",
            note="The court recounts reliance on Triple Point but rejects an additional statutory gloss while separately requiring clear treaty consent.",
        )
    )

    armstead = _lead_by_id(original, "later-treatment-lead-009")
    armstead_source = armstead.get("official_case_page")
    if not isinstance(armstead_source, dict):
        raise ValueError("phase2a_additional_treatment_armstead_source_invalid")
    armstead_path = _regular_bound_file(armstead_source, root=ORIGINAL_ROOT)
    armstead_phrases = (
        "not to be an exclusive or comprehensive analysis",
        "unnecessary and, in our view, unhelpful",
    )
    armstead_texts = _html_paragraph_group(
        armstead_path,
        citation="[2021] UKSC 20",
        required_phrases=armstead_phrases,
    )
    armstead_exact = [
        _sealed_span(
            representation="OFFICIAL_CASE_PAGE_PARAGRAPH",
            exact_text=text,
            source_sha256=str(armstead_source["sha256"]),
        )
        for text in armstead_texts
    ]
    recommendations.append(
        _advisory_row(
            lead_id="later-treatment-lead-009-cross-target-manchester",
            target="[2021] UKSC 20",
            candidate="[2024] UKSC 6",
            candidate_name=str(armstead["candidate_case_name"]),
            candidate_date=str(armstead["candidate_judgment_date"]),
            court_weight=str(armstead["court_weight"]),
            source_lead_sha256=str(armstead["lead_content_sha256"]),
            exact_spans=armstead_exact,
            required_phrases=armstead_phrases,
            relationship="LIMITED_CHECKLIST_USE_OUTSIDE_SCOPE_OF_DUTY_CONTEXT",
            owner_recommendation="LIMITED",
            note="Armstead limits use of the six-question checklist outside the professional scope-of-duty context, not Manchester's core purpose principle.",
        )
    )

    material = {
        "schema": "legalbot.v111.phase2a.additional-treatment-relationships-advisory.v1",
        "status": "FIVE_ADDITIONAL_EXACT_TREATMENT_CONTEXTS_READY_OWNER_DECISIONS_REQUIRED",
        "source_sequana_content_sha256": sequana_sha256,
        "source_additional_leads_content_sha256": additional_sha256,
        "source_original_leads_content_sha256": original_sha256,
        "record_count": len(recommendations),
        "records": recommendations,
        "classification_counts": {"AFFIRMED": 3, "DISTINGUISHED": 1, "LIMITED": 1},
        "target_recommendations": {
            "[2020] UKSC 31": "AFFIRMED",
            "[2021] UKSC 20": "AFFIRMED_WITH_LIMITED_CHECKLIST_USE_NOTE",
            "[2021] UKSC 29": "DISTINGUISHED_IN_STATE_IMMUNITY_CONTEXT",
            "[2022] UKSC 25": "AFFIRMED",
        },
        "targeted_search_is_exhaustive": False,
        "absence_of_other_hits_proves_no_later_treatment": False,
        "owner_decisions_applied": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    artifact = {**material, "artifact_content_sha256": _sealed(material)}
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_additional_treatment_output_mode_invalid")
    name = "ADDITIONAL-LATER-TREATMENT-RELATIONSHIPS-ADVISORY-5.json"
    _write_exclusive(output_root / name, _pretty_json(artifact))
    outcome = (
        "FIVE ADDITIONAL EXACT OFFICIAL TREATMENT CONTEXTS VERIFIED. OWNER "
        "RELATIONSHIP AND PROPOSITION-LEVEL SOURCE-ADMISSION DECISIONS REMAIN "
        "REQUIRED. PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED.\n"
    )
    _write_exclusive(output_root / "OUTCOME.txt", outcome.encode())
    sums = "".join(
        f"{_sha256_file(output_root / item)}  {item}\n" for item in (name, "OUTCOME.txt")
    )
    _write_exclusive(output_root / "SHA256SUMS.txt", sums.encode())
    return artifact


def _failure_fingerprint(exc: BaseException) -> str:
    return _sha256(f"{type(exc).__name__}:{exc}".encode())


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sequana", type=Path, default=SEQUANA_MANIFEST)
    parser.add_argument("--additional", type=Path, default=ADDITIONAL_MANIFEST)
    parser.add_argument("--original", type=Path, default=ORIGINAL_MANIFEST)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    output_root = args.output_root.resolve()
    try:
        result = build_additional_relationships(
            sequana_manifest_path=args.sequana.resolve(strict=True),
            additional_manifest_path=args.additional.resolve(strict=True),
            original_manifest_path=args.original.resolve(strict=True),
            output_root=output_root,
        )
    except Exception as exc:
        if not output_root.exists():
            output_root.mkdir(parents=True, mode=0o700)
        if output_root.is_dir() and not (output_root / "FAILURE.json").exists():
            failure = {
                "schema": "legalbot.v111.phase2a.additional-treatment-failure.v1",
                "status": "FAILED_DIAGNOSTICS_PERSISTED_BEFORE_EXIT",
                "failure_type": type(exc).__name__,
                "failure_message": str(exc),
                "failure_fingerprint": _failure_fingerprint(exc),
                "affected_stage": "PHASE2A_ADDITIONAL_TREATMENT_ADVISORY",
                "phase2b_authorized": False,
                "development30_authorized": False,
            }
            _write_exclusive(output_root / "FAILURE.json", _pretty_json(failure))
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "artifact_content_sha256": result["artifact_content_sha256"],
                "record_count": result["record_count"],
                "owner_decisions_applied": result["owner_decisions_applied"],
                "phase2b_authorized": result["phase2b_authorized"],
                "development30_authorized": result["development30_authorized"],
                "output_root": str(output_root),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
