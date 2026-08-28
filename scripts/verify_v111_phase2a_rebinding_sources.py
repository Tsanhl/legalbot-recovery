#!/usr/bin/env python3
"""Verify the 89-row rebinding queue against quarantined official bytes.

Exact normalized matching preserves every number and provision identifier.
The verifier may identify an exact official match or suggest a lexical anchor
for correction, but it cannot decide materiality, approve a proposition,
admit a source, mutate a candidate, or authorize another phase.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import io
import json
import os
import re
import stat
import unicodedata
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from bs4 import BeautifulSoup
from pypdf import PdfReader

QUEUE_SCHEMA = "legalbot.v111.phase2a.official-rebinding-queue.v1"
QUARANTINE_SCHEMA = "legalbot.v111.phase2a.official-rebinding-quarantine.v1"
EXPECTED_ITEM_COUNT = 89
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SECTION = re.compile(
    r"(?:\bss?\.?|\bsections?|\band|,)\s*(?P<number>\d+[a-z]?)"
    r"(?P<subsections>(?:\s*\([^)]+\))*)",
    re.IGNORECASE,
)
_REGULATION = re.compile(
    r"(?:\bregs?\.?|\bregulations?)\s*(?P<number>\d+[a-z]?)"
    r"(?P<subsections>(?:\s*\([^)]+\))*)",
    re.IGNORECASE,
)
_ARTICLE = re.compile(
    r"(?:\barts?\.?|\barticles?|\band|,)\s*"
    r"(?P<number>\d+[a-z]?|[ivxlcdm]+)"
    r"(?P<subsections>(?:\s*\([^)]+\))*)",
    re.IGNORECASE,
)
_RULE = re.compile(
    r"(?:\br\.?|\brules?)\s*(?P<number>\d+(?:\.\d+)?)"
    r"(?P<subsections>(?:\s*\([^)]+\))*)",
    re.IGNORECASE,
)
_PARAGRAPH = re.compile(
    r"(?:\bparas?\.?|\bparagraphs?)\s*(?P<number>\d+[a-z]?)"
    r"(?P<subsections>(?:\s*\([^)]+\))*)",
    re.IGNORECASE,
)
_TOKEN = re.compile(r"[a-z0-9]+")
_HTML_HEADING_NAMES = frozenset({"h1", "h2", "h3", "h4", "h5", "h6"})
_DISPLAYED_RULE = re.compile(r"(?<![\d.])(?P<number>\d+\.\d+)(?![\d.])")
_PDF_PARAGRAPH = re.compile(
    r"(?m)^\s*(?P<number>\d{1,4}[a-z]?)\.\s+",
    re.IGNORECASE,
)
_BRACKETED_PARAGRAPH = re.compile(r"\[(?P<number>\d{1,4}[a-z]?)\]", re.IGNORECASE)
_SCHEDULE_ARTICLE = re.compile(r"^article\s+(?P<number>[ivxlcdm]+|\d+)$", re.IGNORECASE)
_SCHEDULE_RULE_ID = re.compile(r"(?:^|-)paragraph-(?P<number>\d+[a-z]?)$", re.IGNORECASE)


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
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_rebinding_verification_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_rebinding_verification_input_must_be_object")
    return value


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or supplied != _sealed(material):
        raise ValueError(code)
    return supplied


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


def _normalise_text(value: str) -> str:
    value = html.unescape(unicodedata.normalize("NFKC", value or ""))
    value = (
        value.replace("–", "-")
        .replace("—", "-")
        .replace("’", "'")
        .replace("‘", "'")
        .replace("“", '"')
        .replace("”", '"')
        .replace("\u00a0", " ")
    )
    # XML legislation represents list labels as separate ``Pnumber`` nodes,
    # so normalize only single-letter parenthetical list markers.  Digits and
    # provision identifiers are deliberately preserved exactly.
    value = re.sub(
        r"\(((?:[a-z]|[ivxlcdm]{2,6}))\)",
        r" \1 ",
        value,
        flags=re.IGNORECASE,
    )
    value = re.sub(r"\s+([,.;:])", r"\1", value)
    value = re.sub(r"([\[(])\s+", r"\1", value)
    return re.sub(r"\s+", " ", value).strip().casefold()


def _components(value: str) -> tuple[str, ...]:
    components = tuple(
        normalized for part in re.split(r"\n\s*\n+", value) if (normalized := _normalise_text(part))
    )
    if not components:
        raise ValueError("phase2a_rebinding_verification_proposition_empty")
    return components


def _expected_anchor_stems(locator: str) -> tuple[str, ...]:
    stems: set[str] = set()

    def add(prefix: str, match: re.Match[str]) -> None:
        base = f"{prefix}-{match.group('number').casefold()}"
        stems.add(base)
        subsection_values = re.findall(r"\(([^)]+)\)", match.group("subsections") or "")
        if subsection_values:
            suffix = "-".join(value.casefold() for value in subsection_values)
            stems.add(f"{base}-{suffix}")

    for match in _SECTION.finditer(locator):
        add("section", match)
    for match in _REGULATION.finditer(locator):
        add("regulation", match)
    for match in _ARTICLE.finditer(locator):
        add("article", match)
    for match in _RULE.finditer(locator):
        add("rule", match)
    for match in _PARAGRAPH.finditer(locator):
        add("paragraph", match)
    for match in _BRACKETED_PARAGRAPH.finditer(locator):
        stems.add(f"paragraph-{match.group('number').casefold()}")
    return tuple(sorted(stems))


def _anchor_id_matches(identifier: str, stems: Sequence[str]) -> bool:
    return _anchor_match_score(identifier, stems) > 0


def _anchor_match_score(identifier: str, stems: Sequence[str]) -> int:
    normalized = _normalise_anchor_identifier(identifier)
    score = 0
    for stem in stems:
        normalized_stem = _normalise_anchor_identifier(stem)
        if not normalized_stem:
            continue
        specificity = normalized_stem.count("-") + 1
        if normalized == normalized_stem:
            score += 400 + specificity
        elif normalized.startswith(normalized_stem + "-"):
            score += 300 + specificity
        elif normalized.endswith("-" + normalized_stem):
            score += 200 + specificity
        elif f"-{normalized_stem}-" in f"-{normalized}-":
            score += 100 + specificity
    return score


def _normalise_anchor_identifier(value: str) -> str:
    separated = re.sub(r"(?<=[a-z])(?=\d)", "-", value.casefold())
    separated = re.sub(r"(?<=\d)(?=[a-z])", "-", separated)
    return re.sub(r"[^a-z0-9]+", "-", separated).strip("-")


def _meaningful_tokens(value: str) -> frozenset[str]:
    return frozenset(token for token in _TOKEN.findall(value) if len(token) >= 3)


def _has_substantive_text(value: str) -> bool:
    return bool(re.search(r"[a-z]{2,}", value, re.IGNORECASE))


def _lexical_anchor_suggestions(
    component: str, anchors: Sequence[tuple[str, str]], *, limit: int = 3
) -> list[dict[str, Any]]:
    component_tokens = _meaningful_tokens(component)
    if not component_tokens:
        return []
    ranked: list[tuple[float, int, str, str]] = []
    for identifier, anchor_text in anchors:
        if len(anchor_text) < max(20, len(component) // 5):
            continue
        anchor_tokens = _meaningful_tokens(anchor_text)
        coverage = len(component_tokens & anchor_tokens) / len(component_tokens)
        if coverage >= 0.35:
            ranked.append((coverage, -len(anchor_text), identifier, anchor_text))
    ranked.sort(reverse=True)
    return [
        {
            "anchor_id": identifier,
            "component_token_coverage": round(coverage, 6),
            "anchor_text_sha256": _sha256(anchor_text.encode()),
            "anchor_text": anchor_text,
            "anchor_text_truncated": False,
            "advisory_only_not_exact_match": True,
        }
        for coverage, _, identifier, anchor_text in ranked[:limit]
    ]


def _html_anchors(soup: BeautifulSoup) -> tuple[tuple[str, str], ...]:
    """Return logical HTML sections, including text after empty heading anchors."""

    anchors: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for element in soup.find_all(id=True):
        identifier = str(element.get("id") or "")
        if not identifier:
            continue
        section_root = element.find_parent(_HTML_HEADING_NAMES)
        if section_root is None and element.name in _HTML_HEADING_NAMES:
            section_root = element
        parts: list[str] = []
        if section_root is not None:
            parts.append(section_root.get_text(" "))
            for sibling in section_root.next_siblings:
                sibling_name = str(getattr(sibling, "name", "") or "")
                if sibling_name in _HTML_HEADING_NAMES:
                    break
                if hasattr(sibling, "get_text"):
                    parts.append(sibling.get_text(" "))
                else:
                    parts.append(str(sibling))
        else:
            parts.append(element.get_text(" "))
        normalized = _normalise_text(" ".join(parts))
        if not normalized:
            continue
        pair = (identifier, normalized)
        if pair not in seen:
            anchors.append(pair)
            seen.add(pair)

        displayed_rule = _DISPLAYED_RULE.search(normalized)
        if displayed_rule:
            alias = f"rule-{displayed_rule.group('number').casefold()}"
            alias_pair = (alias, normalized)
            if alias_pair not in seen:
                anchors.append(alias_pair)
                seen.add(alias_pair)
    return tuple(anchors)


def _pdf_anchors(text: str) -> tuple[tuple[str, str], ...]:
    """Bind deterministically extracted PDF text to numbered judgment paragraphs."""

    matches = tuple(_PDF_PARAGRAPH.finditer(text))
    anchors: list[tuple[str, str]] = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        normalized = _normalise_text(text[match.start() : end])
        if normalized:
            anchors.append((f"paragraph-{match.group('number').casefold()}", normalized))
    return tuple(anchors)


def _xml_anchors(root: ET.Element) -> tuple[tuple[str, str], ...]:
    """Expose native legislation IDs plus schedule Article/rule aliases."""

    anchors: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def append(identifier: str, element: ET.Element) -> None:
        normalized = _normalise_text(" ".join(element.itertext()))
        pair = (identifier, normalized)
        if identifier and normalized and pair not in seen:
            anchors.append(pair)
            seen.add(pair)

    for element in root.iter():
        identifier = str(element.attrib.get("id") or "")
        if identifier:
            append(identifier, element)

        number_element = next(
            (child for child in element if str(child.tag).rsplit("}", 1)[-1] == "Number"),
            None,
        )
        if number_element is None:
            continue
        number_text = _normalise_text(" ".join(number_element.itertext()))
        article_match = _SCHEDULE_ARTICLE.fullmatch(number_text)
        if not article_match:
            continue
        article_number = article_match.group("number").casefold()
        append(f"article-{article_number}", element)
        for descendant in element.iter():
            descendant_id = str(descendant.attrib.get("id") or "")
            rule_match = _SCHEDULE_RULE_ID.search(descendant_id)
            if rule_match:
                append(
                    f"article-{article_number}-rule-{rule_match.group('number').casefold()}",
                    descendant,
                )
    return tuple(anchors)


def _stated_locator_evidence_state(
    expected_stems: Sequence[str], documents: Sequence[Mapping[str, Any]]
) -> str:
    if not expected_stems:
        return "LOCATOR_SYNTAX_NOT_RECOGNIZED"
    matching_text = [
        anchor_text
        for document in documents
        for identifier, anchor_text in document["anchors"]
        if _anchor_id_matches(identifier, expected_stems)
    ]
    if not matching_text:
        return "STATED_LOCATOR_NOT_FOUND"
    if any(_has_substantive_text(anchor_text) for anchor_text in matching_text):
        return "SUBSTANTIVE_TEXT_AVAILABLE_AT_STATED_LOCATOR"
    return "EMPTY_OR_OMITTED_AT_TARGET_DATE"


def _stated_locator_corrections(
    component: str,
    expected_stems: Sequence[str],
    documents: Sequence[Mapping[str, Any]],
    *,
    limit: int = 5,
) -> list[dict[str, Any]]:
    """Return exact current text at the stated locator without deciding materiality."""

    component_tokens = _meaningful_tokens(component)
    ranked: list[tuple[int, float, int, str, str, str, Mapping[str, Any]]] = []
    for document in documents:
        for identifier, anchor_text in document["anchors"]:
            locator_match_score = _anchor_match_score(identifier, expected_stems)
            if not locator_match_score:
                continue
            anchor_tokens = _meaningful_tokens(anchor_text)
            if len(anchor_text) < 20 or not anchor_tokens or not _has_substantive_text(anchor_text):
                continue
            coverage = (
                len(component_tokens & anchor_tokens) / len(component_tokens)
                if component_tokens
                else 0.0
            )
            ranked.append(
                (
                    locator_match_score,
                    coverage,
                    -len(anchor_text),
                    str(document["target_id"]),
                    identifier,
                    anchor_text,
                    document,
                )
            )
    ranked.sort(
        key=lambda item: (item[0], item[1], item[2], item[3], item[4], item[5]),
        reverse=True,
    )
    return [
        {
            "target_id": target_id,
            "target_type": document["target_type"],
            "official_url": document["official_url"],
            "official_file_sha256": document["file_sha256"],
            "document_kind": document["document_kind"],
            "anchor_id": identifier,
            "anchor_matches_stated_locator": True,
            "locator_match_specificity_score": locator_match_score,
            "component_token_coverage": round(coverage, 6),
            "exact_normalized_component_match": component in anchor_text,
            "anchor_text_sha256": _sha256(anchor_text.encode()),
            "anchor_text": anchor_text,
            "anchor_text_truncated": False,
            "advisory_only_owner_decision_required": True,
        }
        for locator_match_score, coverage, _, target_id, identifier, anchor_text, document in ranked[
            :limit
        ]
    ]


def _parse_document(
    *, raw: bytes, content_type: str
) -> tuple[str, tuple[tuple[str, str], ...], str]:
    if content_type in {"application/xml", "text/xml", "application/atom+xml"}:
        opening = raw[:100_000].upper()
        if b"<!DOCTYPE" in opening or b"<!ENTITY" in opening:
            raise ValueError("phase2a_rebinding_verification_xml_forbidden_declaration")
        root = ET.fromstring(raw)
        anchors = _xml_anchors(root)
        return _normalise_text(" ".join(root.itertext())), anchors, "xml"
    if content_type == "text/html":
        soup = BeautifulSoup(raw, "lxml")
        for unwanted in soup(["script", "style", "noscript", "template"]):
            unwanted.decompose()
        anchors = _html_anchors(soup)
        return _normalise_text(soup.get_text(" ")), anchors, "html"
    if content_type == "application/pdf":
        reader = PdfReader(io.BytesIO(raw))
        text = "\n".join(page.extract_text() or "" for page in reader.pages)
        return _normalise_text(text), _pdf_anchors(text), "pdf"
    raise ValueError("phase2a_rebinding_verification_content_type_unsupported")


def _component_check(
    *,
    component: str,
    expected_stems: Sequence[str],
    documents: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    document_hits: list[dict[str, Any]] = []
    anchor_candidates: list[tuple[int, str, str, str]] = []
    all_anchors: list[tuple[str, str]] = []
    for document in documents:
        text = str(document["normalized_text"])
        anchors = document["anchors"]
        all_anchors.extend(anchors)
        if component not in text:
            continue
        matching_anchors = [
            (len(anchor_text), identifier, anchor_text)
            for identifier, anchor_text in anchors
            if component in anchor_text
        ]
        matching_anchors.sort()
        for length, identifier, anchor_text in matching_anchors[:5]:
            anchor_candidates.append((length, str(document["target_id"]), identifier, anchor_text))
        document_hits.append(
            {
                "target_id": document["target_id"],
                "target_type": document["target_type"],
                "official_url": document["official_url"],
                "official_file_sha256": document["file_sha256"],
                "document_kind": document["document_kind"],
                "exact_normalized_component_match": True,
            }
        )
    anchor_candidates.sort()
    exact_anchors = [
        {
            "target_id": target_id,
            "anchor_id": identifier,
            "anchor_matches_stated_locator": _anchor_id_matches(identifier, expected_stems),
            "anchor_text_sha256": _sha256(anchor_text.encode()),
        }
        for _, target_id, identifier, anchor_text in anchor_candidates[:5]
    ]
    exact = bool(document_hits)
    material = {
        "component_sha256": _sha256(component.encode()),
        "exact_normalized_component_match": exact,
        "document_hits": document_hits,
        "exact_anchor_hits": exact_anchors,
        "stated_locator_anchor_match": bool(
            exact_anchors and any(item["anchor_matches_stated_locator"] for item in exact_anchors)
        ),
        "stated_locator_evidence_state": _stated_locator_evidence_state(
            expected_stems,
            documents,
        ),
        "lexical_anchor_suggestions_if_not_exact": (
            [] if exact else _lexical_anchor_suggestions(component, all_anchors)
        ),
        "stated_locator_anchor_corrections_if_not_exact": (
            []
            if exact
            else _stated_locator_corrections(
                component,
                expected_stems,
                documents,
            )
        ),
    }
    return {**material, "check_content_sha256": _sealed(material)}


def verify(*, queue_path: Path, quarantine_root: Path, output_root: Path) -> dict[str, Any]:
    """Verify all queue rows while preserving every owner and phase boundary."""

    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_rebinding_verification_output_already_exists")
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_rebinding_verification_output_mode_invalid")
    queue = _load_object(queue_path)
    queue_sha256 = _verify_seal(
        queue, "artifact_content_sha256", "phase2a_rebinding_verification_queue_seal_invalid"
    )
    manifest_path = quarantine_root / "QUARANTINE-MANIFEST.json"
    manifest = _load_object(manifest_path)
    manifest_sha256 = _verify_seal(
        manifest,
        "manifest_content_sha256",
        "phase2a_rebinding_verification_manifest_seal_invalid",
    )
    if (
        queue.get("schema") != QUEUE_SCHEMA
        or queue.get("item_count") != EXPECTED_ITEM_COUNT
        or manifest.get("schema") != QUARANTINE_SCHEMA
        or manifest.get("source_queue_content_sha256") != queue_sha256
        or manifest.get("covered_row_count") != EXPECTED_ITEM_COUNT
        or manifest.get("result_counts") != {"DOWNLOADED_QUARANTINED": 41}
        or queue.get("automatic_source_admission") is not False
        or manifest.get("automatic_source_admission") is not False
        or manifest.get("phase2b_authorized") is not False
    ):
        raise ValueError("phase2a_rebinding_verification_boundary_invalid")

    documents: dict[str, dict[str, Any]] = {}
    children: dict[str, list[str]] = {}
    for record in manifest.get("records", []):
        _verify_seal(
            record,
            "record_content_sha256",
            "phase2a_rebinding_verification_record_seal_invalid",
        )
        if record.get("result") != "DOWNLOADED_QUARANTINED":
            raise ValueError("phase2a_rebinding_verification_official_source_missing")
        member = str(record.get("quarantine_member") or "")
        path = quarantine_root / member
        if path.is_symlink() or not path.is_file():
            raise ValueError("phase2a_rebinding_verification_quarantine_member_missing")
        raw = path.read_bytes()
        if _sha256(raw) != record.get("sha256"):
            raise ValueError("phase2a_rebinding_verification_quarantine_hash_mismatch")
        normalized, anchors, document_kind = _parse_document(
            raw=raw, content_type=str(record.get("content_type") or "")
        )
        target_id = str(record.get("target_id") or "")
        documents[target_id] = {
            "target_id": target_id,
            "target_type": record.get("target_type"),
            "official_url": record.get("final_url"),
            "file_sha256": record.get("sha256"),
            "normalized_text": normalized,
            "anchors": anchors,
            "document_kind": document_kind,
        }
        parent = str(record.get("parent_target_id") or "")
        if parent:
            children.setdefault(parent, []).append(target_id)

    row_targets = manifest.get("row_target_ids")
    if not isinstance(row_targets, dict):
        raise ValueError("phase2a_rebinding_verification_row_targets_invalid")
    records: list[dict[str, Any]] = []
    exact_ready: list[dict[str, Any]] = []
    correction_queue: list[dict[str, Any]] = []
    status_counts: Counter[str] = Counter()
    for item in queue.get("items", []):
        row_id = str(item.get("row_id") or "")
        target_ids = list(row_targets.get(row_id, []))
        for target_id in tuple(target_ids):
            target_ids.extend(children.get(str(target_id), []))
        target_ids = sorted(set(target_ids))
        row_documents = [documents[target_id] for target_id in target_ids]
        expected_stems = _expected_anchor_stems(str(item.get("official_legal_locator") or ""))
        component_values = _components(str(item.get("proposed_exact_proposition_text") or ""))
        component_checks = [
            _component_check(
                component=component,
                expected_stems=expected_stems,
                documents=row_documents,
            )
            for component in component_values
        ]
        all_exact = all(check["exact_normalized_component_match"] for check in component_checks)
        any_anchors = any(check["exact_anchor_hits"] for check in component_checks)
        stated_locator_match = bool(
            all_exact
            and expected_stems
            and all(
                check["stated_locator_anchor_match"] or not check["exact_anchor_hits"]
                for check in component_checks
            )
        )
        if all_exact and stated_locator_match:
            status = "EXACT_OFFICIAL_TEXT_AND_STATED_LOCATOR_MATCH"
        elif all_exact and any_anchors:
            status = "EXACT_OFFICIAL_TEXT_DIFFERENT_OR_UNCONFIRMED_LOCATOR"
        elif all_exact:
            status = "EXACT_OFFICIAL_TEXT_LOCATOR_CONFIRMATION_REQUIRED"
        else:
            status = "STAGING_PROPOSITION_DIFFERS_FROM_FRESH_OFFICIAL_BYTES"
        original_match = str(item.get("match_status") or "")
        if all_exact and original_match == "NO_MATCHING_SOURCE_IN_SEALED_CANDIDATE":
            candidate_action = "OWNER_SOURCE_ADMISSION_DECISION_REQUIRED"
        elif all_exact:
            candidate_action = "CANDIDATE_REBIND_OR_SUCCESSOR_DECISION_REQUIRED"
        else:
            candidate_action = "CORRECT_PROPOSITION_OR_LOCATOR_THEN_REVERIFY"
        material = {
            "ordinal": len(records) + 1,
            "row_id": row_id,
            "source_queue_record_content_sha256": item.get("record_content_sha256"),
            "original_candidate_match_status": original_match,
            "official_source_title": item.get("official_source_title"),
            "official_source_type": item.get("official_source_type"),
            "official_citation": item.get("official_citation"),
            "stated_official_legal_locator": item.get("official_legal_locator"),
            "expected_official_anchor_stems": expected_stems,
            "proposed_exact_proposition_text": item.get("proposed_exact_proposition_text"),
            "proposition_component_count": len(component_values),
            "component_checks": component_checks,
            "all_components_exact_in_fresh_official_bytes": all_exact,
            "stated_locator_confirmed": stated_locator_match,
            "verification_status": status,
            "required_candidate_action": candidate_action,
            "legal_materiality_decided": False,
            "owner_decision_required": True,
            "source_admission_authorized": False,
            "candidate_mutated": False,
            "issue_technically_qualified": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        record = {**material, "record_content_sha256": _sealed(material)}
        records.append(record)
        status_counts[status] += 1
        destination_material = {
            "row_id": row_id,
            "source_verification_record_content_sha256": record["record_content_sha256"],
            "verification_status": status,
            "required_candidate_action": candidate_action,
            "proposed_exact_proposition_text": item.get("proposed_exact_proposition_text"),
            "official_source_title": item.get("official_source_title"),
            "official_citation": item.get("official_citation"),
            "official_legal_locator": item.get("official_legal_locator"),
            "official_source_url": item.get("official_source_url"),
            "owner_decision_required": True,
            "automatic_source_admission": False,
            "automatic_candidate_mutation": False,
        }
        destination = {
            **destination_material,
            "record_content_sha256": _sealed(destination_material),
        }
        (exact_ready if all_exact else correction_queue).append(destination)

    if len(records) != EXPECTED_ITEM_COUNT or len(exact_ready) + len(correction_queue) != 89:
        raise ValueError("phase2a_rebinding_verification_inventory_invalid")
    verification_material = {
        "schema": "legalbot.v111.phase2a.official-rebinding-verification.v1",
        "status": "DETERMINISTIC_VERIFICATION_COMPLETE_OWNER_REVIEW_REQUIRED",
        "source_queue_content_sha256": queue_sha256,
        "source_quarantine_manifest_content_sha256": manifest_sha256,
        "source_quarantine_manifest_file_sha256": _sha256_file(manifest_path),
        "record_count": len(records),
        "verification_status_counts": dict(sorted(status_counts.items())),
        "exact_official_text_count": len(exact_ready),
        "correction_required_count": len(correction_queue),
        "records": records,
        "issue_technical_qualification_count": 0,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    verification = {
        **verification_material,
        "artifact_content_sha256": _sealed(verification_material),
    }
    ready_material = {
        "schema": "legalbot.v111.phase2a.exact-official-rebinding-owner-review.v1",
        "status": "OWNER_REVIEW_REQUIRED_NOT_APPROVED",
        "source_verification_content_sha256": verification["artifact_content_sha256"],
        "item_count": len(exact_ready),
        "items": exact_ready,
        "owner_decision_required": True,
        "automatic_source_admission": False,
        "automatic_candidate_mutation": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    ready = {**ready_material, "artifact_content_sha256": _sealed(ready_material)}
    correction_material = {
        "schema": "legalbot.v111.phase2a.proposition-correction-queue.v1",
        "status": "ADVISORY_CORRECTION_RESEARCH_REQUIRED",
        "source_verification_content_sha256": verification["artifact_content_sha256"],
        "item_count": len(correction_queue),
        "items": correction_queue,
        "owner_decision_required_after_correction": True,
        "automatic_source_admission": False,
        "automatic_candidate_mutation": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    correction = {
        **correction_material,
        "artifact_content_sha256": _sealed(correction_material),
    }
    artifacts = {
        "FRESH-OFFICIAL-REBINDING-VERIFICATION-89.json": verification,
        "OWNER-REVIEW-EXACT-OFFICIAL-MATCHES.json": ready,
        "PROPOSITION-CORRECTION-QUEUE.json": correction,
    }
    for name, artifact in artifacts.items():
        _write_exclusive(output_root / name, _pretty_json(artifact))
    _write_exclusive(
        output_root / "OUTCOME.txt",
        (
            f"PHASE 2A OFFICIAL REBINDING CHECK COMPLETE — {len(exact_ready)} EXACT "
            f"OFFICIAL-TEXT ROWS REQUIRE OWNER REVIEW; {len(correction_queue)} ROWS "
            "REQUIRE CORRECTION; ZERO ISSUES AUTO-QUALIFIED; PHASE 2B NOT AUTHORIZED\n"
        ).encode(),
    )
    files = sorted(path for path in output_root.iterdir() if path.is_file())
    _write_exclusive(
        output_root / "SHA256SUMS.txt",
        "".join(f"{_sha256_file(path)}  {path.name}\n" for path in files).encode(),
    )
    return {
        "output_root": str(output_root),
        "verification_content_sha256": verification["artifact_content_sha256"],
        "exact_official_text_count": len(exact_ready),
        "correction_required_count": len(correction_queue),
        "verification_status_counts": dict(sorted(status_counts.items())),
        "issue_technical_qualification_count": 0,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }


def _persist_failure(output_root: Path, exc: BaseException) -> None:
    try:
        output_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        path = output_root / "FAILURE.json"
        if path.exists():
            return
        material = {
            "schema": "legalbot.v111.phase2a.rebinding-verification-failure.v1",
            "exception_type": type(exc).__name__,
            "error": str(exc),
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        _write_exclusive(
            path,
            _pretty_json({**material, "failure_content_sha256": _sealed(material)}),
        )
    except Exception:
        return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", required=True, type=Path)
    parser.add_argument("--quarantine-root", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = verify(
            queue_path=args.queue.resolve(strict=True),
            quarantine_root=args.quarantine_root.resolve(strict=True),
            output_root=args.output_root.resolve(),
        )
    except Exception as exc:
        _persist_failure(args.output_root.resolve(), exc)
        raise
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
