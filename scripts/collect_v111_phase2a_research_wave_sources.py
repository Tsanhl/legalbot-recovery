#!/usr/bin/env python3
"""Bind genuinely new Phase-2A official representations in quarantine.

This is a create-only, non-authorizing transport stage. It verifies an exact
316-row research-wave set and the sealed 251-source candidate, resolves each
authority independently of URL aliases, and downloads only authorities which
are consistently described as absent with admission required. Unknown or
contradictory identities are emitted as holds and are never fetched.

The manifest is evidence for a later owner packet. It does not admit a source,
touch the catalogue, build or embed an index, decide a legal question, or
authorize any later phase.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import unicodedata
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import httpx

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.retrieval.source_manifest import (  # noqa: E402
    approved_source_manifest_sha256,
)

from scripts import (  # noqa: E402
    validate_v111_phase2a_official_research_waves as wave_validator,
)

ALLOWED_HOSTS = frozenset(wave_validator.ALLOWED_HOSTS)
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_REDIRECTS = 5
USER_AGENT = "LegalBot-v1.11-Phase2A-quarantine-representation-binding/1.0"
TARGET_DATE = date(2026, 8, 14)
EXPECTED_WAVE_ROW_COUNT = 316
EXPECTED_CANONICAL_WAVE_COUNT = 32
EXPECTED_CANDIDATE_SOURCE_COUNT = 251
CANONICAL_WAVE_SET_SCHEMA = "legalbot.v111.phase2a.canonical-research-wave-set.v1"
CANONICAL_Q48_WAVE = "research-live60-q48-q50-r3.json"
OBSOLETE_Q48_WAVES = frozenset(
    {
        "research-live60-q48-q50.json",
        "research-live60-q48-q50-r1.json",
        "research-live60-q48-q50-r2.json",
    }
)
_CANONICAL_SET_REQUIRED_FALSE_FLAGS = frozenset(
    {
        "active_or_previous_write_authorized",
        "automatic_embedding",
        "automatic_indexing",
        "candidate_mutated",
        "catalogue_mutated",
        "development30_authorized",
        "embedding_run",
        "live_activation_authorized",
        "owner_decisions_applied",
        "owner_outcomes_applied",
        "phase2b_authorized",
        "source_admitted",
        "source_collected",
        "source_collection_authorized",
        "validation30_authorized",
    }
)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_SAFE_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}")
_CANONICAL_WAVE_FILE_NAME = re.compile(r"research-live(?:30|60)-q\d+(?:-q\d+)*(?:-r\d+)?\.json")
_NEUTRAL_CITATION = re.compile(
    r"\[(?P<year>\d{4})\]\s*"
    r"(?P<court>UKSC|UKPC|UKHL|EWCA\s+(?:Civ|Crim)|EWHC)\s*"
    r"(?P<number>\d+)(?:\s*\((?P<division>[A-Za-z]+)\))?",
    re.IGNORECASE,
)
_INSTRUMENT_MENTION = re.compile(r"\b(?:Act|Regulations|Order)\s+(?:of\s+)?\d{4}\b", re.IGNORECASE)
_COBS_SECTION_PREFIX = re.compile(r"\b(?P<prefix>\d{1,2}[A-Z]?)\.\d", re.IGNORECASE)
_EWHC_DIVISIONS = {
    "admin": "Admin",
    "ch": "Ch",
    "comm": "Comm",
    "fam": "Fam",
    "kb": "KB",
    "pat": "Pat",
    "qb": "QB",
    "scco": "SCCO",
    "tcc": "TCC",
}
_XML_CONTENT_TYPES = frozenset({"application/atom+xml", "application/xml", "text/xml"})
_SAFE_CONTENT_TYPES = _XML_CONTENT_TYPES | frozenset(
    {
        "application/octet-stream",
        "application/pdf",
        "text/html",
        "application/xhtml+xml",
        "text/plain",
    }
)
_XML_FORBIDDEN = re.compile(rb"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)
_PRIVATE_PATH = re.compile(
    r"(?:(?<![A-Za-z0-9:])/(?:Users|home|private|tmp|var/folders)/"
    r"|(?:^|[^A-Za-z0-9])[A-Za-z]:\\)",
    re.IGNORECASE,
)
_EMAIL_ADDRESS = re.compile(r"\b[^\s@]+@[^\s@]+\.[^\s@]+\b")
_FORBIDDEN_PRIVACY_KEYS = frozenset(
    {
        "absolute_path",
        "canonical_markdown_path",
        "local_path",
        "original_filename",
        "owner_id",
        "owner_identifier",
        "personal_filename",
        "source_file_path",
        "source_path",
    }
)


@dataclass(frozen=True)
class ArtifactBinding:
    """A regular file bound by both logical and byte identities."""

    path: Path
    content_sha256: str
    file_sha256: str


class _JudgmentLinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.casefold() != "a":
            return
        href = next((value for key, value in attrs if key.casefold() == "href"), None)
        if href and "judgment" in href.casefold() and href.casefold().endswith(".pdf"):
            self.hrefs.append(href)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_digest(value: str, *, error_code: str) -> None:
    if _SHA256.fullmatch(str(value)) is None:
        raise ValueError(error_code)


def _assert_privacy_safe(value: Any, *, location: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            key_text = str(key)
            if key_text.casefold() in _FORBIDDEN_PRIVACY_KEYS:
                raise ValueError("phase2a_research_source_privacy_gate_failed")
            _assert_privacy_safe(nested, location=f"{location}.{key_text}")
        return
    if isinstance(value, list | tuple | set | frozenset):
        for index, nested in enumerate(value):
            _assert_privacy_safe(nested, location=f"{location}[{index}]")
        return
    if not isinstance(value, str):
        return
    if (
        "\x00" in value
        or value.casefold().startswith("file://")
        or _PRIVATE_PATH.search(value)
        or _EMAIL_ADDRESS.search(value)
    ):
        raise ValueError("phase2a_research_source_privacy_gate_failed")


def _safe_url(value: str) -> str:
    parsed = urlsplit(value)
    host = (parsed.hostname or "").casefold()
    if (
        parsed.scheme != "https"
        or host not in ALLOWED_HOSTS
        or parsed.username
        or parsed.password
        or parsed.fragment
        or parsed.port not in (None, 443)
    ):
        raise ValueError("phase2a_research_source_url_invalid")
    return urlunsplit(("https", host, parsed.path or "/", parsed.query, ""))


def _normalized_official_identity_url(value: str) -> str:
    safe = _safe_url(value)
    parsed = urlsplit(safe)
    host = (parsed.hostname or "").casefold().removeprefix("www.")
    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    if path != "/":
        path = path.rstrip("/")
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunsplit(("https", host, path, query, ""))


def _legislation_identity_parts(path: str) -> tuple[str, tuple[str, ...]]:
    parts = [part for part in path.split("/") if part]
    if parts and parts[0].casefold() == "id":
        parts = parts[1:]
    if not parts:
        raise ValueError("phase2a_research_legislation_path_invalid")
    kind = parts[0].casefold()
    if kind not in {"eur", "ukpga", "uksi"}:
        raise ValueError("phase2a_research_legislation_path_unsupported")
    if len(parts) < 3:
        raise ValueError("phase2a_research_legislation_identity_incomplete")
    if kind in {"eur", "uksi"} or re.fullmatch(r"\d{4}", parts[1]):
        identity = tuple(parts[:3])
    else:
        # Pre-1963 Acts use regnal paths such as Eliz2/5-6/11.
        identity = tuple(parts[:4])
    if len(identity) < 3 or any(not item for item in identity):
        raise ValueError("phase2a_research_legislation_identity_incomplete")
    return kind, identity


def _legislation_representation_qualifier(path: str, identity: Sequence[str]) -> str | None:
    parts = [part for part in path.split("/") if part]
    if parts and parts[0].casefold() == "id":
        parts = parts[1:]
    remainder = parts[len(identity) :]
    qualifiers: set[str] = set()
    for part in remainder:
        lowered = part.casefold()
        if lowered == "made":
            qualifiers.add("made")
        elif re.fullmatch(r"\d{4}-\d{2}-\d{2}", part):
            try:
                explicit_date = date.fromisoformat(part)
            except ValueError as exc:
                raise ValueError("phase2a_research_legislation_explicit_date_invalid") from exc
            if explicit_date > TARGET_DATE:
                raise ValueError(
                    "phase2a_research_legislation_explicit_date_exceeds_source_ceiling"
                )
            qualifiers.add(part)
    if len(qualifiers) > 1:
        raise ValueError("phase2a_research_legislation_qualifier_conflict")
    return next(iter(qualifiers), None)


def normalized_download_url(value: str) -> str:
    """Return a deterministic direct official representation URL."""

    safe = _safe_url(value)
    parsed = urlsplit(safe)
    host = (parsed.hostname or "").casefold()
    path = parsed.path.rstrip("/")
    if host == "caselaw.nationalarchives.gov.uk":
        if not path.endswith("/data.xml"):
            path = f"{path}/data.xml"
        return urlunsplit(("https", host, path, "", ""))
    if host in {"www.legislation.gov.uk", "legislation.gov.uk"}:
        _, identity = _legislation_identity_parts(path)
        identity_path = "/".join(identity)
        qualifier = _legislation_representation_qualifier(path, identity)
        representation = qualifier or TARGET_DATE.isoformat()
        return urlunsplit(
            (
                "https",
                "www.legislation.gov.uk",
                f"/{identity_path}/{representation}/data.xml",
                "",
                "",
            )
        )
    return _normalized_official_identity_url(safe)


def _canonical_neutral_citation_match(match: re.Match[str]) -> str:
    court_raw = re.sub(r"\s+", " ", match.group("court")).casefold()
    court = {
        "uksc": "UKSC",
        "ukpc": "UKPC",
        "ukhl": "UKHL",
        "ewca civ": "EWCA Civ",
        "ewca crim": "EWCA Crim",
        "ewhc": "EWHC",
    }[court_raw]
    division = match.group("division")
    suffix = ""
    if court == "EWHC" and division:
        canonical_division = _EWHC_DIVISIONS.get(division.casefold(), division)
        suffix = f" ({canonical_division})"
    return f"neutral-citation:[{match.group('year')}] {court} {int(match.group('number'))}{suffix}"


def _canonical_neutral_citations(value: str) -> tuple[str, ...]:
    normalized = unicodedata.normalize("NFKC", value)
    return tuple(
        dict.fromkeys(
            _canonical_neutral_citation_match(match)
            for match in _NEUTRAL_CITATION.finditer(normalized)
        )
    )


def _canonical_neutral_citation(value: str) -> str | None:
    citations = _canonical_neutral_citations(value)
    return citations[0] if citations else None


def _has_composite_instrument_citation(value: str) -> bool:
    identities: set[str] = set()
    for clause in re.split(r"[;\n]", value):
        matches = list(_INSTRUMENT_MENTION.finditer(clause))
        if not matches:
            continue
        # Commencement instruments commonly contain the parent Act and the
        # Regulations in one official title. The final instrument designator
        # in that clause is the represented authority, not a second source.
        label = unicodedata.normalize("NFKC", clause[: matches[-1].end()]).casefold()
        label = re.sub(r"^(?:see|the)\s+", "", label.strip())
        label = re.sub(r"\s+", " ", label)
        identities.add(label)
    return len(identities) > 1


def _has_composite_handbook_citation(value: str, *, official_url: str) -> bool:
    path = urlsplit(official_url).path.casefold()
    if "/handbook/cobs" not in path or "cobs" not in value.casefold():
        return False
    prefixes = {match.group("prefix").casefold() for match in _COBS_SECTION_PREFIX.finditer(value)}
    return len(prefixes) > 1


def _tna_authority_identity(value: str) -> str | None:
    parsed = urlsplit(_safe_url(value))
    if (parsed.hostname or "").casefold() != "caselaw.nationalarchives.gov.uk":
        return None
    parts = [part.casefold() for part in parsed.path.split("/") if part]
    if parts and parts[-1] == "data.xml":
        parts.pop()
    if len(parts) == 3 and parts[0] in {"uksc", "ukpc", "ukhl"}:
        court = parts[0].upper()
        year, number = parts[1:]
        if year.isdigit() and number.isdigit():
            return f"neutral-citation:[{year}] {court} {int(number)}"
    if len(parts) == 4 and parts[0] == "ewca" and parts[1] in {"civ", "crim"}:
        year, number = parts[2:]
        if year.isdigit() and number.isdigit():
            division = "Civ" if parts[1] == "civ" else "Crim"
            return f"neutral-citation:[{year}] EWCA {division} {int(number)}"
    if len(parts) == 4 and parts[0] == "ewhc":
        division = _EWHC_DIVISIONS.get(parts[1])
        year, number = parts[2:]
        if division and year.isdigit() and number.isdigit():
            return f"neutral-citation:[{year}] EWHC {int(number)} ({division})"
    return None


def _citation_fallback(value: str) -> str | None:
    normalized = re.sub(
        r"[^a-z0-9]+",
        "-",
        unicodedata.normalize("NFKC", value).casefold(),
    ).strip("-")
    return f"citation-key:{normalized}" if normalized else None


def _authority_identity(authority: Mapping[str, Any]) -> tuple[str, tuple[str, ...]]:
    official_url = str(authority.get("official_url") or "")
    title = str(authority.get("title") or "")
    citation = str(authority.get("citation") or "")
    citation_label = citation or title
    identity_text = "\n".join(dict.fromkeys(item for item in (title, citation) if item))
    if not official_url:
        neutral_citations = _canonical_neutral_citations(identity_text)
        if len(neutral_citations) > 1 or _has_composite_instrument_citation(citation_label):
            return (
                f"composite-authority:{_sha256(identity_text.encode('utf-8'))[:32]}",
                ("COMPOSITE_AUTHORITY_IDENTITY_HOLD", "OFFICIAL_URL_MISSING"),
            )
        identity = neutral_citations[0] if neutral_citations else _citation_fallback(citation_label)
        if identity is None:
            identity = f"unresolved-authority:{_sha256(identity_text.encode('utf-8'))[:32]}"
        return identity, ("OFFICIAL_URL_MISSING",)
    safe = _safe_url(official_url)
    parsed = urlsplit(safe)
    host = (parsed.hostname or "").casefold()
    reasons: list[str] = []
    neutral_citations = _canonical_neutral_citations(identity_text)
    if (
        len(neutral_citations) > 1
        or _has_composite_instrument_citation(citation_label)
        or _has_composite_handbook_citation(identity_text, official_url=safe)
    ):
        material = {"citation": citation, "title": title, "official_url": safe}
        return (
            f"composite-authority:{_sealed(material)[:32]}",
            ("COMPOSITE_AUTHORITY_IDENTITY_HOLD",),
        )
    url_identity: str | None = None
    if host in {"www.legislation.gov.uk", "legislation.gov.uk"}:
        try:
            _, parts = _legislation_identity_parts(parsed.path)
            url_identity = ":".join(parts)
        except ValueError as exc:
            reasons.append(str(exc))
    elif host == "caselaw.nationalarchives.gov.uk":
        url_identity = _tna_authority_identity(safe)
        if url_identity is None:
            reasons.append("TNA_AUTHORITY_IDENTITY_UNRESOLVED")

    citation_identity = neutral_citations[0] if neutral_citations else None
    if (
        url_identity
        and citation_identity
        and url_identity.casefold() != citation_identity.casefold()
    ):
        reasons.append("AUTHORITY_IDENTITY_URL_CITATION_CONFLICT")
        conflict_material = {
            "official_url": safe,
            "url_identity": url_identity,
            "citation_identity": citation_identity,
        }
        return (
            f"identity-conflict:{_sealed(conflict_material)[:32]}",
            tuple(sorted(set(reasons))),
        )
    if url_identity:
        return url_identity, tuple(sorted(set(reasons)))
    if citation_identity:
        return citation_identity, tuple(sorted(set(reasons)))
    return f"official-url:{_normalized_official_identity_url(safe)}", tuple(sorted(set(reasons)))


def _identity_comparison_key(value: str) -> str:
    neutral = _canonical_neutral_citation(value)
    if neutral:
        return neutral.casefold()
    normalized = unicodedata.normalize("NFKC", value).casefold()
    if value.startswith("official-url:"):
        return unicodedata.normalize("NFKC", value)
    # A ``made`` SI is a representation of the same instrument identity. The
    # bound candidate can legitimately contain that representation while a
    # research URL points at a revised point-in-time XML endpoint.
    if re.fullmatch(r"uksi:\d{4}:\d+:made", normalized):
        return normalized.removesuffix(":made")
    return normalized


def _state_label(value: Any) -> str:
    if value is True:
        return "TRUE"
    if value is False:
        return "FALSE"
    if value == "unknown" or value is None:
        return "UNKNOWN"
    return "INVALID"


def _combined_proposal_metadata_complete(value: Any) -> tuple[bool, tuple[str, ...]]:
    """Check the legacy explicitly-labelled combined legal-review field."""

    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item.strip() for item in value)
    ):
        return False, (
            "JURISDICTION_FINDING_MISSING",
            "CURRENTNESS_FINDING_MISSING",
            "LATER_TREATMENT_FINDING_MISSING",
        )
    joined = (
        " "
        + re.sub(
            r"[^a-z0-9]+",
            " ",
            unicodedata.normalize("NFKC", " ".join(value)).casefold(),
        ).strip()
        + " "
    )
    checks = {
        "JURISDICTION_FINDING_MISSING": (
            "jurisdiction",
            "england",
            "wales",
            "united kingdom",
            " uk ",
            "court of",
            "territorial",
            "extent",
        ),
        "CURRENTNESS_FINDING_MISSING": (
            "currentness",
            "current law",
            "source ceiling",
            "as of",
            "as at",
            "revised",
            "checked",
            "verified",
        ),
        "LATER_TREATMENT_FINDING_MISSING": (
            "later treatment",
            "subsequent treatment",
            "treatment hold",
            "not been owner adopted",
            "no comprehensive subsequent",
        ),
    }
    missing = tuple(
        code for code, terms in checks.items() if not any(term in joined for term in terms)
    )
    return not missing, missing


def proposal_metadata_completeness(authority: Mapping[str, Any]) -> dict[str, Any]:
    """Return deterministic metadata eligibility shared with the owner packet.

    The preferred contract uses three separately typed legal-review fields.
    The explicitly named legacy combined field remains accepted only when its
    text independently covers jurisdiction, currentness and later treatment.
    """

    locators = authority.get("exact_locators")
    locator_complete = (
        isinstance(locators, list)
        and bool(locators)
        and all(isinstance(item, str) and bool(item.strip()) for item in locators)
    )
    separate = {
        "jurisdiction": authority.get("jurisdiction"),
        "currentness": authority.get("currentness_finding"),
        "later_treatment": authority.get("later_treatment_finding"),
    }
    separate_complete = all(
        isinstance(item, str) and bool(item.strip()) for item in separate.values()
    )
    combined_complete, combined_missing = _combined_proposal_metadata_complete(
        authority.get("jurisdiction_currentness_later_treatment_caveats")
    )
    reason_codes: list[str] = []
    if not locator_complete:
        reason_codes.append("EXACT_LOCATORS_MISSING")
    if separate_complete:
        mode = "SEPARATE_FIELDS"
    elif combined_complete:
        mode = "COMBINED_EXPLICIT_FIELD"
    else:
        mode = "INCOMPLETE"
        for field, value in separate.items():
            if not isinstance(value, str) or not value.strip():
                reason_codes.append(f"{field.upper()}_FINDING_MISSING")
        reason_codes.extend(combined_missing)
    reasons = sorted(set(reason_codes))
    return {
        "status": "COMPLETE" if not reasons else "INCOMPLETE_HOLD",
        "metadata_mode": mode,
        "exact_locators_complete": locator_complete,
        "reason_codes": reasons,
    }


def proposal_identity_key(value: str) -> str:
    """Return the case-normalized identity key used by collector and packet."""

    return _identity_comparison_key(value).casefold()


def fetch_eligible_identity_keys(
    plans: Sequence[Mapping[str, Any]],
) -> tuple[str, ...]:
    """Return the exact canonical identities eligible for later collection."""

    keys = tuple(
        sorted(
            proposal_identity_key(str(plan["authority_identity_comparison_key"]))
            for plan in plans
            if plan.get("disposition") == "FETCH_ABSENT_FALSE_TRUE"
        )
    )
    if len(keys) != len(set(keys)):
        raise ValueError("phase2a_research_source_fetch_identity_collision")
    return keys


def fetch_eligible_identity_set_sha256(plans: Sequence[Mapping[str, Any]]) -> str:
    """Seal the exact fetch-eligible identity set for cross-component checks."""

    return _sealed(
        {
            "schema": "legalbot.v111.phase2a.fetch-eligible-identity-set.v1",
            "authority_identity_keys": list(fetch_eligible_identity_keys(plans)),
        }
    )


def _load_wave(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_research_source_wave_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_research_source_wave_must_be_object")
    return value


def _load_bound_wave(binding: ArtifactBinding) -> dict[str, Any]:
    _validate_digest(
        binding.content_sha256,
        error_code="phase2a_research_source_wave_content_digest_invalid",
    )
    _validate_digest(
        binding.file_sha256,
        error_code="phase2a_research_source_wave_file_digest_invalid",
    )
    wave = _load_wave(binding.path)
    if _file_sha256(binding.path) != binding.file_sha256:
        raise ValueError("phase2a_research_source_wave_file_digest_invalid")
    material = dict(wave)
    supplied = str(material.pop("artifact_content_sha256", ""))
    if supplied != binding.content_sha256 or _sealed(material) != supplied:
        raise ValueError("phase2a_research_source_wave_content_digest_invalid")
    return wave


def _load_canonical_wave_set(
    binding: ArtifactBinding,
    wave_bindings: Sequence[ArtifactBinding],
) -> dict[str, Any]:
    _validate_digest(
        binding.content_sha256,
        error_code="phase2a_research_source_canonical_set_content_digest_invalid",
    )
    _validate_digest(
        binding.file_sha256,
        error_code="phase2a_research_source_canonical_set_file_digest_invalid",
    )
    path = binding.path
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_research_source_canonical_set_must_be_regular_file")
    if _file_sha256(path) != binding.file_sha256:
        raise ValueError("phase2a_research_source_canonical_set_file_digest_invalid")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_research_source_canonical_set_must_be_object")
    material = dict(value)
    supplied = str(material.pop("artifact_content_sha256", ""))
    if supplied != binding.content_sha256 or _sealed(material) != supplied:
        raise ValueError("phase2a_research_source_canonical_set_content_digest_invalid")
    entries = value.get("waves")
    queue_binding = value.get("queue_binding")
    if (
        value.get("schema") != CANONICAL_WAVE_SET_SCHEMA
        or value.get("status") != "CANONICAL_32_WAVES_BOUND_NOT_AUTHORIZING"
        or value.get("source_queue_content_sha256") != wave_validator.EXPECTED_QUEUE_CONTENT_SHA256
        or value.get("exact_set_count") != EXPECTED_CANONICAL_WAVE_COUNT
        or value.get("wave_count") != EXPECTED_CANONICAL_WAVE_COUNT
        or value.get("total_row_count") != EXPECTED_WAVE_ROW_COUNT
        or not isinstance(entries, list)
        or len(entries) != EXPECTED_CANONICAL_WAVE_COUNT
        or not isinstance(queue_binding, Mapping)
        or value.get("advisory_only") is not True
        or any(value.get(field) is not False for field in _CANONICAL_SET_REQUIRED_FALSE_FLAGS)
    ):
        raise ValueError("phase2a_research_source_canonical_set_boundary_invalid")

    queue_material = dict(queue_binding)
    queue_record_seal = str(queue_material.pop("record_content_sha256", ""))
    queue_file_sha256 = str(queue_binding.get("file_sha256") or "")
    _validate_digest(
        queue_file_sha256,
        error_code="phase2a_research_source_canonical_set_queue_binding_invalid",
    )
    if (
        queue_record_seal != _sealed(queue_material)
        or queue_binding.get("file_name") != wave_validator.DEFAULT_QUEUE.name
        or queue_binding.get("row_count") != EXPECTED_WAVE_ROW_COUNT
        or queue_binding.get("content_sha256") != wave_validator.EXPECTED_QUEUE_CONTENT_SHA256
        or value.get("source_queue_file_sha256") != queue_file_sha256
    ):
        raise ValueError("phase2a_research_source_canonical_set_queue_binding_invalid")

    expected: set[tuple[str, str, str]] = set()
    names: list[str] = []
    total_record_count = 0
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise ValueError("phase2a_research_source_canonical_set_entry_invalid")
        file_name = str(entry.get("file_name") or "")
        content_sha256 = str(entry.get("content_sha256") or "")
        file_sha256 = str(entry.get("file_sha256") or "")
        if (
            Path(file_name).name != file_name
            or _CANONICAL_WAVE_FILE_NAME.fullmatch(file_name) is None
        ):
            raise ValueError("phase2a_research_source_canonical_set_filename_invalid")
        _validate_digest(
            content_sha256,
            error_code="phase2a_research_source_canonical_set_entry_digest_invalid",
        )
        _validate_digest(
            file_sha256,
            error_code="phase2a_research_source_canonical_set_entry_digest_invalid",
        )
        entry_material = dict(entry)
        entry_record_seal = str(entry_material.pop("record_content_sha256", ""))
        record_count = entry.get("record_count")
        if (
            entry_record_seal != _sealed(entry_material)
            or not isinstance(record_count, int)
            or isinstance(record_count, bool)
            or record_count < 0
        ):
            raise ValueError("phase2a_research_source_canonical_set_entry_invalid")
        total_record_count += record_count
        names.append(file_name)
        expected.add((file_name, content_sha256, file_sha256))
    if len(expected) != EXPECTED_CANONICAL_WAVE_COUNT or len(set(names)) != len(names):
        raise ValueError("phase2a_research_source_canonical_set_duplicate_entry")
    if set(names) & OBSOLETE_Q48_WAVES or CANONICAL_Q48_WAVE not in names:
        raise ValueError("phase2a_research_source_canonical_set_q48_revision_invalid")
    excluded = value.get("excluded_obsolete_wave_files")
    if (
        not isinstance(excluded, list)
        or any(not isinstance(item, str) or Path(item).name != item for item in excluded)
        or len(excluded) != len(set(excluded))
        or not OBSOLETE_Q48_WAVES.issubset(excluded)
        or set(names) & set(excluded)
        or total_record_count != EXPECTED_WAVE_ROW_COUNT
    ):
        raise ValueError("phase2a_research_source_canonical_set_exclusions_invalid")

    supplied_bindings = {
        (item.path.name, item.content_sha256, item.file_sha256) for item in wave_bindings
    }
    if supplied_bindings != expected or len(wave_bindings) != len(expected):
        raise ValueError("phase2a_research_source_wave_bindings_not_canonical_set")
    _assert_privacy_safe(value)
    return value


def _load_candidate(binding: ArtifactBinding) -> dict[str, Any]:
    _validate_digest(
        binding.content_sha256,
        error_code="phase2a_research_source_candidate_content_digest_invalid",
    )
    _validate_digest(
        binding.file_sha256,
        error_code="phase2a_research_source_candidate_file_digest_invalid",
    )
    path = binding.path
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_research_source_candidate_must_be_regular_file")
    if _file_sha256(path) != binding.file_sha256:
        raise ValueError("phase2a_research_source_candidate_file_digest_invalid")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_research_source_candidate_must_be_object")
    sources = value.get("sources")
    calculated = approved_source_manifest_sha256(value)
    if (
        calculated != binding.content_sha256
        or value.get("manifest_sha256") != calculated
        or not isinstance(sources, list)
        or len(sources) != EXPECTED_CANDIDATE_SOURCE_COUNT
        or value.get("source_count") != EXPECTED_CANDIDATE_SOURCE_COUNT
        or value.get("successor_must_remain_non_active") is not True
        or value.get("active_or_previous_write_authorized") is not False
        or value.get("answer_release_eligible") is not False
        or value.get("phase2b_authorized") is not False
    ):
        raise ValueError("phase2a_research_source_candidate_boundary_invalid")
    return value


def _authority_uses(
    named_waves: Sequence[tuple[str, Mapping[str, Any]]],
) -> tuple[dict[str, Any], ...]:
    uses: list[dict[str, Any]] = []
    for wave_name, wave in sorted(named_waves):
        for row in wave.get("records", []):
            row_id = str(row.get("row_id") or "")
            for component_ordinal, component in enumerate(
                row.get("atomic_components", []), start=1
            ):
                for authority_ordinal, authority in enumerate(
                    component.get("authorities", []), start=1
                ):
                    official_url = authority.get("official_url")
                    identity, identity_holds = _authority_identity(authority)
                    metadata = proposal_metadata_completeness(authority)
                    use = {
                        "authority_identity_id": identity,
                        "identity_hold_reason_codes": list(identity_holds),
                        "row_id": row_id,
                        "wave_file_name": wave_name,
                        "component_ordinal": component_ordinal,
                        "authority_ordinal": authority_ordinal,
                        "atomic_proposition": str(component.get("proposition") or ""),
                        "support_fit": str(component.get("support_fit") or ""),
                        "support_bearing": component.get("support_fit") in {"FULL", "PARTIAL"},
                        "proposal_metadata_completeness": metadata,
                        "title": str(authority.get("title") or ""),
                        "citation": str(authority.get("citation") or ""),
                        "official_url": (
                            _safe_url(str(official_url)) if official_url is not None else None
                        ),
                        "exact_locators": sorted(
                            {str(item) for item in authority.get("exact_locators") or []}
                        ),
                        "candidate_existing_state": _state_label(
                            authority.get("candidate_existing")
                        ),
                        "source_admission_required_state": _state_label(
                            authority.get("source_admission_required")
                        ),
                        "claimed_candidate_source_version_ids": sorted(
                            {
                                str(item)
                                for item in authority.get("candidate_source_version_ids") or []
                                if item
                            }
                        ),
                    }
                    _assert_privacy_safe(use)
                    uses.append(use)
    return tuple(uses)


def _candidate_sources_by_identity(
    candidate: Mapping[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    output: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for source in candidate.get("sources", []):
        identity = str(source.get("authority_identity_id") or "")
        if not identity:
            raise ValueError("phase2a_research_source_candidate_identity_missing")
        copied_source = {
            "authority_identity_id": identity,
            "source_version_id": str(source.get("source_version_id") or ""),
            "stable_identifier": str(source.get("stable_identifier") or ""),
            "content_sha256": str(source.get("content_sha256") or ""),
        }
        _assert_privacy_safe(copied_source)
        output[_identity_comparison_key(identity)].append(copied_source)
    for sources in output.values():
        sources.sort(key=lambda item: (item["source_version_id"], item["content_sha256"]))
    return dict(output)


def _representation_priority(value: str) -> tuple[int, str]:
    parsed = urlsplit(value)
    host = (parsed.hostname or "").casefold()
    if host == "caselaw.nationalarchives.gov.uk":
        priority = 0
    elif host in {"www.legislation.gov.uk", "legislation.gov.uk"}:
        priority = 1
    elif parsed.path.casefold().endswith(".pdf"):
        priority = 2
    elif host in {
        "www.supremecourt.uk",
        "supremecourt.uk",
        "www.jcpc.uk",
        "jcpc.uk",
    }:
        priority = 3
    else:
        priority = 4
    return priority, value


def _representation_targets(
    official_urls: Sequence[str],
) -> tuple[tuple[dict[str, Any], ...], tuple[str, ...]]:
    normalized_to_sources: dict[str, set[str]] = defaultdict(set)
    holds: set[str] = set()
    for official_url in official_urls:
        try:
            normalized = normalized_download_url(official_url)
            normalized_to_sources[normalized].add(official_url)
        except ValueError as exc:
            holds.add(str(exc))
    if holds:
        return (), tuple(sorted(holds))
    if not normalized_to_sources:
        return (), ("OFFICIAL_REPRESENTATION_URL_MISSING",)
    ordered = sorted(normalized_to_sources, key=_representation_priority)
    targets = tuple(
        {
            "representation_target_id": (
                "representation-target-" + _sha256(value.encode("utf-8"))[:24]
            ),
            "requested_url": value,
            "selection_rank": rank,
            "representation_role": (
                "PROPOSED_ADMISSION_REPRESENTATION"
                if rank == 1
                else "CORROBORATING_ALIAS_REPRESENTATION"
            ),
            "source_official_urls": sorted(normalized_to_sources[value]),
        }
        for rank, value in enumerate(ordered, start=1)
    )
    return targets, ()


def _choose_download_url(
    official_urls: Sequence[str],
) -> tuple[str | None, tuple[str, ...]]:
    """Compatibility helper returning the selected admission representation."""

    targets, holds = _representation_targets(official_urls)
    return (str(targets[0]["requested_url"]) if targets else None), holds


def _plan_authorities(
    named_waves: Sequence[tuple[str, Mapping[str, Any]]],
    candidate: Mapping[str, Any],
) -> tuple[dict[str, Any], ...]:
    """Return one sealed plan per canonical authority identity."""

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    display_identity: dict[str, str] = {}
    for use in _authority_uses(named_waves):
        key = _identity_comparison_key(str(use["authority_identity_id"]))
        grouped[key].append(use)
        display_identity.setdefault(key, str(use["authority_identity_id"]))
    candidate_by_identity = _candidate_sources_by_identity(candidate)

    plans: list[dict[str, Any]] = []
    for comparison_key, uses in sorted(grouped.items()):
        uses.sort(
            key=lambda item: (
                item["row_id"],
                item["wave_file_name"],
                item["component_ordinal"],
                item["authority_ordinal"],
            )
        )
        candidate_sources = candidate_by_identity.get(comparison_key, [])
        candidate_present = bool(candidate_sources)
        identity = (
            sorted(
                {item["authority_identity_id"] for item in candidate_sources},
                key=lambda item: (item.casefold(), item),
            )[0]
            if candidate_present
            else display_identity[comparison_key]
        )
        candidate_states = sorted({item["candidate_existing_state"] for item in uses})
        admission_states = sorted({item["source_admission_required_state"] for item in uses})
        state_pairs = {
            (
                item["candidate_existing_state"],
                item["source_admission_required_state"],
            )
            for item in uses
        }
        holds = {reason for item in uses for reason in item["identity_hold_reason_codes"]}
        if any("UNKNOWN" in pair or "INVALID" in pair for pair in state_pairs):
            holds.add("WAVE_SOURCE_MEMBERSHIP_OR_ADMISSION_UNKNOWN")
        if len(state_pairs) != 1:
            holds.add("WAVE_SOURCE_MEMBERSHIP_OR_ADMISSION_CONTRADICTION")
        expected_pair = ("TRUE", "FALSE") if candidate_present else ("FALSE", "TRUE")
        if state_pairs != {expected_pair}:
            holds.add(
                "WAVE_CLAIM_CONTRADICTS_BOUND_CANDIDATE"
                if len(state_pairs) == 1
                else "WAVE_STATE_NOT_FETCH_ELIGIBLE"
            )
        support_bearing_uses = [item for item in uses if item["support_bearing"]]
        metadata_complete_support_bearing_uses = [
            item
            for item in support_bearing_uses
            if item["proposal_metadata_completeness"]["status"] == "COMPLETE"
        ]
        metadata_incomplete_reason_codes = sorted(
            {
                reason
                for item in support_bearing_uses
                for reason in item["proposal_metadata_completeness"]["reason_codes"]
            }
        )
        if (
            not candidate_present
            and state_pairs == {("FALSE", "TRUE")}
            and not metadata_complete_support_bearing_uses
        ):
            holds.add("METADATA_INCOMPLETE")

        actual_source_version_ids = {item["source_version_id"] for item in candidate_sources}
        claimed_ids = {
            source_version_id
            for use in uses
            for source_version_id in use["claimed_candidate_source_version_ids"]
        }
        if candidate_present:
            if any(not use["claimed_candidate_source_version_ids"] for use in uses):
                holds.add("CANDIDATE_SOURCE_VERSION_BINDING_MISSING")
            if claimed_ids - actual_source_version_ids:
                holds.add("CANDIDATE_SOURCE_VERSION_BINDING_CONTRADICTS_MANIFEST")
        elif claimed_ids:
            holds.add("NON_CANDIDATE_SOURCE_HAS_CANDIDATE_VERSION_BINDING")

        official_urls = sorted({str(item["official_url"]) for item in uses if item["official_url"]})
        download_url: str | None = None
        representation_targets: tuple[dict[str, Any], ...] = ()
        if not candidate_present and not holds and state_pairs == {("FALSE", "TRUE")}:
            representation_targets, normalization_holds = _representation_targets(official_urls)
            holds.update(normalization_holds)
            if representation_targets:
                download_url = str(representation_targets[0]["requested_url"])

        if holds:
            disposition = "HOLD_NO_FETCH"
            download_url = None
            representation_targets = ()
        elif candidate_present:
            disposition = "CANDIDATE_PRESENT_NO_FETCH"
        else:
            disposition = "FETCH_ABSENT_FALSE_TRUE"

        material = {
            "plan_id": f"authority-plan-{_sha256(comparison_key.encode())[:24]}",
            "authority_identity_id": identity,
            "authority_identity_comparison_key": comparison_key,
            "disposition": disposition,
            "hold_reason_codes": sorted(holds),
            "candidate_present_in_bound_manifest": candidate_present,
            "candidate_existing_states": candidate_states,
            "source_admission_required_states": admission_states,
            "support_bearing_use_count": len(support_bearing_uses),
            "metadata_complete_support_bearing_use_count": len(
                metadata_complete_support_bearing_uses
            ),
            "metadata_incomplete_reason_codes": metadata_incomplete_reason_codes,
            "bound_candidate_sources": candidate_sources,
            "download_url": download_url,
            "representation_targets": list(representation_targets),
            "official_urls": official_urls,
            "titles": sorted({item["title"] for item in uses if item["title"]}),
            "citations": sorted({item["citation"] for item in uses if item["citation"]}),
            "exact_locators": sorted(
                {locator for item in uses for locator in item["exact_locators"]}
            ),
            "affected_row_ids": sorted({item["row_id"] for item in uses}),
            "row_uses": uses,
            "owner_decision_applied": False,
            "source_admission_authorized": False,
            "source_admitted": False,
            "candidate_mutated": False,
            "automatic_indexing": False,
            "automatic_embedding": False,
        }
        _assert_privacy_safe(material)
        plans.append({**material, "plan_content_sha256": _sealed(material)})
    return tuple(plans)


def build_targets(wave_paths: Sequence[Path]) -> tuple[dict[str, Any], ...]:
    """Build identity-aware unbound targets for diagnostics and unit tests."""

    named_waves = [(path.name, _load_wave(path)) for path in sorted(wave_paths)]
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for use in _authority_uses(named_waves):
        grouped[_identity_comparison_key(use["authority_identity_id"])].append(use)
    targets: list[dict[str, Any]] = []
    for _, uses in sorted(grouped.items()):
        official_urls = sorted({str(item["official_url"]) for item in uses if item["official_url"]})
        download_url, holds = _choose_download_url(official_urls)
        identity_holds = {reason for item in uses for reason in item["identity_hold_reason_codes"]}
        identity_holds.update(holds)
        targets.append(
            {
                "authority_identity_id": uses[0]["authority_identity_id"],
                "download_url": download_url,
                "official_urls": official_urls,
                "citations": sorted({item["citation"] for item in uses if item["citation"]}),
                "row_ids": sorted({item["row_id"] for item in uses}),
                "wave_files": sorted({item["wave_file_name"] for item in uses}),
                "candidate_existing_states": sorted(
                    {item["candidate_existing_state"] for item in uses}
                ),
                "source_admission_states": sorted(
                    {item["source_admission_required_state"] for item in uses}
                ),
                "exact_locators": sorted(
                    {locator for item in uses for locator in item["exact_locators"]}
                ),
                "hold_reason_codes": sorted(identity_holds),
            }
        )
    return tuple(targets)


def _fetch(client: httpx.Client, value: str) -> tuple[str, int, str, bytes]:
    current = _safe_url(value)
    for _ in range(MAX_REDIRECTS + 1):
        with client.stream("GET", current) as response:
            status = int(response.status_code)
            if status in {301, 302, 303, 307, 308}:
                location = response.headers.get("location")
                if not location:
                    raise ValueError("phase2a_research_source_redirect_missing")
                current = _safe_url(urljoin(current, location))
                continue
            content_type = (
                str(response.headers.get("content-type") or "").split(";", 1)[0].casefold()
            )
            if status != 200:
                return current, status, content_type, b""
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_bytes():
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    raise ValueError("phase2a_research_source_response_too_large")
                chunks.append(chunk)
            raw = b"".join(chunks)
            if not raw:
                raise ValueError("phase2a_research_source_response_empty")
            return current, status, content_type, raw
    raise ValueError("phase2a_research_source_redirect_limit")


def _official_judgment_pdf_url(raw: bytes, *, landing_url: str) -> str:
    parser = _JudgmentLinkParser()
    parser.feed(raw.decode("utf-8", errors="replace"))
    urls = sorted({_safe_url(urljoin(landing_url, href)) for href in parser.hrefs})
    if len(urls) != 1:
        raise ValueError("phase2a_research_source_judgment_pdf_link_invalid")
    return urls[0]


def _canonical_content(
    raw: bytes, *, content_type: str
) -> tuple[str | None, str | None, tuple[str, ...]]:
    if content_type not in _XML_CONTENT_TYPES:
        return None, "RAW_BYTES_ONLY_MEDIA_TYPE_NOT_CANONICALIZED", ()
    if _XML_FORBIDDEN.search(raw):
        return None, None, ("XML_UNSAFE_DECLARATION",)
    try:
        ET.fromstring(raw)
        canonical = ET.canonicalize(
            raw.decode("utf-8"), with_comments=False, strip_text=False
        ).encode("utf-8")
    except (ET.ParseError, UnicodeError, ValueError):
        return None, None, ("XML_CANONICALIZATION_FAILED",)
    return _sha256(canonical), "W3C_C14N_2_0_NO_COMMENTS", ()


def _suffix(content_type: str, final_url: str) -> str:
    if content_type == "application/pdf" or final_url.casefold().endswith(".pdf"):
        return ".pdf"
    if content_type in _XML_CONTENT_TYPES or final_url.casefold().endswith(".xml"):
        return ".xml"
    if content_type in {"text/html", "application/xhtml+xml"}:
        return ".html"
    if content_type == "text/plain":
        return ".txt"
    return ".bin"


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


def _collect_plan(
    client: httpx.Client,
    plan: Mapping[str, Any],
    *,
    ordinal: int,
    staging_root: Path,
    representation_target: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    target = representation_target or {
        "representation_target_id": (
            "representation-target-" + _sha256(str(plan["download_url"]).encode("utf-8"))[:24]
        ),
        "requested_url": plan["download_url"],
        "selection_rank": 1,
        "representation_role": "PROPOSED_ADMISSION_REPRESENTATION",
        "source_official_urls": plan["official_urls"],
    }
    requested_url = _safe_url(str(target["requested_url"]))
    representation_role = str(target["representation_role"])
    selected_for_proposed_admission = representation_role == "PROPOSED_ADMISSION_REPRESENTATION"
    started = datetime.now(UTC)
    landing_page_url: str | None = None
    hold_reason_codes: list[str] = []
    try:
        final_url, status, content_type, raw = _fetch(client, requested_url)
        requested_host = (urlsplit(requested_url).hostname or "").casefold()
        resolved_judgment_pdf = False
        if (
            status == 200
            and requested_host
            in {"www.supremecourt.uk", "supremecourt.uk", "www.jcpc.uk", "jcpc.uk"}
            and "/cases/" in urlsplit(requested_url).path
            and content_type in {"text/html", "application/xhtml+xml"}
        ):
            landing_page_url = final_url
            judgment_url = _official_judgment_pdf_url(raw, landing_url=final_url)
            final_url, status, content_type, raw = _fetch(client, judgment_url)
            resolved_judgment_pdf = True

        direct_xml_expected = urlsplit(requested_url).path.casefold().endswith("/data.xml")
        direct_pdf_expected = (
            urlsplit(requested_url).path.casefold().endswith(".pdf") or resolved_judgment_pdf
        )
        if status != 200:
            result = "OFFICIAL_SOURCE_UNAVAILABLE_HELD"
            error_code = f"http_{status}"
            hold_reason_codes.append("OFFICIAL_REPRESENTATION_UNAVAILABLE")
            raw_sha256 = None
            canonical_sha256 = None
            canonicalization = None
            member = None
            proposed_source_version_id = None
        elif direct_xml_expected and content_type not in _XML_CONTENT_TYPES:
            result = "REPRESENTATION_TYPE_MISMATCH_HELD"
            error_code = "expected_xml_content_type"
            hold_reason_codes.append("OFFICIAL_XML_REPRESENTATION_TYPE_MISMATCH")
            raw_sha256 = _sha256(raw)
            canonical_sha256 = None
            canonicalization = None
            member = None
            proposed_source_version_id = None
        elif direct_pdf_expected and (
            content_type not in {"application/octet-stream", "application/pdf"}
            or not raw.startswith(b"%PDF-")
        ):
            result = "REPRESENTATION_TYPE_MISMATCH_HELD"
            error_code = "expected_pdf_representation"
            hold_reason_codes.append("OFFICIAL_PDF_REPRESENTATION_TYPE_MISMATCH")
            raw_sha256 = _sha256(raw)
            canonical_sha256 = None
            canonicalization = None
            member = None
            proposed_source_version_id = None
        elif content_type not in _SAFE_CONTENT_TYPES:
            result = "UNSUPPORTED_REPRESENTATION_HELD"
            error_code = "unsupported_content_type"
            hold_reason_codes.append("OFFICIAL_REPRESENTATION_CONTENT_TYPE_UNSUPPORTED")
            raw_sha256 = _sha256(raw)
            canonical_sha256 = None
            canonicalization = None
            member = None
            proposed_source_version_id = None
        else:
            raw_sha256 = _sha256(raw)
            canonical_sha256, canonicalization, canonical_holds = _canonical_content(
                raw, content_type=content_type
            )
            hold_reason_codes.extend(canonical_holds)
            member = (
                f"official-representation-{ordinal:04d}-{raw_sha256[:20]}"
                f"{_suffix(content_type, final_url)}"
            )
            _write_exclusive(staging_root / member, raw)
            if canonical_holds:
                result = "QUARANTINED_CANONICALIZATION_HELD"
                error_code = "canonicalization_failed"
                proposed_source_version_id = None
            elif selected_for_proposed_admission:
                result = "DOWNLOADED_QUARANTINED_BOUND"
                error_code = None
                version_material = {
                    "authority_identity_id": plan["authority_identity_id"],
                    "raw_sha256": raw_sha256,
                    "canonical_content_sha256": canonical_sha256,
                }
                proposed_source_version_id = (
                    "proposed-source-version-" + _sealed(version_material)[:40]
                )
            else:
                result = "DOWNLOADED_QUARANTINED_BOUND"
                error_code = None
                proposed_source_version_id = None
    except Exception as exc:
        final_url = requested_url
        status = 0
        content_type = ""
        raw = b""
        raw_sha256 = None
        canonical_sha256 = None
        canonicalization = None
        member = None
        proposed_source_version_id = None
        result = "COLLECTION_FAILED_HELD"
        error_code = re.sub(r"(?<!^)(?=[A-Z])", "_", type(exc).__name__).casefold()
        hold_reason_codes.append("OFFICIAL_REPRESENTATION_COLLECTION_FAILED")

    material = {
        "record_id": (
            "quarantine-binding-"
            + _sha256(f"{plan['plan_id']}\n{target['representation_target_id']}".encode())[:24]
        ),
        "ordinal": ordinal,
        "authority_plan_id": plan["plan_id"],
        "authority_plan_content_sha256": plan["plan_content_sha256"],
        "authority_identity_id": plan["authority_identity_id"],
        "representation_target_id": target["representation_target_id"],
        "representation_selection_rank": target["selection_rank"],
        "representation_role": representation_role,
        "selected_for_proposed_admission": selected_for_proposed_admission,
        "source_official_urls": target["source_official_urls"],
        "requested_url": requested_url,
        "landing_page_url": landing_page_url,
        "final_url": final_url,
        "http_status": status,
        "content_type": content_type,
        "retrieved_at": started.isoformat(timespec="seconds"),
        "result": result,
        "error_code": error_code,
        "hold_reason_codes": sorted(set(hold_reason_codes)),
        "quarantine_member": member,
        "raw_sha256": raw_sha256,
        "canonical_content_sha256": canonical_sha256,
        "canonicalization_algorithm": canonicalization,
        "bytes": len(raw),
        "proposed_source_version_id": proposed_source_version_id,
        "official_urls": plan["official_urls"],
        "citations": plan["citations"],
        "titles": plan["titles"],
        "exact_locators": plan["exact_locators"],
        "affected_row_ids": plan["affected_row_ids"],
        "row_uses": plan["row_uses"],
        "owner_decision_applied": False,
        "source_admission_authorized": False,
        "source_admitted": False,
        "catalogue_mutated": False,
        "candidate_mutated": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
    }
    _assert_privacy_safe(material)
    return {**material, "record_content_sha256": _sealed(material)}


def _transactional_staging_root(destination: Path) -> Path:
    parent = destination.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError("phase2a_research_source_quarantine_parent_invalid")
    if destination.exists() or destination.is_symlink():
        raise ValueError("phase2a_research_source_quarantine_exists")
    staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=parent))
    staging.chmod(0o700)
    if stat.S_IMODE(staging.stat().st_mode) != 0o700:
        raise ValueError("phase2a_research_source_quarantine_mode_invalid")
    return staging


def _commit_create_only(staging_root: Path, destination: Path) -> None:
    """Atomically publish a staging directory under an exclusive writer lock."""

    lock_path = destination.parent / f".{destination.name}.create.lock"
    lock_descriptor = os.open(
        lock_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        if destination.exists() or destination.is_symlink():
            raise ValueError("phase2a_research_source_quarantine_exists")
        os.rename(staging_root, destination)
    finally:
        os.close(lock_descriptor)
        # A stale private lock is safer than turning an already-committed
        # package into an ambiguous failure.
        with contextlib.suppress(OSError):
            lock_path.unlink(missing_ok=True)


def collect(
    *,
    queue_path: Path,
    wave_bindings: Sequence[ArtifactBinding],
    candidate_binding: ArtifactBinding,
    canonical_set_binding: ArtifactBinding,
    quarantine_root: Path,
    run_id: str,
) -> dict[str, Any]:
    """Create one private transactional quarantine binding package."""

    if _SAFE_RUN_ID.fullmatch(run_id) is None:
        raise ValueError("phase2a_research_source_run_id_invalid")
    if not wave_bindings:
        raise ValueError("phase2a_research_source_explicit_wave_bindings_required")
    names = [binding.path.name for binding in wave_bindings]
    resolved_paths = [binding.path.resolve() for binding in wave_bindings]
    if len(set(names)) != len(names) or len(set(resolved_paths)) != len(resolved_paths):
        raise ValueError("phase2a_research_source_duplicate_wave_binding")
    ordered_wave_bindings = tuple(
        sorted(wave_bindings, key=lambda binding: (binding.path.name, str(binding.path)))
    )
    canonical_wave_set = _load_canonical_wave_set(canonical_set_binding, ordered_wave_bindings)
    canonical_queue_binding = canonical_wave_set["queue_binding"]
    if (
        queue_path.is_symlink()
        or not queue_path.is_file()
        or queue_path.name != canonical_queue_binding["file_name"]
        or _file_sha256(queue_path) != canonical_queue_binding["file_sha256"]
    ):
        raise ValueError("phase2a_research_source_queue_not_canonical_set_binding")

    named_waves = [
        (binding.path.name, _load_bound_wave(binding)) for binding in ordered_wave_bindings
    ]
    canonical_entries = {str(entry["file_name"]): entry for entry in canonical_wave_set["waves"]}
    if any(
        len(wave.get("records", [])) != canonical_entries[binding.path.name]["record_count"]
        for binding, (_, wave) in zip(ordered_wave_bindings, named_waves, strict=True)
    ):
        raise ValueError("phase2a_research_source_wave_record_count_not_canonical_set")
    validation = wave_validator.validate_waves(
        queue_path=queue_path,
        wave_paths=[binding.path for binding in ordered_wave_bindings],
    )
    if (
        validation.get("status") != "PASS_COMPLETE"
        or validation.get("covered_row_count") != EXPECTED_WAVE_ROW_COUNT
        or validation.get("missing_row_count") != 0
    ):
        raise ValueError("phase2a_research_source_wave_coverage_not_exact_complete_316")
    candidate = _load_candidate(candidate_binding)
    plans = _plan_authorities(named_waves, candidate)
    fetch_plans = [plan for plan in plans if plan["disposition"] == "FETCH_ABSENT_FALSE_TRUE"]
    fetch_identity_keys = fetch_eligible_identity_keys(plans)
    fetch_identity_set_sha256 = fetch_eligible_identity_set_sha256(plans)
    fetch_representation_targets = [
        (plan, target) for plan in fetch_plans for target in plan.get("representation_targets", [])
    ]
    if any(not plan.get("representation_targets") for plan in fetch_plans):
        raise ValueError("phase2a_research_source_fetch_plan_has_no_representation")
    identity_holds = [plan for plan in plans if plan["disposition"] == "HOLD_NO_FETCH"]
    candidate_present = [
        plan for plan in plans if plan["disposition"] == "CANDIDATE_PRESENT_NO_FETCH"
    ]

    staging_root = _transactional_staging_root(quarantine_root)
    try:
        records: list[dict[str, Any]] = []
        with httpx.Client(
            follow_redirects=False,
            timeout=httpx.Timeout(30.0, connect=10.0),
            headers={
                "User-Agent": USER_AGENT,
                "Accept": (
                    "application/xml,text/xml,text/html,application/xhtml+xml,"
                    "application/pdf,text/plain"
                ),
            },
            trust_env=False,
        ) as client:
            for ordinal, (plan, target) in enumerate(fetch_representation_targets, start=1):
                records.append(
                    _collect_plan(
                        client,
                        plan,
                        ordinal=ordinal,
                        staging_root=staging_root,
                        representation_target=target,
                    )
                )

        records_by_identity: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for record in records:
            records_by_identity[str(record["authority_identity_id"])].append(record)
        failed_authority_identity_ids = {
            identity
            for identity, identity_records in records_by_identity.items()
            if any(
                record["result"] != "DOWNLOADED_QUARANTINED_BOUND" for record in identity_records
            )
        }

        representation_bindings = [
            {
                "record_id": record["record_id"],
                "record_content_sha256": record["record_content_sha256"],
                "authority_identity_id": record["authority_identity_id"],
                "representation_role": record["representation_role"],
                "selected_for_proposed_admission": record["selected_for_proposed_admission"],
                "authority_representation_set_complete": (
                    record["authority_identity_id"] not in failed_authority_identity_ids
                ),
                "eligible_for_owner_packet": (
                    record["selected_for_proposed_admission"]
                    and record["authority_identity_id"] not in failed_authority_identity_ids
                ),
                "raw_sha256": record["raw_sha256"],
                "canonical_content_sha256": record["canonical_content_sha256"],
                "content_type": record["content_type"],
                "bytes": record["bytes"],
                "final_url": record["final_url"],
                "quarantine_member": record["quarantine_member"],
                "proposed_source_version_id": record["proposed_source_version_id"],
                "exact_locators": record["exact_locators"],
                "affected_row_ids": record["affected_row_ids"],
            }
            for record in records
            if record["result"] == "DOWNLOADED_QUARANTINED_BOUND"
        ]
        selected_admission_bindings = [
            item for item in representation_bindings if item["eligible_for_owner_packet"]
        ]
        held_selected_bindings = [
            item
            for item in representation_bindings
            if item["selected_for_proposed_admission"]
            and item["authority_identity_id"] in failed_authority_identity_ids
        ]
        corroborating_alias_bindings = [
            item for item in representation_bindings if not item["selected_for_proposed_admission"]
        ]
        representation_comparisons: list[dict[str, Any]] = []
        for identity, identity_records in sorted(records_by_identity.items()):
            selected = next(
                (
                    record
                    for record in identity_records
                    if record["selected_for_proposed_admission"]
                ),
                None,
            )
            for alias in identity_records:
                if alias["selected_for_proposed_admission"]:
                    continue
                material = {
                    "authority_identity_id": identity,
                    "selected_record_id": selected["record_id"] if selected else None,
                    "corroborating_record_id": alias["record_id"],
                    "raw_sha256_equal": (
                        selected["raw_sha256"] == alias["raw_sha256"]
                        if selected and selected["raw_sha256"] and alias["raw_sha256"]
                        else None
                    ),
                    "canonical_content_sha256_equal": (
                        selected["canonical_content_sha256"] == alias["canonical_content_sha256"]
                        if selected
                        and selected["canonical_content_sha256"]
                        and alias["canonical_content_sha256"]
                        else None
                    ),
                    "representation_equivalence_assumed": False,
                    "corroborating_alias_selected_for_admission": False,
                }
                representation_comparisons.append(
                    {**material, "comparison_content_sha256": _sealed(material)}
                )
        record_collection_holds = [
            {
                "hold_type": "REPRESENTATION_COLLECTION_HOLD",
                "record_id": record["record_id"],
                "record_content_sha256": record["record_content_sha256"],
                "authority_identity_id": record["authority_identity_id"],
                "hold_reason_codes": record["hold_reason_codes"],
                "owner_decision_applied": False,
                "source_admission_authorized": False,
                "source_admitted": False,
                "candidate_mutated": False,
            }
            for record in records
            if record["hold_reason_codes"]
        ]
        authority_collection_holds: list[dict[str, Any]] = []
        for identity in sorted(failed_authority_identity_ids):
            identity_records = records_by_identity[identity]
            selected = next(
                (
                    record
                    for record in identity_records
                    if record["selected_for_proposed_admission"]
                ),
                None,
            )
            failed_records = [
                record
                for record in identity_records
                if record["result"] != "DOWNLOADED_QUARANTINED_BOUND"
            ]
            material = {
                "hold_type": "AUTHORITY_REPRESENTATION_SET_INCOMPLETE",
                "authority_identity_id": identity,
                "selected_record_id": selected["record_id"] if selected else None,
                "selected_record_content_sha256": (
                    selected["record_content_sha256"] if selected else None
                ),
                "selected_proposed_source_version_id": (
                    selected["proposed_source_version_id"] if selected else None
                ),
                "failed_record_ids": sorted(record["record_id"] for record in failed_records),
                "failed_record_content_sha256s": sorted(
                    record["record_content_sha256"] for record in failed_records
                ),
                "hold_reason_codes": ["AUTHORITY_REPRESENTATION_SET_INCOMPLETE"],
                "selected_binding_eligible": False,
                "owner_decision_applied": False,
                "source_admission_authorized": False,
                "source_admitted": False,
                "candidate_mutated": False,
            }
            authority_collection_holds.append(
                {**material, "hold_content_sha256": _sealed(material)}
            )
        collection_holds = [*record_collection_holds, *authority_collection_holds]
        manifest_material: dict[str, Any] = {
            "schema": "legalbot.v111.phase2a.research-wave-quarantine-binding.v2",
            "status": "QUARANTINE_BINDINGS_CREATED_NOT_ADMITTED",
            "run_id": run_id,
            "source_ceiling_date": TARGET_DATE.isoformat(),
            "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "queue_binding": {
                "file_name": queue_path.name,
                "content_sha256": wave_validator.EXPECTED_QUEUE_CONTENT_SHA256,
                "file_sha256": _file_sha256(queue_path),
                "row_count": EXPECTED_WAVE_ROW_COUNT,
            },
            "wave_validation": {
                "status": validation["status"],
                "covered_row_count": validation["covered_row_count"],
                "missing_row_count": validation["missing_row_count"],
            },
            "canonical_wave_set_binding": {
                "file_name": canonical_set_binding.path.name,
                "content_sha256": canonical_set_binding.content_sha256,
                "file_sha256": canonical_set_binding.file_sha256,
                "wave_count": canonical_wave_set["wave_count"],
            },
            "wave_bindings": [
                {
                    "file_name": binding.path.name,
                    "content_sha256": binding.content_sha256,
                    "file_sha256": binding.file_sha256,
                    "record_count": len(wave.get("records", [])),
                }
                for binding, (_, wave) in zip(ordered_wave_bindings, named_waves, strict=True)
            ],
            "candidate_binding": {
                "file_name": candidate_binding.path.name,
                "content_sha256": candidate_binding.content_sha256,
                "file_sha256": candidate_binding.file_sha256,
                "source_count": EXPECTED_CANDIDATE_SOURCE_COUNT,
            },
            "allowlisted_hosts": sorted(ALLOWED_HOSTS),
            "quarantine_root_name": quarantine_root.name,
            "authority_identity_count": len(plans),
            "fetch_authority_count": len(fetch_plans),
            "fetch_eligible_identity_count": len(fetch_identity_keys),
            "fetch_eligible_identity_set_sha256": fetch_identity_set_sha256,
            "fetch_target_count": len(fetch_representation_targets),
            "candidate_present_no_fetch_count": len(candidate_present),
            "preflight_hold_count": len(identity_holds),
            "collection_record_count": len(records),
            "collection_hold_count": len(collection_holds),
            "held_selected_binding_count": len(held_selected_bindings),
            "result_counts": dict(sorted(Counter(record["result"] for record in records).items())),
            "authority_plans": list(plans),
            "records": records,
            "representation_bindings": representation_bindings,
            "selected_admission_bindings": selected_admission_bindings,
            "held_selected_bindings": held_selected_bindings,
            "corroborating_alias_bindings": corroborating_alias_bindings,
            "representation_comparisons": representation_comparisons,
            "preflight_holds": [
                {
                    "plan_id": plan["plan_id"],
                    "plan_content_sha256": plan["plan_content_sha256"],
                    "authority_identity_id": plan["authority_identity_id"],
                    "affected_row_ids": plan["affected_row_ids"],
                    "hold_reason_codes": plan["hold_reason_codes"],
                }
                for plan in identity_holds
            ],
            "collection_holds": collection_holds,
            "authority_collection_holds": authority_collection_holds,
            "packet_builder_interface": {
                "schema": "legalbot.v111.phase2a.quarantine-to-owner-packet.v1",
                "manifest_digest_field": "manifest_content_sha256",
                "record_digest_field": "record_content_sha256",
                "eligible_representation_record_ids": [
                    item["record_id"] for item in selected_admission_bindings
                ],
                "selected_admission_record_ids": [
                    item["record_id"] for item in selected_admission_bindings
                ],
                "held_selected_record_ids": [item["record_id"] for item in held_selected_bindings],
                "corroborating_alias_record_ids": [
                    item["record_id"] for item in corroborating_alias_bindings
                ],
                "held_authority_identity_ids": sorted(
                    {item["authority_identity_id"] for item in [*identity_holds, *collection_holds]}
                ),
                "fetch_eligible_authority_identity_keys": list(fetch_identity_keys),
                "fetch_eligible_authority_identity_set_sha256": (fetch_identity_set_sha256),
                "candidate_existing_authority_identity_ids": sorted(
                    {item["authority_identity_id"] for item in candidate_present}
                ),
                "owner_must_adopt_exact_packet_before_admission": True,
                "owner_decisions_applied": False,
                "source_admission_authorized": False,
                "source_admitted": False,
                "candidate_mutated": False,
            },
            "advisory_only": True,
            "owner_decisions_applied": False,
            "source_admission_authorized": False,
            "source_admitted": False,
            "catalogue_mutated": False,
            "source_scan_run": False,
            "candidate_mutated": False,
            "index_built": False,
            "automatic_indexing": False,
            "embedding_run": False,
            "automatic_embedding": False,
            "technical_qualification_assigned": False,
            "promotion_authorized": False,
            "active_pointer_write_authorized": False,
            "previous_pointer_write_authorized": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
            "validation30_authorized": False,
            "live_activation_authorized": False,
            "training_export_authorized": False,
        }
        _assert_privacy_safe(manifest_material)
        manifest = {
            **manifest_material,
            "manifest_content_sha256": _sealed(manifest_material),
        }
        _write_exclusive(staging_root / "QUARANTINE-MANIFEST.json", _canonical_json(manifest))
        _commit_create_only(staging_root, quarantine_root)
        return manifest
    except BaseException:
        shutil.rmtree(staging_root, ignore_errors=True)
        raise


def _parse_binding(values: Sequence[str]) -> ArtifactBinding:
    if len(values) != 3:
        raise ValueError("phase2a_research_source_binding_argument_invalid")
    return ArtifactBinding(
        path=Path(values[0]).resolve(strict=True),
        content_sha256=values[1],
        file_sha256=values[2],
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", type=Path, default=wave_validator.DEFAULT_QUEUE)
    parser.add_argument(
        "--wave-binding",
        action="append",
        nargs=3,
        required=True,
        metavar=("PATH", "CONTENT_SHA256", "FILE_SHA256"),
    )
    parser.add_argument("--candidate-manifest", type=Path, required=True)
    parser.add_argument("--candidate-content-sha256", required=True)
    parser.add_argument("--candidate-file-sha256", required=True)
    parser.add_argument(
        "--canonical-set-binding",
        nargs=3,
        required=True,
        metavar=("PATH", "CONTENT_SHA256", "FILE_SHA256"),
    )
    parser.add_argument("--quarantine-root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args(argv)
    result = collect(
        queue_path=args.queue.resolve(strict=True),
        wave_bindings=[_parse_binding(values) for values in args.wave_binding],
        candidate_binding=ArtifactBinding(
            path=args.candidate_manifest.resolve(strict=True),
            content_sha256=args.candidate_content_sha256,
            file_sha256=args.candidate_file_sha256,
        ),
        canonical_set_binding=_parse_binding(args.canonical_set_binding),
        quarantine_root=args.quarantine_root.resolve(),
        run_id=args.run_id,
    )
    print(
        json.dumps(
            {
                "status": result["status"],
                "fetch_target_count": result["fetch_target_count"],
                "bound_representation_count": len(result["representation_bindings"]),
                "preflight_hold_count": result["preflight_hold_count"],
                "collection_hold_count": len(result["collection_holds"]),
                "manifest_content_sha256": result["manifest_content_sha256"],
                "source_admitted": False,
                "candidate_mutated": False,
                "embedding_run": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
