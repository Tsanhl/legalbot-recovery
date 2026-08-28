"""Candidate-derived routing for explicit statutory references.

The resolver uses only the sealed approved-source manifest.  It does not know
benchmark case IDs, expected answers, gold spans or locator allowlists.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .source_manifest import (
    FAMILY_LEGISLATION,
    MANIFEST_SCHEMA,
    approved_source_manifest_sha256,
    source_family,
)

EXPLICIT_REFERENCE_VERSION = "candidate-manifest-legislation-title-section-v1"
_SECTION = re.compile(
    r"\b(?:s(?:ection)?\.?)\s*([0-9]+[A-Za-z]*)(\s*(?:\([0-9A-Za-z]+\)\s*)*)",
    flags=re.IGNORECASE,
)
_CANONICAL_SECTION = re.compile(
    r"(?:s(?:ection)?\.?)\s*([0-9]+[A-Za-z]*)"
    r"(\s*(?:\([0-9A-Za-z]+\)\s*)*)"
    r"(?:\s+(?:chapeau|final proviso|current positive text|concluding application words))?",
    flags=re.IGNORECASE,
)
_NON_ALNUM = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True, slots=True)
class ExplicitLegislationReference:
    """One unambiguous title and section resolved from a sealed candidate."""

    source_identity: str
    title: str
    locator: str
    source_chunk_count: int
    manifest_sha256: str


class CandidateLegislationReferenceResolver:
    """Resolve explicit statute-title/section queries without benchmark knowledge."""

    def __init__(
        self,
        entries: tuple[tuple[str, str, str, int], ...],
        *,
        manifest_sha256: str,
    ) -> None:
        self._entries = entries
        self.manifest_sha256 = manifest_sha256

    @classmethod
    def from_path(cls, path: Path) -> CandidateLegislationReferenceResolver:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise RuntimeError("approved-source manifest is not an object")
        return cls.from_manifest(payload)

    @classmethod
    def from_manifest(cls, manifest: Mapping[str, Any]) -> CandidateLegislationReferenceResolver:
        expected_digest = approved_source_manifest_sha256(manifest)
        if (
            manifest.get("schema") != MANIFEST_SCHEMA
            or manifest.get("manifest_sha256") != expected_digest
        ):
            raise RuntimeError("approved-source manifest identity is invalid")
        sources = manifest.get("sources")
        if not isinstance(sources, list):
            raise RuntimeError("approved-source manifest has no source registry")
        entries: list[tuple[str, str, str, int]] = []
        for raw in sources:
            if not isinstance(raw, Mapping):
                raise RuntimeError("approved-source manifest source entry is invalid")
            source_identity = str(raw.get("stable_identifier") or "")
            if source_family(source_identity) != FAMILY_LEGISLATION:
                continue
            title = str(raw.get("title") or "").strip()
            count = raw.get("body_chunk_count")
            if not title or isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise RuntimeError("candidate legislation source metadata is incomplete")
            normalised_title = _normalise_words(title)
            if not normalised_title:
                raise RuntimeError("candidate legislation title cannot be normalised")
            entries.append((normalised_title, title, source_identity, count))
        entries.sort(key=lambda item: (-len(item[0]), item[0], item[2]))
        return cls(tuple(entries), manifest_sha256=expected_digest)

    def resolve(self, query: str) -> ExplicitLegislationReference | None:
        locator = explicit_section_locator(query)
        if locator is None:
            return None
        normalised_query = f" {_normalise_words(query)} "
        matches = [entry for entry in self._entries if f" {entry[0]} " in normalised_query]
        if not matches:
            return None
        longest = len(matches[0][0])
        most_specific = [entry for entry in matches if len(entry[0]) == longest]
        identities = {entry[2] for entry in most_specific}
        if len(identities) != 1:
            return None
        _, title, source_identity, count = most_specific[0]
        return ExplicitLegislationReference(
            source_identity=source_identity,
            title=title,
            locator=locator,
            source_chunk_count=count,
            manifest_sha256=self.manifest_sha256,
        )


def explicit_section_locator(text: str) -> str | None:
    """Return one explicit section coordinate; ambiguous queries use hybrid search."""

    locators = {
        value
        for match in _SECTION.finditer(text)
        if (value := canonical_legislation_locator(match.group(0))) is not None
    }
    if len(locators) != 1:
        return None
    return next(iter(locators))


def canonical_legislation_locator(value: object) -> str | None:
    """Canonicalize an exact statutory section/subsection coordinate."""

    text = " ".join(str(value or "").split())
    match = _CANONICAL_SECTION.fullmatch(text)
    if match is None:
        return None
    section = match.group(1).upper()
    suffix = re.sub(r"\s+", "", match.group(2) or "").casefold()
    return f"section {section}{suffix}"


def legislation_locator_within(candidate: object, expected: object) -> bool:
    """Return true only for the expected section or one of its descendants."""

    canonical_candidate = canonical_legislation_locator(candidate)
    canonical_expected = canonical_legislation_locator(expected)
    if canonical_candidate is None or canonical_expected is None:
        return False
    return canonical_candidate == canonical_expected or canonical_candidate.startswith(
        canonical_expected + "("
    )


def _normalise_words(value: str) -> str:
    normalised = unicodedata.normalize("NFKC", value).casefold()
    return " ".join(_NON_ALNUM.sub(" ", normalised).split())
