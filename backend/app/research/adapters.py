"""Network-free request planning and staged response validation.

The adapters do not perform HTTP requests.  A separately controlled fetcher
may execute a plan, then return a response for validation and staging.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Protocol
from urllib.parse import quote, urlencode, urlparse

from .source_registry import ContentMode, OfficialSourcePolicy, OfficialSourceRegistry


@dataclass(frozen=True, slots=True)
class FetchPlan:
    source_id: str
    url: str
    expected_content_mode: ContentMode
    headers: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class StagedOnlineCandidate:
    source_id: str
    canonical_url: str
    identity: str
    metadata: Mapping[str, Any]
    content: bytes | None
    content_sha256: str | None
    disposition: str = "staged_only"
    review_state: str = "unreviewed"


class OfficialSourceAdapter(Protocol):
    policy: OfficialSourcePolicy

    def plan(self, identity: str) -> FetchPlan: ...

    def stage(
        self,
        *,
        canonical_url: str,
        identity: str,
        metadata: Mapping[str, Any],
        content: bytes | None,
    ) -> StagedOnlineCandidate: ...


class GenericOfficialAdapter:
    def __init__(self, policy: OfficialSourcePolicy) -> None:
        self.policy = policy

    def plan(self, identity: str) -> FetchPlan:
        clean = identity.strip().strip("/")
        if not clean or ".." in clean or "?" in clean or "#" in clean:
            raise ValueError("source identity is required")
        return FetchPlan(
            self.policy.source_id,
            f"{self.policy.base_url}{quote(clean, safe='/._~-')}",
            self.policy.content_mode,
        )

    def stage(
        self,
        *,
        canonical_url: str,
        identity: str,
        metadata: Mapping[str, Any],
        content: bytes | None,
    ) -> StagedOnlineCandidate:
        candidate = urlparse(canonical_url)
        registered = urlparse(self.policy.base_url)
        if (
            candidate.scheme != "https"
            or candidate.username is not None
            or candidate.password is not None
            or candidate.port not in {None, 443}
            or (candidate.hostname or "").casefold() != (registered.hostname or "").casefold()
            or not candidate.path.startswith(registered.path)
        ):
            raise ValueError("candidate URL is outside registered source origin")
        if self.policy.content_mode is ContentMode.METADATA_ONLY and content is not None:
            raise PermissionError(f"{self.policy.source_id} is metadata-only")
        if self.policy.content_mode is ContentMode.ITEM_LICENCE_REQUIRED:
            licence = str(metadata.get("item_licence", ""))
            if content is not None and not licence:
                raise PermissionError(
                    "item-level licence evidence is required before full text can be staged"
                )
        digest = hashlib.sha256(content).hexdigest() if content is not None else None
        return StagedOnlineCandidate(
            self.policy.source_id,
            canonical_url,
            identity,
            dict(metadata),
            content,
            digest,
        )


class LegislationGovUkAdapter(GenericOfficialAdapter):
    def search_plan(
        self,
        query: str,
        *,
        as_of_date: date,
        title_search: bool,
        results_count: int = 5,
    ) -> FetchPlan:
        """Plan an official Atom search without accepting arbitrary query parameters."""

        clean = " ".join(query.split()).strip()
        if not clean or len(clean) > 160:
            raise ValueError("a bounded legislation search query is required")
        if not 1 <= results_count <= 10:
            raise ValueError("results_count must be between 1 and 10")
        parameters = [
            ("type", "primary"),
            ("type", "secondary"),
            ("version", as_of_date.isoformat()),
            ("results-count", str(results_count)),
            ("sort", "title"),
            ("title" if title_search else "text", clean),
        ]
        return FetchPlan(
            self.policy.source_id,
            f"{self.policy.base_url}search/data.feed?{urlencode(parameters)}",
            ContentMode.FULL_TEXT,
            {
                "Accept": "application/atom+xml, application/xml;q=0.9",
                "User-Agent": "LegalBotResearch/1.0",
            },
        )

    def plan(self, identity: str) -> FetchPlan:
        clean = identity.strip().strip("/")
        if not clean or ".." in clean:
            raise ValueError("invalid legislation path")
        return FetchPlan(
            self.policy.source_id,
            f"{self.policy.base_url}{quote(clean, safe='/')}/data.xml",
            ContentMode.FULL_TEXT,
            {"Accept": "application/xml", "User-Agent": "LegalBotResearch/1.0"},
        )


class FindCaseLawMetadataAdapter(GenericOfficialAdapter):
    def plan(self, identity: str) -> FetchPlan:
        clean = identity.strip().strip("/")
        if not clean or ".." in clean:
            raise ValueError("invalid Find Case Law identity")
        # Metadata/search page only: the adapter cannot request judgment XML.
        return FetchPlan(
            self.policy.source_id,
            f"{self.policy.base_url}{quote(clean, safe='/')}",
            ContentMode.METADATA_ONLY,
            {"Accept": "text/html", "User-Agent": "LegalBotResearch/1.0"},
        )


class EurLexAdapter(GenericOfficialAdapter):
    def plan(self, identity: str) -> FetchPlan:
        celex = identity.strip().upper()
        if not celex or not all(
            character.isalnum() or character in {"-", "(", ")"} for character in celex
        ):
            raise ValueError("invalid CELEX identity")
        return FetchPlan(
            self.policy.source_id,
            f"{self.policy.base_url}legal-content/EN/TXT/?uri=CELEX:{quote(celex, safe='()-')}",
            ContentMode.FULL_TEXT,
            {"Accept": "text/html, application/xhtml+xml", "User-Agent": "LegalBotResearch/1.0"},
        )


class CuriaMetadataAdapter(GenericOfficialAdapter):
    def plan(self, identity: str) -> FetchPlan:
        case_number = identity.strip()
        if not case_number or ".." in case_number:
            raise ValueError("invalid CURIA case identity")
        return FetchPlan(
            self.policy.source_id,
            f"{self.policy.base_url}juris/liste.jsf?num={quote(case_number, safe='-/')}",
            ContentMode.METADATA_ONLY,
            {"Accept": "text/html", "User-Agent": "LegalBotResearch/1.0"},
        )


class HudocMetadataAdapter(GenericOfficialAdapter):
    def plan(self, identity: str) -> FetchPlan:
        document_id = identity.strip()
        if not document_id or ".." in document_id:
            raise ValueError("invalid HUDOC document identity")
        return FetchPlan(
            self.policy.source_id,
            f"{self.policy.base_url}eng?i={quote(document_id, safe='-')}",
            ContentMode.METADATA_ONLY,
            {"Accept": "text/html", "User-Agent": "LegalBotResearch/1.0"},
        )


def adapter_registry(registry: OfficialSourceRegistry) -> dict[str, OfficialSourceAdapter]:
    adapters: dict[str, OfficialSourceAdapter] = {}
    for policy in registry.all():
        if policy.source_id == "legislation_gov_uk":
            adapter: OfficialSourceAdapter = LegislationGovUkAdapter(policy)
        elif policy.source_id == "find_case_law":
            adapter = FindCaseLawMetadataAdapter(policy)
        elif policy.source_id == "eur_lex":
            adapter = EurLexAdapter(policy)
        elif policy.source_id == "curia":
            adapter = CuriaMetadataAdapter(policy)
        elif policy.source_id == "hudoc":
            adapter = HudocMetadataAdapter(policy)
        else:
            adapter = GenericOfficialAdapter(policy)
        adapters[policy.source_id] = adapter
    return adapters
