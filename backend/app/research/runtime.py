"""Fail-closed, allowlisted official-source research for one answer job.

Only structured legislation.gov.uk material can become an ``EvidenceSpan``.
All other registered sources are link/metadata candidates for review.  Nothing
in this module writes to LanceDB or changes the ACTIVE index pointer.
"""

from __future__ import annotations

import hashlib
import re
import ssl
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from email.utils import parsedate_to_datetime
from typing import Any, Protocol, cast
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit

import httpcore
import httpx
from httpcore._backends.auto import AutoBackend
from lxml import etree  # type: ignore[import-untyped]

from ..citations.oscola import render_oscola
from ..config import Settings
from ..db import Database
from ..jurisdictions import normalise
from ..privacy import prompt_injection_hits, scrub_pii
from ..types import EvidenceSpan, MaterialLane
from .adapters import (
    FetchPlan,
    LegislationGovUkAdapter,
    adapter_registry,
)
from .control_plane import ResearchControlPlane
from .fetch_policy import AddressResolver, SafeFetchPolicy
from .gap_queue import GapKind, GapQueue
from .legacy import DatabaseGapCandidateSink
from .source_registry import OfficialSourcePolicy, OfficialSourceRegistry

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_REDIRECTS = 3
MAX_LEGISLATION_RESULTS = 3
MAX_EVIDENCE_SPANS = 6

_INSTRUMENT_TITLE = re.compile(
    r"\b([A-Z][A-Za-z0-9&'’.-]+(?:\s+[A-Z][A-Za-z0-9&'’.-]+){0,8}\s+"
    r"(?:Act|Regulations|Rules|Order)\s+\d{4})\b"
)
_LEGISLATION_PATH = re.compile(
    r"\b(?P<type>ukpga|uksi|wsi|asp|ssi|nia|nisr|anaw|asc)/"
    r"(?P<year>\d{4})/(?P<number>\d+)\b",
    re.IGNORECASE,
)
_PROVISION = re.compile(
    r"\b(?P<label>section|s|regulation|reg|article|art|rule|r)\s*"
    r"(?P<number>\d+[A-Za-z]?(?:\([0-9A-Za-z]+\))*)",
    re.IGNORECASE,
)
_OFFICIAL_URL = re.compile(r"https://[^\s<>()\[\]{}\"']+", re.IGNORECASE)
_SUBJECT_QUERIES = {
    "competition": "competition",
    "contract": "contract",
    "criminal": "criminal",
    "employment": "employment",
    "evidence": "evidence",
    "land": "land registration",
    "medical": "medical treatment",
    "pensions": "pensions",
    "privacy": "data protection",
    "tort": "negligence",
    "trusts": "trustees",
}
_JURISDICTION_SLUGS = {
    "england and wales": "england_wales",
    "united kingdom": "united_kingdom",
    "scotland": "scotland",
    "northern ireland": "northern_ireland",
    "european union": "european_union",
    "european convention on human rights": "european_convention_on_human_rights",
}
_LEGISLATION_TYPES = frozenset({"ukpga", "uksi", "wsi", "asp", "ssi", "nia", "nisr", "anaw", "asc"})
_SECONDARY_TYPES = frozenset({"uksi", "wsi", "ssi", "nisr"})


class OnlineFetchError(RuntimeError):
    """Network or policy failure represented by a safe, non-PII reason code."""

    def __init__(self, code: str, *, retry_after_seconds: int | None = None) -> None:
        self.code = code
        self.retry_after_seconds = retry_after_seconds
        super().__init__(code)


def _retry_after_seconds(value: str, *, now: datetime | None = None) -> int | None:
    raw = value.strip()
    if not raw:
        return None
    if raw.isdigit():
        return min(86_400, int(raw))
    try:
        retry_at = parsedate_to_datetime(raw)
    except (TypeError, ValueError, OverflowError):
        return None
    if retry_at.tzinfo is None:
        retry_at = retry_at.replace(tzinfo=UTC)
    delay = int((retry_at.astimezone(UTC) - (now or datetime.now(UTC))).total_seconds())
    return min(86_400, max(0, delay))


@dataclass(frozen=True, slots=True)
class FetchedResponse:
    url: str
    status_code: int
    headers: Mapping[str, str]
    content: bytes


class OfficialFetcher(Protocol):
    async def fetch(self, plan: FetchPlan, policy: OfficialSourcePolicy) -> FetchedResponse: ...


class _PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Connect only to pre-resolved IPs and verify the socket peer before use.

    HTTP Core still sees the registered hostname as the request origin, so its
    TLS upgrade supplies that hostname for SNI and certificate verification.
    Only the TCP destination is replaced with a validated literal IP.
    """

    def __init__(
        self,
        *,
        hostname: str,
        resolved_addresses: Sequence[str],
        policy: SafeFetchPolicy,
        backend: httpcore.AsyncNetworkBackend | None = None,
    ) -> None:
        self.hostname = hostname.casefold()
        self.resolved_addresses = tuple(resolved_addresses)
        self.policy = policy
        self.backend = backend or AutoBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        if host.casefold() != self.hostname or port != 443:
            raise ValueError("official_transport_origin_mismatch")
        last_error: Exception | None = None
        for address in self.resolved_addresses:
            try:
                stream = await self.backend.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
                try:
                    self.policy.validate_connected_peer(
                        stream.get_extra_info("server_addr"),
                        resolved_addresses=self.resolved_addresses,
                    )
                except ValueError:
                    await stream.aclose()
                    raise
                return stream
            except ValueError:
                raise
            except Exception as exc:  # pragma: no cover - backend-specific connect errors
                last_error = exc
        if last_error is not None:
            raise last_error
        raise ValueError("official_dns_no_addresses")

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise ValueError("official_unix_socket_rejected")

    async def sleep(self, seconds: float) -> None:
        await self.backend.sleep(seconds)


class _PinnedAsyncHttpTransport(httpx.AsyncHTTPTransport):
    """HTTPX transport backed by a single DNS-pinned HTTP Core pool."""

    def __init__(
        self,
        *,
        hostname: str,
        resolved_addresses: Sequence[str],
        policy: SafeFetchPolicy,
        network_backend: httpcore.AsyncNetworkBackend | None = None,
    ) -> None:
        ssl_context = ssl.create_default_context()
        super().__init__(
            verify=ssl_context,
            trust_env=False,
            http1=True,
            http2=False,
            retries=0,
            limits=httpx.Limits(max_connections=1, max_keepalive_connections=0),
        )
        # AsyncHTTPTransport intentionally delegates all protocol and TLS work
        # to this pool. The origin remains the hostname; only connect_tcp is
        # pinned to the validated IP set.
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context,
            max_connections=1,
            max_keepalive_connections=0,
            http1=True,
            http2=False,
            retries=0,
            network_backend=_PinnedNetworkBackend(
                hostname=hostname,
                resolved_addresses=resolved_addresses,
                policy=policy,
                backend=network_backend,
            ),
        )


class AllowlistedHttpFetcher:
    """Bounded HTTPS client with DNS-pinned, origin-checked redirect hops."""

    def __init__(
        self,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout_seconds: float = 12.0,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
        fetch_policy: SafeFetchPolicy | None = None,
        resolver: AddressResolver | None = None,
        network_backend: httpcore.AsyncNetworkBackend | None = None,
    ) -> None:
        self.transport = transport
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.fetch_policy = fetch_policy or SafeFetchPolicy(max_response_bytes=max_response_bytes)
        self.resolver = resolver
        self.network_backend = network_backend

    async def fetch(self, plan: FetchPlan, policy: OfficialSourcePolicy) -> FetchedResponse:
        current = plan.url
        for redirect_count in range(MAX_REDIRECTS + 1):
            current_plan = FetchPlan(
                source_id=plan.source_id,
                url=current,
                expected_content_mode=plan.expected_content_mode,
                headers=plan.headers,
            )
            try:
                hostname = self.fetch_policy.validate_plan(current_plan, policy)
                if self.transport is None:
                    resolved = await self.fetch_policy.validate_resolution(
                        current_plan,
                        policy,
                        resolver=self.resolver,
                    )
                    request_transport: httpx.AsyncBaseTransport = _PinnedAsyncHttpTransport(
                        hostname=hostname,
                        resolved_addresses=resolved,
                        policy=self.fetch_policy,
                        network_backend=self.network_backend,
                    )
                else:
                    # Explicit injected transports are reserved for isolated
                    # tests; production always uses the pinned transport.
                    request_transport = self.transport
                async with (
                    httpx.AsyncClient(
                        transport=request_transport,
                        timeout=self.timeout_seconds,
                        follow_redirects=False,
                        trust_env=False,
                    ) as client,
                    client.stream("GET", current, headers=dict(plan.headers)) as response,
                ):
                    if response.status_code in {301, 302, 303, 307, 308}:
                        if redirect_count >= MAX_REDIRECTS:
                            raise OnlineFetchError("redirect_limit_exceeded")
                        location = response.headers.get("location")
                        if not location:
                            raise OnlineFetchError("redirect_missing_location")
                        redirected = urljoin(current, location)
                        redirected_plan = FetchPlan(
                            source_id=plan.source_id,
                            url=redirected,
                            expected_content_mode=plan.expected_content_mode,
                            headers=plan.headers,
                        )
                        self.fetch_policy.validate_plan(redirected_plan, policy)
                        current = redirected
                        continue
                    if response.status_code != 200:
                        retry_after = _retry_after_seconds(response.headers.get("retry-after", ""))
                        raise OnlineFetchError(
                            f"official_http_status_{response.status_code}",
                            retry_after_seconds=retry_after,
                        )
                    response_headers = {
                        key.casefold(): value for key, value in response.headers.items()
                    }
                    self.fetch_policy.validate_response_headers(response_headers)
                    chunks: list[bytes] = []
                    total = 0
                    async for chunk in response.aiter_bytes():
                        total += len(chunk)
                        if total > self.max_response_bytes:
                            raise OnlineFetchError("official_response_too_large")
                        chunks.append(chunk)
                    return FetchedResponse(
                        str(response.url),
                        response.status_code,
                        response_headers,
                        b"".join(chunks),
                    )
            except OnlineFetchError:
                raise
            except ValueError as exc:
                code = str(exc)
                if code.startswith("official_"):
                    raise OnlineFetchError(code) from exc
                raise OnlineFetchError("official_network_unavailable") from exc
            except (httpx.HTTPError, httpcore.NetworkError) as exc:
                raise OnlineFetchError("official_network_unavailable") from exc
        raise OnlineFetchError("redirect_limit_exceeded")


@dataclass(frozen=True, slots=True)
class AtomLegislationCandidate:
    identity: str
    title: str
    canonical_url: str


@dataclass(frozen=True, slots=True)
class VerifiedLegislation:
    identity: str
    title: str
    canonical_url: str
    content_sha256: str
    currentness_status: str
    citation_data: Mapping[str, Any]
    excerpts: tuple[tuple[str, str], ...]


class OfficialOnlineResearcher:
    """Answer-time official research; no permanent index or auto-promotion path."""

    def __init__(
        self,
        *,
        settings: Settings,
        database: Database,
        registry: OfficialSourceRegistry | None = None,
        fetcher: OfficialFetcher | None = None,
        gap_queue: GapQueue | None = None,
    ) -> None:
        settings.assert_online_research_adapter_allowed()
        self.settings = settings
        self.database = database
        self.registry = registry or OfficialSourceRegistry.load(
            settings.project_root / "config" / "official_sources.json"
        )
        self.adapters = adapter_registry(self.registry)
        self.fetcher = fetcher or AllowlistedHttpFetcher()
        # The retired JSON queue is accepted only when a caller explicitly
        # injects a writable legacy fixture. Production stages into SQLite.
        self.gaps = gap_queue or DatabaseGapCandidateSink(
            ResearchControlPlane(settings, database, registry=self.registry)
        )

    async def research_gap(
        self,
        *,
        proposition: str,
        jurisdiction: str,
        subject: str | None,
        as_of_date: date,
    ) -> tuple[Sequence[EvidenceSpan], list[dict[str, str]], list[str]]:
        searches: list[dict[str, str]] = []
        rejections: list[str] = []
        if as_of_date > date.today():
            return [], searches, ["as_of_date_is_in_the_future"]
        jurisdiction_slug = _JURISDICTION_SLUGS.get(normalise(jurisdiction))
        if jurisdiction_slug is None:
            return [], searches, ["jurisdiction_has_no_registered_official_source"]

        spans: list[EvidenceSpan] = []
        query = _safe_legislation_query(proposition, subject, self.settings.owner_identifiers)
        legislation_policy = self.registry.get("legislation_gov_uk")
        if jurisdiction_slug in legislation_policy.jurisdictions and query is not None:
            searches.append(
                {"source": "legislation_gov_uk", "action": "structured_api", "result": "attempted"}
            )
            try:
                spans.extend(
                    await self._research_legislation(
                        query=query[0],
                        title_search=query[1],
                        proposition=proposition,
                        jurisdiction=jurisdiction,
                        jurisdiction_slug=jurisdiction_slug,
                        subject=subject,
                        as_of_date=as_of_date,
                    )
                )
                searches[-1]["result"] = "qualified" if spans else "no_qualified_span"
            except OnlineFetchError as exc:
                searches[-1]["result"] = "unavailable"
                rejections.append(exc.code)
            except ValueError as exc:
                searches[-1]["result"] = "rejected"
                rejections.append(_safe_error_code(exc))

        direct_rejections = await self._stage_explicit_official_links(
            proposition=proposition,
            jurisdiction=jurisdiction,
            jurisdiction_slug=jurisdiction_slug,
            subject=subject,
            searches=searches,
        )
        rejections.extend(direct_rejections)
        return spans[:MAX_EVIDENCE_SPANS], searches, list(dict.fromkeys(rejections))

    async def _research_legislation(
        self,
        *,
        query: str,
        title_search: bool,
        proposition: str,
        jurisdiction: str,
        jurisdiction_slug: str,
        subject: str | None,
        as_of_date: date,
    ) -> list[EvidenceSpan]:
        policy = self.registry.get("legislation_gov_uk")
        adapter = cast(LegislationGovUkAdapter, self.adapters["legislation_gov_uk"])
        feed_plan = adapter.search_plan(
            query, as_of_date=as_of_date, title_search=title_search, results_count=5
        )
        feed = await self.fetcher.fetch(feed_plan, policy)
        _require_xml_content_type(feed, atom=True)
        candidates = _parse_atom_candidates(feed.content, query, title_search)
        output: list[EvidenceSpan] = []
        rejection_codes: list[str] = []
        for candidate in candidates[:MAX_LEGISLATION_RESULTS]:
            dated_identity = f"{candidate.identity}/{as_of_date.isoformat()}"
            try:
                response = await self.fetcher.fetch(adapter.plan(dated_identity), policy)
                _require_xml_content_type(response, atom=False)
                verified = _verify_legislation(
                    response=response,
                    candidate=candidate,
                    proposition=proposition,
                    query=query,
                    as_of_date=as_of_date,
                    jurisdiction=jurisdiction,
                )
                adapter.stage(
                    canonical_url=verified.canonical_url,
                    identity=verified.identity,
                    metadata={
                        "title": verified.title,
                        "as_of_date": as_of_date.isoformat(),
                        "currentness_status": verified.currentness_status,
                    },
                    content=response.content,
                )
                self._queue_candidate(
                    source_id=policy.source_id,
                    identity=verified.identity,
                    canonical_url=verified.canonical_url,
                    subject=subject,
                    jurisdiction=jurisdiction_slug,
                    kind=GapKind.LEGISLATION,
                    metadata={
                        "content_sha256": verified.content_sha256,
                        "as_of_date": as_of_date.isoformat(),
                        "currentness": verified.currentness_status,
                    },
                )
                staged = self.database.stage_online_source(
                    source_id=policy.source_id,
                    canonical_url=verified.canonical_url,
                    title=verified.title,
                    content_sha256=verified.content_sha256,
                    as_of_date=as_of_date,
                    currentness_status=verified.currentness_status,
                    licence_name=policy.licence.name,
                    licence_url=policy.licence.url,
                    lane=MaterialLane.PRIMARY_AUTHORITY,
                    jurisdiction=jurisdiction,
                    subject=subject or "general",
                    excerpts=[
                        {"locator": locator, "text": text} for locator, text in verified.excerpts
                    ],
                )
                chunks = cast(list[dict[str, str]], staged["chunks"])
                citation_data = dict(verified.citation_data)
                canonical_citation = render_oscola(citation_data)
                for chunk in chunks:
                    evidence_digest = hashlib.sha256(
                        f"{staged['source_version_id']}\0{chunk['id']}".encode()
                    ).hexdigest()
                    output.append(
                        EvidenceSpan(
                            id=f"online-evidence-{evidence_digest[:32]}",
                            source_version_id=str(staged["source_version_id"]),
                            chunk_id=chunk["id"],
                            text=chunk["text"],
                            locator=chunk["locator"],
                            lane=MaterialLane.PRIMARY_AUTHORITY,
                            jurisdiction=jurisdiction,
                            subject=subject or "general",
                            citation_data=citation_data,
                            canonical_citation=canonical_citation,
                            currentness_status=verified.currentness_status,
                            content_sha256=verified.content_sha256,
                            index_build_id=str(staged["index_build_id"]),
                            canonical_url=verified.canonical_url,
                            retrieval_relevance_score=_overlap_score(proposition, chunk["text"]),
                            legal_role=str(chunk.get("legal_role") or "unclassified"),
                            identity_verified=True,
                            currentness_verified=True,
                        )
                    )
                if output:
                    return output
            except OnlineFetchError as exc:
                rejection_codes.append(exc.code)
            except ValueError as exc:
                rejection_codes.append(_safe_error_code(exc))
        if rejection_codes:
            raise ValueError(rejection_codes[0])
        return []

    async def _stage_explicit_official_links(
        self,
        *,
        proposition: str,
        jurisdiction: str,
        jurisdiction_slug: str,
        subject: str | None,
        searches: list[dict[str, str]],
    ) -> list[str]:
        rejections: list[str] = []
        for raw_url in _OFFICIAL_URL.findall(proposition)[:5]:
            url = _strip_url_query(raw_url.rstrip(".,;:!?"))
            policy = _policy_for_url(self.registry, url)
            if policy is None or jurisdiction_slug not in policy.jurisdictions:
                continue
            searches.append(
                {
                    "source": policy.source_id,
                    "action": "official_link_candidate",
                    "result": "review_required",
                }
            )
            identity = urlparse(url).path.strip("/") or policy.source_id
            self._queue_candidate(
                source_id=policy.source_id,
                identity=identity,
                canonical_url=url,
                subject=subject,
                jurisdiction=jurisdiction_slug,
                kind=(
                    GapKind.CASE_AUTHORITY
                    if policy.source_id == "find_case_law"
                    else GapKind.RETRIEVAL_MISS
                ),
                metadata={
                    "content_mode": policy.content_mode.value,
                    "additional_permission_required": bool(policy.additional_permission_required),
                    "network_fetch": "not_permitted_from_proposition_url",
                },
            )
            if policy.source_id == "find_case_law":
                rejections.append("find_case_law_metadata_only_no_full_text_or_vectors")
                continue
            rejections.append("official_link_requires_registered_identity_review")
        return rejections

    def _queue_candidate(
        self,
        *,
        source_id: str,
        identity: str,
        canonical_url: str,
        subject: str | None,
        jurisdiction: str,
        kind: GapKind,
        metadata: Mapping[str, Any],
    ) -> None:
        gap = self.gaps.enqueue(
            subject=subject or "general",
            jurisdiction=jurisdiction,
            kind=kind,
            reason_code="answer_time_official_candidate",
            description="An official answer-time candidate requires human review before index ingestion.",
            query_alias=None,
            priority=80,
            metadata={"disposition": "staged_only", "permanent_index_eligible": False},
        )
        self.gaps.stage_candidate(
            gap.gap_id,
            source_id=source_id,
            source_identity=identity,
            canonical_url=canonical_url,
            metadata=metadata,
        )
        self.gaps.require_review(gap.gap_id)


def _validate_registered_url(url: str, policy: OfficialSourcePolicy) -> None:
    candidate = urlsplit(url)
    registered = urlsplit(policy.base_url)
    try:
        port = candidate.port
    except ValueError as exc:
        raise OnlineFetchError("official_url_invalid_port") from exc
    if (
        candidate.scheme != "https"
        or candidate.username is not None
        or candidate.password is not None
        or port not in {None, 443}
        or (candidate.hostname or "").casefold() != (registered.hostname or "").casefold()
        or not candidate.path.startswith(registered.path)
    ):
        raise OnlineFetchError("official_url_outside_allowlist")


def _policy_for_url(registry: OfficialSourceRegistry, url: str) -> OfficialSourcePolicy | None:
    for policy in registry.all():
        try:
            _validate_registered_url(url, policy)
        except OnlineFetchError:
            continue
        return policy
    return None


def _strip_url_query(url: str) -> str:
    parsed = urlsplit(url)
    cleaned = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    if scrub_pii(cleaned) != cleaned:
        raise ValueError("official_url_contains_private_data")
    return cleaned


def _safe_legislation_query(
    proposition: str, subject: str | None, owner_identifiers: Sequence[str]
) -> tuple[str, bool] | None:
    scrubbed = scrub_pii(proposition, owner_identifiers)
    title = _INSTRUMENT_TITLE.search(scrubbed)
    if title:
        return title.group(1), True
    path = _LEGISLATION_PATH.search(scrubbed)
    if path:
        return "/".join(path.group(name).casefold() for name in ("type", "year", "number")), True
    subject_query = _SUBJECT_QUERIES.get(" ".join((subject or "").casefold().split()))
    if subject_query:
        return subject_query, False
    # Raw question/proposition terms never become network search strings.  A
    # request must resolve to an exact public Act/path identity above or to the
    # fixed subject taxonomy. Otherwise answer-time online research fails
    # closed and records the evidence gap for owner review.
    return None


def _secure_xml(content: bytes) -> Any:
    if not content or b"<!DOCTYPE" in content.upper() or b"<!ENTITY" in content.upper():
        raise ValueError("official_xml_unsafe_or_empty")
    try:
        parser = etree.XMLParser(
            resolve_entities=False, no_network=True, recover=False, huge_tree=False
        )
        return etree.fromstring(content, parser=parser)
    except etree.XMLSyntaxError as exc:
        raise ValueError("official_xml_malformed") from exc


def _local_name(element: Any) -> str:
    return str(etree.QName(element).localname)


def _namespace(element: Any) -> str:
    return str(etree.QName(element).namespace or "")


def _parse_atom_candidates(
    content: bytes, query: str, title_search: bool
) -> list[AtomLegislationCandidate]:
    root = _secure_xml(content)
    if _local_name(root) != "feed":
        raise ValueError("official_atom_feed_expected")
    query_tokens = set(re.findall(r"[a-z0-9]+", query.casefold()))
    candidates: list[AtomLegislationCandidate] = []
    for entry in root.iter():
        if _local_name(entry) != "entry":
            continue
        title = ""
        identity_url = ""
        for child in entry:
            if _local_name(child) == "title":
                title = " ".join("".join(child.itertext()).split())
            elif _local_name(child) == "id":
                identity_url = "".join(child.itertext()).strip()
        identity = _identity_from_legislation_url(identity_url)
        if not title or identity is None:
            continue
        title_tokens = set(re.findall(r"[a-z0-9]+", title.casefold()))
        if (
            title_search
            and query_tokens
            and len(query_tokens & title_tokens) < max(2, len(query_tokens) // 2)
        ):
            continue
        canonical = f"https://www.legislation.gov.uk/{identity}"
        candidates.append(AtomLegislationCandidate(identity, title, canonical))
    return candidates


def _identity_from_legislation_url(value: str) -> str | None:
    parsed = urlparse(value)
    if (parsed.hostname or "").casefold() != "www.legislation.gov.uk":
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if parts and parts[0] == "id":
        parts = parts[1:]
    if len(parts) < 3 or parts[0].casefold() not in _LEGISLATION_TYPES:
        return None
    type_code, year, number = parts[:3]
    if not year.isdigit() or not number.isdigit():
        return None
    return f"{type_code.casefold()}/{year}/{number}"


def _verify_legislation(
    *,
    response: FetchedResponse,
    candidate: AtomLegislationCandidate,
    proposition: str,
    query: str,
    as_of_date: date,
    jurisdiction: str,
) -> VerifiedLegislation:
    root = _secure_xml(response.content)
    if _local_name(root) != "Legislation":
        raise ValueError("official_clml_legislation_expected")
    self_links = [
        str(element.get("href", ""))
        for element in root.iter()
        if _local_name(element) == "link" and str(element.get("rel", "")) == "self"
    ]
    identities = {_identity_from_legislation_url(value) for value in self_links}
    if candidate.identity not in identities:
        raise ValueError("official_identity_mismatch")
    title = _metadata_text(root, "title")
    if not title or _normalised_title(title) != _normalised_title(candidate.title):
        raise ValueError("official_title_identity_mismatch")
    valid = _metadata_text(root, "valid")
    if valid != as_of_date.isoformat():
        raise ValueError("official_point_in_time_mismatch")
    modified = _metadata_text(root, "modified")
    if not modified:
        raise ValueError("official_modified_date_missing")
    try:
        modified_date = datetime.fromisoformat(modified.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("official_modified_date_invalid") from exc
    if modified_date.tzinfo is None:
        modified_date = modified_date.replace(tzinfo=UTC)
    if modified_date > datetime.now(UTC):
        raise ValueError("official_modified_date_in_future")
    if any(_local_name(element) == "UnappliedEffect" for element in root.iter()):
        raise ValueError("official_unapplied_effects_present")

    identity_type = candidate.identity.split("/", 1)[0]
    requested = _PROVISION.search(proposition)
    requested_number = requested.group("number") if requested else None
    requested_kind = requested.group("label").casefold() if requested else None
    query_tokens = set(re.findall(r"[a-z]{3,}", query.casefold()))
    excerpts: list[tuple[str, str, int]] = []
    for element in root.iter():
        fragment_id = str(element.get("id", ""))
        locator = _locator_from_fragment(fragment_id)
        if locator is None or not _fragment_is_current(element, as_of_date, jurisdiction):
            continue
        if requested_number and not _locator_matches(locator, requested_kind, requested_number):
            continue
        text = " ".join(" ".join(element.itertext()).split())
        if len(text) < 20:
            continue
        if len(text) > 4_000:
            text = text[:4_000].rsplit(" ", 1)[0]
        if prompt_injection_hits(text):
            continue
        score = len(query_tokens & set(re.findall(r"[a-z]{3,}", text.casefold())))
        if not requested_number and score == 0:
            continue
        excerpts.append((locator, text, score))
    excerpts.sort(key=lambda item: (-item[2], item[0]))
    if requested_number and not excerpts:
        raise ValueError("official_requested_provision_not_current_or_not_found")
    if not excerpts:
        raise ValueError("official_exact_span_not_found")

    if identity_type in _SECONDARY_TYPES:
        prefix = {"ssi": "SSI", "nisr": "SR"}.get(identity_type, "SI")
        year, number = candidate.identity.split("/")[1:3]
        citation_data: dict[str, Any] = {
            "source_type": "statutory_instrument",
            "title": title,
            "instrument_number": f"{prefix} {year}/{number}",
        }
    else:
        citation_data = {"source_type": "legislation", "title": title}
    return VerifiedLegislation(
        candidate.identity,
        title,
        candidate.canonical_url,
        hashlib.sha256(response.content).hexdigest(),
        f"point_in_time:{as_of_date.isoformat()};unapplied_effects:0",
        citation_data,
        tuple((locator, text) for locator, text, _ in excerpts[:MAX_EVIDENCE_SPANS]),
    )


def _metadata_text(root: Any, local_name: str) -> str:
    for element in root.iter():
        namespace = _namespace(element)
        if _local_name(element).casefold() == local_name.casefold() and "purl.org/dc" in namespace:
            return " ".join("".join(element.itertext()).split())
    return ""


def _fragment_is_current(element: Any, as_of_date: date, jurisdiction: str) -> bool:
    current = element
    while current is not None:
        if str(current.get("Match", "")).casefold() == "false":
            return False
        if str(current.get("Status", "")).casefold() in {"prospective", "repealed", "discarded"}:
            return False
        start = str(current.get("RestrictStartDate", ""))
        end = str(current.get("RestrictEndDate", ""))
        if start and start > as_of_date.isoformat():
            return False
        if end and end <= as_of_date.isoformat():
            return False
        extent = str(current.get("RestrictExtent", ""))
        if extent and not _extent_applies(extent, jurisdiction):
            return False
        current = current.getparent()
    return True


def _extent_applies(extent: str, jurisdiction: str) -> bool:
    normal = normalise(jurisdiction)
    if normal == "united kingdom":
        return True
    codes = set(re.split(r"[+,.\s]+", extent.upper()))
    if normal == "england and wales":
        return bool(codes & {"E", "W"})
    if normal == "scotland":
        return "S" in codes
    if normal == "northern ireland":
        return "N.I" in extent.upper() or "NI" in codes
    return False


def _locator_from_fragment(fragment_id: str) -> str | None:
    match = re.fullmatch(
        r"(?P<kind>section|regulation|article|rule|schedule)-(?P<number>\d+[A-Za-z]?(?:-[0-9A-Za-z]+)*)",
        fragment_id,
        re.IGNORECASE,
    )
    if not match:
        return None
    number = re.sub(r"-([0-9A-Za-z]+)", r"(\1)", match.group("number"))
    prefix = {
        "section": "s",
        "regulation": "reg",
        "article": "art",
        "rule": "r",
        "schedule": "sch",
    }[match.group("kind").casefold()]
    return f"{prefix} {number}"


def _locator_matches(locator: str, kind: str | None, number: str) -> bool:
    expected_prefix = {
        "section": "s",
        "s": "s",
        "regulation": "reg",
        "reg": "reg",
        "article": "art",
        "art": "art",
        "rule": "r",
        "r": "r",
    }.get(kind or "")
    return locator == f"{expected_prefix} {number}" if expected_prefix else locator.endswith(number)


def _normalised_title(value: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", value.casefold()))


def _require_xml_content_type(response: FetchedResponse, *, atom: bool) -> None:
    content_type = response.headers.get("content-type", "").casefold()
    accepted = ("application/atom+xml", "application/xml", "text/xml")
    if not any(item in content_type for item in accepted):
        raise ValueError(
            "official_atom_content_type_invalid" if atom else "official_xml_content_type_invalid"
        )


def _overlap_score(proposition: str, text: str) -> float:
    proposition_tokens = set(re.findall(r"[a-z]{3,}", scrub_pii(proposition).casefold()))
    if not proposition_tokens:
        return 0.0
    text_tokens = set(re.findall(r"[a-z]{3,}", text.casefold()))
    return round(len(proposition_tokens & text_tokens) / len(proposition_tokens), 6)


def _safe_error_code(exc: Exception) -> str:
    message = str(exc)
    if re.fullmatch(r"[a-z0-9_]+", message):
        return message
    return type(exc).__name__.casefold()
