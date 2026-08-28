"""Network-policy hooks for allowlisted official fetchers."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

from .adapters import FetchPlan
from .source_registry import OfficialSourcePolicy

AddressResolver = Callable[[str, int], Awaitable[Sequence[str]]]

_ALLOWED_MEDIA_TYPES = frozenset(
    {
        "application/atom+xml",
        "application/json",
        "application/pdf",
        "application/xhtml+xml",
        "application/xml",
        "text/html",
        "text/xml",
    }
)
_ALLOWED_ENCODINGS = frozenset({"", "identity", "gzip", "br", "deflate"})


def _path_is_within(candidate_path: str, registered_path: str) -> bool:
    boundary = registered_path.rstrip("/")
    if not boundary:
        return candidate_path.startswith("/")
    return candidate_path == boundary or candidate_path.startswith(f"{boundary}/")


@dataclass(frozen=True, slots=True)
class SafeFetchPolicy:
    max_response_bytes: int = 8 * 1024 * 1024

    def validate_plan(self, plan: FetchPlan, source: OfficialSourcePolicy) -> str:
        candidate = urlsplit(plan.url)
        registered = urlsplit(source.base_url)
        try:
            port = candidate.port
        except ValueError as exc:
            raise ValueError("official_url_invalid_port") from exc
        if (
            candidate.scheme != "https"
            or candidate.username is not None
            or candidate.password is not None
            or port not in {None, 443}
            or not candidate.hostname
            or candidate.hostname.casefold() != (registered.hostname or "").casefold()
            or not _path_is_within(candidate.path, registered.path)
        ):
            raise ValueError("official_url_outside_allowlist")
        return candidate.hostname.casefold()

    async def validate_resolution(
        self,
        plan: FetchPlan,
        source: OfficialSourcePolicy,
        *,
        resolver: AddressResolver | None = None,
    ) -> tuple[str, ...]:
        host = self.validate_plan(plan, source)
        resolved = tuple(await (resolver or _system_resolver)(host, 443))
        if not resolved:
            raise ValueError("official_dns_no_addresses")
        validated: list[str] = []
        for raw in resolved:
            try:
                address = ipaddress.ip_address(raw)
            except ValueError as exc:
                raise ValueError("official_dns_invalid_address") from exc
            if not address.is_global:
                raise ValueError("official_dns_non_public_address")
            canonical = address.compressed
            if canonical not in validated:
                validated.append(canonical)
        return tuple(validated)

    def validate_connected_peer(
        self,
        peer: object,
        *,
        resolved_addresses: Sequence[str],
    ) -> str:
        """Verify the connected socket stayed on the DNS-pinned public address set."""

        if not isinstance(peer, tuple | list) or not peer:
            raise ValueError("official_peer_ip_unverifiable")
        raw = str(peer[0]).split("%", 1)[0]
        try:
            address = ipaddress.ip_address(raw)
            allowed = {ipaddress.ip_address(item) for item in resolved_addresses}
        except ValueError as exc:
            raise ValueError("official_peer_ip_invalid") from exc
        if not address.is_global:
            raise ValueError("official_peer_ip_non_public")
        if address not in allowed:
            raise ValueError("official_peer_ip_mismatch")
        return address.compressed

    def validate_response_headers(self, headers: Mapping[str, str]) -> None:
        declared = headers.get("content-length")
        if declared:
            try:
                size = int(declared)
            except ValueError as exc:
                raise ValueError("official_content_length_invalid") from exc
            if size < 0 or size > self.max_response_bytes:
                raise ValueError("official_response_too_large")
        encoding = headers.get("content-encoding", "").casefold().strip()
        if encoding not in _ALLOWED_ENCODINGS:
            raise ValueError("official_content_encoding_rejected")
        media_type = headers.get("content-type", "").split(";", 1)[0].casefold().strip()
        if media_type and media_type not in _ALLOWED_MEDIA_TYPES:
            raise ValueError("official_content_type_rejected")


async def _system_resolver(host: str, port: int) -> tuple[str, ...]:
    def resolve() -> tuple[str, ...]:
        rows = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        return tuple(sorted({str(row[4][0]) for row in rows}))

    return await asyncio.to_thread(resolve)
