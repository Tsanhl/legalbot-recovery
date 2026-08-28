from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

import httpcore
import pytest

from app.research.adapters import FetchPlan
from app.research.runtime import AllowlistedHttpFetcher, OnlineFetchError
from app.research.source_registry import OfficialSourceRegistry

PROJECT_ROOT = Path(__file__).resolve().parents[2]
REGISTRY = OfficialSourceRegistry.load(PROJECT_ROOT / "config" / "official_sources.json")
POLICY = REGISTRY.get("legislation_gov_uk")
PLAN = FetchPlan(
    source_id="legislation_gov_uk",
    url="https://www.legislation.gov.uk/ukpga/2026/1/data.xml",
    expected_content_mode=POLICY.content_mode,
    headers={"Accept": "application/xml"},
)


class ScriptedStream(httpcore.AsyncNetworkStream):
    def __init__(self, *, peer: str, response: bytes) -> None:
        self.peer = peer
        self.response = response
        self.writes: list[bytes] = []
        self.tls_hostnames: list[str | None] = []
        self.closed = False

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        del timeout
        chunk, self.response = self.response[:max_bytes], self.response[max_bytes:]
        return chunk

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        del timeout
        self.writes.append(buffer)

    async def aclose(self) -> None:
        self.closed = True

    async def start_tls(
        self,
        ssl_context: Any,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        del ssl_context, timeout
        self.tls_hostnames.append(server_hostname)
        return self

    def get_extra_info(self, info: str) -> Any:
        if info == "server_addr":
            return (self.peer, 443)
        if info == "is_readable":
            return False
        return None


class ScriptedBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, streams: list[ScriptedStream]) -> None:
        self.streams = list(streams)
        self.connections: list[tuple[str, int]] = []

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        del timeout, local_address, socket_options
        self.connections.append((host, port))
        return self.streams.pop(0)

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        del path, timeout, socket_options
        raise AssertionError("Unix sockets are forbidden")

    async def sleep(self, seconds: float) -> None:
        del seconds


def response(
    status: str = "200 OK",
    *,
    headers: tuple[tuple[str, str], ...] = (("Content-Type", "application/xml"),),
    body: bytes = b"<ok>",
) -> bytes:
    rows = [f"HTTP/1.1 {status}", *(f"{key}: {value}" for key, value in headers)]
    rows.extend((f"Content-Length: {len(body)}", "Connection: close", "", ""))
    return "\r\n".join(rows).encode("ascii") + body


@pytest.mark.asyncio
async def test_fetch_pins_validated_ip_and_preserves_tls_hostname() -> None:
    stream = ScriptedStream(peer="8.8.8.8", response=response())
    backend = ScriptedBackend([stream])
    resolver_calls: list[tuple[str, int]] = []

    async def resolver(host: str, port: int) -> tuple[str, ...]:
        resolver_calls.append((host, port))
        return ("8.8.8.8",)

    fetched = await AllowlistedHttpFetcher(
        resolver=resolver,
        network_backend=backend,
    ).fetch(PLAN, POLICY)

    assert fetched.content == b"<ok>"
    assert resolver_calls == [("www.legislation.gov.uk", 443)]
    assert backend.connections == [("8.8.8.8", 443)]
    assert stream.tls_hostnames == ["www.legislation.gov.uk"]
    assert b"Host: www.legislation.gov.uk" in b"".join(stream.writes)


@pytest.mark.asyncio
async def test_peer_ip_rebinding_is_rejected_before_tls_or_http_write() -> None:
    stream = ScriptedStream(peer="127.0.0.1", response=response())
    backend = ScriptedBackend([stream])

    async def resolver(host: str, port: int) -> tuple[str, ...]:
        del host, port
        return ("8.8.8.8",)

    with pytest.raises(OnlineFetchError) as caught:
        await AllowlistedHttpFetcher(
            resolver=resolver,
            network_backend=backend,
        ).fetch(PLAN, POLICY)

    assert caught.value.code == "official_peer_ip_non_public"
    assert backend.connections == [("8.8.8.8", 443)]
    assert stream.closed
    assert stream.tls_hostnames == []
    assert stream.writes == []


@pytest.mark.asyncio
async def test_public_peer_outside_pinned_dns_set_is_rejected_before_write() -> None:
    stream = ScriptedStream(peer="1.1.1.1", response=response())
    backend = ScriptedBackend([stream])

    async def resolver(host: str, port: int) -> tuple[str, ...]:
        del host, port
        return ("8.8.8.8",)

    with pytest.raises(OnlineFetchError) as caught:
        await AllowlistedHttpFetcher(
            resolver=resolver,
            network_backend=backend,
        ).fetch(PLAN, POLICY)

    assert caught.value.code == "official_peer_ip_mismatch"
    assert stream.closed
    assert stream.tls_hostnames == []
    assert stream.writes == []


@pytest.mark.asyncio
async def test_private_dns_result_never_reaches_transport() -> None:
    backend = ScriptedBackend([])

    async def resolver(host: str, port: int) -> tuple[str, ...]:
        del host, port
        return ("169.254.169.254",)

    with pytest.raises(OnlineFetchError) as caught:
        await AllowlistedHttpFetcher(
            resolver=resolver,
            network_backend=backend,
        ).fetch(PLAN, POLICY)

    assert caught.value.code == "official_dns_non_public_address"
    assert backend.connections == []


@pytest.mark.asyncio
async def test_every_same_origin_redirect_is_resolved_and_pinned_again() -> None:
    first = ScriptedStream(
        peer="8.8.8.8",
        response=response(
            "302 Found",
            headers=(("Location", "/ukpga/2026/1/redirected.xml"),),
            body=b"",
        ),
    )
    second = ScriptedStream(peer="1.1.1.1", response=response(body=b"<final/>"))
    backend = ScriptedBackend([first, second])
    answers = iter((("8.8.8.8",), ("1.1.1.1",)))
    resolver_calls = 0

    async def resolver(host: str, port: int) -> tuple[str, ...]:
        nonlocal resolver_calls
        assert (host, port) == ("www.legislation.gov.uk", 443)
        resolver_calls += 1
        return next(answers)

    fetched = await AllowlistedHttpFetcher(
        resolver=resolver,
        network_backend=backend,
    ).fetch(PLAN, POLICY)

    assert fetched.content == b"<final/>"
    assert resolver_calls == 2
    assert backend.connections == [("8.8.8.8", 443), ("1.1.1.1", 443)]
    assert first.tls_hostnames == ["www.legislation.gov.uk"]
    assert second.tls_hostnames == ["www.legislation.gov.uk"]


@pytest.mark.asyncio
async def test_redirect_rebinding_to_private_dns_is_rejected_before_second_connect() -> None:
    first = ScriptedStream(
        peer="8.8.8.8",
        response=response(
            "302 Found",
            headers=(("Location", "/ukpga/2026/1/private.xml"),),
            body=b"",
        ),
    )
    backend = ScriptedBackend([first])
    answers = iter((("8.8.8.8",), ("127.0.0.1",)))

    async def resolver(host: str, port: int) -> tuple[str, ...]:
        del host, port
        return next(answers)

    with pytest.raises(OnlineFetchError) as caught:
        await AllowlistedHttpFetcher(
            resolver=resolver,
            network_backend=backend,
        ).fetch(PLAN, POLICY)

    assert caught.value.code == "official_dns_non_public_address"
    assert backend.connections == [("8.8.8.8", 443)]
