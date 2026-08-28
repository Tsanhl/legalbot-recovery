"""Canonical source identities and privacy-safe local locator handling."""

from __future__ import annotations

import hashlib
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .models import SourceIdentity

_TRACKING_PARAMETERS = {
    "fbclid",
    "gclid",
    "mc_cid",
    "mc_eid",
    "ref",
    "source",
    "utm_campaign",
    "utm_content",
    "utm_medium",
    "utm_source",
    "utm_term",
}


def canonical_url(url: str) -> str:
    parts = urlsplit(url.strip())
    if parts.scheme.lower() not in {"http", "https"} or not parts.netloc:
        raise ValueError("canonical URLs must be absolute HTTP(S) URLs")
    host = parts.hostname.lower() if parts.hostname else ""
    port = parts.port
    if port and not (
        (parts.scheme.lower() == "http" and port == 80)
        or (parts.scheme.lower() == "https" and port == 443)
    ):
        host = f"{host}:{port}"
    path = re.sub(r"/{2,}", "/", parts.path or "/")
    if path != "/":
        path = path.rstrip("/")
    query = urlencode(
        sorted(
            (k, v)
            for k, v in parse_qsl(parts.query, keep_blank_values=True)
            if k.lower() not in _TRACKING_PARAMETERS
        )
    )
    return urlunsplit((parts.scheme.lower(), host, path, query, ""))


def canonical_source_identity(
    scheme: str,
    value: str,
    *,
    version: str | None = None,
) -> SourceIdentity:
    normalized_scheme = scheme.strip().lower().replace(" ", "_")
    normalized = value.strip()
    if normalized_scheme == "doi":
        normalized = re.sub(
            r"^(?:https?://(?:dx\.)?doi\.org/|doi:\s*)", "", normalized, flags=re.I
        ).lower()
    elif normalized_scheme in {"url", "official_uri"}:
        normalized = canonical_url(normalized)
    elif normalized_scheme == "neutral_citation":
        normalized = re.sub(r"\s+", " ", normalized).strip().upper()
    elif normalized_scheme in {"uk_legislation", "fclid", "isbn", "opaque_local"}:
        normalized = re.sub(r"\s+", "", normalized).lower()
    if not normalized_scheme or not normalized:
        raise ValueError("source identity scheme and value are required")
    return SourceIdentity(normalized_scheme, normalized, version.strip() if version else None)


def private_locator_digest(locator: str, *, salt: bytes) -> str:
    """Return an irreversible locator reference without leaking user paths."""

    if not salt:
        raise ValueError("a non-empty deployment salt is required")
    digest = hashlib.sha256(salt + b"\0" + locator.encode("utf-8", "surrogatepass")).hexdigest()
    return f"sha256:{digest}"
