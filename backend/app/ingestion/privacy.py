"""Deterministic, non-reversible aliases for personal data in public metadata."""

from __future__ import annotations

import hashlib
import hmac
import re


class PIIAliaser:
    def __init__(self, secret: bytes) -> None:
        if len(secret) < 16:
            raise ValueError("alias secret must be at least 16 bytes")
        self._secret = secret

    def alias(self, value: str, *, category: str = "person") -> str:
        safe_category = re.sub(r"[^a-z0-9_]+", "_", category.lower()).strip("_") or "entity"
        digest = hmac.new(
            self._secret,
            f"{safe_category}\0{value}".encode("utf-8", "surrogatepass"),
            hashlib.sha256,
        ).hexdigest()[:20]
        return f"{safe_category}_{digest}"

    def path_alias(self, path: str) -> str:
        suffix = ""
        leaf = path.rsplit("/", 1)[-1]
        if "." in leaf:
            candidate = leaf.rsplit(".", 1)[-1].lower()
            if re.fullmatch(r"[a-z0-9]{1,8}", candidate):
                suffix = f".{candidate}"
        return f"{self.alias(path, category='file')}{suffix}"
