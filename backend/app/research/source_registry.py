"""Validated policies for official and scholarly online sources."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class ContentMode(StrEnum):
    FULL_TEXT = "full_text"
    METADATA_ONLY = "metadata_only"
    ITEM_LICENCE_REQUIRED = "item_licence_required"


class OnlineDisposition(StrEnum):
    STAGED_ONLY = "staged_only"


@dataclass(frozen=True, slots=True)
class SourceLicence:
    name: str
    version: str | None = None
    url: str | None = None


@dataclass(frozen=True, slots=True)
class OfficialSourcePolicy:
    source_id: str
    name: str
    base_url: str
    authority_tier: str
    jurisdictions: tuple[str, ...]
    content_mode: ContentMode
    online_disposition: OnlineDisposition
    licence: SourceLicence
    machine_access: tuple[str, ...]
    currentness: str
    additional_permission_required: bool
    permission_note: str | None = None

    def validate(self) -> None:
        if not self.source_id or not self.base_url.startswith("https://"):
            raise ValueError("source id and HTTPS base URL are required")
        if self.online_disposition is not OnlineDisposition.STAGED_ONLY:
            raise ValueError("online sources must remain staged-only")
        if self.source_id == "find_case_law" and self.content_mode is not ContentMode.METADATA_ONLY:
            raise ValueError("Find Case Law must remain metadata-only without a separate licence")


class OfficialSourceRegistry:
    def __init__(self, policies: tuple[OfficialSourcePolicy, ...]) -> None:
        self._policies = {policy.source_id: policy for policy in policies}
        if len(self._policies) != len(policies):
            raise ValueError("duplicate official source id")
        for policy in policies:
            policy.validate()

    @classmethod
    def load(cls, path: str | Path) -> OfficialSourceRegistry:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if payload.get("schema") != "legalbot.official-source-registry.v1":
            raise ValueError("unsupported official source registry schema")
        policies: list[OfficialSourcePolicy] = []
        for raw in payload.get("sources", []):
            licence = SourceLicence(**raw["licence"])
            policies.append(
                OfficialSourcePolicy(
                    source_id=raw["id"],
                    name=raw["name"],
                    base_url=raw["base_url"],
                    authority_tier=raw["authority_tier"],
                    jurisdictions=tuple(raw["jurisdictions"]),
                    content_mode=ContentMode(raw["content_mode"]),
                    online_disposition=OnlineDisposition(raw["online_disposition"]),
                    licence=licence,
                    machine_access=tuple(raw.get("machine_access", [])),
                    currentness=raw["currentness"],
                    additional_permission_required=bool(
                        raw.get("additional_permission_required", False)
                    ),
                    permission_note=raw.get("permission_note"),
                )
            )
        return cls(tuple(policies))

    def get(self, source_id: str) -> OfficialSourcePolicy:
        try:
            return self._policies[source_id]
        except KeyError as exc:
            raise KeyError(f"unregistered online source: {source_id}") from exc

    def all(self) -> tuple[OfficialSourcePolicy, ...]:
        return tuple(sorted(self._policies.values(), key=lambda item: item.source_id))
