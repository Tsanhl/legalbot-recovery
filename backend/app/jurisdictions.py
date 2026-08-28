from __future__ import annotations

from collections.abc import Mapping
from typing import Any

ALIASES = {
    "england & wales": "england and wales",
    "e&w": "england and wales",
    "ew": "england and wales",
    "uk": "united kingdom",
    "great britain": "united kingdom",
    "eu": "european union",
    "echr": "european convention on human rights",
    "us": "united states",
    "u.s": "united states",
    "u.s.": "united states",
    "usa": "united states",
    "united states of america": "united states",
    "aus": "australia",
}


def normalise(value: str) -> str:
    key = " ".join(value.casefold().split())
    return ALIASES.get(key, key)


def compatible(
    answer_jurisdiction: str,
    source_jurisdiction: str,
    citation_data: Mapping[str, Any] | None = None,
) -> bool:
    answer = normalise(answer_jurisdiction)
    source = normalise(source_jurisdiction)
    if answer == source:
        return True
    if answer == "england and wales" and source == "united kingdom":
        return True
    if source in {"european union", "european convention on human rights"}:
        applies_in = {normalise(str(item)) for item in (citation_data or {}).get("applies_in", [])}
        return answer in applies_in
    return False
