from __future__ import annotations

import re
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


# Retrieval route for EU or foreign material that the unified research retriever
# admitted as in point (the question names that system) or as comparative context.
RESEARCH_FOREIGN_ROUTE = "unified_local_research_mode_foreign"


def admissible(
    answer_jurisdiction: str,
    source_jurisdiction: str,
    citation_data: Mapping[str, Any] | None = None,
    retrieval_route: str | None = None,
) -> bool:
    """Forum-compatible evidence, or labelled EU/comparative research material.

    Labelled foreign material may reach the drafter; each claim that relies on it
    must still name that legal system (see ``attributed_foreign_use``).
    """

    return compatible(answer_jurisdiction, source_jurisdiction, citation_data) or (
        retrieval_route == RESEARCH_FOREIGN_ROUTE
    )


# Words that show a claim (or a question) is expressly about a non-forum system,
# so its material may be used as attributed EU-law or comparative material.
_FOREIGN_MARKERS: dict[str, tuple[str, ...]] = {
    "european union": (
        "eu", "eu law", "european union", "tfeu", "teu", "cjeu", "ecj", "court of justice",
        "directive", "regulation (eu)", "member state", "member states", "internal market",
        "retained eu", "assimilated law", "single market",
    ),
    "european convention on human rights": (
        "echr", "convention right", "convention rights", "strasbourg", "ecthr",
        "european court of human rights", "european convention",
    ),
    "scotland": ("scotland", "scottish", "scots law", "court of session"),
    "northern ireland": ("northern ireland",),
    "united states": ("united states", "us law", "u.s.", "american", "federal law"),
    "comparative": (
        "comparative", "comparatively", "other jurisdictions", "other legal systems",
        "by contrast", "compared with", "elsewhere",
    ),
    "germany": ("germany", "german"),
    "france": ("france", "french"),
    "cyprus": ("cyprus", "cypriot"),
    "australia": ("australia", "australian"),
    "canada": ("canada", "canadian"),
    "ireland": ("ireland", "irish"),
}


def attributed_foreign_use(text: str, source_jurisdiction: str) -> bool:
    """True when ``text`` expressly names the source's (non-forum) legal system.

    Used for questions that are about EU or foreign law, and for claims that
    present foreign material as comparative rather than as forum law.
    """

    source = normalise(source_jurisdiction)
    if not source:
        return False
    markers = _FOREIGN_MARKERS.get(source, (source,))
    lowered = " ".join(text.casefold().split())
    return any(
        re.search(r"(?<![a-z0-9])" + re.escape(marker) + r"(?![a-z0-9])", lowered)
        for marker in markers
    )


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
    # England and Wales law (and UK-wide law) governs a question asked for either nation.
    if answer in {"england", "wales"} and source in {"england and wales", "united kingdom"}:
        return True
    if source in {"european union", "european convention on human rights"}:
        applies_in = {normalise(str(item)) for item in (citation_data or {}).get("applies_in", [])}
        return answer in applies_in
    return False
