"""Shared deterministic text metrics used at runtime and in review projections."""

from __future__ import annotations

import re

_WORD = re.compile(r"\b[\w’'-]+\b")


def word_count(text: str) -> int:
    """Count words using the release/runtime token-boundary contract."""

    return len(_WORD.findall(text))
