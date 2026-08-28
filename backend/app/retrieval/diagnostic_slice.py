"""Diagnostic slice builds are never production candidates.

The 17 August 2026 slice generation may be inspected and used for retrieval
smoke tests. It must not become CURRENT.candidate_build_id, a production
Stage A candidate, a production-promotion attestation target, or ACTIVE.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

DIAGNOSTIC_SLICE_BUILD_ID = "current-law-ew-core-fp16-v111-20260817"
DIAGNOSTIC_SLICE_CORPUS_ID = "current-law-ew-core-slice-v1"
FULL_CANDIDATE_ID_PREFIX = "current-law-ew-full-"
NON_PROMOTABLE_CLASS = "NON_PROMOTABLE_DIAGNOSTIC_SLICE"


def is_diagnostic_slice_build(
    build_id: str | None,
    *,
    corpus_id: str | None = None,
    pointer: Mapping[str, Any] | None = None,
) -> bool:
    ident = str(build_id or "")
    if not ident:
        return False
    marked = {DIAGNOSTIC_SLICE_BUILD_ID}
    if pointer is not None:
        extra = str(pointer.get("diagnostic_slice_build_id") or "")
        if extra:
            marked.add(extra)
    if ident in marked:
        return True
    if ident.startswith(f"{DIAGNOSTIC_SLICE_BUILD_ID}-"):
        return True
    del corpus_id
    return False


def is_current_law_full_corpus(corpus_id: str | None) -> bool:
    return str(corpus_id or "").startswith(FULL_CANDIDATE_ID_PREFIX)


def refuse_diagnostic_slice_for_production(
    build_id: str | None,
    *,
    purpose: str,
    corpus_id: str | None = None,
    pointer: Mapping[str, Any] | None = None,
) -> None:
    if is_diagnostic_slice_build(build_id, corpus_id=corpus_id, pointer=pointer):
        raise ValueError(f"diagnostic slice {build_id} cannot be used for {purpose}")


def allowed_index_statuses_for_pin(build_id: str | None) -> frozenset[str]:
    """Diagnostic slice may be pinned unscored for non-promotable canary only."""

    if is_diagnostic_slice_build(build_id):
        return frozenset({"candidate", "active", "built_unscored"})
    return frozenset({"candidate", "active"})


def bind_current_candidate_build_id(
    pointer: Mapping[str, Any],
    candidate_build_id: str | None,
) -> dict[str, Any]:
    """Return a CURRENT pointer payload that never stores the diagnostic slice."""

    payload = dict(pointer)
    if candidate_build_id:
        refuse_diagnostic_slice_for_production(
            candidate_build_id,
            purpose="CURRENT.candidate_build_id",
            pointer=payload,
        )
        payload["candidate_build_id"] = candidate_build_id
    else:
        payload["candidate_build_id"] = None
    slice_id = str(payload.get("diagnostic_slice_build_id") or "")
    if slice_id:
        payload["diagnostic_slice_build_id"] = slice_id
    return payload
