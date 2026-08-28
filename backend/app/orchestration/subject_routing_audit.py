"""Privacy-safe mixed-topic routing audit. Never stores question text."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ..retrieval.service import _query_subjects
from .classifier import CLASSIFIER_VERSION

SUBJECT_ROUTING_AUDIT_SCHEMA = "legalbot.subject-routing-audit.v1"


def build_subject_routing_audit(
    recognised_subjects: Sequence[str],
) -> dict[str, Any]:
    """Record which subjects were chosen and how they expand.

    Mixed labels expand to the catalogue family instead of collapsing to one
    keyword filter. An empty recognition set is a broad unfiltered search.
    """

    recognised = tuple(item for item in recognised_subjects if item)
    expanded: set[str] = set()
    for subject in recognised:
        expanded.update(_query_subjects(subject))
    if not recognised:
        filter_mode = "broad_unfiltered"
    elif len(recognised) > 1:
        filter_mode = "mixed_prefilter"
    else:
        filter_mode = "single_prefilter"
    return {
        "schema": SUBJECT_ROUTING_AUDIT_SCHEMA,
        "classifier_version": CLASSIFIER_VERSION,
        "recognised_subject_count": len(recognised),
        "recognised_subjects": list(recognised),
        "expanded_catalogue_subject_count": len(expanded),
        "expanded_catalogue_subjects": sorted(expanded),
        "mixed": len(recognised) > 1,
        "filter_mode": filter_mode,
        "elasticsearch_used": False,
    }
