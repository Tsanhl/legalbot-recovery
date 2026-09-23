#!/usr/bin/env python3
"""Rebuild the 330 candidate answers. Does not complete qualified legal review."""

from __future__ import annotations

import json

from app.evaluation.ge_answer_reconstruction import run_answer_reconstruction
from app.evaluation.ge_phase2_progress import (
    NOT_STARTED,
    REVISED_ANSWERS_AWAITING_INDEPENDENT_BLIND_REVIEW,
)


def main() -> int:
    result = run_answer_reconstruction()
    state = result.get("state") or {}
    payload = {
        "result": result.get("result"),
        "pack": result.get("output"),
        "blind_zip": result.get("blind_zip"),
        "overall_state": state.get("overall_state")
        or REVISED_ANSWERS_AWAITING_INDEPENDENT_BLIND_REVIEW,
        "qualified_legal_review": state.get("qualified_legal_review") or NOT_STARTED,
        "answer_legal_gold": state.get("answer_legal_gold") or NOT_STARTED,
        "professional_legal_sign_off": state.get("professional_legal_sign_off"),
        "reconstruction_source_counts": state.get("reconstruction_source_counts"),
        "answer_readiness_counts": state.get("answer_readiness_counts"),
        "readiness": result.get("readiness"),
    }
    print(json.dumps(payload, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
