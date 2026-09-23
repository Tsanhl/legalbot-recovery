#!/usr/bin/env python3
"""Run the owner-authorized GE AI factual and 70+ quality review."""

from __future__ import annotations

import json

from app.evaluation.ge_ai_auto_quality_review import run_campaign


def main() -> int:
    print(json.dumps(run_campaign(), indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
