#!/usr/bin/env python3
"""Issue-led Priority 1 official intake into an evaluation sidecar.

Dedupes against staged sidecar titles only, not the 85-source recovery-b
corpus. Does not mutate catalog.sqlite3, ACTIVE indexes, gold, or admission.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.evaluation.ge_factual_gap_fill import (  # noqa: E402
    PRIORITY1_TITLES,
    existing_sidecar_titles,
    fill_known_titles,
    next_priority1_pack,
)


def main() -> int:
    already = existing_sidecar_titles(ROOT)
    output = next_priority1_pack(ROOT)
    manifest = fill_known_titles(
        titles=PRIORITY1_TITLES,
        output=output,
        already_titled=already,
        project_root=ROOT,
    )
    print(
        json.dumps(
            {
                "output": str(output),
                "ingested_count": manifest.get("ingested_count"),
                "failed_count": manifest.get("failed_count"),
                "skipped_count": manifest.get("skipped_count"),
                "admitted": False,
                "legal_gold": False,
                "live_catalogue_insert": False,
                "deduped_against": manifest.get("deduped_against"),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
