#!/usr/bin/env python3
"""Fetch official sources the baseline coverage check found missing (owner approved 2026-09-26).

Downloads from the allowlisted official hosts only (Find Case Law and
legislation.gov.uk) into data/official-staging/2026-09-26-baseline-gap with a
hash manifest. Nothing is ingested, embedded, reviewed or admitted here: the
files are added to the catalogue and unified index after the main embedding
finishes, then checked by scripts/verify_unified_sources.py.
"""

from __future__ import annotations

import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.evaluation.ge_factual_gap_fill import default_fetch  # noqa: E402

OUT = ROOT / "data/official-staging/2026-09-26-baseline-gap"
SOURCES = {
    "Lachaux v Independent Print Ltd [2019] UKSC 27": "https://caselaw.nationalarchives.gov.uk/uksc/2019/27/data.xml",
    "Stack v Dowden [2007] UKHL 17": "https://caselaw.nationalarchives.gov.uk/ukhl/2007/17/data.xml",
    "MWB v Rock Advertising [2018] UKSC 24": "https://caselaw.nationalarchives.gov.uk/uksc/2018/24/data.xml",
    "R v Clinton [2012] EWCA Crim 2": "https://caselaw.nationalarchives.gov.uk/ewca/crim/2012/2/data.xml",
    "Geary v Rankine [2012] EWCA Civ 555": "https://caselaw.nationalarchives.gov.uk/ewca/civ/2012/555/data.xml",
    "Vedanta Resources plc v Lungowe [2019] UKSC 20": "https://caselaw.nationalarchives.gov.uk/uksc/2019/20/data.xml",
    "Limbu v Dyson Technology Ltd [2024] EWCA Civ 1564": "https://caselaw.nationalarchives.gov.uk/ewca/civ/2024/1564/data.xml",
    "Goodlife Foods Ltd v Hall Fire Protection Ltd [2018] EWCA Civ 1371": "https://caselaw.nationalarchives.gov.uk/ewca/civ/2018/1371/data.xml",
    "Link Lending Ltd v Bustard [2010] EWCA Civ 424": "https://caselaw.nationalarchives.gov.uk/ewca/civ/2010/424/data.xml",
    "Bhullar v Bhullar [2003] EWCA Civ 424": "https://caselaw.nationalarchives.gov.uk/ewca/civ/2003/424/data.xml",
    "Jones v Kernott [2011] UKSC 53": "https://caselaw.nationalarchives.gov.uk/uksc/2011/53/data.xml",
    "Criminal Justice and Immigration Act 2008": "https://www.legislation.gov.uk/ukpga/2008/4/data.xml",
    "Wills Act 1968": "https://www.legislation.gov.uk/ukpga/1968/28/data.xml",
}


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, object] = {
        "schema": "legalbot.official-staging.v1",
        "purpose": "baseline coverage gaps; owner approved fetch 2026-09-26",
        "fetched_at": datetime.now(UTC).isoformat(),
        "items": {},
    }
    for title, url in SOURCES.items():
        result = default_fetch(url)
        entry: dict[str, object] = {"url": url, "ok": bool(result.get("ok"))}
        if result.get("ok"):
            name = url.split("gov.uk/")[1].replace("/", "_")
            (OUT / name).write_bytes(result["body"])
            entry.update({"file": name, "sha256": result["sha256"], "bytes": result["bytes"]})
        else:
            entry["error"] = result.get("error")
        manifest["items"][title] = entry  # type: ignore[index]
        print(f"{'ok ' if entry['ok'] else 'FAIL'} {title} {entry.get('error', '')}", flush=True)
        time.sleep(0.5)
    (OUT / "MANIFEST.json").write_text(json.dumps(manifest, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
