#!/usr/bin/env python3
"""When GE results show a knowledge gap, fetch official sources and index them."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path.cwd()
FILL = ROOT / "scripts" / "fill_ge_knowledge_gaps.py"
GE = ROOT / "data/evaluations/general-enquiries"
FAIL_CLOSED = {
    "cable & wireless plc v ibm united kingdom ltd",
    "mediation act 2025",
    "the mediation act 2025",
    "unidentified mediation act 2025",
}
ALIASES = {
    "wills act 1837 section 9 as it had effect on 2024-01-15": (
        "wills act 1837 (as at 2024-01-15)"
    ),
}
SEARCHABLE = re.compile(
    r"\b(act|regulations?|order|directive|treaty|convention|statute|\bv\b)\b",
    re.IGNORECASE,
)
CONTEXT = (
    "Knowledge-gap fill ran against official sources only: legislation.gov.uk "
    "and Find Case Law. Locator-bound chunks were indexed into the evaluation "
    "sidecar. Not gold, not admitted, not ACTIVE, not catalog.sqlite3."
)


def _norm(title: str) -> str:
    key = re.sub(r"\s+", " ", str(title or "").casefold().replace("’", "'")).strip()
    return ALIASES.get(key, key)


def _staged_titles() -> set[str]:
    titles: set[str] = set()
    if not GE.is_dir():
        return titles
    for manifest in GE.glob("LegalBot-GE-*/STAGED-SOURCE-MANIFEST.json"):
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for row in data.get("sources") or []:
            if isinstance(row, dict) and row.get("title"):
                titles.add(_norm(str(row["title"])))
    return titles


def _latest_results() -> Path | None:
    preferred = GE / "LegalBot-GE-2026-09-02-visible-331-diagnostic-r1/visible/RESULTS.jsonl"
    if preferred.is_file():
        return preferred
    candidates = sorted(
        GE.glob("LegalBot-GE-*/visible/RESULTS.jsonl"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def _remaining() -> list[str]:
    results = _latest_results()
    if results is None:
        return []
    staged = _staged_titles()
    missing: list[str] = []
    seen: set[str] = set()
    try:
        with results.open(encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                row = json.loads(line)
                for name in row.get("known_missing_primary_authorities") or []:
                    key = _norm(str(name))
                    if key in seen or key in staged or key in FAIL_CLOSED:
                        continue
                    if "mediation act 2025" in key:
                        continue
                    if not SEARCHABLE.search(key) and " v " not in f" {key} ":
                        continue
                    seen.add(key)
                    missing.append(str(name))
    except (OSError, json.JSONDecodeError):
        return []
    return missing


def _should_run(payload: dict) -> bool:
    file_path = str(payload.get("file_path") or payload.get("path") or payload.get("file") or "")
    command = str(payload.get("command") or payload.get("command_str") or "")
    if "fill_ge_knowledge_gaps.py" in command:
        return False
    if "RESULTS.jsonl" in file_path.replace("\\", "/"):
        return True
    lowered = command.casefold()
    return any(
        token in lowered
        for token in (
            "run_ge_retrieval_training_cycle",
            "results.jsonl",
            "ge_diagnostic",
            "visible-331",
        )
    )


def _run_fill() -> str:
    env = os.environ.copy()
    env.setdefault("PYTHONPATH", f"{ROOT / 'backend'}:{ROOT}")
    try:
        completed = subprocess.run(
            ["uv", "run", "python", str(FILL)],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=240,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"official gap fill did not finish: {type(exc).__name__}"
    output = (completed.stdout or completed.stderr or "").strip()
    if len(output) > 1200:
        output = output[:1200] + "…"
    return output or f"official gap fill exit {completed.returncode}"


def main() -> int:
    payload: dict = {}
    try:
        raw = sys.stdin.read()
        if raw.strip():
            payload = json.loads(raw)
    except json.JSONDecodeError:
        payload = {}
    remaining = _remaining()
    out: dict[str, str] = {}
    if remaining and _should_run(payload):
        summary = _run_fill()
        still = _remaining()
        out["additional_context"] = CONTEXT + " Fill output: " + summary
        if still:
            out["followup_message"] = (
                "Official knowledge-gap fill still has unresolved titles: "
                + "; ".join(still)
                + ". Keep searching legislation.gov.uk / Find Case Law only. "
                "Do not set gold or write catalog.sqlite3."
            )
    elif remaining:
        out["followup_message"] = (
            "GE knowledge gaps remain. Fetch official XML/PDF from "
            "legislation.gov.uk or Find Case Law and index locator-bound chunks now."
        )
        out["additional_context"] = CONTEXT
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
