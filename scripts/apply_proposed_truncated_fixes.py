#!/usr/bin/env python3
"""Apply owner-approved truncated-span proposed fixes to draft-suite.jsonl.

SAFETY:
  - Does nothing unless BOTH --apply AND --allowlist <file> are provided.
  - Allowlist file: one case_id per line (# comments / blanks ok).
  - Only rows with action=replace_proposed and non-null new_spans are applied.
  - Never sets status to expert_annotated.
  - Never invents expert seals.
  - Never changes acceptable_source_ids.
  - Refuses if a proposed span's source_version_id is not already on the case.

Default mode (no --apply) is a dry-run that prints what would change.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUITE_PATH = ROOT / "benchmarks/evaluation/v1/draft-suite.jsonl"
PROPOSALS_PATH = (
    ROOT / "data/review_queue/expert-review/proposed-fixes-truncated/proposed-fixes.jsonl"
)


def load_allowlist(path: Path) -> set[str]:
    ids: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ids.add(line)
    return ids


def load_proposals(path: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    with path.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            row = json.loads(line)
            out[row["case_id"]] = row
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--apply",
        action="store_true",
        help="Actually write draft-suite.jsonl (REQUIRES --allowlist).",
    )
    ap.add_argument(
        "--allowlist",
        type=Path,
        help="File of case_ids explicitly approved by owner (one per line).",
    )
    ap.add_argument(
        "--proposals",
        type=Path,
        default=PROPOSALS_PATH,
        help="Path to proposed-fixes.jsonl",
    )
    ap.add_argument(
        "--suite",
        type=Path,
        default=SUITE_PATH,
        help="Path to draft-suite.jsonl",
    )
    args = ap.parse_args()

    if args.apply and not args.allowlist:
        print("ERROR: --apply requires --allowlist <file>", file=sys.stderr)
        return 2
    if args.apply and (args.allowlist is None or not args.allowlist.is_file()):
        print("ERROR: allowlist file missing", file=sys.stderr)
        return 2

    proposals = load_proposals(args.proposals)
    allow = load_allowlist(args.allowlist) if args.allowlist else set()

    if args.apply:
        targets = allow
    else:
        # Dry-run: show all replace_proposed (or intersection if allowlist given)
        targets = (
            allow
            if args.allowlist
            else {cid for cid, p in proposals.items() if p.get("action") == "replace_proposed"}
        )

    would: list[str] = []
    skipped: list[str] = []
    for cid in sorted(targets):
        p = proposals.get(cid)
        if p is None:
            skipped.append(f"{cid}: not in proposals")
            continue
        if p.get("action") != "replace_proposed" or not p.get("new_spans"):
            skipped.append(f"{cid}: action={p.get('action')} (not replace_proposed)")
            continue
        would.append(cid)

    print(f"mode: {'APPLY' if args.apply else 'DRY-RUN'}")
    print(f"would_update: {len(would)}")
    print(f"skipped: {len(skipped)}")
    for cid in would:
        p = proposals[cid]
        print(f"  {cid}: {len(p.get('old_spans') or [])} -> {len(p.get('new_spans') or [])} spans")
    for s in skipped[:20]:
        print(f"  skip {s}")

    if not args.apply:
        print("Dry-run only. Re-run with --apply --allowlist <file> to write.")
        return 0

    # Apply path
    lines_out: list[str] = []
    updated = 0
    with args.suite.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            case = json.loads(line)
            cid = case["case_id"]
            if cid in would:
                p = proposals[cid]
                acceptable = set(case.get("acceptable_source_ids") or [])
                bad = [s for s in p["new_spans"] if s.get("source_version_id") not in acceptable]
                if bad:
                    print(
                        f"ERROR: {cid} proposed span source not in acceptable_source_ids",
                        file=sys.stderr,
                    )
                    return 3
                case["exact_gold_spans"] = p["new_spans"]
                # Intentionally do NOT touch status / seals / acceptable_source_ids
                updated += 1
            lines_out.append(json.dumps(case, ensure_ascii=False) + "\n")

    args.suite.write_text("".join(lines_out), encoding="utf-8")
    print(f"updated {updated} cases in {args.suite}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
