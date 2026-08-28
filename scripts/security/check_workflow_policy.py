"""Scan GitHub workflow executable steps for forbidden live-operation tokens.

The token list is assembled from fragments so this file can name the policy
without putting a complete live command into a workflow YAML.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

WORKFLOW_DIR = Path(".github/workflows")

FORBIDDEN_LIVE_TOKENS = (
    "find-generic-" + "password",
    "add-generic-" + "password",
    "live_evaluation_suite.py " + "generate",
    "legalbot " + "live60 generate",
    "legalbot " + "promote",
    "huggingface" + ".co",
    "openai" + ".com",
    "ACTIVE" + ".json",
    "PREVIOUS" + ".json",
    "O-" + "04",
    "./" + "start.sh",
    "bash " + "start.sh",
)


def executable_run_scripts(text: str) -> list[str]:
    """Return only workflow ``run:`` scalars and block scalars."""

    scripts: list[str] = []
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        if stripped.startswith("run:"):
            rest = stripped[4:].strip()
            if rest.startswith("|") or rest.startswith(">"):
                block: list[str] = []
                index += 1
                while index < len(lines):
                    block_line = lines[index]
                    if block_line.strip() == "":
                        block.append(block_line)
                        index += 1
                        continue
                    block_indent = len(block_line) - len(block_line.lstrip())
                    if block_indent <= indent:
                        break
                    block.append(block_line)
                    index += 1
                scripts.append("\n".join(block))
                continue
            if rest:
                scripts.append(rest)
        index += 1
    return scripts


def forbidden_hits(text: str) -> list[str]:
    hits: list[str] = []
    lowered = text.lower()
    if "keychain" in lowered:
        hits.append("keychain")
    for token in FORBIDDEN_LIVE_TOKENS:
        if token.lower() in lowered:
            hits.append(token)
    return hits


def scan_workflow_text(text: str) -> list[str]:
    hits: list[str] = []
    for script in executable_run_scripts(text):
        hits.extend(forbidden_hits(script))
    return hits


def scan_workflow_dir(root: Path) -> list[str]:
    failures: list[str] = []
    for path in sorted(root.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        for token in scan_workflow_text(text):
            failures.append(f"{path} executable step contains forbidden token: {token}")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workflows",
        type=Path,
        default=WORKFLOW_DIR,
        help="Directory of GitHub workflow YAML files",
    )
    args = parser.parse_args(argv)
    failures = scan_workflow_dir(args.workflows)
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("workflow security scan passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
