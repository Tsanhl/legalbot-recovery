"""Fail python-static CI if Ruff or mypy regressions exceed the checked-in baseline."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASELINE_PATH = ROOT / "config" / "ci-static-baseline.json"


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)


def ruff_error_count() -> int:
    result = _run(["uv", "run", "ruff", "check", "backend", "scripts", "--output-format", "json"])
    payload = json.loads(result.stdout or "[]")
    if not isinstance(payload, list):
        raise SystemExit("ruff JSON output was not a list")
    return len(payload)


def mypy_counts() -> tuple[int, int]:
    result = _run(["uv", "run", "mypy", "backend/app"])
    text = result.stdout + result.stderr
    match = re.search(r"Found (\d+) errors? in (\d+) files?", text)
    if match:
        return int(match.group(1)), int(match.group(2))
    if result.returncode == 0:
        return 0, 0
    raise SystemExit("mypy did not report a parseable error summary")


def main() -> int:
    baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    ruff_count = ruff_error_count()
    mypy_errors, mypy_files = mypy_counts()
    ruff_max = int(baseline["ruff"]["max_error_count"])
    mypy_max = int(baseline["mypy"]["max_error_count"])
    files_max = int(baseline["mypy"]["max_file_count"])
    failures: list[str] = []
    if ruff_count > ruff_max:
        failures.append(f"ruff errors {ruff_count} exceed baseline {ruff_max}")
    if mypy_errors > mypy_max:
        failures.append(f"mypy errors {mypy_errors} exceed baseline {mypy_max}")
    if mypy_files > files_max:
        failures.append(f"mypy files {mypy_files} exceed baseline {files_max}")
    print(
        json.dumps(
            {
                "ruff_error_count": ruff_count,
                "mypy_error_count": mypy_errors,
                "mypy_file_count": mypy_files,
                "baseline": baseline,
            },
            indent=2,
            sort_keys=True,
        )
    )
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
