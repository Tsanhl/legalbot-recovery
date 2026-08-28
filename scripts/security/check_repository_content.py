#!/usr/bin/env python3
"""Fail closed on tracked secrets and private paths in release artifacts."""

from __future__ import annotations

import json
import re
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(
        rb"(?i)\b(?:api[_-]?key|client[_-]?secret|password|access[_-]?token)\b"
        rb"\s*[:=]\s*['\"][^'\"\r\n]{12,}['\"]"
    ),
)
PRIVATE_PATH_PATTERNS = (
    re.compile(rb"/(?:Users|home)/[^/\s\"']+/"),
    re.compile(rb"[A-Za-z]:\\Users\\[^\\\s\"']+\\"),
)
ARTIFACT_PREFIXES = (
    "benchmarks/",
    "config/",
    "data/evaluations/",
    "docs/status/",
)


def _tracked_members() -> tuple[str, ...]:
    completed = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        shell=False,
    )
    return tuple(item.decode("utf-8") for item in completed.stdout.split(b"\0") if item)


def _is_release_artifact(member: str) -> bool:
    return (
        member.startswith(ARTIFACT_PREFIXES)
        or (member.startswith("Live60-") and member.endswith((".json", ".jsonl")))
    ) and member.endswith((".json", ".jsonl", ".yaml", ".yml"))


def check_repository_content() -> dict[str, int | str | bool]:
    members = _tracked_members()
    secret_hits = 0
    private_path_hits = 0
    scanned_bytes = 0
    artifact_count = 0
    for member in members:
        path = ROOT / member
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("tracked repository member is not a regular file")
        raw = path.read_bytes()
        scanned_bytes += len(raw)
        if any(pattern.search(raw) for pattern in SECRET_PATTERNS):
            secret_hits += 1
        if _is_release_artifact(member):
            artifact_count += 1
            if any(pattern.search(raw) for pattern in PRIVATE_PATH_PATTERNS):
                private_path_hits += 1
    result: dict[str, int | str | bool] = {
        "schema": "legalbot.repository-content-scan.v1",
        "tracked_member_count": len(members),
        "release_artifact_count": artifact_count,
        "scanned_byte_count": scanned_bytes,
        "secret_hit_count": secret_hits,
        "private_path_hit_count": private_path_hits,
        "passed": secret_hits == 0 and private_path_hits == 0,
    }
    return result


def main() -> int:
    try:
        result = check_repository_content()
    except Exception as exc:
        print(
            json.dumps(
                {
                    "schema": "legalbot.repository-content-scan.v1",
                    "passed": False,
                    "reason_code": type(exc).__name__.casefold(),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0 if result["passed"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
