#!/usr/bin/env python3
"""Validate the non-authorizing v1.11 state, ledger, and archive records."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
STATUS_ROOT = ROOT / "docs/status"
SNAPSHOT = STATUS_ROOT / "v111-integration-state-snapshot-20260822.json"
SNAPSHOT_SCHEMA = STATUS_ROOT / "schemas/v111-integration-state-snapshot.schema.json"
LEDGER = STATUS_ROOT / "v111-integration-commit-ledger-20260822.json"
LEDGER_SCHEMA = STATUS_ROOT / "schemas/v111-integration-commit-ledger.schema.json"
ARCHIVE_RECEIPT = STATUS_ROOT / "v111-deferred-archive-receipt-20260822.json"


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise RuntimeError("integration record must be a JSON object")
    return value


def _git(*arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        shell=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("integration record Git verification failed")
    return completed.stdout


def _validate_schema(instance: dict[str, Any], schema_path: Path) -> None:
    schema = _load_object(schema_path)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(instance)


def _contains_private_absolute_path(value: Any) -> bool:
    if isinstance(value, str):
        return value.startswith("/Users/") or value.startswith("/home/")
    if isinstance(value, list):
        return any(_contains_private_absolute_path(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_private_absolute_path(item) for item in value.values())
    return False


def validate_records() -> dict[str, Any]:
    snapshot = _load_object(SNAPSHOT)
    ledger = _load_object(LEDGER)
    archive = _load_object(ARCHIVE_RECEIPT)
    _validate_schema(snapshot, SNAPSHOT_SCHEMA)
    _validate_schema(ledger, LEDGER_SCHEMA)

    if any(_contains_private_absolute_path(value) for value in (snapshot, ledger, archive)):
        raise RuntimeError("integration record contains a private absolute path")
    entries = ledger["entries"]
    if ledger["entry_count"] != len(entries):
        raise RuntimeError("integration ledger entry count mismatch")
    entry_shas = [str(item["sha"]) for item in entries]
    if len(entry_shas) != len(set(entry_shas)):
        raise RuntimeError("integration ledger contains duplicate commits")
    profiles = ledger["evidence_profiles"]
    if any(item["profile"] not in profiles for item in entries):
        raise RuntimeError("integration ledger references an unknown evidence profile")

    expected_log = _git(
        "log",
        "--format=%H%x09%P%x09%aI%x09%s",
        str(snapshot["git"]["history"]["range"]),
    )
    if (
        hashlib.sha256(expected_log).hexdigest()
        != snapshot["git"]["history"]["canonical_log_sha256"]
    ):
        raise RuntimeError("integration snapshot history digest mismatch")
    expected_commits = _git("log", "--format=%H", str(ledger["range"])).decode().splitlines()
    if set(expected_commits) != set(entry_shas) or len(expected_commits) != len(entries):
        raise RuntimeError("integration ledger does not exactly cover its Git range")
    actual_subjects = {
        line.split("\t", 1)[0]: line.split("\t", 1)[1]
        for line in _git("log", "--format=%H%x09%s", str(ledger["range"])).decode().splitlines()
    }
    if any(actual_subjects.get(item["sha"]) != item["subject"] for item in entries):
        raise RuntimeError("integration ledger commit subject mismatch")

    if (
        archive.get("schema") != "legalbot.v111-deferred-archive-receipt.v1"
        or archive.get("authorizing") is not False
        or archive.get("preservation_only") is not True
        or archive.get("remote_head_verified") is not True
        or archive.get("integration_worktree_copies_removed") is not True
        or len(archive.get("files") or ()) != 4
    ):
        raise RuntimeError("deferred archive receipt contract mismatch")
    archive_commit = str(archive["commit"])
    if _git("rev-parse", str(archive["branch"])).decode().strip() != archive_commit:
        raise RuntimeError("deferred archive branch moved")
    if _git("rev-parse", f"{archive_commit}^{{tree}}").decode().strip() != archive["tree"]:
        raise RuntimeError("deferred archive tree mismatch")
    for item in archive["files"]:
        raw = _git("show", f"{archive_commit}:{item['path']}")
        if len(raw) != item["size"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise RuntimeError("deferred archive blob mismatch")

    snapshot_refs = snapshot["q31_reference_inventory"]
    identities = [(item["path"], tuple(item["lines"])) for item in snapshot_refs]
    if len(identities) != len(set(identities)):
        raise RuntimeError("Q31 inventory contains duplicate reference identities")
    return {
        "schema": "legalbot.v111-integration-record-validation.v1",
        "authorizing": False,
        "snapshot_valid": True,
        "ledger_valid": True,
        "archive_valid": True,
        "ledger_entry_count": len(entries),
        "q31_reference_group_count": len(snapshot_refs),
        "archive_file_count": len(archive["files"]),
    }


def main() -> int:
    try:
        print(json.dumps(validate_records(), sort_keys=True))
        return 0
    except Exception as exc:
        print(
            json.dumps(
                {
                    "schema": "legalbot.v111-integration-record-validation.v1",
                    "authorizing": False,
                    "status": "failed",
                    "reason_code": type(exc).__name__.casefold(),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
