#!/usr/bin/env python3
"""Create the immutable, non-authorizing 146-row semantic routing advisory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.evaluation.phase2a_blocker_semantic_advisory import (  # noqa: E402
    CASES_FILE_SHA256,
    FALLBACK_ADVISORY_CONTENT_SHA256,
    MANIFEST_FILE_SHA256,
    ORIGINAL_PACKET_CONTENT_SHA256,
    R3_REPORT_CONTENT_SHA256,
    build_blocker_semantic_advisory,
)

REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
R3_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2A-2026-08-28-prequalification-blockers-r3"
    / "PREQUALIFICATION-BLOCKER-REPORT.json"
)
ORIGINAL_PACKET_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2A-2026-08-28-exact-remediation-owner-packet-r1"
    / "EXACT-REMEDIATION-OWNER-PACKET-361.json"
)
FALLBACK_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2A-2026-08-28-fact-only-fallback-coverage-advisory-r1"
    / "FACT-ONLY-FALLBACK-COVERAGE-ADVISORY-585.json"
)
CASES_PATH = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1/cases.jsonl"
MANIFEST_PATH = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1/manifest.json"
DEFAULT_OUTPUT_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-blocker-semantic-advisory-r1"
)

EXPECTED_FILE_HASHES = {
    R3_PATH: "7cb044a4c9539162281e10ac41e5e0cb1f0cd846b0eb597a0443b0e67fb48899",
    ORIGINAL_PACKET_PATH: "992770c04cb3e08de64bb98e80aa9801171d3e66e4b573b85919091a78b1db3b",
    FALLBACK_PATH: "caa33a34cf3164a9691f854425cb452a0780590066493a79cd9e6e5f5aeef889",
    CASES_PATH: CASES_FILE_SHA256,
    MANIFEST_PATH: MANIFEST_FILE_SHA256,
}


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"phase2a_semantic_advisory_not_object:{path.name}")
    return value


def _write_new(path: Path, raw: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(raw)
    os.chmod(path, 0o600)


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    project_root = args.project_root.resolve(strict=True)
    if project_root != PROJECT_ROOT.resolve(strict=True):
        raise ValueError("phase2a_semantic_advisory_project_root_changed")
    for path, expected in EXPECTED_FILE_HASHES.items():
        resolved = path.resolve(strict=True)
        if path.is_symlink() or not resolved.is_relative_to(project_root):
            raise ValueError("phase2a_semantic_advisory_input_boundary_violation")
        if _sha256(path.read_bytes()) != expected:
            raise ValueError(f"phase2a_semantic_advisory_file_hash_mismatch:{path.name}")

    report = _load_json(R3_PATH)
    original = _load_json(ORIGINAL_PACKET_PATH)
    fallback = _load_json(FALLBACK_PATH)
    if (
        report.get("artifact_content_sha256") != R3_REPORT_CONTENT_SHA256
        or original.get("artifact_content_sha256") != ORIGINAL_PACKET_CONTENT_SHA256
        or fallback.get("artifact_content_sha256") != FALLBACK_ADVISORY_CONTENT_SHA256
    ):
        raise ValueError("phase2a_semantic_advisory_content_identity_changed")
    advisory = build_blocker_semantic_advisory(
        r3_report=report,
        original_packet=original,
        fallback_advisory=fallback,
        cases_raw=CASES_PATH.read_bytes(),
        manifest_raw=MANIFEST_PATH.read_bytes(),
    )

    output = args.output_root.absolute()
    allowed = (project_root / "data/evaluations/phase2a-owner-review").resolve(strict=True)
    if output.parent.resolve(strict=True) != allowed or output.exists() or output.is_symlink():
        raise ValueError("phase2a_semantic_advisory_output_must_be_new_direct_review_directory")
    output.mkdir(mode=0o700)
    advisory_path = output / "BLOCKER-SEMANTIC-ROUTING-ADVISORY-146.json"
    _write_new(advisory_path, _canonical(advisory))

    package = {
        "schema": "legalbot.v111.phase2a.blocker-semantic-routing-package.v1",
        "status": "READ_ONLY_ADVISORY_SEALED_NOT_APPLIED",
        "advisory_content_sha256": advisory["artifact_content_sha256"],
        "advisory_file_sha256": _sha256(advisory_path.read_bytes()),
        "row_count": advisory["counts"]["row_count"],
        "strict_matter_information_only_fallback_candidate_count": 0,
        "source_scan_run": False,
        "index_build_run": False,
        "embedding_run": False,
        "retrieval_reattestation_run": False,
        "all585_qualification_run": False,
        "execution_chain_consumed": False,
        "owner_decision_applied": False,
        "phase2b_authorized": False,
    }
    package["artifact_content_sha256"] = hashlib.sha256(_canonical(package)).hexdigest()
    package_path = output / "PACKAGE-MANIFEST.json"
    _write_new(package_path, _canonical(package))
    checksums = "\n".join(
        f"{_sha256(path.read_bytes())}  {path.name}"
        for path in (advisory_path, package_path)
    )
    _write_new(output / "SHA256SUMS.txt", (checksums + "\n").encode("utf-8"))
    print(
        json.dumps(
            {
                "status": advisory["status"],
                "advisory_content_sha256": advisory["artifact_content_sha256"],
                "advisory_file_sha256": _sha256(advisory_path.read_bytes()),
                "package_content_sha256": package["artifact_content_sha256"],
                "counts": advisory["counts"],
                "output_root": output.relative_to(project_root).as_posix(),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
