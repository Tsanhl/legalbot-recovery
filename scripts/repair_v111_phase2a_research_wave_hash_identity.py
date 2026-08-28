#!/usr/bin/env python3
"""Repair a research wave that mislabeled proposition hashes as queue hashes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from scripts import validate_v111_phase2a_official_research_waves as validator


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sealed(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def repair(*, queue_path: Path, input_path: Path, output_path: Path) -> dict[str, Any]:
    if output_path.exists() or output_path.is_symlink():
        raise ValueError("phase2a_research_wave_repair_output_already_exists")
    queue = validator._load_queue(queue_path)
    queue_by_row = {
        str(record["row_id"]): record
        for record in queue.get("records", [])
        if isinstance(record, Mapping)
    }
    if input_path.is_symlink() or not input_path.is_file():
        raise ValueError("phase2a_research_wave_repair_input_invalid")
    wave = json.loads(input_path.read_bytes())
    if not isinstance(wave, dict) or wave.get("source_queue_content_sha256") != (
        validator.EXPECTED_QUEUE_CONTENT_SHA256
    ):
        raise ValueError("phase2a_research_wave_repair_boundary_invalid")
    if validator._contains_exact_text(wave):
        raise ValueError("phase2a_research_wave_repair_unbound_exact_text")
    if validator._safety_flag(wave, "advisory_only") is not True or any(
        validator._safety_flag(wave, flag) is not False for flag in validator.REQUIRED_FALSE_FLAGS
    ):
        raise ValueError("phase2a_research_wave_repair_boundary_invalid")
    records = wave.get("records")
    if not isinstance(records, list) or not records:
        raise ValueError("phase2a_research_wave_repair_records_invalid")
    repaired_records: list[dict[str, Any]] = []
    repair_count = 0
    membership_normalization_count = 0
    for raw in records:
        if not isinstance(raw, Mapping):
            raise ValueError("phase2a_research_wave_repair_record_invalid")
        record = dict(raw)
        row_id = str(record.get("row_id") or "")
        queue_record = queue_by_row.get(row_id)
        if queue_record is None:
            raise ValueError("phase2a_research_wave_repair_row_outside_queue")
        supplied = record.get("queue_record_content_sha256")
        queue_hash = queue_record.get("record_content_sha256")
        proposition_hash = queue_record.get("proposition_record_content_sha256")
        if supplied == proposition_hash:
            record["proposition_record_content_sha256"] = supplied
            record["queue_record_content_sha256"] = queue_hash
            repair_count += 1
        elif supplied == queue_hash:
            record.setdefault("proposition_record_content_sha256", proposition_hash)
        else:
            raise ValueError("phase2a_research_wave_repair_unknown_hash_identity")
        components = record.get("atomic_components")
        if not isinstance(components, list):
            raise ValueError("phase2a_research_wave_repair_components_invalid")
        for component in components:
            if not isinstance(component, dict):
                raise ValueError("phase2a_research_wave_repair_component_invalid")
            authorities = component.get("authorities")
            if not isinstance(authorities, list):
                raise ValueError("phase2a_research_wave_repair_authorities_invalid")
            for authority in authorities:
                if not isinstance(authority, dict):
                    raise ValueError("phase2a_research_wave_repair_authority_invalid")
                membership = authority.get("candidate_existing")
                if membership == "yes":
                    authority["candidate_existing"] = True
                    membership_normalization_count += 1
                elif membership == "no":
                    authority["candidate_existing"] = False
                    membership_normalization_count += 1
        repaired_records.append(record)
    material = dict(wave)
    material.pop("artifact_content_sha256", None)
    material["schema"] = "legalbot.v111.phase2a.official-source-research-wave.v1"
    material["records"] = repaired_records
    material["provenance_repair"] = {
        "schema": "legalbot.v111.phase2a.research-wave-hash-identity-repair.v1",
        "source_file": input_path.name,
        "source_file_sha256": hashlib.sha256(input_path.read_bytes()).hexdigest(),
        "repair_count": repair_count,
        "candidate_membership_normalization_count": membership_normalization_count,
        "prior_provenance_repair": wave.get("provenance_repair"),
        "repair": (
            "Preserve the supplied proposition_record_content_sha256 and bind the "
            "distinct queue record_content_sha256 under queue_record_content_sha256; "
            "normalize unambiguous candidate membership yes/no strings to booleans."
        ),
        "substantive_research_changed": False,
        "owner_outcomes_applied": False,
        "source_admitted": False,
        "candidate_mutated": False,
        "embedding_run": False,
        "phase2b_authorized": False,
    }
    result = {**material, "artifact_content_sha256": _sealed(material)}
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _write_exclusive(output_path, _pretty_json(result))
    validator.validate_waves(queue_path=queue_path, wave_paths=[output_path])
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--queue", type=Path, default=validator.DEFAULT_QUEUE)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = repair(queue_path=args.queue, input_path=args.input, output_path=args.output)
    print(
        json.dumps(
            {
                "artifact_content_sha256": result["artifact_content_sha256"],
                "record_count": len(result["records"]),
                "repair_count": result["provenance_repair"]["repair_count"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
