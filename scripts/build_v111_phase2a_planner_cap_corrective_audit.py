#!/usr/bin/env python3
"""Seal the complete r114-r119 planner-cap audit without model execution."""

from __future__ import annotations

import argparse
import json
import os
import socket
import stat
import subprocess
import sys
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
for root in (PROJECT_ROOT, BACKEND_ROOT):
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

from scripts import plan_v111_phase2a_material_gap_research as planner  # noqa: E402

REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
DEFAULT_OUTPUT = REVIEW_ROOT / "LegalBot-Phase2A-2026-08-27-planner-cap-corrective-audit-v2"
MAXIMUM_CUMULATIVE_INVOCATIONS_PER_ROW = 2


@dataclass(frozen=True, slots=True)
class RunSpec:
    run_id: str
    root: Path
    expected_checkpoint_count: int
    expected_diagnostic_count: int
    expected_row_count: int
    status: str


RUNS = (
    RunSpec(
        run_id="r114",
        root=(REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-26-r114-post-r113-gap-research-plans"),
        expected_checkpoint_count=0,
        expected_diagnostic_count=0,
        expected_row_count=0,
        status="SEALED_NON_AUTHORIZING_PRE_MODEL_FAILURE_EVIDENCE",
    ),
    RunSpec(
        run_id="r115",
        root=(REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-26-r115-post-r113-gap-research-plans"),
        expected_checkpoint_count=0,
        expected_diagnostic_count=1,
        expected_row_count=8,
        status="SEALED_NON_AUTHORIZING_UNFINALIZED_RUNTIME_FAILURE_EVIDENCE",
    ),
    RunSpec(
        run_id="r116",
        root=(REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-26-r116-post-r113-gap-research-plans"),
        expected_checkpoint_count=8,
        expected_diagnostic_count=2,
        expected_row_count=29,
        status="SEALED_NON_AUTHORIZING_INTERRUPTED_ADVISORY_EVIDENCE",
    ),
    RunSpec(
        run_id="r117",
        root=(
            REVIEW_ROOT
            / "LegalBot-Phase2AB-2026-08-26-r117-post-r116-stemmer-debug-gap-research-plans"
        ),
        expected_checkpoint_count=112,
        expected_diagnostic_count=85,
        expected_row_count=364,
        status="SEALED_NON_AUTHORIZING_ADVISORY_WITH_HELD_ROWS",
    ),
    RunSpec(
        run_id="r118",
        root=(REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-27-r118-held-gap-singleton-repair"),
        expected_checkpoint_count=27,
        expected_diagnostic_count=11,
        expected_row_count=27,
        status="SEALED_NON_AUTHORIZING_OVER_CAP_DEBUG_EVIDENCE",
    ),
    RunSpec(
        run_id="r119",
        root=(
            REVIEW_ROOT
            / "LegalBot-Phase2AB-2026-08-27-r119-post-r118-timeout-debug-singleton-repair"
        ),
        expected_checkpoint_count=1,
        expected_diagnostic_count=1,
        expected_row_count=1,
        status="SEALED_NON_AUTHORIZING_RUNTIME_FAILURE_EVIDENCE",
    ),
)

EXPECTED_TOP_LEVEL_IDENTITIES = {
    "r114": {},
    "r115": {
        "FAILURE.json": (
            "failure_content_sha256",
            "e18f00aeb377fb56710e702f7172152671a57d6b554efa69a2ac49f174d9c850",
        ),
        "INTENT.json": (
            "intent_content_sha256",
            "bcc91becf227f5c7b7d36c59cd12dc61467a11d01f56a7ab04ec72b643292f7d",
        ),
    },
    "r116": {
        "FAILURE.json": (
            "failure_content_sha256",
            "39e7da88b69c2ed4ff548c1b544a26892d4c64868b2c3fa4a1505be1b71e8ead",
        ),
        "INTENT.json": (
            "intent_content_sha256",
            "be8268b66bc89d3ca16f48f8e74cee3576c7b1f313e1d8f10e9c13429abd66cb",
        ),
    },
    "r117": {
        "MATERIAL-GAP-RESEARCH-PLANS.json": (
            "artifact_content_sha256",
            "e80f15aa2c517531581959aafd7bc956a4383c138fc8015613539549c2dd06fd",
        ),
        "INTENT.json": (
            "intent_content_sha256",
            "4324529f605f9aaf7b31b7dfbbfa20ec57a10d60e2db7eedaac6b78568550d1f",
        ),
    },
    "r118": {
        "FAILURE.json": (
            "failure_content_sha256",
            "11007baa1a62df7914694442f301535c1da2349a3f7f119294fa993a27b5b420",
        ),
        "INTENT.json": (
            "intent_content_sha256",
            "7df05462de3183fc7f1db610302bd76c60fb19350fe6d69999a7c214b3ab1d3d",
        ),
        "SOURCE-HELD-CROSSWALK.json": (
            "artifact_content_sha256",
            "d72fffdcb669f280cdd11d5499c1ca7d2a3a5ddd7160587c9d6a1ef2d489c31b",
        ),
    },
    "r119": {
        "FAILURE.json": (
            "failure_content_sha256",
            "12326d39499b7271847c6c1fa608f9a2744f83c1897945800dd167057dcf3334",
        ),
        "INTENT.json": (
            "intent_content_sha256",
            "3a75fbd6ab719dce64602e5a529e1eefea45763708cd7827fcb62f64c75f7fd0",
        ),
        "SOURCE-REMAINING-CROSSWALK.json": (
            "artifact_content_sha256",
            "4dc5d5cc6505c3dd499664cee59dbc7a18737cb12159795240269b43ac9f2011",
        ),
        "DEBUG-REPORT.json": (
            "artifact_content_sha256",
            "73d6b26c00bf9b94a6bc1c659236c4fd3ff9796579b694710b83519e82ec8766",
        ),
    },
}

EXPECTED_TOP_FAILURE_FINGERPRINTS = {
    "r114": "92779f218178ded07419dde442e9c69e00cc5e94ba704f50115e4f1aaa6d2c2f",
    "r115": "bc17452a257a4dc7752769c3bcdbd7b875e7a8a03671ea1b0a4cf2e65fba2d24",
    "r116": "bc17452a257a4dc7752769c3bcdbd7b875e7a8a03671ea1b0a4cf2e65fba2d24",
    "r118": "be1c295cd5310b0072be67cb9df4fcc5f3ef3e32e1855b61f115e3dc6b82356f",
    "r119": "d812fad1e291e4b833ddc9b63b6617170a8bdfff333f38b7138036abbd17c74e",
}
EXPECTED_RUNTIME_FAILURE_FINGERPRINTS = {
    "r115": "e7c87dd9682c1daa5ea10d3c37097c9572ef4ddd1ffc6e93e69995b331dd774d",
    "r118": "5082f561c363f11dc179227da79ba04950922204d6e0c105d90f033df5eb449d",
    "r119": "d61131760929b67e77f74c9abaf9af60e3db764c228582caa9077c1caf318351",
}
EXPECTED_R114_FAILURE_FILE_SHA256 = (
    "3ac65d8194846f8ea0296b26da3cb2a6448448594767e21eedf74fc22d1c9f4a"
)
FOCUS_ROW_ID = "live30-q10:issue-07"
EXPECTED_FOCUS_FINGERPRINTS = (
    "6f7529bca338254f4490a6b1e3d0f5d86d16b620241bc9985f87d84a5a7299b5",
    "af683f63c7302ae96f2d557eb25546d4078da3281567a5c52f165e92dba51146",
    "1fa70ffb23caa2549decdbdb9d0864c07c4afe6e0e1d65bf2cdf78d075c30370",
    "31b6584a6569ce5d76a4a5fe214724fb243de05fab0563b2a44b1d268532c714",
    "d61131760929b67e77f74c9abaf9af60e3db764c228582caa9077c1caf318351",
)


def _load_json(path: Path) -> dict[str, Any]:
    return planner._load_object(path)


def _verify_top_level_identities(spec: RunSpec) -> None:
    expected = EXPECTED_TOP_LEVEL_IDENTITIES[spec.run_id]
    for name, (seal_field, digest) in expected.items():
        payload = _load_json(spec.root / name)
        observed = planner._verify_seal(
            payload,
            seal_field,
            f"phase2a_corrective_{spec.run_id}_{name}_seal_invalid",
        )
        if observed != digest:
            raise ValueError(f"phase2a_corrective_{spec.run_id}_{name}_identity_changed")
    if (
        spec.run_id == "r114"
        and planner._sha256_file(spec.root / "FAILURE.json") != EXPECTED_R114_FAILURE_FILE_SHA256
    ):
        raise ValueError("phase2a_corrective_r114_failure_file_changed")
    expected_failure = EXPECTED_TOP_FAILURE_FINGERPRINTS.get(spec.run_id)
    if expected_failure is not None:
        failure = _load_json(spec.root / "FAILURE.json")
        if failure.get("failure_fingerprint") != expected_failure:
            raise ValueError(f"phase2a_corrective_{spec.run_id}_failure_fingerprint_changed")


def _file_manifest(spec: RunSpec) -> dict[str, Any]:
    if spec.root.is_symlink() or not spec.root.is_dir():
        raise ValueError(f"phase2a_corrective_{spec.run_id}_root_invalid")
    _verify_top_level_identities(spec)
    records: list[dict[str, Any]] = []
    for path in sorted(spec.root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"phase2a_corrective_{spec.run_id}_symlink_forbidden")
        if not path.is_file():
            continue
        records.append(
            {
                "relative_path": str(path.relative_to(spec.root)),
                "size_bytes": path.stat().st_size,
                "sha256": planner._sha256_file(path),
            }
        )
    material = {
        "run_id": spec.run_id,
        "repository_relative_root": str(spec.root.relative_to(PROJECT_ROOT)),
        "status": spec.status,
        "file_count": len(records),
        "files": records,
    }
    return {**material, "tree_manifest_sha256": planner._sealed(material)}


def _diagnostics_by_row(spec: RunSpec) -> dict[str, list[dict[str, Any]]]:
    by_row: dict[str, list[dict[str, Any]]] = {}
    paths = sorted((spec.root / "diagnostics").glob("*.json"))
    if len(paths) != spec.expected_diagnostic_count:
        raise ValueError(f"phase2a_corrective_{spec.run_id}_diagnostic_count_invalid")
    for path in paths:
        payload = _load_json(path)
        planner._verify_seal(
            payload,
            "diagnostic_content_sha256",
            f"phase2a_corrective_{spec.run_id}_diagnostic_seal_invalid",
        )
        record = {
            "attempt": payload.get("attempt"),
            "error_code": payload.get("error_code"),
            "failure_fingerprint": payload.get("failure_fingerprint"),
            "diagnostic_content_sha256": payload.get("diagnostic_content_sha256"),
            "response_received": payload.get("response_received"),
        }
        for row_id in payload.get("row_ids", []):
            by_row.setdefault(str(row_id), []).append(record)
    return by_row


def _checkpoint_records(spec: RunSpec) -> dict[str, dict[str, Any]]:
    diagnostics = _diagnostics_by_row(spec)
    checkpoints = sorted((spec.root / "checkpoints").glob("*.json"))
    if len(checkpoints) != spec.expected_checkpoint_count:
        raise ValueError(f"phase2a_corrective_{spec.run_id}_checkpoint_count_invalid")
    records: dict[str, dict[str, Any]] = {}
    for path in checkpoints:
        payload = planner._load_checkpoint(path)
        schema = payload.get("schema")
        state = (
            "ACCEPTED_ADVISORY_PLAN"
            if schema == "legalbot.v111.phase2a.gap-plan-checkpoint.v1"
            else "HELD_DEBUG_EVIDENCE"
        )
        seal_field = (
            "checkpoint_content_sha256"
            if state == "ACCEPTED_ADVISORY_PLAN"
            else "held_content_sha256"
        )
        for row_id in payload.get("row_ids", []):
            row_id = str(row_id)
            if row_id in records:
                raise ValueError(f"phase2a_corrective_{spec.run_id}_duplicate_row_checkpoint")
            records[row_id] = {
                "attempt_count": int(payload.get("attempt_count") or 0),
                "state": state,
                "checkpoint_relative_path": str(path.relative_to(spec.root)),
                "checkpoint_content_sha256": payload.get(seal_field),
                "diagnostics": diagnostics.get(row_id, []),
            }
    for row_id, row_diagnostics in diagnostics.items():
        if row_id in records:
            continue
        attempt_count = max(int(item.get("attempt") or 0) for item in row_diagnostics)
        records[row_id] = {
            "attempt_count": attempt_count,
            "state": "UNFINALIZED_DIAGNOSTIC_EVIDENCE",
            "checkpoint_relative_path": None,
            "checkpoint_content_sha256": None,
            "diagnostics": row_diagnostics,
        }
    if len(records) != spec.expected_row_count:
        raise ValueError(f"phase2a_corrective_{spec.run_id}_row_count_invalid")
    return records


def _inventory() -> tuple[dict[str, Any], dict[str, Any]]:
    manifests = [_file_manifest(spec) for spec in RUNS]
    per_run = {spec.run_id: _checkpoint_records(spec) for spec in RUNS}
    all_row_ids = sorted({row_id for records in per_run.values() for row_id in records})
    if len(all_row_ids) != planner.EXPECTED_GAP_COUNT:
        raise ValueError("phase2a_corrective_combined_row_count_invalid")

    over_cap: list[dict[str, Any]] = []
    for row_id in all_row_ids:
        run_records = {
            run_id: records[row_id] for run_id, records in per_run.items() if row_id in records
        }
        total = sum(record["attempt_count"] for record in run_records.values())
        if total <= MAXIMUM_CUMULATIVE_INVOCATIONS_PER_ROW:
            continue
        fingerprints = [
            str(item["failure_fingerprint"])
            for record in run_records.values()
            for item in record["diagnostics"]
            if item.get("failure_fingerprint")
        ]
        over_cap.append(
            {
                "row_id": row_id,
                "cumulative_invocation_count": total,
                "excess_invocation_count": (total - MAXIMUM_CUMULATIVE_INVOCATIONS_PER_ROW),
                "runs": run_records,
                "failure_fingerprints": fingerprints,
                "admissibility": (
                    "EXCLUDED_FROM_SUBSTANTIVE_EVIDENCE_DUE_TO_CUMULATIVE_ATTEMPT_CAP_BREACH"
                ),
            }
        )
    totals = Counter(record["cumulative_invocation_count"] for record in over_cap)
    r118_states = Counter(
        record["runs"]["r118"]["state"] for record in over_cap if "r118" in record["runs"]
    )
    focus = next(record for record in over_cap if record["row_id"] == FOCUS_ROW_ID)
    if (
        len(over_cap) != 38
        or focus["cumulative_invocation_count"] != 5
        or tuple(focus["failure_fingerprints"]) != EXPECTED_FOCUS_FINGERPRINTS
        or totals != Counter({3: 26, 4: 11, 5: 1})
        or r118_states != Counter({"ACCEPTED_ADVISORY_PLAN": 25, "HELD_DEBUG_EVIDENCE": 2})
    ):
        raise ValueError("phase2a_corrective_over_cap_inventory_changed")
    timeout_rows = {
        str(record["row_id"]): record
        for record in over_cap
        if any(
            item.get("error_code") == "read_timeout"
            for run in record["runs"].values()
            for item in run["diagnostics"]
        )
    }
    expected_timeout_rows = {
        *(f"live30-q01:issue-{ordinal:02d}" for ordinal in range(1, 9)),
        FOCUS_ROW_ID,
        "live30-q25:issue-07",
    }
    if set(timeout_rows) != expected_timeout_rows:
        raise ValueError("phase2a_corrective_timeout_rows_changed")
    observed_runtime_fingerprints = {
        run_id: expected
        for run_id, expected in EXPECTED_RUNTIME_FAILURE_FINGERPRINTS.items()
        if any(expected in record["failure_fingerprints"] for record in over_cap)
    }
    if observed_runtime_fingerprints != EXPECTED_RUNTIME_FAILURE_FINGERPRINTS:
        raise ValueError("phase2a_corrective_runtime_fingerprints_missing")

    source_material = {
        "schema": "legalbot.v111.phase2a.planner-cap-source-run-manifest.v2",
        "run_count": len(manifests),
        "runs": manifests,
        "source_runs_mutated": False,
    }
    source_manifest = {
        **source_material,
        "artifact_content_sha256": planner._sealed(source_material),
    }
    inventory_material = {
        "schema": "legalbot.v111.phase2a.planner-cap-corrective-inventory.v2",
        "maximum_cumulative_invocations_per_row": (MAXIMUM_CUMULATIVE_INVOCATIONS_PER_ROW),
        "canonical_row_count": len(all_row_ids),
        "over_cap_row_count": len(over_cap),
        "over_cap_cumulative_invocation_counts": {
            str(key): value for key, value in sorted(totals.items())
        },
        "over_cap_r118_state_counts": dict(sorted(r118_states.items())),
        "timeout_row_count": len(timeout_rows),
        "top_level_failure_fingerprints": EXPECTED_TOP_FAILURE_FINGERPRINTS,
        "runtime_failure_fingerprints": EXPECTED_RUNTIME_FAILURE_FINGERPRINTS,
        "records": over_cap,
    }
    inventory = {
        **inventory_material,
        "artifact_content_sha256": planner._sealed(inventory_material),
    }
    return source_manifest, inventory


def _quiescent_evidence() -> dict[str, Any]:
    process_output = subprocess.run(
        ("ps", "-axo", "pid=,command="),
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout
    forbidden_fragments = (
        "scripts/plan_v111_phase2a_material_gap_research.py",
        "scripts/repair_v111_phase2a_material_gap_research",
        "-m app.model_runtime",
    )
    active = []
    for line in process_output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        pid_text = stripped.split(maxsplit=1)[0]
        if pid_text.isdigit() and int(pid_text) == os.getpid():
            continue
        if any(fragment in stripped for fragment in forbidden_fragments):
            active.append(stripped)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.25)
        port_open = probe.connect_ex(("127.0.0.1", 8779)) == 0
    if active or port_open:
        raise ValueError("phase2a_corrective_planner_or_model_still_active")
    material = {
        "schema": "legalbot.v111.phase2a.planner-quiescence-evidence.v1",
        "observed_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "matching_planner_or_model_process_count": 0,
        "model_runtime_port_8779_listening": False,
        "raw_process_listing_persisted": False,
    }
    return {**material, "artifact_content_sha256": planner._sealed(material)}


def build_audit(
    *, output_root: Path, observed_at: datetime, quiescence: Mapping[str, Any]
) -> dict[str, Any]:
    if observed_at.tzinfo is None:
        raise ValueError("phase2a_corrective_observed_at_naive")
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_corrective_output_already_exists")
    planner._verify_seal(
        quiescence,
        "artifact_content_sha256",
        "phase2a_corrective_quiescence_seal_invalid",
    )
    source_manifest, inventory = _inventory()
    material = {
        "schema": "legalbot.v111.phase2a.planner-cap-corrective-audit.v2",
        "status": "PHASE_2A_SAFELY_STOPPED_OWNER_INPUT_REQUIRED",
        "observed_at": observed_at.astimezone(UTC).isoformat(timespec="seconds"),
        "source_manifest_content_sha256": source_manifest["artifact_content_sha256"],
        "inventory_content_sha256": inventory["artifact_content_sha256"],
        "quiescence_content_sha256": quiescence["artifact_content_sha256"],
        "finding": (
            "The complete r114-r119 history shows that r115/r116 and r118/r119 "
            "re-invoked rows later processed by r117. Every result for a row whose "
            "cumulative history exceeds the two-attempt planner cap is non-authorizing "
            "debug evidence and cannot be reused as admissible substantive evidence."
        ),
        "over_cap_row_count": inventory["over_cap_row_count"],
        "over_cap_results_admissible_as_substantive_evidence": False,
        "r114_through_r119_authorizing": False,
        "supersedes_partial_corrective_audit_content_sha256": (
            "9dd23e03e8579b55a1a06941e00599e897a0c8ef926c30775564bc227acf0711"
        ),
        "next_owner_choices": [
            "AUTHORIZE_DETERMINISTIC_ONLY_PATH",
            "AUTHORIZE_NEW_SEPARATELY_BOUNDED_METHODOLOGY",
        ],
        "candidate_mutated": False,
        "source_admission_state_mutated": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "active_previous_written": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
        "validation30_authorized": False,
        "live_activation_authorized": False,
    }
    audit = {**material, "artifact_content_sha256": planner._sealed(material)}

    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_corrective_output_mode_invalid")
    planner._write_exclusive(
        output_root / "SOURCE-RUN-FILE-MANIFEST.json",
        planner._pretty_json(source_manifest),
    )
    planner._write_exclusive(
        output_root / "OVER-CAP-ROW-INVENTORY.json",
        planner._pretty_json(inventory),
    )
    planner._write_exclusive(
        output_root / "PROCESS-QUIESCENCE.json", planner._pretty_json(quiescence)
    )
    planner._write_exclusive(
        output_root / "PLANNER-CAP-CORRECTIVE-AUDIT.json",
        planner._pretty_json(audit),
    )
    outcome = (
        "PHASE 2A SAFELY STOPPED — OWNER INPUT REQUIRED\n"
        "No planner/model process remains. Phase 2B, Development 30, candidate "
        "mutation, source admission changes, ACTIVE/PREVIOUS writes, Validation, "
        "and live activation remain blocked.\n"
    )
    planner._write_exclusive(output_root / "OUTCOME.txt", outcome.encode())
    files = sorted(path for path in output_root.iterdir() if path.is_file())
    sums = "".join(f"{planner._sha256_file(path)}  {path.name}\n" for path in files)
    planner._write_exclusive(output_root / "SHA256SUMS.txt", sums.encode())
    return audit


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> None:
    args = _arguments()
    quiescence = _quiescent_evidence()
    result = build_audit(
        output_root=args.output_root.resolve(),
        observed_at=datetime.now(UTC),
        quiescence=quiescence,
    )
    print(
        json.dumps(
            {
                "output_root": str(args.output_root),
                "status": result["status"],
                "over_cap_row_count": result["over_cap_row_count"],
                "artifact_content_sha256": result["artifact_content_sha256"],
                "phase2b_authorized": result["phase2b_authorized"],
                "development30_authorized": result["development30_authorized"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
