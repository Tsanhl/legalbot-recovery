"""Run-lineage and effective-source-set builders for GE diagnostic tracks."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from app.contracts.schema_registry import content_sha256

from .ge_factual_gap_fill import sidecar_packs

LINEAGE_SCHEMA = "legalbot.ge-run-lineage-manifest.v1"
SOURCE_SET_SCHEMA = "legalbot.ge-effective-source-set-manifest.v1"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _empty_track(track_id: str, run_id: str, *, present: bool, note: str) -> dict[str, Any]:
    return {
        "track_id": track_id,
        "run_id": run_id,
        "present": present,
        "note": note,
        "question_pack_sha256": "",
        "effective_source_set_sha256": "",
        "retriever_config_sha256": "",
        "reranker_sha256": "",
        "prompt_sha256": "",
        "model_or_adapter_sha256": "",
        "evaluator_sha256": "",
        "locator_receipt_sha256": "",
        "result_sha256": "",
    }


def bind_track(track: Mapping[str, Any], **hashes: str) -> dict[str, Any]:
    value = dict(track)
    for key, item in hashes.items():
        if key in value and item:
            value[key] = item
    return value


def build_run_lineage(
    *,
    historical_r1: Mapping[str, Any],
    historical_r1_rescored: Mapping[str, Any] | None = None,
    new_r2: Mapping[str, Any],
) -> dict[str, Any]:
    rescored = dict(
        historical_r1_rescored
        or _empty_track(
            "historical_r1_rescored_under_r2_evaluator",
            "NOT_EXECUTED",
            present=False,
            note=(
                "No separate r1-rescored-under-r2-evaluator track has been minted. "
                "Do not treat an intermediate comparison summary as historical r1."
            ),
        )
    )
    body = {
        "schema": LINEAGE_SCHEMA,
        "tracks": {
            "historical_r1_immutable": dict(historical_r1),
            "historical_r1_rescored_under_r2_evaluator": rescored,
            "new_r2_generated_and_scored_under_r2_evaluator": dict(new_r2),
        },
        "comparison_uses_specific_baseline_ids": True,
        "do_not_label_an_intermediate_baseline_as_r1": True,
    }
    body["content_sha256"] = content_sha256(body)
    return body


def build_effective_source_set(
    *,
    project_root: Path,
    extra_sidecar_manifests: Sequence[Path] = (),
) -> dict[str, Any]:
    recovery = (
        project_root
        / "data/indexes/builds/current-law-ew-full-fp16-v111-20260829-recovery-b"
        / "approved-source-manifest.json"
    )
    base_hash = _sha256_file(recovery) if recovery.is_file() else "0" * 64
    sidecar_hashes: list[str] = []
    components: list[dict[str, Any]] = [
        {
            "component_id": "current-law-ew-full-fp16-v111-20260829-recovery-b",
            "kind": "recovery_b_approved_sources",
            "manifest_sha256": base_hash,
            "source_count": 85,
        }
    ]
    manifests = [pack / "STAGED-SOURCE-MANIFEST.json" for pack in sidecar_packs(project_root)]
    manifests.extend(path for path in extra_sidecar_manifests if path.is_file())
    for path in manifests:
        if not path.is_file():
            continue
        digest = _sha256_file(path)
        sidecar_hashes.append(digest)
        components.append(
            {
                "component_id": path.parent.name,
                "kind": "evaluation_sidecar",
                "manifest_sha256": digest,
                "source_count": 0,
            }
        )
    sidecar_combined = hashlib.sha256("".join(sorted(sidecar_hashes)).encode()).hexdigest()
    effective = hashlib.sha256(f"{base_hash}:{sidecar_combined}".encode()).hexdigest()
    body = {
        "schema": SOURCE_SET_SCHEMA,
        "base_source_manifest_sha256": base_hash,
        "evaluation_sidecar_manifest_sha256": sidecar_combined,
        "effective_source_set_sha256": effective,
        "components": components,
        "live_catalogue_insert": False,
        "admitted": False,
        "legal_gold": False,
    }
    body["content_sha256"] = content_sha256(body)
    return body


def empty_historical_r1_track() -> dict[str, Any]:
    return _empty_track(
        "historical_r1_immutable",
        "LegalBot-GE-2026-09-02-visible-331-diagnostic-r1",
        present=True,
        note="Immutable diagnostic r1. Case 008 used Equality Act ss 174/208/210; case 174 used Arbitration Act 1996 s9; case 312 used an incomplete Wills Act s9 passage.",
    )


def empty_r2_track() -> dict[str, Any]:
    return _empty_track(
        "new_r2_generated_and_scored_under_r2_evaluator",
        "LegalBot-GE-2026-09-02-visible-331-diagnostic-r2",
        present=True,
        note="Frozen diagnostic r2 generated and scored under the r2 evaluator. Not qualified legal gold.",
    )
