"""One-authority Phase-2A scan/build execution fences.

The default path is preflight-only.  The two mutating helpers are deliberately
separate and must be called explicitly by the final operator script after the
owner-application lane has supplied its sealed materialization/post-scan
ledger.  There is no automatic retry, new-build retry or pointer write here.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
from dataclasses import replace
from pathlib import Path
from typing import Any

from ..config import Settings
from ..crypto import LocalCipher
from ..db import Database
from ..ingestion.service import _configured_files, scan_configured_sources
from ..types import JobType
from .index_build import enqueue_index_build
from .phase2a_dynamic_scope import (
    EXPECTED_OWNER_PACKET_CONTENT_SHA256,
    execution_chain_run_id,
    load_dynamic_phase2a_scope,
)

OWNER_APPROVAL_RECEIPT_CONTENT_SHA256 = (
    "9b47af237fe4a811b51a4c21f02db1702b71505128576fa54cbd4794e1e739fa"
)
OWNER_APPROVAL_RECEIPT_FILE_SHA256 = (
    "dcf5f5f33debcbecff17552e074a9c12437d7b8cd77d0879c7d19072156c3383"
)
EXECUTION_AUTHORITY_CONTENT_SHA256 = (
    "eb0eda2f34c8b261ea38fc9d697257cdd3bd6253c18c2d91355328c8cb78ef7b"
)
EXECUTION_AUTHORITY_FILE_SHA256 = "5171ce79007c68484f9854b5188bf7e7af8f880407b6fbad6e3f808d0c7630ad"
ORIGINAL_OWNER_RECEIPT_CONTENT_SHA256 = (
    "a6ea2794b276946dd24ba3d752203dd81ae14f88aae24224a80b7b62f886d539"
)
PREFLIGHT_SCHEMA = "legalbot.v111.phase2a.final-scan-build-preflight.v1"
SOURCE_ROOT_INVENTORY_SCHEMA = "legalbot.v111.phase2a.source-root-inventory.v1"
SCAN_RECEIPT_SCHEMA = "legalbot.v111.phase2a.complete-source-scan-receipt.v1"
BUILD_RECEIPT_SCHEMA = "legalbot.v111.phase2a.non-active-successor-build-receipt.v1"
SCAN_CLAIM_SCHEMA = "legalbot.v111.phase2a.complete-source-scan-claim.v1"
BUILD_CLAIM_SCHEMA = "legalbot.v111.phase2a.non-active-successor-build-claim.v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MINIMUM_FREE_BYTES = 16 * 1024**3
_MINIMUM_MEMORY_BYTES = 12 * 1024**3
_MATERIALIZATION_NOT_RUN_FIELDS = (
    "source_scan_run",
    "successor_build_run",
    "index_built",
    "embedding_run",
    "retrieval_reattestation_run",
    "all585_qualification_run",
    "answer_model_run",
    "answer_released",
    "phase2b_run",
    "development30_run",
    "validation30_run",
    "promotion_run",
    "active_pointer_written",
    "previous_pointer_written",
    "live_activation_run",
    "training_export_run",
)
_EXECUTION_STAGE_SCHEMAS = {
    "legalbot.v111.phase2a.final-remediation-materialization-ledger.v1": (
        "materialization",
        "artifact_content_sha256",
    ),
    PREFLIGHT_SCHEMA: ("preflight", "preflight_content_sha256"),
    SCAN_CLAIM_SCHEMA: ("scan_claim", "scan_claim_content_sha256"),
    SCAN_RECEIPT_SCHEMA: ("scan_receipt", "scan_receipt_content_sha256"),
    "legalbot.v111.phase2a.owner-application-ledger.v1": (
        "owner_application",
        "artifact_content_sha256",
    ),
    BUILD_CLAIM_SCHEMA: ("build_claim", "build_claim_content_sha256"),
    BUILD_RECEIPT_SCHEMA: ("build_receipt", "build_receipt_content_sha256"),
}
_EXECUTION_STAGE_FILENAMES = {
    "MATERIALIZATION-LEDGER.json",
    "PRE-SCAN-PREFLIGHT.json",
    "SOURCE-SCAN-CLAIM.json",
    "SOURCE-SCAN-RECEIPT.json",
    "OWNER-APPLICATION-LEDGER.json",
    "SUCCESSOR-BUILD-CLAIM.json",
    "SUCCESSOR-BUILD-RECEIPT.json",
}


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(value: dict[str, Any], *, field: str) -> dict[str, Any]:
    output = dict(value)
    output[field] = _sha256_bytes(_canonical_json(output))
    return output


def _verify_seal(value: dict[str, Any], *, field: str, expected: str, code: str) -> None:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if supplied != expected or supplied != _sha256_bytes(_canonical_json(material)):
        raise ValueError(code)


def _load_json(path: Path, *, expected_file_sha256: str, code: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or _sha256_file(path) != expected_file_sha256:
        raise ValueError(code)
    try:
        value = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(code) from exc
    if not isinstance(value, dict):
        raise ValueError(code)
    return value


def _load_unpinned_json(path: Path, *, code: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(code)
    try:
        value = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(code) from exc
    if not isinstance(value, dict):
        raise ValueError(code)
    return value


def _review_relative_path(settings: Settings, path: Path, *, code: str) -> str:
    review_root = (settings.evaluation_dir / "phase2a-owner-review").resolve()
    if path.is_symlink():
        raise ValueError(code)
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(review_root)
    except ValueError as exc:
        raise ValueError(code) from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError(code)
    return relative.as_posix()


def _stage_authority(value: dict[str, Any]) -> str:
    return str(
        value.get("phase2a_execution_authority_content_sha256")
        or value.get("execution_authority_content_sha256")
        or ""
    )


def execution_stage_inventory(settings: Settings) -> dict[str, Any]:
    """Discover every final Phase-2A stage bound to the one authority.

    Only fixed filenames and schemas are eligible.  This keeps the check
    bounded while preventing a second materialization/scan/build receipt from
    silently starting another run under the same owner authority.
    """

    review_root = settings.evaluation_dir / "phase2a-owner-review"
    if review_root.is_symlink():
        raise ValueError("phase2a_execution_stage_review_root_invalid")
    if not review_root.exists():
        return _sealed(
            {
                "schema": "legalbot.v111.phase2a.execution-stage-inventory.v1",
                "execution_authority_content_sha256": EXECUTION_AUTHORITY_CONTENT_SHA256,
                "stage_count": 0,
                "stages": [],
            },
            field="inventory_content_sha256",
        )
    if not review_root.is_dir():
        raise ValueError("phase2a_execution_stage_review_root_invalid")
    records: list[dict[str, Any]] = []
    paths: list[Path] = []
    for filename in sorted(_EXECUTION_STAGE_FILENAMES):
        paths.extend(review_root.glob(f"*/{filename}"))
    for path in sorted(set(paths)):
        value = _load_unpinned_json(path, code="phase2a_execution_stage_artifact_invalid")
        schema = str(value.get("schema") or "")
        contract = _EXECUTION_STAGE_SCHEMAS.get(schema)
        if contract is None:
            continue
        authority = _stage_authority(value)
        if authority != EXECUTION_AUTHORITY_CONTENT_SHA256:
            raise ValueError("phase2a_execution_stage_authority_invalid")
        stage, seal_field = contract
        material = dict(value)
        supplied = str(material.pop(seal_field, ""))
        if _SHA256_RE.fullmatch(supplied) is None or supplied != _sha256_bytes(
            _canonical_json(material)
        ):
            raise ValueError("phase2a_execution_stage_seal_invalid")
        records.append(
            {
                "stage": stage,
                "schema": schema,
                "artifact_content_sha256": supplied,
                "relative_path": _review_relative_path(
                    settings,
                    path,
                    code="phase2a_execution_stage_path_invalid",
                ),
                "materialization_ledger_content_sha256": value.get(
                    "materialization_ledger_content_sha256"
                ),
                "preflight_content_sha256": value.get("preflight_content_sha256"),
                "source_scan_id": value.get("source_scan_id"),
                "source_scan_manifest_sha256": value.get("source_scan_manifest_sha256"),
                "phase2a_owner_application_ledger_content_sha256": value.get(
                    "phase2a_owner_application_ledger_content_sha256"
                ),
                "build_id": value.get("build_id"),
            }
        )
    records.sort(key=lambda item: (str(item["stage"]), str(item["relative_path"])))
    return _sealed(
        {
            "schema": "legalbot.v111.phase2a.execution-stage-inventory.v1",
            "execution_authority_content_sha256": EXECUTION_AUTHORITY_CONTENT_SHA256,
            "stage_count": len(records),
            "stages": records,
        },
        field="inventory_content_sha256",
    )


def _approval_root(settings: Settings) -> Path:
    return (
        settings.evaluation_dir
        / "phase2a-owner-review"
        / "LegalBot-Phase2A-2026-08-28-final-remediation-owner-approved-r1"
    )


def verify_execution_authority(settings: Settings) -> dict[str, Any]:
    root = _approval_root(settings)
    receipt = _load_json(
        root / "OWNER-ADOPTION-RECEIPT.json",
        expected_file_sha256=OWNER_APPROVAL_RECEIPT_FILE_SHA256,
        code="phase2a_final_owner_receipt_file_invalid",
    )
    authority = _load_json(
        root / "PHASE2A-EXECUTION-AUTHORITY.json",
        expected_file_sha256=EXECUTION_AUTHORITY_FILE_SHA256,
        code="phase2a_execution_authority_file_invalid",
    )
    _verify_seal(
        receipt,
        field="artifact_content_sha256",
        expected=OWNER_APPROVAL_RECEIPT_CONTENT_SHA256,
        code="phase2a_final_owner_receipt_seal_invalid",
    )
    _verify_seal(
        authority,
        field="artifact_content_sha256",
        expected=EXECUTION_AUTHORITY_CONTENT_SHA256,
        code="phase2a_execution_authority_seal_invalid",
    )
    if (
        receipt.get("schema") != "legalbot.v111.phase2a.final-remediation-owner-adoption-receipt.v1"
        or receipt.get("status")
        != "FINAL_REMEDIATION_OWNER_ADOPTION_RECORDED_EXECUTION_CHAIN_AVAILABLE"
        or receipt.get("final_owner_packet_content_sha256") != EXPECTED_OWNER_PACKET_CONTENT_SHA256
        or receipt.get("original_owner_receipt_content_sha256")
        != ORIGINAL_OWNER_RECEIPT_CONTENT_SHA256
        or receipt.get("execution_authority_content_sha256") != EXECUTION_AUTHORITY_CONTENT_SHA256
        or receipt.get("owner_approved") is not True
        or receipt.get("owner_adoption_recorded") is not True
        or receipt.get("complete_source_scan_authorized") is not True
        or receipt.get("successor_build_authorized") is not True
        or receipt.get("embedding_authorized") is not True
        or receipt.get("execution_chain_count") != 1
        or receipt.get("execution_chain_consumed_count") != 0
        or receipt.get("execution_chain_remaining_count") != 1
        or receipt.get("execution_chain_status") != "AVAILABLE_UNSPENT"
    ):
        raise ValueError("phase2a_final_owner_receipt_boundary_invalid")
    if (
        authority.get("schema") != "legalbot.v111.phase2a.final-remediation-execution-authority.v1"
        or authority.get("status") != "AVAILABLE_UNSPENT"
        or authority.get("final_owner_packet_content_sha256")
        != EXPECTED_OWNER_PACKET_CONTENT_SHA256
        or authority.get("authority_origin_owner_receipt_content_sha256")
        != ORIGINAL_OWNER_RECEIPT_CONTENT_SHA256
        or authority.get("complete_source_scan_maximum_count") != 1
        or authority.get("successor_build_with_embedding_maximum_count") != 1
        or authority.get("total_execution_chain_count") != 1
        or authority.get("execution_chain_consumed_count") != 0
        or authority.get("execution_chain_remaining_count") != 1
        or authority.get("successor_must_remain_non_active") is not True
        or authority.get("successor_must_remain_answer_ineligible") is not True
    ):
        raise ValueError("phase2a_execution_authority_boundary_invalid")
    for value in (receipt, authority):
        if (
            value.get("active_pointer_write_authorized") is not False
            or value.get("previous_pointer_write_authorized") is not False
            or value.get("answer_model_authorized") is not False
            or value.get("answer_release_authorized") is not False
            or value.get("phase2b_authorized") is not False
            or value.get("development30_authorized") is not False
            or value.get("validation30_authorized") is not False
            or value.get("promotion_authorized") is not False
            or value.get("live_activation_authorized") is not False
            or value.get("training_export_authorized") is not False
            or value.get("source_scan_run") is not False
            or value.get("successor_build_run") is not False
            or value.get("embedding_run") is not False
        ):
            raise ValueError("phase2a_execution_authority_release_boundary_invalid")
    return {"receipt": receipt, "authority": authority}


def exact_source_roots(settings: Settings) -> tuple[Path, Path, Path]:
    """Return only the three approved clean-room roots for this run."""

    return (
        Path("/Users/hltsang/Desktop/Law"),
        settings.project_root / "sources" / "materials-2026-08-12",
        settings.project_root / "sources" / "phase2a-approved-2026-08-27",
    )


def _root_inventory(root: Path, *, label: str) -> dict[str, Any]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"phase2a_source_root_{label}_invalid")
    if any(path.is_symlink() for path in root.rglob("*")):
        raise ValueError(f"phase2a_source_root_{label}_contains_symlink")
    digest = hashlib.sha256()
    count = 0
    total_bytes = 0
    for path in _configured_files(root):
        if path.is_symlink():
            raise ValueError(f"phase2a_source_root_{label}_contains_symlink")
        identity = path.lstat()
        if not stat.S_ISREG(identity.st_mode):
            raise ValueError(f"phase2a_source_root_{label}_contains_non_regular_file")
        relative = path.relative_to(root).as_posix().encode("utf-8")
        file_sha256 = bytes.fromhex(_sha256_file(path))
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(identity.st_size.to_bytes(8, "big"))
        digest.update(file_sha256)
        count += 1
        total_bytes += identity.st_size
    if count < 1:
        raise ValueError(f"phase2a_source_root_{label}_empty")
    return {
        "root_id": label,
        "file_count": count,
        "total_bytes": total_bytes,
        "tree_sha256": digest.hexdigest(),
        "symlink_count": 0,
    }


def source_root_inventory(settings: Settings) -> dict[str, Any]:
    roots = exact_source_roots(settings)
    resolved_roots = tuple(path.resolve() for path in roots)
    for index, root in enumerate(resolved_roots):
        for other in resolved_roots[index + 1 :]:
            if root == other or root in other.parents or other in root.parents:
                raise ValueError("phase2a_source_roots_overlap")
    records = [
        _root_inventory(root, label=label)
        for root, label in zip(
            roots,
            ("law", "base-approved-materials", "phase2a-approved-materialized"),
            strict=True,
        )
    ]
    return _sealed(
        {
            "schema": SOURCE_ROOT_INVENTORY_SCHEMA,
            "root_count": len(records),
            "file_count": sum(int(record["file_count"]) for record in records),
            "total_bytes": sum(int(record["total_bytes"]) for record in records),
            "roots": records,
            "absolute_paths_disclosed": False,
            "old_project_fallback_used": False,
        },
        field="inventory_content_sha256",
    )


def verify_materialization_ledger(
    settings: Settings, materialization_ledger_path: Path
) -> dict[str, Any]:
    if materialization_ledger_path.is_symlink() or not materialization_ledger_path.is_file():
        raise ValueError("phase2a_materialization_ledger_unavailable")
    try:
        ledger = json.loads(materialization_ledger_path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("phase2a_materialization_ledger_invalid") from exc
    if not isinstance(ledger, dict):
        raise ValueError("phase2a_materialization_ledger_invalid")
    material = dict(ledger)
    content_sha256 = str(material.pop("artifact_content_sha256", ""))
    if _SHA256_RE.fullmatch(content_sha256) is None or content_sha256 != _sha256_bytes(
        _canonical_json(material)
    ):
        raise ValueError("phase2a_materialization_ledger_seal_invalid")
    records = ledger.get("representations")
    packet_values = {
        str(value)
        for value in (
            ledger.get("phase2a_owner_packet_content_sha256"),
            ledger.get("final_owner_packet_content_sha256"),
        )
        if value is not None
    }
    receipt_values = {
        str(value)
        for value in (
            ledger.get("phase2a_owner_approval_receipt_content_sha256"),
            ledger.get("final_approval_receipt_content_sha256"),
        )
        if value is not None
    }
    if (
        ledger.get("schema") != "legalbot.v111.phase2a.final-remediation-materialization-ledger.v1"
        or ledger.get("status") != "OWNER_DECISIONS_APPLIED_SOURCE_MATERIALIZED_SCAN_NOT_RUN"
        or packet_values != {EXPECTED_OWNER_PACKET_CONTENT_SHA256}
        or receipt_values != {OWNER_APPROVAL_RECEIPT_CONTENT_SHA256}
        or ledger.get("execution_authority_content_sha256") != EXECUTION_AUTHORITY_CONTENT_SHA256
        or ledger.get("original_owner_receipt_content_sha256")
        != ORIGINAL_OWNER_RECEIPT_CONTENT_SHA256
        or ledger.get("source_root_relative_path") != "sources/phase2a-approved-2026-08-27"
        or ledger.get("materialized_source_root_relative_path")
        != ("sources/phase2a-approved-2026-08-27/final-remediation-2026-08-28-r1")
        or ledger.get("representation_count") != 254
        or ledger.get("materialized_file_count") != 254
        or ledger.get("index_eligible_representation_count") != 250
        or ledger.get("provenance_companion_count") != 4
        or ledger.get("owner_decisions_applied") is not True
        or ledger.get("source_materialized") is not True
        or ledger.get("catalogue_mutated") is not False
        or any(ledger.get(field) is not False for field in _MATERIALIZATION_NOT_RUN_FIELDS)
        or not isinstance(records, list)
        or len(records) != 254
    ):
        raise ValueError("phase2a_materialization_ledger_boundary_invalid")
    materialized_root = settings.project_root / str(
        ledger["materialized_source_root_relative_path"]
    )
    approved_root = settings.project_root / "sources" / "phase2a-approved-2026-08-27"
    if (
        materialized_root.is_symlink()
        or not materialized_root.is_dir()
        or materialized_root.parent.resolve() != approved_root.resolve()
    ):
        raise ValueError("phase2a_materialized_source_root_invalid")
    content_hashes: set[str] = set()
    target_paths: set[str] = set()
    index_count = 0
    provenance_count = 0
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("phase2a_materialization_record_invalid")
        record_material = dict(record)
        record_sha256 = str(record_material.pop("record_content_sha256", ""))
        content = str(record.get("content_sha256") or "")
        target_relative = str(record.get("target_relative_path") or "")
        relative = Path(target_relative)
        if (
            _SHA256_RE.fullmatch(record_sha256) is None
            or record_sha256 != _sha256_bytes(_canonical_json(record_material))
            or _SHA256_RE.fullmatch(content) is None
            or content in content_hashes
            or not target_relative
            or target_relative in target_paths
            or relative.is_absolute()
            or ".." in relative.parts
            or record.get("index_eligible") not in {True, False}
            or record.get("provenance_only") not in {True, False}
            or bool(record["index_eligible"]) == bool(record["provenance_only"])
        ):
            raise ValueError("phase2a_materialization_record_invalid")
        target = materialized_root / relative
        if (
            target.is_symlink()
            or not target.is_file()
            or _sha256_file(target) != content
            or target.stat().st_size != int(record.get("byte_size") or -1)
        ):
            raise ValueError("phase2a_materialized_source_file_invalid")
        content_hashes.add(content)
        target_paths.add(target_relative)
        index_count += int(record["index_eligible"] is True)
        provenance_count += int(record["provenance_only"] is True)
    physical_files = [
        path for path in materialized_root.rglob("*") if path.is_file() and not path.is_symlink()
    ]
    if len(physical_files) != 254 or index_count != 250 or provenance_count != 4:
        raise ValueError("phase2a_materialized_source_inventory_invalid")
    return {
        "content_sha256": content_sha256,
        "file_sha256": _sha256_file(materialization_ledger_path),
        "materialized_file_count": len(physical_files),
        "index_eligible_representation_count": index_count,
        "provenance_companion_count": provenance_count,
    }


def _directory_size(root: Path) -> int:
    total = 0
    if root.is_symlink() or not root.is_dir():
        return 0
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            total += path.stat().st_size
    return total


def _physical_memory_bytes() -> int:
    try:
        return int(os.sysconf("SC_PAGE_SIZE")) * int(os.sysconf("SC_PHYS_PAGES"))
    except (AttributeError, OSError, ValueError):
        return 0


def _pointer_snapshot(settings: Settings) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name in ("ACTIVE.json", "PREVIOUS.json"):
        path = settings.index_dir / name
        if path.is_symlink():
            raise ValueError("phase2a_index_pointer_is_symlink")
        result[name] = {
            "exists": path.exists(),
            "sha256": _sha256_file(path) if path.is_file() else None,
        }
    return result


def _active_catalogue_work(database: Database) -> dict[str, int]:
    scan = database.fetchone(
        "SELECT COUNT(*) AS n FROM source_scans WHERE status IN ('queued','running')"
    )
    jobs = database.fetchone(
        """
        SELECT COUNT(*) AS n FROM jobs
        WHERE job_type=? AND status IN ('queued','running')
        """,
        (JobType.INDEX_BUILD,),
    )
    builds = database.fetchone(
        "SELECT COUNT(*) AS n FROM index_builds WHERE status IN ('queued','building')"
    )
    return {
        "active_source_scan_count": int(scan["n"] if scan else 0),
        "active_index_job_count": int(jobs["n"] if jobs else 0),
        "active_index_build_count": int(builds["n"] if builds else 0),
    }


def build_preflight(
    settings: Settings,
    database: Database,
    *,
    predecessor_build_id: str,
    materialization_ledger_path: Path | None = None,
) -> dict[str, Any]:
    authority = verify_execution_authority(settings)
    stage_inventory = execution_stage_inventory(settings)
    inventory = source_root_inventory(settings)
    pointers = _pointer_snapshot(settings)
    active = _active_catalogue_work(database)
    blockers: list[str] = []
    if any(item["exists"] for item in pointers.values()):
        blockers.append("ACTIVE_OR_PREVIOUS_POINTER_PRESENT")
    if any(active.values()):
        blockers.append("CONCURRENT_SCAN_OR_BUILD_PRESENT")
    predecessor_path = settings.index_dir / "builds" / predecessor_build_id
    predecessor_size = _directory_size(predecessor_path)
    if predecessor_size < 1:
        blockers.append("PRIOR_251_SOURCE_CANDIDATE_UNAVAILABLE")
    disk = shutil.disk_usage(settings.project_root)
    required_free = max(
        _MINIMUM_FREE_BYTES,
        predecessor_size * 3 + int(inventory["total_bytes"]),
    )
    if disk.free < required_free:
        blockers.append("INSUFFICIENT_FREE_DISK")
    memory_bytes = _physical_memory_bytes()
    if memory_bytes and memory_bytes < _MINIMUM_MEMORY_BYTES:
        blockers.append("INSUFFICIENT_PHYSICAL_MEMORY")
    for model_path in (settings.embedding_model_path, settings.reranker_model_path):
        if model_path.is_symlink() or not model_path.is_dir():
            blockers.append("RETRIEVAL_MODEL_UNAVAILABLE")
            break

    materialization_ledger_sha256 = None
    materialization_ledger_file_sha256 = None
    if materialization_ledger_path is None:
        blockers.append("MATERIALIZATION_LEDGER_NOT_SUPPLIED")
    elif materialization_ledger_path.is_symlink() or not materialization_ledger_path.is_file():
        blockers.append("MATERIALIZATION_LEDGER_UNAVAILABLE")
    else:
        try:
            materialization = verify_materialization_ledger(settings, materialization_ledger_path)
        except ValueError:
            blockers.append("MATERIALIZATION_LEDGER_INVALID")
        else:
            materialization_ledger_sha256 = str(materialization["content_sha256"])
            materialization_ledger_file_sha256 = str(materialization["file_sha256"])
            resolved_materialization_ledger_path = materialization_ledger_path.resolve()

    prior_by_stage: dict[str, list[dict[str, Any]]] = {}
    for record in stage_inventory["stages"]:
        prior_by_stage.setdefault(str(record["stage"]), []).append(record)
    materialization_stages = prior_by_stage.get("materialization", [])
    if materialization_ledger_sha256 is not None:
        matching_materialization = [
            record
            for record in materialization_stages
            if record["artifact_content_sha256"] == materialization_ledger_sha256
            and (
                settings.evaluation_dir / "phase2a-owner-review" / str(record["relative_path"])
            ).resolve()
            == resolved_materialization_ledger_path
        ]
        if len(materialization_stages) != 1 or len(matching_materialization) != 1:
            blockers.append("CONFLICTING_EXECUTION_MATERIALIZATION_STAGE")
    elif materialization_stages:
        blockers.append("UNBOUND_EXECUTION_MATERIALIZATION_STAGE_PRESENT")
    if prior_by_stage.get("preflight"):
        blockers.append("PRIOR_EXECUTION_PREFLIGHT_PRESENT")
    if any(
        prior_by_stage.get(stage)
        for stage in (
            "scan_claim",
            "scan_receipt",
            "owner_application",
            "build_claim",
            "build_receipt",
        )
    ):
        blockers.append("PRIOR_EXECUTION_STAGE_RECEIPT_PRESENT")

    scan_identity_material = {
        "schema": "legalbot.v111.phase2a.final-source-scan-identity.v1",
        "execution_authority_content_sha256": EXECUTION_AUTHORITY_CONTENT_SHA256,
        "source_root_inventory_content_sha256": inventory["inventory_content_sha256"],
        "materialization_ledger_content_sha256": materialization_ledger_sha256,
    }
    chain_run_id = (
        execution_chain_run_id(materialization_ledger_sha256)
        if materialization_ledger_sha256 is not None
        else None
    )
    scan_id = "phase2a-final-" + _sha256_bytes(_canonical_json(scan_identity_material))[:16]
    existing_scan = database.fetchone("SELECT status FROM source_scans WHERE id=?", (scan_id,))
    if existing_scan is not None:
        blockers.append("EXACT_SOURCE_SCAN_ID_ALREADY_EXISTS")
    return _sealed(
        {
            "schema": PREFLIGHT_SCHEMA,
            "status": "READY_FOR_ONE_SOURCE_SCAN" if not blockers else "BLOCKED_PREFLIGHT",
            "phase2a_owner_packet_content_sha256": EXPECTED_OWNER_PACKET_CONTENT_SHA256,
            "phase2a_owner_approval_receipt_content_sha256": (
                OWNER_APPROVAL_RECEIPT_CONTENT_SHA256
            ),
            "phase2a_execution_authority_content_sha256": (EXECUTION_AUTHORITY_CONTENT_SHA256),
            "execution_chain_id": authority["authority"]["chain_id"],
            "execution_chain_run_id": chain_run_id,
            "execution_stage_inventory_content_sha256": stage_inventory["inventory_content_sha256"],
            "execution_stage_count_before_preflight": stage_inventory["stage_count"],
            "source_root_inventory": inventory,
            "source_root_inventory_content_sha256": inventory["inventory_content_sha256"],
            "materialization_ledger_content_sha256": materialization_ledger_sha256,
            "materialization_ledger_file_sha256": materialization_ledger_file_sha256,
            "source_scan_id": scan_id,
            "predecessor_build_id": predecessor_build_id,
            "predecessor_build_bytes": predecessor_size,
            "free_disk_bytes": disk.free,
            "required_free_disk_bytes": required_free,
            "physical_memory_bytes": memory_bytes,
            "pointers_before": pointers,
            "active_catalogue_work": active,
            "blockers": blockers,
            "source_scan_run": False,
            "successor_build_run": False,
            "embedding_run": False,
            "automatic_retry": False,
            "new_build_retry_authorized": False,
            "same_build_identity_resume_only": True,
            "active_or_previous_write_authorized": False,
            "answer_release_eligible": False,
            "phase2b_authorized": False,
        },
        field="preflight_content_sha256",
    )


def run_complete_source_scan_once(
    settings: Settings,
    database: Database,
    cipher: LocalCipher,
    *,
    preflight: dict[str, Any],
) -> dict[str, Any]:
    """Run the single scan only when the exact preflight is still current."""

    expected = str(preflight.get("preflight_content_sha256") or "")
    _verify_seal(
        preflight,
        field="preflight_content_sha256",
        expected=expected,
        code="phase2a_scan_preflight_seal_invalid",
    )
    if preflight.get("status") != "READY_FOR_ONE_SOURCE_SCAN":
        raise ValueError("phase2a_scan_preflight_not_ready")
    if preflight.get("execution_chain_run_id") != execution_chain_run_id(
        str(preflight.get("materialization_ledger_content_sha256") or "")
    ):
        raise ValueError("phase2a_scan_execution_chain_identity_invalid")
    stages = execution_stage_inventory(settings)["stages"]
    matching_preflights = [
        record
        for record in stages
        if record["stage"] == "preflight" and record["artifact_content_sha256"] == expected
    ]
    matching_materializations = [
        record
        for record in stages
        if record["stage"] == "materialization"
        and record["artifact_content_sha256"]
        == preflight.get("materialization_ledger_content_sha256")
    ]
    if (
        len(matching_preflights) != 1
        or len(matching_materializations) != 1
        or any(
            record["stage"] in {"scan_receipt", "owner_application", "build_claim", "build_receipt"}
            for record in stages
        )
    ):
        raise ValueError("phase2a_scan_execution_chain_stage_invalid")
    current_inventory = source_root_inventory(settings)
    if current_inventory["inventory_content_sha256"] != preflight.get(
        "source_root_inventory_content_sha256"
    ):
        raise ValueError("phase2a_source_inventory_changed_after_preflight")
    if any(item["exists"] for item in _pointer_snapshot(settings).values()):
        raise ValueError("phase2a_pointer_present_before_scan")
    if any(_active_catalogue_work(database).values()):
        raise ValueError("phase2a_concurrent_scan_or_build_before_scan")
    scan_settings = replace(settings, explicit_source_roots=exact_source_roots(settings))
    result = scan_configured_sources(
        scan_settings,
        database,
        cipher,
        str(preflight["source_scan_id"]),
    )
    scan = database.fetchone(
        """
        SELECT id,status,expected_file_count,files_accounted,manifest_sha256,
               required_roots_json,roots_seen_json FROM source_scans WHERE id=?
        """,
        (preflight["source_scan_id"],),
    )
    if (
        scan is None
        or scan["status"] != "complete"
        or int(scan["expected_file_count"] or -1) != int(current_inventory["file_count"])
        or int(scan["files_accounted"] or -2) != int(current_inventory["file_count"])
        or scan["required_roots_json"] != scan["roots_seen_json"]
        or not _SHA256_RE.fullmatch(str(scan["manifest_sha256"] or ""))
        or result.get("wrote_active") is not False
    ):
        raise RuntimeError("phase2a_complete_source_scan_not_reconciled")
    pointers_after = _pointer_snapshot(settings)
    if any(item["exists"] for item in pointers_after.values()):
        raise RuntimeError("phase2a_source_scan_wrote_pointer")
    return _sealed(
        {
            "schema": SCAN_RECEIPT_SCHEMA,
            "status": "ONE_COMPLETE_SOURCE_SCAN_RECONCILED",
            "phase2a_owner_packet_content_sha256": EXPECTED_OWNER_PACKET_CONTENT_SHA256,
            "phase2a_owner_approval_receipt_content_sha256": (
                OWNER_APPROVAL_RECEIPT_CONTENT_SHA256
            ),
            "phase2a_execution_authority_content_sha256": (EXECUTION_AUTHORITY_CONTENT_SHA256),
            "preflight_content_sha256": preflight["preflight_content_sha256"],
            "materialization_ledger_content_sha256": preflight[
                "materialization_ledger_content_sha256"
            ],
            "execution_chain_run_id": preflight["execution_chain_run_id"],
            "source_root_inventory_content_sha256": current_inventory["inventory_content_sha256"],
            "source_scan_id": scan["id"],
            "source_scan_manifest_sha256": scan["manifest_sha256"],
            "source_scan_expected_file_count": int(scan["expected_file_count"]),
            "source_scan_files_accounted": int(scan["files_accounted"]),
            "pointers_after": pointers_after,
            "source_scan_run": True,
            "successor_build_run": False,
            "embedding_run": False,
            "automatic_retry": False,
            "active_or_previous_written": False,
            "phase2b_authorized": False,
        },
        field="scan_receipt_content_sha256",
    )


def dynamic_build_id(scope: dict[str, Any]) -> str:
    ledger_sha256 = str(scope.get("phase2a_owner_application_ledger_content_sha256") or "")
    if _SHA256_RE.fullmatch(ledger_sha256) is None:
        raise ValueError("phase2a_build_application_ledger_digest_invalid")
    return f"current-law-ew-full-fp16-v111-20260828-phase2a-{ledger_sha256[:16]}"


def run_non_active_successor_build_once(
    settings: Settings,
    database: Database,
    *,
    corpus_id: str,
    worker_id: str,
) -> dict[str, Any]:
    """Enqueue and claim exactly one build attempt; never retries automatically."""

    from ..orchestration.index_worker import DedicatedIndexWorker

    verify_execution_authority(settings)
    scope = load_dynamic_phase2a_scope(settings, corpus_id)
    stages = execution_stage_inventory(settings)["stages"]
    if (
        len(
            [
                record
                for record in stages
                if record["stage"] == "materialization"
                and record["artifact_content_sha256"]
                == scope["materialization_ledger_content_sha256"]
            ]
        )
        != 1
        or len(
            [
                record
                for record in stages
                if record["stage"] == "scan_receipt"
                and record["source_scan_id"] == scope["source_scan_id"]
                and record["source_scan_manifest_sha256"] == scope["source_scan_manifest_sha256"]
            ]
        )
        != 1
        or len(
            [
                record
                for record in stages
                if record["stage"] == "owner_application"
                and record["artifact_content_sha256"]
                == scope["phase2a_owner_application_ledger_content_sha256"]
            ]
        )
        != 1
        or any(record["stage"] in {"build_claim", "build_receipt"} for record in stages)
    ):
        raise ValueError("phase2a_build_execution_chain_stage_invalid")
    pointers_before = _pointer_snapshot(settings)
    if any(item["exists"] for item in pointers_before.values()):
        raise ValueError("phase2a_pointer_present_before_build")
    if any(_active_catalogue_work(database).values()):
        raise ValueError("phase2a_concurrent_scan_or_build_before_build")
    build_id = dynamic_build_id(scope)
    if database.fetchone("SELECT id FROM index_builds WHERE id=?", (build_id,)) is not None:
        raise ValueError("phase2a_exact_successor_build_identity_already_exists")
    queued = enqueue_index_build(
        settings,
        database,
        corpus_id=corpus_id,
        build_id=build_id,
        max_chunks=None,
        preferred_small_first=False,
        reuse_vectors_from_build_id=str(scope["predecessor_build_id"]),
    )
    if (
        queued.get("build_id") != build_id
        or queued.get("source_count") != scope["source_count"]
        or queued.get("chunk_count") != scope["chunk_count"]
        or queued.get("reused") is not False
    ):
        raise RuntimeError("phase2a_successor_enqueue_identity_changed")
    row = database.claim_next_job(worker_id, job_types=(JobType.INDEX_BUILD,))
    if row is None:
        raise RuntimeError("phase2a_exact_successor_job_not_claimed")
    if (
        row["id"] != queued["job_id"]
        or row["pinned_index_build_id"] != build_id
        or int(row["attempt_count"] or 0) != 1
    ):
        database.release_job_lease(str(row["id"]), worker_id)
        raise RuntimeError("phase2a_successor_claimed_wrong_job_or_attempt")
    DedicatedIndexWorker(settings, database, worker_id=worker_id)._run_claim(dict(row))
    job = database.job(str(queued["job_id"]))
    build = database.fetchone(
        """
        SELECT status,stage,document_count,chunk_count,vector_count,
               manifest_sha256,candidate_manifest_hash,failure_reason_code,counts_json
        FROM index_builds WHERE id=?
        """,
        (build_id,),
    )
    pointers_after = _pointer_snapshot(settings)
    if (
        job is None
        or build is None
        or int(job["attempt_count"] or 0) != 1
        or any(item["exists"] for item in pointers_after.values())
    ):
        raise RuntimeError("phase2a_single_build_attempt_boundary_changed")
    succeeded = job["status"] == "complete" and build["status"] == "built_unscored"
    if succeeded and (
        int(build["document_count"] or 0) != int(scope["source_count"])
        or int(build["chunk_count"] or 0) != int(scope["chunk_count"])
        or int(build["vector_count"] or 0) != int(scope["chunk_count"])
        or build["manifest_sha256"] != build["candidate_manifest_hash"]
        or build["failure_reason_code"] not in (None, "")
    ):
        raise RuntimeError("phase2a_non_active_successor_counts_changed")
    return _sealed(
        {
            "schema": BUILD_RECEIPT_SCHEMA,
            "status": (
                "NON_ACTIVE_ANSWER_INELIGIBLE_SUCCESSOR_BUILT"
                if succeeded
                else "SINGLE_BUILD_ATTEMPT_STOPPED_FOR_DEBUG"
            ),
            "phase2a_owner_packet_content_sha256": EXPECTED_OWNER_PACKET_CONTENT_SHA256,
            "phase2a_owner_approval_receipt_content_sha256": (
                OWNER_APPROVAL_RECEIPT_CONTENT_SHA256
            ),
            "phase2a_owner_application_ledger_content_sha256": scope[
                "phase2a_owner_application_ledger_content_sha256"
            ],
            "phase2a_execution_authority_content_sha256": (EXECUTION_AUTHORITY_CONTENT_SHA256),
            "materialization_ledger_content_sha256": scope["materialization_ledger_content_sha256"],
            "execution_chain_run_id": scope["execution_chain_run_id"],
            "source_scan_id": scope["source_scan_id"],
            "source_scan_manifest_sha256": scope["source_scan_manifest_sha256"],
            "source_version_id_set_sha256": scope["source_version_id_set_sha256"],
            "corpus_id": corpus_id,
            "build_id": build_id,
            "job_id": queued["job_id"],
            "source_manifest_sha256": queued["source_manifest_hash"],
            "source_count": int(scope["source_count"]),
            "chunk_count": int(scope["chunk_count"]),
            "job_status": str(job["status"]),
            "build_status": str(build["status"]),
            "build_stage": str(build["stage"]),
            "failure_reason_code": build["failure_reason_code"],
            "attempt_count": int(job["attempt_count"] or 0),
            "automatic_second_attempt": False,
            "new_build_retry_authorized": False,
            "same_build_identity_resume_only": True,
            "answer_release_eligible": False,
            "successor_must_remain_non_active": True,
            "pointers_before": pointers_before,
            "pointers_after": pointers_after,
            "active_or_previous_written": False,
            "phase2b_authorized": False,
        },
        field="build_receipt_content_sha256",
    )


def assess_same_identity_embedding_resume(
    settings: Settings,
    database: Database,
    *,
    corpus_id: str,
    build_id: str,
) -> dict[str, Any]:
    """Read-only resume assessment; it never requeues or claims a job."""

    from .incomplete_index_audit import audit_incomplete_index

    scope = load_dynamic_phase2a_scope(settings, corpus_id)
    if build_id != dynamic_build_id(scope):
        raise ValueError("phase2a_resume_requires_same_build_identity")
    job = database.job(f"index-{build_id}")
    build = database.fetchone(
        "SELECT status,stage,failure_reason_code FROM index_builds WHERE id=?",
        (build_id,),
    )
    if job is None or build is None:
        raise ValueError("phase2a_resume_build_unavailable")
    request = json.loads(str(job["request_json"] or "{}"))
    audit = audit_incomplete_index(settings, database, build_id)
    eligible = bool(
        int(job["attempt_count"] or 0) == 1
        and request.get("build_id") == build_id
        and request.get("corpus_id") == corpus_id
        and request.get("approved_source_manifest_hash")
        and request.get("source_version_ids")
        == [str(source["source_version_id"]) for source in scope["sources"]]
        and build["status"] == "failed"
        and audit.get("resumable") is True
        and not any(item["exists"] for item in _pointer_snapshot(settings).values())
    )
    return {
        "schema": "legalbot.v111.phase2a.same-build-resume-assessment.v1",
        "eligible": eligible,
        "build_id": build_id,
        "corpus_id": corpus_id,
        "attempt_count": int(job["attempt_count"] or 0),
        "same_build_identity": True,
        "new_build_created": False,
        "automatic_resume": False,
        "targeted_debug_required_before_resume": True,
        "audit_resumable": audit.get("resumable") is True,
        "active_or_previous_written": False,
    }


__all__ = [
    "EXECUTION_AUTHORITY_CONTENT_SHA256",
    "OWNER_APPROVAL_RECEIPT_CONTENT_SHA256",
    "assess_same_identity_embedding_resume",
    "build_preflight",
    "dynamic_build_id",
    "exact_source_roots",
    "run_complete_source_scan_once",
    "run_non_active_successor_build_once",
    "source_root_inventory",
    "verify_execution_authority",
]
