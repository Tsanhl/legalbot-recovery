"""Exact predecessor proof for one held General Enquiries index expansion.

The proof is read-only.  It authenticates a completed immutable predecessor,
its database row and its three controlling files, then snapshots every source
manifest member in its original order.  It does not open Lance, enqueue work,
write an index pointer, or authorize the successor.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ..config import Settings
from ..contracts import canonical_json_bytes, load_json_strict
from ..db import Database

EXPANSION_MODE = "strict_successor"
PREDECESSOR_PROOF_SCHEMA = "legalbot.ge-strict-predecessor-proof.v1"
MEMBER_SEQUENCE_SCHEMA = "legalbot.ge-source-member-sequence.v1"
MEMBER_SET_SCHEMA = "legalbot.ge-source-member-set.v1"
SOURCE_ID_SET_SCHEMA = "legalbot.ge-source-version-id-set.v1"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_BUILD_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_QUALIFYING_STATUSES = {"candidate": "candidate", "built_unscored": "built_unscored"}
_REQUIRED_PROOF_FIELDS = frozenset(
    {
        "schema",
        "expansion_mode",
        "build_id",
        "build_status",
        "build_stage",
        "index_build_record_sha256",
        "seal_file_sha256",
        "build_manifest_file_sha256",
        "source_manifest_file_sha256",
        "source_manifest_sha256",
        "source_member_count",
        "source_chunk_count",
        "source_version_ids",
        "source_version_id_set_sha256",
        "source_member_sha256s",
        "source_member_set_sha256",
        "source_member_sequence_sha256",
        "source_members",
        "source_lane_bindings",
        "source_lane_binding_sha256",
        "active_pointer_absent",
        "previous_pointer_absent",
        "promotion_history_absent",
        "content_sha256",
    }
)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _stored_value(value: Any) -> Any:
    if isinstance(value, bytes | bytearray | memoryview):
        raw = bytes(value)
        return {
            "type": "bytes",
            "length": len(raw),
            "base64": base64.b64encode(raw).decode("ascii"),
        }
    if value is None or isinstance(value, bool | str | int | float):
        return value
    raise ValueError("ge_predecessor_stored_record_type_invalid")


def _stored_record_sha256(row: Any) -> str:
    snapshot = {
        "schema": "legalbot.exact-stored-record.v1",
        "table": "index_builds",
        "fields": {
            str(key): _stored_value(row[key]) for key in row.keys()  # noqa: SIM118
        },
    }
    return hashlib.sha256(canonical_json_bytes(snapshot)).hexdigest()


def _strict_object(path: Path, *, code: str) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size < 2:
        raise ValueError(code)
    raw = path.read_bytes()
    try:
        value = load_json_strict(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(code) from exc
    if not isinstance(value, dict):
        raise ValueError(code)
    return dict(value), raw


def _source_manifest_sha256(manifest: Mapping[str, Any]) -> str:
    identity = {
        key: value
        for key, value in manifest.items()
        if key not in {"created_at", "manifest_sha256"}
    }
    encoded = (
        json.dumps(
            identity,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def source_member_sha256(member: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(dict(member))).hexdigest()


def source_version_id_set_sha256(source_version_ids: Sequence[str]) -> str:
    values = sorted(source_version_ids)
    if not values or len(values) != len(set(values)) or any(not value for value in values):
        raise ValueError("ge_expansion_source_version_set_invalid")
    return hashlib.sha256(
        canonical_json_bytes(
            {"schema": SOURCE_ID_SET_SCHEMA, "source_version_ids": values}
        )
    ).hexdigest()


def source_member_sequence_sha256(
    source_members: Sequence[Mapping[str, Any]],
) -> str:
    if not source_members:
        raise ValueError("ge_expansion_source_members_empty")
    entries = [
        {
            "ordinal": ordinal,
            "source_version_id": str(member.get("source_version_id") or ""),
            "member_sha256": source_member_sha256(member),
        }
        for ordinal, member in enumerate(source_members)
    ]
    if any(not entry["source_version_id"] for entry in entries):
        raise ValueError("ge_expansion_source_member_invalid")
    return hashlib.sha256(
        canonical_json_bytes({"schema": MEMBER_SEQUENCE_SCHEMA, "members": entries})
    ).hexdigest()


def source_member_set_sha256(source_members: Sequence[Mapping[str, Any]]) -> str:
    if not source_members:
        raise ValueError("ge_expansion_source_members_empty")
    entries = sorted(
        (
            {
                "source_version_id": str(member.get("source_version_id") or ""),
                "member_sha256": source_member_sha256(member),
            }
            for member in source_members
        ),
        key=lambda item: item["source_version_id"],
    )
    if any(not entry["source_version_id"] for entry in entries) or len(entries) != len(
        {entry["source_version_id"] for entry in entries}
    ):
        raise ValueError("ge_expansion_source_member_invalid")
    return hashlib.sha256(
        canonical_json_bytes({"schema": MEMBER_SET_SCHEMA, "members": entries})
    ).hexdigest()


def _lane_bindings(manifest: Mapping[str, Any]) -> list[dict[str, str]]:
    # Local import keeps this low-level verifier outside the source-manifest /
    # GE-scope import cycle.
    from .incomplete_index_audit import source_lane_bindings_for_manifest

    return [binding.as_dict() for binding in source_lane_bindings_for_manifest(manifest)]


def _lane_binding_sha256(bindings: Sequence[Mapping[str, Any]]) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "schema": "legalbot.ge-index-source-lane-bindings.v1",
                "bindings": [dict(binding) for binding in bindings],
            }
        )
    ).hexdigest()


def _pointer_build_id(path: Path) -> str | None:
    if not path.exists():
        return None
    value, _raw = _strict_object(path, code="ge_predecessor_pointer_invalid")
    build_id = str(value.get("build_id") or "")
    if not build_id:
        raise ValueError("ge_predecessor_pointer_invalid")
    return build_id


def _verified_build_path(settings: Settings, row: Mapping[str, Any], build_id: str) -> Path:
    builds_root = (settings.index_dir / "builds").resolve(strict=True)
    build_path = settings.index_dir / "builds" / build_id
    if (
        build_path.is_symlink()
        or not build_path.is_dir()
        or build_path.resolve(strict=True).parent != builds_root
        or (settings.index_dir / "builds" / f".{build_id}.incomplete").exists()
    ):
        raise ValueError("ge_predecessor_build_tree_invalid")
    stored = Path(str(row.get("path") or ""))
    stored_path = stored if stored.is_absolute() else settings.project_root / stored
    if stored_path.resolve(strict=False) != build_path.resolve(strict=True):
        raise ValueError("ge_predecessor_build_path_differed")
    return build_path


def load_verified_ge_predecessor(
    settings: Settings,
    database: Database,
    predecessor_build_id: str,
) -> dict[str, Any]:
    """Replay one exact completed, sealed and never-promoted predecessor."""

    if _BUILD_ID_RE.fullmatch(predecessor_build_id) is None:
        raise ValueError("ge_predecessor_build_id_invalid")
    row = database.fetchone("SELECT * FROM index_builds WHERE id=?", (predecessor_build_id,))
    if row is None:
        raise ValueError("ge_predecessor_index_build_missing")
    status = str(row["status"] or "")
    stage = str(row["stage"] or "")
    if (
        status not in _QUALIFYING_STATUSES
        or stage != _QUALIFYING_STATUSES[status]
        or row["promoted_at"] is not None
        or str(row["promotion_decision"] or "") != "not_requested"
    ):
        raise ValueError("ge_predecessor_not_completed_non_active")
    build_path = _verified_build_path(settings, dict(row), predecessor_build_id)
    paths = {
        "seal": build_path / "seal.json",
        "build_manifest": build_path / "manifest.json",
        "source_manifest": build_path / "approved-source-manifest.json",
    }
    seal, seal_raw = _strict_object(paths["seal"], code="ge_predecessor_seal_invalid")
    build_manifest, _build_raw = _strict_object(
        paths["build_manifest"], code="ge_predecessor_build_manifest_invalid"
    )
    source_manifest, _source_raw = _strict_object(
        paths["source_manifest"], code="ge_predecessor_source_manifest_invalid"
    )
    seal_sha256 = hashlib.sha256(seal_raw).hexdigest()
    build_manifest_file_sha256 = _file_sha256(paths["build_manifest"])
    source_manifest_file_sha256 = _file_sha256(paths["source_manifest"])
    source_manifest_sha256 = _source_manifest_sha256(source_manifest)
    if (
        seal.get("schema") != "legalbot.index-seal.v2"
        or seal.get("build_id") != predecessor_build_id
        or seal.get("promotion") != "not_requested"
        or seal.get("manifest_sha256") != build_manifest_file_sha256
        or seal.get("source_manifest_file_sha256") != source_manifest_file_sha256
        or build_manifest.get("schema") != "legalbot.lance-build.v1"
        or build_manifest.get("build_id") != predecessor_build_id
        or build_manifest.get("sealed") is not True
        or build_manifest.get("source_manifest_sha256") != source_manifest_sha256
        or source_manifest.get("schema") != "legalbot.approved-source-manifest.v1"
        or source_manifest.get("manifest_sha256") != source_manifest_sha256
        or str(row["manifest_sha256"] or "") != seal_sha256
        or str(row["candidate_manifest_hash"] or "") != seal_sha256
        or str(row["source_manifest_hash"] or "") != source_manifest_sha256
    ):
        raise ValueError("ge_predecessor_sealed_identity_differed")
    raw_members = source_manifest.get("sources")
    if not isinstance(raw_members, list) or not raw_members:
        raise ValueError("ge_predecessor_source_members_invalid")
    members: list[dict[str, Any]] = []
    source_ids: list[str] = []
    document_ids: list[str] = []
    stable_ids: list[str] = []
    for value in raw_members:
        if not isinstance(value, dict):
            raise ValueError("ge_predecessor_source_member_invalid")
        member = dict(value)
        source_id = str(member.get("source_version_id") or "")
        document_id = str(member.get("document_id") or "")
        stable_id = str(member.get("stable_identifier") or "")
        lane = str(member.get("lane") or "")
        if (
            not source_id
            or not document_id
            or not stable_id
            or lane not in {"primary_authority", "official_secondary"}
            or int(member.get("body_chunk_count") or 0) < 1
        ):
            raise ValueError("ge_predecessor_source_member_invalid")
        members.append(member)
        source_ids.append(source_id)
        document_ids.append(document_id)
        stable_ids.append(stable_id)
    if (
        len(source_ids) != len(set(source_ids))
        or len(document_ids) != len(set(document_ids))
        or len(stable_ids) != len(set(stable_ids))
        or int(source_manifest.get("source_count") or -1) != len(members)
        or int(source_manifest.get("chunk_count") or -1)
        != sum(int(member["body_chunk_count"]) for member in members)
        or int(row["document_count"] or -1) != len(members)
        or int(row["chunk_count"] or -1) != int(source_manifest["chunk_count"])
        or int(row["vector_count"] or -1) != int(source_manifest["chunk_count"])
    ):
        raise ValueError("ge_predecessor_source_inventory_differed")
    lane_bindings = _lane_bindings(source_manifest)
    if [binding["source_version_id"] for binding in lane_bindings] != source_ids:
        raise ValueError("ge_predecessor_source_lane_order_differed")
    active_id = _pointer_build_id(settings.index_dir / "ACTIVE.json")
    previous_id = _pointer_build_id(settings.index_dir / "PREVIOUS.json")
    if predecessor_build_id in {active_id, previous_id}:
        raise ValueError("ge_predecessor_release_pointer_history_forbidden")

    member_sha256s = [source_member_sha256(member) for member in members]
    proof: dict[str, Any] = {
        "schema": PREDECESSOR_PROOF_SCHEMA,
        "expansion_mode": EXPANSION_MODE,
        "build_id": predecessor_build_id,
        "build_status": status,
        "build_stage": stage,
        "index_build_record_sha256": _stored_record_sha256(row),
        "seal_file_sha256": seal_sha256,
        "build_manifest_file_sha256": build_manifest_file_sha256,
        "source_manifest_file_sha256": source_manifest_file_sha256,
        "source_manifest_sha256": source_manifest_sha256,
        "source_member_count": len(members),
        "source_chunk_count": int(source_manifest["chunk_count"]),
        "source_version_ids": source_ids,
        "source_version_id_set_sha256": source_version_id_set_sha256(source_ids),
        "source_member_sha256s": member_sha256s,
        "source_member_set_sha256": source_member_set_sha256(members),
        "source_member_sequence_sha256": source_member_sequence_sha256(members),
        "source_members": members,
        "source_lane_bindings": lane_bindings,
        "source_lane_binding_sha256": _lane_binding_sha256(lane_bindings),
        "active_pointer_absent": True,
        "previous_pointer_absent": True,
        "promotion_history_absent": True,
    }
    proof["content_sha256"] = hashlib.sha256(canonical_json_bytes(proof)).hexdigest()
    return proof


def validate_ge_predecessor_proof(proof: Mapping[str, Any]) -> str:
    if set(proof) != _REQUIRED_PROOF_FIELDS:
        raise ValueError("ge_predecessor_proof_fields_invalid")
    material = dict(proof)
    supplied = str(material.pop("content_sha256", ""))
    actual = hashlib.sha256(canonical_json_bytes(material)).hexdigest()
    if _SHA256_RE.fullmatch(supplied) is None or supplied != actual:
        raise ValueError("ge_predecessor_proof_seal_invalid")
    if (
        proof.get("schema") != PREDECESSOR_PROOF_SCHEMA
        or proof.get("expansion_mode") != EXPANSION_MODE
        or proof.get("build_status") not in _QUALIFYING_STATUSES
        or proof.get("build_stage") != _QUALIFYING_STATUSES[proof["build_status"]]
        or proof.get("active_pointer_absent") is not True
        or proof.get("previous_pointer_absent") is not True
        or proof.get("promotion_history_absent") is not True
    ):
        raise ValueError("ge_predecessor_proof_boundary_invalid")
    for field in (
        "index_build_record_sha256",
        "seal_file_sha256",
        "build_manifest_file_sha256",
        "source_manifest_file_sha256",
        "source_manifest_sha256",
        "source_version_id_set_sha256",
        "source_member_set_sha256",
        "source_member_sequence_sha256",
        "source_lane_binding_sha256",
    ):
        if _SHA256_RE.fullmatch(str(proof.get(field) or "")) is None:
            raise ValueError("ge_predecessor_proof_digest_invalid")
    members = proof.get("source_members")
    member_sha256s = proof.get("source_member_sha256s")
    source_ids = proof.get("source_version_ids")
    lane_bindings = proof.get("source_lane_bindings")
    if (
        not isinstance(members, list)
        or not isinstance(member_sha256s, list)
        or not isinstance(source_ids, list)
        or not isinstance(lane_bindings, list)
        or not members
        or not all(isinstance(member, dict) for member in members)
        or not all(isinstance(binding, dict) for binding in lane_bindings)
    ):
        raise ValueError("ge_predecessor_proof_inventory_invalid")
    typed_members = [dict(member) for member in members]
    typed_bindings = [dict(binding) for binding in lane_bindings]
    expected_ids = [str(member.get("source_version_id") or "") for member in typed_members]
    if (
        source_ids != expected_ids
        or member_sha256s != [source_member_sha256(member) for member in typed_members]
        or proof.get("source_member_count") != len(typed_members)
        or proof.get("source_chunk_count")
        != sum(int(member.get("body_chunk_count") or 0) for member in typed_members)
        or proof.get("source_version_id_set_sha256")
        != source_version_id_set_sha256(expected_ids)
        or proof.get("source_member_set_sha256")
        != source_member_set_sha256(typed_members)
        or proof.get("source_member_sequence_sha256")
        != source_member_sequence_sha256(typed_members)
        or [binding.get("source_version_id") for binding in typed_bindings]
        != expected_ids
        or proof.get("source_lane_binding_sha256")
        != _lane_binding_sha256(typed_bindings)
    ):
        raise ValueError("ge_predecessor_proof_inventory_invalid")
    return supplied


def replay_ge_predecessor_proof(
    settings: Settings,
    database: Database,
    proof: Mapping[str, Any],
) -> dict[str, Any]:
    """Reload the exact stored/filesystem predecessor and compare full proof."""

    validate_ge_predecessor_proof(proof)
    current = load_verified_ge_predecessor(settings, database, str(proof["build_id"]))
    if canonical_json_bytes(current) != canonical_json_bytes(proof):
        raise ValueError("ge_predecessor_proof_replay_differed")
    return current


__all__ = [
    "EXPANSION_MODE",
    "PREDECESSOR_PROOF_SCHEMA",
    "load_verified_ge_predecessor",
    "replay_ge_predecessor_proof",
    "source_member_sequence_sha256",
    "source_member_set_sha256",
    "source_member_sha256",
    "source_version_id_set_sha256",
    "validate_ge_predecessor_proof",
]
