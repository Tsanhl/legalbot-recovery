#!/usr/bin/env python3
"""Seal the post-54 Phase-2A remainder and approved-source byte custody.

This create-only command proves which 448 issue rows remain after the exact
54-row owner decision and binds each of the 16 owner-approved authorities to
already quarantined official bytes.  It does not index, embed, build or mutate
a candidate, qualify an issue, or authorize a later gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from collections import defaultdict
from pathlib import Path
from typing import Any

EXPECTED_UNRESOLVED_DIGEST = (
    "0718758e3bd9b0f938c4beab09eb3b603ffc5f419d68574399accc47c4a4015c"
)
EXPECTED_APPROVED_PACKAGE_DIGEST = (
    "40d7ded06badedee0349fcb3efc3c1ed2f707e2915c2b1d1208dc1796a73cf31"
)
EXPECTED_SOURCE_SCOPE_DIGEST = (
    "f898a2db5e20a4ff86e4742672a0bc28ac00581c43453f14dde4ac783f40613b"
)
EXPECTED_STARTING_ROWS = 502
EXPECTED_APPROVED_ROWS = 54
EXPECTED_REMAINING_ROWS = 448
EXPECTED_AUTHORITY_COUNT = 16
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_post54_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_post54_input_must_be_object")
    return value


def _verify_seal(value: dict[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or supplied != _sealed(material):
        raise ValueError(code)
    return supplied


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _evidence_records(row: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for field in ("component_evidence", "currentness_evidence"):
        value = row.get(field, [])
        if not isinstance(value, list):
            raise ValueError("phase2a_post54_evidence_collection_invalid")
        for item in value:
            if not isinstance(item, dict):
                raise ValueError("phase2a_post54_evidence_record_invalid")
            records.append(item)
    return records


def _authority_evidence(
    rows: list[dict[str, Any]],
) -> dict[str, dict[str, set[str]]]:
    result: dict[str, dict[str, set[str]]] = defaultdict(
        lambda: defaultdict(set)
    )
    for row in rows:
        row_id = str(row.get("row_id") or "")
        authorities = {
            str(value)
            for value in row.get("authority_identity_ids", [])
            if str(value)
        }
        if not row_id or not authorities:
            raise ValueError("phase2a_post54_source_scope_row_invalid")
        for evidence in _evidence_records(row):
            coverage = evidence.get("candidate_coverage")
            authority = ""
            if isinstance(coverage, dict):
                authority = str(coverage.get("authority_identity") or "")
            if not authority and len(authorities) == 1:
                authority = next(iter(authorities))
            if authority not in authorities:
                continue
            digest = str(evidence.get("official_file_sha256") or "")
            url = str(evidence.get("official_url") or "")
            if not _SHA256.fullmatch(digest) or not url.startswith("https://"):
                raise ValueError("phase2a_post54_official_evidence_identity_invalid")
            target = result[authority]
            target["official_file_sha256"].add(digest)
            target["official_urls"].add(url)
            target["row_ids"].add(row_id)
            target["source_target_ids"].add(str(evidence.get("source_target_id") or ""))
            target["source_titles"].add(
                str(evidence.get("official_source_title") or row.get("official_source_title") or "")
            )
            target["anchor_ids"].add(str(evidence.get("anchor_id") or ""))
    return result


def _quarantine_records(
    quarantine_roots: list[Path],
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    records_by_digest: dict[str, list[dict[str, Any]]] = defaultdict(list)
    manifest_sources: list[dict[str, Any]] = []
    for root in quarantine_roots:
        if root.is_symlink() or not root.is_dir():
            raise ValueError("phase2a_post54_quarantine_root_invalid")
        manifest_path = root / "QUARANTINE-MANIFEST.json"
        manifest = _load_object(manifest_path)
        manifest_digest = _verify_seal(
            manifest,
            "manifest_content_sha256",
            "phase2a_post54_quarantine_manifest_seal_invalid",
        )
        if (
            manifest.get("automatic_source_admission") is not False
            or manifest.get("automatic_indexing") is not False
            or manifest.get("automatic_embedding") is not False
            or manifest.get("candidate_mutated") is not False
            or int(manifest.get("record_count") or 0) != len(manifest.get("records") or [])
        ):
            raise ValueError("phase2a_post54_quarantine_boundary_invalid")
        manifest_sources.append(
            {
                "quarantine_root": root.name,
                "manifest_content_sha256": manifest_digest,
                "manifest_file_sha256": _sha256_file(manifest_path),
            }
        )
        for raw in manifest["records"]:
            if not isinstance(raw, dict):
                raise ValueError("phase2a_post54_quarantine_record_invalid")
            digest = str(raw.get("sha256") or "")
            member_name = str(raw.get("quarantine_member") or "")
            if not _SHA256.fullmatch(digest) or not member_name:
                continue
            member = root / member_name
            if (
                member.parent != root
                or member.is_symlink()
                or not member.is_file()
                or _sha256_file(member) != digest
                or member.stat().st_size != int(raw.get("bytes") or -1)
            ):
                raise ValueError("phase2a_post54_quarantine_member_integrity_failed")
            records_by_digest[digest].append(
                {
                    **raw,
                    "quarantine_root": root.name,
                    "quarantine_manifest_content_sha256": manifest_digest,
                    "quarantine_manifest_file_sha256": _sha256_file(manifest_path),
                }
            )
    return records_by_digest, sorted(
        manifest_sources, key=lambda item: str(item["quarantine_root"])
    )


def build_inventory(
    *,
    unresolved_path: Path,
    approved_package_path: Path,
    source_scope_path: Path,
    quarantine_roots: list[Path],
    output_root: Path,
) -> dict[str, Any]:
    """Create the exact remaining-row and approved-byte custody artifacts."""

    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_post54_output_already_exists")
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_post54_output_mode_invalid")

    unresolved = _load_object(unresolved_path)
    unresolved_digest = _verify_seal(
        unresolved,
        "artifact_content_sha256",
        "phase2a_post54_unresolved_seal_invalid",
    )
    approved = _load_object(approved_package_path)
    approved_digest = _verify_seal(
        approved,
        "approved_package_content_sha256",
        "phase2a_post54_approved_package_seal_invalid",
    )
    source_scope = _load_object(source_scope_path)
    source_scope_digest = _verify_seal(
        source_scope,
        "artifact_content_sha256",
        "phase2a_post54_source_scope_seal_invalid",
    )
    if (
        unresolved_digest != EXPECTED_UNRESOLVED_DIGEST
        or unresolved.get("row_count") != EXPECTED_STARTING_ROWS
        or unresolved.get("technical_qualification_assigned") is True
        or unresolved.get("source_admission_authorized") is not False
        or unresolved.get("candidate_mutated") is not False
        or approved_digest != EXPECTED_APPROVED_PACKAGE_DIGEST
        or approved.get("row_count") != EXPECTED_APPROVED_ROWS
        or approved.get("automatic_indexing_or_embedding_authorized") is not False
        or source_scope_digest != EXPECTED_SOURCE_SCOPE_DIGEST
        or source_scope.get("authority_count") != EXPECTED_AUTHORITY_COUNT
        or source_scope.get("automatic_indexing_or_embedding_authorized") is not False
    ):
        raise ValueError("phase2a_post54_input_boundary_invalid")

    unresolved_rows = unresolved.get("rows")
    approved_rows = approved.get("rows")
    source_rows = source_scope.get("rows")
    if not all(isinstance(value, list) for value in (unresolved_rows, approved_rows, source_rows)):
        raise ValueError("phase2a_post54_rows_invalid")
    starting_by_id = {
        str(row.get("row_id") or ""): row
        for row in unresolved_rows
        if isinstance(row, dict) and str(row.get("row_id") or "")
    }
    approved_ids = {
        str(row.get("row_id") or "")
        for row in approved_rows
        if isinstance(row, dict) and str(row.get("row_id") or "")
    }
    if (
        len(starting_by_id) != EXPECTED_STARTING_ROWS
        or len(approved_ids) != EXPECTED_APPROVED_ROWS
        or not approved_ids.issubset(starting_by_id)
    ):
        raise ValueError("phase2a_post54_row_set_invariant_failed")
    remaining_rows = [
        starting_by_id[row_id]
        for row_id in sorted(set(starting_by_id) - approved_ids)
    ]
    if len(remaining_rows) != EXPECTED_REMAINING_ROWS:
        raise ValueError("phase2a_post54_remaining_count_invalid")

    remaining_material = {
        "schema": "legalbot.v111.phase2a.remaining-research-packets-after-54.v1",
        "status": "OWNER_OR_QUALIFIED_REVIEWER_DECISIONS_REQUIRED",
        "source_unresolved_research_packets_content_sha256": unresolved_digest,
        "source_owner_approved_package_content_sha256": approved_digest,
        "starting_row_count": EXPECTED_STARTING_ROWS,
        "removed_owner_approved_row_count": EXPECTED_APPROVED_ROWS,
        "row_count": len(remaining_rows),
        "rows": remaining_rows,
        "ai_review_advisory_only": True,
        "technical_qualification_assigned": False,
        "automatic_source_admission": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    remaining = {
        **remaining_material,
        "artifact_content_sha256": _sealed(remaining_material),
    }

    authority_evidence = _authority_evidence(source_rows)
    expected_authorities = set(source_scope["authority_identity_ids"])
    if set(authority_evidence) != expected_authorities:
        raise ValueError("phase2a_post54_authority_evidence_incomplete")
    records_by_digest, manifest_sources = _quarantine_records(quarantine_roots)
    custody_records: list[dict[str, Any]] = []
    for authority in sorted(expected_authorities):
        evidence = authority_evidence[authority]
        digests = evidence["official_file_sha256"]
        if len(digests) != 1:
            raise ValueError("phase2a_post54_authority_file_identity_ambiguous")
        digest = next(iter(digests))
        candidates = records_by_digest.get(digest, [])
        if not candidates:
            raise ValueError("phase2a_post54_approved_file_not_in_quarantine")
        selected = sorted(
            candidates,
            key=lambda item: (
                0 if str(item["quarantine_root"]).endswith("r21-quarantine") else 1,
                str(item["quarantine_root"]),
                str(item.get("quarantine_member") or ""),
            ),
        )[0]
        record_material = {
            "authority_identity": authority,
            "official_file_sha256": digest,
            "official_urls": sorted(value for value in evidence["official_urls"] if value),
            "source_titles": sorted(value for value in evidence["source_titles"] if value),
            "source_target_ids": sorted(
                value for value in evidence["source_target_ids"] if value
            ),
            "anchor_ids": sorted(value for value in evidence["anchor_ids"] if value),
            "row_ids": sorted(evidence["row_ids"]),
            "quarantine_root": selected["quarantine_root"],
            "quarantine_member": selected["quarantine_member"],
            "quarantine_manifest_content_sha256": selected[
                "quarantine_manifest_content_sha256"
            ],
            "quarantine_manifest_file_sha256": selected[
                "quarantine_manifest_file_sha256"
            ],
            "bytes": selected["bytes"],
            "content_type": selected.get("content_type"),
            "retrieved_at": selected.get("retrieved_at"),
            "requested_url": selected.get("requested_url"),
            "final_url": selected.get("final_url"),
            "quarantine_result": selected.get("result"),
            "proposition_level_source_admission_owner_approved": True,
            "indexed": False,
            "embedded": False,
            "candidate_mutated": False,
        }
        custody_records.append(
            {**record_material, "record_content_sha256": _sealed(record_material)}
        )

    custody_material = {
        "schema": "legalbot.v111.phase2a.owner-approved-source-custody.v1",
        "status": "APPROVED_OFFICIAL_BYTES_VERIFIED_AWAITING_SUCCESSOR_MANIFEST",
        "source_owner_approved_scope_content_sha256": source_scope_digest,
        "source_owner_approved_package_content_sha256": approved_digest,
        "quarantine_manifests": manifest_sources,
        "authority_count": len(custody_records),
        "record_count": len(custody_records),
        "records": custody_records,
        "all_approved_authorities_bound_to_verified_quarantine_bytes": True,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "one_consolidated_successor_manifest_not_yet_built": True,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    custody = {**custody_material, "artifact_content_sha256": _sealed(custody_material)}

    progress_material = {
        "schema": "legalbot.v111.phase2a.post-54-inventory-progress.v1",
        "status": "PHASE2A_REMEDIATION_CONTINUES_OWNER_REVIEW_REQUIRED",
        "recorded_owner_decision_count": 137,
        "remaining_owner_decision_issue_count": len(remaining_rows),
        "approved_source_authority_count": len(custody_records),
        "approved_source_bytes_verified": True,
        "successor_candidate_built": False,
        "all585_technical_qualification_passed": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
        "terminal_verdict": (
            "PHASE 2A REMEDIATION CONTINUES — 448 OWNER DECISIONS REMAIN; "
            "PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED"
        ),
    }
    progress = {
        **progress_material,
        "progress_content_sha256": _sealed(progress_material),
    }

    artifacts = {
        "REMAINING-448-RESEARCH-PACKETS.json": remaining,
        "APPROVED-SOURCE-CUSTODY-16.json": custody,
        "PHASE2A-PROGRESS.json": progress,
    }
    for name, artifact in artifacts.items():
        _write_exclusive(output_root / name, _pretty_json(artifact))
    _write_exclusive(output_root / "OUTCOME.txt", (progress["terminal_verdict"] + "\n").encode())
    files = sorted(path for path in output_root.iterdir() if path.is_file())
    _write_exclusive(
        output_root / "SHA256SUMS.txt",
        "".join(f"{_sha256_file(path)}  {path.name}\n" for path in files).encode(),
    )
    return {
        "output_root": str(output_root),
        "remaining_artifact_content_sha256": remaining["artifact_content_sha256"],
        "source_custody_content_sha256": custody["artifact_content_sha256"],
        "remaining_owner_decision_issue_count": len(remaining_rows),
        "approved_source_authority_count": len(custody_records),
        "all_approved_source_bytes_verified": True,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }


def _persist_failure(output_root: Path, exc: BaseException) -> None:
    try:
        output_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        path = output_root / "FAILURE.json"
        if path.exists():
            return
        material = {
            "schema": "legalbot.v111.phase2a.post-54-inventory-failure.v1",
            "exception_type": type(exc).__name__,
            "error": str(exc),
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        _write_exclusive(
            path,
            _pretty_json({**material, "failure_content_sha256": _sealed(material)}),
        )
    except Exception:
        return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unresolved", required=True, type=Path)
    parser.add_argument("--approved-package", required=True, type=Path)
    parser.add_argument("--source-scope", required=True, type=Path)
    parser.add_argument("--quarantine-root", required=True, action="append", type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = build_inventory(
            unresolved_path=args.unresolved.resolve(strict=True),
            approved_package_path=args.approved_package.resolve(strict=True),
            source_scope_path=args.source_scope.resolve(strict=True),
            quarantine_roots=[path.resolve(strict=True) for path in args.quarantine_root],
            output_root=args.output_root.resolve(),
        )
    except Exception as exc:
        _persist_failure(args.output_root.resolve(), exc)
        raise
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
