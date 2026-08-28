#!/usr/bin/env python3
"""Seal judgment source custody and honest later-treatment readiness.

The command verifies all 20 historical judgment snapshots, links them to the
remaining 502-row research set, and excludes legacy bulk-search findings when
separate Find Case Law computational-analysis licence evidence is absent.  It
does not decide treatment, qualify a proposition, admit a source, index,
embed, mutate a candidate, or authorize a later phase.
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

from app.retrieval.source_manifest import approved_source_manifest_sha256

EXPECTED_JUDGMENTS_DIGEST = (
    "1a691e9799cd8636515b47a42a186a68ed47e6bd9511755a5029a139c21437b7"
)
EXPECTED_RESEARCH_DIGEST = (
    "0718758e3bd9b0f938c4beab09eb3b603ffc5f419d68574399accc47c4a4015c"
)
EXPECTED_CANDIDATE_MANIFEST_DIGEST = (
    "d2c1434fd5fc44d4f2f7e4f7629293f646bb28ed9b8466687feb6c470ea53ac0"
)
EXPECTED_FRESH_MANIFEST_DIGEST = (
    "5bd11e398bcf40a42b1dda5e3261a01bc2497fe9bd8fd41c886e1b8a18f502ff"
)
EXPECTED_QUISTCLOSE_DOWNLOAD_FILE_SHA256 = (
    "e9240e046ea3d38f6ed4fc9b53171b6570804a832205ab21914f3f7f7d418833"
)
EXPECTED_QUISTCLOSE_APPROVAL_FILE_SHA256 = (
    "1d392975376e21021b66f8a6067ce77ccb18bb09d02da3b4bb315311f1495f5e"
)
EXPECTED_QUISTCLOSE_MANIFEST_SHA256 = (
    "b4a848d4487fd61b44fa17b4ef89fd0510b93d3c226bd499e1ac6c7df47bc532"
)
EXPECTED_PRIOR_APPROVALS = (
    (
        "d82e02f02461883b9bbc18904b50be582c3517039eb5c79739ee14d8d2a4e569",
        "binding_count",
        48,
    ),
    (
        "ae4bd86e0ac87066f6dc703aef99a17de8857770a81f9780939382a4a0297ba7",
        "row_count",
        35,
    ),
    (
        "c314dc1717f7a03986b4e551dc68eeeebf4a76ecf040238af5bcc2f0ae8429cf",
        "row_count",
        54,
    ),
)
EXPECTED_JUDGMENT_RECORDS = 20
EXPECTED_UNIQUE_CITATIONS = 18
EXPECTED_RESEARCH_ROWS = 502
EXPECTED_REFERENCED_SOURCE_VERSIONS = 14
EXPECTED_UNREFERENCED_SOURCE_VERSIONS = 6
EXPECTED_REFERENCED_ROWS = 306
EXPECTED_CANDIDATE_REFERENCES = 690
EXPECTED_FRESH_DOWNLOADS = 17
EXPECTED_LOCAL_RECOVERIES = 3
OUTPUT_NAME = "JUDGMENT-SOURCE-CUSTODY-AND-LATER-TREATMENT-READINESS-20.json"
PROGRESS_NAME = "PHASE2A-JUDGMENT-READINESS-PROGRESS.json"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()


def _pretty_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode()


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
        raise ValueError("phase2a_judgment_readiness_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_judgment_readiness_input_must_be_object")
    return value


def _verify_seal(value: dict[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or supplied != _sealed(material):
        raise ValueError(code)
    return supplied


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


def _strings(value: Any) -> set[str]:
    result: set[str] = set()
    if isinstance(value, str):
        result.add(value)
    elif isinstance(value, dict):
        for item in value.values():
            result.update(_strings(item))
    elif isinstance(value, list):
        for item in value:
            result.update(_strings(item))
    return result


def _validated_judgments(path: Path) -> tuple[str, list[dict[str, Any]]]:
    value = _load_object(path)
    digest = _verify_seal(
        value,
        "artifact_content_sha256",
        "phase2a_judgment_readiness_judgment_seal_invalid",
    )
    records = value.get("records")
    if (
        digest != EXPECTED_JUDGMENTS_DIGEST
        or value.get("schema") != "legalbot.v111.phase2a.owner-reviewed-judgments.v1"
        or value.get("record_count") != EXPECTED_JUDGMENT_RECORDS
        or not isinstance(records, list)
        or len(records) != EXPECTED_JUDGMENT_RECORDS
        or value.get("automatic_source_admission") is not False
        or value.get("candidate_mutated") is not False
        or value.get("phase2b_authorized") is not False
        or value.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_judgment_readiness_judgment_boundary_invalid")
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("phase2a_judgment_readiness_judgment_record_invalid")
        source_version_id = str(record.get("source_version_id") or "")
        owner_review = record.get("owner_review")
        if (
            not source_version_id
            or source_version_id in seen
            or not _SHA256.fullmatch(str(record.get("record_sha256") or ""))
            or record.get("proposition_binding_status")
            != "UNBOUND_IN_CANONICAL_REGISTRY"
            or record.get("proposition_relied_upon") is not None
            or record.get("owner_decision_required") is not True
            or not isinstance(owner_review, dict)
            or owner_review.get("status") != "OWNER_REQUESTED_MORE_EVIDENCE"
            or owner_review.get("does_not_admit_index_or_embed_source") is not True
            or owner_review.get("does_not_authorize_phase2b_or_development30") is not True
        ):
            raise ValueError("phase2a_judgment_readiness_judgment_record_boundary_invalid")
        seen.add(source_version_id)
    if len({str(record.get("neutral_citation")) for record in records}) != EXPECTED_UNIQUE_CITATIONS:
        raise ValueError("phase2a_judgment_readiness_citation_count_invalid")
    return digest, records


def _validated_candidate_sources(
    path: Path, judgment_ids: set[str]
) -> tuple[str, dict[str, dict[str, Any]]]:
    value = _load_object(path)
    digest = approved_source_manifest_sha256(value)
    if digest != EXPECTED_CANDIDATE_MANIFEST_DIGEST or value.get("manifest_sha256") != digest:
        raise ValueError("phase2a_judgment_readiness_candidate_manifest_invalid")
    sources = {
        str(source.get("source_version_id") or ""): source
        for source in value.get("sources", [])
        if isinstance(source, dict)
        and str(source.get("source_version_id") or "") in judgment_ids
    }
    if set(sources) != judgment_ids or any(
        source.get("subsequent_treatment_check_required") is not True
        or source.get("subsequent_treatment_verified") is not False
        or not str(source.get("authority_identity_id") or "").startswith(
            "neutral-citation:"
        )
        for source in sources.values()
    ):
        raise ValueError("phase2a_judgment_readiness_candidate_source_boundary_invalid")
    return digest, sources


def _validated_fresh_records(
    manifest_path: Path,
    quarantine_root: Path,
    judgment_ids: set[str],
) -> tuple[str, dict[str, dict[str, Any]]]:
    manifest = _load_object(manifest_path)
    digest = _verify_seal(
        manifest,
        "manifest_sha256",
        "phase2a_judgment_readiness_fresh_manifest_seal_invalid",
    )
    licence = manifest.get("find_case_law_computational_analysis")
    if (
        digest != EXPECTED_FRESH_MANIFEST_DIGEST
        or manifest.get("schema")
        != "legalbot.v111-phase2a-official-source-quarantine.v1"
        or not isinstance(licence, dict)
        or licence.get("separate_licence_required") is not True
        or licence.get("licence_evidence_sha256") is not None
        or licence.get("bulk_later_treatment_search_authorized") is not False
        or licence.get("bulk_later_treatment_search_omitted_when_unlicensed") is not True
        or any(
            record.get("target_type") == "later_treatment_search"
            for record in manifest.get("records", [])
            if isinstance(record, dict)
        )
    ):
        raise ValueError("phase2a_judgment_readiness_fresh_manifest_boundary_invalid")
    records = {
        str(record.get("target_id") or ""): record
        for record in manifest.get("records", [])
        if isinstance(record, dict)
        and record.get("target_type") == "candidate_judgment_source"
    }
    if set(records) != judgment_ids:
        raise ValueError("phase2a_judgment_readiness_fresh_record_set_invalid")
    for _source_version_id, record in records.items():
        if (
            record.get("automatically_admitted") is not False
            or record.get("automatically_indexed") is not False
            or record.get("automatically_embedded") is not False
        ):
            raise ValueError("phase2a_judgment_readiness_fresh_record_boundary_invalid")
        if record.get("result") != "DOWNLOADED_QUARANTINED":
            continue
        member = quarantine_root / str(record.get("quarantine_member") or "")
        if (
            member.parent != quarantine_root
            or member.is_symlink()
            or not member.is_file()
            or _sha256_file(member) != record.get("sha256")
            or member.stat().st_size != record.get("bytes")
        ):
            raise ValueError("phase2a_judgment_readiness_fresh_member_integrity_failed")
        citation = str(record.get("authority_identity") or "").removeprefix(
            "neutral-citation:"
        )
        if citation.encode() not in member.read_bytes():
            raise ValueError("phase2a_judgment_readiness_fresh_identity_not_found")
    return digest, records


def _validated_research(
    path: Path, judgment_ids: set[str]
) -> tuple[str, dict[str, list[dict[str, Any]]]]:
    value = _load_object(path)
    digest = _verify_seal(
        value,
        "artifact_content_sha256",
        "phase2a_judgment_readiness_research_seal_invalid",
    )
    rows = value.get("rows")
    if (
        digest != EXPECTED_RESEARCH_DIGEST
        or value.get("row_count") != EXPECTED_RESEARCH_ROWS
        or not isinstance(rows, list)
        or len(rows) != EXPECTED_RESEARCH_ROWS
        or value.get("source_admission_authorized") is not False
        or value.get("candidate_mutated") is not False
        or value.get("phase2b_authorized") is not False
        or value.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_judgment_readiness_research_boundary_invalid")
    references: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("phase2a_judgment_readiness_research_row_invalid")
        row_material = dict(row)
        row_seal = str(row_material.pop("row_packet_content_sha256", ""))
        if row_seal != _sealed(row_material):
            raise ValueError("phase2a_judgment_readiness_research_row_seal_invalid")
        for candidate in row.get("candidates", []):
            if not isinstance(candidate, dict):
                raise ValueError("phase2a_judgment_readiness_candidate_invalid")
            source_version_id = str(candidate.get("source_version_id") or "")
            if source_version_id not in judgment_ids:
                continue
            candidate_material = dict(candidate)
            candidate_seal = str(
                candidate_material.pop("candidate_record_content_sha256", "")
            )
            if candidate_seal != _sealed(candidate_material):
                raise ValueError("phase2a_judgment_readiness_candidate_seal_invalid")
            references[source_version_id].append(
                {
                    "row_id": row.get("row_id"),
                    "case_id": row.get("case_id"),
                    "issue_id": row.get("issue_id"),
                    "issue_label": row.get("issue_label"),
                    "rank": candidate.get("rank"),
                    "locator": candidate.get("locator"),
                    "span_bundle_sha256": candidate.get("span_bundle_sha256"),
                    "candidate_record_content_sha256": candidate_seal,
                }
            )
    return digest, dict(references)


def _validate_prior_approvals(paths: list[Path], judgment_ids: set[str]) -> list[str]:
    if len(paths) != len(EXPECTED_PRIOR_APPROVALS):
        raise ValueError("phase2a_judgment_readiness_prior_approval_set_invalid")
    digests: list[str] = []
    for path, (expected_digest, count_field, expected_count) in zip(
        paths, EXPECTED_PRIOR_APPROVALS, strict=True
    ):
        value = _load_object(path)
        digest = _verify_seal(
            value,
            "artifact_content_sha256",
            "phase2a_judgment_readiness_prior_approval_seal_invalid",
        )
        if (
            digest != expected_digest
            or value.get(count_field) != expected_count
            or value.get("phase2b_authorized") is not False
            or value.get("development30_authorized") is not False
            or _strings(value).intersection(judgment_ids)
        ):
            raise ValueError("phase2a_judgment_readiness_prior_approval_boundary_invalid")
        digests.append(digest)
    return digests


def _validated_quistclose(
    download_path: Path,
    approval_path: Path,
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    if _sha256_file(download_path) != EXPECTED_QUISTCLOSE_DOWNLOAD_FILE_SHA256:
        raise ValueError("phase2a_judgment_readiness_quistclose_download_file_invalid")
    if _sha256_file(approval_path) != EXPECTED_QUISTCLOSE_APPROVAL_FILE_SHA256:
        raise ValueError("phase2a_judgment_readiness_quistclose_approval_file_invalid")
    download = _load_object(download_path)
    approval = _load_object(approval_path)
    if (
        download.get("manifest_sha256") != EXPECTED_QUISTCLOSE_MANIFEST_SHA256
        or approval.get("manifest_sha256") != EXPECTED_QUISTCLOSE_MANIFEST_SHA256
        or approval.get("present_law_currentness_verified") is not False
        or approval.get("subsequent_treatment_check_required") is not True
    ):
        raise ValueError("phase2a_judgment_readiness_quistclose_boundary_invalid")
    items = {
        str(item.get("representation_id") or ""): item
        for item in download.get("items", [])
        if isinstance(item, dict)
        and item.get("authority_id") == "neutral-citation:[2002] UKHL 12"
    }
    required = {
        "ukhl-2002-12-part-1",
        "ukhl-2002-12-part-3",
        "ukhl-2002-12-part-4",
    }
    if not required.issubset(items):
        raise ValueError("phase2a_judgment_readiness_quistclose_items_missing")
    return items, {
        "source_pack_manifest_sha256": EXPECTED_QUISTCLOSE_MANIFEST_SHA256,
        "download_report_file_sha256": EXPECTED_QUISTCLOSE_DOWNLOAD_FILE_SHA256,
        "approval_report_file_sha256": EXPECTED_QUISTCLOSE_APPROVAL_FILE_SHA256,
    }


def build_judgment_readiness(
    *,
    judgments_path: Path,
    candidate_manifest_path: Path,
    research_packets_path: Path,
    fresh_quarantine_root: Path,
    vault_root: Path,
    quistclose_download_path: Path,
    quistclose_approval_path: Path,
    prior_approval_paths: list[Path],
    output_root: Path,
) -> dict[str, Any]:
    """Create the sealed 20-record source-custody and currentness hold packet."""

    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_judgment_readiness_output_already_exists")
    judgments_digest, judgments = _validated_judgments(judgments_path)
    judgment_ids = {str(record["source_version_id"]) for record in judgments}
    candidate_digest, sources = _validated_candidate_sources(
        candidate_manifest_path, judgment_ids
    )
    fresh_digest, fresh = _validated_fresh_records(
        fresh_quarantine_root / "QUARANTINE-MANIFEST.json",
        fresh_quarantine_root,
        judgment_ids,
    )
    research_digest, references = _validated_research(
        research_packets_path, judgment_ids
    )
    prior_digests = _validate_prior_approvals(prior_approval_paths, judgment_ids)
    quistclose, quistclose_provenance = _validated_quistclose(
        quistclose_download_path, quistclose_approval_path
    )

    packets: list[dict[str, Any]] = []
    for record in judgments:
        source_version_id = str(record["source_version_id"])
        source = sources[source_version_id]
        version_sha256 = str(source.get("version_sha256") or "")
        citation = str(record.get("neutral_citation") or "")
        authority_identity = f"neutral-citation:{citation}"
        fresh_record = fresh[source_version_id]
        if (
            source.get("authority_identity_id") != authority_identity
            or source.get("stable_identifier") != authority_identity
            or source.get("identity_verified") is not True
            or record.get("candidate_version_sha256") != version_sha256
            or fresh_record.get("authority_identity") != authority_identity
            or fresh_record.get("expected_version_sha256") != version_sha256
        ):
            raise ValueError("phase2a_judgment_readiness_identity_binding_invalid")
        snapshot = vault_root / version_sha256[:2] / version_sha256
        if (
            not _SHA256.fullmatch(version_sha256)
            or snapshot.is_symlink()
            or not snapshot.is_file()
            or _sha256_file(snapshot) != version_sha256
        ):
            raise ValueError("phase2a_judgment_readiness_snapshot_integrity_failed")
        representation = str(source.get("official_representation_id") or "")
        local_provenance: dict[str, Any] | None = None
        if fresh_record.get("result") != "DOWNLOADED_QUARANTINED":
            item = quistclose.get(representation)
            if (
                item is None
                or item.get("sha256") != version_sha256
                or item.get("bytes") != snapshot.stat().st_size
                or item.get("status") != "downloaded_verified_unapproved"
            ):
                raise ValueError("phase2a_judgment_readiness_local_recovery_invalid")
            local_provenance = {
                **quistclose_provenance,
                "representation_id": representation,
                "official_representation_url": item.get(
                    "official_representation_url"
                ),
                "snapshot_sha256": item.get("sha256"),
                "snapshot_bytes": item.get("bytes"),
                "historical_identity_approved": True,
                "present_law_currentness_verified": False,
            }
        source_references = references.get(source_version_id, [])
        row_ids = sorted({str(item["row_id"]) for item in source_references})
        if row_ids:
            recommendation = (
                "BIND_EXACT_PROPOSITIONS_THEN_COMPLETE_LICENCE_COMPLIANT_"
                "LATER_TREATMENT_REVIEW"
            )
        else:
            recommendation = (
                "OWNER_CONFIRM_NO_585_PROPOSITION_RELIANCE_AND_EXCLUDE_FROM_"
                "SUCCESSOR_IF_NOT_NEEDED"
            )
        material: dict[str, Any] = {
            "schema": "legalbot.v111.phase2a.judgment-readiness-row.v1",
            "ordinal": record.get("ordinal"),
            "source_version_id": source_version_id,
            "title": record.get("title"),
            "neutral_citation": citation,
            "authority_identity": source.get("authority_identity_id"),
            "official_representation_id": representation,
            "canonical_url": source.get("canonical_url"),
            "licence_name": source.get("licence_name"),
            "candidate_version_sha256": version_sha256,
            "sealed_historical_snapshot": {
                "relative_vault_member": f"{version_sha256[:2]}/{version_sha256}",
                "sha256": version_sha256,
                "bytes": snapshot.stat().st_size,
                "integrity_verified": True,
                "identity_binding_verified": True,
                "identity_binding_basis": (
                    "sealed_candidate_manifest_source_version_authority_and_hash"
                ),
            },
            "fresh_official_retrieval": {
                "requested_url": fresh_record.get("requested_url"),
                "result": fresh_record.get("result"),
                "http_status": fresh_record.get("http_status"),
                "sha256": fresh_record.get("sha256"),
                "bytes": fresh_record.get("bytes"),
                "identity_marker_verified": (
                    fresh_record.get("result") == "DOWNLOADED_QUARANTINED"
                ),
                "automatic_source_admission": False,
            },
            "historical_local_recovery_provenance": local_provenance,
            "approved_137_row_reference_count": 0,
            "unresolved_502_row_reference_count": len(row_ids),
            "unresolved_502_row_ids": row_ids,
            "unresolved_502_candidate_reference_count": len(source_references),
            "unresolved_502_candidate_references": source_references,
            "proposition_binding_status": "UNBOUND_IN_CANONICAL_REGISTRY",
            "legacy_bulk_search_candidate_count_excluded": record.get(
                "later_mention_candidate_count"
            ),
            "legacy_bulk_search_findings_consumed": False,
            "legacy_bulk_search_exclusion_reason": (
                "No separate Find Case Law computational-analysis licence evidence "
                "is bound to the collection; candidate counts are not treatment "
                "conclusions and may contain unrelated full-text results."
            ),
            "later_treatment_status": "BLOCKED_PENDING_PROPOSITION_SCOPE_AND_LICENCE",
            "affirmed_limited_distinguished_displaced_status": (
                "OWNER_DECISION_REQUIRED"
            ),
            "advisory_recommendation": recommendation,
            "owner_decision_required": True,
            "owner_decision_recorded": False,
            "technical_qualification_assigned": False,
            "source_admitted": False,
            "indexed": False,
            "embedded": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        packets.append({**material, "packet_content_sha256": _sealed(material)})

    referenced_ids = {
        packet["source_version_id"]
        for packet in packets
        if packet["unresolved_502_row_reference_count"] > 0
    }
    referenced_rows = {
        row_id for packet in packets for row_id in packet["unresolved_502_row_ids"]
    }
    candidate_reference_count = sum(
        int(packet["unresolved_502_candidate_reference_count"])
        for packet in packets
    )
    fresh_downloads = sum(
        packet["fresh_official_retrieval"]["result"]
        == "DOWNLOADED_QUARANTINED"
        for packet in packets
    )
    local_recoveries = sum(
        packet["historical_local_recovery_provenance"] is not None
        for packet in packets
    )
    if (
        len(referenced_ids) != EXPECTED_REFERENCED_SOURCE_VERSIONS
        or len(packets) - len(referenced_ids) != EXPECTED_UNREFERENCED_SOURCE_VERSIONS
        or len(referenced_rows) != EXPECTED_REFERENCED_ROWS
        or candidate_reference_count != EXPECTED_CANDIDATE_REFERENCES
        or fresh_downloads != EXPECTED_FRESH_DOWNLOADS
        or local_recoveries != EXPECTED_LOCAL_RECOVERIES
    ):
        raise ValueError("phase2a_judgment_readiness_fingerprint_changed")

    summary = {
        "judgment_record_count": len(packets),
        "unique_neutral_citation_count": EXPECTED_UNIQUE_CITATIONS,
        "sealed_historical_snapshot_integrity_verified": len(packets),
        "fresh_official_identity_downloaded": fresh_downloads,
        "fresh_official_access_blocked_with_sealed_local_provenance": local_recoveries,
        "source_versions_referenced_in_unresolved_502": len(referenced_ids),
        "source_versions_not_referenced_in_approved_137_or_unresolved_502": (
            len(packets) - len(referenced_ids)
        ),
        "unresolved_502_rows_with_judgment_candidates": len(referenced_rows),
        "unresolved_502_judgment_candidate_references": candidate_reference_count,
        "later_treatment_owner_decisions_required": len(packets),
        "later_treatment_resolved": 0,
    }
    material = {
        "schema": "legalbot.v111.phase2a.judgment-readiness.v1",
        "status": "SOURCE_CUSTODY_VERIFIED_LATER_TREATMENT_REMAINS_BLOCKED",
        "source_judgments_content_sha256": judgments_digest,
        "source_candidate_manifest_sha256": candidate_digest,
        "source_research_packets_content_sha256": research_digest,
        "source_fresh_quarantine_manifest_sha256": fresh_digest,
        "source_prior_approval_content_sha256s": prior_digests,
        "find_case_law_computational_analysis_licence_evidence_sha256": None,
        "legacy_bulk_search_findings_consumed": False,
        "summary": summary,
        "records": packets,
        "all_historical_snapshot_bytes_verified": True,
        "all_later_treatment_resolved": False,
        "common_cutoff_supportable": False,
        "automatic_source_admission": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    artifact = {**material, "artifact_content_sha256": _sealed(material)}
    artifact_raw = _pretty_json(artifact)
    progress_material = {
        "schema": "legalbot.v111.phase2a.judgment-readiness-progress.v1",
        "status": "PHASE2A_REMEDIATION_CONTINUES_LATER_TREATMENT_OWNER_REVIEW_REQUIRED",
        "judgment_readiness_content_sha256": artifact["artifact_content_sha256"],
        "judgment_readiness_file_sha256": _sha256(artifact_raw),
        "summary": summary,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    progress = {
        **progress_material,
        "progress_content_sha256": _sealed(progress_material),
    }
    progress_raw = _pretty_json(progress)

    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_judgment_readiness_output_mode_invalid")
    _write_exclusive(output_root / OUTPUT_NAME, artifact_raw)
    _write_exclusive(output_root / PROGRESS_NAME, progress_raw)
    _write_exclusive(
        output_root / "SHA256SUMS",
        (
            f"{_sha256(artifact_raw)}  {OUTPUT_NAME}\n"
            f"{_sha256(progress_raw)}  {PROGRESS_NAME}\n"
        ).encode(),
    )
    return progress


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--judgments", type=Path, required=True)
    parser.add_argument("--candidate-manifest", type=Path, required=True)
    parser.add_argument("--research-packets", type=Path, required=True)
    parser.add_argument("--fresh-quarantine-root", type=Path, required=True)
    parser.add_argument("--vault-root", type=Path, required=True)
    parser.add_argument("--quistclose-download", type=Path, required=True)
    parser.add_argument("--quistclose-approval", type=Path, required=True)
    parser.add_argument("--prior-approval", type=Path, action="append", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    result = build_judgment_readiness(
        judgments_path=args.judgments,
        candidate_manifest_path=args.candidate_manifest,
        research_packets_path=args.research_packets,
        fresh_quarantine_root=args.fresh_quarantine_root,
        vault_root=args.vault_root,
        quistclose_download_path=args.quistclose_download,
        quistclose_approval_path=args.quistclose_approval,
        prior_approval_paths=args.prior_approval,
        output_root=args.output_root,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
