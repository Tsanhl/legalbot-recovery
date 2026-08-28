#!/usr/bin/env python3
"""Verify supplemental official spans and build a non-admitting owner batch."""

from __future__ import annotations

import argparse
import json
import os
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from app.retrieval.source_manifest import approved_source_manifest_sha256

if __package__:
    from scripts import collect_v111_phase2a_official_sources as official
    from scripts import verify_v111_phase2a_rebinding_sources as rebinding
else:
    import collect_v111_phase2a_official_sources as official
    import verify_v111_phase2a_rebinding_sources as rebinding

PLAN_SCHEMA = "legalbot.v111.phase2a.supplemental-binding-plan.v1"
MANIFEST_SCHEMA = "legalbot.v111.phase2a.supplemental-source-quarantine.v1"


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_supplemental_verification_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_supplemental_verification_input_must_be_object")
    return value


def _sealed(value: Any) -> str:
    return official._sha256(official._canonical_json(value))


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if supplied != _sealed(material):
        raise ValueError(code)
    return supplied


def _write_exclusive(path: Path, value: Any) -> None:
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _is_downloaded_record(record: Mapping[str, Any]) -> bool:
    return record.get("result") == "DOWNLOADED_QUARANTINED_NOT_ADMITTED"


def _validate_plan(plan: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    if (
        plan.get("schema") != PLAN_SCHEMA
        or plan.get("owner_materiality_decision_required") is not True
        or plan.get("owner_source_admission_required") is not True
        or plan.get("automatic_source_admission") is not False
        or plan.get("automatic_gold_change") is not False
        or plan.get("automatic_indexing") is not False
        or plan.get("automatic_embedding") is not False
        or plan.get("candidate_mutation_authorized") is not False
        or plan.get("phase2b_authorized") is not False
        or plan.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_supplemental_binding_plan_boundary_invalid")
    values = plan.get("bindings")
    if not isinstance(values, list) or not values:
        raise ValueError("phase2a_supplemental_binding_plan_inventory_invalid")
    bindings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, dict):
            raise ValueError("phase2a_supplemental_binding_invalid")
        binding = dict(value)
        binding_id = str(binding.get("binding_id") or "")
        legacy_spans = bool(binding.get("material_claim_anchor_ids")) and bool(
            binding.get("currentness_anchor_ids")
        )
        exact_claims = bool(binding.get("material_claims")) and bool(
            binding.get("currentness_claims")
        )
        if (
            not binding_id
            or binding_id in seen
            or not binding.get("source_target_id")
            or not binding.get("row_ids")
            or legacy_spans == exact_claims
            or not rebinding._SHA256.fullmatch(
                str(binding.get("expected_source_file_sha256") or "")
            )
        ):
            raise ValueError("phase2a_supplemental_binding_invalid")
        if exact_claims:
            _validate_exact_claims(binding["material_claims"])
            _validate_exact_claims(binding["currentness_claims"])
        seen.add(binding_id)
        bindings.append(binding)
    return tuple(bindings)


def _validate_exact_claims(value: Any) -> None:
    if not isinstance(value, list) or not value:
        raise ValueError("phase2a_supplemental_exact_claims_invalid")
    seen: set[str] = set()
    for claim in value:
        if not isinstance(claim, Mapping):
            raise ValueError("phase2a_supplemental_exact_claim_invalid")
        claim_id = str(claim.get("claim_id") or "")
        exact_text = str(claim.get("exact_normalized_span_text") or "")
        if (
            not claim_id
            or claim_id in seen
            or not claim.get("proposition")
            or not claim.get("anchor_id")
            or not exact_text
            or exact_text != " ".join(exact_text.split())
        ):
            raise ValueError("phase2a_supplemental_exact_claim_invalid")
        seen.add(claim_id)


def _span(
    *,
    anchor_id: str,
    anchors: Mapping[str, str],
    source_record: Mapping[str, Any],
) -> dict[str, Any]:
    text = anchors.get(anchor_id)
    if not text or not rebinding._has_substantive_text(text):
        raise ValueError(f"phase2a_supplemental_anchor_missing_or_empty:{anchor_id}")
    material = {
        "source_target_id": source_record["target_id"],
        "source_title": source_record["source_title"],
        "official_url": source_record["final_url"],
        "official_file_sha256": source_record["sha256"],
        "anchor_id": anchor_id,
        "exact_normalized_span_text": text,
        "exact_normalized_span_sha256": official._sha256(text.encode()),
        "span_truncated": False,
    }
    return {**material, "span_content_sha256": _sealed(material)}


def _exact_claim_span(
    *,
    claim: Mapping[str, Any],
    anchors: Mapping[str, str],
    source_record: Mapping[str, Any],
) -> dict[str, Any]:
    anchor_id = str(claim["anchor_id"])
    parent_text = anchors.get(anchor_id)
    exact_text = str(claim["exact_normalized_span_text"])
    if not parent_text or not rebinding._has_substantive_text(parent_text):
        raise ValueError(f"phase2a_supplemental_anchor_missing_or_empty:{anchor_id}")
    if parent_text.count(exact_text) != 1:
        raise ValueError(
            f"phase2a_supplemental_exact_span_not_unique_in_anchor:{claim['claim_id']}"
        )
    start = parent_text.index(exact_text)
    material = {
        "claim_id": claim["claim_id"],
        "proposition": claim["proposition"],
        "source_target_id": source_record["target_id"],
        "source_title": source_record["source_title"],
        "official_url": source_record["final_url"],
        "official_file_sha256": source_record["sha256"],
        "anchor_id": anchor_id,
        "parent_anchor_text_sha256": official._sha256(parent_text.encode()),
        "exact_normalized_span_text": exact_text,
        "exact_normalized_span_sha256": official._sha256(exact_text.encode()),
        "start_character": start,
        "end_character_exclusive": start + len(exact_text),
        "span_truncated": False,
    }
    return {**material, "span_content_sha256": _sealed(material)}


def verify(
    *,
    binding_plan_path: Path,
    candidate_manifest_path: Path,
    quarantine_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Verify every pinned source byte and exact requested anchor."""

    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_supplemental_verification_output_already_exists")
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_supplemental_verification_output_mode_invalid")
    plan = _load_object(binding_plan_path)
    bindings = _validate_plan(plan)
    candidate_manifest = _load_object(candidate_manifest_path)
    candidate_manifest_digest = approved_source_manifest_sha256(candidate_manifest)
    if candidate_manifest.get("manifest_sha256") != candidate_manifest_digest:
        raise ValueError("phase2a_supplemental_candidate_manifest_invalid")
    candidate_sources = {
        str(source.get("authority_identity_id") or ""): source
        for source in candidate_manifest.get("sources", [])
        if source.get("authority_identity_id")
    }
    manifest_path = quarantine_root / "QUARANTINE-MANIFEST.json"
    manifest = _load_object(manifest_path)
    manifest_digest = _verify_seal(
        manifest,
        "manifest_content_sha256",
        "phase2a_supplemental_quarantine_manifest_seal_invalid",
    )
    if (
        manifest.get("schema") != MANIFEST_SCHEMA
        or manifest_digest != plan.get("source_quarantine_manifest_content_sha256")
        or manifest.get("source_plan_file_sha256") != plan.get("source_plan_file_sha256")
        or manifest.get("automatic_source_admission") is not False
        or manifest.get("automatic_indexing") is not False
        or manifest.get("candidate_mutated") is not False
        or manifest.get("phase2b_authorized") is not False
    ):
        raise ValueError("phase2a_supplemental_quarantine_boundary_invalid")

    sources: dict[str, dict[str, Any]] = {}
    unavailable_source_target_ids: list[str] = []
    for record in manifest.get("records", []):
        _verify_seal(
            record,
            "record_content_sha256",
            "phase2a_supplemental_source_record_seal_invalid",
        )
        if not _is_downloaded_record(record):
            unavailable_source_target_ids.append(str(record.get("target_id") or ""))
            continue
        member = quarantine_root / str(record.get("quarantine_member") or "")
        if member.is_symlink() or not member.is_file():
            raise ValueError("phase2a_supplemental_source_member_missing")
        raw = member.read_bytes()
        if official._sha256(raw) != record.get("sha256"):
            raise ValueError("phase2a_supplemental_source_member_hash_mismatch")
        _, anchor_values, kind = rebinding._parse_document(
            raw=raw,
            content_type=str(record.get("content_type") or ""),
        )
        if kind != "xml":
            raise ValueError("phase2a_supplemental_source_not_xml")
        native_anchors = dict(anchor_values)
        sources[str(record["target_id"])] = {
            "record": record,
            "anchors": native_anchors,
        }

    proposals: list[dict[str, Any]] = []
    for binding in bindings:
        source = sources.get(str(binding["source_target_id"]))
        if source is None:
            raise ValueError("phase2a_supplemental_binding_source_missing")
        source_record = source["record"]
        if source_record.get("sha256") != binding["expected_source_file_sha256"]:
            raise ValueError("phase2a_supplemental_binding_source_hash_mismatch")
        authority_identity = str(source_record.get("authority_identity") or "")
        candidate_source = candidate_sources.get(authority_identity)
        source_admission_required = candidate_source is None
        candidate_action = (
            "SOURCE_ADMISSION_AND_SUCCESSOR_CANDIDATE_REQUIRED_IF_OWNER_APPROVES"
            if source_admission_required
            else "EXISTING_SEALED_CANDIDATE_AUTHORITY_PRESENT_REBIND_ONLY"
        )
        if binding.get("material_claims"):
            material_claim_spans = [
                _exact_claim_span(
                    claim=claim,
                    anchors=source["anchors"],
                    source_record=source_record,
                )
                for claim in binding["material_claims"]
            ]
            currentness_spans = [
                _exact_claim_span(
                    claim=claim,
                    anchors=source["anchors"],
                    source_record=source_record,
                )
                for claim in binding["currentness_claims"]
            ]
        else:
            material_claim_spans = [
                _span(
                    anchor_id=str(anchor_id),
                    anchors=source["anchors"],
                    source_record=source_record,
                )
                for anchor_id in binding["material_claim_anchor_ids"]
            ]
            currentness_spans = [
                _span(
                    anchor_id=str(anchor_id),
                    anchors=source["anchors"],
                    source_record=source_record,
                )
                for anchor_id in binding["currentness_anchor_ids"]
            ]
        material = {
            "binding_id": binding["binding_id"],
            "row_ids": binding["row_ids"],
            "source_target_id": binding["source_target_id"],
            "authority_identity": authority_identity,
            "source_title": source_record["source_title"],
            "official_url": source_record["final_url"],
            "official_file_sha256": source_record["sha256"],
            "material_claim_spans": material_claim_spans,
            "currentness_spans": currentness_spans,
            "binding_scope": binding.get("binding_scope", "DIRECT"),
            "unresolved_scope_note": binding.get("unresolved_scope_note"),
            "proposed_action": binding["proposed_action"],
            "candidate_coverage_assessment": candidate_action,
            "candidate_source_version_id": (
                candidate_source.get("source_version_id") if candidate_source else None
            ),
            "candidate_source_as_of_date": (
                candidate_source.get("as_of_date") if candidate_source else None
            ),
            "candidate_source_currentness_verified": (
                candidate_source.get("currentness_verified") if candidate_source else None
            ),
            "advisory_recommendation": (
                "APPROVE_PROPOSITION_BINDING_AND_SOURCE_ADMISSION"
                if source_admission_required
                else "APPROVE_PROPOSITION_REBIND_WITHOUT_SOURCE_ADMISSION"
            ),
            "owner_materiality_decision": None,
            "owner_source_admission_required": source_admission_required,
            "owner_source_admission_decision": (
                None if source_admission_required else "NOT_APPLICABLE_EXISTING_AUTHORITY"
            ),
            "source_admission_authorized": False,
            "gold_change_authorized": False,
            "indexing_authorized": False,
            "embedding_authorized": False,
            "candidate_mutated": False,
            "issue_technically_qualified": False,
        }
        proposals.append({**material, "proposal_content_sha256": _sealed(material)})

    verification_material = {
        "schema": "legalbot.v111.phase2a.supplemental-source-verification.v1",
        "status": "EXACT_OFFICIAL_SPANS_VERIFIED_OWNER_DECISION_REQUIRED",
        "source_quarantine_manifest_content_sha256": manifest_digest,
        "sealed_candidate_manifest_sha256": candidate_manifest_digest,
        "sealed_candidate_manifest_file_sha256": official._sha256(
            candidate_manifest_path.read_bytes()
        ),
        "binding_plan_file_sha256": official._sha256(binding_plan_path.read_bytes()),
        "binding_plan_content_sha256": _sealed(plan),
        "source_count": len(sources),
        "quarantine_unavailable_source_count": len(unavailable_source_target_ids),
        "quarantine_unavailable_source_target_ids": sorted(unavailable_source_target_ids),
        "binding_count": len(proposals),
        "row_count": len({row for item in proposals for row in item["row_ids"]}),
        "all_requested_spans_present": True,
        "all_source_hashes_match": True,
        "span_truncation_count": 0,
        "existing_candidate_authority_count": sum(
            item["owner_source_admission_required"] is False for item in proposals
        ),
        "new_source_admission_proposal_count": sum(
            item["owner_source_admission_required"] is True for item in proposals
        ),
        "owner_decision_required": True,
        "owner_source_admission_required": any(
            item["owner_source_admission_required"] for item in proposals
        ),
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    verification = {
        **verification_material,
        "artifact_content_sha256": _sealed(verification_material),
    }
    batch_material = {
        "schema": "legalbot.v111.phase2a.owner-source-admission-batch.v1",
        "status": "OWNER_MATERIALITY_AND_SOURCE_ADMISSION_DECISION_REQUIRED",
        "source_verification_content_sha256": verification["artifact_content_sha256"],
        "proposal_count": len(proposals),
        "proposals": proposals,
        "owner_decision_required": True,
        "automatic_source_admission": False,
        "automatic_gold_change": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    batch = {**batch_material, "artifact_content_sha256": _sealed(batch_material)}
    _write_exclusive(output_root / "SUPPLEMENTAL-SOURCE-VERIFICATION.json", verification)
    _write_exclusive(output_root / "OWNER-SOURCE-ADMISSION-BATCH.json", batch)
    official._write_exclusive(
        output_root / "OUTCOME.txt",
        (
            "PHASE 2A SUPPLEMENTAL SOURCE REVIEW READY — EXACT OFFICIAL SPANS "
            "VERIFIED; OWNER MATERIALITY AND SOURCE ADMISSION REQUIRED; NO INDEX "
            "OR CANDIDATE CHANGE; PHASE 2B NOT AUTHORIZED\n"
        ).encode(),
    )
    return {
        "output_root": str(output_root),
        "verification_content_sha256": verification["artifact_content_sha256"],
        "owner_batch_content_sha256": batch["artifact_content_sha256"],
        "proposal_count": len(proposals),
        "row_count": verification["row_count"],
        "source_admission_authorized": False,
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
            "schema": "legalbot.v111.phase2a.supplemental-verification-failure.v1",
            "exception_type": type(exc).__name__,
            "error": str(exc),
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        _write_exclusive(
            path,
            {**material, "failure_content_sha256": _sealed(material)},
        )
    except Exception:
        return


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binding-plan", required=True, type=Path)
    parser.add_argument("--candidate-manifest", required=True, type=Path)
    parser.add_argument("--quarantine-root", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = args.output_root.resolve()
    try:
        result = verify(
            binding_plan_path=args.binding_plan.resolve(strict=True),
            candidate_manifest_path=args.candidate_manifest.resolve(strict=True),
            quarantine_root=args.quarantine_root.resolve(strict=True),
            output_root=root,
        )
    except Exception as exc:
        _persist_failure(root, exc)
        raise
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
