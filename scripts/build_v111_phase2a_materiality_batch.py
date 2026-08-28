#!/usr/bin/env python3
"""Build the exact 54-row Phase-2A owner materiality decision batch."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from app.retrieval.source_manifest import approved_source_manifest_sha256

if __package__:
    from scripts import collect_v111_phase2a_official_sources as official
    from scripts import verify_v111_phase2a_rebinding_sources as rebinding
else:
    import collect_v111_phase2a_official_sources as official
    import verify_v111_phase2a_rebinding_sources as rebinding

EXPECTED_CORRECTED_ROW_COUNT = 51
EXPECTED_SUPPLEMENTAL_ROW_COUNT = 3
EXPECTED_BATCH_ROW_COUNT = 54
SUPPLEMENTAL_ROW_IDS = frozenset(
    {
        "live30-q29:issue-01",
        "live60-q43:issue-02",
        "live60-q48:issue-07",
    }
)
_NEUTRAL_CITATION = re.compile(
    r"(?P<citation>\[\d{4}\]\s+(?:UKSC|UKHL|EWCA\s+Civ|EWHC\s+\d+\s+\([A-Za-z]+\))\s*\d*)",
    re.IGNORECASE,
)


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_materiality_batch_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_materiality_batch_input_must_be_object")
    return value


def _sealed(value: Any) -> str:
    return official._sha256(official._canonical_json(value))


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if supplied != _sealed(material):
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


def _authority_identity(*, url: str, title: str, citation: str) -> str | None:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").casefold()
    parts = [part for part in parsed.path.split("/") if part]
    if (
        host in {"legislation.gov.uk", "www.legislation.gov.uk"}
        and parts
        and parts[0] in {"ukpga", "uksi", "eur"}
    ):
        end = next(
            (index for index, part in enumerate(parts) if re.fullmatch(r"\d{4}-\d{2}-\d{2}", part)),
            len(parts),
        )
        identity_parts = parts[:end]
        if len(identity_parts) >= 3:
            return ":".join(identity_parts)
    if host in {"justice.gov.uk", "www.justice.gov.uk"} and "procedure rules" in title.casefold():
        return "uksi:1998:3132"
    match = _NEUTRAL_CITATION.search(citation)
    if match:
        return f"neutral-citation:{' '.join(match.group('citation').split())}"
    return None


def _candidate_assessment(
    *, authority_identity: str | None, candidate_sources: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    candidate = candidate_sources.get(str(authority_identity or ""))
    if candidate is None:
        return {
            "authority_identity": authority_identity,
            "assessment": (
                "CANDIDATE_IDENTITY_MAPPING_REQUIRED"
                if authority_identity is None
                else "MISSING_CANDIDATE_AUTHORITY_REQUIRES_SOURCE_ADMISSION_IF_APPROVED"
            ),
            "candidate_source_version_id": None,
            "candidate_source_as_of_date": None,
            "candidate_source_currentness_verified": None,
            "owner_source_admission_required": authority_identity is not None,
        }
    current = (
        candidate.get("as_of_date") == "2026-08-14"
        and candidate.get("currentness_verified") is True
    )
    return {
        "authority_identity": authority_identity,
        "assessment": (
            "EXISTING_SEALED_CANDIDATE_AUTHORITY_PRESENT_REBIND_ONLY"
            if current
            else "POTENTIALLY_STALE_CANDIDATE_AUTHORITY_REQUIRES_REVIEW"
        ),
        "candidate_source_version_id": candidate.get("source_version_id"),
        "candidate_source_as_of_date": candidate.get("as_of_date"),
        "candidate_source_currentness_verified": candidate.get("currentness_verified"),
        "owner_source_admission_required": not current,
    }


def _exact_component_evidence(*, component: str, check: Mapping[str, Any]) -> dict[str, Any]:
    anchors = list(check.get("exact_anchor_hits") or [])
    anchors.sort(
        key=lambda item: (
            item.get("anchor_matches_stated_locator") is not True,
            str(item.get("target_id") or ""),
            str(item.get("anchor_id") or ""),
        )
    )
    if not anchors:
        raise ValueError("phase2a_materiality_exact_component_anchor_missing")
    anchor = anchors[0]
    documents = {
        str(item.get("target_id") or ""): item for item in check.get("document_hits") or []
    }
    document = documents.get(str(anchor.get("target_id") or ""))
    if document is None:
        raise ValueError("phase2a_materiality_exact_component_document_missing")
    return {
        "component_action": "RETAIN_EXACT_COMPONENT_AND_REBIND",
        "prior_component_text": component,
        "proposed_bound_span_text": component,
        "proposed_bound_span_sha256": official._sha256(component.encode()),
        "source_target_id": document["target_id"],
        "source_type": document["target_type"],
        "official_url": document["official_url"],
        "official_file_sha256": document["official_file_sha256"],
        "anchor_id": anchor["anchor_id"],
        "anchor_matches_stated_locator": anchor["anchor_matches_stated_locator"],
        "span_truncated": False,
    }


def _corrected_component_evidence(*, component: str, check: Mapping[str, Any]) -> dict[str, Any]:
    corrections = list(check.get("stated_locator_anchor_corrections_if_not_exact") or [])
    if not corrections:
        raise ValueError("phase2a_materiality_corrected_component_span_missing")
    correction = corrections[0]
    if correction.get("anchor_text_truncated") is not False:
        raise ValueError("phase2a_materiality_corrected_component_span_truncated")
    text = str(correction.get("anchor_text") or "")
    if (
        not text
        or not rebinding._has_substantive_text(text)
        or official._sha256(text.encode()) != correction.get("anchor_text_sha256")
    ):
        raise ValueError("phase2a_materiality_corrected_component_span_invalid")
    return {
        "component_action": "REPLACE_STAGING_COMPONENT_WITH_CURRENT_OFFICIAL_SPAN",
        "prior_component_text": component,
        "proposed_bound_span_text": text,
        "proposed_bound_span_sha256": correction["anchor_text_sha256"],
        "source_target_id": correction["target_id"],
        "source_type": correction["target_type"],
        "official_url": correction["official_url"],
        "official_file_sha256": correction["official_file_sha256"],
        "anchor_id": correction["anchor_id"],
        "anchor_matches_stated_locator": True,
        "component_token_coverage": correction["component_token_coverage"],
        "span_truncated": False,
    }


def _corrected_rows(
    *, verification: Mapping[str, Any], candidate_sources: Mapping[str, Mapping[str, Any]]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in verification.get("records", []):
        row_id = str(record.get("row_id") or "")
        if record.get("all_components_exact_in_fresh_official_bytes") is True:
            continue
        if row_id in SUPPLEMENTAL_ROW_IDS:
            continue
        components = rebinding._components(str(record.get("proposed_exact_proposition_text") or ""))
        checks = list(record.get("component_checks") or [])
        if len(components) != len(checks):
            raise ValueError("phase2a_materiality_component_inventory_mismatch")
        evidence: list[dict[str, Any]] = []
        for component, check in zip(components, checks, strict=True):
            item = (
                _exact_component_evidence(component=component, check=check)
                if check.get("exact_normalized_component_match") is True
                else _corrected_component_evidence(component=component, check=check)
            )
            identity = _authority_identity(
                url=str(item["official_url"] or ""),
                title=str(record.get("official_source_title") or ""),
                citation=str(record.get("official_citation") or ""),
            )
            assessment = _candidate_assessment(
                authority_identity=identity,
                candidate_sources=candidate_sources,
            )
            component_material = {**item, "candidate_coverage": assessment}
            evidence.append(
                {
                    **component_material,
                    "component_evidence_content_sha256": _sealed(component_material),
                }
            )
        source_admission_required = any(
            item["candidate_coverage"]["owner_source_admission_required"] for item in evidence
        )
        material = {
            "row_id": row_id,
            "official_source_title": record.get("official_source_title"),
            "official_citation": record.get("official_citation"),
            "stated_official_legal_locator": record.get("stated_official_legal_locator"),
            "prior_proposed_proposition_text": record.get("proposed_exact_proposition_text"),
            "component_count": len(evidence),
            "component_evidence": evidence,
            "advisory_recommendation": (
                "APPROVE_CORRECTED_BINDING_AND_REQUIRED_SOURCE_ADMISSION"
                if source_admission_required
                else "APPROVE_CORRECTED_BINDING_WITHOUT_SOURCE_ADMISSION"
            ),
            "owner_materiality_decision": None,
            "owner_source_admission_required": source_admission_required,
            "owner_source_admission_decision": (
                None if source_admission_required else "NOT_APPLICABLE_EXISTING_AUTHORITY"
            ),
            "owner_comments": None,
            "gold_change_authorized": False,
            "source_admission_authorized": False,
            "indexing_authorized": False,
            "embedding_authorized": False,
            "candidate_mutated": False,
            "issue_technically_qualified": False,
        }
        rows.append({**material, "row_content_sha256": _sealed(material)})
    if len(rows) != EXPECTED_CORRECTED_ROW_COUNT:
        raise ValueError("phase2a_materiality_corrected_row_count_invalid")
    return rows


def _supplemental_rows(batch: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for proposal in batch.get("proposals", []):
        for row_id in proposal.get("row_ids", []):
            material = {
                "row_id": row_id,
                "official_source_title": proposal["source_title"],
                "official_citation": proposal["authority_identity"],
                "stated_official_legal_locator": [
                    item["anchor_id"] for item in proposal["material_claim_spans"]
                ],
                "prior_proposed_proposition_text": None,
                "component_count": len(proposal["material_claim_spans"]),
                "component_evidence": proposal["material_claim_spans"],
                "currentness_evidence": proposal["currentness_spans"],
                "proposed_action": proposal["proposed_action"],
                "candidate_coverage": {
                    "authority_identity": proposal["authority_identity"],
                    "assessment": proposal["candidate_coverage_assessment"],
                    "candidate_source_version_id": proposal["candidate_source_version_id"],
                    "candidate_source_as_of_date": proposal["candidate_source_as_of_date"],
                    "candidate_source_currentness_verified": proposal[
                        "candidate_source_currentness_verified"
                    ],
                    "owner_source_admission_required": proposal["owner_source_admission_required"],
                },
                "advisory_recommendation": proposal["advisory_recommendation"],
                "owner_materiality_decision": None,
                "owner_source_admission_required": proposal["owner_source_admission_required"],
                "owner_source_admission_decision": proposal["owner_source_admission_decision"],
                "owner_comments": None,
                "gold_change_authorized": False,
                "source_admission_authorized": False,
                "indexing_authorized": False,
                "embedding_authorized": False,
                "candidate_mutated": False,
                "issue_technically_qualified": False,
            }
            rows.append({**material, "row_content_sha256": _sealed(material)})
    if len(rows) != EXPECTED_SUPPLEMENTAL_ROW_COUNT:
        raise ValueError("phase2a_materiality_supplemental_row_count_invalid")
    return rows


def build(
    *,
    rebinding_verification_path: Path,
    supplemental_batch_path: Path,
    candidate_manifest_path: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Create one exact owner decision batch without applying any decision."""

    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_materiality_output_already_exists")
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_materiality_output_mode_invalid")
    verification = _load_object(rebinding_verification_path)
    verification_digest = _verify_seal(
        verification,
        "artifact_content_sha256",
        "phase2a_materiality_rebinding_seal_invalid",
    )
    supplemental = _load_object(supplemental_batch_path)
    supplemental_digest = _verify_seal(
        supplemental,
        "artifact_content_sha256",
        "phase2a_materiality_supplemental_seal_invalid",
    )
    candidate_manifest = _load_object(candidate_manifest_path)
    candidate_manifest_digest = approved_source_manifest_sha256(candidate_manifest)
    if candidate_manifest.get("manifest_sha256") != candidate_manifest_digest:
        raise ValueError("phase2a_materiality_candidate_manifest_invalid")
    candidate_sources = {
        str(item.get("authority_identity_id") or ""): item
        for item in candidate_manifest.get("sources", [])
        if item.get("authority_identity_id")
    }
    rows = _corrected_rows(
        verification=verification,
        candidate_sources=candidate_sources,
    ) + _supplemental_rows(supplemental)
    rows.sort(key=lambda item: str(item["row_id"]))
    if len(rows) != EXPECTED_BATCH_ROW_COUNT or len({item["row_id"] for item in rows}) != 54:
        raise ValueError("phase2a_materiality_batch_row_inventory_invalid")

    admission_authorities = sorted(
        {
            coverage["authority_identity"]
            for row in rows
            if row["owner_source_admission_required"]
            for coverage in (
                [row["candidate_coverage"]]
                if "candidate_coverage" in row
                else [item["candidate_coverage"] for item in row["component_evidence"]]
            )
            if coverage.get("owner_source_admission_required")
            and coverage.get("authority_identity")
        }
    )
    recommendation_counts = Counter(str(item["advisory_recommendation"]) for item in rows)
    material = {
        "schema": "legalbot.v111.phase2a.owner-materiality-batch-54.v1",
        "status": "OWNER_ROW_MATERIALITY_DECISIONS_REQUIRED_NOT_APPLIED",
        "source_rebinding_verification_content_sha256": verification_digest,
        "source_supplemental_batch_content_sha256": supplemental_digest,
        "sealed_candidate_manifest_sha256": candidate_manifest_digest,
        "sealed_candidate_identity": candidate_manifest.get("candidate_id"),
        "row_count": len(rows),
        "recommendation_counts": dict(sorted(recommendation_counts.items())),
        "proposed_source_admission_authorities": admission_authorities,
        "proposed_source_admission_authority_count": len(admission_authorities),
        "rows": rows,
        "owner_decision_required": True,
        "owner_decisions_applied": False,
        "automatic_gold_change": False,
        "automatic_source_admission": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "issue_technically_qualified_count": 0,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    artifact = {**material, "artifact_content_sha256": _sealed(material)}
    artifact_path = output_root / "OWNER-MATERIALITY-DECISION-BATCH-54.json"
    _write_exclusive(
        artifact_path,
        (json.dumps(artifact, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(),
    )
    approval = (
        "OWNER DECISION — APPROVE EXACT PHASE-2A MATERIALITY BATCH ONLY\n\n"
        f"I, [OWNER FULL NAME], approve all 54 row-level materiality and binding "
        f"recommendations in artifact digest {artifact['artifact_content_sha256']}.\n\n"
        "I expressly approve proposition-level admission of only the new official "
        f"authorities listed in that artifact: {', '.join(admission_authorities) or 'NONE'}.\n\n"
        "This approval authorizes continued Phase 2A remediation only. It does not "
        "authorize Phase 2B, Development 30, Validation, promotion, or live activation.\n\n"
        "Owner typed name: [OWNER FULL NAME]\n"
        "Owner decision date: [YYYY-MM-DD]\n\n"
        "I APPROVE THIS EXACT DIGEST.\n"
    )
    _write_exclusive(output_root / "OWNER-APPROVAL-TEMPLATE.txt", approval.encode())
    return {
        "output_root": str(output_root),
        "artifact_content_sha256": artifact["artifact_content_sha256"],
        "row_count": len(rows),
        "proposed_source_admission_authorities": admission_authorities,
        "owner_decision_required": True,
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
            "schema": "legalbot.v111.phase2a.materiality-batch-failure.v1",
            "exception_type": type(exc).__name__,
            "error": str(exc),
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        _write_exclusive(
            path,
            (
                json.dumps(
                    {**material, "failure_content_sha256": _sealed(material)},
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                )
                + "\n"
            ).encode(),
        )
    except Exception:
        return


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rebinding-verification", required=True, type=Path)
    parser.add_argument("--supplemental-batch", required=True, type=Path)
    parser.add_argument("--candidate-manifest", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = args.output_root.resolve()
    try:
        result = build(
            rebinding_verification_path=args.rebinding_verification.resolve(strict=True),
            supplemental_batch_path=args.supplemental_batch.resolve(strict=True),
            candidate_manifest_path=args.candidate_manifest.resolve(strict=True),
            output_root=root,
        )
    except Exception as exc:
        _persist_failure(root, exc)
        raise
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
