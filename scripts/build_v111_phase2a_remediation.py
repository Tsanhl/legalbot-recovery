#!/usr/bin/env python3
"""Build a conservative all-585 Phase-2A remediation package.

This command performs deterministic evidence inventory and reconciliation.  It
does not use an answer model, make owner legal judgments, admit sources, mutate
the sealed candidate, build a split, or authorize Phase 2B.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

import lancedb  # type: ignore[import-untyped]

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BASELINE_PACKAGE_ID = "v111-phase2a-20260823-r4-ee47fda9d00a"
BASELINE_INDEX_SHA256 = "e83681be7b737a9bd10e5886449e50da88e47e51428a53efc21836054600ac8e"
BASELINE_REGISTRY_SHA256 = "78a738afd920ff840dcedeb0fd3fd5ca81035f499a0630d351d49e7c6cd3777a"
BASELINE_CANDIDATE_ID = "current-law-ew-full-fp16-v111-20260818-a"
ARTIFACT_ORDER = (
    "canonical-registry-snapshot",
    "remediation-matrix-585",
    "gold-case-reconciliation-509",
    "candidate-impact-reconciliation-76",
    "legislative-effects-register-1896",
    "judgment-later-treatment-register-20",
    "official-source-provenance-register",
    "gold-successor-manifest",
    "successor-source-admission-manifest",
    "successor-candidate-decision",
    "retrieval-reattestation",
    "corrected-all585-qualification",
    "cutoff-proposal",
    "material-change-policy",
    "advisory-ai-audit",
    "exact-head-verification",
    "owner-adoption-draft",
    "final-invariants",
)
_WORD = re.compile(r"[a-z0-9]+")
_NEUTRAL_CITATION = re.compile(
    r"neutral-citation:\[(?P<year>\d{4})\]\s+(?P<court>UKSC|UKHL)\s+(?P<number>\d+)",
    re.IGNORECASE,
)
_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "as",
        "at",
        "by",
        "for",
        "from",
        "in",
        "of",
        "on",
        "or",
        "the",
        "to",
        "with",
    }
)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _load_json(path: Path) -> Any:
    return json.loads(path.read_bytes())


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


def _local_name(value: str) -> str:
    return value.rsplit("}", 1)[-1]


def _normalise_text(value: str) -> str:
    return " ".join(value.split())


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _baseline(package_root: Path) -> tuple[dict[str, Any], tuple[dict[str, Any], ...]]:
    index = _load_json(package_root / "PHASE2A-INDEX.json")
    if (
        index.get("index_sha256") != BASELINE_INDEX_SHA256
        or index.get("registry_canonical_sha256") != BASELINE_REGISTRY_SHA256
        or index.get("artifact_count") != 15
    ):
        raise ValueError("phase2a_baseline_package_binding_invalid")
    issue_artifact = _load_json(package_root / "issue-currentness-register.json")
    rows = issue_artifact.get("payload", {}).get("issues", [])
    if not isinstance(rows, list) or len(rows) != 585:
        raise ValueError("phase2a_baseline_issue_register_invalid")
    if len({str(item.get("row_id")) for item in rows}) != 585:
        raise ValueError("phase2a_baseline_issue_rows_duplicated")
    return index, tuple(item for item in rows if isinstance(item, dict))


def _registry(bundle_path: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    cases: list[dict[str, Any]] = []
    rows: dict[str, dict[str, Any]] = {}
    with bundle_path.open("r", encoding="utf-8") as handle:
        for raw in handle:
            if raw.strip():
                cases.append(json.loads(raw))
    if len(cases) != 60:
        raise ValueError("phase2a_registry_case_count_invalid")
    snapshot_cases: list[dict[str, Any]] = []
    ordinal = 0
    for case in cases:
        issues: list[dict[str, Any]] = []
        for issue_number, label in enumerate(case.get("must_cover_issues", []), start=1):
            ordinal += 1
            issue_id = f"issue-{issue_number:02d}"
            row_id = f"{case['case_id']}:{issue_id}"
            issue = {
                "ordinal": ordinal,
                "row_id": row_id,
                "case_id": case["case_id"],
                "issue_id": issue_id,
                "issue_label": str(label),
                "issue_label_sha256": _sha256(str(label).encode("utf-8")),
                "legal_domain": case["subject"],
                "task_type": case["task_type"],
                "jurisdiction": case["jurisdiction"],
                "case_record_sha256": case["record_sha256"],
                "question_sha256": case["question_sha256"],
            }
            rows[row_id] = issue
            issues.append(
                {
                    "ordinal": ordinal,
                    "row_id": row_id,
                    "issue_id": issue_id,
                    "issue_label": str(label),
                    "issue_label_sha256": issue["issue_label_sha256"],
                }
            )
        snapshot_cases.append(
            {
                "ordinal": case["ordinal"],
                "case_id": case["case_id"],
                "case_record_sha256": case["record_sha256"],
                "question_sha256": case["question_sha256"],
                "subject": case["subject"],
                "task_type": case["task_type"],
                "jurisdiction": case["jurisdiction"],
                "issue_count": len(issues),
                "issues": issues,
            }
        )
    if ordinal != 585:
        raise ValueError("phase2a_registry_issue_count_invalid")
    snapshot: dict[str, Any] = {
        "schema": "legalbot.v111-phase2a-canonical-registry-snapshot.v1",
        "source_registry_sha256": BASELINE_REGISTRY_SHA256,
        "case_count": len(snapshot_cases),
        "issue_count": ordinal,
        "contains_question_prose": False,
        "cases": snapshot_cases,
    }
    snapshot["snapshot_sha256"] = _sealed(snapshot)
    return snapshot, rows


def _query_tokens(label: str) -> tuple[str, ...]:
    return tuple(
        token
        for token in _WORD.findall(label.casefold())
        if len(token) >= 3 and token not in _STOPWORDS
    )


def _fts_candidates(table: Any, *, label: str, limit: int = 5) -> list[dict[str, Any]]:
    tokens = _query_tokens(label)
    if not tokens:
        return []
    query = " ".join(tokens[:12])
    try:
        raw_rows = (
            table.search(query, query_type="fts")
            .where("retrieval_eligible = true")
            .limit(limit)
            .select(
                [
                    "chunk_id",
                    "source_version_id",
                    "title",
                    "canonical_url",
                    "canonical_citation",
                    "locator",
                    "content_sha256",
                    "source_date",
                    "as_of_date",
                    "currentness_status",
                    "identity_verified",
                    "currentness_verified",
                    "legal_role",
                    "text",
                    "_score",
                ]
            )
            .to_list()
        )
    except Exception:
        return []
    candidates: list[dict[str, Any]] = []
    for row in raw_rows:
        text = _normalise_text(str(row.get("text") or ""))
        haystack = f"{row.get('title') or ''} {text}".casefold()
        matched = tuple(token for token in tokens if token in haystack)
        binding = {
            "chunk_id": row.get("chunk_id"),
            "source_version_id": row.get("source_version_id"),
            "title": row.get("title"),
            "canonical_url": row.get("canonical_url"),
            "canonical_citation": row.get("canonical_citation"),
            "locator": row.get("locator"),
            "content_sha256": row.get("content_sha256"),
            "source_date": row.get("source_date"),
            "as_of_date": row.get("as_of_date"),
            "currentness_status": row.get("currentness_status"),
            "identity_verified": row.get("identity_verified"),
            "currentness_verified": row.get("currentness_verified"),
            "legal_role": row.get("legal_role"),
            "fts_score": round(float(row.get("_score") or 0.0), 8),
            "issue_token_count": len(tokens),
            "matched_issue_tokens": list(matched),
            "lexical_token_coverage": round(len(matched) / len(tokens), 6),
            "candidate_span_text": text,
            "semantic_binding_verified": False,
        }
        binding["candidate_binding_sha256"] = _sealed(binding)
        candidates.append(binding)
    return candidates


def _determined_defects(
    baseline: Mapping[str, Any], *, candidates: Sequence[Mapping[str, Any]]
) -> list[str]:
    defects: list[str] = []
    if not baseline.get("registry_gold_binding_sha256"):
        defects.append("MISSING_PROPOSITION_BINDING")
    if not baseline.get("gold_source_ids"):
        defects.append("MISSING_OFFICIAL_SOURCE_BINDING")
    if not baseline.get("official_source_version_ids"):
        defects.append("MISSING_SOURCE_VERSION_BINDING")
    if not baseline.get("gold_span_binding_sha256s"):
        defects.append("MISSING_EXACT_SPAN_BINDING")
    if baseline.get("primary_status") == "MATERIAL_CANDIDATE_COVERAGE_GAP":
        defects.append("UNPROVEN_EXTERNAL_FINDING_TO_PROPOSITION_MAPPING")
    if not candidates or max(float(item["lexical_token_coverage"]) for item in candidates) < 0.5:
        defects.append("POSSIBLE_ADDITIONAL_CANDIDATE_COVERAGE_GAP")
    return defects


def _remediation_rows(
    *,
    baseline_rows: Sequence[Mapping[str, Any]],
    registry_rows: Mapping[str, Mapping[str, Any]],
    table: Any,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    remediated: list[dict[str, Any]] = []
    gold: list[dict[str, Any]] = []
    candidate: list[dict[str, Any]] = []
    for baseline in baseline_rows:
        row_id = str(baseline["row_id"])
        registry = registry_rows.get(row_id)
        if registry is None:
            raise ValueError("phase2a_registry_row_missing")
        fts = _fts_candidates(table, label=str(registry["issue_label"]))
        defects = _determined_defects(baseline, candidates=fts)
        row = {
            **registry,
            "baseline_primary_status": baseline.get("primary_status"),
            "baseline_reason_code": baseline.get("reason_code"),
            "baseline_official_finding_ids": baseline.get("external_official_finding_ids", []),
            "determined_defects": defects,
            "candidate_evidence_candidates": fts,
            "candidate_evidence_candidate_count": len(fts),
            "candidate_evidence_semantically_verified_count": 0,
            "proposition_binding": None,
            "official_source_binding": None,
            "source_version_binding": None,
            "exact_span_binding": None,
            "remediation_result": (
                "EXTERNAL_FINDING_RELEVANCE_AND_EXACT_PROVISION_UNPROVEN"
                if baseline.get("primary_status") == "MATERIAL_CANDIDATE_COVERAGE_GAP"
                else "GOLD_SOURCE_VERSION_SPAN_BINDING_INCOMPLETE"
            ),
            "technical_status": "BLOCKED_MATERIAL_GAP",
            "owner_adopted": False,
            "candidate_change_authorized": False,
            "candidate_change_proven_required": False,
            "answer_model_used": False,
        }
        row["row_evidence_sha256"] = _sealed(row)
        remediated.append(row)
        reconciliation = {
            "ordinal": row["ordinal"],
            "row_id": row_id,
            "case_id": row["case_id"],
            "issue_id": row["issue_id"],
            "issue_label": row["issue_label"],
            "legal_domain": row["legal_domain"],
            "determined_defects": defects,
            "baseline_official_finding_ids": row["baseline_official_finding_ids"],
            "candidate_evidence_candidates": fts,
            "result": row["remediation_result"],
            "technical_status": row["technical_status"],
        }
        reconciliation["record_sha256"] = _sealed(reconciliation)
        if baseline.get("primary_status") == "GOLD_OR_CASE_DEFECT":
            gold.append(reconciliation)
        else:
            candidate.append(reconciliation)
    if len(remediated) != 585 or len(gold) != 509 or len(candidate) != 76:
        raise ValueError("phase2a_reconciliation_count_invalid")
    return remediated, gold, candidate


def _quarantine_records(manifest: Mapping[str, Any]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for item in manifest.get("records", []):
        if isinstance(item, dict):
            grouped[(str(item.get("target_type")), str(item.get("target_id")))].append(item)
    return grouped


def _source_bytes_by_hash(source_root: Path) -> dict[str, tuple[bytes, str]]:
    values: dict[str, tuple[bytes, str]] = {}
    for path in source_root.rglob("*__retrieved-2026-08-14.xml"):
        raw = path.read_bytes()
        digest = _sha256(raw)
        values[digest] = (raw, path.name)
    return values


def _quarantined_bytes(
    *,
    quarantine_root: Path,
    records: Mapping[tuple[str, str], Sequence[Mapping[str, Any]]],
    target_type: str,
    target_id: str,
) -> tuple[bytes, Mapping[str, Any]] | None:
    matches = records.get((target_type, target_id), ())
    for record in sorted(matches, key=lambda item: int(item.get("page") or 0)):
        member = record.get("quarantine_member")
        if record.get("result") != "DOWNLOADED_QUARANTINED" or not member:
            continue
        path = quarantine_root / str(member)
        raw = path.read_bytes()
        if _sha256(raw) != record.get("sha256"):
            raise ValueError("phase2a_quarantine_member_digest_invalid")
        return raw, record
    return None


def _effect_refs(element: ET.Element, child_name: str) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    for child in element:
        if _local_name(child.tag) != child_name:
            continue
        if _normalise_text(child.text or ""):
            values.append({"text": _normalise_text(child.text or ""), "attributes": {}})
        for descendant in child.iter():
            if descendant is child:
                continue
            text = _normalise_text(descendant.text or "")
            attrs = {_local_name(key): str(value) for key, value in descendant.attrib.items()}
            if text or attrs:
                values.append(
                    {
                        "element": _local_name(descendant.tag),
                        "text": text or None,
                        "attributes": attrs,
                    }
                )
    return values


def _in_force_records(element: ET.Element) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    for child in element.iter():
        if _local_name(child.tag) != "InForce":
            continue
        values.append({_local_name(key): str(value) for key, value in child.attrib.items()})
    return values


def _effect_disposition(
    *, requires_applied: bool, in_force: Sequence[Mapping[str, Any]], ceiling: date
) -> tuple[str, bool, str]:
    if not requires_applied:
        return (
            "APPLICABLE_ONLY_TO_METADATA_OR_CURRENTNESS",
            True,
            "Non-textual or editorial effect still requires proposition-level materiality review.",
        )
    dates: list[date] = []
    prospective = False
    applied = False
    for item in in_force:
        prospective = prospective or str(item.get("Prospective") or "").casefold() == "true"
        applied = applied or str(item.get("Applied") or "").casefold() == "true"
        value = str(item.get("Date") or "")
        try:
            if value:
                dates.append(date.fromisoformat(value[:10]))
        except ValueError:
            pass
    if applied:
        return (
            "OWNER_DECISION_REQUIRED_PARTIAL_OR_EXTENT_STATE",
            True,
            "An unapplied-effect record contains an applied in-force state and needs extent/transition review.",
        )
    if dates and all(item > ceiling for item in dates):
        return (
            "NOT_YET_COMMENCED_AT_TARGET_CEILING",
            False,
            "All recorded in-force dates fall after the target ceiling.",
        )
    if dates and any(item <= ceiling for item in dates):
        return (
            "APPLICABLE_AND_MUST_BE_INCORPORATED_OR_EXPLAINED",
            True,
            "At least one recorded in-force date is on or before the target ceiling.",
        )
    if prospective:
        return (
            "NOT_YET_COMMENCED",
            False,
            "The official effect metadata marks the effect prospective and records no in-force date.",
        )
    return (
        "OWNER_DECISION_REQUIRED",
        True,
        "RequiresApplied is true but commencement, extent, transition, or saving is not deterministically resolved.",
    )


def _effects_register(
    *,
    candidate_manifest: Mapping[str, Any],
    source_root: Path,
    quarantine_root: Path,
    quarantine_records: Mapping[tuple[str, str], Sequence[Mapping[str, Any]]],
    ceiling: date,
) -> dict[str, Any]:
    source_by_hash = _source_bytes_by_hash(source_root)
    effects: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    for source in candidate_manifest.get("sources", []):
        authority = str(source.get("authority_identity_id") or "")
        if not authority.startswith(("ukpga:", "uksi:")):
            continue
        source_version_id = str(source["source_version_id"])
        expected = str(source["version_sha256"])
        downloaded = _quarantined_bytes(
            quarantine_root=quarantine_root,
            records=quarantine_records,
            target_type="candidate_legislation",
            target_id=source_version_id,
        )
        if downloaded is not None and _sha256(downloaded[0]) == expected:
            raw = downloaded[0]
            byte_source = "FRESH_POINT_IN_TIME_OFFICIAL_DOWNLOAD_MATCHED_SEALED_VERSION"
            official_record_sha256 = downloaded[1].get("sha256")
        elif expected in source_by_hash:
            raw = source_by_hash[expected][0]
            byte_source = "SEALED_QUARANTINED_POINT_IN_TIME_SOURCE"
            official_record_sha256 = expected
        else:
            raise ValueError("phase2a_legislation_source_bytes_missing")
        root = ET.fromstring(raw)
        source_effect_count = 0
        for effect_ordinal, element in enumerate(
            (item for item in root.iter() if _local_name(item.tag) == "UnappliedEffect"),
            start=1,
        ):
            source_effect_count += 1
            attrs = {_local_name(key): str(value) for key, value in element.attrib.items()}
            in_force = _in_force_records(element)
            disposition, blocks, rationale = _effect_disposition(
                requires_applied=str(attrs.get("RequiresApplied") or "").casefold() == "true",
                in_force=in_force,
                ceiling=ceiling,
            )
            effect = {
                "ordinal": len(effects) + 1,
                "source_effect_ordinal": effect_ordinal,
                "effect_id": attrs.get("EffectId") or attrs.get("URI") or None,
                "source_version_id": source_version_id,
                "source_title": source.get("title"),
                "authority_identity": authority,
                "official_source_url": source.get("canonical_url"),
                "official_source_version_sha256": expected,
                "effect_xml_sha256": _sha256(ET.tostring(element, encoding="utf-8")),
                "type": attrs.get("Type"),
                "affected_uri": attrs.get("AffectedURI"),
                "affected_provisions": attrs.get("AffectedProvisions"),
                "affecting_uri": attrs.get("AffectingURI"),
                "affecting_provisions": attrs.get("AffectingProvisions"),
                "affecting_extent": attrs.get("AffectingEffectsExtent"),
                "requires_applied": str(attrs.get("RequiresApplied") or "").casefold() == "true",
                "modified": attrs.get("Modified"),
                "in_force": in_force,
                "commencement_authority": _effect_refs(element, "CommencementAuthority"),
                "savings": _effect_refs(element, "Savings"),
                "transitional_provisions": _effect_refs(element, "TransitionalProvisions"),
                "disposition": disposition,
                "disposition_rationale": rationale,
                "blocks_common_cutoff": blocks,
                "owner_decision_required": blocks,
                "automatically_ingested": False,
            }
            effect["record_sha256"] = _sealed(effect)
            effects.append(effect)
        declared = int(source.get("unapplied_effect_count") or 0)
        if source_effect_count != declared:
            raise ValueError("phase2a_legislation_effect_count_differs_from_sealed_manifest")
        sources.append(
            {
                "source_version_id": source_version_id,
                "title": source.get("title"),
                "authority_identity": authority,
                "declared_effect_count": declared,
                "extracted_effect_count": source_effect_count,
                "byte_source": byte_source,
                "official_record_sha256": official_record_sha256,
            }
        )
    if len(sources) != 65 or len(effects) != 1896:
        raise ValueError("phase2a_legislative_effect_total_invalid")
    counts = Counter(str(item["disposition"]) for item in effects)
    payload: dict[str, Any] = {
        "schema": "legalbot.v111-phase2a-legislative-effects-register.v1",
        "target_ceiling": ceiling.isoformat(),
        "source_count": len(sources),
        "effect_count": len(effects),
        "disposition_counts": dict(sorted(counts.items())),
        "common_cutoff_blocking_effect_count": sum(
            1 for item in effects if item["blocks_common_cutoff"]
        ),
        "sources": sources,
        "effects": effects,
    }
    payload["register_sha256"] = _sealed(payload)
    return payload


def _atom_entries(raw: bytes) -> list[dict[str, Any]]:
    root = ET.fromstring(raw)
    atom = "{http://www.w3.org/2005/Atom}"
    tna = "{https://caselaw.nationalarchives.gov.uk}"
    values: list[dict[str, Any]] = []
    for entry in root.findall(f"{atom}entry"):
        links = [
            item.attrib
            for item in entry.findall(f"{atom}link")
            if item.attrib.get("rel") == "alternate"
        ]
        html_url = next((item.get("href") for item in links if not item.get("type")), None)
        xml_url = next(
            (item.get("href") for item in links if item.get("type") == "application/akn+xml"),
            None,
        )
        citation = None
        for identifier in entry.findall(f"{tna}identifier"):
            if identifier.attrib.get("type") == "ukncn":
                citation = _normalise_text(identifier.text or "")
                break
        values.append(
            {
                "title": _normalise_text(entry.findtext(f"{atom}title") or ""),
                "neutral_citation": citation,
                "published": entry.findtext(f"{atom}published"),
                "updated": entry.findtext(f"{atom}updated"),
                "html_url": html_url,
                "xml_url": xml_url,
                "content_sha256": entry.findtext(f"{tna}contenthash"),
            }
        )
    return values


def _source_date(table: Any, source_version_id: str) -> date | None:
    escaped = source_version_id.replace("'", "''")
    rows = (
        table.search()
        .where(f"source_version_id = '{escaped}'")
        .limit(1)
        .select(["source_date"])
        .to_list()
    )
    if not rows or not rows[0].get("source_date"):
        return None
    try:
        return date.fromisoformat(str(rows[0]["source_date"])[:10])
    except ValueError:
        return None


def _judgment_register(
    *,
    candidate_manifest: Mapping[str, Any],
    table: Any,
    quarantine_root: Path,
    quarantine_records: Mapping[tuple[str, str], Sequence[Mapping[str, Any]]],
    ceiling: date,
) -> dict[str, Any]:
    search_cache: dict[str, list[dict[str, Any]]] = {}
    rows: list[dict[str, Any]] = []
    for source in candidate_manifest.get("sources", []):
        if source.get("subsequent_treatment_check_required") is not True:
            continue
        authority = str(source.get("authority_identity_id") or "")
        match = _NEUTRAL_CITATION.fullmatch(authority)
        if match is None:
            raise ValueError("phase2a_candidate_judgment_citation_invalid")
        citation = (
            f"[{match.group('year')}] {match.group('court').upper()} {int(match.group('number'))}"
        )
        if citation not in search_cache:
            entries: list[dict[str, Any]] = []
            for record in sorted(
                quarantine_records.get(("later_treatment_search", f"search:{citation}"), ()),
                key=lambda item: int(item.get("page") or 0),
            ):
                if record.get("result") != "DOWNLOADED_QUARANTINED":
                    continue
                path = quarantine_root / str(record["quarantine_member"])
                raw = path.read_bytes()
                if _sha256(raw) != record.get("sha256"):
                    raise ValueError("phase2a_later_treatment_feed_digest_invalid")
                entries.extend(_atom_entries(raw))
            dedup: dict[str, dict[str, Any]] = {}
            for item in entries:
                key = str(item.get("html_url") or item.get("xml_url") or item.get("content_sha256"))
                dedup[key] = item
            search_cache[citation] = list(dedup.values())
        decision_date = _source_date(table, str(source["source_version_id"]))
        later: list[dict[str, Any]] = []
        for entry in search_cache[citation]:
            try:
                published = date.fromisoformat(str(entry.get("published") or "")[:10])
            except ValueError:
                continue
            if published > ceiling or (decision_date is not None and published <= decision_date):
                continue
            if entry.get("neutral_citation") == citation:
                continue
            later.append(entry)
        later.sort(key=lambda item: str(item.get("published") or ""), reverse=True)
        row = {
            "ordinal": len(rows) + 1,
            "source_version_id": source.get("source_version_id"),
            "title": source.get("title"),
            "neutral_citation": citation,
            "decision_date": decision_date.isoformat() if decision_date else None,
            "court_status": "SUPREME_APPELLATE_AUTHORITY_POTENTIALLY_BINDING_SUBJECT_TO_HOLDING",
            "proposition_relied_upon": None,
            "proposition_binding_status": "UNBOUND_IN_CANONICAL_REGISTRY",
            "candidate_version_sha256": source.get("version_sha256"),
            "candidate_version_sealed": True,
            "later_mention_search_source": "FIND_CASE_LAW_OFFICIAL_FULL_TEXT_SEARCH",
            "later_mention_candidate_count": len(later),
            "later_mention_candidates": later[:25],
            "later_treatment_status": (
                "SEARCH_CANDIDATES_IDENTIFIED_SEMANTIC_TREATMENT_REVIEW_REQUIRED"
                if later
                else "NO_LATER_MENTION_FOUND_NOT_PROOF_OF_NO_LATER_TREATMENT"
            ),
            "affirmed_limited_distinguished_displaced_status": "OWNER_DECISION_REQUIRED",
            "gold_proposition_current": None,
            "technical_status": "OWNER_DECISION_REQUIRED",
            "answer_model_used": False,
        }
        row["record_sha256"] = _sealed(row)
        rows.append(row)
    if len(rows) != 20:
        raise ValueError("phase2a_judgment_register_count_invalid")
    payload: dict[str, Any] = {
        "schema": "legalbot.v111-phase2a-judgment-later-treatment-register.v1",
        "target_ceiling": ceiling.isoformat(),
        "record_count": len(rows),
        "unique_neutral_citation_count": len({str(item["neutral_citation"]) for item in rows}),
        "resolved_record_count": 0,
        "owner_decision_required_count": len(rows),
        "records": rows,
    }
    payload["register_sha256"] = _sealed(payload)
    return payload


def _external_reconciliation(
    *,
    candidate_rows: Sequence[dict[str, Any]],
    package_root: Path,
    quarantine_records: Mapping[tuple[str, str], Sequence[Mapping[str, Any]]],
) -> list[dict[str, Any]]:
    source_artifact = _load_json(package_root / "official-source-provenance-register.json")
    payload = source_artifact.get("payload", {})
    findings = {
        str(item["finding_id"]): item
        for item in payload.get("external_official_findings", [])
        if isinstance(item, dict)
    }
    details = payload.get("review_details", {})
    review_records = {
        str(item["finding_id"]): item
        for item in details.get("external_finding_review_records", [])
        if isinstance(item, dict)
    }
    results: list[dict[str, Any]] = []
    for row in candidate_rows:
        ids = [str(item) for item in row.get("baseline_official_finding_ids", [])]
        official: list[dict[str, Any]] = []
        for finding_id in ids:
            finding = findings[finding_id]
            fetch = quarantine_records.get(("external_finding_source", finding_id), ())
            official.append(
                {
                    "finding": finding,
                    "baseline_review_record": review_records.get(finding_id),
                    "fresh_official_fetch_records": list(fetch),
                    "specific_proposition_identified": False,
                    "specific_provision_or_holding_identified": False,
                    "commencement_extent_transition_saving_resolved": False,
                    "candidate_absence_observed": True,
                    "candidate_gap_proven_material": False,
                }
            )
        result = {
            **row,
            "external_findings": official,
            "candidate_impact_conclusion": "DEFER_SOURCE_ADMISSION_UNTIL_PROPOSITION_MAPPING_PROVEN",
            "candidate_rebuild_authorized": False,
            "candidate_rebuild_proven_required": False,
            "technical_status": "BLOCKED_MATERIAL_GAP",
        }
        result["record_sha256"] = _sealed(
            {key: value for key, value in result.items() if key != "record_sha256"}
        )
        results.append(result)
    if len(results) != 76:
        raise ValueError("phase2a_candidate_impact_reconciliation_count_invalid")
    return results


def _artifact(schema: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    value = {"schema": schema, **payload}
    value["artifact_sha256"] = _sealed(value)
    return value


def _optional_artifact(path: Path | None, *, unavailable_reason: str) -> dict[str, Any]:
    if path is None:
        return {"status": "UNAVAILABLE", "reason": unavailable_reason}
    value = _load_json(path)
    return {
        "status": "AVAILABLE",
        "source_file_sha256": _sha256(path.read_bytes()),
        "report": value,
    }


def _official_source_summary(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    legislation = [item for item in records if item.get("target_type") == "candidate_legislation"]
    downloaded = [item for item in legislation if item.get("result") == "DOWNLOADED_QUARANTINED"]
    exact_matches = [
        item for item in downloaded if item.get("matches_expected_version_sha256") is True
    ]
    byte_mismatches = [
        item for item in downloaded if item.get("matches_expected_version_sha256") is False
    ]
    unavailable = [item for item in records if item.get("result") == "OFFICIAL_SOURCE_UNAVAILABLE"]
    return {
        "candidate_legislation_record_count": len(legislation),
        "candidate_legislation_downloaded_count": len(downloaded),
        "candidate_legislation_exact_hash_match_count": len(exact_matches),
        "candidate_legislation_byte_mismatch_count": len(byte_mismatches),
        "official_source_unavailable_count": len(unavailable),
        "byte_mismatch_interpretation": (
            "A byte mismatch proves that the fresh official point-in-time XML is not the exact "
            "sealed candidate source byte sequence. It does not alone prove a substantive legal "
            "change; proposition-level materiality remains OWNER_DECISION_REQUIRED."
        ),
    }


def build(
    *,
    package_root: Path,
    bundle_path: Path,
    candidate_root: Path,
    source_root: Path,
    quarantine_root: Path,
    quarantine_manifest_path: Path,
    output_root: Path,
    target_date: date,
    run_id: str,
    retrieval_report: Path | None,
    verification_report: Path | None,
) -> dict[str, Any]:
    if output_root.exists():
        raise ValueError("phase2a_remediation_output_already_exists")
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_remediation_output_mode_invalid")
    baseline_index, baseline_rows = _baseline(package_root)
    registry_snapshot, registry_rows = _registry(bundle_path)
    candidate_manifest = _load_json(candidate_root / "approved-source-manifest.json")
    if candidate_manifest.get("manifest_sha256") != baseline_index.get(
        "candidate_source_manifest_sha256"
    ):
        raise ValueError("phase2a_candidate_manifest_differs_from_baseline")
    quarantine_manifest = _load_json(quarantine_manifest_path)
    material = dict(quarantine_manifest)
    manifest_digest = str(material.pop("manifest_sha256", ""))
    if manifest_digest != _sealed(material):
        raise ValueError("phase2a_quarantine_manifest_digest_invalid")
    grouped = _quarantine_records(quarantine_manifest)
    quarantine_records = quarantine_manifest.get("records", [])
    if not isinstance(quarantine_records, list):
        raise ValueError("phase2a_quarantine_records_invalid")
    official_source_summary = _official_source_summary(quarantine_records)
    table = lancedb.connect(str(candidate_root / "lance" / "authority")).open_table("chunks")
    remediation, gold_rows, candidate_rows = _remediation_rows(
        baseline_rows=baseline_rows,
        registry_rows=registry_rows,
        table=table,
    )
    candidate_reconciliation = _external_reconciliation(
        candidate_rows=candidate_rows,
        package_root=package_root,
        quarantine_records=grouped,
    )
    effects = _effects_register(
        candidate_manifest=candidate_manifest,
        source_root=source_root,
        quarantine_root=quarantine_root,
        quarantine_records=grouped,
        ceiling=target_date,
    )
    judgments = _judgment_register(
        candidate_manifest=candidate_manifest,
        table=table,
        quarantine_root=quarantine_root,
        quarantine_records=grouped,
        ceiling=target_date,
    )
    status_counts = Counter(str(item["technical_status"]) for item in remediation)
    tracked_status = _git("status", "--porcelain", "--untracked-files=no")
    exact_head = {
        "commit_sha": _git("rev-parse", "HEAD"),
        "tree_sha": _git("rev-parse", "HEAD^{tree}"),
        "branch": _git("branch", "--show-current"),
        "tracked_worktree_clean": not bool(tracked_status),
        "baseline_checkpoint": "79d0629c66e9758ad932a58261e7466ad0a8dbfc",
        "verification_report": _optional_artifact(
            verification_report,
            unavailable_reason="No exact-HEAD verification report was supplied to this build.",
        ),
    }
    retrieval = _optional_artifact(
        retrieval_report,
        unavailable_reason=(
            "A successor candidate was not built because no external source was admitted; "
            "retrieval re-attestation therefore remains a separately reportable mechanical check."
        ),
    )
    artifacts: dict[str, dict[str, Any]] = {
        "canonical-registry-snapshot": registry_snapshot,
        "remediation-matrix-585": _artifact(
            "legalbot.v111-phase2a-remediation-matrix.v1",
            {
                "run_id": run_id,
                "row_count": len(remediation),
                "technical_status_counts": dict(sorted(status_counts.items())),
                "rows": remediation,
            },
        ),
        "gold-case-reconciliation-509": _artifact(
            "legalbot.v111-phase2a-gold-case-reconciliation.v1",
            {"record_count": len(gold_rows), "records": gold_rows},
        ),
        "candidate-impact-reconciliation-76": _artifact(
            "legalbot.v111-phase2a-candidate-impact-reconciliation.v1",
            {"record_count": len(candidate_reconciliation), "records": candidate_reconciliation},
        ),
        "legislative-effects-register-1896": effects,
        "judgment-later-treatment-register-20": judgments,
        "official-source-provenance-register": _artifact(
            "legalbot.v111-phase2a-official-source-provenance.v1",
            {
                "quarantine_manifest_sha256": manifest_digest,
                "record_count": quarantine_manifest.get("record_count"),
                "records": quarantine_records,
                "summary": official_source_summary,
                "automatic_source_admission": False,
            },
        ),
        "gold-successor-manifest": _artifact(
            "legalbot.v111-phase2a-gold-successor-manifest.v1",
            {
                "status": "WITHHELD_INCOMPLETE_PROPOSITION_SOURCE_VERSION_SPAN_BINDINGS",
                "predecessor_registry_sha256": BASELINE_REGISTRY_SHA256,
                "successor_gold_row_count": 0,
                "historical_artifacts_preserved": True,
            },
        ),
        "successor-source-admission-manifest": _artifact(
            "legalbot.v111-phase2a-successor-source-admission-manifest.v1",
            {
                "status": "WITHHELD_NO_PROVEN_PROPOSITION_LEVEL_SOURCE_GAPS",
                "admitted_source_count": 0,
                "candidate_external_finding_count": 11,
                "automatic_source_admission": False,
                "automatic_indexing": False,
                "automatic_embedding": False,
            },
        ),
        "successor-candidate-decision": _artifact(
            "legalbot.v111-phase2a-successor-candidate-decision.v1",
            {
                "status": "WITHHELD_NO_PROVEN_CONSOLIDATED_SCOPE",
                "successor_candidate_built": False,
                "existing_candidate_mutated": False,
                "reason": "No external finding has a completed proposition/provision/holding mapping, so a consolidated successor scope is not yet supportable.",
                "candidate_build_id": candidate_manifest.get("corpus_id") or BASELINE_CANDIDATE_ID,
                "candidate_manifest_sha256": candidate_manifest.get("manifest_sha256"),
            },
        ),
        "retrieval-reattestation": _artifact(
            "legalbot.v111-phase2a-retrieval-reattestation.v1", retrieval
        ),
        "corrected-all585-qualification": _artifact(
            "legalbot.v111-phase2a-corrected-all585-qualification.v1",
            {
                "case_count": 60,
                "issue_count": 585,
                "status_counts": dict(sorted(status_counts.items())),
                "technically_evidence_ready_for_owner_adoption": 0,
                "technically_ready_with_nonmaterial_note": 0,
                "blocked_material_gap": 585,
                "owner_decision_required": 0,
                "owner_adopted_qualified": 0,
                "phase2b_allowed": False,
            },
        ),
        "cutoff-proposal": _artifact(
            "legalbot.v111-phase2a-cutoff-proposal.v1",
            {
                "target_ceiling": "2026-08-14T23:59:59+01:00 Europe/London",
                "target_ceiling_only": True,
                "common_cutoff_supportable": False,
                "proposed_common_cutoff": None,
                "reason": "All 585 rows lack complete adopted proposition/source/version/span bindings and material currentness questions remain.",
            },
        ),
        "material-change-policy": _artifact(
            "legalbot.v111-phase2a-material-change-policy.v1",
            {
                "material_changes": [
                    "new-or-amended-primary-authority-affecting-a-bound-proposition",
                    "commencement-extent-transition-saving-or-repeal-change",
                    "later-treatment-affecting-a-relied-upon-holding",
                    "gold-proposition-source-version-or-span-change",
                    "candidate-source-or-index-byte-change",
                ],
                "required_response": "new-versioned-artifact-and-full-affected-gate-replay",
                "historical_overwrite_forbidden": True,
            },
        ),
        "advisory-ai-audit": _artifact(
            "legalbot.v111-phase2a-advisory-ai-audit.v1",
            {
                "status": "UNAVAILABLE",
                "reason": "No reproducibly digest-pinned verification-only reviewer transport was provisioned for Phase 2A.",
                "official_source_remediation_blocked_by_unavailability": False,
                "answer_model_invoked": False,
                "hidden_reasoning_persisted": False,
            },
        ),
        "exact-head-verification": _artifact(
            "legalbot.v111-phase2a-exact-head-verification.v1", exact_head
        ),
        "owner-adoption-draft": _artifact(
            "legalbot.v111-phase2a-owner-adoption-draft.v1",
            {
                "status": "UNSIGNED_NONAUTHORIZING_DRAFT",
                "owner_adoption_available": False,
                "reason": "The package contains 585 BLOCKED_MATERIAL_GAP rows.",
                "phase2b_authorized": False,
                "cryptographic_signature_present": False,
                "private_key_requested": False,
            },
        ),
        "final-invariants": _artifact(
            "legalbot.v111-phase2a-final-invariants.v1",
            {
                "terminal_verdict": "PHASE 2A SAFELY STOPPED — PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED",
                "phase2b_allowed": False,
                "all585_accounted": True,
                "legislative_effects_1896_accounted": True,
                "judgment_records_20_accounted": True,
                "successor_candidate_built": False,
                "existing_candidate_mutated": False,
                "real_split_created": False,
                "split_secret_created": False,
                "owner_key_created": False,
                "session_or_csrf_secret_created": False,
                "private_review_roots_created": False,
                "model_socket_created": False,
                "stage_a_invoked": False,
                "answer_model_invoked": False,
                "development_30_generated": False,
                "promotion_or_live_action": False,
            },
        ),
    }
    if tuple(artifacts) != ARTIFACT_ORDER:
        raise ValueError("phase2a_remediation_artifact_order_invalid")
    entries: list[dict[str, Any]] = []
    for ordinal, artifact_id in enumerate(ARTIFACT_ORDER, start=1):
        raw = _canonical_json(artifacts[artifact_id])
        name = f"{artifact_id}.json"
        _write_exclusive(output_root / name, raw)
        entries.append(
            {
                "ordinal": ordinal,
                "artifact_id": artifact_id,
                "file_name": name,
                "file_sha256": _sha256(raw),
                "bytes": len(raw),
            }
        )
    index: dict[str, Any] = {
        "schema": "legalbot.v111-phase2a-remediation-package-index.v1",
        "run_id": run_id,
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "phase": "2A",
        "authorizing": False,
        "baseline_package_id": BASELINE_PACKAGE_ID,
        "baseline_index_sha256": BASELINE_INDEX_SHA256,
        "candidate_manifest_sha256": candidate_manifest.get("manifest_sha256"),
        "artifact_count": len(entries),
        "artifact_order": list(ARTIFACT_ORDER),
        "entries": entries,
        "terminal_verdict": "PHASE 2A SAFELY STOPPED — PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED",
    }
    index["package_digest"] = _sealed(index)
    _write_exclusive(output_root / "PACKAGE-INDEX.json", _canonical_json(index))
    _write_exclusive(
        output_root / "OUTCOME.txt",
        b"PHASE 2A SAFELY STOPPED \xe2\x80\x94 PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED\n",
    )
    return index


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase2a-package-root", type=Path, required=True)
    parser.add_argument("--bundle-cases", type=Path, required=True)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--quarantine-root", type=Path, required=True)
    parser.add_argument("--quarantine-manifest", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--target-date", type=date.fromisoformat, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--retrieval-report", type=Path)
    parser.add_argument("--verification-report", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    index = build(
        package_root=args.phase2a_package_root.resolve(strict=True),
        bundle_path=args.bundle_cases.resolve(strict=True),
        candidate_root=args.candidate_root.resolve(strict=True),
        source_root=args.source_root.resolve(strict=True),
        quarantine_root=args.quarantine_root.resolve(strict=True),
        quarantine_manifest_path=args.quarantine_manifest.resolve(strict=True),
        output_root=args.output_root.resolve(),
        target_date=args.target_date,
        run_id=str(args.run_id),
        retrieval_report=args.retrieval_report.resolve(strict=True)
        if args.retrieval_report
        else None,
        verification_report=args.verification_report.resolve(strict=True)
        if args.verification_report
        else None,
    )
    print(
        json.dumps(
            {
                "status": "safely_stopped",
                "package_digest": index["package_digest"],
                "artifact_count": index["artifact_count"],
                "terminal_verdict": index["terminal_verdict"],
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
