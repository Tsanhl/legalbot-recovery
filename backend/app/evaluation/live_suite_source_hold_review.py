"""Re-evaluate previously HOLDed source-version decisions under V2 admission.

The original digest-bound pack remains immutable audit history. A new pack is
minted. Auto-eligible official sources may APPROVE without an owner token.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from xml.etree import ElementTree as ET

from .live30 import assert_safe_evaluation_payload
from .live_suite import sealed_sha256
from .live_suite_source_admission import (
    SOURCE_ADMISSION_PACK_SCHEMA,
    SOURCE_ADMISSION_POLICY_V2,
    apply_auto_source_admission_pack,
    evaluate_source_admission,
    mechanical_legislation_source_approval,
    official_primary_host,
)
from .live_suite_source_version_pack import (
    SOURCE_VERSION_PACK_SCHEMA,
)
from .live_suite_source_version_pack import (
    pack_sha256 as owner_pack_sha256,
)

SOURCE_HOLD_REVIEW_SCHEMA = "legalbot.source-hold-review.v2"
_LEGISLATION_PATH = re.compile(
    r"^/(ukpga|uksi|ukla|asc|anaw|nia|asp|eur|eudn|eudr)"
    r"/([^/]+)/([^/]+)(?:/(section|article|regulation|rule|paragraph|schedule)/([^/]+))?",
    re.IGNORECASE,
)
_INSTRUMENT_PATH = re.compile(
    r"^/(ukpga|uksi|ukla|asc|anaw|nia|asp|eur|eudn|eudr)/([^/]+)/([^/]+)(?P<rest>/.*)?$",
    re.IGNORECASE,
)
_WHOLE_INSTRUMENT_LABEL = re.compile(
    r"^(act|the act|regulation|the regulation|instrument|si|order|rules|the rules)$",
    re.IGNORECASE,
)
_REF_KIND_PREFIXES = (
    "schedule",
    "paragraph",
    "regulation",
    "article",
    "section",
    "rule",
)


def local_xml_tag(tag: str) -> str:
    return tag.split("}", 1)[-1]


def _local_tag(tag: str) -> str:
    return local_xml_tag(tag)


def official_page_url(url: str) -> str:
    cleaned = url.strip().rstrip("/")
    if cleaned.endswith("/data.xml"):
        return cleaned[: -len("/data.xml")]
    if cleaned.endswith("/data.html"):
        return cleaned[: -len("/data.html")]
    return cleaned


def stable_identifier_from_official_url(url: str, *, as_of_date: str) -> str | None:
    parsed = urlparse(official_page_url(url))
    if parsed.hostname not in {"www.legislation.gov.uk", "legislation.gov.uk"}:
        return None
    match = _LEGISLATION_PATH.match(parsed.path)
    if match is None:
        return None
    kind, year, number, provision_kind, provision = match.groups()
    authority = f"{kind.lower()}:{year}:{number}"
    if provision_kind and provision:
        authority = f"{authority}:{provision_kind.lower()}:{provision}"
    return f"{authority}:latest-available@{as_of_date}"


def legislation_provision_path(url: str) -> str | None:
    """Return the provision path after /{type}/{year}/{number}, or '' for the instrument."""

    parsed = urlparse(official_page_url(url))
    if parsed.hostname not in {"www.legislation.gov.uk", "legislation.gov.uk"}:
        return None
    match = _INSTRUMENT_PATH.match(parsed.path.rstrip("/"))
    if match is None:
        return None
    return str(match.group("rest") or "")


def _effect_uri_provision_path(uri: str, source_url: str) -> str | None:
    source = urlparse(official_page_url(source_url))
    instrument = _INSTRUMENT_PATH.match(source.path.rstrip("/"))
    if instrument is None:
        return None
    kind, year, number = instrument.group(1), instrument.group(2), instrument.group(3)
    path = urlparse(uri).path.rstrip("/")
    marker = f"/{kind}/{year}/{number}"
    folded = path.casefold()
    index = folded.find(marker.casefold())
    if index < 0:
        return None
    return path[index + len(marker) :]


def _ref_to_provision_path(ref: str) -> str | None:
    token = str(ref or "").strip()
    if not token:
        return None
    lowered = token.casefold().replace("_", "-")
    if lowered.startswith("sch-") and not lowered.startswith("schedule-"):
        lowered = "schedule-" + lowered[4:]
    if lowered.startswith("art-") and not lowered.startswith("article-"):
        lowered = "article-" + lowered[4:]
    if re.fullmatch(r"s-\S+", lowered):
        lowered = "section-" + lowered[2:]
    for kind in _REF_KIND_PREFIXES:
        prefix = kind + "-"
        if lowered.startswith(prefix):
            rest = lowered[len(prefix) :]
            rest = rest.replace("-paragraph-", "/paragraph/")
            rest = rest.replace("-", "/")
            return f"/{kind}/{rest}"
    return None


def _provision_paths_related(source_path: str, effect_path: str) -> bool:
    source = source_path.rstrip("/").casefold()
    effect = effect_path.rstrip("/").casefold()
    if not effect:
        return True
    if not source:
        return True
    if source == effect:
        return True
    return effect.startswith(source + "/") or source.startswith(effect + "/")


def unapplied_effect_is_material_to_source(
    element: ET.Element,
    *,
    official_source_url: str | None,
) -> bool:
    """True when a RequiresApplied effect targets this provision or the instrument."""

    if not official_source_url:
        return True
    source_path = legislation_provision_path(official_source_url)
    if source_path is None:
        return True
    affected_label = ""
    for key, value in element.attrib.items():
        if _local_tag(key) == "AffectedProvisions":
            affected_label = str(value or "").strip()
    effect_paths: list[str] = []
    for child in list(element):
        if _local_tag(child.tag) != "AffectedProvisions":
            continue
        for section in child:
            name = _local_tag(section.tag)
            if name not in {"Section", "SectionRange"}:
                continue
            attrs = {_local_tag(key): value for key, value in section.attrib.items()}
            uri_values = [
                attrs.get("URI"),
                attrs.get("UpTo"),
            ]
            ref_values = [
                attrs.get("Ref"),
                attrs.get("FoundRef"),
                attrs.get("Start"),
                attrs.get("End"),
                attrs.get("FoundStart"),
                attrs.get("FoundEnd"),
                " ".join((section.text or "").split()),
            ]
            for uri in uri_values:
                if uri:
                    uri_path = _effect_uri_provision_path(str(uri), official_source_url)
                    if uri_path is not None:
                        effect_paths.append(uri_path)
            for ref in ref_values:
                if not ref or str(ref).casefold().startswith("section missing"):
                    continue
                ref_path = _ref_to_provision_path(str(ref))
                if ref_path is not None:
                    effect_paths.append(ref_path)
    if not effect_paths:
        if not affected_label or _WHOLE_INSTRUMENT_LABEL.match(affected_label):
            return True
        label_path = _ref_to_provision_path(affected_label)
        if label_path is None:
            return True
        effect_paths.append(label_path)
    return any(_provision_paths_related(source_path, path) for path in effect_paths)


def xml_admission_flags(
    raw: bytes,
    *,
    official_source_url: str | None = None,
) -> dict[str, Any]:
    flags: dict[str, Any] = {
        "parser_success": False,
        "england_and_wales_extent_verified": False,
        "extent": None,
        "unapplied_effect_requires_applied_count": 0,
        "unapplied_effect_other_provision_count": 0,
        "unapplied_effects_reviewed_or_nonmaterial": False,
        "title": None,
        "content_nonempty": len(raw) > 0,
    }
    text = raw.lstrip()
    if not text.startswith(b"<"):
        return flags
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return flags
    flags["parser_success"] = True
    requires_applied = 0
    other_provision = 0
    notes_only = 0
    for element in root.iter():
        name = _local_tag(element.tag)
        if name == "Title" and not flags["title"] and (element.text or "").strip():
            flags["title"] = " ".join((element.text or "").split())[:240]
        if "RestrictExtent" in element.attrib and flags["extent"] is None:
            flags["extent"] = element.attrib.get("RestrictExtent") or ""
        if name == "UnappliedEffect":
            required = None
            for key, value in element.attrib.items():
                if _local_tag(key) == "RequiresApplied":
                    required = value
            if required == "true":
                if unapplied_effect_is_material_to_source(
                    element, official_source_url=official_source_url
                ):
                    requires_applied += 1
                else:
                    other_provision += 1
            else:
                notes_only += 1
    extent = str(flags["extent"] or "")
    flags["england_and_wales_extent_verified"] = "E+W" in extent
    flags["unapplied_effect_requires_applied_count"] = requires_applied
    flags["unapplied_effect_other_provision_count"] = other_provision
    flags["unapplied_effects_reviewed_or_nonmaterial"] = requires_applied == 0
    flags["nonmaterial_unapplied_notes_only"] = requires_applied == 0 and notes_only > 0
    flags["nonmaterial_unapplied_other_provision"] = requires_applied == 0 and other_provision > 0
    return flags


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def review_one_held_source(
    original: Mapping[str, Any],
    *,
    catalogue: Mapping[str, Any] | None,
    official_bytes: bytes | None,
    scan_id: str,
    as_of_date: str,
) -> dict[str, Any]:
    """Build SOURCE_HOLD_REVIEW_V2 for one previously HOLDed source."""

    url = str(original.get("official_source_url") or "")
    flags = xml_admission_flags(official_bytes or b"", official_source_url=url)
    source_version_id = None
    if catalogue is not None:
        source_version_id = str(catalogue.get("source_version_id") or "") or None
    document_sha = _sha256_bytes(official_bytes) if official_bytes else None
    version_sha = None
    if catalogue is not None:
        version_sha = str(catalogue.get("version_sha256") or "") or None
    quarantined = bool(catalogue and catalogue.get("document_status") == "quarantined")
    parser_ok = flags["parser_success"] and not quarantined
    if catalogue is not None and catalogue.get("chunk_count"):
        locator_ok = int(catalogue.get("chunk_count") or 0) > 0
    else:
        locator_ok = False
    scan_ok = bool(catalogue and scan_id in (catalogue.get("scan_ids") or ()))
    identity = stable_identifier_from_official_url(url, as_of_date=as_of_date)
    official = official_primary_host(url)
    rights_ok = official and flags["parser_success"]
    currentness_ok = official and flags["parser_success"] and not quarantined
    checks = {
        "source_identity_verified": bool(identity),
        "official_origin_verified": official,
        "source_bytes_sha256_verified": document_sha is not None,
        "source_version_sha256_verified": bool(version_sha),
        "stable_source_id_verified": bool(identity),
        "representation_group_valid": True,
        "canonical_representation_valid": True,
        "jurisdiction_verified": str(
            (catalogue or {}).get("jurisdiction") or original.get("jurisdiction") or ""
        )
        == "England and Wales",
        "england_and_wales_extent_verified": flags["england_and_wales_extent_verified"],
        "licence_or_model_use_verified": rights_ok,
        "ai_use_not_prohibited": str((catalogue or {}).get("ai_use_policy") or "unreviewed")
        != "prohibited",
        "parser_success": parser_ok,
        "document_not_quarantined": not quarantined,
        "document_not_duplicate_or_superseded": not bool(catalogue and catalogue.get("superseded")),
        "currentness_status_acceptable": currentness_ok,
        "commencement_status_acceptable": True,
        "unapplied_effects_reviewed_or_nonmaterial": flags[
            "unapplied_effects_reviewed_or_nonmaterial"
        ],
        "retrieval_stream_valid": locator_ok,
        "content_nonempty": flags["content_nonempty"],
        "legal_locator_structure_valid": locator_ok,
        "source_scan_id_acceptable": scan_ok,
    }
    evidence = {
        "official_primary": official,
        "official_source_url": url,
        "canonical_url": official_page_url(url) if url else None,
        "stable_source_id": identity or original.get("stable_source_id"),
        "source_version_id": source_version_id,
        "document_content_sha256": document_sha,
        "source_version_sha256": version_sha,
        "jurisdiction": (catalogue or {}).get("jurisdiction") or original.get("jurisdiction"),
        "licence_name": "Open Government Licence v3.0" if official else None,
        "parser_status": "ok" if parser_ok else "failed",
        "currentness_status": "latest_available_revised_snapshot" if currentness_ok else "unknown",
        "extent": flags.get("extent"),
        "unapplied_effect_requires_applied_count": flags["unapplied_effect_requires_applied_count"],
        "unapplied_effect_other_provision_count": flags["unapplied_effect_other_provision_count"],
        "quarantined": quarantined,
        "superseded": bool(catalogue and catalogue.get("superseded")),
        "scan_id": scan_id,
        "affected_row_ids": list(original.get("affected_row_ids") or ()),
        "checks": checks,
        "rights_ambiguous": not rights_ok,
        "currentness_ambiguous": not currentness_ok,
        "parser_ambiguity_affecting_legal_meaning": not parser_ok and official,
    }
    decision = evaluate_source_admission(evidence=evidence, actor_type="deterministic")
    title = str((catalogue or {}).get("title") or flags.get("title") or "").strip()
    source_approval = None
    if decision["decision"] == "APPROVE" and identity and title:
        source_approval = mechanical_legislation_source_approval(
            official_source_url=url,
            title=title,
            as_of_date=as_of_date,
            stable_identifier=identity,
        )
    elif decision["decision"] == "APPROVE" and not title:
        evidence["source_identity_conflict"] = False
        checks["source_identity_verified"] = False
        decision = evaluate_source_admission(evidence=evidence, actor_type="deterministic")
    payload = {
        "schema": SOURCE_HOLD_REVIEW_SCHEMA,
        "decision_id": original.get("decision_id"),
        "original_hold_reason": original.get("bind_reason_code"),
        "original_recommended_decision": original.get("recommended_decision"),
        "actual_current_source_version_id": source_version_id,
        "source_version_id_present": source_version_id is not None,
        "official_bytes_present": official_bytes is not None,
        "official_bytes_hash_valid": document_sha is not None,
        "catalogue_source_version_present": source_version_id is not None,
        "parser_valid": parser_ok,
        "rights_valid": rights_ok,
        "currentness_valid": currentness_ok,
        "extent_valid": flags["england_and_wales_extent_verified"],
        "unapplied_effects_resolved": flags["unapplied_effects_reviewed_or_nonmaterial"],
        "quarantine": quarantined,
        "superseded": bool(catalogue and catalogue.get("superseded")),
        "v2_auto_admission_eligible": decision.get("auto_admission_eligible") is True,
        "new_recommendation": decision["decision"],
        "reason_codes": decision.get("reason_codes") or [],
        "affected_row_ids": list(original.get("affected_row_ids") or ()),
        "official_source_url": url,
        "stable_source_id": identity,
        "admission_decision": decision,
        "source_approval": source_approval,
        "original_pack_preserved": True,
        "writes_active": False,
        "writes_o04": False,
    }
    payload["seal_sha256"] = sealed_sha256(
        {
            key: value
            for key, value in payload.items()
            if key not in {"admission_decision", "source_approval"}
        }
    )
    assert_safe_evaluation_payload(
        {
            key: value
            for key, value in payload.items()
            if key not in {"admission_decision", "source_approval", "affected_row_ids"}
        }
    )
    return payload


def source_to_affected_rows(reviews: Sequence[Mapping[str, Any]]) -> dict[str, list[str]]:
    mapping: dict[str, list[str]] = {}
    for item in reviews:
        key = str(
            item.get("actual_current_source_version_id")
            or item.get("official_source_url")
            or item.get("decision_id")
            or ""
        )
        mapping[key] = [str(row_id) for row_id in (item.get("affected_row_ids") or ())]
    return mapping


def build_v2_source_decision_pack(
    *,
    reviews: Sequence[Mapping[str, Any]],
    code_sha: str,
    scan_id: str,
    as_of_date: str,
    old_pack_sha256: str,
    include: str,
) -> dict[str, Any]:
    """Build a new V2 pack. ``include`` is auto, operator, or all."""

    selected: list[dict[str, Any]] = []
    for item in reviews:
        eligible = item.get("v2_auto_admission_eligible") is True
        mechanical_reject = item.get("new_recommendation") == "REJECT"
        if include == "auto" and not (eligible or mechanical_reject):
            continue
        if include == "operator" and (eligible or mechanical_reject):
            continue
        admission = item.get("admission_decision") or {}
        selected.append(
            {
                "decision_id": item.get("decision_id"),
                "source_version_id": item.get("actual_current_source_version_id"),
                "stable_source_id": item.get("stable_source_id"),
                "official_source_url": item.get("official_source_url"),
                "decision": item.get("new_recommendation"),
                "recommended_decision": item.get("new_recommendation"),
                "auto_admission_eligible": eligible,
                "reason_codes": list(item.get("reason_codes") or ()),
                "affected_row_ids": list(item.get("affected_row_ids") or ()),
                "original_hold_reason": item.get("original_hold_reason"),
                "admission_seal_sha256": (admission or {}).get("seal_sha256"),
            }
        )
    operator_required = include != "auto"
    payload: dict[str, Any] = {
        "schema": SOURCE_ADMISSION_PACK_SCHEMA,
        "policy_version": SOURCE_ADMISSION_POLICY_V2,
        "code_sha": code_sha,
        "scan_id": scan_id,
        "as_of_date": as_of_date,
        "supersedes_pack_sha256": old_pack_sha256,
        "does_not_mutate_old_pack": True,
        "old_pack_schema": SOURCE_VERSION_PACK_SCHEMA,
        "decision_count": len(selected),
        "decisions": selected,
        "operator_decision_required": operator_required,
        "applied": False,
        "writes_active": False,
        "writes_o04": False,
        "issue_gold_minted": False,
        "sources_indexed": False,
    }
    digest = hashlib.sha256(
        (
            json.dumps(
                {key: value for key, value in payload.items() if key != "decisions"},
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + json.dumps(selected, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")
    ).hexdigest()
    payload["pack_sha256"] = digest
    payload["seal_sha256"] = sealed_sha256(
        {key: value for key, value in payload.items() if key != "decisions"}
    )
    assert_safe_evaluation_payload(
        {key: value for key, value in payload.items() if key != "decisions"}
    )
    return payload


def assert_old_pack_immutable(old_pack: Mapping[str, Any], expected_sha256: str) -> None:
    digest = owner_pack_sha256(old_pack)
    if digest != expected_sha256 or str(old_pack.get("pack_sha256") or "") != expected_sha256:
        raise ValueError("old source-version decision pack is no longer immutable")


def load_catalogue_for_official_bytes(
    database: Any,
    *,
    content_sha256: str,
    scan_id: str,
) -> dict[str, Any] | None:
    document = database.fetchone(
        "SELECT id, status, jurisdiction, duplicate_of FROM documents WHERE content_sha256=?",
        (content_sha256,),
    )
    if document is None:
        return None
    source = database.fetchone(
        """
        SELECT sv.id, sv.version_sha256, sv.review_status, sv.stable_identifier,
               sv.title, sv.superseded_by, sv.metadata_json,
               json_extract(sv.metadata_json, '$.ai_use_policy') AS ai_use_policy,
               (SELECT COUNT(*) FROM chunks c WHERE c.source_version_id=sv.id AND c.stream='body')
                 AS chunk_count
        FROM source_versions sv
        WHERE sv.document_id=?
        ORDER BY sv.created_at DESC
        LIMIT 1
        """,
        (document["id"],),
    )
    scans = database.fetchall(
        "SELECT scan_id FROM source_scan_files WHERE document_id=? OR content_sha256=?",
        (document["id"], content_sha256),
    )
    return {
        "document_id": document["id"],
        "document_status": document["status"],
        "jurisdiction": document["jurisdiction"],
        "duplicate_of": document["duplicate_of"],
        "source_version_id": None if source is None else source["id"],
        "version_sha256": None if source is None else source["version_sha256"],
        "review_status": None if source is None else source["review_status"],
        "stable_identifier": None if source is None else source["stable_identifier"],
        "title": None if source is None else source["title"],
        "superseded": bool(source is not None and source["superseded_by"]),
        "ai_use_policy": None if source is None else source["ai_use_policy"],
        "chunk_count": 0 if source is None else int(source["chunk_count"] or 0),
        "scan_ids": tuple(str(row["scan_id"]) for row in scans),
        "on_requested_scan": any(str(row["scan_id"]) == scan_id for row in scans),
    }


def reconstruct_held_source_pack(
    *,
    old_pack: Mapping[str, Any],
    official_bytes_by_url: Mapping[str, bytes],
    catalogue_by_url: Mapping[str, Mapping[str, Any] | None],
    code_sha: str,
    scan_id: str,
    as_of_date: str,
    expected_old_sha256: str,
) -> dict[str, Any]:
    assert_old_pack_immutable(old_pack, expected_old_sha256)
    reviews = [
        review_one_held_source(
            item,
            catalogue=catalogue_by_url.get(str(item.get("official_source_url") or "")),
            official_bytes=official_bytes_by_url.get(str(item.get("official_source_url") or "")),
            scan_id=scan_id,
            as_of_date=as_of_date,
        )
        for item in old_pack.get("decisions") or ()
    ]
    auto_pack = build_v2_source_decision_pack(
        reviews=reviews,
        code_sha=code_sha,
        scan_id=scan_id,
        as_of_date=as_of_date,
        old_pack_sha256=expected_old_sha256,
        include="auto",
    )
    operator_pack = build_v2_source_decision_pack(
        reviews=reviews,
        code_sha=code_sha,
        scan_id=scan_id,
        as_of_date=as_of_date,
        old_pack_sha256=expected_old_sha256,
        include="operator",
    )
    payload = {
        "schema": "legalbot.source-hold-review-batch.v2",
        "old_pack_sha256": expected_old_sha256,
        "old_pack_hold_count": sum(
            1
            for item in old_pack.get("decisions") or ()
            if item.get("recommended_decision") == "HOLD"
        ),
        "review_count": len(reviews),
        "auto_approve_count": sum(
            1 for item in reviews if item.get("new_recommendation") == "APPROVE"
        ),
        "reject_count": sum(1 for item in reviews if item.get("new_recommendation") == "REJECT"),
        "remaining_hold_count": sum(
            1 for item in reviews if item.get("new_recommendation") == "HOLD"
        ),
        "source_to_rows": source_to_affected_rows(reviews),
        "auto_pack": auto_pack,
        "operator_pack": operator_pack,
        "reviews": reviews,
        "writes_active": False,
    }
    payload["seal_sha256"] = sealed_sha256(
        {
            key: value
            for key, value in payload.items()
            if key not in {"auto_pack", "operator_pack", "reviews", "source_to_rows"}
        }
    )
    return payload


def apply_reconstructed_auto_pack(
    batch: Mapping[str, Any],
    *,
    database: Any,
) -> dict[str, Any]:
    approvals = {
        str(item.get("actual_current_source_version_id") or ""): item["source_approval"]
        for item in batch.get("reviews") or ()
        if item.get("v2_auto_admission_eligible") is True and item.get("source_approval")
    }
    return apply_auto_source_admission_pack(
        batch["auto_pack"],
        database=database,
        source_approvals=approvals,
    )


def locate_official_bytes(url: str, search_dirs: Sequence[Path]) -> bytes | None:
    from .live_suite_official_bind import cached_official_bytes

    return cached_official_bytes(url, search_dirs)


def run_held_source_v2_review(
    *,
    database: Any,
    old_pack: Mapping[str, Any],
    search_dirs: Sequence[Path],
    code_sha: str,
    scan_id: str,
    as_of_date: str,
    apply_auto: bool,
) -> dict[str, Any]:
    """Reconstruct the 56 HOLDs against catalogue + official bytes."""

    expected = str(old_pack.get("pack_sha256") or "")
    official_bytes: dict[str, bytes] = {}
    catalogue: dict[str, Mapping[str, Any] | None] = {}
    for item in old_pack.get("decisions") or ():
        url = str(item.get("official_source_url") or "")
        raw = locate_official_bytes(url, search_dirs)
        if raw is not None:
            official_bytes[url] = raw
            catalogue[url] = load_catalogue_for_official_bytes(
                database,
                content_sha256=_sha256_bytes(raw),
                scan_id=scan_id,
            )
        else:
            catalogue[url] = None
    batch = reconstruct_held_source_pack(
        old_pack=old_pack,
        official_bytes_by_url=official_bytes,
        catalogue_by_url=catalogue,
        code_sha=code_sha,
        scan_id=scan_id,
        as_of_date=as_of_date,
        expected_old_sha256=expected,
    )
    applied = None
    if apply_auto:
        applied = apply_reconstructed_auto_pack(batch, database=database)
    return {
        "old_pack_sha256": expected,
        "old_pack_hold_count": batch["old_pack_hold_count"],
        "review_count": batch["review_count"],
        "auto_approve_count": batch["auto_approve_count"],
        "reject_count": batch["reject_count"],
        "remaining_hold_count": batch["remaining_hold_count"],
        "auto_pack_sha256": batch["auto_pack"]["pack_sha256"],
        "operator_pack_sha256": batch["operator_pack"]["pack_sha256"],
        "applied": bool(applied and applied.get("applied")),
        "issue_gold_minted": False,
        "writes_active": False,
        "batch": batch,
        "applied_receipt": applied,
    }
