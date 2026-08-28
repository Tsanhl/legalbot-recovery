"""Approved-source manifests for authority-lane candidate builds."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import date
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]  # PyYAML does not ship inline typing.

from ..config import Settings
from ..currentness import case_present_law_currentness_qualifies
from ..db import Database, utc_iso
from ..jobs import (
    CANONICAL_MARKDOWN_VERSION,
    CHUNKER_VERSION,
    INDEX_SCHEMA_VERSION,
    PARSER_VERSION,
)
from .phase2a_dynamic_scope import (
    is_dynamic_phase2a_scope_corpus,
    load_dynamic_phase2a_scope,
    select_dynamic_phase2a_scope_rows,
    source_manifest_member_set_sha256,
    source_manifest_member_sha256,
)
from .phase2a_frozen_scope import (
    is_phase2a_frozen_scope_corpus,
    load_phase2a_frozen_scope,
    select_phase2a_frozen_scope_rows,
)

MANIFEST_SCHEMA = "legalbot.approved-source-manifest.v1"
SCOPED_CORPUS_ID = "ogl-uksc-authority-2026-08-13"
SESSION_SCOPED_CORPUS_ID = "ogl-uksc-authority-session-cap-2026-08-13"
CURRENT_LAW_SLICE_CORPUS_ID = "current-law-ew-core-slice-v1"
CURRENT_LAW_SLICE_BUILD_ID = "current-law-ew-core-slice-v1"
AUTHORITY_LANE = "primary_authority"
OGL_LICENCE_PREFIX = "Open Government Licence"
OFFICIAL_JUDGMENT_LICENCE_PREFIXES = (
    "Open Government Licence",
    "Open Parliament Licence",
)
FAMILY_LEGISLATION = "legislation"
# Compatibility value retained for existing manifests/policies.  This family
# covers all rights-reviewed official judgments, including UKHL decisions.
FAMILY_UKSC = "uksc"
FAMILY_OFFICIAL_JUDGMENT = FAMILY_UKSC
CURRENT_SNAPSHOT_MARKER = ":latest-available@"
CURRENT_SNAPSHOT_DATE_RE = re.compile(r"20\d{2}-\d{2}-\d{2}")
CURRENTNESS_LABEL = "latest_available_revised_snapshot"
SLICE_POLICY_RELATIVE = Path("config/current_law_slice_policy.yaml")

# Compatibility exports only.  They are intentionally empty: source selection
# must never be driven by benchmark answer identifiers or locator allowlists.
SLICE_CURRENT_IDENTIFIERS: tuple[str, ...] = ()
SLICE_UKSC_IDENTIFIERS: tuple[str, ...] = ()
SLICE_HISTORICAL_IDENTIFIERS: tuple[str, ...] = ()
SLICE_LOCATOR_ALLOWLISTS: dict[str, tuple[str, ...]] = {}
HOLDOUT_ONLY_IDENTIFIERS: frozenset[str] = frozenset()


def load_current_law_slice_policy(settings: Settings) -> dict[str, Any]:
    path = settings.project_root / SLICE_POLICY_RELATIVE
    if not path.is_file():
        raise ValueError("current-law slice policy is missing")
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != "legalbot.current-law-slice-policy.v1"
    ):
        raise ValueError("current-law slice policy is invalid")
    if payload.get("benchmark_case_ids_used_for_selection") is not False:
        raise ValueError("current-law slice must be independent of benchmark answers")
    if payload.get("locator_allowlists") is not False:
        raise ValueError("current-law slice must not use benchmark-shaped locator allowlists")
    return payload


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def approved_source_manifest_sha256(manifest: Mapping[str, Any]) -> str:
    """Digest the immutable manifest identity, excluding time/self fields."""

    identity = {
        key: value
        for key, value in manifest.items()
        if key not in {"created_at", "manifest_sha256"}
    }
    return _sha256_bytes(_canonical_bytes(dict(identity)))


def is_current_law_full_corpus(corpus_id: str | None) -> bool:
    from .diagnostic_slice import is_current_law_full_corpus as _is_full

    return _is_full(corpus_id)


def is_current_law_slice_corpus(corpus_id: str | None) -> bool:
    ident = str(corpus_id or "")
    if is_current_law_full_corpus(ident):
        return False
    return (
        ident == CURRENT_LAW_SLICE_CORPUS_ID
        or ident.startswith("scoped-current-law-")
        or ident.startswith("current-law-ew-")
    )


def chunk_locator_allowed(
    stable_identifier: str,
    locator: str,
    allowlists: Mapping[str, Sequence[str]] | None = None,
) -> bool:
    lists = allowlists if allowlists is not None else SLICE_LOCATOR_ALLOWLISTS
    allowed = lists.get(stable_identifier)
    if not allowed:
        return True
    loc = str(locator or "").strip()
    return any(loc == item or loc.startswith(f"{item}(") for item in allowed)


def _validated_snapshot_date(value: Any) -> str:
    snapshot_date = str(value or "")
    if not CURRENT_SNAPSHOT_DATE_RE.fullmatch(snapshot_date):
        raise ValueError("current legislation pack as_of_date must be an ISO date")
    try:
        date.fromisoformat(snapshot_date)
    except ValueError as exc:
        raise ValueError("current legislation pack as_of_date is not a valid date") from exc
    return snapshot_date


def _current_snapshot_suffix(as_of_date: Any) -> str:
    return f"{CURRENT_SNAPSHOT_MARKER}{_validated_snapshot_date(as_of_date)}"


def _current_snapshot_stem(stable_identifier: str) -> str | None:
    value = str(stable_identifier or "")
    stem, marker, snapshot_date = value.rpartition(CURRENT_SNAPSHOT_MARKER)
    if not marker or not stem:
        return None
    try:
        _validated_snapshot_date(snapshot_date)
    except ValueError:
        return None
    return stem


def load_pack_identities(settings: Settings, *, corpus_id: str | None = None) -> dict[str, Any]:
    legislation = json.loads(
        (settings.project_root / "config" / "official_legislation_pack.json").read_text(
            encoding="utf-8"
        )
    )
    current_path = settings.project_root / "config" / "current_legislation_pack.json"
    if current_path.is_file():
        current = json.loads(current_path.read_text(encoding="utf-8"))
        if current.get("schema") != "legalbot.current-legislation-pack.v1":
            raise ValueError("config/current_legislation_pack.json has an invalid schema")
        current_snapshot_suffix = _current_snapshot_suffix(current.get("as_of_date"))
        legislation_ids = [
            f"{item['identity'].replace('/', ':')}{current_snapshot_suffix}"
            for item in current["items"]
        ]
    elif settings.test_mode:
        # Unit fixtures predate the current-snapshot pack.  This branch is
        # deliberately test-only and is disclosed in the manifest.
        current = {"version": "test-fixture-fallback", "items": legislation["items"]}
        legislation_ids = [
            f"{item['identity'].replace('/', ':')}:enacted" for item in legislation["items"]
        ]
    else:
        raise ValueError("config/current_legislation_pack.json is required for serving builds")
    uksc_path = settings.project_root / "config" / "uksc_authority_pack.json"
    uksc_bytes = uksc_path.read_bytes()
    uksc = json.loads(uksc_bytes)
    quistclose_path = settings.project_root / "config" / "quistclose_authority_pack.json"
    if quistclose_path.is_file():
        quistclose_bytes = quistclose_path.read_bytes()
        quistclose = json.loads(quistclose_bytes)
        if quistclose.get("schema") != "legalbot.quistclose-authority-pack.v1":
            raise ValueError("config/quistclose_authority_pack.json has an invalid schema")
        if not isinstance(quistclose.get("items"), list) or len(quistclose["items"]) != 3:
            raise ValueError("reviewed Quistclose authority pack must contain exactly three cases")
        licence_ids = set((quistclose.get("licences") or {}).keys())
        if licence_ids != {"uk_parliament_opl_v3", "uksc_ogl_v3"}:
            raise ValueError("reviewed Quistclose pack licence identities are invalid")
        for item in quistclose["items"]:
            if item.get("licence_id") not in licence_ids:
                raise ValueError("Quistclose case is not bound to a reviewed reuse licence")
    else:
        # Older unit fixtures have no optional extension pack. Production has
        # the reviewed file and seals it below; no implicit source is invented.
        quistclose_bytes = b""
        quistclose = {"version": None, "items": []}
    uksc_neutral_citations = [
        f"neutral-citation:{item['neutral_citation']}" for item in uksc["items"]
    ]
    quistclose_neutral_citations = [
        f"neutral-citation:{item['neutral_citation']}" for item in quistclose["items"]
    ]
    official_judgment_neutral_citations = list(
        dict.fromkeys(uksc_neutral_citations + quistclose_neutral_citations)
    )
    payload: dict[str, Any] = {
        "legislation_pack_version": legislation.get("version"),
        "uksc_pack_version": uksc.get("version"),
        "uksc_pack_sha256": _sha256_bytes(uksc_bytes),
        "quistclose_pack_version": quistclose.get("version"),
        "quistclose_pack_sha256": (_sha256_bytes(quistclose_bytes) if quistclose_bytes else None),
        # Serving/current-law manifests select revised snapshots.  The enacted
        # pack remains catalogued only for historical research.
        "legislation_stable_ids": legislation_ids,
        "uksc_neutral_citations": uksc_neutral_citations,
        "quistclose_neutral_citations": quistclose_neutral_citations,
        "official_judgment_neutral_citations": official_judgment_neutral_citations,
        "legislation_titles": [item["title"] for item in current["items"]],
        "uksc_case_names": [item["case_name"] for item in uksc["items"]],
        "quistclose_case_names": [item["case_name"] for item in quistclose["items"]],
        "official_judgment_pack_versions": {
            "uksc_ogl": uksc.get("version"),
            "quistclose_opl_ogl": quistclose.get("version"),
        },
        "official_judgment_pack_sha256s": {
            "uksc_ogl": _sha256_bytes(uksc_bytes),
            "quistclose_opl_ogl": (_sha256_bytes(quistclose_bytes) if quistclose_bytes else None),
        },
        "historical_legislation_pack_version": legislation.get("version"),
        "current_legislation_pack_version": current.get("version"),
        "current_law_as_of_date": current.get("as_of_date"),
        "current_legislation_stable_ids": legislation_ids,
        "test_fixture_pack_fallback": not current_path.is_file(),
    }
    return payload


def source_family(stable_identifier: str) -> str | None:
    ident = str(stable_identifier or "")
    if ident.startswith("neutral-citation:") or ident.startswith("uksc:"):
        return FAMILY_OFFICIAL_JUDGMENT
    if ident.startswith("ukpga:") or ident.startswith("uksi:"):
        return FAMILY_LEGISLATION
    return None


def authority_identity_id(stable_identifier: str) -> str:
    """Unify immutable enacted/revised representations under one authority."""

    value = str(stable_identifier or "")
    current_stem = _current_snapshot_stem(value)
    if current_stem is not None:
        return current_stem
    if value.endswith(":enacted"):
        value = value.removesuffix(":enacted")
    return value


def required_source_families(
    packs: dict[str, Any], *, corpus_id: str | None = None
) -> tuple[str, ...]:
    if is_current_law_slice_corpus(corpus_id):
        return (FAMILY_LEGISLATION, FAMILY_OFFICIAL_JUDGMENT)
    required: list[str] = []
    if packs.get("legislation_stable_ids"):
        required.append(FAMILY_LEGISLATION)
    if packs.get("official_judgment_neutral_citations"):
        required.append(FAMILY_OFFICIAL_JUDGMENT)
    return tuple(required)


def selected_source_families(sources: list[dict[str, Any]]) -> set[str]:
    families: set[str] = set()
    for item in sources:
        family = source_family(str(item.get("stable_identifier") or ""))
        if family:
            families.add(family)
    return families


def _wanted_identifiers(packs: dict[str, Any], *, corpus_id: str | None) -> set[str]:
    return set(packs["legislation_stable_ids"]) | set(
        packs.get("official_judgment_neutral_citations")
        or packs.get("uksc_neutral_citations")
        or ()
    )


def _mapping_value(row: Mapping[str, Any], key: str, default: Any = None) -> Any:
    """Read mapping-like SQLite rows without assuming ``dict.get`` exists."""

    try:
        return row[key]
    except (KeyError, IndexError):
        return default


def _source_selection_key(row: Mapping[str, Any]) -> str:
    """Select reviewed split judgments once per immutable representation."""

    stable_identifier = str(_mapping_value(row, "stable_identifier") or "")
    try:
        metadata = json.loads(_mapping_value(row, "metadata_json") or "{}")
    except (TypeError, json.JSONDecodeError):
        return stable_identifier
    if not isinstance(metadata, dict):
        return stable_identifier
    materialization = metadata.get("reviewed_evidence_materialization")
    snapshot = metadata.get("official_snapshot")
    if not isinstance(materialization, dict) or not isinstance(snapshot, dict):
        return stable_identifier
    representation_id = str(snapshot.get("representation_id") or "")
    if not representation_id:
        return stable_identifier
    return f"{stable_identifier}#official-representation:{representation_id}"


def _filtered_body_chunk_count(
    database: Database, source_version_id: str, stable_identifier: str
) -> int:
    del stable_identifier
    row = database.fetchone(
        "SELECT COUNT(*) AS n FROM chunks WHERE source_version_id=? AND stream='body'",
        (source_version_id,),
    )
    return int(row["n"] if row else 0)


def select_approved_authority_rows(
    database: Database,
    settings: Settings,
    *,
    corpus_id: str | None = None,
    max_chunks: int | None = None,
    preferred_small_first: bool = False,
) -> list[dict[str, Any]]:
    if is_phase2a_frozen_scope_corpus(corpus_id):
        rows, _scope = select_phase2a_frozen_scope_rows(
            database,
            settings,
            corpus_id=str(corpus_id),
            max_chunks=max_chunks,
            preferred_small_first=preferred_small_first,
        )
        return rows
    if is_dynamic_phase2a_scope_corpus(corpus_id):
        rows, _scope = select_dynamic_phase2a_scope_rows(
            database,
            settings,
            corpus_id=str(corpus_id),
            max_chunks=max_chunks,
            preferred_small_first=preferred_small_first,
        )
        return rows
    packs = load_pack_identities(settings, corpus_id=corpus_id)
    wanted = _wanted_identifiers(packs, corpus_id=corpus_id)
    slice_mode = is_current_law_slice_corpus(corpus_id)
    slice_policy = load_current_law_slice_policy(settings) if slice_mode else None
    slice_subjects = set(slice_policy.get("subjects", [])) if slice_policy else set()
    max_source_chunks = int(slice_policy.get("max_source_body_chunks") or 0) if slice_policy else 0
    rows = database.fetchall(
        """
        SELECT
          sv.id AS source_version_id,
          sv.stable_identifier,
          sv.title,
          sv.canonical_markdown_path,
          sv.version_sha256,
          sv.licence_name,
          sv.review_status,
          sv.canonical_url,
          sv.source_date,
          sv.as_of_date,
          sv.created_at AS last_updated,
          sv.currentness_status,
          sv.metadata_json,
          d.id AS document_id,
          d.lane,
          d.status AS document_status,
          d.subject_primary,
          d.jurisdiction,
          d.content_sha256,
          (
            SELECT COUNT(*) FROM chunks c
            WHERE c.source_version_id=sv.id AND c.stream='body'
          ) AS body_chunk_count
        FROM source_versions sv
        JOIN documents d ON d.id=sv.document_id
        WHERE sv.review_status='approved'
          AND sv.superseded_by IS NULL
          AND d.duplicate_of IS NULL
          AND d.lane=?
          AND d.status='citable'
          AND d.status<>'quarantined'
          AND d.retrieval_canonical=1
          AND json_extract(sv.metadata_json, '$.eligible_for_model_use')=1
          AND COALESCE(json_extract(sv.metadata_json, '$.ai_use_policy'), '')<>'prohibited'
        ORDER BY sv.stable_identifier ASC,
          COALESCE(sv.as_of_date, sv.source_date, substr(sv.created_at,1,10), '') DESC,
          sv.created_at DESC,
          sv.id DESC
        """,
        (AUTHORITY_LANE,),
    )
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    total_chunks = 0
    # The SQL ordering places the newest approved version first for each exact
    # source representation.  Collapse older duplicates before any optional
    # small-source ordering so an old short document can never outrank a newer
    # reviewed version merely because it has fewer chunks.
    newest_rows: list[Any] = []
    seen_versions: set[str] = set()
    for row in rows:
        selection_key = _source_selection_key(dict(row))
        if selection_key in seen_versions:
            continue
        seen_versions.add(selection_key)
        newest_rows.append(row)
    ordered = newest_rows
    if preferred_small_first:
        ordered.sort(
            key=lambda row: (int(row["body_chunk_count"] or 0), str(row["stable_identifier"]))
        )
    for row in ordered:
        ident = str(row["stable_identifier"] or "")
        selection_key = _source_selection_key(dict(row))
        if selection_key in seen or ident not in wanted:
            continue
        if slice_mode and str(row["subject_primary"] or "") not in slice_subjects:
            continue
        licence = str(row["licence_name"] or "")
        if (ident.startswith("ukpga:") or ident.startswith("uksi:")) and not licence.startswith(
            OGL_LICENCE_PREFIX
        ):
            continue
        if ident.startswith("neutral-citation:") and not licence.startswith(
            OFFICIAL_JUDGMENT_LICENCE_PREFIXES
        ):
            continue
        chunks = int(row["body_chunk_count"] or 0)
        if slice_mode and max_source_chunks and chunks > max_source_chunks:
            continue
        if chunks < 1:
            continue
        if max_chunks is not None and total_chunks + chunks > max_chunks and selected:
            continue
        item = dict(row)
        item["body_chunk_count"] = chunks
        item["unfiltered_body_chunk_count"] = int(row["body_chunk_count"] or 0)
        selected.append(item)
        seen.add(selection_key)
        total_chunks += chunks
        if max_chunks is not None and total_chunks >= max_chunks:
            break
    return selected


def build_approved_source_manifest(
    database: Database,
    settings: Settings,
    *,
    corpus_id: str,
    max_chunks: int | None = None,
    preferred_small_first: bool = False,
) -> dict[str, Any]:
    from .provision_verification import load_provision_verifications

    frozen_scope = None
    dynamic_phase2a_scope = None
    if is_phase2a_frozen_scope_corpus(corpus_id):
        frozen_scope = load_phase2a_frozen_scope(settings)
    elif is_dynamic_phase2a_scope_corpus(corpus_id):
        dynamic_phase2a_scope = load_dynamic_phase2a_scope(settings, corpus_id)
    packs = load_pack_identities(settings, corpus_id=corpus_id)
    provision_verifications, provision_verification_sha256 = load_provision_verifications(
        settings.project_root, allow_test_empty=settings.test_mode
    )
    slice_mode = is_current_law_slice_corpus(corpus_id)
    rows = select_approved_authority_rows(
        database,
        settings,
        corpus_id=corpus_id,
        max_chunks=max_chunks,
        preferred_small_first=preferred_small_first,
    )
    sources = []
    chunk_total = 0
    for row in rows:
        chunk_total += int(row["body_chunk_count"])
        try:
            metadata = json.loads(row["metadata_json"] or "{}")
        except (TypeError, json.JSONDecodeError):
            metadata = {}
        stable_identifier = str(row["stable_identifier"] or "")
        family = source_family(stable_identifier)
        official_snapshot = metadata.get("official_snapshot")
        if not isinstance(official_snapshot, dict):
            official_snapshot = {}
        unapplied = official_snapshot.get("unapplied_effect_count")
        extent_status = str(metadata.get("provision_extent_status") or "unverified")
        currentness_status = (
            CURRENTNESS_LABEL
            if family == FAMILY_LEGISLATION
            and _current_snapshot_stem(stable_identifier) is not None
            else str(row["currentness_status"] or "unknown")
        )
        identity_verified = metadata.get("identity_verified") is True
        currentness_verified = metadata.get("currentness_verified") is True
        currentness_reviewed_as_of_date = (
            row["as_of_date"]
            if family == FAMILY_LEGISLATION
            else metadata.get("currentness_reviewed_as_of_date")
        )
        subsequent_treatment_required = metadata.get("subsequent_treatment_check_required") is True
        subsequent_treatment_verified = metadata.get("subsequent_treatment_verified") is True
        citation_data = metadata.get("citation_data")
        if not isinstance(citation_data, dict):
            citation_data = {}
        case_currentness_eligible = case_present_law_currentness_qualifies(
            citation_data=citation_data,
            currentness_status=currentness_status,
            source_metadata=metadata,
        )
        source = {
            "source_version_id": row["source_version_id"],
            "document_id": row["document_id"],
            "document_status": row["document_status"],
            "stable_identifier": stable_identifier,
            "authority_identity_id": authority_identity_id(stable_identifier),
            "title": row["title"],
            "lane": row["lane"],
            "jurisdiction": row["jurisdiction"],
            "licence_name": row["licence_name"],
            "canonical_url": row["canonical_url"],
            "content_sha256": row["content_sha256"],
            "version_sha256": row["version_sha256"],
            "canonical_markdown_path": row["canonical_markdown_path"],
            "body_chunk_count": int(row["body_chunk_count"]),
            "currentness_status": currentness_status,
            "source_date": row["source_date"],
            "as_of_date": row["as_of_date"],
            "last_updated": row["last_updated"],
            "currentness_reviewed_as_of_date": currentness_reviewed_as_of_date,
            "catalogue_currentness_status": row["currentness_status"],
            "identity_verified": identity_verified,
            "currentness_verified": currentness_verified,
            "subsequent_treatment_check_required": subsequent_treatment_required,
            "subsequent_treatment_verified": subsequent_treatment_verified,
            "unapplied_effect_count": unapplied,
            "provision_extent_status": extent_status,
            "full_current_law_verification_eligible": bool(
                (
                    identity_verified
                    and currentness_verified
                    and case_currentness_eligible
                    and family != FAMILY_LEGISLATION
                )
                or (
                    identity_verified
                    and currentness_verified
                    and family == FAMILY_LEGISLATION
                    and unapplied == 0
                    and extent_status
                    in {"england_and_wales_verified", "uk_with_england_wales_verified"}
                )
            ),
        }
        representation_id = str(official_snapshot.get("representation_id") or "")
        if representation_id:
            source["official_representation_id"] = representation_id
        if "unfiltered_body_chunk_count" in row:
            source["unfiltered_body_chunk_count"] = int(row["unfiltered_body_chunk_count"])
        if dynamic_phase2a_scope is not None:
            source["phase2a_scope_record_content_sha256"] = row[
                "phase2a_scope_record_content_sha256"
            ]
            source["phase2a_member_schema"] = "legalbot.v111.phase2a.source-manifest-member.v1"
            source["phase2a_member_content_sha256"] = source_manifest_member_sha256(source)
        sources.append(source)
    required = required_source_families(packs, corpus_id=corpus_id)
    selected_families = sorted(selected_source_families(sources))
    omitted = [family for family in required if family not in set(selected_families)]
    slice_policy = load_current_law_slice_policy(settings) if slice_mode else None
    from ..ingestion.scan_attestation import (
        latest_complete_reconciled_scan,
        selected_sources_exclude_quarantine,
    )
    from .diagnostic_slice import is_current_law_full_corpus

    selected_sources_exclude_quarantine(rows)
    selected_sources_exclude_quarantine(sources)
    reconciled = latest_complete_reconciled_scan(database)
    if is_current_law_full_corpus(corpus_id) and reconciled is None:
        raise ValueError("full candidate cannot reference an incomplete scan")
    latest_scan = None
    if reconciled is not None:
        latest_scan = database.fetchone(
            """SELECT id,manifest_sha256,expected_file_count,files_accounted
               FROM source_scans WHERE id=?""",
            (reconciled["scan_id"],),
        )
    payload = {
        "schema": MANIFEST_SCHEMA,
        "corpus_id": corpus_id,
        "created_at": utc_iso(),
        "authority_lane_only": True,
        "exclude_find_case_law_full_text": True,
        "exclude_teaching_as_authority": True,
        "exclude_assessment_as_authority": True,
        "historical_default_excluded": True,
        "selection_policy": (
            "exact-owner-approved-dynamic-phase2a-successor-scope"
            if dynamic_phase2a_scope is not None
            else (
                "exact-owner-approved-held-phase2a-successor-scope"
                if frozen_scope is not None
                else (
                    "subject-policy-current-law-slice"
                    if slice_mode
                    else "current-legislation-and-rights-reviewed-official-judgments"
                )
            )
        ),
        "benchmark_answers_used_for_selection": False,
        "parser_version": PARSER_VERSION,
        "chunker_version": CHUNKER_VERSION,
        "canonical_markdown_version": CANONICAL_MARKDOWN_VERSION,
        "index_schema_version": INDEX_SCHEMA_VERSION,
        "provision_verification_schema": "legalbot.provision-verification.v1",
        "provision_verification_sha256": provision_verification_sha256,
        "verified_provision_count": len(provision_verifications),
        "legislation_pack_version": packs["legislation_pack_version"],
        "uksc_pack_version": packs["uksc_pack_version"],
        "uksc_pack_sha256": packs["uksc_pack_sha256"],
        "quistclose_pack_version": packs.get("quistclose_pack_version"),
        "quistclose_pack_sha256": packs.get("quistclose_pack_sha256"),
        "official_judgment_pack_versions": packs.get("official_judgment_pack_versions", {}),
        "official_judgment_pack_sha256s": packs.get("official_judgment_pack_sha256s", {}),
        "current_legislation_pack_version": packs.get("current_legislation_pack_version"),
        "current_law_as_of_date": packs.get("current_law_as_of_date"),
        "source_count": len(sources),
        "chunk_count": chunk_total,
        "max_chunks_cap": max_chunks,
        "locator_allowlists": {},
        "slice_policy": slice_policy,
        "source_scan_id": str(latest_scan["id"]) if latest_scan else None,
        "source_scan_manifest_sha256": (
            str(latest_scan["manifest_sha256"]) if latest_scan else None
        ),
        "source_scan_reconciled": bool(
            latest_scan
            and int(latest_scan["expected_file_count"]) == int(latest_scan["files_accounted"])
        ),
        "required_source_families": list(required),
        "selected_source_families": selected_families,
        "omitted_required_families": omitted,
        "sources": sources,
    }
    if frozen_scope is not None:
        if (
            payload["source_count"] != frozen_scope["source_count"]
            or payload["chunk_count"] != frozen_scope["chunk_count"]
            or payload["source_scan_id"] != frozen_scope["source_scan_id"]
            or payload["source_scan_manifest_sha256"] != frozen_scope["source_scan_manifest_sha256"]
            or payload["omitted_required_families"]
        ):
            raise ValueError("Phase-2A successor manifest departed from its frozen scope")
        payload.update(
            {
                "frozen_scope_schema": frozen_scope["schema"],
                "frozen_scope_content_sha256": frozen_scope["scope_content_sha256"],
                "frozen_scope_package_content_sha256": (
                    "923270611744c0da1927c639b64b042612fb34628e8b115f65c9562cc91f86bf"
                ),
                "predecessor_build_id": frozen_scope["predecessor_build_id"],
                "predecessor_source_manifest_sha256": frozen_scope[
                    "predecessor_source_manifest_sha256"
                ],
                "owner_admitted_source_count": frozen_scope["owner_admitted_source_count"],
                "answer_release_eligible": False,
                "successor_must_remain_non_active": True,
                "common_legal_currentness_cutoff": None,
                "active_or_previous_write_authorized": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            }
        )
    elif dynamic_phase2a_scope is not None:
        if (
            payload["source_count"] != dynamic_phase2a_scope["source_count"]
            or payload["chunk_count"] != dynamic_phase2a_scope["chunk_count"]
            or payload["source_scan_id"] != dynamic_phase2a_scope["source_scan_id"]
            or payload["source_scan_manifest_sha256"]
            != dynamic_phase2a_scope["source_scan_manifest_sha256"]
            or payload["omitted_required_families"]
        ):
            raise ValueError("dynamic Phase-2A manifest departed from its frozen scope")
        payload.update(
            {
                "frozen_scope_schema": dynamic_phase2a_scope["schema"],
                "frozen_scope_content_sha256": dynamic_phase2a_scope["scope_content_sha256"],
                "phase2a_owner_packet_content_sha256": dynamic_phase2a_scope[
                    "phase2a_owner_packet_content_sha256"
                ],
                "phase2a_owner_approval_receipt_content_sha256": (
                    dynamic_phase2a_scope["phase2a_owner_approval_receipt_content_sha256"]
                ),
                "phase2a_owner_application_ledger_content_sha256": (
                    dynamic_phase2a_scope["phase2a_owner_application_ledger_content_sha256"]
                ),
                "phase2a_execution_authority_content_sha256": dynamic_phase2a_scope[
                    "phase2a_execution_authority_content_sha256"
                ],
                "materialization_ledger_content_sha256": dynamic_phase2a_scope[
                    "materialization_ledger_content_sha256"
                ],
                "execution_chain_run_id": dynamic_phase2a_scope["execution_chain_run_id"],
                "source_root_inventory_content_sha256": dynamic_phase2a_scope[
                    "source_root_inventory_content_sha256"
                ],
                "source_version_id_set_sha256": dynamic_phase2a_scope[
                    "source_version_id_set_sha256"
                ],
                "source_manifest_member_set_sha256": source_manifest_member_set_sha256(sources),
                "predecessor_build_id": dynamic_phase2a_scope["predecessor_build_id"],
                "answer_release_eligible": False,
                "successor_must_remain_non_active": True,
                "common_legal_currentness_cutoff": None,
                "active_or_previous_write_authorized": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
                "validation30_authorized": False,
                "promotion_authorized": False,
            }
        )
    payload["manifest_sha256"] = approved_source_manifest_sha256(payload)
    return payload


def write_approved_source_manifest(path: Path, manifest: dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    material = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    digest = approved_source_manifest_sha256(material)
    material["manifest_sha256"] = digest
    path.write_bytes(_canonical_bytes(material))
    return digest


def source_version_ids(manifest: dict[str, Any]) -> tuple[str, ...]:
    return tuple(str(item["source_version_id"]) for item in manifest.get("sources", []))
