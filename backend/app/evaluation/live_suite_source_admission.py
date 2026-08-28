"""Actor-neutral V2 official-source admission.

Proof determines acceptance. Actor type (deterministic, AI, human, hybrid)
does not. AI confidence is never approval. Source admission does not qualify
an issue, write ACTIVE, or mint issue gold.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Literal

from .live30 import assert_safe_evaluation_payload
from .live_suite import sealed_sha256

SOURCE_ADMISSION_POLICY_V2 = "legalbot.source-admission-policy.v2"
SOURCE_ADMISSION_DECISION_SCHEMA = "legalbot.source-admission-decision.v2"
SOURCE_ADMISSION_PACK_SCHEMA = "legalbot.source-admission-decision-pack.v2"
OFFICIAL_PRIMARY_HOSTS = frozenset(
    {
        "www.legislation.gov.uk",
        "legislation.gov.uk",
        "caselaw.nationalarchives.gov.uk",
    }
)
OGL_LICENCE_NAME = "Open Government Licence v3.0"
OGL_LICENCE_URL = "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/"
ACCEPTABLE_CURRENTNESS = frozenset(
    {
        "current",
        "historical",
        "point_in_time",
        "latest_available_revised_snapshot",
    }
)
AUTO_ADMISSION_REQUIRED_TRUE = (
    "source_identity_verified",
    "official_origin_verified",
    "source_bytes_sha256_verified",
    "source_version_sha256_verified",
    "stable_source_id_verified",
    "jurisdiction_verified",
    "england_and_wales_extent_verified",
    "licence_or_model_use_verified",
    "ai_use_not_prohibited",
    "parser_success",
    "document_not_quarantined",
    "document_not_duplicate_or_superseded",
    "currentness_status_acceptable",
    "unapplied_effects_reviewed_or_nonmaterial",
    "content_nonempty",
    "legal_locator_structure_valid",
    "source_scan_id_acceptable",
)
Decision = Literal["APPROVE", "REJECT", "HOLD"]
ActorType = Literal["deterministic", "ai", "human", "hybrid"]


def official_primary_host(url: str | None) -> bool:
    host = ""
    text = str(url or "")
    if "://" in text:
        host = text.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0].lower()
    return host in OFFICIAL_PRIMARY_HOSTS


def _check_true(checks: Mapping[str, Any], name: str) -> bool:
    return checks.get(name) is True


def evaluate_source_admission(
    *,
    evidence: Mapping[str, Any],
    actor_type: ActorType = "deterministic",
    ai_confidence: float | None = None,
) -> dict[str, Any]:
    """Decide APPROVE / REJECT / HOLD from objective checks only."""

    checks = dict(evidence.get("checks") or {})
    source_version_id = str(evidence.get("source_version_id") or "").strip() or None
    official_url = str(evidence.get("official_source_url") or evidence.get("canonical_url") or "")
    reasons: list[str] = []
    ambiguity: list[str] = []
    official = (
        evidence.get("official_primary") is True
        or official_primary_host(official_url)
        or _check_true(checks, "official_origin_verified")
    )

    if checks.get("document_not_quarantined") is False or evidence.get("quarantined") is True:
        reasons.append("quarantined_source")
        return seal_source_admission_decision(
            {
                "decision": "REJECT",
                "actor_type": actor_type,
                "auto_admission_eligible": False,
                "operator_decision_required": False,
                "source_version_id": source_version_id,
                "reason_codes": reasons,
                "checks": checks,
                "evidence": _safe_evidence(evidence),
            }
        )
    if checks.get("parser_success") is False or evidence.get("parser_success") is False:
        reasons.append("parser_failure")
        return seal_source_admission_decision(
            {
                "decision": "REJECT",
                "actor_type": actor_type,
                "auto_admission_eligible": False,
                "operator_decision_required": False,
                "source_version_id": source_version_id,
                "reason_codes": reasons,
                "checks": checks,
                "evidence": _safe_evidence(evidence),
            }
        )
    if ai_confidence is not None and not _all_required_verified(checks):
        reasons.append("ai_confidence_is_not_approval")
        return seal_source_admission_decision(
            {
                "decision": "HOLD",
                "actor_type": actor_type,
                "auto_admission_eligible": False,
                "operator_decision_required": True,
                "source_version_id": source_version_id,
                "reason_codes": reasons,
                "checks": checks,
                "evidence": _safe_evidence(evidence),
            }
        )
    if not source_version_id:
        reasons.append("missing_source_version_id")
        ambiguity.append("catalogue_source_version_absent")
    if checks.get("licence_or_model_use_verified") is False or evidence.get("rights_ambiguous"):
        reasons.append("rights_ambiguity")
        ambiguity.append("computational_use_rights_unresolved")
    if (
        checks.get("currentness_status_acceptable") is False
        or evidence.get("currentness_ambiguous") is True
    ):
        reasons.append("currentness_ambiguity")
        ambiguity.append("currentness_unresolved")
    if checks.get("unapplied_effects_reviewed_or_nonmaterial") is False:
        reasons.append("unapplied_effects_unresolved")
        ambiguity.append("material_amendments_unresolved")
    if checks.get("england_and_wales_extent_verified") is False:
        reasons.append("extent_unverified")
        ambiguity.append("jurisdiction_or_extent_unresolved")
    if evidence.get("non_official_proposed_as_authority") is True:
        reasons.append("non_official_source_proposed_as_authority")
        ambiguity.append("non_official_authority")
    if evidence.get("source_identity_conflict") is True:
        reasons.append("source_identity_conflict")
        ambiguity.append("source_identity_conflict")
    if evidence.get("parser_ambiguity_affecting_legal_meaning") is True:
        reasons.append("parser_ambiguity_affecting_legal_meaning")
        ambiguity.append("parser_ambiguity")

    required_ok = _all_required_verified(checks) and source_version_id is not None
    if official and required_ok and not ambiguity:
        return seal_source_admission_decision(
            {
                "decision": "APPROVE",
                "actor_type": actor_type,
                "auto_admission_eligible": True,
                "operator_decision_required": False,
                "source_version_id": source_version_id,
                "reason_codes": ["v2_objective_checks_verified"],
                "checks": checks,
                "evidence": _safe_evidence(evidence),
            }
        )
    if not reasons:
        reasons.append("source_admission_incomplete")
    return seal_source_admission_decision(
        {
            "decision": "HOLD",
            "actor_type": actor_type,
            "auto_admission_eligible": False,
            "operator_decision_required": True,
            "source_version_id": source_version_id,
            "reason_codes": reasons,
            "ambiguity_codes": ambiguity,
            "checks": checks,
            "evidence": _safe_evidence(evidence),
        }
    )


def _all_required_verified(checks: Mapping[str, Any]) -> bool:
    return all(_check_true(checks, name) for name in AUTO_ADMISSION_REQUIRED_TRUE)


def _safe_evidence(evidence: Mapping[str, Any]) -> dict[str, Any]:
    payload = {
        key: value
        for key, value in evidence.items()
        if key
        in {
            "stable_source_id",
            "source_version_id",
            "document_content_sha256",
            "source_version_sha256",
            "official_source_url",
            "canonical_url",
            "jurisdiction",
            "licence_name",
            "parser_status",
            "currentness_status",
            "extent",
            "unapplied_effect_requires_applied_count",
            "quarantined",
            "superseded",
            "scan_id",
            "affected_row_ids",
            "official_primary",
        }
    }
    return payload


def seal_source_admission_decision(material: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(material)
    payload.setdefault("schema", SOURCE_ADMISSION_DECISION_SCHEMA)
    payload.setdefault("policy_version", SOURCE_ADMISSION_POLICY_V2)
    payload.setdefault("writes_active", False)
    payload.setdefault("writes_o04", False)
    payload.setdefault("issue_gold_minted", False)
    payload.setdefault("sources_indexed", False)
    payload.setdefault("ai_confidence_is_not_approval", True)
    payload.setdefault("actor_type_does_not_determine_acceptance", True)
    payload["seal_sha256"] = sealed_sha256(payload)
    assert_safe_evaluation_payload(
        {key: value for key, value in payload.items() if key != "checks"}
    )
    return payload


def apply_source_admission_decision(
    database: Any,
    decision: Mapping[str, Any],
    *,
    source_approval: Mapping[str, Any] | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    """Write source-admission APPROVE/REJECT. Never mints issue gold or ACTIVE."""

    from ..db import utc_iso

    outcome = str(decision.get("decision") or "")
    source_version_id = str(decision.get("source_version_id") or "")
    if outcome == "REJECT" and not source_version_id:
        return {
            "applied": True,
            "decision": "REJECT",
            "source_version_id": None,
            "catalogue_write": False,
            "issue_gold_minted": False,
            "sources_indexed": False,
            "writes_active": False,
            "writes_o04": False,
        }
    if outcome == "APPROVE" and not source_version_id:
        raise ValueError("APPROVE cannot be applied without a catalogue source_version_id")
    if outcome == "APPROVE" and decision.get("auto_admission_eligible") is not True:
        raise ValueError("non-eligible source admission cannot auto-apply")
    if outcome == "HOLD":
        return {
            "applied": False,
            "decision": "HOLD",
            "source_version_id": source_version_id or None,
            "issue_gold_minted": False,
            "sources_indexed": False,
            "writes_active": False,
        }
    if outcome not in {"APPROVE", "REJECT"}:
        raise ValueError("source-admission decision is invalid")
    existing = database.fetchone(
        "SELECT review_status FROM source_versions WHERE id=?",
        (source_version_id,),
    )
    expected_status = "approved" if outcome == "APPROVE" else "rejected"
    if existing is not None and str(existing["review_status"]) == expected_status:
        return {
            "applied": True,
            "decision": outcome,
            "source_version_id": source_version_id,
            "review_status": expected_status,
            "actor_type": decision.get("actor_type"),
            "already_applied": True,
            "issue_gold_minted": False,
            "sources_indexed": False,
            "writes_active": False,
            "writes_o04": False,
        }
    review = database.fetchone(
        """
        SELECT id FROM reviews
        WHERE review_type='source_version' AND target_id=? AND status='pending'
        """,
        (source_version_id,),
    )
    stamp = now or utc_iso()
    if review is None:
        review_id = f"review-v2-admission-{source_version_id[:40]}"
        database.execute(
            """
            INSERT INTO reviews(id, review_type, target_id, status, reason, created_at)
            VALUES (?, 'source_version', ?, 'pending', ?, ?)
            """,
            (
                review_id,
                source_version_id,
                "Source-admission review required before primary_authority enters a candidate build",
                stamp,
            ),
        )
    else:
        review_id = str(review["id"])
    if outcome == "REJECT":
        changed = database.decide_review(review_id, "rejected", None)
        if not changed:
            raise ValueError("source-admission REJECT could not be recorded")
    else:
        if not isinstance(source_approval, Mapping):
            raise ValueError("V2 APPROVE requires mechanical source-approval metadata")
        changed = database.decide_review(
            review_id,
            "approved",
            None,
            source_approval=dict(source_approval),
        )
        if not changed:
            raise ValueError("source-admission APPROVE could not be recorded")
    row = database.fetchone(
        "SELECT review_status FROM source_versions WHERE id=?",
        (source_version_id,),
    )
    status = str(row["review_status"]) if row is not None else None
    return {
        "applied": True,
        "decision": outcome,
        "source_version_id": source_version_id,
        "review_status": status,
        "actor_type": decision.get("actor_type"),
        "issue_gold_minted": False,
        "sources_indexed": False,
        "writes_active": False,
        "writes_o04": False,
    }


def mechanical_legislation_source_approval(
    *,
    official_source_url: str,
    title: str,
    as_of_date: str,
    stable_identifier: str,
    currentness_status: str = "latest_available_revised_snapshot",
) -> dict[str, Any]:
    """Build V1-compatible approval metadata from official legislation identity."""

    url = official_source_url.strip().rstrip("/")
    if url.endswith("/data.xml"):
        url = url[: -len("/data.xml")]
    material_type = "legislation"
    citation_data: dict[str, Any] = {"source_type": "legislation", "title": title}
    if "/uksi/" in url:
        material_type = "legislation"
        parts = url.split("/uksi/", 1)[-1].split("/")
        if len(parts) >= 2:
            citation_data = {
                "source_type": "statutory_instrument",
                "title": title.removeprefix("The "),
                "instrument_number": f"SI {parts[0]}/{parts[1]}",
            }
    return {
        "identity_verified": True,
        "currentness_verified": True,
        "stable_identifier": stable_identifier,
        "as_of_date": as_of_date,
        "currentness_status": currentness_status,
        "material_type": material_type,
        "citation_data": citation_data,
        "canonical_url": url,
        "licence_name": OGL_LICENCE_NAME,
        "licence_url": OGL_LICENCE_URL,
    }


def apply_auto_source_admission_pack(
    pack: Mapping[str, Any],
    *,
    database: Any | None = None,
    source_approvals: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Apply a V2 pack whose APPROVE rows are all auto-admission eligible.

    No owner confirmation token. HOLD rows are not applied.
    """

    if str(pack.get("schema") or "") != SOURCE_ADMISSION_PACK_SCHEMA:
        raise ValueError("source-admission pack schema is invalid")
    if pack.get("operator_decision_required") is True:
        raise ValueError("operator-required source pack cannot auto-apply")
    counts = {"APPROVE": 0, "REJECT": 0, "HOLD": 0}
    applied_ids: list[str] = []
    approvals = source_approvals or {}
    for item in pack.get("decisions") or ():
        if not isinstance(item, Mapping):
            raise ValueError("source-admission decision is not an object")
        outcome = str(item.get("decision") or item.get("recommended_decision") or "")
        if outcome not in {"APPROVE", "REJECT", "HOLD"}:
            raise ValueError("source-admission decision is invalid")
        counts[outcome] += 1
        if outcome == "HOLD":
            continue
        if outcome == "APPROVE" and item.get("auto_admission_eligible") is not True:
            raise ValueError("pack contains a non-eligible APPROVE")
        if outcome == "APPROVE" and not str(item.get("source_version_id") or ""):
            raise ValueError("APPROVE cannot be applied without a catalogue source_version_id")
        if database is not None:
            source_version_id = str(item.get("source_version_id") or "")
            if outcome == "REJECT" and not source_version_id:
                continue
            if outcome == "REJECT":
                apply_source_admission_decision(database, item)
            else:
                apply_source_admission_decision(
                    database,
                    item,
                    source_approval=approvals.get(source_version_id),
                )
            applied_ids.append(source_version_id)
    payload = {
        **dict(pack),
        "applied": True,
        "operator_confirmed": False,
        "operator_decision_counts": counts,
        "applied_source_version_ids": applied_ids,
        "issue_gold_minted": False,
        "sources_indexed": False,
        "writes_active": False,
        "writes_o04": False,
    }
    assert_safe_evaluation_payload(
        {key: value for key, value in payload.items() if key != "decisions"}
    )
    return payload


def one_source_may_affect_many_rows(
    decisions: Sequence[Mapping[str, Any]],
) -> dict[str, tuple[str, ...]]:
    mapping: dict[str, tuple[str, ...]] = {}
    for item in decisions:
        key = str(
            item.get("source_version_id")
            or item.get("decision_id")
            or item.get("official_source_url")
            or ""
        )
        rows = tuple(str(row_id) for row_id in (item.get("affected_row_ids") or ()))
        if key:
            mapping[key] = rows
    return mapping
