"""Owner tick-draft helpers. Mechanical exact-match only; never seals gold."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .live30 import assert_safe_evaluation_payload
from .live_suite import load_live_evaluation_bundle
from .live_suite_held_span_repair import (
    IPFDA_BA_PARENT,
    IPFDA_OPENING_PARENT,
    S14A_SPLICED_PARENT,
)
from .live_suite_repair_span import IPFDA_DOTS_PARENT
from .live_suite_span_accuracy import check_user_span_exact_match

TICK_DRAFT_SCHEMA = "legalbot.live60-issue-ticks-draft.v1"
TICK_PROGRESS_SCHEMA = "legalbot.live60-owner-tick-progress.v1"
ALLOWED_TICK_STATUSES = frozenset({"knowledge_gap", "qualified", "limited"})
SPLICED_PARENT_CHUNK_IDS = frozenset(
    {
        S14A_SPLICED_PARENT,
        IPFDA_OPENING_PARENT,
        IPFDA_BA_PARENT,
        IPFDA_DOTS_PARENT,
    }
)
COPYABLE_FIELDS = (
    "source_version_id",
    "chunk_id",
    "content_sha256",
    "legal_locator",
)


def _normalize_locator(value: str) -> str:
    cleaned = " ".join(value.split()).casefold()
    return cleaned.replace("section ", "s ").replace("article ", "art ")


_PINPOINT_RANGE_RE = re.compile(
    r"\b(?P<kind>ss?|sections?|arts?|articles?|regs?|regulations?|sch(?:edule)?s?)\s+"
    r"(?P<body>[0-9A-Za-z][0-9A-Za-z,\s\-/]*)",
    re.IGNORECASE,
)
_PINPOINT_TOKEN_RE = re.compile(r"^[0-9]+[A-Za-z]*$")


def parse_issue_pinpoint_locators(pinpoint: str) -> tuple[str, ...]:
    """Extract exact locator candidates from a resource-map pinpoint.

    Does not invent a paragraph where the pinpoint only says review is required.
    """

    text = " ".join((pinpoint or "").replace("–", "-").replace("—", "-").split())
    if not text or "pinpoint paragraph review required" in text.casefold():
        return ()
    locators: list[str] = []
    seen: set[str] = set()
    kind_prefix = {
        "s": "section",
        "ss": "section",
        "section": "section",
        "sections": "section",
        "art": "article",
        "arts": "article",
        "article": "article",
        "articles": "article",
        "reg": "regulation",
        "regs": "regulation",
        "regulation": "regulation",
        "regulations": "regulation",
        "sch": "schedule",
        "schs": "schedule",
        "schedule": "schedule",
        "schedules": "schedule",
    }
    for match in _PINPOINT_RANGE_RE.finditer(text):
        kind = kind_prefix[match.group("kind").casefold()]
        body = match.group("body")
        for raw_part in re.split(r",|;|/|\band\b", body, flags=re.IGNORECASE):
            part = raw_part.strip(" .;:")
            if not part:
                continue
            start = part.split("-", 1)[0].strip()
            if not _PINPOINT_TOKEN_RE.fullmatch(start):
                continue
            locator = f"{kind} {start}"
            key = _normalize_locator(locator)
            if key in seen:
                continue
            seen.add(key)
            locators.append(locator)
    return tuple(locators)


def load_repair_payload(path: Path | None) -> Mapping[str, Any] | None:
    if path is None or not path.is_file():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise ValueError("repair payload is not an object")
    return payload


def lookup_catalogue_spans(
    *,
    catalog_path: Path,
    authority_identity_id: str,
    locator: str,
    repair: Mapping[str, Any] | None = None,
    limit: int = 40,
) -> dict[str, Any]:
    """Return copy-paste span identities. Does not include source prose."""

    if not 1 <= limit <= 80:
        raise ValueError("lookup limit is out of range")
    authority = " ".join(authority_identity_id.split())
    wanted = _normalize_locator(locator)
    if not authority or not wanted:
        raise ValueError("authority identity and locator are required")
    if not catalog_path.is_file():
        raise FileNotFoundError("catalogue is not present")
    connection = sqlite3.connect(f"file:{catalog_path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            """
            SELECT sv.id AS source_version_id, sv.authority_identity_id,
                   c.id AS chunk_id, c.locator, c.text_sha256
            FROM chunks c
            JOIN source_versions sv ON sv.id = c.source_version_id
            WHERE sv.authority_identity_id = ?
              AND sv.superseded_by IS NULL
            ORDER BY c.ordinal, c.id
            """,
            (authority,),
        ).fetchall()
    finally:
        connection.close()
    matches: list[dict[str, Any]] = []
    for row in rows:
        catalog_locator = str(row["locator"] or "")
        normalized = _normalize_locator(catalog_locator)
        if normalized != wanted and not normalized.startswith(wanted) and wanted not in normalized:
            continue
        chunk_id = str(row["chunk_id"])
        item = {
            "source_version_id": row["source_version_id"],
            "chunk_id": chunk_id,
            "content_sha256": row["text_sha256"],
            "legal_locator": catalog_locator,
            "use_repair_span": chunk_id in SPLICED_PARENT_CHUNK_IDS,
        }
        if item["use_repair_span"]:
            item["suggested_repair_spans"] = [
                {
                    "repair_span_id": repair_item.get("repair_span_id"),
                    "source_version_id": row["source_version_id"],
                    "chunk_id": repair_item.get("repair_span_id"),
                    "content_sha256": repair_item.get("text_sha256"),
                    "legal_locator": repair_item.get("required_sublocator"),
                    "gold_eligible_candidate": bool(repair_item.get("gold_eligible_candidate")),
                }
                for repair_item in (repair or {}).get("repairs", ())
                if repair_item.get("parent_chunk_id") == chunk_id
            ]
        matches.append(item)
        if len(matches) >= limit:
            break
    payload = {
        "schema": "legalbot.live60-catalogue-span-lookup.v1",
        "authority_identity_id": authority,
        "locator_query": " ".join(locator.split()),
        "match_count": len(matches),
        "matches": matches,
        "ai_role": "mechanical_accuracy_verifier_only",
        "ai_second_reviewer_forbidden": True,
        "seals_expert_gold": False,
        "eligible_for_training": False,
        "training_export_allowed": False,
    }
    assert_safe_evaluation_payload(
        {key: value for key, value in payload.items() if key != "matches"}
    )
    return payload


def _locator_matches(catalog_locator: str, wanted: str) -> bool:
    normalized = _normalize_locator(catalog_locator)
    target = _normalize_locator(wanted)
    if not target:
        return False
    return (
        normalized == target
        or normalized.startswith(f"{target}(")
        or normalized.startswith(f"{target} ")
    )


def lookup_spans_by_document_sha256(
    *,
    catalog_path: Path,
    document_sha256: str,
    locators: Sequence[str],
    limit: int = 8,
) -> list[dict[str, Any]]:
    """Return body-stream chunks for a vault hash and exact locator candidates."""

    digest = document_sha256.strip().casefold()
    wanted = tuple(item for item in locators if item.strip())
    if not re.fullmatch(r"[0-9a-f]{64}", digest) or not wanted:
        return []
    if not catalog_path.is_file():
        raise FileNotFoundError("catalogue is not present")
    connection = sqlite3.connect(f"file:{catalog_path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            """
            SELECT sv.id AS source_version_id, sv.licence_name, sv.review_status,
                   sv.currentness_status, c.id AS chunk_id, c.locator, c.text_sha256
            FROM documents d
            JOIN source_versions sv ON sv.document_id = d.id
            JOIN chunks c ON c.source_version_id = sv.id
            WHERE d.content_sha256 = ?
              AND sv.superseded_by IS NULL
              AND COALESCE(c.stream, 'body') = 'body'
            ORDER BY c.ordinal, c.id
            """,
            (digest,),
        ).fetchall()
    finally:
        connection.close()
    matches: list[dict[str, Any]] = []
    seen: set[str] = set()
    for wanted_locator in wanted:
        for row in rows:
            chunk_id = str(row["chunk_id"])
            if chunk_id in seen or chunk_id in SPLICED_PARENT_CHUNK_IDS:
                continue
            if not _locator_matches(str(row["locator"] or ""), wanted_locator):
                continue
            seen.add(chunk_id)
            matches.append(
                {
                    "source_version_id": row["source_version_id"],
                    "chunk_id": chunk_id,
                    "locator": row["locator"],
                    "catalogue_present": True,
                    "catalogue_locator": row["locator"],
                    "content_sha256": row["text_sha256"],
                    "licence_name": row["licence_name"] or "",
                    "review_status": row["review_status"] or "",
                    "currentness_status": row["currentness_status"] or "",
                }
            )
            break
        if len(matches) >= limit:
            break
    return matches


def empty_tick_draft(*, as_of_date: str) -> dict[str, Any]:
    return {
        "schema": TICK_DRAFT_SCHEMA,
        "as_of_date": as_of_date,
        "contrary_authority_status": "blank",
        "cases": [],
        "seals_expert_gold": False,
        "wrote_expert_qualification": False,
        "wrote_active": False,
        "eligible_for_training": False,
        "training_export_allowed": False,
    }


def load_tick_draft(path: Path, *, as_of_date: str) -> dict[str, Any]:
    if not path.is_file():
        return empty_tick_draft(as_of_date=as_of_date)
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema") != TICK_DRAFT_SCHEMA:
        raise ValueError("issue tick draft schema is not recognised")
    return payload


def _issue_identity(bundle: Any, case_id: str, issue_id: str) -> dict[str, str]:
    case = next((item for item in bundle.registry.cases if item.case_id == case_id), None)
    if case is None:
        raise ValueError("case identity is not in the frozen Live60 registry")
    topics = list(case.must_cover_issues)
    number = int(issue_id.split("-")[1])
    expected = f"issue-{number:02d}"
    if expected != issue_id or number < 1 or number > len(topics):
        raise ValueError("issue identity is not in the frozen Live60 registry")
    return {"case_id": case_id, "issue_id": issue_id, "topic": topics[number - 1]}


def bind_issue_tick(
    draft: dict[str, Any],
    *,
    bundle: Any,
    case_id: str,
    issue_id: str,
    status: str,
    span: Mapping[str, str] | None = None,
    catalog_path: Path | None = None,
    repair: Mapping[str, Any] | None = None,
    later_treatment: str | None = None,
    gap_reason: str | None = None,
) -> dict[str, Any]:
    """Bind one owner tick after exact-match. Never qualifies by nearest vector."""

    if status not in ALLOWED_TICK_STATUSES:
        raise ValueError("tick status is not an allowed owner disposition")
    identity = _issue_identity(bundle, case_id, issue_id)
    spans: list[dict[str, str]] = []
    accuracy: dict[str, Any] | None = None
    if span is not None:
        accuracy = check_user_span_exact_match(
            chunk_id=str(span["chunk_id"]),
            content_sha256=str(span["content_sha256"]),
            legal_locator=str(span["legal_locator"]),
            source_version_id=span.get("source_version_id"),
            catalog_path=catalog_path,
            repair=repair,
        )
        if not accuracy["exact_match"]:
            raise ValueError("user-bound span failed exact-match accuracy check")
        spans.append({key: str(span[key]) for key in COPYABLE_FIELDS if span.get(key)})
    if status in {"qualified", "limited"} and not spans:
        raise ValueError("named qualify ticks require exact spans; none were supplied")
    case_row = next(
        (item for item in draft["cases"] if item["case_id"] == case_id),
        None,
    )
    if case_row is None:
        case_row = {"case_id": case_id, "issues": []}
        draft["cases"].append(case_row)
    issue_row = {
        "issue_id": issue_id,
        "topic": identity["topic"],
        "status": status,
        "exact_gold_spans": spans,
        "later_treatment": later_treatment,
        "gap_reason": gap_reason,
        "mechanical_exact_match": bool(accuracy and accuracy["exact_match"]),
    }
    case_row["issues"] = [item for item in case_row["issues"] if item["issue_id"] != issue_id] + [
        issue_row
    ]
    draft["seals_expert_gold"] = False
    draft["wrote_expert_qualification"] = False
    draft["wrote_active"] = False
    return {
        "bound": True,
        "case_id": case_id,
        "issue_id": issue_id,
        "status": status,
        "span_exact_match": bool(accuracy and accuracy["exact_match"]),
        "mismatch_codes": list((accuracy or {}).get("mismatch_codes") or ()),
        "seals_expert_gold": False,
    }


def apply_contrary_authority_status(draft: dict[str, Any], *, status: str) -> dict[str, Any]:
    if status not in {"reviewed_none", "reviewed_and_bound", "blank"}:
        raise ValueError("contrary authority status is not an allowed tick")
    draft["contrary_authority_status"] = status
    return {"contrary_authority_status": status, "seals_expert_gold": False}


def summarize_tick_draft(draft: Mapping[str, Any]) -> dict[str, Any]:
    qualified = limited = gap = spans_bound = 0
    for case in draft.get("cases", ()):
        for issue in case.get("issues", ()):
            status = issue.get("status")
            if status == "qualified":
                qualified += 1
            elif status == "limited":
                limited += 1
            elif status == "knowledge_gap":
                gap += 1
            if issue.get("exact_gold_spans"):
                spans_bound += 1
    overlay_sealable = (
        (qualified + limited) > 0
        and spans_bound > 0
        and draft.get("contrary_authority_status") in {"reviewed_none", "reviewed_and_bound"}
    )
    payload: dict[str, Any] = {
        "schema": TICK_PROGRESS_SCHEMA,
        "qualified": qualified,
        "limited": limited,
        "gap": gap,
        "spans_bound": spans_bound,
        "contrary_authority_status": draft.get("contrary_authority_status") or "blank",
        "overlay_sealable": overlay_sealable,
        "wrote_expert_qualification": False,
        "wrote_active": False,
        "seals_expert_gold": False,
        "generation_authorised": False,
        "ai_role": "mechanical_accuracy_verifier_only",
        "ai_second_reviewer_forbidden": True,
        "eligible_for_training": False,
        "training_export_allowed": False,
        "blockers": [],
    }
    if qualified + limited == 0:
        payload["blockers"].append("no_qualified_or_limited_issue_with_exact_spans")
    if draft.get("contrary_authority_status") in {None, "blank"}:
        payload["blockers"].append("contrary_authority_blank")
    if not overlay_sealable:
        payload["blockers"].append("overlay_not_sealable")
    assert_safe_evaluation_payload(payload)
    return payload


def write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def load_live60_bundle(project_root: Path) -> Any:
    return load_live_evaluation_bundle(
        project_root / "benchmarks" / "evaluation" / "live-evaluation-60-v1"
    )
