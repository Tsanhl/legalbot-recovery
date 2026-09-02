"""Per-locator gold overlay for GE diagnostic evaluation.

An unsigned or PENDING overlay is a no-op. Only an owner-signed APPROVE
receipt may satisfy currentness and verified-extent checks. Effects must be
reviewed; they do not have to be zero. This module never sets legal gold by
itself.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_MONTHS = {
    "january": "01",
    "february": "02",
    "march": "03",
    "april": "04",
    "may": "05",
    "june": "06",
    "july": "07",
    "august": "08",
    "september": "09",
    "october": "10",
    "november": "11",
    "december": "12",
}
_DAY_MONTH_YEAR = re.compile(
    r"\b(\d{1,2})\s+(January|February|March|April|May|June|July|"
    r"August|September|October|November|December)\s+(20\d{2})\b",
    re.IGNORECASE,
)
_ISO_DATE = re.compile(r"\b(20\d{2}-\d{2}-\d{2})\b")
_LOCATOR_NOISE = re.compile(r"[.,;:()\[\]]+")


def normalize_locator(locator: str) -> str:
    text = _LOCATOR_NOISE.sub(" ", str(locator or "").casefold())
    text = re.sub(r"\bsect\b", "section", text)
    text = re.sub(r"\bs\b", "section", text)
    text = re.sub(r"^s(\d)", r"section \1", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def locator_match_key(source_version_id: str, locator: str) -> str:
    return f"{str(source_version_id or '').strip()}::{normalize_locator(locator)}"


def title_locator_key(title: str, locator: str) -> str:
    return f"{str(title or '').strip().casefold()}::{normalize_locator(locator)}"


def iso_date_from_prompt(prompt: str) -> str | None:
    match = _DAY_MONTH_YEAR.search(str(prompt or ""))
    if match is not None:
        day = int(match.group(1))
        month = _MONTHS[match.group(2).casefold()]
        return f"{match.group(3)}-{month}-{day:02d}"
    iso = _ISO_DATE.search(str(prompt or ""))
    return iso.group(1) if iso else None


@dataclass(frozen=True, slots=True)
class LocatorGoldReceipt:
    source_version_id: str
    title: str
    locator: str
    owner_signed: bool
    owner_decision: str
    effects_reviewed: bool
    provision_extent_status: str
    currentness_reviewed_as_of_date: str
    evaluation_as_of_date: str
    point_in_time_as_at: str | None
    legal_gold: bool
    locator_evaluation_gold: bool
    admitted: bool
    full_current_law_eligible: bool
    qualified_legal_review: bool
    mandatory_evidence_route: bool

    @property
    def is_effective_approve(self) -> bool:
        return (
            self.owner_signed is True
            and self.owner_decision == "APPROVE"
            and self.effects_reviewed is True
            and str(self.provision_extent_status) == "verified"
            and self.locator_evaluation_gold is True
        )


_PIN_TAIL = re.compile(
    r",\s+(?P<pin>(?:section|regulation|rule|article|schedule|paragraph)s?\s+.+)$",
    re.IGNORECASE,
)
_CITATION_TAIL = re.compile(r"\s*\[\d{4}\].*$")
_TITLE_ALIASES = {
    "icc mediation rules effective 1 january 2014": (
        "icc mediation rules (contractually incorporated edition)"
    ),
    "wills act 1837": "wills act 1837 (as at 2024-01-15)",
}


def split_locator_label(label: str) -> tuple[str, str]:
    text = str(label or "").strip()
    match = _PIN_TAIL.search(text)
    if match is None:
        return text, ""
    return text[: match.start()].strip(), match.group("pin").strip()


def base_title(title: str) -> str:
    folded = _CITATION_TAIL.sub("", str(title or "")).strip()
    return folded.replace("’", "'").replace("‘", "'")


def titles_equivalent(left: str, right: str) -> bool:
    a = base_title(left).casefold().strip()
    b = base_title(right).casefold().strip()
    if not a or not b:
        return False
    if a == b:
        return True
    if _TITLE_ALIASES.get(a) == b or _TITLE_ALIASES.get(b) == a:
        return True
    if a.startswith(b) or b.startswith(a):
        return True
    return False


def locators_equivalent(left: str, right: str) -> bool:
    a = normalize_locator(left)
    b = normalize_locator(right)
    if not a or not b:
        return not a and not b
    if a == b:
        return True
    if a in b or b in a:
        return True
    return False


@dataclass(frozen=True, slots=True)
class LocatorGoldOverlay:
    schema: str
    evaluation_as_of_date: str
    receipts: tuple[LocatorGoldReceipt, ...]
    owner_pack_signed: bool

    def lookup(self, row: Mapping[str, Any]) -> LocatorGoldReceipt | None:
        source_id = str(row.get("source_version_id") or "")
        locator = str(row.get("locator") or "")
        title = str(row.get("title") or "")
        if source_id:
            by_source = {
                locator_match_key(item.source_version_id, item.locator): item
                for item in self.receipts
                if item.source_version_id
            }
            hit = by_source.get(locator_match_key(source_id, locator))
            if hit is not None:
                return hit
        by_title = {title_locator_key(item.title, item.locator): item for item in self.receipts}
        hit = by_title.get(title_locator_key(title, locator))
        if hit is not None:
            return hit
        for item in self.receipts:
            if titles_equivalent(item.title, title) and locators_equivalent(item.locator, locator):
                return item
            if titles_equivalent(item.title, title) and not item.locator:
                return item
        return None

    def effective_approve(self, row: Mapping[str, Any]) -> LocatorGoldReceipt | None:
        if self.owner_pack_signed is not True:
            return None
        receipt = self.lookup(row)
        if receipt is None or not receipt.is_effective_approve:
            return None
        return receipt

    def is_rejected_mandatory(self, title: str, locator: str = "") -> bool:
        receipt = self.lookup({"title": title, "locator": locator})
        if receipt is None:
            needle = base_title(title).casefold()
            return any(
                item.owner_decision == "REJECT" and titles_equivalent(item.title, title)
                for item in self.receipts
            ) or "cable & wireless" in needle
        return receipt.owner_decision == "REJECT" or receipt.mandatory_evidence_route is False


def load_locator_gold_overlay(path: Path | None) -> LocatorGoldOverlay | None:
    if path is None or not path.is_file():
        return None
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("locator gold overlay is not an object")
    return overlay_from_mapping(raw)


def overlay_from_mapping(raw: Mapping[str, Any]) -> LocatorGoldOverlay:
    receipts: list[LocatorGoldReceipt] = []
    rows = raw.get("locators") or raw.get("receipts") or raw.get("rows") or ()
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
        raise ValueError("locator gold overlay locators are invalid")
    evaluation_as_of = str(raw.get("evaluation_as_of_date") or "")
    signed = raw.get("owner_pack_signed") is True or raw.get("owner_adopted") is True
    for item in rows:
        if not isinstance(item, Mapping):
            raise ValueError("locator gold overlay row is invalid")
        combined = str(item.get("locator") or "")
        title = str(item.get("title") or "")
        pin = combined
        if not title and combined:
            title, pin = split_locator_label(combined)
        decision = str(
            item.get("owner_decision") or item.get("owner_evaluation_decision") or "PENDING"
        )
        pit = item.get("point_in_time_as_at")
        if not pit and (
            "2024-01-15" in combined or "15 january 2024" in combined.casefold()
        ):
            pit = "2024-01-15"
        approve = decision == "APPROVE" and signed
        receipts.append(
            LocatorGoldReceipt(
                source_version_id=str(item.get("source_version_id") or ""),
                title=title,
                locator=pin,
                owner_signed=item.get("owner_signed") is True or approve,
                owner_decision=decision,
                effects_reviewed=item.get("effects_reviewed") is True or approve,
                provision_extent_status=str(
                    item.get("provision_extent_status")
                    or ("verified" if approve else "unverified")
                ),
                currentness_reviewed_as_of_date=str(
                    item.get("currentness_reviewed_as_of_date") or evaluation_as_of
                ),
                evaluation_as_of_date=str(item.get("evaluation_as_of_date") or evaluation_as_of),
                point_in_time_as_at=str(pit) if pit else None,
                legal_gold=item.get("legal_gold") is True,
                locator_evaluation_gold=(
                    item.get("locator_evaluation_gold") is True or approve
                ),
                admitted=item.get("admitted") is True or item.get("runtime_admitted") is True,
                full_current_law_eligible=item.get("full_current_law_eligible") is True,
                qualified_legal_review=item.get("qualified_legal_review") is True,
                mandatory_evidence_route=item.get("mandatory_evidence_route") is not False
                and decision != "REJECT",
            )
        )
    return LocatorGoldOverlay(
        schema=str(raw.get("schema") or "legalbot.ge-per-locator-gold-draft.v1"),
        evaluation_as_of_date=evaluation_as_of,
        receipts=tuple(receipts),
        owner_pack_signed=signed,
    )


def currentness_cutoff(case: Mapping[str, Any], overlay: LocatorGoldOverlay | None) -> str:
    if overlay is not None and overlay.owner_pack_signed and overlay.evaluation_as_of_date:
        return overlay.evaluation_as_of_date
    return str(case.get("legal_currentness_cutoff") or "")


def row_currentness_ok(
    row: Mapping[str, Any],
    *,
    cutoff: str,
    overlay: LocatorGoldOverlay | None,
) -> bool:
    receipt = overlay.effective_approve(row) if overlay is not None else None
    if receipt is not None:
        reviewed = str(receipt.currentness_reviewed_as_of_date or "")
        return bool(cutoff) and reviewed >= cutoff
    return (
        row.get("currentness_verified") is True
        and row.get("full_current_law_verification_eligible") is True
        and str(row.get("provision_extent_status") or "") == "verified"
        and (row.get("unapplied_effect_count") in {0, None})
        and str(row.get("currentness_reviewed_as_of_date") or "") >= cutoff
    )


def row_extent_verified(row: Mapping[str, Any], overlay: LocatorGoldOverlay | None) -> bool:
    receipt = overlay.effective_approve(row) if overlay is not None else None
    if receipt is not None:
        return str(receipt.provision_extent_status) == "verified"
    return str(row.get("provision_extent_status") or "") == "verified"


def row_point_in_time(row: Mapping[str, Any], overlay: LocatorGoldOverlay | None) -> str | None:
    receipt = overlay.lookup(row) if overlay is not None else None
    if receipt is not None and receipt.point_in_time_as_at:
        return receipt.point_in_time_as_at
    value = row.get("point_in_time_as_at")
    return str(value) if value else None
