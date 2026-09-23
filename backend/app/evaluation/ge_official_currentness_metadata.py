"""Deterministic official-source currentness metadata. Does not decide CURRENT."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .ge_factual_gap_fill import (
    OFFICIAL_REGISTRY,
    PROJECT_ROOT,
    canonical_title_key,
    default_fetch,
    lookup_official,
    official_urls,
    resolve_official,
)
from .ge_locator_gold_overlay import overlay_from_mapping, titles_equivalent

STAGING_RAW = (
    PROJECT_ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-official-staging-intake-r1"
    / "raw"
)
APPROVED_MANIFEST = (
    PROJECT_ROOT
    / "data/indexes/builds/current-law-ew-full-fp16-v111-20260829-recovery-b"
    / "approved-source-manifest.json"
)
OVERLAY_PATH = (
    PROJECT_ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-per-locator-evaluation-gold-resolved-r2"
    / "LOCATOR-EVALUATION-GOLD-REGISTER.json"
)
CAPTURE_AS_AT = "2026-08-14"

EXTENT_RE = re.compile(rb'\bRestrictExtent="([^"]+)"')
START_RE = re.compile(rb'\bRestrictStartDate="([^"]+)"')
VALID_RE = re.compile(rb"<dct:valid>([^<]+)</dct:valid>")
MODIFIED_RE = re.compile(rb"<dc:modified>([^<]+)</dc:modified>")
FRBR_DATE_RE = re.compile(rb'<FRBRdate[^>]*date="([^"]+)"', re.IGNORECASE)
JUDGMENT_DATE_RE = re.compile(
    rb"<(?:uk:)?judgmentDate>([^<]+)</(?:uk:)?judgmentDate>|"
    rb"<dcterms:date>([^<]+)</dcterms:date>|"
    rb'<date[^>]*name="judgment"[^>]*date="([^"]+)"',
    re.IGNORECASE,
)
ISO_DATE_RE = re.compile(r"(20\d{2}-\d{2}-\d{2})")
TRANSITIONAL_RE = re.compile(rb"transitional|savings provision", re.IGNORECASE)
COMMENCEMENT_RE = re.compile(rb"coming into force|commencement", re.IGNORECASE)


def _decode_group(match: re.Match[bytes] | None, group: int = 1) -> str:
    if match is None:
        return ""
    raw = match.group(group)
    return raw.decode("ascii", "replace") if raw else ""


def extract_official_xml_metadata(raw: bytes) -> dict[str, str]:
    extent = _decode_group(EXTENT_RE.search(raw[:12000]) or EXTENT_RE.search(raw))
    start = _decode_group(START_RE.search(raw[:12000]) or START_RE.search(raw))
    valid = _decode_group(VALID_RE.search(raw[:40000]))
    modified = _decode_group(MODIFIED_RE.search(raw[:40000]))
    frbr = _decode_group(FRBR_DATE_RE.search(raw[:40000]))
    judgment = ""
    jmatch = JUDGMENT_DATE_RE.search(raw[:80000])
    if jmatch is not None:
        judgment = next((item.decode("ascii", "replace") for item in jmatch.groups() if item), "")
        iso = ISO_DATE_RE.search(judgment)
        judgment = iso.group(1) if iso else judgment[:40]
    effects = raw.count(b"<ukm:UnappliedEffect") + raw.count(b"<UnappliedEffect")
    prospective = raw.count(b'Prospective="true"')
    version = valid or start or frbr or judgment or ""
    iso = ISO_DATE_RE.search(version)
    version = iso.group(1) if iso else version
    return {
        "source_version_date": version,
        "restrict_extent": extent,
        "restrict_start_date": start,
        "dct_valid": valid,
        "dc_modified": modified,
        "judgment_date": judgment,
        "unapplied_effect_markup_count": str(effects),
        "prospective_true_count": str(prospective),
        "transitional_markup_present": "true" if TRANSITIONAL_RE.search(raw[:200000]) else "false",
        "commencement_markup_present": "true" if COMMENCEMENT_RE.search(raw[:200000]) else "false",
        "xml_sha256": __import__("hashlib").sha256(raw).hexdigest(),
    }


def _staging_xml_path(spec: Mapping[str, str]) -> Path | None:
    if spec.get("kind") == "legislation":
        ident = str(spec.get("identifier") or "").replace("/", "-")
        for as_at in (CAPTURE_AS_AT, "2026-08-28"):
            path = STAGING_RAW / ident / as_at / "data.xml"
            if path.is_file():
                return path
        return None
    url = str(spec.get("url") or "")
    if "caselaw.nationalarchives.gov.uk" in url:
        ident = url.split("nationalarchives.gov.uk/")[-1].replace("/data.xml", "").replace("/", "-")
        path = STAGING_RAW / ident / "data.xml"
        if path.is_file():
            return path
    return None


def load_approved_source_index(path: Path = APPROVED_MANIFEST) -> dict[str, dict[str, Any]]:
    if not path.is_file():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    sources = raw.get("sources") if isinstance(raw, Mapping) else []
    by_id: dict[str, dict[str, Any]] = {}
    for item in sources or []:
        if isinstance(item, Mapping) and item.get("source_version_id"):
            by_id[str(item["source_version_id"])] = dict(item)
    return by_id


def load_overlay(path: Path = OVERLAY_PATH):
    if not path.is_file():
        return None
    return overlay_from_mapping(json.loads(path.read_text(encoding="utf-8")))


class CurrentnessMetadataIndex:
    """One bounded lookup index. Does not conclude owner currentness."""

    def __init__(
        self,
        *,
        fetch=default_fetch,
        allow_network: bool = False,
        project_root: Path = PROJECT_ROOT,
    ) -> None:
        self.fetch = fetch
        self.allow_network = allow_network
        self.approved = load_approved_source_index(
            project_root / APPROVED_MANIFEST.relative_to(PROJECT_ROOT)
            if project_root != PROJECT_ROOT
            else APPROVED_MANIFEST
        )
        overlay_path = (
            project_root / OVERLAY_PATH.relative_to(PROJECT_ROOT)
            if project_root != PROJECT_ROOT
            else OVERLAY_PATH
        )
        self.overlay = load_overlay(overlay_path)
        self._xml_cache: dict[str, dict[str, str]] = {}
        self._spec_cache: dict[str, Mapping[str, str] | None] = {}

    def _spec_for_title(self, title: str) -> Mapping[str, str] | None:
        key = title.casefold()
        if key in self._spec_cache:
            return self._spec_cache[key]
        spec = lookup_official(title)
        if spec is None:
            spec = OFFICIAL_REGISTRY.get(canonical_title_key(title))
        if spec is None and self.allow_network:
            spec = resolve_official(title, self.fetch)
        self._spec_cache[key] = spec
        return spec

    def _xml_metadata(self, title: str) -> dict[str, str]:
        if title in self._xml_cache:
            return self._xml_cache[title]
        spec = self._spec_for_title(title)
        empty = {
            "source_version_date": "",
            "restrict_extent": "",
            "restrict_start_date": "",
            "dct_valid": "",
            "dc_modified": "",
            "judgment_date": "",
            "unapplied_effect_markup_count": "",
            "prospective_true_count": "",
            "transitional_markup_present": "false",
            "commencement_markup_present": "false",
            "xml_sha256": "",
            "xml_origin": "",
        }
        if spec is None:
            self._xml_cache[title] = empty
            return empty
        path = _staging_xml_path(spec)
        origin = ""
        raw = b""
        if path is not None and path.is_file():
            raw = path.read_bytes()
            origin = f"local_official_staging:{path.name}"
        elif self.allow_network:
            urls = official_urls(spec)
            for url in urls:
                if not str(url).endswith(".xml"):
                    continue
                result = self.fetch(url)
                if result.get("ok") and result.get("body"):
                    raw = result["body"]
                    origin = f"official_fetch:{url}"
                    break
        if not raw:
            empty["xml_origin"] = "unavailable"
            self._xml_cache[title] = empty
            return empty
        meta = extract_official_xml_metadata(raw)
        if not meta.get("source_version_date") and spec.get("kind") == "legislation" and origin.startswith(
            "local_official_staging"
        ):
            meta["source_version_date"] = CAPTURE_AS_AT
            meta["source_version_date_basis"] = "official_captured_version_folder_date_not_currentness"
        meta["xml_origin"] = origin
        self._xml_cache[title] = meta
        return meta

    def lookup_locator(self, record: Mapping[str, Any]) -> dict[str, str]:
        title = str(record.get("source_title") or record.get("title") or "")
        locator = str(record.get("exact_locator") or record.get("locator") or "")
        source_id = str(record.get("source_version_id") or "")
        recovered: dict[str, str] = {}
        if self.overlay is not None:
            receipt = self.overlay.lookup(
                {"title": title, "locator": locator, "source_version_id": source_id}
            )
            if receipt is not None:
                if receipt.currentness_reviewed_as_of_date:
                    recovered["source_version_date"] = str(receipt.currentness_reviewed_as_of_date)
                    recovered["source_version_date_origin"] = "locator_overlay_reviewed_as_of"
                if receipt.point_in_time_as_at:
                    recovered.setdefault("source_version_date", str(receipt.point_in_time_as_at))
                    recovered["point_in_time_as_at"] = str(receipt.point_in_time_as_at)
        approved = self.approved.get(source_id)
        if approved is None:
            for item in self.approved.values():
                if titles_equivalent(str(item.get("title") or ""), title):
                    approved = item
                    break
        if approved:
            date = (
                str(approved.get("currentness_reviewed_as_of_date") or "")
                or str(approved.get("as_of_date") or "")
                or str(approved.get("source_date") or "")
            )
            if date:
                recovered.setdefault("source_version_date", date)
                recovered.setdefault("source_version_date_origin", "approved_source_manifest")
            if approved.get("provision_extent_status"):
                recovered["catalogue_extent_status"] = str(approved.get("provision_extent_status"))
        xml = self._xml_metadata(title)
        if xml.get("source_version_date"):
            recovered.setdefault("source_version_date", xml["source_version_date"])
            recovered.setdefault("source_version_date_origin", xml.get("xml_origin") or "official_xml")
        for key in (
            "restrict_extent",
            "restrict_start_date",
            "judgment_date",
            "unapplied_effect_markup_count",
            "prospective_true_count",
            "transitional_markup_present",
            "commencement_markup_present",
            "xml_sha256",
            "xml_origin",
        ):
            if xml.get(key):
                recovered[key] = xml[key]
        return recovered
