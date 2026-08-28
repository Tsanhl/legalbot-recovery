#!/usr/bin/env python3
"""Collect quarantined official-source evidence for v1.11 Phase-2A remediation.

The collector is deliberately non-admitting: it downloads only from the fixed
official allowlist, writes immutable quarantine members, and emits a provenance
manifest.  It never changes gold, a candidate, an index, or a release pointer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit
from xml.etree import ElementTree as ET

import httpx

ALLOWED_HOSTS = frozenset(
    {
        "www.legislation.gov.uk",
        "legislation.gov.uk",
        "caselaw.nationalarchives.gov.uk",
        "publications.parliament.uk",
    }
)
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_REDIRECTS = 5
USER_AGENT = "LegalBot-v1.11-Phase2A-official-source-review/1.0"
_NEUTRAL_CITATION = re.compile(
    r"neutral-citation:\[(?P<year>\d{4})\]\s+(?P<court>UKSC|UKHL)\s+(?P<number>\d+)",
    re.IGNORECASE,
)
_EXTERNAL_JUDGMENT = re.compile(
    r"(?P<year>\d{4})-(?P<court>UKSC|UKHL)-(?P<number>\d+)", re.IGNORECASE
)
_PARLIAMENT_REPRESENTATION = re.compile(
    r"ukhl-(?P<year>\d{4})-(?P<number>\d+)-part-(?P<part>\d+)",
    re.IGNORECASE,
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
FIND_CASE_LAW_COMPUTATIONAL_ANALYSIS_TERMS_URL = (
    "https://caselaw.nationalarchives.gov.uk/permissions-and-licensing"
)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _safe_url(value: str) -> str:
    parsed = urlsplit(value)
    host = (parsed.hostname or "").casefold()
    if parsed.scheme != "https" or host not in ALLOWED_HOSTS:
        raise ValueError("phase2a_official_url_outside_allowlist")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("phase2a_official_url_contains_forbidden_component")
    port = parsed.port
    if port not in (None, 443):
        raise ValueError("phase2a_official_url_uses_nonstandard_port")
    return urlunsplit(("https", parsed.netloc, parsed.path or "/", parsed.query, ""))


def _legislation_identity_path(authority_identity: str) -> str:
    parts = authority_identity.split(":")
    if len(parts) < 3 or parts[0] not in {"ukpga", "uksi"}:
        raise ValueError("phase2a_legislation_identity_invalid")
    if parts[0] == "uksi":
        # Candidate identities may carry a version qualifier such as ``made``;
        # the point-in-time segment belongs immediately after instrument number.
        parts = parts[:3]
    return "/".join(parts)


def _point_in_time_url(authority_identity: str, target_date: date) -> str:
    identity = _legislation_identity_path(authority_identity)
    return f"https://www.legislation.gov.uk/{identity}/{target_date.isoformat()}/data.xml"


def _judgment_url(citation: str) -> str:
    match = _NEUTRAL_CITATION.fullmatch(citation)
    if match is None:
        raise ValueError("phase2a_neutral_citation_invalid")
    court = match.group("court").casefold()
    return (
        "https://caselaw.nationalarchives.gov.uk/"
        f"{court}/{match.group('year')}/{int(match.group('number'))}/data.xml"
    )


def _candidate_judgment_url(source: Mapping[str, Any], citation: str) -> str:
    """Use the sealed official Parliament representation for legacy UKHL parts."""

    canonical = str(source.get("canonical_url") or "")
    if canonical:
        parsed = urlsplit(canonical)
        if (parsed.hostname or "").casefold() == "publications.parliament.uk":
            safe = _safe_url(canonical)
            parsed = urlsplit(safe)
            representation = str(source.get("official_representation_id") or "")
            match = _PARLIAMENT_REPRESENTATION.fullmatch(representation)
            if match is None:
                raise ValueError("phase2a_parliament_judgment_representation_invalid")
            citation_match = _NEUTRAL_CITATION.fullmatch(citation)
            if (
                citation_match is None
                or citation_match.group("court").casefold() != "ukhl"
                or citation_match.group("year") != match.group("year")
                or int(citation_match.group("number")) != int(match.group("number"))
            ):
                raise ValueError("phase2a_parliament_judgment_identity_mismatch")
            part = int(match.group("part"))
            path, replacement_count = re.subn(
                r"-\d+\.html?$",
                f"-{part}.htm",
                parsed.path,
                count=1,
                flags=re.IGNORECASE,
            )
            if replacement_count != 1:
                raise ValueError("phase2a_parliament_judgment_part_url_invalid")
            return _safe_url(
                urlunsplit(("https", parsed.netloc, path, parsed.query, ""))
            )
    return _judgment_url(citation)


def _external_judgment_url(identifier: str) -> str:
    match = _EXTERNAL_JUDGMENT.fullmatch(identifier)
    if match is None:
        raise ValueError("phase2a_external_judgment_identifier_invalid")
    return (
        "https://caselaw.nationalarchives.gov.uk/"
        f"{match.group('court').casefold()}/{match.group('year')}/"
        f"{int(match.group('number'))}/data.xml"
    )


def _external_legislation_identity(url: str) -> str:
    parts = [part for part in urlsplit(url).path.split("/") if part]
    if not parts or parts[0] not in {"ukpga", "uksi"}:
        raise ValueError("phase2a_external_legislation_url_invalid")
    pdf_index = parts.index("pdfs") if "pdfs" in parts else len(parts)
    identity_parts = parts[:pdf_index]
    if len(identity_parts) < 3:
        raise ValueError("phase2a_external_legislation_identity_incomplete")
    return ":".join(identity_parts)


def _search_url(citation: str, *, page: int) -> str:
    query = urlencode({"query": citation, "per_page": 50, "page": page})
    return f"https://caselaw.nationalarchives.gov.uk/atom.xml?{query}"


def _load_json(path: Path) -> Any:
    return json.loads(path.read_bytes())


def _phase2a_findings(package_root: Path) -> tuple[Mapping[str, Any], ...]:
    payload = _load_json(package_root / "official-source-provenance-register.json")
    findings = payload.get("payload", {}).get("external_official_findings", [])
    if not isinstance(findings, list) or len(findings) != 11:
        raise ValueError("phase2a_external_finding_register_invalid")
    return tuple(item for item in findings if isinstance(item, Mapping))


def _targets(
    *,
    candidate_manifest: Mapping[str, Any],
    findings: Iterable[Mapping[str, Any]],
    target_date: date,
    include_bulk_later_treatment_search: bool = False,
) -> tuple[dict[str, Any], ...]:
    targets: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    judgments: dict[str, dict[str, Any]] = {}
    for source in candidate_manifest.get("sources", []):
        authority = str(source.get("authority_identity_id") or "")
        source_version_id = str(source.get("source_version_id") or "")
        if authority.startswith(("ukpga:", "uksi:")):
            target = {
                "target_type": "candidate_legislation",
                "target_id": source_version_id,
                "authority_identity": authority,
                "title": source.get("title"),
                "expected_version_sha256": source.get("version_sha256"),
                "url": _point_in_time_url(authority, target_date),
                "page": None,
            }
            key = (target["target_type"], target["target_id"])
            if key not in seen:
                targets.append(target)
                seen.add(key)
            continue
        match = _NEUTRAL_CITATION.fullmatch(authority)
        if match is None:
            continue
        citation = (
            f"[{match.group('year')}] {match.group('court').upper()} {int(match.group('number'))}"
        )
        source_target = {
            "target_type": "candidate_judgment_source",
            "target_id": source_version_id,
            "authority_identity": authority,
            "title": source.get("title"),
            "expected_version_sha256": source.get("version_sha256"),
            "url": _candidate_judgment_url(source, authority),
            "page": None,
        }
        key = (source_target["target_type"], source_target["target_id"])
        if key not in seen:
            targets.append(source_target)
            seen.add(key)
        judgments.setdefault(
            citation,
            {
                "target_type": "later_treatment_search",
                "target_id": f"search:{citation}",
                "authority_identity": authority,
                "title": source.get("title"),
                "expected_version_sha256": None,
            },
        )
    for finding in findings:
        finding_id = str(finding.get("finding_id") or "")
        source_class = str(finding.get("source_class") or "")
        if source_class == "OFFICIAL_LEGISLATION":
            authority = _external_legislation_identity(str(finding.get("canonical_url") or ""))
            url = _point_in_time_url(authority, target_date)
        elif source_class == "OFFICIAL_BINDING_JUDGMENT":
            authority = str(finding.get("official_identifier") or "")
            url = _external_judgment_url(authority)
        else:
            raise ValueError("phase2a_external_finding_source_class_invalid")
        target = {
            "target_type": "external_finding_source",
            "target_id": finding_id,
            "authority_identity": authority,
            "title": finding.get("official_title"),
            "expected_version_sha256": None,
            "url": url,
            "page": None,
        }
        key = (target["target_type"], target["target_id"])
        if key in seen:
            raise ValueError("phase2a_official_target_duplicated")
        targets.append(target)
        seen.add(key)
    if include_bulk_later_treatment_search:
        for citation, base in sorted(judgments.items()):
            targets.append({**base, "url": _search_url(citation, page=1), "page": 1})
    return tuple(targets)


def _xml_root(raw: bytes) -> ET.Element:
    opening = raw[:100_000].upper()
    if b"<!DOCTYPE" in opening or b"<!ENTITY" in opening:
        raise ValueError("phase2a_official_xml_forbidden_declaration")
    return ET.fromstring(raw)


def _atom_entry_count(raw: bytes) -> int:
    root = _xml_root(raw)
    namespace = "{http://www.w3.org/2005/Atom}"
    if root.tag != f"{namespace}feed":
        raise ValueError("phase2a_later_treatment_feed_invalid")
    return len(root.findall(f"{namespace}entry"))


def _fetch(client: httpx.Client, url: str) -> tuple[str, int, str, bytes]:
    current = _safe_url(url)
    for _ in range(MAX_REDIRECTS + 1):
        with client.stream("GET", current) as response:
            status = int(response.status_code)
            if status in {301, 302, 303, 307, 308}:
                location = response.headers.get("location")
                if not location:
                    raise ValueError("phase2a_official_redirect_missing_location")
                current = _safe_url(urljoin(current, location))
                continue
            content_type = str(response.headers.get("content-type") or "").split(";", 1)[0]
            if status != 200:
                return current, status, content_type, b""
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_bytes():
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    raise ValueError("phase2a_official_response_too_large")
                chunks.append(chunk)
            raw = b"".join(chunks)
            if not raw:
                raise ValueError("phase2a_official_response_empty")
            if content_type in {
                "application/xml",
                "text/xml",
                "application/atom+xml",
                "application/xhtml+xml",
            }:
                _xml_root(raw)
            elif content_type == "text/html":
                if b"<html" not in raw[:100_000].casefold():
                    raise ValueError("phase2a_official_html_invalid")
            else:
                raise ValueError("phase2a_official_content_type_invalid")
            return current, status, content_type, raw
    raise ValueError("phase2a_official_redirect_limit_exceeded")


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


def _member_name(target: Mapping[str, Any], raw: bytes) -> str:
    target_type = re.sub(r"[^a-z0-9]+", "-", str(target["target_type"]).casefold()).strip("-")
    identity = hashlib.sha256(str(target["target_id"]).encode("utf-8")).hexdigest()[:16]
    page = f"-p{int(target['page']):03d}" if target.get("page") else ""
    extension = "html" if str(target.get("url") or "").casefold().endswith((".htm", ".html")) else "xml"
    return f"{target_type}-{identity}{page}-{_sha256(raw)[:16]}.{extension}"


def _next_search_target(target: Mapping[str, Any], entry_count: int) -> dict[str, Any] | None:
    if target.get("target_type") != "later_treatment_search" or entry_count < 50:
        return None
    page = int(target.get("page") or 1) + 1
    if page > 20:
        return None
    citation = str(target["target_id"]).removeprefix("search:")
    return {**target, "url": _search_url(citation, page=page), "page": page}


def collect(
    *,
    candidate_manifest_path: Path,
    package_root: Path,
    quarantine_root: Path,
    target_date: date,
    run_id: str,
    find_case_law_computational_analysis_licence_sha256: str | None = None,
) -> dict[str, Any]:
    if quarantine_root.exists():
        raise ValueError("phase2a_quarantine_root_already_exists")
    quarantine_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(quarantine_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_quarantine_root_mode_invalid")
    manifest = _load_json(candidate_manifest_path)
    licence_digest = str(find_case_law_computational_analysis_licence_sha256 or "")
    if licence_digest and not _SHA256.fullmatch(licence_digest):
        raise ValueError("phase2a_find_case_law_computational_analysis_licence_invalid")
    targets = list(
        _targets(
            candidate_manifest=manifest,
            findings=_phase2a_findings(package_root),
            target_date=target_date,
            include_bulk_later_treatment_search=bool(licence_digest),
        )
    )
    records: list[dict[str, Any]] = []
    with httpx.Client(
        follow_redirects=False,
        timeout=httpx.Timeout(30.0, connect=10.0),
        headers={"User-Agent": USER_AGENT, "Accept": "application/xml, application/atom+xml"},
        trust_env=False,
    ) as client:
        ordinal = 0
        index = 0
        while index < len(targets):
            target = targets[index]
            index += 1
            ordinal += 1
            requested_url = _safe_url(str(target["url"]))
            started = datetime.now(UTC)
            try:
                final_url, status, content_type, raw = _fetch(client, requested_url)
                if status == 200:
                    name = _member_name(target, raw)
                    _write_exclusive(quarantine_root / name, raw)
                    entry_count = (
                        _atom_entry_count(raw)
                        if target["target_type"] == "later_treatment_search"
                        else None
                    )
                    next_target = _next_search_target(target, entry_count or 0)
                    if next_target is not None:
                        targets.append(next_target)
                    result = "DOWNLOADED_QUARANTINED"
                    error_code = None
                else:
                    name = None
                    entry_count = None
                    result = "OFFICIAL_SOURCE_UNAVAILABLE"
                    error_code = f"http_{status}"
                raw_sha256 = _sha256(raw) if raw else None
                raw_bytes = len(raw)
            except Exception as exc:
                final_url = requested_url
                status = 0
                content_type = ""
                name = None
                entry_count = None
                result = "COLLECTION_FAILED"
                error_code = re.sub(r"(?<!^)(?=[A-Z])", "_", type(exc).__name__).casefold()
                raw_sha256 = None
                raw_bytes = 0
            records.append(
                {
                    "ordinal": ordinal,
                    "target_type": target["target_type"],
                    "target_id": target["target_id"],
                    "authority_identity": target.get("authority_identity"),
                    "title": target.get("title"),
                    "page": target.get("page"),
                    "requested_url": requested_url,
                    "final_url": final_url,
                    "http_status": status,
                    "content_type": content_type,
                    "retrieved_at": started.isoformat(timespec="seconds"),
                    "result": result,
                    "error_code": error_code,
                    "quarantine_member": name,
                    "sha256": raw_sha256,
                    "bytes": raw_bytes,
                    "atom_entry_count": entry_count,
                    "pagination_truncated_at_configured_limit": bool(
                        target["target_type"] == "later_treatment_search"
                        and int(target.get("page") or 0) == 20
                        and int(entry_count or 0) >= 50
                    ),
                    "expected_version_sha256": target.get("expected_version_sha256"),
                    "matches_expected_version_sha256": (
                        raw_sha256 == target.get("expected_version_sha256")
                        if raw_sha256 and target.get("expected_version_sha256")
                        else None
                    ),
                    "automatically_admitted": False,
                    "automatically_indexed": False,
                    "automatically_embedded": False,
                }
            )
    payload: dict[str, Any] = {
        "schema": "legalbot.v111-phase2a-official-source-quarantine.v1",
        "run_id": run_id,
        "phase": "2A",
        "target_ceiling": f"{target_date.isoformat()}T23:59:59+01:00 Europe/London",
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "allowlisted_hosts": sorted(ALLOWED_HOSTS),
        "quarantine_root_name": quarantine_root.name,
        "candidate_manifest_sha256": manifest.get("manifest_sha256"),
        "find_case_law_computational_analysis": {
            "terms_url": FIND_CASE_LAW_COMPUTATIONAL_ANALYSIS_TERMS_URL,
            "separate_licence_required": True,
            "licence_evidence_sha256": licence_digest or None,
            "bulk_later_treatment_search_authorized": bool(licence_digest),
            "bulk_later_treatment_search_omitted_when_unlicensed": not bool(
                licence_digest
            ),
        },
        "record_count": len(records),
        "records": records,
        "prohibitions": {
            "automatic_source_admission": True,
            "automatic_gold_change": True,
            "automatic_indexing": True,
            "automatic_embedding": True,
            "answer_model_invocation": True,
        },
    }
    material = dict(payload)
    payload["manifest_sha256"] = _sha256(_canonical_json(material))
    _write_exclusive(quarantine_root / "QUARANTINE-MANIFEST.json", _canonical_json(payload))
    return payload


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-manifest", type=Path, required=True)
    parser.add_argument("--phase2a-package-root", type=Path, required=True)
    parser.add_argument("--quarantine-root", type=Path, required=True)
    parser.add_argument("--target-date", type=date.fromisoformat, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument(
        "--find-case-law-computational-analysis-licence-sha256",
        help=(
            "SHA-256 of separately reviewed Find Case Law computational-analysis "
            "licence evidence. Omit to disable bulk later-treatment searches."
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    result = collect(
        candidate_manifest_path=args.candidate_manifest.resolve(strict=True),
        package_root=args.phase2a_package_root.resolve(strict=True),
        quarantine_root=args.quarantine_root.resolve(),
        target_date=args.target_date,
        run_id=str(args.run_id),
        find_case_law_computational_analysis_licence_sha256=(
            args.find_case_law_computational_analysis_licence_sha256
        ),
    )
    print(
        json.dumps(
            {
                "status": "complete",
                "record_count": result["record_count"],
                "manifest_sha256": result["manifest_sha256"],
                "automatically_admitted": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
