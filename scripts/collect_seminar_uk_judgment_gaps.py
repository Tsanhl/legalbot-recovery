#!/usr/bin/env python3
"""Collect exact seminar-only UK neutral-citation gaps from Find Case Law.

Teaching material is used only to discover citation identifiers and subject
labels.  Every downloaded byte comes from Find Case Law and must carry the
expected neutral citation in its official Akoma Ntoso metadata.  Ambiguous or
unavailable references are recorded, never guessed.  The resulting pack is
staged and non-authorising: no approval, embedding, candidate mutation, or
promotion occurs here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_AUDIT = PROJECT_ROOT / "data/reports/seminar-authority-coverage-2026-08-26-v4.json"
DEFAULT_SOURCE_ROOT = Path("/Users/hltsang/Desktop/Law")
DEFAULT_BASE_DIRECTORY = Path(
    "Official Legislation/seminar-gap-official-2026-08-26/uk-judgments-round2"
)
DEFAULT_MANIFEST = (
    PROJECT_ROOT / "config/seminar_gap_official_uk_judgments_round2.2026-08-26.v1.json"
)
EXISTING_PACKS = (
    PROJECT_ROOT / "config/pensions_seminar_gap_official_judgments.2026-08-26.v2.json",
)
MANIFEST_SCHEMA = "legalbot.seminar-gap-official-uk-judgment-plan.v1"
NEUTRAL = re.compile(
    r"^\[(?P<year>\d{4})\]\s+"
    r"(?P<court>UKSC|UKHL|UKPC|EWCA Civ|EWCA Crim|EWHC)\s+"
    r"(?P<number>\d+)(?:\s+\((?P<division>[A-Za-z]+)\))?$"
)
DIVISIONS = {
    "Admin": "admin",
    "Ch": "ch",
    "Comm": "comm",
    "Fam": "fam",
    "IPEC": "ipec",
    "KB": "kb",
    "Pat": "pat",
    "QB": "qb",
    "TCC": "tcc",
}
MAX_JUDGMENT_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class Request:
    citation: str
    citation_key: str
    court: str
    year: int
    number: int
    division: str | None
    official_url: str
    subjects: tuple[str, ...]
    presentation_document_count: int


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _first(root: ET.Element | None, name: str) -> ET.Element | None:
    if root is None:
        return None
    return next((item for item in root.iter() if _local_name(item.tag) == name), None)


def _attr(element: ET.Element | None, name: str) -> str:
    if element is None:
        return ""
    for key, value in element.attrib.items():
        if _local_name(key) == name:
            return str(value).strip()
    return ""


def _text(element: ET.Element | None) -> str:
    return " ".join("".join(element.itertext()).split()) if element is not None else ""


def _citation_key(value: str) -> str:
    return re.sub(r"\s+\([A-Za-z]+\)$", "", " ".join(value.split()))


def _jurisdiction(court: str) -> str:
    return "United Kingdom" if court in {"UKSC", "UKHL", "UKPC"} else "England and Wales"


def _court_slug(court: str) -> tuple[str, ...]:
    return {
        "UKSC": ("uksc",),
        "UKHL": ("ukhl",),
        "UKPC": ("ukpc",),
        "EWCA Civ": ("ewca", "civ"),
        "EWCA Crim": ("ewca", "crim"),
    }[court]


def _request(reference: dict[str, Any]) -> tuple[Request | None, str | None]:
    citation = str(reference.get("reference") or "")
    match = NEUTRAL.fullmatch(citation)
    if match is None:
        return None, "neutral_citation_shape_invalid"
    court = match.group("court")
    year = int(match.group("year"))
    number = int(match.group("number"))
    division = match.group("division")
    if court == "EWHC" and not division:
        return None, "ewhc_division_missing"
    if court == "EWHC":
        division_slug = DIVISIONS.get(str(division))
        if not division_slug:
            return None, "ewhc_division_unsupported"
        parts = ("ewhc", division_slug)
    else:
        parts = _court_slug(court)
    url = "https://caselaw.nationalarchives.gov.uk/" + "/".join(
        (*parts, str(year), str(number), "data.xml")
    )
    return (
        Request(
            citation=citation,
            citation_key=_citation_key(citation),
            court=court,
            year=year,
            number=number,
            division=division,
            official_url=url,
            subjects=tuple(sorted(str(value) for value in reference["presentation_subjects"])),
            presentation_document_count=int(reference["presentation_document_count"]),
        ),
        None,
    )


def _download(request: Request) -> tuple[bytes, str, str]:
    parsed = urllib.parse.urlsplit(request.official_url)
    if parsed.scheme != "https" or parsed.hostname != "caselaw.nationalarchives.gov.uk":
        raise ValueError("find_case_law_url_invalid")
    web_request = urllib.request.Request(
        request.official_url,
        headers={
            "Accept": "application/xml",
            "User-Agent": "LegalBot-clean-room-source-collector/1.0",
        },
    )
    with urllib.request.urlopen(web_request, timeout=60) as response:
        final = urllib.parse.urlsplit(response.geturl())
        if final.scheme != "https" or final.hostname != "caselaw.nationalarchives.gov.uk":
            raise ValueError("find_case_law_redirect_invalid")
        raw = response.read(MAX_JUDGMENT_BYTES + 1)
    if not raw or len(raw) > MAX_JUDGMENT_BYTES:
        raise ValueError("find_case_law_response_size_invalid")
    opening = raw[:100_000].upper()
    if b"<!DOCTYPE" in opening or b"<!ENTITY" in opening:
        raise ValueError("find_case_law_xml_unsafe_declaration")
    root = ET.fromstring(raw)
    if _local_name(root.tag) != "akomaNtoso":
        raise ValueError("find_case_law_xml_root_invalid")
    judgment = _first(root, "judgment")
    work = _first(judgment, "FRBRWork")
    expression = _first(judgment, "FRBRExpression")
    proprietary = _first(judgment, "proprietary")
    title = _attr(_first(work, "FRBRname"), "value")
    citation = _text(_first(proprietary, "cite"))
    uri = _attr(_first(expression, "FRBRthis"), "value")
    if _citation_key(citation) != request.citation_key:
        raise ValueError(f"official_neutral_citation_mismatch:{citation}")
    if not title:
        raise ValueError("official_judgment_title_missing")
    if uri != request.official_url.removesuffix("/data.xml"):
        raise ValueError("official_judgment_uri_mismatch")
    return raw, title, citation


def _write_exclusive(path: Path, value: bytes, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        mode,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def collect(
    *,
    audit_path: Path,
    source_root: Path,
    manifest_path: Path,
    workers: int,
) -> dict[str, Any]:
    if manifest_path.exists():
        raise ValueError("uk_judgment_gap_manifest_already_exists")
    source_root_resolved = source_root.resolve(strict=True)
    destination = (source_root_resolved / DEFAULT_BASE_DIRECTORY).resolve(strict=False)
    destination.relative_to(source_root_resolved)
    if destination.exists():
        raise ValueError("uk_judgment_gap_destination_already_exists")
    audit = json.loads(audit_path.read_bytes())
    if audit.get("schema") != "legalbot.seminar-authority-coverage-audit.v3":
        raise ValueError("seminar_audit_schema_invalid")

    excluded_keys: set[str] = set()
    existing_pack_hashes: list[dict[str, str]] = []
    for path in EXISTING_PACKS:
        pack = json.loads(path.read_bytes())
        for target in pack.get("targets", []):
            excluded_keys.add(_citation_key(str(target.get("authority_identity") or "")))
        existing_pack_hashes.append({"file": path.name, "sha256": _sha256(path.read_bytes())})

    unresolved: list[dict[str, Any]] = []
    requests: list[Request] = []
    for reference in audit["references"]:
        if not (
            reference.get("kind") == "neutral_citation"
            and reference.get("coverage_status") == "catalogue_missing"
            and int(reference.get("presentation_document_count") or 0) > 0
        ):
            continue
        request, reason = _request(reference)
        if request is None:
            unresolved.append(
                {
                    "authority_identity": reference["reference"],
                    "subjects": sorted(reference["presentation_subjects"]),
                    "reason_code": reason,
                }
            )
        elif request.citation_key in excluded_keys:
            unresolved.append(
                {
                    "authority_identity": request.citation,
                    "subjects": list(request.subjects),
                    "reason_code": "already_staged_in_existing_official_pack",
                }
            )
        else:
            requests.append(request)

    outcomes: dict[str, tuple[Request, bytes, str, str]] = {}
    with ThreadPoolExecutor(max_workers=workers) as executor:
        pending = {executor.submit(_download, request): request for request in requests}
        for future in as_completed(pending):
            request = pending[future]
            try:
                raw, title, official_citation = future.result()
                outcomes[request.citation] = (request, raw, title, official_citation)
            except urllib.error.HTTPError as exc:
                unresolved.append(
                    {
                        "authority_identity": request.citation,
                        "subjects": list(request.subjects),
                        "reason_code": "find_case_law_http_error",
                        "http_status": int(exc.code),
                    }
                )
            except Exception as exc:
                unresolved.append(
                    {
                        "authority_identity": request.citation,
                        "subjects": list(request.subjects),
                        "reason_code": "official_download_or_identity_failure",
                        "failure_fingerprint": f"{type(exc).__name__}:{exc}",
                    }
                )

    destination.mkdir(parents=True, exist_ok=False)
    targets: list[dict[str, Any]] = []
    for citation in sorted(outcomes):
        request, raw, title, official_citation = outcomes[citation]
        court_parts = (
            ("ewhc", str(request.division).casefold())
            if request.court == "EWHC"
            else _court_slug(request.court)
        )
        filename = "-".join((*court_parts, str(request.year), str(request.number), "data.xml"))
        jurisdiction = _jurisdiction(request.court)
        relative_path = DEFAULT_BASE_DIRECTORY / jurisdiction / filename
        output = source_root_resolved / relative_path
        _write_exclusive(output, raw, mode=0o444)
        targets.append(
            {
                "authority_identity": official_citation,
                "source_title": title,
                "official_url": request.official_url,
                "source_root_relative_path": str(relative_path),
                "content_sha256": _sha256(raw),
                "byte_count": len(raw),
                "jurisdiction_expected": jurisdiction,
                "presentation_subjects": list(request.subjects),
                "presentation_document_count": request.presentation_document_count,
                "identity_verified_from_official_xml": True,
                "later_treatment_status": "owner_review_required",
            }
        )

    manifest: dict[str, Any] = {
        "schema": MANIFEST_SCHEMA,
        "version": "seminar-gap-uk-judgments-round2-2026-08-26-v1",
        "download_date": "2026-08-26",
        "source": "https://caselaw.nationalarchives.gov.uk/",
        "source_root_relative_directory": str(DEFAULT_BASE_DIRECTORY),
        "seminar_audit": {
            "file": audit_path.name,
            "sha256": _sha256(audit_path.read_bytes()),
        },
        "existing_official_packs": existing_pack_hashes,
        "teaching_lane_use": "issue_discovery_only_never_legal_authority",
        "targets": targets,
        "unresolved_references": sorted(
            unresolved,
            key=lambda item: (str(item["reason_code"]), str(item["authority_identity"])),
        ),
        "automatic_source_admission": False,
        "automatic_currentness_approval": False,
        "automatic_later_treatment_approval": False,
        "automatic_gold_change": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutation_authorized": False,
        "active_promotion_authorized": False,
        "development30_authorized": False,
        "validation30_authorized": False,
        "live_activation_authorized": False,
    }
    rendered = (
        json.dumps(
            manifest,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )
    _write_exclusive(manifest_path, rendered, mode=0o600)
    return {
        "target_count": len(targets),
        "unresolved_count": len(unresolved),
        "unresolved_by_reason": dict(
            sorted(
                {
                    reason: sum(item["reason_code"] == reason for item in unresolved)
                    for reason in {str(item["reason_code"]) for item in unresolved}
                }.items()
            )
        ),
        "manifest": str(manifest_path),
        "automatic_embedding": False,
        "active_promotion_authorized": False,
    }


def main() -> None:
    arguments = argparse.ArgumentParser()
    arguments.add_argument("--audit", type=Path, default=DEFAULT_AUDIT)
    arguments.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    arguments.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    arguments.add_argument("--workers", type=int, default=8)
    args = arguments.parse_args()
    if not 1 <= args.workers <= 8:
        raise ValueError("uk_judgment_gap_worker_count_invalid")
    print(
        json.dumps(
            collect(
                audit_path=args.audit,
                source_root=args.source_root,
                manifest_path=args.manifest,
                workers=args.workers,
            ),
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
