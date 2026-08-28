#!/usr/bin/env python3
"""Quarantine official-source bytes for the 89-row Phase-2A rebinding queue.

The collector accepts only the sealed queue, derives a fixed official-host
target set, and writes create-only quarantine members.  Retrieved material is
staging evidence only and is never admitted, indexed, embedded, or qualified.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from collections import Counter, defaultdict
from collections.abc import Mapping
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit
from xml.etree import ElementTree as ET

import httpx

QUEUE_SCHEMA = "legalbot.v111.phase2a.official-rebinding-queue.v1"
EXPECTED_QUEUE_COUNT = 89
ALLOWED_HOSTS = frozenset(
    {
        "legislation.gov.uk",
        "www.legislation.gov.uk",
        "justice.gov.uk",
        "www.justice.gov.uk",
        "judiciary.uk",
        "www.judiciary.uk",
    }
)
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_REDIRECTS = 5
USER_AGENT = "LegalBot-v1.11-Phase2A-rebinding-review/1.0"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PDF_LINK = re.compile(
    rb"href\s*=\s*['\"](?P<url>[^'\"]+\.pdf(?:\?[^'\"]*)?)['\"]",
    re.IGNORECASE,
)
_JUSTICE_CANONICAL_PATHS = {
    "/courts/procedure-rules/civil/rules/part44": (
        "/courts/procedure-rules/civil/rules/part-44-general-rules-about-costs"
    ),
}


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_rebinding_collection_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_rebinding_collection_input_must_be_object")
    return value


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or supplied != _sealed(material):
        raise ValueError(code)
    return supplied


def _safe_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    host = (parsed.hostname or "").casefold()
    if parsed.scheme != "https" or host not in ALLOWED_HOSTS:
        raise ValueError("phase2a_rebinding_official_url_outside_allowlist")
    if parsed.username or parsed.password or parsed.fragment or parsed.port not in (None, 443):
        raise ValueError("phase2a_rebinding_official_url_forbidden_component")
    return urlunsplit(("https", parsed.netloc.casefold(), parsed.path or "/", parsed.query, ""))


def _split_official_urls(value: str) -> tuple[str, ...]:
    urls = tuple(_safe_url(item) for item in value.split(";") if item.strip())
    if not urls:
        raise ValueError("phase2a_rebinding_official_url_missing")
    return urls


def _target_url(value: str, target_date: date) -> tuple[str, str]:
    safe = _safe_url(value)
    parsed = urlsplit(safe)
    host = (parsed.hostname or "").casefold()
    parts = [part for part in parsed.path.split("/") if part]
    if host in {"legislation.gov.uk", "www.legislation.gov.uk"}:
        if len(parts) < 3 or parts[0] not in {"ukpga", "uksi", "eur"}:
            raise ValueError("phase2a_rebinding_legislation_identity_invalid")
        # Older Public General Acts use a regnal/session/chapter identity, for
        # example ``ukpga/Geo5/15-16/19``.  Modern year/chapter and retained-EU
        # identities use three path components.
        identity_length = (
            4
            if parts[0] == "ukpga"
            and not re.fullmatch(r"\d{4}", parts[1])
            and len(parts) >= 4
            else 3
        )
        base = "/".join(parts[:identity_length])
        return (
            f"https://www.legislation.gov.uk/{base}/{target_date.isoformat()}/data.xml",
            "point_in_time_legislation_xml",
        )
    if host in {"justice.gov.uk", "www.justice.gov.uk"}:
        canonical_path = _JUSTICE_CANONICAL_PATHS.get(parsed.path.rstrip("/"), parsed.path)
        canonical = urlunsplit(("https", "www.justice.gov.uk", canonical_path, parsed.query, ""))
        return canonical, "current_official_procedural_rule_html"
    if host in {"judiciary.uk", "www.judiciary.uk"}:
        return safe, "official_judgment_landing_html"
    raise ValueError("phase2a_rebinding_official_target_unsupported")


def _targets(queue: Mapping[str, Any], target_date: date) -> list[dict[str, Any]]:
    by_target: dict[str, dict[str, Any]] = {}
    for item in queue.get("items", []):
        row_id = str(item.get("row_id") or "")
        for supplied in _split_official_urls(str(item.get("official_source_url") or "")):
            url, target_type = _target_url(supplied, target_date)
            target = by_target.setdefault(
                url,
                {
                    "target_id": f"official-{_sha256(url.encode())[:24]}",
                    "target_type": target_type,
                    "url": url,
                    "row_ids": [],
                    "supplied_source_urls": [],
                },
            )
            if target["target_type"] != target_type:
                raise ValueError("phase2a_rebinding_target_type_conflict")
            target["row_ids"].append(row_id)
            target["supplied_source_urls"].append(supplied)
    for target in by_target.values():
        target["row_ids"] = sorted(set(target["row_ids"]))
        target["supplied_source_urls"] = sorted(set(target["supplied_source_urls"]))
    return sorted(by_target.values(), key=lambda item: str(item["url"]))


def _xml_is_safe(raw: bytes) -> None:
    opening = raw[:100_000].upper()
    if b"<!DOCTYPE" in opening or b"<!ENTITY" in opening:
        raise ValueError("phase2a_rebinding_xml_forbidden_declaration")
    ET.fromstring(raw)


def _fetch(client: httpx.Client, url: str) -> tuple[str, int, str, bytes]:
    current = _safe_url(url)
    for _ in range(MAX_REDIRECTS + 1):
        with client.stream("GET", current) as response:
            status = int(response.status_code)
            if status in {301, 302, 303, 307, 308}:
                location = response.headers.get("location")
                if not location:
                    raise ValueError("phase2a_rebinding_redirect_missing_location")
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
                    raise ValueError("phase2a_rebinding_response_too_large")
                chunks.append(chunk)
            raw = b"".join(chunks)
            if not raw:
                raise ValueError("phase2a_rebinding_response_empty")
            if content_type in {"application/xml", "text/xml", "application/atom+xml"}:
                _xml_is_safe(raw)
            return current, status, content_type, raw
    raise ValueError("phase2a_rebinding_redirect_limit_exceeded")


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


def _member_name(target: Mapping[str, Any], raw: bytes, content_type: str) -> str:
    extension = {
        "application/xml": "xml",
        "text/xml": "xml",
        "application/atom+xml": "xml",
        "application/pdf": "pdf",
        "text/html": "html",
    }.get(content_type, "bin")
    return f"{target['target_id']}-{_sha256(raw)[:16]}.{extension}"


def _linked_judgment_pdfs(final_url: str, raw: bytes) -> tuple[str, ...]:
    linked: set[str] = set()
    for match in _PDF_LINK.finditer(raw):
        candidate = _safe_url(urljoin(final_url, match.group("url").decode("utf-8", "strict")))
        if urlsplit(candidate).path.casefold().endswith(".pdf"):
            linked.add(candidate)
    return tuple(sorted(linked))


def collect(
    *, queue_path: Path, quarantine_root: Path, target_date: date, run_id: str
) -> dict[str, Any]:
    """Collect fixed official targets without granting any admission authority."""

    if quarantine_root.exists() or quarantine_root.is_symlink():
        raise ValueError("phase2a_rebinding_quarantine_already_exists")
    quarantine_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(quarantine_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_rebinding_quarantine_mode_invalid")
    queue = _load_object(queue_path)
    queue_sha256 = _verify_seal(
        queue,
        "artifact_content_sha256",
        "phase2a_rebinding_queue_seal_invalid",
    )
    if (
        queue.get("schema") != QUEUE_SCHEMA
        or queue.get("item_count") != EXPECTED_QUEUE_COUNT
        or queue.get("automatic_source_admission") is not False
        or queue.get("phase2b_authorized") is not False
        or queue.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_rebinding_queue_boundary_invalid")

    targets = _targets(queue, target_date)
    records: list[dict[str, Any]] = []
    row_target_ids: dict[str, set[str]] = defaultdict(set)
    with httpx.Client(
        follow_redirects=False,
        timeout=httpx.Timeout(30.0, connect=10.0),
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/xml, text/html, application/pdf",
        },
        trust_env=False,
    ) as client:
        index = 0
        while index < len(targets):
            target = targets[index]
            index += 1
            requested_url = _safe_url(str(target["url"]))
            started = datetime.now(UTC)
            try:
                final_url, status, content_type, raw = _fetch(client, requested_url)
                if status == 200:
                    member = _member_name(target, raw, content_type)
                    _write_exclusive(quarantine_root / member, raw)
                    result = "DOWNLOADED_QUARANTINED"
                    error_code = None
                    if target["target_type"] == "official_judgment_landing_html":
                        for ordinal, pdf_url in enumerate(
                            _linked_judgment_pdfs(final_url, raw), start=1
                        ):
                            targets.append(
                                {
                                    "target_id": f"{target['target_id']}-pdf-{ordinal:02d}",
                                    "target_type": "official_judgment_pdf",
                                    "url": pdf_url,
                                    "row_ids": target["row_ids"],
                                    "supplied_source_urls": [final_url],
                                    "parent_target_id": target["target_id"],
                                }
                            )
                else:
                    member = None
                    result = "OFFICIAL_SOURCE_UNAVAILABLE"
                    error_code = f"http_{status}"
                raw_sha256 = _sha256(raw) if raw else None
                raw_bytes = len(raw)
            except Exception as exc:
                final_url = requested_url
                status = 0
                content_type = ""
                raw = b""
                member = None
                result = "COLLECTION_FAILED"
                error_code = re.sub(r"(?<!^)(?=[A-Z])", "_", type(exc).__name__).casefold()
                raw_sha256 = None
                raw_bytes = 0
            record_material = {
                "ordinal": len(records) + 1,
                "target_id": target["target_id"],
                "target_type": target["target_type"],
                "parent_target_id": target.get("parent_target_id"),
                "row_ids": target["row_ids"],
                "supplied_source_urls": target["supplied_source_urls"],
                "requested_url": requested_url,
                "final_url": final_url,
                "http_status": status,
                "content_type": content_type,
                "retrieved_at": started.isoformat(timespec="seconds"),
                "result": result,
                "error_code": error_code,
                "quarantine_member": member,
                "sha256": raw_sha256,
                "bytes": raw_bytes,
                "point_in_time_target_date": (
                    target_date.isoformat()
                    if target["target_type"] == "point_in_time_legislation_xml"
                    else None
                ),
                "automatic_source_admission": False,
                "automatic_indexing": False,
                "automatic_embedding": False,
            }
            record = {
                **record_material,
                "record_content_sha256": _sealed(record_material),
            }
            records.append(record)
            for row_id in target["row_ids"]:
                row_target_ids[row_id].add(str(target["target_id"]))

    queue_rows = {str(item.get("row_id") or "") for item in queue.get("items", [])}
    if set(row_target_ids) != queue_rows:
        raise ValueError("phase2a_rebinding_collection_row_coverage_incomplete")
    manifest_material = {
        "schema": "legalbot.v111.phase2a.official-rebinding-quarantine.v1",
        "status": "OFFICIAL_BYTES_QUARANTINED_NOT_ADMITTED",
        "run_id": run_id,
        "target_ceiling": f"{target_date.isoformat()}T23:59:59+01:00 Europe/London",
        "source_queue_content_sha256": queue_sha256,
        "source_queue_file_sha256": _sha256_file(queue_path),
        "allowlisted_hosts": sorted(ALLOWED_HOSTS),
        "quarantine_root_name": quarantine_root.name,
        "record_count": len(records),
        "result_counts": dict(
            sorted(
                Counter(str(record["result"]) for record in records).items()
            )
        ),
        "covered_row_count": len(row_target_ids),
        "row_target_ids": {
            row_id: sorted(target_ids) for row_id, target_ids in sorted(row_target_ids.items())
        },
        "records": records,
        "automatic_source_admission": False,
        "automatic_gold_change": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    manifest = {
        **manifest_material,
        "manifest_content_sha256": _sealed(manifest_material),
    }
    _write_exclusive(
        quarantine_root / "QUARANTINE-MANIFEST.json", _canonical_json(manifest)
    )
    return manifest


def _persist_failure(root: Path, exc: BaseException) -> None:
    try:
        root.mkdir(parents=True, mode=0o700, exist_ok=True)
        path = root / "FAILURE.json"
        if path.exists():
            return
        material = {
            "schema": "legalbot.v111.phase2a.rebinding-collection-failure.v1",
            "exception_type": type(exc).__name__,
            "error": str(exc),
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        _write_exclusive(
            path,
            _canonical_json({**material, "failure_content_sha256": _sealed(material)}),
        )
    except Exception:
        return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", required=True, type=Path)
    parser.add_argument("--quarantine-root", required=True, type=Path)
    parser.add_argument("--target-date", required=True, type=date.fromisoformat)
    parser.add_argument("--run-id", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = collect(
            queue_path=args.queue.resolve(strict=True),
            quarantine_root=args.quarantine_root.resolve(),
            target_date=args.target_date,
            run_id=str(args.run_id),
        )
    except Exception as exc:
        _persist_failure(args.quarantine_root.resolve(), exc)
        raise
    print(
        json.dumps(
            {
                "status": result["status"],
                "record_count": result["record_count"],
                "result_counts": result["result_counts"],
                "covered_row_count": result["covered_row_count"],
                "manifest_content_sha256": result["manifest_content_sha256"],
                "automatic_source_admission": False,
            },
            sort_keys=True,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
