#!/usr/bin/env python3
"""Download immutable latest-available legislation XML from Legislation.gov.uk."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from xml.etree import ElementTree as ET

import httpx

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = PROJECT_ROOT / "config" / "current_legislation_pack.json"
DEFAULT_REPORT = PROJECT_ROOT / "data" / "review_queue" / "current-legislation-download.json"
OFFICIAL_ORIGIN = "https://www.legislation.gov.uk"
MAX_XML_BYTES = 96 * 1024 * 1024


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--destination-root", type=Path, required=True)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    return parser


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _element_text(root: ET.Element, name: str) -> str:
    for element in root.iter():
        if _local_name(element.tag) == name:
            return " ".join("".join(element.itertext()).split())
    return ""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _normalise_title(value: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", value.casefold()))


def _load_manifest(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") != "legalbot.current-legislation-pack.v1":
        raise ValueError("unsupported current legislation manifest")
    if payload.get("source") != f"{OFFICIAL_ORIGIN}/":
        raise ValueError("current legislation origin is not allowlisted")
    if not re.fullmatch(r"20\d{2}-\d{2}-\d{2}", str(payload.get("as_of_date") or "")):
        raise ValueError("manifest as-of date is invalid")
    identities: set[str] = set()
    for item in payload.get("items") or []:
        identity = str(item.get("identity") or "")
        title = " ".join(str(item.get("title") or "").split())
        folder = " ".join(str(item.get("subject_folder") or "").split())
        if not re.fullmatch(r"(?:ukpga|uksi)/[A-Za-z0-9-]+(?:/[A-Za-z0-9-]+){1,3}", identity):
            raise ValueError(f"invalid legislation identity: {identity}")
        if not title or not folder or identity in identities:
            raise ValueError("current legislation metadata is incomplete or duplicated")
        identities.add(identity)
    if not identities:
        raise ValueError("current legislation manifest is empty")
    return payload


def _official_url(identity: str) -> str:
    url = f"{OFFICIAL_ORIGIN}/{identity}/data.xml"
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "www.legislation.gov.uk":
        raise ValueError("official legislation URL escaped the allowlist")
    return url


def _verify_xml(raw: bytes, *, item: dict[str, Any]) -> dict[str, Any]:
    opening = raw[:100_000].upper()
    if b"<!DOCTYPE" in opening or b"<!ENTITY" in opening:
        raise ValueError("official XML contains a prohibited DTD or entity declaration")
    root = ET.fromstring(raw)
    if _local_name(root.tag) != "Legislation":
        raise ValueError("official endpoint did not return legislation XML")
    expected_uri = f"http://www.legislation.gov.uk/{item['identity']}"
    if root.attrib.get("DocumentURI") != expected_uri:
        raise ValueError("official XML identity does not match the reviewed manifest")
    title = _element_text(root, "title")
    if _normalise_title(title) != _normalise_title(str(item["title"])):
        raise ValueError(f"official XML title mismatch: {title!r}")
    document_status = ""
    for element in root.iter():
        if _local_name(element.tag) == "DocumentStatus":
            document_status = str(element.attrib.get("Value") or "")
            break
    return {
        "title": title,
        "source_modified": _element_text(root, "modified") or None,
        "source_valid_from": _element_text(root, "valid") or None,
        "restrict_start_date": root.attrib.get("RestrictStartDate"),
        "document_status": document_status or None,
        "unapplied_effect_count": sum(
            1 for element in root.iter() if _local_name(element.tag) == "UnappliedEffect"
        ),
        "number_of_provisions": int(root.attrib.get("NumberOfProvisions") or 0),
    }


def _target_path(destination: Path, item: dict[str, Any], as_of_date: str) -> Path:
    identity_leaf = str(item["identity"]).replace("/", "_")
    return (
        destination
        / "Official Legislation"
        / "United Kingdom"
        / "Current"
        / str(item["subject_folder"])
        / f"{identity_leaf}__retrieved-{as_of_date}.xml"
    )


def _download(client: httpx.Client, item: dict[str, Any], target: Path) -> dict[str, Any]:
    url = _official_url(str(item["identity"]))
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raw = target.read_bytes()
        metadata = _verify_xml(raw, item=item)
        return {
            **metadata,
            "identity": item["identity"],
            "status": "already_present",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
            "canonical_url": url,
        }
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".current-law-incoming-", dir=target.parent
    )
    temporary = Path(temporary_name)
    try:
        total = 0
        with (
            os.fdopen(descriptor, "wb") as output,
            client.stream(
                "GET",
                url,
                headers={"Accept": "application/xml", "User-Agent": "LegalBotResearch/1.0"},
            ) as response,
        ):
            response.raise_for_status()
            if "xml" not in response.headers.get("content-type", "").casefold():
                raise ValueError("official endpoint did not return XML")
            for block in response.iter_bytes(1024 * 1024):
                total += len(block)
                if total > MAX_XML_BYTES:
                    raise ValueError("official legislation XML exceeds the size limit")
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
        raw = temporary.read_bytes()
        metadata = _verify_xml(raw, item=item)
        os.chmod(temporary, 0o444)
        os.replace(temporary, target)
        return {
            **metadata,
            "identity": item["identity"],
            "status": "downloaded",
            "sha256": _sha256(target),
            "bytes": len(raw),
            "canonical_url": url,
        }
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    args = _parser().parse_args()
    manifest = _load_manifest(args.manifest)
    destination = args.destination_root.expanduser().resolve()
    if not destination.is_dir():
        raise SystemExit("destination source root does not exist")
    items: list[dict[str, Any]] = []
    with httpx.Client(timeout=60, follow_redirects=False, trust_env=False) as client:
        for item in manifest["items"]:
            result = _download(
                client,
                item,
                _target_path(destination, item, str(manifest["as_of_date"])),
            )
            items.append(result)
            print(
                f"{result['identity']}: {result['status']} "
                f"({result['number_of_provisions']} provisions; "
                f"{result['unapplied_effect_count']} unapplied effects)"
            )
    report = {
        "schema": "legalbot.current-legislation-download-report.v1",
        "manifest_version": manifest["version"],
        "as_of_date": manifest["as_of_date"],
        "created_at": datetime.now(UTC).isoformat(),
        "licence": manifest["licence"],
        "items": items,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    temporary_report = args.report.with_suffix(".tmp")
    temporary_report.write_text(
        json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary_report, args.report)
    print(f"complete: {len(items)} immutable current-law snapshots verified")


if __name__ == "__main__":
    main()
