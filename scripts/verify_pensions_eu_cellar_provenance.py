#!/usr/bin/env python3
"""Bind staged Pensions EU judgments to official Cellar item streams.

This is an independent provenance check for legacy streams that do not embed a
CELEX token in their judgment body.  It follows the official Cellar tree notice
from CELEX work to English HTML/XHTML manifestation to DOC_1, then compares the
downloaded official item bytes with the already staged corpus bytes.  It does
not approve, embed, index, or promote any source.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = (
    PROJECT_ROOT / "config/pensions_seminar_gap_official_eu_judgments.2026-08-26.v1.json"
)
DEFAULT_SOURCE_ROOT = Path("/Users/hltsang/Desktop/Law")
DEFAULT_EVIDENCE_DIR = PROJECT_ROOT / "data/review_queue/pensions-eu-cellar-notices-2026-08-26"
DEFAULT_OUTPUT = PROJECT_ROOT / "data/review_queue/pensions-eu-cellar-provenance-2026-08-26.json"
REPORT_SCHEMA = "legalbot.pensions-eu-cellar-provenance.v1"
MAX_NOTICE_BYTES = 32 * 1024 * 1024
MAX_ITEM_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class ManifestationCandidate:
    kind: str
    item_uri: str
    stream_size: int | None


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _write_exclusive(path: Path, value: bytes, *, mode: int = 0o600) -> None:
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


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child_values(element: ET.Element, name: str) -> list[str]:
    values: list[str] = []
    for candidate in element.iter():
        if _local_name(candidate.tag) != name:
            continue
        value = "".join(candidate.itertext()).strip()
        if value:
            values.append(value)
    return values


def _official_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname != "publications.europa.eu":
        raise ValueError("non_official_cellar_url")
    return urllib.parse.urlunsplit(("https", parsed.netloc, parsed.path, parsed.query, ""))


def _download(url: str, *, headers: dict[str, str], max_bytes: int) -> bytes:
    request = urllib.request.Request(
        _official_url(url),
        headers={"User-Agent": "LegalBot-clean-room-source-verifier/1.0", **headers},
    )
    with urllib.request.urlopen(request, timeout=90) as response:
        final = urllib.parse.urlsplit(response.geturl())
        if final.scheme not in {"http", "https"} or final.hostname != "publications.europa.eu":
            raise ValueError("cellar_redirect_left_official_host")
        raw = response.read(max_bytes + 1)
    if not raw or len(raw) > max_bytes:
        raise ValueError("cellar_response_size_invalid")
    return raw


def _notice_candidates(raw: bytes, *, celex: str) -> tuple[str, list[ManifestationCandidate]]:
    opening = raw[:100_000].upper()
    if b"<!DOCTYPE" in opening or b"<!ENTITY" in opening:
        raise ValueError("cellar_notice_unsafe_declaration")
    root = ET.fromstring(raw)
    if _local_name(root.tag) != "NOTICE":
        raise ValueError("cellar_notice_root_invalid")
    all_values = _child_values(root, "VALUE")
    celex_work = f"http://publications.europa.eu/resource/celex/{celex}"
    if celex_work not in all_values:
        raise ValueError("cellar_notice_celex_work_missing")
    work_uris = [
        value
        for value in all_values
        if re.fullmatch(r"http://publications\.europa\.eu/resource/cellar/[0-9a-f-]{36}", value)
    ]
    if not work_uris:
        raise ValueError("cellar_notice_work_uri_missing")

    candidates: list[ManifestationCandidate] = []
    for manifestation in root.iter():
        if _local_name(manifestation.tag) != "MANIFESTATION":
            continue
        values = _child_values(manifestation, "VALUE")
        kind = str(manifestation.attrib.get("manifestation-type") or "").casefold()
        expected_same_as = f"http://publications.europa.eu/resource/celex/{celex}.ENG.{kind}"
        if kind not in {"html", "xhtml"} or expected_same_as not in values:
            continue
        for item in manifestation:
            if _local_name(item.tag) != "MANIFESTATION_HAS_ITEM":
                continue
            item_values = _child_values(item, "VALUE")
            item_uris = [
                value
                for value in item_values
                if re.fullmatch(
                    r"http://publications\.europa\.eu/resource/cellar/[^/]+/DOC_1",
                    value,
                )
            ]
            sizes: list[int] = []
            for element in item.iter():
                if _local_name(element.tag) != "STREAM_SIZE":
                    continue
                sizes.extend(
                    int(value) for value in _child_values(element, "VALUE") if value.isdigit()
                )
            if item_uris:
                candidates.append(
                    ManifestationCandidate(
                        kind=kind,
                        item_uri=item_uris[0],
                        stream_size=sizes[0] if sizes else None,
                    )
                )
    if not candidates:
        raise ValueError("cellar_notice_english_html_item_missing")
    return work_uris[0], candidates


def _verify_target(target: dict[str, Any], source_root: Path) -> dict[str, Any]:
    celex = str(target["celex"])
    expected_hash = str(target["content_sha256"])
    source_path = (source_root / str(target["source_root_relative_path"])).resolve(strict=True)
    source_path.relative_to(source_root)
    if source_path.is_symlink() or not source_path.is_file():
        raise ValueError("staged_source_not_regular_file")
    staged = source_path.read_bytes()
    if _sha256(staged) != expected_hash or len(staged) != int(target["byte_count"]):
        raise ValueError("staged_source_manifest_identity_mismatch")
    notice_url = f"https://publications.europa.eu/resource/celex/{celex}"
    notice = _download(
        notice_url,
        headers={
            "Accept": "application/xml;notice=tree",
            "Accept-Language": "eng",
        },
        max_bytes=MAX_NOTICE_BYTES,
    )
    work_uri, candidates = _notice_candidates(notice, celex=celex)
    ordered = sorted(
        candidates,
        key=lambda candidate: (
            candidate.stream_size != len(staged),
            candidate.kind != "html",
            candidate.item_uri,
        ),
    )
    attempts: list[dict[str, Any]] = []
    selected: ManifestationCandidate | None = None
    for candidate in ordered:
        item = _download(
            candidate.item_uri,
            headers={"Accept": "text/html,application/xhtml+xml"},
            max_bytes=MAX_ITEM_BYTES,
        )
        actual_hash = _sha256(item)
        attempts.append(
            {
                "kind": candidate.kind,
                "item_uri": candidate.item_uri,
                "stream_size": candidate.stream_size,
                "downloaded_byte_count": len(item),
                "downloaded_sha256": actual_hash,
                "matches_staged_bytes": actual_hash == expected_hash,
            }
        )
        if actual_hash == expected_hash:
            selected = candidate
            break
    if selected is None:
        raise ValueError("cellar_official_item_hash_mismatch")
    return {
        "celex": celex,
        "authority_identity": target["authority_identity"],
        "content_sha256": expected_hash,
        "notice_url": notice_url,
        "notice_sha256": _sha256(notice),
        "notice_bytes": notice,
        "cellar_work_uri": work_uri,
        "manifestation_attempts": attempts,
        "selected_manifestation_kind": selected.kind,
        "selected_item_uri": selected.item_uri,
        "selected_stream_size": selected.stream_size,
        "official_item_matches_staged_bytes": True,
    }


def verify(
    *,
    manifest_path: Path,
    source_root: Path,
    evidence_dir: Path,
    workers: int,
) -> dict[str, Any]:
    if evidence_dir.exists():
        raise ValueError("cellar_evidence_directory_already_exists")
    manifest = json.loads(manifest_path.read_bytes())
    if manifest.get("schema") != ("legalbot.pensions-seminar-gap-official-eu-judgment-plan.v1"):
        raise ValueError("cellar_provenance_manifest_schema_invalid")
    source_root_resolved = source_root.resolve(strict=True)
    targets = manifest.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ValueError("cellar_provenance_target_inventory_invalid")

    results: dict[str, dict[str, Any]] = {}
    failures: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=workers) as executor:
        pending = {
            executor.submit(_verify_target, target, source_root_resolved): str(target["celex"])
            for target in targets
        }
        for future in as_completed(pending):
            celex = pending[future]
            try:
                results[celex] = future.result()
            except Exception as exc:
                failures[celex] = f"{type(exc).__name__}:{exc}"

    evidence_dir.mkdir(parents=True, exist_ok=False)
    safe_records: list[dict[str, Any]] = []
    for celex in sorted(results):
        result = results[celex]
        notice_bytes = result.pop("notice_bytes")
        notice_name = f"cellar-{celex.casefold()}-tree.xml"
        _write_exclusive(evidence_dir / notice_name, notice_bytes, mode=0o600)
        result["notice_evidence_file"] = notice_name
        safe_records.append(result)

    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "source_plan_version": manifest["version"],
        "source_plan_content_sha256": _sha256(_canonical_json(manifest)),
        "official_service": "Publications Office Cellar",
        "method": "celex_work_to_english_manifestation_to_doc_1_exact_byte_hash",
        "summary": {
            "target_count": len(targets),
            "provenance_pass_count": len(safe_records),
            "provenance_failure_count": len(failures),
        },
        "records": safe_records,
        "failures": [
            {"celex": celex, "failure_fingerprint": failures[celex]} for celex in sorted(failures)
        ],
        "provenance_verification_passed": not failures and len(safe_records) == len(targets),
        "release_state": "PROVENANCE_ONLY_OWNER_REVIEW_REQUIRED",
        "automatic_source_admission": False,
        "automatic_currentness_approval": False,
        "automatic_later_treatment_approval": False,
        "automatic_gold_change": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "active_pointer_written": False,
        "live_activation_authorized": False,
    }
    report["report_content_sha256"] = _sha256(_canonical_json(report))
    return report


def main() -> int:
    arguments = argparse.ArgumentParser()
    arguments.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    arguments.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    arguments.add_argument("--evidence-dir", type=Path, default=DEFAULT_EVIDENCE_DIR)
    arguments.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    arguments.add_argument("--workers", type=int, default=6)
    args = arguments.parse_args()
    if not 1 <= args.workers <= 8:
        raise ValueError("cellar_worker_count_invalid")
    report = verify(
        manifest_path=args.manifest,
        source_root=args.source_root,
        evidence_dir=args.evidence_dir,
        workers=args.workers,
    )
    _write_exclusive(
        args.output,
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n",
    )
    print(json.dumps(report["summary"], sort_keys=True))
    return 0 if report["provenance_verification_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
