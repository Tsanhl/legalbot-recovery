#!/usr/bin/env python3
"""Quarantine the bounded official sources required after r108 review.

The four targets are pinned in a repository plan and are downloaded into a
create-only quarantine.  This collector verifies official XML identity,
response bytes, required locators and all gate boundaries.  It never admits,
indexes or embeds a source and never mutates a candidate.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

import httpx

if __package__:
    from scripts import collect_v111_phase2a_official_sources as official
else:
    import collect_v111_phase2a_official_sources as official

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = (
    PROJECT_ROOT
    / "config/phase2a_post_r108_currentness_sources.2026-08-26.v2.json"
)
DEFAULT_OUTPUT_ROOT = (
    PROJECT_ROOT
    / "data/quarantine/2026-08-26/phase2a-post-r108-currentness-sources-r109c"
)
PRIOR_FAILURES = (
    {
        "root": PROJECT_ROOT
        / "data/quarantine/2026-08-26/phase2a-post-r108-currentness-sources-r109",
        "file_sha256": (
            "3b1d42cd5ffe6e55769b2f4c4d9400b847d0eb8c3e3fd74fa725c4400347b113"
        ),
        "content_sha256": (
            "8bf85428f433ce7ef4d29a25173b35bdb066a28e5191fbf613246a275120bea1"
        ),
        "fingerprint": (
            "b92862f054be7bca27e0bb84b566ce30050209e04f83d5ca1b38e5bded5e5abf"
        ),
        "error": "phase2a_r103_judgment_paragraphs_missing",
    },
    {
        "root": PROJECT_ROOT
        / "data/quarantine/2026-08-26/phase2a-post-r108-currentness-sources-r109b",
        "file_sha256": (
            "489996e4281bdffb32f92c69415ad6c7b87fbbd380a3ea6d9d444659d51441b4"
        ),
        "content_sha256": (
            "2fc8db2123a11cf7cb847794968026f312695b878cf680e354c2cefe6819c342"
        ),
        "fingerprint": (
            "7972ec609489cdf6c6b85714ae66b28dc13d1235c2b99158c8e1be24acecf2a6"
        ),
        "error": "phase2a_r109_response_digest_mismatch",
    },
)
TARGET_DATE = "2026-08-14"
TARGET_CEILING = "2026-08-14T23:59:59+01:00 Europe/London"
EXPECTED_TARGET_COUNT = 4
ALLOWED_HOSTS = frozenset(
    {"caselaw.nationalarchives.gov.uk", "www.legislation.gov.uk"}
)
USER_AGENT = "LegalBot-v1.11-Phase2A-post-r108-currentness/1.0"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UKSI = re.compile(r"^uksi:(?P<year>\d{4}):(?P<number>\d+)$")
_JUDGMENT = re.compile(
    r"^neutral-citation:\[(?P<year>\d{4})\] "
    r"(?P<court>UKSC|EWHC) (?P<number>\d+)(?: \((?P<division>Ch)\))?$"
)
_BOUNDARY_FIELDS = (
    "automatic_source_admission",
    "automatic_gold_change",
    "automatic_indexing",
    "automatic_embedding",
    "candidate_mutation_authorized",
    "technical_qualification_assigned",
    "phase2b_authorized",
    "development30_authorized",
)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _load_plan(path: Path = PLAN_PATH) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_r109_plan_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_r109_plan_must_be_object")
    return value


def _safe_url(value: str) -> str:
    safe = official._safe_url(value)
    if httpx.URL(safe).host not in ALLOWED_HOSTS:
        raise ValueError("phase2a_r109_url_outside_narrow_allowlist")
    return safe


def _validate_targets(plan: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    targets = plan.get("targets")
    if (
        plan.get("schema")
        != "legalbot.v111.phase2a.post-r108-currentness-source-plan.v2"
        or plan.get("target_ceiling") != TARGET_CEILING
        or plan.get("owner_source_admission_required") is not True
        or any(plan.get(field) is not False for field in _BOUNDARY_FIELDS)
        or not isinstance(targets, list)
        or len(targets) != EXPECTED_TARGET_COUNT
    ):
        raise ValueError("phase2a_r109_plan_boundary_invalid")
    validated: list[dict[str, Any]] = []
    seen_targets: set[str] = set()
    seen_authorities: set[str] = set()
    for ordinal, raw_target in enumerate(targets, start=1):
        if not isinstance(raw_target, Mapping):
            raise ValueError("phase2a_r109_target_invalid")
        target = dict(raw_target)
        target_id = str(target.get("target_id") or "")
        authority = str(target.get("authority_identity_id") or "")
        official_url = _safe_url(str(target.get("official_url") or ""))
        required_locators = target.get("required_locators")
        affected_rows = target.get("affected_row_ids")
        preflight_sha256 = str(target.get("preflight_response_sha256") or "")
        canonical_sha256 = str(target.get("expected_canonical_xml_sha256") or "")
        judgment_match = _JUDGMENT.fullmatch(authority)
        legislation_match = _UKSI.fullmatch(authority)
        if (
            target_id != f"post-r108-currentness-{ordinal:03d}"
            or target_id in seen_targets
            or authority in seen_authorities
            or (judgment_match is None and legislation_match is None)
            or not _SHA256.fullmatch(preflight_sha256)
            or not _SHA256.fullmatch(canonical_sha256)
            or not isinstance(required_locators, list)
            or not required_locators
            or any(not str(locator).strip() for locator in required_locators)
            or not isinstance(affected_rows, list)
            or not affected_rows
            or any(not str(row_id).strip() for row_id in affected_rows)
            or target.get("proposed_use")
            not in {
                "CURRENT_BINDING_REPLACEMENT_PROPOSITION_SOURCE",
                "LATER_TREATMENT_METADATA_ONLY_UNLESS_SEPARATELY_BOUND",
                "CURRENT_PRIMARY_LEGISLATION_PROPOSITION_SOURCE",
            }
            or not str(target.get("research_reason") or "").strip()
        ):
            raise ValueError("phase2a_r109_target_boundary_invalid")
        if judgment_match is not None:
            court = judgment_match.group("court").casefold()
            if court == "ewhc":
                court = f"{court}/ch"
            expected_path = (
                f"/{court}/{judgment_match.group('year')}/"
                f"{int(judgment_match.group('number'))}/data.xml"
            )
        else:
            assert legislation_match is not None
            expected_path = (
                f"/uksi/{legislation_match.group('year')}/"
                f"{int(legislation_match.group('number'))}/{TARGET_DATE}/data.xml"
            )
        if httpx.URL(official_url).path != expected_path:
            raise ValueError("phase2a_r109_target_url_identity_mismatch")
        target["ordinal"] = ordinal
        target["official_url"] = official_url
        validated.append(target)
        seen_targets.add(target_id)
        seen_authorities.add(authority)
    return tuple(validated)


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _normal_text(element: ET.Element) -> str:
    return " ".join("".join(element.itertext()).replace("\u00a0", " ").split())


def _canonical_xml_sha256(raw: bytes) -> str:
    try:
        canonical = ET.canonicalize(from_file=io.BytesIO(raw), with_comments=False)
    except (ET.ParseError, UnicodeError, ValueError) as exc:
        raise ValueError("phase2a_r109_official_xml_invalid") from exc
    return _sha256(canonical.encode("utf-8"))


def _judgment_extraction(authority: str, raw: bytes) -> dict[str, Any]:
    """Extract numbered paragraphs from both modern and legacy TNA AKN XML."""

    root = official._xml_root(raw)
    if _local_name(root.tag) != "akomaNtoso":
        raise ValueError("phase2a_r109_judgment_xml_root_invalid")
    citation = authority.removeprefix("neutral-citation:")
    citations = {
        _normal_text(element)
        for element in root.iter()
        if _local_name(element.tag) in {"neutralCitation", "cite"}
    }
    if citation not in citations:
        raise ValueError("phase2a_r109_judgment_identity_mismatch")
    titles = [
        str(element.get("value"))
        for element in root.iter()
        if _local_name(element.tag) == "FRBRname" and element.get("value")
    ]
    dates = [
        str(element.get("date"))
        for element in root.iter()
        if _local_name(element.tag) == "FRBRdate"
        and element.get("name") == "judgment"
        and element.get("date")
    ]
    if not titles or not dates or dates[0] > TARGET_DATE:
        raise ValueError("phase2a_r109_judgment_metadata_invalid")
    blocks: list[dict[str, Any]] = []
    seen: set[int] = set()
    for element in root.iter():
        if _local_name(element.tag) != "paragraph":
            continue
        number: int | None = None
        element_id = str(element.get("eId") or "")
        identifier_match = re.fullmatch(r"para_(\d+)", element_id)
        if identifier_match is not None:
            number = int(identifier_match.group(1))
        else:
            direct_num = next(
                (
                    child
                    for child in list(element)
                    if _local_name(child.tag) == "num"
                ),
                None,
            )
            if direct_num is not None:
                number_match = re.match(r"^\s*(\d+)\s*[.]?", _normal_text(direct_num))
                if number_match is not None:
                    number = int(number_match.group(1))
                    element_id = f"para_{number}"
        if number is None or number in seen:
            continue
        text = _normal_text(element)
        if not text:
            continue
        seen.add(number)
        blocks.append(
            {
                "locator": f"paragraph {number}",
                "element_id": element_id,
                "text": text,
                "text_sha256": _sha256(text.encode("utf-8")),
            }
        )
    if not blocks:
        raise ValueError("phase2a_r109_judgment_paragraphs_missing")
    return {
        "source_class": "OFFICIAL_BINDING_OR_PERSUASIVE_JUDGMENT",
        "authority_identity_id": authority,
        "source_title": titles[0],
        "source_date": dates[0],
        "block_count": len(blocks),
        "blocks": blocks,
    }


def _load_prior_failures() -> tuple[dict[str, Any], ...]:
    verified: list[dict[str, Any]] = []
    for expected in PRIOR_FAILURES:
        root = expected["root"]
        assert isinstance(root, Path)
        path = root / "FAILURE.json"
        if _sha256_file(path) != expected["file_sha256"]:
            raise ValueError("phase2a_r109c_prior_failure_file_digest_invalid")
        value = json.loads(path.read_bytes())
        if not isinstance(value, dict):
            raise ValueError("phase2a_r109c_prior_failure_invalid")
        material = dict(value)
        content_sha256 = str(material.pop("failure_content_sha256", ""))
        if (
            content_sha256 != expected["content_sha256"]
            or content_sha256 != _sealed(material)
            or value.get("failure_fingerprint") != expected["fingerprint"]
            or value.get("error") != expected["error"]
            or value.get("source_admission_authorized") is not False
            or value.get("phase2b_authorized") is not False
            or value.get("development30_authorized") is not False
        ):
            raise ValueError("phase2a_r109c_prior_failure_boundary_invalid")
        verified.append(
            {
                "root": str(root.relative_to(PROJECT_ROOT)),
                "failure_content_sha256": content_sha256,
                "failure_fingerprint": value["failure_fingerprint"],
                "error": value["error"],
            }
        )
    return tuple(verified)


def _uksi_extraction(authority: str, raw: bytes) -> dict[str, Any]:
    match = _UKSI.fullmatch(authority)
    root = official._xml_root(raw)
    if match is None or _local_name(root.tag) != "Legislation":
        raise ValueError("phase2a_r109_legislation_identity_invalid")
    years = {
        str(element.get("Value"))
        for element in root.iter()
        if _local_name(element.tag) == "Year" and element.get("Value")
    }
    numbers = {
        str(element.get("Value"))
        for element in root.iter()
        if _local_name(element.tag) == "Number" and element.get("Value")
    }
    document_uri = str(root.get("DocumentURI") or "")
    if (
        match.group("year") not in years
        or match.group("number") not in numbers
        or not document_uri.endswith(f"/{TARGET_DATE}")
    ):
        raise ValueError("phase2a_r109_legislation_identity_mismatch")
    titles = [
        _normal_text(element)
        for element in root.iter()
        if _local_name(element.tag) in {"title", "Title"}
        and _normal_text(element)
    ]
    blocks: list[dict[str, Any]] = []
    seen: set[str] = set()
    for element in root.iter():
        element_id = str(element.get("id") or "")
        if (
            _local_name(element.tag) not in {"P1", "P2", "P3", "P4", "P5"}
            or not element_id
            or element_id in seen
        ):
            continue
        text = _normal_text(element)
        if not text:
            continue
        seen.add(element_id)
        blocks.append(
            {
                "locator": element_id.replace("-", " "),
                "element_id": element_id,
                "text": text,
                "text_sha256": _sha256(text.encode("utf-8")),
            }
        )
    if not titles or not blocks:
        raise ValueError("phase2a_r109_legislation_content_missing")
    return {
        "source_class": "OFFICIAL_POINT_IN_TIME_SECONDARY_LEGISLATION",
        "authority_identity_id": authority,
        "source_title": titles[0],
        "source_date": TARGET_DATE,
        "block_count": len(blocks),
        "blocks": blocks,
    }


def _member_stem(ordinal: int, authority: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", authority.casefold()).strip("-")
    return f"{ordinal:02d}-{slug[:80]}-{_sha256(authority.encode())[:12]}"


def _required_locators_present(
    extraction: Mapping[str, Any], required_locators: Sequence[str]
) -> bool:
    available = {
        str(block.get("locator") or "")
        for block in extraction.get("blocks", [])
        if isinstance(block, Mapping)
    }
    return all(locator in available for locator in required_locators)


def collect(
    *,
    output_root: Path = DEFAULT_OUTPUT_ROOT,
    plan_path: Path = PLAN_PATH,
    transport: httpx.BaseTransport | None = None,
    clock: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_r109_output_already_exists")
    plan = _load_plan(plan_path)
    targets = _validate_targets(plan)
    prior_failures = _load_prior_failures()
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_r109_output_mode_invalid")
    now = clock or (lambda: datetime.now(UTC))
    intent_material = {
        "schema": "legalbot.v111.phase2a.post-r108-currentness-source-intent.v1",
        "status": "BOUNDED_OFFICIAL_CURRENTNESS_SOURCE_QUARANTINE_ONLY",
        "source_plan_file_sha256": _sha256_file(plan_path),
        "source_plan_content_sha256": _sealed(plan),
        "changed_execution_plan": (
            "Use the dual-shape TNA AKN paragraph extractor and pin canonical XML "
            "identity. Preserve and report raw-byte differences caused solely by "
            "XML attribute ordering instead of treating them as legal-text changes."
        ),
        "prior_failures": list(prior_failures),
        "target_ceiling": TARGET_CEILING,
        "target_count": len(targets),
        "targets": list(targets),
        "owner_source_admission_required": True,
        "automatic_source_admission": False,
        "automatic_gold_change": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    intent = {**intent_material, "intent_content_sha256": _sealed(intent_material)}
    _write_exclusive(output_root / "INTENT.json", _pretty_json(intent))

    client_kwargs: dict[str, Any] = {
        "follow_redirects": False,
        "timeout": httpx.Timeout(30.0, connect=10.0),
        "headers": {"User-Agent": USER_AGENT, "Accept": "application/xml"},
        "trust_env": False,
    }
    if transport is not None:
        client_kwargs["transport"] = transport
    records: list[dict[str, Any]] = []
    with httpx.Client(**client_kwargs) as client:
        for target in targets:
            requested_url = str(target["official_url"])
            final_url, status, content_type, raw = official._fetch(client, requested_url)
            if status != 200:
                raise ValueError(
                    f"phase2a_r109_official_source_unavailable_http_{status}"
                )
            if _safe_url(final_url) != requested_url:
                raise ValueError("phase2a_r109_final_url_invalid")
            raw_sha256 = _sha256(raw)
            canonical_xml_sha256 = _canonical_xml_sha256(raw)
            if canonical_xml_sha256 != target["expected_canonical_xml_sha256"]:
                raise ValueError("phase2a_r109c_canonical_xml_digest_mismatch")
            raw_byte_status = (
                "PREFLIGHT_BYTES_EXACT"
                if raw_sha256 == target["preflight_response_sha256"]
                else "CANONICAL_XML_IDENTICAL_RAW_BYTE_VARIANT"
            )
            authority = str(target["authority_identity_id"])
            extraction = (
                _judgment_extraction(authority, raw)
                if authority.startswith("neutral-citation:")
                else _uksi_extraction(authority, raw)
            )
            if not _required_locators_present(
                extraction, [str(value) for value in target["required_locators"]]
            ):
                raise ValueError("phase2a_r109_required_locator_missing")
            extraction_material = {
                "schema": "legalbot.v111.phase2a.post-r108-official-source-extraction.v1",
                **extraction,
                "source_representation_sha256": raw_sha256,
                "source_canonical_xml_sha256": canonical_xml_sha256,
                "preflight_response_sha256": target[
                    "preflight_response_sha256"
                ],
                "raw_byte_status": raw_byte_status,
                "requested_url": requested_url,
                "final_url": final_url,
                "affected_row_ids": target["affected_row_ids"],
                "required_locators": target["required_locators"],
                "proposed_use": target["proposed_use"],
                "research_reason": target["research_reason"],
                "owner_source_admission_required": True,
                "automatically_admitted": False,
                "automatically_indexed": False,
                "automatically_embedded": False,
            }
            extraction_artifact = {
                **extraction_material,
                "artifact_content_sha256": _sealed(extraction_material),
            }
            stem = _member_stem(int(target["ordinal"]), authority)
            raw_member = f"{stem}.xml"
            extraction_member = f"{stem}.extraction.json"
            _write_exclusive(output_root / raw_member, raw)
            _write_exclusive(
                output_root / extraction_member, _pretty_json(extraction_artifact)
            )
            record_material = {
                "ordinal": target["ordinal"],
                "target_id": target["target_id"],
                "authority_identity_id": authority,
                "source_class": extraction_artifact["source_class"],
                "source_title": extraction_artifact["source_title"],
                "source_date": extraction_artifact["source_date"],
                "requested_url": requested_url,
                "final_url": final_url,
                "http_status": status,
                "content_type": content_type,
                "retrieved_at": now().astimezone(UTC).isoformat(timespec="seconds"),
                "affected_row_ids": target["affected_row_ids"],
                "required_locators": target["required_locators"],
                "proposed_use": target["proposed_use"],
                "raw_quarantine_member": raw_member,
                "raw_bytes": len(raw),
                "raw_sha256": raw_sha256,
                "preflight_response_sha256": target[
                    "preflight_response_sha256"
                ],
                "raw_byte_status": raw_byte_status,
                "canonical_xml_sha256": extraction_artifact[
                    "source_canonical_xml_sha256"
                ],
                "extraction_member": extraction_member,
                "extraction_file_sha256": _sha256_file(
                    output_root / extraction_member
                ),
                "extraction_content_sha256": extraction_artifact[
                    "artifact_content_sha256"
                ],
                "extracted_block_count": extraction_artifact["block_count"],
                "result": "OFFICIAL_SOURCE_QUARANTINED_NOT_ADMITTED",
                "owner_source_admission_required": True,
                "automatically_admitted": False,
                "automatically_indexed": False,
                "automatically_embedded": False,
            }
            records.append(
                {**record_material, "record_content_sha256": _sealed(record_material)}
            )

    manifest_material = {
        "schema": "legalbot.v111.phase2a.post-r108-currentness-source-quarantine.v1",
        "status": "OFFICIAL_CURRENTNESS_SOURCES_QUARANTINED_OWNER_REVIEW_REQUIRED",
        "created_at": now().astimezone(UTC).isoformat(timespec="seconds"),
        "source_intent_content_sha256": intent["intent_content_sha256"],
        "source_plan_file_sha256": _sha256_file(plan_path),
        "source_plan_content_sha256": _sealed(plan),
        "prior_failures": list(prior_failures),
        "raw_byte_status_counts": {
            state: sum(record["raw_byte_status"] == state for record in records)
            for state in sorted({str(record["raw_byte_status"]) for record in records})
        },
        "target_ceiling": TARGET_CEILING,
        "allowlisted_hosts": sorted(ALLOWED_HOSTS),
        "record_count": len(records),
        "row_link_count": sum(len(record["affected_row_ids"]) for record in records),
        "records": records,
        "owner_source_admission_required": True,
        "automatic_source_admission": False,
        "automatic_gold_change": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    if len(records) != EXPECTED_TARGET_COUNT:
        raise ValueError("phase2a_r109_collection_inventory_invalid")
    manifest = {
        **manifest_material,
        "manifest_content_sha256": _sealed(manifest_material),
    }
    _write_exclusive(
        output_root / "QUARANTINE-MANIFEST.json", _pretty_json(manifest)
    )
    _write_exclusive(
        output_root / "OUTCOME.txt",
        b"4 OFFICIAL CURRENTNESS SOURCES QUARANTINED. OWNER REVIEW REQUIRED; "
        b"NOTHING ADMITTED, INDEXED, OR EMBEDDED.\n",
    )
    names = sorted(
        path.name
        for path in output_root.iterdir()
        if path.is_file() and path.name != "SHA256SUMS.txt"
    )
    sums = "".join(
        f"{_sha256_file(output_root / name)}  {name}\n" for name in names
    )
    _write_exclusive(output_root / "SHA256SUMS.txt", sums.encode("utf-8"))
    return manifest


def _persist_failure(output_root: Path, exc: BaseException) -> None:
    try:
        output_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        path = output_root / "FAILURE.json"
        if path.exists() or path.is_symlink():
            return
        material = {
            "schema": "legalbot.v111.phase2a.post-r108-currentness-source-failure.v1",
            "failure_fingerprint": _sealed(
                {"exception_type": type(exc).__name__, "error": str(exc)}
            ),
            "exception_type": type(exc).__name__,
            "error": str(exc),
            "affected_stage": "PHASE2A_POST_R108_CURRENTNESS_QUARANTINE",
            "source_admission_authorized": False,
            "automatic_indexing": False,
            "automatic_embedding": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        _write_exclusive(
            path,
            _pretty_json(
                {**material, "failure_content_sha256": _sealed(material)}
            ),
        )
    except Exception:
        return


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    args = parser.parse_args(argv)
    output_root = args.output_root.resolve()
    try:
        manifest = collect(output_root=output_root)
    except Exception as exc:
        _persist_failure(output_root, exc)
        raise
    print(
        json.dumps(
            {
                "manifest_content_sha256": manifest["manifest_content_sha256"],
                "record_count": manifest["record_count"],
                "row_link_count": manifest["row_link_count"],
                "automatic_source_admission": False,
                "automatic_indexing": False,
                "automatic_embedding": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
