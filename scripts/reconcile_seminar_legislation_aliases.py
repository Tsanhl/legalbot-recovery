#!/usr/bin/env python3
"""Reconcile bounded noisy legislation aliases against exact official titles."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PARENT = (
    PROJECT_ROOT / "data/review_queue/seminar-gap-legislation-title-resolution-2026-08-26.json"
)
DEFAULT_OUTPUT = (
    PROJECT_ROOT / "data/review_queue/seminar-gap-legislation-alias-reconciliation-2026-08-26.json"
)
EXPECTED_PARENT_SCHEMA = "legalbot.seminar-gap-legislation-title-resolution.v1"
REPORT_SCHEMA = "legalbot.seminar-gap-legislation-alias-reconciliation.v1"
OFFICIAL_HOST = "www.legislation.gov.uk"
ATOM_NAMESPACE = "http://www.w3.org/2005/Atom"
NON_ALNUM = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True, slots=True)
class Alias:
    official_candidate: str
    reason_code: str


ALIASES = {
    "Applicable Law) Act 1990": Alias(
        "Contracts (Applicable Law) Act 1990", "short_title_completion"
    ),
    "Bills of Sales Act 1878": Alias("Bills of Sale Act 1878", "typographical_normalisation"),
    "Capital and Income) Act 2013": Alias(
        "Trusts (Capital and Income) Act 2013", "short_title_completion"
    ),
    "CJI Act 2008": Alias("Criminal Justice and Immigration Act 2008", "abbreviation_expansion"),
    "Consumer Contracts Regulations 2013": Alias(
        "The Consumer Contracts (Information, Cancellation and Additional Charges) Regulations 2013",
        "short_title_completion",
    ),
    "Contribution) Act 1978": Alias(
        "Civil Liability (Contribution) Act 1978", "short_title_completion"
    ),
    "Corporate Manslaughter Act 2007": Alias(
        "Corporate Manslaughter and Corporate Homicide Act 2007",
        "short_title_completion",
    ),
    "Counter-Terrorism Act 2021": Alias(
        "Counter-Terrorism and Sentencing Act 2021", "short_title_completion"
    ),
    "Effect of REUL Act 2023": Alias(
        "Retained EU Law (Revocation and Reform) Act 2023", "abbreviation_expansion"
    ),
    "Employer Debt) Regulations 2005": Alias(
        "The Occupational Pension Schemes (Employer Debt) Regulations 2005",
        "short_title_completion",
    ),
    "Enterprise and Employment Act 2015": Alias(
        "Small Business, Enterprise and Employment Act 2015", "short_title_completion"
    ),
    "Exceptions) Regulations 2010": Alias(
        "The Equality Act 2010 (Sex Equality Rule) (Exceptions) Regulations 2010",
        "short_title_completion",
    ),
    "F) to the CJI Act 2008": Alias(
        "Criminal Justice and Immigration Act 2008", "abbreviation_expansion"
    ),
    "Fitness for Human Habitation) Act 2018": Alias(
        "Homes (Fitness for Human Habitation) Act 2018", "short_title_completion"
    ),
    "Frustrated Contracts) Act 1943": Alias(
        "Law Reform (Frustrated Contracts) Act 1943", "short_title_completion"
    ),
    "HP Act 1964": Alias("Hire-Purchase Act 1964", "abbreviation_expansion"),
    "Implementation of Agreements) Act 2020": Alias(
        "Private International Law (Implementation of Agreements) Act 2020",
        "short_title_completion",
    ),
    "Insanity) Act 1964": Alias("Criminal Procedure (Insanity) Act 1964", "short_title_completion"),
    "Investment) Regulations 2005": Alias(
        "The Occupational Pension Schemes (Investment) Regulations 2005",
        "short_title_completion",
    ),
    "Justice Act 2009": Alias("Coroners and Justice Act 2009", "short_title_completion"),
    "Land Registration Act 1925": Alias(
        "Land Registration Act 1925", "official_repealed_annotation_reconciliation"
    ),
    "Land Registry Act 1862": Alias(
        "Land Registry Act 1862", "official_repealed_annotation_reconciliation"
    ),
    "Miscellaneous Provisions) Act 1995": Alias(
        "Private International Law (Miscellaneous Provisions) Act 1995",
        "short_title_completion",
    ),
    "Modification of Schemes) Regulations 2006": Alias(
        "The Occupational Pension Schemes (Modification of Schemes) Regulations 2006",
        "short_title_completion",
    ),
    "Notifiable Events) Regulations 2005": Alias(
        "The Pensions Regulator (Notifiable Events) Regulations 2005",
        "short_title_completion",
    ),
    "Pensions Act 2017": Alias("Pension Schemes Act 2017", "typographical_normalisation"),
    "Pensions Ombudsman) Regulations 1996": Alias(
        "The Personal and Occupational Pension Schemes (Pensions Ombudsman) Regulations 1996",
        "short_title_completion",
    ),
    "Pensions Scheme Act 1993": Alias("Pension Schemes Act 1993", "typographical_normalisation"),
    "Pensions Schemes Act 2021": Alias("Pension Schemes Act 2021", "typographical_normalisation"),
    "Preservation) Act 1929": Alias(
        "Infant Life (Preservation) Act 1929", "short_title_completion"
    ),
    "Protection of Employment) Regulations 2006": Alias(
        "The Transfer of Undertakings (Protection of Employment) Regulations 2006",
        "short_title_completion",
    ),
    "Reciprocal Enforcement) Act 1933": Alias(
        "Foreign Judgments (Reciprocal Enforcement) Act 1933", "short_title_completion"
    ),
    "Regulated Activities) Order 2001": Alias(
        "The Financial Services and Markets Act 2000 (Regulated Activities) Order 2001",
        "short_title_completion",
    ),
    "REUL Act 2023": Alias(
        "Retained EU Law (Revocation and Reform) Act 2023", "abbreviation_expansion"
    ),
    "Revocation and Reform) Act 2023": Alias(
        "Retained EU Law (Revocation and Reform) Act 2023", "short_title_completion"
    ),
    "Rights of Third Parties) Act 1999": Alias(
        "Contracts (Rights of Third Parties) Act 1999", "short_title_completion"
    ),
    "S76(5) of the CJI Act 2008": Alias(
        "Criminal Justice and Immigration Act 2008", "abbreviation_expansion"
    ),
    "Scheme Funding) Regulations 2005": Alias(
        "The Occupational Pension Schemes (Scheme Funding) Regulations 2005",
        "short_title_completion",
    ),
    "Sea Act 1924": Alias("Carriage of Goods by Sea Act 1924", "short_title_completion"),
    "Sea Act 1971": Alias("Carriage of Goods by Sea Act 1971", "short_title_completion"),
    "Sex Equality) Exceptions Regulations 2010": Alias(
        "The Equality Act 2010 (Sex Equality Rule) (Exceptions) Regulations 2010",
        "short_title_completion",
    ),
    "the CJI Act 2008": Alias(
        "Criminal Justice and Immigration Act 2008", "abbreviation_expansion"
    ),
    "the European Communities Act 1972": Alias(
        "European Communities Act 1972", "official_repealed_annotation_reconciliation"
    ),
    "the Rules of the Air Regulations 2007": Alias(
        "The Rules of the Air Regulations 2007", "official_repealed_annotation_reconciliation"
    ),
    "the Unfair Contract Terms Regulations 1999": Alias(
        "The Unfair Terms in Consumer Contracts Regulations 1999",
        "typographical_normalisation",
    ),
    "UK Internal Market Act 2020": Alias(
        "United Kingdom Internal Market Act 2020", "abbreviation_expansion"
    ),
    "Withdrawal) Act 2018": Alias("European Union (Withdrawal) Act 2018", "short_title_completion"),
    "Withdrawal Agreement) Act 2020": Alias(
        "European Union (Withdrawal Agreement) Act 2020", "short_title_completion"
    ),
    "Withdrawal Agreement The Trade and Co-operation Agreement The UK Internal Market Act 2020": Alias(
        "United Kingdom Internal Market Act 2020", "compound_reference_disambiguation"
    ),
}


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("legislation_alias_input_must_be_object")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _identity(value: str) -> str:
    normalised = NON_ALNUM.sub(" ", value.casefold()).strip()
    return normalised.removeprefix("the ")


def _official_base_title(value: str) -> tuple[str, str | None]:
    value = " ".join(value.split())
    if value.casefold().endswith(" (repealed)"):
        return value[: -len(" (repealed)")], "repealed"
    return value, None


def _search(candidate: str, *, timeout_seconds: float) -> list[dict[str, str | None]]:
    encoded = urllib.parse.quote(candidate, safe="")
    url = f"https://{OFFICIAL_HOST}/title/{encoded}/data.feed"
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/atom+xml",
            "User-Agent": "LegalBot-v1.11-legislation-alias-reconciliation/1.0",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        final = urllib.parse.urlsplit(response.geturl())
        if final.scheme != "https" or final.hostname != OFFICIAL_HOST:
            raise ValueError("legislation_alias_redirected_outside_official_host")
        root = ET.fromstring(response.read())
    matches: dict[str, dict[str, str | None]] = {}
    for entry in root.findall(f"{{{ATOM_NAMESPACE}}}entry"):
        title_node = entry.find(f"{{{ATOM_NAMESPACE}}}title")
        id_node = entry.find(f"{{{ATOM_NAMESPACE}}}id")
        title = " ".join((title_node.text or "").split()) if title_node is not None else ""
        official_id = (id_node.text or "").strip() if id_node is not None else ""
        base_title, annotation = _official_base_title(title)
        if _identity(base_title) != _identity(candidate) or not official_id:
            continue
        parsed = urllib.parse.urlsplit(official_id)
        if parsed.hostname != OFFICIAL_HOST:
            continue
        canonical_url = urllib.parse.urlunsplit(
            ("https", OFFICIAL_HOST, parsed.path.rstrip("/"), "", "")
        )
        matches[canonical_url] = {
            "official_title": title,
            "official_base_title": base_title,
            "official_status_annotation": annotation,
            "canonical_url": canonical_url,
        }
    return [matches[key] for key in sorted(matches)]


def reconcile(*, parent_path: Path, timeout_seconds: float) -> dict[str, Any]:
    parent = _load(parent_path)
    if parent.get("schema") != EXPECTED_PARENT_SCHEMA:
        raise ValueError("legislation_alias_parent_schema_invalid")
    unresolved = {
        str(record["extracted_reference"]): record
        for record in parent["records"]
        if record["resolution_status"] == "UNRESOLVED_RESEARCH_REQUIRED"
    }
    records: list[dict[str, Any]] = []
    for extracted, alias in ALIASES.items():
        parent_record = unresolved.get(extracted)
        if parent_record is None:
            raise ValueError("legislation_alias_not_in_parent_unresolved_inventory")
        matches = _search(alias.official_candidate, timeout_seconds=timeout_seconds)
        records.append(
            {
                "extracted_reference": extracted,
                "official_candidate": alias.official_candidate,
                "alias_reason_code": alias.reason_code,
                "presentation_subjects": parent_record["presentation_subjects"],
                "official_exact_matches": matches,
                "resolution_status": (
                    "OFFICIAL_ALIAS_EXACT_MATCH_OWNER_INTENT_CONFIRMATION_REQUIRED"
                    if len(matches) == 1
                    else "OFFICIAL_ALIAS_AMBIGUOUS_OWNER_RESEARCH_REQUIRED"
                    if matches
                    else "OFFICIAL_ALIAS_NOT_FOUND_RESEARCH_REQUIRED"
                ),
                "source_admission_gate": "OWNER_REVIEW_REQUIRED",
                "currentness_gate": "OWNER_REVIEW_REQUIRED",
                "seminar_intent_confirmation_gate": "OWNER_REVIEW_REQUIRED",
            }
        )
    matched = sum(
        record["resolution_status"]
        == "OFFICIAL_ALIAS_EXACT_MATCH_OWNER_INTENT_CONFIRMATION_REQUIRED"
        for record in records
    )
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "as_of_date": "2026-08-26",
        "parent_resolution_sha256": _sha256_file(parent_path),
        "summary": {
            "parent_unresolved_count": len(unresolved),
            "bounded_alias_count": len(records),
            "official_alias_exact_match_count": matched,
            "official_alias_not_exact_count": len(records) - matched,
            "remaining_unmapped_parent_count": len(unresolved) - len(records),
        },
        "records": records,
        "matching_policy": (
            "A bounded alias is only retained when legislation.gov.uk returns one exact "
            "normalised official title. A terminal official '(repealed)' annotation is "
            "preserved and never treated as current law. Seminar intent remains owner-held."
        ),
        "automatic_source_admission": False,
        "automatic_currentness_approval": False,
        "automatic_gold_change": False,
        "automatic_download": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "active_pointer_written": False,
        "live_activation_authorized": False,
    }
    encoded = json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    report["report_content_sha256"] = hashlib.sha256(encoded).hexdigest()
    return report


def _write_exclusive(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent", type=Path, default=DEFAULT_PARENT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    args = parser.parse_args()
    report = reconcile(
        parent_path=args.parent,
        timeout_seconds=max(args.timeout_seconds, 1.0),
    )
    _write_exclusive(args.output, report)
    print(json.dumps(report["summary"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
