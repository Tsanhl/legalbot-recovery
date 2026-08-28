#!/usr/bin/env python3
"""Stage official Cellar case-law bytes for the Pensions seminar gap pack.

The script is deliberately non-authorising.  It accepts only the frozen CELEX
inventory below, validates a case marker in the parsed judgment body, copies
the exact bytes into the configured source root without overwriting, and emits
an immutable manifest.  It never approves, embeds, indexes, or promotes a
source.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.ingestion.models import ParseStatus
from app.ingestion.parsers import ParserRegistry

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE_ROOT = Path("/Users/hltsang/Desktop/Law")
DEFAULT_RELATIVE_DIRECTORY = Path(
    "Official Legislation/seminar-gap-official-2026-08-26/eu-judgments"
)
DEFAULT_MANIFEST = (
    PROJECT_ROOT / "config/pensions_seminar_gap_official_eu_judgments.2026-08-26.v1.json"
)
PARENT_JUDGMENT_PLAN = (
    PROJECT_ROOT / "config/pensions_seminar_gap_official_judgments.2026-08-26.v2.json"
)
MANIFEST_SCHEMA = "legalbot.pensions-seminar-gap-official-eu-judgment-plan.v1"


@dataclass(frozen=True)
class Target:
    celex: str
    case_identity: str
    title: str
    marker: str


TARGETS = (
    Target("61975CJ0043", "Case 43/75", "Defrenne v SABENA (No 2)", r"Case 43/75"),
    Target(
        "61977CJ0106",
        "Case 106/77",
        "Amministrazione delle Finanze dello Stato v Simmenthal SpA",
        r"Case 106/77",
    ),
    Target(
        "61988CJ0262",
        "Case C-262/88",
        "Barber v Guardian Royal Exchange Assurance Group",
        r"Case C-262/88",
    ),
    Target(
        "61989CJ0037",
        "Case C-37/89",
        "Weiser v Caisse nationale des barreaux français",
        r"Case C-37/89",
    ),
    Target(
        "61989CJ0106",
        "Case C-106/89",
        "Marleasing SA v La Comercial Internacional de Alimentacion SA",
        r"Case C-106/89",
    ),
    Target("61991CJ0152", "Case C-152/91", "Neath v Hugh Steeper Ltd", r"Case C-152/91"),
    Target(
        "61991CJ0200",
        "Case C-200/91",
        "Coloroll Pension Trustees Ltd v Russell and Others",
        r"Case C-200/91",
    ),
    Target("61992CJ0132", "Case C-132/92", "Birds Eye Walls Ltd v Roberts", r"Case C-132/92"),
    Target(
        "61993CJ0057",
        "Case C-57/93",
        "Vroege v NCIV Instituut voor Volkshuisvesting BV",
        r"Case C-57/93",
    ),
    Target(
        "61996CJ0347",
        "Case C-347/96",
        "Solred SA v Administración General del Estado",
        r"Case C-347/96",
    ),
    Target(
        "62000CJ0164",
        "Case C-164/00",
        "Beckmann v Dynamco Whicheloe Macfarlane Ltd",
        r"Case C-164/00",
    ),
    Target(
        "62001CJ0004", "Case C-4/01", "Martin and Others v South Bank University", r"Case C-4/01"
    ),
    Target(
        "62001CJ0256",
        "Case C-256/01",
        "Allonby v Accrington & Rossendale College and Others",
        r"Case C-256/01",
    ),
    Target(
        "62001CJ0397",
        "Joined Cases C-397/01 to C-403/01",
        "Pfeiffer and Others v Deutsches Rotes Kreuz",
        r"Joined Cases C-397/01 to C-403/01",
    ),
    Target("62004CJ0144", "Case C-144/04", "Mangold v Helm", r"Case C-144/04"),
    Target("62004CJ0227", "Case C-227/04 P", "Lindorfer v Council", r"Case C-227/04 P"),
    Target("62004CJ0300", "Case C-300/04", "Eman and Sevinger", r"Case C-300/04"),
    Target(
        "62004CJ0344",
        "Case C-344/04",
        "IATA and ELFAA v Department for Transport",
        r"Case C-344/04",
    ),
    Target(
        "62005CJ0278",
        "Case C-278/05",
        "Robins and Others v Secretary of State for Work and Pensions",
        r"Case C-278/05",
    ),
    Target(
        "62007CJ0127",
        "Case C-127/07",
        "Société Arcelor Atlantique et Lorraine and Others",
        r"Case C-127/07",
    ),
    Target("62007CJ0555", "Case C-555/07", "Kücükdeveci v Swedex", r"Case C-555/07"),
    Target(
        "62009CJ0236",
        "Case C-236/09",
        "Association Belge des Consommateurs Test-Achats and Others",
        r"Case C-236/09",
    ),
    Target(
        "62011CJ0398",
        "Case C-398/11",
        "Hogan and Others v Minister for Social and Family Affairs",
        r"Case C.?398/11",
    ),
    Target(
        "62016CJ0569",
        "Joined Cases C-569/16 and C-570/16",
        "Bauer and Willmeroth v Broßonn",
        r"Joined Cases C.?569/16\s+and\s+C.?570/16",
    ),
    Target(
        "62017CJ0017",
        "Case C-17/17",
        "Hampshire v Board of the Pension Protection Fund",
        r"Case C.?17/17",
    ),
    Target(
        "62018CJ0168", "Case C-168/18", "Pensions-Sicherungs-Verein VVaG v Bauer", r"Case C.?168/18"
    ),
    Target(
        "62018CJ0171",
        "Case C-171/18",
        "Safeway Ltd v Newton and Safeway Pension Trustees Ltd",
        r"Case C.?171/18",
    ),
)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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


def _load_source(path: Path, *, marker: str, parser: ParserRegistry) -> tuple[bytes, int, int]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"source_not_regular_file:{path.name}")
    raw = path.read_bytes()
    if not raw or b"<html" not in raw[:10_000].lower():
        raise ValueError(f"source_not_html:{path.name}")
    if b"<rdf:RDF" in raw[:10_000] or b"<NOTICE" in raw[:10_000]:
        raise ValueError(f"source_is_metadata_not_judgment:{path.name}")
    parsed = parser.parse(raw, filename=path.name)
    if parsed.status is not ParseStatus.READY or not parsed.body_blocks:
        raise ValueError(f"source_parser_not_ready:{path.name}")
    text = "\n".join(block.text for block in parsed.body_blocks)
    identity_text = html.unescape(raw.decode("utf-8", errors="replace"))
    if re.search(marker, identity_text, flags=re.I) is None:
        raise ValueError(f"source_case_marker_mismatch:{path.name}")
    return raw, len(parsed.body_blocks), len(text)


def stage(*, input_dir: Path, source_root: Path, manifest_path: Path) -> dict[str, Any]:
    if input_dir.is_symlink() or not input_dir.is_dir():
        raise ValueError("input_directory_invalid")
    source_root_resolved = source_root.resolve(strict=True)
    destination = (source_root_resolved / DEFAULT_RELATIVE_DIRECTORY).resolve(strict=False)
    destination.relative_to(source_root_resolved)
    if destination.exists():
        raise ValueError("destination_already_exists")
    if manifest_path.exists():
        raise ValueError("manifest_already_exists")
    parent_raw = PARENT_JUDGMENT_PLAN.read_bytes()
    parser = ParserRegistry.default()
    prepared: list[tuple[Target, bytes, int, int]] = []
    for target in TARGETS:
        path = input_dir / f"{target.celex}.html"
        raw, block_count, character_count = _load_source(
            path,
            marker=target.marker,
            parser=parser,
        )
        prepared.append((target, raw, block_count, character_count))

    targets: list[dict[str, Any]] = []
    created_paths: list[Path] = []
    try:
        destination.mkdir(parents=True, exist_ok=False)
        for target, raw, block_count, character_count in prepared:
            filename = f"eu-celex-{target.celex.lower()}-eng.html"
            output = destination / filename
            _write_exclusive(output, raw, mode=0o444)
            created_paths.append(output)
            targets.append(
                {
                    "authority_identity": target.case_identity,
                    "celex": target.celex,
                    "source_title": target.title,
                    "official_url": (
                        f"https://publications.europa.eu/resource/celex/{target.celex}.ENG.html"
                    ),
                    "source_root_relative_path": str(DEFAULT_RELATIVE_DIRECTORY / filename),
                    "content_sha256": _sha256(raw),
                    "byte_count": len(raw),
                    "runtime_parser_block_count": block_count,
                    "runtime_parser_character_count": character_count,
                    "identity_verified_from_official_stream": True,
                    "currentness_status": "downloaded_official_judgment_unreviewed",
                    "later_treatment_status": "owner_review_required",
                }
            )
        manifest: dict[str, Any] = {
            "schema": MANIFEST_SCHEMA,
            "version": "pensions-seminar-gap-eu-2026-08-26-v1",
            "download_date": "2026-08-26",
            "jurisdiction": "European Union",
            "parent_uk_judgment_plan": {
                "version": "pensions-seminar-gap-2026-08-26-v2",
                "file_sha256": _sha256(parent_raw),
            },
            "source_root_relative_directory": str(DEFAULT_RELATIVE_DIRECTORY),
            "source": "https://publications.europa.eu/resource/celex/",
            "source_service": "Publications Office Cellar",
            "licence_review_status": (
                "official_record_downloaded_for_legal_research_"
                "owner_review_required_before_corpus_admission"
            ),
            "teaching_lane_use": "issue_discovery_only_never_legal_authority",
            "targets": targets,
            "joined_case_representation": {
                "Case C-570/16": "represented_in_62016CJ0569_joined_judgment",
            },
            "automatic_source_admission": False,
            "automatic_currentness_approval": False,
            "automatic_later_treatment_approval": False,
            "automatic_gold_change": False,
            "automatic_indexing": False,
            "automatic_embedding": False,
            "candidate_mutation_authorized": False,
            "active_promotion_authorized": False,
            "phase2b_authorized": False,
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
    except BaseException:
        for path in reversed(created_paths):
            path.unlink(missing_ok=True)
        if destination.exists() and not any(destination.iterdir()):
            destination.rmdir()
        raise
    return {
        "manifest": str(manifest_path),
        "target_count": len(targets),
        "total_bytes": sum(target["byte_count"] for target in targets),
        "automatic_embedding": False,
        "active_promotion_authorized": False,
    }


def main() -> None:
    arguments = argparse.ArgumentParser()
    arguments.add_argument("--input-dir", type=Path, required=True)
    arguments.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    arguments.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    args = arguments.parse_args()
    print(
        json.dumps(
            stage(
                input_dir=args.input_dir,
                source_root=args.source_root,
                manifest_path=args.manifest,
            ),
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
