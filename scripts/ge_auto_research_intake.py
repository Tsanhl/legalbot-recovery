"""Structural parsing of exact official capture bytes for non-live source review.

HTML/PDF blocks without an official anchor get an explicit capture-local locator,
never a fabricated court paragraph or statute section. A reviewer must separately
verify the legal provision identity and its necessary context.
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, replace
from pathlib import Path

from backend.app.contracts.schema_registry import canonical_json_bytes
from backend.app.ingestion.models import ParseResult
from backend.app.ingestion.parsers import ParserRegistry
from backend.app.ingestion.sanitation import sanitize_parse_result

from scripts.ge_unseen_sources import is_allowed_source_url

ROOT = Path(__file__).resolve().parents[1]


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def parser_binding(*, include_legal_tables=False):
    paths = [Path(__file__).resolve(), ROOT / 'backend/app/ingestion/parsers.py',
             ROOT / 'backend/app/ingestion/models.py', ROOT / 'backend/app/ingestion/sanitation.py']
    if include_legal_tables:
        paths.append(ROOT / 'scripts/ge_auto_xml_tables.py')
    value = {p.relative_to(ROOT).as_posix(): _sha(p.read_bytes()) for p in paths}
    return _sha(canonical_json_bytes(value))


def parse_capture(raw: bytes, *, source_url: str, expected_raw_sha256: str,
                  include_legal_tables=False) -> ParseResult:
    if (not is_allowed_source_url(source_url) or len(raw) > 8_000_000
            or _sha(raw) != expected_raw_sha256):
        raise ValueError('official source bytes or identity mismatch')
    opening = raw[:100_000].lstrip().lower()
    if opening.startswith(b'%pdf-'):
        filename = 'capture.pdf'
    elif b'<html' in opening or b'<!doctype html' in opening:
        # HTMLParser does not resolve an external DTD. Never reinterpret an
        # arbitrary XML DTD as HTML merely to make a failed parse pass.
        if b'<!entity' in opening or b'<!doctype html [' in opening:
            raise ValueError('custom entity declarations are not permitted')
        filename = 'capture.html'
    elif b'<legislation' in opening:
        filename = 'capture.xml'
    else:
        raise ValueError('unsupported official source format remains held')
    parsed = ParserRegistry.default().parse(raw, filename=filename)
    if not parsed.is_ready:
        return parsed
    if include_legal_tables and filename == 'capture.xml':
        from scripts.ge_auto_xml_tables import append_missing_legal_tables
        parsed = append_missing_legal_tables(raw, parsed, source_url, expected_raw_sha256)
    blocks = []
    for block in parsed.body_blocks:
        if block.source_anchor:
            blocks.append(block)
        else:
            blocks.append(replace(block,
                source_anchor=f'capture-sha256:{expected_raw_sha256}#block-{block.ordinal}',
                metadata={**block.metadata, 'locator_kind': 'CAPTURE_LOCAL_BLOCK_NOT_OFFICIAL_PROVISION',
                          'canonical_source_url': source_url}))
    return sanitize_parse_result(replace(parsed, body_blocks=tuple(blocks)))


def parsed_manifest(raw: bytes, *, source_url: str, expected_raw_sha256: str,
                    include_legal_tables=True):
    parsed = parse_capture(raw, source_url=source_url, expected_raw_sha256=expected_raw_sha256,
                           include_legal_tables=include_legal_tables)
    value = asdict(parsed)
    return {'source_url': source_url, 'raw_sha256': expected_raw_sha256,
            'parser_sha256': parser_binding(include_legal_tables=include_legal_tables),
            'parsed_sha256': _sha(canonical_json_bytes(value)),
            'parsed': value, 'source_review': 'NOT_PERFORMED',
            'production_admission': False, 'legal_gold': False}
