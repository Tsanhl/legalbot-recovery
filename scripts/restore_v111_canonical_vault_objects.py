#!/usr/bin/env python3
"""Create-only recovery of exact canonical stream objects from retained raw bytes.

The recovery never reads a retired workspace path.  An encrypted historical
alias is decrypted only in memory to recreate the deterministic privacy digest,
classification and filename-dependent parser choice that were bound into the
original canonical streams.  No alias or source title is printed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.config import Settings
from app.crypto import LocalCipher
from app.ingestion.identity import private_locator_digest
from app.ingestion.markdown import CanonicalMarkdownConverter
from app.ingestion.models import CanonicalMarkdownBundle, Provenance, SourceIdentity
from app.ingestion.parsers import ParserRegistry
from app.ingestion.privacy import PIIAliaser
from app.ingestion.service import (
    _classify,
    _document_title,
    _load_alias_secret,
    _path_fingerprint,
    _refine_classification,
)
from app.ingestion.vault import ContentAddressedVault
from app.privacy import safe_source_name

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = (
    PROJECT_ROOT
    / "data/review_queue/approved-source-manifest-current-law-ew-full-recovery-20260829-v1.json"
)
STREAM_FIELDS = {
    "body": ("body_sha256", "canonical_markdown_path", "body_markdown"),
    "comments": ("comments_sha256", "comments_markdown_path", "comments_markdown"),
    "revisions": ("revisions_sha256", "revisions_markdown_path", "revisions_markdown"),
}


@dataclass(frozen=True, slots=True)
class RecoveryCandidate:
    bundle: CanonicalMarkdownBundle
    expected: dict[str, tuple[str, Path]]


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("recovery manifest is missing or unsafe")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise RuntimeError("recovery manifest must be a JSON object")
    return value


def _safe_expected_streams(
    *,
    project_root: Path,
    vault: ContentAddressedVault,
    row: sqlite3.Row,
    metadata: dict[str, Any],
) -> dict[str, tuple[str, Path]]:
    expected: dict[str, tuple[str, Path]] = {}
    for stream, (digest_field, path_field, _bundle_field) in STREAM_FIELDS.items():
        digest = str(metadata.get(digest_field) or "")
        relative = Path(
            str(row["canonical_markdown_path"] if stream == "body" else metadata.get(path_field))
        )
        if (
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or relative.is_absolute()
            or relative != vault.object_path(digest).relative_to(project_root)
        ):
            raise RuntimeError("canonical stream identity is invalid")
        expected[stream] = (digest, project_root / relative)
    return expected


def _bundle_bytes(bundle: CanonicalMarkdownBundle, stream: str) -> bytes:
    bundle_field = STREAM_FIELDS[stream][2]
    return str(getattr(bundle, bundle_field)).encode("utf-8")


def _candidate_for_source(
    *,
    row: sqlite3.Row,
    metadata: dict[str, Any],
    aliases: list[sqlite3.Row],
    raw_bytes: bytes,
    raw_digest: str,
    expected: dict[str, tuple[str, Path]],
    cipher: LocalCipher,
    aliaser: PIIAliaser,
    parsers: ParserRegistry,
    converter: CanonicalMarkdownConverter,
) -> RecoveryCandidate:
    for alias in aliases:
        historical_path = Path(cipher.decrypt_text(bytes(alias["encrypted_path"])))
        fingerprint = str(alias["path_fingerprint"])
        if _path_fingerprint(historical_path) != fingerprint:
            continue
        parsed = parsers.parse(raw_bytes, filename=historical_path.name, aliaser=aliaser)
        if not parsed.is_ready:
            continue
        classification = _refine_classification(_classify(historical_path), parsed)
        fallback_title = safe_source_name(historical_path, raw_digest)
        provenance = Provenance.now(
            source_identity=SourceIdentity(
                "catalog", str(row["source_identity_id"]), version=raw_digest
            ),
            title=_document_title(parsed, fallback_title),
            source_kind=str(metadata["classification_reason"]),
            jurisdiction=classification.ingestion_jurisdiction,
            material_lane=classification.ingestion_lane,
            content_sha256=raw_digest,
            private_locator_digest=private_locator_digest(
                str(historical_path.absolute()), salt=fingerprint.encode("ascii")
            ),
            public_aliases={"display_name": fallback_title},
            extra={"parser_format": parsed.document_format.value},
        )
        bundle = converter.convert(parsed, provenance)
        if all(
            _sha256_bytes(_bundle_bytes(bundle, stream)) == digest
            for stream, (digest, _path) in expected.items()
        ):
            return RecoveryCandidate(bundle=bundle, expected=expected)
    raise RuntimeError("no retained alias reproduces the exact canonical stream identities")


def restore(*, manifest_path: Path, execute: bool) -> dict[str, Any]:
    settings = Settings(project_root=PROJECT_ROOT)
    cipher = LocalCipher.from_local_key(create=False)
    aliaser = PIIAliaser(_load_alias_secret(settings, cipher))
    parsers = ParserRegistry.default()
    converter = CanonicalMarkdownConverter()
    vault = ContentAddressedVault(settings.vault_dir)
    manifest = _load_object(manifest_path)
    sources = manifest.get("sources")
    if not isinstance(sources, list) or not sources:
        raise RuntimeError("recovery manifest has no sources")

    connection = sqlite3.connect(f"file:{settings.database_path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    candidates: list[RecoveryCandidate] = []
    already_present = 0
    try:
        for source in sources:
            if not isinstance(source, dict):
                raise RuntimeError("recovery manifest source is invalid")
            row = connection.execute(
                """
                SELECT sv.*, d.source_identity_id
                FROM source_versions sv
                JOIN documents d ON d.id=sv.document_id
                WHERE sv.id=?
                """,
                (str(source.get("source_version_id") or ""),),
            ).fetchone()
            if row is None:
                raise RuntimeError("recovery manifest source version is missing")
            metadata = json.loads(str(row["metadata_json"] or "{}"))
            if not isinstance(metadata, dict):
                raise RuntimeError("source-version metadata is invalid")
            expected = _safe_expected_streams(
                project_root=PROJECT_ROOT,
                vault=vault,
                row=row,
                metadata=metadata,
            )
            raw_digest = str(metadata.get("raw_object_sha256") or "")
            raw_path = vault.object_path(raw_digest)
            raw_bytes = raw_path.read_bytes()
            if _sha256_bytes(raw_bytes) != raw_digest or raw_digest != row["version_sha256"]:
                raise RuntimeError("retained raw source identity changed")
            for digest, path in expected.values():
                if path.exists():
                    if (
                        path.is_symlink()
                        or not path.is_file()
                        or _sha256_bytes(path.read_bytes()) != digest
                    ):
                        raise RuntimeError("existing canonical stream object is unsafe or corrupt")
                    already_present += 1
            aliases = list(
                connection.execute(
                    "SELECT path_fingerprint, encrypted_path FROM source_aliases "
                    "WHERE document_id=? ORDER BY id",
                    (str(row["document_id"]),),
                ).fetchall()
            )
            if not aliases:
                raise RuntimeError("source version has no retained encrypted alias identity")
            candidates.append(
                _candidate_for_source(
                    row=row,
                    metadata=metadata,
                    aliases=aliases,
                    raw_bytes=raw_bytes,
                    raw_digest=raw_digest,
                    expected=expected,
                    cipher=cipher,
                    aliaser=aliaser,
                    parsers=parsers,
                    converter=converter,
                )
            )
    finally:
        connection.close()

    restored = 0
    if execute:
        for candidate in candidates:
            for stream, (digest, expected_path) in candidate.expected.items():
                value = _bundle_bytes(candidate.bundle, stream)
                if _sha256_bytes(value) != digest:
                    raise RuntimeError("canonical stream changed after recovery preflight")
                if expected_path.exists():
                    continue
                recovered = vault.put_bytes(value)
                if recovered.sha256 != digest or recovered.path != expected_path:
                    raise RuntimeError("canonical stream recovery wrote an unexpected identity")
                restored += 1

    target_stream_count = len(candidates) * len(STREAM_FIELDS)
    final_present = sum(
        path.is_file() and not path.is_symlink() and _sha256_bytes(path.read_bytes()) == digest
        for candidate in candidates
        for digest, path in candidate.expected.values()
    )
    if execute and final_present != target_stream_count:
        raise RuntimeError("canonical stream recovery did not close every target")
    return {
        "schema": "legalbot.v111.canonical-vault-recovery.v1",
        "authorizing": False,
        "execute": execute,
        "manifest_sha256": _sha256_bytes(manifest_path.read_bytes()),
        "source_count": len(candidates),
        "target_stream_count": target_stream_count,
        "already_present_before": already_present,
        "restored": restored,
        "exact_streams_present_after": final_present,
        "audit_provenance_objects_restored": 0,
        "passed": final_present == target_stream_count if execute else True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    result = restore(manifest_path=args.manifest.resolve(), execute=args.execute)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
