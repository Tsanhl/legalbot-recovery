"""Fail-closed selected-schema registry and canonical JSON digests.

New Phase-2 objects may use only the selected schemas. Legacy schemas remain
readable through the explicit audit method and can never be selected for a new
job, release, evaluation run or training experiment.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import orjson
from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from jsonschema.exceptions import ValidationError  # type: ignore[import-untyped]

CANONICALIZATION_ID = "legalbot.canonical-json.orjson-3.11.1.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

SELECTED_SCHEMA_FILES: tuple[str, ...] = (
    "conversation-snapshot.v1.schema.json",
    "matter-fact-snapshot.v2.schema.json",
    "query-plan.v2.schema.json",
    "answer-job.v1.schema.json",
    "job-event.v1.schema.json",
    "knowledge-generation-manifest.v1.schema.json",
    "retrieval-result.v1.schema.json",
    "evidence-pack.v1.schema.json",
    "claim-set.v1.schema.json",
    "validation-report.v1.schema.json",
    "verified-release.v1.schema.json",
    "runtime-capability-manifest.v1.schema.json",
    "evaluation-run.v1.schema.json",
    "evaluation-case-result.v2.schema.json",
    "ge-system-case-result.v1.schema.json",
    "ge-system-run.v1.schema.json",
    "ge-visible-diagnostic-supplement.v1.schema.json",
    "ge-diagnostic-case-result.v1.schema.json",
    "ge-cycle-assessment.v2.schema.json",
    "training-experiment.v1.schema.json",
)

LEGACY_SCHEMA_FILES: tuple[str, ...] = (
    "query-plan.v1.schema.json",
    "matter-fact-snapshot.v1.schema.json",
    "evaluation-case-result.v1.schema.json",
    "ge-cycle-assessment.v1.schema.json",
)


class CanonicalJSONError(ValueError):
    """The value cannot enter the pinned canonical JSON domain."""


class SchemaSelectionError(ValueError):
    """The object does not name one selected schema."""


class LegacySchemaRejectedError(SchemaSelectionError):
    """A legacy read-only schema was presented to a new-write path."""


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalJSONError(f"duplicate JSON object member: {key}")
        result[key] = value
    return result


def load_json_strict(raw: bytes | str) -> Any:
    """Decode JSON while rejecting duplicate members and non-finite numbers."""

    text = raw.decode("utf-8") if isinstance(raw, bytes) else raw

    def reject_constant(value: str) -> None:
        raise CanonicalJSONError(f"non-finite JSON number: {value}")

    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise CanonicalJSONError("JSON is not valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise CanonicalJSONError("invalid JSON") from exc


def _assert_canonical_domain(value: Any, *, path: str = "$") -> None:
    if value is None or isinstance(value, bool | str):
        return
    if isinstance(value, int):
        if not -(2**63) <= value <= 2**63 - 1:
            raise CanonicalJSONError(f"integer outside signed 64-bit range at {path}")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalJSONError(f"non-finite number at {path}")
        return
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise CanonicalJSONError(f"non-string object key at {path}")
            _assert_canonical_domain(child, path=f"{path}.{key}")
        return
    if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray | memoryview):
        for index, child in enumerate(value):
            _assert_canonical_domain(child, path=f"{path}[{index}]")
        return
    raise CanonicalJSONError(f"non-JSON value at {path}: {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    """Encode with the repository-pinned canonicalization profile.

    The profile is UTF-8, sorted object keys, no insignificant whitespace and
    a terminating newline. Values outside the strict JSON domain are rejected.
    The exact implementation/version is part of every schema bundle manifest.
    """

    _assert_canonical_domain(value)
    try:
        return orjson.dumps(value, option=orjson.OPT_SORT_KEYS | orjson.OPT_APPEND_NEWLINE)
    except (TypeError, orjson.JSONEncodeError) as exc:
        raise CanonicalJSONError("canonical JSON encoding failed") from exc


def content_sha256(value: Any, *, digest_field: str = "content_sha256") -> str:
    """Digest a contract object without its self-describing digest field."""

    if not isinstance(value, Mapping):
        raise CanonicalJSONError("contract object must be a mapping")
    material = dict(value)
    material.pop(digest_field, None)
    return hashlib.sha256(canonical_json_bytes(material)).hexdigest()


def seal_contract(
    value: Mapping[str, Any], *, digest_field: str = "content_sha256"
) -> dict[str, Any]:
    sealed = deepcopy(dict(value))
    sealed[digest_field] = content_sha256(sealed, digest_field=digest_field)
    return sealed


@dataclass(frozen=True, slots=True)
class RegisteredSchema:
    filename: str
    schema_name: str
    schema_id: str
    sha256: str
    selected: bool
    document: Mapping[str, Any]


class ContractSchemaRegistry:
    """Load, digest and validate the exact selected Phase-2 schema bundle."""

    def __init__(self, schema_dir: Path) -> None:
        self.schema_dir = schema_dir
        self._selected = self._load(SELECTED_SCHEMA_FILES, selected=True)
        self._legacy = self._load(LEGACY_SCHEMA_FILES, selected=False)
        overlap = set(self._selected).intersection(self._legacy)
        if overlap:
            raise SchemaSelectionError(
                f"selected/legacy schema identity overlap: {sorted(overlap)}"
            )
        self._manifest = self._build_manifest()
        self._manifest_sha256 = hashlib.sha256(canonical_json_bytes(self._manifest)).hexdigest()

    @classmethod
    def from_project_root(cls, project_root: Path) -> ContractSchemaRegistry:
        return cls(project_root / "docs" / "system-design" / "schemas")

    def _load(self, filenames: tuple[str, ...], *, selected: bool) -> dict[str, RegisteredSchema]:
        result: dict[str, RegisteredSchema] = {}
        for filename in filenames:
            path = self.schema_dir / filename
            if not path.is_file():
                raise SchemaSelectionError(f"registered schema is missing: {filename}")
            raw = path.read_bytes()
            document = load_json_strict(raw)
            if not isinstance(document, dict):
                raise SchemaSelectionError(f"schema is not an object: {filename}")
            Draft202012Validator.check_schema(document)
            schema_id = str(document.get("$id") or "")
            schema_const = document.get("properties", {}).get("schema", {}).get("const")
            if not schema_id or not isinstance(schema_const, str):
                raise SchemaSelectionError(f"schema identity is incomplete: {filename}")
            if schema_const in result:
                raise SchemaSelectionError(f"duplicate schema const: {schema_const}")
            result[schema_const] = RegisteredSchema(
                filename=filename,
                schema_name=schema_const,
                schema_id=schema_id,
                sha256=hashlib.sha256(raw).hexdigest(),
                selected=selected,
                document=document,
            )
        return result

    def _build_manifest(self) -> dict[str, Any]:
        entries = [
            {
                "filename": item.filename,
                "schema": item.schema_name,
                "schema_id": item.schema_id,
                "sha256": item.sha256,
            }
            for item in self._selected.values()
        ]
        return {
            "schema": "legalbot.schema-selection-manifest.v1",
            "canonicalization": CANONICALIZATION_ID,
            "selected": sorted(entries, key=lambda item: item["schema"]),
        }

    @property
    def manifest(self) -> dict[str, Any]:
        return deepcopy(self._manifest)

    @property
    def manifest_sha256(self) -> str:
        return self._manifest_sha256

    @property
    def selected_schema_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._selected))

    def validate_new(self, value: Mapping[str, Any], *, verify_digest: bool = True) -> None:
        schema_name = value.get("schema")
        if not isinstance(schema_name, str):
            raise SchemaSelectionError("contract object has no schema identity")
        if schema_name in self._legacy:
            raise LegacySchemaRejectedError(f"legacy schema is read-only: {schema_name}")
        registered = self._selected.get(schema_name)
        if registered is None:
            raise SchemaSelectionError(f"schema is not selected: {schema_name}")
        Draft202012Validator(
            registered.document,
            format_checker=FormatChecker(),
        ).validate(dict(value))
        if verify_digest and "content_sha256" in value:
            supplied = value["content_sha256"]
            if not isinstance(supplied, str) or _SHA256.fullmatch(supplied) is None:
                raise CanonicalJSONError("content_sha256 is malformed")
            if supplied != content_sha256(value):
                raise CanonicalJSONError("content_sha256 does not match canonical content")

    def validate_legacy_for_audit(self, value: Mapping[str, Any]) -> None:
        schema_name = value.get("schema")
        if not isinstance(schema_name, str) or schema_name not in self._legacy:
            raise SchemaSelectionError("object is not a registered legacy schema")
        Draft202012Validator(
            self._legacy[schema_name].document,
            format_checker=FormatChecker(),
        ).validate(dict(value))

    def decode_and_validate_new(
        self, raw: bytes | str, *, verify_digest: bool = True
    ) -> dict[str, Any]:
        value = load_json_strict(raw)
        if not isinstance(value, dict):
            raise SchemaSelectionError("contract JSON must be an object")
        self.validate_new(value, verify_digest=verify_digest)
        return value


__all__ = [
    "CANONICALIZATION_ID",
    "LEGACY_SCHEMA_FILES",
    "SELECTED_SCHEMA_FILES",
    "CanonicalJSONError",
    "ContractSchemaRegistry",
    "LegacySchemaRejectedError",
    "SchemaSelectionError",
    "ValidationError",
    "canonical_json_bytes",
    "content_sha256",
    "load_json_strict",
    "seal_contract",
]
