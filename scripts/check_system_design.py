#!/usr/bin/env python3
"""Validate the living LegalBot system-design documents and selected schemas."""

from __future__ import annotations

import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "docs" / "system-design"
SCHEMAS = DESIGN / "schemas"
REGISTRY = DESIGN / "SCHEMA_REGISTRY.md"

MAINTAINED_DOCS = [
    ROOT / "README.md",
    ROOT / "AGENTS.md",
    ROOT / "docs" / "CURRENT_STATE.md",
    ROOT / "docs" / "V111_SYSTEM_DESIGN.md",
    ROOT / "docs" / "V111_RELEASE_ROADMAP.md",
    ROOT / "docs" / "V111_REBUILD_CHECKLIST.md",
    *sorted(DESIGN.glob("*.md")),
]


def synthesize(schema: dict | bool, name: str = "", *, salt: int = 0):
    if schema is True:
        return None
    if schema is False:
        raise AssertionError(f"cannot synthesize forbidden schema at {name}")
    if "const" in schema:
        return schema["const"]
    if "enum" in schema:
        values = [value for value in schema["enum"] if value is not None]
        return values[salt % len(values)] if values else None
    if "oneOf" in schema:
        return synthesize(schema["oneOf"][0], name, salt=salt)
    value_type = schema.get("type")
    if isinstance(value_type, list):
        value_type = next((item for item in value_type if item != "null"), "null")
    if value_type == "object" or ("properties" in schema and value_type is None):
        return {
            key: synthesize(schema["properties"][key], key, salt=salt)
            for key in schema.get("required", [])
            if key in schema.get("properties", {})
        }
    if value_type == "array":
        prefix_items = schema.get("prefixItems", [])
        item_schema = schema.get("items", {})
        return [
            synthesize(
                prefix_items[index] if index < len(prefix_items) else item_schema,
                f"{name}[{index}]",
                salt=index if schema.get("uniqueItems") is True else 0,
            )
            for index in range(schema.get("minItems", 0))
        ]
    if value_type in {"integer", "number"}:
        return schema.get("minimum", 0) + salt
    if value_type == "boolean":
        return False
    if value_type == "null":
        return None
    if value_type in {"string", None}:
        if schema.get("format") == "date-time":
            return "2026-09-01T00:00:00Z"
        if schema.get("format") == "date":
            return "2026-09-01"
        pattern = schema.get("pattern", "")
        if "0-9a-f" in pattern and "{64}" in pattern:
            return f"{salt:064x}"[-64:]
        if "A-Za-z0-9" in pattern:
            return f"abc{salt}"
        if "a-z0-9" in pattern:
            return f"code{salt}"
        return "x" * max(1, schema.get("minLength", 1))
    raise AssertionError(f"cannot synthesize {name}: {schema}")


def schema_names_from_registry():
    text = REGISTRY.read_text(encoding="utf-8")
    selected_text, remainder = text.split("## Legacy read-only schemas", 1)
    legacy_text = remainder.split("## Selection and digest rules", 1)[0]
    selected = re.findall(r"`([^`]+\.schema\.json)`", selected_text)
    legacy = re.findall(r"`([^`]+\.schema\.json)`", legacy_text)
    return selected, legacy


def check_schemas() -> None:
    selected, legacy = schema_names_from_registry()
    assert len(selected) == len(set(selected)), "duplicate selected schema entry"
    assert not set(selected).intersection(legacy), "selected/legacy schema overlap"

    root_ids: dict[str, str] = {}
    loaded: dict[str, dict] = {}
    for path in sorted(SCHEMAS.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(data)
        root_id = data["$id"]
        assert root_id not in root_ids, f"duplicate root $id: {root_id}"
        root_ids[root_id] = path.name
        loaded[path.name] = data

        instance = synthesize(data)
        if path.name == "query-plan.v2.schema.json":
            instance.update(
                data_intent="KNOWLEDGE_ONLY",
                response_disposition="ANSWER",
                jurisdiction_status="explicit",
                as_of_date_status="explicit",
            )
        if path.name == "claim-set.v1.schema.json":
            instance["claims"][0]["fact_ids"] = ["abc"]
        Draft202012Validator(data, format_checker=FormatChecker()).validate(instance)

    for name in selected + legacy:
        assert name in loaded, f"registry references missing schema: {name}"

    query_dispositions = set(loaded["query-plan.v2.schema.json"]["properties"]["response_disposition"]["enum"])
    release_dispositions = set(loaded["verified-release.v1.schema.json"]["properties"]["response_disposition"]["enum"])
    assert release_dispositions == query_dispositions - {"SYSTEM_HOLD"}

    release_states = set(loaded["verified-release.v1.schema.json"]["properties"]["release_state"]["enum"])
    event_states = {
        value
        for value in loaded["job-event.v1.schema.json"]["properties"]["data"]["properties"]["release_state"]["enum"]
        if value is not None
    }
    assert release_states == event_states

    assert set(loaded["query-plan.v2.schema.json"]["properties"]["data_intent"]["enum"]) == {
        "NO_RETRIEVAL",
        "KNOWLEDGE_ONLY",
        "MATTER_ONLY",
        "HYBRID",
    }


def check_links_and_language() -> None:
    missing: list[str] = []
    for path in MAINTAINED_DOCS:
        assert path.is_file(), f"missing maintained document: {path}"
        text = path.read_text(encoding="utf-8")
        for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", text):
            if target.startswith(("http://", "https://", "#")):
                continue
            target = target.split("#", 1)[0]
            if target and not (path.parent / target).resolve().exists():
                missing.append(f"{path.relative_to(ROOT)} -> {target}")
    assert not missing, "broken maintained links:\n" + "\n".join(missing)

    active_text = "\n".join(path.read_text(encoding="utf-8") for path in MAINTAINED_DOCS)
    forbidden = [
        "Revision 7",
        "revision-7",
        "Step-1 implementation contracts",
        "Every design successor records its predecessor",
        "only outstanding owner decisions",
    ]
    for phrase in forbidden:
        assert phrase not in active_text, f"stale design-history language: {phrase}"

    coverage = (DESIGN / "COVERAGE_MATRIX.md").read_text(encoding="utf-8")
    assert coverage.count("\n|") >= 25, "coverage matrix is unexpectedly incomplete"


def main() -> None:
    check_schemas()
    check_links_and_language()
    selected, legacy = schema_names_from_registry()
    print(
        "System-design check passed: "
        f"{len(selected)} selected schemas, {len(legacy)} legacy schemas, "
        f"{len(MAINTAINED_DOCS)} maintained documents."
    )


if __name__ == "__main__":
    main()
