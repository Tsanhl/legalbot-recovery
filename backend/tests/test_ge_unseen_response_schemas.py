"""Synthetic schema checks only: no provider, jobs, bank reads or filesystem writes.

These are offline structural checks, not evidence of remote API acceptance.
The novelty schema's separate uniqueItems compatibility concern is inspection-only.
"""

from __future__ import annotations

import copy

import jsonschema
import pytest
from scripts import ge_auto_case_protocol as protocol
from scripts import ge_unseen_fixture_repair as fixture
from scripts import ge_unseen_novelty_review as novelty

FIXTURE_SCHEMAS = {
    "fixture-requirement": fixture.REQUIREMENT_SCHEMA,
    "fixture-formatter": fixture.FORMATTER_SCHEMA,
}
PROTOCOL_SCHEMAS = {"protocol-" + name: schema for name, schema in vars(protocol).items()
                    if name.endswith("_SCHEMA")}
SCHEMAS = {**FIXTURE_SCHEMAS, **PROTOCOL_SCHEMAS, "novelty-review": novelty.review_schema()}


def nodes(schema, path=()):
    """Visit schema nodes, including every anyOf branch and array item schema."""
    yield path, schema
    for name, child in schema.get("properties", {}).items():
        yield from nodes(child, (*path, "properties", name))
    if "items" in schema:
        yield from nodes(schema["items"], (*path, "items"))
    for index, child in enumerate(schema.get("anyOf", [])):
        yield from nodes(child, (*path, "anyOf", index))


def assert_typed(schema):
    for path, node in nodes(schema):
        if "anyOf" in node:
            assert set(node) == {"anyOf"}, path
            assert node["anyOf"], path
            continue
        assert node.get("type") in {"object", "array", "string", "integer", "boolean", "null"}, path
        values = [node["const"]] if "const" in node else node.get("enum", [])
        for value in values:
            expected = {str: "string", bool: "boolean", type(None): "null"}[type(value)]
            assert node["type"] == expected, path


@pytest.mark.parametrize("name,schema", SCHEMAS.items(), ids=SCHEMAS)
def test_recursive_response_schema_types_and_closed_objects(name, schema):
    jsonschema.Draft202012Validator.check_schema(schema)
    assert schema["type"] == "object"
    assert "anyOf" not in schema
    assert_typed(schema)
    for path, node in nodes(schema):
        if node.get("type") == "object":
            assert node["additionalProperties"] is False, path
            assert node["required"] == list(node["properties"]), path
        if node.get("type") == "array":
            assert isinstance(node["items"], dict), path


@pytest.mark.parametrize("name,schema", SCHEMAS.items(), ids=SCHEMAS)
def test_schema_size_stays_within_documented_strict_limits(name, schema):
    # https://developers.openai.com/api/docs/guides/structured-outputs#supported-schemas
    properties = enum_values = text_length = 0
    for path, node in nodes(schema):
        # anyOf selects an alternative; it does not introduce a data container.
        assert path.count("properties") + path.count("items") <= 10, path
        properties += len(node.get("properties", {}))
        enum_values += len(node.get("enum", []))
        text_length += sum(len(key) for key in node.get("properties", {}))
        values = [node["const"]] if "const" in node else node.get("enum", [])
        chars = sum(len(value) for value in values if isinstance(value, str))
        text_length += chars
        if len(values) > 250:
            assert chars <= 15_000, path
    assert properties <= 5000
    assert enum_values <= 1000
    assert text_length <= 120_000


@pytest.mark.parametrize("name,schema", {**FIXTURE_SCHEMAS, **PROTOCOL_SCHEMAS}.items())
def test_fixture_and_protocol_use_audited_strict_keyword_subset(name, schema):
    # Non-fine-tuned model subset; retain the existing value/length/range bounds.
    allowed = {"type", "properties", "required", "additionalProperties", "items",
               "minItems", "maxItems", "anyOf", "const", "enum", "minLength",
               "maxLength", "pattern", "minimum", "maximum"}
    for path, node in nodes(schema):
        assert not set(node) - allowed, (path, set(node) - allowed)


@pytest.mark.parametrize("name,schema", {**FIXTURE_SCHEMAS, **PROTOCOL_SCHEMAS}.items())
def test_typed_literals_preserve_exact_accepted_values(name, schema):
    local_check = fixture._schema_ok if name.startswith("fixture-") else protocol.schema_ok
    for path, node in nodes(schema):
        if "const" not in node and "enum" not in node:
            continue
        original = {key: value for key, value in node.items() if key != "type"}
        values = [node["const"]] if "const" in node else node["enum"]
        validator = jsonschema.Draft202012Validator(node)
        for value in [*values, None, True, False, 0, 1, "null", "unlisted-value", {}, []]:
            expected = any(type(value) is type(allowed) and value == allowed for allowed in values)
            assert validator.is_valid(value) == expected, (path, value)
            assert local_check(value, original) == local_check(value, node) == expected, (path, value)


@pytest.mark.parametrize("name,schema", SCHEMAS.items(), ids=SCHEMAS)
def test_recursive_audit_detects_missing_and_wrong_types_in_every_literal(name, schema):
    for path, node in nodes(schema):
        if "const" not in node and "enum" not in node:
            continue
        for replacement in (None, "integer"):
            changed = copy.deepcopy(schema)
            target = changed
            for step in path:
                target = target[step]
            if replacement is None:
                target.pop("type")
            else:
                target["type"] = replacement
            with pytest.raises(AssertionError):
                assert_typed(changed)


def test_fixture_schema_factories_return_matching_fresh_schemas():
    for factory, schema in ((fixture.requirement_schema, fixture.REQUIREMENT_SCHEMA),
                            (fixture.format_schema, fixture.FORMATTER_SCHEMA)):
        generated = factory()
        assert generated == schema
        generated["properties"]["schema"]["type"] = "integer"
        assert factory() == schema
