"""Transport projection only; full immutable schemas still validate every output.

OpenAI's documented array constraint subset lists minItems/maxItems. Keep local
uniqueItems checks without depending on an undocumented remote keyword. This
never changes a prepared schema, scoring rule, prompt, or accepted model output.
"""
from copy import deepcopy


def response_transport_schema(schema):
    result = deepcopy(schema)
    def visit(node):
        if not isinstance(node, dict):
            raise ValueError("RESPONSE_SCHEMA_NODE_REQUIRED")
        if "uniqueItems" in node:
            if node.get("type") != "array" or type(node["uniqueItems"]) is not bool:
                raise ValueError("INVALID_UNIQUENESS_CONSTRAINT")
            node.pop("uniqueItems")
        for child in node.get("properties", {}).values():
            visit(child)
        if "items" in node:
            visit(node["items"])
        for child in node.get("anyOf", []):
            visit(child)
    visit(result)
    return result
