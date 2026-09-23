"""Synthetic pure-function tests; no host initialization, models or artifact IO."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import sys
import unicodedata
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

import pytest
from scripts import ge_auto_case_protocol as protocol


@pytest.fixture(scope="module")
def visible():
    # Execute the real module with its unused execution dependencies fenced off.
    def forbidden(*args, **kwargs):
        raise AssertionError("host/model/artifact access is outside these tests")

    stubs = {}
    for name, exports in {
        "scripts.ge_auto_case_host": ("CaseHost", "runtime_manifest"),
        "scripts.ge_auto_role_runtime": ("CodexRoleRuntime", "safe", "write_new"),
    }.items():
        stub = ModuleType(name)
        for export in exports:
            setattr(stub, export, forbidden)
        stubs[name] = stub
    path = Path(protocol.__file__).with_name("ge_auto_visible_case_execution.py")
    spec = importlib.util.spec_from_file_location("synthetic_visible_execution", path)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, stubs):
        spec.loader.exec_module(module)
    return module


def case():
    prompt = "Synthetic receipt: Cafe\u0301, £12.\r\nWhat does this record show? "
    return {
        "case_id": "synthetic-visible-01", "prompt": prompt,
        "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        "jurisdiction": "GB-SCT", "relevant_date": "2021-10-03",
        "follow_up": {"prompt": "WITHHELD_FUTURE_TURN"},
        "uploads": [{"text": "WITHHELD_UNEXTRACTED_UPLOAD"}],
        "expected_facts": ["WITHHELD_EXPECTATION"], "answer": "WITHHELD_ANSWER",
        "reference_proposals": [{"url": "https://withheld.example/authority"}],
        "oracle": "WITHHELD_ORACLE", "review": {"reason": "WITHHELD_REVIEW"},
    }


def test_projection_discloses_only_due_fields_and_preserves_exact_prompt(visible):
    original = case()
    before = copy.deepcopy(original)
    assert visible.projection(original) == {
        "case_id": "synthetic-visible-01", "question": original["prompt"],
        "question_sha256": hashlib.sha256(original["prompt"].encode("utf-8")).hexdigest(),
        "as_of_date": "2021-10-03", "jurisdictions": ["Scotland"],
    }
    assert original == before


@pytest.mark.parametrize("defect", ["changed-text", "whitespace", "unicode-normalization", "wrong-hash"])
def test_projection_rejects_changed_prompt_bytes_or_hash(visible, defect):
    value = case()
    if defect == "changed-text":
        value["prompt"] = value["prompt"].replace("£12", "£21")
    elif defect == "whitespace":
        value["prompt"] = value["prompt"].rstrip()
    elif defect == "unicode-normalization":
        value["prompt"] = unicodedata.normalize("NFC", value["prompt"])
    else:
        value["prompt_sha256"] = "0" * 64
    before = copy.deepcopy(value)
    with pytest.raises(ValueError, match="^VISIBLE_QUESTION_CHANGED$"):
        visible.projection(value)
    assert value == before


@pytest.mark.parametrize("code,nation", [
    ("GB-ENG", "England"), ("GB-WLS", "Wales"), ("GB-SCT", "Scotland"),
    ("GB-NIR", "Northern Ireland"), ("US-FED", "US federal"),
    ("US-CA", "California"), ("US-NY", "New York"), ("US-TX", "Texas"),
])
def test_projection_maps_explicit_jurisdiction_and_retains_supplied_date(visible, code, nation):
    value = case() | {"jurisdiction": code}
    due = visible.projection(value)
    assert due["jurisdictions"] == [nation]
    assert due["as_of_date"] == "2021-10-03"


@pytest.mark.parametrize("date", ["1999-12-31", "2032-02-29", None])
def test_projection_does_not_invent_or_replace_as_of_date(visible, date):
    assert visible.projection(case() | {"relevant_date": date})["as_of_date"] == date


@pytest.mark.parametrize("code", ["GB", "US", "US-PR", None])
def test_projection_unknown_jurisdiction_has_no_fallback(visible, code):
    with pytest.raises(KeyError):
        visible.projection(case() | {"jurisdiction": code})


def captured_references():
    source_hash = hashlib.sha256(b"synthetic captured source bytes").hexdigest()
    sources = {source_hash: {
        "canonical_url": "https://law.example/captured-act",
        "final_url": "https://law.example/captured-act?view=plain",
        "parts": [{"part_id": "section-2", "locator": "Section 2"},
                  {"part_id": "schedule-1", "locator": "Schedule 1"}],
    }}
    point = {"source_sha256": source_hash, "part_id": "section-2"}
    condition = {"source_sha256": source_hash, "part_id": "schedule-1"}
    evidence = [{"origin": "CASE_LOCAL", "proposition": {
        "proposition_id": "p1", "point": point, "conditions": [condition],
        "context": [point], "currentness": {"checks": [condition]},
    }}]
    return source_hash, sources, evidence


def answer(ids):
    return {"status": "ANSWER", "answer": "Raw **synthetic** answer.\r\nKeep this text. ",
            "cited_proposition_ids": ids}


def test_links_use_exact_captured_source_map_and_preserve_raw_answer():
    sha, sources, evidence = captured_references()
    before = copy.deepcopy((sources, evidence))
    references = protocol.retrieved_source_references(evidence, sources)
    assert references == [{"proposition_id": "p1", "sources": [{
        "source_sha256": sha, "canonical_url": "https://law.example/captured-act",
        "final_url": "https://law.example/captured-act?view=plain",
        "locators": [{"part_id": "section-2", "locator": "Section 2"},
                     {"part_id": "schedule-1", "locator": "Schedule 1"}],
    }]}]
    raw = answer(["p1"])
    frozen = copy.deepcopy((raw, references))
    rendered = protocol.render_source_links(raw, references)
    assert rendered == raw["answer"] + "\n\nSources\n\n- [law.example — Section 2; Schedule 1](https://law.example/captured-act)"
    assert (raw, references) == frozen
    assert (sources, evidence) == before


@pytest.mark.parametrize("defect,code", [("source", "RETRIEVED_SOURCE_REFERENCE_MISSING"),
                                       ("part", "RETRIEVED_LOCATOR_REFERENCE_MISSING")])
def test_source_map_refuses_uncaptured_source_or_locator(defect, code):
    _, sources, evidence = captured_references()
    point = evidence[0]["proposition"]["point"]
    point["source_sha256" if defect == "source" else "part_id"] = "not-captured"
    with pytest.raises(protocol.ProtocolError, match=f"^{code}$"):
        protocol.retrieved_source_references(evidence, sources)


def test_unknown_citation_is_refused_and_uncited_sources_are_not_appended():
    _, sources, evidence = captured_references()
    references = protocol.retrieved_source_references(evidence, sources)
    with pytest.raises(protocol.ProtocolError, match="^RENDER_UNRETRIEVED_CITATION$"):
        protocol.render_source_links(answer(["not-retrieved"]), references)
    raw = answer([])
    assert protocol.render_source_links(raw, references) == raw["answer"]


@pytest.mark.parametrize("url", ["http://law.example/act", "javascript:alert(1)", "file:///synthetic.txt",
                                "//law.example/act", "https:///missing-host",
                                "https://user@law.example/act", "https://user:password@law.example/act"])
def test_unsafe_captured_link_is_refused(url):
    _, sources, evidence = captured_references()
    references = protocol.retrieved_source_references(evidence, sources)
    references[0]["sources"][0]["canonical_url"] = url
    with pytest.raises(protocol.ProtocolError, match="^RENDER_UNSAFE_SOURCE_URL$"):
        protocol.render_source_links(answer(["p1"]), references)


def test_link_labels_and_destinations_are_escaped_without_editing_answer():
    _, sources, evidence = captured_references()
    references = protocol.retrieved_source_references(evidence, sources)
    source = references[0]["sources"][0]
    source["canonical_url"] = "https://law.example/a (draft)/O'Neil?q=one two#part(2)"
    source["locators"] = [{"part_id": "section-2",
                           "locator": "Section [A] <tag> *bold* _x_ `tick` \\file\r\n\tline"}]
    raw = answer(["p1"])
    before = copy.deepcopy((raw, references))
    assert protocol.render_source_links(raw, references) == (
        raw["answer"] + "\n\nSources\n\n"
        r"- [law.example — Section \[A\] \<tag\> \*bold\* \_x\_ \`tick\` \\file line]"
        "(https://law.example/a%20%28draft%29/O%27Neil?q=one%20two#part%282%29)"
    )
    assert (raw, references) == before


def test_duplicate_citations_sources_and_locators_render_once_in_first_citation_order():
    _, sources, evidence = captured_references()
    references = protocol.retrieved_source_references(evidence, sources)
    first = references[0]["sources"][0]
    second = copy.deepcopy(first)
    second.update(canonical_url="https://other.example/captured-rule",
                  final_url="https://other.example/captured-rule")
    second["locators"] = [{"part_id": "rule-3", "locator": "Rule 3"}] * 2
    references[0]["sources"].extend([second, copy.deepcopy(first)])
    references.append({"proposition_id": "p2", "sources": [second]})
    raw = answer(["p2", "p1", "p2", "p1"])
    before = copy.deepcopy((raw, references))
    expected = (raw["answer"] + "\n\nSources\n\n"
                "- [other.example — Rule 3](https://other.example/captured-rule)\n"
                "- [law.example — Section 2; Schedule 1](https://law.example/captured-act)")
    assert protocol.render_source_links(raw, references) == expected
    assert protocol.render_source_links(raw, list(reversed(references))) == expected
    assert protocol.render_source_links(raw, references) == expected
    assert (raw, references) == before
