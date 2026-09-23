"""A research-only zero baseline never relaxes production generation v1."""
from copy import deepcopy

import pytest
from app.contracts import ContractSchemaRegistry, seal_contract
from app.research.ge_auto_index import digest
from jsonschema.exceptions import ValidationError

from backend.tests.test_ge_auto_index import WORKSPACE, bind, contracts


def empty(gen):
    gen = deepcopy(gen)
    gen.update(schema="legalbot.research-empty-baseline.v1", sources=[],
               source_manifest_sha256=digest([]), non_live=True, production_admission=False, training=False)
    gen["counts"] = {k: 1024 if k == "embedding_dimensions" else 0 for k in gen["counts"]}
    return seal_contract(gen)


def test_selected_empty_research_baseline_binds_full_v2_lineage():
    registry = ContractSchemaRegistry.from_project_root(WORKSPACE)
    plan, facts, gen, conversation = contracts(registry)
    baseline = empty(gen)
    registry.validate_new(baseline)
    assert bind(registry, plan, facts, baseline, conversation).knowledge_generation_sha256 == baseline["content_sha256"]


@pytest.mark.parametrize("change", [
    {"non_live": False}, {"production_admission": True}, {"training": True},
    {"source_manifest_sha256": "0"*64}, {"sealed_at": None}, {"closure_status": "candidate"},
])
def test_empty_baseline_cannot_assert_other_scope(change):
    registry = ContractSchemaRegistry.from_project_root(WORKSPACE)
    _, _, gen, _ = contracts(registry)
    baseline = empty(gen)
    baseline.update(change)
    with pytest.raises(ValidationError):
        registry.validate_new(seal_contract(baseline))


@pytest.mark.parametrize("counter", ["source_versions", "canonical_objects", "chunks", "lexical_rows", "vector_rows"])
def test_hidden_source_or_row_count_rejected(counter):
    registry = ContractSchemaRegistry.from_project_root(WORKSPACE)
    _, _, gen, _ = contracts(registry)
    baseline = empty(gen)
    baseline["counts"][counter] = 1
    with pytest.raises(ValidationError):
        registry.validate_new(seal_contract(baseline))


def test_production_knowledge_v1_still_requires_source():
    registry = ContractSchemaRegistry.from_project_root(WORKSPACE)
    _, _, gen, _ = contracts(registry)
    gen["sources"] = []
    with pytest.raises(ValidationError):
        registry.validate_new(seal_contract(gen))
