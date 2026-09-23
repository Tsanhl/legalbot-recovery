"""Disk-free synthetic boundary tests, separate from the actual visible proof.

These use the real selected schema registry and structural chunker. No model,
network or private input is touched. Real model/Lance execution is performed only
by the explicitly authorized successor runner and recorded in its own new root.
"""

from __future__ import annotations

import copy
import unittest
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from backend.app.contracts import ContractSchemaRegistry
from backend.app.ingestion.models import BlockKind, DocumentFormat, ParseResult, ParseStatus, StructuralBlock
from scripts import ge_auto_successor_index_validation as v


H = v.digest(b"synthetic unit fixture, not an actual review or execution receipt")
STAMP = "2026-09-05T00:00:00+00:00"


def fixture():
    original = {"proposition_id": "ENG-SCOPE", "proposed_proposition": "A synthetic legal rule.",
                "source_id": H, "jurisdiction": "GB-ENG", "relevant_date": "2026-09-05"}
    row = {**original, "original_proposition_sha256": v.digest(original), "reviewer_id": v.REVIEWER,
        "jurisdiction": "England", "as_of_date": "2026-09-05", "valid_from": "2026-09-05",
        "valid_to": "2026-09-05", "decision": "ELIGIBLE_RESEARCH_ONLY",
        "checks": {k: {"status": "PASS", "reason": "Synthetic dependency check.",
                       "evidenceURL": "https://www.legislation.gov.uk/synthetic"} for k in v.core.REVIEW_CHECKS},
        "validity_window_authorized": True, "requested_point_in_time_only": True,
        "raw_quote_verified": True, "quote": "Synthetic rule", "quote_sha256": v.digest(b"Synthetic rule"),
        "uncertainties": [{"blocks_this_research_proposition": False,
            "scope": "CASE_FACT_OR_ALTERNATE_ROUTE_NOT_DECIDED", "reason": "Facts not verified."}],
        "professional_legal_sign_off": False, "qualified_legal_review": False,
        "legal_gold": False, "admitted": False, "full_current_law_eligible": False}
    return original, row


class GateBoundaryTests(unittest.TestCase):
    def test_only_explicit_source_code_paths_allowed(self):
        self.assertEqual(v.public_path("scripts/ge_auto_successor_index_validation.py"),
                         v.ROOT / "scripts/ge_auto_successor_index_validation.py")
        for name in (".private/bank.json", "../another-project/a.json", "/private/file",
                     "data/evaluations/general-enquiries/retired-bank/rows.json",
                     str(v.VISIBLE.relative_to(v.ROOT)) + "/candidate-answers/answer.json",
                     str(v.VISIBLE.relative_to(v.ROOT)) + "/independent-source-review/../answers.json"):
            with self.subTest(name=name), self.assertRaises(v.ValidationHold):
                v.public_path(name)

    def test_duplicate_review_record_is_not_silently_replaced(self):
        with self.assertRaisesRegex(v.ValidationHold, "HOLD_DUPLICATE_INVENTORY"):
            v.exact_map([{"id": "one"}, {"id": "one"}], "id")

    def test_all_eleven_checks_and_exact_original_binding_required(self):
        original, row = fixture()
        v.check_decision(row, original)
        for key in v.core.REVIEW_CHECKS:
            changed = copy.deepcopy(row)
            changed["checks"][key]["status"] = "HOLD"
            with self.subTest(key=key), self.assertRaisesRegex(v.ValidationHold, "HOLD_ELEVEN_REVIEW_CHECKS"):
                v.check_decision(changed, original)
        with self.assertRaisesRegex(v.ValidationHold, "HOLD_PROPOSITION_REVIEW_BINDING"):
            v.check_decision(row, {**original, "proposed_proposition": "Changed legal claim"})

    def test_material_uncertainty_cannot_be_reclassified_by_runner(self):
        _, row = fixture()
        self.assertEqual(v.nonblocking_limits(row), row["uncertainties"])
        for change in ({"blocks_this_research_proposition": True},
                       {"scope": "MATERIAL_LAW_UNKNOWN"}, {"reason": ""}):
            changed = copy.deepcopy(row)
            changed["uncertainties"][0].update(change)
            with self.subTest(change=change), self.assertRaisesRegex(v.ValidationHold, "HOLD_MATERIAL_SOURCE_UNCERTAINTY"):
                v.nonblocking_limits(changed)

    def test_review_dates_and_quote_hash_not_invented(self):
        original, row = fixture()
        for change, code in (({"valid_to": "2099-12-31"}, "HOLD_REVIEW_DATE_WINDOW"),
                             ({"quote": "Changed exact quote"}, "HOLD_QUOTE_HASH"),
                             ({"admitted": True}, "HOLD_REVIEW_SCOPE_FLAGS")):
            with self.subTest(change=change), self.assertRaisesRegex(v.ValidationHold, code):
                v.check_decision({**row, **change}, original)

    def test_real_chunker_rejects_unreviewed_neighbor(self):
        parsed = ParseResult(ParseStatus.READY, DocumentFormat.XML, (
            StructuralBlock(1, BlockKind.PARAGRAPH, "The requirement applies.", source_anchor="source/1"),
            StructuralBlock(2, BlockKind.PARAGRAPH, "An exception applies.", source_anchor="source/2")))
        with self.assertRaisesRegex(v.ValidationHold, "HOLD_UNREVIEWED_MERGED_CONTEXT:2"):
            v.covered_chunks(parsed, H, [1])
        chunks = v.covered_chunks(parsed, H, [1, 2])
        self.assertIn("An exception applies.", chunks[0].text)
        for ordinals in ([1, 1], [99], []):
            with self.subTest(ordinals=ordinals), self.assertRaises(v.ValidationHold):
                v.covered_chunks(parsed, H, ordinals)

    def test_real_selected_empty_contract_without_dummy_source(self):
        registry = ContractSchemaRegistry.from_project_root(v.ROOT)
        tools = {k: H for k in ("parser_sha256", "chunker_sha256", "tokenizer_sha256", "embedding_model_sha256",
                               "lexical_config_sha256", "vector_schema_sha256", "reranker_model_sha256")}
        tools["ocr_sha256"] = None
        empty = v.empty_baseline(SimpleNamespace(sha256=H), tools, STAMP)
        registry.validate_new(empty)
        self.assertEqual(empty["sources"], [])
        self.assertEqual(empty["schema"], "legalbot.research-empty-baseline.v1")
        self.assertEqual(empty["counts"]["vector_rows"], 0)
        self.assertFalse(empty["production_admission"])

    def test_full_v2_contract_lineage_with_empty_baseline(self):
        registry = ContractSchemaRegistry.from_project_root(v.ROOT)
        original, row = fixture()
        props, reviews = {}, {}
        for pid in v.SELECTED[:4]:
            props[pid], reviews[pid] = {**original, "proposition_id": pid}, {**row, "proposition_id": pid}
        gate = SimpleNamespace(propositions=props, reviews=reviews)
        scope = v.core.Scope(str(v.OUTPUT / "synthetic-test-only-store"), "candidate_case_local", "unit-test", "case-ENG")
        tools = {k: H for k in ("parser_sha256", "chunker_sha256", "tokenizer_sha256", "embedding_model_sha256",
                               "lexical_config_sha256", "vector_schema_sha256", "reranker_model_sha256")}
        tools["ocr_sha256"] = None
        policy = SimpleNamespace(sha256=H)
        baseline = v.empty_baseline(policy, tools, STAMP)
        contracts = v.contracts_for("ENG", scope, gate, policy, baseline, registry, STAMP)
        lineage = v.bind_lineage(contracts, registry)
        self.assertEqual(lineage.knowledge_generation_sha256, baseline["content_sha256"])
        self.assertEqual(lineage.schema_selection_sha256, registry.manifest_sha256)
        self.assertEqual(contracts["facts"]["facts"], [])
        self.assertEqual(contracts["conversation"]["messages"], [])

    def test_model_window_required_before_any_file_or_model_access(self):
        with self.assertRaisesRegex(v.ValidationHold, "HOLD_PARENT_MODEL_WINDOW_REQUIRED"):
            v.execute(Path("/unread/path"), H, "")

    def test_receipt_enrollment_is_exact_not_permissive(self):
        gate = object.__new__(v.SuccessorReviewGate)
        gate.replay = Mock()
        original, row = fixture()
        gate.propositions, gate.reviews = {"ENG-SCOPE": original}, {"ENG-SCOPE": row}
        receipt = {"actual_review_rows": [{"proposition_id": "ENG-SCOPE", "sha256": v.digest(row)}]}
        gate.enrolled = {v.digest(receipt): v.canonical_json_bytes(receipt)}
        self.assertTrue(gate.verify_review(v.REVIEWER, receipt))
        self.assertFalse(gate.verify_review("author-context", receipt))
        self.assertFalse(gate.verify_review(v.REVIEWER, {**receipt, "invented_tick": True}))
        row["checks"]["rights"]["status"] = "HOLD"
        self.assertFalse(gate.verify_review(v.REVIEWER, receipt))


class RetrievalBoundaryTests(unittest.TestCase):
    def fixture(self):
        scope = v.core.Scope(str(v.OUTPUT / "synthetic-store"), "candidate_case_local", "synthetic", "case-one")
        lineage = v.core.Lineage("request", H, "plan", H, "candidate", H, H, 0, "empty", H, H,
                                "England", "2026-09-05", ("issue",))
        row = {"id": H, "group": H, "text": "Synthetic reviewed source and exception."}
        build = {"rows": [row]}
        value = {"build_sha256": v.digest(build), "lineage": asdict(lineage), "scope": asdict(scope),
            "query_sha256": v.digest(b"synthetic query"), "lexical_ids": [H], "vector_ids": [H],
            "selected_ids": [H], "evidence": [row]}
        result = {**value, "retrieval_sha256": v.digest(value)}
        index = SimpleNamespace(scope=scope, _get=lambda key, kind: copy.deepcopy(value))
        return index, build, result, lineage

    def test_persisted_lexical_vector_and_exact_row_bindings(self):
        index, build, result, lineage = self.fixture()
        got = v.verify_retrieval(index, build, result, "synthetic query", lineage)
        self.assertEqual(got["evidence"], build["rows"])
        changed = copy.deepcopy(result)
        changed["evidence"][0]["text"] = "Changed returned source"
        with self.assertRaisesRegex(v.ValidationHold, "HOLD_PERSISTED_RETRIEVAL_BINDING"):
            v.verify_retrieval(index, build, changed, "synthetic query", lineage)

    def test_empty_vector_path_and_foreign_hits_held_even_if_rehashed(self):
        for key, value in (("vector_ids", []), ("selected_ids", ["f" * 64])):
            index, build, result, lineage = self.fixture()
            material = {k: z for k, z in result.items() if k != "retrieval_sha256"}
            material[key] = value
            index._get = lambda *args: material
            changed = {**material, "retrieval_sha256": v.digest(material)}
            with self.subTest(key=key), self.assertRaises(v.ValidationHold):
                v.verify_retrieval(index, build, changed, "synthetic query", lineage)


if __name__ == "__main__":
    unittest.main()
