"""Actual, isolated visible index fault evidence; no full-runtime or legal PASS.

Read the five approved immutable generations. Exercise filters using their actual
persisted document vectors, explicitly not newly inferred query vectors. Build
two small, separately scoped successors with the pinned provider: a successful
duplicate/no-op probe and a fault injected after persisted readback, before
publication. Preserve the failed generation and attempts. Never change originals,
source eligibility, ACTIVE, model weights, or the selected parser implementation.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import asdict, replace
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch

from backend.app.research.ge_auto_index import AutoResearchIndex, ModelPin, ResearchPolicy, Scope
from backend.app.retrieval.lancedb import ImmutableLanceRepository

from scripts import ge_auto_visible_index_validation as visible

ROOT, INPUT = visible.ROOT, visible.OUTPUT
OUTPUT = visible.VISIBLE / "index-fault-validation"
ACTOR = "visible-index-fault-component"
ELIGIBLE = frozenset(
    {"ENG-DATE", "WLS-DATE", "WLS-CONTRACT-DATE", "SCT-EXCEPTION-DATE", "SCT-FORUM"}
)
digest, read, obj = visible.digest, visible.read, visible.obj


class InjectedInterruption(RuntimeError):
    """Harness injection, never described as a naturally observed crash."""


def historical_review_code(relative: str, current: bytes, expected: str) -> bytes:
    """Recover exact attested bytes for the parent's two declared additions only.

    SHA-256 equality is mandatory. This is a technical compatibility proof, not a
    reconstructed reviewer decision. Historical files are never imported/executed.
    """
    original = current
    if relative == "backend/app/research/ge_auto_index.py":
        original = original.replace(
            b'(knowledge_generation, ("legalbot.knowledge-generation-manifest.v1",\n'
            b'                                    "legalbot.research-empty-baseline.v1")),',
            b'(knowledge_generation, "legalbot.knowledge-generation-manifest.v1"),',
        ).replace(
            b'if value.get("schema") not in (schema if isinstance(schema, tuple) else (schema,)):',
            b'if value.get("schema") != schema:',
        )
    elif relative == "backend/app/contracts/schema_registry.py":
        original = original.replace(b'    "research-empty-baseline.v1.schema.json",\n', b"")
    elif relative == "scripts/ge_auto_research_intake.py":
        for new, old in (
            (b"def parser_binding(*, include_legal_tables=False):", b"def parser_binding():"),
            (
                b"    if include_legal_tables:\n        paths.append(ROOT / 'scripts/ge_auto_xml_tables.py')\n",
                b"",
            ),
            (
                b"def parse_capture(raw: bytes, *, source_url: str, expected_raw_sha256: str,\n                  include_legal_tables=False) -> ParseResult:",
                b"def parse_capture(raw: bytes, *, source_url: str, expected_raw_sha256: str) -> ParseResult:",
            ),
            (
                b"    if include_legal_tables and filename == 'capture.xml':\n        from scripts.ge_auto_xml_tables import append_missing_legal_tables\n        parsed = append_missing_legal_tables(raw, parsed, source_url, expected_raw_sha256)\n",
                b"",
            ),
            (
                b"def parsed_manifest(raw: bytes, *, source_url: str, expected_raw_sha256: str,\n                    include_legal_tables=True):",
                b"def parsed_manifest(raw: bytes, *, source_url: str, expected_raw_sha256: str):",
            ),
            (
                b"    parsed = parse_capture(raw, source_url=source_url, expected_raw_sha256=expected_raw_sha256,\n                           include_legal_tables=include_legal_tables)",
                b"    parsed = parse_capture(raw, source_url=source_url, expected_raw_sha256=expected_raw_sha256)",
            ),
            (
                b"            'parser_sha256': parser_binding(include_legal_tables=include_legal_tables),\n            'parsed_sha256': _sha(canonical_json_bytes(value)),",
                b"            'parser_sha256': parser_binding(), 'parsed_sha256': _sha(canonical_json_bytes(value)),",
            ),
        ):
            original = original.replace(new, old)
        original = original.replace(
            b"\n\nfrom scripts.ge_unseen_sources import is_allowed_source_url",
            b"\nfrom scripts.ge_unseen_sources import is_allowed_source_url",
        )
    if digest(original) != expected:
        raise visible.ValidationHold(f"UNDECLARED_REVIEW_CODE_CHANGE:{relative}")
    return original


class FaultReviewGate(visible.SourceReviewGate):
    """Original file-backed review gate plus exact current implementation pins."""

    def replay(self) -> None:
        super().replay()
        for path, expected in self.current_code_pins.items():
            read(path, ROOT, expected)

    def _revalidate_parser(self) -> None:
        """Fresh base-mode technical verification, never table-mode legal review."""
        prior_path = self.visible / "structural-review-input/PARSER-REVALIDATION.json"
        prior = obj(prior_path, self.visible, self.pins.parser_revalidation_sha256)
        prior_rows = {r["input_manifest_sha256"]: r for r in prior["sources"]}
        proposals = visible.load_json_strict(
            self.read_input("author-research/SOURCE-PROPOSALS.json")
        )
        results = []
        for source in proposals["sources"]:
            if not source.get("raw_path"):
                continue
            relative = f"structural-review-input/{source['source_id']}.json"
            saved = visible.load_json_strict(self.read_input(relative))
            binding = {
                "input_manifest_sha256": self.inputs[relative],
                "parsed_sha256": saved["parsed_sha256"],
                "original_parser_sha256": saved["parser_sha256"],
            }
            if prior_rows.get(self.inputs[relative]) != binding:
                raise visible.ValidationHold("PRIOR_PARSER_REVALIDATION_BINDING_CHANGED")
            raw = self.read_input("author-research/" + source["raw_path"])
            parsed = visible.parse_capture(
                raw,
                source_url=source["url"],
                expected_raw_sha256=source["raw_sha256"],
                include_legal_tables=False,
            )
            if (
                not parsed.is_ready
                or digest(asdict(parsed)) != saved["parsed_sha256"]
                or digest(saved["parsed"]) != saved["parsed_sha256"]
            ):
                raise visible.ValidationHold("BASE_MODE_PARSED_BYTES_CHANGED")
            results.append({**binding, "source_id": source["source_id"], "raw_sha256": digest(raw)})
        if (
            len(results) != prior["identical_parses"]
            or len(results) != len(prior_rows)
            or len(results) != 21
        ):
            raise visible.ValidationHold("BASE_REVALIDATION_21_SOURCE_COVERAGE")
        self.prior_parser_sha256 = prior["current_parser_sha256"]
        current = visible.parser_binding(include_legal_tables=False)
        receipt = {
            "purpose": "PARENT_AUTHORIZED_CURRENT_BASE_MODE_EXACT_REPARSE",
            "include_legal_tables": False,
            "current_parser_sha256": current,
            "prior_revalidation_sha256": self.pins.parser_revalidation_sha256,
            "prior_parser_sha256": self.prior_parser_sha256,
            "identical_parses": len(results),
            "sources": results,
            "table_derivatives_used": False,
            "source_review_decisions_changed": False,
            "legal_review_claimed": False,
        }
        path = OUTPUT / "BASE-PARSER-REVALIDATION.json"
        key = write(path, receipt)
        self.file_pins[prior_path] = self.pins.parser_revalidation_sha256
        self.file_pins[path] = key
        self.parser_bridge = {
            "receipt_sha256": key,
            "current_parser_sha256": current,
            "exact_reparsed_sources": len(results),
            "reviewed_parsed_bytes_changed": False,
            "legal_review_decisions_changed": False,
            "include_legal_tables": False,
        }


def review_gate(pins: visible.ReviewPins) -> FaultReviewGate:
    attestation = obj(
        visible.VISIBLE / "independent-source-review/REVIEW-ATTESTATION.json",
        visible.VISIBLE,
        pins.attestation_sha256,
    )
    history = OUTPUT / "historical-review-code"
    bindings, current_pins = [], {}
    for binding in attestation["code_bindings"]:
        relative = binding["path"]
        current = read(ROOT / relative, ROOT)
        original = historical_review_code(relative, current, binding["sha256"])
        write(history / relative, original)
        current_pins[ROOT / relative] = digest(current)
        bindings.append(
            {
                "path": relative,
                "historical_sha256": digest(original),
                "current_sha256": digest(current),
                "historical_copy": str((history / relative).relative_to(OUTPUT)),
            }
        )
    registry = visible.ContractSchemaRegistry.from_project_root(ROOT)
    current_manifest = registry.manifest
    historical_manifest = {
        **current_manifest,
        "selected": [
            entry
            for entry in current_manifest["selected"]
            if entry["schema"] != "legalbot.research-empty-baseline.v1"
        ],
    }
    if len(current_manifest["selected"]) != len(historical_manifest["selected"]) + 1:
        raise visible.ValidationHold("EXACT_EMPTY_SCHEMA_ADDITION_REQUIRED")
    for entry in current_manifest["selected"]:
        current_pins[ROOT / "docs/system-design/schemas" / entry["filename"]] = entry["sha256"]
    proof = {
        "state": "EXACT_PARENT_DECLARED_TECHNICAL_ADDITIONS_VERIFIED",
        "bindings": bindings,
        "current_schema_manifest": current_manifest,
        "historical_schema_manifest": historical_manifest,
        "source_review_decisions_changed": False,
        "new_legal_review_claimed": False,
        "historical_code_executed": False,
        "opt_in_table_helpers_executed": False,
        "source_review_attestation_sha256": pins.attestation_sha256,
    }
    write(OUTPUT / "TECHNICAL-CODE-BINDING.json", proof)
    # Point the unchanged review constructor at real, exact historical files.
    # It still verifies every attested digest and all current source inputs.
    # Normal current implementations remain imported; historical code is data only.
    with patch.object(visible, "ROOT", history):
        gate = FaultReviewGate(visible.VISIBLE, pins)
    gate.current_code_pins = current_pins
    gate.historical_schema_manifest = historical_manifest
    gate.technical_binding_sha256 = digest(proof)
    gate.replay()
    return gate


def validate_historical_contracts(contracts: Mapping[str, Any], gate: FaultReviewGate) -> None:
    registry = visible.ContractSchemaRegistry.from_project_root(ROOT)
    for name in ("query_plan", "facts", "conversation", "knowledge_generation"):
        registry.validate_new(contracts[name])
    plan = contracts["query_plan"]
    if (
        plan["schema_selection_sha256"] != digest(gate.historical_schema_manifest)
        or plan["request_sha256"] != digest(contracts["request"])
        or plan["fact_snapshot_id"] != contracts["facts"]["snapshot_id"]
        or plan["conversation_snapshot"]["content_sha256"]
        != contracts["conversation"]["content_sha256"]
    ):
        raise visible.ValidationHold("HISTORICAL_CONTRACT_LINEAGE_CHANGED")


def write(path: Path, value: Any) -> str:
    return visible.write_new(path, value, output=OUTPUT)


def snapshot(root: Path, *, exclude_test_fixtures: bool = False) -> dict[str, str]:
    """Content inventory, with no symlink traversal or original-store mutations."""
    visible.safe(root, root)
    result = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        if exclude_test_fixtures and Path(directory) == root:
            if root != INPUT:
                raise visible.ValidationHold("TEST_FIXTURE_EXCLUSION_SCOPE")
            dirs[:] = [name for name in dirs if name != "test-runs"]
        for name in (*dirs, *files):
            path = visible.safe(Path(directory) / name, root)
            if path.is_file():
                result[str(path.relative_to(root))] = digest(read(path, root))
    return result


def denied(call: Callable[[], Any], error: type[Exception], reason: str) -> dict[str, Any]:
    try:
        call()
    except error as exc:
        if reason not in str(exc):
            raise visible.ValidationHold(f"UNEXPECTED_DENIAL_REASON:{exc}") from exc
        return {"state": "DENIED", "error_type": type(exc).__name__, "reason": str(exc)}
    raise visible.ValidationHold("FAULT_BOUNDARY_ACCEPTED")


def literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def filter_probe(
    table: Any, *, query: str, vector: list[float], jurisdiction: str, day: str
) -> dict:
    predicate = (
        f"jurisdiction = {literal(jurisdiction)} AND "
        f"valid_from <= {literal(day)} AND valid_to >= {literal(day)}"
    )
    lexical = (
        table.search(query, query_type="fts").where(predicate, prefilter=True).limit(8).to_list()
    )
    vectors = (
        table.search(vector, vector_column_name="vector")
        .metric("cosine")
        .where(predicate, prefilter=True)
        .limit(8)
        .to_list()
    )
    if any(
        r["jurisdiction"] != jurisdiction or not r["valid_from"] <= day <= r["valid_to"]
        for r in (*lexical, *vectors)
    ):
        raise visible.ValidationHold("FILTER_RETURNED_INELIGIBLE_ROW")
    return {
        "predicate": predicate,
        "lexical_ids": [r["id"] for r in lexical],
        "vector_ids": [r["id"] for r in vectors],
    }


def verify_generation(root: Path, outcome: Mapping[str, Any]) -> tuple[dict, list[dict], Any]:
    import lancedb

    generation = obj(root / "generation.json", root)
    if (
        generation["generation_sha256"] != outcome["generation_sha256"]
        or digest({k: v for k, v in generation.items() if k != "generation_sha256"})
        != generation["generation_sha256"]
    ):
        raise visible.ValidationHold("GENERATION_DIGEST_CHANGED")
    for name, expected in generation["files"].items():
        read(root / name, root, expected)
    table = lancedb.connect(str(root / "lance/authority")).open_table("chunks")
    rows = table.to_arrow().to_pylist()
    if digest(sorted(rows, key=lambda r: r["id"])) != generation["rows_sha256"]:
        raise visible.ValidationHold("PERSISTED_ROW_DIGEST_CHANGED")
    return generation, rows, table


def load_original(readback_sha256: str) -> tuple[Any, dict, dict, list[dict], dict]:
    checked = obj(INPUT / "READBACK-CHECK.json", INPUT, readback_sha256)
    result = obj(INPUT / "RESULTS.json", INPUT, checked["results_sha256"])
    inference = obj(INPUT / "ACTUAL-INFERENCE.json", INPUT, checked["inference_receipt_sha256"])
    read(ROOT / "scripts/ge_auto_visible_index_validation.py", ROOT, checked["runner_sha256"])
    if result["built_generation_count"] != 5 or result["retrieved_source_count"] != 5:
        raise visible.ValidationHold("ORIGINAL_FIVE_GENERATION_PROOF_REQUIRED")
    pins = visible.ReviewPins(
        "c74d65c78ade2d1df79233a56265c849fdfbb3ab2624888b9c597e4dc5d5fc7c",
        "a15656a6fa0092fff05d2df8d6fbd0415eeb22a56b684fd4c9f7d774be6bad9b",
        parser_revalidation_sha256="46441e0c2d34255d66843a1f30ad09b2984fd188d09e595a37d531bc464df3d6",
    )
    gate = review_gate(pins)
    cases, props, sources, _ = visible.load_inputs(gate)
    approved = {key for key, prop in props.items() if gate.eligible(prop)}
    if approved != ELIGIBLE:
        raise visible.ValidationHold("APPROVED_INPUT_SET_CHANGED")
    materials = []
    for outcome in result["outcomes"]:
        key = outcome["proposition_id"]
        if key not in approved:
            if outcome.get("actual_inference_calls", 0):
                raise visible.ValidationHold("HELD_SOURCE_WAS_EMBEDDED")
            continue
        local = INPUT / "propositions" / key
        contracts = obj(local / "CONTRACTS.json", INPUT)
        validate_historical_contracts(contracts, gate)
        retrieval = obj(local / "RETRIEVAL.json", INPUT)
        if (
            retrieval["retrieval_sha256"] != outcome["retrieval_sha256"]
            or digest({k: v for k, v in retrieval.items() if k != "retrieval_sha256"})
            != outcome["retrieval_sha256"]
        ):
            raise visible.ValidationHold("ORIGINAL_RETRIEVAL_CHANGED")
        source = visible.make_capture(
            gate, sources[props[key]["source_id"]], Scope(**retrieval["scope"]), gate.reviews[key]
        )
        derived = gate.bind(proposition=props[key], source=source, issue_id="issue-" + key)
        original_review = obj(local / "DERIVED-SOURCE-REVIEW.json", INPUT)
        historical_source = replace(source, parser_sha256=gate.prior_parser_sha256)
        if (
            original_review["raw_review_sha256"] != digest(gate.reviews[key])
            or original_review["capture_sha256"] != digest(historical_source.manifest())
            or original_review["source_review_file_sha256"] != pins.source_review_sha256
            or original_review["review_attestation_sha256"] != pins.attestation_sha256
        ):
            raise visible.ValidationHold("EXACT_REVIEW_BINDING_CHANGED")
        build = (
            INPUT
            / "stores"
            / outcome["case_id"]
            / "builds"
            / ("ge-auto-" + outcome["build_sha256"])
        )
        generation, rows, table = verify_generation(build, outcome)
        if (
            generation["review_manifest_sha256"] != digest([original_review])
            or generation["source_manifest_sha256"] != digest([historical_source.manifest()])
            or generation["lineage"]["query_plan_sha256"] != digest(contracts["query_plan"])
            or generation["lineage"] != retrieval["lineage"]
        ):
            raise visible.ValidationHold("HISTORICAL_GENERATION_LINEAGE_CHANGED")
        store = INPUT / "stores" / outcome["case_id"]
        with sqlite3.connect((store / "metadata.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
            for sha, payload in db.execute("SELECT digest,payload FROM objects"):
                if digest(payload) != sha:
                    raise visible.ValidationHold("ORIGINAL_SQLITE_METADATA_CHANGED")
            if not db.execute(
                "SELECT 1 FROM objects WHERE digest=? AND kind='retrieval'",
                (outcome["retrieval_sha256"],),
            ).fetchone():
                raise visible.ValidationHold("ORIGINAL_SQLITE_RETRIEVAL_MISSING")
        materials.append(
            {
                "proposition": props[key],
                "case": next(c for c in cases if c["case_id"] == outcome["case_id"]),
                "source": source,
                "derived": derived,
                "original_derived": original_review,
                "generation": generation,
                "rows": rows,
                "table": table,
                "contracts": contracts,
                "original_outcome": outcome,
            }
        )
    if {m["proposition"]["proposition_id"] for m in materials} != ELIGIBLE:
        raise visible.ValidationHold("ORIGINAL_GENERATION_COVERAGE")
    return (
        gate,
        inference["model_identity"],
        checked,
        materials,
        {"cases": cases, "sources": sources},
    )


def actual_filter_checks(materials: list[dict]) -> list[dict]:
    checks = []
    for material in materials:
        prop, review = material["proposition"], material["original_derived"]
        # This exact persisted document vector already has verified source/model
        # provenance. It probes filters; it is not called a query embedding.
        vector_row = material["rows"][0]
        common = {
            "table": material["table"],
            "query": prop["proposed_proposition"],
            "vector": vector_row["vector"],
        }
        positive = filter_probe(
            **common, jurisdiction=review["jurisdiction"], day=review["as_of_date"]
        )
        wrong_jur = filter_probe(**common, jurisdiction="Texas", day=review["as_of_date"])
        outside = (date.fromisoformat(review["valid_to"]) + timedelta(days=1)).isoformat()
        wrong_day = filter_probe(**common, jurisdiction=review["jurisdiction"], day=outside)
        if (
            not positive["lexical_ids"]
            or not positive["vector_ids"]
            or any(
                probe[k] for probe in (wrong_jur, wrong_day) for k in ("lexical_ids", "vector_ids")
            )
        ):
            raise visible.ValidationHold("ACTUAL_FILTER_FAULT_NOT_EXCLUDED")
        checks.append(
            {
                "proposition_id": prop["proposition_id"],
                "state": "VERIFIED_ZERO_INELIGIBLE_EVIDENCE",
                "generation_sha256": material["generation"]["generation_sha256"],
                "review_sha256": digest(review),
                "raw_sha256": digest(material["source"].raw),
                "model_sha256": material["generation"]["model_sha256"],
                "probe_vector_origin": "EXACT_PERSISTED_DOCUMENT_VECTOR_NOT_NEW_QUERY_INFERENCE",
                "probe_chunk_id": vector_row["id"],
                "probe_vector_sha256": digest(vector_row["vector"]),
                "positive": positive,
                "wrong_jurisdiction": wrong_jur,
                "wrong_date": wrong_day,
            }
        )
    return checks


def prepare_successor(
    gate: Any, policy: ResearchPolicy, scope: Scope, material: dict, identity: dict, *, label: str
) -> dict:
    prop = material["proposition"]
    source = replace(material["source"], scope=scope)
    derived = gate.bind(proposition=prop, source=source, issue_id="issue-" + prop["proposition_id"])
    registry = visible.ContractSchemaRegistry.from_project_root(ROOT)
    baseline = obj(INPUT / "EMPTY-SHARED-BASELINE.json", INPUT)
    contracts = visible.make_contracts(
        case=material["case"],
        proposition=prop,
        source=source,
        derived_review=derived,
        policy=policy,
        identity=identity,
        baseline=baseline,
        registry=registry,
        observed_at=datetime.now(UTC).isoformat(),
        toolchain={
            **material["contracts"]["knowledge_generation"]["toolchain"],
            "parser_sha256": source.parser_sha256,
        },
    )
    if contracts["knowledge_generation"]["toolchain"]["parser_sha256"] != source.parser_sha256:
        raise visible.ValidationHold("FAULT_CONTRACT_PARSER_BINDING_MISMATCH")
    lineage = visible.lineage_for(contracts, registry)
    local = OUTPUT / label
    write(local / "CONTRACTS.json", contracts)
    write(local / "DERIVED-SOURCE-REVIEW.json", derived)
    write(local / "COMPANION-CONTEXT.json", gate.contexts[derived["companion_context_sha256"]])
    cap = policy.authorize(
        scope=scope,
        actor=ACTOR,
        role="candidate",
        action="jobs",
        binding_sha256=digest(asdict(lineage)),
    )
    index = AutoResearchIndex(policy=policy, capability=cap, scope=scope, lineage=lineage)
    gap = index.enqueue(
        cap,
        issue_id="issue-" + prop["proposition_id"],
        gap_class="retrieval_miss",
        affected_claim_sha256=digest(prop),
        failure_fingerprint=digest(
            {"explicit_fault_successor": label, "original": material["original_outcome"]}
        ),
    )
    inputs_sha = digest({"capture": source.manifest(), "review": derived, "fault": label})
    attempt = index.begin_attempt(
        cap,
        gap,
        inputs_sha256=inputs_sha,
        existing_retrieval_sha256=material["original_outcome"]["retrieval_sha256"],
    )
    operation = index.reserve(cap, attempt, kind="capture", input_sha256=digest(source.manifest()))
    index.capture(cap, operation, source)
    write(
        local / "CAPTURE-IMPORT.json",
        {
            "operation": "EXISTING_APPROVED_CAPTURE_IMPORT",
            "new_fetch": False,
            "original_generation_sha256": material["generation"]["generation_sha256"],
            "source_sha256": digest(source.raw),
            "attempt": attempt,
            "operation_id": operation,
            "scope": asdict(scope),
        },
    )
    return {
        "index": index,
        "cap": cap,
        "source": source,
        "review": derived,
        "gap": gap,
        "attempt": attempt,
        "inputs_sha256": inputs_sha,
        "scope": scope,
        "local": local,
    }


def prepare_build(unit: dict) -> Any:
    return unit["index"].prepare(
        unit["cap"],
        gap=unit["gap"],
        attempt=unit["attempt"],
        sources=[(unit["source"], unit["review"])],
    )


def build_cap(policy: ResearchPolicy, unit: dict, prepared: Any) -> Any:
    return policy.authorize(
        scope=unit["scope"],
        actor=ACTOR,
        role="candidate",
        action="build",
        binding_sha256=prepared.sha256,
    )


def interrupt_after_readback(repository: Any, build_id: str) -> None:
    staging = repository.staging_path(build_id)
    if not (staging / "generation.json").is_file() or not (staging / "lance/authority").is_dir():
        raise visible.ValidationHold("INJECTION_BOUNDARY_NOT_REACHED")
    raise InjectedInterruption("AFTER_PERSISTED_READBACK_BEFORE_PUBLICATION")


def execute(*, readback_sha256: str, parent_released: bool, ready_reason: str) -> dict:
    if not parent_released or not ready_reason.strip():
        raise visible.ValidationHold("HOLD_PARENT_RERANKER_RELEASE_REQUIRED")
    visible.safe(OUTPUT, ROOT)
    OUTPUT.mkdir(parents=True, exist_ok=True, mode=0o700)
    if (OUTPUT / "RUN-START.json").exists():
        raise visible.ValidationHold("HOLD_FAULT_RUN_ALREADY_STARTED_PRESERVE_NO_REPEAT")
    before = snapshot(INPUT, exclude_test_fixtures=True)
    gate, identity, checked, materials, originals = load_original(readback_sha256)
    filters = actual_filter_checks(materials)
    write(OUTPUT / "FILTER-CHECKS.json", filters)
    chosen = min(materials, key=lambda m: len(m["rows"]))
    other = next(m for m in materials if m["case"]["case_id"] != chosen["case"]["case_id"])
    scopes = [
        Scope(
            str(OUTPUT / "stores" / label),
            "candidate_case_local",
            "VISIBLE_EXPLICIT_FAULT_SUCCESSOR:" + label,
            case["case_id"],
        )
        for label, case in (
            ("successful", chosen["case"]),
            ("interrupted", chosen["case"]),
            ("foreign-case", other["case"]),
        )
    ]
    owner = read(
        ROOT
        / "data/evaluations/general-enquiries/LegalBot-GE-2026-09-05-codex-unseen-r1/PLAN-EXECUTION-AUTHORIZATION.json",
        ROOT,
        visible.OWNER_SHA256,
    )
    from scripts.ge_auto_research_runtime import PinnedEmbeddingSession, verified_model_identity

    if verified_model_identity() != identity:
        raise visible.ValidationHold("PINNED_MODEL_IDENTITY_CHANGED")
    reranking_sha = "f683d45410a6600ce778fbe06c1af9f41af38ae086b0322f8a8500df1ea8b306"
    read(
        visible.VISIBLE / "reranking-validation/ACTUAL-RERANKING.json",
        visible.VISIBLE,
        reranking_sha,
    )
    policy = ResearchPolicy(
        workspace=OUTPUT,
        owner_instruction=owner,
        expected_owner_instruction_sha256=visible.OWNER_SHA256,
        scopes=scopes,
        model=ModelPin.from_runtime_identity(identity),
        reviewers=[gate.pins.reviewer_id],
        verify_review=gate.verify_review,
    )
    started = {
        "created_at": datetime.now(UTC).isoformat(),
        "ready_reason": ready_reason,
        "parent_completed_reranking_receipt_sha256": reranking_sha,
        "owner_instruction_sha256": visible.OWNER_SHA256,
        "input_readback_sha256": readback_sha256,
        "input_results_sha256": checked["results_sha256"],
        "input_tree_sha256": digest(before),
        "model_identity": identity,
        "source_review_pins": asdict(gate.pins),
        "technical_code_binding_sha256": gate.technical_binding_sha256,
        "runner_sha256": digest(read(Path(__file__), ROOT)),
        "selected_proposition": chosen["proposition"]["proposition_id"],
        "explicit_fault_successors": 2,
        "expected_document_embedding_calls": 2 * len(chosen["rows"]),
        "expected_query_embedding_calls": 1,
        "reranker_execution": "NOT_RUN",
        "mandatory_context_truncation": False,
    }
    write(OUTPUT / "RUN-START.json", started)
    write(OUTPUT / "ORIGINAL-FILE-MANIFEST.json", before)
    success = prepare_successor(gate, policy, scopes[0], chosen, identity, label="successful")
    interrupted = prepare_successor(gate, policy, scopes[1], chosen, identity, label="interrupted")
    quote = denied(
        lambda: success["index"].prepare(
            success["cap"],
            gap=success["gap"],
            attempt=success["attempt"],
            sources=[
                (
                    success["source"],
                    {
                        **success["review"],
                        "quote": success["review"]["quote"] + " [INJECTED MISMATCH]",
                    },
                )
            ],
        ),
        PermissionError,
        "independent exact-receipt reviewer verification required",
    )
    quote.update(
        embedding_calls=0, source_mutated=False, fault_injection="DERIVED_RECEIPT_QUOTE_ONLY"
    )
    write(OUTPUT / "QUOTE-MISMATCH.json", quote)
    prepared = prepare_build(success)
    broken = prepare_build(interrupted)
    pointers_before = visible.active_snapshot(scopes)
    with PinnedEmbeddingSession() as provider:
        if provider.pin != policy.model or not provider.verify_binding():
            raise visible.ValidationHold("MODEL_BINDING_CHANGED_BEFORE_FAULT_INFERENCE")
        entered = datetime.now(UTC).isoformat()
        write(
            OUTPUT / "MODEL-SESSION-START.json",
            {"loaded_and_verified_at": entered, "actual_first_inference_not_yet_started": True},
        )
        generation = success["index"].build(
            build_cap(policy, success, prepared), prepared, provider=provider
        )
        count = len(provider.calls)
        again = success["index"].build(
            build_cap(policy, success, prepared), prepared, provider=provider
        )
        duplicate_attempt = success["index"].begin_attempt(
            success["cap"],
            success["gap"],
            inputs_sha256=success["inputs_sha256"],
            existing_retrieval_sha256=chosen["original_outcome"]["retrieval_sha256"],
        )
        if again != generation or len(provider.calls) != count or duplicate_attempt is not None:
            raise visible.ValidationHold("DUPLICATE_WAS_NOT_NO_OP")
        duplicate = {
            "state": "NO_OP",
            "generation_sha256": generation,
            "new_embedding_calls": 0,
            "duplicate_attempt_created": False,
        }
        retrieve_cap = policy.authorize(
            scope=scopes[0],
            actor=ACTOR,
            role="candidate",
            action="retrieve",
            binding_sha256=generation,
        )
        common = {
            "build_sha256": prepared.sha256,
            "generation_sha256": generation,
            "query": chosen["proposition"]["proposed_proposition"],
            "provider": provider,
        }
        index = success["index"]
        wrong_jur = denied(
            lambda: index.retrieve(
                retrieve_cap, **common, lineage=replace(index.lineage, jurisdiction="Texas")
            ),
            ValueError,
            "query lineage/jurisdiction/date mismatch",
        )
        wrong_date = denied(
            lambda: index.retrieve(
                retrieve_cap, **common, lineage=replace(index.lineage, as_of_date="2026-09-06")
            ),
            ValueError,
            "query lineage/jurisdiction/date mismatch",
        )
        foreign = policy.authorize(
            scope=scopes[2],
            actor=ACTOR,
            role="candidate",
            action="retrieve",
            binding_sha256=generation,
        )
        cross = denied(
            lambda: index.retrieve(foreign, **common, lineage=index.lineage),
            PermissionError,
            "wrong action, root, lane, case or exact binding",
        )
        sibling = policy.authorize(
            scope=scopes[1],
            actor=ACTOR,
            role="candidate",
            action="retrieve",
            binding_sha256=generation,
        )
        cross_store = denied(
            lambda: index.retrieve(sibling, **common, lineage=index.lineage),
            PermissionError,
            "wrong action, root, lane, case or exact binding",
        )
        if len(provider.calls) != count:
            raise visible.ValidationHold("DENIED_RETRIEVAL_INVOKED_MODEL")
        retrieved = index.retrieve(retrieve_cap, **common, lineage=index.lineage)
        if (
            not retrieved["lexical_ids"]
            or not retrieved["vector_ids"]
            or len(retrieved["evidence"]) != len(chosen["rows"])
        ):
            raise visible.ValidationHold("FAULT_SUCCESSOR_RETRIEVAL_OR_CONTEXT_MISSING")
        write(OUTPUT / "successful/RETRIEVAL.json", retrieved)
        # An explicitly synthetic failure, with actual approved source bytes,
        # real embeddings, SQLite metadata and persisted Lance indexes beneath it.
        with patch.object(ImmutableLanceRepository, "finalize_staging", interrupt_after_readback):
            injection = denied(
                lambda: interrupted["index"].build(
                    build_cap(policy, interrupted, broken), broken, provider=provider
                ),
                InjectedInterruption,
                "AFTER_PERSISTED_READBACK_BEFORE_PUBLICATION",
            )
        staged = Path(scopes[1].root) / "builds" / (".ge-auto-" + broken.sha256 + ".incomplete")
        retained = snapshot(staged)
        staged_generation = obj(staged / "generation.json", OUTPUT)
        _, retained_rows, _ = verify_generation(staged, staged_generation)
        call_count = len(provider.calls)
        retry = denied(
            lambda: interrupted["index"].build(
                build_cap(policy, interrupted, broken), broken, provider=provider
            ),
            ValueError,
            "attempt is not running under this lineage",
        )
        existing_stage = denied(
            lambda: ImmutableLanceRepository(scopes[1].root).prepare_new_staging(
                "ge-auto-" + broken.sha256
            ),
            FileExistsError,
            "incomplete staging already exists",
        )
        state = interrupted["index"].status(interrupted["gap"])
        if (
            snapshot(staged) != retained
            or len(provider.calls) != call_count
            or state["state"] != "HOLD_BUILD"
            or state["attempts"][0][2] != "FAILED"
        ):
            raise visible.ValidationHold("INTERRUPTION_NOT_PRESERVED")
        if (Path(scopes[1].root) / "builds" / ("ge-auto-" + broken.sha256)).exists():
            raise visible.ValidationHold("INTERRUPTED_GENERATION_PUBLISHED")
        interruption = {
            "state": "RETAINED_UNPUBLISHED_HOLD_BUILD",
            "synthetic_failure_injection": True,
            "actual_source_bytes_and_embeddings": True,
            "injection": injection,
            "retry": retry,
            "existing_staging_guard": existing_stage,
            "staging_path": str(staged.relative_to(OUTPUT)),
            "retained_file_manifest": retained,
            "retained_rows": len(retained_rows),
            "attempt_status": state,
            "build_sha256": broken.sha256,
            "unpublished_generation_sha256": staged_generation["generation_sha256"],
        }
        inference = provider.receipt()
        inference["last_inference_completed_by"] = datetime.now(UTC).isoformat()
    inference["session_exited_at"] = datetime.now(UTC).isoformat()
    write(OUTPUT / "ACTUAL-INFERENCE.json", inference)
    write(OUTPUT / "INTERRUPTION.json", interruption)
    if inference["actual_inference_calls"] != 2 * len(chosen["rows"]) + 1:
        raise visible.ValidationHold("INFERENCE_BUDGET_MISMATCH")
    gate.replay()
    unchanged = snapshot(INPUT, exclude_test_fixtures=True) == before
    pointers_after = visible.active_snapshot(scopes)
    if not unchanged or pointers_before != pointers_after:
        raise visible.ValidationHold("ORIGINALS_OR_ACTIVE_CHANGED")
    result = {
        "state": "INDEX_FAULT_COMPONENT_VERIFIED_WITH_LIMITATIONS",
        "global_visible_validation": "NOT_ASSESSED",
        "source_review_sha256": gate.pins.source_review_sha256,
        "technical_code_binding_sha256": gate.technical_binding_sha256,
        "model_identity_sha256": identity["identity_sha256"],
        "input_readback_sha256": readback_sha256,
        "input_results_sha256": checked["results_sha256"],
        "filter_generation_count": len(filters),
        "filter_checks": filters,
        "quote_mismatch": quote,
        "duplicate": duplicate,
        "wrong_lineage_jurisdiction": wrong_jur,
        "wrong_lineage_date": wrong_date,
        "cross_case_capability": cross,
        "same_case_cross_store_capability": cross_store,
        "interruption_receipt_sha256": digest(interruption),
        "interruption_state": interruption["state"],
        "successor_generation_sha256": generation,
        "successor_retrieval_sha256": retrieved["retrieval_sha256"],
        "actual_inference_receipt_sha256": digest(inference),
        "actual_document_embeddings": 2 * len(chosen["rows"]),
        "actual_query_embeddings": 1,
        "original_successful_builds_repeated": 0,
        "explicit_isolated_fault_successors": 2,
        "original_artifact_tree_unchanged": unchanged,
        "original_inventory_exclusion": "test-runs: retained synthetic test fixtures only",
        "ACTIVE_unchanged": pointers_before == pointers_after,
        "active_pointer_snapshot": pointers_after,
        "superseded_version_retention": {
            "state": "NOT_DEMONSTRATED",
            "reason": "No independently reviewed superseding capture pair among these five approved source versions. Technical fault successors are not new legal-source versions.",
        },
        "reranker_execution": "NOT_RUN",
        "mandatory_context_dropped": False,
        "gap_closures": 0,
        "new_fetches": 0,
        "source_admission": False,
        "training": False,
        "candidate_answers": False,
        "production": False,
    }
    write(OUTPUT / "RESULTS.json", result)
    return result


def captured_version_metadata(raw: bytes) -> dict:
    """Read CLML metadata, never infer legal applicability from a date or link."""
    from lxml import etree

    if not raw.lstrip().startswith(b"<"):
        return {}
    try:
        root = etree.fromstring(raw, etree.XMLParser(resolve_entities=False, no_network=True))
    except etree.XMLSyntaxError:
        # Some captured HTML has an XML declaration but is not well-formed XML.
        return {"xml_metadata_state": "NOT_WELL_FORMED_XML",
                "legal_applicability_verified": False}
    if root.tag != "{http://www.legislation.gov.uk/namespaces/legislation}Legislation":
        return {}
    ns = {"dc": "http://purl.org/dc/elements/1.1/", "dct": "http://purl.org/dc/terms/",
          "atom": "http://www.w3.org/2005/Atom"}
    return {
        "identifiers": root.xpath("//dc:identifier/text()", namespaces=ns),
        "modified_metadata": root.xpath("//dc:modified/text()", namespaces=ns),
        "valid_metadata": root.xpath("//dct:valid/text()", namespaces=ns),
        "observed_version_links": root.xpath(
            '//atom:link[@rel="http://purl.org/dc/terms/hasVersion"]/@href', namespaces=ns),
        "legal_applicability_verified": False,
    }


def inspect_superseded_inputs() -> dict:
    """Bounded missing-evidence report for the inspected original/Tesla corpus.

    This is a technical inventory, not a source-review callback or supersession
    detector. Only selected attested files are checked; no status is granted and
    no historical text is reconstructed from amendment instructions.
    """
    v = visible.VISIBLE
    used: dict[str, str] = {}

    def pinned(path: Path, expected: str | None = None) -> bytes:
        raw = read(path, v, expected)
        used[str(path.relative_to(v))] = digest(raw)
        return raw

    review_specs = [
        ("independent-source-review",
         "c74d65c78ade2d1df79233a56265c849fdfbb3ab2624888b9c597e4dc5d5fc7c"),
        ("independent-source-review/successor-r1",
         "c7a7477b9e5f8f0044b50b912552e8bda1dac3800c6b8c8d4de2495479269875"),
    ]
    bindings: dict[Path, tuple[str, int]] = {}
    reviews = []
    for relative, sha in review_specs:
        directory = v / relative
        attestation = visible.load_json_strict(pinned(directory / "REVIEW-ATTESTATION.json", sha))
        for kind in ("input_files", "output_files"):
            for item in attestation[kind]:
                base = ROOT if relative.endswith("successor-r1") else (
                    v if kind == "input_files" else directory)
                path = base / item["path"]
                # Attestations also list code/docs; this inventory reads only visible data.
                if not path.is_relative_to(v):
                    continue
                visible.safe(path, v)
                binding = (item["sha256"], item["bytes"])
                if path in bindings and bindings[path] != binding:
                    raise visible.ValidationHold("CONFLICTING_VISIBLE_ATTESTATION_BINDING")
                bindings[path] = binding

    def attested(path: Path) -> bytes:
        sha, size = bindings[path]
        raw = pinned(path, sha)
        if len(raw) != size:
            raise visible.ValidationHold("ATTESTED_CAPTURE_LENGTH")
        return raw

    for relative, _ in review_specs:
        reviews.extend(visible.load_json_strict(line) for line in
                       attested(v / relative / "SOURCE-REVIEW.jsonl").splitlines() if line)
    proposals = visible.load_json_strict(attested(v / "author-research/SOURCE-PROPOSALS.json"))
    inventories = [
        (v / "author-research", proposals["sources"]),
        (v / "independent-source-review", visible.load_json_strict(
            attested(v / "independent-source-review/TARGETED-CAPTURE-LOG.json"))),
        (v / "independent-source-review/successor-r1", visible.load_json_strict(
            attested(v / "independent-source-review/successor-r1/CAPTURE-OPERATIONS.json"))),
    ]
    captures, unavailable = [], []
    for directory, records in inventories:
        for record in records:
            if not record.get("raw_path"):
                unavailable.append({"url": record["url"], "source_id": record["source_id"],
                                    "status": record.get("capture_status")})
                continue
            path = directory / record["raw_path"]
            raw = attested(path)
            if digest(raw) != record["raw_sha256"]:
                raise visible.ValidationHold("CAPTURE_RECORD_DIGEST")
            if record.get("capture_receipt_path"):
                receipt = attested(directory / record["capture_receipt_path"])
                if digest(receipt) != record["capture_receipt_sha256"]:
                    raise visible.ValidationHold("CAPTURE_RECEIPT_DIGEST")
            captures.append({
                "path": str(path.relative_to(v)), "url": record["url"],
                "final_url": record.get("final_url"), "raw_sha256": digest(raw),
                "bytes": len(raw), "source_id": record.get("source_id"),
                "evidence_id": record.get("evidence_id"),
                "capture_status": record.get("capture_status", record.get("status")),
                "metadata_only": captured_version_metadata(raw),
            })
    if [len(records) for _, records in inventories] != [23, 3, 8] or len(captures) != 32:
        raise visible.ValidationHold("VISIBLE_VERSION_INSPECTION_CORPUS_CHANGED")
    current = next(c for c in captures if c["url"] ==
                   "https://www.legislation.gov.uk/ssi/2011/176/data.xml")
    older = "http://www.legislation.gov.uk/ssi/2011/176/2017-12-01"
    updated = "http://www.legislation.gov.uk/ssi/2011/176/2019-11-11"
    links = current["metadata_only"]["observed_version_links"]
    if older not in links or updated not in links:
        raise visible.ValidationHold("HISTORICAL_URL_NOT_OBSERVED_IN_CAPTURE")
    same_instrument = [c for c in captures if "/ssi/2011/176" in c["url"]]
    if len(same_instrument) != 1:
        raise visible.ValidationHold("NEW_HISTORICAL_CAPTURE_REQUIRES_INSPECTION")
    amendment = next(c for c in captures if c["url"] ==
                     "https://www.legislation.gov.uk/ssi/2019/331/data.xml")
    correction = visible.load_json_strict(pinned(
        v / "structural-table-review-input/RECONCILIATION-CORRECTION.json"))
    if correction["changed_raw_source_bytes"] is not False:
        raise visible.ValidationHold("TABLE_DERIVATIVE_RAW_SOURCE_CHANGED")
    prior = visible.load_json_strict(pinned(
        OUTPUT / "parser-binding-r2/RESULTS.json",
        "69d9dfe9145fb9b926439abfa3ca034bce802467a9b44ff03e82e2371d954def"))
    # Replay selected file hashes after inspection; this is not a new legal review.
    for relative, expected in used.items():
        read(v / relative, v, expected)
    return {
        "schema": "ge.visible.superseded.capture.inspection.v1",
        "state": "NOT_DEMONSTRATED",
        "reason": "No captured and independently reviewed older/updated legal-version pair in this exact visible corpus.",
        "inspection_kind": "BOUNDED_EXISTING_CAPTURE_AND_REVIEW_INVENTORY",
        "input_files_sha256": used,
        "runner_sha256": digest(read(Path(__file__), ROOT)),
        "captures": captures, "unavailable_original_captures": unavailable,
        "unique_raw_sha256_count": len({c["raw_sha256"] for c in captures}),
        "review_windows": [{k: r.get(k) for k in (
            "proposition_id", "source_id", "decision", "reviewer_id", "valid_from", "valid_to")}
                           for r in reviews],
        "inspection_findings": [
            "Original captures contain one selected representation/version per law locator, not a historical pair.",
            "Tesla's eight check-only captures are undated current provision/commencement pages; they do not capture historical alternatives.",
            "Whole-instrument XML and provision HTML are different representations/granularities, not evidence of supersession.",
            "Table repairs reuse original raw bytes. Review-successor decisions and later capture times do not establish new law versions.",
            "Amending instruments, amendment annotations, prospective text and a repeal schedule do not substitute for captured historical consolidated text.",
            "Three original Texas navigation captures share bytes; rights/help and source-information pages do not form law-version pairs.",
            "Review valid_from/valid_to are one-day research windows, not historical applicability findings.",
        ],
        "missing_evidence": {
            "instrument": "The Tenancy Deposit Schemes (Scotland) Regulations 2011",
            "locator_for_parent_inspection": "regulation 3, especially paragraphs (1A) and (2A)",
            "existing_updated_capture": current,
            "missing_historical_capture_url": older,
            "updated_version_inspection_url": updated,
            "url_origin": "Exact atom hasVersion links in the existing official XML; not fetched here.",
            "existing_amending_instrument": amendment,
            "required_before_retention_proof": [
                "Parent inspect/capture actual older consolidated bytes and verify corresponding updated locator bytes.",
                "Independent reviewer bind both raw/parsed hashes, exact quotes, supersession relationship, jurisdiction and historical/effective-date applicability including exceptions.",
                "Authorize a bounded isolated index successor and verify old/new retention plus exclusion at the wrong legal date. No such build occurred here.",
            ],
            "existing_SCT_PROTECT_and_SCT_REMEDY": "HOLD unchanged",
            "historical_source_reconstructed": False,
        },
        "prior_fault_generation_sha256": prior["successor_generation_sha256"],
        "prior_model_identity_sha256": prior["model_identity_sha256"],
        "model_inference_calls_this_inspection": 0, "model_lease_acquired": False,
        "index_builds": 0, "passed_checks_repeated": 0, "new_fetches": 0,
        "review_statuses_changed": False, "source_admission": False, "gap_closures": 0,
        "global_visible_validation": "NOT_ASSESSED",
    }


VERSION_CAPTURE_URLS = (
    "https://www.legislation.gov.uk/ssi/2011/176/2017-12-01",
    "https://www.legislation.gov.uk/ssi/2011/176/2019-11-11",
)
VERSION_CAPTURE_INSTRUCTION = (
    "Parent officially browsed EXACT HTTPS historicallinks youfound: "
    "https://www.legislation.gov.uk/ssi/2011/176/2017-12-01 web returnedunsupportedXHTML; "
    "2019-11-11 websafeopenfailure. Targeted nativecapture authorized underuser autoofficialintake: "
    "TWO exactURLs only with existingsecureHostCapture/fetch_official raw+headers+redirects+date+hash. "
    "No old endpoint repeat, no search(originalSCT4queries), no modellease. Write "
    "superseded-version-captures underownindexfaultscope; actualcapturebound2 per targetedversionrepair. "
    "Parseactualoperativeversions, don'tinventnewURLdata.xmlunlessactuallylinked. Then reportbindableversionpair "
    "forfreshindependentdate/currentness review beforeindexretentionchecks. KeeporiginalSCTlegalholds; "
    "versionpairtechnicalproofnoanswerpass."
)


def version_capture_emitter(directory: Path, url: str, files: dict[str, str]) -> Callable:
    """Bound the existing transport before each GET, including redirected hops."""
    if url not in VERSION_CAPTURE_URLS:
        raise visible.ValidationHold("EXACT_HISTORICAL_CAPTURE_URL_REQUIRED")

    def emit(name, value):
        if name not in ("raw.bytes", "transport.json") and not re.fullmatch(
            r"hop-\d{2}-(request|response)\.json", name
        ):
            raise visible.ValidationHold("VERSION_CAPTURE_FILE_SCOPE")
        if name in files:
            raise visible.ValidationHold("VERSION_CAPTURE_FILE_REPLAY")
        # fetch_official emits a request before opening the connection. A redirect
        # to any unapproved endpoint is recorded and stopped before its GET.
        files[name] = write(directory / name, value)
        if name.endswith("-request.json") and value["url"] != url:
            raise visible.ValidationHold("REDIRECT_OUTSIDE_TWO_EXACT_URL_AUTHORITY")
        if name.endswith("-request.json") and any(
            other.endswith("-request.json") for other in files if other != name
        ):
            raise visible.ValidationHold("ONE_GET_PER_EXACT_VERSION_URL")
        return files[name]

    return emit


def capture_superseded_versions() -> dict:
    """Two authorized native capture attempts, no retries or legal eligibility."""
    from scripts.ge_auto_host_bridge import fetch_official, parse_official_capture
    from scripts.ge_auto_research_intake import parser_binding

    target = OUTPUT / "superseded-version-captures"
    visible.safe(target, OUTPUT)
    # Atomic create claims both attempts. A crash consumes the run; never resume
    # it by silently fetching either endpoint again.
    target.mkdir(mode=0o700, exist_ok=False)
    code_paths = (
        "scripts/ge_auto_visible_index_faults.py", "scripts/ge_auto_host_bridge.py",
        "scripts/ge_auto_research_intake.py", "scripts/ge_unseen_sources.py",
    )
    pins = {name: digest(read(ROOT / name, ROOT)) for name in code_paths}
    parser_pin = parser_binding(include_legal_tables=True)
    start = {
        "schema": "ge.visible.historical.version.capture.start.v1",
        "started_at": datetime.now(UTC).isoformat(), "urls": VERSION_CAPTURE_URLS,
        "instruction": VERSION_CAPTURE_INSTRUCTION,
        "instruction_utf8_sha256": digest(VERSION_CAPTURE_INSTRUCTION.encode()),
        "authority_kind": "EXPLICIT_CURRENT_USER_INSTRUCTION_NOT_SIGNED_CAPABILITY",
        "max_capture_attempts": 2, "max_gets_per_url": 1,
        "max_bytes_per_capture": 8_000_000, "timeout_seconds_per_capture": 45,
        "searches": 0, "model_lease": False, "parser_sha256": parser_pin,
        "include_legal_tables": True, "code_sha256": pins,
        "prior_inspection_sha256": digest(read(
            OUTPUT / "superseded-version-inspection/RESULTS.json", OUTPUT,
            "dc4a08e468c73e9925cf9f231b2831addc0344256b114686a40fe9d6d704dde4")),
    }
    start_sha = write(target / "RUN-START.json", start)
    write(target / "EXECUTED-FAULT-RUNNER.py", read(Path(__file__), ROOT))
    attempts = []
    for ordinal, url in enumerate(VERSION_CAPTURE_URLS, 1):
        directory = target / url.rsplit("/", 1)[-1]
        directory.mkdir(mode=0o700)
        files: dict[str, str] = {}
        row = {"ordinal": ordinal, "url": url, "started_at": datetime.now(UTC).isoformat(),
               "run_start_sha256": start_sha, "capture_attempt_cost": 1,
               "search_cost": 0, "source_review": "NOT_PERFORMED", "admitted": False}
        write(directory / "ATTEMPT-START.json", row)
        try:
            for name, expected in pins.items():
                read(ROOT / name, ROOT, expected)
            if parser_binding(include_legal_tables=True) != parser_pin:
                raise visible.ValidationHold("PARSER_CHANGED_BEFORE_VERSION_CAPTURE")
            transport = fetch_official(url, max_bytes=8_000_000, timeout_seconds=45,
                emit=version_capture_emitter(directory, url, files))
            raw = read(directory / "raw.bytes", OUTPUT, transport["raw_sha256"])
            if transport["final_url"] != url or len(raw) != transport["byte_count"]:
                raise visible.ValidationHold("EXACT_VERSION_TRANSPORT_BINDING")
            manifest = parse_official_capture(
                raw, source_url=url, expected_raw_sha256=transport["raw_sha256"])
            files["PARSED-MANIFEST.json"] = write(directory / "PARSED-MANIFEST.json", manifest)
            if manifest["parser_sha256"] != parser_pin or manifest["parsed"]["status"] != "ready":
                raise visible.ValidationHold("VERSION_PARSE_NOT_READY_OR_PIN_CHANGED")
            row.update(state="CAPTURED_PARSED_AWAITING_INDEPENDENT_VERSION_REVIEW",
                       transport=transport, parsed_sha256=manifest["parsed_sha256"],
                       parsed_block_count=len(manifest["parsed"]["body_blocks"]),
                       parser_sha256=manifest["parser_sha256"])
        except Exception as exc:
            row.update(state="HOLD_CAPTURE_OR_PARSE", error_type=type(exc).__name__, reason=str(exc))
        row.update(completed_at=datetime.now(UTC).isoformat(), files=files)
        for name, expected in files.items():
            read(directory / name, OUTPUT, expected)
        write(directory / "RESULT.json", row)
        attempts.append(row)
    complete = all(r["state"] == "CAPTURED_PARSED_AWAITING_INDEPENDENT_VERSION_REVIEW" for r in attempts)
    result = {
        "schema": "ge.visible.historical.version.capture.v1",
        "state": "TWO_PARSED_CAPTURES_AWAITING_VERSION_INSPECTION" if complete else "HOLD_CAPTURE_OR_PARSE",
        "run_start_sha256": start_sha, "attempts": attempts, "actual_capture_attempts": len(attempts),
        "new_searches": 0, "model_inference_calls": 0, "model_lease_acquired": False,
        "old_endpoint_repeats": 0, "data_xml_urls_invented_or_fetched": False,
        "superseded_version_retention": "NOT_DEMONSTRATED", "independent_pair_review": "NOT_PERFORMED",
        "SCT_legal_holds_changed": False, "index_builds": 0, "answer_pass": False,
        "source_admission": False, "global_visible_validation": "NOT_ASSESSED",
    }
    write(target / "RESULTS.json", result)
    return result


def main() -> int:
    global OUTPUT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index-readback-sha256")
    parser.add_argument("--inspect-superseded", action="store_true",
                        help="Inspect existing attested visible bytes only; no index or model work")
    parser.add_argument("--capture-superseded", action="store_true",
                        help="Make the two explicitly authorized historical HTTPS captures, once")
    parser.add_argument("--parent-reranker-released", action="store_true")
    parser.add_argument("--ready-reason", default="")
    parser.add_argument("--attempt-subdir", choices=["parser-binding-r2"])
    args = parser.parse_args()
    if args.capture_superseded:
        if args.inspect_superseded or args.attempt_subdir or args.index_readback_sha256 or args.parent_reranker_released:
            parser.error("historical capture is separate from index/model execution")
        result = capture_superseded_versions()
        print(json.dumps({"state": result["state"], "actual_capture_attempts": result["actual_capture_attempts"],
                          "model_calls": 0}))
        return 0 if result["state"] == "TWO_PARSED_CAPTURES_AWAITING_VERSION_INSPECTION" else 2
    if args.inspect_superseded:
        if args.attempt_subdir or args.index_readback_sha256 or args.parent_reranker_released:
            parser.error("superseded inspection is separate from model execution")
        result = inspect_superseded_inputs()
        target = OUTPUT / "superseded-version-inspection"
        write(target / "EXECUTED-FAULT-RUNNER.py", read(Path(__file__), ROOT))
        key = write(target / "RESULTS.json", result)
        print(json.dumps({"state": result["state"], "receipt_sha256": key,
                          "capture_records": len(result["captures"]), "model_calls": 0}))
        return 0
    if not args.index_readback_sha256:
        parser.error("--index-readback-sha256 is required for model execution")
    if args.attempt_subdir:
        OUTPUT = OUTPUT / args.attempt_subdir
    visible.safe(OUTPUT, ROOT)
    OUTPUT.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(
        visible.safe(OUTPUT / ".runner.lock", OUTPUT), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
    )
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = execute(
            readback_sha256=args.index_readback_sha256,
            parent_released=args.parent_reranker_released,
            ready_reason=args.ready_reason,
        )
        print(
            json.dumps(
                {
                    k: result[k]
                    for k in (
                        "state",
                        "actual_document_embeddings",
                        "actual_query_embeddings",
                        "global_visible_validation",
                    )
                }
            )
        )
        return 0
    except (ValueError, PermissionError, RuntimeError, OSError, KeyError, TypeError) as exc:
        hold = {
            "state": "HOLD_FAULT_COMPONENT",
            "reason": str(exc),
            "error_type": type(exc).__name__,
            "global_visible_validation": "NOT_ASSESSED",
        }
        write(OUTPUT / ("HOLD-" + digest(hold) + ".json"), hold)
        print(json.dumps(hold))
        return 2
    finally:
        os.close(fd)


if __name__ == "__main__":
    raise SystemExit(main())
