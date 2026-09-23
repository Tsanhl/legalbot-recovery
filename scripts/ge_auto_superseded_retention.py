"""One actual historical retention run; two reviewed dates, no legal application.

Reuses AutoResearchIndex, StructuralChunker and the parent's pinned runtime.
The review verifier binds actual files and the full reviewed ordinal selection.
No network, changed review decisions, ACTIVE writes, retries or model fallback.
"""
from __future__ import annotations

import json
import sqlite3
from collections import Counter
from dataclasses import asdict, replace
from datetime import UTC, date, datetime
from pathlib import Path

from backend.app.research.ge_auto_index import (
    REVIEW_CHECKS,
    AutoResearchIndex,
    Capture,
    ModelPin,
    ResearchPolicy,
    Scope,
)

from scripts import ge_auto_visible_index_faults as faults
from scripts import ge_auto_visible_index_validation as visible
from scripts.ge_auto_research_intake import parse_capture, parser_binding

ROOT, VISIBLE = faults.ROOT, visible.VISIBLE
OUTPUT = faults.OUTPUT / "superseded-retention"
REVIEW = VISIBLE / "independent-source-review/historical-version-r1"
CAPTURES = faults.OUTPUT / "superseded-version-captures"
PARENT_SHA = "20f209a2b160bd2df8cbb2d81c688154ae8918b04077c61f82c1aec13114e238"
DATES = ("2017-12-01", "2019-11-11")
PURPOSE = "HISTORICAL_REGULATION_3_TEXT_RETENTION_ONLY"
ACTOR = "visible-historical-retention-index-worker"
OWNER_INSTRUCTION = (
    b"Historical independent review is ready: VISIBLE/independent-source-review/historical-version-r1/"
    b"PARENT-REVIEW-BINDING.json (under data/evaluations/general-enquiries/ge-auto-research-visible-20260905). "
    b"Complete actual superseded-law retention test on these two exact versions using the reviewed required "
    b"blocks, real pinned embeddings/new isolated non-live generations. Existing original SCT holds "
    b"unchanged, no 2026 eligibility claims. Shared model lease released/free by Averroes. Use flock one "
    b"inference session, bounded no unchanged retry. Own index-fault-validation/superseded-retention only "
    b"and your helper/tests. Record actual version/date exclusions both generations persist, counts/model "
    b"calls and release lease. Do not read private bank."
)
digest, read, obj = faults.digest, faults.read, faults.obj


def require(condition, reason):
    if not condition:
        raise visible.ValidationHold(reason)


def write(path, value):
    return visible.write_new(path, value, output=OUTPUT)


def scoped_review_eligible(row):
    """ELIGIBLE refers only to historical text retention; application remains HOLD."""
    return (
        row.get("decision") == "ELIGIBLE" and row.get("decision_scope") == PURPOSE
        and row.get("technical_index_retention_eligible") is True
        and row.get("legal_application_decision") == "HOLD" and row.get("holds") == []
        and bool(row.get("application_holds")) and row.get("jurisdiction") == "GB-SCT"
        and row.get("as_of_date") in DATES
        and row.get("valid_from") == row.get("valid_to") == row.get("as_of_date")
        and set(row.get("checks", {})) == REVIEW_CHECKS
        and all(v is True for v in row["checks"].values())
        and set(row.get("check_evidence", {})) == REVIEW_CHECKS
        and all(isinstance(v, str) and v.strip() for v in row["check_evidence"].values())
        and all(row.get(k) is False for k in (
            "admitted", "answer_pass", "full_current_law_eligible", "full_source_admission",
            "qualified_legal_review", "legal_gold"))
    )


def reviewed_selection(context, full, recipe):
    blocks = sorted((b for group in context["groups"].values() for b in group),
                    key=lambda b: b["ordinal"])
    ordinals = [b["ordinal"] for b in blocks]
    originals = {b["ordinal"]: b for b in full["parsed"]["body_blocks"]}
    require(len(ordinals) == len(set(ordinals)) == context["selected_block_count"],
            "REVIEW_SELECTION_DUPLICATE_OR_COUNT")
    require(ordinals == recipe["ordered_block_ordinals"], "REVIEW_SELECTION_ORDINALS")
    require(all(originals.get(b["ordinal"]) == b for b in blocks), "REVIEW_SELECTION_TEXT_CHANGED")
    require(digest(blocks) == context["selected_blocks_sha256"] == recipe["selected_blocks_sha256"],
            "REVIEW_SELECTION_HASH")
    require(digest(context["regulation_3_blocks"]) == context["regulation_3_blocks_sha256"]
            and all(b in blocks for b in context["regulation_3_blocks"]), "REVIEW_REGULATION_3_CONTEXT")
    return blocks


class HistoricalReviewGate:
    """Out-of-band pinned parent binding, exact review files, exact derived receipts."""

    def __init__(self):
        self.files, self.derived, self.materials = {}, {}, {}
        parent = self.file(REVIEW / "PARENT-REVIEW-BINDING.json", PARENT_SHA)
        require(parent["decision_scope"] == PURPOSE and parent["dates"] == list(DATES)
                and parent["technical_index_retention_eligible"] is True
                and parent["full_source_admission"] is False, "PARENT_SCOPE")
        self.parent = parent
        att = self.file(REVIEW / "REVIEW-ATTESTATION.json", parent["review_attestation_sha256"])
        require(att["scope"] == PURPOSE and att["reviewer_authored_or_captured_this_law"] is False
                and att["source_rows"] == 2 and att["cryptographic_signature_claimed"] is False,
                "REVIEW_ROLE_SCOPE")
        # The review supplies a role/attestation, not a named human or a signature.
        self.reviewer_id = "review-attestation-sha256:" + parent["review_attestation_sha256"]
        for name, pin in att["artifact_hashes"].items():
            require(Path(name).name == name, "REVIEW_ARTIFACT_PATH")
            self.file(REVIEW / name, pin["sha256"], size=pin["bytes"], decode=False)
        inputs = self.file(REVIEW / "INPUT-HASHES.json", att["artifact_hashes"]["INPUT-HASHES.json"]["sha256"])
        allowed_code = {"backend/app/contracts/schema_registry.py", "backend/app/ingestion/models.py",
                        "backend/app/ingestion/parsers.py", "backend/app/ingestion/sanitation.py",
                        "scripts/ge_auto_research_intake.py", "scripts/ge_auto_xml_tables.py"}
        for name, pin in inputs.items():
            path = ROOT / name
            require(name in allowed_code or path.is_relative_to(VISIBLE), "REVIEW_INPUT_OUTSIDE_VISIBLE")
            self.file(path, pin["sha256"], size=pin["bytes"], decode=False)
        contexts = self.file(REVIEW / "BOUND-CONTEXT.json", parent["bound_context_sha256"])
        recipe = self.file(REVIEW / "SELECTION-HASH-RECIPE.json", parent["selection_hash_recipe_sha256"])
        final = self.file(REVIEW / "FINAL-VALIDATION.json", parent["final_validation_sha256"])
        require(final["status"] == "VERIFIED_LOCAL_BINDINGS"
                and final["selection_hash_recipe_sha256"] == parent["selection_hash_recipe_sha256"]
                and recipe["review_attestation_sha256"] == parent["review_attestation_sha256"], "FINAL_REVIEW_BINDING")
        raw = self.file(REVIEW / "SOURCE-REVIEW.jsonl", parent["source_review_sha256"], decode=False)
        self.reviews = {r["as_of_date"]: r for r in (visible.load_json_strict(line) for line in raw.splitlines())}
        require(len(raw.splitlines()) == 2 and set(self.reviews) == set(DATES), "EXACT_TWO_REVIEW_ROWS")
        self.relation = self.file(REVIEW / "VERSION-RELATION.json",
                                  att["artifact_hashes"]["VERSION-RELATION.json"]["sha256"])
        self.amendment = self.file(REVIEW / "AMENDMENT-PARSED-MANIFEST.json",
                                   att["artifact_hashes"]["AMENDMENT-PARSED-MANIFEST.json"]["sha256"])
        for day in DATES:
            row = self.reviews[day]
            require(scoped_review_eligible(row), "HISTORICAL_REVIEW_HOLD")
            context = next(s for s in contexts["sources"] if s["as_of_date"] == day)
            selection_recipe = next(s for s in recipe["sources"] if s["as_of_date"] == day)
            full = self.file(ROOT / context["full_manifest_path"], row["binding"]["full_manifest_sha256"])
            raw = self.file(CAPTURES / day / "raw.bytes", row["source_sha256"], decode=False)
            transport = self.file(CAPTURES / day / "transport.json", inputs[str((CAPTURES / day / "transport.json").relative_to(ROOT))]["sha256"])
            require(transport["raw_sha256"] == row["source_sha256"]
                    and transport["canonical_url"] == transport["final_url"] == row["source_url"]
                    and transport["http_status"] == 200 and not transport["redirect_chain"], "REVIEW_TRANSPORT")
            parsed = parse_capture(raw, source_url=row["source_url"], expected_raw_sha256=row["source_sha256"],
                                   include_legal_tables=True)
            require(parsed.is_ready and digest(asdict(parsed)) == full["parsed_sha256"]
                    == row["binding"]["full_parsed_sha256"] == context["full_parsed_sha256"]
                    and full["parser_sha256"] == row["binding"]["parser_sha256"]
                    == parser_binding(include_legal_tables=True), "EXACT_REVIEW_PARSE_BINDING")
            blocks = reviewed_selection(context, full, selection_recipe)
            require(row["binding"]["selected_blocks_sha256"] == digest(blocks)
                    and row["binding"]["regulation_3_blocks_sha256"] == digest(context["regulation_3_blocks"])
                    and context["source_sha256"] == row["source_sha256"], "REVIEW_CONTEXT_BINDING")
            selected_ordinals = {b["ordinal"] for b in blocks}
            selected = replace(parsed, body_blocks=tuple(b for b in parsed.body_blocks if b.ordinal in selected_ordinals))
            self.materials[day] = {"review": row, "context": context, "full": full, "raw": raw,
                                   "parsed": selected, "blocks": blocks, "transport": transport}
        self.replay()

    def file(self, path, expected, *, size=None, decode=True):
        raw = read(path, ROOT, expected)
        require(size is None or len(raw) == size, "REVIEW_FILE_LENGTH")
        self.files[path] = expected
        return visible.load_json_strict(raw) if decode else raw

    def replay(self):
        for path, sha in self.files.items():
            read(path, ROOT, sha)

    def bind(self, day, scope, claim):
        self.replay()
        m, row = self.materials[day], self.reviews[day]
        require(scoped_review_eligible(row), "HISTORICAL_REVIEW_HOLD")
        source = Capture(scope, "visible-historical-capture-worker", m["raw"], m["parsed"],
            row["binding"]["parser_sha256"], row["source_url"], row["source_url"], (),
            m["transport"]["fetched_at"], row["source_url"], "official-law-historical-text", "Scotland",
            digest({"rights": row["check_evidence"]["rights"], "review": digest(row)}))
        quote_block = next(b for b in source.parsed.body_blocks if b.text.startswith("3. —(1)"))
        derived = {
            **row, "decision": "ELIGIBLE_RESEARCH_ONLY", "jurisdiction": "Scotland",
            "reviewer_id": self.reviewer_id, "reviewer_identity_kind": "EXACT_REVIEW_ATTESTATION_REFERENCE",
            "raw_review": row, "raw_review_sha256": digest(row), "parent_binding_sha256": PARENT_SHA,
            "review_attestation_sha256": self.parent["review_attestation_sha256"],
            "source_review_file_sha256": self.parent["source_review_sha256"],
            "bound_context_sha256": self.parent["bound_context_sha256"],
            "selection_hash_recipe_sha256": self.parent["selection_hash_recipe_sha256"],
            "capture_sha256": digest(source.manifest()), "parsed_sha256": digest(asdict(source.parsed)),
            "scope": asdict(scope), "issue_id": "issue-" + claim["proposition_id"],
            "affected_claim_sha256": digest(claim), "checks": sorted(REVIEW_CHECKS),
            "original_checks": row["checks"], "uncertainties": row["holds"],
            "uncertainty_scope": PURPOSE, "application_holds": row["application_holds"],
            "context_block_ordinals": [b.ordinal for b in source.parsed.body_blocks],
            "quote_block_ordinal": quote_block.ordinal, "quote": quote_block.text,
            "locator": quote_block.source_anchor, "legal_locator": row["locator"],
            "selection_is_reviewed_derivative_of_full_parse": True,
        }
        self.derived[digest(derived)] = visible.canonical_json_bytes(derived)
        return source, derived

    def verify_review(self, reviewer, receipt):
        try:
            self.replay()
            row = self.reviews[receipt["as_of_date"]]
            return (reviewer == self.reviewer_id and scoped_review_eligible(row)
                    and receipt["raw_review_sha256"] == digest(row)
                    and self.derived.get(digest(receipt)) == visible.canonical_json_bytes(receipt))
        except (ValueError, KeyError, OSError):
            return False


def contracts_for(source, claim, policy, gate, identity, registry, observed_at):
    """Full v2 contracts with an actual empty baseline and a technical request."""
    key, scope = claim["proposition_id"], asdict(source.scope)
    owner_scope = digest({"instruction_sha256": digest(OWNER_INSTRUCTION), "scope": scope})
    conversation = visible.seal_contract({"schema": "legalbot.conversation-snapshot.v1",
        "snapshot_id": "conversation-snapshot-" + key, "conversation_id": "conversation-" + key,
        "owner_scope_sha256": owner_scope, "revision": 0, "created_at": observed_at,
        "messages": [], "truncated": False, "omitted_message_count": 0,
        "omitted_before_ordinal": None, "truncation_reason": "none", "estimated_tokens": 0})
    facts = visible.seal_contract({"schema": "legalbot.matter-fact-snapshot.v2", "snapshot_id": "facts-" + key,
        "conversation_id": conversation["conversation_id"], "owner_scope_sha256": owner_scope,
        "conversation_revision": 0, "created_at": observed_at, "facts": []})
    spec = obj(ROOT / "scripts/model/manifests/qwen3-retrieval-models.json", ROOT)
    toolchain = {"parser_sha256": source.parser_sha256, "ocr_sha256": None,
        "chunker_sha256": digest(read(ROOT / "backend/app/ingestion/chunking.py", ROOT)),
        "tokenizer_sha256": digest(read(ROOT / identity["directory"] / "tokenizer.json", ROOT)),
        "embedding_model_sha256": identity["file_manifest_sha256"],
        "lexical_config_sha256": digest({"engine": "lancedb-native-fts", "use_tantivy": False}),
        "vector_schema_sha256": digest({"field": "vector", "dtype": "float32", "dimensions": 1024, "metric": "cosine"}),
        "reranker_model_sha256": next(m for m in spec["models"] if m["role"] == "reranker")["file_manifest_sha256"]}
    baseline = visible.seal_contract({"schema": "legalbot.research-empty-baseline.v1",
        "generation_id": "empty-historical-retention-" + key, "source_manifest_sha256": digest([]),
        "qualification_policy_sha256": policy.sha256, "sources": [], "toolchain": toolchain,
        "counts": {"source_versions": 0, "canonical_objects": 0, "chunks": 0,
                   "lexical_rows": 0, "vector_rows": 0, "embedding_dimensions": 1024},
        "file_manifest_sha256": digest({"sources": [], "rows": []}), "closure_status": "validated",
        "attestations": [], "created_at": observed_at, "sealed_at": observed_at,
        "non_live": True, "production_admission": False, "training": False})
    request = {"purpose": PURPOSE, "scope": scope, "proposition": claim, "matter_facts": [],
               "parent_binding_sha256": PARENT_SHA, "answer_generation": False}
    variants = {"queries": [claim["proposed_proposition"]]}
    config = {"helper_sha256": digest(read(Path(__file__).absolute(), ROOT)),
        "model_identity_sha256": identity["identity_sha256"], "toolchain": toolchain,
        "capabilities_to_execute": ["retrieval.lexical", "retrieval.vector"],
        "reranker_execution": "NOT_RUN", "full_query_plan_execution": "NOT_RUN",
        "historical_source_selection_sha256": gate.parent["bound_context_sha256"]}
    plan = visible.build_query_plan(request_id="request-" + key, request_sha256=digest(request),
        original_question_sha256=digest(claim["proposed_proposition"].encode()), task_type="general",
        answer_route="direct", requires_knowledge=True, requires_matter=False, response_disposition="LIMITED",
        jurisdiction="Scotland", jurisdiction_status="explicit", requested_as_of_date=date.fromisoformat(claim["date"]),
        as_of_date_status="explicit", issue_ids=["issue-" + key], missing_facts=[],
        query_variants_ref="queries-" + key, query_variants_sha256=digest(variants),
        candidate_id="historical-retention-component", policy_sha256=policy.sha256, config_sha256=digest(config),
        conversation_snapshot=conversation, fact_snapshot=facts,
        rewrite={"status": "not_needed", "encrypted_query_ref": None, "query_sha256": None,
                 "reason_code": "historical_retention_only"},
        risk_flags=["historical_retention_only", "legal_application_hold"],
        request_observed_at=datetime.fromisoformat(observed_at), frozen_at=datetime.fromisoformat(observed_at),
        registry=registry).value
    for c in (conversation, facts, baseline, plan):
        registry.validate_new(c)
    return {"request": request, "conversation": conversation, "facts": facts,
            "knowledge_generation": baseline, "query_plan": plan, "query_variants": variants, "config": config}


def prepare_run(output):
    """No model load/inference. Persistent queue and exact prepared build packets."""
    from scripts.ge_auto_research_runtime import verified_model_identity

    gate = HistoricalReviewGate()
    identity = verified_model_identity()
    scope = Scope(str(output / "store"), "candidate_case_local", PURPOSE, "SCT-HISTORICAL-RETENTION")
    policy = ResearchPolicy(workspace=output, owner_instruction=OWNER_INSTRUCTION,
        expected_owner_instruction_sha256=digest(OWNER_INSTRUCTION), scopes=[scope],
        model=ModelPin.from_runtime_identity(identity), reviewers=[gate.reviewer_id], verify_review=gate.verify_review)
    registry = visible.ContractSchemaRegistry.from_project_root(ROOT)
    units = []
    for day in DATES:
        claim = {"proposition_id": "SCT-HISTORICAL-" + day, "date": day, "purpose": PURPOSE,
            "proposed_proposition": "Retrieve the historical regulation 3 duties in relation to tenancy deposits as displayed on " + day + ", preserving all reviewed conditions and context; no application to tenancy facts."}
        source, review = gate.bind(day, scope, claim)
        contracts = contracts_for(source, claim, policy, gate, identity, registry, datetime.now(UTC).isoformat())
        lineage = visible.lineage_for(contracts, registry)
        local = output / day
        for name, value in (("CONTRACTS.json", contracts), ("DERIVED-REVIEW.json", review),
                            ("SELECTED-PARSE.json", asdict(source.parsed))):
            visible.write_new(local / name, value, output=output)
        cap = policy.authorize(scope=scope, actor=ACTOR, role="candidate", action="jobs", binding_sha256=digest(asdict(lineage)))
        index = AutoResearchIndex(policy=policy, capability=cap, scope=scope, lineage=lineage)
        builds = Path(scope.root) / "builds"
        existing = sorted(p.name for p in builds.iterdir()) if builds.exists() else []
        require(not existing, "ISOLATED_BASELINE_MUST_START_EMPTY")
        baseline_check = {"scope": asdict(scope), "existing_build_directories": existing,
                          "state": "EMPTY_ISOLATED_INDEX_OBSERVED", "query_executed": False}
        baseline_sha = visible.write_new(local / "EXISTING-INDEX-CHECK.json", baseline_check, output=output)
        gap = index.enqueue(cap, issue_id="issue-" + claim["proposition_id"], gap_class="retrieval_miss",
            affected_claim_sha256=digest(claim), failure_fingerprint=digest({"first_historical_retention": day, "parent": PARENT_SHA}))
        attempt = index.begin_attempt(cap, gap, inputs_sha256=digest({"source": source.manifest(), "review": review}),
            existing_retrieval_sha256=baseline_sha)
        require(attempt is not None, "UNCHANGED_RETENTION_ATTEMPT")
        operation = index.reserve(cap, attempt, kind="capture", input_sha256=digest(source.manifest()))
        index.capture(cap, operation, source)
        prepared = index.prepare(cap, gap=gap, attempt=attempt, sources=[(source, review)])
        value = visible.load_json_strict(prepared.payload)
        ordinals = {n for row in value["rows"] for n in row["structural_chunk"]["block_ordinals"]}
        require(ordinals == set(review["context_block_ordinals"]), "PREPARED_REQUIRED_CONTEXT_NOT_COMPLETE")
        visible.write_new(local / "PREPARED.json", prepared.payload, output=output)
        visible.write_new(local / "CAPTURE-IMPORT.json", {"operation": "IMPORT_EXISTING_REVIEWED_CAPTURE",
            "raw_sha256": digest(source.raw), "origin_transport": gate.materials[day]["transport"],
            "new_fetches": 0, "new_queries": 0, "attempt": attempt, "capture_operation": operation}, output=output)
        units.append({"index": index, "scope": scope, "source": source, "review": review, "cap": cap,
            "gap": gap, "attempt": attempt, "prepared": prepared, "material": value, "claim": claim, "local": local})
    return gate, identity, policy, units


def sqlite_generation_records(db, outcomes):
    """objects.digest hashes the full receipt, including generation_sha256."""
    counts = dict(db.execute("SELECT kind,count(*) FROM objects GROUP BY kind"))
    for sha, payload in db.execute("SELECT digest,payload FROM objects"):
        require(digest(payload) == sha, "SQLITE_METADATA_READBACK")
    found = {}
    for object_sha, payload in db.execute("SELECT digest,payload FROM objects WHERE kind='generation'"):
        receipt = visible.load_json_strict(payload)
        generation_sha = receipt["generation_sha256"]
        require(digest({k: v for k, v in receipt.items() if k != "generation_sha256"}) == generation_sha,
                "SQLITE_INTERNAL_GENERATION_DIGEST")
        require(generation_sha not in found, "DUPLICATE_SQLITE_GENERATION")
        found[generation_sha] = {"sqlite_object_sha256": object_sha, "receipt": receipt}
    for outcome in outcomes:
        generation_sha = outcome["generation_sha256"]
        require(generation_sha in found
                and found[generation_sha]["receipt"]["build_sha256"] == outcome["build_sha256"],
                "BOTH_GENERATIONS_NOT_RETAINED_IN_SQLITE")
    return counts, found


def run():
    from scripts.ge_auto_research_runtime import PinnedEmbeddingSession

    visible.safe(OUTPUT, faults.OUTPUT)
    OUTPUT.mkdir(mode=0o700, exist_ok=True)
    # Tests may already exist under test-runs; this exclusive claim consumes the
    # actual execution even on a pre-inference hold. No unchanged retry.
    (OUTPUT / ".execution-claim").mkdir(mode=0o700, exist_ok=False)
    write(OUTPUT / "RUN-START.json", {"started_at": datetime.now(UTC).isoformat(), "parent_binding_sha256": PARENT_SHA,
        "instruction": OWNER_INSTRUCTION.decode(), "instruction_sha256": digest(OWNER_INSTRUCTION),
        "schema": "ge.visible.superseded.retention.start.v1", "model_sessions_budget": 1, "new_fetches": 0})
    write(OUTPUT / "EXECUTED-HELPER.py", read(Path(__file__).absolute(), ROOT))
    session = None
    outcomes, generation_snapshots = [], {}
    try:
        gate, identity, policy, units = prepare_run(OUTPUT)
        write(OUTPUT / "PINNED-INPUTS.json", {str(p.relative_to(ROOT)): sha for p, sha in gate.files.items()})
        write(OUTPUT / "VERSION-RELATION.json", gate.relation)
        write(OUTPUT / "AMENDING-CONTEXT.json", {"review_attestation_sha256": gate.parent["review_attestation_sha256"],
            "version_relation": gate.relation, "amendment_manifest": gate.amendment,
            "purpose": "INDEPENDENT_REVIEW_EVIDENCE_NOT_THIRD_INDEXED_SOURCE"})
        scopes = [units[0]["scope"]]
        active_before = visible.active_snapshot(scopes)
        expected_documents = sum(len(u["material"]["rows"]) for u in units)
        require(0 < expected_documents <= 128, "BOUNDED_HISTORICAL_EMBEDDING_ROWS")
        write(OUTPUT / "PRE-INFERENCE.json", {"model_identity": identity,
            "documents": expected_documents, "queries": 2, "reviewed_blocks": [len(u["source"].parsed.body_blocks) for u in units],
            "chunks": [len(u["material"]["rows"]) for u in units], "ACTIVE_before": active_before})
        print(json.dumps({"event": "MODEL_LEASE_REQUESTED", "at": datetime.now(UTC).isoformat(),
                          "documents": expected_documents, "queries": 2}), flush=True)
        session = PinnedEmbeddingSession()
        try:
            with session as provider:
                require(provider.identity == identity and provider.verify_binding(), "ACTUAL_PINNED_PROVIDER_IDENTITY")
                # Check every actual tokenizer input before the first embedding, without truncation.
                for unit in units:
                    for row in unit["material"]["rows"]:
                        provider._tokens(row["text"])
                    provider._tokens(unit["claim"]["proposed_proposition"], query=True)
                inference_start = {"event": "INFERENCE_START", "at": datetime.now(UTC).isoformat(),
                    "model_identity_sha256": identity["identity_sha256"], "documents": expected_documents,
                    "queries": 2, "shared_flock_held": session.lock is not None}
                write(OUTPUT / "INFERENCE-START.json", inference_start)
                print(json.dumps(inference_start), flush=True)
                for unit in units:
                    gate.replay()
                    day = unit["claim"]["date"]
                    index, prepared, scope = unit["index"], unit["prepared"], unit["scope"]
                    cap = policy.authorize(scope=scope, actor=ACTOR, role="candidate", action="build", binding_sha256=prepared.sha256)
                    generation = index.build(cap, prepared, provider=provider)
                    cap = policy.authorize(scope=scope, actor=ACTOR, role="candidate", action="retrieve", binding_sha256=generation)
                    retrieval = index.retrieve(cap, build_sha256=prepared.sha256, generation_sha256=generation,
                        query=unit["claim"]["proposed_proposition"], lineage=index.lineage, provider=provider)
                    covered = {n for row in retrieval["evidence"] for n in row["structural_chunk"]["block_ordinals"]}
                    require(covered == set(unit["review"]["context_block_ordinals"])
                            and retrieval["lexical_ids"] and retrieval["vector_ids"], "ACTUAL_RETRIEVAL_REQUIRED_CONTEXT")
                    write(unit["local"] / "RETRIEVAL.json", retrieval)
                    root = Path(scope.root) / "builds" / ("ge-auto-" + prepared.sha256)
                    generation_snapshots[day] = faults.snapshot(root)
                    outcomes.append({"date": day, "build_sha256": prepared.sha256,
                        "generation_sha256": generation, "generation_root": str(root.relative_to(OUTPUT)),
                        "retrieval_sha256": retrieval["retrieval_sha256"], "raw_sha256": digest(unit["source"].raw),
                        "selected_parse_sha256": digest(asdict(unit["source"].parsed)), "review_sha256": digest(unit["review"]),
                        "required_blocks": len(covered), "chunks": len(unit["material"]["rows"]),
                        "status": index.status(unit["gap"]), "application_holds": unit["review"]["application_holds"]})
        finally:
            receipt = session.receipt()
            receipt["session_exited_at"] = datetime.now(UTC).isoformat()
            receipt["lease_released"] = session.lock is None
            write(OUTPUT / "ACTUAL-INFERENCE.json", receipt)
            print(json.dumps({"event": "INFERENCE_SESSION_END", "at": receipt["session_exited_at"],
                "calls": receipt["actual_inference_calls"], "lease_released": receipt["lease_released"]}), flush=True)
        require(len(outcomes) == 2 and receipt["actual_inference_calls"] == expected_documents + 2,
                "HISTORICAL_INFERENCE_BUDGET")
        probes = []
        for outcome in outcomes:
            root = OUTPUT / outcome["generation_root"]
            generation, rows, table = faults.verify_generation(root, outcome)
            require(faults.snapshot(root) == generation_snapshots[outcome["date"]], "OLDER_GENERATION_CHANGED")
            own_day = outcome["date"]
            others = [d for d in DATES if d != own_day] + ["2018-01-01", "2026-09-05"]
            checks = {}
            for day in (own_day, *others):
                probe = faults.filter_probe(table, query="tenancy deposits", vector=rows[0]["vector"], jurisdiction="Scotland", day=day)
                require(bool(probe["lexical_ids"]) == (day == own_day)
                        and bool(probe["vector_ids"]) == (day == own_day), "WRONG_HISTORICAL_VERSION_DATE_RETURNED")
                checks[day] = probe
            require({r["valid_from"] for r in rows} == {own_day} == {r["valid_to"] for r in rows}, "ONE_DAY_INTERVAL_REQUIRED")
            probes.append({"generation_sha256": generation["generation_sha256"], "checks": checks,
                "vector_origin": "ACTUAL_PERSISTED_DOCUMENT_VECTOR_NOT_NEW_QUERY_INFERENCE",
                "vector_chunk_id": rows[0]["id"], "persisted_vector_sha256": digest(rows[0]["vector"]),
                "persisted_rows_sha256": generation["rows_sha256"]})
        store = Path(units[0]["scope"].root)
        with sqlite3.connect((store / "metadata.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
            counts, _ = sqlite_generation_records(db, outcomes)
        gate.replay()
        require(visible.active_snapshot(scopes) == active_before, "ACTIVE_CHANGED")
        result = {"schema": "ge.visible.superseded.retention.v1", "state": "ACTUAL_HISTORICAL_RETENTION_VERIFIED",
            "scope": PURPOSE, "parent_binding_sha256": PARENT_SHA, "outcomes": outcomes,
            "date_exclusion_probes": probes, "generation_file_manifests": generation_snapshots,
            "sqlite_object_counts": counts, "both_generations_persist": True, "ACTIVE_unchanged": True,
            "actual_document_embeddings": expected_documents, "actual_query_embeddings": 2,
            "model_identity_sha256": identity["identity_sha256"], "inference_receipt_sha256": digest(receipt),
            "model_sessions": 1, "lease_released": receipt["lease_released"],
            "historical_eligibility_windows": [[d, d] for d in DATES], "continuous_interval_claimed": False,
            "new_fetches": 0, "new_queries": 0, "unchanged_retries": 0, "gap_closures": 0,
            "original_SCT_holds_changed": False, "eligibility_2026": False, "source_admission": False,
            "answer_pass": False, "reranker_execution": "NOT_RUN", "full_runtime_capability": "NOT_ASSESSED",
            "global_visible_validation": "NOT_ASSESSED"}
        write(OUTPUT / "RESULTS.json", result)
        return result
    except Exception as exc:
        write(OUTPUT / "HOLD.json", {"state": "HOLD_HISTORICAL_RETENTION", "reason": str(exc),
            "exception": type(exc).__name__, "preserved_outcomes": outcomes,
            "lease_released": session is None or session.lock is None,
            "unchanged_retry_permitted": False, "global_visible_validation": "NOT_ASSESSED"})
        raise


def finalize_persisted_readback():
    """Finish the exact post-inference metadata correction; never retry a build.

    The first execution's HOLD and executed helper remain immutable. Reopen its
    already persisted generations and create durable filter/readback evidence.
    No runtime/provider import, model lease, inference, admission or queue change.
    """
    hold = obj(OUTPUT / "HOLD.json", OUTPUT)
    require(hold["reason"] == "BOTH_GENERATIONS_NOT_RETAINED_IN_SQLITE"
            and hold["lease_released"] is True, "EXACT_POST_INFERENCE_HOLD_REQUIRED")
    outcomes = hold["preserved_outcomes"]
    require(len(outcomes) == 2 and [o["date"] for o in outcomes] == list(DATES), "TWO_PERSISTED_OUTCOMES_REQUIRED")
    require(not (OUTPUT / "RESULTS.json").exists(), "READBACK_ALREADY_COMPLETED")
    inference = obj(OUTPUT / "ACTUAL-INFERENCE.json", OUTPUT)
    preflight = obj(OUTPUT / "PRE-INFERENCE.json", OUTPUT)
    require(inference["lease_released"] is True and inference["actual_inference_calls"] == 64
            and preflight["documents"] == 62 and inference["model_identity"] == preflight["model_identity"],
            "ACTUAL_COMPLETED_EMBEDDING_RECEIPT_REQUIRED")
    require(Counter(c["kind"] for c in inference["calls"]) == {"document": 62, "query": 2}, "ACTUAL_INFERENCE_COUNTS")
    for relative, sha in obj(OUTPUT / "PINNED-INPUTS.json", OUTPUT).items():
        read(ROOT / relative, ROOT, sha)
    code_sha = digest(read(OUTPUT / "EXECUTED-HELPER.py", OUTPUT))
    generation_files, probes, document_bindings, query_bindings = {}, [], [], []
    registry = visible.ContractSchemaRegistry.from_project_root(ROOT)
    for outcome in outcomes:
        day = outcome["date"]
        local, root = OUTPUT / day, OUTPUT / outcome["generation_root"]
        generation, rows, table = faults.verify_generation(root, outcome)
        contracts = obj(local / "CONTRACTS.json", OUTPUT)
        lineage = visible.lineage_for(contracts, registry)
        require(digest(generation["lineage"]) == digest(asdict(lineage))
                and contracts["config"]["helper_sha256"] == code_sha, "PERSISTED_FULL_CONTRACT_BINDING")
        prepared = obj(local / "PREPARED.json", OUTPUT, outcome["build_sha256"])
        review = obj(local / "DERIVED-REVIEW.json", OUTPUT, outcome["review_sha256"])
        retrieval = obj(local / "RETRIEVAL.json", OUTPUT)
        require(scoped_review_eligible(review["raw_review"])
                and review["raw_review_sha256"] == digest(review["raw_review"])
                and review["parent_binding_sha256"] == PARENT_SHA, "PERSISTED_REVIEW_SCOPE")
        require(digest({k: v for k, v in retrieval.items() if k != "retrieval_sha256"})
                == retrieval["retrieval_sha256"] == outcome["retrieval_sha256"], "PERSISTED_RETRIEVAL_BINDING")
        require(retrieval["generation_sha256"] == outcome["generation_sha256"]
                and sorted(retrieval["evidence"], key=lambda r: r["id"])
                == sorted(prepared["rows"], key=lambda r: r["id"]), "ACTUAL_FULL_CONTEXT_RETRIEVAL_REQUIRED")
        require({n for r in retrieval["evidence"] for n in r["structural_chunk"]["block_ordinals"]}
                == set(review["context_block_ordinals"]), "REQUIRED_CONTEXT_READBACK")
        for row in rows:
            binding = visible.load_json_strict(row["binding_json"])
            # Runtime vector receipts use compact standard JSON without newline.
            vector_sha = digest(json.dumps(row["vector"], sort_keys=True, separators=(",", ":")).encode())
            document_bindings.append((binding["text_sha256"], vector_sha))
        query_bindings.append(retrieval["query_sha256"])
        require({r["valid_from"] for r in rows} == {day} == {r["valid_to"] for r in rows}, "ONE_DAY_INTERVAL_REQUIRED")
        checks = {}
        for probe_day in (*DATES, "2018-01-01", "2026-09-05"):
            check = faults.filter_probe(table, query="tenancy deposits", vector=rows[0]["vector"],
                                         jurisdiction="Scotland", day=probe_day)
            require(bool(check["lexical_ids"]) == (probe_day == day)
                    and bool(check["vector_ids"]) == (probe_day == day), "WRONG_HISTORICAL_VERSION_DATE_RETURNED")
            checks[probe_day] = check
        generation_files[day] = faults.snapshot(root)
        probes.append({"generation_sha256": outcome["generation_sha256"], "checks": checks,
            "vector_origin": "ACTUAL_PERSISTED_DOCUMENT_VECTOR_NOT_NEW_QUERY_INFERENCE",
            "vector_chunk_id": rows[0]["id"], "persisted_vector_sha256": digest(rows[0]["vector"]),
            "persisted_rows_sha256": generation["rows_sha256"]})
    require(Counter(document_bindings) == Counter((c["text_sha256"], c["vector_sha256"])
            for c in inference["calls"] if c["kind"] == "document"), "ACTUAL_MODEL_TO_PERSISTED_VECTOR_BINDING")
    require(Counter(query_bindings) == Counter(c["text_sha256"] for c in inference["calls"] if c["kind"] == "query"),
            "ACTUAL_MODEL_TO_QUERY_BINDING")
    with sqlite3.connect((OUTPUT / "store/metadata.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        counts, found = sqlite_generation_records(db, outcomes)
        require(counts["generation"] == 2, "EXACT_TWO_PERSISTED_GENERATIONS")
        for outcome in outcomes:
            require(db.execute("SELECT 1 FROM objects WHERE kind='raw_source' AND digest=?", (outcome["raw_sha256"],)).fetchone(), "RAW_VERSION_NOT_RETAINED")
            require(db.execute("SELECT 1 FROM objects WHERE kind='retrieval' AND digest=?", (outcome["retrieval_sha256"],)).fetchone(), "RETRIEVAL_NOT_RETAINED")
    scope = Scope(str(OUTPUT / "store"), "candidate_case_local", PURPOSE, "SCT-HISTORICAL-RETENTION")
    require(visible.active_snapshot([scope]) == preflight["ACTIVE_before"], "ACTIVE_CHANGED")
    correction = {"state": "POST_INFERENCE_SQLITE_READBACK_CORRECTED", "prior_hold_sha256": digest(hold),
        "original_executed_helper_sha256": code_sha, "corrected_helper_sha256": digest(read(Path(__file__).absolute(), ROOT)),
        "reason": "SQLite objects.digest hashes the complete generation receipt including its internal generation_sha256. Verify both identities; do not use the internal digest as the object primary key.",
        "sqlite_generation_records": {sha: row["sqlite_object_sha256"] for sha, row in found.items()},
        "new_inference_calls": 0, "new_builds": 0, "new_model_sessions": 0,
        "original_hold_and_generations_preserved": True}
    write(OUTPUT / "READBACK-CORRECTION.json", correction)
    write(OUTPUT / "READBACK-HELPER.py", read(Path(__file__).absolute(), ROOT))
    result = {"schema": "ge.visible.superseded.retention.v1", "state": "ACTUAL_HISTORICAL_RETENTION_VERIFIED",
        "scope": PURPOSE, "parent_binding_sha256": PARENT_SHA, "outcomes": outcomes,
        "date_exclusion_probes": probes, "generation_file_manifests": generation_files,
        "sqlite_object_counts": counts, "both_generations_persist": True, "ACTIVE_unchanged": True,
        "actual_document_embeddings": 62, "actual_query_embeddings": 2,
        "model_identity_sha256": inference["model_identity"]["identity_sha256"], "inference_receipt_sha256": digest(inference),
        "persisted_vectors_match_actual_model_receipt": True, "model_sessions": 1, "lease_released": True,
        "historical_eligibility_windows": [[d, d] for d in DATES], "continuous_interval_claimed": False,
        "readback_correction_sha256": digest(correction), "new_fetches": 0, "new_queries": 0,
        "unchanged_build_retries": 0, "gap_closures": 0, "original_SCT_holds_changed": False,
        "eligibility_2026": False, "source_admission": False, "answer_pass": False,
        "reranker_execution": "NOT_RUN", "full_runtime_capability": "NOT_ASSESSED",
        "global_visible_validation": "NOT_ASSESSED"}
    write(OUTPUT / "RESULTS.json", result)
    return result


if __name__ == "__main__":
    result = run()
    print(json.dumps({"state": result["state"], "model_calls": result["actual_document_embeddings"] + 2,
                      "lease_released": result["lease_released"]}))
