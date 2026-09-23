"""Actual, bounded visible successor index validation; never a case-answer run.

Prepare first with ``python -B -m scripts.ge_auto_successor_index_validation prepare``.
This verifies the exact fresh context-02 attestation, reparses five original
captures with include_legal_tables=True, verifies all eight check-only captures,
creates selected full contracts, and prepares real SQLite jobs/chunks. It loads
no model. Ask the parent for the shared embedding window after this preparation.

Then the parent/operator may call ``execute --preparation PATH --sha256 HASH
--parent-ready-reason EXACT_CONFIRMATION``. Never supply that confirmation before
the parent coordinates Beauvoir's release. The real pinned session acquires the
existing shared model lock, then real AutoResearchIndex builds and retrieves.
There is no network transport, fake provider, production admission or gap closure.

All new artifacts, temporary files and caches are under successor-index-validation.
The existing global embedding lock is synchronization only. The original five
builds, all original review rows, candidate answers and private banks are untouched.
Inputs are allowlisted, exact-hash bound and replayed. The eight official HTML
captures remain CHECK_ONLY according to their independent attestation; they are
not promoted to indexed law or assigned invented parsed-block review coverage.

Two case-local builds share each case's identical, explicitly reviewed context
across its seven total propositions. Every union block has an actual review
binding. One primary quotation per source is an index anchor; all seven reviewed
quotes are independently checked and separately queried. All companion groups
must be returned by real persisted retrieval before a proposition is released.

Source/proposition review permits expressly nonblocking matter/research limits.
They are retained verbatim outside the legal index and bound by hash in its
reviews. Backend ``uncertainties=[]`` means zero MATERIAL source-law holds only;
it never means an individual matter was verified or every later case was found.
The verifier enrolls only exact mechanical translations of actual attested
decisions. No independent approval, signature or additional review is fabricated.
"""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from dataclasses import asdict
from datetime import UTC, date, datetime
from pathlib import Path
from urllib.parse import urlsplit

from backend.app.contracts import ContractSchemaRegistry, build_query_plan, seal_contract
from backend.app.contracts.schema_registry import canonical_json_bytes, load_json_strict
from backend.app.ingestion.chunking import StructuralChunker
from backend.app.research import ge_auto_index as core
from scripts.ge_auto_research_intake import parse_capture, parser_binding
from scripts.ge_auto_visible_index_validation import (
    JURISDICTIONS, OWNER_SHA256, ValidationHold, check_passes, read, safe, sha, write_new,
)

ROOT = Path(__file__).resolve().parents[1]
VISIBLE = ROOT / "data/evaluations/general-enquiries/ge-auto-research-visible-20260905"
REVIEW = VISIBLE / "independent-source-review/successor-r1"
OUTPUT = VISIBLE / "successor-index-validation"
OWNER = ROOT / "data/evaluations/general-enquiries/LegalBot-GE-2026-09-05-codex-unseen-r1/PLAN-EXECUTION-AUTHORIZATION.json"
REVIEWER = "codex-fresh-independent-visible-source-successor-20260905-context-02"
ATTESTATION_SHA = "c7a7477b9e5f8f0044b50b912552e8bda1dac3800c6b8c8d4de2495479269875"
SOURCE_REVIEW_SHA = "211381bf8dd04737d32d6d035dc785b84b76d3ebbd756ee5f93a3ec7da8fcc5f"
SELECTED = ("ENG-SCOPE", "ENG-QUALITY", "ENG-REJECT", "ENG-REFUND",
            "NIR-DATE", "NIR-CAP", "NIR-TRANSITION")
VERSION = "legalbot.visible-successor-index-validation.v1"
ACTOR = "visible-successor-index-component-runner"
digest = core.digest


def require(ok, code):
    if not ok:
        raise ValidationHold(code)


def public_path(relative: str) -> Path:
    """Only explicit review/code/source paths, never a bank or candidate answer."""
    path = Path(relative)
    require(not path.is_absolute() and ".." not in path.parts and "\\" not in relative,
            "HOLD_INPUT_PATH_TRAVERSAL")
    require(not any(x.lower() in {".private", "private", "eval-bank", "candidate-answers", "answers"}
                    for x in path.parts), "HOLD_PRIVATE_OR_ANSWER_INPUT")
    allowed = ("scripts/", "backend/app/", "docs/system-design/")
    prefix = str(VISIBLE.relative_to(ROOT)) + "/"
    visible_allowed = tuple(prefix + p for p in (
        "author-research/", "structural-review-input/", "structural-table-review-input/",
        "independent-source-review/"))
    require(relative == "AGENTS.md" or relative.startswith(allowed + visible_allowed),
            "HOLD_INPUT_OUTSIDE_SOURCE_SCOPE")
    return safe(ROOT / path, ROOT)


def save(path: Path, value):
    return write_new(path, value, output=OUTPUT)


def exact_map(rows, key):
    require(isinstance(rows, list) and all(isinstance(r, dict) and key in r for r in rows),
            "HOLD_INVENTORY_SHAPE")
    result = {r[key]: r for r in rows}
    require(len(result) == len(rows), "HOLD_DUPLICATE_INVENTORY")
    return result


def nonblocking_limits(row):
    limits = row.get("uncertainties")
    require(isinstance(limits, list), "HOLD_UNCERTAINTY_INVENTORY")
    for item in limits:
        require(isinstance(item, dict) and item.get("blocks_this_research_proposition") is False
                and item.get("scope") in {"CASE_FACT_OR_ALTERNATE_ROUTE_NOT_DECIDED", "DISCLOSED_REVIEW_LIMIT"}
                and isinstance(item.get("reason"), str) and item["reason"].strip(),
                "HOLD_MATERIAL_SOURCE_UNCERTAINTY")
    return limits


def check_decision(row, original):
    require(row.get("proposition_id") in SELECTED and row.get("reviewer_id") == REVIEWER
            and row.get("decision") == "ELIGIBLE_RESEARCH_ONLY"
            and row.get("original_proposition_sha256") == digest(original)
            and row.get("proposed_proposition") == original["proposed_proposition"]
            and row.get("source_id") == original["source_id"]
            and row.get("jurisdiction") == JURISDICTIONS[original["jurisdiction"]]
            and row.get("as_of_date") == original["relevant_date"], "HOLD_PROPOSITION_REVIEW_BINDING")
    require(check_passes(row.get("checks"), core.REVIEW_CHECKS), "HOLD_ELEVEN_REVIEW_CHECKS")
    require(all(row.get(k) is False for k in ("professional_legal_sign_off", "qualified_legal_review",
                "legal_gold", "admitted", "full_current_law_eligible")), "HOLD_REVIEW_SCOPE_FLAGS")
    require(row.get("validity_window_authorized") is True and row.get("requested_point_in_time_only") is True
            and row["valid_from"] == row["as_of_date"] == row["valid_to"], "HOLD_REVIEW_DATE_WINDOW")
    date.fromisoformat(row["as_of_date"])
    require(row.get("raw_quote_verified") is True
            and digest(row["quote"].encode()) == row["quote_sha256"], "HOLD_QUOTE_HASH")
    nonblocking_limits(row)


def covered_chunks(parsed, raw_sha, ordinals):
    require(isinstance(ordinals, (list, tuple)) and ordinals
            and all(type(n) is int for n in ordinals) and len(set(ordinals)) == len(ordinals),
            "HOLD_REVIEW_ORDINALS")
    blocks = {b.ordinal: b for b in parsed.body_blocks}
    require(len(blocks) == len(parsed.body_blocks) and set(ordinals) <= set(blocks), "HOLD_MISSING_REVIEWED_BLOCK")
    chunks = [c for c in StructuralChunker().chunk_body(parsed, document_sha256=raw_sha)
              if set(c.block_ordinals) & set(ordinals)]
    outside = sorted({n for c in chunks for n in c.block_ordinals} - set(ordinals))
    require(not outside, "HOLD_UNREVIEWED_MERGED_CONTEXT:" + ",".join(map(str, outside)))
    require(chunks and set(ordinals) <= {n for c in chunks for n in c.block_ordinals},
            "HOLD_REVIEWED_CONTEXT_NOT_CHUNKED")
    return chunks


class SuccessorReviewGate:
    """File-backed Tesla context-02 verifier, with no model or network calls."""
    def __init__(self):
        self.pins, self.enrolled, self.loaded = {}, {}, {}
        raw = read(REVIEW / "REVIEW-ATTESTATION.json", REVIEW, ATTESTATION_SHA)
        self.attestation = load_json_strict(raw)
        self.loaded[REVIEW / "REVIEW-ATTESTATION.json"] = ATTESTATION_SHA
        a = self.attestation
        require(a.get("schema") == "ge.visible.independent.source.review.attestation.v1"
                and a.get("successor_schema") == "ge.visible.independent.source.successor.attestation.v1"
                and a.get("reviewer_id") == REVIEWER and a.get("reviewer_kind") == "AI_MODEL_REVIEWER"
                and set(a.get("eligible_proposition_ids", [])) == set(SELECTED)
                and a.get("material_source_holds") == [] and a.get("held_proposition_ids") == [],
                "HOLD_FRESH_ATTESTATION_IDENTITY")
        require(all(a.get(k) is False for k in ("professional_legal_sign_off", "qualified_legal_review",
                "legal_gold", "admitted", "full_current_law_eligible", "training_performed",
                "index_build_performed", "candidate_answers_generated", "live_use")), "HOLD_ATTESTATION_SCOPE")
        require(a.get("parser_mode") == {"include_legal_tables": True}
                and a.get("parser_recipe_sha256") == parser_binding(include_legal_tables=True), "HOLD_TABLE_PARSER_RECIPE")
        for group in ("input_files", "output_files", "code_bindings"):
            for binding in a[group]:
                path = public_path(binding["path"])
                expected = sha(binding["sha256"])
                require(path not in self.pins or self.pins[path] == expected, "HOLD_CONFLICTING_ATTESTATION_FILE")
                self.pins[path] = expected
        for binding in a["code_bindings"]:
            self.bound(binding["path"])
        for binding in a["output_files"]:
            self.bound(binding["path"])
        source_raw = self.bound(str((REVIEW / "SOURCE-REVIEW.jsonl").relative_to(ROOT)))
        require(digest(source_raw) == SOURCE_REVIEW_SHA, "HOLD_SOURCE_REVIEW_FILE")
        self.reviews = exact_map([load_json_strict(l) for l in source_raw.splitlines() if l.strip()], "proposition_id")
        require(set(self.reviews) == set(SELECTED), "HOLD_SEVEN_ONLY")
        proposals = self.document(VISIBLE / "author-research/SOURCE-PROPOSALS.json")
        self.propositions = exact_map(proposals["propositions"], "proposition_id")
        self.source_rows = exact_map(proposals["sources"], "source_id")
        self.identities = exact_map(self.document(REVIEW / "IDENTITY-VERIFICATION.json")["source_bindings"], "source_id")
        self.contexts = exact_map(self.document(REVIEW / "BOUND-CONTEXT.json")["sources"], "source_id")
        self.derivatives = exact_map(self.document(REVIEW / "PARENT-DERIVATIVE-VERIFICATION.json")["sources"], "source_id")
        self.check_evidence = exact_map(self.document(REVIEW / "CURRENTNESS-CHECK-EVIDENCE.json"), "evidence_id")
        self.check_operations = exact_map(self.document(REVIEW / "CAPTURE-OPERATIONS.json"), "evidence_id")
        self.parsed, self.raw, self.receipts = {}, {}, {}
        self._unchanged_rows()
        self._check_captures()
        for pid in SELECTED:
            check_decision(self.reviews[pid], self.propositions[pid])
        source_ids = {r["source_id"] for r in self.reviews.values()} | {
            c["source_id"] for r in self.reviews.values() for c in r["companion_source_context"]}
        require(source_ids == set(self.identities) == set(self.contexts) == set(self.derivatives)
                and len(source_ids) == 5, "HOLD_FIVE_SOURCE_CLOSURE")
        for sid in sorted(source_ids):
            self._source(sid)
        self.rows = []
        for pid in SELECTED:
            row = self.reviews[pid]
            try:
                for binding in [row, *row["companion_source_context"]]:
                    self._context(binding)
                block = next(b for b in self.parsed[row["source_id"]].body_blocks if b.ordinal == row["quote_block_ordinal"])
                require(row["quote"] in block.text and row["locator"] == block.source_anchor
                        and row["quote_block_ordinal"] in row["context_block_ordinals"], "HOLD_EXACT_QUOTE_LOCATOR")
                chunks = covered_chunks(self.parsed[row["source_id"]], row["raw_sha256"], row["context_block_ordinals"])
                require(any(row["quote"] in c.text for c in chunks), "HOLD_QUOTE_NOT_RETRIEVABLE")
                self.rows.append({"proposition_id": pid, "state": "SOURCE_CONTEXT_READY", "reason": None})
            except ValidationHold as exc:
                self.rows.append({"proposition_id": pid, "state": "HOLD", "reason": str(exc)})

    def bound(self, relative):
        path = public_path(relative)
        require(path in self.pins, "HOLD_UNATTESTED_INPUT:" + path.name)
        raw = read(path, ROOT, self.pins[path])
        self.loaded[path] = self.pins[path]
        return raw

    def document(self, path):
        return load_json_strict(self.bound(str(path.relative_to(ROOT))))

    def reference(self, binding):
        path = public_path(binding["path"])
        require(self.pins.get(path) == binding["sha256"], "HOLD_REFERENCE_OUTSIDE_ATTESTATION")
        raw = self.bound(binding["path"])
        require(len(raw) == binding["bytes"], "HOLD_REFERENCE_BYTE_LENGTH")
        return raw

    def replay(self):
        for path, expected in self.loaded.items():
            read(path, ROOT, expected)

    def _unchanged_rows(self):
        old = self.reference(self.attestation["original_review_reference"])
        lines = old.splitlines(keepends=True)
        original = exact_map([load_json_strict(l) for l in lines if l.strip()], "proposition_id")
        require(len(original) == 23, "HOLD_ORIGINAL_REVIEW_COUNT")
        for pid, row in self.reviews.items():
            binding = row["original_review_reference"]
            require(binding["sha256"] == digest(old) and binding["record_sha256"] == digest(original[pid])
                    and original[pid]["decision"] == binding["previous_decision"] == "HOLD"
                    and digest(lines[binding["line_number"] - 1]) == binding["line_bytes_sha256_including_newline"],
                    "HOLD_ORIGINAL_ROW_LINEAGE")
        outside = [r for pid, r in original.items() if pid not in SELECTED]
        require(len(outside) == 16 and sum(r["decision"] == "ELIGIBLE_RESEARCH_ONLY" for r in outside) == 5,
                "HOLD_ORIGINAL_FIVE_EXCLUSION")
        self.original_snapshot = {"original_review_sha256": digest(old),
            "outside_successor_row_sha256s": {r["proposition_id"]: digest(r) for r in outside},
            "original_five_builds_executed": False}

    def _check_captures(self):
        require(len(self.check_evidence) == len(self.check_operations) == 8
                and set(self.check_evidence) == set(self.check_operations), "HOLD_EIGHT_CHECK_CAPTURES")
        for key, item in self.check_evidence.items():
            raw = self.reference(item["raw_file"])
            receipt = load_json_strict(self.reference(item["capture_receipt"]))
            text = self.reference(item["text_derivative"]).decode()
            require(receipt == self.check_operations[key]
                    and receipt["status"] == "CAPTURED_CHECK_ONLY_NOT_INDEX_ELIGIBLE"
                    and receipt["http_status"] == 200 and receipt["raw_sha256"] == digest(raw)
                    and receipt["url"] == item["evidenceURL"]
                    and receipt["bytes"] == len(raw), "HOLD_CHECK_CAPTURE_PROVENANCE")
            for url in (receipt["url"], receipt["final_url"], *receipt["redirect_chain"]):
                split = urlsplit(url)
                require(split.scheme == "https" and split.hostname == "www.legislation.gov.uk"
                        and not split.username and not split.password, "HOLD_OFFICIAL_CHECK_URL")
            require(item["status_and_effects_text"] in text and item["editorial_status_not_guarantee"] is True,
                    "HOLD_CURRENTNESS_TEXT_BINDING")
            require(b"Open Government Licence" in raw and b"open-government-licence/version/3" in raw,
                    "HOLD_CAPTURE_LICENCE_EVIDENCE")

    def _source(self, sid):
        identity, meta, context, derivative = self.identities[sid], self.source_rows[sid], self.contexts[sid], self.derivatives[sid]
        raw = self.reference({k: identity[k] for k in ("path", "sha256", "bytes")})
        saved = load_json_strict(self.reference(identity["parsed_manifest"]))
        cap = load_json_strict(self.reference(identity["original_capture_receipt"]))
        parent_path = public_path(derivative["parent_path"])
        require(self.pins.get(parent_path) == derivative["parent_file_sha256"], "HOLD_PARENT_DERIVATIVE_PIN")
        parent = self.document(parent_path)
        parsed = parse_capture(raw, source_url=meta["url"], expected_raw_sha256=digest(raw), include_legal_tables=True)
        require(parsed.is_ready and not parsed.comments and not parsed.revisions, "HOLD_PARSER_READY_BODY_ONLY")
        material = canonical_json_bytes(asdict(parsed))
        require(material == canonical_json_bytes(saved["parsed"]) == canonical_json_bytes(parent["parsed"])
                and digest(material) == identity["parsed_sha256"] == saved["parsed_sha256"]
                == parent["parsed_sha256"] == context["parsed_sha256"] == derivative["parsed_sha256"],
                "HOLD_TABLE_REPARSE_CHANGED")
        require(digest(raw) == meta["raw_sha256"] == cap["raw_sha256"] == identity["sha256"]
                == context["raw_sha256"] and cap["url"] == meta["url"] == context["source_url"]
                and cap["source_id"] == sid and derivative["original_blocks_exactly_preserved"] is True
                and derivative["parsed_value_equal"] is True
                and parser_binding(include_legal_tables=True) == identity["parser_sha256"]
                == saved["parser_sha256"] == parent["parser_sha256"] == context["parser_sha256"],
                "HOLD_ORIGINAL_CAPTURE_IDENTITY")
        blocks = {b.ordinal: asdict(b) for b in parsed.body_blocks}
        bound = context["blocks"]
        require(len(bound) == len(context["context_block_ordinals"])
                and {b["block"]["ordinal"] for b in bound} == set(context["context_block_ordinals"]),
                "HOLD_BOUND_CONTEXT_INVENTORY")
        for item in bound:
            require(canonical_json_bytes(item["block"]) == canonical_json_bytes(blocks.get(item["block"]["ordinal"]))
                    and digest(item["block"]) == item["block_sha256"], "HOLD_BOUND_CONTEXT_BYTES")
        self.raw[sid], self.parsed[sid], self.receipts[sid] = raw, parsed, cap

    def _context(self, binding):
        sid = binding["source_id"]
        expected = self.contexts[sid]
        require(all(binding[k] == expected[k] for k in ("raw_sha256", "parsed_sha256", "parser_sha256"))
                and set(binding["context_block_ordinals"]) <= set(expected["context_block_ordinals"]),
                "HOLD_CONTEXT_NOT_IN_FRESH_REVIEW")
        covered_chunks(self.parsed[sid], binding["raw_sha256"], binding["context_block_ordinals"])

    def source_reviews(self, issue, scope):
        rows = [self.reviews[p] for p in SELECTED if p.startswith(issue + "-")]
        affected = digest([self.propositions[r["proposition_id"]] for r in rows])
        bindings = {}
        for row in rows:
            require(next(r for r in self.rows if r["proposition_id"] == row["proposition_id"])["state"] == "SOURCE_CONTEXT_READY",
                    "HOLD_CASE_SOURCE_CONTEXT")
            for item in [row, *row["companion_source_context"]]:
                bindings.setdefault(item["source_id"], []).append((row, item))
        result = []
        for sid, proofs in sorted(bindings.items()):
            ordinals = sorted({n for _, binding in proofs for n in binding["context_block_ordinals"]})
            chunks = covered_chunks(self.parsed[sid], digest(self.raw[sid]), ordinals)
            primary = next((r for r, _ in proofs if r["source_id"] == sid), None)
            block = next(b for b in self.parsed[sid].body_blocks
                         if b.ordinal == (primary["quote_block_ordinal"] if primary else ordinals[0]))
            quote = primary["quote"] if primary else block.text
            require(quote and block.source_anchor and any(quote in c.text for c in chunks), "HOLD_COMPANION_ANCHOR")
            rights = []
            for row, _ in proofs:
                rights_check = row["checks"]["rights"]
                evidence_file = rights_check.get("evidence_file")
                require(isinstance(evidence_file, str) and evidence_file.startswith("captures/"), "HOLD_RIGHTS_EXACT_CAPTURE")
                path = REVIEW / evidence_file
                raw = self.bound(str(path.relative_to(ROOT)))
                match = [e for e in self.check_evidence.values()
                         if e["raw_file"]["path"] == str(path.relative_to(ROOT))
                         and e["evidenceURL"] == rights_check["evidenceURL"]]
                require(len(match) == 1 and b"Open Government Licence" in raw, "HOLD_RIGHTS_CAPTURE_BINDING")
                rights.append({"review_sha256": digest(row), "check": rights_check, "raw_evidence_sha256": digest(raw)})
            raw_cap = self.receipts[sid]
            source = core.Capture(scope, "visible-original-author-research-context", self.raw[sid], self.parsed[sid],
                parser_binding(include_legal_tables=True), self.source_rows[sid]["url"], raw_cap["final_url"],
                tuple(raw_cap.get("redirect_chain") or []), raw_cap["captured_at"], sid,
                "official-legislation-research-only", rows[0]["jurisdiction"], digest(rights))
            review = {"reviewer_id": REVIEWER, "capture_sha256": digest(source.manifest()),
                "source_sha256": digest(source.raw), "parsed_sha256": digest(asdict(source.parsed)),
                "scope": asdict(scope), "issue_id": "successor-" + issue, "affected_claim_sha256": affected,
                "jurisdiction": source.jurisdiction, "as_of_date": rows[0]["as_of_date"],
                "valid_from": rows[0]["valid_from"], "valid_to": rows[0]["valid_to"],
                "decision": "ELIGIBLE_RESEARCH_ONLY", "checks": sorted(core.REVIEW_CHECKS), "uncertainties": [],
                "quote": quote, "locator": block.source_anchor, "quote_block_ordinal": block.ordinal,
                "context_block_ordinals": ordinals,
                "actual_review_attestation_sha256": ATTESTATION_SHA, "actual_review_file_sha256": SOURCE_REVIEW_SHA,
                "actual_review_rows": [{"proposition_id": r["proposition_id"], "sha256": digest(r),
                    "context_binding_sha256": digest(binding), "nonblocking_limits_sha256": digest(nonblocking_limits(r))}
                    for r, binding in proofs],
                "ordinal_review_bindings": {str(n): [digest(r) for r, binding in proofs if n in binding["context_block_ordinals"]]
                                             for n in ordinals},
                "rights_evidence": rights, "check_only_capture_evidence_sha256": digest([
                    e for e in self.check_evidence.values() if e["issue_id"] == issue]),
                "uncertainty_semantics": "ZERO_MATERIAL_SOURCE_HOLDS_NONBLOCKING_LIMITS_RETAINED_VERBATIM_IN_SIDECAR",
                "admitted": False, "legal_gold": False, "qualified_legal_review": False,
                "full_current_law_eligible": False}
            self.enrolled[digest(review)] = canonical_json_bytes(review)
            result.append((source, review))
        return result

    def verify_review(self, reviewer, receipt):
        try:
            self.replay()
            require(reviewer == REVIEWER and self.enrolled.get(digest(receipt)) == canonical_json_bytes(receipt),
                    "HOLD_UNENROLLED_REVIEW_TRANSLATION")
            for binding in receipt["actual_review_rows"]:
                row = self.reviews[binding["proposition_id"]]
                check_decision(row, self.propositions[row["proposition_id"]])
                require(digest(row) == binding["sha256"], "HOLD_REVIEW_ROW_CHANGED")
            return True
        except (ValueError, KeyError, OSError):
            return False


def runtime_pins(registry, identity):
    paths = (Path(__file__), ROOT / "backend/app/research/ge_auto_index.py",
             ROOT / "scripts/ge_auto_visible_index_validation.py", ROOT / "scripts/ge_auto_research_runtime.py",
             ROOT / "backend/app/ingestion/chunking.py", ROOT / "backend/app/retrieval/lancedb.py",
             ROOT / "backend/app/retrieval/qwen.py")
    return {"code": {str(p.relative_to(ROOT)): digest(read(p, ROOT)) for p in paths},
            "schema_selection_sha256": registry.manifest_sha256, "model_identity": identity,
            "parser_sha256": parser_binding(include_legal_tables=True)}


def toolchain(identity):
    model_spec = load_json_strict(read(ROOT / "scripts/model/manifests/qwen3-retrieval-models.json", ROOT))
    reranker = next(m for m in model_spec["models"] if m["role"] == "reranker")
    return {"parser_sha256": parser_binding(include_legal_tables=True), "ocr_sha256": None,
        "chunker_sha256": digest(read(ROOT / "backend/app/ingestion/chunking.py", ROOT)),
        "tokenizer_sha256": digest(read(ROOT / identity["directory"] / "tokenizer.json", ROOT)),
        "embedding_model_sha256": identity["file_manifest_sha256"],
        "lexical_config_sha256": digest({"engine": "lancedb-native-fts", "use_tantivy": False}),
        "vector_schema_sha256": digest({"field": "vector", "dtype": "float32", "dimensions": 1024, "metric": "cosine"}),
        "reranker_model_sha256": reranker["file_manifest_sha256"]}


def empty_baseline(policy, tools, stamp):
    return seal_contract({"schema": "legalbot.research-empty-baseline.v1",
        "generation_id": "visible-successor-common-empty", "source_manifest_sha256": digest([]),
        "qualification_policy_sha256": policy.sha256, "sources": [], "toolchain": tools,
        "counts": {"source_versions": 0, "canonical_objects": 0, "chunks": 0, "lexical_rows": 0,
                   "vector_rows": 0, "embedding_dimensions": 1024}, "file_manifest_sha256": digest([]),
        "closure_status": "validated", "attestations": [], "created_at": stamp, "sealed_at": stamp,
        "non_live": True, "production_admission": False, "training": False})


def contracts_for(issue, scope, gate, policy, baseline, registry, stamp):
    rows = [gate.reviews[p] for p in SELECTED if p.startswith(issue + "-")]
    request = {"kind": "VISIBLE_SUCCESSOR_INDEX_COMPONENT_ONLY", "case_id": scope.case_id,
        "proposition_sha256s": [digest(gate.propositions[r["proposition_id"]]) for r in rows],
        "review_sha256s": [digest(r) for r in rows], "query": "\n".join(r["quote"] for r in rows),
        "candidate_answer_generation": False, "matter_ingestion": False}
    conv = seal_contract({"schema": "legalbot.conversation-snapshot.v1", "snapshot_id": "snapshot-" + issue,
        "conversation_id": "conversation-successor-" + issue, "owner_scope_sha256": digest(asdict(scope)),
        "revision": 0, "created_at": stamp, "messages": [], "truncated": False,
        "omitted_message_count": 0, "omitted_before_ordinal": None, "truncation_reason": "none", "estimated_tokens": 0})
    facts = seal_contract({"schema": "legalbot.matter-fact-snapshot.v2", "snapshot_id": "facts-successor-" + issue,
        "conversation_id": conv["conversation_id"], "owner_scope_sha256": conv["owner_scope_sha256"],
        "conversation_revision": 0, "created_at": stamp, "facts": []})
    plan = build_query_plan(request_id="request-successor-" + issue, request_sha256=digest(request),
        original_question_sha256=digest(request["query"].encode()), task_type="general", answer_route="direct",
        requires_knowledge=True, requires_matter=False, response_disposition="LIMITED",
        jurisdiction=rows[0]["jurisdiction"], jurisdiction_status="explicit",
        requested_as_of_date=date.fromisoformat(rows[0]["as_of_date"]), as_of_date_status="explicit",
        issue_ids=["successor-" + issue], missing_facts=[], query_variants_ref="queries-successor-" + issue,
        query_variants_sha256=digest([r["quote"] for r in rows]), candidate_id=ACTOR,
        policy_sha256=policy.sha256, config_sha256=digest({"baseline": baseline["content_sha256"],
            "component_only": True, "review_attestation": ATTESTATION_SHA}), conversation_snapshot=conv,
        fact_snapshot=facts, rewrite={"status": "not_needed", "encrypted_query_ref": None,
            "query_sha256": None, "reason_code": "visible_source_component"},
        risk_flags=["source_component_only", "no_candidate_answer", "matter_not_ingested"],
        request_observed_at=datetime.fromisoformat(stamp), frozen_at=datetime.fromisoformat(stamp), registry=registry).value
    return {"request": request, "query_plan": plan, "facts": facts, "conversation": conv, "baseline": baseline}


def bind_lineage(contracts, registry):
    return core.Lineage.bind(registry=registry, query_plan=contracts["query_plan"], fact_snapshot=contracts["facts"],
        conversation_snapshot=contracts["conversation"], knowledge_generation=contracts["baseline"],
        expected_request_sha256=digest(contracts["request"]),
        expected_knowledge_generation_sha256=contracts["baseline"]["content_sha256"])


def capability(policy, scope, action, binding):
    return policy.authorize(scope=scope, actor=ACTOR, role="candidate", action=action, binding_sha256=binding)


def prepare():
    gate = SuccessorReviewGate()
    from scripts.ge_auto_research_runtime import verified_model_identity
    identity = verified_model_identity()  # Only exact local file verification, no model loading.
    registry = ContractSchemaRegistry.from_project_root(ROOT)
    runtime = runtime_pins(registry, identity)
    consumed = {str(p.relative_to(ROOT)): h for p, h in sorted(gate.loaded.items())}
    fingerprint = digest({"runtime": runtime, "consumed_inputs": consumed, "selected": list(SELECTED)})
    directory = safe(OUTPUT / "preparations" / fingerprint, OUTPUT)
    report_path = directory / "PREPARATION.json"
    if report_path.exists():
        report = load_json_strict(read(report_path, OUTPUT))
        require(report["fingerprint"] == fingerprint and report["runtime"] == runtime, "HOLD_EXISTING_PREPARATION_CHANGED")
        return report_path, digest(read(report_path, OUTPUT)), report
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    owner = read(OWNER, ROOT, OWNER_SHA256)
    scopes = [core.Scope(str(directory / "stores" / issue), "candidate_case_local",
                        "VISIBLE_SUCCESSOR_COMPONENT", "visible-successor-" + issue) for issue in ("ENG", "NIR")]
    policy = core.ResearchPolicy(workspace=directory, owner_instruction=owner,
        expected_owner_instruction_sha256=OWNER_SHA256, scopes=scopes,
        model=core.ModelPin.from_runtime_identity(identity), reviewers=[REVIEWER], verify_review=gate.verify_review)
    stamp = datetime.now(UTC).isoformat()
    baseline = empty_baseline(policy, toolchain(identity), stamp)
    registry.validate_new(baseline)
    save(directory / "EMPTY-BASELINE.json", baseline)
    save(directory / "INPUT-PINS.json", consumed)
    save(directory / "ORIGINAL-UNCHANGED-ROWS.json", gate.original_snapshot)
    save(directory / "SOURCE-REVIEW.jsonl", read(REVIEW / "SOURCE-REVIEW.jsonl", REVIEW, SOURCE_REVIEW_SHA))
    save(directory / "REVIEW-ATTESTATION.json", read(REVIEW / "REVIEW-ATTESTATION.json", REVIEW, ATTESTATION_SHA))
    save(directory / "NONBLOCKING-LIMITS.json", {pid: nonblocking_limits(gate.reviews[pid]) for pid in SELECTED})
    save(directory / "CURRENTNESS-CHECK-EVIDENCE.json", list(gate.check_evidence.values()))
    for item in gate.check_evidence.values():
        for field in ("raw_file", "capture_receipt", "text_derivative"):
            binding = item[field]
            save(directory / "check-only-captures" / Path(binding["path"]).name, gate.reference(binding))
    outcomes, groups = [], []
    for issue, scope in zip(("ENG", "NIR"), scopes, strict=True):
        selected = [p for p in SELECTED if p.startswith(issue + "-")]
        try:
            sources = gate.source_reviews(issue, scope)
            contracts = contracts_for(issue, scope, gate, policy, baseline, registry, stamp)
            lineage = bind_lineage(contracts, registry)
            cap = capability(policy, scope, "jobs", digest(asdict(lineage)))
            index = core.AutoResearchIndex(policy=policy, capability=cap, scope=scope, lineage=lineage)
            affected = sources[0][1]["affected_claim_sha256"]
            gap = index.enqueue(cap, issue_id="successor-" + issue, gap_class="retrieval_miss",
                affected_claim_sha256=affected, failure_fingerprint=digest({"review": SOURCE_REVIEW_SHA, "issue": issue}))
            empty_lookup = {"baseline_sha256": baseline["content_sha256"], "sources": [], "rows": [],
                            "scope": asdict(scope), "method": "SELECTED_EMPTY_BASELINE_NO_EXTERNAL_STORE"}
            save(directory / issue / "EMPTY-LOOKUP.json", empty_lookup)
            attempt = index.begin_attempt(cap, gap, inputs_sha256=fingerprint, existing_retrieval_sha256=digest(empty_lookup))
            require(attempt is not None, "HOLD_DUPLICATE_PREPARATION_ATTEMPT")
            for capture, review in sources:
                op = index.reserve(cap, attempt, kind="capture", input_sha256=digest(capture.manifest()))
                require(op is not None, "HOLD_CAPTURE_REGISTRATION_BUDGET")
                index.capture(cap, op, capture)
                save(directory / issue / "reviews" / (capture.source_identity + ".json"), review)
            prepared = index.prepare(cap, gap=gap, attempt=attempt, sources=sources)
            build = load_json_strict(prepared.payload)
            save(directory / issue / "CONTRACTS.json", contracts)
            save(directory / issue / "PREPARED-BUILD.json", prepared.payload)
            group = {"issue": issue, "scope": asdict(scope), "proposition_ids": selected,
                "contracts_sha256": digest(contracts), "build_sha256": prepared.sha256,
                "row_count": len(build["rows"]), "source_count": len(sources), "gap": gap, "attempt": attempt}
            groups.append(group)
            outcomes.extend({"proposition_id": pid, "state": "PREPARED_AWAITING_PARENT_MODEL_WINDOW",
                             "issue": issue, "required_rows": len(build["rows"])} for pid in selected)
        except (ValueError, KeyError, OSError) as exc:
            reason = str(exc) if isinstance(exc, ValidationHold) else "HOLD_PREPARATION:" + type(exc).__name__
            outcomes.extend({"proposition_id": pid, "state": "HOLD", "reason": reason} for pid in selected)
    gate.replay()
    report = {"schema": VERSION, "fingerprint": fingerprint, "created_at": stamp, "runtime": runtime,
        "owner_instruction_sha256": OWNER_SHA256, "review_attestation_sha256": ATTESTATION_SHA,
        "source_review_sha256": SOURCE_REVIEW_SHA, "input_pins_sha256": digest(consumed),
        "policy_sha256": policy.sha256, "baseline_contract_sha256": baseline["content_sha256"],
        "scopes": [asdict(s) for s in scopes], "groups": groups, "outcomes": outcomes,
        "expected_document_embedding_calls": sum(g["row_count"] for g in groups),
        "new_network_calls": 0, "model_loaded": False, "actual_inference_calls": 0,
        "original_five_builds_executed": False, "full_case_passes_claimed": 0, "gaps_closed": 0,
        "parent_model_window": "REQUIRED_BEFORE_ACQUIRE", "candidate_answers_generated": False,
        "non_live": True, "production_admission": False, "training": False}
    report_sha = save(report_path, report)
    save(directory / "MODEL-TIMING-REQUEST.json", {"preparation_sha256": report_sha,
        "prepared_rows": report["expected_document_embedding_calls"], "prepared_groups": len(groups),
        "request": "Parent must coordinate Beauvoir release and confirm a model window before execute acquires the shared embedding lock.",
        "parent_confirmation_received": False, "actual_inference_calls": 0})
    return report_path, report_sha, report


def verify_retrieval(index, build, result, query, lineage):
    sha256 = result["retrieval_sha256"]
    saved = index._get(sha256, "retrieval")
    require(digest(saved) == sha256 == digest({k: v for k, v in result.items() if k != "retrieval_sha256"})
            and saved["build_sha256"] == digest(build)
            and digest(saved["lineage"]) == digest(asdict(lineage))
            and saved["scope"] == asdict(index.scope) and saved["query_sha256"] == digest(query.encode()),
            "HOLD_PERSISTED_RETRIEVAL_BINDING")
    require(saved["lexical_ids"] and saved["vector_ids"] and saved["selected_ids"], "HOLD_LEXICAL_OR_VECTOR_MISS")
    rows = {r["id"]: r for r in build["rows"]}
    require(set(saved["selected_ids"]) <= rows.keys(), "HOLD_FOREIGN_RETRIEVAL_HIT")
    groups = {rows[key]["group"] for key in saved["selected_ids"]}
    require(len({r["id"] for r in saved["evidence"]}) == len(saved["evidence"]), "HOLD_DUPLICATE_RETRIEVAL_ROW")
    for row in saved["evidence"]:
        require(row == rows.get(row["id"]) and row["group"] in groups, "HOLD_RETRIEVED_CONTEXT_CHANGED")
    return saved


def configure_environment(directory):
    for variable, name in (("TMPDIR", "tmp"), ("HF_HOME", "huggingface-cache"),
                           ("XDG_CACHE_HOME", "cache"), ("TORCH_HOME", "torch-cache")):
        path = safe(directory / "runtime" / name, OUTPUT)
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.environ[variable] = str(path)
    os.environ.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", TOKENIZERS_PARALLELISM="false",
                      PYTHONDONTWRITEBYTECODE="1")


def execute(preparation: Path, expected_sha256: str, parent_ready_reason: str):
    require(isinstance(parent_ready_reason, str) and parent_ready_reason.strip(), "HOLD_PARENT_MODEL_WINDOW_REQUIRED")
    safe(preparation, OUTPUT)
    report = load_json_strict(read(preparation, OUTPUT, sha(expected_sha256)))
    directory = preparation.parent
    require(preparation.name == "PREPARATION.json" and directory == OUTPUT / "preparations" / report["fingerprint"],
            "HOLD_EXACT_PREPARATION_ROOT")
    gate = SuccessorReviewGate()
    from scripts.ge_auto_research_runtime import PinnedEmbeddingSession, verified_model_identity
    registry = ContractSchemaRegistry.from_project_root(ROOT)
    identity = verified_model_identity()
    require(runtime_pins(registry, identity) == report["runtime"], "HOLD_PREPARATION_RUNTIME_CHANGED")
    consumed = load_json_strict(read(directory / "INPUT-PINS.json", OUTPUT, report["input_pins_sha256"]))
    for path, expected in consumed.items():
        read(public_path(path), ROOT, expected)
    scopes = [core.Scope(**value) for value in report["scopes"]]
    require(all(Path(s.root).parent == directory / "stores" and s.lane == "candidate_case_local" for s in scopes),
            "HOLD_EXECUTION_SCOPE")
    policy = core.ResearchPolicy(workspace=directory, owner_instruction=read(OWNER, ROOT, OWNER_SHA256),
        expected_owner_instruction_sha256=OWNER_SHA256, scopes=scopes,
        model=core.ModelPin.from_runtime_identity(identity), reviewers=[REVIEWER], verify_review=gate.verify_review)
    require(policy.sha256 == report["policy_sha256"], "HOLD_POLICY_CHANGED")
    jobs = []
    for group in report["groups"]:
        scope = next(s for s in scopes if asdict(s) == group["scope"])
        sources = gate.source_reviews(group["issue"], scope)
        contracts = load_json_strict(read(directory / group["issue"] / "CONTRACTS.json", OUTPUT, group["contracts_sha256"]))
        lineage = bind_lineage(contracts, registry)
        index = core.AutoResearchIndex(policy=policy, scope=scope, lineage=lineage,
            capability=capability(policy, scope, "jobs", digest(asdict(lineage))))
        prepared = core.PreparedBuild(read(directory / group["issue"] / "PREPARED-BUILD.json", OUTPUT, group["build_sha256"]))
        build = load_json_strict(prepared.payload)
        require(build["reviews"] == [r for _, r in sources] and digest(build["lineage"]) == digest(asdict(lineage))
                and prepared.sha256 == group["build_sha256"], "HOLD_PREPARED_REVIEW_CHANGED")
        jobs.append((group, index, prepared, build, lineage))
    completed = directory / "EXECUTION-SUMMARY.json"
    if completed.exists():
        summary = load_json_strict(read(completed, OUTPUT))
        require(summary["preparation_sha256"] == expected_sha256, "HOLD_COMPLETED_LINEAGE_CHANGED")
        for group, index, prepared, _, _ in jobs:
            index._read_generation(prepared.sha256)
        return summary
    require(not (directory / "EXECUTION-START.json").exists(), "HOLD_INTERRUPTED_EXECUTION_NO_BLIND_RETRY")
    require(jobs, "HOLD_NO_PREPARED_GROUPS")
    configure_environment(directory)
    save(directory / "EXECUTION-START.json", {"preparation_sha256": expected_sha256,
        "parent_ready_reason": parent_ready_reason, "confirmed_at": datetime.now(UTC).isoformat(),
        "shared_model_lock": str(ROOT / "data/research/ge-auto-research/embedding.lock"),
        "authorization_kind": "PARENT_COORDINATED_MODEL_WINDOW_NOT_A_SIGNATURE"})

    class RecordingSession(PinnedEmbeddingSession):
        def record(self):
            save(directory / "model-calls" / f"{len(self.calls):06d}.json", self.calls[-1])
            if len(self.calls) % 25 == 0:
                print(json.dumps({"event": "actual_embedding_calls", "count": len(self.calls)}), flush=True)

        def embed_documents(self, texts):
            vectors = []
            for text in texts:
                vectors.extend(super().embed_documents([text]))
                self.record()
            return tuple(vectors)

        def embed_query(self, text):
            vector = super().embed_query(text)
            self.record()
            return vector

    outcomes = [r for r in report["outcomes"] if r["state"] == "HOLD"]
    groups_done = []
    try:
        with RecordingSession() as provider:
            require(provider.identity == identity and provider.pin == policy.model and provider.verify_binding(),
                    "HOLD_ACTUAL_MODEL_PIN")
            for group, index, prepared, build, lineage in jobs:
                issue, scope = group["issue"], index.scope
                print(json.dumps({"event": "build_started", "issue": issue, "rows": len(build["rows"])}), flush=True)
                generation = index.build(capability(policy, scope, "build", prepared.sha256), prepared, provider=provider)
                generation_receipt, _ = index._read_generation(prepared.sha256)
                require(generation_receipt["generation_sha256"] == generation, "HOLD_GENERATION_READBACK")
                save(directory / issue / "GENERATION.json", generation_receipt)
                result_map, found = {}, {}
                queries = [(pid, gate.reviews[pid]["quote"]) for pid in group["proposition_ids"]]
                queries += [("companion-" + str(n), r["quote"]) for n, r in enumerate(build["reviews"], 1)
                            if r["quote"] not in {q for _, q in queries}]
                for label, query in queries:
                    result = index.retrieve(capability(policy, scope, "retrieve", generation),
                        build_sha256=prepared.sha256, generation_sha256=generation,
                        query=query, lineage=lineage, provider=provider, limit=8)
                    saved = verify_retrieval(index, build, result, query, lineage)
                    require(saved["generation_sha256"] == generation, "HOLD_RETRIEVAL_GENERATION")
                    save(directory / issue / "retrievals" / (label + ".json"), result)
                    result_map[label] = {"retrieval_sha256": result["retrieval_sha256"], "file_sha256": digest(result)}
                    found.update({r["id"]: r for r in saved["evidence"]})
                needed = {r["id"] for r in build["rows"]}
                require(set(found) == needed, "HOLD_REQUIRED_COMPANION_CONTEXT_NOT_RETRIEVED")
                evidence = [found[key] for key in sorted(found)]
                evidence_sha = save(directory / issue / "COMPLETE-RETRIEVED-CONTEXT.json", evidence)
                for pid in group["proposition_ids"]:
                    row = gate.reviews[pid]
                    require(any(row["quote"] in e["text"] and e["capture_sha256"] == next(
                        r["capture_sha256"] for r in build["reviews"] if r["source_sha256"] == row["raw_sha256"])
                        for e in evidence), "HOLD_REVIEWED_QUOTE_NOT_RETRIEVED")
                    packet = {"proposition_id": pid, "original_proposition_sha256": digest(gate.propositions[pid]),
                        "actual_source_review": row, "source_review_attestation_sha256": ATTESTATION_SHA,
                        "build_sha256": prepared.sha256, "generation_sha256": generation,
                        "lineage": asdict(lineage), "retrievals": result_map,
                        "complete_context": {"path": str((directory / issue / "COMPLETE-RETRIEVED-CONTEXT.json").relative_to(OUTPUT)),
                                             "sha256": evidence_sha, "rows": len(evidence)},
                        "nonblocking_limits": nonblocking_limits(row),
                        "check_only_evidence": [e for e in gate.check_evidence.values() if e["issue_id"] == issue],
                        "claim_review": "PENDING_PARENT_INDEPENDENT_CONSUMER_REVIEW", "gap_closed": False,
                        "candidate_answer_generated": False, "full_case_pass": False, "reranker": "NOT_RUN"}
                    packet_sha = save(directory / issue / (pid + "-EVIDENCE.json"), packet)
                    outcomes.append({"proposition_id": pid, "state": "RETRIEVED_PENDING_CLAIM_REVIEW",
                        "build_sha256": prepared.sha256, "generation_sha256": generation,
                        "packet_sha256": packet_sha, "required_context_rows": len(evidence)})
                before = len(provider.calls)
                require(index.build(capability(policy, scope, "build", prepared.sha256), prepared, provider=provider) == generation
                        and len(provider.calls) == before, "HOLD_DUPLICATE_BUILD_INFERRED")
                groups_done.append({"issue": issue, "build_sha256": prepared.sha256, "generation_sha256": generation,
                                    "rows": len(evidence), "duplicate_build_model_calls": 0})
                save(directory / issue / "GROUP-EXECUTION.json", groups_done[-1])
                save(directory / issue / "MODEL-RECEIPT.json", provider.receipt())
                print(json.dumps({"event": "group_retrieved", "issue": issue, "rows": len(evidence)}), flush=True)
            model_receipt = provider.receipt()
        require(provider.provider is None and model_receipt["actual_inference_calls"] > 0
                and model_receipt["synthetic_vectors"] is False, "HOLD_REAL_INFERENCE_RECEIPT")
        model_sha = save(directory / "ACTUAL-MODEL-RECEIPT.json", model_receipt)
        gate.replay()
        require(all(not (Path(scope.root) / name).exists() for scope in scopes for name in ("ACTIVE.json", "PREVIOUS.json")),
                "HOLD_ACTIVE_POINTER_CREATED")
        summary = {"schema": VERSION, "preparation_sha256": expected_sha256,
            "state": "VISIBLE_SUCCESSOR_COMPONENT_EXECUTED_CLAIM_REVIEW_PENDING", "completed_at": datetime.now(UTC).isoformat(),
            "outcomes": outcomes, "outcome_counts": dict(Counter(r["state"] for r in outcomes)),
            "groups": groups_done, "actual_model_receipt_sha256": model_sha,
            "actual_inference_calls": model_receipt["actual_inference_calls"],
            "document_calls": sum(c["kind"] == "document" for c in model_receipt["calls"]),
            "query_calls": sum(c["kind"] == "query" for c in model_receipt["calls"]),
            "sqlite_and_lance_readback": "ACTUAL_EXECUTED", "new_network_calls": 0,
            "original_five_builds_executed": False, "original_rows_unchanged": True,
            "full_case_passes_claimed": 0, "gaps_closed": 0, "candidate_answers_generated": False,
            "reranker": "NOT_RUN", "professional_legal_sign_off": False, "non_live": True,
            "production_admission": False, "training": False}
        save(completed, summary)
        return summary
    except Exception as exc:
        save(directory / "EXECUTION-HOLD.json", {"state": "HOLD", "error_type": type(exc).__name__,
            "reason": str(exc), "completed_groups": groups_done, "completed_outcomes": outcomes,
            "all_artifacts_preserved": True, "automatic_retry": False, "full_case_passes_claimed": 0})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("prepare")
    run = sub.add_parser("execute")
    run.add_argument("--preparation", type=Path, required=True)
    run.add_argument("--sha256", required=True)
    run.add_argument("--parent-ready-reason", required=True)
    args = parser.parse_args()
    if args.command == "prepare":
        path, key, report = prepare()
        print(json.dumps({"preparation": str(path), "sha256": key, "outcomes": report["outcomes"],
                          "expected_document_embedding_calls": report["expected_document_embedding_calls"]}), flush=True)
    else:
        print(json.dumps(execute(args.preparation, args.sha256, args.parent_ready_reason)), flush=True)


if __name__ == "__main__":
    main()
