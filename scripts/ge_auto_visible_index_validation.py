"""Visible index component validation; never candidate answers or a global PASS.

Execute only after the parent reviews the independent attestation and explicitly
supplies --execute, --ready-reason, and its exact file hashes. Missing evidence
returns HOLD before model loading. No network transport is called. The original
author's research counters are imported as history, never counted as new queries.

The selected knowledge-generation schema requires a source. Accordingly, an
explicit empty shared baseline is kept separately; each full selected generation
contract describes an independently eligible capture manifest, with zero indexed
rows before the build. This is visible plumbing validation with proposition-led
queries, not a blind candidate workflow. Matter ingestion/turns remain parent work.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, replace
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from backend.app.contracts import ContractSchemaRegistry, build_query_plan, seal_contract
from backend.app.contracts.schema_registry import canonical_json_bytes, load_json_strict
from backend.app.research.ge_auto_index import (
    REVIEW_CHECKS,
    AutoResearchIndex,
    Capture,
    Lineage,
    ModelPin,
    ResearchPolicy,
    Scope,
    digest,
)

from scripts.ge_auto_research_intake import parse_capture, parser_binding

ROOT = Path(__file__).resolve().parents[1]
VISIBLE = ROOT / "data/evaluations/general-enquiries/ge-auto-research-visible-20260905"
OUTPUT = VISIBLE / "index-validation"
REVIEWER_TASK = "01a0706d-9091-7671-ad0b-3830a8311193"
REVIEWER = "codex-fresh-independent-source-review-visible-20260905-context-01"
OWNER_SHA256 = "7b05945138c289e45f30f56819e18cc3b4ef53b5c41835546b095fdabf335bd4"
JURISDICTIONS = {
    "GB-ENG": "England",
    "GB-WLS": "Wales",
    "GB-SCT": "Scotland",
    "GB-NIR": "Northern Ireland",
    "US-FED": "US federal",
    "US-CA": "California",
    "US-NY": "New York",
    "US-TX": "Texas",
}
ACTOR = "visible-index-component-runner"
RESEARCHER = "visible-author-research-context"


class ValidationHold(ValueError):
    """A precise non-approving stop, including missing parent readiness."""


def safe(path: Path, root: Path) -> Path:
    if not path.is_absolute() or ".." in path.parts or not path.is_relative_to(root):
        raise ValidationHold("HOLD_CROSS_ROOT")
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValidationHold("HOLD_SYMLINK")
    if path.is_file() and path.stat().st_nlink != 1:
        raise ValidationHold("HOLD_HARDLINK")
    return path


def sha(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValidationHold("HOLD_EXACT_DIGEST_REQUIRED")
    return value


def read(path: Path, root: Path, expected: str | None = None) -> bytes:
    try:
        raw = safe(path, root).read_bytes()
    except FileNotFoundError as exc:
        raise ValidationHold(f"HOLD_MISSING:{path.name}") from exc
    if expected is not None and digest(raw) != sha(expected):
        raise ValidationHold(f"HOLD_FILE_DIGEST:{path.name}")
    return raw


def obj(path: Path, root: Path, expected: str | None = None) -> Any:
    return load_json_strict(read(path, root, expected))


def write_new(path: Path, value: Any, *, output: Path = OUTPUT) -> str:
    raw = value if isinstance(value, bytes) else canonical_json_bytes(value)
    safe(path, output)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        if read(path, output) != raw:
            raise ValidationHold(f"HOLD_IMMUTABLE_OUTPUT:{path.name}")
        return digest(raw)
    with path.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    return digest(raw)


def records(raw: bytes, identity: str) -> dict[str, dict[str, Any]]:
    rows = [load_json_strict(line) for line in raw.splitlines() if line.strip()]
    if any(not isinstance(row, dict) or not row.get(identity) for row in rows):
        raise ValidationHold("HOLD_REVIEW_RECORD_ID")
    result = {row[identity]: row for row in rows}
    if len(result) != len(rows):
        raise ValidationHold("HOLD_DUPLICATE_REVIEW_RECORD")
    return result


def check_passes(checks: Any, required: set[str] | frozenset[str]) -> bool:
    if not isinstance(checks, dict) or set(checks) != required:
        return False
    return all(
        isinstance(value, dict)
        and value.get("status") == "PASS"
        and isinstance(value.get("reason"), str)
        and value["reason"].strip()
        and value.get("evidenceURL")
        for value in checks.values()
    )


def attestation_files(attestation: Mapping[str, Any]) -> dict[str, str]:
    """Normalize explicit file bindings, never search arbitrary prose for hashes.

    Accept the review's path/sha256 lists or path->sha256 maps under files/inputs/
    outputs. Common companion digest fields have fixed filenames. Unknown formats
    hold until the parent adapts the wrapper; no self-issued replacement receipt.
    """
    result: dict[str, str] = {}
    for key in ("files", "inputs", "outputs", "input_files", "output_files"):
        values = attestation.get(key, [])
        if isinstance(values, dict):
            values = [
                {"path": k, "sha256": v} if isinstance(v, str) else {"path": k, **v}
                for k, v in values.items()
            ]
        if not isinstance(values, list):
            raise ValidationHold("HOLD_ATTESTATION_FILE_FORMAT")
        for row in values:
            if not isinstance(row, dict) or not isinstance(row.get("path"), str):
                raise ValidationHold("HOLD_ATTESTATION_FILE_FORMAT")
            name = row["path"]
            key_sha = sha(row["sha256"])
            if name in result and result[name] != key_sha:
                raise ValidationHold("HOLD_CONFLICTING_ATTESTATION_BINDINGS")
            result[name] = key_sha
    for key, name in (
        ("source_review_sha256", "SOURCE-REVIEW.jsonl"),
        ("input_hashes_sha256", "INPUT-HASHES.json"),
        ("identity_verification_sha256", "IDENTITY-VERIFICATION.json"),
        ("claim_review_sha256", "CLAIM-REVIEW.jsonl"),
    ):
        if key in attestation:
            result[name] = sha(attestation[key])
    return result


def require_attested(files: Mapping[str, str], path: Path, visible: Path, expected: str) -> None:
    names = (path.name, str(path.relative_to(visible)), str(path))
    found = [files[n] for n in names if n in files]
    if not found or any(value != expected for value in found):
        raise ValidationHold(f"HOLD_UNATTESTED_FILE:{path.name}")


@dataclass(frozen=True)
class ReviewPins:
    attestation_sha256: str
    source_review_sha256: str
    reviewer_id: str = REVIEWER
    parser_revalidation_sha256: str | None = None


class SourceReviewGate:
    """Exact file-backed independent review and deterministic derived bindings."""

    def __init__(self, visible: Path, pins: ReviewPins) -> None:
        self.visible, self.pins = visible, pins
        self.directory = visible / "independent-source-review"
        attestation_path = self.directory / "REVIEW-ATTESTATION.json"
        self.attestation = obj(attestation_path, visible, pins.attestation_sha256)
        if (
            self.attestation.get("schema") != "ge.visible.independent.source.review.attestation.v1"
            or self.attestation.get("reviewer_id") != pins.reviewer_id
        ) or any(
            self.attestation.get(key) is not False
            for key in ("professional_legal_sign_off", "legal_gold", "admitted")
        ):
            raise ValidationHold("HOLD_INDEPENDENT_ATTESTATION_IDENTITY_OR_SCOPE")
        files = attestation_files(self.attestation)
        self.review_raw = read(
            self.directory / "SOURCE-REVIEW.jsonl", visible, pins.source_review_sha256
        )
        require_attested(
            files, self.directory / "SOURCE-REVIEW.jsonl", visible, pins.source_review_sha256
        )
        self.file_pins = {
            attestation_path: pins.attestation_sha256,
            self.directory / "SOURCE-REVIEW.jsonl": pins.source_review_sha256,
        }
        # Replay the actual attested supporting files (including rights/currentness),
        # not merely the three top-level JSON receipts.
        for binding in self.attestation.get("output_files", []):
            path = self.directory / binding["path"]
            read(path, self.directory, binding["sha256"])
            self.file_pins[path] = binding["sha256"]
        self.code_pins = {}
        self.parser_bridge = None
        for binding in self.attestation.get("code_bindings", []):
            relative = Path(binding["path"])
            if relative.parts[0] not in {"backend", "scripts"}:
                raise ValidationHold("HOLD_REVIEW_CODE_BINDING_PATH")
            current = read(ROOT / relative, ROOT)
            if digest(current) != binding["sha256"]:
                # Only the attested import-separator change may be bridged. No
                # parser/code substitution is approved by equivalent output alone.
                marker = b"\n\nfrom scripts.ge_unseen_sources import is_allowed_source_url"
                if (
                    str(relative) != "scripts/ge_auto_research_intake.py"
                    or not pins.parser_revalidation_sha256
                    or current.count(marker) != 1
                    or digest(current.replace(marker, marker[1:], 1)) != binding["sha256"]
                ):
                    raise ValidationHold(f"HOLD_REVIEW_CODE_CHANGED:{relative}")
            self.code_pins[ROOT / relative] = digest(current)
        for filename in ("INPUT-HASHES.json", "IDENTITY-VERIFICATION.json"):
            path = self.directory / filename
            raw = read(path, visible)
            require_attested(files, path, visible, digest(raw))
            self.file_pins[path] = digest(raw)
        input_rows = obj(self.directory / "INPUT-HASHES.json", visible)
        self.inputs = {row["path"]: sha(row["sha256"]) for row in input_rows}
        if len(self.inputs) != len(input_rows):
            raise ValidationHold("HOLD_DUPLICATE_INPUT_BINDING")
        for binding in self.attestation.get("input_files", []):
            if self.inputs.get(binding["path"]) != binding["sha256"]:
                raise ValidationHold("HOLD_ATTESTATION_INPUT_HASH_CLOSURE")
        for name, expected in self.inputs.items():
            if Path(name).parts[0] not in {"author-research", "structural-review-input"}:
                raise ValidationHold("HOLD_REVIEW_INPUT_OUTSIDE_VISIBLE_SOURCES")
            read(visible / name, visible, expected)
        required = {
            "author-research/CASES.json",
            "author-research/SOURCE-PROPOSALS.json",
            "author-research/RESEARCH-RECEIPT.json",
            "author-research/SOURCE-METADATA-SUPPLEMENT.json",
            "structural-review-input/MANIFEST.json",
        }
        if not required <= self.inputs.keys():
            raise ValidationHold("HOLD_INCOMPLETE_REVIEW_INPUT_CLOSURE")
        if pins.parser_revalidation_sha256:
            self._revalidate_parser()
        identity_rows = obj(self.directory / "IDENTITY-VERIFICATION.json", visible)
        self.identities = {row["source_id"]: row for row in identity_rows}
        if len(self.identities) != len(identity_rows):
            raise ValidationHold("HOLD_DUPLICATE_SOURCE_IDENTITY")
        self.reviews = records(self.review_raw, "proposition_id")
        self.derived: dict[str, bytes] = {}
        self.contexts: dict[str, dict[str, Any]] = {}

    def _revalidate_parser(self) -> None:
        path = self.visible / "structural-review-input/PARSER-REVALIDATION.json"
        receipt = obj(path, self.visible, self.pins.parser_revalidation_sha256)
        if (
            receipt.get("purpose") != "IMPORT_ORDER_ONLY_CURRENT_IMPLEMENTATION_REPARSE"
            or receipt.get("current_parser_sha256") != parser_binding()
        ):
            raise ValidationHold("HOLD_PARSER_REVALIDATION_IDENTITY")
        bindings = {r["input_manifest_sha256"]: r for r in receipt["sources"]}
        if len(bindings) != len(receipt["sources"]) or len(bindings) != receipt["identical_parses"]:
            raise ValidationHold("HOLD_PARSER_REVALIDATION_COVERAGE")
        proposals = load_json_strict(self.read_input("author-research/SOURCE-PROPOSALS.json"))
        observed = set()
        for source in proposals["sources"]:
            if not source.get("raw_path"):
                continue
            name = f"structural-review-input/{source['source_id']}.json"
            saved = load_json_strict(self.read_input(name))
            manifest_sha = self.inputs[name]
            expected = {
                "input_manifest_sha256": manifest_sha,
                "parsed_sha256": saved["parsed_sha256"],
                "original_parser_sha256": saved["parser_sha256"],
            }
            if bindings.get(manifest_sha) != expected:
                raise ValidationHold("HOLD_PARSER_REVALIDATION_SOURCE_BINDING")
            raw = self.read_input("author-research/" + source["raw_path"])
            parsed = parse_capture(
                raw, source_url=source["url"], expected_raw_sha256=source["raw_sha256"]
            )
            if (
                not parsed.is_ready
                or digest(asdict(parsed)) != saved["parsed_sha256"]
                or canonical_json_bytes(asdict(parsed)) != canonical_json_bytes(saved["parsed"])
            ):
                raise ValidationHold("HOLD_PARSER_REVALIDATION_TEXT_CHANGED")
            observed.add(manifest_sha)
        if observed != set(bindings):
            raise ValidationHold("HOLD_PARSER_REVALIDATION_COVERAGE")
        self.file_pins[path] = self.pins.parser_revalidation_sha256
        self.parser_bridge = {
            "receipt_sha256": self.pins.parser_revalidation_sha256,
            "current_parser_sha256": parser_binding(),
            "exact_reparsed_sources": len(observed),
            "reviewed_parsed_bytes_changed": False,
            "legal_review_decisions_changed": False,
        }

    def replay(self) -> None:
        for path, expected in self.file_pins.items():
            read(path, self.visible, expected)
        for relative, expected in self.inputs.items():
            read(self.visible / relative, self.visible, expected)
        for path, expected in self.code_pins.items():
            read(path, ROOT, expected)

    def read_input(self, relative: str) -> bytes:
        if relative not in self.inputs:
            raise ValidationHold(f"HOLD_UNREVIEWED_INPUT:{relative}")
        return read(self.visible / relative, self.visible, self.inputs[relative])

    def eligible(self, proposition: Mapping[str, Any]) -> bool:
        review = self.reviews[proposition["proposition_id"]]
        if (
            review.get("reviewer_id") != self.pins.reviewer_id
            or review.get("source_id") != proposition["source_id"]
            or review.get("original_proposition_sha256") != digest(proposition)
            or review.get("proposed_proposition") != proposition["proposed_proposition"]
        ):
            raise ValidationHold("HOLD_ORIGINAL_PROPOSITION_LINEAGE")
        if review.get("decision") == "HOLD":
            return False
        if (
            review.get("jurisdiction") != JURISDICTIONS[proposition["jurisdiction"]]
            or review.get("as_of_date") != proposition["relevant_date"]
        ):
            raise ValidationHold("HOLD_ORIGINAL_PROPOSITION_LINEAGE")
        if (
            review.get("decision") != "ELIGIBLE_RESEARCH_ONLY"
            or review.get("uncertainties") != []
            or not check_passes(review.get("checks"), REVIEW_CHECKS)
        ):
            raise ValidationHold("HOLD_ELIGIBILITY_WITHOUT_ELEVEN_PASSES")
        identity = self.identities[proposition["source_id"]]
        if any(
            identity.get(k) is not True
            for k in (
                "raw_exists",
                "structural_exists",
                "author_raw_sha256_match",
                "parsed_hash_match",
                "parser_hash_match",
                "reparse_exact_match",
                "raw_to_structural_match",
            )
        ):
            raise ValidationHold("HOLD_SOURCE_IDENTITY_NOT_VERIFIED")
        return True

    def bind(
        self, *, proposition: Mapping[str, Any], source: Capture, issue_id: str
    ) -> dict[str, Any]:
        self.replay()
        if not self.eligible(proposition):
            raise ValidationHold("HOLD_SOURCE_REVIEW")
        raw_review = self.reviews[proposition["proposition_id"]]
        if raw_review["raw_sha256"] != digest(source.raw) or raw_review["parsed_sha256"] != digest(
            asdict(source.parsed)
        ):
            raise ValidationHold("HOLD_REVIEW_CAPTURE_DIGEST")
        original_sources = load_json_strict(
            self.read_input("author-research/SOURCE-PROPOSALS.json")
        )["sources"]
        context = companion_context(self, raw_review, {r["source_id"]: r for r in original_sources})
        context_sha = digest(context)
        self.contexts[context_sha] = context
        derived = {
            **raw_review,
            "raw_review_sha256": digest(raw_review),
            "review_attestation_sha256": self.pins.attestation_sha256,
            "source_review_file_sha256": self.pins.source_review_sha256,
            "original_checks": raw_review["checks"],
            "checks": sorted(REVIEW_CHECKS),
            "scope": asdict(source.scope),
            "capture_sha256": digest(source.manifest()),
            "source_sha256": digest(source.raw),
            "issue_id": issue_id,
            "affected_claim_sha256": digest(proposition),
            "parser_sha256": source.parser_sha256,
            "original_review_parser_sha256": raw_review.get("parser_sha256"),
            "parser_revalidation": self.parser_bridge,
            "companion_context_sha256": context_sha,
        }
        self.derived[digest(derived)] = canonical_json_bytes(derived)
        return derived

    def verify_review(self, reviewer: str, receipt: Mapping[str, Any]) -> bool:
        try:
            self.replay()
            if reviewer != self.pins.reviewer_id:
                return False
            expected = self.derived.get(digest(receipt))
            if expected is None or expected != canonical_json_bytes(receipt):
                return False
            raw_review = self.reviews[receipt["proposition_id"]]
            return (
                receipt["raw_review_sha256"] == digest(raw_review)
                and check_passes(raw_review["checks"], REVIEW_CHECKS)
                and raw_review["decision"] == "ELIGIBLE_RESEARCH_ONLY"
                and raw_review["uncertainties"] == []
            )
        except (ValueError, KeyError, OSError):
            return False


def load_inputs(
    gate: SourceReviewGate,
) -> tuple[list[dict], dict[str, dict], dict[str, dict], dict]:
    cases = load_json_strict(gate.read_input("author-research/CASES.json"))["cases"]
    proposals = load_json_strict(gate.read_input("author-research/SOURCE-PROPOSALS.json"))
    receipt = load_json_strict(gate.read_input("author-research/RESEARCH-RECEIPT.json"))
    props = {row["proposition_id"]: row for row in proposals["propositions"]}
    sources = {row["source_id"]: row for row in proposals["sources"]}
    if (
        len(props) != len(proposals["propositions"])
        or len(sources) != len(proposals["sources"])
        or len({c["case_id"] for c in cases}) != len(cases)
        or set(gate.reviews) != set(props)
        or receipt["case_count"] != len(cases)
    ):
        raise ValidationHold("HOLD_CASE_SOURCE_REVIEW_COVERAGE")
    for key, path in (
        ("case_file", "author-research/CASES.json"),
        ("proposal_file", "author-research/SOURCE-PROPOSALS.json"),
    ):
        if receipt[key]["sha256"] != digest(gate.read_input(path)):
            raise ValidationHold("HOLD_AUTHOR_RECEIPT_LINEAGE")
    for case in cases:
        if (
            digest(case["prompt"].encode()) != case["prompt_sha256"]
            or not set(case["source_proposition_ids"]) <= props.keys()
            or any(props[p]["issue_id"] != case["issue_id"] for p in case["source_proposition_ids"])
        ):
            raise ValidationHold("HOLD_CASE_PROMPT_OR_PROPOSITION_BINDING")
    budgets = receipt["budgets"]
    if (
        len({r["issue_id"] for r in budgets}) != len(budgets)
        or any(
            not 0 <= r["actual_search_query_count"] <= 4
            or not 0 <= r["actual_capture_call_count"] <= 8
            for r in budgets
        )
        or sum(r["actual_search_query_count"] for r in budgets)
        != receipt["actual_search_query_count"]
        or sum(r["actual_capture_call_count"] for r in budgets)
        != receipt["actual_capture_call_count"]
    ):
        raise ValidationHold("HOLD_ORIGINAL_RESEARCH_BUDGET")
    return cases, props, sources, receipt


def make_capture(
    gate: SourceReviewGate, source_row: Mapping[str, Any], scope: Scope, review: Mapping[str, Any]
) -> Capture:
    raw_path = source_row.get("raw_path")
    if not raw_path:
        raise ValidationHold("HOLD_RAW_SOURCE_MISSING")
    raw = gate.read_input("author-research/" + raw_path)
    source_id = source_row["source_id"]
    saved = load_json_strict(gate.read_input(f"structural-review-input/{source_id}.json"))
    capture_receipt = load_json_strict(
        gate.read_input("author-research/" + source_row["capture_receipt_path"])
    )
    if (
        digest(raw) != source_row["raw_sha256"]
        or digest(raw) != saved["raw_sha256"]
        or (saved["parser_sha256"] != parser_binding() and gate.parser_bridge is None)
        or review.get("parser_sha256", saved["parser_sha256"]) != saved["parser_sha256"]
        or capture_receipt["source_id"] != source_id
        or capture_receipt["raw_sha256"] != digest(raw)
        or capture_receipt["url"] != source_row["url"]
    ):
        raise ValidationHold("HOLD_CAPTURE_PARSER_IDENTITY")
    parsed = parse_capture(
        raw, source_url=source_row["url"], expected_raw_sha256=source_row["raw_sha256"]
    )
    if (
        not parsed.is_ready
        or digest(asdict(parsed)) != saved["parsed_sha256"]
        or canonical_json_bytes(asdict(parsed)) != canonical_json_bytes(saved["parsed"])
    ):
        raise ValidationHold("HOLD_REPARSE_CHANGED")
    if source_row["issue_id"] == "NY":
        raise ValidationHold("HOLD_NY_RAW_SOURCE_ROUTE")
    return Capture(
        scope=scope,
        researcher_id=RESEARCHER,
        raw=raw,
        parsed=parsed,
        parser_sha256=parser_binding(),
        canonical_url=source_row["url"],
        final_url=capture_receipt.get("final_url") or source_row["final_url"],
        redirect_chain=tuple(capture_receipt.get("redirect_chain", [])),
        fetched_at=capture_receipt["captured_at"],
        source_identity=source_id,
        authority_type="official-law-research",
        jurisdiction=review["jurisdiction"],
        rights_sha256=digest(review["checks"]["rights"]),
    )


def make_contracts(
    *,
    case: Mapping[str, Any],
    proposition: Mapping[str, Any],
    source: Capture,
    derived_review: Mapping[str, Any],
    policy: ResearchPolicy,
    identity: Mapping[str, Any],
    baseline: Mapping[str, Any],
    registry: ContractSchemaRegistry,
    observed_at: str,
    toolchain: Mapping[str, Any],
) -> dict[str, Any]:
    """Full selected contracts; facts empty because matter extraction is not run."""
    key = proposition["proposition_id"]
    issue = "issue-" + key
    owner_scope = digest({"owner_instruction_sha256": OWNER_SHA256, "scope": asdict(source.scope)})
    request = {
        "purpose": "VISIBLE_INDEX_COMPONENT_VALIDATION",
        "case_id": case["case_id"],
        "original_case_sha256": digest(case),
        "original_prompt_sha256": case["prompt_sha256"],
        "proposition_id": key,
        "original_proposition_sha256": digest(proposition),
        "query": proposition["proposed_proposition"],
        "candidate_answer_generation": False,
    }
    conversation = seal_contract(
        {
            "schema": "legalbot.conversation-snapshot.v1",
            "snapshot_id": "conversation-snapshot-" + key,
            "conversation_id": "conversation-" + key,
            "owner_scope_sha256": owner_scope,
            "revision": 0,
            "created_at": observed_at,
            "messages": [],
            "truncated": False,
            "omitted_message_count": 0,
            "omitted_before_ordinal": None,
            "truncation_reason": "none",
            "estimated_tokens": 0,
        }
    )
    facts = seal_contract(
        {
            "schema": "legalbot.matter-fact-snapshot.v2",
            "snapshot_id": "facts-" + key,
            "conversation_id": conversation["conversation_id"],
            "owner_scope_sha256": owner_scope,
            "conversation_revision": 0,
            "created_at": observed_at,
            "facts": [],
        }
    )
    source_binding = {
        "source_version_id": "source-" + digest(source.manifest()),
        "bytes_sha256": digest(source.raw),
        "canonical_sha256": digest(asdict(source.parsed)),
        "lane": "primary_authority",
        "jurisdiction": source.jurisdiction,
        "qualification_receipt_sha256": digest(derived_review),
    }
    generation = seal_contract(
        {
            "schema": "legalbot.knowledge-generation-manifest.v1",
            "generation_id": "eligible-capture-" + key,
            "source_manifest_sha256": digest([source_binding]),
            "qualification_policy_sha256": policy.sha256,
            "sources": [source_binding],
            "toolchain": dict(toolchain),
            "counts": {
                "source_versions": 1,
                "canonical_objects": 1,
                "chunks": 0,
                "lexical_rows": 0,
                "vector_rows": 0,
                "embedding_dimensions": 1024,
            },
            "file_manifest_sha256": digest(
                {"capture": source.manifest(), "review": digest(derived_review)}
            ),
            "closure_status": "validated",
            "created_at": observed_at,
            "sealed_at": observed_at,
            "attestations": [
                {
                    "name": "eligible_capture_manifest",
                    "status": "PASS",
                    "evidence_sha256": digest(derived_review),
                    "reason_code": "source_review_only_not_index_or_production",
                },
                {
                    "name": "shared_baseline",
                    "status": "PASS",
                    "evidence_sha256": digest(baseline),
                    "reason_code": "empty_frozen_nonproduction_online_only",
                },
                {
                    "name": "embedding_execution",
                    "status": "NOT_RUN",
                    "evidence_sha256": None,
                    "reason_code": "not_run_before_build",
                },
            ],
        }
    )
    variants = {"kind": "visible-proposition-led", "queries": [request["query"]]}
    config = {
        "model_identity_sha256": identity["identity_sha256"],
        "toolchain": dict(toolchain),
        "runner_sha256": digest(Path(__file__).read_bytes()),
        "shared_baseline_sha256": digest(baseline),
        "executed_capabilities": ["retrieval.lexical", "retrieval.vector"],
        "reranker_execution": "NOT_RUN",
        "full_query_plan_execution": "NOT_RUN",
    }
    plan = build_query_plan(
        request_id="request-" + key,
        request_sha256=digest(request),
        original_question_sha256=case["prompt_sha256"],
        task_type="general",
        answer_route="direct",
        requires_knowledge=True,
        requires_matter=False,
        response_disposition="LIMITED",
        jurisdiction=source.jurisdiction,
        jurisdiction_status="explicit",
        requested_as_of_date=date.fromisoformat(case["relevant_date"]),
        as_of_date_status="explicit",
        issue_ids=[issue],
        missing_facts=[],
        query_variants_ref="queries-" + key,
        query_variants_sha256=digest(variants),
        candidate_id="visible-research-" + case["case_id"],
        policy_sha256=policy.sha256,
        config_sha256=digest(config),
        conversation_snapshot=conversation,
        fact_snapshot=facts,
        rewrite={
            "status": "not_needed",
            "encrypted_query_ref": None,
            "query_sha256": None,
            "reason_code": "visible_component_query",
        },
        risk_flags=["visible_component_only", "matter_ingestion_not_run"],
        request_observed_at=datetime.fromisoformat(observed_at),
        frozen_at=datetime.fromisoformat(observed_at),
        registry=registry,
    ).value
    for contract in (conversation, facts, generation, plan):
        registry.validate_new(contract)
    return {
        "request": request,
        "conversation": conversation,
        "facts": facts,
        "knowledge_generation": generation,
        "query_plan": plan,
        "query_variants": variants,
        "config": config,
    }


def lineage_for(contracts: Mapping[str, Any], registry: ContractSchemaRegistry) -> Lineage:
    return Lineage.bind(
        registry=registry,
        query_plan=contracts["query_plan"],
        fact_snapshot=contracts["facts"],
        knowledge_generation=contracts["knowledge_generation"],
        conversation_snapshot=contracts["conversation"],
        expected_request_sha256=digest(contracts["request"]),
        expected_knowledge_generation_sha256=contracts["knowledge_generation"]["content_sha256"],
    )


def negative_checks(
    index: AutoResearchIndex,
    policy: ResearchPolicy,
    scope: Scope,
    prepared: Any,
    generation: str,
    provider: Any,
    source: Capture,
    derived: Mapping[str, Any],
    gap: str,
    attempt: int,
    job_cap: Any,
    output: Path,
) -> dict[str, Any]:
    def denied(call: Callable[[], Any]) -> bool:
        try:
            call()
        except (ValueError, PermissionError, FileExistsError):
            return True
        raise ValidationHold("HOLD_NEGATIVE_BOUNDARY_ACCEPTED")

    cap = policy.authorize(
        scope=scope, actor=ACTOR, role="candidate", action="retrieve", binding_sha256=generation
    )
    common = {
        "cap": cap,
        "build_sha256": prepared.sha256,
        "generation_sha256": generation,
        "query": derived["quote"],
        "provider": provider,
    }
    wrong_jurisdiction = "Texas" if index.lineage.jurisdiction != "Texas" else "England"
    wrong_date = (date.fromisoformat(index.lineage.as_of_date) + timedelta(days=1)).isoformat()
    wrong_jur = denied(
        lambda: index.retrieve(
            **common, lineage=replace(index.lineage, jurisdiction=wrong_jurisdiction)
        )
    )
    wrong_day = denied(
        lambda: index.retrieve(**common, lineage=replace(index.lineage, as_of_date=wrong_date))
    )
    quote = denied(
        lambda: index.prepare(
            job_cap,
            gap=gap,
            attempt=attempt,
            sources=[(source, {**derived, "quote": "Unreviewed synthetic mismatch"})],
        )
    )
    other = next(s for s in policy.scopes if s != scope)
    foreign = policy.authorize(
        scope=other, actor=ACTOR, role="candidate", action="retrieve", binding_sha256=generation
    )
    cross = denied(lambda: index.retrieve(**{**common, "cap": foreign}, lineage=index.lineage))
    calls_before = len(provider.calls)
    build_cap = policy.authorize(
        scope=scope, actor=ACTOR, role="candidate", action="build", binding_sha256=prepared.sha256
    )
    if (
        index.build(build_cap, prepared, provider=provider) != generation
        or len(provider.calls) != calls_before
    ):
        raise ValidationHold("HOLD_DUPLICATE_BUILD_INFERRED_AGAIN")
    # Exercise the real repository's create-only interruption guard, without another model job.
    from backend.app.retrieval.lancedb import ImmutableLanceRepository

    interrupted_root = output / "fault-checks" / prepared.sha256
    repository = ImmutableLanceRepository(interrupted_root)
    staged = repository.prepare_new_staging("interrupted-before-inference")
    marker = staged / "PRESERVED.json"
    marker_sha = write_new(
        marker, {"state": "INTERRUPTED_BEFORE_INFERENCE", "model_calls": 0}, output=output
    )
    interruption = denied(lambda: repository.prepare_new_staging("interrupted-before-inference"))
    if digest(read(marker, output)) != marker_sha:
        raise ValidationHold("HOLD_INTERRUPTED_BYTES_CHANGED")
    return {
        "wrong_jurisdiction_denied": wrong_jur,
        "wrong_date_denied": wrong_day,
        "quote_mismatch_denied": quote,
        "cross_scope_denied": cross,
        "duplicate_build_no_inference": True,
        "interrupted_staging_preserved": interruption,
        "interruption_boundary": "BEFORE_INFERENCE_NOT_A_MODEL_FAILURE_TEST",
    }


def active_snapshot(scopes: list[Scope]) -> dict[str, Any]:
    result = {}
    for scope in scopes:
        for name in ("ACTIVE.json", "PREVIOUS.json"):
            path = safe(Path(scope.root) / name, Path(scope.root))
            result[str(path)] = digest(path.read_bytes()) if path.exists() else None
    return result


def reconcile_companions(
    *,
    output: Path,
    outcomes: list[dict[str, Any]],
    queue: list[dict[str, Any]],
    reviews: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Keep primary retrieval distinct from a complete required-context bundle.

    Companion passages must themselves have eligible review and persisted retrieval
    in this case. A companion reference cannot promote a held source proposition.
    Missing context is a terminal component hold, preserving primary build evidence.
    """
    entries = {entry["proposition_id"]: entry for entry in queue}
    primary = [dict(row) for row in outcomes if row["proposition_id"] in entries]
    completed = []
    for row in outcomes:
        prop_id = row["proposition_id"]
        if prop_id not in entries:
            continue
        packet = obj(output / entries[prop_id]["path"], output, entries[prop_id]["sha256"])
        companions, missing = [], []
        for companion in reviews[prop_id].get("companion_source_context", []):
            matches = [
                candidate
                for candidate in primary
                if candidate["case_id"] == row["case_id"]
                and candidate["source_id"] == companion["source_id"]
            ]
            found = None
            for candidate in matches:
                other_id = candidate["proposition_id"]
                other_review = reviews[other_id]
                if (
                    other_review["decision"] != "ELIGIBLE_RESEARCH_ONLY"
                    or other_review["raw_sha256"] != companion["raw_sha256"]
                    or other_review["parsed_sha256"] != companion["parsed_sha256"]
                ):
                    continue
                other = obj(output / entries[other_id]["path"], output, entries[other_id]["sha256"])
                ordinals = {
                    ordinal
                    for evidence in other["supported_evidence"]
                    for ordinal in evidence["structural_chunk"]["block_ordinals"]
                }
                if set(companion["context_block_ordinals"]) <= ordinals:
                    found = {
                        "proposition_id": other_id,
                        "packet": entries[other_id],
                        "required_context": dict(companion),
                        "retrieval_sha256": other["retrieval_sha256"],
                        "generation_sha256": other["generation_sha256"],
                        "evidence": other["supported_evidence"],
                    }
                    break
            if found is None:
                missing.append(companion["source_id"])
            else:
                companions.append(found)
        if missing:
            row["state"] = "HOLD_REQUIRED_COMPANION_CONTEXT"
            row["missing_companion_source_ids"] = missing
        bundle = {
            **packet,
            "companion_retrievals": companions,
            "missing_companion_source_ids": missing,
            "all_required_source_context_retrieved": not missing,
            "claim_review": "PENDING_INDEPENDENT_REVIEW",
            "gap_closed": False,
        }
        path = output / "propositions" / prop_id / "CLAIM-REVIEW-BUNDLE.json"
        key = write_new(path, bundle, output=output)
        row["companion_source_count"] = len(companions)
        row["claim_review_bundle_sha256"] = key
        if missing:
            continue
        completed.append(
            {"proposition_id": prop_id, "path": str(path.relative_to(output)), "sha256": key}
        )
    return completed


def companion_context(
    gate: SourceReviewGate, review: Mapping[str, Any], sources: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    """Retain every reviewed dependency, without granting a held claim eligibility.

    These structural passages form a linked context sidecar. Only independently
    eligible primary sources enter lexical/vector builds; sidecar readback is
    distinguished from actual indexed retrieval by reconcile_companions.
    """
    from backend.app.ingestion.chunking import StructuralChunker

    entries = []
    for required in review.get("companion_source_context", []):
        source = sources[required["source_id"]]
        saved = load_json_strict(
            gate.read_input(f"structural-review-input/{source['source_id']}.json")
        )
        raw = gate.read_input("author-research/" + source["raw_path"])
        if (
            digest(raw) != required["raw_sha256"]
            or saved["parsed_sha256"] != required["parsed_sha256"]
            or saved["parser_sha256"] != required["parser_sha256"]
        ):
            raise ValidationHold("HOLD_COMPANION_DIGEST_BINDING")
        parsed = parse_capture(
            raw, source_url=source["url"], expected_raw_sha256=required["raw_sha256"]
        )
        if digest(asdict(parsed)) != required["parsed_sha256"]:
            raise ValidationHold("HOLD_COMPANION_REPARSE_CHANGED")
        ordinals = set(required["context_block_ordinals"])
        if not ordinals or not ordinals <= {b.ordinal for b in parsed.body_blocks}:
            raise ValidationHold("HOLD_COMPANION_CONTEXT_ORDINALS")
        chunks = [
            asdict(c)
            for c in StructuralChunker().chunk_body(parsed, document_sha256=digest(raw))
            if set(c.block_ordinals) & ordinals
        ]
        entries.append(
            {
                "required_context": dict(required),
                "source_original": dict(source),
                "structural_chunks": chunks,
                "primary_independent_review_sha256": digest(review),
                "source_proposition_reviews": [
                    dict(r) for r in gate.reviews.values() if r["source_id"] == source["source_id"]
                ],
                "current_parser_sha256": parser_binding(),
                "parser_revalidation": gate.parser_bridge,
                "indexed_or_embedded_by_this_sidecar": False,
                "legal_eligibility_changed": False,
            }
        )
    return {
        "primary_independent_review": dict(review),
        "review_attestation_sha256": gate.pins.attestation_sha256,
        "source_review_sha256": gate.pins.source_review_sha256,
        "supporting_review_files": gate.attestation.get("output_files", []),
        "companion_sources": entries,
        "all_declared_companions_preserved": len(entries)
        == len(review.get("companion_source_context", [])),
    }


def execute(
    *,
    owner_authorization: Path,
    pins: ReviewPins,
    ready_reason: str,
    parent_authorized: bool = False,
) -> dict[str, Any]:
    """Only the parent/operator calls this after reviewing exact input attestations."""
    if not parent_authorized or not ready_reason.strip():
        raise ValidationHold("HOLD_PARENT_READY_REASON_REQUIRED")
    gate = SourceReviewGate(VISIBLE, pins)  # must complete before importing/loading a model
    cases, propositions, sources, research = load_inputs(gate)
    if any(part in {".private", "current", "retired"} for part in owner_authorization.parts):
        raise ValidationHold("HOLD_OWNER_AUTHORIZATION_PATH")
    owner_bytes = read(owner_authorization, ROOT, OWNER_SHA256)
    OUTPUT.mkdir(parents=True, exist_ok=True, mode=0o700)
    session_lock = ROOT / "data/research/ge-auto-research/embedding.lock"
    # The authorized parent runtime manages this empty synchronization file.
    # Research data and execution evidence are written exclusively beneath OUTPUT.
    safe(session_lock, ROOT)
    from scripts.ge_auto_research_runtime import PinnedEmbeddingSession, verified_model_identity

    identity = verified_model_identity()  # file verification only; no inference
    pin = ModelPin.from_runtime_identity(identity)
    scopes = [
        Scope(
            str(OUTPUT / "stores" / case["case_id"]),
            "candidate_case_local",
            "VISIBLE_INDEX_COMPONENT_VALIDATION",
            case["case_id"],
        )
        for case in cases
    ]
    policy = ResearchPolicy(
        workspace=OUTPUT,
        owner_instruction=owner_bytes,
        expected_owner_instruction_sha256=OWNER_SHA256,
        scopes=scopes,
        model=pin,
        reviewers=[pins.reviewer_id],
        verify_review=gate.verify_review,
    )
    # No source review is granted by policy construction. Exact derived receipt enrollment
    # below precedes issuing any action capability for its case/proposition.
    baseline = {
        "schema": "legalbot.visible-empty-research-baseline.v1",
        "sources": [],
        "lexical_rows": 0,
        "vector_rows": 0,
        "nonproduction": True,
        "frozen": True,
        "route": "ONLINE_ONLY_RESEARCH",
        "candidate_case_deltas_shared": False,
    }
    write_new(OUTPUT / "EMPTY-SHARED-BASELINE.json", baseline)
    write_new(
        OUTPUT / "ORIGINAL-RESEARCH-IMPORT.json",
        {
            "original_receipt_sha256": digest(
                gate.read_input("author-research/RESEARCH-RECEIPT.json")
            ),
            "actual_original_queries": research["actual_search_query_count"],
            "actual_original_captures": research["actual_capture_call_count"],
            "new_network_queries": 0,
            "new_network_captures": 0,
            "budgets": research["budgets"],
            "operation": "IMPORT_EXISTING_CAPTURES",
        },
    )
    start = {
        "created_at": datetime.now(UTC).isoformat(),
        "ready_reason": ready_reason,
        "owner_instruction_sha256": OWNER_SHA256,
        "review_attestation_sha256": pins.attestation_sha256,
        "source_review_sha256": pins.source_review_sha256,
        "parser_revalidation": gate.parser_bridge,
        "model_identity": identity,
        "runner_sha256": digest(Path(__file__).read_bytes()),
        "purpose": "INDEX_COMPONENT_ONLY",
    }
    write_new(OUTPUT / "RUN-START.json", start)
    registry = ContractSchemaRegistry.from_project_root(ROOT)
    model_spec = obj(ROOT / "scripts/model/manifests/qwen3-retrieval-models.json", ROOT)
    reranker_pin = next(m for m in model_spec["models"] if m["role"] == "reranker")
    toolchain = {
        "parser_sha256": parser_binding(),
        "ocr_sha256": None,
        "chunker_sha256": digest(read(ROOT / "backend/app/ingestion/chunking.py", ROOT)),
        "tokenizer_sha256": digest(read(ROOT / identity["directory"] / "tokenizer.json", ROOT)),
        "embedding_model_sha256": identity["file_manifest_sha256"],
        "lexical_config_sha256": digest({"engine": "lancedb-native-fts", "use_tantivy": False}),
        "vector_schema_sha256": digest(
            {"field": "vector", "dtype": "float32", "dimensions": 1024, "metric": "cosine"}
        ),
        "reranker_model_sha256": reranker_pin["file_manifest_sha256"],
    }
    before = active_snapshot(scopes)
    outcomes, claim_inputs = [], []
    with PinnedEmbeddingSession() as provider:
        if provider.pin != pin or not provider.verify_binding():
            raise ValidationHold("HOLD_RUNTIME_IDENTITY_CHANGED")
        for case, scope in zip(cases, scopes, strict=True):
            # Exact synthetic matter and uploads remain outside the authority store.
            evidence_dir = OUTPUT / "case-evidence" / case["case_id"]
            write_new(evidence_dir / "ORIGINAL-CASE.json", case)
            for upload in case.get("uploads", []):
                for kind in ("text", "render_input"):
                    binding = upload.get(kind)
                    if binding:
                        raw = gate.read_input("author-research/" + binding["path"])
                        if digest(raw) != binding["sha256"]:
                            raise ValidationHold("HOLD_UPLOAD_BYTES_CHANGED")
                        write_new(evidence_dir / Path(binding["path"]).name, raw)
            for prop_id in case["source_proposition_ids"]:
                proposition = propositions[prop_id]
                row = {
                    "case_id": case["case_id"],
                    "proposition_id": prop_id,
                    "source_id": proposition["source_id"],
                    "original_proposition_sha256": digest(proposition),
                    "claim_review": "NOT_PERFORMED",
                    "gap_closed": False,
                }
                before_calls = len(provider.calls)
                try:
                    if not gate.eligible(proposition):
                        row.update(
                            state="HOLD_SOURCE_REVIEW", decision=gate.reviews[prop_id]["decision"]
                        )
                        outcomes.append(row)
                        continue
                    source = make_capture(
                        gate, sources[proposition["source_id"]], scope, gate.reviews[prop_id]
                    )
                    derived = gate.bind(
                        proposition=proposition, source=source, issue_id="issue-" + prop_id
                    )
                    contracts = make_contracts(
                        case=case,
                        proposition=proposition,
                        source=source,
                        derived_review=derived,
                        policy=policy,
                        identity=identity,
                        baseline=baseline,
                        registry=registry,
                        observed_at=start["created_at"],
                        toolchain=toolchain,
                    )
                    local = OUTPUT / "propositions" / prop_id
                    write_new(local / "CONTRACTS.json", contracts)
                    write_new(local / "DERIVED-SOURCE-REVIEW.json", derived)
                    context_sha = write_new(
                        local / "COMPANION-CONTEXT.json",
                        gate.contexts[derived["companion_context_sha256"]],
                    )
                    lineage = lineage_for(contracts, registry)
                    cap = policy.authorize(
                        scope=scope,
                        actor=ACTOR,
                        role="candidate",
                        action="jobs",
                        binding_sha256=digest(asdict(lineage)),
                    )
                    index = AutoResearchIndex(
                        policy=policy, capability=cap, scope=scope, lineage=lineage
                    )
                    gap = index.enqueue(
                        cap,
                        issue_id="issue-" + prop_id,
                        gap_class="missing_authority",
                        affected_claim_sha256=digest(proposition),
                        failure_fingerprint=digest({"gap": prop_id, "baseline": baseline}),
                    )
                    lookup = {
                        "scope": "FROZEN_EMPTY_SHARED_BASELINE",
                        "baseline_sha256": digest(baseline),
                        "existing_hits": [],
                        "operation": "IMPORT_PREVIOUSLY_CAPTURED_SOURCE_NO_FETCH",
                    }
                    lookup_sha = write_new(local / "EXISTING-BASELINE-LOOKUP.json", lookup)
                    attempt = index.begin_attempt(
                        cap,
                        gap,
                        inputs_sha256=digest({"source": source.manifest(), "review": derived}),
                        existing_retrieval_sha256=lookup_sha,
                    )
                    if attempt is None:
                        raise ValidationHold("HOLD_UNCHANGED_ATTEMPT_REQUIRES_EXISTING_RECEIPT")
                    operation = index.reserve(
                        cap, attempt, kind="capture", input_sha256=digest(source.manifest())
                    )
                    index.capture(cap, operation, source)
                    write_new(
                        local / "CAPTURE-IMPORT.json",
                        {
                            "operation": "EXISTING_CAPTURE_IMPORT",
                            "source_id": proposition["source_id"],
                            "original_capture_receipt_sha256": sources[proposition["source_id"]][
                                "capture_receipt_sha256"
                            ],
                            "attempt_id": attempt,
                            "operation_id": operation,
                            "new_network_capture": False,
                        },
                    )
                    prepared = index.prepare(
                        cap, gap=gap, attempt=attempt, sources=[(source, derived)]
                    )
                    build_cap = policy.authorize(
                        scope=scope,
                        actor=ACTOR,
                        role="candidate",
                        action="build",
                        binding_sha256=prepared.sha256,
                    )
                    generation = index.build(build_cap, prepared, provider=provider)
                    row.update(gap=gap, build_sha256=prepared.sha256, generation_sha256=generation)
                    retrieve_cap = policy.authorize(
                        scope=scope,
                        actor=ACTOR,
                        role="candidate",
                        action="retrieve",
                        binding_sha256=generation,
                    )
                    result = index.retrieve(
                        retrieve_cap,
                        build_sha256=prepared.sha256,
                        generation_sha256=generation,
                        query=proposition["proposed_proposition"],
                        lineage=lineage,
                        provider=provider,
                        limit=8,
                    )
                    write_new(local / "RETRIEVAL.json", result)
                    row["retrieval_sha256"] = result["retrieval_sha256"]
                    required = set(derived["context_block_ordinals"])
                    observed = {
                        ordinal
                        for r in result["evidence"]
                        for ordinal in r["structural_chunk"]["block_ordinals"]
                    }
                    support = any(derived["quote"] in r["text"] for r in result["evidence"])
                    if (
                        not support
                        or not required <= observed
                        or not result["lexical_ids"]
                        or not result["vector_ids"]
                    ):
                        raise ValidationHold("HOLD_INTENDED_EVIDENCE_OR_CONTEXT_NOT_RETRIEVED")
                    checks = negative_checks(
                        index,
                        policy,
                        scope,
                        prepared,
                        generation,
                        provider,
                        source,
                        derived,
                        gap,
                        attempt,
                        cap,
                        OUTPUT,
                    )
                    write_new(local / "BOUNDARY-CHECKS.json", checks)
                    packet = {
                        "case_id": case["case_id"],
                        "proposition_id": prop_id,
                        "gap": gap,
                        "original_proposition": proposition,
                        "affected_claim_sha256": digest(proposition),
                        "retrieval_sha256": result["retrieval_sha256"],
                        "generation_sha256": generation,
                        "lineage_sha256": index.lineage_sha256,
                        "retrieval_file_sha256": digest(canonical_json_bytes(result)),
                        "selected_chunk_ids": result["selected_ids"],
                        "supported_evidence": result["evidence"],
                        "companion_context": {
                            "path": str((local / "COMPANION-CONTEXT.json").relative_to(OUTPUT)),
                            "sha256": context_sha,
                        },
                        "source_review_sha256": digest(derived),
                        "reranker_execution": "NOT_RUN",
                        "reviewer_decision": "PENDING_INDEPENDENT_POST_RETRIEVAL_CLAIM_REVIEW",
                    }
                    write_new(local / "CLAIM-REVIEW-INPUT.json", packet)
                    claim_inputs.append(
                        {
                            "proposition_id": prop_id,
                            "path": str(local.relative_to(OUTPUT) / "CLAIM-REVIEW-INPUT.json"),
                            "sha256": digest(packet),
                        }
                    )
                    row.update(
                        state="RETRIEVED_PENDING_CLAIM_REVIEW",
                        gap=gap,
                        generation_sha256=generation,
                        build_sha256=prepared.sha256,
                        retrieval_sha256=result["retrieval_sha256"],
                        retrieved_chunk_count=len(result["evidence"]),
                        boundary_checks=checks,
                        gap_state=index.status(gap)["state"],
                    )
                except (
                    ValueError,
                    PermissionError,
                    OSError,
                    RuntimeError,
                    KeyError,
                    TypeError,
                ) as exc:
                    row.update(
                        state="HOLD_INDEX_COMPONENT", reason=str(exc), error_type=type(exc).__name__
                    )
                finally:
                    row["actual_inference_calls"] = len(provider.calls) - before_calls
                    write_new(OUTPUT / "outcomes" / (prop_id + ".json"), row)
                    write_new(
                        OUTPUT / "inference" / (prop_id + ".json"),
                        {
                            "model_identity": provider.identity,
                            "calls": provider.calls[before_calls:],
                            "actual_inference_calls": len(provider.calls) - before_calls,
                        },
                    )
                if row not in outcomes:
                    outcomes.append(row)
        inference = provider.receipt()
    after = active_snapshot(scopes)
    if after != before:
        raise ValidationHold("HOLD_ACTIVE_POINTER_CHANGED")
    write_new(OUTPUT / "ACTUAL-INFERENCE.json", inference)
    claim_inputs = reconcile_companions(
        output=OUTPUT, outcomes=outcomes, queue=claim_inputs, reviews=gate.reviews
    )
    write_new(OUTPUT / "CLAIM-REVIEW-QUEUE.json", claim_inputs)
    result = {
        "schema": "legalbot.visible-index-component-result.v1",
        "state": "INDEX_COMPONENT_RUN_TERMINAL",
        "global_auto_research_visible_validation": "NOT_ASSESSED",
        "case_count": len(cases),
        "source_count": len(sources),
        "proposition_count": len(propositions),
        "outcomes": outcomes,
        "counts": dict(Counter(row["state"] for row in outcomes)),
        "built_generation_count": sum("generation_sha256" in row for row in outcomes),
        "embedded_source_count": len(
            {row["source_id"] for row in outcomes if "generation_sha256" in row}
        ),
        "retrieved_source_count": len(
            {r["source_id"] for r in outcomes if "retrieval_sha256" in r}
        ),
        "cases_with_retrieved_evidence": len(
            {r["case_id"] for r in outcomes if "retrieval_sha256" in r}
        ),
        "propositions_with_complete_context_bundle": len(claim_inputs),
        "whole_case_routes_cleared": 0,
        "parser_revalidation": gate.parser_bridge,
        "actual_inference_calls": inference["actual_inference_calls"],
        "new_network_queries": 0,
        "new_network_captures": 0,
        "original_queries": research["actual_search_query_count"],
        "original_captures": research["actual_capture_call_count"],
        "independent_review_research_counts": gate.attestation.get("research_counts"),
        "ACTIVE_unchanged": after == before,
        "claim_review": "PENDING",
        "candidate_consumer": "PARENT_PENDING",
        "upload_ingestion": "PARENT_PENDING",
        "multi_turn_validation": "PARENT_PENDING",
        "executed_capabilities": ["retrieval.lexical", "retrieval.vector"]
        if any("retrieval_sha256" in row for row in outcomes)
        else [],
        "reranker_execution": "NOT_RUN",
        "reranker_actual_inference_calls": 0,
        "full_query_plan_execution": "NOT_RUN",
        "runtime_capability_pass": False,
        "gap_closures": 0,
        "source_admission": False,
        "qualified_legal_review": False,
        "legal_gold": False,
        "production": False,
        "training": False,
    }
    write_new(OUTPUT / "RESULTS.json", result)
    return result


def claim_review_callback(
    *,
    visible: Path,
    review_path: Path,
    attestation_path: Path,
    review_sha256: str,
    attestation_sha256: str,
    reviewer_id: str,
    expected_packets: Mapping[str, Mapping[str, Any]],
) -> Callable[[str, Mapping[str, Any]], bool]:
    """Later parent hook; no callback or closure is granted while claim review is absent.

    The independent claim attestation must bind CLAIM-REVIEW.jsonl and each exact
    input packet path/hash under files/inputs/outputs. Records use the AutoResearchIndex
    close_gap fields plus proposition_id and checks for affected_claim,
    material_omissions and contrary_authority, each with status/reason/evidenceURL.
    """
    attestation = obj(attestation_path, visible, attestation_sha256)
    if attestation.get("reviewer_id") != reviewer_id or reviewer_id in {ACTOR, RESEARCHER}:
        raise ValidationHold("HOLD_CLAIM_REVIEWER_IDENTITY")
    files = attestation_files(attestation)
    require_attested(files, review_path, visible, review_sha256)
    raw = read(review_path, visible, review_sha256)
    reviewed = records(raw, "proposition_id")
    for entry in expected_packets.values():
        path = visible / entry["path"]
        require_attested(files, path, visible, entry["sha256"])
        read(path, visible, entry["sha256"])

    def verify(reviewer: str, receipt: Mapping[str, Any]) -> bool:
        try:
            read(review_path, visible, review_sha256)
            read(attestation_path, visible, attestation_sha256)
            exact = reviewed[receipt["proposition_id"]]
            entry = expected_packets[receipt["proposition_id"]]
            packet = obj(visible / entry["path"], visible, entry["sha256"])
            if "companion_context" in packet:
                if packet.get("all_required_source_context_retrieved") is not True:
                    return False
                context = packet["companion_context"]
                read(visible / context["path"], visible, context["sha256"])
                for companion in packet.get("companion_retrievals", []):
                    binding = companion["packet"]
                    read(visible / binding["path"], visible, binding["sha256"])
            return (
                reviewer == reviewer_id
                and receipt.get("reviewer_id") == reviewer_id
                and canonical_json_bytes(receipt) == canonical_json_bytes(exact)
                and receipt.get("decision") == "VERIFIED_AFFECTED_CLAIM"
                and receipt.get("material_omissions_checked") is True
                and receipt.get("contrary_authority_checked") is True
                and not any(
                    receipt.get(key) is True
                    for key in (
                        "legal_gold",
                        "admitted",
                        "qualified_legal_review",
                        "full_current_law_eligible",
                    )
                )
                and check_passes(
                    receipt.get("checks"),
                    {"affected_claim", "material_omissions", "contrary_authority"},
                )
                and all(
                    receipt.get(k) == packet[k]
                    for k in (
                        "gap",
                        "affected_claim_sha256",
                        "retrieval_sha256",
                        "generation_sha256",
                        "lineage_sha256",
                    )
                )
            )
        except (KeyError, ValueError, OSError):
            return False

    return verify


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--ready-reason", default="")
    parser.add_argument("--owner-authorization", type=Path, required=True)
    parser.add_argument("--review-attestation-sha256", required=True)
    parser.add_argument("--source-review-sha256", required=True)
    parser.add_argument("--parser-revalidation-sha256")
    args = parser.parse_args()
    if not args.execute or not args.ready_reason.strip():
        print(json.dumps({"state": "HOLD_PARENT_READY_REASON_REQUIRED", "model_loaded": False}))
        return 2
    safe(OUTPUT, ROOT)
    OUTPUT.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(
        safe(OUTPUT / ".runner.lock", OUTPUT), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
    )
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = execute(
            owner_authorization=args.owner_authorization,
            pins=ReviewPins(
                args.review_attestation_sha256,
                args.source_review_sha256,
                parser_revalidation_sha256=args.parser_revalidation_sha256,
            ),
            ready_reason=args.ready_reason,
            parent_authorized=args.execute,
        )
        print(
            json.dumps(
                {
                    "state": result["state"],
                    "counts": result["counts"],
                    "global_auto_research_visible_validation": "NOT_ASSESSED",
                }
            )
        )
        return 0
    except (ValueError, PermissionError, OSError, RuntimeError, KeyError, TypeError) as exc:
        hold = {
            "state": "HOLD_INDEX_VALIDATION",
            "reason": str(exc),
            "error_type": type(exc).__name__,
            "global_auto_research_visible_validation": "NOT_ASSESSED",
        }
        write_new(OUTPUT / ("HOLD-" + digest(hold) + ".json"), hold)
        print(json.dumps(hold))
        return 2
    finally:
        os.close(fd)


if __name__ == "__main__":
    raise SystemExit(main())
