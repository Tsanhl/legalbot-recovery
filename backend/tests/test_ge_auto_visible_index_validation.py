"""Index runner's admission/lineage tests. No embedding session is entered.

Use a fresh --basetemp beneath the visible pack's index-validation/test-runs.
All source/reviewer content below is explicitly synthetic fixture data.
"""

from __future__ import annotations

import json
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from backend.app.contracts import ContractSchemaRegistry
from backend.app.research.ge_auto_index import (
    REVIEW_CHECKS,
    ModelPin,
    ResearchPolicy,
    Scope,
    digest,
)
from scripts import ge_auto_visible_index_validation as runner
from scripts.ge_auto_research_intake import parse_capture, parser_binding


def encoded(value):
    from backend.app.contracts.schema_registry import canonical_json_bytes

    return canonical_json_bytes(value)


def put(root, path, value):
    target = root / path
    raw = value if isinstance(value, bytes) else encoded(value)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    return digest(raw)


def checks(required=REVIEW_CHECKS):
    return {
        key: {
            "status": "PASS",
            "reason": "Synthetic exact-fixture verification only",
            "evidenceURL": "https://www.legislation.gov.uk/ukpga/2026/1",
        }
        for key in required
    }


@pytest.fixture
def reviewed(tmp_path):
    assert tmp_path.is_relative_to(runner.OUTPUT), "fresh --basetemp must be under index-validation"
    visible = tmp_path / "synthetic-visible"
    source_id = digest(b"synthetic source identity")
    url = "https://www.legislation.gov.uk/ukpga/2026/1"
    raw = b"<html><body><p>Notice requires written delivery except during an emergency.</p></body></html>"
    parsed = parse_capture(raw, source_url=url, expected_raw_sha256=digest(raw))
    assert parsed.is_ready
    block = next(b for b in parsed.body_blocks if "written delivery" in b.text)
    source = {
        "source_id": source_id,
        "issue_id": "ENG",
        "url": url,
        "final_url": url,
        "captured_at": "2026-09-05T00:00:00+00:00",
        "capture_status": "CAPTURED_NOT_LEGAL_VERIFIED",
        "raw_path": f"sources/{source_id}.bytes",
        "raw_sha256": digest(raw),
        "capture_receipt_path": f"sources/{source_id}.json",
        "source_admission": False,
    }
    prop = {
        "proposition_id": "ENG-NOTICE",
        "issue_id": "ENG",
        "source_id": source_id,
        "jurisdiction": "GB-ENG",
        "relevant_date": "2026-09-05",
        "proposed_proposition": "Written notice is required except during an emergency.",
        "index_eligible": False,
        "review_status": "NOT_PERFORMED",
    }
    case = {
        "case_id": "VISIBLE-ENG-01",
        "issue_id": "ENG",
        "jurisdiction": "GB-ENG",
        "visibility": "VISIBLE",
        "relevant_date": "2026-09-05",
        "prompt": "Synthetic notice question",
        "prompt_sha256": digest(b"Synthetic notice question"),
        "source_proposition_ids": [prop["proposition_id"]],
        "uploads": [],
        "expected_material_facts": {"synthetic": True},
    }
    capture_receipt = {
        "source_id": source_id,
        "url": url,
        "final_url": url,
        "raw_sha256": digest(raw),
        "captured_at": source["captured_at"],
    }
    input_pins = {}
    input_pins["author-research/" + source["raw_path"]] = put(
        visible, "author-research/" + source["raw_path"], raw
    )
    receipt_hash = put(
        visible, "author-research/" + source["capture_receipt_path"], capture_receipt
    )
    source["capture_receipt_sha256"] = receipt_hash
    input_pins["author-research/" + source["capture_receipt_path"]] = receipt_hash
    input_pins["author-research/CASES.json"] = put(
        visible, "author-research/CASES.json", {"cases": [case]}
    )
    input_pins["author-research/SOURCE-PROPOSALS.json"] = put(
        visible,
        "author-research/SOURCE-PROPOSALS.json",
        {"sources": [source], "propositions": [prop]},
    )
    research = {
        "case_count": 1,
        "actual_search_query_count": 1,
        "actual_capture_call_count": 1,
        "case_file": {"sha256": input_pins["author-research/CASES.json"]},
        "proposal_file": {"sha256": input_pins["author-research/SOURCE-PROPOSALS.json"]},
        "budgets": [
            {"issue_id": "ENG", "actual_search_query_count": 1, "actual_capture_call_count": 1}
        ],
    }
    input_pins["author-research/RESEARCH-RECEIPT.json"] = put(
        visible, "author-research/RESEARCH-RECEIPT.json", research
    )
    input_pins["author-research/SOURCE-METADATA-SUPPLEMENT.json"] = put(
        visible, "author-research/SOURCE-METADATA-SUPPLEMENT.json", {"fixture": "supplement"}
    )
    saved = {
        "raw_sha256": digest(raw),
        "parsed_sha256": digest(asdict(parsed)),
        "parser_sha256": parser_binding(),
        "parsed": asdict(parsed),
    }
    input_pins[f"structural-review-input/{source_id}.json"] = put(
        visible, f"structural-review-input/{source_id}.json", saved
    )
    input_pins["structural-review-input/MANIFEST.json"] = put(
        visible, "structural-review-input/MANIFEST.json", {"sources": [source_id]}
    )
    identity = {
        "source_id": source_id,
        **dict.fromkeys(
            (
                "raw_exists",
                "structural_exists",
                "author_raw_sha256_match",
                "parsed_hash_match",
                "parser_hash_match",
                "reparse_exact_match",
                "raw_to_structural_match",
            ),
            True,
        ),
    }
    review = {
        "reviewer_id": runner.REVIEWER,
        "proposition_id": prop["proposition_id"],
        "source_id": source_id,
        "original_proposition_sha256": digest(prop),
        "proposed_proposition": prop["proposed_proposition"],
        "raw_sha256": digest(raw),
        "parsed_sha256": digest(asdict(parsed)),
        "jurisdiction": "England",
        "as_of_date": "2026-09-05",
        "decision": "ELIGIBLE_RESEARCH_ONLY",
        "checks": checks(),
        "quote_block_ordinal": block.ordinal,
        "locator": block.source_anchor,
        "quote": block.text,
        "context_block_ordinals": [block.ordinal],
        "legal_locator": "Synthetic section 1",
        "valid_from": "2026-09-05",
        "valid_to": "2026-09-05",
        "uncertainties": [],
    }
    directory = visible / "independent-source-review"

    def attest():
        hashes = {}
        hashes["INPUT-HASHES.json"] = put(
            directory,
            "INPUT-HASHES.json",
            [{"path": p, "sha256": h} for p, h in input_pins.items()],
        )
        hashes["IDENTITY-VERIFICATION.json"] = put(
            directory, "IDENTITY-VERIFICATION.json", [identity]
        )
        hashes["SOURCE-REVIEW.jsonl"] = put(directory, "SOURCE-REVIEW.jsonl", encoded(review))
        attestation = {
            "schema": "ge.visible.independent.source.review.attestation.v1",
            "reviewer_id": runner.REVIEWER,
            "professional_legal_sign_off": False,
            "legal_gold": False,
            "admitted": False,
            "files": hashes,
        }
        attestation_sha = put(directory, "REVIEW-ATTESTATION.json", attestation)
        return runner.ReviewPins(attestation_sha, hashes["SOURCE-REVIEW.jsonl"])

    pins = attest()
    return SimpleNamespace(
        visible=visible,
        pins=pins,
        attest=attest,
        input_pins=input_pins,
        source=source,
        proposition=prop,
        case=case,
        review=review,
        identity=identity,
        parsed=parsed,
        raw=raw,
        directory=directory,
    )


def bind_fixture(value):
    gate = runner.SourceReviewGate(value.visible, value.pins)
    scope = Scope(
        str(value.visible / "index-validation/stores/case-one"),
        "candidate_case_local",
        "SYNTHETIC_VISIBLE",
        value.case["case_id"],
    )
    source = runner.make_capture(gate, value.source, scope, value.review)
    derived = gate.bind(proposition=value.proposition, source=source, issue_id="issue-ENG-NOTICE")
    return gate, source, derived


def test_missing_review_and_missing_parent_readiness_fail_before_runtime(reviewed, monkeypatch):
    with pytest.raises(runner.ValidationHold, match="PARENT_READY"):
        runner.execute(
            owner_authorization=Path("unread"),
            pins=reviewed.pins,
            ready_reason="",
            parent_authorized=False,
        )
    with pytest.raises(runner.ValidationHold, match="MISSING"):
        runner.SourceReviewGate(reviewed.visible / "absent", reviewed.pins)
    import scripts.ge_auto_research_runtime as runtime

    monkeypatch.setattr(runner, "VISIBLE", reviewed.visible / "absent")
    monkeypatch.setattr(
        runtime, "PinnedEmbeddingSession", lambda: pytest.fail("model must not load")
    )
    with pytest.raises(runner.ValidationHold, match="MISSING"):
        runner.execute(
            owner_authorization=Path("unread"),
            pins=reviewed.pins,
            ready_reason="synthetic parent readiness",
            parent_authorized=True,
        )


def test_exact_attestation_derived_binding_and_original_inputs_preserved(reviewed):
    before = reviewed.proposition.copy()
    gate, source, derived = bind_fixture(reviewed)
    assert gate.verify_review(runner.REVIEWER, derived)
    assert derived["raw_review_sha256"] == digest(reviewed.review)
    assert derived["original_checks"] == reviewed.review["checks"]
    assert derived["checks"] == sorted(REVIEW_CHECKS)
    assert derived["affected_claim_sha256"] == digest(reviewed.proposition)
    assert derived["source_sha256"] == digest(source.raw)
    assert reviewed.proposition == before and reviewed.proposition["index_eligible"] is False
    assert not gate.verify_review(runner.REVIEWER, {**derived, "quote": "different quote"})
    assert not gate.verify_review(
        runner.REVIEWER, {**derived, "scope": {**derived["scope"], "case_id": "foreign"}}
    )
    assert not gate.verify_review("author", derived)
    _, _, _, receipt = runner.load_inputs(gate)
    assert receipt["actual_search_query_count"] == 1


@pytest.mark.parametrize(
    "mutation",
    [
        "hold",
        "missing_check",
        "uncertainty",
        "wrong_hash",
        "wrong_source",
        "rewritten_claim",
        "wrong_date",
        "wrong_jurisdiction",
    ],
)
def test_no_eligibility_from_weak_or_substituted_review(reviewed, mutation):
    if mutation == "hold":
        reviewed.review["decision"] = "HOLD"
    elif mutation == "missing_check":
        reviewed.review["checks"]["rights"]["status"] = "HOLD"
    elif mutation == "uncertainty":
        reviewed.review["uncertainties"] = ["commencement unresolved"]
    elif mutation == "wrong_hash":
        reviewed.review["original_proposition_sha256"] = digest(b"wrong")
    elif mutation == "wrong_source":
        reviewed.review["source_id"] = digest(b"different source")
    elif mutation == "rewritten_claim":
        reviewed.review["proposed_proposition"] = "A more convenient claim"
    elif mutation == "wrong_date":
        reviewed.review["as_of_date"] = "2026-09-06"
    else:
        reviewed.review["jurisdiction"] = "Texas"
    reviewed.pins = reviewed.attest()
    gate = runner.SourceReviewGate(reviewed.visible, reviewed.pins)
    if mutation == "hold":
        assert gate.eligible(reviewed.proposition) is False
    else:
        with pytest.raises(runner.ValidationHold):
            gate.eligible(reviewed.proposition)


def test_mutated_original_source_after_enrollment_invalidates_callback(reviewed):
    gate, _, derived = bind_fixture(reviewed)
    (reviewed.visible / "author-research" / reviewed.source["raw_path"]).write_bytes(
        b"changed raw bytes"
    )
    assert not gate.verify_review(runner.REVIEWER, derived)


def test_attestation_pins_cannot_be_replaced_or_self_accepted(reviewed):
    with pytest.raises(runner.ValidationHold, match="FILE_DIGEST"):
        runner.SourceReviewGate(
            reviewed.visible, replace(reviewed.pins, attestation_sha256=digest(b"another"))
        )
    attestation = json.loads((reviewed.directory / "REVIEW-ATTESTATION.json").read_bytes())
    attestation["files"].pop("INPUT-HASHES.json")
    new_sha = put(reviewed.directory, "REVIEW-ATTESTATION.json", attestation)
    with pytest.raises(runner.ValidationHold, match="UNATTESTED_FILE"):
        runner.SourceReviewGate(
            reviewed.visible, replace(reviewed.pins, attestation_sha256=new_sha)
        )


def test_reparse_mismatch_and_ny_missing_bytes_hold(reviewed):
    gate = runner.SourceReviewGate(reviewed.visible, reviewed.pins)
    scope = Scope(
        str(reviewed.visible / "index-validation/stores/case"),
        "candidate_case_local",
        "visible",
        "case-one",
    )
    with pytest.raises(runner.ValidationHold, match="RAW_SOURCE_MISSING"):
        runner.make_capture(
            gate, {**reviewed.source, "raw_path": None, "issue_id": "NY"}, scope, reviewed.review
        )
    with pytest.raises(runner.ValidationHold, match="NY_RAW_SOURCE_ROUTE"):
        runner.make_capture(gate, {**reviewed.source, "issue_id": "NY"}, scope, reviewed.review)
    saved_path = f"structural-review-input/{reviewed.source['source_id']}.json"
    saved = json.loads((reviewed.visible / saved_path).read_bytes())
    saved["parsed"]["body_blocks"][0]["text"] = "Altered extracted law"
    reviewed.input_pins[saved_path] = put(reviewed.visible, saved_path, saved)
    reviewed.pins = reviewed.attest()
    gate = runner.SourceReviewGate(reviewed.visible, reviewed.pins)
    with pytest.raises(runner.ValidationHold, match="REPARSE_CHANGED"):
        runner.make_capture(gate, reviewed.source, scope, reviewed.review)


def test_full_contracts_use_real_material_digests_and_zero_prebuild_rows(reviewed):
    gate, source, derived = bind_fixture(reviewed)
    pin = ModelPin("2" * 40, digest(b"synthetic verified files"), digest(b"synthetic recipe"))
    policy = ResearchPolicy(
        workspace=reviewed.visible,
        owner_instruction=b"synthetic authorization",
        expected_owner_instruction_sha256=digest(b"synthetic authorization"),
        scopes=[source.scope],
        model=pin,
        reviewers=[runner.REVIEWER],
        verify_review=gate.verify_review,
    )
    registry = ContractSchemaRegistry.from_project_root(runner.ROOT)
    toolchain = {
        key: digest({"synthetic-component": key})
        for key in (
            "parser_sha256",
            "chunker_sha256",
            "tokenizer_sha256",
            "embedding_model_sha256",
            "lexical_config_sha256",
            "vector_schema_sha256",
            "reranker_model_sha256",
        )
    }
    toolchain["ocr_sha256"] = None
    baseline = {"sources": [], "lexical_rows": 0, "vector_rows": 0, "nonproduction": True}
    value = runner.make_contracts(
        case=reviewed.case,
        proposition=reviewed.proposition,
        source=source,
        derived_review=derived,
        policy=policy,
        identity={"identity_sha256": digest(asdict(pin))},
        baseline=baseline,
        registry=registry,
        observed_at="2026-09-05T00:00:00+00:00",
        toolchain=toolchain,
    )
    lineage = runner.lineage_for(value, registry)
    assert lineage.query_plan_sha256 == digest(value["query_plan"])
    assert lineage.fact_snapshot_sha256 == value["facts"]["content_sha256"]
    assert value["facts"]["facts"] == [] and value["conversation"]["messages"] == []
    assert value["query_plan"]["data_intent"] == "KNOWLEDGE_ONLY"
    generation = value["knowledge_generation"]
    assert generation["sources"][0]["bytes_sha256"] == digest(source.raw)
    assert generation["sources"][0]["qualification_receipt_sha256"] == digest(derived)
    assert generation["counts"]["vector_rows"] == generation["counts"]["lexical_rows"] == 0
    assert generation["attestations"][-1]["status"] == "NOT_RUN"
    assert value["request"]["candidate_answer_generation"] is False


def test_create_only_output_and_cross_root_symlink_denial(reviewed):
    output = reviewed.visible / "index-validation"
    path = output / "kept.json"
    expected = runner.write_new(path, {"receipt": 1}, output=output)
    assert runner.write_new(path, {"receipt": 1}, output=output) == expected
    with pytest.raises(runner.ValidationHold, match="IMMUTABLE"):
        runner.write_new(path, {"receipt": 2}, output=output)
    with pytest.raises(runner.ValidationHold, match="CROSS_ROOT"):
        runner.write_new(reviewed.visible / "outside.json", {}, output=output)
    alias = output / "alias"
    alias.symlink_to(reviewed.visible, target_is_directory=True)
    with pytest.raises(runner.ValidationHold, match="SYMLINK"):
        runner.write_new(alias / "bad.json", {}, output=output)


def test_post_retrieval_callback_needs_exact_independent_packets(reviewed):
    base = reviewed.visible / "independent-claim-review"
    packet = {
        "gap": digest(b"gap"),
        "affected_claim_sha256": digest(reviewed.proposition),
        "retrieval_sha256": digest(b"synthetic retrieval"),
        "generation_sha256": digest(b"generation"),
        "lineage_sha256": digest(b"lineage"),
    }
    packet_path = reviewed.visible / "index-validation/claim-input.json"
    packet_sha = put(reviewed.visible, "index-validation/claim-input.json", packet)
    claim = {
        **packet,
        "proposition_id": "ENG-NOTICE",
        "reviewer_id": "independent-claim-context",
        "decision": "VERIFIED_AFFECTED_CLAIM",
        "material_omissions_checked": True,
        "contrary_authority_checked": True,
        "supported_chunk_ids": ["chunk-1"],
        "checks": checks({"affected_claim", "material_omissions", "contrary_authority"}),
    }
    review_sha = put(base, "CLAIM-REVIEW.jsonl", encoded(claim))
    attestation_sha = put(
        base,
        "REVIEW-ATTESTATION.json",
        {
            "reviewer_id": "independent-claim-context",
            "files": {
                "CLAIM-REVIEW.jsonl": review_sha,
                str(packet_path.relative_to(reviewed.visible)): packet_sha,
            },
        },
    )
    verifier = runner.claim_review_callback(
        visible=reviewed.visible,
        review_path=base / "CLAIM-REVIEW.jsonl",
        attestation_path=base / "REVIEW-ATTESTATION.json",
        review_sha256=review_sha,
        attestation_sha256=attestation_sha,
        reviewer_id="independent-claim-context",
        expected_packets={
            "ENG-NOTICE": {
                "path": str(packet_path.relative_to(reviewed.visible)),
                "sha256": packet_sha,
            }
        },
    )
    assert verifier("independent-claim-context", claim)
    assert not verifier(
        "independent-claim-context", {**claim, "affected_claim_sha256": digest(b"different")}
    )
    assert not verifier(runner.ACTOR, claim)
    packet_path.write_bytes(encoded({**packet, "gap": digest(b"modified input")}))
    assert not verifier("independent-claim-context", claim)


@pytest.mark.parametrize("same_case", [True, False])
def test_companion_context_requires_same_case_persisted_evidence(reviewed, same_case):
    output = reviewed.visible / "index-validation"
    companion = {
        "source_id": "source-companion",
        "raw_sha256": digest(b"raw-companion"),
        "parsed_sha256": digest(b"parsed-companion"),
        "context_block_ordinals": [2, 3],
    }
    reviews = {
        "main": {"companion_source_context": [companion]},
        "companion": {"decision": "ELIGIBLE_RESEARCH_ONLY", **companion},
    }
    outcomes = [
        {
            "case_id": "case-1",
            "source_id": "source-main",
            "proposition_id": "main",
            "state": "RETRIEVED_PENDING_CLAIM_REVIEW",
        },
        {
            "case_id": "case-1" if same_case else "case-2",
            "source_id": "source-companion",
            "proposition_id": "companion",
            "state": "RETRIEVED_PENDING_CLAIM_REVIEW",
        },
    ]
    queue = []
    for row in outcomes:
        key = row["proposition_id"]
        path = output / f"{key}.json"
        packet = {
            "retrieval_sha256": digest({"retrieval": key}),
            "generation_sha256": digest({"generation": key}),
            "supported_evidence": [
                {"text": "Synthetic context", "structural_chunk": {"block_ordinals": [2, 3]}}
            ],
        }
        packet_sha = runner.write_new(path, packet, output=output)
        queue.append({"proposition_id": key, "path": path.name, "sha256": packet_sha})
    complete = runner.reconcile_companions(
        output=output, outcomes=outcomes, queue=queue, reviews=reviews
    )
    if same_case:
        assert len(complete) == 2
        assert outcomes[0]["companion_source_count"] == 1
    else:
        assert outcomes[0]["state"] == "HOLD_REQUIRED_COMPANION_CONTEXT"
        assert len(complete) == 1
        partial = runner.obj(output / "propositions/main/CLAIM-REVIEW-BUNDLE.json", output)
        assert partial["all_required_source_context_retrieved"] is False
        assert partial["missing_companion_source_ids"] == [companion["source_id"]]


@pytest.mark.parametrize("change", [None, "parsed", "coverage", "missing_receipt"])
def test_exact_parser_revalidation_bridge(reviewed, change):
    name = f"structural-review-input/{reviewed.source['source_id']}.json"
    saved = runner.obj(reviewed.visible / name, reviewed.visible)
    saved["parser_sha256"] = digest(b"synthetic prior parser")
    reviewed.review["parser_sha256"] = saved["parser_sha256"]
    reviewed.input_pins[name] = put(reviewed.visible, name, saved)
    receipt = {
        "purpose": "IMPORT_ORDER_ONLY_CURRENT_IMPLEMENTATION_REPARSE",
        "current_parser_sha256": parser_binding(),
        "identical_parses": 1,
        "sources": [
            {
                "input_manifest_sha256": reviewed.input_pins[name],
                "parsed_sha256": saved["parsed_sha256"],
                "original_parser_sha256": saved["parser_sha256"],
            }
        ],
    }
    if change == "parsed":
        receipt["sources"][0]["parsed_sha256"] = digest(b"different parsed text")
    if change == "coverage":
        receipt["identical_parses"] = 2
    key = put(reviewed.visible, "structural-review-input/PARSER-REVALIDATION.json", receipt)
    reviewed.pins = replace(
        reviewed.attest(), parser_revalidation_sha256=None if change == "missing_receipt" else key
    )
    if change:
        with pytest.raises(runner.ValidationHold):
            bind_fixture(reviewed)
    else:
        gate, source, derived = bind_fixture(reviewed)
        assert source.parser_sha256 == parser_binding()
        assert derived["original_review_parser_sha256"] == saved["parser_sha256"]
        assert derived["parser_revalidation"]["receipt_sha256"] == key
        assert gate.verify_review(runner.REVIEWER, derived)


def test_held_companion_preserved_without_index_eligibility(reviewed):
    gate, source, derived = bind_fixture(reviewed)
    raw_review = dict(reviewed.review)
    raw_review["companion_source_context"] = [
        {
            "source_id": reviewed.source["source_id"],
            "raw_sha256": digest(reviewed.raw),
            "parsed_sha256": digest(asdict(reviewed.parsed)),
            "parser_sha256": parser_binding(),
            "context_block_ordinals": reviewed.review["context_block_ordinals"],
        }
    ]
    gate.reviews[reviewed.proposition["proposition_id"]]["decision"] = "HOLD"
    context = runner.companion_context(
        gate, raw_review, {reviewed.source["source_id"]: reviewed.source}
    )
    entry = context["companion_sources"][0]
    assert entry["structural_chunks"]
    assert entry["source_proposition_reviews"][0]["decision"] == "HOLD"
    assert entry["indexed_or_embedded_by_this_sidecar"] is False
    assert entry["legal_eligibility_changed"] is False
