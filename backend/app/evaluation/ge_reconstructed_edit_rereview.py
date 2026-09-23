"""Apply evidence-neutral AI-proposed edits and re-review their exact hashes.

This is a single changed-answer cycle.  A second requested edit is held rather
than looped.  Nothing here can complete qualified legal review or legal gold.
"""

from __future__ import annotations

import json
import zipfile
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .ge_currentness_packets import PROJECT_ROOT, load_jsonl, sha256_file, sha256_text
from .ge_phase2_progress import (
    ANSWER_RECONSTRUCTION_REQUIRED_BEFORE_QUALIFIED_REVIEW,
    AWAITING_QUALIFIED_REVIEWER,
    DOWNSTREAM_GATES,
    NOT_STARTED,
)
from .ge_reconstructed_independent_review import (
    BLOCKING_CLAIM_VERDICTS,
    CLAIM_VERDICTS,
    EXPECTED_SOURCE_SHA256,
    _canonical_hash,
    _normalize_claim,
    _normalize_review_row,
    _validate_review_row,
    _write_json_create,
    _write_jsonl_create,
    _write_text_create,
    source_path,
    validate_source,
)
from .ge_reconstructed_independent_review import (
    CAMPAIGN_ID as INITIAL_CAMPAIGN_ID,
)
from .ge_reconstructed_independent_review import (
    DEFAULT_OUTPUT as INITIAL_OUTPUT,
)

CAMPAIGN_ID = "LegalBot-GE-2026-09-04-reconstructed-edit-rereview-r1"
CAMPAIGN_VERSION = "legalbot.ge-reconstructed-edit-rereview.v1"
DEFAULT_OUTPUT = PROJECT_ROOT / "data/evaluations/general-enquiries" / CAMPAIGN_ID
DESKTOP_ZIP = (Path.home() / "Desktop") / f"{CAMPAIGN_ID}.zip"
FINAL_ROUTING_ZIP = (
    (Path.home() / "Desktop") / "LegalBot-GE-2026-09-04-qualified-review-routing-r1.zip"
)
FORBIDDEN = (
    "closest verified source",
    "complete controlling law for your facts",
    "cannot give a final merits view",
    "planner notes",
    "not yet qualified legal advice or legal gold",
    "your question is:",
    "evidence-bound candidate answer for owner review",
)

INSTRUCTIONS = """# Blind re-review of exact edited GE answers

Review only `EDITED-ANSWER-BLIND.jsonl` and this file. Do not inspect the
initial review, edit register, lineage file, prior recommendations, other
evaluation artifacts, or project status documents. Do not browse or retrieve
additional authorities.

This is an independent AI advisory review of changed exact answer hashes. For
every row, recompute the question and answer SHA-256 values, review every
material claim against its supplied exact quotation, and decide whether the
edited answer is now a direct, useful, evidence-bound answer suitable to send
to a governance-qualified human legal reviewer.

Use only:

- `RECOMMEND_APPROVE` when every material proposition is supported and no
  controlling evidence, currentness, jurisdiction, fact, completeness, or
  answer-construction problem remains.
- `RECOMMEND_HOLD` when any material uncertainty or omission remains.
- `RECOMMEND_REJECT` when the answer is materially wrong, contradicted, or uses
  a wrong route that the supplied evidence cannot cure.

Do not propose another edit in this cycle. If another edit is needed, use
`RECOMMEND_HOLD` with reason code `SECOND_EDIT_REQUIRED_STOP_NO_LOOP`.

Write:

- `EDITED-ANSWER-INDEPENDENT-REVIEW.jsonl`, one record per input row;
- `EDITED-CLAIM-REVIEW.jsonl`, one record per supplied material claim;
- `EDITED-REVIEW-ATTESTATION.json`.

Use the same review and claim fields defined by the input campaign’s review
contract. Routes are `HUMAN_QUALIFIED_REVIEW`,
`HOLD_OUTSIDE_QUALIFIED_REVIEW_QUEUE`, and
`REJECTED_FROM_QUALIFIED_REVIEW_QUEUE`. Record `reviewer_kind =
AI_MODEL_REVIEWER`, `reviewer_model = Codex fresh-context reviewer`, and
`professional_legal_sign_off = false`. Set qualified legal review, answer gold,
and training eligibility to false. Do not set admission, full-current-law
eligibility, sealed unseen, promotion, or live.
"""


def _zip_create(destination: Path, source: Path, files: Sequence[Path]) -> str:
    if destination.exists():
        raise RuntimeError(f"refusing to replace existing zip: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            archive.write(path, arcname=str(Path(source.name) / path.relative_to(source)))
    return sha256_file(destination)


def prepare_campaign(
    *, project_root: Path = PROJECT_ROOT, output: Path = DEFAULT_OUTPUT
) -> dict[str, Any]:
    if output.exists():
        raise RuntimeError(f"campaign already exists: {output}")
    initial_state = INITIAL_OUTPUT / "STATE-TRANSITION-RECEIPT.json"
    if not initial_state.is_file():
        raise RuntimeError("initial reconstructed independent review is not finalized")
    source_file = source_path(project_root)
    source_rows = load_jsonl(source_file)
    validate_source(source_rows, source_file)
    source_by_id = {str(row["case_id"]): row for row in source_rows}
    edits = load_jsonl(INITIAL_OUTPUT / "EDIT-REGISTER.jsonl")
    if not edits:
        raise RuntimeError("initial independent review has no changed answers to re-review")
    edited_rows: list[dict[str, Any]] = []
    lineage: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []
    for edit in edits:
        case_id = str(edit.get("case_id") or "")
        source = source_by_id.get(case_id)
        if source is None:
            raise RuntimeError(f"edit references an unknown case: {case_id}")
        proposed = str(edit.get("proposed_final_answer") or "").strip()
        if not proposed:
            raise RuntimeError(f"edit has no proposed final answer: {case_id}")
        old_hash = str(source["candidate_answer_hash"])
        new_hash = sha256_text(proposed)
        if new_hash == old_hash:
            raise RuntimeError(f"edit did not change the answer hash: {case_id}")
        forbidden = [marker for marker in FORBIDDEN if marker in proposed.casefold()]
        if forbidden:
            raise RuntimeError(f"edited answer contains forbidden wrapper text: {case_id}")
        row = dict(source)
        row["candidate_answer"] = proposed
        row["candidate_answer_hash"] = new_hash
        row["reviewed_answer_hash"] = new_hash
        row["packet_hash"] = _canonical_hash(
            {
                "case_id": case_id,
                "question_hash": row["question_hash"],
                "candidate_answer_hash": new_hash,
                "evidence_manifest_hash": row["reviewed_evidence_hash"],
                "working_disposition": row.get("working_disposition"),
            }
        )
        row["prior_candidate_answer_hash"] = old_hash
        edited_rows.append(row)
        lineage.append(
            {
                "schema": "legalbot.ge-reconstructed-edit-lineage.v1",
                "case_id": case_id,
                "review_ordinal": row["review_ordinal"],
                "initial_review_campaign_id": INITIAL_CAMPAIGN_ID,
                "old_answer_hash": old_hash,
                "new_answer_hash": new_hash,
                "question_hash": row["question_hash"],
                "evidence_manifest_hash": row["reviewed_evidence_hash"],
                "evidence_unchanged": True,
                "question_unchanged": True,
                "new_legal_propositions_authorised": False,
            }
        )
        checks.append(
            {
                "schema": "legalbot.ge-reconstructed-edit-check.v1",
                "case_id": case_id,
                "old_answer_hash": old_hash,
                "new_answer_hash": new_hash,
                "hash_changed": True,
                "question_hash_unchanged": True,
                "evidence_hash_unchanged": True,
                "forbidden_wrapper_text": False,
                "nonempty_answer": True,
                "requires_independent_re_review": True,
            }
        )
    edited_rows.sort(key=lambda row: int(row["review_ordinal"]))
    lineage.sort(key=lambda row: int(row["review_ordinal"]))
    checks.sort(key=lambda row: int(source_by_id[str(row["case_id"])]["review_ordinal"]))
    output.mkdir(parents=True, exist_ok=False)
    _write_text_create(output / "EDITED-INDEPENDENT-REVIEW-INSTRUCTIONS.md", INSTRUCTIONS)
    _write_jsonl_create(output / "EDITED-ANSWER-BLIND.jsonl", edited_rows)
    _write_jsonl_create(output / "EDIT-LINEAGE.jsonl", lineage)
    _write_jsonl_create(output / "CHANGED-ANSWER-CHECKS.jsonl", checks)
    manifest = {
        "schema": "legalbot.ge-reconstructed-edit-rereview-input.v1",
        "campaign_id": CAMPAIGN_ID,
        "campaign_version": CAMPAIGN_VERSION,
        "initial_review_campaign_id": INITIAL_CAMPAIGN_ID,
        "source_reconstructed_workbook_sha256": EXPECTED_SOURCE_SHA256,
        "edited_answer_rows": len(edited_rows),
        "material_claim_rows": sum(len(row.get("material_claims") or []) for row in edited_rows),
        "edited_answer_blind_sha256": sha256_file(output / "EDITED-ANSWER-BLIND.jsonl"),
        "reviewer_kind": "AI_MODEL_REVIEWER",
        "professional_legal_sign_off": False,
        "qualified_legal_review": NOT_STARTED,
    }
    _write_json_create(output / "INPUT-MANIFEST.json", manifest)
    return manifest


def _qualified_decision_template(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "schema": "legalbot.ge-qualified-review-decision-template.v1",
            "case_id": row["case_id"],
            "review_ordinal": row["review_ordinal"],
            "question_hash": row["question_hash"],
            "candidate_answer_hash": row["candidate_answer_hash"],
            "evidence_manifest_hash": row["reviewed_evidence_hash"],
            "packet_hash": row["packet_hash"],
            "qualified_review_decision": "",
            "approved_answer_hash": "",
            "approved_evidence_hash": "",
            "exact_approved_edit": "",
            "reviewer_name": "",
            "reviewer_qualification": "",
            "reviewer_signature": "",
            "review_timestamp": "",
            "professional_legal_sign_off": None,
        }
        for row in rows
    ]


def _adapt_review(review: Mapping[str, Any], source: Mapping[str, Any]) -> dict[str, Any]:
    """Adapt field names without changing the reviewer's recommendation."""

    decision = str(review.get("ai_recommended_decision") or review.get("recommendation") or "")
    reasons = review.get("reasons")
    if not isinstance(reasons, list):
        rationale = str(review.get("rationale") or "").strip()
        reasons = [rationale] if rationale else []
    row = {
        **dict(review),
        "schema": "legalbot.ge-reconstructed-edit-independent-review.v1",
        "case_id": source["case_id"],
        "review_ordinal": source["review_ordinal"],
        "topic": source["topic"],
        "question_hash": review.get("question_hash") or source["question_hash"],
        "candidate_answer_hash": review.get("candidate_answer_hash")
        or review.get("reviewed_answer_hash"),
        "evidence_manifest_hash": review.get("evidence_manifest_hash")
        or review.get("reviewed_evidence_hash"),
        "packet_hash": review.get("packet_hash") or source["packet_hash"],
        "ai_recommended_decision": decision,
        "decision_reason_codes": review.get("decision_reason_codes")
        or review.get("reason_codes")
        or [],
        "reasons": reasons,
        "answer_readiness": review.get("answer_readiness")
        or ("READY" if decision == "RECOMMEND_APPROVE" else "NOT_READY"),
        "currentness_verdict": review.get("currentness_verdict")
        or ("RESOLVED" if source.get("currentness_result") == "PASS" else "UNRESOLVED"),
        "jurisdiction_verdict": review.get("jurisdiction_verdict")
        or ("IN_SCOPE" if source.get("jurisdiction_result") == "PASS" else "UNRESOLVED"),
        "material_omissions": review.get("material_omissions") or [],
        "missing_facts": review.get("missing_facts") or [],
        "risk_flags": review.get("risk_flags") or [],
        "next_route": review.get("next_route") or review.get("route"),
        "review_complete_for_exact_candidate_hash": True,
        "reviewer_kind": "AI_MODEL_REVIEWER",
        "professional_legal_sign_off": False,
        "qualified_legal_review_complete": False,
        "answer_legal_gold": False,
        "training_eligible": False,
    }
    return _normalize_review_row(row, source)


def _adapt_claim(
    claim: Mapping[str, Any], source: Mapping[str, Any], source_claim: Mapping[str, Any]
) -> dict[str, Any]:
    row = {
        **dict(claim),
        "verdict": claim.get("verdict") or claim.get("claim_assessment"),
        "reason": claim.get("reason") or claim.get("rationale") or "",
    }
    return _normalize_claim(row, source, source_claim)


def finalize_campaign(
    *, project_root: Path = PROJECT_ROOT, output: Path = DEFAULT_OUTPUT
) -> dict[str, Any]:
    if (output / "STATE-TRANSITION-RECEIPT.json").exists():
        raise RuntimeError("campaign is already finalized")
    input_path = output / "EDITED-ANSWER-BLIND.jsonl"
    review_path = output / "EDITED-ANSWER-INDEPENDENT-REVIEW.jsonl"
    claim_path = output / "EDITED-CLAIM-REVIEW.jsonl"
    attestation_path = output / "EDITED-REVIEW-ATTESTATION.json"
    for path in (input_path, review_path, claim_path, attestation_path):
        if not path.is_file():
            raise RuntimeError(f"missing edit re-review artifact: {path.name}")
    edited = load_jsonl(input_path)
    raw_reviews = load_jsonl(review_path)
    raw_claims = load_jsonl(claim_path)
    attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
    if str(
        attestation.get("input_sha256") or attestation.get("input_shard_sha256") or ""
    ) != sha256_file(input_path):
        raise RuntimeError("edited review attestation input hash mismatch")
    if len(raw_reviews) != len(edited):
        raise RuntimeError("edited review row count mismatch")
    reviews = [_adapt_review(review, row) for review, row in zip(raw_reviews, edited, strict=True)]
    for review, row in zip(reviews, edited, strict=True):
        _validate_review_row(review, row)
        if review["ai_recommended_decision"] == "RECOMMEND_APPROVE_WITH_EDIT":
            raise RuntimeError(f"second edit request must be HOLD: {review['case_id']}")
    edited_by_id = {str(row["case_id"]): row for row in edited}
    source_claim_by_key = {
        (str(row["case_id"]), str(claim["claim_id"])): claim
        for row in edited
        for claim in row.get("material_claims") or []
    }
    expected_claims = set(source_claim_by_key)
    actual_claims = {
        (str(claim.get("case_id") or ""), str(claim.get("claim_id") or "")) for claim in raw_claims
    }
    if actual_claims != expected_claims or len(raw_claims) != len(expected_claims):
        raise RuntimeError("edited claim-review coverage mismatch")
    claims = [
        _adapt_claim(
            claim,
            edited_by_id[str(claim.get("case_id") or "")],
            source_claim_by_key[
                (str(claim.get("case_id") or ""), str(claim.get("claim_id") or ""))
            ],
        )
        for claim in raw_claims
    ]
    for claim in claims:
        if str(claim.get("verdict") or "") not in CLAIM_VERDICTS:
            raise RuntimeError(
                f"invalid edited claim verdict: {claim.get('case_id')}:{claim.get('claim_id')}"
            )
        if claim.get("professional_legal_sign_off") is not False:
            raise RuntimeError(f"edited claim sign-off leaked: {claim.get('case_id')}")
    claims_by_case: dict[str, list[dict[str, Any]]] = {}
    for claim in claims:
        claims_by_case.setdefault(str(claim["case_id"]), []).append(claim)
    for review in reviews:
        if review["ai_recommended_decision"] == "RECOMMEND_APPROVE" and any(
            str(claim.get("verdict") or "") in BLOCKING_CLAIM_VERDICTS
            for claim in claims_by_case[str(review["case_id"])]
        ):
            raise RuntimeError(f"edited approval has a blocking claim: {review['case_id']}")
    initial_ready = load_jsonl(INITIAL_OUTPUT / "QUALIFIED-REVIEW-READY-BLIND.jsonl")
    initial_nonready = load_jsonl(INITIAL_OUTPUT / "NONREADY-ROUTING.jsonl")
    edited_ids = set(edited_by_id)
    changed_ready_ids = {
        str(review["case_id"])
        for review in reviews
        if review["ai_recommended_decision"] == "RECOMMEND_APPROVE"
    }
    changed_ready = [dict(edited_by_id[case_id]) for case_id in changed_ready_ids]
    final_ready = [dict(row) for row in initial_ready] + changed_ready
    final_ready.sort(key=lambda row: int(row["review_ordinal"]))
    if len({str(row["case_id"]) for row in final_ready}) != len(final_ready):
        raise RuntimeError("duplicate case in final qualified-review routing")
    final_nonready = [row for row in initial_nonready if str(row["case_id"]) not in edited_ids]
    final_nonready.extend(
        {
            "case_id": review["case_id"],
            "review_ordinal": review["review_ordinal"],
            "topic": review.get("topic"),
            "candidate_answer_hash": review["candidate_answer_hash"],
            "ai_recommended_decision": review["ai_recommended_decision"],
            "reasons": review.get("reasons") or [],
            "next_route": review.get("next_route"),
        }
        for review in reviews
        if review["ai_recommended_decision"] != "RECOMMEND_APPROVE"
    )
    final_nonready.sort(key=lambda row: int(row["review_ordinal"]))
    if len(final_ready) + len(final_nonready) != 330:
        raise RuntimeError("final routing does not cover 330 cases")
    _write_jsonl_create(output / "QUALIFIED-REVIEW-READY-BLIND.jsonl", final_ready)
    _write_jsonl_create(
        output / "QUALIFIED-REVIEW-DECISION-TEMPLATE.jsonl",
        _qualified_decision_template(final_ready),
    )
    _write_jsonl_create(output / "NONREADY-ROUTING.jsonl", final_nonready)
    counts = Counter(str(review["ai_recommended_decision"]) for review in reviews)
    summary = {
        "schema": "legalbot.ge-reconstructed-edit-rereview-summary.v1",
        "campaign_id": CAMPAIGN_ID,
        "edited_rows_reviewed": len(reviews),
        "edited_claim_rows_reviewed": len(claims),
        "edited_recommendation_counts": dict(counts),
        "initial_exact_ready_count": len(initial_ready),
        "edited_exact_ready_count": len(changed_ready),
        "final_qualified_review_ready_count": len(final_ready),
        "final_nonready_count": len(final_nonready),
        "professional_legal_sign_off": False,
        "qualified_legal_review": NOT_STARTED,
        "answer_legal_gold": NOT_STARTED,
    }
    _write_json_create(output / "REVIEW-SUMMARY.json", summary)
    overall_state = (
        AWAITING_QUALIFIED_REVIEWER
        if final_ready
        else ANSWER_RECONSTRUCTION_REQUIRED_BEFORE_QUALIFIED_REVIEW
    )
    state = {
        "schema": "legalbot.ge-reconstructed-edit-rereview-state.v1",
        "campaign_id": CAMPAIGN_ID,
        "campaign_version": CAMPAIGN_VERSION,
        "overall_progress": True,
        "overall_state": overall_state,
        "initial_independent_review": "COMPLETE",
        "changed_answer_independent_rereview": "COMPLETE",
        "single_edit_cycle_complete": True,
        "qualified_review_ready_count": len(final_ready),
        "reviewer_kind": "AI_MODEL_REVIEWER",
        "professional_legal_sign_off": False,
        "human_case_by_case_review": "NOT_PERFORMED",
        "qualified_legal_review": NOT_STARTED,
        "answer_legal_gold": NOT_STARTED,
        **{gate: NOT_STARTED for gate in DOWNSTREAM_GATES},
        "full_331_guard": "NO_OP_UNCHANGED_INPUTS",
        "private_306_bank": "SEALED_NOT_OPENED",
        "review_timestamp": datetime.now(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
    }
    _write_json_create(output / "STATE-TRANSITION-RECEIPT.json", state)
    tests = {
        "source_reconstruction_hash_unchanged": sha256_file(source_path(project_root))
        == EXPECTED_SOURCE_SHA256,
        "all_changed_hashes_reviewed": len(reviews) == len(edited),
        "all_changed_claims_reviewed": len(claims) == len(expected_claims),
        "no_second_edit_loop": all(
            review["ai_recommended_decision"] != "RECOMMEND_APPROVE_WITH_EDIT" for review in reviews
        ),
        "final_routing_covers_330": len(final_ready) + len(final_nonready) == 330,
        "no_professional_sign_off": all(
            review.get("professional_legal_sign_off") is False for review in reviews
        ),
        "qualified_review_not_completed": True,
        "gold_not_started": True,
        "training_not_started": True,
    }
    _write_json_create(
        output / "TEST-RECEIPT.json",
        {
            "schema": "legalbot.ge-reconstructed-edit-rereview-test.v1",
            "tests": tests,
            "pass": all(tests.values()),
        },
    )
    _write_text_create(
        output / "QUALIFIED-REVIEW-HANDOFF.md",
        "\n".join(
            [
                "# Qualified legal-review handoff",
                "",
                f"This package contains {len(final_ready)} exact answer hashes that passed AI advisory blind review.",
                "A governance-qualified human reviewer must review each exact answer and evidence hash.",
                "Complete only `APPROVE`, `APPROVE_WITH_EDIT`, `HOLD`, or `REJECT` in the decision template.",
                "Any human edit creates another answer hash and requires changed-answer verification.",
                "Do not populate identity, qualification, signature, or professional sign-off unless the named reviewer actually performs and signs the review.",
                "Qualified legal review, answer gold, training, sealed unseen, promotion, and live remain NOT_STARTED.",
                "",
            ]
        ),
    )
    pack_files = [path for path in sorted(output.iterdir()) if path.is_file()]
    hashes = {path.name: sha256_file(path) for path in pack_files}
    _write_json_create(
        output / "ARTIFACT-SHA256-REGISTER.json",
        {
            "schema": "legalbot.ge-reconstructed-edit-rereview-hashes.v1",
            "campaign_id": CAMPAIGN_ID,
            "artifacts": hashes,
        },
    )
    pack_files = [path for path in sorted(output.iterdir()) if path.is_file()]
    pack_zip_hash = _zip_create(DESKTOP_ZIP, output, pack_files)
    routing_files = [
        output / "QUALIFIED-REVIEW-READY-BLIND.jsonl",
        output / "QUALIFIED-REVIEW-DECISION-TEMPLATE.jsonl",
        output / "QUALIFIED-REVIEW-HANDOFF.md",
        output / "NONREADY-ROUTING.jsonl",
        output / "REVIEW-SUMMARY.json",
        output / "STATE-TRANSITION-RECEIPT.json",
        output / "TEST-RECEIPT.json",
    ]
    routing_zip_hash = _zip_create(FINAL_ROUTING_ZIP, output, routing_files)
    return {
        "campaign_id": CAMPAIGN_ID,
        "output": str(output),
        "pack_zip": str(DESKTOP_ZIP),
        "pack_zip_sha256": pack_zip_hash,
        "routing_zip": str(FINAL_ROUTING_ZIP),
        "routing_zip_sha256": routing_zip_hash,
        "summary": summary,
        "state": state,
    }
