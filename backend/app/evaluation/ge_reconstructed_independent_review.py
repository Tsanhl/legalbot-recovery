"""Prepare and finalize blind review of reconstructed GE answer hashes.

The reviewer outputs are AI advisory evidence only.  This module cannot set
qualified legal review, legal gold, training, unseen, promotion, or live.
"""

from __future__ import annotations

import hashlib
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

CAMPAIGN_ID = "LegalBot-GE-2026-09-04-reconstructed-independent-review-r1"
CAMPAIGN_VERSION = "legalbot.ge-reconstructed-independent-review.v1"
SOURCE_CAMPAIGN_ID = "LegalBot-GE-2026-09-03-answer-reconstruction-r1"
SOURCE_RELATIVE = Path("data/evaluations/general-enquiries") / SOURCE_CAMPAIGN_ID
SOURCE_FILENAME = "REVISED-QUALIFIED-REVIEW-WORKBOOK-BLIND.jsonl"
EXPECTED_SOURCE_SHA256 = "5868b18ba699bd8fec2245da719a479e82ceb406aed600e94244941f3922ceb8"
DEFAULT_OUTPUT = PROJECT_ROOT / "data/evaluations/general-enquiries" / CAMPAIGN_ID
DESKTOP_ZIP = (Path.home() / "Desktop") / f"{CAMPAIGN_ID}.zip"
ROUTING_ZIP = (
    (Path.home() / "Desktop")
    / "LegalBot-GE-2026-09-04-qualified-review-routing-initial-r1.zip"
)
SHARD_COUNT = 8

DECISIONS = {
    "RECOMMEND_APPROVE",
    "RECOMMEND_APPROVE_WITH_EDIT",
    "RECOMMEND_HOLD",
    "RECOMMEND_REJECT",
}
CLAIM_VERDICTS = {
    "SUPPORTED",
    "PARTIALLY_SUPPORTED",
    "UNSUPPORTED",
    "CONTRADICTED",
    "UNCERTAIN",
    "NOT_RELIED_ON_BY_ANSWER",
}
BLOCKING_CLAIM_VERDICTS = {
    "PARTIALLY_SUPPORTED",
    "UNSUPPORTED",
    "CONTRADICTED",
    "UNCERTAIN",
}

INSTRUCTIONS = """# Independent blind review of reconstructed GE answers

Review only the assigned `INPUT-SHARD-XX.jsonl` and this instruction file for
the legal assessment. Do not inspect any earlier ChatGPT, Grok, advisory,
qualified-review, reconstruction, progression, or answer-gold output. Do not
browse or retrieve additional authorities. The supplied question, answer,
material-claim quotations, locators, evidence identities, and status fields are
the complete review record.

This is a de-novo AI advisory review of exact revised answer hashes. You are not
a solicitor, barrister, or governance-qualified human reviewer. Record:

    reviewer_kind = AI_MODEL_REVIEWER
    reviewer_model = Codex fresh-context reviewer
    professional_legal_sign_off = false

For every row:

1. Recompute SHA-256 of the UTF-8 question and candidate answer and compare them
   with `question_hash` and `candidate_answer_hash`.
2. Review the answer as text actually proposed for signature. Do not let
   `progression_disposition`, `working_disposition`, or `risk_tier` override the
   answer and supplied evidence.
3. Review every material claim separately against its exact supplied quotation.
   A shared subject, source title, allegation, background passage, or loosely
   related rule is not support.
4. Check whether the answer directly answers the question; accurately describes
   the supplied rule; avoids unsupported application; states material factual,
   jurisdictional, and currentness limits; gives proportionate practical next
   steps; and does not present a source digest as a finished legal answer.
5. Do not infer currentness, commencement, later treatment, jurisdiction, or
   territorial application where the packet does not establish it.

Decision standard:

- `RECOMMEND_APPROVE`: the exact answer is direct and useful; all material
  propositions are supported; no controlling omission, contradiction, wrong
  route, or unresolved currentness/jurisdiction issue prevents review; and no
  text change is needed.
- `RECOMMEND_APPROVE_WITH_EDIT`: only an exact, evidence-neutral edit is needed.
  Supply the complete proposed final answer. Any edited text receives a new hash
  and must be independently re-reviewed before human qualified review.
- `RECOMMEND_HOLD`: a material evidence, currentness, jurisdiction, fact,
  completeness, or answer-construction issue remains.
- `RECOMMEND_REJECT`: the answer is materially wrong or contradicted, or uses a
  wrong authority route that cannot be cured within the supplied evidence.

Output files for shard XX:

- `REVIEW-PART-XX.jsonl`: one record per input row, in input order.
- `CLAIM-REVIEW-PART-XX.jsonl`: one record for every supplied material claim.
- `EDIT-REGISTER-PART-XX.jsonl`: one record for every
  `RECOMMEND_APPROVE_WITH_EDIT` row; otherwise an empty file is valid.
- `PART-ATTESTATION-XX.json`: counts, exact input shard SHA-256, reviewer fields,
  and a statement that no other evaluation artifacts were used.

Each review record must contain:

`schema`, `case_id`, `review_ordinal`, `topic`, `reviewer_kind`,
`reviewer_model`, `professional_legal_sign_off`, `question_hash`,
`candidate_answer_hash`, `evidence_manifest_hash` (copy
`reviewed_evidence_hash`), `packet_hash`, `input_hash_validation`,
`answer_readiness`, `ai_recommended_decision`, `decision_reason_codes`,
`reasons`, `currentness_verdict`, `jurisdiction_verdict`,
`material_claim_count`, `material_omissions`, `missing_facts`, `risk_flags`,
`next_route`, `review_complete_for_exact_candidate_hash`,
`qualified_legal_review_complete`, `answer_legal_gold`, and
`training_eligible`.

Use these route values:

- approve: `HUMAN_QUALIFIED_REVIEW`
- approve with edit: `APPLY_EDIT_HASH_AND_REVIEW_CHANGED_ANSWER`
- hold: `HOLD_OUTSIDE_QUALIFIED_REVIEW_QUEUE`
- reject: `REJECTED_FROM_QUALIFIED_REVIEW_QUEUE`

Each claim record must copy the case ID, claim ID, materiality, proposition,
source title, locator, and evidence-span SHA-256; then add `verdict`, `reason`,
and the reviewer fields. Claim verdicts are `SUPPORTED`,
`PARTIALLY_SUPPORTED`, `UNSUPPORTED`, `CONTRADICTED`, or `UNCERTAIN`.

Do not set qualified review, gold, admission, full-current-law eligibility,
training, sealed unseen, promotion, or live. Do not fabricate professional
identity or qualification. Do not modify the input shard or any existing file.
"""


def _write_text_create(path: Path, value: str) -> None:
    if path.exists():
        raise RuntimeError(f"refusing to replace existing artifact: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def _write_json_create(path: Path, value: Any) -> None:
    _write_text_create(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def _write_jsonl_create(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    _write_text_create(
        path,
        "".join(json.dumps(dict(row), ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
    )


def _canonical_hash(value: Mapping[str, Any]) -> str:
    payload = json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def source_path(project_root: Path = PROJECT_ROOT) -> Path:
    return project_root / SOURCE_RELATIVE / SOURCE_FILENAME


def validate_source(rows: Sequence[Mapping[str, Any]], path: Path) -> None:
    if sha256_file(path) != EXPECTED_SOURCE_SHA256:
        raise RuntimeError("reconstructed blind workbook hash changed")
    if len(rows) != 330:
        raise RuntimeError(f"expected 330 reconstructed rows, found {len(rows)}")
    case_ids = [str(row.get("case_id") or "") for row in rows]
    if len(set(case_ids)) != 330 or any(not case_id for case_id in case_ids):
        raise RuntimeError("reconstructed workbook case IDs are missing or duplicated")
    for row in rows:
        case_id = str(row["case_id"])
        if sha256_text(str(row.get("question") or "")) != str(row.get("question_hash") or ""):
            raise RuntimeError(f"question hash mismatch: {case_id}")
        if sha256_text(str(row.get("candidate_answer") or "")) != str(
            row.get("candidate_answer_hash") or ""
        ):
            raise RuntimeError(f"candidate answer hash mismatch: {case_id}")


def prepare_campaign(
    *, project_root: Path = PROJECT_ROOT, output: Path = DEFAULT_OUTPUT
) -> dict[str, Any]:
    if output.exists():
        raise RuntimeError(f"campaign already exists: {output}")
    source = source_path(project_root)
    rows = load_jsonl(source)
    validate_source(rows, source)
    output.mkdir(parents=True, exist_ok=False)
    _write_text_create(output / "INDEPENDENT-REVIEW-INSTRUCTIONS.md", INSTRUCTIONS)
    shards: list[dict[str, Any]] = []
    for shard_index in range(SHARD_COUNT):
        shard_rows = rows[shard_index::SHARD_COUNT]
        filename = f"INPUT-SHARD-{shard_index + 1:02d}.jsonl"
        path = output / filename
        _write_jsonl_create(path, shard_rows)
        shards.append(
            {
                "shard": shard_index + 1,
                "filename": filename,
                "rows": len(shard_rows),
                "first_review_ordinal": shard_rows[0]["review_ordinal"],
                "last_review_ordinal": shard_rows[-1]["review_ordinal"],
                "sha256": sha256_file(path),
            }
        )
    manifest = {
        "schema": "legalbot.ge-reconstructed-independent-review-input.v1",
        "campaign_id": CAMPAIGN_ID,
        "campaign_version": CAMPAIGN_VERSION,
        "source_campaign_id": SOURCE_CAMPAIGN_ID,
        "source_filename": SOURCE_FILENAME,
        "source_sha256": sha256_file(source),
        "rows": len(rows),
        "claims": sum(len(row.get("material_claims") or []) for row in rows),
        "shard_count": SHARD_COUNT,
        "shards": shards,
        "reviewer_kind": "AI_MODEL_REVIEWER",
        "professional_legal_sign_off": False,
        "qualified_legal_review": NOT_STARTED,
    }
    _write_json_create(output / "INPUT-MANIFEST.json", manifest)
    _write_json_create(
        output / "RUN-STATUS.json",
        {
            "schema": "legalbot.ge-reconstructed-independent-review-status.v1",
            "campaign_id": CAMPAIGN_ID,
            "state": "BLIND_SHARDS_PREPARED_REVIEW_RUNNING",
            "qualified_legal_review": NOT_STARTED,
            "answer_legal_gold": NOT_STARTED,
            "professional_legal_sign_off": False,
        },
    )
    return manifest


def _part_paths(output: Path, shard: int) -> tuple[Path, Path, Path, Path]:
    suffix = f"{shard:02d}"
    return (
        output / f"REVIEW-PART-{suffix}.jsonl",
        output / f"CLAIM-REVIEW-PART-{suffix}.jsonl",
        output / f"EDIT-REGISTER-PART-{suffix}.jsonl",
        output / f"PART-ATTESTATION-{suffix}.json",
    )


def _validate_review_row(review: Mapping[str, Any], source: Mapping[str, Any]) -> None:
    case_id = str(source.get("case_id") or "")
    if str(review.get("case_id") or "") != case_id:
        raise RuntimeError(f"review case mismatch: {case_id}")
    expected = {
        "question_hash": str(source.get("question_hash") or ""),
        "candidate_answer_hash": str(source.get("candidate_answer_hash") or ""),
        "evidence_manifest_hash": str(source.get("reviewed_evidence_hash") or ""),
        "packet_hash": str(source.get("packet_hash") or ""),
    }
    for key, value in expected.items():
        if str(review.get(key) or "") != value:
            raise RuntimeError(f"{key} mismatch: {case_id}")
    if review.get("reviewer_kind") != "AI_MODEL_REVIEWER":
        raise RuntimeError(f"reviewer kind mismatch: {case_id}")
    if review.get("professional_legal_sign_off") is not False:
        raise RuntimeError(f"professional sign-off leaked: {case_id}")
    if review.get("qualified_legal_review_complete") is not False:
        raise RuntimeError(f"qualified review leaked: {case_id}")
    if review.get("answer_legal_gold") is not False or review.get("training_eligible") is not False:
        raise RuntimeError(f"gold or training leaked: {case_id}")
    decision = str(review.get("ai_recommended_decision") or "")
    if decision not in DECISIONS:
        raise RuntimeError(f"invalid decision {decision!r}: {case_id}")
    validation = review.get("input_hash_validation")
    if not isinstance(validation, Mapping) or not all(
        validation.get(key) is True
        for key in (
            "question_hash_matches",
            "candidate_answer_hash_matches",
            "claim_and_evidence_reference_sets_match",
        )
    ):
        raise RuntimeError(f"input hash validation failed: {case_id}")
    if review.get("review_complete_for_exact_candidate_hash") is not True:
        raise RuntimeError(f"review not complete: {case_id}")


def _normalize_review_row(review: Mapping[str, Any], source: Mapping[str, Any]) -> dict[str, Any]:
    """Canonicalize reviewer formatting without changing its substantive decision."""

    row = dict(review)
    claim_spans = {
        str(claim.get("evidence_span_sha256") or "")
        for claim in source.get("material_claims") or []
        if str(claim.get("evidence_span_sha256") or "")
    }
    evidence_spans = {
        str(evidence.get("evidence_span_sha256") or "")
        for evidence in source.get("evidence_references") or []
        if str(evidence.get("evidence_span_sha256") or "")
    }
    row["input_hash_validation"] = {
        "question_hash_matches": sha256_text(str(source.get("question") or ""))
        == str(source.get("question_hash") or ""),
        "candidate_answer_hash_matches": sha256_text(str(source.get("candidate_answer") or ""))
        == str(source.get("candidate_answer_hash") or ""),
        "claim_and_evidence_reference_sets_match": claim_spans.issubset(evidence_spans),
    }
    row["material_claim_count"] = len(source.get("material_claims") or [])
    return row


def _normalize_edit(edit: Mapping[str, Any], source: Mapping[str, Any]) -> dict[str, Any]:
    proposed = str(edit.get("proposed_final_answer") or "")
    return {
        **dict(edit),
        "schema": "legalbot.ge-reconstructed-independent-edit-register.v1",
        "case_id": source["case_id"],
        "review_ordinal": source["review_ordinal"],
        "original_answer_hash": source["candidate_answer_hash"],
        "proposed_final_answer": proposed,
        "proposed_final_answer_hash": sha256_text(proposed),
        "material_edit": bool(edit.get("material_edit", True)),
        "re_review_required": True,
        "new_legal_propositions_authorised": False,
        "reviewer_kind": "AI_MODEL_REVIEWER",
        "professional_legal_sign_off": False,
        "qualified_legal_review_complete": False,
        "answer_legal_gold": False,
        "training_eligible": False,
    }


def _normalize_claim(
    claim: Mapping[str, Any], source: Mapping[str, Any], source_claim: Mapping[str, Any]
) -> dict[str, Any]:
    """Bind reviewer reasoning to the immutable source claim identity."""

    return {
        **dict(claim),
        "schema": "legalbot.ge-reconstructed-independent-claim-review.v1",
        "case_id": source["case_id"],
        "review_ordinal": source["review_ordinal"],
        "topic": source["topic"],
        "claim_id": source_claim["claim_id"],
        "materiality": source_claim["materiality"],
        "proposition": source_claim["proposition"],
        "source_title": source_claim["title"],
        "locator": source_claim["locator"],
        "evidence_span_sha256": source_claim["evidence_span_sha256"],
        "reviewer_kind": "AI_MODEL_REVIEWER",
        "professional_legal_sign_off": False,
    }


def _zip_create(destination: Path, source: Path, files: Sequence[Path]) -> str:
    if destination.exists():
        raise RuntimeError(f"refusing to replace existing zip: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            archive.write(path, arcname=str(Path(source.name) / path.relative_to(source)))
    return sha256_file(destination)


def finalize_campaign(
    *, project_root: Path = PROJECT_ROOT, output: Path = DEFAULT_OUTPUT
) -> dict[str, Any]:
    manifest_path = output / "INPUT-MANIFEST.json"
    if not manifest_path.is_file():
        raise RuntimeError("campaign has not been prepared")
    if (output / "STATE-TRANSITION-RECEIPT.json").exists():
        raise RuntimeError("campaign is already finalized")
    source = source_path(project_root)
    source_rows = load_jsonl(source)
    validate_source(source_rows, source)
    source_by_id = {str(row["case_id"]): row for row in source_rows}
    all_reviews: list[dict[str, Any]] = []
    all_claims: list[dict[str, Any]] = []
    all_edits: list[dict[str, Any]] = []
    attestations: list[dict[str, Any]] = []
    for shard in range(1, SHARD_COUNT + 1):
        review_path, claim_path, edit_path, attestation_path = _part_paths(output, shard)
        for path in (review_path, claim_path, edit_path, attestation_path):
            if not path.is_file():
                raise RuntimeError(f"missing reviewer output: {path.name}")
        raw_reviews = load_jsonl(review_path)
        raw_claims = load_jsonl(claim_path)
        raw_edits = load_jsonl(edit_path)
        attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
        input_path = output / f"INPUT-SHARD-{shard:02d}.jsonl"
        input_rows = load_jsonl(input_path)
        if len(raw_reviews) != len(input_rows):
            raise RuntimeError(f"shard {shard} review row count mismatch")
        if str(attestation.get("input_shard_sha256") or "") != sha256_file(input_path):
            raise RuntimeError(f"shard {shard} attestation hash mismatch")
        if attestation.get("professional_legal_sign_off") is not False:
            raise RuntimeError(f"shard {shard} attestation claims professional sign-off")
        reviews = [
            _normalize_review_row(review, row)
            for review, row in zip(raw_reviews, input_rows, strict=True)
        ]
        for review, row in zip(reviews, input_rows, strict=True):
            _validate_review_row(review, row)
        expected_claims = {
            (str(row["case_id"]), str(claim.get("claim_id") or ""))
            for row in input_rows
            for claim in row.get("material_claims") or []
        }
        actual_claims = {
            (str(claim.get("case_id") or ""), str(claim.get("claim_id") or ""))
            for claim in raw_claims
        }
        if actual_claims != expected_claims or len(raw_claims) != len(expected_claims):
            raise RuntimeError(f"shard {shard} claim coverage mismatch")
        source_claim_by_key = {
            (str(row["case_id"]), str(claim.get("claim_id") or "")): claim
            for row in input_rows
            for claim in row.get("material_claims") or []
        }
        claims = [
            _normalize_claim(
                claim,
                source_by_id[str(claim.get("case_id") or "")],
                source_claim_by_key[
                    (str(claim.get("case_id") or ""), str(claim.get("claim_id") or ""))
                ],
            )
            for claim in raw_claims
        ]
        for claim in claims:
            if str(claim.get("verdict") or "") not in CLAIM_VERDICTS:
                raise RuntimeError(f"invalid claim verdict in shard {shard}")
            if claim.get("professional_legal_sign_off") is not False:
                raise RuntimeError(f"claim sign-off leaked in shard {shard}")
            key = (str(claim.get("case_id") or ""), str(claim.get("claim_id") or ""))
            source_claim = source_claim_by_key[key]
            exact_fields = {
                "materiality": str(source_claim.get("materiality") or ""),
                "proposition": str(source_claim.get("proposition") or ""),
                "source_title": str(source_claim.get("title") or ""),
                "locator": str(source_claim.get("locator") or ""),
                "evidence_span_sha256": str(source_claim.get("evidence_span_sha256") or ""),
            }
            if any(str(claim.get(field) or "") != value for field, value in exact_fields.items()):
                raise RuntimeError(f"claim identity mismatch in shard {shard}: {key}")
        expected_edit_ids = {
            str(review["case_id"])
            for review in reviews
            if review["ai_recommended_decision"] == "RECOMMEND_APPROVE_WITH_EDIT"
        }
        edits = [
            _normalize_edit(edit, source_by_id[str(edit.get("case_id") or "")])
            for edit in raw_edits
        ]
        edit_by_id = {str(edit.get("case_id") or ""): edit for edit in edits}
        if set(edit_by_id) != expected_edit_ids or len(edits) != len(expected_edit_ids):
            raise RuntimeError(f"shard {shard} edit coverage mismatch")
        for edit in edits:
            proposed = str(edit.get("proposed_final_answer") or "")
            if not proposed.strip():
                raise RuntimeError(f"empty proposed answer edit: {edit.get('case_id')}")
            if str(edit.get("original_answer_hash") or "") != str(
                source_by_id[str(edit["case_id"])]["candidate_answer_hash"]
            ):
                raise RuntimeError(f"edit original hash mismatch: {edit.get('case_id')}")
        all_reviews.extend(dict(row) for row in reviews)
        all_claims.extend(dict(row) for row in claims)
        all_edits.extend(dict(row) for row in edits)
        attestations.append(attestation)
    if len(all_reviews) != 330 or len({str(row["case_id"]) for row in all_reviews}) != 330:
        raise RuntimeError("aggregate review coverage is not exactly 330 unique cases")
    all_reviews.sort(key=lambda row: int(row["review_ordinal"]))
    all_claims.sort(
        key=lambda row: (
            int(source_by_id[str(row["case_id"])]["review_ordinal"]),
            str(row["claim_id"]),
        )
    )
    all_edits.sort(key=lambda row: int(source_by_id[str(row["case_id"])]["review_ordinal"]))
    claims_by_case: dict[str, list[dict[str, Any]]] = {}
    for claim in all_claims:
        claims_by_case.setdefault(str(claim["case_id"]), []).append(claim)
    for review in all_reviews:
        if review["ai_recommended_decision"] == "RECOMMEND_APPROVE":
            blocking = [
                claim
                for claim in claims_by_case[str(review["case_id"])]
                if str(claim.get("verdict") or "") in BLOCKING_CLAIM_VERDICTS
            ]
            if blocking:
                raise RuntimeError(f"approval has blocking claim verdict: {review['case_id']}")
    counts = Counter(str(row["ai_recommended_decision"]) for row in all_reviews)
    by_topic = Counter(str(row.get("topic") or "") for row in all_reviews)
    ready_ids = {
        str(row["case_id"])
        for row in all_reviews
        if row["ai_recommended_decision"] == "RECOMMEND_APPROVE"
    }
    ready_rows = [dict(source_by_id[case_id]) for case_id in ready_ids]
    ready_rows.sort(key=lambda row: int(row["review_ordinal"]))
    decision_template = [
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
        for row in ready_rows
    ]
    held_rows = [
        {
            "case_id": row["case_id"],
            "review_ordinal": row["review_ordinal"],
            "topic": row.get("topic"),
            "candidate_answer_hash": row["candidate_answer_hash"],
            "ai_recommended_decision": row["ai_recommended_decision"],
            "reasons": row.get("reasons") or [],
            "next_route": row.get("next_route"),
        }
        for row in all_reviews
        if row["ai_recommended_decision"] != "RECOMMEND_APPROVE"
    ]
    _write_jsonl_create(output / "INDEPENDENT-REVIEW.jsonl", all_reviews)
    _write_jsonl_create(output / "CLAIM-REVIEW.jsonl", all_claims)
    _write_jsonl_create(output / "EDIT-REGISTER.jsonl", all_edits)
    _write_jsonl_create(output / "QUALIFIED-REVIEW-READY-BLIND.jsonl", ready_rows)
    _write_jsonl_create(output / "QUALIFIED-REVIEW-DECISION-TEMPLATE.jsonl", decision_template)
    _write_jsonl_create(output / "NONREADY-ROUTING.jsonl", held_rows)
    _write_text_create(
        output / "QUALIFIED-REVIEW-HANDOFF.md",
        "\n".join(
            [
                "# Qualified legal-review handoff",
                "",
                "Review only the exact rows in `QUALIFIED-REVIEW-READY-BLIND.jsonl`.",
                "The AI recommendation is advisory and is not professional legal sign-off.",
                "For each row, a governance-qualified reviewer must review the exact answer",
                "and evidence hashes and complete one decision in",
                "`QUALIFIED-REVIEW-DECISION-TEMPLATE.jsonl`: `APPROVE`,",
                "`APPROVE_WITH_EDIT`, `HOLD`, or `REJECT`.",
                "",
                "An edit creates a new answer hash. It must pass changed-answer checks before",
                "any answer-gold candidate is assembled. Do not populate reviewer identity,",
                "qualification, signature, or professional sign-off unless the named reviewer",
                "actually performs and signs the review.",
                "",
                "Qualified legal review, answer gold, training, sealed unseen, promotion, and",
                "live remain NOT_STARTED until their applicable gates are completed.",
                "",
            ]
        ),
    )
    summary = {
        "schema": "legalbot.ge-reconstructed-independent-review-summary.v1",
        "campaign_id": CAMPAIGN_ID,
        "source_campaign_id": SOURCE_CAMPAIGN_ID,
        "source_sha256": sha256_file(source),
        "review_rows": len(all_reviews),
        "unique_case_ids": len({str(row["case_id"]) for row in all_reviews}),
        "claim_rows": len(all_claims),
        "edit_rows": len(all_edits),
        "recommendation_counts": dict(counts),
        "topic_counts": dict(by_topic),
        "qualified_review_ready_count": len(ready_rows),
        "qualified_review_ready_means_ai_advisory_only": True,
        "professional_legal_sign_off": False,
        "qualified_legal_review": NOT_STARTED,
        "answer_legal_gold": NOT_STARTED,
    }
    _write_json_create(output / "REVIEW-SUMMARY.json", summary)
    tests = {
        "source_hash_matches": sha256_file(source) == EXPECTED_SOURCE_SHA256,
        "exactly_330_reviews": len(all_reviews) == 330,
        "unique_330_case_ids": len({str(row["case_id"]) for row in all_reviews}) == 330,
        "claim_coverage_exact": len(all_claims)
        == sum(len(row.get("material_claims") or []) for row in source_rows),
        "all_input_hashes_validated": all(
            all(
                (row.get("input_hash_validation") or {}).get(key) is True
                for key in (
                    "question_hash_matches",
                    "candidate_answer_hash_matches",
                    "claim_and_evidence_reference_sets_match",
                )
            )
            for row in all_reviews
        ),
        "no_professional_sign_off": all(
            row.get("professional_legal_sign_off") is False for row in all_reviews
        ),
        "qualified_review_not_completed": all(
            row.get("qualified_legal_review_complete") is False for row in all_reviews
        ),
        "gold_false": all(row.get("answer_legal_gold") is False for row in all_reviews),
        "training_false": all(row.get("training_eligible") is False for row in all_reviews),
        "approvals_have_no_blocking_claim_verdict": True,
    }
    if not all(tests.values()):
        raise RuntimeError(f"final review tests failed: {tests}")
    _write_json_create(
        output / "TEST-RECEIPT.json",
        {
            "schema": "legalbot.ge-reconstructed-independent-review-test.v1",
            "tests": tests,
            "pass": True,
        },
    )
    overall_state = (
        AWAITING_QUALIFIED_REVIEWER
        if ready_rows
        else ANSWER_RECONSTRUCTION_REQUIRED_BEFORE_QUALIFIED_REVIEW
    )
    state = {
        "schema": "legalbot.ge-reconstructed-independent-review-state.v1",
        "campaign_id": CAMPAIGN_ID,
        "campaign_version": CAMPAIGN_VERSION,
        "overall_progress": True,
        "overall_state": overall_state,
        "independent_blind_review": "COMPLETE",
        "reviewer_kind": "AI_MODEL_REVIEWER",
        "professional_legal_sign_off": False,
        "human_case_by_case_review": "NOT_PERFORMED",
        "qualified_review_ready_count": len(ready_rows),
        "qualified_legal_review": NOT_STARTED,
        "answer_legal_gold": NOT_STARTED,
        **{gate: NOT_STARTED for gate in DOWNSTREAM_GATES},
        "full_331_guard": "NO_OP_UNCHANGED_INPUTS",
        "private_306_bank": "SEALED_NOT_OPENED",
        "recommendation_counts": dict(counts),
        "review_timestamp": datetime.now(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
    }
    _write_json_create(output / "STATE-TRANSITION-RECEIPT.json", state)
    attestation = {
        "schema": "legalbot.ge-reconstructed-independent-review-attestation.v1",
        "campaign_id": CAMPAIGN_ID,
        "reviewer_kind": "AI_MODEL_REVIEWER",
        "review_method": "EIGHT_DISJOINT_FRESH_CONTEXT_BLIND_SHARDS",
        "professional_legal_sign_off": False,
        "prior_ai_recommendations_supplied_to_reviewers": False,
        "additional_retrieval_performed": False,
        "qualified_legal_review": NOT_STARTED,
        "answer_legal_gold": NOT_STARTED,
        "part_attestations": attestations,
    }
    _write_json_create(output / "REVIEW-ATTESTATION.json", attestation)
    readme = "\n".join(
        [
            "# GE reconstructed-answer independent blind review r1",
            "",
            f"Source blind workbook SHA-256: `{sha256_file(source)}`.",
            f"Review rows: {len(all_reviews)}; material-claim rows: {len(all_claims)}.",
            f"Recommendations: `{dict(counts)}`.",
            f"Exact unchanged answers routed to qualified review: {len(ready_rows)}.",
            "",
            "This is AI advisory review, not qualified legal review or professional sign-off.",
            "Answer gold, training, sealed unseen, promotion, and live remain NOT_STARTED.",
            "",
        ]
    )
    _write_text_create(output / "README.md", readme)
    artifact_files = [
        path
        for path in sorted(output.iterdir())
        if path.is_file() and path.name != "RUN-STATUS.json"
    ]
    hashes = {path.name: sha256_file(path) for path in artifact_files}
    _write_json_create(
        output / "ARTIFACT-SHA256-REGISTER.json",
        {
            "schema": "legalbot.ge-reconstructed-independent-review-hashes.v1",
            "campaign_id": CAMPAIGN_ID,
            "artifacts": hashes,
        },
    )
    full_files = [path for path in sorted(output.iterdir()) if path.is_file()]
    review_zip_hash = _zip_create(DESKTOP_ZIP, output, full_files)
    routing_files = [
        output / "QUALIFIED-REVIEW-READY-BLIND.jsonl",
        output / "QUALIFIED-REVIEW-DECISION-TEMPLATE.jsonl",
        output / "QUALIFIED-REVIEW-HANDOFF.md",
        output / "NONREADY-ROUTING.jsonl",
        output / "INDEPENDENT-REVIEW.jsonl",
        output / "CLAIM-REVIEW.jsonl",
        output / "REVIEW-SUMMARY.json",
        output / "REVIEW-ATTESTATION.json",
        output / "STATE-TRANSITION-RECEIPT.json",
        output / "TEST-RECEIPT.json",
    ]
    routing_zip_hash = _zip_create(ROUTING_ZIP, output, routing_files)
    return {
        "campaign_id": CAMPAIGN_ID,
        "output": str(output),
        "review_zip": str(DESKTOP_ZIP),
        "review_zip_sha256": review_zip_hash,
        "routing_zip": str(ROUTING_ZIP),
        "routing_zip_sha256": routing_zip_hash,
        "summary": summary,
        "state": state,
    }
