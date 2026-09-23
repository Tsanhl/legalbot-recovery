"""Only invented caller-supplied texts; no bank, evaluation corpus or runner IO."""
from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import FrozenInstanceError, replace

import pytest
from scripts import ge_unseen_novelty as novelty

QUESTION = (
    "On 12 March 2026 I booked an insulated studio in England for a ceramic workshop. "
    "The organiser promised overnight access and a locked kiln cupboard. After delivery, "
    "the caretaker disabled my entry badge, moved several glazed bowls into a damp corridor, "
    "and charged an extra 450 pounds. I saved the booking messages, photographed the cracked "
    "bowls, and recorded our telephone conversation. How can I recover the items and "
    "challenge this unexpected charge?"
)
COPIED_SPAN = (
    "Photograph the distinctive ceramic bowls beside the locked kiln cupboard, retain "
    "the handwritten delivery checklist, identify the caretaker who disabled the entry "
    "badge, and preserve messages describing the unexpected storage charge before arranging collection."
)


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def scenario(text, identifier="new-1"):
    return {"case_id": identifier, "question": text}


def reference(text, identifier="exposed-1"):
    return {"id": identifier, "text": text}


def check(scenarios, **corpora):
    return novelty.check_novelty(scenarios, expected_contract_sha256=novelty.novelty_contract()["content_sha256"],
                                 **corpora)


def test_exact_receipt_binds_raw_text_records_corpora_and_contract_without_mutation():
    inputs = {"scenarios": [scenario(QUESTION)], "exposed_questions": [reference(QUESTION)],
              "trained_answers": [], "policy_examples": []}
    original = copy.deepcopy(inputs)
    first = check(**inputs)
    assert first == check(**inputs)
    assert inputs == original
    assert first["content_sha256"] == digest({k: v for k, v in first.items() if k != "content_sha256"})
    assert first["input_sha256"] == digest(inputs)
    assert first["contract_sha256"] == novelty.novelty_contract()["content_sha256"]
    assert first["mechanical_check"] == "COMPLETE"
    assert first["exact_overlap_pair_count"] == 1 and first["near_candidate_pair_count"] == 0
    pair = first["exact_overlaps"][0]
    assert pair["reason"] == "RAW_TEXT_EXACT"
    assert pair["scenario"]["text_sha256"] == hashlib.sha256(QUESTION.encode()).hexdigest()
    assert pair["scenario"]["record_sha256"] == digest(inputs["scenarios"][0])
    assert pair["reference"]["record_sha256"] == digest(inputs["exposed_questions"][0])
    assert pair["requires_fresh_review"] is True
    assert QUESTION not in json.dumps(first)


def test_unicode_case_punctuation_and_formatting_are_normalized_but_raw_hashes_differ():
    original = "My café receipt records a broken blue vase from the studio."
    variant = "ＭＹ\u00a0cafe\u0301 receipt\u200b records—A broken blue vase from the studio!!!"
    result = check([scenario(variant)], exposed_questions=[reference(original)])
    pair = result["exact_overlaps"][0]
    assert pair["reason"] == "NORMALIZED_QUESTION_EXACT"
    assert pair["scenario"]["text_sha256"] != pair["reference"]["text_sha256"]
    assert pair["scenario"]["normalized_tokens_sha256"] == pair["reference"]["normalized_tokens_sha256"]


def test_high_similarity_paraphrase_is_flagged_as_lexical_review_candidate():
    paraphrase = QUESTION
    for before, after in (("booked", "rented"), ("promised", "offered"), ("disabled", "deactivated"),
                          ("extra", "additional"), ("saved", "kept"), ("challenge", "dispute")):
        paraphrase = paraphrase.replace(before, after)
    result = check([scenario(paraphrase)], exposed_questions=[reference(QUESTION)])
    assert result["exact_overlaps"] == []
    assert len(result["near_candidates"]) == 1
    flag = result["near_candidates"][0]
    assert flag["reason"] == "HIGH_LEXICAL_SCENARIO_OVERLAP"
    assert flag["token_dice_basis_points"] >= 8600
    assert flag["bigram_dice_basis_points"] >= 6500
    assert flag["shared_distinctive_tokens"] >= 10
    assert result["semantic_independence_proven"] is False


def test_sentence_reordering_retains_distinctive_ngram_evidence():
    sentences = QUESTION.split(". ")
    reordered = ". ".join([sentences[1], sentences[0], *sentences[2:]])
    result = check([scenario(reordered)], exposed_questions=[reference(QUESTION)])
    assert result["exact_overlap_pair_count"] == 0
    assert result["near_candidate_pair_count"] == 1


def test_swapped_numbers_dates_and_amounts_are_near_flags_never_exact():
    changed = QUESTION.replace("12 March 2026", "29 November 2025").replace("450", "975")
    result = check([scenario(changed)], exposed_questions=[reference(QUESTION)])
    assert result["exact_overlaps"] == []
    flag = result["near_candidates"][0]
    assert flag["number_or_month_mask_applied"] is True
    assert flag["token_dice_basis_points"] == flag["bigram_dice_basis_points"] == 10_000
    assert flag["scenario"]["normalized_tokens_sha256"] != flag["reference"]["normalized_tokens_sha256"]


@pytest.mark.parametrize("left,right", [
    ("What remedies follow a breach of contract?", "How can I prove a breach of contract?"),
    ("The court applies a reasonable duty of care.", "A reasonable person owes a duty of care."),
    ("legal claim breach duty care court damages statute section rights " * 6,
     "court damages statute rights section legal claim breach care duty " * 6),
])
def test_common_legal_terms_are_not_fuzzy_or_training_span_matches(left, right):
    result = check([scenario(left)], exposed_questions=[reference(right)],
                   trained_answers=[reference(right, "trained-1")])
    assert result["exact_overlaps"] == result["near_candidates"] == []


def test_short_exact_question_is_still_explicit_exposure_evidence():
    result = check([scenario("What is a contract?")], exposed_questions=[reference("What is a contract?")])
    assert result["exact_overlap_pair_count"] == 1
    assert result["near_candidate_pair_count"] == 0


def test_unrelated_scenarios_with_shared_setting_do_not_match():
    different = (
        "My studio in England shares a corridor with a bicycle repair workshop. A courier "
        "delivered an unsigned parcel containing a brass clock while I was away last Thursday. "
        "The owner of the clock contacted me using a handwritten address label but cannot "
        "describe the packaging. I have no receipt and need to establish the intended recipient."
    )
    result = check([scenario(different)], exposed_questions=[reference(QUESTION)])
    assert result["exact_overlap_pair_count"] == result["near_candidate_pair_count"] == 0


def test_long_training_answer_span_reports_hash_bound_token_locations():
    answer = "Synthetic introductory answer context. " + COPIED_SPAN + " Synthetic closing context."
    question = "Could you explain this passage: " + COPIED_SPAN
    result = check([scenario(question)], trained_answers=[reference(answer, "trained-1")])
    assert result["trained_answer_span_pair_count"] == 1
    assert result["exact_overlaps"] == []
    flag = result["near_candidates"][0]
    assert flag["reason"] == "NORMALIZED_TRAINED_ANSWER_SPAN"
    assert flag["scenario_token_span"] == [5, 29]
    assert flag["reference_token_span"] == [4, 28]
    assert flag["span_token_count"] == 24
    left = novelty._tokens(question)[5:29]
    right = novelty._tokens(answer)[4:28]
    assert flag["scenario_span_sha256"] == digest(left)
    assert flag["reference_span_sha256"] == digest(right)
    assert left == right
    assert result["training_derivation_proven"] is False
    assert result["independent_novelty_review"] == "REQUIRED_FOR_ALL_CASES"


def test_answer_span_minimum_distinctiveness_and_boundary_are_enforced():
    words = list(novelty._tokens(COPIED_SPAN))
    short = " ".join(words[:23])
    long = " ".join(words[:24])
    answer = "Training opening " + long + " training ending."
    assert check([scenario(short)], trained_answers=[reference(answer)])["trained_answer_span_pair_count"] == 0
    assert check([scenario(long)], trained_answers=[reference(answer)])["trained_answer_span_pair_count"] == 1
    repetitive = "breach contract damages legal law claim court duty care rights " * 5
    assert check([scenario(repetitive)], trained_answers=[reference(repetitive)])["near_candidates"] == []


def test_answer_span_finds_tail_beyond_unrelated_long_intro_and_masks_changed_dates():
    copied = "On 12 March 2026 " + COPIED_SPAN
    answer = "Unrelated introduction to the synthetic fixture. " * 90 + copied
    question = copied.replace("12 March 2026", "29 November 2025")
    result = check([scenario(question)], trained_answers=[reference(answer)])
    flag = result["near_candidates"][0]
    assert flag["reason"] == "NUMBER_MONTH_VARIANT_TRAINED_ANSWER_SPAN"
    assert flag["reference_token_span"][0] > 500
    assert flag["scenario_span_sha256"] != flag["reference_span_sha256"]
    assert flag["reference"]["text_sha256"] == hashlib.sha256(answer.encode()).hexdigest()


def test_each_training_pair_has_one_deterministic_review_span():
    answer = COPIED_SPAN + " " + COPIED_SPAN
    result = check([scenario(answer)], trained_answers=[reference(answer)])
    assert result["trained_answer_span_pair_count"] == 1
    assert result["near_candidates"][0]["reference_token_span"] == [0, 24]


def test_explicit_policy_example_is_used_only_when_supplied_by_caller():
    example = "Synthetic caller example: a parent bought a faulty toy and requested a refund."
    assert check([scenario(example)])["exact_overlaps"] == []
    result = check([scenario(example)], policy_examples=[reference(example, "caller-example")])
    pair = result["exact_overlaps"][0]
    assert pair["policy_example_overlap"] is True
    assert pair["reference"]["group"] == "policy_examples"
    assert result["input_counts"]["policy_examples"] == 1
    assert result["required_policy_examples"] == "CALLER_MUST_SUPPLY_NO_BUILT_IN_EXAMPLE_TEXT"


def test_within_new_scenarios_compares_each_pair_once_without_self_pairs():
    later = QUESTION.replace("450", "650")
    result = check([scenario(QUESTION, "first"), scenario(QUESTION, "second"), scenario(later, "third")])
    assert [(row["scenario"]["id"], row["reference"]["id"]) for row in result["exact_overlaps"]] == [("second", "first")]
    assert [(row["scenario"]["id"], row["reference"]["id"]) for row in result["near_candidates"]] == [("third", "first"), ("third", "second")]
    assert all(row["reference"]["group"] == "scenarios" for row in result["near_candidates"])


def test_no_flags_never_claims_novelty_pass_and_empty_corpus_is_explicit():
    result = check([scenario(QUESTION)])
    assert result["status"] == "NO_LEXICAL_FLAGS_IN_SUPPLIED_TEXT"
    assert result["model_semantic_comparison"] == "NOT_PERFORMED"
    assert result["semantic_independence_proven"] is False
    assert result["independent_novelty_review"] == "REQUIRED_FOR_ALL_CASES"
    assert result["corpus_authorization_and_completeness"] == "CALLER_RESPONSIBILITY_NOT_VERIFIED"
    assert result["input_counts"]["exposed_questions"] == result["input_counts"]["trained_answers"] == 0
    assert result["case_mutation"] == "NONE"
    assert "pass" not in result


def test_fixed_contract_snapshot_cannot_be_mutated_or_silently_replaced():
    original = novelty.novelty_contract()
    snapshot = novelty.novelty_contract()
    snapshot["thresholds_and_limits"]["min_question_tokens"] = 1
    snapshot["common_tokens"].clear()
    assert novelty.novelty_contract() == original
    with pytest.raises(FrozenInstanceError):
        novelty._POLICY.min_question_tokens = 1
    with pytest.raises(novelty.NoveltyInputError, match="contract hash"):
        novelty.check_novelty([scenario(QUESTION)], expected_contract_sha256="0" * 64)


@pytest.mark.parametrize("inputs", [
    {"scenarios": "not a corpus"},
    {"scenarios": [{"case_id": "id", "path": "/not-a-text-input"}]},
    {"scenarios": [scenario("")]}, {"scenarios": [scenario("!!!")]},
    {"scenarios": [scenario("\ud800")]}, {"scenarios": [scenario(b"bytes are not text")]},
    {"scenarios": [scenario(QUESTION), scenario(QUESTION)]},
    {"scenarios": [scenario(QUESTION, "")]},
    {"scenarios": [], "exposed_questions": [reference(QUESTION), reference(QUESTION)]},
    {"scenarios": [], "policy_examples": [{"id": "p", "text": QUESTION, "unbound_extra": 1}]},
])
def test_malformed_or_ambiguous_inputs_raise_without_a_clean_receipt(inputs):
    with pytest.raises(novelty.NoveltyInputError):
        check(**inputs)


@pytest.mark.parametrize("inputs", [
    {"scenarios": [scenario("hello", str(i)) for i in range(444)]},
    {"scenarios": [scenario("word " * 1025)]},
    {"scenarios": [], "trained_answers": [reference("word " * 8193)]},
    {"scenarios": [scenario("a" * 100001)]},
])
def test_oversize_inputs_are_rejected_never_truncated(inputs):
    with pytest.raises(novelty.NoveltyInputError, match="limit"):
        check(**inputs)


def test_indexed_search_avoids_cartesian_pair_scan_for_large_disjoint_corpora():
    # 443,000 possible cross-corpus pairs, but no shared distinctive anchors.
    exposed = [reference(" ".join(f"old{i}word{j}" for j in range(30)), f"old-{i}") for i in range(1000)]
    scenarios = [scenario(" ".join(f"new{i}word{j}" for j in range(30)), f"new-{i}") for i in range(443)]
    result = check(scenarios, exposed_questions=exposed)
    assert result["mechanical_check"] == "COMPLETE"
    assert result["work"]["pair_checks"] == result["work"]["posting_visits"] == 0
    assert len(result["completed_case_ids"]) == 443


@pytest.mark.parametrize("limit", ["posting_visits", "pair_checks", "flag_pairs"])
def test_exhausted_work_budget_is_deterministic_incomplete_not_clean(monkeypatch, limit):
    # Synthetic resource envelope only; changed limits necessarily change the
    # frozen contract hash and cannot masquerade as the production contract.
    before_contract = novelty.novelty_contract()["content_sha256"]
    monkeypatch.setattr(novelty, "_POLICY", replace(novelty._POLICY, **{"max_" + limit: 1}))
    assert novelty.novelty_contract()["content_sha256"] != before_contract
    questions = [scenario(QUESTION, "one"), scenario(QUESTION, "two")]
    exposed = [reference(QUESTION.replace("450", str(value)), str(value)) for value in (700, 800)]
    result = check(questions, exposed_questions=exposed)
    assert result == check(questions, exposed_questions=exposed)
    assert result["status"] == "INCOMPLETE_REQUIRES_FRESH_REVIEW"
    assert result["mechanical_check"] == "INCOMPLETE"
    assert result["work"]["exhausted_limit"] == limit
    assert result["work"][limit] == 1
    assert result["incomplete_case_ids"] == ["one", "two"]
    assert result["completed_case_ids"] == []
    assert result["independent_novelty_review"] == "REQUIRED_FOR_ALL_CASES"
    if limit == "flag_pairs":
        assert result["near_candidate_pair_count"] == 1  # Partial evidence retained.


def test_pure_checker_never_opens_files_or_network(monkeypatch):
    import builtins
    import os
    import socket

    def forbidden(*args, **kwargs):
        raise AssertionError("no filesystem or network access allowed")

    with monkeypatch.context() as fence:
        fence.setattr(builtins, "open", forbidden)
        fence.setattr(os, "scandir", forbidden)
        fence.setattr(socket, "socket", forbidden)
        result = check([scenario(QUESTION)], exposed_questions=[reference(QUESTION)])
    assert result["exact_overlap_pair_count"] == 1
