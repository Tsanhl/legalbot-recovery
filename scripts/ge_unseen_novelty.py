"""Pure, bounded lexical exposure flags for explicitly supplied texts only.

Freeze ``novelty_contract()`` before unseen disclosure, then pass its
``content_sha256`` to ``check_novelty``. This function checks that binding, not
when or by whom the contract was frozen. No files, models, corpora, runner or
network are consulted. No example text is built in, including owner examples.

Scenarios are {case_id, question}; references in exposed_questions,
trained_answers and policy_examples are {id, text}. Lists/tuples may be empty;
IDs must be unique within each input group. The caller selects and authorizes
every text and must supply required policy examples. Only supplied question
text is checked, not uploads, answers, future turns or omitted corpus members.

Question comparisons include supplied exposed/policy questions and earlier new
scenarios. Exact normalized equality is reported even for short questions.
Fuzzy flags require substantial shared distinctive wording; trained-answer
flags require a long contiguous span. Neither is proof of semantic similarity,
copying, training influence or independence. Every case still needs independent
novelty review. Nothing is deleted, dropped, rewritten or approved by this code.
"""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class _Policy:
    min_question_tokens: int = 24
    min_distinctive_tokens: int = 10
    min_shared_distinctive_tokens: int = 10
    token_dice_min_basis_points: int = 8600
    bigram_dice_min_basis_points: int = 6500
    question_anchor_tokens: int = 3
    answer_span_tokens: int = 24
    max_scenarios: int = 443
    max_references: int = 10_000
    max_question_tokens: int = 1024
    max_answer_tokens: int = 8192
    max_text_characters: int = 100_000
    max_total_utf8_bytes: int = 8_000_000
    max_total_tokens: int = 400_000
    max_posting_visits: int = 250_000
    max_pair_checks: int = 10_000
    max_flag_pairs: int = 5000


_POLICY = _Policy()
_MONTHS = frozenset(("january", "february", "march", "april", "may", "june", "july", "august",
                     "september", "october", "november", "december", "jan", "feb", "mar", "apr",
                     "jun", "jul", "aug", "sep", "sept", "oct", "nov", "dec"))
_COMMON = frozenset((
    "a", "an", "the", "and", "or", "but", "if", "then", "than", "as", "at", "by", "for", "from",
    "in", "into", "of", "on", "onto", "to", "with", "without", "about", "after", "before",
    "between", "during", "over", "under", "through", "up", "down", "out", "off", "this", "that",
    "these", "those", "here", "there", "it", "its", "itself", "i", "me", "my", "mine", "we", "us",
    "our", "ours", "you", "your", "yours", "he", "him", "his", "she", "her", "hers", "they", "them",
    "their", "theirs", "who", "whom", "whose", "which", "what", "when", "where", "why", "how",
    "is", "am", "are", "was", "were", "be", "been", "being", "do", "does", "did", "doing", "have",
    "has", "had", "having", "can", "could", "may", "might", "must", "shall", "should", "will",
    "would", "not", "no", "nor", "so", "such", "any", "all", "each", "every", "both", "either",
    "neither", "some", "more", "most", "other", "same", "only", "own", "also", "just", "very", "now",
    "still", "already", "please", "want", "need", "ask", "tell", "help", "know", "whether",
    "legal", "law", "laws", "court", "courts", "claim", "claims", "claimant", "defendant", "rights",
    "right", "advice", "contract", "contracts", "breach", "duty", "care", "negligence", "liability",
    "liable", "damages", "remedy", "remedies", "act", "acts", "statute", "statutory", "section",
    "sections", "case", "cases", "civil", "criminal", "justice", "reasonable", "person", "party",
    "parties", "evidence", "proceeding", "proceedings",
))


class NoveltyInputError(ValueError):
    """Invalid input or mismatched frozen contract; no result implies a pass."""


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")).encode("utf-8")).hexdigest()


def _seal(value) -> dict:
    return {**value, "content_sha256": _digest(value)}


def novelty_contract() -> dict:
    """Return a fresh serializable contract to freeze/hash before new text is seen."""
    return _seal({
        "schema": "legalbot.ge-lexical-novelty-contract.v1",
        "algorithm": "INDEXED_DISTINCTIVE_TRIGRAM_TOKEN_BIGRAM_DICE_AND_ANSWER_SPANS_V1",
        "normalization": "NFKC_CASEFOLD_REMOVE_CF_UNICODE_ALPHANUMERIC_TOKENS_V1",
        "fuzzy_fact_mask": "DECIMAL_TOKEN_TO_NUMBER_AND_LISTED_MONTH_TO_MONTH_V1",
        "unicode_database_version": unicodedata.unidata_version,
        "common_tokens": sorted(_COMMON), "month_tokens": sorted(_MONTHS),
        "thresholds_and_limits": asdict(_POLICY),
        "exact_rule": "RAW_UTF8_OR_NORMALIZED_TOKEN_EQUALITY_FOR_QUESTION_TEXTS",
        "near_rule": "MIN_LENGTH_DISTINCTIVE_OVERLAP_AND_BOTH_DICE_THRESHOLDS",
        "answer_rule": "FIRST_DISTINCTIVE_CONTIGUOUS_MASKED_TOKEN_WINDOW_PER_PAIR",
        "candidate_rule": "SHARED_TRIGRAM_WITH_AT_LEAST_ONE_DISTINCTIVE_TOKEN",
        "order": "INPUT_ORDER_THEN_REFERENCE_ORDER_EARLIER_NEW_SCENARIOS_ONLY",
        "budget_exhaustion": "RETURN_INCOMPLETE_WITH_UNFINISHED_CASE_IDS_NO_CLEAN_RESULT",
        "independent_novelty_review": "REQUIRED_FOR_ALL_CASES",
        "freeze_timing_verification": "CALLER_RESPONSIBILITY_NOT_VERIFIED_HERE",
    })


def _tokens(text: str) -> tuple[str, ...]:
    # Matches the existing question contract's Unicode normalization policy.
    normal = unicodedata.normalize("NFKC", text).casefold()
    normal = "".join(char for char in normal if unicodedata.category(char) != "Cf")
    return tuple(re.findall(r"[^\W_]+", normal))


def _masked(tokens):
    return tuple("<number>" if token.isdecimal() else "<month>" if token in _MONTHS else token
                 for token in tokens)


def _distinctive(tokens):
    return frozenset(token for token in tokens if len(token) >= 3
                     and token not in _COMMON and token not in ("<number>", "<month>")
                     and not token.isdecimal())


def _grams(tokens, size):
    for index in range(len(tokens) - size + 1):
        yield index, tokens[index:index + size]


@dataclass
class _Text:
    group: str
    identifier: str
    text_hash: str
    record_hash: str
    tokens: tuple[str, ...]
    masked: tuple[str, ...]
    normalized_hash: str
    distinctive: frozenset[str]
    token_counts: Counter
    bigram_counts: Counter

    def identity(self):
        return {"group": self.group, "id": self.identifier,
                "text_sha256": self.text_hash, "record_sha256": self.record_hash,
                "normalized_tokens_sha256": self.normalized_hash}


def _inputs(groups):
    """Bound parsing/index size up front; never accept paths or iterable loaders."""
    result = {}
    byte_count = token_count = reference_count = 0
    for group, supplied in groups.items():
        if not isinstance(supplied, list | tuple):
            raise NoveltyInputError("input groups must be lists or tuples of text records")
        if group == "scenarios":
            if len(supplied) > _POLICY.max_scenarios:
                raise NoveltyInputError("scenario count exceeds frozen limit")
        else:
            reference_count += len(supplied)
            if reference_count > _POLICY.max_references:
                raise NoveltyInputError("reference count exceeds frozen limit")
        id_key, text_key = ("case_id", "question") if group == "scenarios" else ("id", "text")
        rows, seen = [], set()
        for row in supplied:
            if not isinstance(row, Mapping) or set(row) != {id_key, text_key}:
                raise NoveltyInputError("text record fields differ from contract")
            identifier, text = row[id_key], row[text_key]
            if not isinstance(identifier, str) or not identifier.strip() or len(identifier) > 200:
                raise NoveltyInputError("text record requires a nonblank bounded id")
            if identifier in seen:
                raise NoveltyInputError("duplicate id within input group")
            seen.add(identifier)
            if not isinstance(text, str) or not text.strip() or len(text) > _POLICY.max_text_characters:
                raise NoveltyInputError("text must be nonblank and within frozen size limit")
            try:
                raw = text.encode("utf-8")
                record_hash = _digest(dict(row))
            except UnicodeError as exc:
                raise NoveltyInputError("input must encode as valid UTF-8") from exc
            byte_count += len(raw)
            if byte_count > _POLICY.max_total_utf8_bytes:
                raise NoveltyInputError("total text bytes exceed frozen limit")
            tokens = _tokens(text)
            token_count += len(tokens)
            limit = _POLICY.max_answer_tokens if group == "trained_answers" else _POLICY.max_question_tokens
            if not tokens or len(tokens) > limit or token_count > _POLICY.max_total_tokens:
                raise NoveltyInputError("token count empty or exceeds frozen limit")
            masked = _masked(tokens)
            rows.append(_Text(group, identifier, hashlib.sha256(raw).hexdigest(), record_hash,
                              tokens, masked, _digest(tokens), _distinctive(masked),
                              Counter(masked), Counter(gram for _, gram in _grams(masked, 2))))
        result[group] = rows
    return result, {"input_utf8_bytes": byte_count, "input_tokens": token_count}


class _LimitReached(Exception):
    pass


class _Budget:
    def __init__(self):
        self.counts = {"posting_visits": 0, "pair_checks": 0, "flag_pairs": 0}
        self.exhausted = None

    def use(self, name):
        if self.counts[name] >= getattr(_POLICY, "max_" + name):
            self.exhausted = name
            raise _LimitReached
        self.counts[name] += 1


def _dice(left, right):
    overlap = sum((left & right).values())
    return 2 * overlap * 10_000 // (sum(left.values()) + sum(right.values()))


def _near(left, right):
    if (min(len(left.tokens), len(right.tokens)) < _POLICY.min_question_tokens
            or min(len(left.distinctive), len(right.distinctive)) < _POLICY.min_distinctive_tokens):
        return None
    shared = len(left.distinctive & right.distinctive)
    if shared < _POLICY.min_shared_distinctive_tokens:
        return None
    token_dice = _dice(left.token_counts, right.token_counts)
    if token_dice < _POLICY.token_dice_min_basis_points:
        return None
    bigram_dice = _dice(left.bigram_counts, right.bigram_counts)
    if bigram_dice < _POLICY.bigram_dice_min_basis_points:
        return None
    return {"reason": "HIGH_LEXICAL_SCENARIO_OVERLAP",
            "token_dice_basis_points": token_dice,
            "bigram_dice_basis_points": bigram_dice,
            "shared_distinctive_tokens": shared,
            "number_or_month_mask_applied": left.tokens != left.masked or right.tokens != right.masked}


def _anchors(row):
    if len(row.tokens) < _POLICY.min_question_tokens or len(row.distinctive) < _POLICY.min_distinctive_tokens:
        return set()
    return {gram for _, gram in _grams(row.masked, _POLICY.question_anchor_tokens)
            if any(token in row.distinctive for token in gram)}


def _index_question(row, index, exact, phrases):
    exact[row.normalized_hash].append(index)
    for anchor in _anchors(row):
        phrases[anchor].append(index)


def _answer_index(answers):
    # Only the first position per answer/window is needed for a review flag.
    # Fixed-length windows avoid quadratic longest-substring or alignment work.
    index = defaultdict(list)
    for number, answer in enumerate(answers):
        seen = set()
        for position, window in _grams(answer.masked, _POLICY.answer_span_tokens):
            if window in seen:
                continue
            seen.add(window)
            if len(_distinctive(window)) >= _POLICY.min_distinctive_tokens:
                index[window].append((number, position))
    return index


def _pair(scenario, reference, evidence):
    return {"scenario": scenario.identity(), "reference": reference.identity(),
            "requires_fresh_review": True, "policy_example_overlap": reference.group == "policy_examples",
            **evidence}


def check_novelty(
    scenarios: Sequence[Mapping[str, str]], *, expected_contract_sha256: str,
    exposed_questions: Sequence[Mapping[str, str]] = (),
    trained_answers: Sequence[Mapping[str, str]] = (),
    policy_examples: Sequence[Mapping[str, str]] = (),
) -> dict:
    """Return a deterministic hash-bound receipt of mechanical exposure flags.

    ``COMPLETE`` describes the declared lexical procedure only. A zero-flag
    receipt is never a novelty PASS. Work limits return an INCOMPLETE receipt,
    with retained partial flags and every not-fully-checked case ID. Oversize or
    malformed inputs raise NoveltyInputError, never silently truncate inputs.
    Inputs are not mutated. Hashes refer to raw UTF-8 text and canonical JSON
    input records, not source files or proof that the corpus was authorized.
    """
    contract = novelty_contract()
    if expected_contract_sha256 != contract["content_sha256"]:
        raise NoveltyInputError("frozen novelty contract hash mismatch")
    supplied = {"scenarios": scenarios, "exposed_questions": exposed_questions,
                "trained_answers": trained_answers, "policy_examples": policy_examples}
    groups, input_work = _inputs(supplied)
    inventory = {group: [row.identity() for row in rows] for group, rows in groups.items()}
    input_hash = _digest({group: [dict(row) for row in rows] for group, rows in supplied.items()})
    questions = [*groups["exposed_questions"], *groups["policy_examples"]]
    answers = groups["trained_answers"]
    exact_index, phrase_index = defaultdict(list), defaultdict(list)
    for index, row in enumerate(questions):
        _index_question(row, index, exact_index, phrase_index)
    answer_index = _answer_index(answers)
    budget = _Budget()
    exact_flags, near_flags, completed = [], [], []
    for scenario in groups["scenarios"]:
        try:
            exact_matches = set()
            for index in exact_index.get(scenario.normalized_hash, ()):
                budget.use("posting_visits")
                reference = questions[index]
                # Verify tokens as well as the digest, so hashes are not an oracle.
                if scenario.tokens != reference.tokens:
                    continue
                budget.use("flag_pairs")
                exact_flags.append(_pair(scenario, reference, {
                    "reason": "RAW_TEXT_EXACT" if scenario.text_hash == reference.text_hash else "NORMALIZED_QUESTION_EXACT"}))
                exact_matches.add(index)
            candidates = set()
            # Rare anchors first; sort tie-breaks so work limits are reproducible.
            for anchor in sorted(_anchors(scenario), key=lambda gram: (len(phrase_index.get(gram, ())), gram)):
                for index in phrase_index.get(anchor, ()):
                    budget.use("posting_visits")
                    if index not in exact_matches:
                        candidates.add(index)
            for index in sorted(candidates):
                budget.use("pair_checks")
                reference = questions[index]
                evidence = _near(scenario, reference)
                if evidence is not None:
                    budget.use("flag_pairs")
                    near_flags.append(_pair(scenario, reference, evidence))
            matched_answers = set()
            for position, window in _grams(scenario.masked, _POLICY.answer_span_tokens):
                for index, reference_position in answer_index.get(window, ()):
                    budget.use("posting_visits")
                    if index in matched_answers:
                        continue
                    budget.use("pair_checks")
                    reference = answers[index]
                    size = _POLICY.answer_span_tokens
                    left = scenario.tokens[position:position + size]
                    right = reference.tokens[reference_position:reference_position + size]
                    budget.use("flag_pairs")
                    near_flags.append(_pair(scenario, reference, {
                        "reason": "NORMALIZED_TRAINED_ANSWER_SPAN" if left == right else "NUMBER_MONTH_VARIANT_TRAINED_ANSWER_SPAN",
                        "span_token_count": size, "shared_distinctive_tokens": len(_distinctive(window)),
                        "scenario_token_span": [position, position + size],
                        "reference_token_span": [reference_position, reference_position + size],
                        "span_coordinates": "ZERO_BASED_HALF_OPEN_NORMALIZED_TOKENS_NOT_CHARACTER_OFFSETS",
                        "scenario_span_sha256": _digest(left), "reference_span_sha256": _digest(right),
                        "masked_span_sha256": _digest(window),
                    }))
                    matched_answers.add(index)
        except _LimitReached:
            break
        completed.append(scenario.identifier)
        _index_question(scenario, len(questions), exact_index, phrase_index)
        questions.append(scenario)
    incomplete = [row.identifier for row in groups["scenarios"][len(completed):]]
    status = ("INCOMPLETE_REQUIRES_FRESH_REVIEW" if incomplete else
              "FLAGS_REQUIRE_FRESH_REVIEW" if exact_flags or near_flags else
              "NO_LEXICAL_FLAGS_IN_SUPPLIED_TEXT")
    return _seal({
        "schema": "legalbot.ge-lexical-novelty-receipt.v1", "kind": "MECHANICAL_EXPOSURE_FLAGS",
        "status": status, "mechanical_check": "INCOMPLETE" if incomplete else "COMPLETE",
        "contract_sha256": contract["content_sha256"], "input_sha256": input_hash,
        "input_inventory": inventory, "input_counts": {group: len(rows) for group, rows in groups.items()},
        "exact_overlaps": exact_flags, "near_candidates": near_flags,
        "exact_overlap_pair_count": len(exact_flags), "near_candidate_pair_count": len(near_flags),
        "trained_answer_span_pair_count": sum(flag["reference"]["group"] == "trained_answers" for flag in near_flags),
        "completed_case_ids": completed, "incomplete_case_ids": incomplete,
        "work": {**input_work, **budget.counts, "exhausted_limit": budget.exhausted},
        "text_scope": "EXPLICITLY_SUPPLIED_QUESTION_AND_REFERENCE_TEXTS_ONLY",
        "data_access": "CALLER_SUPPLIED_TEXT_ONLY_NO_IO",
        "corpus_authorization_and_completeness": "CALLER_RESPONSIBILITY_NOT_VERIFIED",
        "required_policy_examples": "CALLER_MUST_SUPPLY_NO_BUILT_IN_EXAMPLE_TEXT",
        "contract_freeze_timing": "CALLER_MUST_BIND_BEFORE_DISCLOSURE_NOT_VERIFIED_HERE",
        "independent_novelty_review": "REQUIRED_FOR_ALL_CASES",
        "semantic_independence_proven": False, "training_derivation_proven": False,
        "model_semantic_comparison": "NOT_PERFORMED", "case_mutation": "NONE",
        "remaining_review": "Independent reviewers must assess semantic paraphrases, shared scenario structure, answer-derived clues and required policy exclusions. Lexical flags need fresh review; their absence does not prove novelty or permit an outcome gate to be relaxed.",
    })
