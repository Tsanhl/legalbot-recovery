from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.retrieval.service import _forward_last_token_logits


class _Logits:
    def __init__(self, last_vocab: list[list[float]]) -> None:
        self.last_vocab = last_vocab

    def __getitem__(self, item: object) -> list[list[float]]:
        batch, seq, vocab = item  # type: ignore[misc]
        assert batch == slice(None)
        assert vocab == slice(None)
        assert seq == -1
        return self.last_vocab


class _Output:
    def __init__(self, logits: _Logits) -> None:
        self.logits = logits


def _yes_probability(false_logit: float, true_logit: float) -> float:
    peak = max(false_logit, true_logit)
    false_exp = pow(2.718281828, false_logit - peak)
    true_exp = pow(2.718281828, true_logit - peak)
    return true_exp / (false_exp + true_exp)


def test_forward_requests_last_token_logits_without_cache() -> None:
    calls: list[dict[str, object]] = []
    last = [[0.2, 1.4, 0.0], [1.1, 0.3, 0.0]]

    def _model(**kwargs: object) -> _Output:
        calls.append(dict(kwargs))
        return _Output(_Logits(last))

    sliced = _forward_last_token_logits(
        torch=SimpleNamespace(),
        model=_model,
        model_inputs={"input_ids": object()},
    )
    assert calls[0]["logits_to_keep"] == 1
    assert calls[0]["use_cache"] is False
    assert sliced == last


def test_forward_fails_closed_when_logits_to_keep_unsupported() -> None:
    def _model(**kwargs: object) -> _Output:
        if "logits_to_keep" in kwargs:
            raise TypeError("got an unexpected keyword argument 'logits_to_keep'")
        raise AssertionError("must not retry the full-sequence logit path")

    with pytest.raises(RuntimeError, match="logits_to_keep=1"):
        _forward_last_token_logits(
            torch=SimpleNamespace(),
            model=_model,
            model_inputs={"input_ids": object()},
        )


def test_last_token_scores_match_full_sequence_tail_and_preserve_order() -> None:
    # Prefix vocab is poisoned so a wrong-token slice would invert ranking.
    last = [[0.1, 2.4, 0.0], [1.8, 0.2, 0.0]]
    full_path = [row[:] for row in last]
    kept_path = _forward_last_token_logits(
        torch=SimpleNamespace(),
        model=lambda **kwargs: _Output(_Logits(last)),
        model_inputs={"input_ids": object()},
    )
    assert kept_path == full_path
    scores_old = [_yes_probability(row[0], row[1]) for row in full_path]
    scores_new = [_yes_probability(row[0], row[1]) for row in kept_path]
    assert scores_old == pytest.approx(scores_new, rel=0, abs=1e-12)
    assert [index for index, _ in sorted(enumerate(scores_new), key=lambda item: -item[1])] == [
        0,
        1,
    ]
