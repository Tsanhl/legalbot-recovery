# Blind human 70+ calibration protocol

This gate cannot be completed by the developer, the answer-generating model or
the automated academic lint. It requires at least two independent legal
reviewers who do not see the model identity or automated score while marking.

Use at least 20 privacy-passed answers across at least five subjects. Include at
least five genuine 70+ answers, five below-70 answers and double-mark at least
20% of the set. Do not include the answer's automated score, retrieval variant
or model identity in the review pack.

Score the frozen rubric: issue spotting 15; rule accuracy 20; application or
critical analysis 20; authority and counterargument 15; completeness and
uncertainty 15; structure and conclusion 10; citation accuracy 5. Any material
legal or citation error forces `below_70`, even where the arithmetic total is
70 or more.

Human records contain only safe case/run IDs, a SHA-256 reviewer pseudonym,
subject, scores and blindness attestations. They must not contain names, source
text, questions or review prose. Private comments remain encrypted in the
evaluation vault.

After marking, export the automated scores separately and run:

```bash
uv run python scripts/validate_blind_calibration.py HUMAN.jsonl AUTOMATED.jsonl
```

The aggregate gate requires at least 85% pass/fail agreement, mean absolute
score error at most 10 points and zero automated 70+ classifications on an
answer with a fatal legal or citation error. Passing this gate calibrates the
lint signal; it does not turn automated scoring into legal proof.
