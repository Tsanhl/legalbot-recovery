# Retrieval benchmark — current state

`v1.1.jsonl` is the only current benchmark. It contains 24 positive ranking
cases: 16 development and 8 promotion. On 13 August 2026 the owner adopted the
official-source fact check (5 approve, 19 amend, 0 reject), and
`v1.1.freeze.json` sealed the amended JSONL, policy, scorer, decision and fact
check by SHA-256.

The freeze covers the queries, E&W/as-of scope, expected immutable source
version, legal locator, exact supporting span bundles, match mode, split,
policy and scorer.
It does **not** freeze the corpus, current law, embeddings, model, index or
instructions. Those have separate immutable manifests and may advance.

Before scoring, the canonical runner now creates an in-memory, audited
candidate binding.  A statute's frozen authority/locator/span may resolve to a
newer ``latest-available`` source version only when every exact gold span is
still present and the candidate's sealed provision registry qualifies that
locator and immutable source bytes.  Missing review, changed spans, ambiguous
versions or a candidate/seal digest mismatch stop scoring.  The frozen JSONL
is never rewritten.  Immutable case versions must remain exact.

Refusal, clarification, wrong-jurisdiction and zero-evidence behaviour belong
to sealed A2 and are deliberately absent here. The source/locator gold resolves
to candidate chunk IDs at evaluation time; chunk IDs are not fundamental gold.

Broad statutory questions use source-and-locator ranking plus separately
measured exact-span bundle recall. Narrow propositions use source-and-span;
explicit case identifiers use source-identity-only. This prevents one opening
fragment from pretending to be complete gold while keeping the promotion gate
about retrieval ranking rather than answer generation.

`v1.jsonl` and its companion files are retained as invalidated v1.0 audit
material. The provisional v1.1 draft is preserved under
`archive/v1.1-provisional-2026-08-13/`. No current loader may select either.
