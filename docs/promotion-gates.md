# Promotion gates

A candidate cannot become the active owner-only release until all applicable checks pass:

- 100% source-file accounting with visible duplicate, OCR, encrypted, unsupported and quarantine outcomes.
- Canonical Markdown/provenance hashes reproduce from raw vault bytes.
- All production vectors are 1,024-dimensional Qwen3 embeddings; lexical and vector counts equal chunk counts.
- The embedding runtime is pinned to `Qwen/Qwen3-Embedding-0.6B@97b0c614be4d77ee51c0cef4e5f07c00f9eb65b3;dtype=float16;batch=8` for the 16-GB release machine.
  and the reranker to `Qwen/Qwen3-Reranker-0.6B@e61197ed45024b0ed8a2d74b80b4d909f1255473`.
  Mutable `main` revisions and unverified local directories are rejected.
- Reranker smoke must identify `Qwen3ForCausalLM`, use left padding and the official yes/no
  log-softmax semantics, rank a related passage above an unrelated control, and emit no untrained
  classifier-head warning. Generic sequence-classification fallback is forbidden.
- Full-corpus catalogue reads, embeddings and LanceDB writes are bounded batches. A second streamed
  pass must reproduce the first source-manifest digest or the build fails as a changed snapshot.
- A versioned, owner-approved benchmark from `benchmarks/retrieval/v1.1.jsonl` is required. Draft,
  missing, malformed or empty benchmarks fail closed before model/index work begins.
- Primary-authority must-hit Recall@5 is 100%, broader Recall@10 at least 95%, and MRR
  is at least 0.8. A missing expected chunk or a must-hit labelled with a non-primary lane is
  an integrity failure, not merely a low score. Gold is stable authority +
  source version + legal locator/span hash; candidate chunk IDs are resolved
  at evaluation time and are never fundamental legal gold.
- Hard jurisdiction and material-lane isolation tests have zero leaks.
  Exact normalized jurisdiction keys are applied in the Lance prefilter and post-filter, including
  for non-core jurisdictions that share the broad `comparative` type.
- Every released material claim binds a verified span; zero invented authorities, false quotations or wrong citation identities.
- Until blind human calibration is complete, the automated 70+ score is a
  repair-oriented lint signal, not a release-safety gate or proof of quality.
- The 970→391 regression retains both versions and their diff, performs targeted repair, and returns a full/concise/limited answer rather than a generic failure.
- Offline, no-source, conflicting authority, model crash, malformed JSON, OCR failure, encrypted PDF and injected-document cases have deterministic named outcomes.
- PII never appears in prompts, review JSON, logs, training exports or unrelated answers.
- Training export remains disabled without explicit user opt-in and owner approval.
- The clean-room script finds no old imports, indexes, databases, adapters or runtime dependencies.

Promotion is atomic and rollback is exercised before acceptance. Online candidates and feedback-derived rules require human approval independent of index promotion.

Each evaluated build preserves immutable `retrieval-benchmark.jsonl`,
`retrieval-benchmark-report.json` and `evaluation.json` files. Their SHA-256 hashes are part of
the build seal and are rechecked with the metric thresholds immediately before `ACTIVE` changes.
Failed candidates retain their report for diagnosis but never receive a seal.

The eight-case retrieval smoke (including fixture fallback) is diagnostic only
and can never set `promotion_eligible=true`. A durable build is
`built_unscored` until the canonical v1.1 scorer produces an immutable passing
attestation bound to the build, source manifest, policy and benchmark hashes.
