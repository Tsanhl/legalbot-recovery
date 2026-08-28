# LegalBot v1.11 Phase 1C — r6 retrieval diagnosis

Status: **one structured-reference admission miss identified; r6 remains failed evidence**.

The one real r6 run completed all 24 retrieval calls. It passed MRR (0.90625), recall@10 (0.95833), every promotion gate and every contamination gate. The unchanged recall@5 requirement failed at 23/24 because `dev-trustee-act-s1` returned no Trustee Act 2000 section 1 passage in the final ten.

The required evidence was in the unchanged candidate and in the unchanged lexical/vector union. The first frozen section 1 gold chunk was lexical rank 11 and fused rank 18. It did not reach Qwen: eight higher-fused chunks from Trustee Act 2000—principally schedules 1 and 2—filled the per-source admission cap first. r6 therefore fixed the earlier locator-collapse defect but exposed a separate problem: an explicit statute-title/section query was still treated only as unstructured text.

The r7 correction is candidate-derived and case-agnostic. It validates the sealed approved-source manifest, resolves an unambiguous legislation title and section from that manifest, reads only that exact source, keeps only the named section and descendants, and sends those candidates through the unchanged Qwen reranker. Unknown or ambiguous references do not acquire special authority. The route has no benchmark case IDs, gold hashes, source allowlist or locator allowlist.

A non-authorizing prepare-only diagnostic against the sealed candidate resolved Trustee Act 2000 section 1 to exactly four chunks—all four frozen section 1 spans—within the existing 40-candidate rerank ceiling. The same case-agnostic route resolved the named source and section for all 18 explicit-legislation cases. It did not run Qwen, repeat r6, mutate the candidate, change top-k, lower thresholds or invoke the answer model.

r6 is not rerun and cannot become passing evidence. Machine record: `docs/status/v111-phase1c-r6-retrieval-diagnosis-20260822-a1.json`.
