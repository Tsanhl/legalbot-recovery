# LegalBot v1.11 Phase 1C — r4 retrieval diagnosis

Status: **systematic candidate-date filtering defect identified; r4 remains failed evidence**.

The immutable r4 attempt completed 24/24 retrieval calls. It passed candidate/gold binding and every contamination gate, but achieved only 6/24 hits, recall@5 = 0.25, recall@10 = 0.25 and MRR = 0.25 in the aggregate and in both frozen subgroups. The six exact neutral-citation identity queries passed at rank 1. All 18 legislation queries failed.

Read-only stage diagnostics showed that the r4 evaluation adapter gave both Lance backends a hard-coded as-of date of 2026-08-13 after the binding gate had validly rebound the legislation rows to the sealed 2026-08-14 candidate snapshot. The ordinary Lance predicate consequently excluded every statute before lexical/vector ranking. With only the already-proven candidate-bound date substituted for diagnosis, the correct source appeared in the unchanged vector top-20 for all 18 legislation queries and in the lexical top-20 for 12/18.

The r5 correction is therefore limited to deriving the evaluation retrieval date from the strict candidate binding and revalidating every legislation row against that date, source and version. It does not alter the candidate, queries, gold, thresholds, top-k values, embeddings, fusion or reranker. r4 is not rerun and cannot become passing evidence.

Machine record: `docs/status/v111-phase1c-r4-retrieval-diagnosis-20260822-a1.json`.
