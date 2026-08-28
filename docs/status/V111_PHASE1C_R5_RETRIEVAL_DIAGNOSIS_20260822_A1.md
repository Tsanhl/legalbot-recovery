# LegalBot v1.11 Phase 1C — r5 retrieval diagnosis

Status: **two pre-rerank admission misses identified; r5 remains failed evidence**.

The one real r5 run completed 24/24 retrieval calls and improved the result from 6/24 to 22/24. MRR passed at 0.8958 and every contamination gate passed. The unchanged recall gates failed because `dev-ola1957-s2` and `prom-perpetuities-s5` did not return their exact frozen spans.

Both gold spans were already present in the unchanged candidate pools. The OLA 1957 gold chunks were vector ranks 1 and 3 and fused ranks 4 and 6. The Perpetuities and Accumulations Act gold chunk was vector rank 6 and fused rank 12. None reached Qwen because admission treated every chunk sharing a source and statutory locator—or its locator-derived ordinal—as one duplicate. That assumption is invalid for atomic legislation, where several independently citable propositions share a section locator.

The r6 correction retains the same candidate, filters, queries, embeddings, fusion, per-source cap, reranker, top-k values, gold and thresholds. It replaces locator-only suppression with content-overlap suppression for genuine sibling windows. A two-case diagnostic using that generic rule put the exact gold at final ranks 3/4 and 2 without changing any retrieval depth.

r5 is not rerun and cannot become passing evidence. Machine record: `docs/status/v111-phase1c-r5-retrieval-diagnosis-20260822-a1.json`.
