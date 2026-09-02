# LegalBot v1.11 Phase 1 recovery readiness

31 August update: this is the preserved 29 August checklist. Git metadata, both
pinned retrieval models and completed source-scan records are now present;
the new candidate and sealed baseline are still missing. Current work is tracked
in [the rebuild checklist](../V111_REBUILD_CHECKLIST.md) and
[current state](../CURRENT_STATE.md). The dated missing-input statements below
are historical, not instructions to repeat completed work.

Status: **historically complete at r8; current recovered workspace requires a new Phase 1 baseline**.

This checklist is limited to Phase 1. Missing Phase-2A seminar manifests,
historical owner-review packages and later source representations do not block
this technical rebaseline and must not be fabricated to make Phase 1 pass.

## Remaining work

1. **Owner-created Git repository and clean HEAD.** The active workspace has no
   `.git` by owner instruction. After the owner initializes the new repository,
   create one clean committed baseline and bind the exact commit and tree. The
   recovered Git bundle is evidence only.
2. **Phase-scope hygiene.** Keep incomplete Phase-2A/2B generators and their
   artifact-dependent tests outside the Phase-1 pass/fail scope, or make those
   tests fixture-complete. The recovered 455 last-failed entries are not a
   Phase-1 result: 430 are Phase 2A, 18 Phase 2B, two seminar and five
   candidate/retrieval entries.
3. **Freeze the new source topology.** The default roots are now the external
   `Law` root and the project-owned source vault only. Run and account a fresh
   complete scan, or bind a retained scan after proving its root tuple and every
   file outcome. Do not access `LegalBot-New` or any old-project source root.
4. **Restore pinned retrieval models.** Hash-verify the exact embedding and
   reranker stores required by `scripts/model/manifests/qwen3-retrieval-models.json`:
   `models/retrieval/Qwen3-Embedding-0.6B` and
   `models/retrieval/Qwen3-Reranker-0.6B`. They are absent now.
5. **Build one new non-ACTIVE candidate.** The historical Lance table bytes are
   unavailable. Build from the verified catalogue/source scope; seal source,
   qualification, parser/chunker/model identities and lexical/vector count
   parity. Do not write `ACTIVE` or `PREVIOUS`.
6. **Run the frozen 24-case retrieval attestation once.** Bind checked-in
   `benchmarks/retrieval/v1.1.jsonl` to the new candidate and require 24/24
   binding, Recall@5 `1.0`, Recall@10 at least `0.95`, MRR at least `0.8`, and
   zero teaching/private-path/wrong-version contamination. The last surviving
   tracked result is r6 at 23/24; no passing r7 result survived.
7. **Pass the 18-check Integration matrix on the exact clean HEAD.** Use Python
   3.13 and Node 24, then run locks, Ruff/format, mypy, static baseline, complete
   Phase-1 Python scope, immutable Live60 verification, clean-room, workflow and
   content security, web clean install/lint/test/build/audit, and final diff/
   identity checks. Recovery smoke evidence (1,528 Python passes, three skips,
   and 10/10 web tests) is useful but is not this sealed run.
8. **Seal the new exit.** Write one immutable recovery-baseline report bound to
   the new commit/tree, locks, source scan, candidate/seal, scorer closure and
   passing attestation. Keep release pointers absent. Only then may the current
   workspace claim `INTEGRATION BASELINE COMPLETE - READY TO BEGIN OWNER CERTIFICATION`.

## Authority boundary

No substantive legal/currentness or Phase-2 owner decision is required for
these Phase-1 technical repairs. A new scan/build/embedding is operational work
only and must remain bounded, non-ACTIVE and answer-ineligible. It must not be
used to resume Phase 2A, run an answer model or activate the product.

## Not Phase-1 blockers

- Seven unavailable seminar config entries.
- Eight unavailable exact later Phase-2A source representations.
- 420 unproven or unavailable Phase-2A evaluation/quarantine roots.
- The prior Phase-2A 585-row outcome and every Phase-2B draft package.
