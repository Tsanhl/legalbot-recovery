# LegalBot v1.11 disaster-recovery report

Status: **partial verified recovery, non-ACTIVE, awaiting owner decision**.

The latest provable Git and local-code state has been reconstructed in:

`/Users/hltsang/Desktop/LegalBot-v111-Recovery-20260829/work/posthead-replay-r6`

The damaged original repository has not been replaced. Its material data/evidence appears unchanged insofar as verified, but an early verification created a non-material `.ruff_cache` subtree there at 2026-08-29 01:55:54 HKT; it is preserved and disclosed, not hidden or deleted. `LegalBot-New` was absent when checked and was neither created nor modified. During this recovery, no Phase 2A execution chain, Phase 2B, source scan, candidate build, embedding, retrieval re-attestation, all-585 qualification, pointer write, answer run, promotion or live activation was performed.

A local embedding-server process that started before this recovery workspace was created was observed and left alone. This recovery did not invoke it or send it work.

## What was recovered

- Verified Git baseline `79d0629…`, all 10 lost local commits, recovered HEAD `1ea0ed9…`, and tree `15cead6…`. `git fsck --full --no-reflogs` passes.
- The chronological r6 replay contains 1,784 successful patch effects and 238 observed historical Ruff mutation actions. Failed replay revisions r1–r5 remain preserved as evidence.
- Git-status parity is 431 of 438 expected incident entries: all 78 tracked modifications and 353 of 360 untracked entries are present, with no unexpected entry.
- The catalogue was placed with sealed SHA-256 `fac8cf47…` (6,204,092,416 bytes). Its staged integrity evidence records `quick_check=ok`, zero foreign-key violations and exact counts for all 45 tables.
- The source tree contains 316 exact files (395,974,546 bytes), tree SHA-256 `b972cbd2…`: 254 Cursor-snapshot legacy files, 46 exact Law matches and 16 additional exact official-source recoveries.
- Four complete evaluation roots were restored exactly: 25 files and 3,329,523 bytes. One partial Q53 root remains evidence-only and was not installed.
- Exact candidate metadata/config members were preserved as evidence. The successor qualification config and archived predecessor config match their sealed hashes.
- Python code/safety scope: 1,528 passed and 3 skipped across 1,531 selected nodes. Web build and SPA tests passed 10/10. Clean-room and whitespace checks pass.

## What could not be honestly reconstructed

- Seven expected seminar config entries remain absent. Four exact children and one deterministic-semantic derivative are preserved in recovery evidence, but they were withheld from runnable config because two required parent manifests cannot be recovered exactly.
- Eight exact source representations remain absent: five current official responses no longer match the sealed historical bytes, and three JCPC targets were outside the bounded allowlist and were not requested.
- Of 425 pre-loss referenced evaluation/quarantine roots, four complete roots were restored, one partial root was staged but excluded, and 420 remain unproven or unavailable.
- The actual Lance vector trees for the historical 2026-08-18 and 2026-08-27 candidates are unavailable. `data/indexes` therefore contains only `.gitkeep`; there is no runnable, ACTIVE or PREVIOUS candidate.
- Artifact-dependent verification is not green: 455 node IDs across 106 test files remain in the last-failed cache. The saved bounded-run log reaches 100% and lists 321 `FAILED` plus 134 `ERROR` identifiers, but contains no final pytest aggregate line. This is recovery evidence, not Phase 2A qualification.
- Full Ruff check reports 48 issues already present in the reconstructed incident code state. They were not auto-fixed because byte-faithful recovery takes precedence over cleanup.

## Catalogue verification side effect

A final read-only SQLite verification connection created a zero-byte WAL and a 32 KB SHM sidecar. The redundant verifier was stopped, the sidecars were preserved and hashed, and the main catalogue inode, size and mtime remained unchanged from its placement receipt. This is disclosed rather than silently cleaned up.

## Decision boundary

This package is suitable for owner review, not automatic replacement. Approving it would mean accepting a partial, fail-closed recovery with the listed unavailable bytes and no runnable vector candidate. The original repository path must remain untouched until the owner gives a new approval bound to the exact manifest/checksum digest.

See `RECOVERY-MANIFEST.json` for exact hashes and inventories.
