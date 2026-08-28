# LegalBot v1.11 workspace cleanup report

Completed: 29 August 2026 (Hong Kong)

Status: **PASS — the recovery root is now the single clean, non-Git active
workspace.**

## Outcome

- The complete recovered `posthead-replay-r6` working tree was flattened into
  `/Users/hltsang/Desktop/LegalBot-v111-Recovery-20260829` without `.git`,
  virtual environments, dependency trees, build outputs or caches.
- Pre-cleanup checksum comparison found zero working-tree differences and zero
  source-tree differences.
- Old side-work, toolchain cache, forensic working copies and generated caches
  were moved to macOS Trash. This was recoverable cleanup, not permanent
  deletion.
- The active catalogue, 316-source vault, one current catalogue backup, one
  immediate predecessor, a 316-source snapshot, recovery receipts and the
  verified ten-commit Git bundle remain under custody.
- No candidate was built or embedded. `ACTIVE.json` and `PREVIOUS.json` remain
  absent. Phase 2B, answer release and live activation were not run.

## Final checks

- Git metadata directories in the active workspace: `0`.
- Generated dependency/cache directories: `0`.
- Active catalogue SHA-256:
  `fac8cf47689a4088d2224af3ec8773d5372a41874cefe620ae38f019607804e5`.
- Active source files: `316`; retained source-snapshot files: `316`.
- Search-index contents: only `data/indexes/.gitkeep`.
- Python 3.13 clean-room check: **PASS**.
- The complete dependency-backed matrix was not rerun after intentionally
  removing environments and dependencies. It belongs to the new clean Git
  Phase 1 rebaseline.

## Remaining external cleanup

`/Users/hltsang/Desktop/LegalBot-v111-Integration` has not been moved. Seven
Codex/ChatGPT processes, including the current task, still use that path as
their working directory. Moving it while those handles exist would be unsafe.
After those tasks are closed or handed off, both the working-directory and
open-file checks must return zero; it can then be moved to recoverable Trash.

`LegalBot-New` was absent at preflight and was not accessed or modified.

## Phase 1

The exact recovery rebaseline checklist is maintained in
`docs/status/V111_PHASE1_RECOVERY_READINESS_20260829.md`. Historical Phase 1
evidence is retained, but the recovered workspace must establish a new Git
baseline, retrieval-model custody, non-ACTIVE candidate, retrieval attestation
and complete Integration matrix before it can claim a current Phase 1 pass.
