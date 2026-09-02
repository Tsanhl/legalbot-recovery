# GE technical verification snapshot r2

Created: 2026-09-01T09:58:57.315900+00:00

The finalized broad GE matrix passes all 130 tests across the visible harness, 23-domain coverage authority and loop, encrypted persistence, schema registry, official-research control, source scope, held-index lanes, generic-read rejection, recovery/resume, DB-to-Lance parity and vector carry-forward. Strict mypy passes all 309 application modules; Ruff, clean-room and system-design checks pass. The selected registry digest is `ca93229c3a446801424024c3074509ef589597aa3afc36f74bceade865f429d7`.

The ordinary non-ACTIVE build `current-law-ew-full-fp16-v111-20260829-recovery-b` is `built_unscored`. Its sealed tree and all 149,855 DB-to-Lance rows passed exact content, source, order, vector-dimension and lane parity with zero mismatches. No `ACTIVE.json` or `PREVIOUS.json` exists.

The complete Python suite is not green: 2,512 tests were collected and the first full run recorded 443 failed/error nodes. One current defect was repaired: re-attestation now supports the explicitly known catalogue schema range through v31 and its 9 tests pass. The remaining recorded failures are dominated by 430 historical Phase-2A nodes whose immutable input packages/builds are absent or whose sealed dependency digests differ after hardening. Repository-bound candidate and seminar tests also require missing historical artifacts. These fingerprints must not be retried unchanged or hidden by weakening tests; historical restoration/replacement requires exact owner authority.

No real GE run, unseen access, training, official-source gap download, promotion, live action, Git/GitHub action or deletion occurred. Exact machine-readable details and the recorded node list are in `VERIFICATION.json`.
