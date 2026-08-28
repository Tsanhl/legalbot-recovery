# LegalBot v1.11 recovery-workspace agent rules

## Workspace authority

- `/Users/hltsang/Desktop/LegalBot-v111-Recovery-20260829` is the only writable v1.11 implementation workspace.
- `/Users/hltsang/Desktop/LegalBot-New` is outside this workspace. Do not read, edit, format, generate artifacts in, initialize or alter Git in, commit, rebase, clean, stash or otherwise access or mutate it without a new explicit owner authorization.
- `/Users/hltsang/Desktop/LegalBot-v111-Integration` is a damaged retired path. Do not import, execute, write, or recover from it. It may only be moved to recoverable Trash after every process using it has stopped.
- This workspace intentionally has no active Git metadata after the 29 August recovery cleanup. Do not initialize Git, add a remote, create a branch, commit, push or restore the historical bundle unless the owner explicitly authorizes that exact action. The owner will establish the new Git repository separately.
- Do not promote a candidate, run Owner Certification 60, unseal Validation 30 or activate live without the applicable owner gate.
- Keep Phase 2A and all later phase implementation and execution in this repository. Do not create a sibling top-level repository or clone for an individual phase.
- Store new phase evidence beneath this repository and use concise phase/date run names, for example `LegalBot-Phase2A-2026-08-24`, `LegalBot-Phase2B-2026-08-24` or `LegalBot-Phase2AB-2026-08-24`. Add `-rN` only when a new immutable revision is required. Preserve existing sealed artifact names and digests.
- Keep `README.md`, this `AGENTS.md` and `docs/CURRENT_STATE.md` as maintained control documents. Do not delete them as historical clutter; update their current-state sections without rewriting sealed evidence history.

## Autonomous repair and stop policy

- Codex may make conservative technical repairs, add regressions, implement and test synthetic non-authorizing report/projection scaffolding and choose implementation mechanics that do not change an owner-approved policy, legal judgment, candidate, split or release authority.
- Only the owner may supply or approve signatures, credentials/secrets, legal-currentness judgments, model transport, private review roots, resource envelope, certification contract, 30/30 split secret, Development acceptance, promotion, O-04, Validation acceptance and live activation.
- Classify failures by a stable fingerprint: command/gate, failing test or stage, exception/error code and relevant artifact identity.
- Never rerun an unchanged failing command merely hoping for a different result. Diagnose the fingerprint and make a targeted change first.
- After the same fingerprint has failed twice despite attempted repair, stop that path before a third retry. Preserve evidence and report the blocker/root cause; do not loop or spend tokens repeating the same step.
- A distinct formatting or environment prerequisite failure is tracked separately, but it must still be corrected before rerunning the substantive gate.
- No real answer-model, Development-30, Validation-30, promotion or live invocation is a debugging tool.
- Generated gRPC stubs, UDS server/client and synthetic transport tests are technical preparation only. Production gRPC activation and model-backed conversation rewriting remain disabled until the exact Phase-2B model-transport owner gate creates the verified capability.
- Catalogue compaction and full-row classification are offline maintenance-window operations. Never run an online blind delete or in-place `VACUUM`; require a recent successful backup/restore receipt, zero writers/jobs/scans/builds, bounded diagnostics and create-new verification before any separately approved swap.
- Backup pruning requires a current successful restore drill and an exact prune manifest. Preserve at least the current recoverable backup and the most recent predecessor; use recoverable Trash for approved local cleanup rather than silent deletion.

## Review-output layout

- Development, sealed Validation custody and ordinary live review use three distinct owner-approved private roots; none may fall back to a shared canary root or another lane's root.
- Readable Development/live question-answer folders are non-authorizing projections. The immutable upstream package and signed owner decision remain authoritative.
- Codex may implement and test the folder projection with synthetic records in Phase 1. It must not invoke a real Development or live projection until the exact root is owner-approved and a typed strict verifier has accepted the exact upstream package.
- Never project or expose Sealed Validation outputs before its frozen one-pass disclosure gate.

## Clean-room rules

- Never import, copy, mount, query or fall back to code, databases, indexes, adapters, gates, configuration or runtime state from the old project.
- Do not access an old project or `LegalBot-New`, including any `New_materials` directory, without a new explicit owner authorization. `/Users/hltsang/Desktop/Law` remains the only external configured source root currently permitted.
- Raw source bytes and canonical Markdown are immutable. Search indexes are derived, versioned and disposable.
- No absolute source path, owner identifier or original personal filename may enter a prompt, answer, review JSON or application log.
- No material legal claim is released without a frozen `EvidenceSpan` whose identity, jurisdiction and currentness have passed.
- The model never renders citations. OSCOLA is deterministic from reviewed metadata.
- Teaching and feedback lanes never count as independent legal authority.
- Repairs create new versions and explicit diffs; they do not mutate or silently delete earlier prose.
- The first release binds only to `127.0.0.1`. Do not add auth, cloud storage, sharing or training exports without a new approval phase.
- Remaining selected-issue checks may use official-source internet (`legislation.gov.uk`, Find Case Law) and may download official files into configured source roots. Those bytes are not gold until catalogue or accepted v2-repair hashes match. AI is not the `legal_reviewer`.
- Run `python scripts/check_clean_room.py`, the complete Python suite and the web build/tests before promotion.
