# Real-browser recovery drill recording

This gate is recorded only after an owner has run the local browser flow and
personally observed all of the following:

- a real browser submitted one ordinary local answer job before O-04;
- the page was reloaded while the job was still running;
- the same job identity was recovered and progress resumed;
- a terminal state became visible without an indefinite spinner;
- exactly one released answer appeared;
- the released view passed privacy inspection;
- API and model traffic remained loopback-only; and
- no online research adapter was called.

The recorder does **not** drive a browser or manufacture those observations.
It also requires the exact job, trace, target Live60 run, suite digest,
Europe/London date and ACTIVE build. The drill job itself must have no Live60
evaluation headers, evaluation-request digest, full-retention flag or
evaluation-case-run link; those remain unavailable until O-04. It is expressly
sealed as `counts_as_live60_selected_outcome=false`, so the ordinary drill can
never satisfy one of the final 30 Live60 outcomes.

Before writing anything, the recorder reconciles the job and release outbox in
SQLite, the immutable target-run snapshots, the current Live60 suite and the
integrity-checked ACTIVE pointer. It also binds a privacy-safe request
fingerprint (including a digest of the encrypted question bytes), actual route,
legal date, word target, model, ACTIVE build and source-manifest digest, plus the
actual prompt, router, classifier, policy and assessment-bundle identities.
Those identities must agree with both the worker job and the current run
manifest.

After the drill, run `scripts/record_browser_recovery_drill.py --help` and
provide every required identity and every `--confirm-*` flag. Missing flags or
any runtime mismatch fail closed and leave no gate file. The successful result
is an owner-only, create-once, self-sealed JSON artifact at
`data/evaluations/e2e/gates/browser-recovery-drill.json`.

Do not record the gate from static web tests, screenshots, a simulated client,
or a job that did not undergo reload/recovery. The gate contains only opaque
IDs, hashes, states, counts and timings; never paste questions, answers,
filenames, source text or filesystem paths into it.
