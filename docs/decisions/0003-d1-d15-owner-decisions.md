# ADR 0003 — Sealed D1–D15 owner decisions and contrary-authority review

**Status:** accepted
**Date:** 2026-08-16
**Code never self-authors these records.**

## Decision

Owner decisions for Live60 are a sealed artifact
`legalbot.live60-owner-decisions.v1` covering D1–D15. Contrary-authority review
is a separate sealed artifact `legalbot.contrary-authority-review.v1`.

`reviewed_none_in_defined_source_set` means the owner reviewed a named source
set and bound no contrary span in that set. It does not mean English law has
no contrary authority. Critical or disputed propositions still need independent
second review.

D5–D9 stay conditional. D6 (ACTIVE promotion), D7 (rollback proof), D8 (browser
recovery) and D9 (O-04) remain real later owner actions and are never written
by this control plane.

ACTIVE status is a read-only reconciler
(`missing`, `candidate_unpromoted`, `active_reconciled`, mismatch, rollback,
`invalid_or_tampered`). `status`, `readiness`, `export` and `verify` cannot
create `ACTIVE.json`. Promotion remains `legalbot promote` only.
