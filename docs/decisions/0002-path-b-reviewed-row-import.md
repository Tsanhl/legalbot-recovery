# ADR 0002 — Path-B reviewed-row import and owner overlay seal

**Status:** accepted
**Date:** 2026-08-16
**Does not fabricate legal gold. Does not write ACTIVE or O-04.**

## Decision

Path B is an owner-controlled workflow:

1. Export sealed candidate rows (`legalbot live60-review-export`).
2. Owner reviews those exact rows.
3. Import only rows that match the export (`legalbot live60-review-import`).
4. Reconstruct dispositions for all 585 issues (`qualified` / `limited` /
   `knowledge_gap`).
5. Explicit owner-only overlay seal requiring 585 dispositions, exact
   candidate / run-plan / legal-date binding, and an owner-supplied
   `reviewer_ref`.

Plaintext span preview lives only in an owner-controlled encrypted object.
`apply_owner_ticks()` stays fail-closed: named qualifies without spans are
refused. Code never self-authors the overlay. One selected case becoming
generation-eligible does not authorise the other 29, and never triggers model
calls.

## Consequences

Owner ticks remain a draft control plane. Overlay sealing is a separate
privileged action. Stage A remains later.
