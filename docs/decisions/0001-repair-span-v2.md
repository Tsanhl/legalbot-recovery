# ADR 0001 — Repair-span v2 identity

**Status:** accepted
**Date:** 2026-08-16
**Does not seal gold. Does not write ACTIVE or O-04.**

## Decision

New per-span schema `legalbot.live60-repair-span.v2` is the successor for
contiguous held-statute repair candidates. `repair_span_id` is derived from the
full identity tuple:

- parent chunk id
- source version id
- legal authority id
- official snapshot content hash
- required sublocator
- role
- markdown text
- derivation manifest

Existing v1 artifacts remain byte-identical on disk. They are rejected as new
gold. Exact-match verification fails closed on any identity field mismatch,
including a recomputed id that does not match the stored id. The dots-only
IPFDA parent `chunk-0bdcbc97ae11975ac1032cc3c6974aeaad9e43a7` stays excluded.
Spliced parents are not reconstructed.

## Consequences

Catalogue parents stay immutable. Repair spans remain candidates until the
owner binds them through path B. AI checks mechanical equality only.
