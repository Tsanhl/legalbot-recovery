# ADR 0004 — Xerj is not merged

**Status:** accepted
**Date:** 2026-08-16

## Decision

Xerj is not copied, vendored or merged into LegalBot. No `crates/`, Lance
replacement or AutoIndex lands here. An optional sidecar adapter may exist
later, defaulting to `LEGALBOT_XERJ_ENABLED=false`. If cloned at all, it is a
sibling Desktop reference only and must never be pointed at the catalogue,
vault, questions, answers or review material.

Later viewer choice is Phoenix **or** Xerj, not both. Neither is enabled
before first live.
