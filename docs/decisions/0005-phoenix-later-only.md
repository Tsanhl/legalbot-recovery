# ADR 0005 — Phoenix is later-only and disabled before first live

**Status:** accepted
**Date:** 2026-08-16

## Decision

Arize Phoenix is not enabled for first live. A disabled adapter and contract
tests may exist so a later owner can choose Phoenix **or** Xerj as a local
viewer, never both, never with raw question/answer/source text in exported
spans. Default OpenTelemetry export is local JSONL bridged from the existing
privacy-safe live-tracing contract. No external telemetry endpoint is
configured.
