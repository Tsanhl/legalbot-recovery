# Evidence-first architecture

The complete rebuild design is [V111_SYSTEM_DESIGN.md](V111_SYSTEM_DESIGN.md).
Delivery now has three phases: system design; GE-first evaluation/training/unseen
(PB/Essay retained); live last. Legacy phase names below identify retained control
contracts, not additional delivery phases. The complete design adds scoped
structured matter-facts lookup as an explicit unimplemented adapter alongside
existing legal-source retrieval and encrypted conversation storage.
This page describes the retained architecture; component presence is not proof
of a running or certified system. See [CURRENT_STATE.md](CURRENT_STATE.md) for
the current non-ACTIVE state and missing runtime artifacts.

## Immutable layers

1. Raw source bytes are written once under a SHA-256 vault key.
2. Canonical Markdown is generated with a provenance header and stable page, paragraph, provision or heading anchors.
3. Comments and tracked revisions are separate Markdown streams. Student prose is not silently mixed with marker feedback.
4. SQLite records every path alias encrypted, plus the public-safe source label, status, lane, subject, jurisdiction, rights and currentness.
5. Each LanceDB build is sealed with a manifest and metrics. The single atomic `ACTIVE.json` pointer is the only runtime selector.

Vectors and lexical indexes are rebuildable from Markdown. They are never the source of truth.

### Canonical Markdown provenance schemas

The current converter uses `legalbot.canonical-markdown.v3`; v2 is a retained
historical schema. Canonical headers contain stable provenance. Audit-only fields such as
`retrieved_at` and scan-run identifiers are excluded, so identical parsed content, classification
and source identity always produce identical body, comment and revision bytes and SHA-256 keys.
The separate `legalbot.provenance-audit.v1` JSON object retains the full provenance record,
including retrieval time and scan identifiers. Audit JSON is therefore allowed to differ between
clean rebuilds; canonical Markdown is not.

## Answer transaction

Each durable job stores encrypted input, progress events and checkpoints. The orchestrator classifies task and jurisdiction, retrieves only approved compatible evidence, optionally creates a staged official-research review item, asks the local model for evidence-ID-bound claims, renders OSCOLA, verifies every material claim, evaluates the 70+ rubric and repairs only named sections.

Released answers freeze their claim/span snapshot, model revision, index generation and policy version. A later reindex cannot rewrite an old answer’s evidence.

## Conversation and freshness boundaries

Conversation sessions are encrypted durable SQLite records with a 30-day
inactivity lifetime. The hot process-local cache has a seven-day TTL and a
bounded LRU; prompt context uses explicit message/token sliding-window limits.
Conversation prose may help resolve a follow-up question, but it is never an
authority lane and cannot satisfy a material-claim evidence gate. Redis is not
a dependency for this single-owner host; the cache contract leaves room for a
future adapter without replacing the durable record.

Knowledge changes arrive as idempotent events. Low volume is admitted directly
to the existing durable research queue; bursts use the same queue in batch
mode. Fetches are allowlisted and quarantined. Chunking, embedding and LanceDB
ingestion occur only in a new candidate generation after proposition-level
owner admission. `source_date` describes the official record while
`last_updated` describes the observed/ingested version; retrieval collapses
eligible duplicates to the newest approved authority version before scoring.

For the GE loop, an official-source addition must replay the exact diagnosed
result, research/retrieval evidence, reviews, quarantine/vault bytes, staged and
approved rows and chunks. Its index is a strict non-ACTIVE successor of one exact
sealed predecessor: all predecessor source members remain byte-identical and in
order, and at least one separately qualified source is appended. Held GE trees are
readable only through the verifier-issued evaluation capability; generic retrieval,
benchmark, research, vector-reuse, evidence, live and direct-Lance paths reject
them before opening the index.

GE coverage is also capability-bound. A trusted verifier replays the exact stored
owner request and resolution before issuing an opaque authorization over the
ordered topology. The required floor is 23 distinct domains: all 17 fixed-bank
topics plus separate housing, employment, family, immigration, benefits/debt and
consumer domains. Empty public-domain assignments remain explicit gaps and require
separate visible diagnostics; a narrower, reordered or aliased manifest cannot
close the loop.

There is no in-place vector update or generic write-then-delete path. The legal
equivalent is a new immutable generation, full verification and an explicit
owner-approved pointer switch.

## Security boundaries

- HTTP services bind to IPv4 loopback.
- Source paths and original filenames are encrypted; safe aliases enter retrieval.
- Model requests contain evidence text and IDs, never filesystem paths.
- Document-borne prompt instructions are quarantined or blocked.
- Unreleased versions use a macOS Keychain-held Fernet key and expire after 30 days.
- Online fetch adapters use an allowlist and produce staged candidates only.

## Local runtime topology and transport

The target local deployment uses an API, durable worker and model sidecar. FastAPI serves `/api/v1`, `/`,
`/admin`, and hashed Vite assets from the same origin at `127.0.0.1:8777`. The
existing versioned MLX HTTP adapter targets the loopback model interface at
`127.0.0.1:8778`; generation belongs to the durable worker. `scripts/start.sh` validates the built UI and pinned model
artifact before starting the model runtime, API and durable worker, and
terminates the group if any process exits.

Development adds Vite: it owns `127.0.0.1:8777` and proxies `/api` to
FastAPI at `127.0.0.1:8776`; the model interface remains at `8778`. This split
exists only for hot module replacement.

The local application remains a modular service, not a fleet of independently
deployed microservices: conversation, query routing, retrieval and release
validation share the FastAPI/worker codebase and SQLite transaction boundary.
The official-source research worker is separately leased and disabled by
default. The model runtime is the one process boundary that benefits from a
typed streaming contract.

The browser receives bounded, replayable progress and final release identity
over WebSocket. Raw model tokens and unvalidated draft sentences never cross
that boundary, because only deterministically validated claims may be shown.
The Phase-2B replacement model contract is protobuf server-streaming gRPC over
a private Unix-domain socket. It records time-to-first-token and sentence-level
evidence/standards/knowledge-hurdle diagnostics internally, but does not make a
sentence releaseable merely because it streamed. The HTTP adapter remains in
code but no answer runtime is currently active. Production UDS/gRPC activation
and model-backed rewriting remain disabled until the exact Phase-2B owner gate;
synthetic transport preparation does not confer that authority.

`docs/CURRENT_STATE.md` is the authoritative live architecture. Dated reports
are historical snapshots and must identify their code commit.
