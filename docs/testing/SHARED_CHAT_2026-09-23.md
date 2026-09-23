# Shared chat implementation and acceptance report

## Outcome

The local connection/conversation integration is implemented. **The legal-answering
acceptance criteria are not met.** Forty real browser conversations (20 per selected
Codex/base-Qwen route) and six withheld follow-up turns ended with evidence holds.
No campaign substantive answer was generated or published. This is a reproducible
failure result, not a 40/40 legal-quality pass or a model comparison score.

The [frozen cases and rubric](CHAT_CAMPAIGN_20.json) predate generation. Its semantic
manifest digest is `c7524551b7cd2bcc864218e479b5ecb7bf2a144c9a01e052018a26256dceeb95`;
the complete file digest is
`1e69bbbc5c706ae8157687a34f2338129447ef8aeaf74403aaf9a0b9a0d03174`.
The [per-case report](CHAT_CAMPAIGN_2026-09-23_RESULTS.json) provides all 40 rows,
turn latency, actual selected route, question equality, source outcomes, retrieval
scope, publication status and private rendered-transcript hashes. All twenty
cases remain in each model's denominator.

## What changed

- One chat replaces the Operations dashboard for owner and local testers.
  `/admin` redirects to `/`; management API access defaults off.
- Session-owned connection create/list/test/disconnect, encrypted temporary keys
  with expiry, native OS credential storage for remembered keys, and ownership
  checks on conversation/job/answer reads and cancellation. Switching providers
  does not mutate process-wide credentials.
- Encrypted durable user and assistant messages replace the four-message browser
  workaround. The append-only matter ledger stores statements and literal dates
  and amounts without inventing their legal roles. Follow-ups use complete saved
  context within an explicit bound; overflow asks for a confirmed summary.
- The local launcher privately supplies candidate/route authority. User controls
  no longer ask for internal hashes or an owner capability key.
- The existing LanceDB/embedding/reranker path now records actual in-scope query
  vectors, retrieved IDs, scores and generation bindings. Out-of-scope metadata
  holds are labelled explicitly and do not masquerade as embedding runs.
- Indexed-only and index-plus-online modes are available with remote consent.
  UK dated legislation receives identity, extent, version and effects checks,
  followed by a real case-specific source review before drafting. Actual official
  UK/US full-text bytes and capture metadata are privately retained. US captures
  remain review-pending; bounded discovery is not a general deep-search service.
- Find Case Law has purpose-specific executed-licence gates. Approved application
  correspondence does not activate capture, vectors, external-model use or training.
- Shared `.4` guidance encodes the consumer alternative route, factual questions,
  essay holding/academic-attribution distinctions, PB fact/financial-ledger discipline,
  default OSCOLA and requested grouped bibliography. GE450/Essay-PB700 ±10% and
  at most two repairs are enforced independently of the advisory 70+ score.
- Private encrypted records separate raw provider invocation/response, review
  decisions and browser DOM text. A system clarification/hold is labelled as such;
  it is not presented as a Qwen-generated legal answer.

## Real campaign

Runtime: `shared-chat-20260923-r5`, fresh non-ACTIVE candidate, existing dated
reviewed generation. All 40 exact initial prompts and six exact follow-ups match
the frozen campaign. Each final displayed conversation has an encrypted DOM
receipt. First-turn prompts for GE02, GE04 and GE09 were submitted without future
facts. The actual clarification appeared before the follow-up was sent.

| Observation | Codex route | Base Qwen route |
|---|---:|---:|
| Conversations | 20 | 20 |
| Submitted turns | 23 | 23 |
| Genuine clarification followed by resolved intake | 3 | 3 |
| Final evidence holds | 20 | 20 |
| Substantive campaign generation | 0 | 0 |
| Published legal answers | 0 | 0 |
| Accuracy, omissions, legal citations, word-count quality | Not assessable | Not assessable |

Both actual connection tests passed. The requested Codex model was `gpt-5.5`;
CLI selection does not attest to the provider's undisclosed internal snapshot.
The earlier `gpt-6-sol` rejection was a model-access rejection by this signed-in
account; it does not establish that the account lacks all Codex models.
No silent fallback occurred. The Qwen connection is the pinned
`mlx-community/Qwen3.5-9B-4bit`, with no adapter.

The first baseline (`r4`, Codex only) exposed repeated Scottish will questions,
assistant-question contamination of the missing-document detector and irrelevant
commencement-order discovery. Those records remain preserved. The repaired `r5`
follow-ups no longer repeat resolved facts. Exact instrument identities now reach
the correct legislation, where unresolved effects/version checks still hold.

### Why substantive answers held

The installed shared generation is England consumer law at **5 September 2026**.
The campaign asks for 23 September and many other topics/jurisdictions. It cannot
supply current evidence for them. Online acquisition found unresolved unapplied
legislative effects, point-in-time mismatches, source outages/403s and US documents
awaiting source/currentness review. Search hits, contents pages and successful
fetches were never substituted for verified material support.

Thus the campaign does not prove that every legal omission would be caught after
generation. It proves the current evidence gap, durable intake, explicit refusal
and transcript provenance. The writing rubric, OSCOLA renderer and length checks
have engineering tests; there is no current full-answer quality result to score.

## Separate in-scope probes and fault checks

In `r5`, a separate English consumer-law probe selected the index's actual
5 September date and indexed-only mode. Qwen performed real vector retrieval
and reached drafting, then exceeded the stage deadline. Codex queued behind it
expired its queue-wait deadline. These outcomes are separate from the forty-case
campaign and cannot be called legal answers. The private receipts distinguish
initial probe submissions whose date control had remained 23 September from the
correctly dated probes; none was silently replaced.

| Check | Evidence and limit |
|---|---|
| Refresh | Actual browser reload retained the same saved tenancy transcript |
| Invalid credential | Real OpenAI endpoint rejected a deliberately invalid test key; UI showed failed; connection was disconnected and encrypted secret revoked |
| Cancellation | Real queued job cancelled before execution; exact safe terminal displayed and saved |
| Cross-session access | ASGI integration tests deny foreign conversation, connection, job reads and cancellation |
| Model timeout | Actual Qwen stage timeout; bounded worker timeout tests separately exercise cancellation and cleanup |
| Source outage | Actual network/403 failures held; deterministic transport tests cover unavailable official sources |
| Prompt injection | Deterministic evidence/prompt tests remove or reject injected instructions; evidence-hold campaign is not an adversarial full-answer pass |
| Hosted model identity | Mocked OpenAI/Claude/Gemini adapters check routing and identity; valid-key live legal tests were unavailable |
| Credential persistence | Encryption/expiry/worker access and OS-vault contract tested; no genuine API credential was saved during testing |

A fault-test regression in the new private error capture initially raised an
attribute error with minimal service doubles. It was fixed so diagnostic storage
cannot mask the original durable terminal transition; the repaired suite is rerun.

## Rights and cleanup

The executed Find Case Law licence was not available to the gate. The official
[permission guidance](https://caselaw.nationalarchives.gov.uk/when-you-need-permission)
identifies computational uses including vector databases and AI training; its
terms must be checked separately for each intended use. Personal correspondence
and any future signed document remain private. No new permission is inferred here.

Unused dashboard components were removed from the application; recoverable copies
and obsolete README/current-state working text are under ignored `tmp/` storage.
Backend diagnostics, immutable evaluation evidence and protected material remain.
The four pre-existing `8-17 review` README/checksum deletions are excluded from the
commit. No `.cursor` directory is required by the application. No raw transcript,
credential, licence document, training output or personal absolute path is intended
for the public commit.

## Remaining work before acceptance

1. Produce reviewed, point-in-time source packets and generations covering the
   campaign's material issues; resolve relevant amendment/commencement effects,
   permitted judgment access and US source applicability. General official-source
   discovery and reviewed reuse are still incomplete.
2. Complete supported answers through Codex and Qwen, with claim-level review,
   real citations, substantive word counts and at most two preserved repairs.
   Diagnose Qwen's observed drafting deadline before treating it as a training need.
3. Run the conditional rights-cleared 60-example LoRA experiment only if isolated
   model-specific defects remain after those repairs. None has been run; no
   unverified target answers or protected cases have been turned into training data.
4. Re-run affected exposed UI cases and record remaining failures. Professional
   legal validation, public hosting, visitor desktop connections and production
   activation remain separate. Only training is **not** all that remains.


## Handoff update after the owner paused implementation

The separate empty-queue Codex probe in `shared-chat-20260923-r6` completed at
13:38:42 UTC, with its held terminal subsequently viewed in the real UI. Retrieval
made three actual queries and returned 24 candidates in 94.664 seconds. Codex
received eight spans and produced a structured draft recorded at 469 words.
Its preliminary automated writing score was 87.0, but evidence failed: unsupported
duration, non-atomic claim and three writing-standard findings. No AI evidence
review or repair stage was recorded. Nothing was published. This is separate from
the 40-conversation current-date campaign; 87.0 is not a quality pass.

Further implementation is paused at the owner's request for a detailed guide.
Follow [the continuation guide](../system-design/SHARED_CHAT_CONTINUATION_GUIDE.md).
No implementation commit or push has been made. Narrow final test/lint confirmation
remains pending after the interruption; the guide records the known prior results.
