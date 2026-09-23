# LegalBot current state

## Latest owner direction: show drafts and choose the Codex model in chat

The local chat now shows a saved, session-owned **unverified model draft** beside
its held or running job. It remains outside released answers and conversation
facts. A live r27 attempt exposed a date-control error, which was fixed, then
timed out before saving a draft. A separate r28 Codex `gpt-6-astra` attempt used
the reviewed 5 September England index and displayed its saved 424-word
structured draft while claim review continued. This demonstrates the preview
path, not a verified legal answer.

The composer now places a Codex model selector beside **Words**. The next signed-in
chat launcher issues separately pinned routes for `gpt-6-sol`, `gpt-6-astra`
and `gpt-6-luna`. Selecting one creates or reuses a session-owned connection
for the next question. A running job keeps its original model. The current r28
authority was issued before this change and remains immutable, so its other
model options are marked as available in the next session.

## Continuation guide

On 23 September the owner directed Codex-first repair. Reviewed whole-provision
context now retains its original vector-hit lineage. r17–r25 exposed answer
length, unsupported-claim and reviewer-transport defects, recorded in the
[continuation findings](testing/SHARED_CHAT_CONTINUATION_2026-09-23.md). r26
explicitly selected gpt-6-astra and passed its actual connection test. Its legal
job drafted 398 words and a 419-word first repair. Owned processes disappeared
during the second repair after an interrupted turn; the database row remained
stale as running. No second-repair output or published answer was adopted. The
full campaign and Qwen training have not been repeated.
The owner supplied the executed Find Case Law terms and confirmed all parties
signed. They cover a local England-and-Wales research assistant for private
study plus invited friends, including local indexing and RAG. The signed file
is not yet bound to the private permission gate; external-model transfer,
internet hosting and model training have not been enabled for its text. The
owner now wants a friends-only audience and may defer Qwen. The current
launcher is loopback-only and has no invite authentication. No licence
activation or ACTIVE change has been made.

Updated: 23 September 2026. **Shared local chat implemented; legal-answering acceptance incomplete.**

## Current owner direction

Implement the accepted single-chat plan with Codex default, base Qwen evaluated
separately and optional per-session OpenAI/Claude/Gemini API connections. This
supersedes the historical planning pause and owner/public dashboard split for
this scoped work. UK/USA first. External access is now intended only for invited
friends. Internet hosting and friend authentication remain unimplemented;
sharing an open link would not enforce that audience. Existing protected-bank custody and attempt limits
remain unchanged; no bank worker has been dispatched by this implementation.

## Observed results

- Real browser campaign: 40 conversations, 46 submitted turns; 20 cases for each
  selected route. Exact frozen messages and encrypted final DOM receipts exist
  for all 40. All final legal requests held for evidence; zero substantive answers.
- Six genuine clarification sequences: first response displayed before withheld
  facts were supplied; tenancy, Scottish succession and Florida relocation each
  retain facts and stop asking resolved questions on both routes.
- Actual Codex and pinned base Qwen connection tests passed. Hosted APIs have
  adapter/identity tests, but no valid provider keys were available for live answers.
- Source acquisition reached official UK/US endpoints. Holds include unapplied
  effects, point-in-time mismatch, network/403 failures and pending US source review.
- The reviewed retrieval generation remains England consumer law at 2026-09-05.
  Rejecting an out-of-scope generation is not a query-embedding run or proof of
  worldwide coverage. Separate in-scope probes are recorded in the report.

[Acceptance report](testing/SHARED_CHAT_2026-09-23.md) ·
[per-case results](testing/CHAT_CAMPAIGN_2026-09-23_RESULTS.json) ·
[frozen questions/rubric](testing/CHAT_CAMPAIGN_20.json) ·
[maintained design](system-design/GE_PRE_BROWSER_IMPROVEMENT_PLAN.md)

## Implemented boundaries

One answering UI; no Operations dashboard. Backend diagnostics remain private
and owner management APIs are disabled by default. Session ownership applies to
connections, conversations, jobs, cancel/reconnect and answer reads. Temporary
keys use expiring encrypted storage; remembered keys require native OS storage.
Switching providers does not alter environment variables or silently fall back.
Conversation and append-only fact records preserve stated dates/amounts and raw
messages. Assistant questions are excluded from fact detection.

Online material is captured with provenance, not automatically admitted. UK
legislation can enter a case-only snapshot only after structural/currentness and
actual model source review. Current US captures and other judgment candidates
remain review-pending. Executed Find Case Law terms were supplied in chat, but
the signed file has not been bound to the purpose-specific runtime gate. Local
indexing is within the stated purpose, subject to current-version, withdrawal,
notice, crawler and personal-data controls. External processing and training
remain gated for that licensed text.

## Remaining acceptance work

Complete relevant source/currentness packets and reviewed index generations;
prove supported material claims, citations, full-length answers and bounded repairs
through both model routes. Current campaign cannot assess legal accuracy, material
omissions, citation validity or word count because no substantive output exists.
The advisory 70+ standard is not a legal validation certificate.

No new weight training has run. The conditional 60-example/48-train/12-validation
LoRA experiment must exclude all campaign cases, protected banks and private chats;
source failures do not establish model-specific training need. ACTIVE, production,
professional legal validation, protected-bank readiness and its unspent gated
one-pass execution are unchanged. Historical frozen reports and attempt receipts
remain at their original locations. The four pre-existing review-file deletions
are excluded from this implementation commit.
