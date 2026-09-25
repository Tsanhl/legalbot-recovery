# LegalBot current state

## 25 September 2026: Qwen only, one unified index, research mode

Diagnosis: the chat's answers failed because retrieval found nothing (the
reviewed index held only the Consumer Rights Act) and the gates rejected every
unreviewed source, not because of Qwen's weights. See
[the recovery plan](system-design/QWEN_RECOVERY_PLAN_2026-09-25.md).

Done on the owner's instructions:

- **Qwen is the only answering route.** Hosted-API (OpenAI, Claude, Gemini),
  local-endpoint and Codex routes, API-key storage and their UI were removed.
- **One unified index** (`data/indexes/unified-local-v1`, built by
  `scripts/build_unified_local_index.py`) is embedding every citable authority,
  scholarship and official-secondary document; about 16 hours on this Mac.
- **Research mode** (`LEGALBOT_RESEARCH_MODE`, set by the chat launcher): the
  unified retriever returns reviewed and unreviewed sources. Unreviewed ones
  render as "Title [unverified source]" and raise an informational finding
  instead of a hard blocker. Jurisdiction, quotation, support, contradiction
  and teaching-lane gates still apply.
- **New answer standard** from a full read of the Law folder:
  [LAW_FOLDER_ANSWER_GUIDE.md](system-design/LAW_FOLDER_ANSWER_GUIDE.md),
  approved and encoded as bundle `owner-law-folder-2026-09-25.1` (31 rules, each
  scored). Qwen receives every applicable rule in compact form.
- **Qwen runtime:** 16k context, 3,072 output tokens, 14.5k evidence characters;
  answer workflow 45 minutes, model call 10 minutes. The 16k load has not yet
  been measured on hardware (the GPU is busy embedding).
- OSCOLA 5 court identifiers and the pre-2001 neutral-citation rule; a question
  for England or Wales now accepts England-and-Wales and UK sources.

Also done (evening):
- the lecture-note rewrite and a law-and-rules knowledge lane for issue spotting;
- labelled EU and comparative material;
- fixes to three research-mode release blockers;
- a first official-record verification pass (legislation.gov.uk and Find Case
  Law) via `VERIFICATION.json`.

See section 8 of the recovery plan.

Also done (night):
- Only legislation, case law, journal articles and books may be cited. Teaching
  material and the owner's own work never are; unidentified sources are held.
- Documents the user attaches in the chat can be read and cited by Qwen, labelled
  as the user's uploaded document.

See section 9 of the recovery plan.

Not yet done:
- finish the embedding, apply exclusions, and build the search indexes and the
  knowledge lane;
- Qwen titling for the roughly 930 untitled sources, then verify those;
- a Qwen hardware test and the baseline quality run;
- then training, only if needed.

Nothing is ACTIVE, promoted or trained.

## Earlier (superseded): faster private review and one GE check with 6 Sol

The r28 Astra job ended during review after saving a 424-word structured draft
and a 440-word repair; its queued companion expired. Neither produced a released
answer. Its terminal receipt is private. The local UI keeps the saved draft in a
collapsed, session-owned **private diagnostic** panel, separate from released
answers and conversation facts.

The r29 launcher pins separate 6 Sol, 6 Astra and 6 Luna routes. The owner asked
to use 6 Sol for the final GE check. Its real signed-in CLI connection test
failed with a provider error stating that this ChatGPT account does not support
`gpt-6-sol`. No r29 legal question was submitted. The UI now shows the failure
and prevents a question from being sent through that failed connection. A
choice about using Astra for the single fixture is pending; it must retain its
own model identity.

Answer review now checks up to four independent material claims concurrently,
preserves input order, and reports the count completed. This removes a serial
wait in the prior trace without weakening the claim or full-answer gates.
Encrypted conversations have a 30-day activity expiry for access, with a
seven-day hot-window bound. Expiry does not silently delete immutable evaluation
records. The existing API, query processing, indexed retrieval, drafting and
release boundary are retained; one substantive GE answer remains unproven.

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
