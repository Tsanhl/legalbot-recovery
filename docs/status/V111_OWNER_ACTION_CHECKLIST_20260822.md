# LegalBot v1.11 owner action checklist

Status: **non-authorizing planning checklist**. This file records which choices must
come from the owner; it is not a signature, approval, credential, split, promotion or
release decision.

## No owner decision is required for Phase-1 technical repair

Codex may diagnose and conservatively repair implementation defects, add regression
tests, enforce bounded queues and deadlines, verify immutable model/index bytes, create
non-authorizing reports, compare the scorer closure and perform the required append-only
24-case retrieval re-attestation. These actions cannot promote a candidate, expose a
sealed result or activate live.

## Phase-2 preparation choices received

The owner has authorized preparation only and selected the following bounded policy:
pinned local Ed25519 verification, exclusive private Unix-domain-socket model
transport, 12 GiB maximum memory with 3 GiB minimum free, official-source review
before fixing the legal cutoff, literal `127.0.0.1` with strict Host/Origin/CSRF and a
local session secret, three distinct private non-synchronised review roots, a
conservative certification contract, and a locally keyed deterministic stratified
30/30 complement after qualification.

This conversational preparation authorization permits implementation and non-model
verification only. It is not the detached owner signature, does not provision any
resource, does not freeze a split, and does not authorize Stage A, Development 30 or an
answer-model request. No further owner input is required for the preparation
checkpoint.

Private UDS endpoint policy and observation are prepared, but a usable model transport
remains closed until exact socket-instance verification is enforced at every connect
and reconnect. This does not block the preparation checkpoint and prevents any model
request under the present authorization.

## Required before a real Development-30 run

The owner must later sign the append-only
`legalbot.v111-owner-decision-package.v1` chain bound to the exact candidate and
certification implementation:

1. a policy tranche containing the selected bounded policy;
2. a configuration tranche binding the frozen contract, pinned key, exact local
   security observations, stable UDS endpoint intent and the exact three root
   identities;
3. an owner decision on the legal-currentness cutoff, freshness and material-change
   rule after official-source findings are presented;
4. a split tranche only after exact qualification and local split-secret generation;
5. a separate action-specific authorization for the exact Development-30 run.

Codex must ask the owner again before emitting signing material or starting Development
30. No secret, credential, root, socket or signed policy is generated from this
checklist.

## Required during and after Development

The owner must review the readable Development folders, provide case-level feedback and
sign final Development acceptance bound to the exact Production Candidate commit/tree,
candidate, contract, split and result package. Codex may implement technical corrections
between Development cycles, but it cannot self-accept its answers or silently redraw the
split.

## Required in Phase 3

Only the owner may:

1. approve atomic promotion for controlled operational proof;
2. sign O-04 after the exact promoted snapshot passes operational and currentness proof;
3. approve disclosure and acceptance of the one-pass Sealed Validation result;
4. give final approval to fast-forward `main`, tag the certified commit and activate
   owner-only loopback live.

## Readable review layout

When the signed private roots and strictly verified upstream packages exist, Development
review is projected create-only as:

```text
<approved-private-root>/
  phase-2-development-<release-id>/
    00-OWNER-REVIEW-INDEX.md
    cases/
      01-<case-id>/
        QUESTION.md
        ANSWER.md
        OWNER-NOTES.md
    projection-manifest.json
    PROJECTION-COMPLETE.json
```

The Development projection requires exactly 30 records. Sealed Validation has no
readable projection mode before its frozen disclosure gate. Projection manifests are
non-authorizing indexes; immutable upstream packages and signed owner decisions remain
the authority.

Ordinary owner-only live review uses its separately signed live root and a distinct
Phase-3 directory:

```text
<approved-live-private-root>/
  phase-3-live-<release-id>/
    00-OWNER-REVIEW-INDEX.md
    cases/
      01-<case-or-job-id>/
        QUESTION.md
        ANSWER.md
        OWNER-NOTES.md
    projection-manifest.json
    PROJECTION-COMPLETE.json
```

The Phase-1 projection implementation accepts only explicit synthetic test input. A
real Development or live projection remains fail-closed until a typed strict verifier
binds the exact upstream package and the signed decision binds the exact, distinct,
non-synchronised root. Post-disclosure Validation review packaging, if required, is a
separate owner-policy decision and is not inferred from either layout.
