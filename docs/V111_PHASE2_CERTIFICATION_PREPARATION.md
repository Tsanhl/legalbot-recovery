# LegalBot v1.11 Phase-2 certification preparation

The preparation command creates two strictly non-authorizing, schema-validated
artifacts and a replay index:

- `certification-contract-draft.json` is the conservative certification contract
  draft;
- `qualification-currentness-preparation.json` is the question-free 60-case issue
  inventory and official-source review workflow; and
- `PREPARATION-INDEX.json` binds their file bytes, embedded seals, exact Git commit,
  and Git tree.

The draft binds the immutable Owner Certification 60 registry, its issue count as
derived from the registry bytes, the sealed candidate and index tree, and the exact
clean implementation tree. It also binds the selected Phase-1 retrieval
re-attestation and proves that the current scorer closure is semantically identical:
the complete member list, Python runtime identity and legacy scorer digest must match.
Only the Git `revision` and `tree` identity fields may differ, and both the historical
and current aggregate digests remain recorded rather than being treated as equal.

The contract records the agreed 12 GiB/3 GiB resource envelope,
single generation worker, private Unix-domain-socket transport, conservative evidence
and scoring rules, one-pass semantics, and the same-fingerprint stop limit of two.

The qualification preparation artifact contains case and issue identities and hashes,
not question prose, answers, owner notes, source prose, URLs, or private paths. Its
candidate-source section is aggregate baseline evidence only. In particular, the
candidate snapshot date is not treated as the owner legal-currentness cutoff.

Both artifacts remain drafts. They explicitly record that:

- no owner signature is present;
- the legal-currentness cutoff is pending official-source review and owner decision;
- the prompt, model, evaluator, reviewer, review roots and local security material are
  not yet frozen;
- no 30/30 split exists;
- no Stage A, answer-model, Development 30, promotion, O-04, Validation 30 or live
  action is authorized; and
- internal hash consistency cannot create authority.

## Owner-decision chain prepared, not signed

The append-only `legalbot.v111-owner-decision-package.v1` protocol has three
independently signed tranches in this order:

1. **policy** records the bounded choices for Ed25519, private UDS transport, the
   12 GiB/3 GiB resource envelope, official-source currentness review, literal
   `127.0.0.1` security, three isolated review lanes, a conservative contract and
   post-qualification keyed splitting;
2. **configuration** binds the exact contract digest, all three distinct private-root
   identities, pinned public-key identity, loopback request policy, session-secret
   observation and stable UDS endpoint intent; and
3. **split** binds the exact qualification and deterministic 30/30 split after the
   locally generated secret has been committed but not recorded.

Each append preserves the prior canonical tranche bytes. A signature statement binds
one exact tranche, its chronology and the pinned Ed25519 public-key digest. A complete
verification requires exactly one valid signature for every appended tranche in order.
Even a complete cryptographic signature set remains non-authorizing: Development 30
also requires a separate action-specific owner authorization.

The companion CLI is read-only with respect to project and owner state. It cannot
generate keys, create or append packages, sign, choose a split, or authorize a run. A
future signing-payload request requires a literal later owner invocation and first
reconstructs the exact clean Git/candidate/index binding rather than trusting the
package's self-declared hashes. Configuration- and split-tranche signing payloads and
complete-set verification remain explicitly unavailable until their exact resource,
qualification and split-evidence replayers are implemented; schema validity alone
cannot produce owner signing bytes for those tranches. The underlying signature
primitives enforce the same boundary through an opaque strict-evidence-replay
capability, so bypassing the CLI does not relax it.

## Local resource boundaries prepared, not provisioned

Dedicated Phase-2 configuration observes but never creates:

- one pinned local Ed25519 public-key file;
- three distinct external owner-only mode-`0700` review roots;
- one external owner-only local-session-secret file;
- literal loopback Host/Origin/CSRF request policy; and
- one external private Unix-domain-socket endpoint.

The endpoint intent is stable across safe socket restarts and binds the exact lexical
path hash, exact private parent identity, `AF_UNIX`/`SOCK_STREAM`, required `0600`
socket mode, no network or environment fallback, zero transport retries and one
connection. Live socket-instance identity is checked separately. Neither observation
connects to a model. The usable HTTP transport remains deliberately unavailable:
pathname-only lazy connection would permit socket replacement after observation, so
the builder fails closed until the production connector can enforce the exact socket
instance at connect and reconnect time.

The split API accepts neither raw qualification data nor a caller-supplied secret. Its
public entry point requires a future strict-replay, action-specific opaque capability.
The sealed Validation manifest has one fixed create-only filename under an exact signed
custody root. Preparation code cannot mint either capability, so no split IDs or secret
commitment can be produced during this work.

## Readable Development review layout

The already tested non-authorizing review projection gives each Development case a
clear question, answer and owner-notes folder:

```text
<signed-development-root>/
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

It requires exactly 30 Development records and currently accepts only explicit
synthetic test inputs. There is deliberately no Sealed Validation projection before
the one-pass disclosure gate. A real Development projection remains closed until the
signed lane root and exact upstream answer package have passed a typed strict verifier.

After the implementation is committed and the worktree is clean, generate a unique
private package with:

```sh
uv run --frozen --all-extras python scripts/prepare_v111_phase2_certification.py \
  --candidate-build-id current-law-ew-full-fp16-v111-20260818-a \
  --expected-head <exact-40-character-commit> \
  --output-directory data/evaluations/phase2-preparation/<unique-package-id>
```

The command is offline and immutable/read-only with respect to the candidate and
catalogue. It opens only an existing current-owner mode-`0600`, single-link regular
SQLite file using `mode=ro&immutable=1` plus `query_only`; it refuses symlinks and any
WAL, SHM or rollback-journal sidecar, performs integrity and foreign-key checks, and
proves that catalogue
bytes and stat identity did not change and that no sidecar appeared before it writes
the package. It never uses the normal catalogue constructor or migration path.

The command also refuses a dirty or different HEAD, an unsealed candidate, an output
outside the private preparation root, an existing output directory, a
candidate/source binding mismatch, an invalid historical selected attestation, or any
current scorer-closure change beyond commit/tree identity. The output files are
create-only mode `0600` under a mode `0700` package directory.

The next substantive step is a staged official-primary-source currentness review with
no owner cutoff assumed. Its dated potential deltas and gaps are then presented to the
owner, who decides and signs the exact cutoff and materiality rule. The source review is
replayed through that signed cutoff before qualification can freeze. Only the later
signed owner-decision package and a separate action-specific authorization may permit
Development 30.

No further owner input is needed to finish this preparation checkpoint. Later work
must stop and ask the owner again before any signing payload is emitted, before exact
resources are accepted as signed configuration, before the 30/30 split is frozen, and
before Development 30 or any answer-model request begins.
