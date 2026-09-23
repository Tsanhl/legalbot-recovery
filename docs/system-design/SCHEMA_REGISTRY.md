# Selected schema registry

This registry removes version ambiguity. New jobs and runs accept exactly the
selected schema listed below. A schema file is a design contract, not proof of
implementation or authorization to execute.

| Object | Selected schema | Purpose |
| --- | --- | --- |
| Conversation snapshot | `conversation-snapshot.v1.schema.json` | Exact bounded message projection and omitted-history disclosure |
| Matter fact snapshot | `matter-fact-snapshot.v2.schema.json` | Separate fact origin/status, corrections, conflicts and FactRefs |
| Query plan | `query-plan.v2.schema.json` | Data intent, response disposition, issues, budgets and capabilities |
| Answer job | `answer-job.v1.schema.json` | Durable stage, attempt, lease and frozen input chain |
| Browser job event | `job-event.v1.schema.json` | Replay-safe progress, reset and distinct terminal release event |
| Knowledge generation | `knowledge-generation-manifest.v1.schema.json` | Complete source/parser/chunker/model/index closure and seal |
| Empty research baseline | `research-empty-baseline.v1.schema.json` | Zero-source, zero-row, 1024-dimensional non-live starting point for isolated online research only; no source qualification or production admission |
| Retrieval result | `retrieval-result.v1.schema.json` | Route, rank, qualification, issue allocation, timing and gaps |
| Evidence pack | `evidence-pack.v1.schema.json` | Qualified selected EvidenceSpans and named gaps |
| Claim set | `claim-set.v1.schema.json` | Atomic fact/rule/application/limitation provenance |
| Validation report | `validation-report.v1.schema.json` | Deterministic/advisory checks and final disposition |
| Verified release | `verified-release.v1.schema.json` | Digest-consistent committed answer and outbox identity |
| Runtime capability | `runtime-capability-manifest.v1.schema.json` | Per-process readiness and operation grants |
| Evaluation run | `evaluation-run.v1.schema.json` | Exact authorized run inputs, denominator, custody and validity |
| Evaluation case result | `evaluation-case-result.v2.schema.json` | One case/job factual and quality terminal result with exact ordered factual checks and quality dimensions |
| GE system case result | `ge-system-case-result.v1.schema.json` | One replayable, unscored system-behaviour result outside the fixed 331 denominator |
| GE completed system run | `ge-system-run.v1.schema.json` | Exact reconciliation of all 32 separate system scenarios against one visible-run execution identity |
| GE visible diagnostic supplement | `ge-visible-diagnostic-supplement.v1.schema.json` | Cumulative visible diagnostic questions bound to audited coverage gaps and barred from unseen/training use |
| GE diagnostic case result | `ge-diagnostic-case-result.v1.schema.json` | One factual-first diagnostic result outside the fixed visible and system denominators |
| GE cycle assessment | `ge-cycle-assessment.v2.schema.json` | Immutable loop status, exact owner-authorized 23-domain coverage topology, decision basis, retry stop, custody checks, builder-local side-effect record and owner-acceptance exit state |
| Training experiment | `training-experiment.v1.schema.json` | Rights/privacy/leakage-reviewed optional weight-change experiment |
| Proposition qualification receipt | `proposition-qualification-receipt.v1.schema.json` | Locator/proposition/span sidecar; not knowledge-generation v1 and not answer gold |
| GE run lineage | `ge-run-lineage-manifest.v1.schema.json` | Distinct historical-r1, r1-rescored, and r2 generated/scored tracks |
| GE effective source set | `ge-effective-source-set-manifest.v1.schema.json` | Recovery-b plus evaluation-sidecar closure for a diagnostic run |
| GE evaluation control plane v2 | `ge-evaluation-control-plane.v2.schema.json` | Scoped phase/run/case/claim blocker states plus progression-disposition counts; FACTUAL_HOLD is not equivalent failure |
| GE currentness review packet | `ge-currentness-review-packet.v1.schema.json` | Case-level currentness dossier; not owner currentness approval or gold |

## Legacy read-only schemas

- `query-plan.v1.schema.json`
- `matter-fact-snapshot.v1.schema.json`
- `evaluation-case-result.v1.schema.json`
- `ge-cycle-assessment.v1.schema.json`

They remain for migration/audit only. New jobs, releases, evaluation runs and
training experiments reject them. They are not fallback formats.

## Selection and digest rules

- The selected schema bundle has a canonical manifest and SHA-256 digest for every
  actual job or run.
- JSON is validated against Draft 2020-12 with format checks enabled.
- Canonical object digests use one documented JSON canonicalization method; raw
  language/runtime serialization order is not a digest contract.
- Unknown properties fail unless a selected schema explicitly allows them.
- IDs and digests bind objects; an ID alone never permits substitution.
- Schema migration is create-new, validate, compare and switch. Existing evidence
  stays attributable to the schema digest it used.
- The living design may update the selected bundle before implementation. Once an
  actual job/run freezes a bundle, changing it requires a successor job/run.
