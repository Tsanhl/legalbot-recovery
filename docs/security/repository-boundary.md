# Repository boundary

The GitHub remote for this working tree may be a **public source repository**.
That does not make LegalBot a public product, a hosted service, or a shared
research assistant.

## What remains private

- The application is owner-only and loopback-bound (`127.0.0.1`) for first live.
- Local catalogues, vaults, indexes, answers, review material and evaluation
  artefacts stay on the owner machine.
- Evaluation artefacts are ineligible for training and must not be exported as
  training data.
- No account system, cloud storage, sharing or telemetry endpoint is part of
  first live.

## What this document does not change

- Licence text in `pyproject.toml` is unchanged.
- Repository visibility is unchanged.
- Publication of this repository, if any, does not authorise copying licensed
  source materials, Keychain secrets, or local `data/` state.

## Wording

## Public tracking of Live60-2026-08-16

`Live60-2026-08-16/` is tracked evaluation and owner-review work product, not a
live-run export and not training data. Every publicly tracked byte should be
treated as a product artifact.

Owner-review Word packs (`.docx`) are local-only. They are gitignored and must
not be published in the source tree. The product may still generate review
workbooks after an authorised export; those files stay on the owner machine.

This tree no longer tracks XLSX workbooks, Path-B review ledgers, or
generated go-execution inventories. Local originals remain on the owner
machine. The scan of remaining Live60/docs artifacts is recorded in
`docs/security/PUBLIC_REPO_ARTIFACT_AUDIT.json`.

Classification pending explicit owner rights, privacy and product-boundary
review:

- **Rights:** not a licence clearance for third-party reuse of review packs.
- **Privacy:** keep owner-review Word files, filled returns and other
  attachments that are not ready for a public tree in ignored local storage.
- **Product boundary:** tracking JSON/spreadsheet evaluation files does not
  make them live-ready, O-04, or an English-law gold overlay.

Do not treat this branch as merge-ready public product until that owner review
is recorded. Do not copy question or answer prose from local Word packs into
logs, prompts or close-out reports.
