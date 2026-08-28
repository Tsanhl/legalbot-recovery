# LegalBot v1.11 Phase 1B binding reconciliation

Status: **resolved without candidate mutation or owner legal/currentness decision**.

The r2 re-attestation stopped correctly before retrieval. The sealed candidate contains every required frozen digest for the four failed cases. The eight findings came from two generic identity defects, not missing law.

| Finding | Case | Root cause | Exact evidence | Correction |
| --- | --- | --- | --- | --- |
| P1B-001 | `dev-limitation-s2` | `qualification_manifest_omission` | The reviewed and candidate section 2 provision snapshots both hash to `d6dc546d…d337b`; inherited extent/effective context is identical. | Candidate-bound successor qualification for the exact candidate source bytes. |
| P1B-002 | `dev-limitation-s2` | `canonical_provision_identifier_mismatch` | Frozen digest `00b14462…266fe` exists at candidate locator `s 2`, exact candidate source/version. | Strict `section 2` → `s 2` canonical section identity. |
| P1B-003 | `dev-limitation-s14a` | `qualification_manifest_omission` | The reviewed and candidate section 14A provision snapshots both hash to `fdd1fe42…c1ef8`; inherited extent/effective context is identical. | Candidate-bound successor qualification for the exact candidate source bytes. |
| P1B-004 | `dev-limitation-s14a` | `canonical_provision_identifier_mismatch` | All 14 failed digests exist at deterministic locators from `s 14A(1)` through `s 14A(9)` in the exact candidate source/version. | Strict top-level section/descendant locator parsing; no semantic or fuzzy match. |
| P1B-005 | `dev-trustee-act-s1` | `qualification_manifest_omission` | The reviewed and candidate section 1 provision snapshots both hash to `c7ed6b59…f3f1b`; inherited extent/effective context is identical. | Candidate-bound successor qualification for the exact candidate source bytes. |
| P1B-006 | `dev-trustee-act-s1` | `canonical_provision_identifier_mismatch` | All four failed digests exist at `s 1(1) chapeau`, `s 1(1)(a)`, `s 1(1)(b)` and `s 1(2)` in the exact candidate source/version. | Strict top-level section/descendant locator parsing. |
| P1B-007 | `prom-family-provision-s1` | `qualification_manifest_omission` | The reviewed and candidate section 1 provision snapshots both hash to `e15346b5…68858`; inherited extent/effective context is identical. | Candidate-bound successor qualification for the exact candidate source bytes. |
| P1B-008 | `prom-family-provision-s1` | `canonical_provision_identifier_mismatch` | All eight failed digests exist at the exact subsection locators in the exact candidate source/version. | Strict top-level section/descendant locator parsing. |

The predecessor qualification, the r2 embedded qualification, and the r2 failure diagnostic remain unchanged. The successor qualification is bound to the candidate manifest, seal, source manifest, embedded qualification registry, Lance tree, exact source/version bytes, predecessor review records, and replayed provision snapshots.

The locator rule recognizes only parsed statutory section coordinates and a closed set of deterministic chunk-role suffixes. It rejects another section, a section-number prefix collision, a non-section alias, a wrong source version, a changed exact digest, and changed provision or inherited extent bytes.

Authoritative machine record: `docs/status/v111-phase1b-reconciliation-20260822-a1.json`.
