# OSCOLA 5 deterministic metadata profile

Renderer policy version: `oscola-5.0-2026-03.v2`

The renderer accepts only reviewed metadata. The answer model supplies evidence IDs, never
citation strings. At release, the renderer verifies the stored source-level canonical citation
against the structured metadata, adds the exact `EvidenceSpan.locator` using source-specific
pinpoint rules, and places the linked full citation in parentheses immediately after the supported
sentence.

The profile follows the official Oxford Faculty of Law sources:

- [OSCOLA 5 full guide](https://www.law.ox.ac.uk/sites/default/files/2026-03/OSCOLA%205.pdf),
  especially sections 2.1, 2.4-2.5 and 3.1-3.7.
- [OSCOLA 5 Quick Reference Guide](https://www.law.ox.ac.uk/sites/default/files/2026-03/OSCOLA%205th%20Edition%20-%20Quick%20Reference%20Guide.pdf).
- [Oxford's OSCOLA 5 journal-article FAQ](https://www.law.ox.ac.uk/oscola-5th-edition-faqs).

## Supported source metadata

All values are plain metadata strings. Fields described as required must be present and non-empty.

| `source_type` | Required fields | Optional fields and rules |
|---|---|---|
| `case` | `case_name` and one of `neutral_citation`, `report_citation`, or `decision_date` | `report_citation`; `neutral_court_identifier` for High Court neutral citations; `court_identifier` is required when there is a report but no neutral citation and for unreported decisions; `court_identifier_not_required=true` is an explicit reviewed exception; `pinpoint_type=paragraph` disambiguates a bare numeric locator. |
| `legislation` | `title` | `provision`; answer-time locators override the source-level provision. |
| `statutory_instrument` | `title`, `instrument_number` | `instrument_number` includes the series, year and number, for example `SI 2023/1242`, `SSI 2021/489` or `SR 2022/50`; optional `provision`. |
| `rule` | `title`, `provision` | Use an OSCOLA rule-set title such as `CPR`, `CrPR`, `FPR` or `CPR PD`; answer-time locator may supply the provision. |
| `journal` | `author`, `title`, `year`, `journal` | `year_format` must be `square` or `round` when `year` is bare; alternatively supply `[2005]` or `(2009)`. `volume`, `issue`, `first_page`; `online_only=true` permits no first page. Issue is valid only with volume. |
| `book` | `author`, `title`, `publisher`, `year` | `translator`, `editor`, `additional_information`, `edition`, `volume`, and pinpoint. Contributor values include their role, for example `Tony Weir tr`. |
| `book_chapter` | `author`, `title`, `editor`, `book_title`, `publisher`, `year` | `editor_role` is `ed` or `eds`; optional `additional_information`, `edition`, and pinpoint. The editor is not repeated in publication details. |
| `web` | `title` and one of `doi` or `url` | `author`, `website`, `publication_date`. DOI and persistent URLs omit access date. A non-persistent URL requires `accessed`. Set `url_is_persistent=true` for a reviewed persistent link; `perma.cc` is recognised. Direct PDF URLs are rejected. |
| `official_guidance` | `author_or_body`, `title`, `publication_date` | `title_style` is `quoted` (default) or `italic`; optional pinpoint and online fields governed by the same DOI/URL/access rules. |
| `report` | `author_or_body`, `title`, `report_type` | `law_commission` and `command_paper` require `report_number`, `year`; `select_committee` requires `session`, `paper_number`; `government_publication` requires `publication_date` and supports `title_style` plus online fields. |
| `parliamentary` | `parliamentary_type` | `hansard` requires `house` (`HC`/`HL`), `date`, `volume`, and `column` or `columns`; `bill_debate` requires `title`, `date`, and `column` or `columns`. |

## Pinpoint normalization

- Case `para 42` becomes `[42]`; `paras 42-45` becomes `[42]-[45]` using an en dash.
- Case page pinpoints lose `p`/`pp` and follow the court identifier.
- Statutory parts normalize leading words to OSCOLA forms such as `s`, `ss`, `reg`, `regs`,
  `art`, `r`, `para` and `sch`, with a comma after the Act or instrument citation.
- Secondary-source page pinpoints lose `p`/`pp`; paragraph, chapter and footnote labels remain.
- Numeric ranges use an en dash.

Unsupported or incomplete metadata raises `CitationMetadataError`; it is never repaired by the
language model or replaced with a guessed citation.
