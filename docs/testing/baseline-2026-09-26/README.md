# Qwen baseline question set (26 September 2026)

[BASELINE_QUESTIONS.json](BASELINE_QUESTIONS.json) is built by
[build_baseline.py](build_baseline.py) before any baseline answer is generated.

## What it contains

- 10 General Enquiries, 5 Essays and 5 Problem questions, all England and Wales
  except one EU essay that tests EU routing.
- 3 system tests reused from the practice bank:
  - an unknown jurisdiction, which should produce a clarifying question;
  - instructions hidden in an uploaded document, which should be ignored;
  - an unavailable authority, which should be reported, not invented.
- For every question: the expected issues, the key authorities, known pitfalls,
  a word target and an automatic catalogue coverage check.

A missed key authority is then diagnosed as one of three things: absent from the
index, not retrieved, or retrieved but misused. That tells us whether to fix
sources, retrieval or Qwen.

This is an exposed development baseline. It is not an unseen test and never
training data. The older 50-question practice bank and the 20-case chat campaign
remain regression material only. Most of them are everyday or non-UK questions
the index cannot yet answer.

## Coverage gaps found (title check, 26 September)

The statutes are mostly present. Many leading cases are not titled sources in
the catalogue, though some may be among the untitled PDFs.

- **Available from Find Case Law (post-2001).** These should be fetched and
  embedded before the baseline:
  - Lachaux [2019] UKSC 27, Stack v Dowden [2007] UKHL 17, MWB v Rock [2018] UKSC 24;
  - R v Clinton [2012] EWCA Crim 2, Geary v Rankine [2012] EWCA Civ 555;
  - Vedanta [2019] UKSC 20 and Limbu v Dyson [2024] EWCA Civ 1564 (title check
    uncertain);
  - Goodlife Foods [2018] EWCA Civ 1371, Link Lending [2010] EWCA Civ 424,
    Bhullar [2003] EWCA Civ 424.
- **From legislation.gov.uk:** Criminal Justice and Immigration Act 2008 (s 76)
  and Wills Act 1968.
- **Pre-2001 cases:** Williams v Roffey, Foakes v Beer, High Trees, Rosset,
  Spiliada, Lubbe, L'Estrange, Majewski, Savage, Boland, Hedley Byrne, Caparo and
  Regal. These are not on Find Case Law, so they are available only through
  textbooks and articles in the index. Identify them once the untitled PDFs are
  titled.
- **EU cases:** Keck, Dassonville, Trailers and Mickelsson would need EUR-Lex,
  which is not an approved source host. The EU essay therefore depends on
  scholarship and must use EU material labelled correctly.
