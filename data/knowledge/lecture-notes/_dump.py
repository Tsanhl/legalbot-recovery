"""Print slide-deck text from the catalogue for rephrasing (read-only)."""
import json, re, sqlite3, sys
ids = json.load(open("data/knowledge/lecture-notes/_DECKS.json"))
c = sqlite3.connect("file:data/catalog.sqlite3?mode=ro", uri=True)
for i in map(int, sys.argv[1:]):
    text = " ".join(r[0] for r in c.execute(
        "SELECT markdown_text FROM chunks WHERE source_version_id=? AND stream='body' ORDER BY ordinal", (ids[i],)))
    text = re.sub(r"\S+@\S+", "", text)          # drop email addresses
    text = re.sub(r"\s+", " ", text)
    print(f"\n===== DECK {i} =====\n{text}")
