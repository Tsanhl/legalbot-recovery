"""Bounded official discovery seeds. These are candidates, never legal answers.

Only fixed public search identities and explicit allowlisted URLs leave the
host. This initial catalogue is not a general web-search engine.
"""

from __future__ import annotations

import re

# Discovery identities only. The fetched dated XML still has to pass identity,
# title, extent, effects and case-specific source review. These are not approvals.
LEGISLATION_IDENTITIES = {
    "Consumer Rights Act 2015": ("ukpga/2015/15", "Consumer Rights Act 2015"),
    "Consumer Contracts Information Cancellation Additional Charges Regulations 2013": (
        "uksi/2013/3134", "The Consumer Contracts (Information, Cancellation and Additional Charges) Regulations 2013"),
    "Housing Act 1988": ("ukpga/1988/50", "Housing Act 1988"),
    "Renters Rights Act 2025": ("ukpga/2025/26", "Renters’ Rights Act 2025"),
}


def discovery_urls(question: str, jurisdiction: str) -> tuple[str, ...]:
    text = question.casefold()
    nation = jurisdiction.casefold()
    urls = re.findall(r"https://[^\s<>\[\]{}\"']+", question)
    if "california" in nation:
        if "deposit" in text:
            urls.append(
                "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1950.5"
            )
        if any(word in text for word in ("worker", "employee", "wages")):
            urls.append(
                "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=LAB&sectionNum=2775"
            )
    if "new york" in nation and "freelance" in text:
        urls.extend(
            f"https://www.nysenate.gov/legislation/laws/GBS/{number}"
            for number in (1410, 1411, 1412)
        )
    if "florida" in nation and any(word in text for word in ("relocat", "move with", "moving")):
        urls.append(
            "https://www.leg.state.fl.us/Statutes/index.cfm?App_mode=Display_Statute&URL=0000-0099%2F0061%2FSections%2F0061.13001.html"
        )
    if "texas" in nation and any(word in text for word in ("consumer", "repair", "refund")):
        urls.append("https://statutes.capitol.texas.gov/Docs/BC/htm/BC.17.htm")
    if "federal" in nation and any(word in text for word in ("foia", "information", "records")):
        urls.append(
            "https://uscode.house.gov/view.xhtml?req=granuleid:USC-prelim-title5-section552&num=0&edition=prelim"
        )
    return tuple(dict.fromkeys(url.rstrip(".,;!") for url in urls))


def legislation_queries(question: str, initial: tuple[str, bool] | None) -> list[tuple[str, bool]]:
    text = question.casefold()
    queries = [initial] if initial else []
    if any(word in text for word in ("laptop", "faulty goods", "retailer", "store credit")):
        queries = [("Consumer Rights Act 2015", True)]
        if any(word in text for word in ("online", "website", "distance")):
            queries.append(("Consumer Contracts Information Cancellation Additional Charges Regulations 2013", True))
    elif any(word in text for word in ("landlord", "tenancy")):
        queries = [("Housing Act 1988", True), ("Renters Rights Act 2025", True)]
    return list(dict.fromkeys(queries))[:2]
