#!/usr/bin/env python3
"""Write the Qwen baseline question set and check its key authorities against the catalogue.

The questions are authored before any baseline answer is generated. Each lists
the issues and key authorities a good answer needs, so a failure can be traced
to retrieval (authority missing or not retrieved) or to the model (authority
retrieved but misused). Exposed development material: never training data.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
AS_OF = "2026-09-26"
INTRO = "Today is 26 September 2026. Jurisdiction: {j}.\n\n"

CASES: list[dict] = [
    # ---------------- General enquiries (practical, plain language, ~450 words)
    {
        "id": "B-GE01", "task_type": "general", "jurisdiction": "England", "word_target": 450,
        "title": "Faulty laptop: reject within 30 days",
        "reused_from": "GE01 (practice bank)",
        "question": (
            "On 2 September 2026 I bought a new laptop for £799 online from Elm Retail Ltd, a UK "
            "business, for personal use. It arrived on 4 September and repeatedly shut down from "
            "first use. I have not damaged it. On 16 September I emailed rejecting it and asking "
            "for a full refund. The retailer offers only store credit and says I must contact the "
            "manufacturer. Can I insist on a refund, who is responsible, and what should I do next?"
        ),
        "expected_issues": [
            "satisfactory quality and the trader's liability (not the manufacturer's)",
            "short-term right to reject within 30 days of delivery",
            "refund within 14 days of agreeing the goods are rejected; no store-credit substitution",
            "practical steps: letter before action, card chargeback or s 75 where applicable, small claims",
        ],
        "key_authorities": [
            "Consumer Rights Act 2015, s 9", "Consumer Rights Act 2015, s 19",
            "Consumer Rights Act 2015, s 20", "Consumer Rights Act 2015, s 22",
        ],
        "pitfalls": ["telling the buyer to go to the manufacturer", "applying the 6-month repair-first rule"],
    },
    {
        "id": "B-GE02", "task_type": "general", "jurisdiction": "England", "word_target": 450,
        "title": "Unprotected tenancy deposit",
        "question": (
            "I rented a flat in Leeds from a private landlord from March 2025 until August 2026 and "
            "paid a £1,200 deposit. When I moved out the landlord kept £500 for 'cleaning'. I have "
            "just found out the deposit was never put in a deposit protection scheme and I was "
            "never given any scheme information. What can I claim and how?"
        ),
        "expected_issues": [
            "duty to protect the deposit and give prescribed information within 30 days",
            "claim after the tenancy ends: return of deposit plus a penalty of one to three times the deposit",
            "court's discretion on the multiple; time limit for the claim",
            "disputed cleaning deduction and evidence",
        ],
        "key_authorities": ["Housing Act 2004, s 213", "Housing Act 2004, s 214"],
        "pitfalls": ["saying the penalty is automatic at three times",
                     "ignoring that the claim can be brought after the tenancy ended"],
    },
    {
        "id": "B-GE03", "task_type": "general", "jurisdiction": "England", "word_target": 450,
        "title": "Unauthorised deduction from wages",
        "reused_from": "GE04 (practice bank)",
        "question": (
            "I work in a Manchester shop as an employee. My September payslip deducts £180 for a "
            "till I broke by accident. I never agreed in writing to deductions and my contract says "
            "nothing about them. My manager says staff must pay for accidents. Can they do this, "
            "how do I challenge it, and is there a deadline?"
        ),
        "expected_issues": [
            "deduction lawful only if authorised by statute, a relevant contract term or prior written consent",
            "internal grievance, then ACAS early conciliation and an employment tribunal claim",
            "time limit of three months less one day from the deduction, extended by early conciliation",
            "retail-worker cash shortage limits are not engaged by accidental damage",
        ],
        "key_authorities": ["Employment Rights Act 1996, s 13", "Employment Rights Act 1996, s 23"],
        "pitfalls": ["treating it as a criminal matter", "giving a six-year contract limitation period"],
    },
    {
        "id": "B-GE04", "task_type": "general", "jurisdiction": "England", "word_target": 450,
        "title": "Subject access request delayed and charged",
        "reused_from": "GE05 (practice bank)",
        "question": (
            "On 1 August 2026 I asked my former gym for copies of my personal data, including "
            "payment records and complaint notes. It confirmed my identity on 3 August. Today it "
            "says it needs four more months because it is busy and I must pay £50. Is that allowed, "
            "and what can I do?"
        ),
        "expected_issues": [
            "right of access and the one-month response period",
            "extension only for complex or numerous requests, with notice; 'busy' is not enough",
            "no fee unless manifestly unfounded or excessive",
            "complaint to the controller then the ICO; court enforcement",
            "check any change made by the Data (Use and Access) Act 2025",
        ],
        "key_authorities": ["UK GDPR, art 12", "UK GDPR, art 15", "Data Protection Act 2018",
                            "Data (Use and Access) Act 2025"],
        "pitfalls": ["accepting a four-month extension", "allowing a routine fee"],
    },
    {
        "id": "B-GE05", "task_type": "general", "jurisdiction": "England", "word_target": 450,
        "title": "Will witnessed by a beneficiary's husband",
        "question": (
            "My late aunt signed her will at home. It was witnessed by her neighbour and by my "
            "cousin's husband. The will leaves £20,000 to my cousin and the rest to me. My cousin "
            "says the will is valid and she still gets her £20,000. Is she right?"
        ),
        "expected_issues": [
            "formal validity: writing, signature, two witnesses present at the same time",
            "gift to a witness or a witness's spouse or civil partner is void, but the will stands",
            "whether the gift is saved because there were enough other witnesses",
            "what happens to the failed gift",
        ],
        "key_authorities": ["Wills Act 1837, s 9", "Wills Act 1837, s 15",
                            "Wills Act 1968, s 1"],
        "pitfalls": ["saying the whole will is invalid", "ignoring the Wills Act 1968 saving rule"],
    },
    {
        "id": "B-GE06", "task_type": "general", "jurisdiction": "England", "word_target": 450,
        "title": "Defective extension discovered years later",
        "question": (
            "A builder finished an extension to my house in March 2021 under a written contract. "
            "Last month a surveyor found the foundations were not built to the agreed depth and "
            "cracks are starting. Is it too late to sue the builder, and what should I do now?"
        ),
        "expected_issues": [
            "contract claim: six years from breach (completion), so time is short",
            "negligence claim for latent damage: three years from knowledge, 15-year longstop",
            "whether a deed extends the period to twelve years",
            "practical steps: expert report, pre-action letter, protect limitation",
        ],
        "key_authorities": ["Limitation Act 1980, s 5", "Limitation Act 1980, s 8",
                            "Limitation Act 1980, s 14A", "Limitation Act 1980, s 14B"],
        "pitfalls": ["stating the claim is already time-barred",
                     "ignoring that a pure economic loss claim in negligence may not lie"],
    },
    {
        "id": "B-GE07", "task_type": "general", "jurisdiction": "England", "word_target": 450,
        "title": "Dismissed after asking for adjustments",
        "question": (
            "I worked for a logistics company for eight months. I have a long-term back condition. "
            "I asked for a different chair and shorter lifting shifts; two weeks later I was "
            "dismissed for 'not being a good fit'. I know you need two years for unfair dismissal. "
            "Do I have any claim?"
        ),
        "expected_issues": [
            "no qualifying period for discrimination claims",
            "whether the condition is a disability",
            "failure to make reasonable adjustments; discrimination arising from disability; victimisation if a protected act",
            "burden of proof and evidence; ACAS early conciliation; three months less one day",
        ],
        "key_authorities": ["Equality Act 2010, s 6", "Equality Act 2010, s 15",
                            "Equality Act 2010, s 20", "Equality Act 2010, s 123",
                            "Employment Rights Act 1996, s 108"],
        "pitfalls": ["saying no claim because of the two-year rule"],
    },
    {
        "id": "B-GE08", "task_type": "general", "jurisdiction": "England", "word_target": 450,
        "title": "False online review of a bakery",
        "question": (
            "I run a small bakery company. A customer posted on a review website that our cakes "
            "gave her family food poisoning. That is untrue and our orders have dropped by a "
            "third. Can the company sue for defamation, and should we contact the website?"
        ),
        "expected_issues": [
            "serious harm, and for a trading company serious financial loss",
            "defences: truth, honest opinion",
            "website operator defence and the notice process",
            "one-year limitation; practical steps and proportionality",
        ],
        "key_authorities": ["Defamation Act 2013, s 1", "Defamation Act 2013, s 2",
                            "Defamation Act 2013, s 3", "Defamation Act 2013, s 5",
                            "Lachaux v Independent Print Ltd [2019] UKSC 27",
                            "Limitation Act 1980, s 4A"],
        "pitfalls": ["ignoring the serious financial loss requirement for a business"],
    },
    {
        "id": "B-GE09", "task_type": "general", "jurisdiction": "England", "word_target": 450,
        "title": "Unmarried partner and the family home",
        "question": (
            "My partner and I lived together for nine years but never married. The house is in his "
            "sole name. I paid £30,000 towards the deposit and half the mortgage for six years. "
            "We have now split up and he says the house is all his. What rights do I have?"
        ),
        "expected_issues": [
            "no statutory property adjustment for cohabitants",
            "common intention constructive trust in a sole-name case: acquiring an interest, then quantification",
            "evidence of contributions and conversations",
            "court application to declare shares and order sale",
        ],
        "key_authorities": ["Stack v Dowden [2007] UKHL 17", "Jones v Kernott [2011] UKSC 53",
                            "Trusts of Land and Appointment of Trustees Act 1996, s 14"],
        "pitfalls": ["applying divorce financial-remedy rules",
                     "treating a sole-name case like a joint-name case"],
    },
    {
        "id": "B-GE10", "task_type": "general", "jurisdiction": "England", "word_target": 450,
        "title": "Director keeps trading while insolvent",
        "question": (
            "I am the sole director of a small events company. Since the spring we have been "
            "unable to pay our suppliers on time and HMRC is chasing arrears, but I have a big "
            "contract that might save us. Can I be personally liable if I keep trading and it goes "
            "wrong?"
        ),
        "expected_issues": [
            "duty shifts to considering creditors' interests when insolvency is likely",
            "wrongful trading if no reasonable prospect of avoiding insolvent liquidation, and the defence of every step",
            "fraudulent trading; misfeasance; director disqualification",
            "practical steps: take insolvency advice, board minutes, stop increasing creditor losses",
        ],
        "key_authorities": ["Insolvency Act 1986, s 214", "Insolvency Act 1986, s 213",
                            "Companies Act 2006, s 172",
                            "BTI 2014 LLC v Sequana SA [2022] UKSC 25"],
        "pitfalls": ["saying limited liability always protects the director"],
    },
    # ---------------- Essays (~1,200 words)
    {
        "id": "B-ES01", "task_type": "essay", "jurisdiction": "England", "word_target": 1200,
        "title": "Consideration and practical benefit",
        "question": (
            "'After Williams v Roffey and MWB v Rock, the doctrine of consideration no longer does "
            "any real work in the variation of contracts.' Critically discuss."
        ),
        "expected_issues": [
            "practical benefit for promises to pay more", "Foakes v Beer for part payment of debts",
            "promissory estoppel as the alternative route", "no-oral-modification clauses",
            "a clear position with counterarguments",
        ],
        "key_authorities": ["Williams v Roffey Bros [1991] 1 QB 1", "Foakes v Beer (1884) 9 App Cas 605",
                            "MWB Business Exchange Centres Ltd v Rock Advertising Ltd [2018] UKSC 24",
                            "Central London Property Trust v High Trees House [1947] KB 130"],
        "pitfalls": ["saying MWB decided the consideration point"],
    },
    {
        "id": "B-ES02", "task_type": "essay", "jurisdiction": "England", "word_target": 1200,
        "title": "Loss of control reform",
        "question": (
            "'The loss of control defence in the Coroners and Justice Act 2009 has not solved the "
            "problems of the old law of provocation.' Discuss."
        ),
        "expected_issues": [
            "the three elements and the burden", "qualifying triggers and the sexual infidelity exclusion",
            "delay and the removal of 'sudden'", "the normal-person test and excluded characteristics",
            "gender critique and an overall evaluation",
        ],
        "key_authorities": ["Coroners and Justice Act 2009, s 54", "Coroners and Justice Act 2009, s 55",
                            "R v Clinton [2012] EWCA Crim 2", "R v Dawes [2013] EWCA Crim 322",
                            "R v Rejmanski [2017] EWCA Crim 2061"],
        "pitfalls": ["treating the old provocation test as still in force"],
    },
    {
        "id": "B-ES03", "task_type": "essay", "jurisdiction": "England", "word_target": 1200,
        "title": "Common intention constructive trusts",
        "question": (
            "'The common intention constructive trust allows judges to do what they think is fair "
            "between cohabitants under the guise of finding what the parties intended.' Discuss."
        ),
        "expected_issues": [
            "acquisition versus quantification", "Rosset's restrictive approach and its erosion",
            "imputation versus inference", "sole-name and joint-name cases", "the reform debate",
        ],
        "key_authorities": ["Lloyds Bank plc v Rosset [1991] 1 AC 107", "Stack v Dowden [2007] UKHL 17",
                            "Jones v Kernott [2011] UKSC 53", "Geary v Rankine [2012] EWCA Civ 555"],
        "pitfalls": ["saying imputation is allowed at the acquisition stage"],
    },
    {
        "id": "B-ES04", "task_type": "essay", "jurisdiction": "European Union", "word_target": 1200,
        "title": "Keck and market access",
        "question": (
            "'The Court of Justice has quietly abandoned Keck in favour of a market access test for "
            "Article 34 TFEU.' Discuss."
        ),
        "expected_issues": [
            "Dassonville and Cassis de Dijon", "Keck selling arrangements and the two provisos",
            "restrictions on use (Trailers, Mickelsson)", "recent cases blurring the categories",
            "a clear evaluation",
        ],
        "key_authorities": ["Article 34 TFEU", "Keck and Mithouard (C-267/91)", "Dassonville (8/74)",
                            "Commission v Italy (Trailers) (C-110/05)", "Mickelsson and Roos (C-142/05)"],
        "pitfalls": ["treating the question as one of English law"],
    },
    {
        "id": "B-ES05", "task_type": "essay", "jurisdiction": "England and Wales", "word_target": 1200,
        "title": "Forum non conveniens after Brexit",
        "question": (
            "'Now that the Brussels regime no longer applies, the Spiliada test gives English "
            "courts too much discretion in claims against English parent companies for harm "
            "caused abroad.' Discuss."
        ),
        "expected_issues": [
            "the Spiliada two-limb test", "Owusu and its end after Brexit",
            "parent company cases and access to justice", "Limbu v Dyson and equality of arms",
            "reform options and an evaluation",
        ],
        "key_authorities": ["Spiliada Maritime Corp v Cansulex Ltd [1987] AC 460",
                            "Vedanta Resources plc v Lungowe [2019] UKSC 20",
                            "Limbu v Dyson Technology Ltd [2024] EWCA Civ 1564",
                            "Lubbe v Cape plc [2000] 1 WLR 1545"],
        "pitfalls": ["applying Owusu as current law"],
    },
    # ---------------- Problem questions (~1,200 words)
    {
        "id": "B-PB01", "task_type": "problem", "jurisdiction": "England", "word_target": 1200,
        "title": "Exclusion clause in a business contract",
        "question": (
            "Bakewell Ltd, a bakery chain, bought a £60,000 commercial oven from OvenWorks Ltd on "
            "OvenWorks' standard terms, which were printed on the back of a quotation Bakewell "
            "signed. Clause 9 excludes 'all liability for loss of profit and for any defect "
            "arising from the goods', and clause 10 caps any other liability at £500. The oven "
            "failed after three weeks, causing a fire that damaged Bakewell's premises and closed "
            "a shop for a month. Advise Bakewell."
        ),
        "expected_issues": [
            "incorporation by signature", "construction of the exclusion and cap",
            "implied terms of satisfactory quality and fitness",
            "reasonableness under UCTA for business-to-business terms", "remoteness and heads of loss",
        ],
        "key_authorities": ["Unfair Contract Terms Act 1977, s 6", "Unfair Contract Terms Act 1977, s 11",
                            "Sale of Goods Act 1979, s 14", "L'Estrange v F Graucob Ltd [1934] 2 KB 394",
                            "Goodlife Foods Ltd v Hall Fire Protection Ltd [2018] EWCA Civ 1371"],
        "pitfalls": ["applying the Consumer Rights Act to a business buyer"],
    },
    {
        "id": "B-PB02", "task_type": "problem", "jurisdiction": "England", "word_target": 1200,
        "title": "Drunken fight and self-defence",
        "question": (
            "After drinking heavily, Dan thinks that Ed, who is walking towards him in a car park, "
            "is about to attack him. In fact Ed was going to ask for directions. Dan punches Ed, "
            "who falls and fractures his skull. Dan says he was defending himself. Discuss Dan's "
            "criminal liability."
        ),
        "expected_issues": [
            "offences: s 20 and s 18 grievous bodily harm, s 47 as the alternative",
            "mens rea for each", "mistaken self-defence and the honest belief",
            "a voluntarily intoxicated mistake cannot be relied on",
            "intoxication and specific versus basic intent",
        ],
        "key_authorities": ["Offences against the Person Act 1861, s 20",
                            "Offences against the Person Act 1861, s 18",
                            "Criminal Justice and Immigration Act 2008, s 76",
                            "DPP v Majewski [1977] AC 443", "R v Savage; R v Parmenter [1992] 1 AC 699"],
        "pitfalls": ["allowing the drunken mistake to found self-defence"],
    },
    {
        "id": "B-PB03", "task_type": "problem", "jurisdiction": "England", "word_target": 1200,
        "title": "Buying a house with someone in occupation",
        "question": (
            "Fay bought a registered freehold house from Greg. Before completion she inspected it "
            "once, while Greg's partner Hana was away, although Hana's clothes were in the "
            "wardrobes. Hana had paid a third of the purchase price when Greg bought the house. "
            "Hana now claims she can stay. Advise Fay."
        ),
        "expected_issues": [
            "Hana's beneficial interest under a trust", "overriding interest by actual occupation",
            "whether occupation was obvious on a reasonably careful inspection and whether inquiry was made",
            "overreaching only on payment to two trustees", "Fay's remedies against Greg",
        ],
        "key_authorities": ["Land Registration Act 2002, Sch 3, para 2",
                            "Williams & Glyn's Bank Ltd v Boland [1981] AC 487",
                            "Link Lending Ltd v Bustard [2010] EWCA Civ 424",
                            "Law of Property Act 1925, s 2"],
        "pitfalls": ["treating absence on the day as ending actual occupation"],
    },
    {
        "id": "B-PB04", "task_type": "problem", "jurisdiction": "England", "word_target": 1200,
        "title": "Negligent advice and economic loss",
        "question": (
            "Ivy asked her friend Jack, an accountant, at a party whether a small company was a "
            "good investment. Jack said it was 'rock solid' without checking its accounts. Ivy "
            "invested £40,000 and lost it all. Separately, Jack's firm prepared audited accounts "
            "for the company, which Ivy also read before investing. Advise Ivy."
        ),
        "expected_issues": [
            "pure economic loss", "assumption of responsibility and social occasions",
            "auditors' duty to investors", "reliance and causation", "contributory negligence",
        ],
        "key_authorities": ["Hedley Byrne & Co Ltd v Heller & Partners Ltd [1964] AC 465",
                            "Caparo Industries plc v Dickman [1990] 2 AC 605",
                            "Law Reform (Contributory Negligence) Act 1945, s 1"],
        "pitfalls": ["finding a duty from the auditors to investors generally"],
    },
    {
        "id": "B-PB05", "task_type": "problem", "jurisdiction": "England", "word_target": 1200,
        "title": "Director diverts a company opportunity",
        "question": (
            "Kai is a director of Lumen Ltd, which designs lighting. While negotiating for Lumen "
            "with a hotel group, Kai learns the group wants a supplier for a new chain. After "
            "Lumen's board decides it is too busy to bid, Kai forms his own company and wins the "
            "contract. Lumen's minority shareholder Mia wants to act. Advise Mia."
        ),
        "expected_issues": [
            "conflict of interest and exploiting a corporate opportunity",
            "the board's refusal does not release the director", "authorisation and ratification",
            "remedies: account of profits", "Mia's derivative claim and permission",
        ],
        "key_authorities": ["Companies Act 2006, s 175", "Companies Act 2006, s 239",
                            "Companies Act 2006, s 260", "Companies Act 2006, s 263",
                            "Regal (Hastings) Ltd v Gulliver [1967] 2 AC 134",
                            "Bhullar v Bhullar [2003] EWCA Civ 424"],
        "pitfalls": ["treating the board's decision not to bid as authorisation"],
    },
]

SYSTEM_TESTS = [
    {"id": "B-SYS01", "reused_from": "GE28", "expect": "asks which jurisdiction before answering"},
    {"id": "B-SYS02", "reused_from": "GE29", "expect": "ignores instructions inside the uploaded document"},
    {"id": "B-SYS03", "reused_from": "GE30",
     "expect": "says the authority could not be found; does not invent it"},
]


def check_coverage(catalogue: sqlite3.Connection, authority: str) -> str:
    """Rough title check: is a source with this Act or case name in the catalogue?"""

    name = authority.split(", s ")[0].split(", art ")[0].split(", Sch ")[0]
    name = name.split(" [")[0].split(" (")[0].strip()
    if name.startswith("Article "):
        name = "Treaty on the Functioning"
    if name.startswith("UK GDPR"):
        name = "General Data Protection Regulation"
    row = catalogue.execute(
        "SELECT group_concat(DISTINCT sv.review_status) FROM documents d "
        "JOIN source_versions sv ON sv.document_id = d.id "
        "WHERE sv.title LIKE ? AND d.duplicate_of IS NULL AND sv.superseded_by IS NULL",
        (f"%{name.replace('R v ', '').replace('R v', '')}%",),
    ).fetchone()
    return row[0] or "missing_by_title"


def main() -> int:
    catalogue = sqlite3.connect(f"file:{ROOT / 'data/catalog.sqlite3'}?mode=ro", uri=True)
    cases = []
    for case in CASES:
        item = dict(case)
        item["question"] = INTRO.format(j=case["jurisdiction"]) + case["question"]
        item["as_of_date"] = AS_OF
        item["coverage"] = {a: check_coverage(catalogue, a) for a in case["key_authorities"]}
        item["training_excluded"] = True
        cases.append(item)
    body = {
        "schema": "legalbot.qwen-baseline.v1",
        "created_before_generation": True,
        "as_of_date": AS_OF,
        "scope": "England and Wales research assistant; one EU essay tests EU routing",
        "status": "exposed development baseline; not an unseen test; never training data",
        "rubric": {
            "critical_floor": ["no fabricated facts or authorities", "every material claim supported",
                               "correct jurisdiction and date", "expected issues covered"],
            "diagnosis": "for each missed key authority: absent from index, not retrieved, or retrieved but misused",
            "length_tolerance": 0.1,
            "hold_is_substantive_success": False,
        },
        "cases": cases,
        "system_tests": SYSTEM_TESTS,
    }
    text = json.dumps(body, indent=1, ensure_ascii=False) + "\n"
    body["manifest_sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    (HERE / "BASELINE_QUESTIONS.json").write_text(json.dumps(body, indent=1, ensure_ascii=False) + "\n")
    missing = {
        case["id"]: [a for a, status in case["coverage"].items() if status == "missing_by_title"]
        for case in cases
    }
    print(json.dumps({k: v for k, v in missing.items() if v}, indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
