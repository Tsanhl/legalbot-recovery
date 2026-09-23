"""Freeze exposed scenarios and issue expectations before any answer generation."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "docs/testing/CHAT_CAMPAIGN_20.json"
DATE = "2026-09-23"


def main():
    old = json.loads(
        (
            ROOT / "data/evaluations/visible-final-check-20260923/PRACTICE-QUESTIONS-50.json"
        ).read_text()
    )
    existing = {q["id"]: q for q in old["questions"]}
    rows = []

    def add(id, mode, jurisdiction, title, question, issues, follow=None, original=False):
        rows.append(
            {
                "id": id,
                "task_type": mode,
                "jurisdiction": jurisdiction,
                "as_of_date": DATE,
                "title": title,
                "question": question,
                "word_target": 450 if mode == "general" else 700,
                "expected_issues": issues,
                "follow_up": follow,
                "provenance": "existing_exposed_regression" if original else "new_scenario_first",
                "training_excluded": True,
            }
        )

    q = existing["GE01"]
    add(
        "GE01",
        "general",
        "England",
        "Laptop refund",
        q["question"],
        [
            "faulty goods rejection and dates",
            "separate distance-selling route and exceptions",
            "retailer responsibility",
            "refund timing qualification",
            "collection/return distinction",
            "chargeback and court have separate sources",
        ],
        original=True,
    )
    q = existing["GE02"]
    add(
        "GE02",
        "general",
        "UK",
        "Tenancy notice",
        q["question"],
        [
            "first turn asks only unresolved observable facts",
            "follow-up retains dates/rent",
            "England commencement and transitional law",
            "notice validity",
            "court procedure and immediate steps",
        ],
        q["follow_up"],
        True,
    )
    add(
        "GE03",
        "general",
        "Wales",
        "School support",
        "Today is 23 September 2026. My 10-year-old attends a maintained primary school in Cardiff, Wales. The school agreed she has additional learning needs and issued an individual development plan in June 2026 providing daily small-group literacy support. Since term began on 3 September, that support has not happened. The head says there is no available teaching assistant. I have the plan and the head's email. What can I ask the school or local authority to do, and how can I challenge this? Do not assume the English SEND system applies.",
        [
            "Welsh ALN framework",
            "responsibility for specified provision",
            "review/reconsideration and appeal route",
            "no English EHC substitution",
        ],
    )
    add(
        "GE04",
        "general",
        "Scotland",
        "Succession clarification",
        "Today is 23 September 2026. My father lived in Edinburgh, Scotland, and has died. My sister says I inherit nothing because everything goes to her. I do not know what information matters. What should I do?",
        [
            "ask will/family/death date facts",
            "Scottish movable versus heritable estate",
            "legal rights versus will/intestacy",
            "no invented estate value",
            "practical records/executor steps",
        ],
        "He died on 12 August 2026, domiciled in Scotland. He was widowed, never remarried, and had only two children, my sister and me. A signed will leaves everything to my sister. His only assets were a solely owned Edinburgh house worth about £250,000 and £60,000 in savings; there are £10,000 of debts and funeral expenses. I have not signed any waiver. Please continue from my earlier message and explain which sums need confirmation.",
    )
    add(
        "GE05",
        "general",
        "Northern Ireland",
        "Wage deduction",
        "Today is 23 September 2026. I work as an employee at a shop in Belfast, Northern Ireland. My September payslip shows a £180 deduction for a till shortage. My written contract says nothing about deductions, and I never agreed to one. I received my wages on 20 September. My employer says everyone must share losses regardless of fault. What should I do, what time limits matter, and which body handles the dispute?",
        [
            "NI statute and tribunal route",
            "authorisation/retail worker limits",
            "time limit/conciliation qualifications",
            "no automatic Great Britain ACAS substitution",
        ],
    )
    add(
        "GE06",
        "general",
        "California",
        "Rental deposit",
        "Today is 23 September 2026. I rented an unfurnished apartment in Sacramento, California, under a one-year lease signed in August 2025. I paid a $2,000 security deposit. I moved out and returned keys on 31 August 2026, leaving a forwarding address. I received no refund or itemised deductions by today. The landlord now texts that repainting always uses the entire deposit. I paid all rent and photographed ordinary wear. What can I request and what remedies might exist?",
        [
            "applicable California deposit rules and effective dates",
            "deadline/documentation",
            "ordinary wear versus damage",
            "bad faith fact dependent",
            "no invented evidence content",
        ],
    )
    add(
        "GE07",
        "general",
        "New York",
        "Freelance payment",
        "Today is 23 September 2026. I am a freelance graphic designer based in Albany, New York. A New York company engaged me under a signed $1,800 contract for a logo, due 15 August, with payment due 30 August. I delivered the files on 14 August and the client used the logo. They have not paid and now demand an unrelated extra project for free. I have the contract and emails. Which payment protections and enforcement options may apply?",
        [
            "state versus NYC coverage",
            "written contract and payment deadlines",
            "scope/threshold exclusions",
            "enforcement and remedies without guaranteed penalties",
        ],
    )
    add(
        "GE08",
        "general",
        "Texas",
        "Home repair service",
        "Today is 23 September 2026. I live in Austin, Texas. On 1 August I paid a licensed local company $2,400 to repair my home air conditioner under a written contract. They promised a working compressor and completed the job on 5 August. It stopped cooling on 7 August. A second technician says the old faulty compressor was never replaced; I have a written diagnostic report. The first company refuses to respond. What should I do before suing, and what claims or limitations should I check?",
        [
            "contract versus consumer protection",
            "notice/opportunity to resolve",
            "evidence versus inference of intent",
            "damages and mitigation",
            "licensing status not guarantee of liability",
        ],
    )
    add(
        "GE09",
        "general",
        "Florida",
        "Child relocation clarification",
        "Today is 23 September 2026. I live in Florida with my child and have been offered a job elsewhere. Can I move with my child next month, or must I ask the other parent first?",
        [
            "ask order/distance/duration/agreement",
            "statutory relocation scope",
            "written consent or petition process",
            "best-interest factors",
            "do not treat request as approved",
        ],
        "We live in Orlando. A Florida court entered a parenting plan in 2024 providing shared parental responsibility and alternating weeks with our 8-year-old. I propose moving 200 miles to Miami permanently for a job starting 20 October 2026. The other parent objects in writing. There is no emergency or abuse allegation. The plan has no special relocation permission. Please use my earlier message.",
    )
    add(
        "GE10",
        "general",
        "US federal",
        "Federal records request",
        "Today is 23 September 2026. On 1 July 2026 I submitted a written FOIA request through a US federal agency's published portal for a final inspection report about a public facility. The agency acknowledged receipt on 2 July, gave a tracking number and assigned it to its simple queue. It has sent no determination, exemption explanation or extension notice. I am willing to pay reasonable duplication fees and do not seek personal records. What steps and deadlines should I check?",
        [
            "federal FOIA determination versus production",
            "working day calculation caveats",
            "administrative appeal/exhaustion",
            "exemptions and segregability",
            "no guaranteed immediate release",
        ],
    )
    q = existing["ES01"]
    add(
        "ES01",
        "essay",
        "England",
        "Consideration and estoppel",
        q["question"],
        [
            "purpose tested against operation",
            "variations and debt distinction",
            "Rock undecided consideration issue",
            "promissory versus convention estoppel",
            "suspension/extinction/revival",
            "accurate scholar attribution",
        ],
        original=True,
    )
    add(
        "ES02",
        "essay",
        "England",
        "Negligence duties",
        "Write a critical essay of approximately 700 words: 'The distinction between causing harm and failing to protect is a coherent foundation for English negligence liability.' Apply English law as at 23 September 2026. Analyse omissions, assumptions of responsibility and public authority cases; test significant counterarguments rather than listing cases. Distinguish holdings from evaluation. Use verified authorities and OSCOLA; identify material verification limits.",
        [
            "acts versus omissions",
            "assumption of responsibility",
            "public authorities and statutory context",
            "counterargument",
            "holding precision",
        ],
    )
    add(
        "ES03",
        "essay",
        "England",
        "Judicial review",
        "Write a critical essay of approximately 700 words: 'Proportionality should replace irrationality as the general standard of substantive judicial review in English law.' Use law as at 23 September 2026. Compare rationality and proportionality, rights and non-rights settings, judicial competence and separation of powers. Develop a reasoned position and address opposing arguments. Use verified authorities with OSCOLA and a bibliography grouped into Case law, Legislation and Secondary sources.",
        [
            "current doctrine versus proposed reform",
            "rights context",
            "intensity of review",
            "institutional arguments",
            "no claim universal replacement already settled",
            "grouped bibliography",
        ],
    )
    add(
        "ES04",
        "essay",
        "US federal",
        "First Amendment",
        "Write a critical essay of approximately 700 words: 'Content neutrality adequately protects freedom of speech under the First Amendment.' Apply US federal constitutional law as at 23 September 2026. Discuss content and viewpoint discrimination, scrutiny, time/place/manner regulation and significant limitations of the neutrality approach. Address counterarguments and distinguish current doctrine from your evaluation. Cite verified case pinpoints; use OSCOLA by default.",
        [
            "state action scope",
            "content/viewpoint distinction",
            "scrutiny qualifications",
            "time place manner",
            "counterargument",
        ],
    )
    add(
        "ES05",
        "essay",
        "US federal",
        "Copyright fair use",
        "Write a critical essay of approximately 700 words: 'Transformative use has made US copyright fair use both more principled and less predictable.' Apply US federal law as at 23 September 2026. Analyse the four statutory factors, purpose and character, commercial use and market effect. Compare relevant Supreme Court reasoning without treating transformation as dispositive. Use verified authorities and identify unverified developments. Append an OSCOLA bibliography grouped into Case law, Legislation and Secondary sources.",
        [
            "all four factors",
            "specific use not abstract transformation",
            "commercial/market interaction",
            "case distinctions",
            "no categorical AI-training conclusion",
            "grouped bibliography",
        ],
    )
    q = existing["PB01"]
    add(
        "PB01",
        "problem",
        "England",
        "OvenWorks",
        q["question"],
        [
            "term and misrepresentation alternatives",
            "knowledge versus inference",
            "variation and economic duress",
            "nonreliance and exclusion clause prerequisites",
            "£600 stated not documented",
            "deposit balance extra demand losses separate",
            "elections and no double recovery",
        ],
        original=True,
    )
    add(
        "PB02",
        "problem",
        "England",
        "Criminal liability and defences",
        "Answer in approximately 700 words under English law as at 23 September 2026. At a party in Leeds, Alex sees Ben quickly reach into his jacket after saying 'I will hurt you'. Alex, who voluntarily drank several beers, honestly believes Ben has a knife and punches him once. Ben was actually reaching for his phone, falls onto a table and sustains a broken jaw. Alex says the punch was necessary; a witness says Ben had already stepped away. Later Alex takes Ben's phone, intending to keep it until Ben pays for a damaged jacket, and leaves. Analyse possible non-fatal offences, self-defence, intoxication and theft, addressing evidential alternatives. Do not decide disputed facts or invent intent. Cite verified authorities and distinguish prosecution elements from defences.",
        [
            "offence harm and mens rea",
            "honest mistake versus intoxicated mistake",
            "reasonable force/disputed facts",
            "theft elements and belief in legal right",
            "no invented intent",
        ],
    )
    add(
        "PB03",
        "problem",
        "California",
        "Worker classification and wages",
        "Answer in approximately 700 words applying California and relevant federal law as at 23 September 2026. Lina delivers parcels full time for a courier company in Los Angeles under a contract labelling her an independent contractor. The company sets routes and delivery windows, supplies the van, prohibits substitution and pays $18 per scheduled hour. She has no other clients or independent business. For six weeks she worked 50 hours weekly, including mandatory loading and unloading, but was paid for only 40 hours each week. The company says the label removes overtime rights. No facts establish a statutory exemption. Analyse classification, unpaid time/overtime, possible remedies and information needed; avoid assuming federal and state tests are identical.",
        [
            "California test and exceptions",
            "contract label not decisive",
            "hours worked proof",
            "state/federal overtime interaction",
            "avoid duplicate recovery",
        ],
    )
    add(
        "PB04",
        "problem",
        "New York",
        "Housing repairs",
        "Answer in approximately 700 words applying New York law as at 23 September 2026. Amir rents a private market-rate apartment in Buffalo as his main home under a written lease. The landlord does not live in the building. A roof leak reported by email on 2 August has made one bedroom unusable; photographs show water damage. The landlord has not repaired it. Amir withheld all September rent without obtaining legal advice. On 18 September the landlord changed the entrance lock while Amir was at work; his belongings remain inside. No court case or order exists. The landlord claims the lease waives all repair duties. Analyse repair duties, possible rent remedies, the risks of withholding and the lockout; identify urgent practical steps and avoid assuming NYC-specific rules apply.",
        [
            "habitability and waiver",
            "abatement proportionality proof",
            "withholding risks",
            "self-help lockout",
            "Buffalo versus NYC rules",
        ],
    )
    add(
        "PB05",
        "problem",
        "Florida",
        "Debt collection",
        "Answer in approximately 700 words applying Florida and relevant federal law as at 23 September 2026. Eva lives in Tampa. A third-party collection agency buys a personal credit-card debt and first calls her on 1 September 2026. On 4 September she receives a letter stating the debt amount and dispute rights. She mails a written dispute on 10 September, delivered on 12 September, asking for verification. On 16 September the collector calls her employer and tells a manager Eva owes the debt; the employer had already told it workplace calls are prohibited. It calls Eva at 10:30 pm on 18 September and threatens arrest unless she pays immediately. No verification has arrived. Analyse the federal and Florida frameworks, facts affecting their scope, remedies and limitations. Do not assume the amount or validity of the underlying debt is established.",
        [
            "federal debt collector/consumer coverage",
            "validation dispute timing",
            "third party and workplace communications",
            "time of call/arrest threats",
            "Florida separate statute",
            "remedies limitation no automatic debt cancellation",
        ],
    )
    assert len(rows) == 20
    value = {
        "schema": "legalbot.exposed-chat-campaign.v1",
        "created_before_generation": True,
        "models": ["codex_bridge", "qwen_local"],
        "as_of_date": DATE,
        "review_kind": "same-provider AI plus deterministic checks; not professional legal validation",
        "rubric": {
            "critical_floor": [
                "no fabricated facts or authorities",
                "supported material claims",
                "correct jurisdiction/date",
                "material coverage",
            ],
            "length_tolerance": 0.1,
            "clarification_exempt": True,
            "repairs_max": 2,
            "advisory_writing_target": 70,
            "hold_is_substantive_success": False,
        },
        "cases": rows,
    }
    value["manifest_sha256"] = hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if DEST.exists():
        raise RuntimeError("Campaign already frozen; do not overwrite attempted inputs")
    DEST.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    print(value["manifest_sha256"])


if __name__ == "__main__":
    main()
