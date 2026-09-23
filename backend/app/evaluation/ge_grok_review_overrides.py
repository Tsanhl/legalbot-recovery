"""Independent Grok case-level recommendations.

These are AI_MODEL_REVIEWER recommendations only. They must not populate
qualified_legal_review or legal gold.
"""

from __future__ import annotations

from typing import Any

from .ge_fact_dependent_packets import CONDITIONAL_ANSWER, MISSING_FACTS
from .ge_hold_reason_router import CASE_174, CASE_312
from .ge_progression_taxonomy import LAND_LAW_D05

RECOMMEND_APPROVE = "RECOMMEND_APPROVE"
RECOMMEND_APPROVE_WITH_EDIT = "RECOMMEND_APPROVE_WITH_EDIT"
RECOMMEND_HOLD = "RECOMMEND_HOLD"
RECOMMEND_REJECT = "RECOMMEND_REJECT"

# Full-candidate locators that do not answer the question (wrong statute/part).
WRONG_ROUTE_FULL = frozenset(
    {
        "administrative-law:cp-d13",
        "business-and-company-law:cp-d12",
        "business-and-company-law:cp-d16",
        "business-and-company-law:cp-d18",
        "commercial-law:cp-d09",
        "commercial-law:cp-d17",
        "land-law:cp-d11",
        "trusts-law:cp-d07",
    }
)

# Full-candidate locators that are on the topic but omit a controlling rule.
INCOMPLETE_FULL = frozenset(
    {
        "administrative-law:cp-d01",
        "administrative-law:cp-d04",
        "administrative-law:cp-d07",
        "administrative-law:cp-d14",
        "business-and-company-law:cp-d05",
        "business-and-company-law:cp-d17",
        "commercial-law:cp-d03",
        "commercial-law:cp-d11",
        "commercial-law:cp-s01",
        "contract-law:cp-d02",
        "contract-law:cp-d11",
        "wills-and-estates:cp-d16",
    }
)

LIMITED_RETAINED = (
    "ai-and-data-protection:cp-d07",
    "competition-law:cp-d02",
)
LIMITED_RECLASSIFIED = (
    "ai-and-data-protection:cp-d03",
    "ai-and-data-protection:cp-d09",
    "land-law:cp-d17",
)


def _edit(
    *,
    proposed: str,
    instruction: str,
    omissions: list[str] | None = None,
    missing: list[str] | None = None,
    risks: list[str] | None = None,
    contrary: list[str] | None = None,
    confidence: str = "MEDIUM",
    claim_verdict: str = "PARTIALLY_SUPPORTED",
) -> dict[str, Any]:
    return {
        "ai_recommended_decision": RECOMMEND_APPROVE_WITH_EDIT,
        "question_answer_adequacy": "FAIL",
        "currentness_verdict": "RESOLVED",
        "jurisdiction_verdict": "IN_SCOPE",
        "proposed_final_answer": proposed,
        "exact_edit_instructions": [
            {
                "instruction": instruction,
                "reason": "The candidate is a diagnostic quotation wrapper, not a finished practical answer.",
                "material_edit": True,
            }
        ],
        "no_new_proposition": True,
        "material_edit": True,
        "re_review_required": True,
        "new_evidence_required": False,
        "confidence": confidence,
        "material_omissions": omissions or [],
        "missing_facts": missing or [],
        "risk_flags": ["diagnostic_template_answer", *(risks or [])],
        "contrary_or_limiting_authorities": contrary or [],
        "claim_verdict": claim_verdict,
        "unresolved_questions": missing or [],
    }


def _hold(
    *,
    reason: str,
    adequacy: str = "FAIL",
    currentness: str = "UNRESOLVED",
    jurisdiction: str = "UNRESOLVED",
    omissions: list[str] | None = None,
    missing: list[str] | None = None,
    risks: list[str] | None = None,
    contrary: list[str] | None = None,
    new_evidence: bool = False,
    proposed_ids: list[str] | None = None,
    proposed: str = "",
    claim_verdict: str = "PARTIALLY_SUPPORTED",
    confidence: str = "MEDIUM",
) -> dict[str, Any]:
    return {
        "ai_recommended_decision": RECOMMEND_HOLD,
        "question_answer_adequacy": adequacy,
        "currentness_verdict": currentness,
        "jurisdiction_verdict": jurisdiction,
        "proposed_final_answer": proposed,
        "exact_edit_instructions": [],
        "no_new_proposition": True,
        "material_edit": False,
        "re_review_required": False,
        "new_evidence_required": new_evidence,
        "proposed_new_evidence_ids": proposed_ids or [],
        "confidence": confidence,
        "material_omissions": omissions or [],
        "missing_facts": missing or [],
        "risk_flags": risks or ["material_issue_unresolved"],
        "contrary_or_limiting_authorities": contrary or [],
        "claim_verdict": claim_verdict,
        "unresolved_questions": [reason, *(missing or [])],
        "hold_reason": reason,
    }


def _reject(
    *,
    reason: str,
    proposed: str = "",
    risks: list[str] | None = None,
    new_evidence: bool = False,
    proposed_ids: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "ai_recommended_decision": RECOMMEND_REJECT,
        "question_answer_adequacy": "FAIL",
        "currentness_verdict": "UNRESOLVED",
        "jurisdiction_verdict": "UNRESOLVED",
        "proposed_final_answer": proposed,
        "exact_edit_instructions": [],
        "no_new_proposition": True,
        "material_edit": False,
        "re_review_required": False,
        "new_evidence_required": new_evidence,
        "proposed_new_evidence_ids": proposed_ids or [],
        "confidence": "HIGH",
        "material_omissions": [reason],
        "missing_facts": [],
        "risk_flags": ["misleading_or_wrong_route", *(risks or [])],
        "contrary_or_limiting_authorities": [],
        "claim_verdict": "UNSUPPORTED",
        "unresolved_questions": [reason],
        "reject_reason": reason,
    }


OVERRIDES: dict[str, dict[str, Any]] = {
    "administrative-law:cp-d08": _edit(
        proposed=(
            "You can ask the public authority for a reasonable adjustment so you can use "
            "the online form, and you can complain if it fails to make one. Equality Act "
            "2010 section 29 makes it unlawful for a person providing a service to the "
            "public, or exercising a public function, to discriminate. Sections 20 and 21 "
            "require reasonable adjustments where a disabled person is put at a substantial "
            "disadvantage, and Schedule 2 applies those duties to public functions. The "
            "Public Sector Bodies (Websites and Mobile Applications) (No. 2) Accessibility "
            "Regulations 2018 regulation 12 provides a reporting route for website "
            "accessibility. The attached locators do not decide whether any particular "
            "adjustment is reasonable or which complaint body will act."
        ),
        instruction="Replace the diagnostic wrapper with the Equality Act and accessibility-regulation limited answer.",
        missing=["What barrier the form creates and what adjustment has already been requested."],
        confidence="HIGH",
        claim_verdict="SUPPORTED",
    ),
    "administrative-law:cp-d16": _edit(
        proposed=(
            "No. A statement that the official had statutory power to make the decision "
            "does not, by itself, end a challenge. Senior Courts Act 1981 section 31 and "
            "CPR 54.5 show that an application for judicial review may still be made, "
            "promptly and in any event not later than three months after the grounds first "
            "arose. Whether the particular decision is lawful is a separate merits question "
            "not answered by the attached locators."
        ),
        instruction="State that statutory power does not automatically immunise the decision, limited to SCA 31 and CPR 54.5.",
        omissions=["Grounds of review and any statutory appeal replacing judicial review."],
    ),
    "administrative-law:cp-d17": _edit(
        proposed=(
            "If removal from emergency accommodation is due tomorrow, urgent legal help is "
            "needed today. The attached locators show that the High Court may grant an "
            "interim injunction (Senior Courts Act 1981 section 37) and that CPR 25.1 lists "
            "interim remedies, including an interim injunction. They do not decide whether "
            "you have a homelessness or housing right to remain, and they do not complete "
            "an application for you. Keep the decision letter, any notice to leave, and "
            "evidence of overnight need."
        ),
        instruction="Lead with urgent interim relief from SCA 37 / CPR 25.1. Do not invent a homelessness outcome.",
        risks=["urgent_housing"],
        missing=["The exact notice, decision letter and any review or appeal already lodged."],
        confidence="HIGH",
        claim_verdict="SUPPORTED",
    ),
    "administrative-law:cp-s01": _edit(
        proposed=(
            "Do not wait for the internal complaint result if the three-month judicial-review "
            "period may end in two days. CPR 54.5 requires a judicial-review claim to be filed "
            "promptly and in any event not later than three months after the grounds first "
            "arose. Senior Courts Act 1981 section 31 is the High Court procedure for that "
            "claim. An internal complaint does not, on the attached locators, stop time "
            "running. Get urgent advice today about filing or seeking an extension."
        ),
        instruction="State that the CPR 54.5 time limit is not shown to be paused by an internal complaint.",
        confidence="HIGH",
        claim_verdict="SUPPORTED",
    ),
    "business-and-company-law:cp-d03": _edit(
        proposed=(
            "Yes, you can still be responsible. Companies Act 2006 section 172 requires a "
            "director to act in the way they consider, in good faith, would be most likely "
            "to promote the success of the company for the benefit of its members as a "
            "whole. Section 174 requires the care, skill and diligence of a reasonably "
            "diligent person with the general knowledge reasonably expected of a director "
            "and of that director. Agreeing to be a director as a favour, or not attending "
            "meetings, is not shown by these sections to remove those duties."
        ),
        instruction="Answer from CA 2006 ss 172 and 174 only. Do not add disqualification or shadow-director routes.",
        claim_verdict="SUPPORTED",
    ),
    "business-and-company-law:cp-d09": _edit(
        proposed=(
            "A 51% or majority shareholder using the company account for personal expenses "
            "and refusing dividends may be challenged, but the attached locators do not "
            "guarantee any particular order. Companies Act 2006 section 994 allows a member "
            "to apply to the court for relief where the company's affairs are being conducted "
            "in a manner unfairly prejudicial to members. Sections 171, 172 and 175 bind "
            "directors to use powers for proper purposes, promote success, and avoid "
            "conflicts. Whether these facts meet the s994 test, and whether dividends can be "
            "compelled, is not decided on the attached text."
        ),
        instruction="Limit the answer to unfair-prejudice and director-duty locators. Do not promise a dividend order.",
        claim_verdict="SUPPORTED",
    ),
    "business-and-company-law:cp-d10": _edit(
        proposed=(
            "Directors cannot treat a self-issue of shares as automatically valid. Companies "
            "Act 2006 section 549 restricts allotment without the required authorisation. "
            "Section 561 gives existing holders a right of pre-emption on allotment of "
            "equity securities unless disapplied. Section 171 requires directors to act in "
            "accordance with the constitution and only for proper purposes. The attached "
            "locators do not by themselves void the allotment or award an injunction; "
            "shareholders need the constitution, notice of the allotment, and urgent advice."
        ),
        instruction="Use ss 549, 561 and 171 only. Do not assert that the allotment is already void.",
        claim_verdict="SUPPORTED",
    ),
    "business-and-company-law:cp-d11": _edit(
        proposed=(
            "The company may have a claim. Companies Act 2006 section 175 requires a "
            "director to avoid a situation in which they have, or can have, a direct or "
            "indirect interest that conflicts with the company's interests, including the "
            "exploitation of any property, information or opportunity. Taking a business "
            "opportunity found through the company, then leasing it back at a profit, is "
            "the kind of situation s175 addresses. Authorisation, ratification and remedy "
            "are not completed by the attached locator."
        ),
        instruction="Answer from CA 2006 s175 only.",
        claim_verdict="SUPPORTED",
    ),
    "business-and-company-law:cp-s02": _edit(
        proposed=(
            "No. I cannot help arrange a transfer of company equipment to a sibling for £1 "
            "to put it beyond creditors. If the company may become insolvent, Companies Act "
            "2006 section 172 still requires directors to promote the success of the company, "
            "and Insolvency Act 1986 section 238 (transaction at an undervalue) and section "
            "423 (transaction defrauding creditors) are the attached routes by which such a "
            "transfer may later be challenged. Do not make the transfer. Get insolvency advice."
        ),
        instruction="Refuse the requested arrangement. Explain only the attached IA 1986 ss 238 and 423 and CA 2006 s172.",
        risks=["refusal_of_unlawful_or_abusive_request"],
        confidence="HIGH",
        claim_verdict="SUPPORTED",
    ),
    "commercial-law:cp-d02": _edit(
        proposed=(
            "On the attached locator, you do not own any of the 80 bags merely because you "
            "paid. Sale of Goods Act 1979 section 20A can pass property in an identified "
            "bulk to a buyer who has paid, but only where the goods form part of a bulk "
            "identified in the contract and the buyer has paid for some or all of the goods "
            "forming part of that bulk. The known facts say the bags were identical and not "
            "numbered or moved. Section 20A is therefore not shown to be satisfied."
        ),
        instruction="Apply SOGA s20A conditions. Do not invent a trust or retention-of-title outcome.",
        claim_verdict="SUPPORTED",
    ),
    "commercial-law:cp-d04": _edit(
        proposed=(
            "The starting rule is that the original owner can reclaim the stock if the "
            "dealer did not own it. Sale of Goods Act 1979 section 21 says that where goods "
            "are sold by a person who is not the owner, and who does not sell under the "
            "owner's authority or with the owner's consent, the buyer acquires no better "
            "title than the seller had, unless the owner is by conduct precluded from "
            "denying the seller's authority. Exceptions to that rule are not attached in "
            "this packet."
        ),
        instruction="State nemo dat from s21 and expressly note that exceptions are unattached.",
        omissions=["Sale of Goods Act 1979 ss 24–25 and Factors Act exceptions are not attached."],
        claim_verdict="SUPPORTED",
    ),
    "commercial-law:cp-d07": _edit(
        proposed=(
            "Risk does not pass merely because the seller says it passed when the goods left "
            "the warehouse. Sale of Goods Act 1979 section 20 provides that, unless otherwise "
            "agreed, risk passes with property. If delivery is delayed through the fault of "
            "buyer or seller, the goods are at the risk of the party at fault as regards any "
            "loss which might not have occurred but for that fault. Whether property has "
            "passed, and whether any contrary agreement exists, is not shown."
        ),
        instruction="Answer from SOGA s20 only.",
        claim_verdict="SUPPORTED",
    ),
    "contract-law:cp-d14": _edit(
        proposed=(
            "No. Clicking 'I agree' does not, on the attached locators, make exclusion or "
            "price-variation terms unchallengeable. Consumer Rights Act 2015 section 62 "
            "provides that an unfair term of a consumer contract is not binding on the "
            "consumer. Section 64 limits when a term may be assessed for fairness if it is "
            "transparent and prominent and specifies the main subject matter or the price. "
            "Unfair Contract Terms Act 1977 section 11 uses a reasonableness test for certain "
            "non-consumer terms. Which Act applies, and whether these terms are fair or "
            "reasonable, depends on whether you dealt as a consumer and on the full wording."
        ),
        instruction="Limit the answer to CRA 2015 ss 62 and 64 and UCTA 1977 s11.",
        claim_verdict="SUPPORTED",
    ),
    "criminal-law:cp-d08": _edit(
        proposed=(
            "Yes. Police and Criminal Evidence Act 1984 section 58 gives a person who is in "
            "police detention a right to consult a solicitor privately at any time. If the "
            "interview is truly voluntary and you are not detained, s58 as attached does not "
            "itself decide the leaving question, but you may still ask for legal advice "
            "before answering. Do not rely on this packet for a charging outcome."
        ),
        instruction="Answer the solicitor-access question from PACE s58. Do not overstate detention status.",
        missing=["Whether you are in police detention or free to leave."],
        confidence="HIGH",
        claim_verdict="SUPPORTED",
    ),
    "criminal-law:cp-d14": _edit(
        proposed=(
            "You can still ask for a solicitor. Police and Criminal Evidence Act 1984 "
            "section 58 is the attached right of a person in police detention to consult a "
            "solicitor privately. If officers say you may leave at any time, ask them to "
            "confirm whether you are under arrest or in detention and whether you are free "
            "to go. The attached locator does not authorise them to discourage legal advice, "
            "and it does not decide if the interview is voluntary."
        ),
        instruction="Use PACE s58 for solicitor access. Identify detention versus voluntary attendance as a missing fact.",
        missing=["Whether the attendee is under arrest or in police detention."],
        confidence="HIGH",
        claim_verdict="SUPPORTED",
    ),
    "tort-law:cp-d08": _edit(
        proposed=(
            "Responsibility is not limited to one person on the attached locator. Consumer "
            "Protection Act 1987 section 2 can make the producer of a defective product, and "
            "in some cases the importer or a person who holds themselves out as producer, "
            "liable for damage caused wholly or partly by a defect. A defective heater that "
            "caused a fire may fall within that regime if it is a product and the claimant "
            "suffered damage of the kind the Act covers. Occupiers', landlord and installer "
            "duties are not attached and are not decided here."
        ),
        instruction="Limit liability discussion to CPA 1987 s2. Expressly omit occupier/landlord routes as unattached.",
        omissions=["Occupiers' Liability and landlord repairing obligations are not attached."],
        claim_verdict="SUPPORTED",
    ),
    "tort-law:cp-d09": _edit(
        proposed=(
            "You may still have a claim even if you were distracted, but the attached locator "
            "does not decide who is liable. Law Reform (Contributory Negligence) Act 1945 "
            "section 1 allows the court to reduce damages to the extent it thinks just and "
            "equitable having regard to the claimant's share in the responsibility. It does "
            "not create the cyclist's or highway authority's duty. Those duties are not in "
            "this packet."
        ),
        instruction="Treat s1 as an apportionment rule only, not as a complete liability answer.",
        omissions=["Duty and breach for the cyclist and for streetlighting are unattached."],
        claim_verdict="SUPPORTED",
    ),
    "trusts-law:cp-d03": _edit(
        proposed=(
            "Beneficiaries may challenge the investment decision, but success is not shown. "
            "Trustee Act 2000 section 3 confers a general power of investment. Section 4 "
            "requires the standard investment criteria, including suitability and "
            "diversification so far as appropriate. Investing nearly everything in one risky "
            "company is the kind of concentration s4 is capable of addressing. Whether the "
            "trust deed restricted or widened that power is not in the packet."
        ),
        instruction="Answer from TA 2000 ss 3 and 4 only.",
        claim_verdict="SUPPORTED",
    ),
    "trusts-law:cp-d10": _edit(
        proposed=(
            "Trustees who delegate investment management remain answerable under the attached "
            "locator if they do not comply with Trustee Act 2000 section 11. That section "
            "restricts when trustees may authorise an agent to exercise functions. The "
            "adviser's breach of deed limits does not, on this locator alone, transfer all "
            "liability to the adviser or excuse the trustees. The deed, the agency terms and "
            "what the trustees did to supervise are missing."
        ),
        instruction="Limit the answer to TA 2000 s11. Do not invent a complete indemnity or exclusion.",
        claim_verdict="SUPPORTED",
    ),
    "wills-and-estates:cp-d01": _edit(
        proposed=(
            "If a parent died intestate domiciled in England and Wales, Administration of "
            "Estates Act 1925 section 46 sets the statutory order of beneficial distribution. "
            "It does not by itself appoint an administrator or say who may take the grant. "
            "Who inherits depends on whether there is a surviving spouse or civil partner "
            "and on which relatives survived. The attached locator does not name personal "
            "representatives."
        ),
        instruction="Use AEA 1925 s46 for beneficial order only. Do not invent grant practice.",
        omissions=["Non-contentious probate rules and who may take a grant are unattached."],
        missing=["Whether there is a surviving spouse or civil partner and which children survived."],
        claim_verdict="SUPPORTED",
    ),
    "wills-and-estates:cp-d07": _edit(
        proposed=(
            "There may be a claim, and time matters. Inheritance (Provision for Family and "
            "Dependants) Act 1975 section 1 can allow a person who was being maintained by "
            "the deceased to apply for financial provision from an English estate. Section 2 "
            "sets out the orders the court may make. Section 4 requires an application to be "
            "made within six months from the date of the first grant, unless the court "
            "permits a later application. A grant five months ago means the ordinary window "
            "may have about one month left. Get advice immediately. The attached locators do "
            "not decide that you will succeed."
        ),
        instruction="Lead with I(PFD)A 1975 ss 1, 2 and 4 and the six-month period.",
        confidence="HIGH",
        claim_verdict="SUPPORTED",
    ),
    "wills-and-estates:cp-d08": _edit(
        proposed=(
            "An unmarried partner does not inherit the home under Administration of Estates "
            "Act 1925 section 46 merely by living there for eight years. Section 46 gives "
            "the intestate's estate to the statutory class, which does not include a "
            "cohabitant as such. Inheritance (Provision for Family and Dependants) Act 1975 "
            "sections 1 and 2 can allow a person living in the same household as the "
            "husband or wife of the deceased, or a person being maintained, to apply for "
            "provision. Whether the home can be kept depends on that application and on how "
            "title was held. Those facts are not completed here."
        ),
        instruction="Combine AEA s46 (no automatic cohabitant share) with I(PFD)A ss 1–2.",
        missing=["Exactly how the home was held and whether the partner was being maintained."],
        claim_verdict="SUPPORTED",
    ),
    CASE_312: {
        "ai_recommended_decision": RECOMMEND_APPROVE_WITH_EDIT,
        "question_answer_adequacy": "FAIL",
        "currentness_verdict": "LIMITED",
        "jurisdiction_verdict": "IN_SCOPE",
        "proposed_final_answer": CONDITIONAL_ANSWER,
        "exact_edit_instructions": [
            {
                "instruction": (
                    "Replace the diagnostic wrapper with the frozen conditional formality "
                    "answer. Keep law as at 15 January 2024, Wills Act 1837 s9, SI 2020/952 "
                    "and SI 2022/18. Do not declare definitive validity."
                ),
                "reason": "The candidate does not use the required conditional formulation.",
                "material_edit": True,
            }
        ],
        "no_new_proposition": True,
        "material_edit": True,
        "re_review_required": True,
        "new_evidence_required": False,
        "confidence": "HIGH",
        "material_omissions": [],
        "missing_facts": list(MISSING_FACTS),
        "risk_flags": ["diagnostic_template_answer", "fact_dependent_validity"],
        "contrary_or_limiting_authorities": [],
        "claim_verdict": "SUPPORTED",
        "unresolved_questions": list(MISSING_FACTS),
    },
    CASE_174: _hold(
        reason=(
            "Jurisdiction and condition-precedent scope remain unresolved. The attached ICC "
            "article 5, Ohpen, Kajima paragraph 29, Churchill and CPR material should be "
            "preserved. Cable & Wireless and Arbitration Act 1996 section 9 must stay "
            "excluded. The diagnostic wrapper does not decide whether the English court "
            "must stay for ICC mediation on these contract words."
        ),
        currentness="LIMITED",
        jurisdiction="UNRESOLVED",
        risks=["named_case_174_jurisdiction_only", "diagnostic_template_answer"],
        contrary=["Cable & Wireless remains a rejected route.", "Arbitration Act 1996 s9 stays excluded."],
        missing=[
            "Whether the ICC clause is a condition precedent to English proceedings.",
            "What seat, forum and governing-law consequences follow for a German buyer.",
        ],
        confidence="HIGH",
    ),
    LAND_LAW_D05: _hold(
        reason=(
            "The 1 May 2026 / 15 August 2026 date ambiguity is preserved. The attached "
            "Law of Property Act 1925 section 52 and CPR 55.11 passages are not shown to "
            "be the controlling private-tenancy continuation rule. No governing date is "
            "chosen by assumption."
        ),
        risks=["named_land_law_d05_date_ambiguity", "wrong_or_off_issue_locator", "diagnostic_template_answer"],
        new_evidence=True,
        proposed_ids=["housing-act-1988-s5", "landlord-and-tenant-covenants-act-1995"],
        claim_verdict="UNSUPPORTED",
        confidence="HIGH",
    ),
    "wills-and-estates:cp-s02": _reject(
        reason=(
            "The candidate quotes intestacy distribution in response to a request to create "
            "and backdate a will. That is the wrong legal route and is unsuitable. A "
            "backdated will would be a false instrument."
        ),
        proposed=(
            "No. I cannot create or backdate a will after death. A will must be made by the "
            "will-maker, with the required formalities, during their lifetime. After death "
            "without a signed will, Administration of Estates Act 1925 section 46 may govern "
            "who benefits on intestacy. I will not draft a false will."
        ),
        risks=["refusal_of_unlawful_or_abusive_request"],
    ),
    "tort-law:cp-d18": _reject(
        reason=(
            "Khan v Meadows (clinical-negligence scope of duty) is not a supporting authority "
            "for a website spreading an address and a false accusation. The candidate is on "
            "the wrong legal route."
        ),
        new_evidence=True,
        proposed_ids=["defamation-act-2013", "protection-from-harassment-act-1997", "uk-gdpr-art-17"],
        risks=["wrong_route", "urgent_privacy_harm"],
    ),
    "tort-law:cp-d02": _hold(
        reason=(
            "Manchester Building Society v Grant Thornton is a professional-negligence scope "
            "authority and is not shown to control a neighbour-tree claim. Contributory "
            "negligence s4 is a definitional provision, not a complete duty analysis."
        ),
        new_evidence=True,
        proposed_ids=["occupiers-liability-or-nuisance-tree-duty"],
        claim_verdict="UNSUPPORTED",
        risks=["wrong_route", "diagnostic_template_answer"],
    ),
    "contemporary-biolaw-and-regulation:cp-d03": _hold(
        reason=(
            "HFEA 1990 section 2 definitions, Medical Devices Regulations 2002 reg 44ZC and "
            "DPA 2018 section 67 (breach-notification threshold) are not shown to answer a "
            "consumer DNA-risk-score explanation request."
        ),
        new_evidence=True,
        proposed_ids=["uk-gdpr-art-13", "uk-gdpr-art-15", "uk-gdpr-art-22"],
        claim_verdict="UNSUPPORTED",
        risks=["wrong_route", "diagnostic_template_answer"],
    ),
    "land-law:cp-d11": _hold(
        reason=(
            "Law of Property Act 1925 section 101 (mortgagee power of sale) is not the "
            "controlling registered-title alteration/indemnity route for a fraudster who "
            "changed the registered address and took a mortgage."
        ),
        currentness="RESOLVED",
        jurisdiction="IN_SCOPE",
        new_evidence=True,
        proposed_ids=["lra-2002-sch-4", "lra-2002-sch-8"],
        claim_verdict="UNSUPPORTED",
        risks=["wrong_route", "diagnostic_template_answer"],
        adequacy="FAIL",
    ),
}

for _case_id in WRONG_ROUTE_FULL:
    OVERRIDES.setdefault(
        _case_id,
        _hold(
            reason="Attached locators are not the controlling provisions for this question.",
            currentness="RESOLVED",
            jurisdiction="IN_SCOPE",
            claim_verdict="UNSUPPORTED",
            risks=["wrong_or_off_issue_locator", "diagnostic_template_answer"],
            new_evidence=True,
        ),
    )

for _case_id in INCOMPLETE_FULL:
    OVERRIDES.setdefault(
        _case_id,
        _hold(
            reason=(
                "Currentness and jurisdiction are recorded as passed, but a controlling "
                "proposition needed to answer the question is not in the attached locators. "
                "The diagnostic wrapper is not a finished answer."
            ),
            currentness="RESOLVED",
            jurisdiction="IN_SCOPE",
            claim_verdict="PARTIALLY_SUPPORTED",
            risks=["incomplete_controlling_locator", "diagnostic_template_answer"],
        ),
    )

for _case_id in LIMITED_RETAINED:
    OVERRIDES.setdefault(
        _case_id,
        _hold(
            reason=(
                "The contracted answer is a meaningful limited response and does not look "
                "like the diagnostic wrapper, but packet currentness is NOT_ASSESSABLE and "
                "jurisdiction is FAIL. RECOMMEND_APPROVE requires those issues to be resolved."
            ),
            adequacy="PASS",
            currentness="UNRESOLVED",
            jurisdiction="UNRESOLVED",
            risks=["limited_candidate_currentness_or_jurisdiction_unresolved"],
            confidence="MEDIUM",
            claim_verdict="PARTIALLY_SUPPORTED",
        ),
    )

for _case_id in LIMITED_RECLASSIFIED:
    OVERRIDES.setdefault(
        _case_id,
        _hold(
            reason=(
                "The contracted answer is in the right legal area but post-contraction "
                "claim-support did not pass, and currentness/jurisdiction remain unresolved."
            ),
            adequacy="PASS",
            currentness="UNRESOLVED",
            jurisdiction="UNRESOLVED",
            risks=["contraction_claim_support_failed", "currentness_or_jurisdiction_unresolved"],
            claim_verdict="PARTIALLY_SUPPORTED",
        ),
    )

HOLD_MATERIAL_TEMPLATE_REASONS = {
    "commercial-law:cp-d01": (
        "SOGA ss 14 and 35 are on topic for quality and acceptance, but rejection versus "
        "repair, consumer-versus-business regime and currentness are unresolved."
    ),
    "contract-law:cp-d10": (
        "Misrepresentation Act 1967 s2 is attached, but shared reliance on the same expert "
        "report raises inducement and causation questions the locator does not resolve. "
        "The wrapper is not a finished answer."
    ),
    "contract-law:cp-s01": (
        "CRA 2015 digital-content remedies may be relevant, but trader identity, goods-versus-"
        "digital-content characterisation and currentness are unresolved."
    ),
    "criminal-law:cp-d17": (
        "PACE s58 is on solicitor access, but s22 seizure does not answer whether the person "
        "must sign a statement or unlock a phone before the solicitor arrives."
    ),
    "land-law:cp-d01": (
        "TOLATA s14 is a court-order power, not a complete common-intention constructive "
        "trust analysis of mortgage contributions."
    ),
    "land-law:cp-d02": (
        "LPA 1925 s202 and LRA 2002 s132 are not shown to be the prescription/easement "
        "locators needed for a path used for years."
    ),
    "land-law:cp-d03": (
        "LRA 2002 Sch 3 and LPA s101 do not complete an occupying non-mortgagor defence "
        "to possession."
    ),
    "land-law:cp-d07": (
        "LRA 2002 ss 96, 27 and 29 do not by themselves establish a twelve-year adverse "
        "possession application outcome."
    ),
    "tort-law:cp-s01": (
        "Limitation Act 1980 ss 11 and 14 are on topic, but date of knowledge and whether "
        "the claim is still in time remain fact-dependent."
    ),
    "tort-law:cp-s02": (
        "Limitation Act 1980 s11 does not establish a secondary-victim psychiatric claim."
    ),
    "wills-and-estates:cp-d14": (
        "AEA 1925 s46 can answer whether the oldest child takes everything, but the "
        "candidate wrapper never states that distribution. A finished answer is still required."
    ),
}

for _case_id, _reason in HOLD_MATERIAL_TEMPLATE_REASONS.items():
    _cur = "RESOLVED" if _case_id in {"contract-law:cp-d10", "wills-and-estates:cp-d14"} else "UNRESOLVED"
    _jur = "IN_SCOPE" if _case_id in {"contract-law:cp-d10", "wills-and-estates:cp-d14"} else "UNRESOLVED"
    OVERRIDES.setdefault(
        _case_id,
        _hold(
            reason=_reason,
            currentness=_cur,
            jurisdiction=_jur,
            risks=["hold_material", "diagnostic_template_answer"],
        ),
    )

NEW_EVIDENCE_PROPOSALS = [
    {
        "proposal_id": "housing-act-1988-s5",
        "case_id": LAND_LAW_D05,
        "claim_id": f"{LAND_LAW_D05}:continuation-on-sale",
        "exact_missing_legal_proposition": (
            "A periodic assured tenancy does not end merely because the landlord sells the dwelling."
        ),
        "official_source_title": "Housing Act 1988",
        "official_identifier": "ukpga/1988/50",
        "exact_locator": "section 5",
        "official_source_location": "https://www.legislation.gov.uk/ukpga/1988/50/section/5",
        "why_required": "The packet quotes off-issue LPA s52 / CPR 55.11 text for a private tenancy continuation question.",
        "changes_proposed_answer": True,
        "attached": False,
        "create_only_proposal": True,
    },
    {
        "proposal_id": "lra-2002-sch-4",
        "case_id": "land-law:cp-d11",
        "claim_id": "land-law:cp-d11:alteration",
        "exact_missing_legal_proposition": "The register may be altered where there is a mistake, including fraud.",
        "official_source_title": "Land Registration Act 2002",
        "official_identifier": "ukpga/2002/9",
        "exact_locator": "schedule 4",
        "official_source_location": "https://www.legislation.gov.uk/ukpga/2002/9/schedule/4",
        "why_required": "LPA 1925 s101 power of sale is the wrong route for a fraudulently registered mortgage.",
        "changes_proposed_answer": True,
        "attached": False,
        "create_only_proposal": True,
    },
    {
        "proposal_id": "ia-1986-s239",
        "case_id": "business-and-company-law:cp-d12",
        "claim_id": "business-and-company-law:cp-d12:preference",
        "exact_missing_legal_proposition": "A preference given to a connected creditor shortly before insolvency may be challenged.",
        "official_source_title": "Insolvency Act 1986",
        "official_identifier": "ukpga/1986/45",
        "exact_locator": "section 239",
        "official_source_location": "https://www.legislation.gov.uk/ukpga/1986/45/section/239",
        "why_required": "The packet attached partnership/IVA locators rather than preference/undervalue.",
        "changes_proposed_answer": True,
        "attached": False,
        "create_only_proposal": True,
    },
    {
        "proposal_id": "charities-act-2011-s62",
        "case_id": "trusts-law:cp-d07",
        "claim_id": "trusts-law:cp-d07:cy-pres",
        "exact_missing_legal_proposition": "Charity property may be applied cy-près where the original purpose cannot be carried out.",
        "official_source_title": "Charities Act 2011",
        "official_identifier": "ukpga/2011/25",
        "exact_locator": "section 62",
        "official_source_location": "https://www.legislation.gov.uk/ukpga/2011/25/section/62",
        "why_required": "Trustee Act 2000 s11 is a delegation power, not the cy-près occasion.",
        "changes_proposed_answer": True,
        "attached": False,
        "create_only_proposal": True,
    },
    {
        "proposal_id": "defamation-act-2013",
        "case_id": "tort-law:cp-d18",
        "claim_id": "tort-law:cp-d18:false-accusation",
        "exact_missing_legal_proposition": "Publication of a false accusation may engage defamation and related privacy/harassment routes.",
        "official_source_title": "Defamation Act 2013",
        "official_identifier": "ukpga/2013/26",
        "exact_locator": "section 1",
        "official_source_location": "https://www.legislation.gov.uk/ukpga/2013/26/section/1",
        "why_required": "Khan v Meadows is not a supporting authority for a website spreading an address and accusation.",
        "changes_proposed_answer": True,
        "attached": False,
        "create_only_proposal": True,
    },
    {
        "proposal_id": "uk-gdpr-art-15",
        "case_id": "contemporary-biolaw-and-regulation:cp-d03",
        "claim_id": "contemporary-biolaw-and-regulation:cp-d03:access-to-logic",
        "exact_missing_legal_proposition": "A data subject may request access to personal data and information about processing.",
        "official_source_title": "UK GDPR",
        "official_identifier": "UK GDPR",
        "exact_locator": "article 15",
        "official_source_location": "https://www.legislation.gov.uk/eur/2016/679/article/15",
        "why_required": "HFEA definitions and MDR 44ZC do not answer a DNA-service explanation request.",
        "changes_proposed_answer": True,
        "attached": False,
        "create_only_proposal": True,
    },
]
