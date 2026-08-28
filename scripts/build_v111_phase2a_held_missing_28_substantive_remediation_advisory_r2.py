#!/usr/bin/env python3
"""Build the immutable r2 corrective advisory for the exact held/missing 28 cohort.

R1 is an input only and is expressly superseded as NO-GO.  This builder never
turns a missing source into exclusion proof: unresolved legal propositions are
retained as qualification blockers.  Only six exact nonlegal/meta components
are proposed for exclusion.  The artifact is create-only and cannot apply a
decision, admit/materialize a source, scan, build, embed, retrieve, qualify,
invoke a model, write a pointer, or start Phase 2B.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts import (  # noqa: E402
    build_v111_phase2a_held_missing_28_substantive_remediation_advisory as r1_builder,
)

REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"

R1_ROOT = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-held-missing-28-substantive-remediation-advisory-r1"
)
R1_ADVISORY_PATH = R1_ROOT / r1_builder.ADVISORY_NAME
R1_SOURCE_MANIFEST_PATH = R1_ROOT / r1_builder.SOURCE_MANIFEST_NAME
R1_PACKAGE_PATH = R1_ROOT / r1_builder.PACKAGE_NAME

R1_ADVISORY_FILE_SHA256 = "971bb4390e3284ab37172246de729ab68718faba33d5add7cfd725e503058534"
R1_ADVISORY_CONTENT_SHA256 = "2bfd1baec0603f03140dd2aaa44437d2c9bfc9ef0e585bbe9ff5fcc1e322f53f"
R1_SOURCE_MANIFEST_FILE_SHA256 = (
    "3b573ba336776e6b625114694518a2ed815f9dda391c4048f9e381fbe9623b7d"
)
R1_SOURCE_MANIFEST_CONTENT_SHA256 = (
    "42c15bb950b51ee0fcff0e11360398644fc807103e9818b0c4dbad5ffd3e5046"
)
R1_PACKAGE_FILE_SHA256 = "b9732b6baa81c63b19e2010c1e109777b44655169dc0b6ff781013725e9ab7d8"
R1_PACKAGE_CONTENT_SHA256 = "944be291003776b5e9b95cca308cb731b7e84e685c46742f0a26d2837c8fb995"

R2_SOURCE_QUARANTINE_ROOT = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-held-missing-28-r2-source-quarantine-r1"
)
CJIA_2008_SECTION_76_PATH = R2_SOURCE_QUARANTINE_ROOT / (
    "cjia-2008-section-76-2026-08-14.xml"
)
CJIA_2008_SECTION_76_SHA256 = (
    "093c795ecb3912333eadc4e1d11e2b7deaa3e500ff56371372397ff06e4acf71"
)
CRIMINAL_LAW_ACT_1967_PATH = PROJECT_ROOT / (
    "sources/phase2a-approved-2026-08-27/Official Legislation/"
    "002-ukpga-1967-58-191cdb8510792ff0.xml"
)
CRIMINAL_LAW_ACT_1967_SHA256 = (
    "191cdb8510792ff065606830c2fd7371e8b9df1c341f1dbaed7db147d9cebce1"
)

OUTPUT_ROOT = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-held-missing-28-substantive-remediation-advisory-r2"
)
ADVISORY_NAME = "EXACT-28-ROW-SUBSTANTIVE-REMEDIATION-ADVISORY-R2.json"
SOURCE_MANIFEST_NAME = "NINE-PROPOSED-REPRESENTATION-BINDINGS-R2.json"
R1_NO_GO_NAME = "R1-SUBSTANTIVE-AUDIT-NO-GO.json"
PACKAGE_NAME = "PACKAGE-MANIFEST.json"
CHECKSUMS_NAME = "SHA256SUMS.txt"

NO_EXECUTION = r1_builder.NO_EXECUTION
STANDARD_NO_EXECUTION_FLAGS = r1_builder.STANDARD_NO_EXECUTION_FLAGS


def _key(row_id: str, ordinal: int) -> str:
    return f"{row_id}#{ordinal}"


FULL_REUSE_KEYS = {
    _key("live30-q01:issue-01", 1),
    _key("live30-q01:issue-01", 2),
    _key("live30-q05:issue-07", 1),
    _key("live60-q32:issue-04", 1),
    _key("live60-q32:issue-04", 2),
    _key("live60-q46:issue-05", 1),
    _key("live60-q46:issue-05", 2),
    _key("live60-q50:issue-06", 5),
    _key("live60-q59:issue-15", 2),
    _key("live60-q59:issue-17", 3),
}
NEW_FULL_KEYS = {_key("live30-q04:issue-07", 1)}
PARTIAL_KEYS = {
    _key("live30-q04:issue-07", 4),
    _key("live30-q19:issue-01", 1),
    _key("live30-q20:issue-08", 1),
    _key("live30-q28:issue-05", 4),
    _key("live60-q37:issue-06", 1),
    _key("live60-q40:issue-09", 1),
}

RETAIN_REASONS = {
    _key("live30-q01:issue-03", 3): (
        "Waiver is a live legal route distinct from affirmation.  The located election material does "
        "not proposition-completely establish waiver of strict compliance, so r1's exclusion is reversed."
    ),
    _key("live30-q05:issue-06", 2): (
        "Perry supports valuation contingencies but not every avoided-cost, costs-risk or settlement "
        "deduction in this composite.  The unsupported deductions remain operative rather than excluded."
    ),
    _key("live30-q13:issue-04", 3): (
        "The conflict rule is legally material, but authorisation, profit, loss and remedy cannot be "
        "collapsed into the already supported no-conflict components."
    ),
    _key("live30-q13:issue-08", 1): (
        "Tracing and proprietary relief are live legal routes.  Menelaou does not by itself complete the "
        "mixed-account, proprietary-versus-personal proposition and missing completeness is not exclusion proof."
    ),
    _key("live30-q13:issue-08", 4): (
        "Dishonest assistance is distinct from knowing receipt and remains legally material.  The located "
        "sources do not proposition-completely bind every element of this component."
    ),
    _key("live30-q19:issue-03", 2): (
        "Competition Act tying and self-preferencing remain live section 18 legal routes.  Fact-specificity "
        "prevents a per-se conclusion but is not a valid basis to exclude the route."
    ),
    _key("live30-q19:issue-04", 2): (
        "Discriminatory or exclusive access remains a live section 18 route.  Dominance, abuse and competitive "
        "disadvantage are unresolved elements, not exclusion proof."
    ),
    _key("live30-q24:issue-01", 2): (
        "The contractual reasonable-care-and-skill route remains legally distinct from SRA discipline and "
        "cannot be removed merely because its factual application is incomplete."
    ),
    _key("live30-q24:issue-08", 3): (
        "The solicitor-client costs-assessment route remains legally available in principle.  No exact "
        "Solicitors Act/CPR composite span presently completes this component."
    ),
    _key("live30-q30:issue-07", 2): (
        "Interim judicial-review relief is a live legal route.  Its merits, urgency, notice and undertakings "
        "test is not supplied by final-remedy provisions and remains unsupported."
    ),
    _key("live30-q30:issue-10", 5): (
        "Part 36 and interim-relief consequences are live procedural law.  A universal tactical preference "
        "would be false, but the exact legal frameworks cannot be excluded."
    ),
    _key("live30-q30:issue-16", 4): (
        "Trade-secret and confidence causes of action remain live.  Missing secrecy, acquisition/use and "
        "disclosure facts prevent application but do not make the legal route out of scope."
    ),
    _key("live30-q30:issue-18", 5): (
        "Preservation, disclosure, sanctions and evidential consequences are live procedural routes.  The "
        "composite needs exact PD57AD/CPR propositions and cannot be excluded for incomplete evidence."
    ),
    _key("live60-q32:issue-04", 3): (
        "Identification of an unnamed member of a criticised group is a live defamation issue.  The absence "
        "of a proposition-complete official representation requires retention, not exclusion."
    ),
    _key("live60-q42:issue-03", 3): (
        "Aabar identifies the corporate client and authorised communicators but does not establish ownership "
        "or actual authority to waive privilege.  The waiver proposition remains operative."
    ),
    _key("live60-q42:issue-08", 3): (
        "Common-interest and shareholder-privilege questions remain legal issues.  Source role, doctrine and "
        "relationship-specific application remain incomplete and r1's exclusion is reversed."
    ),
    _key("live60-q59:issue-14", 3): (
        "Security for costs and non-party costs against funders are live route-specific powers.  Their "
        "conditions and discretion cannot be removed because the actual funding facts are missing."
    ),
    _key("live60-q59:issue-14", 4): (
        "Funder control and disclosure are live route-specific legal questions.  No universal rule was proved, "
        "so the component remains held rather than being treated as nonlegal."
    ),
}

EXCLUSION_PROOFS = {
    _key("live30-q05:issue-07", 2): {
        "classification": "MATTER_APPLICATION_AND_PROFESSIONAL_STANDARD_META_COMPONENT",
        "proof": "The exact component asks whether manual verification was required on unidentified facts and an unsealed professional standard; it supplies no freestanding positive rule beyond the retained SRA competence/supervision proposition.",
        "coverage": "The row's exact SRA paragraphs 3.2, 3.3 and 3.5 proposition remains; risk, workflow, oversight and verification evidence must be requested before any application conclusion.",
    },
    _key("live30-q30:issue-07", 6): {
        "classification": "EXACT_FALSE_UNIVERSAL_REMEDY_META_COMPONENT",
        "proof": "The component itself denies a universal remedy and is a cross-route synthesis instruction, not a separately sourceable positive rule.",
        "coverage": "Cause-specific retained FULL remedy components remain authoritative; output is prohibited from asserting a universal remedy or duplicate recovery.",
    },
    _key("live30-q30:issue-10", 1): {
        "classification": "LITIGATION_STRATEGY_APPLICATION_COMPONENT",
        "proof": "Ranking claims by objectives, cost, evidence, solvency and recoverability is professional strategy rather than an atomic legal proposition.",
        "coverage": "The row retains its exact procedural, ADR and limitation rules; claimant objectives and litigation facts must be supplied for strategy.",
    },
    _key("live60-q46:issue-05", 3): {
        "classification": "MATTER_INFORMATION_GAP_APPLICATION_COMPONENT",
        "proof": "The component expressly cannot identify minimum disclosure without the detector, procedure and safeguards; it is an information-dependent application decision.",
        "coverage": "The exact Osborn fairness principle and regulation 10 confidentiality safeguards remain; the system must request the missing procedure, detector evidence and safeguards.",
    },
    _key("live60-q59:issue-15", 3): {
        "classification": "UNIDENTIFIED_PRODUCT_AND_MARKET_FACT_COMPONENT",
        "proof": "Availability, price, insurer rating, exclusions and limits of an unidentified ATE product are contractual and market facts, not a sourceable legal rule.",
        "coverage": "The exact Infinity security framework remains; the actual policy, deed, insurer, exclusions and limits must be requested.",
    },
    _key("live60-q59:issue-17", 4): {
        "classification": "UNIDENTIFIED_PROCEDURAL_VEHICLE_APPLICATION_COMPONENT",
        "proof": "Selecting distribution terms across unidentified representative, GLO and regulatory routes is an application decision, and the component states no universal rule.",
        "coverage": "The row retains exact CAT aggregate-damages/collective-settlement components and AXA only for GLO mechanics; distribution must follow the identified vehicle and order.",
    },
}

INVALID_R1_EXCLUSIONS = {
    _key("live30-q01:issue-03", 3),
    _key("live30-q04:issue-07", 1),
    _key("live30-q13:issue-08", 1),
    _key("live30-q13:issue-08", 4),
    _key("live30-q19:issue-03", 2),
    _key("live30-q19:issue-04", 2),
    _key("live30-q24:issue-01", 2),
    _key("live30-q24:issue-08", 3),
    _key("live30-q30:issue-07", 2),
    _key("live30-q30:issue-10", 5),
    _key("live30-q30:issue-16", 4),
    _key("live30-q30:issue-18", 5),
    _key("live60-q32:issue-04", 3),
    _key("live60-q42:issue-08", 3),
    _key("live60-q59:issue-14", 3),
}
PROVE_OR_REVERSE = {
    _key("live30-q05:issue-06", 2),
    _key("live30-q13:issue-04", 3),
    _key("live60-q59:issue-14", 4),
}

PARTIAL_RESIDUALS = {
    _key("live30-q04:issue-07", 4): "The rule that duress is unavailable to murder or attempted murder remains unsupported by locally bound primary official bytes; Johnson paragraphs 49-50 cannot supply it.",
    _key("live30-q19:issue-01", 1): "Section 18 supplies the statutory dominance/abuse gateway but not a complete product-and-geographic market-definition methodology.",
    _key("live30-q20:issue-08", 1): "Montgomery supplies material-risk and reasonable-alternative disclosure only; diagnosis, professional practice and AI governance remain unsupported.",
    _key("live30-q28:issue-05", 4): "Waller-Edwards supplies lender-on-inquiry mechanics only; it does not establish actual or presumed undue influence or any benchmark fact.",
    _key("live60-q37:issue-06", 1): "SI 2024/234 corrects the instrument identity but exact provision-level disclosure, capital-protection, distribution, commencement and effects propositions remain unsupported.",
    _key("live60-q40:issue-09", 1): "Senior Courts Act 1981 section 31(4) supplies only the damages condition; interim relief and the remaining discretionary/final-remedy rules require their own exact sources.",
}


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _content_sha(value: dict[str, Any], field: str) -> str:
    material = dict(value)
    material.pop(field, None)
    return _sha256(r1_builder._canonical_json(material))


def _load_r1() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    advisory = r1_builder._load(R1_ADVISORY_PATH, R1_ADVISORY_FILE_SHA256)
    manifest = r1_builder._load(R1_SOURCE_MANIFEST_PATH, R1_SOURCE_MANIFEST_FILE_SHA256)
    package = r1_builder._load(R1_PACKAGE_PATH, R1_PACKAGE_FILE_SHA256)
    r1_builder._verify_content(
        advisory, "artifact_content_sha256", R1_ADVISORY_CONTENT_SHA256
    )
    r1_builder._verify_content(
        manifest, "artifact_content_sha256", R1_SOURCE_MANIFEST_CONTENT_SHA256
    )
    r1_builder._verify_content(package, "package_content_sha256", R1_PACKAGE_CONTENT_SHA256)
    package_by_name = {item["name"]: item for item in package["artifacts"]}
    if package_by_name[r1_builder.ADVISORY_NAME]["file_sha256"] != R1_ADVISORY_FILE_SHA256:
        raise ValueError("r1_package_advisory_binding_invalid")
    if (
        package_by_name[r1_builder.SOURCE_MANIFEST_NAME]["file_sha256"]
        != R1_SOURCE_MANIFEST_FILE_SHA256
    ):
        raise ValueError("r1_package_source_manifest_binding_invalid")
    return advisory, manifest, package


def _validate_source_binding(binding: dict[str, Any]) -> None:
    path = r1_builder._binding_path(binding)
    if path.is_symlink() or _file_sha256(path) != binding["representation_file_sha256"]:
        raise ValueError(f"source_binding_byte_mismatch:{binding['authority_identity_id']}")
    text, mode = r1_builder._representation_text(binding)
    if _sha256(text.encode()) != binding["normalized_representation_text_sha256"]:
        raise ValueError(f"source_binding_text_mismatch:{binding['authority_identity_id']}")
    if mode != binding["representation_text_extraction_mode"]:
        raise ValueError(f"source_binding_extraction_mismatch:{binding['authority_identity_id']}")


def _freeze_span(span: dict[str, Any]) -> dict[str, Any]:
    material = dict(span)
    material.pop("span_proposal_content_sha256", None)
    material.update(
        {
            "schema": "legalbot.v111.phase2a.held-missing-28-evidence-span-proposal.r2.v1",
            "supersedes_r1_span_proposal_content_sha256": span[
                "span_proposal_content_sha256"
            ],
            "frozen_exact_span_for_owner_decision": True,
            "frozen_for_execution": False,
        }
    )
    return r1_builder._seal(material, "span_proposal_content_sha256")


def _make_binding(
    *,
    identity: str,
    path: Path,
    expected_sha: str,
    source_origin: str,
    official_url: str,
    assessment: dict[str, str],
    source_admission_recommended: bool,
    source_version_id: str | None = None,
) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or _file_sha256(path) != expected_sha:
        raise ValueError(f"new_source_byte_mismatch:{identity}")
    member = path.relative_to(PROJECT_ROOT).as_posix()
    seed = {
        "authority_identity_id": identity,
        "root_alias": "PROJECT_ROOT",
        "representation_member": member,
        "representation_file_sha256": expected_sha,
    }
    text, mode = r1_builder._representation_text(seed)
    return r1_builder._seal(
        {
            "schema": "legalbot.v111.phase2a.held-missing-28-source-binding.r2.v1",
            **seed,
            "source_origin": source_origin,
            "media_type": "application/xml",
            "official_url": official_url,
            "source_version_id": source_version_id,
            "normalized_representation_text_sha256": _sha256(text.encode()),
            "representation_text_extraction_mode": mode,
            "primary_official_bytes_bound": True,
            "legal_assessment_recommendation": assessment,
            "assessment_owner_adoption_required": True,
            "assessment_owner_adopted": False,
            "qualification_scope": "EXACT_DATED_OFFICIAL_SNAPSHOT_PROPOSITION_ONLY",
            "source_admission_recommended": source_admission_recommended,
            "source_admitted": False,
            "answer_release_eligible": False,
        },
        "record_content_sha256",
    )


def _make_span(
    *,
    ordinal: int,
    binding: dict[str, Any],
    locators: list[str],
    excerpts: list[str],
    locator_basis: str,
) -> dict[str, Any]:
    _validate_source_binding(binding)
    text, _ = r1_builder._representation_text(binding)
    excerpt_records = []
    for excerpt in excerpts:
        normalized = r1_builder._normalise_evidence_text(excerpt)
        if normalized not in text:
            raise ValueError(
                f"new_span_excerpt_missing:{binding['authority_identity_id']}:"
                f"{_sha256(normalized.encode())}"
            )
        excerpt_records.append(
            {
                "text": excerpt,
                "normalized_text_sha256": _sha256(normalized.encode()),
                "verified_in_primary_official_bytes": True,
            }
        )
    assessment = binding["legal_assessment_recommendation"]
    return r1_builder._seal(
        {
            "schema": "legalbot.v111.phase2a.held-missing-28-evidence-span-proposal.r2.v1",
            "span_ordinal": ordinal,
            "authority_identity_id": binding["authority_identity_id"],
            "source_binding_content_sha256": binding["record_content_sha256"],
            "exact_locators": locators,
            "locator_verification_basis": locator_basis,
            "locator_verified_in_primary_official_bytes": True,
            "primary_official_bytes_bound": True,
            "supporting_excerpts": excerpt_records,
            "normalization": "UNICODE_NFKC_HTML_UNESCAPE_COLLAPSE_WHITESPACE",
            "normalized_representation_text_sha256": binding[
                "normalized_representation_text_sha256"
            ],
            "jurisdiction": assessment["jurisdiction"],
            "source_role": assessment["source_role"],
            "currentness_finding": assessment["currentness_finding"],
            "later_treatment_finding": assessment["later_treatment_finding"],
            "owner_adoption_required": True,
            "owner_adopted": False,
            "proposal_payload_immutable": True,
            "frozen_exact_span_for_owner_decision": True,
            "frozen_for_execution": False,
        },
        "span_proposal_content_sha256",
    )


def _reseal_recommendation(
    r1_recommendation: dict[str, Any],
    **updates: Any,
) -> dict[str, Any]:
    material = dict(r1_recommendation)
    material.pop("recommendation_content_sha256", None)
    material.update(
        {
            "schema": "legalbot.v111.phase2a.held-missing-28-blocker-recommendation.r2.v1",
            "supersedes_r1_recommendation_content_sha256": r1_recommendation[
                "recommendation_content_sha256"
            ],
            **updates,
        }
    )
    return r1_builder._seal(material, "recommendation_content_sha256")


def _full_reuse(r1_recommendation: dict[str, Any]) -> dict[str, Any]:
    return _reseal_recommendation(
        r1_recommendation,
        action="REPLACE_WITH_EXACT_NARROW_SOURCE_BOUND_PROPOSITION",
        evidence_span_proposals=[
            _freeze_span(span) for span in r1_recommendation["evidence_span_proposals"]
        ],
        r2_disposition="PROPOSED_FULL_FOR_EXACT_NARROW_PROPOSITION",
        clears_exact_original_blocker_if_owner_adopted=True,
        residual_qualification_blocker=False,
        missing_source_is_exclusion_proof=False,
    )


def _new_self_defence(
    r1_recommendation: dict[str, Any],
    bindings: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    proposition = (
        "Criminal Law Act 1967 section 3(1)-(2) permits reasonable force only for "
        "preventing crime or effecting or assisting lawful arrest and replaces the common-law rules "
        "only for those purposes. Criminal Justice and Immigration Act 2008 section 76(1), "
        "(3)-(5) and (6A)-(9) separately records that common-law self-defence force is judged by the "
        "circumstances D genuinely believed, even where a mistake was unreasonable, while the degree "
        "of force must be reasonable. No defence or factual outcome is inferred."
    )
    spans = [
        _make_span(
            ordinal=1,
            binding=bindings["ukpga:1967:58"],
            locators=["section 3(1)-(2)"],
            excerpts=[
                "A person may use such force as is reasonable in the circumstances in the prevention of crime, or in effecting or assisting in the lawful arrest",
                "Subsection (1) above shall replace the rules of the common law on the question when force used for a purpose mentioned in the subsection is justified by that purpose.",
            ],
            locator_basis="OFFICIAL_XML_SECTION_3_STRUCTURE_AND_EXACT_TEXT",
        ),
        _make_span(
            ordinal=2,
            binding=bindings["ukpga:2008:4"],
            locators=["section 76(1)", "section 76(3)-(5)", "section 76(6A)-(9)"],
            excerpts=[
                "The question whether the degree of force used by D was reasonable in the circumstances is to be decided by reference to the circumstances as D believed them to be",
                "if it is determined that D did genuinely hold it, D is entitled to rely on it",
            ],
            locator_basis="OFFICIAL_XML_SECTION_76_SUBSECTION_STRUCTURE_AND_EXACT_TEXT",
        ),
    ]
    return _reseal_recommendation(
        r1_recommendation,
        action="REPLACE_WITH_EXACT_NARROW_SOURCE_BOUND_PROPOSITION",
        after_propositions=[
            {
                "proposition": proposition,
                "proposition_text_sha256": _sha256(proposition.encode()),
                "proposed_support_scope": "FULL_FOR_EXACT_DATED_OFFICIAL_STATUTORY_PROPOSITION_IF_OWNER_ADOPTED",
                "current_law_answer_release_eligible": False,
            }
        ],
        evidence_span_proposals=spans,
        excluded_scope="Any factual finding that force was used, that either statutory/common-law route applies, or that the believed circumstances or force were reasonable.",
        reason="Split and source the distinct prevention-of-crime and common-law self-defence routes; correct the Act title to Criminal Law Act 1967.",
        issue_coverage=None,
        r2_disposition="PROPOSED_FULL_FOR_EXACT_NARROW_PROPOSITION",
        clears_exact_original_blocker_if_owner_adopted=True,
        residual_qualification_blocker=False,
        missing_source_is_exclusion_proof=False,
    )


def _partial_recommendation(
    key: str,
    r1_recommendation: dict[str, Any],
    r1_bindings: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    after_propositions = list(r1_recommendation["after_propositions"])
    spans = [_freeze_span(span) for span in r1_recommendation["evidence_span_proposals"]]
    excluded_scope = r1_recommendation["excluded_scope"]
    reason = r1_recommendation["reason"]

    if key == _key("live30-q04:issue-07", 4):
        proposition = (
            "R v Johnson [2022] EWCA Crim 832 at paragraphs 49-50 states the Hasan "
            "immediacy/evasion/objective-person framework for duress. Those paragraphs do not state "
            "the separate rule that duress is unavailable to murder or attempted murder, so that "
            "limitation is not proposed from Johnson."
        )
        after_propositions = [
            {
                "proposition": proposition,
                "proposition_text_sha256": _sha256(proposition.encode()),
                "proposed_support_scope": "FULL_ONLY_FOR_JOHNSON_PARAGRAPHS_49_TO_50_FRAMEWORK",
                "current_law_answer_release_eligible": False,
            }
        ]
        excluded_scope = "Any no-duress-for-murder/attempted-murder rule, benchmark threat/evasion finding, or application outcome."
        reason = "Johnson is retained only for what paragraphs 49-50 actually state; it cannot imply the separate homicide limitation."
    elif key == _key("live30-q28:issue-05", 4):
        proposition = (
            "Waller-Edwards v One Savings Bank Plc [2025] UKSC 22 at paragraphs 1-6, "
            "25-40, 46-49 and 52-58 addresses when a lender is put on inquiry in a non-commercial "
            "surety or hybrid transaction. It does not establish the underlying actual or presumed "
            "undue influence, transaction, occupation, priority or notice facts in this row."
        )
        after_propositions = [
            {
                "proposition": proposition,
                "proposition_text_sha256": _sha256(proposition.encode()),
                "proposed_support_scope": "FULL_ONLY_FOR_WALLER_EDWARDS_LENDER_ON_INQUIRY_HOLDING",
                "current_law_answer_release_eligible": False,
            }
        ]
        reason = "Use Waller-Edwards only for the lender-on-inquiry holding and retain the underlying undue-influence/fact proposition."
    elif key == _key("live60-q37:issue-06", 1):
        proposition = (
            "SI 2024/234, regulation 1, is the Limited Liability Partnerships (Application "
            "of Company Law) Regulations 2024, and regulation 5(1) states that the 2009 Regulations "
            "are amended in accordance with regulations 6 to 46. This proves the corrected instrument "
            "identity only; it does not itself prove any disclosure, capital, distribution or insolvency proposition."
        )
        binding = r1_bindings["uksi:2024:234"]
        spans = [
            _make_span(
                ordinal=1,
                binding=binding,
                locators=["regulation 1", "regulation 5(1)"],
                excerpts=[
                    "These Regulations may be cited as the Limited Liability Partnerships (Application of Company Law) Regulations 2024.",
                    "The Limited Liability Partnerships (Application of Companies Act 2006) Regulations 2009 are amended in accordance with regulations 6 to 46.",
                ],
                locator_basis="OFFICIAL_XML_REGULATIONS_1_AND_5_EXACT_STRUCTURE_AND_TEXT",
            )
        ]
        after_propositions = [
            {
                "proposition": proposition,
                "proposition_text_sha256": _sha256(proposition.encode()),
                "proposed_support_scope": "FULL_ONLY_FOR_INSTRUMENT_IDENTITY_AND_REGULATION_5_AMENDMENT_STATEMENT",
                "current_law_answer_release_eligible": False,
            }
        ]
        excluded_scope = "SI 2024/1377 and every disclosure, filing, capital-protection, distribution, commencement, extent/effects or insolvency conclusion not bound to an exact provision."
        reason = "Ban whole-Part and unparticularised regulation-range locators; bind only regulations 1 and 5(1), leaving the substantive LLP duties held."
    elif key == _key("live60-q40:issue-09", 1):
        proposition = (
            "Senior Courts Act 1981 section 31(4) permits damages, restitution or recovery of "
            "a sum on a judicial-review application only where the application includes that claim and "
            "the court is satisfied the award would have been made in an action begun at that time. "
            "It does not supply an interim-relief test or the row's remaining discretionary-remedy propositions."
        )
        binding = r1_bindings["ukpga:1981:54"]
        spans = [
            _make_span(
                ordinal=1,
                binding=binding,
                locators=["section 31(4)(a)-(b)"],
                excerpts=[
                    "On an application for judicial review the High Court may award to the applicant damages, restitution or the recovery of a sum due if",
                    "the court is satisfied that such an award would have been made if the claim had been made in an action begun by the applicant at the time of making the application.",
                ],
                locator_basis="OFFICIAL_XML_SECTION_31_SUBSECTION_4_EXACT_STRUCTURE_AND_TEXT",
            )
        ]
        after_propositions = [
            {
                "proposition": proposition,
                "proposition_text_sha256": _sha256(proposition.encode()),
                "proposed_support_scope": "FULL_ONLY_FOR_SECTION_31_4_DAMAGES_CONDITION",
                "current_law_answer_release_eligible": False,
            }
        ]
        excluded_scope = "Interim relief, declarations/injunctions, suspended/prospective quashing, highly-likely outcome, delay/prejudice and all application facts."
        reason = "Bind damages exactly to section 31(4); retain rather than infer interim and other discretionary rules."

    return _reseal_recommendation(
        r1_recommendation,
        action="REPLACE_WITH_EXACT_SOURCE_BOUND_PROPOSITION_AND_RETAIN_RESIDUAL",
        after_propositions=after_propositions,
        evidence_span_proposals=spans,
        excluded_scope=excluded_scope,
        reason=reason,
        issue_coverage=None,
        r2_disposition="PROPOSED_NARROW_SUBPROPOSITION_WITH_OPERATIVE_RESIDUAL",
        clears_exact_original_blocker_if_owner_adopted=False,
        residual_qualification_blocker=True,
        residual_scope=PARTIAL_RESIDUALS[key],
        missing_source_is_exclusion_proof=False,
    )


def _retain(key: str, r1_recommendation: dict[str, Any]) -> dict[str, Any]:
    return _reseal_recommendation(
        r1_recommendation,
        action="RETAIN_OPERATIVE_LEGAL_ROUTE_BLOCKER",
        after_propositions=[],
        evidence_span_proposals=[],
        excluded_scope="NONE; THE EXACT LEGAL ROUTE REMAINS OPERATIVE",
        reason=RETAIN_REASONS[key],
        issue_coverage=None,
        r2_disposition="RESIDUAL_BLOCKED_RETAIN",
        clears_exact_original_blocker_if_owner_adopted=False,
        residual_qualification_blocker=True,
        residual_scope=r1_recommendation["baseline_proposition"],
        missing_source_is_exclusion_proof=False,
    )


def _exclude(key: str, r1_recommendation: dict[str, Any]) -> dict[str, Any]:
    proof = EXCLUSION_PROOFS[key]
    return _reseal_recommendation(
        r1_recommendation,
        action="EXCLUDE_EXACT_NONLEGAL_OR_META_COMPONENT",
        after_propositions=[],
        evidence_span_proposals=[],
        excluded_scope="THE_EXACT_BASELINE_COMPONENT_ONLY; NO LEGAL ROUTE IS EXCLUDED",
        reason=proof["proof"],
        issue_coverage=proof["coverage"],
        r2_disposition="PROPOSED_EXCLUSION_WITH_EXACT_COVERAGE_PROOF",
        exclusion_proof_class=proof["classification"],
        exclusion_coverage_proof=proof["coverage"],
        exclusion_does_not_remove_safety_boundary=True,
        clears_exact_original_blocker_if_owner_adopted=True,
        residual_qualification_blocker=False,
        missing_source_is_exclusion_proof=False,
    )


def _build_new_source_bindings() -> dict[str, dict[str, Any]]:
    candidate = json.loads(r1_builder.CANDIDATE_MANIFEST_PATH.read_bytes())
    cla = next(
        source
        for source in candidate["sources"]
        if source["authority_identity_id"] == "ukpga:1967:58"
    )
    cla_binding = _make_binding(
        identity="ukpga:1967:58",
        path=CRIMINAL_LAW_ACT_1967_PATH,
        expected_sha=CRIMINAL_LAW_ACT_1967_SHA256,
        source_origin="SEALED_APPROVED_SOURCE_PRIMARY_OFFICIAL_REPRESENTATION",
        official_url="https://www.legislation.gov.uk/ukpga/1967/58",
        source_version_id=cla["source_version_id"],
        source_admission_recommended=False,
        assessment={
            "jurisdiction": "England and Wales for the exact section 3 route, subject to provision-level extent and application",
            "source_role": "Primary legislation; Criminal Law Act 1967 (not Criminal Justice Act 1967)",
            "currentness_finding": "Exact official revised representation already exists in the sealed candidate; provision-level currentness/extent was not fully verified and remains an answer-release hold.",
            "later_treatment_finding": "Not a judgment; amendment, extent and effects review remains an answer-release hold.",
        },
    )
    cjia_binding = _make_binding(
        identity="ukpga:2008:4",
        path=CJIA_2008_SECTION_76_PATH,
        expected_sha=CJIA_2008_SECTION_76_SHA256,
        source_origin="R2_OFFICIAL_RESEARCH_QUARANTINE_NOT_ADMITTED",
        official_url="https://www.legislation.gov.uk/ukpga/2008/4/section/76/data.xml",
        source_version_id=None,
        source_admission_recommended=True,
        assessment={
            "jurisdiction": "England and Wales and Northern Ireland only as the exact section provides; application remains fact-specific",
            "source_role": "Primary legislation clarifying common-law self-defence and related force defences",
            "currentness_finding": "Official section representation retrieved 2026-08-28 is byte-bound; extent, amendments and effects remain answer-release holds.",
            "later_treatment_finding": "Not a judgment; amendment, extent and effects review remains an answer-release hold.",
        },
    )
    return {binding["authority_identity_id"]: binding for binding in (cla_binding, cjia_binding)}


def build_advisory() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    r1_advisory, r1_manifest, _ = _load_r1()
    r3 = r1_builder._load(r1_builder.R3_PATH, r1_builder.R3_FILE_SHA256)
    r1_builder._verify_content(r3, "artifact_content_sha256", r1_builder.R3_CONTENT_SHA256)

    r1_bindings = {
        binding["authority_identity_id"]: binding for binding in r1_advisory["source_bindings"]
    }
    for binding in r1_bindings.values():
        _validate_source_binding(binding)
    new_bindings = _build_new_source_bindings()

    all_mode_keys = (
        FULL_REUSE_KEYS
        | NEW_FULL_KEYS
        | PARTIAL_KEYS
        | set(RETAIN_REASONS)
        | set(EXCLUSION_PROOFS)
    )
    expected_keys = {
        _key(rec["row_id"], rec["component_ordinal"])
        for row in r1_advisory["rows"]
        for rec in row["blocker_recommendations"]
    }
    if len(expected_keys) != 41 or all_mode_keys != expected_keys:
        raise ValueError("r2_disposition_partition_not_exact_41")
    if any(
        left & right
        for index, left in enumerate(
            [FULL_REUSE_KEYS, NEW_FULL_KEYS, PARTIAL_KEYS, set(RETAIN_REASONS), set(EXCLUSION_PROOFS)]
        )
        for right in [FULL_REUSE_KEYS, NEW_FULL_KEYS, PARTIAL_KEYS, set(RETAIN_REASONS), set(EXCLUSION_PROOFS)][index + 1 :]
    ):
        raise ValueError("r2_disposition_partition_overlaps")

    rows: list[dict[str, Any]] = []
    action_counts: Counter[str] = Counter()
    active_source_hashes: set[str] = set()
    residual_blocker_keys: list[str] = []
    for r1_row in r1_advisory["rows"]:
        recommendations = []
        row_residuals = []
        for r1_recommendation in r1_row["blocker_recommendations"]:
            key = _key(
                r1_recommendation["row_id"], r1_recommendation["component_ordinal"]
            )
            if key in FULL_REUSE_KEYS:
                recommendation = _full_reuse(r1_recommendation)
            elif key in NEW_FULL_KEYS:
                recommendation = _new_self_defence(r1_recommendation, new_bindings)
            elif key in PARTIAL_KEYS:
                recommendation = _partial_recommendation(
                    key, r1_recommendation, r1_bindings
                )
            elif key in RETAIN_REASONS:
                recommendation = _retain(key, r1_recommendation)
            else:
                recommendation = _exclude(key, r1_recommendation)
            action_counts[recommendation["action"]] += 1
            if recommendation["residual_qualification_blocker"]:
                residual_blocker_keys.append(recommendation["blocker_key"])
                row_residuals.append(recommendation["blocker_key"])
            for span in recommendation["evidence_span_proposals"]:
                active_source_hashes.add(span["source_binding_content_sha256"])
            recommendations.append(recommendation)

        material = dict(r1_row)
        material.pop("record_content_sha256", None)
        material.update(
            {
                "schema": "legalbot.v111.phase2a.held-missing-28-row-substantive-remediation.r2.v1",
                "supersedes_r1_row_record_content_sha256": r1_row[
                    "record_content_sha256"
                ],
                "blocker_recommendations": recommendations,
                "residual_qualification_blocker_predeclared": bool(row_residuals),
                "residual_blocker_keys": row_residuals,
                "qualification_effect_if_exactly_owner_adopted": (
                    "RESIDUAL_BLOCKED; DO_NOT_PREDECLARE_PHASE2A_SUCCESS"
                    if row_residuals
                    else "EXACT_R2_SUPPORT_BLOCKERS_PROPOSED_CLEARED; SUCCESSOR_ALL585_MUST_VERIFY"
                ),
                "answer_release_eligible": False,
                "owner_adopted": False,
                "applied": False,
                "technical_success_not_predeclared": True,
            }
        )
        rows.append(r1_builder._seal(material, "record_content_sha256"))

    expected_counts = {
        "REPLACE_WITH_EXACT_NARROW_SOURCE_BOUND_PROPOSITION": 11,
        "REPLACE_WITH_EXACT_SOURCE_BOUND_PROPOSITION_AND_RETAIN_RESIDUAL": 6,
        "RETAIN_OPERATIVE_LEGAL_ROUTE_BLOCKER": 18,
        "EXCLUDE_EXACT_NONLEGAL_OR_META_COMPONENT": 6,
    }
    if action_counts != expected_counts:
        raise ValueError(f"unexpected_r2_action_counts:{dict(action_counts)}")
    if len(residual_blocker_keys) != 24 or len(set(residual_blocker_keys)) != 24:
        raise ValueError("unexpected_r2_residual_blocker_count")

    all_bindings = {**r1_bindings, **new_bindings}
    active_bindings = sorted(
        (
            binding
            for binding in all_bindings.values()
            if binding["record_content_sha256"] in active_source_hashes
        ),
        key=lambda binding: binding["authority_identity_id"],
    )
    if len(active_bindings) != 19:
        raise ValueError(f"unexpected_active_source_binding_count:{len(active_bindings)}")
    if {
        binding["record_content_sha256"] for binding in active_bindings
    } != active_source_hashes:
        raise ValueError("active_source_binding_crosswalk_incomplete")

    recommendation_by_identity: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        for recommendation in row["blocker_recommendations"]:
            for span in recommendation["evidence_span_proposals"]:
                recommendation_by_identity.setdefault(
                    span["authority_identity_id"], []
                ).append(
                    {
                        "row_id": recommendation["row_id"],
                        "component_ordinal": recommendation["component_ordinal"],
                        "baseline_proposition_text_sha256": recommendation[
                            "baseline_proposition_text_sha256"
                        ],
                        "recommendation_content_sha256": recommendation[
                            "recommendation_content_sha256"
                        ],
                        "after_proposition_text_sha256s": [
                            item["proposition_text_sha256"]
                            for item in recommendation["after_propositions"]
                        ],
                        "span_proposal_content_sha256": span[
                            "span_proposal_content_sha256"
                        ],
                        "exact_locators": span["exact_locators"],
                        "source_binding_content_sha256": span[
                            "source_binding_content_sha256"
                        ],
                    }
                )

    r2_manifest_records = []
    for r1_record in r1_manifest["representations"]:
        identity = r1_record["authority_identity_id"]
        component_bindings = sorted(
            recommendation_by_identity.get(identity, []),
            key=lambda item: (item["row_id"], item["component_ordinal"]),
        )
        material = dict(r1_record)
        material.pop("record_content_sha256", None)
        material.update(
            {
                "schema": "legalbot.v111.phase2a.held-missing-nine-proposed-representation.r2.v1",
                "supersedes_r1_record_content_sha256": r1_record[
                    "record_content_sha256"
                ],
                "component_bindings": component_bindings,
                "affected_row_ids": sorted(
                    {item["row_id"] for item in component_bindings}
                ),
                "admission_recommended": bool(component_bindings),
                "not_needed_reason": (
                    None
                    if component_bindings
                    else "NO_R2_PROPOSITION_RELIES_ON_THIS_REPRESENTATION; REMOVE_ALL_LOOSE_AFFECTED_ROW_LINKS"
                ),
                "source_admitted": False,
                "materialized": False,
                "indexed": False,
                "embedded": False,
            }
        )
        r2_manifest_records.append(r1_builder._seal(material, "record_content_sha256"))

    if len(r2_manifest_records) != 9:
        raise ValueError("r2_nine_representation_count_invalid")
    by_identity = {item["authority_identity_id"]: item for item in r2_manifest_records}
    for unused_identity in {
        "neutral-citation:[2014] UKSC 58",
        "official-url:https://www.justice.gov.uk/courts/procedure-rules/civil/rules/part-46-costs-special-cases",
        "official-url:https://www.justice.gov.uk/courts/procedure-rules/civil/rules/part-57a-business-and-property-courts/practice-direction-57ad-disclosure-in-the-business-and-property-courts",
    }:
        if by_identity[unused_identity]["component_bindings"]:
            raise ValueError(f"unused_representation_has_loose_link:{unused_identity}")
    sra_identity = (
        "official-url:https://www.sra.org.uk/solicitors/standards-regulations/"
        "code-conduct-solicitors"
    )
    if [
        (item["row_id"], item["component_ordinal"])
        for item in by_identity[sra_identity]["component_bindings"]
    ] != [("live30-q05:issue-07", 1)]:
        raise ValueError("sra_component_binding_not_exact")

    source_manifest = r1_builder._seal(
        {
            "schema": "legalbot.v111.phase2a.held-missing-nine-proposed-representation-bindings.r2.v1",
            "status": "CREATE_ONLY_R2_EXACT_COMPONENT_BINDINGS_NOT_ADMITTED_NOT_MATERIALIZED",
            "supersedes_r1_manifest_content_sha256": R1_SOURCE_MANIFEST_CONTENT_SHA256,
            "representation_count": 9,
            "admission_recommended_representation_count": sum(
                record["admission_recommended"] for record in r2_manifest_records
            ),
            "representations": r2_manifest_records,
            "additional_q04_official_representation": {
                "authority_identity_id": "ukpga:2008:4",
                "source_binding_content_sha256": new_bindings["ukpga:2008:4"][
                    "record_content_sha256"
                ],
                "representation_file_sha256": CJIA_2008_SECTION_76_SHA256,
                "component_binding": recommendation_by_identity["ukpga:2008:4"][0],
                "source_admission_recommended": True,
                "source_admitted": False,
                "materialized": False,
                "indexed": False,
                "embedded": False,
            },
            "identity_correction": {
                "row_id": "live60-q37:issue-06",
                "accepted_identity_id": "uksi:2024:234",
                "accepted_exact_locators": ["regulation 1", "regulation 5(1)"],
                "rejected_identity_id": "uksi:2024:1377",
                "rejected_mapping": True,
                "whole_part_or_regulations_6_to_46_locator_banned": True,
                "substantive_effects_residual_retained": True,
                "owner_adoption_required": True,
            },
            "recursive_no_execution_control": r1_builder._recursive_no_execution_control(),
            **NO_EXECUTION,
        }
    )

    residual_rows = [row["row_id"] for row in rows if row["residual_blocker_keys"]]
    advisory = r1_builder._seal(
        {
            "schema": "legalbot.v111.phase2a.held-missing-28-substantive-remediation-advisory.r2.v1",
            "status": "CREATE_ONLY_CORRECTIVE_ADVISORY_WITH_HONEST_RESIDUALS_NOT_ADOPTED",
            "phase_scope": "PHASE2A_ONLY",
            "advisory_date": "2026-08-28",
            "r1_status": "NO_GO_NEVER_ADOPT_NEVER_CONSOLIDATE",
            "input_bindings": {
                "r1_advisory_content_sha256": R1_ADVISORY_CONTENT_SHA256,
                "r1_source_manifest_content_sha256": R1_SOURCE_MANIFEST_CONTENT_SHA256,
                "r1_package_content_sha256": R1_PACKAGE_CONTENT_SHA256,
                "r3_report_content_sha256": r1_builder.R3_CONTENT_SHA256,
                "baseline_held_missing_r2_content_sha256": r1_builder.BASELINE_ADVISORY_CONTENT_SHA256,
                "owner_packet_content_sha256": r1_builder.OWNER_PACKET_CONTENT_SHA256,
                "execution_authority_content_sha256": r1_builder.EXECUTION_AUTHORITY_CONTENT_SHA256,
            },
            "counts": {
                "row_count": 28,
                "original_blocker_count": 41,
                "proposed_full_source_bound_count": 11,
                "partial_source_bound_with_residual_count": 6,
                "retained_operative_legal_route_count": 18,
                "exact_nonlegal_or_meta_exclusion_count": 6,
                "residual_blocker_count": 24,
                "residual_row_count": len(residual_rows),
                "active_source_binding_count": len(active_bindings),
                "nine_proposed_representation_count": 9,
                "action_counts": dict(sorted(action_counts.items())),
            },
            "exact_invalid_r1_exclusion_partition": sorted(INVALID_R1_EXCLUSIONS),
            "exact_prove_or_reverse_partition": sorted(PROVE_OR_REVERSE),
            "exact_permitted_nonlegal_or_meta_exclusion_partition": sorted(
                EXCLUSION_PROOFS
            ),
            "residual_blocker_keys": sorted(residual_blocker_keys),
            "residual_row_ids": residual_rows,
            "legal_accuracy_contract": {
                "missing_source_is_never_exclusion_proof": True,
                "only_exact_false_duplicate_or_nonlegal_meta_components_may_be_excluded": True,
                "criminal_law_act_1967_title_corrected": True,
                "johnson_49_50_not_used_for_murder_or_attempted_murder_duress_limitation": True,
                "section_18_not_used_as_complete_market_definition_methodology": True,
                "montgomery_not_used_as_whole_ai_governance_answer": True,
                "waller_edwards_not_used_for_underlying_actual_or_presumed_undue_influence": True,
                "aabar_not_used_for_privilege_ownership_or_actual_authority_waiver": True,
                "axa_not_used_for_damages_distribution": True,
                "q50_narrow_aig_various_eateries_wording_dependent_pass_preserved": True,
                "answer_release_holds_remain_distinct_from_qualification_residuals": True,
                "technical_success_not_predeclared": True,
            },
            "source_bindings": active_bindings,
            "rows": rows,
            "decision_boundary": {
                "owner_must_adopt_exact_future_consolidated_digest": True,
                "residual_blockers_must_be_resolved_or_explicitly_handled_by_the_qualification_contract": True,
                "one_existing_execution_chain_not_consumed": True,
                "no_second_chain_created": True,
                "all585_must_recompute_after_any_future_adoption": True,
            },
            "recursive_no_execution_control": r1_builder._recursive_no_execution_control(),
            **NO_EXECUTION,
        }
    )

    no_go = r1_builder._seal(
        {
            "schema": "legalbot.v111.phase2a.held-missing-28-r1-substantive-audit-no-go.v1",
            "status": "R1_NO_GO_NEVER_ADOPT_NEVER_CONSOLIDATE",
            "r1_advisory_file_sha256": R1_ADVISORY_FILE_SHA256,
            "r1_advisory_content_sha256": R1_ADVISORY_CONTENT_SHA256,
            "r1_source_manifest_file_sha256": R1_SOURCE_MANIFEST_FILE_SHA256,
            "r1_source_manifest_content_sha256": R1_SOURCE_MANIFEST_CONTENT_SHA256,
            "r1_package_file_sha256": R1_PACKAGE_FILE_SHA256,
            "r1_package_content_sha256": R1_PACKAGE_CONTENT_SHA256,
            "independent_audit_findings": {
                "invalid_legal_route_exclusion_count": len(INVALID_R1_EXCLUSIONS),
                "prove_or_reverse_count": len(PROVE_OR_REVERSE),
                "permitted_nonlegal_or_meta_exclusion_count": len(EXCLUSION_PROOFS),
                "broad_llp_locator_banned": True,
                "johnson_duress_overreach_removed": True,
                "s31_4_damages_locator_required": True,
                "loose_nine_representation_affected_row_links_removed": True,
            },
            "r2_advisory_content_sha256": advisory["artifact_content_sha256"],
            "r2_source_manifest_content_sha256": source_manifest[
                "artifact_content_sha256"
            ],
            "owner_adoption_required": True,
            "owner_adopted": False,
            "recursive_no_execution_control": r1_builder._recursive_no_execution_control(),
            **NO_EXECUTION,
        }
    )

    for artifact in (advisory, source_manifest, no_go):
        violations = r1_builder._recursive_no_execution_violations(artifact)
        if violations:
            raise ValueError("recursive_no_execution_violation:" + ",".join(violations))
        rendered = json.dumps(artifact, ensure_ascii=False, sort_keys=True)
        if r1_builder._PRIVATE_PATH.search(rendered):
            raise ValueError("r2_review_artifact_contains_private_or_old_project_path")
    return advisory, source_manifest, no_go


def publish(output_root: Path = OUTPUT_ROOT) -> dict[str, str]:
    if output_root.exists():
        raise FileExistsError(f"create-only output already exists:{output_root}")
    advisory, source_manifest, no_go = build_advisory()
    output_root.parent.mkdir(parents=True, exist_ok=True)
    temp_root = Path(tempfile.mkdtemp(prefix=f".{output_root.name}-", dir=output_root.parent))
    try:
        artifacts = {
            ADVISORY_NAME: advisory,
            SOURCE_MANIFEST_NAME: source_manifest,
            R1_NO_GO_NAME: no_go,
        }
        for name, value in artifacts.items():
            (temp_root / name).write_bytes(r1_builder._pretty_json(value))
            os.chmod(temp_root / name, 0o600)
        package_records = [
            {
                "name": name,
                "file_sha256": _file_sha256(temp_root / name),
                "content_sha256": value["artifact_content_sha256"],
                "bytes": (temp_root / name).stat().st_size,
            }
            for name, value in sorted(artifacts.items())
        ]
        package = r1_builder._seal(
            {
                "schema": "legalbot.v111.phase2a.held-missing-28-substantive-remediation-package.r2.v1",
                "status": "CREATE_ONLY_NON_AUTHORIZING_NOT_EXECUTED",
                "artifact_count": len(package_records),
                "artifacts": package_records,
                "recursive_no_execution_control": r1_builder._recursive_no_execution_control(),
                **NO_EXECUTION,
            },
            "package_content_sha256",
        )
        if r1_builder._recursive_no_execution_violations(package):
            raise ValueError("package_recursive_no_execution_violation")
        (temp_root / PACKAGE_NAME).write_bytes(r1_builder._pretty_json(package))
        os.chmod(temp_root / PACKAGE_NAME, 0o600)
        checksum_names = sorted([*artifacts, PACKAGE_NAME])
        (temp_root / CHECKSUMS_NAME).write_text(
            "".join(
                f"{_file_sha256(temp_root / name)}  {name}\n" for name in checksum_names
            ),
            encoding="utf-8",
        )
        os.chmod(temp_root / CHECKSUMS_NAME, 0o600)
        os.chmod(temp_root, 0o700)
        temp_root.rename(output_root)
    except Exception:
        shutil.rmtree(temp_root, ignore_errors=True)
        raise
    return {
        "status": "CREATE_ONLY_NON_AUTHORIZING_NOT_EXECUTED",
        "advisory": str(output_root / ADVISORY_NAME),
        "source_manifest": str(output_root / SOURCE_MANIFEST_NAME),
        "r1_no_go": str(output_root / R1_NO_GO_NAME),
        "package": str(output_root / PACKAGE_NAME),
        "checksums": str(output_root / CHECKSUMS_NAME),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=OUTPUT_ROOT)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    advisory, source_manifest, no_go = build_advisory()
    if args.dry_run:
        print(
            json.dumps(
                {
                    "advisory_content_sha256": advisory["artifact_content_sha256"],
                    "source_manifest_content_sha256": source_manifest[
                        "artifact_content_sha256"
                    ],
                    "r1_no_go_content_sha256": no_go["artifact_content_sha256"],
                    "counts": advisory["counts"],
                },
                sort_keys=True,
            )
        )
        return 0
    print(json.dumps(publish(args.output_root.resolve()), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
