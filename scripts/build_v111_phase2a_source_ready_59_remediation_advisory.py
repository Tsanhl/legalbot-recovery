#!/usr/bin/env python3
"""Build the create-only Phase-2A advisory for the 59 source-ready rows.

This builder is deliberately non-authorizing.  It verifies the exact r3
blocker cohort, the owner packet, the sealed local source representations and
the unspent execution chain.  It then recommends either exact removal of a
PARTIAL/NONE component when the row already has FULL support, or a narrowly
worded replacement tied to source text when the row otherwise has no FULL
component.  It never applies a decision or runs a source scan, build,
embedding, retrieval, qualification, answer model, pointer write, or Phase 2B.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import unicodedata
from collections import Counter
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from pypdf import PdfReader

from scripts.apply_v111_phase2a_final_remediation import build_materialization_plan

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"

R3_PATH = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-prequalification-blockers-r3/PREQUALIFICATION-BLOCKER-REPORT.json"
)
OWNER_PACKET_PATH = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-exact-remediation-owner-packet-r1/"
    "EXACT-REMEDIATION-OWNER-PACKET-361.json"
)
QUARANTINE_ROOT = REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-source-quarantine"
QUARANTINE_MANIFEST_PATH = QUARANTINE_ROOT / "QUARANTINE-MANIFEST.json"
CANDIDATE_MANIFEST_PATH = PROJECT_ROOT / (
    "data/indexes/builds/current-law-ew-full-fp16-v111-20260827-phase2a-a/"
    "approved-source-manifest.json"
)
EXECUTION_AUTHORITY_PATH = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-final-remediation-owner-approved-r1/"
    "PHASE2A-EXECUTION-AUTHORITY.json"
)
BASELINE_ADVISORY_PATH = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-146-row-superseding-remediation-advisory-r2/"
    "EXACT-146-ROW-SUPERSEDING-REMEDIATION-ADVISORY.json"
)

OUTPUT_ROOT = REVIEW_ROOT / ("LegalBot-Phase2A-2026-08-28-source-ready-59-remediation-advisory-r1")
ADVISORY_NAME = "SOURCE-READY-59-REMEDIATION-ADVISORY.json"
PACKAGE_NAME = "PACKAGE-MANIFEST.json"
CHECKSUMS_NAME = "SHA256SUMS.txt"

R3_CONTENT_SHA256 = "5efc17b16adcae1ceb2ea1bbd7efcaba469ab0340c24b65c1e994132cb337980"
R3_FILE_SHA256 = "7cb044a4c9539162281e10ac41e5e0cb1f0cd846b0eb597a0443b0e67fb48899"
OWNER_PACKET_CONTENT_SHA256 = "93ad9113af76896f0570a3666c446472af7587b7e3ff32b7464e670777ec6b6c"
OWNER_PACKET_FILE_SHA256 = "992770c04cb3e08de64bb98e80aa9801171d3e66e4b573b85919091a78b1db3b"
QUARANTINE_MANIFEST_CONTENT_SHA256 = (
    "b6d900b23232379a4d6c19d313f35c47e0758ce5e0bb6eb04008f9eba07a3819"
)
QUARANTINE_MANIFEST_FILE_SHA256 = "f482366a2ba0d9f636c56104d632767a8eadd6e9a9625d50ef5391a5f62995eb"
CANDIDATE_MANIFEST_CONTENT_SHA256 = (
    "b304ab1223987bf9b57d3e2560413b2f325c16213ae0071a45dface2e10dc206"
)
CANDIDATE_MANIFEST_FILE_SHA256 = "0bbb1edb169c84a26e5f1d42e367f9e2f83fcdd9c652a9061980652f15979b21"
EXECUTION_AUTHORITY_CONTENT_SHA256 = (
    "eb0eda2f34c8b261ea38fc9d697257cdd3bd6253c18c2d91355328c8cb78ef7b"
)
EXECUTION_AUTHORITY_FILE_SHA256 = "5171ce79007c68484f9854b5188bf7e7af8f880407b6fbad6e3f808d0c7630ad"
BASELINE_ADVISORY_CONTENT_SHA256 = (
    "6078e556e8ee3eb551bd48d310b2a89728e317dc8c240f22030799b54e595e1d"
)
BASELINE_ADVISORY_FILE_SHA256 = "81eebbe55d18d5257217d28760d136544523716adfb17746cd6cb34bceb27659"
MATERIALIZATION_PLAN_CONTENT_SHA256 = (
    "de7b8e8c0d5d4a6e1f99f0f338d623bb7e371222b8c0341b35515fe1d1567c7b"
)

SOURCE_READY_ROW_IDS = (
    "live30-q06:issue-05",
    "live30-q08:issue-04",
    "live30-q09:issue-02",
    "live30-q13:issue-02",
    "live30-q16:issue-02",
    "live30-q16:issue-03",
    "live30-q16:issue-04",
    "live30-q18:issue-01",
    "live30-q18:issue-02",
    "live30-q18:issue-03",
    "live30-q18:issue-04",
    "live30-q18:issue-05",
    "live30-q18:issue-07",
    "live30-q21:issue-03",
    "live30-q22:issue-07",
    "live30-q25:issue-09",
    "live30-q26:issue-02",
    "live30-q26:issue-10",
    "live30-q27:issue-03",
    "live30-q29:issue-02",
    "live30-q30:issue-01",
    "live30-q30:issue-03",
    "live30-q30:issue-04",
    "live60-q31:issue-07",
    "live60-q31:issue-08",
    "live60-q34:issue-06",
    "live60-q35:issue-06",
    "live60-q36:issue-06",
    "live60-q37:issue-05",
    "live60-q37:issue-07",
    "live60-q37:issue-08",
    "live60-q37:issue-10",
    "live60-q38:issue-05",
    "live60-q38:issue-06",
    "live60-q40:issue-01",
    "live60-q41:issue-05",
    "live60-q41:issue-09",
    "live60-q42:issue-01",
    "live60-q42:issue-05",
    "live60-q44:issue-10",
    "live60-q45:issue-03",
    "live60-q45:issue-04",
    "live60-q45:issue-05",
    "live60-q45:issue-06",
    "live60-q45:issue-09",
    "live60-q47:issue-05",
    "live60-q48:issue-09",
    "live60-q49:issue-05",
    "live60-q51:issue-02",
    "live60-q51:issue-09",
    "live60-q52:issue-06",
    "live60-q52:issue-08",
    "live60-q53:issue-05",
    "live60-q53:issue-08",
    "live60-q56:issue-02",
    "live60-q57:issue-02",
    "live60-q58:issue-07",
    "live60-q58:issue-11",
    "live60-q60:issue-01",
)
SOURCE_READY_ROW_ID_SET_SHA256 = "265da7032985c7d978d49c6cb3d602d28551743f9c453f22651a3863753b31a3"


def _span(authority: str, locator: str, *excerpts: str) -> dict[str, Any]:
    return {
        "authority_identity_id": authority,
        "exact_locator": locator,
        "supporting_excerpts": list(excerpts),
    }


# Only rows with no pre-existing FULL component are rewritten.  Every sentence
# below is narrower than its r3 predecessor and is tied to text verified in the
# sealed representation.  Other cited authorities remain inspected but are not
# used to expand the replacement proposition.
REWRITES: dict[tuple[str, int], dict[str, Any]] = {
    ("live60-q34:issue-06", 1): {
        "after": (
            "Whether earlier encouragement or assistance remained operative is a "
            "question of fact and degree: it may have faded, been spent by an "
            "overwhelming intervening occurrence, or become so distanced in time, "
            "place or circumstances that the principal offence is no longer "
            "realistically regarded as encouraged or assisted; Tas also recognises "
            "that withdrawal may end the relevant joint enterprise."
        ),
        "spans": [
            _span(
                "neutral-citation:[2018] EWCA Crim 2603",
                "paragraphs 31 and 44",
                "Ultimately it is a question of fact and degree whether D2’s conduct was so distanced in time, place or circumstances",
                "if the defendant had withdrawn from the joint enterprise to assault the deceased, then there had been no relevant joint enterprise still operational",
            )
        ],
    },
    ("live60-q37:issue-05", 1): {
        "after": (
            "Section 5 provides that an LLP's internal mutual rights and duties are "
            "governed by agreement or, where no agreement addresses a matter, by "
            "regulations; regulation 7 supplies default rules subject to the general "
            "law and the LLP agreement."
        ),
        "spans": [
            _span(
                "ukpga:2000:12",
                "section 5(1)",
                "the mutual rights and duties of the members of a limited liability partnership",
                "in the absence of agreement as to any matter",
            ),
            _span(
                "uksi:2001:1090",
                "regulation 7 and Schedule 2",
                "shall be determined, subject to the provisions of the general law and to the terms of any limited liability partnership agreement",
            ),
        ],
    },
    ("live60-q37:issue-07", 1): {
        "after": (
            "For an LLP, regulation 5 applies the specified Insolvency Act 1986 "
            "provisions subject to the substitutions and other modifications in "
            "regulation 5 and Schedule 3; no unmodified company route is asserted."
        ),
        "spans": [
            _span(
                "uksi:2001:1090",
                "regulation 5(1)-(2) and Schedule 3",
                "the following provisions of the 1986 Act, shall apply to limited liability partnerships",
                "the modifications set out in Schedule 3 to these Regulations",
            )
        ],
    },
    ("live60-q37:issue-08", 1): {
        "after": (
            "The LLP insolvency routes in regulation 5 are the specified Insolvency "
            "Act 1986 provisions as applied with the regulation 5 and Schedule 3 "
            "modifications; the company provisions are not applied without those "
            "modifications."
        ),
        "spans": [
            _span(
                "uksi:2001:1090",
                "regulation 5(1)-(2) and Schedule 3",
                "The provisions of the 1986 Act referred to in paragraph (1) shall apply to limited liability partnerships",
                "the modifications set out in Schedule 3 to these Regulations",
            )
        ],
    },
    ("live60-q37:issue-10", 1): {
        "after": (
            "An LLP is a body corporate with legal personality separate from its "
            "members, and each member is its agent subject to section 6; by contrast, "
            "under section 5 of the Partnership Act 1890 each partner is an agent of "
            "the firm and the other partners for partnership business."
        ),
        "spans": [
            _span(
                "ukpga:2000:12",
                "sections 1(2) and 6(1)-(2)",
                "A limited liability partnership is a body corporate (with legal personality separate from that of its members)",
                "Every member of a limited liability partnership is the agent of the limited liability partnership",
            ),
            _span(
                "ukpga:Vict:53-54:39",
                "section 5",
                "Every partner is an agent of the firm and his other partners for the purpose of the business of the partnership",
            ),
        ],
    },
    ("live60-q38:issue-05", 1): {
        "after": (
            "Section 19 permits a seller, by the contract or appropriation terms, "
            "to reserve disposal of identified goods until stated conditions are "
            "fulfilled; no proposition about title in a new manufactured product is "
            "adopted from that section."
        ),
        "spans": [
            _span(
                "ukpga:1979:54",
                "section 19(1)",
                "the seller may, by the terms of the contract or appropriation, reserve the right of disposal of the goods until certain conditions are fulfilled",
            )
        ],
    },
    ("live60-q38:issue-06", 1): {
        "after": (
            "Sections 19 and 25 address reservation of disposal in goods and the "
            "effect of a disposition by a buyer in possession to a good-faith "
            "recipient without notice; no proceeds-trust proposition is adopted from "
            "those sections."
        ),
        "spans": [
            _span(
                "ukpga:1979:54",
                "sections 19(1) and 25(1)",
                "reserve the right of disposal of the goods until certain conditions are fulfilled",
                "to any person receiving the same in good faith and without notice of any lien or other right of the original seller",
            )
        ],
    },
    ("live60-q40:issue-01", 1): {
        "after": (
            "Ordinary planning-application publicity is governed by article 15 of "
            "the 2015 Order. Separately, regulation 3 of the 2017 Regulations "
            "prohibits permission for EIA development unless an EIA has been carried "
            "out, and regulation 18 requires an EIA application to be accompanied by "
            "an environmental statement, subject to regulation 9."
        ),
        "spans": [
            _span(
                "uksi:2015:595",
                "article 15(1)",
                "An application for planning permission must be publicised by the local planning authority to which the application is made",
            ),
            _span(
                "uksi:2017:571",
                "regulations 3 and 18(1)",
                "must not grant planning permission or subsequent consent for EIA development unless an EIA has been carried out",
                "Subject to regulation 9, an EIA application must be accompanied by an environmental statement",
            ),
        ],
    },
    ("live60-q45:issue-03", 1): {
        "after": (
            "Charity Commission CC9 states that a charity cannot have a political "
            "purpose and that political activity may support charitable purposes but "
            "cannot be the charity's continuing and sole activity."
        ),
        "spans": [
            _span(
                "official-url:https://gov.uk/government/publications/speaking-out-guidance-on-campaigning-and-political-activity-by-charities-cc9/speaking-out-guidance-on-campaigning-and-political-activity-by-charities",
                "sections 3.3-3.5",
                "A charity cannot have a political purpose.",
                "political activity can only support, or contribute to, the achievement of charitable purposes",
                "political activity cannot be the continuing and sole activity of the charity",
            )
        ],
    },
    ("live60-q45:issue-04", 1): {
        "after": (
            "CC9 states that trustees considering political activity must decide "
            "whether there is a reasonable expectation that it will support the "
            "charity's purposes, and that political activity cannot be the continuing "
            "and sole activity."
        ),
        "spans": [
            _span(
                "official-url:https://gov.uk/government/publications/speaking-out-guidance-on-campaigning-and-political-activity-by-charities-cc9/speaking-out-guidance-on-campaigning-and-political-activity-by-charities",
                "sections 3.4-3.5",
                "trustees must first decide whether there is a reasonable expectation that it will support the charity’s purposes",
                "political activity cannot be the continuing and sole activity of the charity",
            )
        ],
    },
    ("live60-q45:issue-04", 2): {
        "after": (
            "CC9 states that a charity must not support a political party or "
            "candidate, although it may advocate a policy advanced by one where the "
            "policy supports the charity's purposes while the charity remains "
            "independent."
        ),
        "spans": [
            _span(
                "official-url:https://gov.uk/government/publications/speaking-out-guidance-on-campaigning-and-political-activity-by-charities-cc9/speaking-out-guidance-on-campaigning-and-political-activity-by-charities",
                "sections 4.1-4.2",
                "a charity must not support a political party or candidate",
                "a charity must always guard its independence, and ensure it remains independent",
            )
        ],
    },
    ("live60-q45:issue-05", 1): {
        "after": (
            "CC3 states that trustees must decide for themselves what best enables "
            "the charity to carry out its purposes, make balanced and adequately "
            "informed decisions, and use reasonable care and skill with appropriate "
            "advice where necessary."
        ),
        "spans": [
            _span(
                "official-url:https://gov.uk/government/publications/the-essential-trustee-what-you-need-to-know-what-you-need-to-do-cc3/the-essential-trustee-what-you-need-to-know-what-you-need-to-do",
                "sections 6 and 8",
                "do what you and your co-trustees (and no one else) decide will best enable the charity to carry out its purposes",
                "make balanced and adequately informed decisions",
                "must use reasonable care and skill, making use of your skills and experience and taking appropriate advice when necessary",
            )
        ],
    },
    ("live60-q45:issue-06", 1): {
        "after": (
            "Charity Commission guidance states that trustees considering refusal or "
            "return of a donation must have a legal power to do so and be satisfied "
            "that using it is in the charity's best interests; the applicable power "
            "depends on the circumstances."
        ),
        "spans": [
            _span(
                "official-url:https://gov.uk/guidance/accepting-refusing-and-returning-donations-to-your-charity",
                "Check you have a legal power to refuse or return a donation",
                "You must have a legal power to refuse or return a donation and be satisfied that using the power is in the best interests of your charity",
                "Which power you use will depend on the circumstances",
            )
        ],
    },
    ("live60-q45:issue-09", 1): {
        "after": (
            "CC27 states that trustees must be sufficiently informed, take all "
            "relevant factors into account, disregard irrelevant factors, and remain "
            "within the range of reasonable trustee-body decisions; reputational "
            "impact is one potentially relevant factor."
        ),
        "spans": [
            _span(
                "official-url:https://gov.uk/government/publications/decision-making-for-charity-trustees-cc27/decision-making-for-charity-trustees",
                "principles 3-5 and 7",
                "You must be able to show that as trustees you based your decisions on enough relevant information",
                "You must take all relevant factors into account when you make a decision",
                "Trustees must identify and disregard irrelevant factors",
                "the impact on the charity’s reputation of all options",
            )
        ],
    },
    ("live60-q51:issue-02", 1): {
        "after": (
            "Ingenious Media states that a recipient of personal or confidential "
            "information obtained under legal power or public duty generally owes a "
            "duty not to use it for other purposes, subject to statutory authority; "
            "an impermissible disclosure is not made permissible merely because it is "
            "passed on in confidence."
        ),
        "spans": [
            _span(
                "neutral-citation:[2016] UKSC 54",
                "paragraphs 17-18, 26-27 and 31",
                "where information of a personal or confidential nature is obtained or received in the exercise of a legal power or in furtherance of a public duty",
                "an impermissible disclosure of confidential information is no less impermissible just because the information is passed on in confidence",
            )
        ],
    },
    ("live60-q58:issue-07", 1): {
        "after": (
            "Electricity Act 1989 section 9 imposes general system-development and "
            "competition-facilitation duties on electricity distributors and "
            "transmission licence holders; sections 6-9 do not themselves establish "
            "a project-specific damages entitlement."
        ),
        "spans": [
            _span(
                "ukpga:1989:29",
                "section 9(1)-(2)",
                "It shall be the duty of the holder of a licence authorising him to  participate in the transmission of  electricity",
                "to develop and maintain an efficient, co-ordinated and economical system of electricity transmission",
            )
        ],
    },
    ("live60-q58:issue-11", 1): {
        "after": (
            "Under section 1 of the Contracts (Rights of Third Parties) Act 1999, a "
            "non-party may enforce a term only where the contract expressly permits "
            "it or the term purports to benefit that identified third party, subject "
            "to the Act and the contract's other relevant terms; the Act does not "
            "create a generic lender step-in right."
        ),
        "spans": [
            _span(
                "ukpga:1999:31",
                "section 1(1)-(5)",
                "a person who is not a party to a contract (a “third party”) may in his own right enforce a term of the contract",
                "the contract expressly provides that he may",
                "the term purports to confer a benefit on him",
            )
        ],
    },
}

NO_EXECUTION_FLAGS = {
    "owner_approved": False,
    "owner_decisions_applied": False,
    "source_admission_authorized": False,
    "source_admitted": False,
    "source_scan_run": False,
    "successor_build_run": False,
    "index_build_run": False,
    "embedding_run": False,
    "retrieval_reattestation_run": False,
    "all585_qualification_run": False,
    "answer_model_run": False,
    "answer_released": False,
    "phase2b_authorized": False,
    "phase2b_run": False,
    "development30_run": False,
    "validation30_run": False,
    "owner_certification60_run": False,
    "promotion_run": False,
    "active_pointer_written": False,
    "previous_pointer_written": False,
    "live_activation_run": False,
    "training_export_run": False,
}


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _seal(value: dict[str, Any], field: str = "artifact_content_sha256") -> dict[str, Any]:
    material = dict(value)
    material.pop(field, None)
    return {**material, field: _sha256(_canonical_json(material))}


def _load(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"input_not_regular:{path.name}")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"input_not_object:{path.name}")
    return value


def _verify_seal(value: dict[str, Any], field: str, expected: str) -> None:
    material = dict(value)
    observed = str(material.pop(field, ""))
    if observed != expected or _sha256(_canonical_json(material)) != observed:
        raise ValueError(f"invalid_content_seal:{field}")


def _normalise_text(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).split())


def _representation_text(path: Path) -> tuple[str, str]:
    raw = path.read_bytes()
    suffix = path.suffix.lower()
    if suffix == ".xml":
        root = ElementTree.fromstring(raw)
        text = "".join(root.itertext())
        mode = "XML_ITERATION_TEXT"
    elif suffix in {".html", ".htm"}:
        text = raw.decode("utf-8", errors="strict")
        mode = "UTF8_OFFICIAL_HTML"
    elif suffix == ".pdf":
        reader = PdfReader(path)
        if not reader.pages:
            raise ValueError(f"empty_pdf:{path.name}")
        text = "\n".join(page.extract_text() or "" for page in reader.pages)
        mode = "PDF_TEXT_EXTRACTION"
    else:
        text = raw.decode("utf-8", errors="strict")
        mode = "UTF8_CANONICAL_MARKDOWN"
    normalised = _normalise_text(text)
    if len(normalised) < 40:
        raise ValueError(f"empty_representation_text:{path.name}")
    return normalised, mode


def _source_bindings(
    r3_rows: list[dict[str, Any]],
    quarantine: dict[str, Any],
    candidate: dict[str, Any],
    plan: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], dict[str, str]]:
    authority_metadata: dict[str, dict[str, Any]] = {}
    for row in r3_rows:
        for component in row["blocking_components"]:
            for authority in component["authorities"]:
                identity = authority["canonical_authority_identity_id"]
                existing = authority_metadata.setdefault(
                    identity,
                    {
                        "authority_identity_id": identity,
                        "citations": set(),
                        "official_urls": set(),
                        "original_exact_locators": set(),
                    },
                )
                existing["citations"].add(authority["citation"])
                existing["official_urls"].add(authority["official_url"])
                existing["original_exact_locators"].update(authority["exact_locators"])

    qrecords = {
        record["authority_identity_id"]: record
        for record in quarantine["records"]
        if record.get("selected_for_proposed_admission") is True
    }
    candidate_sources = {source["authority_identity_id"]: source for source in candidate["sources"]}
    plan_records = {
        record["authority_identity_id"]: record
        for record in plan["representations"]
        if record["index_eligible"] is True
    }

    bindings: list[dict[str, Any]] = []
    source_texts: dict[str, str] = {}
    source_modes: dict[str, str] = {}
    for identity in sorted(authority_metadata):
        metadata = authority_metadata[identity]
        if identity in plan_records:
            plan_record = plan_records[identity]
            qrecord = qrecords.get(identity)
            if qrecord is None:
                raise ValueError(f"planned_source_missing_quarantine_record:{identity}")
            member = qrecord["quarantine_member"]
            path = QUARANTINE_ROOT / member
            if (
                path.is_symlink()
                or not path.is_file()
                or path.parent.resolve() != QUARANTINE_ROOT.resolve()
                or _file_sha256(path) != qrecord["raw_sha256"]
                or plan_record["content_sha256"] != qrecord["raw_sha256"]
                or plan_record["input_member"] != member
            ):
                raise ValueError(f"quarantine_source_byte_mismatch:{identity}")
            text, mode = _representation_text(path)
            source = {
                "source_origin": "EXACT_OWNER_ADOPTED_MATERIALIZATION_PLAN",
                "proposed_source_version_id": qrecord["proposed_source_version_id"],
                "representation_member": member,
                "representation_file_sha256": qrecord["raw_sha256"],
                "canonical_content_sha256": qrecord.get("canonical_content_sha256"),
                "materialization_record_content_sha256": plan_record["record_content_sha256"],
                "materialization_target_relative_path": plan_record["target_relative_path"],
            }
        elif identity in candidate_sources:
            candidate_source = candidate_sources[identity]
            relative = Path(candidate_source["canonical_markdown_path"])
            path = PROJECT_ROOT / relative
            vault_root = (PROJECT_ROOT / "data/vault/objects/sha256").resolve()
            if (
                path.is_symlink()
                or not path.is_file()
                or vault_root not in path.resolve().parents
                or _file_sha256(path) != path.name
            ):
                raise ValueError(f"candidate_source_byte_mismatch:{identity}")
            text, mode = _representation_text(path)
            source = {
                "source_origin": "SEALED_251_SOURCE_CANDIDATE",
                "source_version_id": candidate_source["source_version_id"],
                "canonical_object_sha256": path.name,
                "catalogue_content_sha256": candidate_source["content_sha256"],
                "candidate_identity_verified": candidate_source["identity_verified"],
            }
        else:
            raise ValueError(f"source_identity_not_resolved:{identity}")

        source_texts[identity] = text
        source_modes[identity] = mode
        binding = _seal(
            {
                "schema": "legalbot.v111.phase2a.source-ready-authority-byte-binding.v1",
                "authority_identity_id": identity,
                "citations": sorted(metadata["citations"]),
                "official_urls": sorted(metadata["official_urls"]),
                "original_exact_locators": sorted(metadata["original_exact_locators"]),
                "representation_parse_mode": mode,
                "representation_byte_hash_verified": True,
                **source,
            },
            "record_content_sha256",
        )
        bindings.append(binding)
    return bindings, {row["authority_identity_id"]: row for row in bindings}, source_texts


def build_advisory() -> dict[str, Any]:
    expected_set_hash = _sha256(("\n".join(SOURCE_READY_ROW_IDS) + "\n").encode())
    if expected_set_hash != SOURCE_READY_ROW_ID_SET_SHA256:
        raise ValueError("source_ready_row_set_digest_invalid")

    input_files = (
        (R3_PATH, R3_FILE_SHA256),
        (OWNER_PACKET_PATH, OWNER_PACKET_FILE_SHA256),
        (QUARANTINE_MANIFEST_PATH, QUARANTINE_MANIFEST_FILE_SHA256),
        (CANDIDATE_MANIFEST_PATH, CANDIDATE_MANIFEST_FILE_SHA256),
        (EXECUTION_AUTHORITY_PATH, EXECUTION_AUTHORITY_FILE_SHA256),
        (BASELINE_ADVISORY_PATH, BASELINE_ADVISORY_FILE_SHA256),
    )
    for path, expected in input_files:
        if _file_sha256(path) != expected:
            raise ValueError(f"input_file_digest_invalid:{path.name}")

    r3 = _load(R3_PATH)
    owner_packet = _load(OWNER_PACKET_PATH)
    quarantine = _load(QUARANTINE_MANIFEST_PATH)
    candidate = _load(CANDIDATE_MANIFEST_PATH)
    execution_authority = _load(EXECUTION_AUTHORITY_PATH)
    baseline = _load(BASELINE_ADVISORY_PATH)
    _verify_seal(r3, "artifact_content_sha256", R3_CONTENT_SHA256)
    _verify_seal(owner_packet, "artifact_content_sha256", OWNER_PACKET_CONTENT_SHA256)
    _verify_seal(quarantine, "manifest_content_sha256", QUARANTINE_MANIFEST_CONTENT_SHA256)
    _verify_seal(
        execution_authority,
        "artifact_content_sha256",
        EXECUTION_AUTHORITY_CONTENT_SHA256,
    )
    _verify_seal(baseline, "artifact_content_sha256", BASELINE_ADVISORY_CONTENT_SHA256)
    if (
        candidate.get("manifest_sha256") != CANDIDATE_MANIFEST_CONTENT_SHA256
        or candidate.get("source_count") != 251
    ):
        raise ValueError("candidate_manifest_identity_invalid")
    if (
        execution_authority.get("status") != "AVAILABLE_UNSPENT"
        or execution_authority.get("total_execution_chain_count") != 1
        or execution_authority.get("execution_chain_consumed_count") != 0
        or execution_authority.get("execution_chain_remaining_count") != 1
    ):
        raise ValueError("execution_chain_not_unspent")

    plan = build_materialization_plan()
    if (
        plan.get("artifact_content_sha256") != MATERIALIZATION_PLAN_CONTENT_SHA256
        or plan.get("source_materialized") is not False
        or plan.get("representation_count") != 254
        or plan.get("index_eligible_representation_count") != 250
    ):
        raise ValueError("materialization_plan_identity_invalid")

    r3_by_id = {row["row_id"]: row for row in r3["rows"]}
    packet_by_id = {decision["row_id"]: decision for decision in owner_packet["decisions"]}
    if (
        set(SOURCE_READY_ROW_IDS) - r3_by_id.keys()
        or set(SOURCE_READY_ROW_IDS) - packet_by_id.keys()
    ):
        raise ValueError("source_ready_row_missing_upstream")
    r3_rows = [r3_by_id[row_id] for row_id in SOURCE_READY_ROW_IDS]

    source_bindings, source_by_id, source_texts = _source_bindings(
        r3_rows, quarantine, candidate, plan
    )
    if len(source_bindings) != 77:
        raise ValueError("source_ready_authority_count_invalid")
    origins = Counter(row["source_origin"] for row in source_bindings)
    if origins != {
        "EXACT_OWNER_ADOPTED_MATERIALIZATION_PLAN": 52,
        "SEALED_251_SOURCE_CANDIDATE": 25,
    }:
        raise ValueError("source_ready_authority_topology_invalid")

    row_advisories: list[dict[str, Any]] = []
    rewrite_rows: set[str] = set()
    rewrite_components = 0
    excluded_components = 0
    full_retained_total = 0
    for row_id in SOURCE_READY_ROW_IDS:
        r3_row = r3_by_id[row_id]
        decision = packet_by_id[row_id]
        all_components = decision["source_research_record"]["atomic_components"]
        full_components = [
            component for component in all_components if component["support_fit"] == "FULL"
        ]
        full_retained_total += len(full_components)
        no_full_component = not full_components
        recommendations: list[dict[str, Any]] = []
        for component in r3_row["blocking_components"]:
            key = (row_id, component["component_ordinal"])
            rewrite = REWRITES.get(key)
            if no_full_component and rewrite is None:
                raise ValueError(f"zero_full_row_without_rewrite:{row_id}")
            if rewrite is not None and not no_full_component:
                raise ValueError(f"rewrite_not_restricted_to_zero_full_row:{row_id}")

            inspected_sources = [
                {
                    "authority_identity_id": authority["canonical_authority_identity_id"],
                    "source_binding_content_sha256": source_by_id[
                        authority["canonical_authority_identity_id"]
                    ]["record_content_sha256"],
                    "original_exact_locators": authority["exact_locators"],
                    "original_support_fit": component["support_fit"],
                }
                for authority in component["authorities"]
            ]
            before = {
                "component_ordinal": component["component_ordinal"],
                "proposition": component["proposition"],
                "proposition_text_sha256": component["proposition_text_sha256"],
                "support_fit": component["support_fit"],
            }
            if rewrite is None:
                excluded_components += 1
                recommendation = {
                    "action": "EXCLUDE_EXACT_UNSUPPORTED_COMPONENT",
                    "before": before,
                    "after_propositions": [],
                    "reason_code": "ROW_RETAINS_PREEXISTING_FULL_COMPONENTS_BLOCKER_NOT_NEEDED",
                    "frozen_evidence_span_proposals": [],
                    "source_inspection": inspected_sources,
                    "owner_adoption_required": True,
                    "applied": False,
                }
            else:
                rewrite_rows.add(row_id)
                rewrite_components += 1
                spans: list[dict[str, Any]] = []
                for ordinal, span in enumerate(rewrite["spans"], start=1):
                    identity = span["authority_identity_id"]
                    if identity not in source_texts:
                        raise ValueError(f"rewrite_source_not_in_row_cohort:{identity}")
                    excerpt_records = []
                    for excerpt in span["supporting_excerpts"]:
                        normalised = _normalise_text(excerpt)
                        if normalised not in source_texts[identity]:
                            raise ValueError(
                                f"supporting_excerpt_not_in_source:{row_id}:{identity}"
                            )
                        excerpt_records.append(
                            {
                                "text": excerpt,
                                "normalised_text_sha256": _sha256(normalised.encode()),
                                "verified_in_bound_source_bytes": True,
                            }
                        )
                    span_payload = _seal(
                        {
                            "schema": "legalbot.v111.phase2a.frozen-evidence-span-proposal.v1",
                            "span_ordinal": ordinal,
                            "authority_identity_id": identity,
                            "source_binding_content_sha256": source_by_id[identity][
                                "record_content_sha256"
                            ],
                            "exact_locator": span["exact_locator"],
                            "supporting_excerpts": excerpt_records,
                            "normalization": "UNICODE_NFKC_AND_COLLAPSE_WHITESPACE",
                            "proposal_payload_immutable": True,
                            "owner_adopted": False,
                            "evidence_span_frozen_for_execution": False,
                        },
                        "span_proposal_content_sha256",
                    )
                    spans.append(span_payload)
                after = rewrite["after"]
                recommendation = {
                    "action": "REPLACE_WITH_EXACT_NARROW_SOURCE_TEXT",
                    "before": before,
                    "after_propositions": [
                        {
                            "proposition": after,
                            "proposition_text_sha256": _sha256(after.encode()),
                            "proposed_support_fit": "FULL_IF_EXACT_OWNER_ADOPTED",
                        }
                    ],
                    "reason_code": "ZERO_PREEXISTING_FULL_COMPONENT_NARROWED_TO_VERIFIED_SOURCE_TEXT",
                    "frozen_evidence_span_proposals": spans,
                    "source_inspection": inspected_sources,
                    "owner_adoption_required": True,
                    "applied": False,
                }
            recommendations.append(_seal(recommendation, "recommendation_content_sha256"))

        retained_full = []
        for ordinal, component in enumerate(all_components, start=1):
            if component["support_fit"] != "FULL":
                continue
            proposition = component["proposition"]
            retained_full.append(
                {
                    "component_ordinal": ordinal,
                    "proposition": proposition,
                    "proposition_text_sha256": _sha256(proposition.encode()),
                    "support_fit": "FULL",
                    "authority_identity_ids": sorted(
                        authority.get("canonical_authority_identity_id")
                        or authority.get("authority_identity_id")
                        or authority.get("citation")
                        for authority in component["authorities"]
                    ),
                }
            )

        row_record = _seal(
            {
                "schema": "legalbot.v111.phase2a.source-ready-row-remediation-advisory.v1",
                "row_id": row_id,
                "r3_row_record_content_sha256": r3_row["record_content_sha256"],
                "owner_decision_content_sha256": decision["decision_content_sha256"],
                "route": (
                    "REWRITE_ZERO_FULL_ROW_TO_EXACT_SOURCE_TEXT"
                    if no_full_component
                    else "EXCLUDE_BLOCKERS_RETAIN_PREEXISTING_FULL_COMPONENTS"
                ),
                "original_blocking_component_count": len(r3_row["blocking_components"]),
                "component_recommendations": recommendations,
                "preexisting_full_components_retained": retained_full,
                "all_unclassified_holds_retained": [
                    {
                        "record_content_sha256": hold["record_content_sha256"],
                        "hold_text_sha256": hold["hold_text_sha256"],
                        "hold_text": hold["hold_text"],
                        "classification_preserved": "UNCLASSIFIED_NON_OPERATIVE",
                    }
                    for hold in r3_row["unclassified_unresolved_holds"]
                ],
                "fallback_eligible": False,
                "owner_adoption_required": True,
                "owner_decision_applied": False,
                "technical_success_not_predeclared": True,
            },
            "record_content_sha256",
        )
        row_advisories.append(row_record)

    if (
        len(row_advisories) != 59
        or len(rewrite_rows) != 16
        or rewrite_components != 17
        or excluded_components != 55
    ):
        raise ValueError("source_ready_recommendation_counts_invalid")

    advisory = {
        "schema": "legalbot.v111.phase2a.source-ready-59-remediation-advisory.v1",
        "status": "CREATE_ONLY_EXACT_REMEDIATION_READY_FOR_CONSOLIDATION_NOT_OWNER_ADOPTED",
        "phase_scope": "PHASE2A_ONLY",
        "advisory_date": "2026-08-28",
        "advisory_effect": "NON_AUTHORIZING_RECOMMENDATIONS_ONLY",
        "source_ready_row_id_set_sha256": SOURCE_READY_ROW_ID_SET_SHA256,
        "source_ready_row_ids": list(SOURCE_READY_ROW_IDS),
        "counts": {
            "row_count": len(row_advisories),
            "original_blocking_component_count": 72,
            "rewrite_row_count": len(rewrite_rows),
            "rewrite_component_count": rewrite_components,
            "exact_exclusion_row_count": len(row_advisories) - len(rewrite_rows),
            "exact_exclusion_component_count": excluded_components,
            "preexisting_full_component_retained_count": full_retained_total,
            "unique_authority_identity_count": len(source_bindings),
            "materialization_plan_source_count": origins[
                "EXACT_OWNER_ADOPTED_MATERIALIZATION_PLAN"
            ],
            "sealed_candidate_source_count": origins["SEALED_251_SOURCE_CANDIDATE"],
            "unresolved_source_identity_count": 0,
            "new_fallback_row_count": 0,
        },
        "input_bindings": [
            {
                "kind": "r3_prequalification_blocker_report",
                "content_sha256": R3_CONTENT_SHA256,
                "file_sha256": R3_FILE_SHA256,
            },
            {
                "kind": "exact_remediation_owner_packet_361",
                "content_sha256": OWNER_PACKET_CONTENT_SHA256,
                "file_sha256": OWNER_PACKET_FILE_SHA256,
            },
            {
                "kind": "source_quarantine_manifest",
                "content_sha256": QUARANTINE_MANIFEST_CONTENT_SHA256,
                "file_sha256": QUARANTINE_MANIFEST_FILE_SHA256,
            },
            {
                "kind": "sealed_251_candidate_approved_source_manifest",
                "content_sha256": CANDIDATE_MANIFEST_CONTENT_SHA256,
                "file_sha256": CANDIDATE_MANIFEST_FILE_SHA256,
            },
            {
                "kind": "exact_owner_adopted_materialization_plan_read_only",
                "content_sha256": MATERIALIZATION_PLAN_CONTENT_SHA256,
            },
            {
                "kind": "single_unspent_phase2a_execution_authority",
                "content_sha256": EXECUTION_AUTHORITY_CONTENT_SHA256,
                "file_sha256": EXECUTION_AUTHORITY_FILE_SHA256,
            },
            {
                "kind": "authoritative_146_row_baseline_advisory_r2",
                "content_sha256": BASELINE_ADVISORY_CONTENT_SHA256,
                "file_sha256": BASELINE_ADVISORY_FILE_SHA256,
            },
        ],
        "source_byte_bindings": source_bindings,
        "row_advisories": row_advisories,
        "decision_boundary": {
            "recommendations_are_not_owner_decisions": True,
            "owner_must_approve_exact_future_consolidated_digest": True,
            "no_blanket_fallback": True,
            "all_other_146_row_routes_outside_this_artifact": True,
            "one_execution_chain_total": 1,
            "execution_chain_consumed": 0,
            "execution_chain_remaining": 1,
            "technical_success_not_predeclared": True,
        },
        **NO_EXECUTION_FLAGS,
    }
    return _seal(advisory)


def publish(output_root: Path = OUTPUT_ROOT) -> dict[str, str]:
    advisory = build_advisory()
    advisory_bytes = _pretty_json(advisory)
    package = _seal(
        {
            "schema": "legalbot.v111.phase2a.source-ready-59-remediation-advisory-package.v1",
            "status": advisory["status"],
            "advisory_content_sha256": advisory["artifact_content_sha256"],
            "advisory_file_sha256": _sha256(advisory_bytes),
            "row_count": advisory["counts"]["row_count"],
            "rewrite_component_count": advisory["counts"]["rewrite_component_count"],
            "exact_exclusion_component_count": advisory["counts"][
                "exact_exclusion_component_count"
            ],
            "execution_chain_consumed": 0,
            **NO_EXECUTION_FLAGS,
        }
    )
    package_bytes = _pretty_json(package)
    checksums = (
        f"{_sha256(advisory_bytes)}  {ADVISORY_NAME}\n{_sha256(package_bytes)}  {PACKAGE_NAME}\n"
    ).encode()

    output_root.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, raw in (
        (ADVISORY_NAME, advisory_bytes),
        (PACKAGE_NAME, package_bytes),
        (CHECKSUMS_NAME, checksums),
    ):
        path = output_root / name
        with path.open("xb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        path.chmod(0o600)
    return {
        "output_root": output_root.name,
        "advisory_content_sha256": advisory["artifact_content_sha256"],
        "advisory_file_sha256": _sha256(advisory_bytes),
        "package_content_sha256": package["artifact_content_sha256"],
        "package_file_sha256": _sha256(package_bytes),
        "status": advisory["status"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("verify", "publish"))
    args = parser.parse_args()
    if args.command == "verify":
        advisory = build_advisory()
        print(
            json.dumps(
                {
                    "artifact_content_sha256": advisory["artifact_content_sha256"],
                    "counts": advisory["counts"],
                    "status": advisory["status"],
                },
                sort_keys=True,
            )
        )
    else:
        print(json.dumps(publish(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
