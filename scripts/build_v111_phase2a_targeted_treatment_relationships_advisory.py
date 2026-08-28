#!/usr/bin/env python3
"""Extract exact treatment contexts for five conditional official case leads.

The classification is a deterministic screen over explicit treatment phrases
in already quarantined UKSC/JCPC material.  It is advisory, non-exhaustive, and
cannot decide owner outcomes, admit a source, qualify a proposition, mutate a
candidate, or authorize a later phase.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
QUARANTINE_ROOT = PROJECT_ROOT / "data/quarantine/2026-08-24/phase2a-targeted-later-treatment-r42"
DEFAULT_LEADS = QUARANTINE_ROOT / "TARGETED-LATER-TREATMENT-LEADS-9.json"
DEFAULT_NO_RELIANCE = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review"
    / "LegalBot-Phase2AB-2026-08-25-r54-no-reliance-judgment-advisory"
    / "NO-585-RELIANCE-JUDGMENT-ADVISORY-6.json"
)
DEFAULT_OUTPUT = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review"
    / "LegalBot-Phase2AB-2026-08-25-r55-targeted-treatment-advisory"
)

EXPECTED_LEADS_CONTENT_SHA256 = "ad887ac1d18b06ed459b05471188cd6f999fa6b0580589edc4bbacc46cd902a9"
EXPECTED_NO_RELIANCE_CONTENT_SHA256 = (
    "b4092b9479f59b6b29c133f6b99e2526550957060ff8facf9ad4b92622c68026"
)
EXPECTED_RELATIONSHIPS = {
    "later-treatment-lead-003": {
        "target": "[2015] UKSC 66",
        "candidate": "[2017] UKSC 29",
        "required_phrases": (
            "This leaves unanswered the critical question",
            "what connection, nexus or link is sufficient?",
        ),
        "advisory_relationship": "LIMITED_FORMULATION_NOT_OUTCOME",
        "recommended_owner_outcome": "LIMITED",
    },
    "later-treatment-lead-004": {
        "target": "[2021] UKSC 21",
        "candidate": "[2024] UKSC 1",
        "required_phrases": (
            "illustrates the importance of this consideration",
            "The Supreme Court held that",
        ),
        "advisory_relationship": "AFFIRMED_OR_APPLIED",
        "recommended_owner_outcome": "AFFIRMED",
    },
    "later-treatment-lead-007": {
        "target": "[2024] UKSC 28",
        "candidate": "[2026] UKSC 1",
        "required_phrases": ("discussion and acceptance", "somewhat analogously"),
        "advisory_relationship": "AFFIRMED_OR_APPLIED_BY_ANALOGY",
        "recommended_owner_outcome": "AFFIRMED",
    },
    "later-treatment-lead-008": {
        "target": "[2023] UKSC 48",
        "candidate": "[2025] UKPC 6",
        "required_phrases": (
            "recent authoritative restatement",
            "the long-standing general rule in civil cases",
        ),
        "advisory_relationship": "AFFIRMED_PERSUASIVE_APPLICATION",
        "recommended_owner_outcome": "AFFIRMED",
    },
    "later-treatment-lead-009": {
        "target": "[2015] UKSC 67",
        "candidate": "[2024] UKSC 6",
        "required_phrases": ("Under the modern test formulated", "must not impose"),
        "advisory_relationship": "AFFIRMED_OR_APPLIED",
        "recommended_owner_outcome": "AFFIRMED",
    },
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PARAGRAPH_MARKER = re.compile(r"(?<!\d)(?P<number>\d{1,3})\.\s")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_treatment_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_treatment_input_must_be_object")
    return value


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or supplied != _sealed(material):
        raise ValueError(code)
    return supplied


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _citation_paragraph(text: str, citation: str) -> tuple[int, int, str]:
    occurrences = [match.start() for match in re.finditer(re.escape(citation), text)]
    if len(occurrences) != 1:
        raise ValueError("phase2a_treatment_target_citation_occurrence_invalid")
    position = occurrences[0]
    markers = list(_PARAGRAPH_MARKER.finditer(text))
    prior = [marker for marker in markers if marker.start() < position]
    following = [marker for marker in markers if marker.start() > position]
    if not prior or not following:
        raise ValueError("phase2a_treatment_paragraph_boundary_missing")
    start = prior[-1].start()
    end = following[0].start()
    paragraph = text[start:end].strip()
    if citation not in paragraph or not 40 <= len(paragraph) <= 5_000:
        raise ValueError("phase2a_treatment_paragraph_invalid")
    return start, end, paragraph


def build_treatment_relationships(
    *, leads_path: Path, no_reliance_path: Path, output_root: Path
) -> dict[str, Any]:
    """Build the five-row exact-context advisory artifact."""

    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_treatment_output_already_exists")
    leads = _load_object(leads_path)
    leads_sha256 = _verify_seal(
        leads, "artifact_content_sha256", "phase2a_treatment_leads_seal_invalid"
    )
    if leads_sha256 != EXPECTED_LEADS_CONTENT_SHA256:
        raise ValueError("phase2a_treatment_leads_identity_invalid")
    records = leads.get("records")
    if (
        not isinstance(records, list)
        or len(records) != 9
        or leads.get("targeted_search_is_exhaustive") is not False
        or leads.get("absence_of_other_hits_proves_no_later_treatment") is not False
        or leads.get("source_admission_authorized") is not False
        or leads.get("candidate_mutated") is not False
        or leads.get("phase2b_authorized") is not False
        or leads.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_treatment_leads_boundary_invalid")

    no_reliance = _load_object(no_reliance_path)
    no_reliance_sha256 = _verify_seal(
        no_reliance,
        "artifact_content_sha256",
        "phase2a_treatment_no_reliance_seal_invalid",
    )
    if (
        no_reliance_sha256 != EXPECTED_NO_RELIANCE_CONTENT_SHA256
        or no_reliance.get("remaining_conditional_later_treatment_lead_count") != 5
        or set(no_reliance.get("remaining_conditional_later_treatment_lead_ids") or [])
        != set(EXPECTED_RELATIONSHIPS)
    ):
        raise ValueError("phase2a_treatment_no_reliance_boundary_invalid")

    records_by_id: dict[str, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("phase2a_treatment_lead_record_invalid")
        _verify_seal(
            record,
            "lead_content_sha256",
            "phase2a_treatment_lead_record_seal_invalid",
        )
        lead_id = str(record.get("lead_id") or "")
        if lead_id in records_by_id:
            raise ValueError("phase2a_treatment_duplicate_lead")
        records_by_id[lead_id] = record
    if not set(EXPECTED_RELATIONSHIPS).issubset(records_by_id):
        raise ValueError("phase2a_treatment_required_leads_missing")

    recommendations: list[dict[str, Any]] = []
    for lead_id, rule in EXPECTED_RELATIONSHIPS.items():
        lead = records_by_id[lead_id]
        if (
            lead.get("candidate_neutral_citation") != rule["candidate"]
            or lead.get("target_neutral_citations") != [rule["target"]]
            or lead.get("targeted_search_is_exhaustive") is not False
            or lead.get("source_admitted") is not False
            or lead.get("indexed") is not False
            or lead.get("embedded") is not False
        ):
            raise ValueError("phase2a_treatment_lead_boundary_invalid")
        derived = lead.get("derived_review_text")
        if not isinstance(derived, dict):
            raise ValueError("phase2a_treatment_derived_text_record_invalid")
        path = (PROJECT_ROOT / str(derived.get("relative_path") or "")).resolve(strict=True)
        if (
            not path.is_relative_to(QUARANTINE_ROOT)
            or path.is_symlink()
            or _sha256_file(path) != derived.get("sha256")
            or path.stat().st_size != derived.get("bytes")
            or derived.get("is_official_source_representation") is not False
        ):
            raise ValueError("phase2a_treatment_derived_text_integrity_invalid")
        text = path.read_text(encoding="utf-8")
        start, end, paragraph = _citation_paragraph(text, str(rule["target"]))
        if any(str(phrase) not in paragraph for phrase in rule["required_phrases"]):
            raise ValueError("phase2a_treatment_explicit_phrase_fingerprint_invalid")
        context_material = {
            "schema": "legalbot.v111.phase2a.targeted-treatment-exact-context.v1",
            "derived_review_text_sha256": derived["sha256"],
            "start_character": start,
            "end_character_exclusive": end,
            "exact_text": paragraph,
            "exact_text_sha256": _sha256(paragraph.encode("utf-8")),
        }
        material = {
            "schema": "legalbot.v111.phase2a.targeted-treatment-advisory-row.v1",
            "source_lead_content_sha256": lead["lead_content_sha256"],
            "lead_id": lead_id,
            "target_neutral_citation": rule["target"],
            "candidate_neutral_citation": rule["candidate"],
            "candidate_case_name": lead["candidate_case_name"],
            "candidate_judgment_date": lead["candidate_judgment_date"],
            "court_weight": lead["court_weight"],
            "exact_treatment_context": {
                **context_material,
                "context_content_sha256": _sealed(context_material),
            },
            "explicit_required_phrases": list(rule["required_phrases"]),
            "advisory_relationship": rule["advisory_relationship"],
            "recommended_owner_outcome": rule["recommended_owner_outcome"],
            "advisory_method": (
                "DETERMINISTIC_EXPLICIT_TREATMENT_PHRASE_SCREEN_NOT_LEGAL_DECISION"
            ),
            "targeted_search_is_exhaustive": False,
            "absence_of_other_hits_proves_no_later_treatment": False,
            "final_relationship_depends_on_exact_proposition_scope": True,
            "recommended_source_disposition_if_owner_approves_relationship": (
                "ADMIT_FOR_APPROVED_PROPOSITION_LEVEL_LATER_TREATMENT_USE"
            ),
            "owner_outcome": None,
            "owner_decision_required": True,
            "proposition_level_materiality_approved": False,
            "source_admitted": False,
            "indexed": False,
            "embedded": False,
            "candidate_mutated": False,
            "technical_qualification_assigned": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        recommendations.append({**material, "record_content_sha256": _sealed(material)})

    material = {
        "schema": "legalbot.v111.phase2a.targeted-treatment-relationships-advisory.v1",
        "status": "FIVE_EXACT_TREATMENT_CONTEXTS_READY_OWNER_DECISIONS_REQUIRED",
        "source_leads_content_sha256": leads_sha256,
        "source_no_reliance_content_sha256": no_reliance_sha256,
        "record_count": len(recommendations),
        "records": recommendations,
        "classification_counts": {
            "AFFIRMED": 4,
            "LIMITED": 1,
        },
        "targeted_search_is_exhaustive": False,
        "absence_of_other_hits_proves_no_later_treatment": False,
        "owner_decisions_applied": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    artifact = {**material, "artifact_content_sha256": _sealed(material)}
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_treatment_output_mode_invalid")
    name = "TARGETED-LATER-TREATMENT-RELATIONSHIPS-ADVISORY-5.json"
    _write_exclusive(output_root / name, _pretty_json(artifact))
    outcome = (
        "FIVE EXACT OFFICIAL TREATMENT CONTEXTS VERIFIED. RELATIONSHIP AND "
        "PROPOSITION-LEVEL SOURCE-ADMISSION DECISIONS REQUIRE OWNER APPROVAL. "
        "PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED.\n"
    )
    _write_exclusive(output_root / "OUTCOME.txt", outcome.encode())
    sums = "".join(
        f"{_sha256_file(output_root / item)}  {item}\n" for item in (name, "OUTCOME.txt")
    )
    _write_exclusive(output_root / "SHA256SUMS.txt", sums.encode())
    return artifact


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--leads", type=Path, default=DEFAULT_LEADS)
    parser.add_argument("--no-reliance", type=Path, default=DEFAULT_NO_RELIANCE)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> None:
    args = _arguments()
    result = build_treatment_relationships(
        leads_path=args.leads,
        no_reliance_path=args.no_reliance,
        output_root=args.output_root,
    )
    print(
        json.dumps(
            {
                "output_root": str(args.output_root),
                "status": result["status"],
                "record_count": result["record_count"],
                "classification_counts": result["classification_counts"],
                "artifact_content_sha256": result["artifact_content_sha256"],
                "phase2b_authorized": result["phase2b_authorized"],
                "development30_authorized": result["development30_authorized"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
