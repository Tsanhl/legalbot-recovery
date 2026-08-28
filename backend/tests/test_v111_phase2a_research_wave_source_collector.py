from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from scripts import collect_v111_phase2a_research_wave_sources as collector
from scripts import validate_v111_phase2a_official_research_waves as validator


def _wave(tmp_path: Path) -> Path:
    queue = json.loads(validator.DEFAULT_QUEUE.read_text(encoding="utf-8"))
    first = queue["records"][0]
    second = queue["records"][1]
    payload = {
        "schema": "test-wave",
        "source_queue_content_sha256": validator.EXPECTED_QUEUE_CONTENT_SHA256,
        "records": [
            {
                "row_id": first["row_id"],
                "queue_record_content_sha256": first["record_content_sha256"],
                "atomic_components": [
                    {
                        "proposition": "First proposition.",
                        "support_fit": "FULL",
                        "authorities": [
                            {
                                "citation": "Test Act",
                                "official_url": "https://www.legislation.gov.uk/ukpga/2015/15/section/49",
                                "exact_locators": ["section 49"],
                                "candidate_existing": True,
                                "source_admission_required": False,
                            }
                        ],
                    }
                ],
                "unresolved_holds": [],
            },
            {
                "row_id": second["row_id"],
                "queue_record_content_sha256": second["record_content_sha256"],
                "atomic_components": [
                    {
                        "proposition": "Second proposition.",
                        "support_fit": "PARTIAL",
                        "authorities": [
                            {
                                "citation": "Test Act",
                                "official_url": "https://www.legislation.gov.uk/ukpga/2015/15/part/1",
                                "exact_locators": ["section 49"],
                                "candidate_existing": True,
                                "source_admission_required": False,
                            }
                        ],
                    }
                ],
                "unresolved_holds": ["Application remains factual."],
            },
        ],
        "advisory_only": True,
        "owner_outcomes_applied": False,
        "source_admitted": False,
        "candidate_mutated": False,
        "embedding_run": False,
        "phase2b_authorized": False,
    }
    path = tmp_path / "wave.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _authority(
    *,
    citation: str,
    url: str,
    candidate_existing: bool | str,
    admission_required: bool | str,
    candidate_ids: list[str] | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "title": citation.split(" [", 1)[0],
        "citation": citation,
        "official_url": url,
        "exact_locators": ["paragraph 1"],
        "jurisdiction": "England and Wales",
        "currentness_finding": "Checked at the fixed source ceiling.",
        "later_treatment_finding": "Later-treatment review remains separately recorded.",
        "candidate_existing": candidate_existing,
        "source_admission_required": admission_required,
    }
    if candidate_ids is not None:
        value["candidate_source_version_ids"] = candidate_ids
    return value


def _research_wave(*rows: tuple[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "records": [
            {
                "row_id": row_id,
                "atomic_components": [
                    {
                        "proposition": f"Synthetic proposition for {row_id}.",
                        "support_fit": "FULL",
                        "authorities": [authority],
                    }
                ],
                "unresolved_holds": [],
            }
            for row_id, authority in rows
        ]
    }


def _candidate_source(identity: str, source_version_id: str) -> dict[str, str]:
    return {
        "authority_identity_id": identity,
        "source_version_id": source_version_id,
        "stable_identifier": identity,
        "content_sha256": "a" * 64,
        "canonical_url": "https://caselaw.nationalarchives.gov.uk/uksc/2015/36",
    }


def _canonical_set_binding(
    tmp_path: Path,
) -> tuple[collector.ArtifactBinding, tuple[collector.ArtifactBinding, ...]]:
    names = [f"research-live30-q{number:02d}-r2.json" for number in range(1, 32)]
    names.append(collector.CANONICAL_Q48_WAVE)
    wave_bindings = tuple(
        collector.ArtifactBinding(
            path=tmp_path / name,
            content_sha256=hashlib.sha256(f"content:{name}".encode()).hexdigest(),
            file_sha256=hashlib.sha256(f"file:{name}".encode()).hexdigest(),
        )
        for name in names
    )
    wave_entries = []
    for index, binding in enumerate(wave_bindings):
        entry_material = {
            "file_name": binding.path.name,
            "record_count": 6 if index == len(wave_bindings) - 1 else 10,
            "content_sha256": binding.content_sha256,
            "file_sha256": binding.file_sha256,
        }
        wave_entries.append(
            {
                **entry_material,
                "record_content_sha256": collector._sealed(entry_material),
            }
        )
    queue_material = {
        "file_name": validator.DEFAULT_QUEUE.name,
        "row_count": collector.EXPECTED_WAVE_ROW_COUNT,
        "content_sha256": validator.EXPECTED_QUEUE_CONTENT_SHA256,
        "file_sha256": "f" * 64,
    }
    material = {
        "schema": collector.CANONICAL_WAVE_SET_SCHEMA,
        "status": "CANONICAL_32_WAVES_BOUND_NOT_AUTHORIZING",
        "source_queue_content_sha256": validator.EXPECTED_QUEUE_CONTENT_SHA256,
        "source_queue_file_sha256": queue_material["file_sha256"],
        "queue_binding": {
            **queue_material,
            "record_content_sha256": collector._sealed(queue_material),
        },
        "exact_set_count": collector.EXPECTED_CANONICAL_WAVE_COUNT,
        "wave_count": collector.EXPECTED_CANONICAL_WAVE_COUNT,
        "total_row_count": collector.EXPECTED_WAVE_ROW_COUNT,
        "waves": wave_entries,
        "excluded_obsolete_wave_files": sorted(collector.OBSOLETE_Q48_WAVES),
        "advisory_only": True,
        "active_or_previous_write_authorized": False,
        "automatic_embedding": False,
        "automatic_indexing": False,
        "catalogue_mutated": False,
        "development30_authorized": False,
        "owner_decisions_applied": False,
        "owner_outcomes_applied": False,
        "source_collection_authorized": False,
        "source_collected": False,
        "source_admitted": False,
        "candidate_mutated": False,
        "embedding_run": False,
        "phase2b_authorized": False,
        "validation30_authorized": False,
        "live_activation_authorized": False,
    }
    payload = {**material, "artifact_content_sha256": collector._sealed(material)}
    path = tmp_path / "CANONICAL-RESEARCH-WAVE-BINDINGS-32.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return (
        collector.ArtifactBinding(
            path=path,
            content_sha256=payload["artifact_content_sha256"],
            file_sha256=collector._file_sha256(path),
        ),
        wave_bindings,
    )


def _synthetic_collect_canonical_set(binding: collector.ArtifactBinding) -> dict[str, Any]:
    return {
        "wave_count": 32,
        "queue_binding": {
            "file_name": binding.path.name,
            "file_sha256": binding.file_sha256,
        },
        "waves": [{"file_name": binding.path.name, "record_count": 0}],
    }


def test_normalized_download_url_uses_direct_official_representations() -> None:
    assert (
        collector.normalized_download_url("https://caselaw.nationalarchives.gov.uk/uksc/2024/33")
        == "https://caselaw.nationalarchives.gov.uk/uksc/2024/33/data.xml"
    )
    assert (
        collector.normalized_download_url(
            "https://www.legislation.gov.uk/ukpga/2015/15/section/49",
        )
        == "https://www.legislation.gov.uk/ukpga/2015/15/2026-08-14/data.xml"
    )
    assert (
        collector.normalized_download_url(
            "https://www.legislation.gov.uk/ukpga/Eliz2/5-6/11/section/2"
        )
        == "https://www.legislation.gov.uk/ukpga/Eliz2/5-6/11/2026-08-14/data.xml"
    )
    assert (
        collector.normalized_download_url(
            "https://www.legislation.gov.uk/eur/2016/679/article/28",
        )
        == "https://www.legislation.gov.uk/eur/2016/679/2026-08-14/data.xml"
    )


def test_normalized_download_url_preserves_explicit_legislation_qualifier() -> None:
    assert collector.normalized_download_url(
        "https://www.legislation.gov.uk/ukpga/2015/20/2026-04-30/section/1"
    ) == ("https://www.legislation.gov.uk/ukpga/2015/20/2026-04-30/data.xml")
    assert (
        collector.normalized_download_url(
            "https://www.legislation.gov.uk/uksi/2026/421/made/regulation/1"
        )
        == "https://www.legislation.gov.uk/uksi/2026/421/made/data.xml"
    )


def test_normalized_download_url_rejects_qualifier_after_fixed_ceiling() -> None:
    with pytest.raises(
        ValueError,
        match="phase2a_research_legislation_explicit_date_exceeds_source_ceiling",
    ):
        collector.normalized_download_url(
            "https://www.legislation.gov.uk/ukpga/2015/20/2026-08-15/section/1"
        )
    assert (
        collector.normalized_download_url(
            "https://www.legislation.gov.uk/eur/2016/679/2026-08-14/data.xml"
        )
        == "https://www.legislation.gov.uk/eur/2016/679/2026-08-14/data.xml"
    )


def test_normalized_download_url_rejects_non_official_host() -> None:
    with pytest.raises(ValueError, match="phase2a_research_source_url_invalid"):
        collector.normalized_download_url("https://example.com/case")


def test_build_targets_deduplicates_one_instrument_and_retains_rows(
    tmp_path: Path,
) -> None:
    targets = collector.build_targets([_wave(tmp_path)])

    assert len(targets) == 1
    assert targets[0]["download_url"].endswith("/ukpga/2015/15/2026-08-14/data.xml")
    assert len(targets[0]["row_ids"]) == 2
    assert targets[0]["exact_locators"] == ["section 49"]


@pytest.mark.parametrize(
    ("first_url", "second_url"),
    [
        (
            "https://www.justice.gov.uk/courts/procedure-rules/civil/rules/part57/pd_part57ad",
            "https://justice.gov.uk/courts/procedure-rules/civil/rules/part57/pd_part57ad/",
        ),
        (
            "https://www.sra.org.uk/solicitors/standards-regulations/",
            "https://sra.org.uk/solicitors/standards-regulations",
        ),
        (
            "https://www.tas-cas.org/en/general-information/frequently-asked-questions.html",
            "https://tas-cas.org/en/general-information/frequently-asked-questions.html/",
        ),
    ],
)
def test_untyped_official_authority_deduplicates_by_normalized_url(
    first_url: str, second_url: str
) -> None:
    wave = _research_wave(
        (
            "live60-q01:issue-01",
            _authority(
                citation="First descriptive label",
                url=first_url,
                candidate_existing=False,
                admission_required=True,
            ),
        ),
        (
            "live60-q02:issue-01",
            _authority(
                citation="Different descriptive label",
                url=second_url,
                candidate_existing=False,
                admission_required=True,
            ),
        ),
    )

    plans = collector._plan_authorities([("wave.json", wave)], {"sources": []})

    assert len(plans) == 1
    assert plans[0]["authority_identity_id"].startswith("official-url:https://")
    assert plans[0]["disposition"] == "FETCH_ABSENT_FALSE_TRUE"
    assert len(plans[0]["row_uses"]) == 2
    assert len(plans[0]["representation_targets"]) == 1


def test_same_untyped_official_url_with_mixed_states_is_one_no_fetch_hold() -> None:
    url = "https://www.justice.gov.uk/courts/procedure-rules/civil/rules/part54"
    wave = _research_wave(
        (
            "live60-q03:issue-01",
            _authority(
                citation="CPR Part 54",
                url=url,
                candidate_existing=False,
                admission_required=True,
            ),
        ),
        (
            "live60-q04:issue-01",
            _authority(
                citation="Judicial review procedure",
                url=f"{url}/",
                candidate_existing=True,
                admission_required=False,
            ),
        ),
    )

    plans = collector._plan_authorities([("wave.json", wave)], {"sources": []})

    assert len(plans) == 1
    assert plans[0]["disposition"] == "HOLD_NO_FETCH"
    assert plans[0]["representation_targets"] == []
    assert "WAVE_SOURCE_MEMBERSHIP_OR_ADMISSION_CONTRADICTION" in plans[0]["hold_reason_codes"]


def test_official_case_page_resolves_exactly_one_judgment_pdf() -> None:
    raw = b"""<html><a href="/uploads/uksc_2015_0015_judgment_abc.pdf">Judgment</a>
    <a href="/uploads/uksc_2015_0015_press_summary.pdf">Press summary</a></html>"""

    result = collector._official_judgment_pdf_url(
        raw,
        landing_url="https://www.supremecourt.uk/cases/uksc-2015-0015",
    )

    assert result == "https://www.supremecourt.uk/uploads/uksc_2015_0015_judgment_abc.pdf"


def test_unsupported_legislation_path_becomes_hold_not_plan_abort(
    tmp_path: Path,
) -> None:
    payload = _research_wave(
        (
            "live60-q01:issue-01",
            _authority(
                citation="Synthetic Northern Ireland instrument",
                url="https://www.legislation.gov.uk/nia/1998/1/section/1",
                candidate_existing=False,
                admission_required=True,
            ),
        )
    )
    path = tmp_path / "unsupported-wave.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    targets = collector.build_targets([path])

    assert len(targets) == 1
    assert targets[0]["download_url"] is None
    assert "phase2a_research_legislation_path_unsupported" in targets[0]["hold_reason_codes"]


def test_candidate_crosscheck_holds_arnold_and_supply_act_conflicts() -> None:
    wave = _research_wave(
        (
            "live30-q26:issue-08",
            _authority(
                citation="Arnold v Britton [2015] UKSC 36",
                url="https://caselaw.nationalarchives.gov.uk/uksc/2015/36",
                candidate_existing=True,
                admission_required=False,
                candidate_ids=["arnold-v1"],
            ),
        ),
        (
            "live60-q52:issue-01",
            _authority(
                citation="Arnold v Britton [2015] UKSC 36",
                url="https://www.supremecourt.uk/cases/uksc-2013-0193",
                candidate_existing=False,
                admission_required=True,
                candidate_ids=[],
            ),
        ),
        (
            "live30-q01:issue-01",
            _authority(
                citation="Supply of Goods and Services Act 1982, s 13",
                url="https://www.legislation.gov.uk/ukpga/1982/29/section/13",
                candidate_existing=True,
                admission_required=False,
                candidate_ids=["supply-v1"],
            ),
        ),
        (
            "live30-q24:issue-01",
            _authority(
                citation="Supply of Goods and Services Act 1982, s 13",
                url="https://www.legislation.gov.uk/ukpga/1982/29",
                candidate_existing=False,
                admission_required=True,
                candidate_ids=[],
            ),
        ),
    )
    candidate = {
        "sources": [
            _candidate_source("neutral-citation:[2015] UKSC 36", "arnold-v1"),
            _candidate_source("ukpga:1982:29", "supply-v1"),
        ]
    }

    plans = collector._plan_authorities([("wave.json", wave)], candidate)

    assert len(plans) == 2
    assert {plan["disposition"] for plan in plans} == {"HOLD_NO_FETCH"}
    assert all(plan["download_url"] is None for plan in plans)
    assert all(
        "WAVE_SOURCE_MEMBERSHIP_OR_ADMISSION_CONTRADICTION" in plan["hold_reason_codes"]
        for plan in plans
    )


def test_made_si_candidate_alias_is_present_not_a_new_fetch() -> None:
    wave = _research_wave(
        (
            "live60-q46:issue-05",
            _authority(
                citation="Trade Secrets (Enforcement, etc.) Regulations 2018",
                url="https://www.legislation.gov.uk/uksi/2018/597/regulation/10",
                candidate_existing=True,
                admission_required=False,
                candidate_ids=["trade-secrets-v1"],
            ),
        )
    )
    candidate = {
        "sources": [
            _candidate_source("uksi:2018:597:made", "trade-secrets-v1"),
        ]
    }

    plans = collector._plan_authorities([("wave.json", wave)], candidate)

    assert len(plans) == 1
    assert plans[0]["authority_identity_id"] == "uksi:2018:597:made"
    assert plans[0]["disposition"] == "CANDIDATE_PRESENT_NO_FETCH"
    assert plans[0]["download_url"] is None


def test_same_uksc_authority_via_tna_and_uksc_alias_is_one_fetch_target() -> None:
    wave = _research_wave(
        (
            "live60-q41:issue-01",
            _authority(
                citation="Kabab-Ji SAL v Kout Food Group [2021] UKSC 48",
                url="https://caselaw.nationalarchives.gov.uk/uksc/2021/48",
                candidate_existing=False,
                admission_required=True,
                candidate_ids=[],
            ),
        ),
        (
            "live60-q41:issue-02",
            _authority(
                citation="Kabab-Ji SAL v Kout Food Group [2021] UKSC 48",
                url="https://www.supremecourt.uk/cases/uksc-2020-0036",
                candidate_existing=False,
                admission_required=True,
                candidate_ids=[],
            ),
        ),
    )

    plans = collector._plan_authorities([("wave.json", wave)], {"sources": []})

    assert len(plans) == 1
    plan = plans[0]
    assert plan["authority_identity_id"] == "neutral-citation:[2021] UKSC 48"
    assert plan["disposition"] == "FETCH_ABSENT_FALSE_TRUE"
    assert plan["download_url"] == ("https://caselaw.nationalarchives.gov.uk/uksc/2021/48/data.xml")
    assert len(plan["official_urls"]) == 2
    assert len(plan["row_uses"]) == 2
    assert len(plan["representation_targets"]) == 2
    assert plan["representation_targets"][0]["representation_role"] == (
        "PROPOSED_ADMISSION_REPRESENTATION"
    )
    assert plan["representation_targets"][1]["representation_role"] == (
        "CORROBORATING_ALIAS_REPRESENTATION"
    )


def test_composite_authority_is_a_no_fetch_hold() -> None:
    wave = _research_wave(
        (
            "live60-q31:issue-01",
            _authority(
                citation=(
                    "R v Jogee; Ruddock v The Queen [2016] UKSC 8; Odunewu v R [2026] EWCA Crim 444"
                ),
                url="https://caselaw.nationalarchives.gov.uk/uksc/2016/8",
                candidate_existing=False,
                admission_required=True,
                candidate_ids=[],
            ),
        )
    )

    plans = collector._plan_authorities([("wave.json", wave)], {"sources": []})

    assert len(plans) == 1
    assert plans[0]["disposition"] == "HOLD_NO_FETCH"
    assert plans[0]["download_url"] is None
    assert plans[0]["hold_reason_codes"] == ["COMPOSITE_AUTHORITY_IDENTITY_HOLD"]


def test_composite_neutral_citations_split_between_title_and_citation_are_held() -> None:
    authority = _authority(
        citation="R v Jogee [2016] UKSC 8",
        url="https://caselaw.nationalarchives.gov.uk/uksc/2016/8",
        candidate_existing=False,
        admission_required=True,
    )
    authority["title"] = "R v Jogee and Odunewu v R [2026] EWCA Crim 444"
    wave = _research_wave(("live60-q31:issue-01", authority))

    plans = collector._plan_authorities([("wave.json", wave)], {"sources": []})

    assert plans[0]["disposition"] == "HOLD_NO_FETCH"
    assert plans[0]["representation_targets"] == []
    assert "COMPOSITE_AUTHORITY_IDENTITY_HOLD" in plans[0]["hold_reason_codes"]


def test_repeated_same_instrument_is_not_a_composite_identity() -> None:
    wave = _research_wave(
        (
            "live60-q31:issue-02",
            _authority(
                citation="Companies Act 2006, s 1; Companies Act 2006, s 2",
                url="https://www.legislation.gov.uk/ukpga/2006/46",
                candidate_existing=False,
                admission_required=True,
            ),
        )
    )

    plans = collector._plan_authorities([("wave.json", wave)], {"sources": []})

    assert plans[0]["authority_identity_id"] == "ukpga:2006:46"
    assert plans[0]["disposition"] == "FETCH_ABSENT_FALSE_TRUE"


def test_composite_legislation_authority_is_a_no_fetch_hold() -> None:
    wave = _research_wave(
        (
            "live30-q28:issue-01",
            _authority(
                citation=(
                    "Insolvency Act 1986, s 335A; Trusts of Land and "
                    "Appointment of Trustees Act 1996, s 15(4)"
                ),
                url="https://www.legislation.gov.uk/ukpga/1986/45/section/335A",
                candidate_existing=False,
                admission_required=True,
                candidate_ids=[],
            ),
        )
    )

    plans = collector._plan_authorities([("wave.json", wave)], {"sources": []})

    assert plans[0]["disposition"] == "HOLD_NO_FETCH"
    assert "COMPOSITE_AUTHORITY_IDENTITY_HOLD" in plans[0]["hold_reason_codes"]


def test_composite_fca_cobs_modules_are_a_no_fetch_hold() -> None:
    wave = _research_wave(
        (
            "live60-q44:issue-04",
            _authority(
                citation=("FCA Handbook, COBS 2.2A.2R-2.2A.3R and 14.3A.7R-14.3A.9R"),
                url=(
                    "https://handbook.fca.org.uk/handbook/cobs2/cobs2s2"
                    "?date=2026-08-14&timeline=true"
                ),
                candidate_existing=False,
                admission_required=True,
                candidate_ids=[],
            ),
        )
    )

    plans = collector._plan_authorities([("wave.json", wave)], {"sources": []})

    assert plans[0]["disposition"] == "HOLD_NO_FETCH"
    assert plans[0]["representation_targets"] == []
    assert "COMPOSITE_AUTHORITY_IDENTITY_HOLD" in plans[0]["hold_reason_codes"]


def test_unknown_membership_is_a_no_fetch_hold() -> None:
    wave = _research_wave(
        (
            "live60-q01:issue-01",
            _authority(
                citation="Mutable professional guidance",
                url="https://www.sra.org.uk/solicitors/standards-regulations/",
                candidate_existing="unknown",
                admission_required="unknown",
            ),
        )
    )

    plans = collector._plan_authorities([("wave.json", wave)], {"sources": []})

    assert len(plans) == 1
    assert plans[0]["disposition"] == "HOLD_NO_FETCH"
    assert plans[0]["download_url"] is None
    assert "WAVE_SOURCE_MEMBERSHIP_OR_ADMISSION_UNKNOWN" in plans[0]["hold_reason_codes"]


def test_new_source_requires_complete_support_bearing_legal_review_metadata() -> None:
    authority = _authority(
        citation="DPP v Ziegler [2021] UKSC 23",
        url="https://caselaw.nationalarchives.gov.uk/uksc/2021/23",
        candidate_existing=False,
        admission_required=True,
    )
    authority.pop("currentness_finding")
    authority.pop("later_treatment_finding")
    wave = _research_wave(("live60-q01:issue-01", authority))

    plans = collector._plan_authorities([("wave.json", wave)], {"sources": []})

    assert len(plans) == 1
    assert plans[0]["disposition"] == "HOLD_NO_FETCH"
    assert "METADATA_INCOMPLETE" in plans[0]["hold_reason_codes"]
    assert plans[0]["support_bearing_use_count"] == 1
    assert plans[0]["metadata_complete_support_bearing_use_count"] == 0
    assert plans[0]["metadata_incomplete_reason_codes"] == [
        "CURRENTNESS_FINDING_MISSING",
        "JURISDICTION_FINDING_MISSING",
        "LATER_TREATMENT_FINDING_MISSING",
    ]


def test_one_complete_support_bearing_use_satisfies_identity_metadata_gate() -> None:
    incomplete = _authority(
        citation="DPP v Ziegler [2021] UKSC 23",
        url="https://caselaw.nationalarchives.gov.uk/uksc/2021/23",
        candidate_existing=False,
        admission_required=True,
    )
    incomplete.pop("currentness_finding")
    complete = _authority(
        citation="DPP v Ziegler [2021] UKSC 23",
        url="https://www.supremecourt.uk/cases/uksc-2019-0106",
        candidate_existing=False,
        admission_required=True,
    )
    wave = _research_wave(
        ("live60-q01:issue-01", incomplete),
        ("live60-q02:issue-01", complete),
    )

    plans = collector._plan_authorities([("wave.json", wave)], {"sources": []})

    assert len(plans) == 1
    assert plans[0]["disposition"] == "FETCH_ABSENT_FALSE_TRUE"
    assert plans[0]["support_bearing_use_count"] == 2
    assert plans[0]["metadata_complete_support_bearing_use_count"] == 1


def test_explicit_combined_legacy_metadata_field_is_deterministically_typed() -> None:
    authority = _authority(
        citation="DPP v Ziegler [2021] UKSC 23",
        url="https://caselaw.nationalarchives.gov.uk/uksc/2021/23",
        candidate_existing=False,
        admission_required=True,
    )
    for field in ("jurisdiction", "currentness_finding", "later_treatment_finding"):
        authority.pop(field)
    authority["jurisdiction_currentness_later_treatment_caveats"] = [
        "England and Wales jurisdiction; currentness checked as of the source ceiling; "
        "later treatment remains subject to owner review."
    ]

    result = collector.proposal_metadata_completeness(authority)

    assert result == {
        "status": "COMPLETE",
        "metadata_mode": "COMBINED_EXPLICIT_FIELD",
        "exact_locators_complete": True,
        "reason_codes": [],
    }


def test_non_support_bearing_use_cannot_make_new_identity_fetch_eligible() -> None:
    authority = _authority(
        citation="DPP v Ziegler [2021] UKSC 23",
        url="https://caselaw.nationalarchives.gov.uk/uksc/2021/23",
        candidate_existing=False,
        admission_required=True,
    )
    wave = _research_wave(("live60-q01:issue-01", authority))
    wave["records"][0]["atomic_components"][0]["support_fit"] = "NONE"

    plans = collector._plan_authorities([("wave.json", wave)], {"sources": []})

    assert plans[0]["disposition"] == "HOLD_NO_FETCH"
    assert plans[0]["support_bearing_use_count"] == 0
    assert "METADATA_INCOMPLETE" in plans[0]["hold_reason_codes"]


def test_proposal_identity_key_casefolds_official_url_identity() -> None:
    assert collector.proposal_identity_key(
        "official-url:https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:61976CJ0027"
    ) == ("official-url:https://eur-lex.europa.eu/legal-content/en/txt/?uri=celex:61976cj0027")


def test_recursive_privacy_gate_rejects_copied_nested_input() -> None:
    wave = _research_wave(
        (
            "live60-q01:issue-01",
            _authority(
                citation="Mutable professional guidance",
                url="https://www.sra.org.uk/solicitors/standards-regulations/",
                candidate_existing=False,
                admission_required=True,
            ),
        )
    )
    wave["records"][0]["atomic_components"][0]["proposition"] = (
        "Copied from /Users/example/private-seminar.docx"
    )

    with pytest.raises(
        ValueError,
        match="phase2a_research_source_privacy_gate_failed",
    ):
        collector._plan_authorities([("wave.json", wave)], {"sources": []})


def test_missing_official_url_is_preserved_as_no_fetch_hold() -> None:
    authority = {
        "title": "Unresolved authority",
        "citation": "Unresolved authority [2024] UKSC 99",
        "official_url": None,
        "exact_locators": [],
        "candidate_existing": "unknown",
        "source_admission_required": "unknown",
    }
    wave = _research_wave(("live60-q01:issue-02", authority))

    plans = collector._plan_authorities([("wave.json", wave)], {"sources": []})

    assert len(plans) == 1
    assert plans[0]["authority_identity_id"] == "neutral-citation:[2024] UKSC 99"
    assert plans[0]["disposition"] == "HOLD_NO_FETCH"
    assert plans[0]["official_urls"] == []
    assert "OFFICIAL_URL_MISSING" in plans[0]["hold_reason_codes"]


def test_bound_wave_requires_explicit_matching_content_and_file_digests(
    tmp_path: Path,
) -> None:
    material = {
        "schema": "test-wave",
        "source_queue_content_sha256": validator.EXPECTED_QUEUE_CONTENT_SHA256,
        "records": [],
        "advisory_only": True,
        "owner_outcomes_applied": False,
        "source_admitted": False,
        "candidate_mutated": False,
        "embedding_run": False,
        "phase2b_authorized": False,
    }
    payload = {**material, "artifact_content_sha256": collector._sealed(material)}
    path = tmp_path / "sealed-wave.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    binding = collector.ArtifactBinding(
        path=path,
        content_sha256=payload["artifact_content_sha256"],
        file_sha256=collector._file_sha256(path),
    )

    assert collector._load_bound_wave(binding) == payload
    with pytest.raises(ValueError, match="phase2a_research_source_wave_content_digest_invalid"):
        collector._load_bound_wave(
            collector.ArtifactBinding(
                path=path,
                content_sha256="0" * 64,
                file_sha256=binding.file_sha256,
            )
        )


def test_canonical_wave_set_requires_exact_bound_32_wave_set(tmp_path: Path) -> None:
    canonical_binding, wave_bindings = _canonical_set_binding(tmp_path)

    loaded = collector._load_canonical_wave_set(canonical_binding, wave_bindings)

    assert loaded["wave_count"] == 32
    assert {entry["file_name"] for entry in loaded["waves"]} == {
        binding.path.name for binding in wave_bindings
    }

    replaced = list(wave_bindings)
    original = replaced[0]
    replaced[0] = collector.ArtifactBinding(
        original.path,
        "0" * 64,
        original.file_sha256,
    )
    with pytest.raises(
        ValueError,
        match="phase2a_research_source_wave_bindings_not_canonical_set",
    ):
        collector._load_canonical_wave_set(canonical_binding, replaced)


def test_canonical_wave_set_rejects_obsolete_q48_revision(tmp_path: Path) -> None:
    canonical_binding, wave_bindings = _canonical_set_binding(tmp_path)
    value = json.loads(canonical_binding.path.read_text(encoding="utf-8"))
    material = dict(value)
    material.pop("artifact_content_sha256")
    replacement_entry = dict(material["waves"][-1])
    replacement_entry.pop("record_content_sha256")
    replacement_entry["file_name"] = "research-live60-q48-q50-r2.json"
    material["waves"][-1] = {
        **replacement_entry,
        "record_content_sha256": collector._sealed(replacement_entry),
    }
    payload = {**material, "artifact_content_sha256": collector._sealed(material)}
    canonical_binding.path.write_text(json.dumps(payload), encoding="utf-8")
    obsolete_bindings = (
        *wave_bindings[:-1],
        collector.ArtifactBinding(
            path=tmp_path / "research-live60-q48-q50-r2.json",
            content_sha256=wave_bindings[-1].content_sha256,
            file_sha256=wave_bindings[-1].file_sha256,
        ),
    )
    obsolete_binding = collector.ArtifactBinding(
        path=canonical_binding.path,
        content_sha256=payload["artifact_content_sha256"],
        file_sha256=collector._file_sha256(canonical_binding.path),
    )

    with pytest.raises(
        ValueError,
        match="phase2a_research_source_canonical_set_q48_revision_invalid",
    ):
        collector._load_canonical_wave_set(obsolete_binding, obsolete_bindings)


def test_xml_binding_has_raw_and_canonical_content_hashes(tmp_path: Path) -> None:
    plan_material = {
        "plan_id": "authority-plan-test",
        "authority_identity_id": "neutral-citation:[2021] UKSC 48",
        "official_urls": ["https://caselaw.nationalarchives.gov.uk/uksc/2021/48"],
        "citations": ["[2021] UKSC 48"],
        "titles": ["Kabab-Ji"],
        "exact_locators": ["paragraph 35"],
        "affected_row_ids": ["live60-q41:issue-01"],
        "row_uses": [],
        "download_url": "https://caselaw.nationalarchives.gov.uk/uksc/2021/48/data.xml",
    }
    plan = {
        **plan_material,
        "plan_content_sha256": collector._sealed(plan_material),
    }
    xml = b'<judgment xmlns="urn:test"><p id="1">Rule</p></judgment>'

    class _Client:
        pass

    original = collector._fetch
    collector._fetch = lambda _client, url: (url, 200, "application/xml", xml)
    try:
        record = collector._collect_plan(
            _Client(),
            plan,
            ordinal=1,
            staging_root=tmp_path,  # type: ignore[arg-type]
        )
    finally:
        collector._fetch = original

    assert record["result"] == "DOWNLOADED_QUARANTINED_BOUND"
    assert record["raw_sha256"] == collector._sha256(xml)
    assert len(record["canonical_content_sha256"]) == 64
    assert record["canonicalization_algorithm"] == "W3C_C14N_2_0_NO_COMMENTS"
    assert record["proposed_source_version_id"].startswith("proposed-source-version-")
    assert record["source_admitted"] is False
    assert record["candidate_mutated"] is False
    assert record["automatic_embedding"] is False


def test_direct_xml_returning_html_is_held_and_not_written(tmp_path: Path) -> None:
    plan_material = {
        "plan_id": "authority-plan-html-mismatch",
        "authority_identity_id": "ukpga:2015:15",
        "official_urls": ["https://www.legislation.gov.uk/ukpga/2015/15"],
        "citations": ["Consumer Rights Act 2015"],
        "titles": ["Consumer Rights Act 2015"],
        "exact_locators": ["section 49"],
        "affected_row_ids": ["live30-q01:issue-01"],
        "row_uses": [],
        "download_url": ("https://www.legislation.gov.uk/ukpga/2015/15/2026-08-14/data.xml"),
    }
    plan = {
        **plan_material,
        "plan_content_sha256": collector._sealed(plan_material),
    }

    class _Client:
        pass

    original = collector._fetch
    collector._fetch = lambda _client, url: (
        url,
        200,
        "text/html",
        b"<html>not XML</html>",
    )
    try:
        record = collector._collect_plan(
            _Client(),
            plan,
            ordinal=1,
            staging_root=tmp_path,  # type: ignore[arg-type]
        )
    finally:
        collector._fetch = original

    assert record["result"] == "REPRESENTATION_TYPE_MISMATCH_HELD"
    assert record["quarantine_member"] is None
    assert record["proposed_source_version_id"] is None
    assert record["hold_reason_codes"] == ["OFFICIAL_XML_REPRESENTATION_TYPE_MISMATCH"]
    assert list(tmp_path.iterdir()) == []


def test_collect_rejects_incomplete_wave_set_before_creating_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    material = {"records": [], "artifact_role": "synthetic-bound-wave"}
    payload = {**material, "artifact_content_sha256": collector._sealed(material)}
    wave_path = tmp_path / "wave.json"
    wave_path.write_text(json.dumps(payload), encoding="utf-8")
    binding = collector.ArtifactBinding(
        wave_path,
        payload["artifact_content_sha256"],
        collector._file_sha256(wave_path),
    )
    monkeypatch.setattr(
        collector.wave_validator,
        "validate_waves",
        lambda **_kwargs: {
            "status": "PASS_INCOMPLETE",
            "covered_row_count": 315,
            "missing_row_count": 1,
        },
    )
    monkeypatch.setattr(
        collector,
        "_load_canonical_wave_set",
        lambda *_args, **_kwargs: _synthetic_collect_canonical_set(binding),
    )
    destination = tmp_path / "quarantine"

    with pytest.raises(
        ValueError,
        match="phase2a_research_source_wave_coverage_not_exact_complete_316",
    ):
        collector.collect(
            queue_path=wave_path,
            wave_bindings=[binding],
            candidate_binding=binding,
            canonical_set_binding=binding,
            quarantine_root=destination,
            run_id="synthetic-incomplete",
        )

    assert not destination.exists()


def test_collect_is_private_transactional_and_non_authorizing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    material = {"records": [], "artifact_role": "synthetic-bound-wave"}
    payload = {**material, "artifact_content_sha256": collector._sealed(material)}
    wave_path = tmp_path / "wave.json"
    wave_path.write_text(json.dumps(payload), encoding="utf-8")
    binding = collector.ArtifactBinding(
        wave_path,
        payload["artifact_content_sha256"],
        collector._file_sha256(wave_path),
    )
    target = {
        "representation_target_id": "representation-target-test",
        "requested_url": ("https://caselaw.nationalarchives.gov.uk/uksc/2021/48/data.xml"),
        "selection_rank": 1,
        "representation_role": "PROPOSED_ADMISSION_REPRESENTATION",
        "source_official_urls": ["https://caselaw.nationalarchives.gov.uk/uksc/2021/48"],
    }
    plan_material = {
        "plan_id": "authority-plan-transaction",
        "authority_identity_id": "neutral-citation:[2021] UKSC 48",
        "authority_identity_comparison_key": "neutral-citation:[2021] uksc 48",
        "disposition": "FETCH_ABSENT_FALSE_TRUE",
        "official_urls": target["source_official_urls"],
        "citations": ["[2021] UKSC 48"],
        "titles": ["Kabab-Ji"],
        "exact_locators": ["paragraph 35"],
        "affected_row_ids": ["live60-q41:issue-01"],
        "row_uses": [],
        "download_url": target["requested_url"],
        "representation_targets": [target],
    }
    plan = {
        **plan_material,
        "plan_content_sha256": collector._sealed(plan_material),
    }
    monkeypatch.setattr(
        collector.wave_validator,
        "validate_waves",
        lambda **_kwargs: {
            "status": "PASS_COMPLETE",
            "covered_row_count": 316,
            "missing_row_count": 0,
        },
    )
    monkeypatch.setattr(
        collector,
        "_load_canonical_wave_set",
        lambda *_args, **_kwargs: _synthetic_collect_canonical_set(binding),
    )
    monkeypatch.setattr(collector, "_load_candidate", lambda _binding: {"sources": []})
    monkeypatch.setattr(
        collector,
        "_plan_authorities",
        lambda *_args, **_kwargs: (plan,),
    )
    xml = b"<judgment><p>Rule</p></judgment>"
    monkeypatch.setattr(
        collector,
        "_fetch",
        lambda _client, url: (url, 200, "application/xml", xml),
    )
    destination = tmp_path / "quarantine"

    manifest = collector.collect(
        queue_path=wave_path,
        wave_bindings=[binding],
        candidate_binding=binding,
        canonical_set_binding=binding,
        quarantine_root=destination,
        run_id="synthetic-transaction",
    )

    assert destination.is_dir()
    assert destination.stat().st_mode & 0o777 == 0o700
    assert (destination / "QUARANTINE-MANIFEST.json").stat().st_mode & 0o777 == 0o600
    assert len(manifest["representation_bindings"]) == 1
    assert manifest["representation_bindings"][0]["eligible_for_owner_packet"] is True
    assert manifest["fetch_eligible_identity_count"] == 1
    assert manifest["packet_builder_interface"]["fetch_eligible_authority_identity_keys"] == [
        "neutral-citation:[2021] uksc 48"
    ]
    assert (
        manifest["packet_builder_interface"]["fetch_eligible_authority_identity_set_sha256"]
        == manifest["fetch_eligible_identity_set_sha256"]
    )
    assert manifest["packet_builder_interface"]["eligible_representation_record_ids"] == [
        manifest["records"][0]["record_id"]
    ]
    for flag in (
        "owner_decisions_applied",
        "source_admission_authorized",
        "source_admitted",
        "catalogue_mutated",
        "source_scan_run",
        "candidate_mutated",
        "index_built",
        "automatic_indexing",
        "embedding_run",
        "automatic_embedding",
        "promotion_authorized",
        "active_pointer_write_authorized",
        "previous_pointer_write_authorized",
        "phase2b_authorized",
    ):
        assert manifest[flag] is False
    assert str(tmp_path) not in json.dumps(manifest)
    sealed_material = dict(manifest)
    supplied = sealed_material.pop("manifest_content_sha256")
    assert supplied == collector._sealed(sealed_material)


def test_failed_alias_holds_entire_authority_and_selected_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    material = {"records": [], "artifact_role": "synthetic-bound-wave"}
    payload = {**material, "artifact_content_sha256": collector._sealed(material)}
    wave_path = tmp_path / "wave.json"
    wave_path.write_text(json.dumps(payload), encoding="utf-8")
    binding = collector.ArtifactBinding(
        wave_path,
        payload["artifact_content_sha256"],
        collector._file_sha256(wave_path),
    )
    selected_url = "https://caselaw.nationalarchives.gov.uk/uksc/2021/48/data.xml"
    alias_url = "https://supremecourt.uk/uploads/uksc_2020_0036_judgment.pdf"
    targets = [
        {
            "representation_target_id": "representation-target-tna",
            "requested_url": selected_url,
            "selection_rank": 1,
            "representation_role": "PROPOSED_ADMISSION_REPRESENTATION",
            "source_official_urls": [selected_url],
        },
        {
            "representation_target_id": "representation-target-uksc",
            "requested_url": alias_url,
            "selection_rank": 2,
            "representation_role": "CORROBORATING_ALIAS_REPRESENTATION",
            "source_official_urls": [alias_url],
        },
    ]
    plan_material = {
        "plan_id": "authority-plan-alias-failure",
        "authority_identity_id": "neutral-citation:[2021] UKSC 48",
        "authority_identity_comparison_key": "neutral-citation:[2021] uksc 48",
        "disposition": "FETCH_ABSENT_FALSE_TRUE",
        "official_urls": [selected_url, alias_url],
        "citations": ["[2021] UKSC 48"],
        "titles": ["Kabab-Ji"],
        "exact_locators": ["paragraph 35"],
        "affected_row_ids": ["live60-q41:issue-01"],
        "row_uses": [],
        "download_url": selected_url,
        "representation_targets": targets,
    }
    plan = {**plan_material, "plan_content_sha256": collector._sealed(plan_material)}
    monkeypatch.setattr(
        collector,
        "_load_canonical_wave_set",
        lambda *_args, **_kwargs: _synthetic_collect_canonical_set(binding),
    )
    monkeypatch.setattr(
        collector.wave_validator,
        "validate_waves",
        lambda **_kwargs: {
            "status": "PASS_COMPLETE",
            "covered_row_count": 316,
            "missing_row_count": 0,
        },
    )
    monkeypatch.setattr(collector, "_load_candidate", lambda _binding: {"sources": []})
    monkeypatch.setattr(collector, "_plan_authorities", lambda *_args: (plan,))
    monkeypatch.setattr(
        collector,
        "_fetch",
        lambda _client, url: (
            (url, 200, "application/xml", b"<judgment>selected</judgment>")
            if url == selected_url
            else (url, 404, "text/html", b"")
        ),
    )

    manifest = collector.collect(
        queue_path=wave_path,
        wave_bindings=[binding],
        candidate_binding=binding,
        canonical_set_binding=binding,
        quarantine_root=tmp_path / "alias-failure-quarantine",
        run_id="synthetic-alias-failure",
    )

    assert len(manifest["representation_bindings"]) == 1
    assert manifest["representation_bindings"][0]["eligible_for_owner_packet"] is False
    assert manifest["representation_bindings"][0]["authority_representation_set_complete"] is False
    assert manifest["selected_admission_bindings"] == []
    assert len(manifest["held_selected_bindings"]) == 1
    assert manifest["packet_builder_interface"]["eligible_representation_record_ids"] == []
    assert manifest["packet_builder_interface"]["held_selected_record_ids"] == [
        manifest["records"][0]["record_id"]
    ]
    authority_hold = manifest["authority_collection_holds"][0]
    assert authority_hold["hold_type"] == "AUTHORITY_REPRESENTATION_SET_INCOMPLETE"
    assert authority_hold["selected_record_id"] == manifest["records"][0]["record_id"]
    assert authority_hold["failed_record_ids"] == [manifest["records"][1]["record_id"]]
    assert authority_hold["selected_binding_eligible"] is False


def test_transactional_commit_never_overwrites_existing_destination(
    tmp_path: Path,
) -> None:
    staging = tmp_path / ".staging"
    destination = tmp_path / "quarantine"
    staging.mkdir(mode=0o700)
    destination.mkdir(mode=0o700)
    marker = destination / "existing.json"
    marker.write_text("preserve", encoding="utf-8")

    with pytest.raises(ValueError, match="phase2a_research_source_quarantine_exists"):
        collector._commit_create_only(staging, destination)

    assert marker.read_text(encoding="utf-8") == "preserve"
    assert staging.is_dir()
    assert not (tmp_path / ".quarantine.create.lock").exists()


def test_alias_representation_is_bound_but_never_selected_for_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base_plan = {
        "plan_id": "authority-plan-aliases",
        "authority_identity_id": "neutral-citation:[2021] UKSC 48",
        "official_urls": [
            "https://caselaw.nationalarchives.gov.uk/uksc/2021/48",
            "https://supremecourt.uk/uploads/uksc_2020_0036_judgment.pdf",
        ],
        "citations": ["[2021] UKSC 48"],
        "titles": ["Kabab-Ji"],
        "exact_locators": ["paragraph 35"],
        "affected_row_ids": ["live60-q41:issue-01"],
        "row_uses": [],
        "download_url": ("https://caselaw.nationalarchives.gov.uk/uksc/2021/48/data.xml"),
    }
    plan = {**base_plan, "plan_content_sha256": collector._sealed(base_plan)}
    selected = {
        "representation_target_id": "representation-target-tna",
        "requested_url": base_plan["download_url"],
        "selection_rank": 1,
        "representation_role": "PROPOSED_ADMISSION_REPRESENTATION",
        "source_official_urls": [base_plan["official_urls"][0]],
    }
    alias = {
        "representation_target_id": "representation-target-uksc",
        "requested_url": base_plan["official_urls"][1],
        "selection_rank": 2,
        "representation_role": "CORROBORATING_ALIAS_REPRESENTATION",
        "source_official_urls": [base_plan["official_urls"][1]],
    }
    bodies = {
        selected["requested_url"]: ("application/xml", b"<judgment>TNA</judgment>"),
        alias["requested_url"]: ("application/pdf", b"%PDF-1.7 alias bytes"),
    }
    monkeypatch.setattr(
        collector,
        "_fetch",
        lambda _client, url: (url, 200, *bodies[url]),
    )

    first = collector._collect_plan(
        object(),  # type: ignore[arg-type]
        plan,
        ordinal=1,
        staging_root=tmp_path,
        representation_target=selected,
    )
    second = collector._collect_plan(
        object(),  # type: ignore[arg-type]
        plan,
        ordinal=2,
        staging_root=tmp_path,
        representation_target=alias,
    )

    assert first["raw_sha256"] != second["raw_sha256"]
    assert first["selected_for_proposed_admission"] is True
    assert first["proposed_source_version_id"] is not None
    assert second["selected_for_proposed_admission"] is False
    assert second["proposed_source_version_id"] is None
    assert second["representation_role"] == "CORROBORATING_ALIAS_REPRESENTATION"


def test_production_corpus_dry_fetch_identity_set_is_exactly_bound() -> None:
    wave_root = (
        collector.PROJECT_ROOT
        / "data/evaluations/phase2a-owner-review"
        / "LegalBot-Phase2A-2026-08-27-remediation-working-r1"
    )
    canonical_path = wave_root / "CANONICAL-RESEARCH-WAVE-BINDINGS-32.json"
    canonical_binding = collector.ArtifactBinding(
        path=canonical_path,
        content_sha256=("2fb9416e0e948a40157ca392e4d2b295b1de44a875b81b0c1c03d1cf76f14937"),
        file_sha256=("2a0207ed1f302636b29ba70586ce88a9a62fad6d46ed0b341195f0cdcb4074b2"),
    )
    canonical_value = json.loads(canonical_path.read_text(encoding="utf-8"))
    wave_bindings = tuple(
        collector.ArtifactBinding(
            path=wave_root / entry["file_name"],
            content_sha256=entry["content_sha256"],
            file_sha256=entry["file_sha256"],
        )
        for entry in canonical_value["waves"]
    )
    collector._load_canonical_wave_set(canonical_binding, wave_bindings)
    waves = [(binding.path.name, collector._load_bound_wave(binding)) for binding in wave_bindings]
    validation = validator.validate_waves(
        queue_path=validator.DEFAULT_QUEUE,
        wave_paths=[binding.path for binding in wave_bindings],
    )
    assert (
        validation["status"],
        validation["covered_row_count"],
        validation["missing_row_count"],
    ) == ("PASS_COMPLETE", 316, 0)

    candidate_path = (
        collector.PROJECT_ROOT
        / "data/evaluations/phase2a-owner-review"
        / "LegalBot-Phase2A-2026-08-27-final-owner-review-blocked"
        / "machine/candidate/approved-source-manifest.json"
    )
    candidate = collector._load_candidate(
        collector.ArtifactBinding(
            path=candidate_path,
            content_sha256=("b304ab1223987bf9b57d3e2560413b2f325c16213ae0071a45dface2e10dc206"),
            file_sha256=("0bbb1edb169c84a26e5f1d42e367f9e2f83fcdd9c652a9061980652f15979b21"),
        )
    )
    plans = collector._plan_authorities(waves, candidate)
    fetch_keys = collector.fetch_eligible_identity_keys(plans)

    assert len(fetch_keys) == 278
    assert collector.fetch_eligible_identity_set_sha256(plans) == (
        "3133440a3cd141110b4217918d48e87f80342d2987702ba7c696212a3a94f368"
    )
    metadata_holds = {
        plan["authority_identity_id"]
        for plan in plans
        if "METADATA_INCOMPLETE" in plan["hold_reason_codes"]
    }
    assert metadata_holds == {
        "neutral-citation:[2018] EWCA Civ 1307",
        "neutral-citation:[2023] UKSC 26",
        ("official-url:https://eur-lex.europa.eu/legal-content/EN/TXT?uri=CELEX%3A61976CJ0027"),
        ("official-url:https://eur-lex.europa.eu/legal-content/EN/TXT?uri=CELEX%3A61986CJ0062"),
        "ukpga:2002:40",
        "ukpga:2008:4",
    }
    plans_by_key = {
        collector.proposal_identity_key(plan["authority_identity_comparison_key"]): plan
        for plan in plans
    }
    for held_key in (
        "official-url:https://justice.gov.uk/courts/procedure-rules/civil/rules/part54",
        (
            "official-url:https://sra.org.uk/solicitors/standards-regulations/"
            "code-conduct-solicitors"
        ),
    ):
        assert plans_by_key[held_key]["disposition"] == "HOLD_NO_FETCH"
        assert held_key not in fetch_keys
