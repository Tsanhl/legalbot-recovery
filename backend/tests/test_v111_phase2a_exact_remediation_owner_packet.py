from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from backend.app.retrieval.source_manifest import approved_source_manifest_sha256
from scripts import build_v111_phase2a_exact_remediation_owner_packet as builder


def test_direct_script_help_resolves_repository_imports() -> None:
    script = builder.PROJECT_ROOT / "scripts/build_v111_phase2a_exact_remediation_owner_packet.py"

    result = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=builder.PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "ModuleNotFoundError" not in result.stderr
    assert "--canonical-set-binding PATH CONTENT_SHA256 FILE_SHA256" in result.stdout
    assert "--quarantine-manifest PATH CONTENT_SHA256 FILE_SHA256" in result.stdout
    assert "--wave PATH CONTENT_SHA256 FILE_SHA256" in result.stdout


def test_production_canonical_wave_set_constants_bind_exact_artifact() -> None:
    value = json.loads(builder.DEFAULT_CANONICAL_SET_PATH.read_bytes())

    assert builder.DEFAULT_CANONICAL_SET_PATH.name == ("CANONICAL-RESEARCH-WAVE-BINDINGS-32.json")
    assert value["artifact_content_sha256"] == builder.CANONICAL_SET_CONTENT_SHA256
    assert builder._file_sha256(builder.DEFAULT_CANONICAL_SET_PATH) == (
        builder.CANONICAL_SET_FILE_SHA256
    )


def test_real_canonical_corpus_builder_and_collector_fetch_sets_equal_278() -> None:
    canonical = json.loads(builder.DEFAULT_CANONICAL_SET_PATH.read_bytes())
    wave_bindings = [
        builder.BoundArtifact(
            builder.WORKING_ROOT / entry["file_name"],
            entry["content_sha256"],
            entry["file_sha256"],
        )
        for entry in canonical["waves"]
    ]
    waves = builder._load_waves(wave_bindings)
    builder._load_canonical_wave_set(
        builder.BoundArtifact(
            builder.DEFAULT_CANONICAL_SET_PATH,
            builder.CANONICAL_SET_CONTENT_SHA256,
            builder.CANONICAL_SET_FILE_SHA256,
        ),
        wave_bindings=wave_bindings,
    )
    candidate = builder._load_candidate(
        builder.BoundArtifact(
            builder.DEFAULT_CANDIDATE_PATH,
            builder.CANDIDATE_CONTENT_SHA256,
            builder.CANDIDATE_FILE_SHA256,
        )
    )
    candidate_index = builder._candidate_index(candidate)
    plans, plans_by_identity, fetch_keys, fetch_digest = builder._collector_plan_set(
        wave_bindings=wave_bindings,
        waves=waves,
        candidate=candidate,
    )
    queue = builder._load_queue(
        builder.BoundArtifact(
            builder.DEFAULT_QUEUE_PATH,
            builder.QUEUE_CONTENT_SHA256,
            builder.QUEUE_FILE_SHA256,
        )
    )
    queue_by_row = {record["row_id"]: record for record in queue["records"]}
    decisions = [
        builder._research_decision(
            record=record,
            queue_record=queue_by_row[record["row_id"]],
            wave_binding=binding,
            candidate_index=candidate_index,
            collector_plans_by_identity=plans_by_identity,
        )
        for binding, wave in zip(wave_bindings, waves, strict=True)
        for record in wave["records"]
    ]
    proposals = builder._source_admission_proposals(
        decisions,
        eligible_identity_keys=fetch_keys,
    )
    builder_keys = tuple(proposal["canonical_authority_identity_key"] for proposal in proposals)

    assert len(fetch_keys) == 278
    assert len(proposals) == 278
    assert builder_keys == fetch_keys
    assert fetch_digest == ("3133440a3cd141110b4217918d48e87f80342d2987702ba7c696212a3a94f368")
    forbidden = {
        "identity:official-url:https://justice.gov.uk/courts/procedure-rules/civil/rules/part54",
        "identity:official-url:https://sra.org.uk/solicitors/"
        "standards-regulations/code-conduct-solicitors",
    }
    assert forbidden.isdisjoint(builder_keys)
    metadata_holds = {
        builder.source_collector.proposal_identity_key(plan["authority_identity_comparison_key"])
        for plan in plans
        if "METADATA_INCOMPLETE" in plan["hold_reason_codes"]
    }
    assert metadata_holds == {
        "neutral-citation:[2018] ewca civ 1307",
        "neutral-citation:[2023] uksc 26",
        "official-url:https://eur-lex.europa.eu/legal-content/en/txt?uri=celex%3a61976cj0027",
        "official-url:https://eur-lex.europa.eu/legal-content/en/txt?uri=celex%3a61986cj0062",
        "ukpga:2002:40",
        "ukpga:2008:4",
    }


def test_immutable_real_quarantine_manifest_accounts_for_all_278_fetch_identities() -> None:
    manifest_path = (
        builder.REVIEW_ROOT
        / "LegalBot-Phase2A-2026-08-28-source-quarantine"
        / "QUARANTINE-MANIFEST.json"
    )
    expected_content_sha256 = "b6d900b23232379a4d6c19d313f35c47e0758ce5e0bb6eb04008f9eba07a3819"
    expected_file_sha256 = "f482366a2ba0d9f636c56104d632767a8eadd6e9a9625d50ef5391a5f62995eb"
    manifest = json.loads(manifest_path.read_bytes())
    assert manifest["manifest_content_sha256"] == expected_content_sha256
    assert builder._file_sha256(manifest_path) == expected_file_sha256

    canonical = json.loads(builder.DEFAULT_CANONICAL_SET_PATH.read_bytes())
    wave_bindings = [
        builder.BoundArtifact(
            builder.WORKING_ROOT / entry["file_name"],
            entry["content_sha256"],
            entry["file_sha256"],
        )
        for entry in canonical["waves"]
    ]
    waves = builder._load_waves(wave_bindings)
    candidate_binding = builder.BoundArtifact(
        builder.DEFAULT_CANDIDATE_PATH,
        builder.CANDIDATE_CONTENT_SHA256,
        builder.CANDIDATE_FILE_SHA256,
    )
    candidate = builder._load_candidate(candidate_binding)
    _, _, fetch_keys, fetch_digest = builder._collector_plan_set(
        wave_bindings=wave_bindings,
        waves=waves,
        candidate=candidate,
    )
    (
        _,
        selected_by_key,
        held_selected_by_key,
        authority_collection_holds_by_key,
        _,
        _,
    ) = builder._load_representation_bindings(
        builder.BoundArtifact(
            manifest_path,
            expected_content_sha256,
            expected_file_sha256,
        ),
        queue_binding=builder.BoundArtifact(
            builder.DEFAULT_QUEUE_PATH,
            builder.QUEUE_CONTENT_SHA256,
            builder.QUEUE_FILE_SHA256,
        ),
        candidate_binding=candidate_binding,
        canonical_set_binding=builder.BoundArtifact(
            builder.DEFAULT_CANONICAL_SET_PATH,
            builder.CANONICAL_SET_CONTENT_SHA256,
            builder.CANONICAL_SET_FILE_SHA256,
        ),
        wave_bindings=wave_bindings,
        expected_fetch_identity_keys=fetch_keys,
        expected_fetch_identity_set_sha256=fetch_digest,
    )

    assert len(fetch_keys) == 278
    assert len(selected_by_key) == 247
    assert len(held_selected_by_key) == 2
    assert len(authority_collection_holds_by_key) == 31
    assert set(selected_by_key).isdisjoint(authority_collection_holds_by_key)
    assert set(selected_by_key) | set(authority_collection_holds_by_key) == set(fetch_keys)
    assert set(held_selected_by_key).issubset(authority_collection_holds_by_key)


def _bound_wave(path: Path) -> builder.BoundArtifact:
    value = json.loads(path.read_bytes())
    material = dict(value)
    supplied = material.pop("artifact_content_sha256", None)
    content_sha256 = builder._sealed(material if supplied is not None else value)
    return builder.BoundArtifact(path, content_sha256, builder._file_sha256(path))


def _wave_record(queue_record: dict[str, Any], ordinal: int) -> dict[str, Any]:
    authorities: list[dict[str, Any]] = []
    if ordinal in {1, 2}:
        authorities = [
            {
                "title": "Synthetic Test Act 2099",
                "citation": f"Synthetic Test Act 2099, s {48 + ordinal}",
                "official_url": (
                    f"https://www.legislation.gov.uk/ukpga/2099/999/section/{48 + ordinal}"
                ),
                "exact_locators": [f"section {48 + ordinal}"],
                "candidate_existing": False,
                "candidate_source_version_ids": [],
                "source_admission_required": True,
                "caveats": ["The transaction facts remain unresolved."],
                **(
                    {
                        "jurisdiction_currentness_later_treatment_caveats": [
                            "United Kingdom jurisdiction.",
                            "Currentness checked at the source ceiling.",
                            "Later treatment hold remains retained.",
                        ]
                    }
                    if ordinal == 2
                    else {
                        "jurisdiction": ("United Kingdom statute with application caveats."),
                        "currentness_finding": ("Target-date official page reviewed."),
                        "later_treatment_finding": ("Effects review remains retained."),
                    }
                ),
            }
        ]
    elif ordinal == 3:
        authorities = [
            {
                "title": "Existing candidate authority",
                "citation": "Existing candidate authority",
                "official_url": ("https://www.legislation.gov.uk/ukpga/1977/50/section/3"),
                "exact_locators": ["section 3"],
                "jurisdiction": "United Kingdom statute.",
                "currentness_finding": "Candidate currentness record reviewed.",
                "later_treatment_finding": "Candidate treatment hold retained.",
                "candidate_existing": True,
                "source_admission_required": False,
                "caveats": ["Candidate source-version binding is absent."],
            }
        ]
    elif ordinal == 4:
        authorities = [
            {
                "title": "Mutable official guidance",
                "citation": "Mutable official guidance",
                "official_url": "https://www.sra.org.uk/solicitors/guidance/misuse-ai/",
                "exact_locators": ["guidance page"],
                "jurisdiction": "England and Wales professional guidance.",
                "currentness_finding": "Mutable official page checked.",
                "later_treatment_finding": "Later revision hold retained.",
                "candidate_existing": False,
                "source_admission_required": "unknown",
                "caveats": ["No immutable representation has been selected."],
            }
        ]
    elif ordinal == 5:
        authorities = [
            {
                "title": "Identity reconciliation authority",
                "citation": "Identity reconciliation authority",
                "official_url": ("https://caselaw.nationalarchives.gov.uk/uksc/2024/33"),
                "exact_locators": ["paragraph 1"],
                "jurisdiction": "United Kingdom Supreme Court.",
                "currentness_finding": "Official page checked.",
                "later_treatment_finding": "Later treatment hold retained.",
                "candidate_existing": "unknown",
                "source_admission_required": "unknown",
                "caveats": ["Combined identity requires reconciliation."],
            }
        ]
    elif ordinal == 6:
        authorities = [
            {
                "title": "Incomplete metadata authority",
                "citation": "Incomplete metadata authority",
                "official_url": ("https://www.legislation.gov.uk/ukpga/2098/998/section/1"),
                "exact_locators": ["section 1"],
                "candidate_existing": False,
                "candidate_source_version_ids": [],
                "source_admission_required": True,
                "caveats": ["Legal metadata is intentionally incomplete."],
            }
        ]
    elif ordinal == 7:
        authorities = [
            {
                "title": "Unfair Contract Terms Act 1977",
                "citation": "Unfair Contract Terms Act 1977, s 3",
                "official_url": ("https://www.legislation.gov.uk/ukpga/1977/50/section/3"),
                "exact_locators": ["section 3"],
                "jurisdiction": "United Kingdom statute.",
                "currentness_finding": "Candidate currentness record reviewed.",
                "later_treatment_finding": "Candidate treatment hold retained.",
                "candidate_existing": False,
                "candidate_source_version_ids": [],
                "source_admission_required": True,
                "caveats": ["The false non-candidate claim must be rejected."],
            }
        ]
    return {
        "row_id": queue_record["row_id"],
        "queue_record_content_sha256": queue_record["record_content_sha256"],
        "atomic_components": [
            {
                "proposition": f"Exact bounded proposition {queue_record['row_id']}.",
                "support_fit": "FULL" if authorities else "NONE",
                "authorities": authorities,
            }
        ],
        "unresolved_holds": (
            ["The listed factual application hold remains."] if ordinal == 1 else []
        ),
    }


def _write_wave(path: Path, records: list[dict[str, Any]]) -> builder.BoundArtifact:
    material = {
        "schema": "legalbot.test.exact-owner-packet-wave.v1",
        "wave_scope": [record["row_id"] for record in records],
        "source_queue_content_sha256": builder.QUEUE_CONTENT_SHA256,
        "records": records,
        "advisory_only": True,
        "owner_outcomes_applied": False,
        "source_admitted": False,
        "candidate_mutated": False,
        "embedding_run": False,
        "phase2b_authorized": False,
    }
    value = {**material, "artifact_content_sha256": builder._sealed(material)}
    path.write_bytes(builder._pretty_json(value))
    return _bound_wave(path)


def _bound_quarantine_manifest(path: Path) -> builder.BoundArtifact:
    value = json.loads(path.read_bytes())
    return builder.BoundArtifact(
        path,
        value["manifest_content_sha256"],
        builder._file_sha256(path),
    )


def _representation_binding(
    tmp_path: Path,
    wave_bindings: list[builder.BoundArtifact],
    canonical_set_binding: builder.BoundArtifact,
) -> builder.BoundArtifact:
    candidate = json.loads(builder.DEFAULT_CANDIDATE_PATH.read_bytes())
    collector_plans = builder.source_collector._plan_authorities(
        [(binding.path.name, json.loads(binding.path.read_bytes())) for binding in wave_bindings],
        candidate,
    )
    fetch_identity_keys = builder.source_collector.fetch_eligible_identity_keys(collector_plans)
    fetch_identity_set_sha256 = builder.source_collector.fetch_eligible_identity_set_sha256(
        collector_plans
    )
    authority_identity_id = "ukpga:2099:999"
    assert fetch_identity_keys == (authority_identity_id,)
    official_urls = [
        "https://www.legislation.gov.uk/ukpga/2099/999/section/49",
        "https://www.legislation.gov.uk/ukpga/2099/999/section/50",
    ]
    raw = b"<legislation><section>synthetic</section></legislation>\n"
    raw_sha256 = builder._sha256(raw)
    member = f"official-representation-0001-{raw_sha256[:20]}.xml"
    (tmp_path / member).write_bytes(raw)
    content_identity_sha256, canonicalization, holds = builder.source_collector._canonical_content(
        raw, content_type="application/xml"
    )
    assert not holds
    version_material = {
        "authority_identity_id": authority_identity_id,
        "raw_sha256": raw_sha256,
        "canonical_content_sha256": content_identity_sha256,
    }
    proposed_source_version_id = "proposed-source-version-" + builder._sealed(version_material)[:40]
    record_material = {
        "record_id": "quarantine-binding-synthetic-selected",
        "ordinal": 1,
        "authority_plan_id": "authority-plan-synthetic",
        "authority_plan_content_sha256": builder._sha256(b"synthetic plan"),
        "authority_identity_id": authority_identity_id,
        "representation_target_id": "representation-target-synthetic-selected",
        "representation_selection_rank": 1,
        "representation_role": "PROPOSED_ADMISSION_REPRESENTATION",
        "selected_for_proposed_admission": True,
        "source_official_urls": official_urls,
        "requested_url": ("https://www.legislation.gov.uk/ukpga/2099/999/2026-08-14/data.xml"),
        "landing_page_url": None,
        "final_url": ("https://www.legislation.gov.uk/ukpga/2099/999/2026-08-14/data.xml"),
        "http_status": 200,
        "content_type": "application/xml",
        "retrieved_at": "2026-08-28T00:00:00+00:00",
        "result": "DOWNLOADED_QUARANTINED_BOUND",
        "error_code": None,
        "hold_reason_codes": [],
        "quarantine_member": member,
        "raw_sha256": raw_sha256,
        "canonical_content_sha256": content_identity_sha256,
        "canonicalization_algorithm": canonicalization,
        "bytes": len(raw),
        "proposed_source_version_id": proposed_source_version_id,
        "official_urls": official_urls,
        "citations": ["Synthetic Test Act 2099, ss 49-50"],
        "titles": ["Synthetic Test Act 2099"],
        "exact_locators": ["section 49", "section 50"],
        "affected_row_ids": ["live30-q01:issue-01", "live30-q01:issue-02"],
        "row_uses": [],
        "owner_decision_applied": False,
        "source_admission_authorized": False,
        "source_admitted": False,
        "catalogue_mutated": False,
        "candidate_mutated": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
    }
    record = {**record_material, "record_content_sha256": builder._sealed(record_material)}
    binding_item = {
        **{field: record[field] for field in builder._COLLECTOR_RECORD_BINDING_FIELDS},
        "authority_representation_set_complete": True,
        "eligible_for_owner_packet": True,
    }
    manifest_material = {
        "schema": builder.REPRESENTATION_BINDING_SCHEMA,
        "status": "QUARANTINE_BINDINGS_CREATED_NOT_ADMITTED",
        "run_id": "synthetic-owner-packet-test",
        "source_ceiling_date": "2026-08-14",
        "created_at": "2026-08-28T00:00:00+00:00",
        "queue_binding": {
            "file_name": builder.DEFAULT_QUEUE_PATH.name,
            "content_sha256": builder.QUEUE_CONTENT_SHA256,
            "file_sha256": builder.QUEUE_FILE_SHA256,
            "row_count": 316,
        },
        "wave_validation": {
            "status": "PASS_COMPLETE",
            "covered_row_count": 316,
            "missing_row_count": 0,
        },
        "canonical_wave_set_binding": {
            "file_name": canonical_set_binding.path.name,
            "content_sha256": canonical_set_binding.content_sha256,
            "file_sha256": canonical_set_binding.file_sha256,
            "wave_count": builder.EXPECTED_CANONICAL_WAVE_COUNT,
        },
        "wave_bindings": [
            {
                "file_name": wave.path.name,
                "content_sha256": wave.content_sha256,
                "file_sha256": wave.file_sha256,
                "record_count": len(json.loads(wave.path.read_bytes())["records"]),
            }
            for wave in sorted(wave_bindings, key=lambda item: item.path.name)
        ],
        "candidate_binding": {
            "file_name": builder.DEFAULT_CANDIDATE_PATH.name,
            "content_sha256": builder.CANDIDATE_CONTENT_SHA256,
            "file_sha256": builder.CANDIDATE_FILE_SHA256,
            "source_count": 251,
        },
        "allowlisted_hosts": ["www.legislation.gov.uk"],
        "quarantine_root_name": "synthetic-quarantine",
        "authority_identity_count": 1,
        "fetch_authority_count": 1,
        "fetch_eligible_identity_count": len(fetch_identity_keys),
        "fetch_eligible_identity_set_sha256": fetch_identity_set_sha256,
        "fetch_target_count": 1,
        "candidate_present_no_fetch_count": 0,
        "preflight_hold_count": 0,
        "collection_record_count": 1,
        "collection_hold_count": 0,
        "held_selected_binding_count": 0,
        "result_counts": {"DOWNLOADED_QUARANTINED_BOUND": 1},
        "authority_plans": [],
        "records": [record],
        "representation_bindings": [binding_item],
        "selected_admission_bindings": [binding_item],
        "held_selected_bindings": [],
        "corroborating_alias_bindings": [],
        "representation_comparisons": [],
        "preflight_holds": [],
        "collection_holds": [],
        "authority_collection_holds": [],
        "packet_builder_interface": {
            "schema": builder.PACKET_BUILDER_INTERFACE_SCHEMA,
            "manifest_digest_field": "manifest_content_sha256",
            "record_digest_field": "record_content_sha256",
            "eligible_representation_record_ids": [record["record_id"]],
            "selected_admission_record_ids": [record["record_id"]],
            "held_selected_record_ids": [],
            "corroborating_alias_record_ids": [],
            "held_authority_identity_ids": [],
            "fetch_eligible_authority_identity_keys": list(fetch_identity_keys),
            "fetch_eligible_authority_identity_set_sha256": (fetch_identity_set_sha256),
            "candidate_existing_authority_identity_ids": [],
            "owner_must_adopt_exact_packet_before_admission": True,
            "owner_decisions_applied": False,
            "source_admission_authorized": False,
            "source_admitted": False,
            "candidate_mutated": False,
        },
        "advisory_only": True,
        "owner_decisions_applied": False,
        "source_admission_authorized": False,
        "source_admitted": False,
        "catalogue_mutated": False,
        "source_scan_run": False,
        "candidate_mutated": False,
        "index_built": False,
        "automatic_indexing": False,
        "embedding_run": False,
        "automatic_embedding": False,
        "technical_qualification_assigned": False,
        "promotion_authorized": False,
        "active_pointer_write_authorized": False,
        "previous_pointer_write_authorized": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
        "validation30_authorized": False,
        "live_activation_authorized": False,
        "training_export_authorized": False,
    }
    manifest = {
        **manifest_material,
        "manifest_content_sha256": builder._sealed(manifest_material),
    }
    path = tmp_path / "QUARANTINE-MANIFEST.json"
    path.write_bytes(builder._pretty_json(manifest))
    return _bound_quarantine_manifest(path)


def _build(
    output: Path,
    *,
    wave_bindings: list[builder.BoundArtifact],
    representation_binding: builder.BoundArtifact,
    **kwargs: Any,
) -> dict[str, Any]:
    manifest = json.loads(representation_binding.path.read_bytes())
    canonical_reference = manifest["canonical_wave_set_binding"]
    canonical_set_binding = builder.BoundArtifact(
        representation_binding.path.parent / canonical_reference["file_name"],
        canonical_reference["content_sha256"],
        canonical_reference["file_sha256"],
    )
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(builder, "REVIEW_ROOT", output.parent)
        monkeypatch.setattr(builder, "DEFAULT_CANONICAL_SET_PATH", canonical_set_binding.path)
        monkeypatch.setattr(
            builder,
            "CANONICAL_SET_CONTENT_SHA256",
            canonical_set_binding.content_sha256,
        )
        monkeypatch.setattr(
            builder,
            "CANONICAL_SET_FILE_SHA256",
            canonical_set_binding.file_sha256,
        )
        return builder.build(
            output,
            wave_bindings=wave_bindings,
            canonical_set_binding=canonical_set_binding,
            representation_binding=representation_binding,
            **kwargs,
        )


@pytest.fixture
def complete_wave_bindings(tmp_path: Path) -> list[builder.BoundArtifact]:
    queue = json.loads(builder.DEFAULT_QUEUE_PATH.read_bytes())
    regular_buckets: list[list[dict[str, Any]]] = [
        [] for _ in range(builder.EXPECTED_CANONICAL_WAVE_COUNT - 1)
    ]
    q48: list[dict[str, Any]] = []
    for ordinal, queue_record in enumerate(queue["records"], start=1):
        record = _wave_record(queue_record, ordinal)
        if record["row_id"].startswith(("live60-q48:", "live60-q49:", "live60-q50:")):
            q48.append(record)
        else:
            regular_buckets[(ordinal - 1) % len(regular_buckets)].append(record)
    bindings = [
        _write_wave(
            tmp_path / f"research-synthetic-canonical-{index:02d}.json",
            records,
        )
        for index, records in enumerate(regular_buckets, start=1)
    ]
    bindings.append(_write_wave(tmp_path / builder.CANONICAL_Q48_NAME, q48))
    return sorted(bindings, key=lambda item: item.path.name)


@pytest.fixture
def canonical_set_binding(
    tmp_path: Path,
    complete_wave_bindings: list[builder.BoundArtifact],
) -> builder.BoundArtifact:
    queue_binding_material = {
        "file_name": builder.DEFAULT_QUEUE_PATH.name,
        "content_sha256": builder.QUEUE_CONTENT_SHA256,
        "file_sha256": builder.QUEUE_FILE_SHA256,
        "row_count": 316,
    }
    wave_entries: list[dict[str, Any]] = []
    for wave in complete_wave_bindings:
        wave_value = json.loads(wave.path.read_bytes())
        wave_entry_material = {
            "file_name": wave.path.name,
            "content_sha256": wave.content_sha256,
            "file_sha256": wave.file_sha256,
            "record_count": len(wave_value["records"]),
        }
        wave_entries.append(
            {
                **wave_entry_material,
                "record_content_sha256": builder._sealed(wave_entry_material),
            }
        )
    material = {
        "schema": builder.CANONICAL_WAVE_SET_SCHEMA,
        "status": "CANONICAL_32_WAVES_BOUND_NOT_AUTHORIZING",
        "source_queue_content_sha256": builder.QUEUE_CONTENT_SHA256,
        "source_queue_file_sha256": builder.QUEUE_FILE_SHA256,
        "queue_binding": {
            **queue_binding_material,
            "record_content_sha256": builder._sealed(queue_binding_material),
        },
        "exact_set_count": builder.EXPECTED_CANONICAL_WAVE_COUNT,
        "total_row_count": 316,
        "wave_count": builder.EXPECTED_CANONICAL_WAVE_COUNT,
        "waves": wave_entries,
        "excluded_obsolete_wave_files": sorted(builder.OLD_Q48_NAMES),
        "advisory_only": True,
        "source_collected": False,
        "source_collection_authorized": False,
        "owner_decisions_applied": False,
        "owner_outcomes_applied": False,
        "source_admitted": False,
        "catalogue_mutated": False,
        "candidate_mutated": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "embedding_run": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
        "validation30_authorized": False,
        "active_or_previous_write_authorized": False,
        "live_activation_authorized": False,
    }
    value = {**material, "artifact_content_sha256": builder._sealed(material)}
    path = tmp_path / "CANONICAL-RESEARCH-WAVE-SET.json"
    path.write_bytes(builder._pretty_json(value))
    return _bound_wave(path)


@pytest.fixture
def representation_binding(
    tmp_path: Path,
    complete_wave_bindings: list[builder.BoundArtifact],
    canonical_set_binding: builder.BoundArtifact,
) -> builder.BoundArtifact:
    return _representation_binding(
        tmp_path,
        complete_wave_bindings,
        canonical_set_binding,
    )


def test_packet_is_exact_361_preserves_evidence_and_is_non_authorizing(
    tmp_path: Path,
    complete_wave_bindings: list[builder.BoundArtifact],
    representation_binding: builder.BoundArtifact,
) -> None:
    output = tmp_path / "owner-packet"
    packet = _build(
        output,
        wave_bindings=complete_wave_bindings,
        representation_binding=representation_binding,
    )

    summary = packet["decision_summary"]
    assert summary["decision_count"] == 361
    assert summary["research_decision_count"] == 316
    assert summary["direct_exact_span_decision_count"] == 45
    assert summary["unique_row_count"] == 361
    assert summary["collector_builder_proposal_identity_set_equal"] is True
    assert (
        summary["builder_proposal_identity_set_sha256"]
        == summary["collector_fetch_eligible_identity_set_sha256"]
    )
    assert packet["research_wave_validation"]["status"] == "PASS_COMPLETE"
    assert packet["research_wave_validation"]["covered_row_count"] == 316
    assert len({row["row_id"] for row in packet["decisions"]}) == 361

    research = next(row for row in packet["decisions"] if row["row_id"] == "live30-q01:issue-01")
    authority = research["source_research_record"]["atomic_components"][0]["authorities"][0]
    assert authority["exact_locators"] == ["section 49"]
    assert authority["currentness_finding"] == "Target-date official page reviewed."
    assert authority["later_treatment_finding"] == "Effects review remains retained."
    assert authority["jurisdiction"].startswith("United Kingdom")
    assert authority["caveats"] == ["The transaction facts remain unresolved."]
    assert research["source_research_record"]["unresolved_holds"]

    direct_source = json.loads(builder.DEFAULT_DIRECT_PATH.read_bytes())["records"][0]
    direct = next(row for row in packet["decisions"] if row["row_id"] == direct_source["row_id"])
    assert direct["source_direct_record"] == direct_source
    assert direct["source_direct_record"]["selected_local_evidence"]

    for field in builder._TOP_LEVEL_FALSE_FIELDS:
        assert packet[field] is False
    assert all(row["owner_outcome"] is None for row in packet["decisions"])
    assert all(
        row["source_admission_authorized"] is False
        for row in packet["proposed_new_source_admissions"]
    )


def test_source_admissions_are_deduplicated_and_anomalies_are_held(
    tmp_path: Path,
    complete_wave_bindings: list[builder.BoundArtifact],
    representation_binding: builder.BoundArtifact,
) -> None:
    packet = _build(
        tmp_path / "owner-packet",
        wave_bindings=complete_wave_bindings,
        representation_binding=representation_binding,
    )

    proposals = packet["proposed_new_source_admissions"]
    assert len(proposals) == 1
    assert proposals[0]["canonical_authority_identity_key"] == ("identity:ukpga:2099:999")
    assert proposals[0]["canonical_source_keys"] == [
        "https://www.legislation.gov.uk/ukpga/2099/999"
    ]
    assert proposals[0]["affected_row_ids"] == [
        "live30-q01:issue-01",
        "live30-q01:issue-02",
    ]
    assert proposals[0]["candidate_existing_states"] == ["False"]
    assert proposals[0]["source_admission_required_states"] == ["True"]
    assert proposals[0]["representation_binding_complete"] is True
    assert (
        proposals[0]["quarantine_representation_binding"]["selected_admission_binding"][
            "authority_identity_id"
        ]
        == "ukpga:2099:999"
    )
    assert proposals[0]["quarantine_representation_binding"]["selected_admission_binding"][
        "proposed_source_version_id"
    ].startswith("proposed-source-version-")

    reasons = packet["decision_summary"]["source_identity_anomaly_reason_counts"]
    expected_reasons = {
        "CANDIDATE_MEMBERSHIP_UNKNOWN": 1,
        "CURRENTNESS_FINDING_MISSING": 1,
        "JURISDICTION_FINDING_MISSING": 1,
        "LATER_TREATMENT_FINDING_MISSING": 1,
        "NON_CANDIDATE_CLAIM_CONTRADICTS_BOUND_MANIFEST": 1,
        "SOURCE_ADMISSION_REQUIREMENT_UNKNOWN": 2,
    }
    assert all(reasons[code] >= count for code, count in expected_reasons.items())
    assert reasons["CANDIDATE_SOURCE_VERSION_BINDING_MISSING"] >= 1
    assert reasons["COLLECTOR_FETCH_ELIGIBILITY_HOLD"] >= 1
    anomalies = packet["source_identity_and_admission_holds"]
    assert len(anomalies) == 5
    assert all(item["owner_outcome"] is None for item in anomalies)
    assert all(item["source_admission_authorized"] is False for item in anomalies)


def test_every_input_digest_decision_and_package_seal_is_verified(
    tmp_path: Path,
    complete_wave_bindings: list[builder.BoundArtifact],
    representation_binding: builder.BoundArtifact,
) -> None:
    output = tmp_path / "owner-packet"
    packet = _build(
        output,
        wave_bindings=complete_wave_bindings,
        representation_binding=representation_binding,
    )

    persisted = json.loads((output / builder.PACKET_NAME).read_bytes())
    material = dict(persisted)
    supplied = material.pop("artifact_content_sha256")
    assert supplied == builder._sealed(material) == packet["artifact_content_sha256"]
    for decision in packet["decisions"]:
        decision_material = dict(decision)
        decision_digest = decision_material.pop("decision_content_sha256")
        assert decision_digest == builder._sealed(decision_material)
    for proposal in packet["proposed_new_source_admissions"]:
        proposal_material = dict(proposal)
        proposal_digest = proposal_material.pop("proposal_content_sha256")
        assert proposal_digest == builder._sealed(proposal_material)
    for anomaly in packet["source_identity_and_admission_holds"]:
        anomaly_material = dict(anomaly)
        anomaly_digest = anomaly_material.pop("anomaly_content_sha256")
        assert anomaly_digest == builder._sealed(anomaly_material)

    package = json.loads((output / builder.PACKAGE_NAME).read_bytes())
    package_material = dict(package)
    package_digest = package_material.pop("artifact_content_sha256")
    assert package_digest == builder._sealed(package_material)
    for line in (output / builder.CHECKSUM_NAME).read_text().splitlines():
        digest, name = line.split("  ", 1)
        assert digest == builder._file_sha256(output / name)
    prompt = (output / builder.PROMPT_NAME).read_text()
    assert packet["artifact_content_sha256"] in prompt
    assert "I do not authorize an answer-model run" in prompt
    assert str(tmp_path) not in json.dumps(packet)


def test_tampered_wave_and_duplicate_wave_are_rejected_before_output(
    tmp_path: Path,
    complete_wave_bindings: list[builder.BoundArtifact],
    representation_binding: builder.BoundArtifact,
) -> None:
    tampered = complete_wave_bindings[0]
    tampered.path.write_bytes(tampered.path.read_bytes() + b"\n")
    output = tmp_path / "tampered-output"
    with pytest.raises(ValueError, match="wave_file_digest_invalid"):
        _build(
            output,
            wave_bindings=complete_wave_bindings,
            representation_binding=representation_binding,
        )
    assert not output.exists()

    repaired_bindings = complete_wave_bindings.copy()
    repaired_bindings[0] = _bound_wave(tampered.path)
    duplicate_output = tmp_path / "duplicate-output"
    with pytest.raises(ValueError, match="duplicate_wave"):
        _build(
            duplicate_output,
            wave_bindings=[*repaired_bindings, repaired_bindings[0]],
            representation_binding=representation_binding,
        )
    assert not duplicate_output.exists()


def test_old_q48_revision_and_non_active_candidate_drift_are_rejected(
    tmp_path: Path,
    complete_wave_bindings: list[builder.BoundArtifact],
    representation_binding: builder.BoundArtifact,
) -> None:
    canonical = next(
        item for item in complete_wave_bindings if item.path.name == builder.CANONICAL_Q48_NAME
    )
    old_path = tmp_path / "research-live60-q48-q50-r2.json"
    old_path.write_bytes(canonical.path.read_bytes())
    old_binding = _bound_wave(old_path)
    with pytest.raises(ValueError, match="old_q48_revision_forbidden"):
        _build(
            tmp_path / "old-q48-output",
            wave_bindings=[
                *(
                    item
                    for item in complete_wave_bindings
                    if item.path.name != builder.CANONICAL_Q48_NAME
                ),
                old_binding,
            ],
            representation_binding=representation_binding,
        )

    candidate_path = tmp_path / "candidate.json"
    candidate = json.loads(builder.DEFAULT_CANDIDATE_PATH.read_bytes())
    candidate["answer_release_eligible"] = True
    candidate["manifest_sha256"] = approved_source_manifest_sha256(candidate)
    candidate_path.write_bytes(builder._pretty_json(candidate))
    candidate_binding = builder.BoundArtifact(
        candidate_path,
        candidate["manifest_sha256"],
        builder._file_sha256(candidate_path),
    )
    with pytest.raises(ValueError, match="candidate_scope_or_boundary_invalid"):
        _build(
            tmp_path / "candidate-drift-output",
            wave_bindings=complete_wave_bindings,
            representation_binding=representation_binding,
            candidate_binding=candidate_binding,
        )


def test_canonical_32_wave_set_rejects_digest_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    complete_wave_bindings: list[builder.BoundArtifact],
    canonical_set_binding: builder.BoundArtifact,
) -> None:
    monkeypatch.setattr(builder, "DEFAULT_CANONICAL_SET_PATH", canonical_set_binding.path)
    monkeypatch.setattr(
        builder, "CANONICAL_SET_CONTENT_SHA256", canonical_set_binding.content_sha256
    )
    monkeypatch.setattr(builder, "CANONICAL_SET_FILE_SHA256", canonical_set_binding.file_sha256)
    canonical = builder._load_canonical_wave_set(
        canonical_set_binding,
        wave_bindings=complete_wave_bindings,
    )
    assert canonical["wave_count"] == 32

    canonical["waves"][0]["content_sha256"] = "0" * 64
    entry_material = dict(canonical["waves"][0])
    entry_material.pop("record_content_sha256")
    canonical["waves"][0]["record_content_sha256"] = builder._sealed(entry_material)
    material = dict(canonical)
    material.pop("artifact_content_sha256")
    canonical["artifact_content_sha256"] = builder._sealed(material)
    path = tmp_path / "CANONICAL-RESEARCH-WAVE-SET-substitute.json"
    path.write_bytes(builder._pretty_json(canonical))
    substituted = _bound_wave(path)
    monkeypatch.setattr(builder, "DEFAULT_CANONICAL_SET_PATH", substituted.path)
    monkeypatch.setattr(builder, "CANONICAL_SET_CONTENT_SHA256", substituted.content_sha256)
    monkeypatch.setattr(builder, "CANONICAL_SET_FILE_SHA256", substituted.file_sha256)

    with pytest.raises(ValueError, match="wave_bindings_not_canonical_set"):
        builder._load_canonical_wave_set(
            substituted,
            wave_bindings=complete_wave_bindings,
        )


def test_builder_is_create_only(
    tmp_path: Path,
    complete_wave_bindings: list[builder.BoundArtifact],
    representation_binding: builder.BoundArtifact,
) -> None:
    output = tmp_path / "owner-packet"
    _build(
        output,
        wave_bindings=complete_wave_bindings,
        representation_binding=representation_binding,
    )
    with pytest.raises(ValueError, match="output_already_exists"):
        _build(
            output,
            wave_bindings=complete_wave_bindings,
            representation_binding=representation_binding,
        )


def test_candidate_crosscheck_and_metadata_holds_fail_closed(
    tmp_path: Path,
    complete_wave_bindings: list[builder.BoundArtifact],
    representation_binding: builder.BoundArtifact,
) -> None:
    packet = _build(
        tmp_path / "owner-packet",
        wave_bindings=complete_wave_bindings,
        representation_binding=representation_binding,
    )
    assessments = [
        assessment
        for decision in packet["decisions"]
        if decision["decision_class"] == "OFFICIAL_RESEARCH_RECOMMENDATION"
        for assessment in decision["authority_assessments"]
    ]

    reconciled = next(
        item
        for item in assessments
        if item["candidate_crosscheck"]["missing_ids_reconciled_from_manifest"]
    )
    assert reconciled["candidate_crosscheck"]["resolved_candidate_source_version_ids"]
    assert "CANDIDATE_SOURCE_VERSION_BINDING_MISSING" in reconciled["hold_reason_codes"]
    assert "COLLECTOR_FETCH_ELIGIBILITY_HOLD" in reconciled["hold_reason_codes"]

    false_new = next(
        item
        for item in assessments
        if "NON_CANDIDATE_CLAIM_CONTRADICTS_BOUND_MANIFEST" in item["hold_reason_codes"]
    )
    assert false_new["new_source_admission_proposal_eligible"] is False
    assert false_new["candidate_crosscheck"]["candidate_alias_match_source_version_ids"]

    combined = next(
        item
        for item in assessments
        if item["metadata_completeness"]["metadata_mode"] == "COMBINED_EXPLICIT_FIELD"
    )
    assert combined["metadata_completeness"]["status"] == "COMPLETE"

    incomplete = next(
        item for item in assessments if item["metadata_completeness"]["status"] == "INCOMPLETE_HOLD"
    )
    assert incomplete["new_source_admission_proposal_eligible"] is False
    assert set(incomplete["metadata_completeness"]["reason_codes"]) == {
        "CURRENTNESS_FINDING_MISSING",
        "JURISDICTION_FINDING_MISSING",
        "LATER_TREATMENT_FINDING_MISSING",
    }


def test_candidate_alias_crosscheck_normalizes_made_instrument_identity() -> None:
    version_id = "source-version-" + "1" * 40
    candidate_index = builder._candidate_index(
        {
            "sources": [
                {
                    "source_version_id": version_id,
                    "authority_identity_id": "uksi:2018:597:made",
                    "stable_identifier": ("uksi:2018:597:made:latest-available@2026-08-14"),
                    "canonical_url": ("https://www.legislation.gov.uk/uksi/2018/597/made"),
                }
            ]
        }
    )
    crosscheck = builder._authority_candidate_crosscheck(
        authority={
            "title": "Trade Secrets (Enforcement, etc.) Regulations 2018",
            "citation": "Trade Secrets (Enforcement, etc.) Regulations 2018",
            "official_url": (
                "https://www.legislation.gov.uk/uksi/2018/597/regulation/3/2026-08-14"
            ),
            "candidate_existing": False,
            "candidate_source_version_ids": [],
            "source_admission_required": True,
        },
        candidate_index=candidate_index,
    )

    assert crosscheck["candidate_alias_match_source_version_ids"] == [version_id]
    assert "NON_CANDIDATE_CLAIM_CONTRADICTS_BOUND_MANIFEST" in crosscheck["reason_codes"]
    assert crosscheck["verified_new_source"] is False


def test_known_composite_authority_is_an_explicit_non_admission_hold() -> None:
    candidate = builder._load_candidate(
        builder.BoundArtifact(
            builder.DEFAULT_CANDIDATE_PATH,
            builder.CANDIDATE_CONTENT_SHA256,
            builder.CANDIDATE_FILE_SHA256,
        )
    )
    record = {
        "row_id": "live60-q44:issue-04",
        "atomic_components": [
            {"proposition": "None one.", "support_fit": "NONE", "authorities": []},
            {"proposition": "None two.", "support_fit": "NONE", "authorities": []},
            {
                "proposition": "Composite proposition.",
                "support_fit": "FULL",
                "authorities": [
                    {
                        "title": "COBS information disclosure and timing rules",
                        "citation": (
                            "FCA Handbook, COBS 2.2A.2R-2.2A.3R and COBS 14.3A.7R-14.3A.9R"
                        ),
                        "official_url": ("https://www.legislation.gov.uk/ukpga/2099/997"),
                        "exact_locators": ["section 1"],
                        "jurisdiction": "United Kingdom jurisdiction.",
                        "currentness_finding": "Currentness checked.",
                        "later_treatment_finding": "Later treatment checked.",
                        "candidate_existing": False,
                        "candidate_source_version_ids": [],
                        "source_admission_required": True,
                    }
                ],
            },
        ],
    }
    assessments, _ = builder._authority_assessments(
        record=record,
        candidate_index=builder._candidate_index(candidate),
    )

    composite = assessments[0]
    assert "COMPOSITE_AUTHORITY_IDENTITY_REQUIRES_SPLIT" in composite["hold_reason_codes"]
    assert composite["adoption_eligible"] is False
    assert composite["new_source_admission_proposal_eligible"] is False
    assert len(builder._KNOWN_COMPOSITE_AUTHORITY_SIGNATURES) == 14

    record["atomic_components"][2]["authorities"][0]["citation"] = (
        "FCA Handbook, COBS 2.2A.2R-2.2A.3R"
    )
    split_assessments, _ = builder._authority_assessments(
        record=record,
        candidate_index=builder._candidate_index(candidate),
    )
    assert (
        "COMPOSITE_AUTHORITY_IDENTITY_REQUIRES_SPLIT"
        not in split_assessments[0]["hold_reason_codes"]
    )


@pytest.mark.parametrize(
    "unsafe",
    [
        {"nested": [{"path": "/tmp/private-source.json"}]},
        {"nested": {"owner": "hltsang"}},
        {"nested": {"api_key": "not-permitted"}},
        {"nested": {"original_filename": "private-notes.docx"}},
    ],
)
def test_recursive_privacy_gate_rejects_paths_owner_data_and_secrets(
    unsafe: dict[str, Any],
) -> None:
    with pytest.raises(ValueError, match="phase2a_exact_packet_test_privacy_gate_failed"):
        builder._assert_privacy_safe(unsafe, role="test")


def test_output_must_be_beneath_review_root(tmp_path: Path) -> None:
    review_root = tmp_path / "review"
    review_root.mkdir()
    with pytest.raises(ValueError, match="output_outside_review_root"):
        builder._validated_output_root(
            tmp_path / "outside",
            review_root=review_root,
        )


def test_transaction_failure_removes_private_staging_and_output(
    tmp_path: Path,
    complete_wave_bindings: list[builder.BoundArtifact],
    representation_binding: builder.BoundArtifact,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "owner-packet"

    def fail_publish(_staging: Path, _output: Path) -> None:
        raise RuntimeError("synthetic publish fault")

    monkeypatch.setattr(builder, "_atomic_publish", fail_publish)
    with pytest.raises(RuntimeError, match="synthetic publish fault"):
        _build(
            output,
            wave_bindings=complete_wave_bindings,
            representation_binding=representation_binding,
        )

    assert not output.exists()
    assert not list(tmp_path.glob(".owner-packet.staging-*"))


def test_representation_binding_requires_untampered_selected_bytes(
    tmp_path: Path,
    complete_wave_bindings: list[builder.BoundArtifact],
    representation_binding: builder.BoundArtifact,
) -> None:
    manifest = json.loads(representation_binding.path.read_bytes())
    member = manifest["records"][0]["quarantine_member"]
    (representation_binding.path.parent / member).write_bytes(b"tampered\n")

    output = tmp_path / "owner-packet"
    with pytest.raises(ValueError, match="representation_raw_digest_invalid"):
        _build(
            output,
            wave_bindings=complete_wave_bindings,
            representation_binding=representation_binding,
        )
    assert not output.exists()


def test_representation_content_identity_is_recomputed_from_selected_bytes(
    tmp_path: Path,
    complete_wave_bindings: list[builder.BoundArtifact],
    representation_binding: builder.BoundArtifact,
) -> None:
    manifest = json.loads(representation_binding.path.read_bytes())
    record = manifest["records"][0]
    record["canonical_content_sha256"] = "0" * 64
    record_material = dict(record)
    record_material.pop("record_content_sha256")
    record["record_content_sha256"] = builder._sealed(record_material)
    for field in ("representation_bindings", "selected_admission_bindings"):
        manifest[field][0]["canonical_content_sha256"] = "0" * 64
        manifest[field][0]["record_content_sha256"] = record["record_content_sha256"]
    manifest_material = dict(manifest)
    manifest_material.pop("manifest_content_sha256")
    manifest["manifest_content_sha256"] = builder._sealed(manifest_material)
    representation_binding.path.write_bytes(builder._pretty_json(manifest))
    rebound = _bound_quarantine_manifest(representation_binding.path)

    with pytest.raises(ValueError, match="representation_content_identity_invalid"):
        _build(
            tmp_path / "owner-packet",
            wave_bindings=complete_wave_bindings,
            representation_binding=rebound,
        )


def test_representation_source_version_identity_must_match_authority(
    tmp_path: Path,
    complete_wave_bindings: list[builder.BoundArtifact],
    representation_binding: builder.BoundArtifact,
) -> None:
    manifest = json.loads(representation_binding.path.read_bytes())
    record = manifest["records"][0]
    record["authority_identity_id"] = "ukpga:2099:123"
    record_material = dict(record)
    record_material.pop("record_content_sha256")
    record["record_content_sha256"] = builder._sealed(record_material)
    for field in ("representation_bindings", "selected_admission_bindings"):
        manifest[field][0]["authority_identity_id"] = record["authority_identity_id"]
        manifest[field][0]["record_content_sha256"] = record["record_content_sha256"]
    manifest_material = dict(manifest)
    manifest_material.pop("manifest_content_sha256")
    manifest["manifest_content_sha256"] = builder._sealed(manifest_material)
    representation_binding.path.write_bytes(builder._pretty_json(manifest))
    rebound = _bound_quarantine_manifest(representation_binding.path)

    with pytest.raises(ValueError, match="proposed_source_version_identity_invalid"):
        _build(
            tmp_path / "owner-packet",
            wave_bindings=complete_wave_bindings,
            representation_binding=rebound,
        )


def test_distinct_corroborating_content_identity_is_allowed(
    tmp_path: Path,
    complete_wave_bindings: list[builder.BoundArtifact],
    representation_binding: builder.BoundArtifact,
) -> None:
    manifest = json.loads(representation_binding.path.read_bytes())
    selected_record = manifest["records"][0]
    corroborating_raw = b"%PDF-1.7 independent corroborating representation\n"
    corroborating_sha = builder._sha256(corroborating_raw)
    member = f"official-representation-0002-{corroborating_sha[:20]}.pdf"
    (tmp_path / member).write_bytes(corroborating_raw)
    corroborating_content_sha256, canonicalization, holds = (
        builder.source_collector._canonical_content(
            corroborating_raw,
            content_type="application/pdf",
        )
    )
    assert not holds
    corroborating_material = {
        **{key: value for key, value in selected_record.items() if key != "record_content_sha256"},
        "record_id": "quarantine-binding-synthetic-corroborating",
        "ordinal": 2,
        "representation_target_id": "representation-target-synthetic-corroborating",
        "representation_selection_rank": 2,
        "representation_role": "CORROBORATING_ALIAS_REPRESENTATION",
        "selected_for_proposed_admission": False,
        "requested_url": "https://official.example.test/synthetic.pdf",
        "final_url": "https://official.example.test/synthetic.pdf",
        "content_type": "application/pdf",
        "quarantine_member": member,
        "raw_sha256": corroborating_sha,
        "canonical_content_sha256": corroborating_content_sha256,
        "canonicalization_algorithm": canonicalization,
        "bytes": len(corroborating_raw),
        "proposed_source_version_id": None,
    }
    corroborating_record = {
        **corroborating_material,
        "record_content_sha256": builder._sealed(corroborating_material),
    }
    corroborating_binding = {
        **{
            field: corroborating_record[field] for field in builder._COLLECTOR_RECORD_BINDING_FIELDS
        },
        "authority_representation_set_complete": True,
        "eligible_for_owner_packet": False,
    }
    manifest["records"].append(corroborating_record)
    manifest["representation_bindings"].append(corroborating_binding)
    manifest["corroborating_alias_bindings"].append(corroborating_binding)
    manifest["packet_builder_interface"]["corroborating_alias_record_ids"].append(
        corroborating_record["record_id"]
    )
    manifest["collection_record_count"] = 2
    manifest["fetch_target_count"] = 2
    manifest["result_counts"]["DOWNLOADED_QUARANTINED_BOUND"] = 2
    comparison_material = {
        "authority_identity_id": selected_record["authority_identity_id"],
        "selected_record_id": selected_record["record_id"],
        "corroborating_record_id": corroborating_record["record_id"],
        "raw_sha256_equal": False,
        "canonical_content_sha256_equal": False,
        "representation_equivalence_assumed": False,
        "corroborating_alias_selected_for_admission": False,
    }
    manifest["representation_comparisons"] = [
        {
            **comparison_material,
            "comparison_content_sha256": builder._sealed(comparison_material),
        }
    ]
    manifest_material = dict(manifest)
    manifest_material.pop("manifest_content_sha256")
    manifest["manifest_content_sha256"] = builder._sealed(manifest_material)
    representation_binding.path.write_bytes(builder._pretty_json(manifest))
    rebound = _bound_quarantine_manifest(representation_binding.path)

    packet = _build(
        tmp_path / "owner-packet",
        wave_bindings=complete_wave_bindings,
        representation_binding=rebound,
    )
    bound = packet["proposed_new_source_admissions"][0]["quarantine_representation_binding"]
    assert len(bound["corroborating_alias_bindings"]) == 1
    assert (
        bound["corroborating_alias_bindings"][0]["canonical_content_sha256"]
        != bound["selected_admission_binding"]["canonical_content_sha256"]
    )
    assert bound["representation_equivalence_assumed"] is False


def test_failed_alias_moves_selected_representation_to_explicit_admission_hold(
    tmp_path: Path,
    complete_wave_bindings: list[builder.BoundArtifact],
    representation_binding: builder.BoundArtifact,
) -> None:
    manifest = json.loads(representation_binding.path.read_bytes())
    selected_record = manifest["records"][0]
    selected_binding = manifest["selected_admission_bindings"].pop()
    selected_binding["authority_representation_set_complete"] = False
    selected_binding["eligible_for_owner_packet"] = False
    manifest["representation_bindings"][0] = selected_binding
    manifest["held_selected_bindings"] = [selected_binding]
    manifest["held_selected_binding_count"] = 1
    interface = manifest["packet_builder_interface"]
    interface["eligible_representation_record_ids"] = []
    interface["selected_admission_record_ids"] = []
    interface["held_selected_record_ids"] = [selected_record["record_id"]]
    interface["held_authority_identity_ids"] = [selected_record["authority_identity_id"]]

    failed_material = {
        **{key: value for key, value in selected_record.items() if key != "record_content_sha256"},
        "record_id": "quarantine-binding-synthetic-failed-alias",
        "ordinal": 2,
        "representation_target_id": "representation-target-synthetic-failed-alias",
        "representation_selection_rank": 2,
        "representation_role": "CORROBORATING_ALIAS_REPRESENTATION",
        "selected_for_proposed_admission": False,
        "requested_url": "https://official.example.test/failed-alias.pdf",
        "final_url": "https://official.example.test/failed-alias.pdf",
        "http_status": 503,
        "content_type": "application/pdf",
        "result": "HTTP_STATUS_HOLD",
        "error_code": "HTTP_STATUS_503",
        "hold_reason_codes": ["HTTP_STATUS_503"],
        "quarantine_member": None,
        "raw_sha256": None,
        "canonical_content_sha256": None,
        "canonicalization_algorithm": None,
        "bytes": 0,
        "proposed_source_version_id": None,
    }
    failed_record = {
        **failed_material,
        "record_content_sha256": builder._sealed(failed_material),
    }
    manifest["records"].append(failed_record)
    manifest["collection_record_count"] = 2
    manifest["fetch_target_count"] = 2
    manifest["result_counts"] = {
        "DOWNLOADED_QUARANTINED_BOUND": 1,
        "HTTP_STATUS_HOLD": 1,
    }
    comparison_material = {
        "authority_identity_id": selected_record["authority_identity_id"],
        "selected_record_id": selected_record["record_id"],
        "corroborating_record_id": failed_record["record_id"],
        "raw_sha256_equal": None,
        "canonical_content_sha256_equal": None,
        "representation_equivalence_assumed": False,
        "corroborating_alias_selected_for_admission": False,
    }
    manifest["representation_comparisons"] = [
        {
            **comparison_material,
            "comparison_content_sha256": builder._sealed(comparison_material),
        }
    ]
    record_hold = {
        "hold_type": "REPRESENTATION_COLLECTION_HOLD",
        "record_id": failed_record["record_id"],
        "record_content_sha256": failed_record["record_content_sha256"],
        "authority_identity_id": failed_record["authority_identity_id"],
        "hold_reason_codes": failed_record["hold_reason_codes"],
        "owner_decision_applied": False,
        "source_admission_authorized": False,
        "source_admitted": False,
        "candidate_mutated": False,
    }
    authority_hold_material = {
        "hold_type": "AUTHORITY_REPRESENTATION_SET_INCOMPLETE",
        "authority_identity_id": selected_record["authority_identity_id"],
        "selected_record_id": selected_record["record_id"],
        "selected_record_content_sha256": selected_record["record_content_sha256"],
        "selected_proposed_source_version_id": selected_record["proposed_source_version_id"],
        "failed_record_ids": [failed_record["record_id"]],
        "failed_record_content_sha256s": [failed_record["record_content_sha256"]],
        "hold_reason_codes": ["AUTHORITY_REPRESENTATION_SET_INCOMPLETE"],
        "selected_binding_eligible": False,
        "owner_decision_applied": False,
        "source_admission_authorized": False,
        "source_admitted": False,
        "candidate_mutated": False,
    }
    authority_hold = {
        **authority_hold_material,
        "hold_content_sha256": builder._sealed(authority_hold_material),
    }
    manifest["collection_holds"] = [record_hold, authority_hold]
    manifest["authority_collection_holds"] = [authority_hold]
    manifest["collection_hold_count"] = 2
    manifest_material = dict(manifest)
    manifest_material.pop("manifest_content_sha256")
    manifest["manifest_content_sha256"] = builder._sealed(manifest_material)
    representation_binding.path.write_bytes(builder._pretty_json(manifest))
    rebound = _bound_quarantine_manifest(representation_binding.path)

    packet = _build(
        tmp_path / "owner-packet",
        wave_bindings=complete_wave_bindings,
        representation_binding=rebound,
    )

    assert packet["proposed_new_source_admissions"] == []
    assert len(packet["quarantine_source_admission_holds"]) == 1
    hold = packet["quarantine_source_admission_holds"][0]
    assert hold["source_admission_authorized"] is False
    assert hold["recommended_owner_outcome"] == (
        "RETAIN_QUARANTINE_REPRESENTATION_SET_HOLD_NO_SOURCE_ADMISSION"
    )
    assert packet["decision_summary"]["quarantine_held_selected_binding_count"] == 1


def test_failed_selected_download_is_accounted_by_authority_hold_without_admission(
    tmp_path: Path,
    complete_wave_bindings: list[builder.BoundArtifact],
    representation_binding: builder.BoundArtifact,
) -> None:
    manifest = json.loads(representation_binding.path.read_bytes())
    selected_record = manifest["records"][0]
    failed_material = {
        **{key: value for key, value in selected_record.items() if key != "record_content_sha256"},
        "http_status": 503,
        "result": "HTTP_STATUS_HOLD",
        "error_code": "HTTP_STATUS_503",
        "hold_reason_codes": ["HTTP_STATUS_503"],
        "quarantine_member": None,
        "raw_sha256": None,
        "canonical_content_sha256": None,
        "canonicalization_algorithm": None,
        "bytes": 0,
        "proposed_source_version_id": None,
    }
    failed_record = {
        **failed_material,
        "record_content_sha256": builder._sealed(failed_material),
    }
    manifest["records"] = [failed_record]
    manifest["representation_bindings"] = []
    manifest["selected_admission_bindings"] = []
    manifest["held_selected_bindings"] = []
    manifest["held_selected_binding_count"] = 0
    manifest["result_counts"] = {"HTTP_STATUS_HOLD": 1}

    interface = manifest["packet_builder_interface"]
    interface["eligible_representation_record_ids"] = []
    interface["selected_admission_record_ids"] = []
    interface["held_selected_record_ids"] = []
    interface["held_authority_identity_ids"] = [failed_record["authority_identity_id"]]

    record_hold = {
        "hold_type": "REPRESENTATION_COLLECTION_HOLD",
        "record_id": failed_record["record_id"],
        "record_content_sha256": failed_record["record_content_sha256"],
        "authority_identity_id": failed_record["authority_identity_id"],
        "hold_reason_codes": failed_record["hold_reason_codes"],
        "owner_decision_applied": False,
        "source_admission_authorized": False,
        "source_admitted": False,
        "candidate_mutated": False,
    }
    authority_hold_material = {
        "hold_type": "AUTHORITY_REPRESENTATION_SET_INCOMPLETE",
        "authority_identity_id": failed_record["authority_identity_id"],
        "selected_record_id": failed_record["record_id"],
        "selected_record_content_sha256": failed_record["record_content_sha256"],
        "selected_proposed_source_version_id": None,
        "failed_record_ids": [failed_record["record_id"]],
        "failed_record_content_sha256s": [failed_record["record_content_sha256"]],
        "hold_reason_codes": ["AUTHORITY_REPRESENTATION_SET_INCOMPLETE"],
        "selected_binding_eligible": False,
        "owner_decision_applied": False,
        "source_admission_authorized": False,
        "source_admitted": False,
        "candidate_mutated": False,
    }
    authority_hold = {
        **authority_hold_material,
        "hold_content_sha256": builder._sealed(authority_hold_material),
    }
    manifest["collection_holds"] = [record_hold, authority_hold]
    manifest["authority_collection_holds"] = [authority_hold]
    manifest["collection_hold_count"] = 2
    manifest_material = dict(manifest)
    manifest_material.pop("manifest_content_sha256")
    manifest["manifest_content_sha256"] = builder._sealed(manifest_material)
    representation_binding.path.write_bytes(builder._pretty_json(manifest))
    rebound = _bound_quarantine_manifest(representation_binding.path)

    packet = _build(
        tmp_path / "owner-packet",
        wave_bindings=complete_wave_bindings,
        representation_binding=rebound,
    )

    assert packet["proposed_new_source_admissions"] == []
    assert len(packet["quarantine_source_admission_holds"]) == 1
    hold = packet["quarantine_source_admission_holds"][0]
    assert hold["canonical_authority_identity_key"] == "identity:ukpga:2099:999"
    assert hold["held_selected_binding"] is None
    assert hold["authority_collection_hold"] == authority_hold
    assert hold["source_admission_authorized"] is False
    assert hold["source_admitted"] is False
    assert hold["automatic_indexing"] is False
    assert hold["automatic_embedding"] is False
    assert packet["decision_summary"]["proposed_new_source_admission_count"] == 0
    assert packet["decision_summary"]["quarantine_source_admission_hold_count"] == 1


def test_atomic_publish_rolls_back_after_visible_durability_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging = tmp_path / ".owner-packet.staging-test"
    output = tmp_path / "owner-packet"
    staging.mkdir(mode=0o700)
    (staging / "artifact.json").write_text("{}\n")

    monkeypatch.setattr(
        builder.os, "fsync", lambda _descriptor: (_ for _ in ()).throw(OSError("fault"))
    )
    with pytest.raises(OSError, match="fault"):
        builder._atomic_publish(staging, output)

    assert not output.exists()
    assert staging.is_dir()


def test_cli_failure_is_sanitized(
    tmp_path: Path,
    complete_wave_bindings: list[builder.BoundArtifact],
    representation_binding: builder.BoundArtifact,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail_build(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("/Users/hltsang/private-secret-token")

    monkeypatch.setattr(builder, "build", fail_build)
    manifest = json.loads(representation_binding.path.read_bytes())
    canonical_reference = manifest["canonical_wave_set_binding"]
    args = [
        "--output-root",
        str(tmp_path / "owner-packet"),
        "--canonical-set-binding",
        str(representation_binding.path.parent / canonical_reference["file_name"]),
        canonical_reference["content_sha256"],
        canonical_reference["file_sha256"],
        "--quarantine-manifest",
        str(representation_binding.path),
        representation_binding.content_sha256,
        representation_binding.file_sha256,
    ]
    for wave in complete_wave_bindings:
        args.extend(["--wave", str(wave.path), wave.content_sha256, wave.file_sha256])

    assert builder.main(args) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "/Users" not in captured.err
    assert "hltsang" not in captured.err
    assert "private-secret-token" not in captured.err
    assert '"reason_code": "phase2a_exact_packet_unexpected_runtimeerror"' in captured.err
