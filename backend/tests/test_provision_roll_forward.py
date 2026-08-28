from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from app.retrieval.provision_roll_forward import artifact_bytes, build_roll_forward
from app.retrieval.provision_verification import (
    load_provision_verifications,
    qualification_for,
)


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _xml(identity: str, *, marker: str = "same", modified: str = "2026-08-01") -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<Legislation DocumentURI="http://www.legislation.gov.uk/{identity}" '
        'RestrictStartDate="2020-01-01">'
        '<DocumentStatus Value="revised"/>'
        f"<modified>{modified}</modified><valid>2020-01-01</valid>"
        f"<Body>{marker}</Body></Legislation>"
    ).encode()


def _source_path(root: Path, identity: str, date: str) -> Path:
    path = (
        root
        / "Official Legislation"
        / "United Kingdom"
        / "Current"
        / "Contract law"
        / f"{identity.replace('/', '_')}__retrieved-{date}.xml"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _fixture(tmp_path: Path) -> tuple[bytes, bytes, bytes, Path]:
    old_date = "2026-08-12"
    new_date = "2026-08-14"
    source_root = tmp_path / "sources"
    identities = ("ukpga/1977/50", "ukpga/1980/58")
    old_same = _xml(identities[0])
    old_changed = _xml(identities[1], marker="old")
    new_changed = _xml(identities[1], marker="new")
    _source_path(source_root, identities[0], old_date).write_bytes(old_same)
    _source_path(source_root, identities[0], new_date).write_bytes(old_same)
    _source_path(source_root, identities[1], old_date).write_bytes(old_changed)
    _source_path(source_root, identities[1], new_date).write_bytes(new_changed)
    pack = {
        "schema": "legalbot.current-legislation-pack.v1",
        "version": "test-2026-08-14",
        "as_of_date": new_date,
        "items": [
            {"identity": identity, "title": identity, "subject_folder": "Contract law"}
            for identity in identities
        ],
    }
    predecessor = {
        "schema": "legalbot.provision-verification.v1",
        "version": "1.0.0",
        "verified_at": "2026-08-13",
        "jurisdiction": "England and Wales",
        "records": [
            {
                "stable_source_id": f"{identity.replace('/', ':')}:latest-available@{old_date}",
                "legal_locator": "section 2",
                "official_source_url": f"https://www.legislation.gov.uk/{identity}/section/2",
                "verified_extent": "E+W",
                "section_unapplied_effect_count": 0,
                "unapplied_effect_materiality": "none_recorded",
            }
            for identity in identities
        ],
    }
    report = {
        "schema": "legalbot.current-legislation-download-report.v1",
        "manifest_version": pack["version"],
        "as_of_date": new_date,
        "items": [
            {
                "identity": identities[0],
                "sha256": hashlib.sha256(old_same).hexdigest(),
            },
            {
                "identity": identities[1],
                "sha256": hashlib.sha256(new_changed).hexdigest(),
            },
        ],
    }
    return _json_bytes(predecessor), _json_bytes(pack), _json_bytes(report), source_root


def _build(tmp_path: Path):
    predecessor, pack, report, source_root = _fixture(tmp_path)
    return build_roll_forward(
        predecessor_raw=predecessor,
        current_pack_raw=pack,
        download_report_raw=report,
        source_root=source_root,
        predecessor_archive_relative_path=(
            "config/archive/provision-verification/provision-verification-2026-08-12.v1.json"
        ),
        exception_report_relative_path=(
            "config/archive/provision-verification/"
            "provision-verification-roll-forward-2026-08-14.json"
        ),
        download_report_relative_path=(
            "config/archive/provision-verification/current-legislation-download-2026-08-14.json"
        ),
    )


def test_roll_forward_inherits_only_identical_official_bytes(tmp_path: Path) -> None:
    artifacts = _build(tmp_path)

    assert artifacts.registry["inherited_record_count"] == 1
    assert artifacts.registry["excluded_record_count"] == 1
    inherited = artifacts.registry["records"][0]
    assert inherited["stable_source_id"].endswith("@2026-08-14")
    assert inherited["source_content_sha256"] == inherited["source_version_sha256"]
    assert inherited["qualification_provenance"] == "inherited_identical_official_snapshot"
    exception = artifacts.exception_report["exceptions"][0]
    assert exception["reason_codes"] == ["official_source_bytes_changed"]
    assert exception["review_action"] == "fresh_human_provision_review_required"
    assert artifacts.exception_report["contains_source_text"] is False
    assert artifacts.exception_report["contains_filesystem_paths"] is False


def test_loader_checks_manifest_date_artifacts_and_runtime_source_sha(tmp_path: Path) -> None:
    artifacts = _build(tmp_path)
    rendered = artifact_bytes(artifacts)
    paths = {
        "registry": tmp_path / "config" / "provision_verification.v1.json",
        "predecessor": tmp_path
        / "config"
        / "archive"
        / "provision-verification"
        / "provision-verification-2026-08-12.v1.json",
        "exception_report": tmp_path
        / "config"
        / "archive"
        / "provision-verification"
        / "provision-verification-roll-forward-2026-08-14.json",
        "download_report": tmp_path
        / "config"
        / "archive"
        / "provision-verification"
        / "current-legislation-download-2026-08-14.json",
        "pack": tmp_path / "config" / "current_legislation_pack.json",
    }
    for path in paths.values():
        path.parent.mkdir(parents=True, exist_ok=True)
    paths["registry"].write_bytes(rendered["registry"])
    paths["predecessor"].write_bytes(rendered["predecessor"])
    paths["exception_report"].write_bytes(rendered["exception_report"])
    _, pack, _, _ = _fixture(tmp_path / "second-fixture")
    paths["pack"].write_bytes(pack)
    paths["download_report"].write_bytes(rendered["download_report"])

    records, _ = load_provision_verifications(tmp_path)
    record = next(iter(records.values()))
    source_id = str(record["stable_source_id"])
    locator = str(record["legal_locator"])
    digest = str(record["source_content_sha256"])
    assert (
        qualification_for(
            records,
            stable_source_id=source_id,
            legal_locator=locator,
            source_content_sha256=digest,
            source_version_sha256=digest,
        )
        is not None
    )
    assert (
        qualification_for(
            records,
            stable_source_id=source_id,
            legal_locator=locator,
            source_content_sha256="f" * 64,
            source_version_sha256="f" * 64,
        )
        is None
    )

    registry_payload = json.loads(rendered["registry"])
    registry_payload["download_report"]["relative_path"] = (
        "data/review_queue/current-legislation-download.json"
    )
    paths["registry"].write_bytes(_json_bytes(registry_payload))
    with pytest.raises(RuntimeError, match="tracked provision-verification archive"):
        load_provision_verifications(tmp_path)
    paths["registry"].write_bytes(rendered["registry"])

    pack_payload = json.loads(paths["pack"].read_text())
    pack_payload["as_of_date"] = "2026-08-15"
    paths["pack"].write_bytes(_json_bytes(pack_payload))
    with pytest.raises(RuntimeError, match="dates do not match"):
        load_provision_verifications(tmp_path)


def test_roll_forward_rejects_download_digest_mismatch(tmp_path: Path) -> None:
    predecessor, pack, report, source_root = _fixture(tmp_path)
    report_payload = json.loads(report)
    report_payload["items"][0]["sha256"] = "0" * 64
    with pytest.raises(RuntimeError, match="does not bind"):
        build_roll_forward(
            predecessor_raw=predecessor,
            current_pack_raw=pack,
            download_report_raw=_json_bytes(report_payload),
            source_root=source_root,
            predecessor_archive_relative_path="config/archive/predecessor.json",
            exception_report_relative_path=(
                "config/archive/provision-verification/exceptions.json"
            ),
            download_report_relative_path=("config/archive/provision-verification/download.json"),
        )
