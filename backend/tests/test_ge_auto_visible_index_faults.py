"""Synthetic fault-harness unit tests; these never establish real inference.

Run with a fresh --basetemp under index-fault-validation/test-runs. The separate
file-executed fault runner produces evidence against actual approved sources.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from scripts import ge_auto_visible_index_faults as faults


@pytest.fixture
def area(tmp_path):
    assert tmp_path.is_relative_to(faults.OUTPUT)
    return tmp_path


@pytest.mark.parametrize("released,reason", [(False, "parent not released"), (True, "")])
def test_readiness_holds_before_input_or_model_work(monkeypatch, released, reason):
    def unexpected(*args):
        raise AssertionError("not allowed before readiness")

    monkeypatch.setattr(faults, "load_original", unexpected)
    with pytest.raises(faults.visible.ValidationHold, match="PARENT_RERANKER_RELEASE"):
        faults.execute(readback_sha256="unread", parent_released=released, ready_reason=reason)


def test_original_receipt_digest_is_required(area, monkeypatch):
    (area / "READBACK-CHECK.json").write_bytes(b'{"synthetic":"changed"}')
    monkeypatch.setattr(faults, "INPUT", area)
    with pytest.raises(faults.visible.ValidationHold, match="FILE_DIGEST"):
        faults.load_original(faults.digest(b"different receipt"))


def test_started_execution_cannot_repeat(area, monkeypatch):
    monkeypatch.setattr(faults, "OUTPUT", area)
    (area / "RUN-START.json").write_bytes(b"synthetic previously started run")
    with pytest.raises(faults.visible.ValidationHold, match="ALREADY_STARTED"):
        faults.execute(readback_sha256="unread", parent_released=True, ready_reason="fixture")


def test_denial_needs_exact_expected_error():
    def forbidden():
        raise PermissionError("exact capability mismatch")

    assert faults.denied(forbidden, PermissionError, "capability mismatch")["state"] == "DENIED"
    with pytest.raises(faults.visible.ValidationHold, match="UNEXPECTED_DENIAL_REASON"):
        faults.denied(forbidden, PermissionError, "different policy")
    with pytest.raises(faults.visible.ValidationHold, match="BOUNDARY_ACCEPTED"):
        faults.denied(lambda: [], PermissionError, "capability mismatch")
    with pytest.raises(PermissionError):
        faults.denied(forbidden, ValueError, "capability mismatch")


def test_snapshot_detects_byte_change_and_rejects_aliases(area):
    target = area / "real.bytes"
    target.write_bytes(b"synthetic before")
    before = faults.snapshot(area)
    assert faults.snapshot(area) == before
    target.write_bytes(b"synthetic after")
    assert faults.snapshot(area) != before
    (area / "alias.bytes").symlink_to(target)
    with pytest.raises(faults.visible.ValidationHold, match="SYMLINK"):
        faults.snapshot(area)


def test_cross_root_denied_even_for_nonexistent_path(area):
    with pytest.raises(faults.visible.ValidationHold, match="CROSS_ROOT"):
        faults.visible.safe(area.parent / "outside", area)


def test_only_original_test_fixture_directory_can_be_excluded(area, monkeypatch):
    monkeypatch.setattr(faults, "INPUT", area)
    (area / "generation.bytes").write_bytes(b"synthetic persisted generation")
    fixtures = area / "test-runs"
    fixtures.mkdir()
    (fixtures / "deliberate-alias").symlink_to(area / "generation.bytes")
    assert set(faults.snapshot(area, exclude_test_fixtures=True)) == {"generation.bytes"}
    (area / "illegal-generation-alias").symlink_to(area / "generation.bytes")
    with pytest.raises(faults.visible.ValidationHold, match="SYMLINK"):
        faults.snapshot(area, exclude_test_fixtures=True)


def test_generation_hash_failure_precedes_lance_connection(area, monkeypatch):
    import lancedb

    def unexpected(*args):
        raise AssertionError("Lance cannot be opened with an unbound generation")

    monkeypatch.setattr(lancedb, "connect", unexpected)
    faults.visible.write_new(
        area / "generation.json",
        {
            "generation_sha256": faults.digest(b"wrong generation"),
            "synthetic": True,
        },
        output=area,
    )
    with pytest.raises(faults.visible.ValidationHold, match="GENERATION_DIGEST"):
        faults.verify_generation(area, {"generation_sha256": faults.digest(b"wrong generation")})


def test_generation_file_tamper_precedes_lance_connection(area, monkeypatch):
    import lancedb

    def unexpected(*args):
        raise AssertionError("Lance cannot be opened with changed generation files")

    monkeypatch.setattr(lancedb, "connect", unexpected)
    (area / "source.bytes").write_bytes(b"changed synthetic source")
    generation = {"files": {"source.bytes": faults.digest(b"original synthetic source")}}
    generation["generation_sha256"] = faults.digest(generation)
    faults.visible.write_new(area / "generation.json", generation, output=area)
    with pytest.raises(faults.visible.ValidationHold, match="FILE_DIGEST"):
        faults.verify_generation(area, generation)


@pytest.mark.parametrize(
    "row",
    [
        {
            "id": "synthetic-wrong-jur",
            "jurisdiction": "Texas",
            "valid_from": "2026-09-05",
            "valid_to": "2026-09-05",
        },
        {
            "id": "synthetic-wrong-date",
            "jurisdiction": "Wales",
            "valid_from": "2026-09-04",
            "valid_to": "2026-09-04",
        },
    ],
)
def test_filter_probe_rejects_backend_returning_ineligible_rows(row):
    class IneligibleBackend:
        def search(self, *args, **kwargs):
            return self

        def where(self, *args, **kwargs):
            return self

        def metric(self, *args, **kwargs):
            return self

        def limit(self, *args, **kwargs):
            return self

        def to_list(self):
            return [row]

    # Empty vector is a deliberately non-executing backend input, not an embedding.
    with pytest.raises(faults.visible.ValidationHold, match="INELIGIBLE_ROW"):
        faults.filter_probe(
            IneligibleBackend(),
            query="synthetic filter fault",
            vector=[],
            jurisdiction="Wales",
            day="2026-09-05",
        )


def test_interruption_boundary_must_have_persisted_artifacts(area):
    repository = SimpleNamespace(staging_path=lambda build: area)
    with pytest.raises(faults.visible.ValidationHold, match="BOUNDARY_NOT_REACHED"):
        faults.interrupt_after_readback(repository, "synthetic-build")
    (area / "generation.json").write_bytes(b"synthetic marker only")
    (area / "lance/authority").mkdir(parents=True)
    with pytest.raises(faults.InjectedInterruption, match="AFTER_PERSISTED_READBACK"):
        faults.interrupt_after_readback(repository, "synthetic-build")


def test_write_is_immutable_and_output_scoped(area, monkeypatch):
    monkeypatch.setattr(faults, "OUTPUT", area)
    path = area / "receipt.json"
    first = faults.write(path, {"synthetic": "original"})
    assert faults.write(path, {"synthetic": "original"}) == first
    with pytest.raises(faults.visible.ValidationHold, match="IMMUTABLE_OUTPUT"):
        faults.write(path, {"synthetic": "changed"})
    with pytest.raises(faults.visible.ValidationHold, match="CROSS_ROOT"):
        faults.write(area.parent / "outside.json", {})


@pytest.mark.parametrize(
    "relative,expected",
    [
        (
            "backend/app/research/ge_auto_index.py",
            "2321be81ad63a3b57bdab623fa9fc382f2f86f9506587c447f72768b9f3f0bc7",
        ),
        (
            "backend/app/contracts/schema_registry.py",
            "0d7407f9449409a38179fcd6062f73c539e0f466acdd3d8ab9c259940ae9b803",
        ),
        (
            "scripts/ge_auto_research_intake.py",
            "2fc7ff3bd94d32645be5880595e0c7f3c3553b6111ffa88d8f64dab5b2594c8d",
        ),
    ],
)
def test_declared_addition_recovers_exact_reviewed_code_and_rejects_other_changes(
    relative, expected
):
    current = faults.read(faults.ROOT / relative, faults.ROOT)
    original = faults.historical_review_code(relative, current, expected)
    assert faults.digest(original) == expected
    with pytest.raises(faults.visible.ValidationHold, match="UNDECLARED_REVIEW_CODE_CHANGE"):
        faults.historical_review_code(
            relative, current + b"\n# unexpected additional edit\n", expected
        )


def test_successor_contract_binds_actual_revalidated_base_parser(area, monkeypatch):
    """Actual approved visible inputs, with fresh test scope and zero inference."""
    monkeypatch.setattr(faults, "OUTPUT", area)
    key = faults.digest(faults.read(faults.INPUT / "READBACK-CHECK.json", faults.INPUT))
    gate, identity, _, materials, _ = faults.load_original(key)
    material = min(materials, key=lambda m: len(m["rows"]))
    scope = faults.Scope(
        str(area / "stores/regression"),
        "candidate_case_local",
        "VISIBLE_PARSER_BINDING_REGRESSION",
        material["case"]["case_id"],
    )
    owner = faults.read(
        faults.ROOT
        / "data/evaluations/general-enquiries/LegalBot-GE-2026-09-05-codex-unseen-r1/PLAN-EXECUTION-AUTHORIZATION.json",
        faults.ROOT,
        faults.visible.OWNER_SHA256,
    )
    policy = faults.ResearchPolicy(
        workspace=area,
        owner_instruction=owner,
        expected_owner_instruction_sha256=faults.visible.OWNER_SHA256,
        scopes=[scope],
        model=faults.ModelPin.from_runtime_identity(identity),
        reviewers=[gate.pins.reviewer_id],
        verify_review=gate.verify_review,
    )
    unit = faults.prepare_successor(gate, policy, scope, material, identity, label="regression")
    contracts = faults.obj(unit["local"] / "CONTRACTS.json", area)
    actual = contracts["knowledge_generation"]["toolchain"]["parser_sha256"]
    assert actual == unit["source"].parser_sha256 == gate.parser_bridge["current_parser_sha256"]
    assert actual != material["contracts"]["knowledge_generation"]["toolchain"]["parser_sha256"]


def test_superseded_metadata_links_and_dates_do_not_grant_applicability():
    raw = b'''<Legislation
      xmlns="http://www.legislation.gov.uk/namespaces/legislation"
      xmlns:dc="http://purl.org/dc/elements/1.1/"
      xmlns:dct="http://purl.org/dc/terms/" xmlns:a="http://www.w3.org/2005/Atom">
      <dc:identifier>synthetic-document</dc:identifier><dct:valid>2019-11-11</dct:valid>
      <a:link rel="http://purl.org/dc/terms/hasVersion" href="synthetic-older-link"/>
      </Legislation>'''
    result = faults.captured_version_metadata(raw)
    assert result["observed_version_links"] == ["synthetic-older-link"]
    assert result["valid_metadata"] == ["2019-11-11"]
    assert result["legal_applicability_verified"] is False
    assert "superseded" not in result


def test_superseded_metadata_html_and_xml_entities_are_not_historical_evidence():
    assert faults.captured_version_metadata(b"<html>synthetic current page</html>") == {}
    invalid = faults.captured_version_metadata(b'<?xml version="1.0"?><html>&broken</html>')
    assert invalid["xml_metadata_state"] == "NOT_WELL_FORMED_XML"
    assert invalid["legal_applicability_verified"] is False


def test_superseded_actual_capture_inventory_never_runs_model_or_indexes(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("this read-only inspection cannot perform an index proof")

    monkeypatch.setattr(faults, "load_original", unexpected)
    monkeypatch.setattr(faults, "prepare_successor", unexpected)
    monkeypatch.setattr(faults, "execute", unexpected)
    result = faults.inspect_superseded_inputs()
    assert result["state"] == "NOT_DEMONSTRATED"
    assert len(result["captures"]) == 32
    assert len(result["unavailable_original_captures"]) == 2
    assert len(result["review_windows"]) == 30
    assert result["model_inference_calls_this_inspection"] == result["index_builds"] == 0
    assert result["missing_evidence"]["historical_source_reconstructed"] is False
    assert result["missing_evidence"]["missing_historical_capture_url"].endswith("/2017-12-01")
    assert result["global_visible_validation"] == "NOT_ASSESSED"


def test_superseded_changed_attestation_stops_before_capture_inspection(monkeypatch):
    actual_read = faults.read

    def changed(path, root, expected=None):
        if path.name == "REVIEW-ATTESTATION.json":
            assert expected
            raise faults.visible.ValidationHold("FILE_DIGEST: synthetic changed attestation")
        return actual_read(path, root, expected)

    monkeypatch.setattr(faults, "read", changed)
    with pytest.raises(faults.visible.ValidationHold, match="FILE_DIGEST"):
        faults.inspect_superseded_inputs()


def test_version_capture_redirect_and_repeat_are_denied_before_another_get(area):
    url = faults.VERSION_CAPTURE_URLS[0]
    files = {}
    emit = faults.version_capture_emitter(area, url, files)
    emit("hop-00-request.json", {"url": url, "synthetic": True})
    with pytest.raises(faults.visible.ValidationHold, match="REDIRECT_OUTSIDE"):
        emit("hop-01-request.json", {"url": url + "/data.xml", "synthetic": True})
    assert "hop-01-request.json" in files  # attempted redirect remains recorded
    with pytest.raises(faults.visible.ValidationHold, match="FILE_REPLAY"):
        emit("hop-00-request.json", {"url": url, "synthetic": True})
    with pytest.raises(faults.visible.ValidationHold, match="FILE_SCOPE"):
        emit("../outside.bytes", b"synthetic")


def test_version_capture_other_endpoint_denied(area):
    with pytest.raises(faults.visible.ValidationHold, match="EXACT_HISTORICAL_CAPTURE_URL"):
        faults.version_capture_emitter(area, "https://www.legislation.gov.uk/ssi/2011/176/data.xml", {})


def test_version_capture_started_pack_cannot_refetch(area, monkeypatch):
    from scripts import ge_auto_host_bridge as bridge

    def unexpected(*args, **kwargs):
        raise AssertionError("no repeated capture is authorized")

    monkeypatch.setattr(faults, "OUTPUT", area)
    monkeypatch.setattr(bridge, "fetch_official", unexpected)
    (area / "superseded-version-captures").mkdir()
    with pytest.raises(FileExistsError):
        faults.capture_superseded_versions()
