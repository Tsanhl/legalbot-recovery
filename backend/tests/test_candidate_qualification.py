from __future__ import annotations

from app.config import PROJECT_ROOT, Settings
from app.retrieval.binding_preflight import run_binding_preflight
from app.retrieval.candidate_qualification import (
    load_candidate_provision_qualifications,
    official_provision_snapshot,
)


def _xml(
    *,
    section_text: str = "The reviewed proposition.",
    sibling_text: str = "Unrelated law.",
    extent: str = "E+W",
) -> bytes:
    return (
        '<Legislation DocumentURI="http://www.legislation.gov.uk/ukpga/2000/1" '
        f'RestrictExtent="{extent}">'
        '<Primary><Body><P1group RestrictStartDate="2020-01-01">'
        '<P1 id="section-1" '
        'DocumentURI="http://www.legislation.gov.uk/ukpga/2000/1/section/1">'
        f"<Pnumber>1</Pnumber><Text>{section_text}</Text></P1>"
        f'<P1 id="section-2"><Pnumber>2</Pnumber><Text>{sibling_text}</Text></P1>'
        "</P1group></Body></Primary></Legislation>"
    ).encode()


def _snapshot(raw: bytes) -> dict[str, object]:
    return official_provision_snapshot(
        raw,
        authority_identity="ukpga:2000:1",
        legal_locator="section 1",
    )


def test_provision_snapshot_ignores_unrelated_sibling_drift() -> None:
    assert _snapshot(_xml(sibling_text="Old sibling.")) == _snapshot(
        _xml(sibling_text="New sibling.")
    )


def test_provision_snapshot_detects_provision_or_inherited_extent_drift() -> None:
    baseline = _snapshot(_xml())

    assert baseline != _snapshot(_xml(section_text="Changed proposition."))
    assert baseline != _snapshot(_xml(extent="S"))


def test_repository_candidate_qualification_replays_deterministically() -> None:
    build_id = "current-law-ew-full-fp16-v111-20260827-phase2a-a"
    build_path = PROJECT_ROOT / "data" / "indexes" / "builds" / build_id

    first = load_candidate_provision_qualifications(
        PROJECT_ROOT, build_path=build_path, build_id=build_id
    )
    second = load_candidate_provision_qualifications(
        PROJECT_ROOT,
        build_path=build_path,
        build_id=build_id,
        qualification_path=PROJECT_ROOT / "config/candidate_provision_qualification.v1.json",
    )

    assert first == second
    assert len(first[0]) == 4
    assert len(first[1]) == 64


def test_predecessor_candidate_qualification_remains_replayable_from_archive() -> None:
    build_id = "current-law-ew-full-fp16-v111-20260818-a"
    build_path = PROJECT_ROOT / "data" / "indexes" / "builds" / build_id
    archive = (
        PROJECT_ROOT
        / "config/archive/provision-verification/"
        "candidate-provision-qualification-current-law-ew-full-fp16-v111-20260818-a.v1.json"
    )

    records, digest = load_candidate_provision_qualifications(
        PROJECT_ROOT,
        build_path=build_path,
        build_id=build_id,
        qualification_path=archive,
    )

    assert len(records) == 4
    assert digest == "91468882d1a6e9e57057f24e098936df14abe07d50c5a76b14ee03dc57e91b2b"


def test_generic_correction_contains_no_failed_case_allowlist() -> None:
    implementation = (PROJECT_ROOT / "backend" / "app" / "retrieval" / "retrieval_v1.py").read_text(
        encoding="utf-8"
    )
    implementation += (
        PROJECT_ROOT / "backend" / "app" / "retrieval" / "candidate_qualification.py"
    ).read_text(encoding="utf-8")

    assert "dev-limitation-s2" not in implementation
    assert "dev-limitation-s14a" not in implementation
    assert "dev-trustee-act-s1" not in implementation
    assert "prom-family-provision-s1" not in implementation


def test_production_binding_preflight_is_zero_query_and_model_free(monkeypatch) -> None:
    monkeypatch.delenv("LEGALBOT_TEST_MODE", raising=False)

    report = run_binding_preflight(
        Settings(), build_id="current-law-ew-full-fp16-v111-20260827-phase2a-a"
    )

    assert report["status"] == "passed"
    assert report["suite"]["bound_row_count"] == 24
    assert report["binding"]["issues"] == []
    assert report["retrieval_query_count"] == 0
    assert report["answer_model_invoked"] is False
