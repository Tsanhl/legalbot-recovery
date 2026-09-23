from __future__ import annotations

import json
import shutil
from copy import deepcopy
from pathlib import Path

import pytest

from app.evaluation.ge_everyday_unseen import (
    DOMAIN_FAMILIES,
    ORIGINAL_DOMAINS,
    REQUEST_ROOT,
    SYSTEM_FAMILIES,
    ExpandedUnseenError,
    coverage_slots,
    creation_contract,
    require_seal,
    validate_coverage,
    validate_custodian_connection,
    verify_request,
)


def test_expansion_preserves_original_domains_and_requires_realistic_inputs() -> None:
    rows = coverage_slots()
    validate_coverage(rows)
    assert len(ORIGINAL_DOMAINS) == 23
    assert len(DOMAIN_FAMILIES) == 35
    assert len(SYSTEM_FAMILIES) == 23
    assert len(rows) == 420
    assert sum(row["synthetic_upload_required"] for row in rows) == 210
    assert sum(row["multi_turn_required"] for row in rows) == 140
    assert sum(row["cross_issue_required"] for row in rows) == 70
    assert {"housing", "employment", "family", "immigration", "benefits-and-debt", "consumer"}.issubset(ORIGINAL_DOMAINS)


@pytest.mark.parametrize("change", ["drop", "duplicate", "relabel", "private_question"])
def test_coverage_cannot_omit_alias_or_leak_cases(change: str) -> None:
    rows = deepcopy(coverage_slots())
    if change == "drop":
        rows = rows[:-1]
    elif change == "duplicate":
        rows[-1] = rows[0]
    elif change == "relabel":
        rows[0]["domain"] = "consumer"
    else:
        rows[0]["question_text"] = "Private content must not enter the public coverage file."
    with pytest.raises(ExpandedUnseenError):
        validate_coverage(rows)


def test_authorization_is_creation_only_and_oracle_is_withheld() -> None:
    contract = creation_contract()
    require_seal(contract)
    assert contract["creation_authorized"] is True
    assert contract["execution_authorized"] is False
    assert contract["bank_created"] is False
    assert contract["reference_evidence_visible_to_candidate"] is False
    assert contract["candidate_must_retrieve_authority"] is True
    assert contract["law_verified_before_seal"] is False
    assert contract["professional_legal_sign_off"] is False
    assert contract["pass_denominators"] == {"legal_factual": 420, "legal_quality": 420, "system": 23}
    assert sum(contract["quality_maxima"].values()) == 100
    contract["execution_authorized"] = True
    with pytest.raises(ExpandedUnseenError, match="seal"):
        require_seal(contract)


@pytest.mark.parametrize("provider", [None, "", "openai", "codex"])
def test_same_provider_or_missing_custodian_is_rejected(provider: str | None) -> None:
    with pytest.raises(ExpandedUnseenError, match="independent"):
        validate_custodian_connection({"provider": provider})


def test_external_provider_name_alone_does_not_establish_custody() -> None:
    with pytest.raises(ExpandedUnseenError, match="custody evidence missing"):
        validate_custodian_connection({"provider": "external-test-provider"})


@pytest.mark.parametrize("field,value", [
    ("developer_has_decryption_key", True),
    ("retired_bank_access", "ALLOWED"),
    ("execution_authorized", True),
])
def test_custody_cannot_expose_bank_or_confer_execution(field: str, value: object) -> None:
    receipt = {
        "provider": "external-test-provider", "identity": "synthetic-custodian",
        "authentication_receipt_sha256": "a" * 64, "private_root_identity_sha256": "b" * 64,
        "encryption_recipient_fingerprint": "synthetic-key-id",
        "access_isolation_receipt_sha256": "c" * 64, "retired_bank_access": "DENIED",
        "developer_has_decryption_key": False, "execution_authorized": False,
    }
    receipt[field] = value
    with pytest.raises(ExpandedUnseenError):
        validate_custodian_connection(receipt)


def test_frozen_public_request_reconciles_without_claiming_bank_exists() -> None:
    result = verify_request()
    assert result["creation_authorized"] is True
    assert result["bank_created"] is False
    assert result["execution_authorized"] is False
    assert result["legal_slots"] == 420


def test_private_content_cannot_be_added_to_public_handoff(tmp_path: Path) -> None:
    target = tmp_path / "request"
    shutil.copytree(REQUEST_ROOT, target)
    (target / "private-questions.json").write_text(json.dumps({"unexpected": "content"}))
    with pytest.raises(ExpandedUnseenError, match="artifact register"):
        verify_request(target)
