from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest

from app.config import Settings
from app.crypto import LocalCipher
from app.db import Database
from app.orchestration.object_store import EncryptedObjectStore
from app.research.review import ResearchReviewService
from app.research.source_intake_bridge import (
    ResearchSourceIntakeBridge,
    SourceIntakeBridgeError,
)
from app.research.source_intake_create_only import (
    CreateOnlyResearchSourceIngestor,
    CreateOnlySourceIntakeRequest,
)
from app.research.source_registry import ContentMode, OfficialSourcePolicy, OfficialSourceRegistry
from app.research.worker import EncryptedResearchQuarantine

PROJECT_ROOT = Path(__file__).resolve().parents[2]
REGISTRY = OfficialSourceRegistry.load(PROJECT_ROOT / "config" / "official_sources.json")


def test_bridge_and_create_only_ingestor_have_no_destructive_primitives() -> None:
    sources = "\n".join(
        (PROJECT_ROOT / relative).read_text(encoding="utf-8")
        for relative in (
            "backend/app/research/source_intake_bridge.py",
            "backend/app/research/source_intake_create_only.py",
        )
    )
    forbidden = (
        r"\bDELETE\s+FROM\b",
        r"\bUPDATE\s+\w+\s+SET\b",
        r"\bINSERT\s+OR\b",
        r"\bON\s+CONFLICT\b",
        r"\.unlink\s*\(",
        r"\bos\.remove\s*\(",
        r"\brmtree\s*\(",
        r"\bos\.replace\s*\(",
    )
    assert all(re.search(pattern, sources, flags=re.IGNORECASE) is None for pattern in forbidden)


class _CountingCreateOnlyIngestor(CreateOnlyResearchSourceIngestor):
    """Count calls while exercising the production create-only implementation."""

    def __init__(self, settings: Settings, database: Database, cipher: LocalCipher) -> None:
        super().__init__(settings, database, cipher)
        self.calls = 0

    def ingest(self, request: CreateOnlySourceIntakeRequest) -> dict[str, Any]:
        self.calls += 1
        return super().ingest(request)


def _settings(tmp_path: Path) -> tuple[Settings, Path]:
    source_root = tmp_path / "permitted-source-root"
    source_root.mkdir()
    return (
        Settings(
            project_root=tmp_path,
            test_mode=True,
            explicit_source_roots=(source_root,),
        ),
        source_root,
    )


def _reviewed_candidate(
    settings: Settings,
    database: Database,
    cipher: LocalCipher,
    *,
    envelope_override: dict[str, Any] | None = None,
    complete_owner_review: bool = True,
    content_override: bytes | None = None,
    content_type: str = "application/xml",
) -> tuple[str, bytes, EncryptedObjectStore]:
    candidate_id = "candidate-source-intake-001"
    task_id = "research-source-intake-001"
    source_identity = "ukpga:2026:1"
    default_content = b"""<?xml version='1.0' encoding='UTF-8'?>
    <Legislation xmlns='http://www.legislation.gov.uk/namespaces/legislation'
      xmlns:dc='http://purl.org/dc/elements/1.1/'
      DocumentURI='http://www.legislation.gov.uk/ukpga/2026/1'>
      <Metadata><dc:title>Example Act 2026</dc:title>
        <dc:modified>2026-09-01</dc:modified></Metadata>
      <Body><Part DocumentURI='http://www.legislation.gov.uk/ukpga/2026/1/part/1'>
        <Number>PART 1</Number><Title>General provision</Title>
        <P1 DocumentURI='http://www.legislation.gov.uk/ukpga/2026/1/section/1'>
          <Pnumber>1</Pnumber><P1para><Text>Section 1 applies to the reviewed matter.</Text></P1para>
        </P1>
      </Part></Body>
    </Legislation>"""
    content = content_override if content_override is not None else default_content
    content_sha256 = hashlib.sha256(content).hexdigest()
    database.enqueue_research_task(
        task_id=task_id,
        idempotency_key="idem-source-intake-001",
        task_type="source_update_check",
        trigger_kind="manual",
        priority_band="high",
        subject="contract",
        jurisdiction="England and Wales",
        as_of_date="2026-09-01",
        query_sha256="a" * 64,
        source_id="legislation_gov_uk",
        origin_host="www.legislation.gov.uk",
        authority_identity_id=source_identity,
        initial_status="staging_sync",
    )
    objects = EncryptedObjectStore(settings.runtime_object_dir, database, cipher)
    if envelope_override is None:
        object_key = EncryptedResearchQuarantine(objects).store(
            source_id="legislation_gov_uk",
            source_identity=source_identity,
            content=content,
            content_sha256=content_sha256,
        )
    else:
        envelope = {
            "source_id": "legislation_gov_uk",
            "source_identity": source_identity,
            "content_sha256": content_sha256,
            "content_base64": base64.b64encode(content).decode("ascii"),
            **envelope_override,
        }
        object_key = objects.put_json(
            namespace="research_candidates",
            value=envelope,
            metadata={
                "source_id": "legislation_gov_uk",
                "content_sha256": content_sha256,
            },
            ttl_days=30,
        )
    safe_metadata = {
        "content_type": content_type,
        "disposition": "staged_only",
        "response_sha256": content_sha256,
        "owner_decision_required": True,
    }
    metadata_sha256 = hashlib.sha256(
        json.dumps(safe_metadata, sort_keys=True).encode("utf-8")
    ).hexdigest()
    database.add_research_candidate(
        candidate_id=candidate_id,
        task_id=task_id,
        source_id="legislation_gov_uk",
        source_identity=source_identity,
        canonical_url="https://www.legislation.gov.uk/ukpga/2026/1/data.xml",
        metadata_sha256=metadata_sha256,
        content_sha256=content_sha256,
        content_object_key=object_key,
        status="quarantined",
        rights_state="unreviewed",
        safe_metadata=safe_metadata,
    )
    database.mark_staged_research_task_for_review(task_id)
    review = ResearchReviewService(settings, database)
    review.system_verify_candidate(candidate_id)
    if complete_owner_review:
        review.review_candidate(
            candidate_id,
            decision="accept_for_source_intake",
            rights_state="verified",
            identity_review_state="candidate_matched",
            currentness_review_state="verified",
            reviewer_ref=f"reviewer:{'b' * 64}",
            review_manifest_sha256="c" * 64,
        )
    return candidate_id, content, objects


def test_bridge_materialises_once_and_leaves_exact_source_staged(
    tmp_path: Path, database: Database, cipher: LocalCipher
) -> None:
    settings, source_root = _settings(tmp_path)
    candidate_id, content, objects = _reviewed_candidate(settings, database, cipher)
    ingestor = _CountingCreateOnlyIngestor(settings, database, cipher)
    bridge = ResearchSourceIntakeBridge(
        settings,
        database,
        cipher,
        objects=objects,
        registry=REGISTRY,
        ingestor=ingestor,
    )

    planned = bridge.plan(candidate_id, source_root=source_root)
    assert planned.opaque_relative_path.startswith("official-research-intake/legislation/")
    assert tuple(source_root.iterdir()) == ()
    first = bridge.intake(candidate_id, source_root=source_root)
    second = bridge.intake(candidate_id, source_root=source_root)

    assert first.materialization_state == "created"
    assert first.ingestion_status == "citable"
    assert second.materialization_state == "existing_verified"
    assert second.ingestion_status == "already_staged"
    assert first.intake_id == second.intake_id
    assert first.source_version_id == second.source_version_id
    assert first.content_sha256 == hashlib.sha256(content).hexdigest()
    assert first.opaque_relative_path.startswith("official-research-intake/legislation/")
    assert "/Users/" not in json.dumps(first.__dict__ if hasattr(first, "__dict__") else {
        "path": first.opaque_relative_path
    })
    assert ingestor.calls == 2
    assert database.active_index_id() is None
    assert database.fetchone("SELECT COUNT(*) AS n FROM index_builds")["n"] == 0
    candidate = database.fetchone(
        "SELECT status, intake_review_id FROM research_candidates WHERE id=?", (candidate_id,)
    )
    assert candidate is not None and candidate["status"] == "source_intake_pending"
    assert database.fetchone(
        "SELECT status FROM reviews WHERE id=?", (candidate["intake_review_id"],)
    )["status"] == "pending"
    staged = database.fetchone(
        "SELECT review_status, currentness_status, metadata_json FROM source_versions WHERE id=?",
        (first.source_version_id,),
    )
    assert staged is not None
    assert (staged["review_status"], staged["currentness_status"]) == ("staged", "unknown")
    marker = json.loads(staged["metadata_json"])["research_source_intake"]
    assert marker == {
        "schema": "legalbot.research-source-intake-bridge.v1",
        "intake_id": first.intake_id,
        "binding_sha256": first.binding_sha256,
        "candidate_id": candidate_id,
        "task_id": first.task_id,
        "source_id": "legislation_gov_uk",
        "content_sha256": first.content_sha256,
        "system_verification_sha256": first.system_verification_sha256,
        "owner_review_id": first.owner_review_id,
        "owner_review_manifest_sha256": first.owner_review_manifest_sha256,
        "rights_state": "verified",
        "pending_intake_review_id": first.pending_intake_review_id,
    }


def test_bridge_rejects_candidate_before_owner_review(
    tmp_path: Path, database: Database, cipher: LocalCipher
) -> None:
    settings, source_root = _settings(tmp_path)
    candidate_id, _, objects = _reviewed_candidate(
        settings, database, cipher, complete_owner_review=False
    )
    bridge = ResearchSourceIntakeBridge(
        settings, database, cipher, objects=objects, registry=REGISTRY
    )

    with pytest.raises(SourceIntakeBridgeError) as error:
        bridge.plan(candidate_id, source_root=source_root)

    assert error.value.code == "source_intake_candidate_state_invalid"
    assert not tuple(source_root.rglob("official-*"))


def test_bridge_rejects_metadata_only_or_unlicensed_rights_state(
    tmp_path: Path, database: Database, cipher: LocalCipher
) -> None:
    settings, source_root = _settings(tmp_path)
    candidate_id, _, objects = _reviewed_candidate(settings, database, cipher)
    database.execute(
        "UPDATE research_candidates SET rights_state='metadata_only' WHERE id=?", (candidate_id,)
    )
    bridge = ResearchSourceIntakeBridge(
        settings, database, cipher, objects=objects, registry=REGISTRY
    )

    with pytest.raises(SourceIntakeBridgeError) as error:
        bridge.plan(candidate_id, source_root=source_root)

    assert error.value.code == "source_intake_owner_gate_incomplete"


@pytest.mark.parametrize(
    ("envelope_override", "expected_code"),
    [
        (
            {"source_identity": "ukpga:2026:999"},
            "source_intake_quarantine_binding_mismatch",
        ),
        ({"content_base64": "%%%invalid%%%"}, "source_intake_quarantine_base64_invalid"),
    ],
)
def test_bridge_reopens_and_verifies_exact_quarantine_envelope(
    tmp_path: Path,
    database: Database,
    cipher: LocalCipher,
    envelope_override: dict[str, Any],
    expected_code: str,
) -> None:
    settings, source_root = _settings(tmp_path)
    candidate_id, _, objects = _reviewed_candidate(
        settings, database, cipher, envelope_override=envelope_override
    )
    bridge = ResearchSourceIntakeBridge(
        settings, database, cipher, objects=objects, registry=REGISTRY
    )

    with pytest.raises(SourceIntakeBridgeError) as error:
        bridge.plan(candidate_id, source_root=source_root)

    assert error.value.code == expected_code


def test_bridge_fails_closed_on_create_only_materialisation_conflict(
    tmp_path: Path, database: Database, cipher: LocalCipher
) -> None:
    settings, source_root = _settings(tmp_path)
    candidate_id, _, objects = _reviewed_candidate(settings, database, cipher)
    ingestor = _CountingCreateOnlyIngestor(settings, database, cipher)
    bridge = ResearchSourceIntakeBridge(
        settings,
        database,
        cipher,
        objects=objects,
        registry=REGISTRY,
        ingestor=ingestor,
    )
    plan = bridge.plan(candidate_id, source_root=source_root)
    conflict = source_root / plan.opaque_relative_path
    conflict.parent.mkdir(parents=True)
    conflict.write_bytes(b"different immutable bytes")

    with pytest.raises(SourceIntakeBridgeError) as error:
        bridge.intake(candidate_id, source_root=source_root)

    assert error.value.code == "source_intake_materialization_conflict"
    assert conflict.read_bytes() == b"different immutable bytes"
    assert ingestor.calls == 0
    assert database.fetchone("SELECT COUNT(*) AS n FROM source_versions")["n"] == 0


def test_create_only_catalogue_conflict_is_atomic_and_path_free(
    tmp_path: Path, database: Database, cipher: LocalCipher
) -> None:
    settings, source_root = _settings(tmp_path)
    candidate_id, _, objects = _reviewed_candidate(settings, database, cipher)
    bridge = ResearchSourceIntakeBridge(
        settings, database, cipher, objects=objects, registry=REGISTRY
    )
    plan = bridge.plan(candidate_id, source_root=source_root)
    conflicting_document_id = (
        "research-document-"
        + hashlib.sha256(plan.binding_sha256.encode()).hexdigest()[:40]
    )
    now = "2026-09-01T00:00:00+00:00"
    database.execute(
        """
        INSERT INTO documents(
          id, content_sha256, source_identity_id, safe_display_name, media_type,
          status, lane, subject_primary, jurisdiction, created_at, updated_at
        ) VALUES (?, ?, 'synthetic-conflict', 'source-conflict.xml', 'application/xml',
                  'citable', 'primary_authority', 'contract',
                  'England and Wales', ?, ?)
        """,
        (conflicting_document_id, "f" * 64, now, now),
    )

    with pytest.raises(SourceIntakeBridgeError) as error:
        bridge.intake(candidate_id, source_root=source_root)

    assert error.value.code == "source_intake_catalogue_identity_conflict"
    assert "/" not in error.value.code
    assert database.fetchone("SELECT COUNT(*) AS n FROM source_versions")["n"] == 0
    assert database.fetchone("SELECT COUNT(*) AS n FROM source_aliases")["n"] == 0
    assert database.fetchone("SELECT COUNT(*) AS n FROM chunks")["n"] == 0
    assert database.fetchone(
        "SELECT COUNT(*) AS n FROM reviews WHERE review_type='source_version'"
    )["n"] == 0


def test_bridge_requires_the_exact_configured_source_root(
    tmp_path: Path, database: Database, cipher: LocalCipher
) -> None:
    settings, source_root = _settings(tmp_path)
    candidate_id, _, objects = _reviewed_candidate(settings, database, cipher)
    outside = tmp_path / "outside"
    outside.mkdir()
    bridge = ResearchSourceIntakeBridge(
        settings, database, cipher, objects=objects, registry=REGISTRY
    )

    with pytest.raises(SourceIntakeBridgeError) as error:
        bridge.plan(candidate_id, source_root=outside)

    assert error.value.code == "source_intake_root_not_configured"
    assert tuple(source_root.iterdir()) == ()


def test_bridge_rejects_metadata_only_registered_policy_even_after_valid_review_chain(
    tmp_path: Path, database: Database, cipher: LocalCipher
) -> None:
    settings, source_root = _settings(tmp_path)
    candidate_id, _, objects = _reviewed_candidate(settings, database, cipher)
    legislation = REGISTRY.get("legislation_gov_uk")
    metadata_policy = OfficialSourcePolicy(
        source_id=legislation.source_id,
        name=legislation.name,
        base_url=legislation.base_url,
        authority_tier=legislation.authority_tier,
        jurisdictions=legislation.jurisdictions,
        content_mode=ContentMode.METADATA_ONLY,
        online_disposition=legislation.online_disposition,
        licence=legislation.licence,
        machine_access=legislation.machine_access,
        currentness=legislation.currentness,
        additional_permission_required=False,
    )
    bridge = ResearchSourceIntakeBridge(
        settings,
        database,
        cipher,
        objects=objects,
        registry=OfficialSourceRegistry((metadata_policy,)),
    )

    with pytest.raises(SourceIntakeBridgeError) as error:
        bridge.plan(candidate_id, source_root=source_root)

    assert error.value.code == "source_intake_full_text_rights_not_permitted"


def test_bridge_rejects_scholarship_discovery_as_independent_authority(
    tmp_path: Path, database: Database, cipher: LocalCipher
) -> None:
    settings, source_root = _settings(tmp_path)
    candidate_id, _, objects = _reviewed_candidate(settings, database, cipher)
    legislation = REGISTRY.get("legislation_gov_uk")
    scholarship_policy = OfficialSourcePolicy(
        source_id=legislation.source_id,
        name=legislation.name,
        base_url=legislation.base_url,
        authority_tier="secondary_scholarship",
        jurisdictions=legislation.jurisdictions,
        content_mode=ContentMode.FULL_TEXT,
        online_disposition=legislation.online_disposition,
        licence=legislation.licence,
        machine_access=legislation.machine_access,
        currentness=legislation.currentness,
        additional_permission_required=False,
    )
    bridge = ResearchSourceIntakeBridge(
        settings,
        database,
        cipher,
        objects=objects,
        registry=OfficialSourceRegistry((scholarship_policy,)),
    )

    with pytest.raises(SourceIntakeBridgeError) as error:
        bridge.plan(candidate_id, source_root=source_root)

    assert error.value.code == "source_intake_non_authority_source_forbidden"
    assert tuple(source_root.iterdir()) == ()


def test_create_only_ingestion_rejects_scholarship_content_and_preserves_hold(
    tmp_path: Path, database: Database, cipher: LocalCipher
) -> None:
    settings, source_root = _settings(tmp_path)
    scholarship = (
        b"Abstract\nThis article examines a legal question.\n"
        b"Keywords: law, policy\nDOI: 10.1234/example.2026.1\n"
    )
    candidate_id, _, objects = _reviewed_candidate(
        settings,
        database,
        cipher,
        content_override=scholarship,
        content_type="text/plain",
    )
    bridge = ResearchSourceIntakeBridge(
        settings, database, cipher, objects=objects, registry=REGISTRY
    )
    plan = bridge.plan(candidate_id, source_root=source_root)

    with pytest.raises(SourceIntakeBridgeError) as error:
        bridge.intake(candidate_id, source_root=source_root)

    assert error.value.code == "source_intake_non_authority_content_forbidden"
    held_path = source_root / plan.opaque_relative_path
    assert held_path.read_bytes() == scholarship
    assert database.fetchone("SELECT COUNT(*) AS n FROM source_versions")["n"] == 0
    assert database.fetchone("SELECT COUNT(*) AS n FROM chunks")["n"] == 0
