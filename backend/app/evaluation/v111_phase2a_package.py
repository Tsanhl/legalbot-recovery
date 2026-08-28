"""Strict, non-authorizing Phase-2A evidence-package construction.

The builder in this module has no I/O and no runtime dependencies.  It turns
the immutable Owner Certification 60 registry, an exact approved-source
manifest, and externally supplied legal-review dispositions into fifteen
sealed JSON payloads plus a replay index.  It never infers a positive legal
qualification and deliberately has no operation that can create a split,
secret, signature, Stage-A run, model run, promotion, or live state.
"""

from __future__ import annotations

import hashlib
import posixpath
import re
from collections import Counter
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Literal, Self, cast
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..retrieval.source_manifest import (
    MANIFEST_SCHEMA,
    approved_source_manifest_sha256,
)
from .live_suite import LiveEvaluationBundle, canonical_json, sealed_sha256

type Phase2AIssueStatus = Literal[
    "QUALIFIED",
    "QUALIFIED_WITH_NONMATERIAL_NOTE",
    "MATERIAL_CURRENTNESS_GAP",
    "MATERIAL_CANDIDATE_COVERAGE_GAP",
    "SOURCE_VERSION_CONFLICT",
    "GOLD_OR_CASE_DEFECT",
    "OWNER_LEGAL_JUDGMENT_REQUIRED",
    "OFFICIAL_SOURCE_UNAVAILABLE",
    "OUTSIDE_DECLARED_SCOPE",
]

type Phase2ACutoffSupportStatus = Literal[
    "SUPPORTED_FOR_OWNER_DECISION",
    "UNSUPPORTABLE_ON_CURRENT_CANDIDATE",
]

ALLOWED_ISSUE_STATUSES: tuple[str, ...] = (
    "QUALIFIED",
    "QUALIFIED_WITH_NONMATERIAL_NOTE",
    "MATERIAL_CURRENTNESS_GAP",
    "MATERIAL_CANDIDATE_COVERAGE_GAP",
    "SOURCE_VERSION_CONFLICT",
    "GOLD_OR_CASE_DEFECT",
    "OWNER_LEGAL_JUDGMENT_REQUIRED",
    "OFFICIAL_SOURCE_UNAVAILABLE",
    "OUTSIDE_DECLARED_SCOPE",
)
POSITIVE_ISSUE_STATUSES = frozenset({"QUALIFIED", "QUALIFIED_WITH_NONMATERIAL_NOTE"})

ARTIFACT_IDS: tuple[str, ...] = (
    "entry-state",
    "issue-currentness-register",
    "official-source-provenance-register",
    "case-qualification-register",
    "qualification-aggregate",
    "gap-conflict-register",
    "candidate-impact-report",
    "cutoff-recommendation",
    "freshness-material-change-policy",
    "security-owner-controls-proposal",
    "certification-contract-proposal",
    "synthetic-split-verification",
    "owner-readable-summary",
    "owner-decision-payload-draft",
    "final-invariants",
)
ARTIFACT_SCHEMAS = {
    artifact_id: f"legalbot.v111-phase2a.{artifact_id}.v1" for artifact_id in ARTIFACT_IDS
}

PACKAGE_INDEX_SCHEMA = "legalbot.v111-phase2a-package-index.v1"
PACKAGE_STATE = "phase2a_review_only_owner_approval_required"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,254}$")
_ROW_ID = re.compile(r"^(?:live30|live60)-q[0-9]{2}:issue-[0-9]{2}$")
_WINDOWS_ABSOLUTE_PATH = re.compile(r"^[A-Za-z]:[\\/]")
_EMBEDDED_PRIVATE_PATH = re.compile(
    r"(?:^|[\s'\"])(?:/Users/|/home/|/root/|~/|file://|[A-Za-z]:[\\/])"
)
_PRIVATE_KEY_BLOCK = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_PERCENT_ESCAPE = re.compile(r"%([0-9A-Fa-f]{2})")
_URL_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")

_FORBIDDEN_PAYLOAD_KEYS = frozenset(
    {
        "active",
        "active_changed",
        "answer",
        "answer_model_invoked",
        "answer_text",
        "authorizing",
        "canonical_signing_payload",
        "development_30_invoked",
        "development_case_ids",
        "live_activated",
        "model_invocation",
        "o04_issued",
        "owner_signature",
        "owner_signature_present",
        "previous",
        "previous_changed",
        "private_key",
        "prompt",
        "promotion_performed",
        "question",
        "question_text",
        "session_secret",
        "signing_authority_created",
        "signing_payload",
        "split_created",
        "split_frozen",
        "split_secret",
        "split_secret_generated",
        "stage_a_invoked",
        "validation_case_ids",
    }
)

# These are the only control/state claims that may occur inside the payload or
# its optional ``review_details`` extension.  Each entry binds both the type and
# the only safe value.  ``phase2b_allowed`` is the sole dynamic core claim: its
# value is independently recomputed by ``verify_phase2a_package``.
_CORE_CONTROL_FIELDS: dict[str, tuple[type[object], object | None]] = {
    "activepointerabsent": (bool, True),
    "answergenerationbatchsizeiflaterauthorized": (int, 30),
    "answermodelresultsabsent": (bool, True),
    "canonicalpayloaddeferredtophase2b": (bool, True),
    "credentialscreated": (bool, False),
    "previouspointerabsent": (bool, True),
    "realsecretabsent": (bool, True),
    "realsecretgenerated": (bool, False),
    "realsplitabsent": (bool, True),
    "realsplitsecretabsent": (bool, True),
    "sessionsecretabsent": (bool, True),
    "signaturematerialabsent": (bool, True),
    "signingkeyabsent": (bool, True),
    "signingmaterialabsent": (bool, True),
    "splitallowedbythisartifact": (bool, False),
    "stagearesultsabsent": (bool, True),
    "stricthostorigincsrfandsessionsecretproposed": (bool, True),
}

_CORE_PAYLOAD_KEYS_BY_ARTIFACT: dict[str, frozenset[str]] = {
    "entry-state": frozenset(
        {
            "generated_at",
            "exact_commit_sha",
            "exact_tree_sha",
            "worktree_clean",
            "entry_state_sha256",
            "registry_case_count",
            "registry_issue_count",
            "candidate_source_count",
            "candidate",
            "action_absence_audit",
            "phase",
        }
    ),
    "issue-currentness-register": frozenset(
        {"issue_count", "issues", "official_source_review_method_sha256"}
    ),
    "official-source-provenance-register": frozenset(
        {
            "source_count",
            "candidate_current_law_as_of_date",
            "sources",
            "external_official_finding_count",
            "external_official_findings",
        }
    ),
    "case-qualification-register": frozenset({"case_count", "cases"}),
    "qualification-aggregate": frozenset(
        {
            "case_count",
            "issue_count",
            "status_counts",
            "qualified_case_count",
            "all_issues_positive_qualified",
            "owner_approval_required",
            "split_allowed_by_this_artifact",
        }
    ),
    "gap-conflict-register": frozenset({"nonpositive_issue_count", "rows"}),
    "candidate-impact-report": frozenset(
        {
            "candidate_change_required_issue_count",
            "material_candidate_or_currentness_status_count",
            "source_conflict_or_unavailable_issue_count",
            "gold_or_case_remediation_issue_count",
            "owner_legal_judgment_issue_count",
            "candidate_rebuild_required",
            "confirmed_material_candidate_finding_count",
            "external_official_finding_ids",
            "terminal_verdict",
            "candidate_unchanged_by_package",
        }
    ),
    "cutoff-recommendation": frozenset(
        {
            "recommended_cutoff_date",
            "review_target_cutoff_date",
            "cutoff_support_status",
            "common_cutoff_freezable",
            "cutoff_basis_sha256",
            "recommendation_is_authority",
            "owner_approval_required",
        }
    ),
    "freshness-material-change-policy": frozenset(
        {
            "policy_sha256",
            "official_primary_sources_only",
            "material_candidate_delta_requires_reseal",
            "material_candidate_delta_requires_requalification",
            "material_candidate_delta_requires_retrieval_reattestation",
            "material_candidate_delta_requires_final_development_rerun",
            "source_currentness_status_counts",
        }
    ),
    "security-owner-controls-proposal": frozenset(
        {
            "proposal_sha256",
            "pinned_local_ed25519_public_key_proposed",
            "private_unix_domain_socket_transport_proposed",
            "maximum_memory_gib_proposed",
            "minimum_free_memory_gib_proposed",
            "distinct_private_review_root_count_proposed",
            "literal_loopback_host_proposed",
            "strict_host_origin_csrf_and_session_secret_proposed",
            "controls_created",
            "credentials_created",
        }
    ),
    "certification-contract-proposal": frozenset(
        {
            "proposal_sha256",
            "contract_state",
            "threshold_relaxation_after_results_allowed",
            "same_failure_fingerprint_limit",
            "answer_generation_batch_size_if_later_authorized",
            "owner_approval_required",
        }
    ),
    "synthetic-split-verification": frozenset(
        {
            "verification_sha256",
            "synthetic_only",
            "verification_passed",
            "real_registry_used_for_partition",
            "real_secret_generated",
            "real_complement_frozen",
        }
    ),
    "owner-readable-summary": frozenset(
        {
            "phase",
            "case_count",
            "issue_count",
            "candidate_source_count",
            "qualified_issue_count",
            "nonpositive_issue_count",
            "terminal_verdict",
            "candidate_rebuild_required",
            "next_gate",
        }
    ),
    "owner-decision-payload-draft": frozenset(
        {
            "draft_state",
            "cutoff_basis_sha256",
            "freshness_policy_sha256",
            "security_controls_proposal_sha256",
            "certification_contract_proposal_sha256",
            "canonical_payload_deferred_to_phase2b",
            "signature_material_absent",
            "owner_choices_pending",
        }
    ),
    "final-invariants": frozenset(
        {
            "registry_case_count",
            "registry_issue_count",
            "issue_rows_unique",
            "candidate_source_manifest_unchanged",
            "candidate_unchanged",
            "real_split_absent",
            "real_secret_absent",
            "signing_material_absent",
            "runtime_actions_absent",
            "owner_approval_required",
            "action_absence_audit_sha256",
            "terminal_verdict",
            "candidate_rebuild_required",
            "phase2b_allowed",
        }
    ),
}

_CORE_LITERAL_VALUES_BY_ARTIFACT: dict[str, Mapping[str, object]] = {
    "entry-state": {
        "worktree_clean": True,
        "registry_case_count": 60,
        "registry_issue_count": 585,
        "phase": "PHASE_2A",
    },
    "issue-currentness-register": {"issue_count": 585},
    "case-qualification-register": {"case_count": 60},
    "qualification-aggregate": {
        "case_count": 60,
        "issue_count": 585,
        "owner_approval_required": True,
        "split_allowed_by_this_artifact": False,
    },
    "candidate-impact-report": {"candidate_unchanged_by_package": True},
    "cutoff-recommendation": {
        "recommendation_is_authority": False,
        "owner_approval_required": True,
    },
    "freshness-material-change-policy": {
        "official_primary_sources_only": True,
        "material_candidate_delta_requires_reseal": True,
        "material_candidate_delta_requires_requalification": True,
        "material_candidate_delta_requires_retrieval_reattestation": True,
        "material_candidate_delta_requires_final_development_rerun": True,
    },
    "security-owner-controls-proposal": {
        "pinned_local_ed25519_public_key_proposed": True,
        "private_unix_domain_socket_transport_proposed": True,
        "maximum_memory_gib_proposed": 12,
        "minimum_free_memory_gib_proposed": 3,
        "distinct_private_review_root_count_proposed": 3,
        "literal_loopback_host_proposed": "127.0.0.1",
        "strict_host_origin_csrf_and_session_secret_proposed": True,
        "controls_created": False,
        "credentials_created": False,
    },
    "certification-contract-proposal": {
        "contract_state": "PROPOSED_NOT_FROZEN",
        "threshold_relaxation_after_results_allowed": False,
        "same_failure_fingerprint_limit": 2,
        "answer_generation_batch_size_if_later_authorized": 30,
        "owner_approval_required": True,
    },
    "synthetic-split-verification": {
        "synthetic_only": True,
        "verification_passed": True,
        "real_registry_used_for_partition": False,
        "real_secret_generated": False,
        "real_complement_frozen": False,
    },
    "owner-readable-summary": {"phase": "PHASE_2A", "case_count": 60, "issue_count": 585},
    "owner-decision-payload-draft": {
        "draft_state": "NONAUTHORIZING_RECOMMENDATIONS_ONLY",
        "canonical_payload_deferred_to_phase2b": True,
        "signature_material_absent": True,
        "owner_choices_pending": True,
    },
    "final-invariants": {
        "registry_case_count": 60,
        "registry_issue_count": 585,
        "issue_rows_unique": True,
        "candidate_source_manifest_unchanged": True,
        "candidate_unchanged": True,
        "real_split_absent": True,
        "real_secret_absent": True,
        "signing_material_absent": True,
        "runtime_actions_absent": True,
        "owner_approval_required": True,
    },
}

_REVIEW_DETAIL_CONTROL_FIELDS: dict[str, tuple[type[object], object]] = {
    "answermodelexecuted": (bool, False),
    "answermodelresult": (int, 0),
    "futureownersignedpayloaddeferred": (bool, True),
    "futuresigningdomain": (str, "LEGALBOT-V111-OWNER-DECISION-ED25519-V1-NUL"),
    "phase2bauthorized": (bool, False),
    "privatekeycustody": (str, "owner-offline-only-mode-0600"),
    "privatekeyformat": (str, "encrypted-pkcs8"),
    "promotionorliveaction": (bool, False),
    "realsecretgenerated": (bool, False),
    "realsplit": (int, 0),
    "realsplitexecuted": (bool, False),
    "stageaexecuted": (bool, False),
    "stagearesult": (int, 0),
    "stageaused": (bool, False),
}

# Every boolean inside caller-supplied review details is an assertion, even if
# its key avoids obvious words such as ``authorize`` or ``split``.  Keep the
# accepted assertion vocabulary closed and value-bound so semantic aliases
# such as ``gate_open`` or ``all_issues_positive_qualified`` fail closed.
_REVIEW_DETAIL_BOOLEAN_FIELDS: dict[str, bool] = {
    "accountedexactlyonce": True,
    "all585accounted": True,
    "answerhistoryused": False,
    "answermodelexecuted": False,
    "automatedtargetislegalsafetygate": False,
    "blockingreviewsufficienttostop": True,
    "candidatebytesunchanged": True,
    "cloudorsyncancestorallowed": False,
    "cloudpublicationtrainingexport": False,
    "contentbytesembeddedinpackage": False,
    "contentbytesretrievedbybuilder": False,
    "contentdigestisexternalreviewobservation": True,
    "createonlyartifacts": True,
    "crosslaneprojectionallowed": False,
    "dedicatedownercontrolrootabsent": True,
    "doesnotclaimabsencefromarbitraryhostorunconfiguredsources": True,
    "doesnotclaimarbitraryhostforensicabsence": True,
    "doesnotclaimprocessmemoryephemeralrandomnessabsence": True,
    "environmentproxytrust": False,
    "existingcandidatemutated": False,
    "externalcontentobservationreplayablefrompackagealone": False,
    "externaldocumentbytesembedded": False,
    "externaldocumentbytesretrievedbybuilder": False,
    "futureownersignedpayloaddeferred": True,
    "humanowneradjudicationrequired": True,
    "legalpropositionreviewcomplete": False,
    "legalqualificationcomplete": False,
    "materialclaimrequiresfrozenevidencespan": True,
    "modelrenderedcitationsallowed": False,
    "mutablejudgmentlandingpagesusedascontentproof": False,
    "officialjudgmentpdfcontentidentitiesrecorded": True,
    "officialprimarysourcesonly": True,
    "ordinarylogscontaincaseoranswerprose": False,
    "ownerauthoritative": False,
    "ownercontrolscreated": False,
    "partitionrandomnesspersistentlocationschecked": True,
    "perprovisioncommencementeffectivetransitionreviewrequired": True,
    "phase2bauthorized": False,
    "preflightfailureconsumessealedrun": False,
    "preflightrequired": True,
    "priorcyclesimmutable": True,
    "promotionorliveaction": False,
    "qualificationstopapplied": True,
    "qualitymotivatedselectivererunallowed": False,
    "reallaneidentitiesemitted": False,
    "realregistrypartitioned": False,
    "realsecretgenerated": False,
    "realsplitexecuted": False,
    "recommended": True,
    "resultsexposureendssealedstatus": True,
    "reviewerversionsfrozenbeforerun": True,
    "rowreviewrecordsunique": True,
    "royalassentisnotcommencement": True,
    "rubricorthresholdrelaxationafterresults": False,
    "silentcandidateboundupdateallowed": False,
    "singleactwideeffectivedateinferenceallowed": False,
    "singleeffectivedateclaimed": False,
    "sourceidentityjurisdictioncurrentnessrequired": True,
    "stageaexecuted": False,
    "stageaused": False,
    "symlinkshardlinksallowed": False,
    "tcphttpcloudfallbackallowed": False,
    "timeoutandtokenfencesrequired": True,
    "unresolvedsourceversionconflictshidden": False,
    "wildcardlanpublicbindallowed": False,
}

_CONTROL_KEY_TOKENS = (
    "active",
    "answermodel",
    "authoriz",
    "credential",
    "development30",
    "modelinvocation",
    "o04",
    "ownersigned",
    "phase2b",
    "previous",
    "privatekey",
    "promotion",
    "sessionsecret",
    "sessiontoken",
    "signature",
    "signing",
    "split",
    "stagea",
)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _artifact_seal(value: Mapping[str, Any]) -> str:
    material = dict(value)
    material.pop("seal_sha256", None)
    return _sha256_bytes(canonical_json(material))


def _index_seal(value: Mapping[str, Any]) -> str:
    material = dict(value)
    material.pop("index_sha256", None)
    return _sha256_bytes(canonical_json(material))


def _is_private_path(value: str) -> bool:
    stripped = value.strip()
    return (
        stripped.startswith(("/", "~/", "file://"))
        or _WINDOWS_ABSOLUTE_PATH.match(stripped) is not None
        or _EMBEDDED_PRIVATE_PATH.search(stripped) is not None
        or _PRIVATE_KEY_BLOCK.search(stripped) is not None
    )


def _normalised_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def _key_is_forbidden(value: str) -> bool:
    normalised = _normalised_key(value)
    exact = {_normalised_key(item) for item in _FORBIDDEN_PAYLOAD_KEYS}
    return (
        value.casefold() in _FORBIDDEN_PAYLOAD_KEYS
        or normalised in exact
        or normalised
        in {
            "credential",
            "credentials",
            "password",
            "privatekey",
            "secret",
            "sessiontoken",
            "signingkey",
        }
        or "splitsecret" in normalised
        or "sessionsecret" in normalised
        or "questiontext" in normalised
        or "answertext" in normalised
        or "modeloutput" in normalised
        or normalised.endswith("signature")
    )


def _assert_typed_control_field(
    *,
    key: str,
    value: Any,
    location: str,
    in_review_details: bool,
    artifact_id: str | None,
) -> None:
    normalised = _normalised_key(key)
    if in_review_details and type(value) is bool:
        expected_boolean = _REVIEW_DETAIL_BOOLEAN_FIELDS.get(normalised)
        if expected_boolean is None or value is not expected_boolean:
            raise ValueError(
                f"Phase-2A review detail boolean is not an exact safe assertion at {location}.{key}"
            )
    if in_review_details and normalised in {
        "qualificationstate",
        "ownerapprovalstate",
        "gateopen",
        "releaseready",
    }:
        raise ValueError(f"Phase-2A review details contain a forbidden semantic alias: {key}")
    if normalised == "phase2ballowed":
        if (
            artifact_id != "final-invariants"
            or in_review_details
            or location != "payload"
            or key != "phase2b_allowed"
            or type(value) is not bool
        ):
            raise ValueError(
                "Phase-2A phase2b_allowed is forbidden outside final-invariants.payload"
            )
        return
    is_control_field = _key_is_forbidden(key) or any(
        token in normalised for token in _CONTROL_KEY_TOKENS
    )
    if not is_control_field:
        return
    allowlist = _REVIEW_DETAIL_CONTROL_FIELDS if in_review_details else _CORE_CONTROL_FIELDS
    contract = allowlist.get(normalised)
    if contract is None:
        raise ValueError(f"Phase-2A payload contains forbidden control field: {key}")
    expected_type, expected_value = contract
    if type(value) is not expected_type or (expected_value is not None and value != expected_value):
        raise ValueError(
            f"Phase-2A payload control field has an unsafe type or value at {location}.{key}"
        )


def _assert_prose_and_private_path_free(
    value: Any,
    *,
    location: str = "payload",
    in_review_details: bool = False,
    artifact_id: str | None = None,
) -> None:
    if isinstance(value, Mapping):
        for raw_key, child in value.items():
            key = str(raw_key)
            child_is_review_details = in_review_details or key == "review_details"
            _assert_typed_control_field(
                key=key,
                value=child,
                location=location,
                in_review_details=child_is_review_details,
                artifact_id=artifact_id,
            )
            if _is_private_path(key):
                raise ValueError(f"Phase-2A payload contains a private path key at {location}")
            _assert_prose_and_private_path_free(
                child,
                location=f"{location}.{key}",
                in_review_details=child_is_review_details,
                artifact_id=artifact_id,
            )
        return
    if isinstance(value, list | tuple):
        for index, child in enumerate(value):
            _assert_prose_and_private_path_free(
                child,
                location=f"{location}[{index}]",
                in_review_details=in_review_details,
                artifact_id=artifact_id,
            )
        return
    if isinstance(value, str) and _is_private_path(value):
        raise ValueError(f"Phase-2A payload contains a private path at {location}")


def _assert_exact_artifact_payload_contract(
    *, artifact_id: str, payload: Mapping[str, Any]
) -> None:
    expected_keys = _CORE_PAYLOAD_KEYS_BY_ARTIFACT.get(artifact_id)
    if expected_keys is None:
        raise ValueError("Phase-2A artifact has no exact payload contract")
    actual_keys = set(payload)
    allowed_keys = set(expected_keys)
    if "review_details" in actual_keys:
        allowed_keys.add("review_details")
        if not isinstance(payload["review_details"], Mapping):
            raise ValueError("Phase-2A review_details must be a mapping")
    if actual_keys != allowed_keys:
        raise ValueError("Phase-2A artifact payload keys differ from its exact contract")
    for key, expected in _CORE_LITERAL_VALUES_BY_ARTIFACT.get(artifact_id, {}).items():
        actual = payload.get(key)
        if type(actual) is not type(expected) or actual != expected:
            raise ValueError(
                f"Phase-2A artifact payload constant differs from its contract: {artifact_id}.{key}"
            )


def _iter_payload_strings(value: Any) -> Iterator[str]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            yield str(key)
            yield from _iter_payload_strings(child)
    elif isinstance(value, list | tuple):
        for child in value:
            yield from _iter_payload_strings(child)
    elif isinstance(value, str):
        yield value


def _json_replay_value_equal(actual: Any, expected: Any) -> bool:
    """Compare replay values while normalising only JSON array containers."""
    if isinstance(actual, list | tuple) or isinstance(expected, list | tuple):
        if not isinstance(actual, list | tuple) or not isinstance(expected, list | tuple):
            return False
        return len(actual) == len(expected) and all(
            _json_replay_value_equal(actual_item, expected_item)
            for actual_item, expected_item in zip(actual, expected, strict=True)
        )
    if isinstance(actual, Mapping) or isinstance(expected, Mapping):
        if not isinstance(actual, Mapping) or not isinstance(expected, Mapping):
            return False
        if set(actual) != set(expected):
            return False
        return all(_json_replay_value_equal(actual[key], expected[key]) for key in actual)
    return type(actual) is type(expected) and actual == expected


class Phase2ACodeBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    commit_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    tree_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    worktree_clean: Literal[True]


class Phase2ACandidateBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    build_id: Literal["current-law-ew-full-fp16-v111-20260818-a"]
    candidate_manifest_sha256: Literal[
        "e28a4138e87cfeb2502e746073208ab25a647de8082a3c7fe96a44ed7d5cc74a"
    ]
    candidate_seal_file_sha256: Literal[
        "d8009de258306cb13ae2b5d0c0d03dbf725d8c0e563bccde74cedaa9acdba04a"
    ]
    approved_source_manifest_sha256: Literal[
        "d2c1434fd5fc44d4f2f7e4f7629293f646bb28ed9b8466687feb6c470ea53ac0"
    ]
    approved_source_manifest_file_sha256: Literal[
        "02a13a3641d0e406d974a1c8f1a4912ae6e761d059774bd68ff97a4cc7732e0e"
    ]
    embedding_store_sha256: Literal[
        "1d7b1bddebe83694815066f5254c5b0c7a1d05febd4e2b9e2120f2ec3fe3c018"
    ]
    reranker_store_sha256: Literal[
        "f775cce47e7cbed490693a954aadcf6141cdf5ffa31b3e33f229adc374223e29"
    ]
    document_count: Literal[85]
    chunk_count: Literal[149855]
    vector_count: Literal[149855]
    dimensions: Literal[1024]


class Phase2AActionAbsenceAudit(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    audit_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    active_pointer_absent: Literal[True]
    previous_pointer_absent: Literal[True]
    real_split_absent: Literal[True]
    real_split_secret_absent: Literal[True]
    signing_key_absent: Literal[True]
    session_secret_absent: Literal[True]
    real_review_roots_absent: Literal[True]
    stage_a_results_absent: Literal[True]
    answer_model_results_absent: Literal[True]
    development_projection_absent: Literal[True]


class Phase2AReviewInputs(BaseModel):
    """External identities and owner proposals; none conveys authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    generated_at: datetime
    code: Phase2ACodeBinding
    candidate: Phase2ACandidateBinding
    action_absence_audit: Phase2AActionAbsenceAudit
    entry_state_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    official_source_review_method_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    recommended_cutoff_date: date | None = None
    review_target_cutoff_date: date | None = None
    cutoff_support_status: Phase2ACutoffSupportStatus = "SUPPORTED_FOR_OWNER_DECISION"
    cutoff_basis_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    freshness_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    security_controls_proposal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    certification_contract_proposal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    synthetic_split_verification_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    synthetic_split_verification_passed: bool
    terminal_verdict: Literal["OWNER_DECISIONS_REQUIRED", "BLOCKED_MATERIAL_GAPS"] = (
        "OWNER_DECISIONS_REQUIRED"
    )
    candidate_rebuild_required: bool = False
    confirmed_material_candidate_finding_count: int = Field(default=0, ge=0)

    @field_validator("generated_at")
    @classmethod
    def generated_at_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Phase-2A generation time must be timezone-aware")
        return value

    @model_validator(mode="after")
    def cutoff_claim_matches_support_status(self) -> Self:
        if self.cutoff_support_status == "SUPPORTED_FOR_OWNER_DECISION":
            if self.recommended_cutoff_date is None:
                raise ValueError("a supported cutoff requires a recommended cutoff date")
        elif self.recommended_cutoff_date is not None:
            raise ValueError("an unsupported cutoff cannot be presented as recommended")
        if (
            self.review_target_cutoff_date is not None
            and self.recommended_cutoff_date is not None
            and self.recommended_cutoff_date > self.review_target_cutoff_date
        ):
            raise ValueError("recommended cutoff cannot exceed the review target")
        if self.candidate_rebuild_required and (
            self.terminal_verdict != "BLOCKED_MATERIAL_GAPS"
            or self.cutoff_support_status != "UNSUPPORTABLE_ON_CURRENT_CANDIDATE"
            or self.confirmed_material_candidate_finding_count < 1
        ):
            raise ValueError("candidate rebuild findings require fail-closed blocked semantics")
        return self


class Phase2AExternalOfficialFinding(BaseModel):
    """One official primary-source record confirmed absent from the candidate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,127}$")
    source_class: Literal["OFFICIAL_LEGISLATION", "OFFICIAL_BINDING_JUDGMENT"]
    official_title: str = Field(min_length=1, max_length=512)
    official_identifier: str = Field(min_length=1, max_length=128)
    canonical_url: str = Field(min_length=1, max_length=2048)
    retrieved_at: datetime
    retrieved_content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    legal_effect_date: date
    authority_status_code: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,127}$")
    affected_case_ids: tuple[str, ...]
    candidate_present: Literal[False]
    materiality: Literal["MATERIAL"]
    candidate_rebuild_required: Literal[True]

    @field_validator("retrieved_at")
    @classmethod
    def retrieval_time_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("official finding retrieval time must be timezone-aware")
        return value

    @field_validator("canonical_url")
    @classmethod
    def source_url_is_official_https(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or parsed.hostname
            not in {
                "legislation.gov.uk",
                "www.legislation.gov.uk",
                "supremecourt.uk",
                "www.supremecourt.uk",
            }
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("official finding URL is not an approved primary-source URL")
        return value

    @field_validator("affected_case_ids")
    @classmethod
    def affected_cases_are_safe_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if (
            not values
            or len(values) != len(set(values))
            or any(not re.fullmatch(r"(?:live30|live60)-q[0-9]{2}", item) for item in values)
        ):
            raise ValueError("official finding affected cases are unsafe or duplicated")
        return values


class IssueDispositionInput(BaseModel):
    """One externally supplied legal-review result; no status is inferred."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    primary_status: Phase2AIssueStatus
    official_review_record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    official_source_version_ids: tuple[str, ...] = ()
    evidence_span_binding_sha256s: tuple[str, ...] = ()
    registry_gold_binding_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    candidate_source_binding_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    source_gold_consistency_binding_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    currentness_binding_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    effective_date_binding_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    note_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    reason_code: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9-]{2,127}$")
    supporting_evidence_sha256s: tuple[str, ...] = ()
    affected_proposition_state: Literal[
        "POSITIVELY_BOUND",
        "UNMAPPABLE_WITHOUT_GOLD",
        "MAPPED_MATERIAL_GAP",
        "OWNER_JUDGMENT_PENDING",
        "OUTSIDE_SCOPE",
    ] = "POSITIVELY_BOUND"
    prevents_common_cutoff: bool = False
    remediation_code: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9-]{2,127}$")
    candidate_bytes_change_required: bool | None = None
    owner_approval_required: bool = False
    external_official_finding_ids: tuple[str, ...] = ()

    @field_validator("official_source_version_ids")
    @classmethod
    def source_ids_are_safe_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)) or any(not _SAFE_ID.fullmatch(item) for item in values):
            raise ValueError("issue disposition source identities are unsafe or duplicated")
        return values

    @field_validator("evidence_span_binding_sha256s")
    @classmethod
    def evidence_digests_are_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)) or any(not _SHA256.fullmatch(item) for item in values):
            raise ValueError("issue disposition evidence bindings are invalid or duplicated")
        return values

    @field_validator("supporting_evidence_sha256s")
    @classmethod
    def support_digests_are_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)) or any(not _SHA256.fullmatch(item) for item in values):
            raise ValueError("issue disposition supporting evidence is invalid or duplicated")
        return values

    @field_validator("external_official_finding_ids")
    @classmethod
    def external_findings_are_safe_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)) or any(not _SAFE_ID.fullmatch(item) for item in values):
            raise ValueError("issue disposition external findings are unsafe or duplicated")
        return values

    @model_validator(mode="after")
    def positive_dispositions_have_explicit_evidence(self) -> Self:
        if self.primary_status in POSITIVE_ISSUE_STATUSES and (
            not self.official_source_version_ids
            or not self.evidence_span_binding_sha256s
            or self.registry_gold_binding_sha256 is None
            or self.candidate_source_binding_sha256 is None
            or self.source_gold_consistency_binding_sha256 is None
            or self.currentness_binding_sha256 is None
            or self.effective_date_binding_sha256 is None
        ):
            raise ValueError(
                "positive issue qualification requires explicit row-specific source, candidate, "
                "gold, currentness and effective-date bindings"
            )
        if self.primary_status == "QUALIFIED_WITH_NONMATERIAL_NOTE" and self.note_sha256 is None:
            raise ValueError("qualified-with-note disposition requires a note digest")
        if self.primary_status in POSITIVE_ISSUE_STATUSES:
            if (
                self.reason_code is not None
                or self.affected_proposition_state != "POSITIVELY_BOUND"
                or self.prevents_common_cutoff
                or self.remediation_code is not None
                or self.candidate_bytes_change_required is not False
                or self.owner_approval_required
            ):
                raise ValueError("positive issue qualification contains contradictory blockers")
        else:
            if any(
                value is not None
                for value in (
                    self.registry_gold_binding_sha256,
                    self.candidate_source_binding_sha256,
                    self.source_gold_consistency_binding_sha256,
                    self.currentness_binding_sha256,
                    self.effective_date_binding_sha256,
                )
            ):
                raise ValueError("nonpositive issue disposition cannot carry positive bindings")
            if (
                self.reason_code is None
                or not self.supporting_evidence_sha256s
                or self.affected_proposition_state == "POSITIVELY_BOUND"
                or self.remediation_code is None
                or not self.owner_approval_required
            ):
                raise ValueError("nonpositive issue disposition requires complete blocker details")
        return self


class Phase2AArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: str = Field(alias="schema", min_length=1, max_length=128)
    artifact_id: str = Field(min_length=1, max_length=64)
    document_state: Literal["phase2a_review_only_owner_approval_required"]
    authorizing: Literal[False]
    owner_signature_present: Literal[False]
    signing_authority_created: Literal[False]
    split_created: Literal[False]
    split_secret_generated: Literal[False]
    stage_a_invoked: Literal[False]
    answer_model_invoked: Literal[False]
    development_30_invoked: Literal[False]
    active_changed: Literal[False]
    previous_changed: Literal[False]
    promotion_performed: Literal[False]
    o04_issued: Literal[False]
    live_activated: Literal[False]
    contains_question_prose: Literal[False]
    contains_private_paths: Literal[False]
    registry_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_source_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    payload: dict[str, Any]
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def artifact_is_exact_and_safe(self) -> Self:
        expected_schema = ARTIFACT_SCHEMAS.get(self.artifact_id)
        if expected_schema is None or self.schema_name != expected_schema:
            raise ValueError("Phase-2A artifact schema does not match its identity")
        _assert_exact_artifact_payload_contract(artifact_id=self.artifact_id, payload=self.payload)
        _assert_prose_and_private_path_free(self.payload, artifact_id=self.artifact_id)
        if self.payload_sha256 != _sha256_bytes(canonical_json(self.payload)):
            raise ValueError("Phase-2A payload digest does not match")
        if self.seal_sha256 != _artifact_seal(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("Phase-2A artifact seal does not match")
        return self


class Phase2AArtifactIndexEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ordinal: int = Field(ge=1, le=15)
    artifact_id: str
    schema_name: str
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class Phase2APackageIndex(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.v111-phase2a-package-index.v1"] = Field(alias="schema")
    document_state: Literal["phase2a_review_only_owner_approval_required"]
    authorizing: Literal[False]
    owner_signature_present: Literal[False]
    signing_payload_created: Literal[False]
    artifact_count: Literal[15]
    artifact_order: tuple[str, ...]
    entries: tuple[Phase2AArtifactIndexEntry, ...]
    registry_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_source_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    index_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def index_is_complete(self) -> Self:
        if self.artifact_order != ARTIFACT_IDS:
            raise ValueError("Phase-2A package artifact order is not exact")
        if len(self.entries) != 15 or tuple(item.ordinal for item in self.entries) != tuple(
            range(1, 16)
        ):
            raise ValueError("Phase-2A package index is incomplete")
        if tuple(item.artifact_id for item in self.entries) != ARTIFACT_IDS:
            raise ValueError("Phase-2A package index identities are incomplete")
        if len({item.artifact_sha256 for item in self.entries}) != 15:
            raise ValueError("Phase-2A package index contains duplicate artifacts")
        if self.index_sha256 != _index_seal(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("Phase-2A package index seal does not match")
        return self


@dataclass(frozen=True, slots=True)
class Phase2APackage:
    artifacts: tuple[Phase2AArtifact, ...]
    index: Phase2APackageIndex

    def artifact(self, artifact_id: str) -> Phase2AArtifact:
        for artifact in self.artifacts:
            if artifact.artifact_id == artifact_id:
                return artifact
        raise KeyError(artifact_id)


def _registry_issue_rows(bundle: LiveEvaluationBundle) -> tuple[dict[str, Any], ...]:
    if len(bundle.registry.cases) != 60:
        raise ValueError("Phase-2A requires exactly 60 registry cases")
    rows: list[dict[str, Any]] = []
    ordinal = 0
    for case in bundle.registry.cases:
        gold_source_ids = tuple(case.acceptable_source_ids)
        gold_span_binding_sha256s = tuple(
            _sha256_bytes(canonical_json(span)) for span in case.exact_gold_spans
        )
        for issue_number, label in enumerate(case.must_cover_issues, start=1):
            ordinal += 1
            issue_id = f"issue-{issue_number:02d}"
            label_sha256 = _sha256_bytes(label.encode("utf-8"))
            identity_sha256 = sealed_sha256(
                {
                    "schema": "legalbot.v111-registry-issue-identity.v1",
                    "ordinal": ordinal,
                    "case_id": case.case_id,
                    "case_record_sha256": case.record_sha256,
                    "issue_id": issue_id,
                    "issue_label_sha256": label_sha256,
                }
            )
            rows.append(
                {
                    "ordinal": ordinal,
                    "row_id": f"{case.case_id}:{issue_id}",
                    "case_id": case.case_id,
                    "case_record_sha256": case.record_sha256,
                    "issue_id": issue_id,
                    "issue_label_sha256": label_sha256,
                    "registry_issue_identity_sha256": identity_sha256,
                    "legal_domain": case.subject,
                    "task_type": case.task_type,
                    "jurisdiction": case.jurisdiction,
                    "gold_source_binding_count": len(case.acceptable_source_ids),
                    "gold_span_binding_count": len(case.exact_gold_spans),
                    "gold_source_ids": gold_source_ids,
                    "gold_span_binding_sha256s": gold_span_binding_sha256s,
                    "expected_registry_gold_binding_sha256": sealed_sha256(
                        {
                            "schema": "legalbot.v111-phase2a-registry-gold-binding.v1",
                            "row_id": f"{case.case_id}:{issue_id}",
                            "registry_issue_identity_sha256": identity_sha256,
                            "gold_source_ids": gold_source_ids,
                            "gold_span_binding_sha256s": gold_span_binding_sha256s,
                        }
                    ),
                }
            )
    if len(rows) != 585 or len({str(row["row_id"]) for row in rows}) != 585:
        raise ValueError("Phase-2A requires exactly 585 unique registry issues")
    return tuple(rows)


def _candidate_sources(manifest: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    if (
        manifest.get("schema") != MANIFEST_SCHEMA
        or manifest.get("manifest_sha256") != approved_source_manifest_sha256(manifest)
        or manifest.get("authority_lane_only") is not True
        or manifest.get("benchmark_answers_used_for_selection") is not False
    ):
        raise ValueError("Phase-2A candidate source manifest identity or policy is invalid")
    raw_sources = manifest.get("sources")
    if not isinstance(raw_sources, list) or int(manifest.get("source_count") or -1) != len(
        raw_sources
    ):
        raise ValueError("Phase-2A candidate source inventory is incomplete")
    rows: list[dict[str, Any]] = []
    for ordinal, raw in enumerate(raw_sources, start=1):
        if not isinstance(raw, Mapping):
            raise ValueError("Phase-2A candidate source row is invalid")
        source_version_id = str(raw.get("source_version_id") or "")
        canonical_url = str(raw.get("canonical_url") or "")
        parsed = urlsplit(canonical_url)
        if (
            not _SAFE_ID.fullmatch(source_version_id)
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.hostname in {"localhost", "127.0.0.1", "::1"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Phase-2A candidate source identity or URL is unsafe")
        content_sha256 = str(raw.get("content_sha256") or "")
        version_sha256 = str(raw.get("version_sha256") or "")
        lane = str(raw.get("lane") or "")
        currentness_status = str(raw.get("currentness_status") or "")
        if (
            not _SHA256.fullmatch(content_sha256)
            or not _SHA256.fullmatch(version_sha256)
            or lane != "primary_authority"
            or not _SAFE_ID.fullmatch(currentness_status)
        ):
            raise ValueError("Phase-2A candidate source digest is invalid")
        rows.append(
            {
                "ordinal": ordinal,
                "source_version_id": source_version_id,
                "authority_identity_sha256": _sha256_bytes(
                    str(raw.get("authority_identity_id") or "").encode("utf-8")
                ),
                "stable_identifier_sha256": _sha256_bytes(
                    str(raw.get("stable_identifier") or "").encode("utf-8")
                ),
                "canonical_url": canonical_url,
                "content_sha256": content_sha256,
                "version_sha256": version_sha256,
                "jurisdiction_sha256": _sha256_bytes(
                    str(raw.get("jurisdiction") or "").encode("utf-8")
                ),
                "lane": lane,
                "as_of_date": raw.get("as_of_date"),
                "currentness_reviewed_as_of_date": raw.get("currentness_reviewed_as_of_date"),
                "currentness_status": currentness_status,
                "currentness_verified": raw.get("currentness_verified") is True,
                "full_current_law_verification_eligible": raw.get(
                    "full_current_law_verification_eligible"
                )
                is True,
                "subsequent_treatment_check_required": raw.get(
                    "subsequent_treatment_check_required"
                )
                is True,
                "subsequent_treatment_verified": raw.get("subsequent_treatment_verified") is True,
            }
        )
    if not rows or len({str(row["source_version_id"]) for row in rows}) != len(rows):
        raise ValueError("Phase-2A candidate source identities are empty or duplicated")
    return tuple(rows)


def _canonical_official_url_identity(value: str) -> str:
    """Collapse harmless host/trailing-slash aliases for absence comparison."""

    parsed = urlsplit(value)
    hostname = (parsed.hostname or "").casefold()
    if hostname.startswith("www."):
        hostname = hostname[4:]
    decoded_path = _PERCENT_ESCAPE.sub(
        lambda match: (
            chr(int(match.group(1), 16))
            if chr(int(match.group(1), 16)) in _URL_UNRESERVED
            else f"%{match.group(1).upper()}"
        ),
        parsed.path,
    )
    path = posixpath.normpath(decoded_path) if decoded_path else "/"
    if not path.startswith("/"):
        path = f"/{path}"
    path = path.rstrip("/") or "/"
    return f"{parsed.scheme.casefold()}://{hostname}{path}"


def _coerce_disposition(value: IssueDispositionInput | Mapping[str, Any]) -> IssueDispositionInput:
    if isinstance(value, IssueDispositionInput):
        return value
    return IssueDispositionInput.model_validate(value)


def _resolved_dispositions(
    *,
    issue_rows: Sequence[Mapping[str, Any]],
    source_rows: Sequence[Mapping[str, Any]],
    dispositions: Mapping[str, IssueDispositionInput | Mapping[str, Any]],
    default_disposition: IssueDispositionInput | Mapping[str, Any] | None,
) -> dict[str, IssueDispositionInput]:
    expected_ids = {str(row["row_id"]) for row in issue_rows}
    if any(not _ROW_ID.fullmatch(row_id) for row_id in dispositions):
        raise ValueError("Phase-2A disposition mapping contains an unsafe row identity")
    unknown = set(dispositions).difference(expected_ids)
    if unknown:
        raise ValueError("Phase-2A disposition mapping contains unknown issue rows")
    default = _coerce_disposition(default_disposition) if default_disposition is not None else None
    if default is not None and default.primary_status in POSITIVE_ISSUE_STATUSES:
        raise ValueError("Phase-2A positive qualification cannot use a blanket default")
    source_ids = {str(row["source_version_id"]) for row in source_rows}
    output: dict[str, IssueDispositionInput] = {}
    for row in issue_rows:
        row_id = str(row["row_id"])
        raw = dispositions.get(row_id)
        if raw is None:
            if default is None:
                raise ValueError("Phase-2A disposition mapping does not cover all 585 issues")
            resolved = default
        else:
            resolved = _coerce_disposition(raw)
        if not set(resolved.official_source_version_ids).issubset(source_ids):
            raise ValueError("Phase-2A disposition references a source outside the candidate")
        output[row_id] = resolved
    if len(output) != 585:
        raise ValueError("Phase-2A disposition mapping does not account for 585 issues")
    return output


_POSITIVE_BINDING_FIELDS = (
    "registry_gold_binding_sha256",
    "candidate_source_binding_sha256",
    "source_gold_consistency_binding_sha256",
    "currentness_binding_sha256",
    "effective_date_binding_sha256",
)


def _positive_binding_expectations(
    *,
    issue_row: Mapping[str, Any],
    disposition: IssueDispositionInput,
    source_rows: Sequence[Mapping[str, Any]],
    source_manifest_sha256: str,
    cutoff_date: date | None,
) -> dict[str, str]:
    """Reconstruct every fact needed for one positive legal qualification."""

    if disposition.primary_status not in POSITIVE_ISSUE_STATUSES:
        raise ValueError("positive binding replay requires a positive disposition")
    gold_source_ids = tuple(str(item) for item in issue_row["gold_source_ids"])
    gold_span_bindings = tuple(str(item) for item in issue_row["gold_span_binding_sha256s"])
    if not gold_source_ids or not gold_span_bindings:
        raise ValueError("positive issue qualification requires nonempty row-bound registry gold")
    if cutoff_date is None:
        raise ValueError("positive issue qualification requires a supported legal cutoff")

    selected_ids = tuple(disposition.official_source_version_ids)
    selected_span_bindings = tuple(disposition.evidence_span_binding_sha256s)
    if selected_ids != tuple(sorted(selected_ids)) or selected_span_bindings != tuple(
        sorted(selected_span_bindings)
    ):
        raise ValueError("positive issue qualification bindings must use canonical order")
    if not set(selected_ids).issubset(set(gold_source_ids)) or set(selected_span_bindings) != set(
        gold_span_bindings
    ):
        raise ValueError("positive issue qualification lacks positive source-to-gold consistency")

    source_lookup = {str(row["source_version_id"]): row for row in source_rows}
    selected_sources = tuple(source_lookup[source_id] for source_id in selected_ids)
    currentness_material: list[dict[str, Any]] = []
    effective_date_material: list[dict[str, Any]] = []
    candidate_source_material: list[dict[str, Any]] = []
    for source in selected_sources:
        as_of_raw = source.get("as_of_date")
        reviewed_raw = source.get("currentness_reviewed_as_of_date")
        try:
            as_of_date = date.fromisoformat(str(as_of_raw))
            reviewed_date = date.fromisoformat(str(reviewed_raw))
        except (TypeError, ValueError) as error:
            raise ValueError(
                "positive issue qualification lacks an effective-date/currentness date"
            ) from error
        if (
            source.get("currentness_verified") is not True
            or source.get("full_current_law_verification_eligible") is not True
            or reviewed_date < cutoff_date
            or (
                source.get("subsequent_treatment_check_required") is True
                and source.get("subsequent_treatment_verified") is not True
            )
        ):
            raise ValueError("positive issue qualification lacks verified candidate currentness")
        candidate_source_material.append(
            {
                "source_version_id": source["source_version_id"],
                "content_sha256": source["content_sha256"],
                "version_sha256": source["version_sha256"],
            }
        )
        currentness_material.append(
            {
                "source_version_id": source["source_version_id"],
                "currentness_status": source["currentness_status"],
                "currentness_verified": source["currentness_verified"],
                "full_current_law_verification_eligible": source[
                    "full_current_law_verification_eligible"
                ],
                "currentness_reviewed_as_of_date": reviewed_date.isoformat(),
                "subsequent_treatment_check_required": source[
                    "subsequent_treatment_check_required"
                ],
                "subsequent_treatment_verified": source["subsequent_treatment_verified"],
            }
        )
        effective_date_material.append(
            {
                "source_version_id": source["source_version_id"],
                "source_as_of_date": as_of_date.isoformat(),
                "reviewed_through_date": reviewed_date.isoformat(),
            }
        )

    binding_common = {
        "row_id": issue_row["row_id"],
        "registry_issue_identity_sha256": issue_row["registry_issue_identity_sha256"],
        "official_review_record_sha256": disposition.official_review_record_sha256,
    }
    return {
        "registry_gold_binding_sha256": str(issue_row["expected_registry_gold_binding_sha256"]),
        "candidate_source_binding_sha256": sealed_sha256(
            {
                "schema": "legalbot.v111-phase2a-positive-candidate-source-binding.v1",
                **binding_common,
                "candidate_source_manifest_sha256": source_manifest_sha256,
                "sources": candidate_source_material,
            }
        ),
        "source_gold_consistency_binding_sha256": sealed_sha256(
            {
                "schema": "legalbot.v111-phase2a-positive-source-gold-consistency.v1",
                **binding_common,
                "registry_gold_binding_sha256": issue_row["expected_registry_gold_binding_sha256"],
                "selected_source_ids": selected_ids,
                "selected_gold_span_binding_sha256s": selected_span_bindings,
                "consistency_verified": True,
            }
        ),
        "currentness_binding_sha256": sealed_sha256(
            {
                "schema": "legalbot.v111-phase2a-positive-currentness-binding.v1",
                **binding_common,
                "cutoff_date": cutoff_date.isoformat(),
                "sources": currentness_material,
            }
        ),
        "effective_date_binding_sha256": sealed_sha256(
            {
                "schema": "legalbot.v111-phase2a-positive-effective-date-binding.v1",
                **binding_common,
                "cutoff_date": cutoff_date.isoformat(),
                "sources": effective_date_material,
            }
        ),
    }


def _assert_positive_bindings_replay(
    *,
    issue_row: Mapping[str, Any],
    disposition: IssueDispositionInput,
    source_rows: Sequence[Mapping[str, Any]],
    source_manifest_sha256: str,
    cutoff_date: date | None,
) -> None:
    if disposition.primary_status not in POSITIVE_ISSUE_STATUSES:
        return
    expected = _positive_binding_expectations(
        issue_row=issue_row,
        disposition=disposition,
        source_rows=source_rows,
        source_manifest_sha256=source_manifest_sha256,
        cutoff_date=cutoff_date,
    )
    actual = {field: getattr(disposition, field) for field in _POSITIVE_BINDING_FIELDS}
    if actual != expected:
        raise ValueError("positive issue qualification binding replay failed")


def _make_artifact(
    *,
    artifact_id: str,
    registry_sha256: str,
    source_manifest_sha256: str,
    payload: Mapping[str, Any],
) -> Phase2AArtifact:
    raw: dict[str, Any] = {
        "schema": ARTIFACT_SCHEMAS[artifact_id],
        "artifact_id": artifact_id,
        "document_state": PACKAGE_STATE,
        "authorizing": False,
        "owner_signature_present": False,
        "signing_authority_created": False,
        "split_created": False,
        "split_secret_generated": False,
        "stage_a_invoked": False,
        "answer_model_invoked": False,
        "development_30_invoked": False,
        "active_changed": False,
        "previous_changed": False,
        "promotion_performed": False,
        "o04_issued": False,
        "live_activated": False,
        "contains_question_prose": False,
        "contains_private_paths": False,
        "registry_canonical_sha256": registry_sha256,
        "candidate_source_manifest_sha256": source_manifest_sha256,
        "payload": dict(payload),
        "payload_sha256": _sha256_bytes(canonical_json(payload)),
    }
    raw["seal_sha256"] = _artifact_seal(raw)
    return Phase2AArtifact.model_validate(raw)


def _make_index(artifacts: Sequence[Phase2AArtifact]) -> Phase2APackageIndex:
    first = artifacts[0]
    entries = tuple(
        Phase2AArtifactIndexEntry(
            ordinal=ordinal,
            artifact_id=artifact.artifact_id,
            schema_name=artifact.schema_name,
            payload_sha256=artifact.payload_sha256,
            seal_sha256=artifact.seal_sha256,
            artifact_sha256=_sha256_bytes(
                canonical_json(artifact.model_dump(mode="json", by_alias=True))
            ),
        )
        for ordinal, artifact in enumerate(artifacts, start=1)
    )
    raw: dict[str, Any] = {
        "schema": PACKAGE_INDEX_SCHEMA,
        "document_state": PACKAGE_STATE,
        "authorizing": False,
        "owner_signature_present": False,
        "signing_payload_created": False,
        "artifact_count": 15,
        "artifact_order": ARTIFACT_IDS,
        "entries": [item.model_dump(mode="json") for item in entries],
        "registry_canonical_sha256": first.registry_canonical_sha256,
        "candidate_source_manifest_sha256": first.candidate_source_manifest_sha256,
    }
    raw["index_sha256"] = _index_seal(raw)
    return Phase2APackageIndex.model_validate(raw)


def build_phase2a_package(
    *,
    bundle: LiveEvaluationBundle,
    candidate_source_manifest: Mapping[str, Any],
    review: Phase2AReviewInputs,
    dispositions: Mapping[str, IssueDispositionInput | Mapping[str, Any]],
    default_disposition: IssueDispositionInput | Mapping[str, Any] | None = None,
    external_official_findings: Sequence[Phase2AExternalOfficialFinding | Mapping[str, Any]] = (),
    artifact_payload_extensions: Mapping[str, Mapping[str, Any]] | None = None,
) -> Phase2APackage:
    """Build fifteen deterministic non-authorizing artifacts in memory."""

    issue_rows = _registry_issue_rows(bundle)
    source_rows = _candidate_sources(candidate_source_manifest)
    if review.candidate.approved_source_manifest_sha256 != candidate_source_manifest.get(
        "manifest_sha256"
    ) or review.candidate.document_count != len(source_rows):
        raise ValueError("Phase-2A candidate binding differs from the exact approved candidate")
    findings = tuple(
        item
        if isinstance(item, Phase2AExternalOfficialFinding)
        else Phase2AExternalOfficialFinding.model_validate(item)
        for item in external_official_findings
    )
    finding_ids = {item.finding_id for item in findings}
    registry_case_ids = {case.case_id for case in bundle.registry.cases}
    if len(finding_ids) != len(findings) or any(
        not set(item.affected_case_ids).issubset(registry_case_ids) for item in findings
    ):
        raise ValueError("Phase-2A external official findings are duplicated or out of registry")
    if len(findings) != review.confirmed_material_candidate_finding_count:
        raise ValueError("Phase-2A external official finding count contradicts review inputs")
    resolved = _resolved_dispositions(
        issue_rows=issue_rows,
        source_rows=source_rows,
        dispositions=dispositions,
        default_disposition=default_disposition,
    )
    review_record_ids = tuple(
        disposition.official_review_record_sha256 for disposition in resolved.values()
    )
    if len(set(review_record_ids)) != len(issue_rows):
        raise ValueError("Phase-2A requires one row-bound official review record per issue")
    if any(
        not set(disposition.external_official_finding_ids).issubset(finding_ids)
        for disposition in resolved.values()
    ):
        raise ValueError("Phase-2A issue disposition references an unknown external finding")
    source_manifest_sha256 = str(candidate_source_manifest["manifest_sha256"])
    supported_cutoff = (
        review.recommended_cutoff_date
        if review.cutoff_support_status == "SUPPORTED_FOR_OWNER_DECISION"
        else None
    )
    for issue_row in issue_rows:
        _assert_positive_bindings_replay(
            issue_row=issue_row,
            disposition=resolved[str(issue_row["row_id"])],
            source_rows=source_rows,
            source_manifest_sha256=source_manifest_sha256,
            cutoff_date=supported_cutoff,
        )

    issue_register = tuple(
        {
            **dict(row),
            "primary_status": resolved[str(row["row_id"])].primary_status,
            "official_review_record_sha256": resolved[
                str(row["row_id"])
            ].official_review_record_sha256,
            "official_source_version_ids": resolved[str(row["row_id"])].official_source_version_ids,
            "evidence_span_binding_sha256s": resolved[
                str(row["row_id"])
            ].evidence_span_binding_sha256s,
            "registry_gold_binding_sha256": resolved[
                str(row["row_id"])
            ].registry_gold_binding_sha256,
            "candidate_source_binding_sha256": resolved[
                str(row["row_id"])
            ].candidate_source_binding_sha256,
            "source_gold_consistency_binding_sha256": resolved[
                str(row["row_id"])
            ].source_gold_consistency_binding_sha256,
            "currentness_binding_sha256": resolved[str(row["row_id"])].currentness_binding_sha256,
            "effective_date_binding_sha256": resolved[
                str(row["row_id"])
            ].effective_date_binding_sha256,
            "note_sha256": resolved[str(row["row_id"])].note_sha256,
            "reason_code": resolved[str(row["row_id"])].reason_code,
            "supporting_evidence_sha256s": resolved[str(row["row_id"])].supporting_evidence_sha256s,
            "affected_proposition_state": resolved[str(row["row_id"])].affected_proposition_state,
            "prevents_common_cutoff": resolved[str(row["row_id"])].prevents_common_cutoff,
            "remediation_code": resolved[str(row["row_id"])].remediation_code,
            "candidate_bytes_change_required": resolved[
                str(row["row_id"])
            ].candidate_bytes_change_required,
            "owner_approval_required": resolved[str(row["row_id"])].owner_approval_required,
            "external_official_finding_ids": resolved[
                str(row["row_id"])
            ].external_official_finding_ids,
        }
        for row in issue_rows
    )
    status_counts = Counter(str(row["primary_status"]) for row in issue_register)
    issue_candidate_rebuild_required = any(
        row["candidate_bytes_change_required"] is True
        or row["primary_status"] in {"MATERIAL_CURRENTNESS_GAP", "MATERIAL_CANDIDATE_COVERAGE_GAP"}
        for row in issue_register
    )
    effective_candidate_rebuild_required = bool(findings) or issue_candidate_rebuild_required
    if review.candidate_rebuild_required != effective_candidate_rebuild_required:
        raise ValueError("Phase-2A candidate rebuild claim contradicts confirmed findings")
    common_cutoff_blocked = effective_candidate_rebuild_required or any(
        row["prevents_common_cutoff"] is True for row in issue_register
    )
    expected_terminal_verdict = (
        "BLOCKED_MATERIAL_GAPS" if common_cutoff_blocked else "OWNER_DECISIONS_REQUIRED"
    )
    if review.terminal_verdict != expected_terminal_verdict:
        raise ValueError("Phase-2A terminal verdict contradicts issue dispositions")
    if common_cutoff_blocked and (
        review.cutoff_support_status != "UNSUPPORTABLE_ON_CURRENT_CANDIDATE"
        or review.recommended_cutoff_date is not None
    ):
        raise ValueError("Phase-2A cutoff claim contradicts issue dispositions")

    cases: list[dict[str, Any]] = []
    for case in bundle.registry.cases:
        member_rows = tuple(row for row in issue_register if row["case_id"] == case.case_id)
        member_counts = Counter(str(row["primary_status"]) for row in member_rows)
        cases.append(
            {
                "ordinal": case.ordinal,
                "case_id": case.case_id,
                "case_record_sha256": case.record_sha256,
                "issue_count": len(member_rows),
                "issue_identity_sha256s": tuple(
                    str(row["registry_issue_identity_sha256"]) for row in member_rows
                ),
                "primary_status_counts": {
                    status: member_counts[status] for status in ALLOWED_ISSUE_STATUSES
                },
                "qualification_state": (
                    "QUALIFIED"
                    if all(
                        str(row["primary_status"]) in POSITIVE_ISSUE_STATUSES for row in member_rows
                    )
                    else "NOT_QUALIFIED"
                ),
                "qualified_issue_count": sum(
                    str(row["primary_status"]) in POSITIVE_ISSUE_STATUSES for row in member_rows
                ),
                "blocked_issue_count": sum(
                    str(row["primary_status"]) not in POSITIVE_ISSUE_STATUSES for row in member_rows
                ),
                "candidate_evidence_coverage": (
                    "COMPLETE_POSITIVE_BINDING"
                    if all(
                        str(row["primary_status"]) in POSITIVE_ISSUE_STATUSES
                        and row["official_source_version_ids"]
                        and row["evidence_span_binding_sha256s"]
                        and all(row[field] is not None for field in _POSITIVE_BINDING_FIELDS)
                        for row in member_rows
                    )
                    else "NOT_POSITIVELY_BOUND"
                ),
                "official_source_coverage": (
                    "COMPLETE"
                    if all(
                        str(row["primary_status"]) in POSITIVE_ISSUE_STATUSES
                        and row["official_source_version_ids"]
                        for row in member_rows
                    )
                    else "INCOMPLETE_OR_UNMAPPED"
                ),
                "gold_consistency": (
                    "POSITIVELY_VERIFIED"
                    if all(
                        str(row["primary_status"]) in POSITIVE_ISSUE_STATUSES
                        and row["gold_source_binding_count"] > 0
                        and row["gold_span_binding_count"] > 0
                        and row["source_gold_consistency_binding_sha256"] is not None
                        for row in member_rows
                    )
                    else "NOT_POSITIVELY_VERIFIED"
                ),
                "source_version_consistency": (
                    "POSITIVELY_VERIFIED"
                    if all(
                        str(row["primary_status"]) in POSITIVE_ISSUE_STATUSES
                        and row["candidate_source_binding_sha256"] is not None
                        for row in member_rows
                    )
                    else "NOT_POSITIVELY_VERIFIED"
                ),
                "material_currentness_result": (
                    "PASS"
                    if all(
                        str(row["primary_status"]) in POSITIVE_ISSUE_STATUSES for row in member_rows
                    )
                    else "BLOCKED"
                ),
            }
        )

    nonpositive_rows = tuple(
        {
            "ordinal": row["ordinal"],
            "row_id": row["row_id"],
            "registry_issue_identity_sha256": row["registry_issue_identity_sha256"],
            "primary_status": row["primary_status"],
            "official_review_record_sha256": row["official_review_record_sha256"],
            "reason_code": row["reason_code"],
            "supporting_evidence_sha256s": row["supporting_evidence_sha256s"],
            "affected_proposition_state": row["affected_proposition_state"],
            "prevents_common_cutoff": row["prevents_common_cutoff"],
            "remediation_code": row["remediation_code"],
            "candidate_bytes_change_required": row["candidate_bytes_change_required"],
            "owner_approval_required": row["owner_approval_required"],
            "external_official_finding_ids": row["external_official_finding_ids"],
        }
        for row in issue_register
        if str(row["primary_status"]) not in POSITIVE_ISSUE_STATUSES
    )
    source_currentness_counts = Counter(str(row["currentness_status"]) for row in source_rows)
    all_positive = not nonpositive_rows
    common = {
        "generated_at": review.generated_at.isoformat(),
        "exact_commit_sha": review.code.commit_sha,
        "exact_tree_sha": review.code.tree_sha,
    }
    payloads: dict[str, Mapping[str, Any]] = {
        "entry-state": {
            **common,
            "worktree_clean": review.code.worktree_clean,
            "entry_state_sha256": review.entry_state_sha256,
            "registry_case_count": 60,
            "registry_issue_count": 585,
            "candidate_source_count": len(source_rows),
            "candidate": review.candidate.model_dump(mode="json"),
            "action_absence_audit": review.action_absence_audit.model_dump(mode="json"),
            "phase": "PHASE_2A",
        },
        "issue-currentness-register": {
            "issue_count": 585,
            "issues": issue_register,
            "official_source_review_method_sha256": review.official_source_review_method_sha256,
        },
        "official-source-provenance-register": {
            "source_count": len(source_rows),
            "candidate_current_law_as_of_date": candidate_source_manifest.get(
                "current_law_as_of_date"
            ),
            "sources": source_rows,
            "external_official_finding_count": len(findings),
            "external_official_findings": tuple(item.model_dump(mode="json") for item in findings),
        },
        "case-qualification-register": {"case_count": 60, "cases": tuple(cases)},
        "qualification-aggregate": {
            "case_count": 60,
            "issue_count": 585,
            "status_counts": {status: status_counts[status] for status in ALLOWED_ISSUE_STATUSES},
            "qualified_case_count": sum(
                item["qualification_state"] == "QUALIFIED" for item in cases
            ),
            "all_issues_positive_qualified": all_positive,
            "owner_approval_required": True,
            "split_allowed_by_this_artifact": False,
        },
        "gap-conflict-register": {
            "nonpositive_issue_count": len(nonpositive_rows),
            "rows": nonpositive_rows,
        },
        "candidate-impact-report": {
            "candidate_change_required_issue_count": sum(
                row["candidate_bytes_change_required"] is True for row in issue_register
            ),
            "material_candidate_or_currentness_status_count": status_counts[
                "MATERIAL_CANDIDATE_COVERAGE_GAP"
            ]
            + status_counts["MATERIAL_CURRENTNESS_GAP"],
            "source_conflict_or_unavailable_issue_count": status_counts["SOURCE_VERSION_CONFLICT"]
            + status_counts["OFFICIAL_SOURCE_UNAVAILABLE"],
            "gold_or_case_remediation_issue_count": status_counts["GOLD_OR_CASE_DEFECT"],
            "owner_legal_judgment_issue_count": status_counts["OWNER_LEGAL_JUDGMENT_REQUIRED"],
            "candidate_rebuild_required": effective_candidate_rebuild_required,
            "confirmed_material_candidate_finding_count": (len(findings)),
            "external_official_finding_ids": tuple(item.finding_id for item in findings),
            "terminal_verdict": expected_terminal_verdict,
            "candidate_unchanged_by_package": True,
        },
        "cutoff-recommendation": {
            "recommended_cutoff_date": (
                review.recommended_cutoff_date.isoformat()
                if review.recommended_cutoff_date is not None
                else None
            ),
            "review_target_cutoff_date": (
                review.review_target_cutoff_date.isoformat()
                if review.review_target_cutoff_date is not None
                else None
            ),
            "cutoff_support_status": review.cutoff_support_status,
            "common_cutoff_freezable": (
                review.cutoff_support_status == "SUPPORTED_FOR_OWNER_DECISION"
            ),
            "cutoff_basis_sha256": review.cutoff_basis_sha256,
            "recommendation_is_authority": False,
            "owner_approval_required": True,
        },
        "freshness-material-change-policy": {
            "policy_sha256": review.freshness_policy_sha256,
            "official_primary_sources_only": True,
            "material_candidate_delta_requires_reseal": True,
            "material_candidate_delta_requires_requalification": True,
            "material_candidate_delta_requires_retrieval_reattestation": True,
            "material_candidate_delta_requires_final_development_rerun": True,
            "source_currentness_status_counts": dict(sorted(source_currentness_counts.items())),
        },
        "security-owner-controls-proposal": {
            "proposal_sha256": review.security_controls_proposal_sha256,
            "pinned_local_ed25519_public_key_proposed": True,
            "private_unix_domain_socket_transport_proposed": True,
            "maximum_memory_gib_proposed": 12,
            "minimum_free_memory_gib_proposed": 3,
            "distinct_private_review_root_count_proposed": 3,
            "literal_loopback_host_proposed": "127.0.0.1",
            "strict_host_origin_csrf_and_session_secret_proposed": True,
            "controls_created": False,
            "credentials_created": False,
        },
        "certification-contract-proposal": {
            "proposal_sha256": review.certification_contract_proposal_sha256,
            "contract_state": "PROPOSED_NOT_FROZEN",
            "threshold_relaxation_after_results_allowed": False,
            "same_failure_fingerprint_limit": 2,
            "answer_generation_batch_size_if_later_authorized": 30,
            "owner_approval_required": True,
        },
        "synthetic-split-verification": {
            "verification_sha256": review.synthetic_split_verification_sha256,
            "synthetic_only": True,
            "verification_passed": review.synthetic_split_verification_passed,
            "real_registry_used_for_partition": False,
            "real_secret_generated": False,
            "real_complement_frozen": False,
        },
        "owner-readable-summary": {
            "phase": "PHASE_2A",
            "case_count": 60,
            "issue_count": 585,
            "candidate_source_count": len(source_rows),
            "qualified_issue_count": sum(
                status_counts[status] for status in POSITIVE_ISSUE_STATUSES
            ),
            "nonpositive_issue_count": len(nonpositive_rows),
            "terminal_verdict": expected_terminal_verdict,
            "candidate_rebuild_required": effective_candidate_rebuild_required,
            "next_gate": (
                "CANDIDATE_AND_GOLD_REMEDIATION_BEFORE_PHASE_2B"
                if expected_terminal_verdict == "BLOCKED_MATERIAL_GAPS"
                else "OWNER_APPROVAL_BEFORE_PHASE_2B"
            ),
        },
        "owner-decision-payload-draft": {
            "draft_state": "NONAUTHORIZING_RECOMMENDATIONS_ONLY",
            "cutoff_basis_sha256": review.cutoff_basis_sha256,
            "freshness_policy_sha256": review.freshness_policy_sha256,
            "security_controls_proposal_sha256": review.security_controls_proposal_sha256,
            "certification_contract_proposal_sha256": (
                review.certification_contract_proposal_sha256
            ),
            "canonical_payload_deferred_to_phase2b": True,
            "signature_material_absent": True,
            "owner_choices_pending": True,
        },
        "final-invariants": {
            "registry_case_count": 60,
            "registry_issue_count": 585,
            "issue_rows_unique": True,
            "candidate_source_manifest_unchanged": True,
            "candidate_unchanged": True,
            "real_split_absent": True,
            "real_secret_absent": True,
            "signing_material_absent": True,
            "runtime_actions_absent": True,
            "owner_approval_required": True,
            "action_absence_audit_sha256": review.action_absence_audit.audit_sha256,
            "terminal_verdict": expected_terminal_verdict,
            "candidate_rebuild_required": effective_candidate_rebuild_required,
            "phase2b_allowed": all_positive
            and expected_terminal_verdict != "BLOCKED_MATERIAL_GAPS"
            and review.cutoff_support_status == "SUPPORTED_FOR_OWNER_DECISION"
            and review.recommended_cutoff_date is not None,
        },
    }
    extensions = artifact_payload_extensions or {}
    unknown_extensions = set(extensions).difference(ARTIFACT_IDS)
    if unknown_extensions:
        raise ValueError("Phase-2A payload extensions contain unknown artifact identities")
    for artifact_id, extension in extensions.items():
        if not isinstance(extension, Mapping):
            raise TypeError("Phase-2A payload extension must be a mapping")
        _assert_prose_and_private_path_free(
            extension,
            location=f"extension.{artifact_id}",
            in_review_details=True,
            artifact_id=artifact_id,
        )
        payloads[artifact_id] = {
            **payloads[artifact_id],
            "review_details": dict(extension),
        }
    artifacts = tuple(
        _make_artifact(
            artifact_id=artifact_id,
            registry_sha256=bundle.registry.canonical_sha256,
            source_manifest_sha256=source_manifest_sha256,
            payload=payloads[artifact_id],
        )
        for artifact_id in ARTIFACT_IDS
    )
    package = Phase2APackage(artifacts=artifacts, index=_make_index(artifacts))
    verify_phase2a_package(
        package,
        bundle=bundle,
        candidate_source_manifest=candidate_source_manifest,
        candidate_replay_binding=review.candidate,
        expected_artifact_payload_extensions=extensions,
    )
    return package


def verify_phase2a_package(
    package: Phase2APackage,
    *,
    bundle: LiveEvaluationBundle,
    candidate_source_manifest: Mapping[str, Any],
    candidate_replay_binding: Phase2ACandidateBinding,
    expected_artifact_payload_extensions: Mapping[str, Mapping[str, Any]],
) -> None:
    """Replay package facts against an independently verified candidate binding.

    The caller must obtain ``candidate_replay_binding`` from the durable
    candidate/tree and retrieval-model-store verifier.  Package hashes alone
    are deliberately insufficient evidence that ignored candidate bytes have
    not changed.
    """

    issue_rows = _registry_issue_rows(bundle)
    source_rows = _candidate_sources(candidate_source_manifest)
    source_manifest_sha256 = str(candidate_source_manifest["manifest_sha256"])
    if (
        len(package.artifacts) != 15
        or tuple(artifact.artifact_id for artifact in package.artifacts) != ARTIFACT_IDS
        or not set(expected_artifact_payload_extensions).issubset(ARTIFACT_IDS)
    ):
        raise ValueError("Phase-2A package must contain the exact 15 artifacts")

    entry_payload = package.artifact("entry-state").payload
    candidate_binding = Phase2ACandidateBinding.model_validate(entry_payload.get("candidate"))
    action_audit = Phase2AActionAbsenceAudit.model_validate(
        entry_payload.get("action_absence_audit")
    )
    if (
        candidate_binding != candidate_replay_binding
        or candidate_replay_binding.approved_source_manifest_sha256 != source_manifest_sha256
        or candidate_binding.approved_source_manifest_sha256 != source_manifest_sha256
        or candidate_binding.document_count != len(source_rows)
        or entry_payload.get("candidate_source_count") != len(source_rows)
    ):
        raise ValueError("Phase-2A exact candidate binding is inconsistent")

    reparsed = tuple(
        Phase2AArtifact.model_validate(artifact.model_dump(mode="json", by_alias=True))
        for artifact in package.artifacts
    )
    for artifact in reparsed:
        expected_extension = expected_artifact_payload_extensions.get(artifact.artifact_id)
        actual_extension = artifact.payload.get("review_details")
        if (
            artifact.registry_canonical_sha256 != bundle.registry.canonical_sha256
            or artifact.candidate_source_manifest_sha256 != source_manifest_sha256
            or (expected_extension is None and "review_details" in artifact.payload)
            or (
                expected_extension is not None
                and (
                    not isinstance(actual_extension, Mapping)
                    or canonical_json(actual_extension) != canonical_json(dict(expected_extension))
                )
            )
        ):
            raise ValueError(
                "Phase-2A artifact binding or review details differ from replay inputs"
            )
        payload_strings = tuple(_iter_payload_strings(artifact.payload))
        for case in bundle.registry.cases:
            probe = " ".join(case.question.split())
            if any(probe in " ".join(value.split()) for value in payload_strings):
                raise ValueError("Phase-2A artifact contains registry question prose")

    issue_payload = package.artifact("issue-currentness-register").payload
    actual_issues = cast(list[dict[str, Any]], issue_payload.get("issues"))
    expected_identities = tuple(
        (row["ordinal"], row["row_id"], row["registry_issue_identity_sha256"]) for row in issue_rows
    )
    actual_identities = tuple(
        (row.get("ordinal"), row.get("row_id"), row.get("registry_issue_identity_sha256"))
        for row in actual_issues
    )
    registry_bound_fields = tuple(issue_rows[0])
    exact_issue_fields = set(registry_bound_fields) | set(IssueDispositionInput.model_fields)
    if (
        issue_payload.get("issue_count") != 585
        or len(actual_issues) != 585
        or actual_identities != expected_identities
        or any(set(row) != exact_issue_fields for row in actual_issues)
        or any(
            any(
                not _json_replay_value_equal(actual.get(field), expected[field])
                for field in registry_bound_fields
            )
            for actual, expected in zip(actual_issues, issue_rows, strict=True)
        )
        or any(row.get("primary_status") not in ALLOWED_ISSUE_STATUSES for row in actual_issues)
    ):
        raise ValueError("Phase-2A issue register is incomplete or reordered")

    source_payload = package.artifact("official-source-provenance-register").payload
    actual_sources = source_payload.get("sources")
    if (
        source_payload.get("source_count") != len(source_rows)
        or source_payload.get("candidate_current_law_as_of_date")
        != candidate_source_manifest.get("current_law_as_of_date")
        or not isinstance(actual_sources, list | tuple)
        or tuple(actual_sources) != source_rows
    ):
        raise ValueError("Phase-2A source provenance differs from the candidate manifest")
    raw_findings = source_payload.get("external_official_findings")
    if not isinstance(raw_findings, list | tuple):
        raise ValueError("Phase-2A external official finding register is missing")
    findings = tuple(Phase2AExternalOfficialFinding.model_validate(item) for item in raw_findings)
    finding_ids = {item.finding_id for item in findings}
    candidate_urls = {
        _canonical_official_url_identity(str(item["canonical_url"])) for item in source_rows
    }
    registry_case_ids = {case.case_id for case in bundle.registry.cases}
    if (
        source_payload.get("external_official_finding_count") != len(findings)
        or len(finding_ids) != len(findings)
        or any(
            _canonical_official_url_identity(item.canonical_url) in candidate_urls
            for item in findings
        )
        or any(not set(item.affected_case_ids).issubset(registry_case_ids) for item in findings)
    ):
        raise ValueError("Phase-2A external official finding register is inconsistent")

    finding_review_records: dict[str, Mapping[str, Any]] = {}
    if findings:
        review_details = source_payload.get("review_details")
        raw_review_records = (
            review_details.get("external_finding_review_records")
            if isinstance(review_details, Mapping)
            else None
        )
        if not isinstance(raw_review_records, list | tuple) or len(raw_review_records) != len(
            findings
        ):
            raise ValueError("Phase-2A findings lack exact issue/content review records")
        issue_row_ids = {str(row["row_id"]) for row in issue_rows}
        candidate_authority_hashes = {str(row["authority_identity_sha256"]) for row in source_rows}
        candidate_content_hashes = {
            digest
            for row in source_rows
            for digest in (str(row["content_sha256"]), str(row["version_sha256"]))
        }
        observed_authority_identities: set[str] = set()
        observed_document_identities: set[str] = set()
        observed_document_urls: set[str] = set()
        for raw_record in raw_review_records:
            if not isinstance(raw_record, Mapping):
                raise ValueError("Phase-2A finding review record is invalid")
            record = dict(raw_record)
            finding_id = str(record.get("finding_id") or "")
            if finding_id not in finding_ids or finding_id in finding_review_records:
                raise ValueError("Phase-2A finding review identities are inconsistent")
            record_sha256 = str(record.pop("record_sha256", ""))
            if record_sha256 != sealed_sha256(record):
                raise ValueError("Phase-2A finding review record digest differs")
            affected_rows_raw = record.get("affected_issue_row_ids")
            if not isinstance(affected_rows_raw, list | tuple):
                raise ValueError("Phase-2A finding review has no issue-row mapping")
            affected_rows = tuple(str(item) for item in affected_rows_raw)
            finding = next(item for item in findings if item.finding_id == finding_id)
            expected_row_set_sha256 = sealed_sha256(
                {
                    "schema": "legalbot.v111-phase2a-finding-issue-row-set.v1",
                    "finding_id": finding_id,
                    "row_ids": affected_rows,
                }
            )
            if (
                not affected_rows
                or len(affected_rows) != len(set(affected_rows))
                or not set(affected_rows).issubset(issue_row_ids)
                or {row_id.split(":", 1)[0] for row_id in affected_rows}
                != set(finding.affected_case_ids)
                or record.get("affected_issue_row_set_sha256") != expected_row_set_sha256
                or record.get("mapping_state") != "PROPOSITION_REVIEW_REQUIRED_NOT_POSITIVE_HOLDING"
            ):
                raise ValueError("Phase-2A finding-to-issue mapping is inconsistent")
            document_raw = record.get("document_content_identity")
            temporal_raw = record.get("temporal_status")
            absence_raw = record.get("candidate_absence_observation")
            if not all(
                isinstance(value, Mapping) for value in (document_raw, temporal_raw, absence_raw)
            ):
                raise ValueError("Phase-2A finding review evidence is incomplete")
            document = dict(cast(Mapping[str, Any], document_raw))
            temporal = dict(cast(Mapping[str, Any], temporal_raw))
            absence = dict(cast(Mapping[str, Any], absence_raw))
            document_identity = str(document.pop("identity_sha256", ""))
            temporal_identity = str(temporal.pop("temporal_identity_sha256", ""))
            absence_identity = str(absence.pop("observation_sha256", ""))
            authority_identity = str(document.get("authority_identity") or "")
            version_identity = str(document.get("version_identity") or "")
            content_sha256 = str(document.get("content_sha256") or "")
            content_url = str(document.get("content_url") or "")
            content_url_parts = urlsplit(content_url)
            is_legislation = finding.source_class == "OFFICIAL_LEGISLATION"
            authority_parts = authority_identity.split(":")
            expected_official_identifier = (
                f"{authority_parts[1]}-c-{authority_parts[2]}"
                if is_legislation and len(authority_parts) == 3 and authority_parts[0] == "ukpga"
                else authority_identity.removeprefix("neutral-citation:[").replace(
                    "] UKSC ", "-UKSC-"
                )
            )
            expected_core_binding = sealed_sha256(
                {
                    "schema": "legalbot.v111-phase2a-core-finding-binding.v1",
                    "finding": finding.model_dump(mode="json"),
                    "affected_issue_row_ids": affected_rows,
                    "document_content_identity_sha256": document_identity,
                    "temporal_identity_sha256": temporal_identity,
                    "candidate_absence_observation_sha256": absence_identity,
                }
            )
            canonical_document_url = _canonical_official_url_identity(content_url)
            if (
                document_identity != sealed_sha256(document)
                or temporal_identity != sealed_sha256(temporal)
                or absence_identity != sealed_sha256(absence)
                or not authority_identity
                or not version_identity.startswith(f"{authority_identity}:")
                or not _SHA256.fullmatch(content_sha256)
                or content_url_parts.scheme != "https"
                or content_url_parts.hostname
                not in {
                    "legislation.gov.uk",
                    "www.legislation.gov.uk",
                    "caselaw.nationalarchives.gov.uk",
                }
                or content_url_parts.username is not None
                or content_url_parts.password is not None
                or content_url_parts.query
                or content_url_parts.fragment
                or document.get("media_type") != "application/pdf"
                or document.get("content_bytes_embedded_in_package") is not False
                or document.get("content_bytes_retrieved_by_builder") is not False
                or document.get("content_digest_is_external_review_observation") is not True
                or temporal.get("single_effective_date_claimed") is not False
                or temporal.get("authority_date") != finding.legal_effect_date.isoformat()
                or absence.get("scope") != "SEALED_APPROVED_SOURCE_MANIFEST_ONLY"
                or absence.get("candidate_source_manifest_sha256") != source_manifest_sha256
                or any(
                    absence.get(field) != 0
                    for field in (
                        "authority_identity_match_count",
                        "official_document_content_match_count",
                        "exact_official_url_match_count",
                    )
                )
                or _sha256_bytes(authority_identity.encode("utf-8")) in candidate_authority_hashes
                or content_sha256 in candidate_content_hashes
                or canonical_document_url in candidate_urls
                or finding.official_identifier != expected_official_identifier
                or record.get("core_finding_binding_sha256") != expected_core_binding
                or authority_identity in observed_authority_identities
                or document_identity in observed_document_identities
                or canonical_document_url in observed_document_urls
                or (
                    is_legislation
                    and (
                        _canonical_official_url_identity(finding.canonical_url)
                        != canonical_document_url
                        or finding.retrieved_content_sha256 != content_sha256
                        or temporal.get("authority_date_kind") != "ROYAL_ASSENT_DATE"
                        or record.get("core_canonical_url_role") != "OFFICIAL_DOCUMENT_CONTENT"
                    )
                )
                or (
                    not is_legislation
                    and (
                        not authority_identity.startswith("neutral-citation:[")
                        or temporal.get("authority_date_kind") != "JUDGMENT_DELIVERY_DATE"
                        or record.get("core_canonical_url_role")
                        != "MUTABLE_OFFICIAL_LOCATOR_ONLY_NOT_CONTENT_PROOF"
                    )
                )
            ):
                raise ValueError("Phase-2A finding content/absence binding is inconsistent")
            observed_authority_identities.add(authority_identity)
            observed_document_identities.add(document_identity)
            observed_document_urls.add(canonical_document_url)
            finding_review_records[finding_id] = raw_record

    candidate_source_ids = {str(item["source_version_id"]) for item in source_rows}
    disposition_fields = tuple(IssueDispositionInput.model_fields)
    cutoff_for_positive = package.artifact("cutoff-recommendation").payload
    cutoff_date: date | None = None
    if cutoff_for_positive.get("cutoff_support_status") == "SUPPORTED_FOR_OWNER_DECISION":
        raw_cutoff = cutoff_for_positive.get("recommended_cutoff_date")
        try:
            cutoff_date = date.fromisoformat(str(raw_cutoff))
        except (TypeError, ValueError) as error:
            raise ValueError("Phase-2A supported cutoff date is invalid") from error
    dispositions_by_row: dict[str, IssueDispositionInput] = {}
    for row, expected_issue_row in zip(actual_issues, issue_rows, strict=True):
        disposition = IssueDispositionInput.model_validate(
            {field: row.get(field) for field in disposition_fields}
        )
        if not set(disposition.official_source_version_ids).issubset(
            candidate_source_ids
        ) or not set(disposition.external_official_finding_ids).issubset(finding_ids):
            raise ValueError("Phase-2A issue disposition source binding is inconsistent")
        _assert_positive_bindings_replay(
            issue_row=expected_issue_row,
            disposition=disposition,
            source_rows=source_rows,
            source_manifest_sha256=source_manifest_sha256,
            cutoff_date=cutoff_date,
        )
        dispositions_by_row[str(row["row_id"])] = disposition
    if finding_review_records:
        for finding_id, raw_record in finding_review_records.items():
            affected_rows = tuple(str(item) for item in raw_record["affected_issue_row_ids"])
            reverse_rows = tuple(
                row_id
                for row_id, disposition in dispositions_by_row.items()
                if finding_id in disposition.external_official_finding_ids
            )
            if set(reverse_rows) != set(affected_rows) or any(
                dispositions_by_row[row_id].candidate_bytes_change_required is not True
                or dispositions_by_row[row_id].primary_status != "MATERIAL_CANDIDATE_COVERAGE_GAP"
                for row_id in affected_rows
            ):
                raise ValueError("Phase-2A finding issue dispositions do not reconcile")

    case_payload = package.artifact("case-qualification-register").payload
    actual_cases = cast(list[dict[str, Any]], case_payload.get("cases"))
    if (
        case_payload.get("case_count") != 60
        or len(actual_cases) != 60
        or tuple(item.get("case_id") for item in actual_cases)
        != tuple(case.case_id for case in bundle.registry.cases)
        or sum(int(item.get("issue_count") or 0) for item in actual_cases) != 585
    ):
        raise ValueError("Phase-2A case qualification register is incomplete")

    for case, case_row in zip(bundle.registry.cases, actual_cases, strict=True):
        member_rows = tuple(row for row in actual_issues if row.get("case_id") == case.case_id)
        member_counts = Counter(str(row["primary_status"]) for row in member_rows)
        positive_count = sum(
            str(row["primary_status"]) in POSITIVE_ISSUE_STATUSES for row in member_rows
        )
        expected_state = "QUALIFIED" if positive_count == len(member_rows) else "NOT_QUALIFIED"
        if (
            set(case_row)
            != {
                "ordinal",
                "case_id",
                "case_record_sha256",
                "issue_count",
                "issue_identity_sha256s",
                "primary_status_counts",
                "qualification_state",
                "qualified_issue_count",
                "blocked_issue_count",
                "candidate_evidence_coverage",
                "official_source_coverage",
                "gold_consistency",
                "source_version_consistency",
                "material_currentness_result",
            }
            or case_row.get("ordinal") != case.ordinal
            or case_row.get("case_record_sha256") != case.record_sha256
            or case_row.get("issue_count") != len(member_rows)
            or tuple(case_row.get("issue_identity_sha256s") or ())
            != tuple(str(row["registry_issue_identity_sha256"]) for row in member_rows)
            or case_row.get("primary_status_counts")
            != {status: member_counts[status] for status in ALLOWED_ISSUE_STATUSES}
            or case_row.get("qualification_state") != expected_state
            or case_row.get("qualified_issue_count") != positive_count
            or case_row.get("blocked_issue_count") != len(member_rows) - positive_count
            or case_row.get("material_currentness_result")
            != ("PASS" if expected_state == "QUALIFIED" else "BLOCKED")
            or case_row.get("candidate_evidence_coverage")
            != (
                "COMPLETE_POSITIVE_BINDING"
                if all(
                    str(row["primary_status"]) in POSITIVE_ISSUE_STATUSES
                    and row["official_source_version_ids"]
                    and row["evidence_span_binding_sha256s"]
                    and all(row[field] is not None for field in _POSITIVE_BINDING_FIELDS)
                    for row in member_rows
                )
                else "NOT_POSITIVELY_BOUND"
            )
            or case_row.get("official_source_coverage")
            != (
                "COMPLETE"
                if all(
                    str(row["primary_status"]) in POSITIVE_ISSUE_STATUSES
                    and row["official_source_version_ids"]
                    for row in member_rows
                )
                else "INCOMPLETE_OR_UNMAPPED"
            )
            or case_row.get("gold_consistency")
            != (
                "POSITIVELY_VERIFIED"
                if all(
                    str(row["primary_status"]) in POSITIVE_ISSUE_STATUSES
                    and int(row["gold_source_binding_count"]) > 0
                    and int(row["gold_span_binding_count"]) > 0
                    and row["source_gold_consistency_binding_sha256"] is not None
                    for row in member_rows
                )
                else "NOT_POSITIVELY_VERIFIED"
            )
            or case_row.get("source_version_consistency")
            != (
                "POSITIVELY_VERIFIED"
                if all(
                    str(row["primary_status"]) in POSITIVE_ISSUE_STATUSES
                    and row["candidate_source_binding_sha256"] is not None
                    for row in member_rows
                )
                else "NOT_POSITIVELY_VERIFIED"
            )
        ):
            raise ValueError("Phase-2A case qualification does not reconcile to issue rows")

    aggregate = package.artifact("qualification-aggregate").payload
    actual_counts = Counter(str(row["primary_status"]) for row in actual_issues)
    if aggregate.get("status_counts") != {
        status: actual_counts[status] for status in ALLOWED_ISSUE_STATUSES
    }:
        raise ValueError("Phase-2A aggregate does not reconcile to issue rows")
    nonpositive = tuple(
        row for row in actual_issues if str(row["primary_status"]) not in POSITIVE_ISSUE_STATUSES
    )
    if (
        aggregate.get("qualified_case_count")
        != sum(item["qualification_state"] == "QUALIFIED" for item in actual_cases)
        or aggregate.get("all_issues_positive_qualified") != (not nonpositive)
        or aggregate.get("split_allowed_by_this_artifact") is not False
    ):
        raise ValueError("Phase-2A aggregate qualification flags are inconsistent")

    gap_payload = package.artifact("gap-conflict-register").payload
    gap_rows = gap_payload.get("rows")
    if not isinstance(gap_rows, list | tuple) or gap_payload.get("nonpositive_issue_count") != len(
        nonpositive
    ):
        raise ValueError("Phase-2A gap register count is inconsistent")
    if tuple(row.get("row_id") for row in gap_rows) != tuple(
        row.get("row_id") for row in nonpositive
    ):
        raise ValueError("Phase-2A gap register identities are inconsistent")
    for issue, gap in zip(nonpositive, gap_rows, strict=True):
        if set(gap) != {
            "ordinal",
            "row_id",
            "registry_issue_identity_sha256",
            "primary_status",
            "official_review_record_sha256",
            "reason_code",
            "supporting_evidence_sha256s",
            "affected_proposition_state",
            "prevents_common_cutoff",
            "remediation_code",
            "candidate_bytes_change_required",
            "owner_approval_required",
            "external_official_finding_ids",
        }:
            raise ValueError("Phase-2A gap register row contract is inconsistent")
        for field in (
            "ordinal",
            "row_id",
            "registry_issue_identity_sha256",
            "official_review_record_sha256",
            "primary_status",
            "reason_code",
            "supporting_evidence_sha256s",
            "affected_proposition_state",
            "prevents_common_cutoff",
            "remediation_code",
            "candidate_bytes_change_required",
            "owner_approval_required",
            "external_official_finding_ids",
        ):
            if gap.get(field) != issue.get(field):
                raise ValueError("Phase-2A gap register details are inconsistent")

    impact = package.artifact("candidate-impact-report").payload
    if (
        impact.get("candidate_change_required_issue_count")
        != sum(row.get("candidate_bytes_change_required") is True for row in actual_issues)
        or impact.get("material_candidate_or_currentness_status_count")
        != actual_counts["MATERIAL_CANDIDATE_COVERAGE_GAP"]
        + actual_counts["MATERIAL_CURRENTNESS_GAP"]
        or impact.get("gold_or_case_remediation_issue_count")
        != actual_counts["GOLD_OR_CASE_DEFECT"]
        or impact.get("owner_legal_judgment_issue_count")
        != actual_counts["OWNER_LEGAL_JUDGMENT_REQUIRED"]
        or impact.get("source_conflict_or_unavailable_issue_count")
        != actual_counts["SOURCE_VERSION_CONFLICT"] + actual_counts["OFFICIAL_SOURCE_UNAVAILABLE"]
    ):
        raise ValueError("Phase-2A candidate impact does not reconcile to issue rows")
    candidate_rebuild_required = impact.get("candidate_rebuild_required") is True
    terminal_verdict = impact.get("terminal_verdict")
    issue_candidate_rebuild_required = any(
        row.get("candidate_bytes_change_required") is True
        or row.get("primary_status")
        in {"MATERIAL_CURRENTNESS_GAP", "MATERIAL_CANDIDATE_COVERAGE_GAP"}
        for row in actual_issues
    )
    expected_candidate_rebuild = bool(findings) or issue_candidate_rebuild_required
    common_cutoff_blocked = expected_candidate_rebuild or any(
        row.get("prevents_common_cutoff") is True for row in actual_issues
    )
    expected_terminal_verdict = (
        "BLOCKED_MATERIAL_GAPS" if common_cutoff_blocked else "OWNER_DECISIONS_REQUIRED"
    )
    if (
        candidate_rebuild_required != expected_candidate_rebuild
        or terminal_verdict != expected_terminal_verdict
        or impact.get("confirmed_material_candidate_finding_count") != len(findings)
        or tuple(impact.get("external_official_finding_ids") or ())
        != tuple(item.finding_id for item in findings)
    ):
        raise ValueError("Phase-2A candidate impact is not fail-closed")

    cutoff = package.artifact("cutoff-recommendation").payload
    if common_cutoff_blocked:
        if (
            cutoff.get("cutoff_support_status") != "UNSUPPORTABLE_ON_CURRENT_CANDIDATE"
            or cutoff.get("recommended_cutoff_date") is not None
            or cutoff.get("common_cutoff_freezable") is not False
        ):
            raise ValueError("Phase-2A unsupported cutoff is misrepresented")
    elif (
        cutoff.get("cutoff_support_status") != "SUPPORTED_FOR_OWNER_DECISION"
        or cutoff.get("recommended_cutoff_date") is None
        or cutoff.get("common_cutoff_freezable") is not True
    ):
        raise ValueError("Phase-2A supported cutoff is incomplete")

    freshness = package.artifact("freshness-material-change-policy").payload
    expected_source_currentness_counts = dict(
        sorted(Counter(str(row["currentness_status"]) for row in source_rows).items())
    )
    if freshness.get("source_currentness_status_counts") != expected_source_currentness_counts:
        raise ValueError("Phase-2A freshness source-currentness counts are inconsistent")

    summary = package.artifact("owner-readable-summary").payload
    expected_next_gate = (
        "CANDIDATE_AND_GOLD_REMEDIATION_BEFORE_PHASE_2B"
        if terminal_verdict == "BLOCKED_MATERIAL_GAPS"
        else "OWNER_APPROVAL_BEFORE_PHASE_2B"
    )
    if (
        summary.get("qualified_issue_count") != len(actual_issues) - len(nonpositive)
        or summary.get("nonpositive_issue_count") != len(nonpositive)
        or summary.get("candidate_source_count") != len(source_rows)
        or summary.get("terminal_verdict") != terminal_verdict
        or summary.get("candidate_rebuild_required") != candidate_rebuild_required
        or summary.get("next_gate") != expected_next_gate
    ):
        raise ValueError("Phase-2A owner summary is inconsistent")

    decision_draft = package.artifact("owner-decision-payload-draft").payload
    if (
        decision_draft.get("cutoff_basis_sha256") != cutoff.get("cutoff_basis_sha256")
        or decision_draft.get("freshness_policy_sha256") != freshness.get("policy_sha256")
        or decision_draft.get("security_controls_proposal_sha256")
        != package.artifact("security-owner-controls-proposal").payload.get("proposal_sha256")
        or decision_draft.get("certification_contract_proposal_sha256")
        != package.artifact("certification-contract-proposal").payload.get("proposal_sha256")
    ):
        raise ValueError("Phase-2A owner decision draft proposal bindings are inconsistent")

    invariants = package.artifact("final-invariants").payload
    phase2b_allowed = (
        not nonpositive
        and expected_terminal_verdict != "BLOCKED_MATERIAL_GAPS"
        and cutoff.get("cutoff_support_status") == "SUPPORTED_FOR_OWNER_DECISION"
        and cutoff.get("recommended_cutoff_date") is not None
    )
    if (
        invariants.get("terminal_verdict") != terminal_verdict
        or invariants.get("candidate_rebuild_required") != candidate_rebuild_required
        or invariants.get("action_absence_audit_sha256") != action_audit.audit_sha256
        or invariants.get("phase2b_allowed") != phase2b_allowed
        or any(
            invariants.get(field) is not True
            for field in (
                "real_split_absent",
                "real_secret_absent",
                "signing_material_absent",
                "runtime_actions_absent",
            )
        )
    ):
        raise ValueError("Phase-2A final invariants are inconsistent")

    expected_index = _make_index(reparsed)
    reparsed_index = Phase2APackageIndex.model_validate(
        package.index.model_dump(mode="json", by_alias=True)
    )
    if reparsed_index != expected_index:
        raise ValueError("Phase-2A package index does not reconcile to its artifacts")


def phase2a_package_json_payloads(package: Phase2APackage) -> dict[str, bytes]:
    """Return canonical bytes without writing files or granting authority."""

    reparsed = tuple(
        Phase2AArtifact.model_validate(artifact.model_dump(mode="json", by_alias=True))
        for artifact in package.artifacts
    )
    verify_ids = tuple(artifact.artifact_id for artifact in reparsed)
    if verify_ids != ARTIFACT_IDS:
        raise ValueError("Phase-2A package artifact identities are incomplete")
    expected_index = _make_index(reparsed)
    if (
        Phase2APackageIndex.model_validate(package.index.model_dump(mode="json", by_alias=True))
        != expected_index
    ):
        raise ValueError("Phase-2A package index differs from current artifact bytes")
    output = {
        f"{artifact.artifact_id}.json": canonical_json(
            artifact.model_dump(mode="json", by_alias=True)
        )
        for artifact in reparsed
    }
    output["PHASE2A-INDEX.json"] = canonical_json(
        package.index.model_dump(mode="json", by_alias=True)
    )
    return output
