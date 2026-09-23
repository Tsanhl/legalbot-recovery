"""Isolated GE research/index seam. No network, provider loading or ACTIVE access.

The trusted parent supplies the *out-of-band* owner instruction digest, exact
store scopes, independent reviewer verifier and a verified pinned embedder. These
are dependency-injection trust boundaries, not signatures or legacy capabilities.
Never construct that policy from a research payload. No runtime test-vector
fallback exists. Unit tests do not establish actual embedding validation.

Flow: bind v2 lineage -> enqueue -> begin_attempt -> reserve/finish research
operations -> capture -> prepare (independent eligibility) -> authorize exact
build -> build -> retrieve -> close_gap (independent affected-claim review).
All API data must already belong to the caller's scope; private facts, answers
and bank selections must never be supplied to a shared scope. The module stores
lineage digests, not request/fact bodies. Locks coordinate cooperating processes;
the parent must also enforce OS role isolation against hostile same-host writers.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import re
import sqlite3
import struct
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from ..contracts.schema_registry import ContractSchemaRegistry, canonical_json_bytes
from ..ingestion.chunking import StructuralChunker
from ..ingestion.models import ParseResult
from ..ingestion.sanitation import sanitize_parse_result
from ..retrieval.lancedb import ImmutableLanceRepository
from ..retrieval.qwen import EMBEDDING_MODEL, LEGAL_RETRIEVAL_INSTRUCTION

LANE_ROLES = {
    "shared_research": {"development", "evaluation"},
    "private_reference": {"curator", "reviewer"},
    "candidate_case_local": {"candidate"},
}
REVIEW_CHECKS = frozenset(
    {
        "official_identity",
        "authority_type",
        "jurisdiction",
        "date_commencement",
        "amendments_effects",
        "later_treatment",
        "quote_support",
        "issue_relevance",
        "necessary_context",
        "parser_binding",
        "rights",
    }
)
RESEARCH_GAPS = frozenset(
    {"missing_authority", "currentness", "retrieval_miss", "unsupported_claim"}
)
PENDING_EMBEDDING_VALIDATION = "ACTUAL_EMBEDDING_VALIDATION_PENDING"
SUPPORTED_JURISDICTIONS = frozenset(
    {
        "England",
        "Wales",
        "England and Wales",
        "Scotland",
        "Northern Ireland",
        "UK",
        "US federal",
        "District of Columbia",
        *[
            "Alabama",
            "Alaska",
            "Arizona",
            "Arkansas",
            "California",
            "Colorado",
            "Connecticut",
            "Delaware",
            "Florida",
            "Georgia",
            "Hawaii",
            "Idaho",
            "Illinois",
            "Indiana",
            "Iowa",
            "Kansas",
            "Kentucky",
            "Louisiana",
            "Maine",
            "Maryland",
            "Massachusetts",
            "Michigan",
            "Minnesota",
            "Mississippi",
            "Missouri",
            "Montana",
            "Nebraska",
            "Nevada",
            "New Hampshire",
            "New Jersey",
            "New Mexico",
            "New York",
            "North Carolina",
            "North Dakota",
            "Ohio",
            "Oklahoma",
            "Oregon",
            "Pennsylvania",
            "Rhode Island",
            "South Carolina",
            "South Dakota",
            "Tennessee",
            "Texas",
            "Utah",
            "Vermont",
            "Virginia",
            "Washington",
            "West Virginia",
            "Wisconsin",
            "Wyoming",
        ],
    }
)
_BOUND_LINEAGES: set[Lineage] = set()


def digest(value: Any) -> str:
    return hashlib.sha256(
        value if isinstance(value, bytes) else canonical_json_bytes(value)
    ).hexdigest()


def _sha(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("exact SHA-256 required")
    return value


def _day(value: str) -> str:
    if date.fromisoformat(value).isoformat() != value:
        raise ValueError("exact ISO date required")
    return value


def _safe_path(path: Path, root: Path) -> Path:
    """Reject aliases before following any component; rechecked on every access."""
    if not path.is_absolute() or ".." in path.parts or not path.is_relative_to(root):
        raise PermissionError("cross-root path denied")
    for component in (path, *path.parents):
        if component.is_symlink():
            raise PermissionError("symlink path denied")
    if path.exists() and path.is_file() and path.stat().st_nlink != 1:
        raise PermissionError("hard-linked file denied")
    return path


@dataclass(frozen=True)
class Scope:
    root: str
    lane: str
    origin_id: str
    case_id: str | None = None

    def validate(self, workspace: Path) -> None:
        root = _safe_path(Path(self.root), workspace)
        if root == workspace or self.lane not in LANE_ROLES or not self.origin_id:
            raise PermissionError("exact lane/origin/root required")
        if (self.lane == "candidate_case_local") != bool(self.case_id):
            raise PermissionError("candidate scope requires exactly one case")


@dataclass(frozen=True)
class ModelPin:
    revision: str
    files_sha256: str
    recipe_sha256: str
    model: str = EMBEDDING_MODEL
    dimensions: int = 1024

    @classmethod
    def from_runtime_identity(cls, identity: Mapping[str, Any]) -> ModelPin:
        """Accept the parent's exact local runtime identity format (not a model name)."""
        material = json.loads(canonical_json_bytes(identity))
        claimed = material.pop("identity_sha256", None)
        # The existing runtime identity profile has no terminating newline.
        if claimed != digest(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()):
            raise ValueError("runtime model identity digest mismatch")
        recipe = {
            "local_files_only": True,
            "device": "cpu",
            "max_tokens": 2048,
            "batch_size": 1,
            "torch_threads": 2,
            "normalise_embeddings": True,
            "training": False,
        }
        if any(type(material.get(k)) is not type(v) or material[k] != v for k, v in recipe.items()):
            raise ValueError("unsupported local inference recipe")
        pin = cls(
            material["revision"],
            material["file_manifest_sha256"],
            digest({**recipe, "query_instruction": LEGAL_RETRIEVAL_INSTRUCTION}),
            material["source_repo"],
            material["dimensions"],
        )
        pin.validate()
        return pin

    def validate(self) -> None:
        if self.model != EMBEDDING_MODEL or self.dimensions != 1024:
            raise ValueError("only the existing 1024-dimensional Qwen embedder is permitted")
        if re.fullmatch(r"[0-9a-f]{40}", self.revision) is None:
            raise ValueError("immutable model revision required")
        _sha(self.files_sha256)
        _sha(self.recipe_sha256)


class PinnedEmbedder(Protocol):
    """Parent verifies actual local files/recipe/provider; never downloads here."""

    pin: ModelPin

    def verify_binding(self) -> bool: ...
    def embed_documents(self, texts: Sequence[str]) -> Sequence[Sequence[float]]: ...
    def embed_query(self, text: str) -> Sequence[float]: ...


class RuntimeEmbeddingAdapter:
    """Wrap the parent's already-active, local-only PinnedEmbeddingSession.

    verify_identity must be the trusted runtime's local file/revision verifier,
    not a callback supplied by a research payload. No inference occurs here.
    """

    def __init__(
        self,
        session: Any,
        *,
        expected_identity: Mapping[str, Any],
        verify_identity: Callable[[], Mapping[str, Any]],
    ) -> None:
        self._identity = canonical_json_bytes(expected_identity)
        self.pin = ModelPin.from_runtime_identity(expected_identity)
        self._session, self._verify_identity = session, verify_identity

    def verify_binding(self) -> bool:
        return (
            self._session.provider is not None
            and canonical_json_bytes(self._session.identity) == self._identity
            and canonical_json_bytes(self._verify_identity()) == self._identity
            and ModelPin.from_runtime_identity(self._session.identity) == self.pin
        )

    def embed_documents(self, texts: Sequence[str]) -> Sequence[Sequence[float]]:
        return self._session.embed_documents(texts)

    def embed_query(self, text: str) -> Sequence[float]:
        return self._session.embed_query(text)


@dataclass(frozen=True)
class Lineage:
    request_id: str
    request_sha256: str
    query_plan_id: str
    query_plan_sha256: str
    candidate_id: str
    fact_snapshot_sha256: str
    conversation_snapshot_sha256: str
    conversation_revision: int
    knowledge_generation_id: str
    knowledge_generation_sha256: str
    schema_selection_sha256: str
    jurisdiction: str
    as_of_date: str
    issue_ids: tuple[str, ...]

    @classmethod
    def bind(
        cls,
        *,
        registry: ContractSchemaRegistry,
        query_plan: Mapping[str, Any],
        fact_snapshot: Mapping[str, Any],
        knowledge_generation: Mapping[str, Any],
        expected_request_sha256: str,
        expected_knowledge_generation_sha256: str,
        conversation_snapshot: Mapping[str, Any],
    ) -> Lineage:
        for value, schema in (
            (query_plan, "legalbot.query-plan.v2"),
            (fact_snapshot, "legalbot.matter-fact-snapshot.v2"),
            (knowledge_generation, ("legalbot.knowledge-generation-manifest.v1",
                                    "legalbot.research-empty-baseline.v1")),
            (conversation_snapshot, "legalbot.conversation-snapshot.v1"),
        ):
            if value.get("schema") not in (schema if isinstance(schema, tuple) else (schema,)):
                raise ValueError("selected v2 request/fact and knowledge contracts required")
            registry.validate_new(value)
        ref = query_plan["conversation_snapshot"]
        if (
            query_plan["schema_selection_sha256"] != registry.manifest_sha256
            or query_plan["request_sha256"] != _sha(expected_request_sha256)
            or query_plan["fact_snapshot_id"] != fact_snapshot["snapshot_id"]
            or ref["conversation_id"] != fact_snapshot["conversation_id"]
            or ref["revision"] != fact_snapshot["conversation_revision"]
            or ref["content_sha256"] != conversation_snapshot["content_sha256"]
            or ref["conversation_id"] != conversation_snapshot["conversation_id"]
            or ref["revision"] != conversation_snapshot["revision"]
            or fact_snapshot["owner_scope_sha256"] != conversation_snapshot["owner_scope_sha256"]
            or query_plan["data_intent"] not in {"KNOWLEDGE_ONLY", "HYBRID"}
            or query_plan["jurisdiction_status"] != "explicit"
            or query_plan["jurisdiction"] not in SUPPORTED_JURISDICTIONS
            or query_plan["as_of_date_status"] == "unresolved"
        ):
            raise ValueError("request/fact lineage mismatch or unresolved scope")
        if (
            knowledge_generation["content_sha256"] != _sha(expected_knowledge_generation_sha256)
            or knowledge_generation["closure_status"] not in {"validated", "candidate"}
            or not knowledge_generation["sealed_at"]
        ):
            raise ValueError("exact sealed baseline knowledge generation required")
        lineage = cls(
            query_plan["request_id"],
            expected_request_sha256,
            query_plan["query_plan_id"],
            digest(query_plan),
            query_plan["candidate_id"],
            fact_snapshot["content_sha256"],
            _sha(ref["content_sha256"]),
            ref["revision"],
            knowledge_generation["generation_id"],
            knowledge_generation["content_sha256"],
            registry.manifest_sha256,
            query_plan["jurisdiction"],
            _day(query_plan["requested_as_of_date"]),
            tuple(query_plan["issue_ids"]),
        )
        _BOUND_LINEAGES.add(lineage)
        return lineage


@dataclass(frozen=True)
class Capability:
    """Only meaningful with the same trusted policy's in-process issuer token."""

    policy_sha256: str
    scope: Scope
    actor: str
    role: str
    action: str
    binding_sha256: str
    _issuer: object


class ResearchPolicy:
    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_frozen", False):
            raise AttributeError("research policy bindings are immutable")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        *,
        workspace: Path,
        owner_instruction: bytes,
        expected_owner_instruction_sha256: str,
        scopes: Sequence[Scope],
        model: ModelPin,
        reviewers: Sequence[str],
        verify_review: Callable[[str, Mapping[str, Any]], bool],
    ) -> None:
        if not owner_instruction.strip() or digest(owner_instruction) != _sha(
            expected_owner_instruction_sha256
        ):
            raise PermissionError("owner instruction digest mismatch")
        _safe_path(workspace, workspace)
        model.validate()
        for scope in scopes:
            scope.validate(workspace)
        roots = [Path(scope.root) for scope in scopes]
        if any(
            a.is_relative_to(b) or b.is_relative_to(a)
            for i, a in enumerate(roots)
            for b in roots[i + 1 :]
        ):
            raise PermissionError("store roots must be disjoint, including cases")
        self.workspace, self.scopes, self.model = workspace, tuple(scopes), model
        self.reviewers, self.verify_review = frozenset(reviewers), verify_review
        self.owner_instruction = bytes(owner_instruction)
        self.sha256 = digest(
            {
                "schema": "legalbot.ge-auto-research-policy.v1",
                "owner_instruction_sha256": expected_owner_instruction_sha256,
                "scopes": [asdict(s) for s in scopes],
                "model": asdict(model),
                "reviewers": sorted(self.reviewers),
                "actions": ["jobs", "build", "retrieve", "close_gap"],
            }
        )
        self._issuer = object()
        self._issued: set[Capability] = set()
        self._frozen = True

    def authorize(
        self, *, scope: Scope, actor: str, role: str, action: str, binding_sha256: str
    ) -> Capability:
        """Called by the trusted coordinator, never by a source/research payload."""
        if (
            scope not in self.scopes
            or role not in LANE_ROLES.get(scope.lane, set())
            or not actor
            or action not in {"jobs", "build", "retrieve", "close_gap"}
        ):
            raise PermissionError("action/lane/role denied")
        scope.validate(self.workspace)
        capability = Capability(
            self.sha256, scope, actor, role, action, _sha(binding_sha256), self._issuer
        )
        self._issued.add(capability)
        return capability

    def require(self, cap: Capability, scope: Scope, action: str, binding: str) -> None:
        if (
            type(cap) is not Capability
            or cap._issuer is not self._issuer
            or cap not in self._issued
            or cap.policy_sha256 != self.sha256
            or cap.scope != scope
            or cap.action != action
            or cap.binding_sha256 != binding
            or cap.role not in LANE_ROLES.get(scope.lane, set())
        ):
            raise PermissionError("wrong action, root, lane, case or exact binding")
        scope.validate(self.workspace)

    def independent(self, receipt: Mapping[str, Any], excluded: Sequence[str]) -> None:
        reviewer = receipt.get("reviewer_id")
        if (
            reviewer not in self.reviewers
            or reviewer in excluded
            or self.verify_review(str(reviewer), receipt) is not True
        ):
            raise PermissionError("independent exact-receipt reviewer verification required")


@dataclass(frozen=True)
class Capture:
    scope: Scope
    researcher_id: str
    raw: bytes
    parsed: ParseResult
    parser_sha256: str
    canonical_url: str
    final_url: str
    redirect_chain: tuple[str, ...]
    fetched_at: str
    source_identity: str
    authority_type: str
    jurisdiction: str
    rights_sha256: str

    def manifest(self) -> dict[str, Any]:
        return {
            "scope": asdict(self.scope),
            "researcher_id": self.researcher_id,
            "source_sha256": digest(self.raw),
            "parsed_sha256": digest(asdict(self.parsed)),
            "parser_sha256": self.parser_sha256,
            "canonical_url": self.canonical_url,
            "final_url": self.final_url,
            "redirect_chain": self.redirect_chain,
            "fetched_at": self.fetched_at,
            "source_identity": self.source_identity,
            "authority_type": self.authority_type,
            "jurisdiction": self.jurisdiction,
            "rights_sha256": self.rights_sha256,
        }


@dataclass(frozen=True)
class PreparedBuild:
    """Canonical bytes avoid mutable mappings under a frozen capability."""

    payload: bytes

    @property
    def sha256(self) -> str:
        return digest(self.payload)


class AutoResearchIndex:
    """One exact lane/root. SQLite jobs and receipts; immutable Lance generations."""

    def __init__(
        self, *, policy: ResearchPolicy, capability: Capability, scope: Scope, lineage: Lineage
    ) -> None:
        if type(lineage) is not Lineage or lineage not in _BOUND_LINEAGES:
            raise ValueError("lineage must come from selected-contract Lineage.bind")
        self.policy, self.scope, self.lineage = policy, scope, lineage
        self.lineage_sha256 = digest(asdict(lineage))
        policy.require(capability, scope, "jobs", self.lineage_sha256)
        self.actor = capability.actor
        self.root = Path(scope.root)
        self.root.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS objects (
                    digest TEXT PRIMARY KEY, kind TEXT NOT NULL, payload BLOB NOT NULL);
                CREATE TABLE IF NOT EXISTS gaps (
                    id TEXT PRIMARY KEY, payload BLOB NOT NULL, state TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS attempts (
                    id INTEGER PRIMARY KEY, gap TEXT NOT NULL, inputs TEXT NOT NULL,
                    change_reason TEXT NOT NULL, state TEXT NOT NULL,
                    failure TEXT, reason TEXT, UNIQUE(gap, inputs));
                CREATE TABLE IF NOT EXISTS operations (
                    id INTEGER PRIMARY KEY, attempt INTEGER NOT NULL, kind TEXT NOT NULL,
                    input_sha TEXT NOT NULL, state TEXT NOT NULL, result TEXT,
                    UNIQUE(attempt, kind, input_sha));
            """)
            # executescript commits its schema transaction; reacquire for identity check.
            db.execute("BEGIN IMMEDIATE")
            identity = {"scope": asdict(scope), "policy_sha256": policy.sha256}
            old = db.execute("SELECT digest FROM objects WHERE kind='store_identity'").fetchone()
            if old and old[0] != digest(identity):
                raise PermissionError("existing store identity mismatch")
            self._put(db, "store_identity", identity)
            self._put(db, "owner_instruction", policy.owner_instruction)

    def _path(self, path: Path) -> Path:
        self.scope.validate(self.policy.workspace)
        return _safe_path(path, self.root)

    @contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        path = self._path(self.root / "metadata.sqlite3")
        for suffix in ("-journal", "-wal", "-shm"):
            self._path(Path(str(path) + suffix))
        db = sqlite3.connect(path, timeout=10)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def _put(db: sqlite3.Connection, kind: str, value: Any) -> str:
        raw = value if isinstance(value, bytes) else canonical_json_bytes(value)
        key = digest(raw)
        existing = db.execute("SELECT payload FROM objects WHERE digest=?", (key,)).fetchone()
        if existing and existing[0] != raw:
            raise ValueError("immutable metadata artifact was modified")
        db.execute("INSERT OR IGNORE INTO objects VALUES (?, ?, ?)", (key, kind, raw))
        return key

    def _raw(self, key: str, kind: str | None = None) -> bytes:
        with self._db() as db:
            row = db.execute(
                "SELECT kind,payload FROM objects WHERE digest=?", (_sha(key),)
            ).fetchone()
        if row is None or (kind is not None and row[0] != kind) or digest(row[1]) != key:
            raise ValueError("missing or modified exact artifact")
        return row[1]

    def _get(self, key: str, kind: str | None = None) -> Any:
        return json.loads(self._raw(key, kind))

    def _require(self, cap: Capability, action: str, binding: str) -> None:
        self.policy.require(cap, self.scope, action, binding)

    def enqueue(
        self,
        cap: Capability,
        *,
        issue_id: str,
        gap_class: str,
        affected_claim_sha256: str,
        failure_fingerprint: str,
    ) -> str:
        self._require(cap, "jobs", self.lineage_sha256)
        if issue_id not in self.lineage.issue_ids:
            raise ValueError("issue absent from exact QueryPlan")
        value = {
            "scope": asdict(self.scope),
            "lineage": asdict(self.lineage),
            "issue_id": issue_id,
            "gap_class": gap_class,
            "affected_claim_sha256": _sha(affected_claim_sha256),
            "failure_fingerprint": _sha(failure_fingerprint),
        }
        key = digest(value)
        with self._db() as db:
            db.execute(
                "INSERT OR IGNORE INTO gaps VALUES (?, ?, ?)",
                (
                    key,
                    canonical_json_bytes(value),
                    "OPEN" if gap_class in RESEARCH_GAPS else "HOLD_NON_RESEARCH",
                ),
            )
        return key

    def status(self, gap: str) -> dict[str, Any]:
        with self._db() as db:
            row = db.execute("SELECT payload,state FROM gaps WHERE id=?", (_sha(gap),)).fetchone()
            attempts = db.execute(
                "SELECT id,inputs,state,failure,reason FROM attempts WHERE gap=? ORDER BY id",
                (gap,),
            ).fetchall()
        if row is None or digest(row[0]) != gap:
            raise ValueError("unknown or modified gap")
        value = json.loads(row[0])
        if digest(value["lineage"]) != self.lineage_sha256 or value["scope"] != asdict(self.scope):
            raise PermissionError("gap lineage/scope mismatch")
        return {"gap": value, "state": row[1], "attempts": attempts}

    def begin_attempt(
        self,
        cap: Capability,
        gap: str,
        *,
        inputs_sha256: str,
        existing_retrieval_sha256: str,
        change_reason: str = "",
    ) -> int | None:
        """None is unchanged work. A failed path permits only one changed-input retry."""
        self._require(cap, "jobs", self.lineage_sha256)
        self.status(gap)
        _sha(inputs_sha256)
        _sha(existing_retrieval_sha256)  # parent-bound existing index check, before discovery
        with self._db() as db:
            rows = db.execute(
                "SELECT id,inputs,state FROM attempts WHERE gap=? ORDER BY id", (gap,)
            ).fetchall()
            state = db.execute("SELECT state FROM gaps WHERE id=?", (gap,)).fetchone()[0]
            if any(row[1] == inputs_sha256 for row in rows) or state == "CLOSED":
                return None
            if state == "HOLD_NON_RESEARCH":
                raise ValueError("research cannot repair this gap class")
            if rows and (rows[-1][2] != "FAILED" or len(rows) >= 2 or not change_reason.strip()):
                raise ValueError(
                    "active/unchanged/exhausted path; one documented targeted retry only"
                )
            cursor = db.execute(
                "INSERT INTO attempts(gap,inputs,change_reason,state) VALUES (?,?,?,'RUNNING')",
                (gap, inputs_sha256, change_reason),
            )
            attempt = int(cursor.lastrowid)
            self._put(
                db,
                "attempt_start",
                {
                    "attempt": attempt,
                    "gap": gap,
                    "inputs_sha256": inputs_sha256,
                    "existing_retrieval_sha256": existing_retrieval_sha256,
                    "change_reason": change_reason,
                },
            )
            db.execute("UPDATE gaps SET state='RESEARCHING' WHERE id=?", (gap,))
        return attempt

    def _attempt(self, db: sqlite3.Connection, attempt: int) -> str:
        row = db.execute(
            "SELECT a.gap,a.state,g.payload FROM attempts a JOIN gaps g ON g.id=a.gap WHERE a.id=?",
            (attempt,),
        ).fetchone()
        if (
            not row
            or row[1] != "RUNNING"
            or digest(row[2]) != row[0]
            or digest(json.loads(row[2])["lineage"]) != self.lineage_sha256
        ):
            raise ValueError("attempt is not running under this lineage")
        return row[0]

    def reserve(self, cap: Capability, attempt: int, *, kind: str, input_sha256: str) -> int | None:
        """Reserve before external work; crashed/failed operations still consume budget."""
        self._require(cap, "jobs", self.lineage_sha256)
        if kind not in {"query", "capture"}:
            raise ValueError("unknown research operation")
        _sha(input_sha256)
        with self._db() as db:
            gap = self._attempt(db, attempt)
            if db.execute(
                "SELECT 1 FROM operations WHERE attempt=? AND kind=? AND input_sha=?",
                (attempt, kind, input_sha256),
            ).fetchone():
                return None
            count = db.execute(
                "SELECT count(*) FROM operations WHERE attempt=? AND kind=?", (attempt, kind)
            ).fetchone()[0]
            if count >= {"query": 4, "capture": 8}[kind]:
                db.execute(
                    "UPDATE attempts SET state='FAILED',failure=?,reason='BUDGET_HOLD' WHERE id=?",
                    (digest({"failure": "budget", "kind": kind}), attempt),
                )
                db.execute("UPDATE gaps SET state='HOLD_BUDGET' WHERE id=?", (gap,))
                return None
            return int(
                db.execute(
                    "INSERT INTO operations(attempt,kind,input_sha,state) VALUES (?,?,?,'RESERVED')",
                    (attempt, kind, input_sha256),
                ).lastrowid
            )

    def finish_operation(
        self, cap: Capability, operation: int, *, receipt: Mapping[str, Any], success: bool
    ) -> str:
        self._require(cap, "jobs", self.lineage_sha256)
        with self._db() as db:
            row = db.execute(
                "SELECT attempt,state FROM operations WHERE id=?", (operation,)
            ).fetchone()
            if not row or row[1] != "RESERVED":
                raise ValueError("operation already terminal or unknown")
            self._attempt(db, row[0])
            key = self._put(db, "operation_receipt", dict(receipt))
            db.execute(
                "UPDATE operations SET state=?,result=? WHERE id=?",
                ("COMPLETE" if success else "FAILED", key, operation),
            )
        return key

    def fail_attempt(self, cap: Capability, attempt: int, *, fingerprint: str, reason: str) -> None:
        self._require(cap, "jobs", self.lineage_sha256)
        if not reason.strip():
            raise ValueError("precise hold reason required")
        with self._db() as db:
            gap = self._attempt(db, attempt)
            db.execute(
                "UPDATE attempts SET state='FAILED',failure=?,reason=? WHERE id=?",
                (_sha(fingerprint), reason, attempt),
            )
            db.execute("UPDATE gaps SET state='HOLD' WHERE id=?", (gap,))

    def capture(self, cap: Capability, operation: int, source: Capture) -> str:
        self._require(cap, "jobs", self.lineage_sha256)
        if source.scope != self.scope:
            raise PermissionError("cross-lane/case capture denied")
        if not source.researcher_id or not source.source_identity or not source.authority_type:
            raise ValueError("source identity, authority type and researcher required")
        if not source.raw or len(source.raw) > 8 * 1024 * 1024:
            raise ValueError("empty/oversized capture held")
        _sha(source.parser_sha256)
        _sha(source.rights_sha256)
        if datetime.fromisoformat(source.fetched_at).tzinfo is None:
            raise ValueError("capture timestamp requires timezone")
        for url in (source.canonical_url, source.final_url, *source.redirect_chain):
            parsed_url = urlsplit(url)
            if parsed_url.scheme != "https" or not parsed_url.hostname or parsed_url.username:
                raise ValueError("exact HTTPS capture provenance required")
        manifest = source.manifest()
        with self._db() as db:
            row = db.execute(
                "SELECT attempt,kind,state FROM operations WHERE id=?", (operation,)
            ).fetchone()
            if not row or row[1:] != ("capture", "RESERVED"):
                raise ValueError("capture requires reserved budget")
            gap = self._attempt(db, row[0])
            self._put(db, "raw_source", source.raw)
            self._put(db, "parsed_source", asdict(source.parsed))
            key = self._put(db, "capture", manifest)
            self._put(db, "capture_binding", {"gap": gap, "capture_sha256": key, "attempt": row[0]})
            db.execute(
                "UPDATE operations SET state='COMPLETE',result=? WHERE id=?", (key, operation)
            )
        return key  # retained quarantine; deliberately no eligibility transition

    def prepare(
        self,
        cap: Capability,
        *,
        gap: str,
        attempt: int,
        sources: Sequence[tuple[Capture, Mapping[str, Any]]],
    ) -> PreparedBuild:
        self._require(cap, "jobs", self.lineage_sha256)
        job = self.status(gap)["gap"]
        if not 1 <= len(sources) <= 8:
            raise ValueError("one to eight reviewed sources required")
        chunker = StructuralChunker()
        chunker_sha = digest(
            {
                "schema": chunker.schema,
                "max_chars": chunker.max_chars,
                "min_chars": chunker.min_chars,
                "implementation": digest(
                    Path(__file__).parents[1].joinpath("ingestion/chunking.py").read_bytes()
                ),
                "sanitation": digest(
                    Path(__file__).parents[1].joinpath("ingestion/sanitation.py").read_bytes()
                ),
            }
        )
        rows, manifests, reviews = [], [], []
        for source, review_input in sources:
            review = json.loads(canonical_json_bytes(review_input))
            manifest = source.manifest()
            capture_sha = digest(manifest)
            with self._db() as db:
                if self._attempt(db, attempt) != gap:
                    raise ValueError("attempt/gap mismatch")
                binding = {"gap": gap, "capture_sha256": capture_sha, "attempt": attempt}
                if not db.execute(
                    "SELECT 1 FROM objects WHERE digest=? AND kind='capture_binding'",
                    (digest(binding),),
                ).fetchone():
                    raise ValueError("source was not captured for this attempt")
                self._put(db, "source_review_attempt", review)
            if self._get(capture_sha, "capture") != json.loads(canonical_json_bytes(manifest)):
                raise ValueError("source capture mismatch")
            self.policy.independent(review, (source.researcher_id, cap.actor))
            expected = {
                "capture_sha256": capture_sha,
                "source_sha256": digest(source.raw),
                "parsed_sha256": digest(asdict(source.parsed)),
                "scope": asdict(self.scope),
                "issue_id": job["issue_id"],
                "affected_claim_sha256": job["affected_claim_sha256"],
                "jurisdiction": self.lineage.jurisdiction,
                "as_of_date": self.lineage.as_of_date,
            }
            if any(review.get(k) != v for k, v in expected.items()):
                raise ValueError("review source/quote/jurisdiction/date/claim binding mismatch")
            if (
                set(review.get("checks", [])) != REVIEW_CHECKS
                or review.get("decision") != "ELIGIBLE_RESEARCH_ONLY"
                or review.get("uncertainties") != []
                or source.scope != self.scope
                or source.jurisdiction != self.lineage.jurisdiction
                or any(
                    review.get(k) is True
                    for k in (
                        "admitted",
                        "legal_gold",
                        "qualified_legal_review",
                        "professional_legal_sign_off",
                        "full_current_law_eligible",
                    )
                )
            ):
                raise ValueError("source eligibility held")
            start, end = _day(review["valid_from"]), _day(review["valid_to"])
            if not start <= self.lineage.as_of_date <= end:
                raise ValueError("wrong legal date excluded")
            if not source.parsed.is_ready or sanitize_parse_result(source.parsed) != source.parsed:
                raise ValueError("review must bind ready, sanitized parse bytes")
            blocks = {block.ordinal: block for block in source.parsed.body_blocks}
            if len(blocks) != len(source.parsed.body_blocks):
                raise ValueError("duplicate structural block ordinal")
            selected = tuple(review["context_block_ordinals"])
            block = blocks.get(review["quote_block_ordinal"])
            if (
                not block
                or not review.get("quote")
                or review["quote"] not in block.text
                or review.get("locator") != block.source_anchor
                or not block.source_anchor
                or block.ordinal not in selected
                or len(set(selected)) != len(selected)
                or not set(selected) <= blocks.keys()
            ):
                raise ValueError("exact quote/locator/necessary context mismatch")
            chunks = chunker.chunk_body(source.parsed, document_sha256=digest(source.raw))
            # Include every chunk touching required blocks, including split exceptions.
            included = [c for c in chunks if set(c.block_ordinals).intersection(selected)]
            if not included or not any(review["quote"] in c.text for c in included):
                raise ValueError("reviewed quote not retrievable after structural chunking")
            if any(not set(c.block_ordinals) <= set(selected) for c in included):
                raise ValueError("chunk includes context outside the reviewed block selection")
            review_sha = digest(review)
            group = digest({"capture": capture_sha, "review": review_sha})
            for chunk in included:
                rows.append(
                    {
                        "id": digest(
                            {"group": group, "chunk": asdict(chunk), "chunker": chunker_sha}
                        ),
                        "text": chunk.text,
                        "text_sha256": digest(chunk.text.encode()),
                        "structural_chunk": asdict(chunk),
                        "group": group,
                        "capture_sha256": capture_sha,
                        "review_sha256": review_sha,
                        "jurisdiction": source.jurisdiction,
                        "valid_from": start,
                        "valid_to": end,
                        "lane": self.scope.lane,
                        "scope_sha256": digest(asdict(self.scope)),
                    }
                )
            manifests.append(manifest)
            reviews.append(review)
        if len({row["id"] for row in rows}) != len(rows):
            raise ValueError("duplicate source/chunk identity")
        material = {
            "schema": "legalbot.ge-auto-index-build.v1",
            "scope": asdict(self.scope),
            "policy_sha256": self.policy.sha256,
            "lineage": asdict(self.lineage),
            "gap": gap,
            "attempt": attempt,
            "sources": manifests,
            "reviews": reviews,
            "source_manifest_sha256": digest(manifests),
            "review_manifest_sha256": digest(reviews),
            "chunk_manifest_sha256": digest(rows),
            "chunker_sha256": chunker_sha,
            "model": asdict(self.policy.model),
            "model_sha256": digest(asdict(self.policy.model)),
            "rows": rows,
            "runtime_sha256": digest(Path(__file__).read_bytes()),
            "query_instruction_sha256": digest(LEGAL_RETRIEVAL_INSTRUCTION.encode()),
        }
        prepared = PreparedBuild(canonical_json_bytes(material))
        with self._db() as db:
            self._put(db, "prepared_build", prepared.payload)
        return prepared

    @contextmanager
    def _embedding_lock(self, provider: PinnedEmbedder) -> Iterator[None]:
        # One lock shared by all policy scopes, outside candidate/reference stores.
        path = _safe_path(
            self.policy.workspace / ".ge-auto-index-embedding.lock", self.policy.workspace
        )
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if provider.pin != self.policy.model or provider.verify_binding() is not True:
                raise PermissionError("pinned embedding provider/files/recipe verification failed")
            yield
        finally:
            os.close(fd)

    @staticmethod
    def _vector(value: Sequence[float]) -> list[float]:
        if len(value) != 1024:
            raise ValueError("embedding dimension mismatch")
        output = [struct.unpack("f", struct.pack("f", float(x)))[0] for x in value]
        if not all(math.isfinite(x) for x in output) or sum(x * x for x in output) == 0:
            raise ValueError("non-finite/zero embedding rejected")
        return output

    def _tree(self, root: Path) -> dict[str, str]:
        self._path(root)
        result = {}
        for directory, dirs, files in os.walk(root, followlinks=False):
            for name in (*dirs, *files):
                path = self._path(Path(directory) / name)
                if path.is_file() and path != root / "generation.json":
                    result[str(path.relative_to(root))] = digest(path.read_bytes())
        return result

    def build(self, cap: Capability, prepared: PreparedBuild, *, provider: PinnedEmbedder) -> str:
        self._require(cap, "build", prepared.sha256)
        value = self._get(prepared.sha256, "prepared_build")
        if (
            canonical_json_bytes(value) != prepared.payload
            or digest(value["lineage"]) != self.lineage_sha256
        ):
            raise ValueError("prepared build lineage mismatch")
        build_id = "ge-auto-" + prepared.sha256
        self._path(self.root / "builds")
        final = self._path(self.root / "builds" / build_id)
        if final.exists():
            receipt = self._read_generation(prepared.sha256)[0]
            self._record_generation(value, receipt)
            return receipt["generation_sha256"]
        if value["runtime_sha256"] != digest(Path(__file__).read_bytes()):
            raise ValueError("runtime changed after build preparation")
        self._verify_sources(value)
        with self._db() as db:
            if self._attempt(db, value["attempt"]) != value["gap"]:
                raise ValueError("build attempt/gap mismatch")
        staging = self._path(self.root / "builds" / ("." + build_id + ".incomplete"))
        repository = ImmutableLanceRepository(self.root)
        repository.prepare_new_staging(build_id)
        boundary = {
            "schema": "legalbot.index-build-boundary.v1",
            "build_id": build_id,
            "ge_held_scope": True,
            "successor_must_remain_non_active": True,
        }
        (staging / "build-boundary.json").write_bytes(canonical_json_bytes(boundary))
        try:
            with self._embedding_lock(provider):
                vectors = provider.embed_documents([row["text"] for row in value["rows"]])
                if len(vectors) != len(value["rows"]):
                    raise ValueError("embedding count mismatch")
                vectors = [self._vector(v) for v in vectors]
            import lancedb
            import pyarrow as pa

            rows = [
                {
                    "id": row["id"],
                    "text": row["text"],
                    "jurisdiction": row["jurisdiction"],
                    "valid_from": row["valid_from"],
                    "valid_to": row["valid_to"],
                    "vector": vector,
                    "binding_json": canonical_json_bytes(row).decode(),
                }
                for row, vector in zip(value["rows"], vectors, strict=True)
            ]
            schema = pa.schema(
                [(k, pa.string()) for k in rows[0] if k != "vector"]
                + [("vector", pa.list_(pa.float32(), 1024))]
            )
            lane_path = staging / "lance" / "authority"
            connection = lancedb.connect(str(lane_path))
            table = connection.create_table(
                "chunks", data=pa.Table.from_pylist(rows, schema=schema), mode="create"
            )
            table.create_fts_index("text", replace=False, use_tantivy=False)
            repository.create_vector_indexes(staging / "lance", lancedb)
            # A new connection performs persisted read-back; no insertion count shortcut.
            readback = lancedb.connect(str(lane_path)).open_table("chunks").to_arrow().to_pylist()
            expected = sorted(rows, key=lambda r: r["id"])
            if sorted(readback, key=lambda r: r["id"]) != expected:
                raise ValueError("persisted LanceDB text/vector binding mismatch")
            for row in rows:
                lexical = table.search(row["text"], query_type="fts").limit(len(rows)).to_list()
                vector = (
                    table.search(row["vector"], vector_column_name="vector")
                    .metric("cosine")
                    .limit(len(rows))
                    .to_list()
                )
                if row["id"] not in {r["id"] for r in lexical} or row["id"] not in {
                    r["id"] for r in vector
                }:
                    raise ValueError("intended passage lexical/vector read-back failed")
            receipt = {
                "schema": "legalbot.ge-auto-index-generation.v1",
                "build_sha256": prepared.sha256,
                "scope": asdict(self.scope),
                "lineage": asdict(self.lineage),
                "source_manifest_sha256": value["source_manifest_sha256"],
                "review_manifest_sha256": value["review_manifest_sha256"],
                "chunk_manifest_sha256": value["chunk_manifest_sha256"],
                "model_sha256": value["model_sha256"],
                "rows_sha256": digest(expected),
                "files": self._tree(staging),
                "chunk_count": len(rows),
                "embedding_execution": "INJECTED_PROVIDER_EXECUTED",
                "embedding_validation": PENDING_EMBEDDING_VALIDATION,
                "non_live": True,
                "admitted": False,
                "legal_gold": False,
                "qualified_legal_review": False,
                "full_current_law_eligible": False,
            }
            receipt["generation_sha256"] = digest(receipt)
            with (staging / "generation.json").open("xb") as handle:
                handle.write(canonical_json_bytes(receipt))
                handle.flush()
                os.fsync(handle.fileno())
            repository.finalize_staging(build_id)
            self._record_generation(value, receipt)
            return receipt["generation_sha256"]
        except Exception as exc:
            with self._db() as db:
                self._put(
                    db,
                    "build_hold",
                    {
                        "build_sha256": prepared.sha256,
                        "error_type": type(exc).__name__,
                        "reason": str(exc),
                        "preserved_staging": str(staging),
                    },
                )
                db.execute("UPDATE gaps SET state='HOLD_BUILD' WHERE id=?", (value["gap"],))
                db.execute(
                    "UPDATE attempts SET state='FAILED',failure=?,reason=? WHERE id=? AND state='RUNNING'",
                    (
                        digest({"type": type(exc).__name__, "reason": str(exc)}),
                        str(exc),
                        value["attempt"],
                    ),
                )
            raise

    def _record_generation(self, value: Mapping[str, Any], receipt: Mapping[str, Any]) -> None:
        # Recover a crash between atomic publication and SQLite commit without inference.
        with self._db() as db:
            self._put(db, "generation", receipt)
            db.execute(
                "UPDATE gaps SET state='INDEXED_PENDING_CLAIM_REVIEW' WHERE id=? AND state!='CLOSED'",
                (value["gap"],),
            )

    def _verify_sources(self, value: Mapping[str, Any]) -> None:
        for source in value["sources"]:
            self._raw(source["source_sha256"], "raw_source")
            self._raw(source["parsed_sha256"], "parsed_source")
            self._raw(digest(source), "capture")
        for review in value["reviews"]:
            self._raw(digest(review), "source_review_attempt")

    def _read_generation(self, build_sha256: str) -> tuple[dict[str, Any], Path]:
        value = self._get(build_sha256, "prepared_build")
        if digest(value["lineage"]) != self.lineage_sha256 or value["scope"] != asdict(self.scope):
            raise PermissionError("generation cross-root/lineage denial")
        self._verify_sources(value)
        root = self._path(self.root / "builds" / ("ge-auto-" + build_sha256))
        receipt = json.loads(self._path(root / "generation.json").read_bytes())
        material = dict(receipt)
        key = material.pop("generation_sha256")
        if (
            digest(material) != key
            or receipt["build_sha256"] != build_sha256
            or receipt["files"] != self._tree(root)
            or any(
                receipt[k] != value[k]
                for k in (
                    "scope",
                    "lineage",
                    "source_manifest_sha256",
                    "review_manifest_sha256",
                    "chunk_manifest_sha256",
                    "model_sha256",
                )
            )
        ):
            raise ValueError("generation digest/file integrity mismatch")
        return receipt, root

    def retrieve(
        self,
        cap: Capability,
        *,
        build_sha256: str,
        generation_sha256: str,
        query: str,
        lineage: Lineage,
        provider: PinnedEmbedder,
        limit: int = 8,
    ) -> dict[str, Any]:
        self._require(cap, "retrieve", generation_sha256)
        if lineage != self.lineage or not query.strip() or not 1 <= limit <= 32:
            raise ValueError("query lineage/jurisdiction/date mismatch or invalid budget")
        receipt, root = self._read_generation(build_sha256)
        if receipt["generation_sha256"] != generation_sha256:
            raise ValueError("generation substitution")
        with self._embedding_lock(provider):
            vector = self._vector(provider.embed_query(query))
        import lancedb

        table = lancedb.connect(str(root / "lance" / "authority")).open_table("chunks")

        def literal(value: str) -> str:
            return "'" + value.replace("'", "''") + "'"

        predicate = (
            f"jurisdiction = {literal(lineage.jurisdiction)} AND "
            f"valid_from <= {literal(lineage.as_of_date)} AND valid_to >= {literal(lineage.as_of_date)}"
        )
        lexical = (
            table.search(query, query_type="fts")
            .where(predicate, prefilter=True)
            .limit(limit)
            .to_list()
        )
        vector_hits = (
            table.search(vector, vector_column_name="vector")
            .metric("cosine")
            .where(predicate, prefilter=True)
            .limit(limit)
            .to_list()
        )
        all_rows = table.to_arrow().to_pylist()
        if digest(sorted(all_rows, key=lambda r: r["id"])) != receipt["rows_sha256"]:
            raise ValueError("persisted row binding changed")
        ranks: dict[str, float] = {}
        for hits in (lexical, vector_hits):
            for rank, row in enumerate(hits, 1):
                ranks[row["id"]] = ranks.get(row["id"], 0) + 1 / (60 + rank)
        selected = sorted(ranks, key=lambda key: (-ranks[key], key))[:limit]
        bindings = {r["id"]: json.loads(r["binding_json"]) for r in all_rows}
        groups = {bindings[key]["group"] for key in selected}
        # Context expansion is mandatory, never truncated to the hit budget.
        evidence = [
            r
            for r in bindings.values()
            if r["group"] in groups
            and r["jurisdiction"] == lineage.jurisdiction
            and r["valid_from"] <= lineage.as_of_date <= r["valid_to"]
        ]
        result = {
            "schema": "legalbot.ge-auto-index-retrieval.v1",
            "scope": asdict(self.scope),
            "lineage": asdict(lineage),
            "build_sha256": build_sha256,
            "generation_sha256": generation_sha256,
            "query_sha256": digest(query.encode()),
            "retrieval_runtime_sha256": digest(Path(__file__).read_bytes()),
            "selected_ids": selected,
            "evidence": evidence,
            "retriever_id": cap.actor,
            "lexical_ids": [r["id"] for r in lexical],
            "vector_ids": [r["id"] for r in vector_hits],
        }
        with self._db() as db:
            result_sha = self._put(db, "retrieval", result)
        return {**result, "retrieval_sha256": result_sha}

    def close_gap(
        self, cap: Capability, *, gap: str, retrieval_sha256: str, claim_review: Mapping[str, Any]
    ) -> None:
        """An insert, a search hit, or an arbitrary caller PASS cannot close a gap."""
        self._require(cap, "close_gap", retrieval_sha256)
        job = self.status(gap)["gap"]
        result = self._get(retrieval_sha256, "retrieval")
        build = self._get(result["build_sha256"], "prepared_build")
        generation, _ = self._read_generation(result["build_sha256"])
        with self._db() as db:
            self._put(db, "claim_review_attempt", dict(claim_review))
        self.policy.independent(
            claim_review,
            (cap.actor, result["retriever_id"], *(s["researcher_id"] for s in build["sources"])),
        )
        expected = {
            "gap": gap,
            "affected_claim_sha256": job["affected_claim_sha256"],
            "retrieval_sha256": retrieval_sha256,
            "generation_sha256": generation["generation_sha256"],
            "lineage_sha256": self.lineage_sha256,
            "decision": "VERIFIED_AFFECTED_CLAIM",
            "material_omissions_checked": True,
            "contrary_authority_checked": True,
        }
        supported = set(claim_review.get("supported_chunk_ids", []))
        if (
            build["gap"] != gap
            or any(claim_review.get(k) != v for k, v in expected.items())
            or not supported
            or not supported <= {r["id"] for r in result["evidence"]}
            or not supported.intersection(result["selected_ids"])
        ):
            raise ValueError("retrieved evidence and affected-claim verification required")
        with self._db() as db:
            self._put(db, "gap_closure", {**expected, "review_sha256": digest(claim_review)})
            db.execute("UPDATE gaps SET state='CLOSED' WHERE id=?", (gap,))
            db.execute("UPDATE attempts SET state='COMPLETE' WHERE id=?", (build["attempt"],))
