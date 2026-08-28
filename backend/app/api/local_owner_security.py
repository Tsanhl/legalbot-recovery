"""Literal-loopback session and CSRF policy preparation for owner-only live.

No session secret is created here and the current API middleware is not
activated by this module.  The exact request policy and resource observer are
ready for Phase 2, while the production capability remains impossible to mint
until a trusted signed owner-package verifier is implemented.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from ..governance.immutable_capability import ImmutableOpaqueCapability
from ..governance.v111_exact_private_root import (
    open_exact_private_root_descriptor,
    require_exact_private_root_descriptor_current,
)
from ..governance.v111_phase2_preparation import (
    Phase2LocalConfiguration,
    Phase2PreparationStop,
    require_external_nonsynced_path_configuration,
)

LOCAL_SESSION_SECRET_OBSERVATION_SCHEMA = "legalbot.local-session-secret-observation.v1"
LOCAL_OWNER_REQUEST_POLICY_SCHEMA = "legalbot.local-owner-request-policy.v1"
LOCAL_SESSION_COOKIE_NAME = "legalbot_owner_session"
LOCAL_CSRF_HEADER_NAME = "x-legalbot-csrf"

_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_VERIFIED_LOCAL_OWNER_SECURITY_TOKEN = object()


class LocalRequestSecurityError(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _sealed_sha256(value: object) -> str:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class LocalSessionSecretObservation:
    identity_sha256: str
    parent_root_identity_sha256: str
    secret_path: Path = field(repr=False, compare=False)
    authorizing: Literal[False] = False


@dataclass(frozen=True, slots=True)
class LocalSessionTokens:
    session_token: str = field(repr=False)
    csrf_token: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class LiteralLoopbackRequestPolicy:
    port: int
    host: str
    origin: str
    session_cookie_name: str = LOCAL_SESSION_COOKIE_NAME
    csrf_header_name: str = LOCAL_CSRF_HEADER_NAME
    schema: str = LOCAL_OWNER_REQUEST_POLICY_SCHEMA

    @property
    def identity_sha256(self) -> str:
        return _sealed_sha256(
            {
                "schema": self.schema,
                "bind_host": "127.0.0.1",
                "port": self.port,
                "host": self.host,
                "origin": self.origin,
                "session_cookie_name": self.session_cookie_name,
                "csrf_header_name": self.csrf_header_name,
            }
        )


def literal_loopback_request_policy(port: int) -> LiteralLoopbackRequestPolicy:
    if not 1 <= port <= 65535:
        raise ValueError("local owner request port is invalid")
    return LiteralLoopbackRequestPolicy(
        port=port,
        host=f"127.0.0.1:{port}",
        origin=f"http://127.0.0.1:{port}",
    )


def configured_literal_loopback_request_policy(
    settings: Phase2LocalConfiguration,
) -> LiteralLoopbackRequestPolicy:
    """Bind preparation to the literal loopback server setting, not aliases."""

    if settings.bind_host != "127.0.0.1":
        raise Phase2PreparationStop("local_owner_bind_not_literal_loopback")
    return literal_loopback_request_policy(settings.port)


def _read_secret_path(
    path: Path,
    *,
    project_root: Path,
) -> tuple[LocalSessionSecretObservation, bytes]:
    secret_path = require_external_nonsynced_path_configuration(
        path,
        project_root=project_root,
    )
    parent = secret_path.parent
    try:
        parent_descriptor, parent_identity = open_exact_private_root_descriptor(
            parent,
            project_root=project_root,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        raise Phase2PreparationStop("local_session_secret_parent_not_private") from exc
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        os.close(parent_descriptor)
        raise Phase2PreparationStop("local_session_secret_secure_read_unavailable")
    member_descriptor = -1
    try:
        member_descriptor = os.open(
            secret_path.name,
            os.O_RDONLY | no_follow,
            dir_fd=parent_descriptor,
        )
        before = os.fstat(member_descriptor)
        path_before = os.stat(
            secret_path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )

        def stat_identity(value: os.stat_result) -> tuple[int, ...]:
            return (
                value.st_dev,
                value.st_ino,
                value.st_uid,
                value.st_mode,
                value.st_nlink,
                value.st_size,
                value.st_mtime_ns,
                value.st_ctime_ns,
            )

        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or not 32 <= before.st_size <= 64
            or stat_identity(before) != stat_identity(path_before)
        ):
            raise Phase2PreparationStop("local_session_secret_identity_invalid")
        secret = b""
        while len(secret) <= 64:
            block = os.read(member_descriptor, 65 - len(secret))
            if not block:
                break
            secret += block
        after = os.fstat(member_descriptor)
        path_after = os.stat(
            secret_path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            len(secret) != before.st_size
            or stat_identity(before) != stat_identity(after)
            or stat_identity(before) != stat_identity(path_after)
        ):
            raise Phase2PreparationStop("local_session_secret_changed_during_read")
        try:
            require_exact_private_root_descriptor_current(
                parent_descriptor,
                root=parent,
                project_root=project_root,
                expected_identity_sha256=parent_identity,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            raise Phase2PreparationStop("local_session_secret_parent_changed") from exc
    except OSError as exc:
        raise Phase2PreparationStop("local_session_secret_not_provisioned") from exc
    finally:
        if member_descriptor >= 0:
            os.close(member_descriptor)
        os.close(parent_descriptor)
    lexical_path_sha256 = hashlib.sha256(
        b"legalbot.local-session-secret-path.v1\x00" + os.fsencode(secret_path)
    ).hexdigest()
    identity = _sealed_sha256(
        {
            "schema": LOCAL_SESSION_SECRET_OBSERVATION_SCHEMA,
            "lexical_path_sha256": lexical_path_sha256,
            "parent_root_identity_sha256": parent_identity,
            "device": before.st_dev,
            "inode": before.st_ino,
            "owner_uid": before.st_uid,
            "mode": stat.S_IMODE(before.st_mode),
            "size": before.st_size,
            "content_sha256": hashlib.sha256(secret).hexdigest(),
        }
    )
    return (
        LocalSessionSecretObservation(
            identity_sha256=identity,
            parent_root_identity_sha256=parent_identity,
            secret_path=secret_path,
        ),
        secret,
    )


def observe_local_session_secret(
    settings: Phase2LocalConfiguration,
) -> LocalSessionSecretObservation:
    """Observe an existing secret file without exposing or retaining its bytes."""

    if settings.local_session_secret_path is None:
        raise Phase2PreparationStop("local_session_secret_not_provisioned")
    observation, _secret = _read_secret_path(
        settings.local_session_secret_path,
        project_root=settings.project_root,
    )
    return observation


def derive_local_session_tokens(secret: bytes, nonce: bytes) -> LocalSessionTokens:
    """Derive one session/CSRF pair from caller-supplied random bytes.

    This function does not generate a nonce or persist session state.
    """

    if not 32 <= len(secret) <= 64 or len(nonce) != 32:
        raise ValueError("local session token input is invalid")
    encoded_nonce = base64.urlsafe_b64encode(nonce).rstrip(b"=").decode("ascii")
    session_mac = hmac.new(
        secret,
        b"legalbot.owner-session.v1\x00" + nonce,
        hashlib.sha256,
    ).hexdigest()
    session_token = f"{encoded_nonce}.{session_mac}"
    csrf_token = hmac.new(
        secret,
        b"legalbot.owner-csrf.v1\x00" + session_token.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return LocalSessionTokens(session_token=session_token, csrf_token=csrf_token)


def _expected_tokens_for_session(
    secret: bytes,
    session_token: str,
) -> LocalSessionTokens | None:
    # A canonical token is a 43-character base64url nonce, one separator, and
    # a 64-character lowercase SHA-256 MAC.  Bound the input before decoding so
    # an unauthenticated request cannot force unbounded base64 work.
    if len(session_token) != 108:
        return None
    try:
        encoded_nonce, _supplied_mac = session_token.split(".", 1)
        if len(encoded_nonce) != 43 or len(_supplied_mac) != 64:
            return None
        padding = "=" * (-len(encoded_nonce) % 4)
        nonce = base64.b64decode(encoded_nonce + padding, altchars=b"-_", validate=True)
        return derive_local_session_tokens(secret, nonce)
    except (ValueError, UnicodeEncodeError):
        return None


def _session_token_valid(secret: bytes, session_token: str) -> bool:
    expected = _expected_tokens_for_session(secret, session_token)
    return expected is not None and hmac.compare_digest(session_token, expected.session_token)


def _tokens_valid(secret: bytes, session_token: str, csrf_token: str | None) -> bool:
    if csrf_token is None or len(csrf_token) != 64:
        return False
    expected = _expected_tokens_for_session(secret, session_token)
    return (
        expected is not None
        and hmac.compare_digest(session_token, expected.session_token)
        and hmac.compare_digest(csrf_token, expected.csrf_token)
    )


def validate_literal_loopback_request(
    *,
    policy: LiteralLoopbackRequestPolicy,
    secret: bytes,
    client_host: str,
    host_header: str,
    origin_header: str | None,
    fetch_site_header: str | None,
    method: str,
    session_token: str | None,
    csrf_token: str | None,
) -> None:
    """Apply the future exact owner-browser boundary to plain request values."""

    normalized_method = method.upper()
    if normalized_method not in _SAFE_METHODS | _MUTATING_METHODS:
        raise LocalRequestSecurityError("local_owner_request_method_refused")
    if client_host != "127.0.0.1":
        raise LocalRequestSecurityError("local_owner_client_not_literal_loopback")
    if host_header != policy.host:
        raise LocalRequestSecurityError("local_owner_host_header_invalid")
    if origin_header is not None and origin_header != policy.origin:
        raise LocalRequestSecurityError("local_owner_origin_invalid")
    fetch_site = (fetch_site_header or "").casefold()
    if fetch_site == "cross-site":
        raise LocalRequestSecurityError("local_owner_cross_site_request_refused")
    if session_token is None:
        raise LocalRequestSecurityError("local_owner_session_missing")
    if normalized_method in _MUTATING_METHODS:
        if origin_header != policy.origin or fetch_site != "same-origin":
            raise LocalRequestSecurityError("local_owner_mutation_origin_proof_missing")
        if not _tokens_valid(secret, session_token, csrf_token):
            raise LocalRequestSecurityError("local_owner_session_or_csrf_invalid")
    elif not _session_token_valid(secret, session_token):
        raise LocalRequestSecurityError("local_owner_session_invalid")


class VerifiedLocalOwnerSecurity(ImmutableOpaqueCapability):
    """Opaque secret-bearing capability reserved for trusted package replay."""

    __slots__ = ("_observation", "_policy", "_secret", "_token", "package_sha256")

    def __init__(
        self,
        *,
        observation: LocalSessionSecretObservation,
        policy: LiteralLoopbackRequestPolicy,
        secret: bytes,
        package_sha256: str,
        _token: object,
    ) -> None:
        if _token is not _VERIFIED_LOCAL_OWNER_SECURITY_TOKEN:
            raise TypeError("trusted local owner security verification required")
        self._observation = observation
        self._policy = policy
        self._secret = secret
        self.package_sha256 = package_sha256
        self._token = _token

    def __repr__(self) -> str:
        return "<VerifiedLocalOwnerSecurity>"


def require_local_owner_security(
    settings: Phase2LocalConfiguration,
) -> VerifiedLocalOwnerSecurity:
    """Fail after secret observation until signed-package verification exists."""

    observe_local_session_secret(settings)
    configured_literal_loopback_request_policy(settings)
    raise Phase2PreparationStop("trusted_phase2_owner_decision_package_verifier_missing")


def verify_local_owner_request(
    capability: object,
    *,
    client_host: str,
    host_header: str,
    origin_header: str | None,
    fetch_site_header: str | None,
    method: str,
    session_token: str | None,
    csrf_token: str | None,
) -> None:
    if (
        type(capability) is not VerifiedLocalOwnerSecurity
        or capability._token is not _VERIFIED_LOCAL_OWNER_SECURITY_TOKEN
    ):
        raise LocalRequestSecurityError("local_owner_security_authority_not_verified")
    validate_literal_loopback_request(
        policy=capability._policy,
        secret=capability._secret,
        client_host=client_host,
        host_header=host_header,
        origin_header=origin_header,
        fetch_site_header=fetch_site_header,
        method=method,
        session_token=session_token,
        csrf_token=csrf_token,
    )


__all__ = [
    "LOCAL_CSRF_HEADER_NAME",
    "LOCAL_OWNER_REQUEST_POLICY_SCHEMA",
    "LOCAL_SESSION_COOKIE_NAME",
    "LOCAL_SESSION_SECRET_OBSERVATION_SCHEMA",
    "LiteralLoopbackRequestPolicy",
    "LocalRequestSecurityError",
    "LocalSessionSecretObservation",
    "LocalSessionTokens",
    "VerifiedLocalOwnerSecurity",
    "configured_literal_loopback_request_policy",
    "derive_local_session_tokens",
    "literal_loopback_request_policy",
    "observe_local_session_secret",
    "require_local_owner_security",
    "validate_literal_loopback_request",
    "verify_local_owner_request",
]
