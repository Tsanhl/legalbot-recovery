from __future__ import annotations

import base64
import os
import platform
import subprocess
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken

SERVICE = "LegalBot-New"
ACCOUNT = "local-content-encryption"


class KeyUnavailableError(RuntimeError):
    pass


def _read_keychain() -> bytes | None:
    if platform.system() != "Darwin":
        return None
    result = subprocess.run(
        ["security", "find-generic-password", "-s", SERVICE, "-a", ACCOUNT, "-w"],
        capture_output=True,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip().encode("ascii")


def _write_keychain(key: bytes) -> None:
    result = subprocess.run(
        [
            "security",
            "add-generic-password",
            "-U",
            "-s",
            SERVICE,
            "-a",
            ACCOUNT,
            "-w",
            key.decode("ascii"),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        raise KeyUnavailableError("Unable to store the local encryption key in macOS Keychain")


def load_or_create_key(*, create: bool = True) -> bytes:
    supplied = os.getenv("LEGALBOT_ENCRYPTION_KEY_B64")
    if supplied:
        try:
            decoded = base64.urlsafe_b64decode(supplied.encode("ascii"))
            if len(decoded) == 32:
                return base64.urlsafe_b64encode(decoded)
        except (ValueError, UnicodeEncodeError):
            pass
        try:
            Fernet(supplied.encode("ascii"))
            return supplied.encode("ascii")
        except (ValueError, UnicodeEncodeError) as exc:
            raise KeyUnavailableError("LEGALBOT_ENCRYPTION_KEY_B64 is not a Fernet key") from exc

    key = _read_keychain()
    if key:
        return key
    if not create:
        raise KeyUnavailableError("No local encryption key is available")
    if platform.system() != "Darwin":
        raise KeyUnavailableError(
            "Set LEGALBOT_ENCRYPTION_KEY_B64 outside macOS; keys are never written to project files"
        )
    key = Fernet.generate_key()
    _write_keychain(key)
    return key


@dataclass(slots=True)
class LocalCipher:
    _fernet: Fernet

    @classmethod
    def from_local_key(cls, *, create: bool = True) -> LocalCipher:
        return cls(Fernet(load_or_create_key(create=create)))

    def encrypt_text(self, value: str) -> bytes:
        return self._fernet.encrypt(value.encode("utf-8"))

    def decrypt_text(self, value: bytes) -> str:
        try:
            return self._fernet.decrypt(value).decode("utf-8")
        except InvalidToken as exc:
            raise KeyUnavailableError("Encrypted local content could not be decrypted") from exc

    def encrypt_bytes(self, value: bytes) -> bytes:
        """Encrypt an opaque local artifact without converting it to text."""

        return self._fernet.encrypt(value)

    def decrypt_bytes(self, value: bytes) -> bytes:
        """Decrypt an opaque local artifact and fail closed on key/ciphertext drift."""

        try:
            return self._fernet.decrypt(value)
        except InvalidToken as exc:
            raise KeyUnavailableError("Encrypted local content could not be decrypted") from exc
