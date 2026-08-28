from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from ..crypto import LocalCipher
from ..privacy import assert_review_payload_safe, scrub_pii
from ..types import KnowledgeGap


class GapQueue:
    def __init__(self, root: Path, cipher: LocalCipher) -> None:
        self.root = root
        self.cipher = cipher
        self.root.mkdir(parents=True, exist_ok=True)

    def persist(self, gap: KnowledgeGap) -> Path:
        payload = gap.model_dump(mode="json")
        payload["missing_proposition"] = scrub_pii(payload["missing_proposition"])
        payload["searches_attempted"] = [
            {str(key): scrub_pii(str(value)) for key, value in item.items()}
            for item in payload["searches_attempted"]
        ]
        payload["rejection_reasons"] = [scrub_pii(item) for item in payload["rejection_reasons"]]
        serialised = json.dumps(payload, indent=2, sort_keys=True)
        assert_review_payload_safe(serialised)
        descriptor, temporary = tempfile.mkstemp(prefix=f".{gap.id}-", suffix=".enc", dir=self.root)
        try:
            encrypted = self.cipher.encrypt_text(serialised)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(encrypted)
                handle.flush()
                os.fsync(handle.fileno())
            destination = self.root / f"{gap.id}.enc"
            os.replace(temporary, destination)
            return destination
        except Exception:
            Path(temporary).unlink(missing_ok=True)
            raise

    def migrate_legacy_files(self) -> list[tuple[Path, Path]]:
        """Replace legacy plaintext gap records with encrypted equivalents."""

        migrated: list[tuple[Path, Path]] = []
        for legacy in sorted(self.root.glob("*.json")):
            serialised = legacy.read_text(encoding="utf-8")
            assert_review_payload_safe(serialised)
            destination = legacy.with_suffix(".enc")
            if destination.exists():
                raise FileExistsError(f"encrypted gap record already exists: {destination.name}")
            descriptor, temporary = tempfile.mkstemp(
                prefix=f".{legacy.stem}-", suffix=".enc", dir=self.root
            )
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(self.cipher.encrypt_text(serialised))
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, destination)
                legacy.unlink()
            except Exception:
                Path(temporary).unlink(missing_ok=True)
                raise
            migrated.append((legacy, destination))
        return migrated
