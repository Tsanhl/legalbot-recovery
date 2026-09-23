"""Private executed-licence gate. Approval correspondence grants no runtime rights."""

from __future__ import annotations

import hashlib
import json
from datetime import date
from pathlib import Path
from typing import Literal

Purpose = Literal["capture", "vector_index", "external_model", "training"]


def permits_find_case_law(private_root: Path, purpose: Purpose, *, today: date) -> bool:
    try:
        record_path = private_root / "find-case-law-permissions.json"
        if record_path.is_symlink() or not record_path.is_file():
            return False
        record = json.loads(record_path.read_bytes())
        relative = Path(record["executed_document"])
        document = private_root / relative
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or not document.resolve().is_relative_to(private_root.resolve())
            or document.is_symlink()
        ):
            return False
        if (
            record.get("schema") != "legalbot.executed-fcl-permissions.v1"
            or record.get("executed") is not True
            or record.get("terms_reviewed") is not True
            or date.fromisoformat(record["effective_from"]) > today
            or (record.get("effective_to") and date.fromisoformat(record["effective_to"]) < today)
            or record.get("revoked") is not False
            or record.get("permissions", {}).get(purpose) is not True
        ):
            return False
        # Each purpose requires a reviewed term locator, not a blanket flag.
        if not str(record.get("term_locators", {}).get(purpose, "")).strip():
            return False
        return (
            hashlib.sha256(document.read_bytes()).hexdigest() == record["executed_document_sha256"]
        )
    except (ValueError, KeyError, OSError, TypeError):
        return False
