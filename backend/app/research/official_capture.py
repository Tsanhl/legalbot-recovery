"""Private full-text capture, never a claim that fetched material is verified law.

The existing reviewed-generation pipeline must approve text, applicability and
rights before reuse. HTML paragraph offsets are capture locators, not legal
pinpoints. Contents pages and search results cannot qualify an answer.
"""

from __future__ import annotations

import hashlib
import io
import json
from dataclasses import replace
from datetime import UTC, date, datetime
from typing import Any

from lxml import etree, html

from ..crypto import LocalCipher
from ..privacy import prompt_injection_hits
from .adapters import FetchPlan
from .licence_permissions import permits_find_case_law
from .source_registry import ContentMode


def extract_segments(content: bytes, media: str) -> list[dict[str, str]]:
    if "pdf" in media:
        from pypdf import PdfReader

        pages = PdfReader(io.BytesIO(content)).pages
        if len(pages) > 500:
            raise ValueError("official_pdf_page_bound_exceeded")
        return [
            {"capture_locator": f"page {i}", "text": page.extract_text() or ""}
            for i, page in enumerate(pages, 1)
        ]
    if "xml" in media and "html" not in media:
        if b"<!DOCTYPE" in content.upper() or b"<!ENTITY" in content.upper():
            raise ValueError("official_xml_unsafe")
        root = etree.fromstring(content, etree.XMLParser(resolve_entities=False, no_network=True))
        elements = root.xpath("//*[local-name()='p' or local-name()='P1' or local-name()='P2']")
    else:
        root = html.fromstring(content)
        for item in root.xpath("//script|//style|//nav|//header|//footer|//form"):
            item.drop_tree()
        containers = root.xpath("//main|//article") or [root]
        elements = [
            e for container in containers for e in container.xpath(".//p|.//h1|.//h2|.//h3|.//li")
        ]
    return [
        {
            "capture_locator": str(e.get("id") or f"capture-paragraph-{i}"),
            "text": " ".join(e.itertext()).strip(),
        }
        for i, e in enumerate(elements, 1)
        if " ".join(e.itertext()).strip()
    ]


async def capture_official_candidate(
    *, settings: Any, fetcher: Any, policy: Any, url: str, jurisdiction: str, as_of_date: date
) -> dict[str, Any]:
    # FCL permission checks are purpose-specific and are rechecked at the use
    # boundary. The capture path grants neither embeddings nor model processing.
    if policy.source_id == "find_case_law":
        if not permits_find_case_law(
            settings.vault_dir / "licences", "capture", today=date.today()
        ):
            raise PermissionError("find_case_law_executed_capture_permission_missing")
        policy = replace(policy, content_mode=ContentMode.FULL_TEXT)
    elif policy.content_mode is not ContentMode.FULL_TEXT:
        raise PermissionError("official_item_rights_review_required")
    response = await fetcher.fetch(
        FetchPlan(
            policy.source_id, url, ContentMode.FULL_TEXT, {"User-Agent": "LegalBotResearch/1.0"}
        ),
        policy,
    )
    segments = extract_segments(response.content, response.headers.get("content-type", ""))
    digest = hashlib.sha256(response.content).hexdigest()
    record = {
        "schema": "legalbot.official-capture.v1",
        "source_id": policy.source_id,
        "requested_url": url,
        "resolved_url": response.url,
        "content_sha256": digest,
        "captured_at": datetime.now(UTC).isoformat(),
        "requested_jurisdiction": jurisdiction,
        "requested_as_of_date": as_of_date.isoformat(),
        "segments": segments,
        "prompt_injection_detected": bool(
            prompt_injection_hits("\n".join(s["text"] for s in segments))
        ),
        "review_state": "PENDING_SOURCE_AND_CURRENTNESS_REVIEW",
        "legal_pinpoints_verified": False,
        "model_processing_permitted": False,
        "vector_index_permitted": False,
        "training_permitted": False,
        "shared_index_updated": False,
        "admitted": False,
    }
    directory = settings.vault_dir / "official-captures"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    cipher = LocalCipher.from_local_key(create=False)
    # Full bytes and parsed text are retained separately; no snippets stand in
    # for actual captured text. Repeated fetches retain a new timestamped receipt.
    for name, value in (
        (digest + ".body.enc", response.content),
        (
            hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()
            + ".receipt.enc",
            json.dumps(record, sort_keys=True).encode(),
        ),
    ):
        path = directory / name
        if not path.exists():
            with path.open("xb") as handle:
                handle.write(cipher.encrypt_bytes(value))
            path.chmod(0o600)
    return {
        k: v for k, v in record.items() if k not in {"segments", "requested_url", "resolved_url"}
    }
