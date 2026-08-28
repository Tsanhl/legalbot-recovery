from __future__ import annotations

from hypothesis import given
from hypothesis import settings as hypothesis_settings
from hypothesis import strategies as st

from app.evaluation.live_suite_repair_span import (
    identity_tuple,
    repair_span_id_v2,
    repair_span_identity_v2,
)

_SAFE = st.text(
    min_size=1, max_size=40, alphabet=st.characters(min_codepoint=32, max_codepoint=126)
)


@given(
    parent=_SAFE,
    source=_SAFE,
    authority=_SAFE,
    snapshot=st.from_regex(r"[0-9a-f]{64}", fullmatch=True),
    locator=_SAFE,
    role=_SAFE,
    text=_SAFE,
    manifest=st.from_regex(r"[0-9a-f]{64}", fullmatch=True),
    stable=_SAFE,
    source_type=_SAFE,
    jurisdiction=_SAFE,
)
@hypothesis_settings(max_examples=40, deadline=None)
def test_repair_span_v2_id_is_deterministic(
    parent: str,
    source: str,
    authority: str,
    snapshot: str,
    locator: str,
    role: str,
    text: str,
    manifest: str,
    stable: str,
    source_type: str,
    jurisdiction: str,
) -> None:
    identity = repair_span_identity_v2(
        parent_chunk_id=parent,
        source_version_id=source,
        legal_authority_id=authority,
        official_snapshot_sha256=snapshot,
        required_sublocator=locator,
        role=role,
        markdown_text=text,
        derivation_manifest_sha256=manifest,
        stable_source_id=stable,
        source_type=source_type,
        jurisdiction=jurisdiction,
        legal_locator=locator,
    )
    assert identity == identity_tuple(
        parent_chunk_id=parent,
        source_version_id=source,
        legal_authority_id=authority,
        official_snapshot_sha256=snapshot,
        required_sublocator=locator,
        role=role,
        markdown_text=text,
        derivation_manifest_sha256=manifest,
        stable_source_id=stable,
        source_type=source_type,
        jurisdiction=jurisdiction,
        legal_locator=locator,
    )
    first = repair_span_id_v2(identity=identity)
    second = repair_span_id_v2(identity=identity)
    assert first == second
    assert first.startswith("repair-span-")
    other = repair_span_id_v2(identity=(*identity[:-1], f"x{locator}"))
    assert other != first
