from __future__ import annotations

from collections.abc import Sequence
from datetime import timedelta
from pathlib import Path
from typing import Any

from app.config import Settings
from app.evaluation.ge_coverage_authorization import (
    VerifiedGECoverageAuthorization,
    build_ge_coverage_decision_request,
    ge_coverage_decision_binding,
    ge_coverage_decision_id,
    load_verified_ge_coverage_authorization,
)
from app.evaluation.ge_improvement_loop import (
    GECoverageCell,
    build_coverage_cell_manifest,
    build_coverage_topology_predecision,
)
from app.evaluation.ge_visible_harness import VisibleGEPack
from app.governance.owner_stop import OwnerDecisionStore, seal_owner_decision_resolution


def authorize_test_coverage(
    *,
    root: Path,
    pack: VisibleGEPack,
    manifest_id: str,
    cells: Sequence[GECoverageCell],
    proposed_at: Any,
) -> tuple[
    dict[str, Any], VerifiedGECoverageAuthorization, dict[str, Any]
]:
    """Issue a test-only proof through the real stored-decision replay path."""

    predecision = build_coverage_topology_predecision(
        pack=pack,
        manifest_id=manifest_id,
        cells=cells,
        proposed_at=proposed_at,
    )
    binding = ge_coverage_decision_binding(predecision)
    request = build_ge_coverage_decision_request(
        binding=binding,
        created_at=proposed_at + timedelta(seconds=1),
    )
    settings = Settings(project_root=root / str(predecision["content_sha256"])[:24])
    settings.evaluation_dir.mkdir(parents=True, mode=0o700)
    settings.evaluation_dir.chmod(0o700)
    store = OwnerDecisionStore(settings.owner_decision_root)
    store.write_request(request)
    resolution = seal_owner_decision_resolution(
        request=request,
        selected_option_id="approve-exact-ge-coverage-topology",
        owner_ref=f"owner:{'c' * 64}",
        decided_at=proposed_at + timedelta(seconds=2),
    )
    store.write_resolution(resolution)
    authorization = load_verified_ge_coverage_authorization(
        settings,
        predecision=predecision,
        decision_id=ge_coverage_decision_id(binding),
        decision_content_sha256=resolution.seal_sha256,
    )
    manifest = build_coverage_cell_manifest(
        predecision=predecision,
        authorization=authorization,
    )
    return predecision, authorization, manifest
