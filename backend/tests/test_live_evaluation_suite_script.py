from __future__ import annotations

from argparse import Namespace

import pytest
from scripts.live_evaluation_suite import (
    PROJECT_ROOT,
    _require_current_runtime_identities,
)

from app.assessment.guidance_bundle import OWNER_ASSESSMENT_BUNDLE
from app.config import Settings
from app.orchestration.classifier import CLASSIFIER_VERSION
from app.orchestration.routing import ROUTER_VERSION
from app.quality.policy import POLICY_SHA256
from app.runtime_adapters import PROMPT_VERSION


def _current_arguments(**changes: str) -> Namespace:
    values = {
        "model_version": Settings(project_root=PROJECT_ROOT).model_id,
        "prompt_version": PROMPT_VERSION,
        "router_version": ROUTER_VERSION,
        "classifier_version": CLASSIFIER_VERSION,
        "policy_sha256": POLICY_SHA256,
        "assessment_rules_sha256": OWNER_ASSESSMENT_BUNDLE.sha256,
    }
    values.update(changes)
    return Namespace(**values)


def test_create_run_accepts_only_exact_current_runtime_identities() -> None:
    _require_current_runtime_identities(_current_arguments())


@pytest.mark.parametrize(
    "field",
    (
        "model_version",
        "prompt_version",
        "router_version",
        "classifier_version",
        "policy_sha256",
        "assessment_rules_sha256",
    ),
)
def test_create_run_rejects_each_stale_runtime_identity(field: str) -> None:
    with pytest.raises(SystemExit, match=field):
        _require_current_runtime_identities(_current_arguments(**{field: "stale"}))
