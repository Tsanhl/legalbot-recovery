from __future__ import annotations

from app.evaluation.ge_reconstructed_edit_rereview import FORBIDDEN


def test_changed_answer_forbidden_markers_remain_lowercase() -> None:
    assert FORBIDDEN
    assert all(marker == marker.casefold() for marker in FORBIDDEN)
