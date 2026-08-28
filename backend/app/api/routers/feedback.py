"""Answer feedback routes extracted from the API façade."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request, status

from ...orchestration.refinements import RefinementService
from ...types import AnswerFeedbackRequest
from ..deps import services

router = APIRouter()


@router.post("/api/v1/answers/{answer_id}/feedback", status_code=status.HTTP_201_CREATED)
async def create_answer_feedback(
    answer_id: str, payload: AnswerFeedbackRequest, request: Request
) -> dict[str, Any]:
    """Record encrypted, answer-owned feedback without mutating runtime policy."""

    svc = services(request)
    try:
        result = RefinementService(svc.database, svc.cipher).submit_answer_feedback(
            answer_id, payload
        )
    except KeyError:
        raise HTTPException(404, "Released answer not found") from None
    except PermissionError:
        raise HTTPException(409, "Feedback is accepted only for released answers") from None
    except ValueError:
        raise HTTPException(422, "Feedback target is not part of this answer") from None
    except RuntimeError:
        raise HTTPException(409, "Feedback idempotency key was reused with other content") from None
    return {
        "refinement_id": result.refinement_id,
        "status": result.status,
        "priority": result.priority,
        "duplicate": result.duplicate,
    }
