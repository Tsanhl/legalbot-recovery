"""Extracted FastAPI routers. The main module remains the public façade."""

from .evaluation import router as evaluation_router
from .feedback import router as feedback_router
from .incidents import router as incidents_router

__all__ = ["evaluation_router", "feedback_router", "incidents_router"]
