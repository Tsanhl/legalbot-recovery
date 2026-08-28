"""Shared API request helpers."""

from __future__ import annotations

from typing import Any, cast

from fastapi import Request

from ..services import Services


def services(request: Request) -> Services:
    return cast(Services, request.app.state.services)


def row(value: Any) -> dict[str, Any]:
    keys: list[str] = value.keys()
    return {key: value[key] for key in keys}
