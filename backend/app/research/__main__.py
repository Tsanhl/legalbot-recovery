"""Operator entry point for the connected research canary/worker."""

from __future__ import annotations

import asyncio

from ..config import settings
from ..services import build_services
from .jobs import run_research_worker


async def main() -> None:
    services = build_services(settings)
    try:
        await run_research_worker(settings, services.database, services.cipher, once=False)
    finally:
        services.database.close()


if __name__ == "__main__":
    asyncio.run(main())
