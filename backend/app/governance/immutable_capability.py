"""Write-once base for opaque in-process authorization capabilities."""

from __future__ import annotations

from typing import NoReturn


class ImmutableOpaqueCapability:
    """Allow slot initialization once and reject later mutation or deletion.

    Capability consumers still require exact concrete types and private minting
    tokens.  This base closes the separate risk that a legitimately issued
    capability could be retargeted through ordinary attribute assignment.
    """

    __slots__ = ()

    def __setattr__(self, name: str, value: object) -> None:
        if hasattr(self, name):
            raise AttributeError("opaque capability is immutable")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> NoReturn:
        del name
        raise AttributeError("opaque capability is immutable")


__all__ = ["ImmutableOpaqueCapability"]
