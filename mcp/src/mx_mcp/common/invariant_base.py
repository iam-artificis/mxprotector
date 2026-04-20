"""IInvariant ABC + decorator-based registry (OCP).

Every protection invariant is one file under ``mx_mcp.invariants``.
An invariant declares the probes it needs (possibly empty for static-
only checks) and implements ``evaluate(ctx)``.

The aggregator tool (``verify_protection_invariants``) computes the
union of ``probes`` across selected invariants, spawns the binary
exactly once under Frida, then dispatches the collected event stream
plus the sidecar to every ``evaluate``. Static-only invariants
(probes==[]) skip the spawn entirely if no other invariant needs it.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, ClassVar

from mx_mcp.common.events import Event
from mx_mcp.common.sidecar import Sidecar


class VerdictStatus(str, Enum):
    """Tri-state invariant outcome.

    ``pass`` — evidence confirmed the invariant.
    ``fail`` — evidence contradicts the invariant (regression).
    ``skip`` — the invariant does not apply (e.g. pass gated off,
               required section absent from the sidecar).
    """

    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"


@dataclass(frozen=True, slots=True)
class InvariantContext:
    events: list[Event]
    sidecar: Sidecar
    binary_path: Path


@dataclass(frozen=True, slots=True)
class InvariantVerdict:
    name: str
    status: VerdictStatus
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def is_failure(self) -> bool:
        return self.status is VerdictStatus.FAIL


class IInvariant(ABC):
    """Single protection invariant.

    Subclasses declare class-level metadata (``name``,
    ``description``, ``probes``) and implement ``evaluate``.
    """

    name: ClassVar[str]
    description: ClassVar[str]
    probes: ClassVar[list[str]]  # empty = static-only

    @abstractmethod
    def evaluate(self, ctx: InvariantContext) -> InvariantVerdict:
        ...


_REGISTRY: list[type[IInvariant]] = []


def register_invariant(cls: type[IInvariant]) -> type[IInvariant]:
    """Class decorator: register an invariant at import time.

    Validates the contract (required class attrs, unique name).
    """
    if not issubclass(cls, IInvariant):
        raise TypeError(f"{cls.__name__} must subclass IInvariant")

    for required in ("name", "description", "probes"):
        if not hasattr(cls, required):
            raise TypeError(
                f"{cls.__name__} missing required class attr '{required}'"
            )

    for existing in _REGISTRY:
        if existing.name == cls.name:
            raise ValueError(
                f"invariant name collision on '{cls.name}': "
                f"{existing.__module__}.{existing.__name__} vs "
                f"{cls.__module__}.{cls.__name__}"
            )

    _REGISTRY.append(cls)
    return cls


def all_invariants() -> list[type[IInvariant]]:
    """Return registered invariant classes in registration order."""
    return list(_REGISTRY)
