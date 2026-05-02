"""IDetector ABC + registry for anti-analysis tool detection.

Every detector is one file under :mod:`mx_mcp.anti_analysis.detectors`.
A detector targets one analysis tool family (x64dbg, Frida, …) and
answers: does the protected binary ship primitives that defend
against this family?

Adding a new detector = new file + one import line in
``detectors/__init__.py``. Zero edits to existing detectors, the
benchmark, or the registry — same OCP shape as IBenchmark / IGate.

## Detection contract

:meth:`IDetector.detect` is async to leave room for future dynamic
detectors that drive an external subprocess. Current static
detectors run their work synchronously and return immediately.

A detector that requires an external tool not available on the host
returns a :class:`DetectionResult` with ``skipped=True`` and a
``skip_reason``. The aggregator excludes skipped results from the
coverage denominator so the metric is not deflated by missing
tooling.

A detector crash (raised exception bubbling out of ``detect``) is
treated as ``detected=False, error=<repr>`` by the benchmark, never
as a fail-closed PASS — same fail-closed posture as the rest of the
MCP stack.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, ClassVar

from pydantic import BaseModel, Field


_LOG = logging.getLogger(__name__)


# ============================================================================
# Result model
# ============================================================================


class DetectionResult(BaseModel):
    """Per-detector outcome for one protected binary.

    ``detected`` collapses the actual question into the bool the
    coverage aggregator needs. ``skipped`` separates "tool/backend
    unavailable" from "tool ran but found nothing"; the former
    leaves the denominator alone, the latter shrinks the rate.

    ``evidence`` carries arbitrary diagnostic data — typically the
    list of API-name patterns / opcodes the static detector matched
    on, or the per-event trace summary a future dynamic detector
    would emit.
    """

    tool: str = Field(description="Detector name, matches IDetector.name.")
    detected: bool
    skipped: bool = False
    skip_reason: str | None = None
    error: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)

    @property
    def informative(self) -> bool:
        """True iff this result contributes to the coverage rate.

        ``skipped`` excludes the detector from both numerator and
        denominator; everything else (including ``detected=False``
        and errored runs) participates.
        """
        return not self.skipped


# ============================================================================
# IDetector ABC
# ============================================================================


class IDetector(ABC):
    """Single anti-analysis tool detector.

    Subclasses declare class-level metadata (``name``,
    ``description``, ``targets`` — a friendly tool family list for
    evidence) and implement :meth:`detect`.

    The detector is constructed with no args by the benchmark; tests
    inject a stub by monkeypatching the class methods.
    """

    name: ClassVar[str]
    description: ClassVar[str]
    targets: ClassVar[tuple[str, ...]]

    @abstractmethod
    async def detect(self, binary_path: Path) -> DetectionResult:
        """Run the detection step against ``binary_path``.

        Implementations MUST return a :class:`DetectionResult` and
        SHOULD never raise — internal failures fold into
        ``DetectionResult.error``. The benchmark contains a
        defensive try/except as a last-resort guard.
        """


# ============================================================================
# Registry
# ============================================================================


_REGISTRY: list[type[IDetector]] = []


def register_detector(cls: type[IDetector]) -> type[IDetector]:
    """Class decorator: register a detector at import time.

    Validates the contract (required class attrs, unique name) so
    misconfigured detectors fail fast at module load rather than on
    first call.
    """
    if not issubclass(cls, IDetector):
        raise TypeError(f"{cls.__name__} must subclass IDetector")

    for required in ("name", "description", "targets"):
        if not hasattr(cls, required):
            raise TypeError(
                f"{cls.__name__} missing required class attr '{required}'"
            )

    for existing in _REGISTRY:
        if existing.name == cls.name:
            raise ValueError(
                f"detector name collision on '{cls.name}': "
                f"{existing.__module__}.{existing.__name__} vs "
                f"{cls.__module__}.{cls.__name__}"
            )

    _LOG.debug("registered detector: %s (targets=%s)", cls.name, cls.targets)
    _REGISTRY.append(cls)
    return cls


def all_detectors() -> list[type[IDetector]]:
    """Return registered detector classes in registration order."""
    return list(_REGISTRY)


__all__ = [
    "DetectionResult",
    "IDetector",
    "all_detectors",
    "register_detector",
]
