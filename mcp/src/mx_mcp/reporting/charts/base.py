"""``IChartRenderer`` ABC + decorator-based registry (OCP).

Charts are keyed by a class-level ``name`` so tools can look up a
renderer by identifier (or hold a concrete reference for MVP
simplicity — see ``tools/measure_defense.py``). Every renderer binds
its input type via ``input_schema`` so serialisation paths can be
validated on the way in.

Adding a new chart type = new file + ``@register_chart``. No edits
to existing code.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import ClassVar, Generic, TypeVar

from pydantic import BaseModel


_LOG = logging.getLogger(__name__)


InputT = TypeVar("InputT", bound=BaseModel)


class IChartRenderer(ABC, Generic[InputT]):
    """Contract for a single PNG chart renderer."""

    name: ClassVar[str]
    description: ClassVar[str]
    input_schema: ClassVar[type[BaseModel]]

    @abstractmethod
    def is_available(self) -> bool:
        """True when the backend (matplotlib) can be imported."""

    @abstractmethod
    def render(self, data: InputT, output_path: Path) -> Path:
        """Render ``data`` to ``output_path`` (PNG). Returns the path
        that was actually written (normalised / absolute).

        Implementations may raise:
            RuntimeError: backend not available at call time.
            ValueError: input is malformed for this renderer.
            OSError: filesystem write failed.
        """


_REGISTRY: list[type[IChartRenderer]] = []


def register_chart(cls: type[IChartRenderer]) -> type[IChartRenderer]:
    """Class decorator: register a chart renderer at import time.

    Same contract as ``register_tool`` / ``register_benchmark`` —
    validates required class attrs and rejects name collisions so
    misconfigured renderers fail fast at module load.
    """
    if not issubclass(cls, IChartRenderer):
        raise TypeError(f"{cls.__name__} must subclass IChartRenderer")
    for required in ("name", "description", "input_schema"):
        if not hasattr(cls, required):
            raise TypeError(
                f"{cls.__name__} missing required class attr '{required}'"
            )
    for existing in _REGISTRY:
        if existing.name == cls.name:
            raise ValueError(
                f"chart renderer name collision on '{cls.name}': "
                f"{existing.__module__}.{existing.__name__} vs "
                f"{cls.__module__}.{cls.__name__}"
            )
    _LOG.debug("registered chart renderer: %s", cls.name)
    _REGISTRY.append(cls)
    return cls


def all_chart_renderers() -> list[type[IChartRenderer]]:
    return list(_REGISTRY)
