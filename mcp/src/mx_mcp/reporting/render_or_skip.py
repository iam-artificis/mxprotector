"""Fail-closed wrapper around ``IChartRenderer.render``.

The two MCP tools that expose an ``output_png`` argument delegate to
this helper so they neither duplicate the try-backend-then-render
dance nor let an exception from matplotlib propagate out of the tool
response. Contract:

* ``output_path is None`` → caller did not request a chart; skip
  quietly (``(None, None)``).
* Backend unavailable → return a readable install hint in the note
  slot and leave the path ``None``.
* Unexpected exception during rendering → caught and surfaced as a
  note; zero chance of blowing up the tool's pydantic response.

SOLID note — SRP: this helper only dispatches. The concrete renderer
owns the "how to draw it" decision, the tool owns the "what to pass
to it" decision.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel


_LOG = logging.getLogger(__name__)


class _Renderer(Protocol):
    """Structural subtype of ``IChartRenderer`` — lets this helper
    accept any renderer without importing the ABC module and risking
    an import cycle."""

    def is_available(self) -> bool: ...

    def render(self, data: BaseModel, output_path: Path) -> Path: ...


def try_render_png(
    renderer: _Renderer,
    data: BaseModel,
    output_path: str | None,
) -> tuple[str | None, str | None]:
    """Attempt to render ``data`` to ``output_path``.

    Returns a ``(resolved_path, note)`` pair. Exactly one of the two
    is ``None`` in every real case:

    +----------------------------+----------------+-------------------+
    | Situation                  | resolved_path  | note              |
    +============================+================+===================+
    | ``output_path is None``    | ``None``       | ``None``          |
    | backend unavailable        | ``None``       | install hint      |
    | rendering raised           | ``None``       | error preview     |
    | success                    | absolute path  | ``None``          |
    +----------------------------+----------------+-------------------+
    """
    if output_path is None:
        return None, None

    if not renderer.is_available():
        return None, (
            "matplotlib not installed — pip install -e \".[viz]\" in mcp/"
        )

    try:
        resolved = renderer.render(data, Path(output_path))
    except Exception as e:  # noqa: BLE001 — fail-closed presentation layer
        _LOG.exception("chart render failed")
        return None, f"chart render failed: {type(e).__name__}: {e}"

    return str(resolved), None
