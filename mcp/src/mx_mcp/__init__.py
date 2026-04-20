"""MxProtector MCP — Defense Measurement Suite.

Multi-backend MCP server that measures MxProtector's protection strength
against state-of-the-art reversing tools. Architecture and phase plan
live in ``MCP.md`` at the repo root; post-MVP backlog in ``FUTURE.md``.

The top-level package exposes only ``__version__``. Backend subpackages
(``dynamic``, ``emulation``, ``symbolic``, ``static``, ``deobfuscation``,
``unpacking``, ``anti_analysis``, ``diffing``) are loaded lazily by
``server.py`` so that a missing optional dependency (e.g. ``unicorn``)
fails only the affected tool, not the whole server.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
