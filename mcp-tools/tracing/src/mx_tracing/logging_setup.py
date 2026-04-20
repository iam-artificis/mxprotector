"""Stdlib logging configuration for the MCP server.

Stdout is owned by the MCP stdio protocol — every log line must go to
stderr. ``MX_TRACING_DEBUG=1`` raises the level to ``DEBUG``.
"""

from __future__ import annotations

import logging
import os
import sys


_FMT = "%(asctime)s %(name)s %(levelname)s %(message)s"

_configured = False


def configure_logging() -> None:
    """Configure root logger once per process."""
    global _configured
    if _configured:
        return
    level = logging.DEBUG if os.environ.get("MX_TRACING_DEBUG") == "1" else logging.INFO
    logging.basicConfig(level=level, format=_FMT, stream=sys.stderr)
    _configured = True
