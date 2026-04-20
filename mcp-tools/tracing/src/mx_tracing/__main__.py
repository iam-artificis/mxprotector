"""Entry point for ``py -3 -m mx_tracing``.

Phase 0 wires only ``--version`` and ``--help``. The MCP stdio server
itself arrives in Phase 2.
"""

from __future__ import annotations

import argparse
import sys

from mx_tracing import __version__


def _build_parser() -> argparse.ArgumentParser:
    """Build the Phase 0 argument parser (``--version`` / ``--help``)."""
    parser = argparse.ArgumentParser(
        prog="mx-tracing",
        description="Runtime tracer MCP server for MxProtector (Phase 0 scaffold).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"mx-tracing MCP server v{__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Parse CLI args and return the process exit code."""
    _build_parser().parse_args(argv)
    print(f"mx-tracing MCP server v{__version__} (Phase 0 scaffold)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
