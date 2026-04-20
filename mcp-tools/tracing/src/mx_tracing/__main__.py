"""Entry point for ``py -3 -m mx_tracing``.

Phase 2: default behavior (no args) is to run the MCP stdio server.
Phase 0 smoke flags ``--version`` / ``--help`` are preserved for
diagnostic use.
"""

from __future__ import annotations

import argparse
import sys

from mx_tracing import __version__


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mx-tracing",
        description="Runtime tracer MCP server for MxProtector.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"mx-tracing MCP server v{__version__}",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.add_parser(
        "serve",
        help="Run the MCP stdio server (default when no command is given).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command in (None, "serve"):
        from mx_tracing.server import run
        return run()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
