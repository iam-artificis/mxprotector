"""Entry point for ``py -3 -m mx_mcp``.

Default behavior (no args) is to run the MCP stdio server. Smoke flags
``--version`` / ``--help`` are preserved for diagnostic use.
"""

from __future__ import annotations

import argparse
import sys

from mx_mcp import __version__


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mx-mcp",
        description=(
            "MxProtector MCP defense measurement server. "
            "See MCP.md for architecture."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"mx-mcp server v{__version__}",
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
        from mx_mcp.server import run
        return run()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
