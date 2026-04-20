"""MCP stdio server entry point.

The server introspects the tool registry (``tools.base.all_tools``)
and wires each entry into MCP's ``list_tools`` / ``call_tool`` hooks.
Discovery happens via ``import mx_tracing.tools`` — each tool file
registers itself at import time through ``@register_tool``.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import mcp.server.stdio
import mcp.types as mcp_types
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions
from pydantic import ValidationError

from mx_tracing import __version__
from mx_tracing import tools as _tools_pkg  # noqa: F401  — triggers @register_tool
from mx_tracing.logging_setup import configure_logging
from mx_tracing.session import Session
from mx_tracing.tools.base import all_tools


_LOG = logging.getLogger(__name__)


def _build_server(session: Session) -> Server:
    server: Server = Server("mx-tracing")
    tool_classes = {cls.name: cls for cls in all_tools()}
    tool_instances = {name: cls() for name, cls in tool_classes.items()}

    @server.list_tools()
    async def _list_tools() -> list[mcp_types.Tool]:
        return [
            mcp_types.Tool(
                name=cls.name,
                description=cls.description,
                inputSchema=cls.input_schema.model_json_schema(),
            )
            for cls in tool_classes.values()
        ]

    @server.call_tool()
    async def _call_tool(
        name: str, arguments: dict
    ) -> list[mcp_types.TextContent]:
        tool = tool_instances.get(name)
        if tool is None:
            return [mcp_types.TextContent(
                type="text", text=f"[error] unknown tool: {name}"
            )]
        try:
            parsed = tool.input_schema.model_validate(arguments or {})
        except ValidationError as e:
            return [mcp_types.TextContent(
                type="text", text=f"[input error]\n{e}"
            )]
        try:
            result = await tool.run(parsed, session)
        except Exception as e:  # noqa: BLE001 — surface as a tool error
            _LOG.exception("tool '%s' raised", name)
            return [mcp_types.TextContent(
                type="text", text=f"[tool error] {type(e).__name__}: {e}"
            )]
        return [mcp_types.TextContent(
            type="text", text=result.model_dump_json(indent=2)
        )]

    return server


async def _serve_stdio(session: Session) -> None:
    server = _build_server(session)
    _LOG.info(
        "mx-tracing MCP server v%s ready, tools: %s",
        __version__,
        ", ".join(sorted(cls.name for cls in all_tools())),
    )
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(
            read,
            write,
            InitializationOptions(
                server_name="mx-tracing",
                server_version=__version__,
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


def run() -> int:
    """Synchronous entry: block on the MCP stdio loop."""
    configure_logging()
    session = Session(workspace_root=None)  # auto-detect
    try:
        asyncio.run(_serve_stdio(session))
    except KeyboardInterrupt:
        _LOG.info("interrupted")
    return 0
