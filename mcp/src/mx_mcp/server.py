"""MCP stdio server entry point.

Introspects the tool registry (``common.tool_base.all_tools``) and
wires each entry into MCP's ``list_tools`` / ``call_tool`` hooks.
Tool discovery happens at import time — every ``tools`` subpackage
under ``mx_mcp`` is imported below, triggering ``@register_tool`` on
every concrete tool module.

When a new tools subpackage is added under a new backend (e.g.
``mx_mcp.emulation.unicorn.tools``) a single import line lands here.
The rest of the server stays untouched — discovery is OCP by design.
"""

from __future__ import annotations

import asyncio
import logging

import mcp.server.stdio
import mcp.types as mcp_types
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions
from pydantic import ValidationError

from mx_mcp import __version__
from mx_mcp.common.logging_setup import configure_logging
from mx_mcp.common.tool_base import all_tools
from mx_mcp.dynamic.frida.session import Session

# Side-effect imports — each subpackage's ``__init__.py`` runs the
# ``@register_tool`` / ``@register_benchmark`` decorators on its
# concrete modules. Adding a new tools or benchmarks subpackage: add
# one line here. noqa: F401 throughout.
from mx_mcp import tools as _tools_pkg  # noqa: F401
from mx_mcp.dynamic.frida import tools as _frida_tools_pkg  # noqa: F401
from mx_mcp.static import sidecar_tools as _sidecar_tools_pkg  # noqa: F401
from mx_mcp import benchmarks as _benchmarks_pkg  # noqa: F401
from mx_mcp import gates as _gates_pkg  # noqa: F401


_LOG = logging.getLogger(__name__)


def _build_server(session: Session) -> Server:
    server: Server = Server("mx-mcp")
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
        "mx-mcp server v%s ready, tools: %s",
        __version__,
        ", ".join(sorted(cls.name for cls in all_tools())),
    )
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(
            read,
            write,
            InitializationOptions(
                server_name="mx-mcp",
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
