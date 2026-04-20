"""Frida-backed MCP tools.

Importing this subpackage triggers the ``@register_tool`` decorator on
every tool module under it, which is how the server discovers tools
without a manifest. Adding a new Frida tool = create ``<name>.py`` here
and add one import line below.
"""

from mx_mcp.dynamic.frida.tools import protect_and_trace as _protect_and_trace  # noqa: F401
