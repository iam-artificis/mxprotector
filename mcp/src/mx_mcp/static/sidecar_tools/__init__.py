"""MCP tools that read the builder's ``.mxtrace.json`` sidecar.

Importing this subpackage triggers ``@register_tool`` for every tool
module under it. Sidecar-only tools do not spawn the binary — they
answer questions that can be resolved from the JSON + the PE header.
"""

from mx_mcp.static.sidecar_tools import list_sections as _list_sections  # noqa: F401
