"""Top-level MCP tools — backend-agnostic.

Tools here orchestrate multiple backends (e.g. ``verify_protection_invariants``
runs static invariants plus Frida-traced ones). Backend-specific tools
live under the backend's own ``tools/`` subpackage (e.g.
``dynamic/frida/tools/protect_and_trace``).

Importing this subpackage triggers ``@register_tool`` for every tool
module here.
"""

from mx_mcp.tools import verify_protection_invariants as _verify_protection_invariants  # noqa: F401
