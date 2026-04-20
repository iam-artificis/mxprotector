"""Top-level MCP tools — backend-agnostic.

Tools here orchestrate multiple backends (e.g. ``measure_defense`` runs
every registered benchmark; ``verify_protection_invariants`` runs
static invariants plus Frida-traced ones). Backend-specific tools live
under the backend's own ``tools/`` subpackage (e.g.
``dynamic/frida/tools/protect_and_trace``).

Importing this subpackage triggers ``@register_tool`` for every tool
module here. Adding a new top-level tool = create ``<name>.py`` here
and add one import line below.
"""

from mx_mcp.tools import diff_defense_baseline as _diff_defense_baseline  # noqa: F401
from mx_mcp.tools import measure_defense as _measure_defense  # noqa: F401
from mx_mcp.tools import record_baseline as _record_baseline  # noqa: F401
from mx_mcp.tools import verify_protection_invariants as _verify_protection_invariants  # noqa: F401
