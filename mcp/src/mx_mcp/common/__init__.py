"""Cross-backend primitives.

Contains ABCs shared by every backend:

* ``tool_base``      — ``ITool`` + ``@register_tool`` decorator
* ``invariant_base`` — ``IInvariant`` + ``@register_invariant``
* ``sidecar``        — pydantic schema for ``<output>.mxtrace.json``
* ``events``         — NDJSON envelope produced by runtime probes
* ``pe_reader``      — minimal PE header reader (stdlib-only)
* ``logging_setup``  — stderr logging config (stdout is MCP-owned)

Kept free of third-party runtime deps (no ``frida`` / ``unicorn`` / ``angr``)
so every backend and tool can import from here without triggering
optional-dep imports.
"""
