"""Reporting — cross-cutting rendering of measurement + diff results.

Two sibling concerns live here:

* ``text_formatter`` — human-readable string summaries, no third-party
  dependencies. Always available.
* ``charts/`` — PNG renderers built on matplotlib, gated by an
  ``[viz]`` install extra. Guarded import means the bare package
  stays importable without matplotlib present.
* ``render_or_skip`` — thin helper the MCP tools call to attach an
  optional chart to their pydantic output with fail-closed exception
  handling.

Kept deliberately outside ``benchmarks/`` and ``tools/``: reporting is
a presentation concern separate from metric computation and tool
orchestration. New output formats slot in as sibling modules without
touching either.
"""
