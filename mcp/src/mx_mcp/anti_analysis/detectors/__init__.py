"""Anti-analysis detectors — one file per tool family.

Importing this package triggers ``@register_detector`` for every
concrete detector module. Adding a new detector = create
``<name>_detector.py`` here and add one import line below.
``benchmarks.anti_analysis_benchmark`` imports this subpackage so
the registry is populated before the benchmark walks it.

Initial catalogue (P10) covers the five tool families called out in
``MCP.md``: x64dbg, Frida, Unicorn, pafish, al-khaser. Every
detector currently runs as a static scan over the protected PE on
disk; dynamic-tool wiring (driving x64dbg.exe, pafish.exe, …) is
deferred to FUTURE.md.
"""

from mx_mcp.anti_analysis.detectors import al_khaser_detector as _al_khaser_detector  # noqa: F401
from mx_mcp.anti_analysis.detectors import frida_detector as _frida_detector  # noqa: F401
from mx_mcp.anti_analysis.detectors import pafish_detector as _pafish_detector  # noqa: F401
from mx_mcp.anti_analysis.detectors import unicorn_detector as _unicorn_detector  # noqa: F401
from mx_mcp.anti_analysis.detectors import x64dbg_detector as _x64dbg_detector  # noqa: F401
