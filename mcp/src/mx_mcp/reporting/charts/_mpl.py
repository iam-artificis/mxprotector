"""Matplotlib guard + shared figure helpers.

Isolates every matplotlib import behind ``matplotlib_available()`` so
the rest of the package stays importable without the ``[viz]`` extra
installed. Concrete renderers call :func:`require_matplotlib` and get
back a ready-to-use ``pyplot`` module with the Agg backend already
selected.

All chart modules use ``Agg`` deliberately — the MCP server runs
headless, there is no display to open, and Agg has no GUI dependencies
which keeps ``pip install -e ".[viz]"`` minimal.
"""

from __future__ import annotations

import logging
from types import ModuleType

_LOG = logging.getLogger(__name__)


def matplotlib_available() -> bool:
    """True when ``import matplotlib`` succeeds on this interpreter."""
    try:
        import matplotlib  # noqa: F401
        return True
    except ImportError:
        return False


def require_matplotlib() -> ModuleType:
    """Return a ready-to-use ``matplotlib.pyplot`` module.

    Forces the ``Agg`` backend before the first ``pyplot`` import so
    no display / GUI-toolkit init ever runs. Subsequent callers pick
    up the same backend transparently.

    Raises:
        RuntimeError: matplotlib is not installed.
    """
    try:
        import matplotlib
    except ImportError as e:
        raise RuntimeError(
            "matplotlib is not installed — pip install -e \".[viz]\" in mcp/"
        ) from e

    # ``force=False`` — if something earlier in the process already
    # selected a backend, honour it. We only *prefer* Agg.
    matplotlib.use("Agg", force=False)
    import matplotlib.pyplot as plt
    return plt


# ----------------------------------------------------------------------
# Shared styling — kept at module scope so both renderers stay
# visually consistent without duplicating constants.
# ----------------------------------------------------------------------

DIRECTION_COLORS: dict[str, str] = {
    "higher_better": "#2e7dd7",  # cool blue — value should grow
    "lower_better":  "#d96d2e",  # warm orange — value should shrink
    "false_best":    "#c12e7a",  # magenta — failure rate (distinct hue)
}

VERDICT_COLORS: dict[str, str] = {
    "improved":  "#2aa24a",
    "regressed": "#d24545",
    "unchanged": "#888888",
    "skipped":   "#bbbbbb",
    "added":     "#2d8a9c",
    "removed":   "#aa7a2a",
}

FIGURE_DPI: int = 110
