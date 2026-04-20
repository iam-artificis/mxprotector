"""Matplotlib guard + shared figure helpers.

Isolates every matplotlib import behind :func:`matplotlib_available` so
the rest of the package stays importable without the ``[viz]`` extra
installed. Concrete renderers call :func:`require_matplotlib` and get
back a ready-to-use ``pyplot`` module with the Agg backend already
selected.

All chart modules use ``Agg`` deliberately — the MCP server runs
headless, there is no display to open, and Agg has no GUI dependencies
which keeps ``pip install -e ".[viz]"`` minimal.

## Palette

All charts share the ``DARK_THEME`` dict below so the MCP reporting
output has one consistent look. Keys are scoped so individual
renderers can read just what they need (``theme["bg"]`` without
depending on the full palette).

The palette was tuned for:

1. Low-light readability — the background is a deep navy rather than
   pure black to avoid eye strain on OLED or office-light displays.
2. Colour-blind legibility — the direction / verdict hues pair
   saturation with distinct hue (cyan vs orange vs magenta) so they
   remain distinguishable under the common dichromacies.
3. One warm accent (``accent``) drives titles, axis labels, and
   anything else "chrome" on the chart — the user-requested "reddish"
   text. Annotations that overlay colored bars use ``text_on_bar``
   (off-white) instead so readability wins over theme consistency
   where they conflict.
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
# Dark theme — single source of truth for chart colours.
# ----------------------------------------------------------------------

DARK_THEME: dict[str, str] = {
    # Canvas
    "bg":            "#141420",   # deep navy-black — figure + axes face
    "panel":         "#1b1b2a",   # slight lift for legend / text boxes

    # Chrome (titles, axis labels, tick labels — the "reddish" text)
    "accent":        "#ff6e6e",   # main title + axis label
    "accent_muted":  "#e9a8a8",   # ticks + secondary labels

    # Content
    "text_on_bar":   "#f5f5fa",   # annotations that overlay coloured bars
    "text_dim":      "#9a9ab0",   # "no data" placeholder text

    # Structure
    "grid":          "#242438",   # grid lines
    "spine":         "#4a4a66",   # axis spines + zero/mid reference
    "edge":          "#2a2a3c",   # bar edges

    # Hatch overlay (no-scale rows)
    "hatch_edge":    "#8a8aa0",
}


# Direction-coloured bars, tuned for the dark canvas (more saturated
# and brighter than a light-background palette would use).
DIRECTION_COLORS: dict[str, str] = {
    "higher_better": "#4fb3ff",  # bright cyan-blue — value should grow
    "lower_better":  "#ffa94d",  # warm orange — value should shrink
    "false_best":    "#e94db1",  # pink-magenta — failure rate
}


VERDICT_COLORS: dict[str, str] = {
    "improved":  "#3ee08a",      # bright green
    "regressed": "#ff5c6c",      # bright red
    "unchanged": "#8a8aa0",      # muted blue-grey
    "skipped":   "#5a5a72",      # dim
    "added":     "#4fd9e0",      # teal — new metrics since baseline
    "removed":   "#ffc352",      # amber — metrics disappeared
}

FIGURE_DPI: int = 110


def style_axis_for_dark(ax) -> None:
    """Apply the dark palette to a matplotlib ``Axes``.

    Centralised so every renderer gets identical spine / tick / label
    colouring without duplicating rcParams shuffles. Deliberately does
    *not* touch face colours on bars, lines, or user-supplied artists —
    those stay under the renderer's control.
    """
    ax.set_facecolor(DARK_THEME["bg"])
    for spine in ax.spines.values():
        spine.set_color(DARK_THEME["spine"])
        spine.set_linewidth(0.6)
    ax.tick_params(
        colors=DARK_THEME["accent_muted"],
        labelcolor=DARK_THEME["accent_muted"],
        which="both",
    )
    ax.xaxis.label.set_color(DARK_THEME["accent"])
    ax.yaxis.label.set_color(DARK_THEME["accent"])
    ax.title.set_color(DARK_THEME["accent"])


def style_figure_for_dark(fig) -> None:
    """Apply the dark face colour + suptitle tint to a ``Figure``."""
    fig.patch.set_facecolor(DARK_THEME["bg"])
    # ``suptitle`` is created lazily; tint it if already present.
    if getattr(fig, "_suptitle", None) is not None:
        fig._suptitle.set_color(DARK_THEME["accent"])
