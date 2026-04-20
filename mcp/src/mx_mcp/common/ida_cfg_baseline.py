"""IDA-backed implementation of :class:`ICfgBaselineProvider`.

Runs the ``cff_metrics.py`` IDAPython script in **per-function** mode
(no ``MX_MCP_IDA_REGIONS`` env) so the decompiler enumerates every
function it can lift, aggregates the per-function records into one
:class:`CfgBaseline`, and reads the PE ``.text`` virtual size from raw
headers (no extra IDA work for section geometry — :mod:`pe_reader` is
essentially free).

Kept in its own module so :mod:`common.baseline` stays free of
IDA-specific dependencies. Another backend (radare2, Ghidra) can
plug in by implementing the same Protocol without touching either
the cache or the benchmarks that consume it (DIP + OCP).
"""

from __future__ import annotations

import logging
from pathlib import Path

import mx_mcp.static.ida as _ida_pkg
from mx_mcp.common.baseline import (
    BaselineError,
    CfgBaseline,
    ICfgBaselineProvider,
)
from mx_mcp.common.pe_reader import (
    NotAPeError,
    SectionNotFoundError,
    get_section_virtual_size,
)
from mx_mcp.static.ida.runner import (
    IdaNotFoundError,
    run_ida_script,
)


_LOG = logging.getLogger(__name__)


__all__ = ["IdaCfgBaselineProvider"]


# Shared with :mod:`benchmarks.cff_benchmark`. In per-function mode
# (the script's default when ``MX_MCP_IDA_REGIONS`` is absent) it
# iterates every function IDA + Hex-Rays can lift and emits one
# record per function. The baseline collapses the per-function
# records into aggregate totals — the denominator of amplification
# ratios.
_CFF_METRICS_SCRIPT = (
    Path(_ida_pkg.__file__).parent / "scripts" / "cff_metrics.py"
)

# Standard PE code section — where the compiler places unprotected
# machine code before the protector gets to it. Protected builds
# leave ``.text`` mostly as trampolines / stubs that jump to
# bytecode sections (``.vm``, ``.cff``, …); measuring those against
# the unprotected ``.text`` gives a per-byte density ratio.
_TEXT_SECTION_NAME = ".text"


class IdaCfgBaselineProvider:
    """IDA + Hex-Rays baseline measurement backend.

    Stateless — safe to share across benchmarks and across the
    process lifetime. All caching happens in the
    :class:`CfgBaselineCache` that wraps this provider.
    """

    def __init__(
        self,
        *,
        script_path: Path = _CFF_METRICS_SCRIPT,
        ida_path: str | Path | None = None,
    ) -> None:
        """Construct the provider.

        ``ida_path`` is forwarded to :func:`run_ida_script` unchanged.
        Setting it to ``None`` uses the usual env-var / PATH lookup,
        which is what benchmarks want outside of tests.
        """
        self._script_path = script_path
        self._ida_path = ida_path

    async def measure(self, binary: Path) -> CfgBaseline:
        """See :meth:`ICfgBaselineProvider.measure`."""
        _LOG.info("baseline: IDA per-function on %s", binary.name)

        try:
            ida_result = await run_ida_script(
                binary=binary,
                script=self._script_path,
                ida_path=self._ida_path,
            )
        except IdaNotFoundError as e:
            raise BaselineError(f"IDA missing: {e}") from e
        except FileNotFoundError as e:
            raise BaselineError(f"IDA launch: {e}") from e

        if not ida_result.ok or ida_result.output is None:
            raise BaselineError(
                f"IDA on baseline {binary.name} failed: "
                f"{ida_result.error or 'no output'}"
            )

        output = ida_result.output
        if not output.get("hexrays_available", False):
            raise BaselineError(
                f"Hex-Rays unavailable on baseline {binary.name}"
            )

        records = output.get("functions") or []
        total_blocks = sum(int(r.get("mc_blocks", 0)) for r in records)
        total_cyc = sum(int(r.get("mc_cyclomatic", 0)) for r in records)
        total_gotos = sum(int(r.get("mc_gotos", 0)) for r in records)

        try:
            text_size = get_section_virtual_size(binary, _TEXT_SECTION_NAME)
        except (NotAPeError, SectionNotFoundError) as e:
            raise BaselineError(
                f"PE .text lookup failed on {binary.name}: {e}"
            ) from e
        except OSError as e:
            raise BaselineError(
                f"PE read IO error on {binary.name}: {e}"
            ) from e

        _LOG.info(
            "baseline: %s — fns=%d blocks=%d cyc=%d gotos=%d .text=%dB",
            binary.name, len(records), total_blocks, total_cyc,
            total_gotos, text_size,
        )

        return CfgBaseline(
            binary_path=binary,
            function_count=len(records),
            total_blocks=total_blocks,
            total_cyclomatic=total_cyc,
            total_gotos=total_gotos,
            text_section_size=text_size,
        )
