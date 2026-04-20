"""CFF-metrics extractor — runs inside IDA Pro via ``idat64 -A -Sthis_script``.

Emits JSON to the path given by the ``MX_MCP_IDA_OUTPUT`` environment
variable.

This file is *IDAPython* — it is **not** a normal Python module.
``ida_funcs`` / ``ida_hexrays`` / ``idautils`` / ``idc`` are only
importable inside IDA's embedded interpreter. The MCP ``pytest``
suite does **not** import it. Syntax is covered by ``py -3 -m
py_compile``.

## Two measurement modes

The script measures microcode complexity and runs in one of two
modes, chosen by environment variables:

**Region mode** (preferred by the CFF benchmark).

Triggered by ``MX_MCP_IDA_REGIONS`` — a JSON array of
``{"name": str, "rva": int, "size": int}`` objects. For each region
the script builds microcode via ``ida_hexrays.gen_microcode`` on the
explicit byte range, bypassing IDA's auto-analysis function
recognition. This is the only reliable way to measure the CFF
dispatcher code: IDA does not create functions at the dispatcher
entries (they're reachable only through indirect jumps from a small
``.text`` trampoline), so any "iterate functions" strategy returns
an empty set for the CFF section.

**Per-function mode** (legacy, for non-CFF analyses).

Activated when ``MX_MCP_IDA_REGIONS`` is not set. The script iterates
every function the decompiler can lift and emits one record per
function.

Both modes emit the same record shape through the ``functions`` field.
In region mode the ``name`` comes from the caller; in function mode
it comes from ``idc.get_func_name``. Downstream code ignores the
distinction — every record carries ``rva``, ``size``, ``mba_maturity``,
and the ``mc_*`` metrics.

## Emitted metrics per record

* ``mc_blocks``         — microcode basic-block count.
* ``mc_gotos``          — block tails whose opcode is ``m_goto`` /
                          ``m_ijmp``. CFF dispatchers show up here.
* ``mc_edges``          — sum of ``nsucc()`` over all blocks.
* ``mc_backedges``      — edges whose successor index is ``<=`` the
                          source index (heuristic proxy for "back-edge
                          in reverse-postorder").
* ``mc_cyclomatic``     — ``E - N + 2`` cyclomatic complexity.
* ``mc_backedge_ratio`` — ``mc_backedges / mc_edges`` (0 when E==0).

All four ↑ higher-is-better for CFF: stronger flattening inflates
every count.

## Exit

``idc.qexit(0)`` at the tail forces IDA to exit once analysis +
collection finish. Without it, ``-A`` mode still holds the process
open for the database save step and the runner times out.
"""

# ruff: noqa: E402, I001 — IDAPython-only imports, ordering follows IDA convention

from __future__ import annotations

import json
import os
import sys
import traceback

# IDA-only modules; imports guarded so a mistake during dev surfaces a
# readable message in stderr instead of a bare ImportError traceback.
try:
    import ida_auto
    import ida_funcs
    import ida_hexrays
    import ida_nalt
    import ida_range
    import idautils
    import idc
except Exception as exc:  # pragma: no cover — runs only inside IDA
    sys.stderr.write(f"[mx_mcp] IDAPython imports failed: {exc}\n")
    raise


_SCHEMA_VERSION = 1


# ============================================================================
# Microcode → metrics (pure, no I/O)
# ============================================================================


def _count_block_metrics(mba: object) -> dict[str, int | float]:
    """Walk ``mba`` once, tallying the per-block counts the benchmark
    surfaces. Kept purely arithmetic so the two generation paths
    (function-scoped vs range-scoped) share one analyser.
    """
    n_blocks = int(getattr(mba, "qty", 0))
    n_gotos = 0
    n_edges = 0
    n_backedges = 0

    goto_opcodes = {
        getattr(ida_hexrays, "m_goto", None),
        getattr(ida_hexrays, "m_ijmp", None),
    }
    goto_opcodes.discard(None)

    for i in range(n_blocks):
        blk = mba.get_mblock(i)
        if blk is None:
            continue

        tail = blk.tail
        if tail is not None:
            opcode = getattr(tail, "opcode", -1)
            if opcode in goto_opcodes:
                n_gotos += 1

        nsucc = blk.nsucc()
        n_edges += nsucc
        for s in range(nsucc):
            # Heuristic: ``mba`` numbers blocks in quasi-topological
            # order, so a successor index ``<=`` current points back
            # up the order — i.e. a back-edge.
            if blk.succ(s) <= i:
                n_backedges += 1

    cyclomatic = n_edges - n_blocks + 2
    backedge_ratio = (n_backedges / n_edges) if n_edges > 0 else 0.0

    return {
        "mc_blocks": int(n_blocks),
        "mc_gotos": int(n_gotos),
        "mc_edges": int(n_edges),
        "mc_backedges": int(n_backedges),
        "mc_cyclomatic": int(cyclomatic),
        "mc_backedge_ratio": float(backedge_ratio),
    }


# ============================================================================
# Microcode generation — two entry points (function vs range)
# ============================================================================


def _gen_microcode_for_range(start_ea: int, end_ea: int) -> tuple[object, str] | tuple[None, None]:
    """Generate microcode for an explicit byte range at MMAT_GLBOPT3.

    Used by region-mode to measure the CFF section directly, without
    relying on ``ida_funcs.get_func`` which does not cover the
    dispatcher entries.
    """
    try:
        mbr = ida_hexrays.mba_ranges_t()
        mbr.ranges.push_back(ida_range.range_t(int(start_ea), int(end_ea)))
        hf = ida_hexrays.hexrays_failure_t()
        mba = ida_hexrays.gen_microcode(
            mbr, hf, None, 0, ida_hexrays.MMAT_GLBOPT3,
        )
        if mba is not None and getattr(mba, "qty", 0) > 0:
            return mba, "MMAT_GLBOPT3"
    except Exception:
        pass
    return None, None


def _gen_microcode_for_function(fn: object) -> tuple[object, str] | tuple[None, None]:
    """Function-scope microcode: prefer MMAT_GLBOPT3 via ``gen_microcode``,
    fall back to the full-decompile MBA if the explicit path fails.

    Used by per-function mode. Reaches the same maturity level as
    range mode on the happy path but gains a ``decompile()`` fallback
    for pathological entries (malformed prologues, SEH landing pads,
    …).
    """
    mba, maturity = _gen_microcode_for_range(fn.start_ea, fn.end_ea)
    if mba is not None:
        return mba, maturity

    try:
        cfunc = ida_hexrays.decompile(fn.start_ea)
        if cfunc is not None and cfunc.mba is not None:
            return cfunc.mba, "MMAT_GENERATED"
    except Exception:
        pass
    return None, None


# ============================================================================
# Record builders — one per mode.
# ============================================================================


def _record_for_function(fn_ea: int, image_base: int) -> dict | None:
    """Return one per-function record or ``None`` if the function is
    unreachable by the decompiler (uncaught library code, stripped
    thunks, SEH landing pads)."""
    fn = ida_funcs.get_func(fn_ea)
    if fn is None:
        return None

    mba, maturity = _gen_microcode_for_function(fn)
    if mba is None or maturity is None:
        return None

    try:
        name = idc.get_func_name(fn_ea) or f"sub_{fn_ea:X}"
    except Exception:
        name = f"sub_{fn_ea:X}"

    return {
        "ea": int(fn_ea),
        "rva": int(fn_ea - image_base),
        "name": str(name),
        "size": int(fn.size()),
        "mba_maturity": str(maturity),
        **_count_block_metrics(mba),
    }


def _record_for_region(region: dict, image_base: int) -> dict | None:
    """Return one per-region record or ``None`` if the region is empty
    or ``gen_microcode`` produced nothing.

    ``region`` shape: ``{"name": str, "rva": int, "size": int}``.
    Caller owns naming — typically the sidecar section role
    (``"cff_section"``) — so the benchmark can correlate back without
    guessing.
    """
    rva = int(region.get("rva", -1))
    size = int(region.get("size", 0))
    if rva < 0 or size <= 0:
        return None

    start_ea = image_base + rva
    end_ea = start_ea + size

    mba, maturity = _gen_microcode_for_range(start_ea, end_ea)
    if mba is None or maturity is None:
        return None

    return {
        "ea": int(start_ea),
        "rva": rva,
        "name": str(region.get("name", f"region_{rva:X}")),
        "size": size,
        "mba_maturity": str(maturity),
        **_count_block_metrics(mba),
    }


# ============================================================================
# Mode dispatcher
# ============================================================================


def _parse_regions_env() -> list[dict] | None:
    """Parse ``MX_MCP_IDA_REGIONS``. Returns a validated region list
    or ``None`` when the env var is absent / invalid.

    An invalid payload emits a stderr warning and falls back to
    per-function mode, so a malformed caller does not lose the whole
    run.
    """
    raw = os.environ.get("MX_MCP_IDA_REGIONS")
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"[mx_mcp] MX_MCP_IDA_REGIONS not valid JSON: {e}\n")
        return None
    if not isinstance(parsed, list):
        sys.stderr.write("[mx_mcp] MX_MCP_IDA_REGIONS must be a JSON array\n")
        return None
    regions: list[dict] = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        if "rva" not in item or "size" not in item:
            continue
        regions.append(item)
    return regions


# ============================================================================
# Main
# ============================================================================


def _main() -> None:
    output_path = os.environ.get("MX_MCP_IDA_OUTPUT")
    if not output_path:
        sys.stderr.write("[mx_mcp] MX_MCP_IDA_OUTPUT not set; nowhere to write\n")
        idc.qexit(2)
        return

    # Block until IDA's auto-analysis finishes; otherwise function
    # discovery and Hex-Rays decompilation return partial results.
    ida_auto.auto_wait()

    hexrays_ok = False
    try:
        hexrays_ok = bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        hexrays_ok = False

    try:
        image_base = int(ida_nalt.get_imagebase())
    except Exception:
        image_base = 0

    regions = _parse_regions_env()
    mode = "region" if regions is not None else "function"

    output = {
        "schema_version": _SCHEMA_VERSION,
        "mode": mode,
        "hexrays_available": hexrays_ok,
        "image_base": image_base,
        "functions": [],   # name kept for backward compat; holds regions in region mode
        "errors": [],
    }

    if hexrays_ok:
        if mode == "region":
            for region in regions or []:
                try:
                    entry = _record_for_region(region, image_base)
                    if entry is not None:
                        output["functions"].append(entry)
                    else:
                        output["errors"].append(
                            f"region {region.get('name', '?')}: "
                            f"microcode generation produced no blocks"
                        )
                except Exception as exc:
                    output["errors"].append(
                        f"region {region.get('name', '?')}: "
                        f"{type(exc).__name__}: {exc}"
                    )
                    sys.stderr.write(traceback.format_exc())
        else:
            for fn_ea in idautils.Functions():
                try:
                    entry = _record_for_function(fn_ea, image_base)
                    if entry is not None:
                        output["functions"].append(entry)
                except Exception as exc:
                    output["errors"].append(
                        f"sub_{fn_ea:X}: {type(exc).__name__}: {exc}"
                    )
                    sys.stderr.write(traceback.format_exc())

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)
    except Exception as exc:
        sys.stderr.write(f"[mx_mcp] failed to write output JSON: {exc}\n")
        idc.qexit(3)
        return

    idc.qexit(0)


_main()
