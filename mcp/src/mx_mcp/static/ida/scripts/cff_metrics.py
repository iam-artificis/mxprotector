"""CFF-metrics extractor — runs inside IDA Pro via ``idat64 -A -Sthis_script``.

Emits JSON to the path given by the ``MX_MCP_IDA_OUTPUT`` environment
variable. Reads nothing else from the environment, takes no CLI args.

This file is *IDAPython* — it is **not** a normal Python module.
``ida_funcs`` / ``ida_hexrays`` / ``idautils`` / ``idc`` are only
importable inside IDA's embedded interpreter. The MCP ``pytest``
suite does **not** import it. Syntax is covered by ``py -3 -m
py_compile``.

## What it measures

For every function the HexRays decompiler can lift, the script walks
the microcode block array (``cfunc_t.mba``) and emits:

* ``mc_blocks``         — number of microcode basic blocks.
* ``mc_gotos``          — block tails whose opcode is ``m_goto`` /
                          ``m_ijmp``. CFF dispatchers show up here.
* ``mc_edges``          — sum of ``nsucc()`` over all blocks.
* ``mc_backedges``      — edges whose successor index is ``<=`` the
                          source index (heuristic proxy for "back-edge
                          in reverse-postorder"). Flattened CFGs tend
                          to have more.
* ``mc_cyclomatic``     — ``E - N + 2`` cyclomatic complexity.
* ``mc_backedge_ratio`` — ``mc_backedges / mc_edges`` (0 when ``E==0``).

All four "↑ higher-is-better" from CFF's perspective: a stronger CFF
pass inflates every count.

## Hex-Rays gating

If Hex-Rays is not available in this IDA installation,
``hexrays_available`` is set to ``false`` in the output and
``functions`` stays empty. The benchmark layer reads this and fails
the run rather than silently reporting zeros.

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
    import idautils
    import idc
except Exception as exc:  # pragma: no cover — runs only inside IDA
    sys.stderr.write(f"[mx_mcp] IDAPython imports failed: {exc}\n")
    raise


_SCHEMA_VERSION = 1


def _collect_function_metrics(fn_ea: int) -> dict | None:
    """Return one per-function record or None if the function is
    unreachable by the decompiler (uncaught library code, stripped
    thunks, SEH landing pads, …)."""
    fn = ida_funcs.get_func(fn_ea)
    if fn is None:
        return None

    try:
        cfunc = ida_hexrays.decompile(fn.start_ea)
    except Exception:
        return None
    if cfunc is None:
        return None

    mba = cfunc.mba
    if mba is None:
        return None

    n_blocks = mba.qty
    n_gotos = 0
    n_edges = 0
    n_backedges = 0

    for i in range(n_blocks):
        blk = mba.get_mblock(i)
        if blk is None:
            continue

        # Goto-tail detection — m_goto is the unconditional branch
        # opcode; m_ijmp covers the indirect-jump form that CFF
        # dispatchers frequently use.
        tail = blk.tail
        if tail is not None:
            opcode = getattr(tail, "opcode", -1)
            goto_opcodes = {
                getattr(ida_hexrays, "m_goto", None),
                getattr(ida_hexrays, "m_ijmp", None),
            }
            goto_opcodes.discard(None)
            if opcode in goto_opcodes:
                n_gotos += 1

        nsucc = blk.nsucc()
        n_edges += nsucc
        for s in range(nsucc):
            succ_idx = blk.succ(s)
            # Heuristic proxy for back-edge: successor index <=
            # current. HexRays numbers blocks in quasi-topological
            # order, so this catches the common loop-header case.
            if succ_idx <= i:
                n_backedges += 1

    # Cyclomatic complexity with standard single-entry assumption.
    cyclomatic = n_edges - n_blocks + 2
    backedge_ratio = (n_backedges / n_edges) if n_edges > 0 else 0.0

    try:
        name = idc.get_func_name(fn_ea) or f"sub_{fn_ea:X}"
    except Exception:
        name = f"sub_{fn_ea:X}"

    return {
        "ea": int(fn_ea),
        "name": str(name),
        "size": int(fn.size()),
        "mc_blocks": int(n_blocks),
        "mc_gotos": int(n_gotos),
        "mc_edges": int(n_edges),
        "mc_backedges": int(n_backedges),
        "mc_cyclomatic": int(cyclomatic),
        "mc_backedge_ratio": float(backedge_ratio),
    }


def _main() -> None:
    output_path = os.environ.get("MX_MCP_IDA_OUTPUT")
    if not output_path:
        sys.stderr.write("[mx_mcp] MX_MCP_IDA_OUTPUT not set; nowhere to write\n")
        idc.qexit(2)
        return

    # Block until IDA's auto-analysis finishes; otherwise function
    # discovery and Hex-Rays decompilation return partial results.
    ida_auto.auto_wait()

    # Hex-Rays can be initialised lazily; force a decision now so the
    # fallback path (no Hex-Rays) writes a complete record.
    hexrays_ok = False
    try:
        hexrays_ok = bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        hexrays_ok = False

    output = {
        "schema_version": _SCHEMA_VERSION,
        "hexrays_available": hexrays_ok,
        "functions": [],
        "errors": [],
    }

    if hexrays_ok:
        for fn_ea in idautils.Functions():
            try:
                entry = _collect_function_metrics(fn_ea)
                if entry is not None:
                    output["functions"].append(entry)
            except Exception as exc:  # defensive: one bad function
                output["errors"].append(
                    f"sub_{fn_ea:X}: {type(exc).__name__}: {exc}"
                )
                # Include traceback in stderr for post-mortem; not in JSON.
                sys.stderr.write(traceback.format_exc())

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)
    except Exception as exc:
        sys.stderr.write(f"[mx_mcp] failed to write output JSON: {exc}\n")
        idc.qexit(3)
        return

    # Clean exit — without this, IDA holds the process waiting for the
    # database save prompt.
    idc.qexit(0)


_main()
