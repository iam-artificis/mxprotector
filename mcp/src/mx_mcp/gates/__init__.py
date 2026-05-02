"""Ship-gate definitions — one file per gate.

Importing this package triggers ``@register_gate`` for every concrete
gate module. Adding a new gate = create ``<name>_gate.py`` here and
add one import line below. ``shipgate.runner`` imports this subpackage
so the registry is populated before the runner walks it.

Initial catalog (P8) covers the hard thresholds called out in
``MCP.md``: VM symbolic summarisation (slow), packer pe-sieve dump
(fast), Unicorn OEP-reach (fast), MBA simplification rates (slow),
budget-to-crack OEP (slow), BinDiff similarity (slow), and the
cross-cutting metadata-leakage signals (any tier). Future gates land
as new files; the runner never needs editing.
"""

from mx_mcp.gates import bindiff_similarity_gate as _bindiff_similarity_gate  # noqa: F401
from mx_mcp.gates import budget_to_crack_oep_gate as _budget_to_crack_oep_gate  # noqa: F401
from mx_mcp.gates import leakage_forbidden_literal_gate as _leakage_forbidden_literal_gate  # noqa: F401
from mx_mcp.gates import mba_claripy_simplification_gate as _mba_claripy_simplification_gate  # noqa: F401
from mx_mcp.gates import mba_pattern_simplification_gate as _mba_pattern_simplification_gate  # noqa: F401
from mx_mcp.gates import packer_pe_sieve_gate as _packer_pe_sieve_gate  # noqa: F401
from mx_mcp.gates import unicorn_oep_reach_gate as _unicorn_oep_reach_gate  # noqa: F401
from mx_mcp.gates import vm_symbolic_summarization_gate as _vm_symbolic_summarization_gate  # noqa: F401
