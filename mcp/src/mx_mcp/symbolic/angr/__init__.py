"""angr backend — symbolic execution surface.

Two runners share one budget model and one backend loader:

* :func:`analyse_handler` — per-VM-handler summarisation
  (``vm_handler_summarization_rate``, P6 first half).
* :func:`analyse_oep_reach` — symbolic-step count to land on the
  original entry point starting from the protected binary's stub
  (``budget_to_crack_steps_to_oep``, P6 second half).

Public surface:

* :class:`SymbolicBudget` — wall-clock / step / path caps shared by
  both runners.
* :class:`HandlerAnalysisResult` / :class:`OepReachResult` — per-call
  outcome records, both carrying ``termination_reason`` for evidence.
* :class:`AngrNotAvailableError` — raised when the backend is missing
  or disabled; benchmarks convert this into one top-level error
  without crashing the whole run.
"""

from mx_mcp.symbolic.angr.budget import SymbolicBudget
from mx_mcp.symbolic.angr.oep_reach import (
    OepReachResult,
    analyse_oep_reach,
)
from mx_mcp.symbolic.angr.runner import (
    AngrNotAvailableError,
    HandlerAnalysisResult,
    analyse_handler,
)

__all__ = [
    "AngrNotAvailableError",
    "HandlerAnalysisResult",
    "OepReachResult",
    "SymbolicBudget",
    "analyse_handler",
    "analyse_oep_reach",
]
