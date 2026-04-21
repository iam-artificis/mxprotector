"""angr backend — symbolic execution of VM handlers.

Public surface:

* :class:`SymbolicBudget` — wall-clock / step / path caps per handler.
* :class:`HandlerAnalysisResult` — outcome record.
* :class:`AngrNotAvailableError` — raised when the backend is missing
  or disabled; benchmarks convert this into a per-sample error without
  crashing the run.
* :func:`analyse_handler` — the one runner the P6 benchmark calls.
"""

from mx_mcp.symbolic.angr.budget import SymbolicBudget
from mx_mcp.symbolic.angr.runner import (
    AngrNotAvailableError,
    HandlerAnalysisResult,
    analyse_handler,
)

__all__ = [
    "AngrNotAvailableError",
    "HandlerAnalysisResult",
    "SymbolicBudget",
    "analyse_handler",
]
