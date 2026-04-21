"""Defense benchmarks — one file per benchmark.

Importing this package triggers ``@register_benchmark`` for every
concrete benchmark module. Adding a new benchmark = create
``<name>.py`` here and add one import line below. ``server.py``
imports this subpackage so the registry is populated before
``measure_defense`` is called.
"""

from mx_mcp.benchmarks import bindiff_benchmark as _bindiff_benchmark  # noqa: F401
from mx_mcp.benchmarks import cff_benchmark as _cff_benchmark  # noqa: F401
from mx_mcp.benchmarks import leakage_benchmark as _leakage_benchmark  # noqa: F401
from mx_mcp.benchmarks import packer_benchmark as _packer_benchmark  # noqa: F401
from mx_mcp.benchmarks import vm_benchmark as _vm_benchmark  # noqa: F401
from mx_mcp.benchmarks import vm_mba_benchmark as _vm_mba_benchmark  # noqa: F401
from mx_mcp.benchmarks import vm_symbolic_benchmark as _vm_symbolic_benchmark  # noqa: F401
