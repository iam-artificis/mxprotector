"""Protection invariants.

Importing this package runs the ``@register_invariant`` decorator on
every invariant module, populating the global registry used by
``verify_protection_invariants``. Adding a new invariant: create
``<name>.py`` with a ``@register_invariant`` class and add one import
line below.
"""

from mx_mcp.invariants import oep_is_stub as _oep_is_stub  # noqa: F401
from mx_mcp.invariants import packer_decrypted as _packer_decrypted  # noqa: F401
