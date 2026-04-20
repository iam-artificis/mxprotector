"""Invariants package — importing a module runs its ``@register_invariant``.

Adding a new invariant: create ``<name>.py`` with a
``@register_invariant`` class, then add one import line here.
"""

from mx_tracing.invariants import oep_is_stub as _oep_is_stub  # noqa: F401
from mx_tracing.invariants import packer_decrypted as _packer_decrypted  # noqa: F401
