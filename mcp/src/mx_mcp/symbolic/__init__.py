"""Symbolic-execution backends.

Each backend lives in a subpackage (``angr``, future: ``triton``,
``miasm``, ``z3``). Benchmarks consume runner helpers from the
subpackages; tools consume benchmark results.
"""
