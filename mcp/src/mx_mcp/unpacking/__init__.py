"""Unpacking backends.

Subpackages under here drive external unpackers / implant scanners
to measure the packer-defence quality. Each backend exposes a
``runner`` + supporting modules; higher-level benchmarks
(``benchmarks/packer_benchmark.py``) consume these runners.

MVP population:

* ``pe_sieve/`` — wraps hasherezade/pe-sieve, the de-facto standard
  for runtime implant / unpack detection.

``FUTURE.md`` lists the remaining slots (``unipacker``, ``scylla``,
``vmattack``, …) that will arrive in later phases.
"""
