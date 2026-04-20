"""pe-sieve backend — subprocess driver for hasherezade/pe-sieve.

Three small modules with strict SRP:

* :mod:`report` — pure pydantic parser for pe-sieve's JSON summary.
  Zero I/O.
* :mod:`process_controller` — child-process lifecycle (launch, wait,
  terminate). Zero pe-sieve knowledge.
* :mod:`runner` — orchestration: resolve pe-sieve path, launch the
  target, give the packer decrypt time, scan with pe-sieve, parse,
  clean up. The single public entry point the benchmark layer
  imports.
"""
