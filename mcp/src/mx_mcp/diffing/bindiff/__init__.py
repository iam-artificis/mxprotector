"""BinDiff backend — subprocess driver for Google/zynamics BinDiff 8.

Three small modules with strict SRP:

* :mod:`report` — pure parser for BinDiff's stdout summary plus the
  ``.results`` statistics file. Zero I/O.
* :mod:`binexport_runner` — wraps IDA headless + the BinExport
  plugin to turn one PE into one ``.BinExport`` file. Zero BinDiff
  knowledge.
* :mod:`bindiff_runner` — wraps ``bindiff.exe`` on a
  ``.BinExport`` pair and points callers at the produced
  ``.BinDiff`` + ``.results`` artefacts.

Higher-level orchestration (benchmark-side "build twice, export
each, diff, record metrics") lives in
``benchmarks/bindiff_benchmark.py`` — it is the only consumer that
ties the three modules together.
"""
