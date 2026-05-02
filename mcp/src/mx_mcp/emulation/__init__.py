"""Emulation backends.

P9 introduces ``emulation/unicorn/`` — a Unicorn-driven emulator
used by two benchmarks: OEP-reach (does dynamic emulation crack the
packer?) and VM handler replay (how much native work does each
handler do?).

Future emulation backends (Qiling, Triton-DBA) plug in by adding
their own subpackage here.
"""
