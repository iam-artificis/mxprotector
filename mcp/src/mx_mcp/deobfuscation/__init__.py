"""Deobfuscation backends.

Each subpackage wraps one attacker-side deobfuscation tool (MBA
simplifier, CFF deobfuscator, devirtualiser, …) behind a common
runner interface. Benchmarks consume runners; tools consume benchmark
results.
"""
