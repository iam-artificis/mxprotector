"""Diffing-resistance backends.

Subpackages here measure how well a protector randomises output:
given two seeded builds of the same input, low structural match =
strong randomisation (an attacker cannot cross-reference between
builds). High match = weak randomisation.

MVP population:

* ``bindiff/`` — wraps Google/zynamics BinDiff, the industry
  reference for binary-level structural diffing.

``FUTURE.md`` lists additional slots (Diaphora, Qiling-diff, …).
"""
