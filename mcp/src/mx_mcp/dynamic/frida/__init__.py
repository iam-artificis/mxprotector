"""Frida DBI backend.

Owns the ``Session`` lifecycle, ``probes/`` JavaScript, and Frida-specific
tools. Kept isolated so other dynamic backends (post-MVP) slot in as
sibling packages without touching this one.
"""
