"""IDA Pro headless backend.

Drives ``idat64.exe`` in autonomous mode (``-A``) to run IDAPython
scripts against a target binary and collect JSON metrics. Tests mock
the subprocess layer via ``runner._run_subprocess`` so no actual IDA
install is needed to exercise the invocation logic.

Scripts live under ``scripts/`` as plain IDAPython (NOT importable as
a Python package — those modules rely on IDA-only stdlib stand-ins).
The runner passes a script path to IDA; IDA loads and runs it under
its own interpreter.
"""
