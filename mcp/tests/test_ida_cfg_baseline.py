"""Unit tests for :class:`mx_mcp.common.ida_cfg_baseline.IdaCfgBaselineProvider`.

Mocks both the IDA runner (at the module level) and the PE section
reader so every test runs hermetically — no real IDA needed. The
tests pin the translation between raw IDA records and the aggregated
:class:`CfgBaseline` record, plus each of the failure modes the
provider must convert into a :class:`BaselineError`.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from mx_mcp.common import ida_cfg_baseline as mod
from mx_mcp.common.baseline import BaselineError, CfgBaseline
from mx_mcp.common.ida_cfg_baseline import IdaCfgBaselineProvider
from mx_mcp.common.pe_reader import NotAPeError, SectionNotFoundError
from mx_mcp.static.ida.runner import IdaNotFoundError, IdaRunResult


# ============================================================================
# Fake injection helpers
# ============================================================================


def _install_fake_ida(
    monkeypatch,
    *,
    ok: bool = True,
    output: dict[str, Any] | None = None,
    error: str | None = None,
    raise_exc: Exception | None = None,
) -> list[dict[str, Any]]:
    """Replace ``run_ida_script`` at the module level.

    Returns a capture list so tests can inspect the call site.
    """
    captured: list[dict[str, Any]] = []

    async def fake_run(binary, script, **kwargs):  # noqa: ANN001, ANN003
        captured.append({
            "binary": binary, "script": script, **kwargs,
        })
        if raise_exc is not None:
            raise raise_exc
        return IdaRunResult(
            ok=ok,
            duration_ms=10,
            stdout_tail="",
            stderr_tail="",
            output=output,
            error=error,
        )

    monkeypatch.setattr(mod, "run_ida_script", fake_run)
    return captured


def _install_fake_text_size(monkeypatch, *, size: int = 8192) -> None:
    monkeypatch.setattr(
        mod, "get_section_virtual_size",
        lambda binary, name: size,
    )


def _install_text_size_error(monkeypatch, exc: Exception) -> None:
    def boom(binary, name):  # noqa: ANN001
        raise exc
    monkeypatch.setattr(mod, "get_section_virtual_size", boom)


def _touch_binary(tmp_path: Path, name: str = "src.exe") -> Path:
    p = tmp_path / name
    p.write_bytes(b"\x4d\x5a")  # MZ prefix — not a valid PE, but present
    return p


def _ida_output(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "mode": "function",
        "hexrays_available": True,
        "image_base": 0x140000000,
        "functions": records,
        "errors": [],
    }


# ============================================================================
# Happy path — per-function mode aggregation
# ============================================================================


def test_measure_aggregates_per_function_records(tmp_path: Path, monkeypatch):
    binary = _touch_binary(tmp_path)
    records = [
        {"mc_blocks": 10, "mc_cyclomatic": 5, "mc_gotos": 1},
        {"mc_blocks": 25, "mc_cyclomatic": 12, "mc_gotos": 3},
        {"mc_blocks": 8, "mc_cyclomatic": 4, "mc_gotos": 0},
    ]
    captured = _install_fake_ida(monkeypatch, output=_ida_output(records))
    _install_fake_text_size(monkeypatch, size=16384)

    provider = IdaCfgBaselineProvider()
    baseline = asyncio.run(provider.measure(binary))

    assert isinstance(baseline, CfgBaseline)
    assert baseline.binary_path == binary
    assert baseline.function_count == 3
    assert baseline.total_blocks == 43          # 10 + 25 + 8
    assert baseline.total_cyclomatic == 21      # 5 + 12 + 4
    assert baseline.total_gotos == 4            # 1 + 3 + 0
    assert baseline.text_section_size == 16384

    # IDA was invoked in per-function mode (no MX_MCP_IDA_REGIONS env)
    # — the provider must NOT pass extra_env that switches the script
    # into region mode.
    assert len(captured) == 1
    extra_env = captured[0].get("extra_env")
    assert extra_env is None or "MX_MCP_IDA_REGIONS" not in extra_env


def test_measure_with_no_functions_returns_zeros(tmp_path: Path, monkeypatch):
    """Empty function list is a valid measurement (weird but legal) —
    the baseline records zeros and the ratio helper's denominator
    guard handles the downstream."""
    binary = _touch_binary(tmp_path)
    _install_fake_ida(monkeypatch, output=_ida_output([]))
    _install_fake_text_size(monkeypatch, size=1024)

    provider = IdaCfgBaselineProvider()
    baseline = asyncio.run(provider.measure(binary))

    assert baseline.function_count == 0
    assert baseline.total_blocks == 0
    assert baseline.total_cyclomatic == 0
    assert baseline.total_gotos == 0
    assert baseline.text_section_size == 1024


def test_measure_tolerates_missing_metric_keys(tmp_path: Path, monkeypatch):
    """A record from a future IDAPython that drops a field must not
    crash — treat missing keys as zero (defensive read)."""
    binary = _touch_binary(tmp_path)
    records = [
        {"mc_blocks": 10},  # no cyclomatic / gotos
        {"mc_cyclomatic": 7},  # no blocks / gotos
    ]
    _install_fake_ida(monkeypatch, output=_ida_output(records))
    _install_fake_text_size(monkeypatch)

    provider = IdaCfgBaselineProvider()
    baseline = asyncio.run(provider.measure(binary))

    assert baseline.total_blocks == 10
    assert baseline.total_cyclomatic == 7
    assert baseline.total_gotos == 0


# ============================================================================
# Failure modes — each gets converted to BaselineError
# ============================================================================


def test_ida_not_found_raises_baseline_error(tmp_path: Path, monkeypatch):
    binary = _touch_binary(tmp_path)
    _install_fake_ida(
        monkeypatch, raise_exc=IdaNotFoundError("idat64.exe not at /x"),
    )

    provider = IdaCfgBaselineProvider()
    with pytest.raises(BaselineError, match="IDA missing"):
        asyncio.run(provider.measure(binary))


def test_ida_launch_filenotfound_raises_baseline_error(
    tmp_path: Path, monkeypatch,
):
    binary = _touch_binary(tmp_path)
    _install_fake_ida(
        monkeypatch, raise_exc=FileNotFoundError("script.py missing"),
    )

    provider = IdaCfgBaselineProvider()
    with pytest.raises(BaselineError, match="IDA launch"):
        asyncio.run(provider.measure(binary))


def test_ida_ok_false_raises_baseline_error(tmp_path: Path, monkeypatch):
    binary = _touch_binary(tmp_path)
    _install_fake_ida(
        monkeypatch, ok=False, output=None, error="IDA exit=7",
    )

    provider = IdaCfgBaselineProvider()
    with pytest.raises(BaselineError, match="IDA on baseline .* failed"):
        asyncio.run(provider.measure(binary))


def test_hexrays_unavailable_raises_baseline_error(
    tmp_path: Path, monkeypatch,
):
    binary = _touch_binary(tmp_path)
    payload = _ida_output([])
    payload["hexrays_available"] = False
    _install_fake_ida(monkeypatch, output=payload)

    provider = IdaCfgBaselineProvider()
    with pytest.raises(BaselineError, match="Hex-Rays unavailable"):
        asyncio.run(provider.measure(binary))


def test_text_section_missing_raises_baseline_error(
    tmp_path: Path, monkeypatch,
):
    binary = _touch_binary(tmp_path)
    _install_fake_ida(monkeypatch, output=_ida_output([]))
    _install_text_size_error(
        monkeypatch, SectionNotFoundError("no .text here"),
    )

    provider = IdaCfgBaselineProvider()
    with pytest.raises(BaselineError, match=r"PE \.text lookup failed"):
        asyncio.run(provider.measure(binary))


def test_not_a_pe_raises_baseline_error(tmp_path: Path, monkeypatch):
    binary = _touch_binary(tmp_path)
    _install_fake_ida(monkeypatch, output=_ida_output([]))
    _install_text_size_error(monkeypatch, NotAPeError("malformed header"))

    provider = IdaCfgBaselineProvider()
    with pytest.raises(BaselineError, match=r"PE \.text lookup failed"):
        asyncio.run(provider.measure(binary))


def test_pe_read_oserror_raises_baseline_error(tmp_path: Path, monkeypatch):
    binary = _touch_binary(tmp_path)
    _install_fake_ida(monkeypatch, output=_ida_output([]))
    _install_text_size_error(monkeypatch, OSError("disk gone"))

    provider = IdaCfgBaselineProvider()
    with pytest.raises(BaselineError, match="PE read IO error"):
        asyncio.run(provider.measure(binary))


# ============================================================================
# Constructor defaults
# ============================================================================


def test_default_script_path_points_to_cff_metrics():
    """Guards against accidental rename / move of the companion script."""
    provider = IdaCfgBaselineProvider()
    # The provider's private path ends at the shared script file used
    # by cff_benchmark — if someone moves it, both places need to
    # update in lockstep.
    assert provider._script_path.name == "cff_metrics.py"  # type: ignore[attr-defined]
    assert provider._script_path.exists()  # type: ignore[attr-defined]
