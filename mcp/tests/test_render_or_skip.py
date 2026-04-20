"""Unit tests for reporting.render_or_skip.

Exercises every branch of the ``(resolved_path, note)`` decision
table: no-op, backend-missing, render-success, render-exception.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel

from mx_mcp.reporting.render_or_skip import try_render_png


class _Dummy(BaseModel):
    x: int = 1


class _AlwaysSuccess:
    def is_available(self) -> bool:
        return True

    def render(self, data, output_path: Path) -> Path:
        output_path.write_bytes(b"FAKE PNG")
        return output_path.resolve()


class _Unavailable:
    def is_available(self) -> bool:
        return False

    def render(self, data, output_path: Path) -> Path:  # pragma: no cover
        raise AssertionError("should not be called")


class _Raiser:
    def is_available(self) -> bool:
        return True

    def render(self, data, output_path: Path) -> Path:
        raise ValueError("simulated render error")


def test_none_output_path_short_circuits(tmp_path: Path):
    path, note = try_render_png(_AlwaysSuccess(), _Dummy(), None)
    assert path is None and note is None


def test_backend_unavailable_returns_install_hint(tmp_path: Path):
    path, note = try_render_png(_Unavailable(), _Dummy(), str(tmp_path / "out.png"))
    assert path is None
    assert note is not None
    assert "matplotlib" in note and "pip install" in note


def test_render_success_returns_path(tmp_path: Path):
    target = tmp_path / "out.png"
    path, note = try_render_png(_AlwaysSuccess(), _Dummy(), str(target))
    assert note is None
    assert path is not None
    # The helper returns the path the renderer wrote to — resolved /
    # absolute — and the file exists.
    assert Path(path).exists()


def test_render_exception_caught_and_surfaced(tmp_path: Path):
    path, note = try_render_png(_Raiser(), _Dummy(), str(tmp_path / "out.png"))
    assert path is None
    assert note is not None
    assert "ValueError" in note
    assert "simulated render error" in note
