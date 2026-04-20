"""Unit tests for reporting.charts.base — ABC + registry."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import BaseModel

from mx_mcp.reporting.charts import base as charts_base
from mx_mcp.reporting.charts.base import (
    IChartRenderer,
    all_chart_renderers,
    register_chart,
)


@pytest.fixture(autouse=True)
def _clean_registry():
    saved = list(charts_base._REGISTRY)
    charts_base._REGISTRY.clear()
    try:
        yield
    finally:
        charts_base._REGISTRY.clear()
        charts_base._REGISTRY.extend(saved)


class _Dummy(BaseModel):
    x: int = 1


class _StubRenderer(IChartRenderer):
    name = "stub"
    description = "stub"
    input_schema = _Dummy

    def is_available(self) -> bool:  # pragma: no cover — contract only
        return True

    def render(self, data, output_path: Path) -> Path:  # pragma: no cover
        return output_path


def test_register_chart_adds_to_registry():
    assert all_chart_renderers() == []
    register_chart(_StubRenderer)
    assert all_chart_renderers() == [_StubRenderer]


def test_register_chart_duplicate_name_rejected():
    register_chart(_StubRenderer)

    class Dup(IChartRenderer):
        name = "stub"
        description = "dup"
        input_schema = _Dummy

        def is_available(self) -> bool:  # pragma: no cover
            return True

        def render(self, data, output_path: Path) -> Path:  # pragma: no cover
            return output_path

    with pytest.raises(ValueError, match="name collision"):
        register_chart(Dup)


def test_register_chart_rejects_non_subclass():
    class NotARenderer:
        name = "nope"
        description = "x"
        input_schema = _Dummy

    with pytest.raises(TypeError, match="must subclass IChartRenderer"):
        register_chart(NotARenderer)  # type: ignore[arg-type]


def test_register_chart_rejects_missing_attrs():
    class MissingName(IChartRenderer):
        description = "no name"
        input_schema = _Dummy

        def is_available(self) -> bool:  # pragma: no cover
            return True

        def render(self, data, output_path: Path) -> Path:  # pragma: no cover
            return output_path

    with pytest.raises(TypeError, match="missing required class attr"):
        register_chart(MissingName)  # type: ignore[misc]
