"""Unit tests for ``anti_analysis.detector_base``.

Covers:

1. ``DetectionResult.informative`` flag respects ``skipped``.
2. ``register_detector`` validates contract (subclass, attrs, name).
3. Decorator chain returns the class.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

import pytest

from mx_mcp.anti_analysis.detector_base import (
    DetectionResult,
    IDetector,
    register_detector,
)
from mx_mcp.anti_analysis.detector_base import _REGISTRY as _DETECTOR_REGISTRY


# ============================================================================
# DetectionResult
# ============================================================================


def test_detection_result_informative_flag_respects_skipped():
    detected = DetectionResult(tool="x", detected=True)
    not_detected = DetectionResult(tool="x", detected=False)
    skipped = DetectionResult(tool="x", detected=False, skipped=True)

    assert detected.informative is True
    assert not_detected.informative is True
    assert skipped.informative is False


def test_detection_result_evidence_default_is_empty():
    r = DetectionResult(tool="x", detected=False)
    assert r.evidence == {}
    assert r.error is None
    assert r.skip_reason is None


# ============================================================================
# Registration
# ============================================================================


def _stash_registry():
    return list(_DETECTOR_REGISTRY)


def _restore_registry(snapshot):
    _DETECTOR_REGISTRY.clear()
    _DETECTOR_REGISTRY.extend(snapshot)


def test_register_detector_adds_to_registry():
    snap = _stash_registry()
    try:
        @register_detector
        class _D(IDetector):
            name: ClassVar[str] = "test_register_unique"
            description: ClassVar[str] = "x"
            targets: ClassVar[tuple[str, ...]] = ("x",)

            async def detect(self, p: Path) -> DetectionResult:
                return DetectionResult(tool=self.name, detected=False)

        assert _D in _DETECTOR_REGISTRY
    finally:
        _restore_registry(snap)


def test_register_detector_rejects_non_subclass():
    class _NotA:
        name = "n"
        description = "d"
        targets = ()

    with pytest.raises(TypeError, match="must subclass IDetector"):
        register_detector(_NotA)  # type: ignore[arg-type]


def test_register_detector_rejects_missing_attr():
    snap = _stash_registry()
    try:
        with pytest.raises(TypeError, match="missing required class attr"):
            @register_detector
            class _D(IDetector):
                name: ClassVar[str] = "test_missing"
                description: ClassVar[str] = "x"
                # targets missing

                async def detect(self, p: Path) -> DetectionResult:  # pragma: no cover
                    return DetectionResult(tool=self.name, detected=False)
    finally:
        _restore_registry(snap)


def test_register_detector_rejects_duplicate_name():
    snap = _stash_registry()
    try:
        @register_detector
        class _D1(IDetector):
            name: ClassVar[str] = "test_dup_aaaa"
            description: ClassVar[str] = "x"
            targets: ClassVar[tuple[str, ...]] = ("x",)

            async def detect(self, p: Path) -> DetectionResult:
                return DetectionResult(tool=self.name, detected=False)

        with pytest.raises(ValueError, match="name collision"):
            @register_detector
            class _D2(IDetector):
                name: ClassVar[str] = "test_dup_aaaa"
                description: ClassVar[str] = "x"
                targets: ClassVar[tuple[str, ...]] = ("y",)

                async def detect(self, p: Path) -> DetectionResult:  # pragma: no cover
                    return DetectionResult(tool=self.name, detected=False)
    finally:
        _restore_registry(snap)
