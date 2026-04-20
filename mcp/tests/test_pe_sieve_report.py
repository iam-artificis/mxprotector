"""Unit tests for unpacking.pe_sieve.report.

Covers every shape we expect from pe-sieve: full report, minimal
required fields only, unknown future fields (forward-compat), and
every malformed-input path (non-JSON, non-object root, missing
required ``pid``).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mx_mcp.unpacking.pe_sieve.report import (
    PesieveParseError,
    PesieveReport,
    parse_report,
    parse_report_file,
)


# ============================================================================
# Happy path — full report
# ============================================================================


_FULL_REPORT = {
    "pid": 1234,
    "main_image_path": "C:\\Users\\myzve\\test.exe",
    "output_dir": "process_1234",
    "scanned": {
        "total": 42,
        "skipped": 1,
        "modified": {
            "total": 3,
            "patched": 1,
            "iat_hooks": 1,
            "implanted": 0,
            "implanted_pe": 1,
            "implanted_shc": 0,
            "replaced": 0,
            "unreachable_file": 0,
            "other": 0,
        },
    },
    "dumped": {"dir": "process_1234", "modules": 2},
    "errors": ["module X.dll: cannot read"],
}


def test_parse_full_report_preserves_every_field():
    report = parse_report(_FULL_REPORT)
    assert isinstance(report, PesieveReport)
    assert report.pid == 1234
    assert report.main_image_path == "C:\\Users\\myzve\\test.exe"
    assert report.output_dir == "process_1234"
    assert report.scanned.total == 42
    assert report.scanned.skipped == 1
    assert report.scanned.modified.total == 3
    assert report.scanned.modified.patched == 1
    assert report.scanned.modified.iat_hooks == 1
    assert report.scanned.modified.implanted_pe == 1
    assert report.dumped.dir == "process_1234"
    assert report.dumped.modules == 2
    assert report.errors == ["module X.dll: cannot read"]


def test_parse_accepts_json_text():
    report = parse_report(json.dumps(_FULL_REPORT))
    assert report.pid == 1234


def test_parse_accepts_bytes():
    report = parse_report(json.dumps(_FULL_REPORT).encode("utf-8"))
    assert report.pid == 1234


# ============================================================================
# Minimal shape — only the required ``pid``
# ============================================================================


def test_parse_minimal_report_populates_defaults():
    report = parse_report({"pid": 99})
    assert report.pid == 99
    assert report.main_image_path is None
    assert report.output_dir is None
    assert report.scanned.total == 0
    assert report.scanned.modified.total == 0
    assert report.dumped.modules == 0
    assert report.errors == []


def test_parse_partial_scanned_block_fills_modified_defaults():
    """pe-sieve may omit ``modified`` when nothing was flagged."""
    report = parse_report({
        "pid": 99,
        "scanned": {"total": 10, "skipped": 0},
    })
    assert report.scanned.total == 10
    assert report.scanned.modified.total == 0


# ============================================================================
# Forward-compat — unknown fields silently ignored
# ============================================================================


def test_parse_ignores_unknown_top_level_field():
    report = parse_report({
        "pid": 1,
        "future_field": {"anything": "goes"},
    })
    assert report.pid == 1


def test_parse_ignores_unknown_nested_field():
    report = parse_report({
        "pid": 1,
        "scanned": {
            "total": 5,
            "future_class_of_modification": 42,
            "modified": {"unknown": 99},
        },
    })
    assert report.scanned.total == 5


# ============================================================================
# Malformed input — each failure mode raises PesieveParseError
# ============================================================================


def test_parse_invalid_json_raises():
    with pytest.raises(PesieveParseError, match="not parseable"):
        parse_report("{ not valid json")


def test_parse_non_object_root_raises():
    with pytest.raises(PesieveParseError, match="must be an object"):
        parse_report("[1, 2, 3]")


def test_parse_missing_required_pid_raises():
    with pytest.raises(PesieveParseError, match="failed validation"):
        parse_report({"scanned": {}})


def test_parse_negative_count_raises():
    """Counts are ``ge=0``; a negative value in an upstream report is a
    corruption signal, not silent-truncate territory."""
    with pytest.raises(PesieveParseError, match="failed validation"):
        parse_report({
            "pid": 1,
            "scanned": {"modified": {"patched": -1}},
        })


def test_parse_wrong_type_for_pid_raises():
    with pytest.raises(PesieveParseError, match="failed validation"):
        parse_report({"pid": "not-a-number"})


# ============================================================================
# File convenience
# ============================================================================


def test_parse_report_file_roundtrip(tmp_path: Path):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(_FULL_REPORT), encoding="utf-8")
    report = parse_report_file(path)
    assert report.pid == 1234


def test_parse_report_file_missing_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        parse_report_file(tmp_path / "no_such_file.json")
