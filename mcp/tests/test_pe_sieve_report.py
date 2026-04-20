"""Unit tests for unpacking.pe_sieve.report.

Exercises the real pe-sieve 0.4.x schema (scan_report + dump_report
blocks) plus every degradation mode: full report, minimal required
fields, unknown future fields (forward-compat), malformed input.

A real pe-sieve 0.4.1.1 capture is included verbatim below — the
parser must round-trip it losslessly and the convenience accessors
must pick out the attacker-relevant counters unchanged.
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
# Fixtures
# ============================================================================


# Real pe-sieve 0.4.1.1 output — captured from a live run against a
# packed mxprotector binary. Kept verbatim so we notice any schema
# drift on upgrade.
_REAL_REPORT = {
    "scan_report": {
        "pid": 64196,
        "is_64_bit": 1,
        "is_managed": 0,
        "main_image_path": "C:\\temp\\t.mx.exe",
        "used_reflection": 0,
        "scanner_version": "0.4.1.1",
        "scanned": {
            "total": 5,
            "skipped": 0,
            "modified": {
                "total": 1,
                "patched": 1,
                "iat_hooked": 0,
                "replaced": 0,
                "hdr_modified": 0,
                "implanted_pe": 0,
                "implanted_shc": 0,
                "unreachable_file": 0,
                "other": 0,
            },
            "errors": 0,
        },
        "scans": [
            {
                "code_scan": {
                    "status": 1,
                    "module": "140000000",
                    "module_size": "37000",
                    "module_file": "C:\\temp\\t.mx.exe",
                    "scanned_sections": 3,
                    "patches": 422,
                },
            },
        ],
    },
    "dump_report": {
        "pid": 64196,
        "output_dir": "process_64196",
        "dumped": {"total": 1, "dumped": 1},
        "dumps": [
            {
                "module": "140000000",
                "module_size": "37000",
                "dump_file": "140000000.t.mx.exe",
                "tags_file": "140000000.t.mx.exe.tag",
                "dump_mode": "REALIGNED",
                "is_shellcode": 0,
                "status": 1,
            },
        ],
    },
}


# ============================================================================
# Round-trip — real pe-sieve output parses losslessly
# ============================================================================


def test_parse_real_report_populates_nested_blocks():
    report = parse_report(_REAL_REPORT)
    assert isinstance(report, PesieveReport)
    assert report.scan_report.pid == 64196
    assert report.scan_report.scanner_version == "0.4.1.1"
    assert report.scan_report.scanned.total == 5
    assert report.scan_report.scanned.modified.patched == 1
    assert report.dump_report.output_dir == "process_64196"
    assert report.dump_report.dumped.dumped == 1
    assert len(report.dump_report.dumps) == 1
    assert report.dump_report.dumps[0].status == 1
    assert report.dump_report.dumps[0].dump_mode == "REALIGNED"


def test_convenience_accessors_flatten_nested_fields():
    """The benchmark reads ``dumped_count`` / ``implanted_pe_count`` /
    ``modified_total`` directly without knowing which sub-block owns
    each counter."""
    report = parse_report(_REAL_REPORT)
    assert report.pid == 64196
    assert report.dumped_count == 1
    assert report.implanted_pe_count == 0
    assert report.modified_total == 1
    assert report.main_image_path == "C:\\temp\\t.mx.exe"
    assert report.output_dir == "process_64196"


def test_parse_accepts_json_text():
    report = parse_report(json.dumps(_REAL_REPORT))
    assert report.pid == 64196


def test_parse_accepts_bytes():
    report = parse_report(json.dumps(_REAL_REPORT).encode("utf-8"))
    assert report.pid == 64196


# ============================================================================
# Minimal + partial shapes
# ============================================================================


def test_parse_scan_report_only_leaves_dump_empty():
    """Minimum the parser accepts: just ``scan_report.pid``. Absent
    ``dump_report`` parses as empty defaults — convenience accessors
    read zero."""
    report = parse_report({"scan_report": {"pid": 7}})
    assert report.pid == 7
    assert report.dumped_count == 0
    assert report.dump_report.dumps == []


def test_partial_modified_block_fills_defaults():
    """pe-sieve sometimes omits ``modified`` keys it would emit as 0."""
    report = parse_report({
        "scan_report": {
            "pid": 1,
            "scanned": {"total": 2, "modified": {"total": 0}},
        },
    })
    assert report.modified_total == 0
    assert report.scan_report.scanned.modified.iat_hooked == 0


# ============================================================================
# Forward-compat — unknown fields silently ignored
# ============================================================================


def test_parse_ignores_unknown_top_level_field():
    report = parse_report({
        "scan_report": {"pid": 1},
        "future_field": {"anything": "goes"},
    })
    assert report.pid == 1


def test_parse_ignores_unknown_nested_field():
    report = parse_report({
        "scan_report": {
            "pid": 1,
            "scanned": {
                "total": 5,
                "future_class_of_modification": 42,
                "modified": {"unknown_counter": 99},
            },
        },
    })
    assert report.scan_report.scanned.total == 5


# ============================================================================
# Malformed input — each failure mode raises PesieveParseError
# ============================================================================


def test_parse_invalid_json_raises():
    with pytest.raises(PesieveParseError, match="not parseable"):
        parse_report("{ not valid json")


def test_parse_non_object_root_raises():
    with pytest.raises(PesieveParseError, match="must be an object"):
        parse_report("[1, 2, 3]")


def test_parse_missing_scan_report_raises():
    with pytest.raises(PesieveParseError, match="failed validation"):
        parse_report({"dump_report": {}})


def test_parse_missing_required_pid_raises():
    with pytest.raises(PesieveParseError, match="failed validation"):
        parse_report({"scan_report": {}})


def test_parse_negative_count_raises():
    with pytest.raises(PesieveParseError, match="failed validation"):
        parse_report({
            "scan_report": {
                "pid": 1,
                "scanned": {"modified": {"patched": -1}},
            },
        })


def test_parse_wrong_type_for_pid_raises():
    with pytest.raises(PesieveParseError, match="failed validation"):
        parse_report({"scan_report": {"pid": "not-a-number"}})


# ============================================================================
# File convenience
# ============================================================================


def test_parse_report_file_roundtrip(tmp_path: Path):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(_REAL_REPORT), encoding="utf-8")
    report = parse_report_file(path)
    assert report.pid == 64196


def test_parse_report_file_missing_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        parse_report_file(tmp_path / "no_such_file.json")
