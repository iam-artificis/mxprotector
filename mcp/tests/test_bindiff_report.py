"""Unit tests for diffing.bindiff.report.

Separates pure-logic tests (regex / dotted-label parsing) from
round-trip tests that use a verbatim BinDiff 8 capture. The
verbatim samples guard against BinDiff upgrades silently changing
output shape — any real drift surfaces as a test failure.
"""

from __future__ import annotations

import pytest

from mx_mcp.diffing.bindiff.report import (
    BinDiffParseError,
    BinDiffReport,
    ResultsStats,
    StdoutSummary,
    parse_report,
    parse_results_file,
    parse_stdout_summary,
)


# ============================================================================
# Verbatim samples (from a live BinDiff 8 run on the mxprotector corpus)
# ============================================================================


_REAL_STDOUT = """\
BinDiff 8 (@568181968, Sep 25 2023), (c)2004-2011 zynamics GmbH, (c)2011-2023 Google LLC.
Setup: 0.0s
primary:   pure_cff_a: 248 functions, 37 calls
secondary: pure_cff_b: 264 functions, 36 calls
Matching: 0.0s
matched: 202 of 248/264 (primary/secondary, 169/186 non-library)
call graph MD index: primary   0.912216
                     secondary 0.957014
Similarity: 61.5239% (Confidence: 92.7311%)
Writing results: 0.6s
"""


_REAL_RESULTS = """\
pure_cff_a
pure_cff_b
call graph1 MD index 0.9122162095471092
call graph2 MD index 0.9570138327261732

 --------- statistics ---------
Basic Block Matches (Library)...............................:      0
Basic Block Matches (Non-Library)...........................:    221
Basic Blocks Primary (Library)..............................:      0
Basic Blocks Primary (Non-Library)..........................:    343
Basic Blocks Secondary (Library)............................:      0
Basic Blocks Secondary (Non-Library)........................:    435
Function Matches (Library)..................................:     78
Function Matches (Non-Library)..............................:    124
Functions Primary (Library).................................:     79
Functions Primary (Non-Library).............................:    169
Functions Secondary (Library)...............................:     78
Functions Secondary (Non-Library)...........................:    186
Instruction Matches (Library)...............................:      0
Instruction Matches (Non-Library)...........................:   2238
Instructions Primary (Library)..............................:      0
Instructions Primary (Non-Library)..........................:   3139
Instructions Secondary (Library)............................:      0
Instructions Secondary (Non-Library)........................:   3752

basicBlock: MD index matching (bottom up)...................:      1
basicBlock: MD index matching (top down)....................:     73
basicBlock: edges MD index (top down).......................:     18
"""


# ============================================================================
# parse_stdout_summary
# ============================================================================


def test_parse_real_stdout_extracts_all_headline_fields():
    summary = parse_stdout_summary(_REAL_STDOUT)
    assert isinstance(summary, StdoutSummary)
    # Percentages normalised to [0, 1].
    assert summary.similarity == pytest.approx(0.615239, abs=1e-6)
    assert summary.confidence == pytest.approx(0.927311, abs=1e-6)
    # Function counts match the "matched: X of Y/Z" line.
    assert summary.matched_functions == 202
    assert summary.primary_functions == 248
    assert summary.secondary_functions == 264


def test_parse_stdout_with_missing_similarity_line():
    """BinDiff can skip the Similarity line (e.g. primary had no
    non-library functions). Other fields still parse."""
    stdout = (
        "BinDiff 8\n"
        "matched: 0 of 5/7 (primary/secondary, 0/0 non-library)\n"
    )
    summary = parse_stdout_summary(stdout)
    assert summary.similarity is None
    assert summary.confidence is None
    assert summary.matched_functions == 0
    assert summary.primary_functions == 5
    assert summary.secondary_functions == 7


def test_parse_empty_stdout_returns_empty_summary():
    summary = parse_stdout_summary("")
    assert summary.similarity is None
    assert summary.matched_functions is None


def test_parse_stdout_tolerates_surrounding_noise():
    """A banner, log timings, warnings — the regex anchors on the
    specific lines we care about; anything else is ignored."""
    stdout = (
        "Random warning from matplotlib\n"
        "Similarity: 12.3456% (Confidence: 98.7654%)\n"
        "Another unrelated log line\n"
    )
    summary = parse_stdout_summary(stdout)
    assert summary.similarity == pytest.approx(0.123456, abs=1e-6)
    assert summary.confidence == pytest.approx(0.987654, abs=1e-6)


# ============================================================================
# parse_results_file
# ============================================================================


def test_parse_real_results_populates_structured_fields():
    stats = parse_results_file(_REAL_RESULTS)
    assert isinstance(stats, ResultsStats)
    assert stats.basic_block_matches_non_library == 221
    assert stats.basic_blocks_primary_non_library == 343
    assert stats.basic_blocks_secondary_non_library == 435
    assert stats.function_matches_non_library == 124
    assert stats.functions_primary_non_library == 169
    assert stats.functions_secondary_non_library == 186
    assert stats.instruction_matches_non_library == 2238


def test_parse_real_results_preserves_all_counters():
    """Unknown (un-mapped) counters end up in ``all_counters`` so
    evidence carries the full breakdown without schema churn."""
    stats = parse_results_file(_REAL_RESULTS)
    # A row present in the real file but *not* in our structured
    # mapping should still be accessible.
    assert stats.all_counters["basicBlock: MD index matching (top down)"] == 73
    # And the structured row is also duplicated in all_counters.
    assert stats.all_counters["Function Matches (Non-Library)"] == 124


def test_parse_results_empty_returns_defaults():
    stats = parse_results_file("")
    assert stats.function_matches_non_library == 0
    assert stats.all_counters == {}


def test_parse_results_ignores_non_kv_lines():
    """The preamble and blank lines must not break parsing."""
    stats = parse_results_file(
        "pure_cff_a\n"
        "pure_cff_b\n"
        "some free text\n"
        "\n"
        "Function Matches (Non-Library)....: 5\n"
    )
    assert stats.function_matches_non_library == 5


def test_parse_results_tolerates_variable_dot_count():
    """BinDiff right-justifies values; dot count varies per label.
    The parser must accept any run of two or more dots."""
    stats = parse_results_file(
        "Function Matches (Non-Library)....:    12\n"
        "Functions Primary (Non-Library)..........................:    20\n"
    )
    assert stats.function_matches_non_library == 12
    assert stats.functions_primary_non_library == 20


def test_parse_results_rejects_negative_count():
    with pytest.raises(BinDiffParseError, match="failed schema validation"):
        parse_results_file(
            "Function Matches (Non-Library)...: -1\n"
        )


# ============================================================================
# parse_report — combined
# ============================================================================


def test_parse_report_combines_both_sources():
    report = parse_report(
        stdout=_REAL_STDOUT, results_file_contents=_REAL_RESULTS,
    )
    assert isinstance(report, BinDiffReport)
    assert report.similarity == pytest.approx(0.615239, abs=1e-6)
    assert report.results.function_matches_non_library == 124


def test_parse_report_accepts_stdout_only():
    """``.results`` may be absent if BinDiff crashed after stdout
    but before writing the log. We still return a partially-
    populated report so the benchmark records what it can."""
    report = parse_report(stdout=_REAL_STDOUT)
    assert report.similarity == pytest.approx(0.615239, abs=1e-6)
    assert report.results.function_matches_non_library == 0


def test_parse_report_both_empty_returns_defaults():
    report = parse_report(stdout="", results_file_contents=None)
    assert report.similarity is None
    assert report.results.function_matches_non_library == 0


# ============================================================================
# Convenience accessors
# ============================================================================


def test_function_match_ratio_computed_from_stdout():
    report = parse_report(stdout=_REAL_STDOUT)
    # 202 matched / ((248 + 264) / 2) = 202 / 256 ≈ 0.789
    assert report.function_match_ratio == pytest.approx(202 / 256, abs=1e-6)


def test_function_match_ratio_none_when_counts_missing():
    report = parse_report(stdout="Similarity: 50.0% (Confidence: 90.0%)")
    assert report.similarity == pytest.approx(0.5)
    # matched/total counts not in stdout → ratio is None.
    assert report.function_match_ratio is None


def test_function_match_ratio_none_on_zero_denominator():
    """Degenerate case: both inputs had 0 functions. Ratio cannot
    be computed without dividing by zero."""
    report = parse_report(
        stdout=(
            "matched: 0 of 0/0 (primary/secondary, 0/0 non-library)\n"
            "Similarity: 100.0% (Confidence: 0.0%)\n"
        ),
    )
    assert report.function_match_ratio is None
