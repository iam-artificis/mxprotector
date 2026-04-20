"""Parsers for BinDiff's textual output.

Zero I/O — callers hand us the raw stdout bytes and the ``.results``
file contents as strings. Keeping parsing side-effect-free lets
tests exercise every malformed shape without touching disk.

## Sources we parse

BinDiff 8 emits two text surfaces the benchmark consumes:

1. **stdout summary** — printed at the end of a successful diff.
   A single-line ``Similarity: X% (Confidence: Y%)`` row carries the
   two headline aggregates. The lines immediately above it carry
   function-count detail (``matched: A of B/C (primary/secondary,
   D/E non-library)``).

2. **``.results`` file** — a key-padded-with-dots table of fine-
   grained counters (basic-block matches, instruction matches,
   edge counts, …). Always present when ``--output_format`` includes
   ``log``. The structure is stable across versions we have seen.

The stdout summary is cheaper and sufficient for the scored
metrics. The ``.results`` file is parsed additionally and stored in
per-sample evidence so a reviewer can drill into why a similarity
number landed where it did.

## Scope

Only fields the P4 BinDiff benchmark currently scores on (plus a
small evidence set) are modelled. Unknown fields in the ``.results``
table are silently skipped — pydantic's ``extra='ignore'`` plus the
defensive dotted-label parser make future BinDiff versions
backward-compatible.
"""

from __future__ import annotations

import logging
import re
from typing import Mapping

from pydantic import BaseModel, Field


_LOG = logging.getLogger(__name__)


# ============================================================================
# Exceptions
# ============================================================================


class BinDiffParseError(ValueError):
    """Raised when BinDiff output cannot be parsed into the expected shape."""


# ============================================================================
# Stdout-summary parsing
#
# Example tail of a successful BinDiff 8 run:
#
#   matched: 202 of 248/264 (primary/secondary, 169/186 non-library)
#   call graph MD index: primary   0.912216
#                        secondary 0.957014
#   Similarity: 61.5239% (Confidence: 92.7311%)
#   Writing results: 0.6s
#
# The parser is tolerant of surrounding log noise (BinDiff's banner,
# setup timings) because we anchor on regexes matching the specific
# lines; non-matching lines are ignored.
# ============================================================================


class StdoutSummary(BaseModel):
    """Headline numbers lifted from BinDiff's stdout.

    All percentages are normalised to ``[0, 1]`` at parse time so
    callers never need to divide by 100 downstream. ``None`` is
    reserved for "BinDiff did not emit this line" — distinct from
    "BinDiff emitted zero".
    """

    similarity: float | None = Field(
        default=None, ge=0.0, le=1.0,
        description="BinDiff's overall similarity score, normalised to [0, 1].",
    )
    confidence: float | None = Field(
        default=None, ge=0.0, le=1.0,
        description="BinDiff's confidence in its matches, normalised to [0, 1].",
    )
    matched_functions: int | None = Field(
        default=None, ge=0,
        description="Total matched functions (library + non-library).",
    )
    primary_functions: int | None = Field(
        default=None, ge=0,
        description="Total functions in the primary input.",
    )
    secondary_functions: int | None = Field(
        default=None, ge=0,
        description="Total functions in the secondary input.",
    )


# ``Similarity: 61.5239% (Confidence: 92.7311%)`` — floats with optional
# negative sign (never observed in practice but accepted for safety).
_RE_SIMILARITY = re.compile(
    r"Similarity:\s+(?P<sim>-?\d+(?:\.\d+)?)%\s+"
    r"\(Confidence:\s+(?P<conf>-?\d+(?:\.\d+)?)%\)",
)

# ``matched: 202 of 248/264 (primary/secondary, 169/186 non-library)``
_RE_MATCHED = re.compile(
    r"matched:\s+(?P<matched>\d+)\s+of\s+"
    r"(?P<primary>\d+)\s*/\s*(?P<secondary>\d+)\s*\(primary/secondary",
)


def parse_stdout_summary(stdout: str) -> StdoutSummary:
    """Extract headline numbers from BinDiff's stdout.

    Never raises — fields that cannot be located are left ``None``
    in the returned :class:`StdoutSummary`. BinDiff suppresses the
    ``Similarity`` line when it cannot diff (e.g. one side had no
    non-library functions), and callers must handle that case
    anyway; surfacing it as ``None`` keeps the benchmark layer
    fail-closed without a second exception type.
    """
    summary = StdoutSummary()

    m = _RE_SIMILARITY.search(stdout)
    if m:
        summary = summary.model_copy(update={
            "similarity": float(m.group("sim")) / 100.0,
            "confidence": float(m.group("conf")) / 100.0,
        })

    m = _RE_MATCHED.search(stdout)
    if m:
        summary = summary.model_copy(update={
            "matched_functions":   int(m.group("matched")),
            "primary_functions":   int(m.group("primary")),
            "secondary_functions": int(m.group("secondary")),
        })

    return summary


# ============================================================================
# .results file parsing
#
# Each interesting line looks like:
#
#   Basic Block Matches (Non-Library)...........................:    221
#
# That is: ``<label>`` padded with dots to a fixed column, then
# ``: <number>``. We normalise the label (dots + whitespace) and
# index by exact string. The leading free-text preamble plus the
# trailing matching-heuristic breakdown are ignored — neither is
# scored on today.
# ============================================================================


_RE_KV_LINE = re.compile(
    r"^\s*(?P<key>.+?)\s*\.{2,}\s*:\s*(?P<value>-?\d+)\s*$",
)


class ResultsStats(BaseModel):
    """Key counters lifted from ``<primary>_vs_<secondary>.results``.

    Fields mirror BinDiff's own label names lower-cased with spaces
    replaced by underscores. Defaults to 0 absorb "line not present
    in this file" the same way pe-sieve's schema does.
    """

    basic_block_matches_non_library: int = Field(default=0, ge=0)
    basic_blocks_primary_non_library: int = Field(default=0, ge=0)
    basic_blocks_secondary_non_library: int = Field(default=0, ge=0)
    function_matches_non_library: int = Field(default=0, ge=0)
    functions_primary_non_library: int = Field(default=0, ge=0)
    functions_secondary_non_library: int = Field(default=0, ge=0)
    instruction_matches_non_library: int = Field(default=0, ge=0)
    instructions_primary_non_library: int = Field(default=0, ge=0)
    instructions_secondary_non_library: int = Field(default=0, ge=0)

    # Full breakdown keyed by normalised-label stays as a dict so
    # evidence can carry every line BinDiff emitted without
    # forcing the schema to enumerate them all.
    all_counters: dict[str, int] = Field(default_factory=dict)


# Label → field-name mapping for the structured rows we care about.
# Everything else lands in ``all_counters`` only.
_LABEL_TO_FIELD: Mapping[str, str] = {
    "Basic Block Matches (Non-Library)":        "basic_block_matches_non_library",
    "Basic Blocks Primary (Non-Library)":       "basic_blocks_primary_non_library",
    "Basic Blocks Secondary (Non-Library)":     "basic_blocks_secondary_non_library",
    "Function Matches (Non-Library)":           "function_matches_non_library",
    "Functions Primary (Non-Library)":          "functions_primary_non_library",
    "Functions Secondary (Non-Library)":        "functions_secondary_non_library",
    "Instruction Matches (Non-Library)":        "instruction_matches_non_library",
    "Instructions Primary (Non-Library)":       "instructions_primary_non_library",
    "Instructions Secondary (Non-Library)":     "instructions_secondary_non_library",
}


def parse_results_file(contents: str) -> ResultsStats:
    """Parse a BinDiff ``.results`` file payload into :class:`ResultsStats`.

    Never raises on partial input — unknown keys populate only the
    ``all_counters`` dict; missing structured fields keep their 0
    defaults. The only hard failure path is a negative count (not
    observed in practice but rejected by the pydantic model so a
    malformed upstream change fails loudly).

    Raises:
        BinDiffParseError: on schema-level validation failure
            (currently only negative counts).
    """
    counters: dict[str, int] = {}
    structured: dict[str, int] = {}

    for line in contents.splitlines():
        m = _RE_KV_LINE.match(line)
        if not m:
            continue
        key = m.group("key").strip()
        try:
            value = int(m.group("value"))
        except ValueError:
            continue
        counters[key] = value
        field_name = _LABEL_TO_FIELD.get(key)
        if field_name is not None:
            structured[field_name] = value

    try:
        return ResultsStats(**structured, all_counters=counters)
    except Exception as e:  # pydantic ValidationError subclasses ValueError
        raise BinDiffParseError(
            f"BinDiff .results contents failed schema validation: {e}"
        ) from e


# ============================================================================
# Combined report
# ============================================================================


class BinDiffReport(BaseModel):
    """Parsed view of one BinDiff run.

    Combines the stdout summary (headline similarity / confidence /
    function counts) with the ``.results`` table (per-metric
    counters). Either half can be absent — the attributes that come
    from a missing source remain at their defaults so consumers can
    read uniformly.
    """

    stdout: StdoutSummary = Field(default_factory=StdoutSummary)
    results: ResultsStats = Field(default_factory=ResultsStats)

    # ------------------------------------------------------------------
    # Convenience accessors — stable flat names the benchmark reads
    # ------------------------------------------------------------------

    @property
    def similarity(self) -> float | None:
        """Overall similarity on [0, 1], or None when BinDiff did not emit it."""
        return self.stdout.similarity

    @property
    def confidence(self) -> float | None:
        return self.stdout.confidence

    @property
    def function_match_ratio(self) -> float | None:
        """Matched functions divided by the mean of the two sides.

        Returns ``None`` when BinDiff did not report function counts
        (extremely rare — typically a BinDiff crash).
        """
        s = self.stdout
        if (s.matched_functions is None
                or s.primary_functions is None
                or s.secondary_functions is None):
            return None
        denom = (s.primary_functions + s.secondary_functions) / 2.0
        if denom <= 0:
            return None
        return s.matched_functions / denom


def parse_report(
    *, stdout: str, results_file_contents: str | None = None,
) -> BinDiffReport:
    """Combine stdout and (optional) ``.results`` contents into a report.

    Either input may be empty — the corresponding half of the report
    then stays at its defaults. This is deliberate: we prefer to
    return a partially-populated report over raising, because the
    benchmark layer already treats ``similarity is None`` as the
    signal to surface a per-entry error without a second exception
    type.
    """
    summary = parse_stdout_summary(stdout or "")
    stats = (
        parse_results_file(results_file_contents)
        if results_file_contents
        else ResultsStats()
    )
    return BinDiffReport(stdout=summary, results=stats)
