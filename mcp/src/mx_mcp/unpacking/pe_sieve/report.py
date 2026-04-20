"""Pydantic parser for pe-sieve's JSON summary.

Zero I/O — the runner reads pe-sieve's stdout (or the ``scan_report.json``
on disk) and hands it here. Keeping the parser side-effect-free lets
tests exercise every malformed / partial shape without touching disk.

## Observed schema (pe-sieve 0.4.1.1)

Real output has two top-level blocks:

```
{
  "scan_report": {
    "pid":  <int>,
    "is_64_bit": 0|1,
    "is_managed": 0|1,
    "main_image_path": "...",
    "used_reflection": 0|1,
    "scanner_version": "...",
    "scanned": {
      "total": N,
      "skipped": N,
      "modified": {
        "total": N,
        "patched": N,
        "iat_hooked": N,
        "replaced": N,
        "hdr_modified": N,
        "implanted_pe": N,
        "implanted_shc": N,
        "unreachable_file": N,
        "other": N
      },
      "errors": N
    },
    "scans": [ { "code_scan": { ... } }, ... ]
  },
  "dump_report": {
    "pid": <int>,
    "output_dir": "process_<pid>",
    "dumped": { "total": N, "dumped": N },
    "dumps": [ { "module":..., "dump_file":..., "status":1, ... }, ... ]
  }
}
```

Scope of this module: model every field the packer benchmark scores on,
ignore the rest (``extra='ignore'`` absorbs future fields). Counts
read as zero when missing — conservative from the attacker's
perspective (absence scores as "packer held").

## Key attacker signals

* ``dump_report.dumped.dumped`` — number of PE images pe-sieve
  successfully wrote to disk. **The** primary "attacker won" signal:
  non-zero means the packer failed to hide its payload.
* ``scan_report.scanned.modified.implanted_pe`` — implant-PE
  classifications; usually zero for a self-modifying packer but
  flags real hollowing.
* ``scan_report.scanned.modified.total`` — aggregate modification
  count (patched / IAT-hooked / replaced / …). Our packer modifies
  itself by design so non-zero is expected; it still tracks
  "visibility": a bigger number = more fingerprints for the
  attacker to lean on.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


_LOG = logging.getLogger(__name__)


class PesieveParseError(ValueError):
    """Raised when pe-sieve JSON cannot be parsed into the expected shape."""


# ============================================================================
# scan_report block
# ============================================================================


class ModifiedCounts(BaseModel):
    """Per-class modification counts under ``scanned.modified``.

    Fields below follow pe-sieve's actual naming (e.g. ``iat_hooked``
    past tense, ``hdr_modified``). ``extra='ignore'`` absorbs any
    future columns so a pe-sieve upgrade cannot regress parsing.
    """

    total: int = Field(default=0, ge=0)
    patched: int = Field(default=0, ge=0)
    iat_hooked: int = Field(default=0, ge=0)
    replaced: int = Field(default=0, ge=0)
    hdr_modified: int = Field(default=0, ge=0)
    implanted_pe: int = Field(default=0, ge=0)
    implanted_shc: int = Field(default=0, ge=0)
    unreachable_file: int = Field(default=0, ge=0)
    other: int = Field(default=0, ge=0)


class ScannedCounts(BaseModel):
    """``scanned`` block inside ``scan_report``."""

    total: int = Field(default=0, ge=0)
    skipped: int = Field(default=0, ge=0)
    modified: ModifiedCounts = Field(default_factory=ModifiedCounts)
    errors: int = Field(default=0, ge=0)


class ScanReport(BaseModel):
    """The full ``scan_report`` block.

    ``scans`` (the per-module detail list) is intentionally left
    as ``list[dict]`` — its shape varies per-entry (code_scan vs
    workingset_scan vs artefact_scan) and the benchmark does not yet
    score on it. Evidence carries it verbatim.
    """

    pid: int = Field(ge=0)
    is_64_bit: int = 0
    is_managed: int = 0
    main_image_path: str | None = None
    used_reflection: int = 0
    scanner_version: str | None = None
    scanned: ScannedCounts = Field(default_factory=ScannedCounts)
    scans: list[dict[str, Any]] = Field(default_factory=list)


# ============================================================================
# dump_report block
# ============================================================================


class DumpedCounts(BaseModel):
    """``dumped`` summary inside ``dump_report``.

    ``total`` is modules attempted, ``dumped`` is modules
    successfully written. The benchmark scores on ``dumped``: a
    non-zero value is the attacker's artefact count.
    """

    total: int = Field(default=0, ge=0)
    dumped: int = Field(default=0, ge=0)


class DumpEntry(BaseModel):
    """One entry inside ``dumps[]``.

    ``module`` / ``module_size`` are reported by pe-sieve as
    hex strings (``"140000000"`` / ``"38000"``) — we preserve them
    as strings, the benchmark does not yet arithmetic on them.
    """

    module: str | None = None
    module_size: str | None = None
    dump_file: str | None = None
    tags_file: str | None = None
    dump_mode: str | None = None
    is_shellcode: int = 0
    status: int = 0


class DumpReport(BaseModel):
    """The full ``dump_report`` block."""

    pid: int = Field(default=0, ge=0)
    output_dir: str | None = None
    dumped: DumpedCounts = Field(default_factory=DumpedCounts)
    dumps: list[DumpEntry] = Field(default_factory=list)


# ============================================================================
# Top-level
# ============================================================================


class PesieveReport(BaseModel):
    """Parsed pe-sieve JSON document.

    One field per top-level block. The ``dump_report`` default lets
    tests / edge cases that omit it load cleanly — benchmarks read
    ``dump_report.dumped.dumped`` which stays zero in that case.
    """

    scan_report: ScanReport
    dump_report: DumpReport = Field(default_factory=DumpReport)

    # Convenience accessors — stable flat names the benchmark layer
    # actually reads. Keeping them here means the benchmark does not
    # need to know which nested block a given counter lives under.

    @property
    def pid(self) -> int:
        return self.scan_report.pid

    @property
    def main_image_path(self) -> str | None:
        return self.scan_report.main_image_path

    @property
    def output_dir(self) -> str | None:
        return self.dump_report.output_dir

    @property
    def dumped_count(self) -> int:
        """Number of PE images pe-sieve successfully wrote to disk."""
        return self.dump_report.dumped.dumped

    @property
    def implanted_pe_count(self) -> int:
        return self.scan_report.scanned.modified.implanted_pe

    @property
    def modified_total(self) -> int:
        return self.scan_report.scanned.modified.total


# ============================================================================
# Public parser
# ============================================================================


def parse_report(payload: str | bytes | dict[str, Any]) -> PesieveReport:
    """Parse a pe-sieve JSON document into :class:`PesieveReport`.

    Accepts either raw JSON text (``str`` / ``bytes``) or an
    already-decoded ``dict``.

    Raises:
        PesieveParseError: the payload is not valid JSON, not a JSON
            object, or fails schema validation.
    """
    if isinstance(payload, (str, bytes)):
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as e:
            raise PesieveParseError(
                f"pe-sieve JSON is not parseable: {e}"
            ) from e
    else:
        data = payload

    if not isinstance(data, dict):
        raise PesieveParseError(
            f"pe-sieve JSON root must be an object, got {type(data).__name__}"
        )

    try:
        return PesieveReport.model_validate(data)
    except Exception as e:  # pydantic ValidationError subclasses ValueError
        raise PesieveParseError(
            f"pe-sieve JSON failed validation: {e}"
        ) from e


def parse_report_file(path: Path) -> PesieveReport:
    """Convenience wrapper — read ``path`` and parse its contents."""
    return parse_report(path.read_text(encoding="utf-8"))
