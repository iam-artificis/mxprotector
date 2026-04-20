"""Pydantic parser for pe-sieve's JSON summary.

Zero I/O — the runner reads the file and hands its contents (bytes or
str) to :func:`parse_report`. Keeping the parser side-effect-free
lets the tests exercise every malformed / partial shape without
touching disk.

## Schema scope

pe-sieve emits a rich JSON document. We model only the fields the
packer benchmark actually needs; ``extra='ignore'`` (pydantic default)
means future pe-sieve versions that grow new fields do not regress
callers. If a field the benchmark does score on later disappears,
the default value (0 / empty / None) guarantees a safe low-noise
result rather than crashing.

## Fields modelled

* ``pid`` — scan target.
* ``main_image_path`` — the image pe-sieve identified as the main
  module (provenance).
* ``output_dir`` — relative directory where pe-sieve wrote its
  artefacts for this scan.
* ``scanned.modified.*`` — counts pe-sieve assigns after analysis.
  ``implanted_pe`` is the "clean dump possible" signal; ``patched``
  / ``iat_hooks`` / ``replaced`` are finer-grained.
* ``dumped.modules`` — how many PE images pe-sieve wrote to the
  output dir. Nonzero = the attacker has a usable artefact.
* ``errors`` — pe-sieve's own per-module error strings. Surface to
  the caller verbatim.
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
# Nested count blocks
# ============================================================================


class ModifiedCounts(BaseModel):
    """Per-class modification counts under ``scanned.modified``.

    Every field is optional at the JSON level; older pe-sieve versions
    omit ones we care about. The default-zero policy means missing
    fields read as "no modifications of this kind" — a conservative
    stance from the attacker's point of view (absence is reported as
    "packer held"), and the benchmark never branches on ``None``.
    """

    total: int = Field(default=0, ge=0)
    patched: int = Field(default=0, ge=0)
    iat_hooks: int = Field(default=0, ge=0)
    implanted: int = Field(default=0, ge=0)
    implanted_pe: int = Field(default=0, ge=0)
    implanted_shc: int = Field(default=0, ge=0)
    replaced: int = Field(default=0, ge=0)
    unreachable_file: int = Field(default=0, ge=0)
    other: int = Field(default=0, ge=0)


class ScannedCounts(BaseModel):
    """``scanned`` block — totals + the nested modification breakdown."""

    total: int = Field(default=0, ge=0)
    skipped: int = Field(default=0, ge=0)
    modified: ModifiedCounts = Field(default_factory=ModifiedCounts)


class DumpedCounts(BaseModel):
    """``dumped`` block — where pe-sieve wrote artefacts and how many.

    ``dir`` is *usually* a relative path (``process_<pid>``) but
    pe-sieve sometimes fills in absolute — we accept both verbatim
    and let the runner resolve against its workdir.
    """

    dir: str | None = None
    modules: int = Field(default=0, ge=0)


# ============================================================================
# Top-level report
# ============================================================================


class PesieveReport(BaseModel):
    """Parsed pe-sieve JSON summary.

    Only fields consumed by the benchmark or by human post-mortem are
    modelled. See module docstring for the intentional-gaps list.
    """

    pid: int = Field(ge=0)
    main_image_path: str | None = None
    output_dir: str | None = None
    scanned: ScannedCounts = Field(default_factory=ScannedCounts)
    dumped: DumpedCounts = Field(default_factory=DumpedCounts)
    errors: list[str] = Field(default_factory=list)


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
    """Convenience wrapper — read ``path`` and parse its contents.

    Raises ``FileNotFoundError`` or :class:`PesieveParseError`.
    """
    return parse_report(path.read_text(encoding="utf-8"))
