"""Corpus loader for benchmark input binaries.

A *corpus* is a curated set of small mini-binaries that benchmarks
run against. Kept strictly separate from ``build_testapp/`` — that
directory is for functional stress testing (15/15 strong, DLL guard
VEH smoke, driver cipher body) where the value is "does it run".
Benchmark corpora want the *opposite* property: stable inputs so
metric variance reflects defense changes, not corpus churn.

## Manifest

The corpus root carries a ``corpus.json`` manifest that declares each
entry. Paths inside the manifest are relative to the manifest's own
directory, so the corpus can be vendored or moved without edits.

```json
{
  "schema_version": 1,
  "entries": [
    {
      "name": "pure_vm",
      "binary": "bin/unprotected/pure_vm.exe",
      "tags": ["vm", "pure"]
    }
  ]
}
```

## Tags

Tags partition the corpus by protection surface. A VM benchmark reads
``corpus.with_tags("vm")``; a packer benchmark reads
``corpus.with_tags("exe")`` and skips DLL entries, etc. Tag
vocabulary is intentionally open — benchmarks assert what they need
in their own registration; manifest accepts whatever.

## Binaries

Unprotected ``.exe`` / ``.dll`` binaries live under
``bin/unprotected/`` and are **not** committed to git (too bulky,
volatile). The manifest + source under ``src/`` + ``build.bat`` is
the reproducible corpus; binaries are produced by running the build
script. ``Corpus.load`` validates that every declared binary exists
and raises a readable error otherwise.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from pydantic import BaseModel, Field, model_validator


_LOG = logging.getLogger(__name__)


CORPUS_SCHEMA_VERSION = 1


# ============================================================================
# Manifest pydantic models
# ============================================================================


class CorpusEntrySpec(BaseModel):
    """Manifest-level description of one corpus entry.

    Values are validated by pydantic at load time but not yet resolved
    to filesystem paths — that happens in ``CorpusEntry`` below.

    A single entry is one of two kinds:

    * **Buildable** — ``binary`` points to an *unprotected* input that
      the benchmark will feed through the current ``mxprotector_builder``
      to produce a fresh protected artefact. Classic flow.
    * **Pre-protected** — ``pre_protected`` points to an already-built
      protected binary (e.g. a legacy exe preserved from an older
      builder version). Build step is skipped; benchmarks that do not
      need a sidecar (pe-sieve, unicorn, OEP-reach) run directly.
      Sidecar-dependent benchmarks (CFF / VM) skip such entries with a
      "no sidecar" error — they cannot retrofit the role→section
      mapping from a bare binary.

    At least one of ``binary`` / ``pre_protected`` must be present.
    Supplying both is also legal (the pre-protected path takes
    precedence; the unprotected one stays for provenance).
    """

    name: str = Field(description="Stable identifier; used in metric evidence.")
    binary: str | None = Field(
        default=None,
        description=(
            "Path to the unprotected binary, relative to the corpus "
            "root. Feed into mxprotector_builder at benchmark time."
        ),
    )
    pre_protected: str | None = Field(
        default=None,
        description=(
            "Path to an already-protected binary, relative to the "
            "corpus root. When set, the benchmark skips the build step "
            "and analyses this file directly."
        ),
    )
    pre_sidecar: str | None = Field(
        default=None,
        description=(
            "Optional sidecar (.mxtrace.json) that accompanies "
            "``pre_protected``. Sidecar-dependent benchmarks use it "
            "instead of re-emitting one. Ignored when unset."
        ),
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Protection-surface tags (vm, cff, mixed, tls, seh, dll, …).",
    )

    @model_validator(mode="after")
    def _require_source(self) -> "CorpusEntrySpec":
        if self.binary is None and self.pre_protected is None:
            raise ValueError(
                f"corpus entry '{self.name}' has neither 'binary' nor "
                f"'pre_protected' — at least one is required"
            )
        return self


class CorpusManifest(BaseModel):
    """Top-level ``corpus.json`` schema.

    Additive changes within v1 are silently accepted (pydantic default
    ``extra='ignore'``); breaking changes bump ``schema_version``.
    """

    schema_version: int = Field(
        description="Manifest schema version; see CORPUS_SCHEMA_VERSION.",
    )
    entries: list[CorpusEntrySpec]


# ============================================================================
# Runtime types
# ============================================================================


@dataclass(frozen=True, slots=True)
class CorpusEntry:
    """Resolved corpus entry — every present path is verified at load time.

    Buildable entries carry ``unprotected_binary`` set,
    ``pre_protected_binary=None``. Pre-protected entries carry
    ``pre_protected_binary`` set (and optionally ``pre_sidecar``);
    ``unprotected_binary`` may be ``None`` for purely legacy artefacts
    whose original source is no longer available.

    Invariant: at least one of ``unprotected_binary`` /
    ``pre_protected_binary`` is non-``None`` (enforced in ``Corpus.load``).
    """

    name: str
    unprotected_binary: Path | None
    pre_protected_binary: Path | None
    pre_sidecar: Path | None
    tags: frozenset[str]

    @property
    def is_pre_protected(self) -> bool:
        """True when this entry skips the builder (legacy / preserved binary)."""
        return self.pre_protected_binary is not None


class CorpusLoadError(ValueError):
    """Raised when the corpus manifest or its referenced binaries are invalid."""


class Corpus:
    """In-memory view over a corpus directory.

    Construction is cheap (manifest parse + path exists check per
    entry); the actual binary bytes are not loaded until a benchmark
    reads them.
    """

    def __init__(self, root: Path, entries: list[CorpusEntry]) -> None:
        self._root = root
        self._entries = list(entries)
        self._by_name = {e.name: e for e in entries}

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, root: Path) -> "Corpus":
        """Load the corpus rooted at ``root`` (must contain ``corpus.json``)."""
        manifest_path = root / "corpus.json"
        if not manifest_path.exists():
            raise CorpusLoadError(
                f"corpus manifest missing: {manifest_path}. "
                "Expected structure: <root>/corpus.json + <root>/bin/unprotected/*.exe"
            )

        try:
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest = CorpusManifest.model_validate(raw)
        except Exception as e:
            raise CorpusLoadError(
                f"failed to parse {manifest_path}: {e}"
            ) from e

        if manifest.schema_version != CORPUS_SCHEMA_VERSION:
            raise CorpusLoadError(
                f"unsupported corpus schema_version={manifest.schema_version} "
                f"(this MCP reads v{CORPUS_SCHEMA_VERSION})"
            )

        seen_names: set[str] = set()
        entries: list[CorpusEntry] = []
        missing: list[str] = []

        for spec in manifest.entries:
            if spec.name in seen_names:
                raise CorpusLoadError(
                    f"duplicate corpus entry name: '{spec.name}'"
                )
            seen_names.add(spec.name)

            resolved = cls._resolve_entry_paths(root, spec, missing)
            if resolved is None:
                continue
            entries.append(resolved)

        if missing:
            raise CorpusLoadError(
                f"corpus binaries missing ({len(missing)} of "
                f"{len(manifest.entries)}):\n"
                + "\n".join(missing)
                + f"\n\nRun {root / 'build.bat'} to produce buildable "
                f"inputs, or fix the pre_protected path."
            )

        _LOG.info("loaded corpus '%s': %d entries", root, len(entries))
        return cls(root=root, entries=entries)

    # ------------------------------------------------------------------
    # Path resolution (per-entry)
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_entry_paths(
        root: Path, spec: CorpusEntrySpec, missing: list[str],
    ) -> CorpusEntry | None:
        """Verify every declared path exists and build a :class:`CorpusEntry`.

        Missing paths are appended to ``missing`` (accumulated so the
        error message lists every broken reference at once, not just
        the first). On any missing path, ``None`` is returned and the
        caller skips the entry.

        Precondition (enforced by ``CorpusEntrySpec.model_validator``):
        at least one of ``binary`` / ``pre_protected`` is set.
        """
        unprotected: Path | None = None
        pre_protected: Path | None = None
        pre_sidecar: Path | None = None
        entry_missing = False

        if spec.binary is not None:
            p = (root / spec.binary).resolve()
            if not p.exists():
                missing.append(f"  {spec.name} (binary): {p}")
                entry_missing = True
            else:
                unprotected = p

        if spec.pre_protected is not None:
            p = (root / spec.pre_protected).resolve()
            if not p.exists():
                missing.append(f"  {spec.name} (pre_protected): {p}")
                entry_missing = True
            else:
                pre_protected = p

        if spec.pre_sidecar is not None:
            p = (root / spec.pre_sidecar).resolve()
            if not p.exists():
                missing.append(f"  {spec.name} (pre_sidecar): {p}")
                entry_missing = True
            else:
                pre_sidecar = p

        if entry_missing:
            return None

        return CorpusEntry(
            name=spec.name,
            unprotected_binary=unprotected,
            pre_protected_binary=pre_protected,
            pre_sidecar=pre_sidecar,
            tags=frozenset(spec.tags),
        )

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def root(self) -> Path:
        return self._root

    def entries(self) -> list[CorpusEntry]:
        """All entries in manifest order."""
        return list(self._entries)

    def by_name(self, name: str) -> CorpusEntry:
        """Entry lookup by stable name; raises ``KeyError`` on miss."""
        return self._by_name[name]

    def tags(self) -> frozenset[str]:
        """Union of all tags across all entries."""
        return frozenset().union(*(e.tags for e in self._entries))

    def with_tags(
        self, *tags: str, match_all: bool = False
    ) -> list[CorpusEntry]:
        """Filter by tags.

        ``match_all=False`` (default): entry included if it carries at
        least one of the requested tags. ``match_all=True``: entry must
        carry every requested tag.

        Empty ``tags`` returns all entries verbatim — useful for
        benchmarks that declare ``corpus_tags=frozenset()``.
        """
        if not tags:
            return list(self._entries)
        required = frozenset(tags)
        if match_all:
            return [e for e in self._entries if required <= e.tags]
        return [e for e in self._entries if e.tags & required]

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self) -> Iterable[CorpusEntry]:
        return iter(self._entries)
