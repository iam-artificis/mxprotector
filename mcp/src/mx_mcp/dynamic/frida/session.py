"""Per-process MCP session + Frida lifecycle.

Exposes ``Session`` with:

- ``workspace_root`` — project root used for resolving relative paths
  in tool inputs. Detected by walking up from CWD looking for a
  ``.mcp.json`` / ``CMakeLists.txt`` / ``.git`` marker.
- ``device()`` — lazy-init Frida local device.
- ``compose_script()`` — build the final probe JS from ``_loader.js``
  plus the enabled probe files.
- ``run_probed()`` — spawn a binary under Frida, load the composed
  script, collect events until the process exits or the timeout
  elapses, return a ``ProbedRun``.

ABC-free for now — a second Session implementation is not yet visible
on the road map. When/if a non-Frida "Session" is introduced (e.g. for
Unicorn-based dynamic emulation), the shared surface lifts into
``common/``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

import frida

from mx_mcp.common.events import Event, parse_event, summarize


_LOG = logging.getLogger(__name__)

_PROBES_DIR = Path(__file__).parent / "probes"

_WORKSPACE_MARKERS = frozenset({".mcp.json", "CMakeLists.txt", ".git"})


@dataclass(frozen=True, slots=True)
class ProbedRun:
    exit_code: int | None
    duration_ms: int
    timed_out: bool
    events: list[Event]
    events_summary: dict[str, int]


def _find_workspace_root(start: Path) -> Path:
    current = start.resolve()
    while True:
        if any((current / m).exists() for m in _WORKSPACE_MARKERS):
            return current
        if current.parent == current:
            return start.resolve()
        current = current.parent


class Session:
    """Shared per-server state. Not thread-safe by design — the MCP
    server is single-event-loop."""

    def __init__(self, workspace_root: Path | None = None) -> None:
        if workspace_root is None:
            workspace_root = _find_workspace_root(Path.cwd())
        self.workspace_root = workspace_root.resolve()
        self._device: frida.core.Device | None = None
        _LOG.info("workspace root: %s", self.workspace_root)

    # ------------------------------------------------------------------
    # Frida device
    # ------------------------------------------------------------------

    def device(self) -> frida.core.Device:
        if self._device is None:
            self._device = frida.get_local_device()
        return self._device

    # ------------------------------------------------------------------
    # Probe composition
    # ------------------------------------------------------------------

    def compose_script(
        self,
        enabled_probes: Sequence[str],
        config_extras: dict[str, Any] | None = None,
    ) -> str:
        """Return the full JS source: ``_loader.js`` + enabled probes."""
        config: dict[str, Any] = {"probes": list(enabled_probes)}
        if config_extras:
            config.update(config_extras)

        loader_text = (_PROBES_DIR / "_loader.js").read_text(encoding="utf-8")
        loader_text = loader_text.replace("__MX_CONFIG__", json.dumps(config))

        parts: list[str] = [loader_text]
        for name in enabled_probes:
            probe_path = _PROBES_DIR / f"{name}.js"
            if not probe_path.exists():
                raise FileNotFoundError(
                    f"probe '{name}' not found at {probe_path}"
                )
            parts.append(probe_path.read_text(encoding="utf-8"))

        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Spawn + trace
    # ------------------------------------------------------------------

    async def run_probed(
        self,
        binary: Path,
        *,
        enabled_probes: Sequence[str],
        config_extras: dict[str, Any] | None = None,
        args: Sequence[str] = (),
        timeout_s: float = 30.0,
    ) -> ProbedRun:
        """Spawn ``binary`` under Frida with ``enabled_probes``.

        Frida's local device does I/O on its own threads, so the
        blocking spawn/attach/wait chain runs in a worker thread.
        """
        if not binary.exists():
            raise FileNotFoundError(f"binary not found: {binary}")

        script_source = self.compose_script(enabled_probes, config_extras)

        return await asyncio.to_thread(
            self._run_probed_blocking,
            binary=binary,
            script_source=script_source,
            args=list(args),
            timeout_s=timeout_s,
        )

    def _run_probed_blocking(
        self,
        *,
        binary: Path,
        script_source: str,
        args: list[str],
        timeout_s: float,
    ) -> ProbedRun:
        events: list[Event] = []
        detached = threading.Event()
        detach_reason: dict[str, str] = {}

        def _on_message(msg: dict[str, Any], _data: bytes | None) -> None:
            mtype = msg.get("type")
            if mtype == "send":
                evt = parse_event(msg.get("payload"))
                if evt is not None:
                    events.append(evt)
            elif mtype == "error":
                _LOG.warning("frida script error: %s", msg.get("description"))

        def _on_detached(reason: str, *_rest: Any) -> None:
            detach_reason["reason"] = reason
            detached.set()

        device = self.device()
        command = [str(binary), *args]
        _LOG.info("spawn %s", command)

        pid = device.spawn(command)
        try:
            frida_session = device.attach(pid)
            frida_session.on("detached", _on_detached)

            script = frida_session.create_script(script_source)
            script.on("message", _on_message)
            script.load()
            device.resume(pid)

            t0 = time.monotonic()
            timed_out = not detached.wait(timeout=timeout_s)
            duration_ms = int((time.monotonic() - t0) * 1000)
        except Exception:
            try:
                device.kill(pid)
            except Exception:  # noqa: BLE001 — best-effort cleanup
                pass
            raise

        exit_code: int | None = None
        if timed_out:
            _LOG.warning("timeout %.1fs; killing pid=%d", timeout_s, pid)
            try:
                device.kill(pid)
            except Exception as e:  # noqa: BLE001
                _LOG.warning("kill failed: %s", e)
        elif detach_reason.get("reason") == "process-terminated":
            # Frida does not expose the exact exit code on detach; 0
            # means "process ran to completion", not literal success.
            # A future phase may wire GetExitCodeProcess via ctypes
            # for exact codes if an invariant needs it.
            exit_code = 0

        return ProbedRun(
            exit_code=exit_code,
            duration_ms=duration_ms,
            timed_out=timed_out,
            events=events,
            events_summary=summarize(events),
        )
