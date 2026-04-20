"""Runtime event envelopes produced by Frida probes.

Each probe emits NDJSON-shaped messages via ``MxEvt.send(kind, payload)``
in ``probes/_loader.js``:

    { "kind": "api_call", "t": <ms>, "payload": { … } }

The Python side parses them into ``Event`` dataclasses. Higher layers
(invariants, metrics) consume ``list[Event]`` — never raw Frida
messages — so the envelope shape is the contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class Event:
    kind: str
    t_ms: int
    payload: dict[str, Any]


def parse_event(message: Any) -> Event | None:
    """Parse a Frida ``send`` message into an Event, or return None.

    Non-envelope messages (Frida internals, console logs) are silently
    dropped — the caller only sees typed events.
    """
    if not isinstance(message, dict):
        return None
    kind = message.get("kind")
    t = message.get("t")
    payload = message.get("payload")
    if not isinstance(kind, str) or not isinstance(t, int):
        return None
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        return None
    return Event(kind=kind, t_ms=t, payload=payload)


def summarize(events: list[Event]) -> dict[str, int]:
    """Per-kind event counts. Stable ordering by insertion."""
    counts: dict[str, int] = {}
    for e in events:
        counts[e.kind] = counts.get(e.kind, 0) + 1
    return counts
