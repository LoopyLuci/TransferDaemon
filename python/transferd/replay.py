"""A sliding replay window over a per-direction sequence number.

The overlay's control frames carry a frame `seq`. A receiver acts on each one once, so it keeps a
window of the last `span` numbers below the highest it has accepted (PROTOCOL.md §5: "act on each
`seq` once (a 4096-wide window)"). A number inside the window that was already accepted is a
copy; a number older than the window cannot be told from a copy, so it is refused too.

Mirrors `ReplayWindow` in `crates/transferd-overlay/src/protocol.rs`.
"""

from __future__ import annotations

from typing import Optional, Set

# The width the control frames use, in sequence numbers.
CONTROL_WINDOW = 4096


class ReplayWindow:
    """Accepts each sequence number once while it is inside the window."""

    def __init__(self, span: int = CONTROL_WINDOW) -> None:
        self._span = max(1, int(span))
        self._highest: Optional[int] = None
        # The accepted numbers inside the window. Anything below it is pruned as the window slides.
        self._seen: Set[int] = set()

    @property
    def highest(self) -> Optional[int]:
        """The highest sequence number accepted so far, or None before any."""
        return self._highest

    def accept(self, seq: int) -> bool:
        """Accept `seq`, or refuse it as a copy or as older than the window."""
        if self._highest is None:
            self._highest = seq
            self._seen.add(seq)
            return True
        if seq > self._highest:
            self._highest = seq
            self._seen.add(seq)
            floor = max(0, seq - (self._span - 1))
            self._seen = {s for s in self._seen if s >= floor}
            return True
        if self._highest - seq >= self._span:
            return False
        if seq in self._seen:
            return False
        self._seen.add(seq)
        return True
