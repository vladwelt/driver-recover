"""Scan and recover progress on stderr."""

from __future__ import annotations

import sys

from drive_recover.evaluate import human_size


class Progress:
    def __init__(self, label: str, *, byte_counts: bool = True) -> None:
        self.label = label
        self.byte_counts = byte_counts
        self.tty = sys.stderr.isatty()
        self._last_bucket = -1
        self._drew = False
        self._finished = False

    def update(self, current: int, total: int, detail: str = "") -> None:
        total = max(total, 1)
        current = min(max(current, 0), total)
        pct = current * 100 // total
        bucket = pct // 5
        if not self.tty and bucket == self._last_bucket and not (pct == 100 and not self._finished):
            return
        if pct == 100:
            self._finished = True
        self._last_bucket = bucket
        if self.byte_counts:
            amounts = f"{human_size(current)}/{human_size(total)}"
        else:
            amounts = f"{current}/{total}"
        body = f"{pct:3d}%  {amounts}"
        if detail:
            body = f"{body}  {detail}"
        if self.tty:
            bar_w = 24
            filled = bar_w * current // total
            bar = "█" * filled + "░" * (bar_w - filled)
            print(f"\r{self.label} {bar} {body}   ", end="", file=sys.stderr, flush=True)
        else:
            print(f"{self.label} {body}", file=sys.stderr, flush=True)
        self._drew = True

    def close(self) -> None:
        if self._drew and self.tty:
            print(file=sys.stderr)
        self._drew = False
