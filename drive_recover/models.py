"""Carved-file records."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Hit:
    offset: int
    type: str
    length: int
    status: str  # "complete" or "partial"

    def as_record(self, sha256: str, path: str) -> dict:
        return {
            "offset": self.offset,
            "type": self.type,
            "size": self.length,
            "status": self.status,
            "sha256": sha256,
            "path": path,
        }
