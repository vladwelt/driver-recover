"""Canonical recovered-file types and CLI aliases."""

from __future__ import annotations

from drive_recover.errors import UsageError

# Directory name and file extension are the type id.
SUPPORTED: tuple[str, ...] = (
    "jpg",
    "png",
    "gif",
    "bmp",
    "webp",
    "tiff",
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "ole",
    "zip",
    "rar",
    "7z",
    "mp3",
    "wav",
    "mp4",
)

ALIASES: dict[str, str] = {name: name for name in SUPPORTED}
ALIASES.update({"jpeg": "jpg", "tif": "tiff"})


def parse_types(value: str) -> list[str]:
    """Parse a comma-separated type list. Preserves order, drops duplicates."""
    parts = [part.strip().lower() for part in value.split(",") if part.strip()]
    if not parts:
        raise UsageError("no types given")
    chosen: list[str] = []
    for part in parts:
        canon = ALIASES.get(part)
        if canon is None:
            supported = ", ".join(SUPPORTED)
            raise UsageError(f"unknown type {part!r}; supported: {supported}")
        if canon not in chosen:
            chosen.append(canon)
    return chosen
