"""Cheap, informational look at an image before scanning.

Filesystem hints come only from a boot sector or superblock magic. Carving
does not use them and does not require a healthy filesystem.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from drive_recover.io import file_size, open_readonly, read_at


@dataclass(frozen=True)
class ImageInfo:
    path: Path
    size: int
    readable: bool
    filesystem: str | None


def evaluate(path: str | Path) -> ImageInfo:
    image = Path(path)
    with open_readonly(image) as fh:
        size = file_size(fh, image)
        hint = _filesystem_hint(fh, size)
    return ImageInfo(image.resolve(), size, True, hint)


def _filesystem_hint(fh, size: int) -> str | None:
    boot = read_at(fh, 0, 512) if size else b""
    if len(boot) >= 512 and boot[510:512] == b"\x55\xaa":
        oem = boot[3:11]
        if oem == b"NTFS    ":
            return "NTFS boot sector"
        if oem == b"EXFAT   ":
            return "exFAT boot sector"
        if boot[0x52:0x5A] == b"FAT32   ":
            return "FAT32 boot sector"
        if boot[0x36:0x3E] in (b"FAT16   ", b"FAT12   ", b"FAT     "):
            return "FAT boot sector"
        if size >= 520 and read_at(fh, 512, 8) == b"EFI PART":
            return "GPT / EFI partition header"
        return "DOS/MBR boot sector"
    if size >= 1024 + 0x3A:
        superblock = read_at(fh, 1024, 0x3A + 2)
        if len(superblock) >= 0x3A + 2 and superblock[0x38:0x3A] == b"\x53\xef":
            return "ext2/ext3/ext4 superblock"
    if size >= 0x8006 and read_at(fh, 0x8001, 5) == b"CD001":
        return "ISO9660 volume"
    return None


def human_size(n: int) -> str:
    value = float(max(n, 0))
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024:
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"
