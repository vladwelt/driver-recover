"""Read-only access to a disk image.

The image is opened with O_RDONLY. Nothing in this package writes to it.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import BinaryIO

from drive_recover.errors import BadPath


def open_readonly(path: Path) -> BinaryIO:
    """Open path for reading only."""
    try:
        if path.is_dir():
            raise BadPath(f"image is a directory: {path}")
    except BadPath:
        raise
    except OSError as exc:
        raise BadPath(f"image is not readable: {path} ({exc.strerror})") from None
    try:
        fd = os.open(path, os.O_RDONLY)
    except FileNotFoundError:
        raise BadPath(f"image not found: {path}") from None
    except IsADirectoryError:
        raise BadPath(f"image is a directory: {path}") from None
    except PermissionError:
        raise BadPath(f"image is not readable: {path}") from None
    except OSError as exc:
        raise BadPath(f"image is not readable: {path} ({exc.strerror})") from None
    return os.fdopen(fd, "rb")


def file_size(fh: BinaryIO, path: Path) -> int:
    """Byte length of a regular file, or the seekable end for other files."""
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        raise BadPath(f"image is not readable: {path} ({exc.strerror})") from None
    if stat.S_ISDIR(mode):
        raise BadPath(f"image is a directory: {path}")
    if stat.S_ISREG(mode):
        return path.stat().st_size
    try:
        if not fh.seekable():
            raise BadPath(f"image is not seekable: {path}")
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        fh.seek(0)
    except BadPath:
        raise
    except OSError as exc:
        raise BadPath(f"image is not readable: {path} ({exc.strerror})") from None
    return size


def read_at(fh: BinaryIO, offset: int, n: int) -> bytes:
    """Read n bytes at an absolute offset. Short reads return what is there."""
    if offset < 0 or n <= 0:
        return b""
    fh.seek(offset)
    return fh.read(n)
