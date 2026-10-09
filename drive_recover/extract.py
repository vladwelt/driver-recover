"""Write carved files and a manifest. The source image is only read."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Callable

from drive_recover.errors import UsageError
from drive_recover.io import open_readonly
from drive_recover.models import Hit

Progress = Callable[[int, int], None]


def assert_output_safe(image: Path, output: Path) -> Path:
    """Refuse to use the source image as the output path."""
    image_real = image.resolve()
    destination = output.expanduser().resolve()
    if destination == image_real:
        raise UsageError("refusing to write to the source image")
    if output.exists():
        try:
            if destination.samefile(image_real):
                raise UsageError("refusing to write to the source image")
        except OSError:
            pass
        if destination.is_file():
            raise UsageError(f"output is not a directory: {destination}")
    return destination


def extract(
    image: Path,
    hits: list[Hit],
    output: Path,
    progress: Progress | None = None,
) -> list[dict]:
    """Stream each hit into output/<type>/<offset>.<type> and write manifest.json."""
    destination = assert_output_safe(image, output)
    destination.mkdir(parents=True, exist_ok=True)
    records: list[dict] = []
    total = len(hits)
    with open_readonly(image) as src:
        for index, hit in enumerate(hits, start=1):
            folder = destination / hit.type
            folder.mkdir(parents=True, exist_ok=True)
            name = f"{hit.offset}.{hit.type}"
            target = folder / name
            digest = _stream_copy(src, hit.offset, hit.length, target)
            records.append(hit.as_record(digest, f"{hit.type}/{name}"))
            if progress is not None:
                progress(index, total)
    manifest = {"image": str(image.resolve()), "files": records}
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return records


def _stream_copy(src, offset: int, length: int, target: Path) -> str:
    digest = hashlib.sha256()
    src.seek(offset)
    remaining = length
    with target.open("wb") as out:
        while remaining:
            chunk = src.read(min(1 << 20, remaining))
            if not chunk:
                raise OSError("image ended before the carved range was copied")
            out.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()
