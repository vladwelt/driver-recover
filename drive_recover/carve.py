"""Carve files from a disk image by header, footer, and container structure.

Reads are chunked. A short overlap keeps a signature that sits on a chunk
boundary visible. The source is opened read-only.
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path
from typing import BinaryIO, Callable

from drive_recover.io import file_size, open_readonly, read_at
from drive_recover.models import Hit
from drive_recover.signatures import (
    OLE_SIG,
    PNG_SIG,
    RAR4_SIG,
    RAR5_SIG,
    SEVEN_SIG,
    bmp_file_size,
    find_next_strong,
    frame_length,
    looks_like,
    synchsafe,
)

DEFAULT_MAX_BYTES = 32 * 1024 * 1024
DEFAULT_CHUNK = 1 << 20

Progress = Callable[[int, int, int], None]

_JPEG_STANDALONE = {0x01, 0xD8} | set(range(0xD0, 0xD8))
_MP4_BOXES = {
    b"ftyp",
    b"styp",
    b"moov",
    b"mdat",
    b"free",
    b"skip",
    b"wide",
    b"udta",
    b"meta",
    b"pdin",
    b"meco",
    b"sidx",
    b"ssix",
    b"prft",
    b"moof",
    b"mfra",
    b"uuid",
    b"iods",
    b"mvex",
    b"pssh",
    b"bloc",
    b"cmov",
}
_TIFF_TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8}


def scan_image(
    path: str | Path,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    chunk_size: int = DEFAULT_CHUNK,
    progress: Progress | None = None,
) -> list[Hit]:
    """Scan path and return carved hits in offset order."""
    image = Path(path)
    hits: list[Hit] = []
    with open_readonly(image) as fh:
        size = file_size(fh, image)
        pos = 0
        while pos < size:
            nxt = find_next_strong(
                fh,
                pos,
                size,
                size,
                chunk_size,
                None if progress is None else (lambda p: progress(p, size, len(hits))),
            )
            if nxt is None:
                break
            hit = carve_at(fh, nxt, size, max_bytes)
            if hit is None:
                pos = nxt + 1
            else:
                hits.append(hit)
                pos = max(nxt + 1, hit.offset + hit.length)
            if progress is not None:
                progress(min(pos, size), size, len(hits))
        if progress is not None:
            progress(size, size, len(hits))
    return hits


def carve_at(fh: BinaryIO, offset: int, image_size: int, max_bytes: int) -> Hit | None:
    kind = looks_like(fh, offset, image_size)
    if kind is None:
        return None
    carvers = {
        "jpg": carve_jpeg,
        "png": carve_png,
        "gif": carve_gif,
        "bmp": carve_bmp,
        "webp": carve_riff,
        "wav": carve_riff,
        "tiff": carve_tiff,
        "pdf": carve_pdf,
        "zip": carve_zip,
        "rar": carve_rar,
        "7z": carve_7z,
        "mp3": carve_mp3,
        "mp4": carve_mp4,
        "ole": carve_ole,
    }
    hit = carvers[kind](fh, offset, image_size, max_bytes)
    if hit is None or hit.length <= 0 or hit.offset != offset:
        return None
    if hit.offset + hit.length > image_size:
        return None
    if hit.status not in ("complete", "partial"):
        return None
    return hit


def _complete(offset: int, kind: str, end: int, image_size: int) -> Hit | None:
    if offset < end <= image_size:
        return Hit(offset, kind, end - offset, "complete")
    return None


def _partial_at(offset: int, kind: str, end: int, image_size: int) -> Hit | None:
    end = min(end, image_size)
    if end <= offset:
        return None
    return Hit(offset, kind, end - offset, "partial")


def _partial(
    fh: BinaryIO,
    offset: int,
    kind: str,
    image_size: int,
    max_bytes: int,
    content_start: int,
) -> Hit | None:
    """Bounded partial: stop at the next file header or at max_bytes."""
    window = min(image_size, offset + max(1, max_bytes))
    nxt = None
    if content_start < window:
        nxt = find_next_strong(fh, content_start, window, image_size)
    end = nxt if nxt is not None else window
    return _partial_at(offset, kind, end, image_size)


def _read_marker(fh: BinaryIO, pos: int, limit: int) -> tuple[int, int] | None:
    if pos >= limit or read_at(fh, pos, 1) != b"\xff":
        return None
    pos += 1
    while pos < limit:
        raw = read_at(fh, pos, 1)
        pos += 1
        if not raw:
            return None
        if raw != b"\xff":
            return raw[0], pos
    return None


def _segment_end(fh: BinaryIO, pos: int, image_size: int) -> int | None:
    raw = read_at(fh, pos, 2)
    if len(raw) < 2:
        return None
    length = struct.unpack(">H", raw)[0]
    if length < 2:
        return None
    end = pos + length
    if end > image_size:
        return None
    return end


def _scan_entropy(fh: BinaryIO, start: int, end: int) -> tuple[str, int]:
    """Walk JPEG entropy. Return ('eoi', end), ('marker', ff_pos), or ('none', end)."""
    pos = start
    pending_ff = False
    while pos < end:
        fh.seek(pos)
        chunk = fh.read(min(1 << 20, end - pos))
        if not chunk:
            break
        for index, byte in enumerate(chunk):
            if pending_ff:
                if byte == 0xFF:
                    continue
                if byte == 0xD9:
                    return "eoi", pos + index + 1
                if byte == 0x00 or 0xD0 <= byte <= 0xD7:
                    pending_ff = False
                    continue
                return "marker", pos + index - 1
            pending_ff = byte == 0xFF
        pos += len(chunk)
    return "none", end


def carve_jpeg(fh: BinaryIO, offset: int, image_size: int, max_bytes: int) -> Hit | None:
    limit = min(image_size, offset + max_bytes)
    if read_at(fh, offset, 3) != b"\xff\xd8\xff":
        return None
    pos = offset + 2
    while pos < limit:
        marker = _read_marker(fh, pos, limit)
        if marker is None:
            return _partial(fh, offset, "jpg", image_size, max_bytes, max(offset + 3, pos))
        marker_id, after = marker
        if marker_id == 0xD9:
            return _complete(offset, "jpg", after, image_size)
        if marker_id in _JPEG_STANDALONE:
            pos = after
            continue
        if marker_id == 0x00:
            return _partial(fh, offset, "jpg", image_size, max_bytes, offset + 3)
        seg_end = _segment_end(fh, after, image_size)
        if seg_end is None or seg_end > limit:
            return _partial(fh, offset, "jpg", image_size, max_bytes, offset + 3)
        if marker_id != 0xDA:
            pos = seg_end
            continue
        cursor = seg_end
        while cursor < limit:
            strong = find_next_strong(fh, cursor, limit, image_size)
            stop = strong if strong is not None else limit
            kind, at = _scan_entropy(fh, cursor, stop)
            if kind == "eoi":
                return _complete(offset, "jpg", at, image_size)
            if kind == "marker" and (strong is None or at < strong):
                pos = at
                break
            if strong is not None:
                return _partial_at(offset, "jpg", strong, image_size)
            return _partial(fh, offset, "jpg", image_size, max_bytes, cursor)
        else:
            return _partial(fh, offset, "jpg", image_size, max_bytes, offset + 3)
    return _partial(fh, offset, "jpg", image_size, max_bytes, offset + 3)


def carve_png(fh: BinaryIO, offset: int, image_size: int, max_bytes: int) -> Hit | None:
    if read_at(fh, offset, 8) != PNG_SIG:
        return None
    pos = offset + 8
    saw_ihdr = False
    while pos + 12 <= image_size:
        hdr = read_at(fh, pos, 8)
        if len(hdr) < 8:
            break
        length = struct.unpack(">I", hdr[:4])[0]
        ctype = hdr[4:8]
        if not saw_ihdr and (ctype != b"IHDR" or length != 13):
            return None
        if length > image_size or pos + 12 + length > image_size:
            break
        if not all(65 <= c <= 90 or 97 <= c <= 122 for c in ctype):
            break
        if ctype in (b"IHDR", b"IEND"):
            data = read_at(fh, pos + 8, length)
            crc_raw = read_at(fh, pos + 8 + length, 4)
            if len(data) != length or len(crc_raw) < 4:
                break
            crc = struct.unpack(">I", crc_raw)[0]
            expect = zlib.crc32(ctype + data) & 0xFFFFFFFF
            if crc != expect:
                break
        if ctype == b"IEND":
            if length != 0:
                break
            return _complete(offset, "png", pos + 12, image_size)
        pos += 12 + length
        saw_ihdr = True
    if not saw_ihdr:
        return None
    return _partial(fh, offset, "png", image_size, max_bytes, offset + 8)


def _skip_subblocks(fh: BinaryIO, pos: int, image_size: int) -> int | None:
    while pos < image_size:
        raw = read_at(fh, pos, 1)
        if not raw:
            return None
        size = raw[0]
        pos += 1
        if size == 0:
            return pos
        if pos + size > image_size:
            return None
        pos += size
    return None


def carve_gif(fh: BinaryIO, offset: int, image_size: int, max_bytes: int) -> Hit | None:
    if read_at(fh, offset, 6) not in (b"GIF87a", b"GIF89a"):
        return None
    pos = offset + 6
    lsd = read_at(fh, pos, 7)
    if len(lsd) < 7:
        return _partial(fh, offset, "gif", image_size, max_bytes, offset + 6)
    packed = lsd[4]
    pos += 7
    if packed & 0x80:
        gct = 3 * (2 ** ((packed & 7) + 1))
        if pos + gct > image_size:
            return _partial(fh, offset, "gif", image_size, max_bytes, offset + 6)
        pos += gct
    while pos < image_size:
        kind = read_at(fh, pos, 1)
        if not kind:
            break
        pos += 1
        if kind == b"\x3b":
            return _complete(offset, "gif", pos, image_size)
        if kind == b"\x21":
            if pos >= image_size:
                break
            pos += 1
            end = _skip_subblocks(fh, pos, image_size)
            if end is None:
                break
            pos = end
            continue
        if kind == b"\x2c":
            desc = read_at(fh, pos, 9)
            if len(desc) < 9:
                break
            pos += 9
            if desc[8] & 0x80:
                lct = 3 * (2 ** ((desc[8] & 7) + 1))
                if pos + lct > image_size:
                    break
                pos += lct
            if pos >= image_size:
                break
            pos += 1
            end = _skip_subblocks(fh, pos, image_size)
            if end is None:
                break
            pos = end
            continue
        break
    return _partial(fh, offset, "gif", image_size, max_bytes, offset + 6)


def carve_bmp(fh: BinaryIO, offset: int, image_size: int, max_bytes: int) -> Hit | None:
    raw = read_at(fh, offset, 54)
    declared = bmp_file_size(raw)
    if declared is None:
        return None
    if offset + declared <= image_size:
        return _complete(offset, "bmp", offset + declared, image_size)
    return _partial(fh, offset, "bmp", image_size, max_bytes, offset + 2)


def carve_riff(fh: BinaryIO, offset: int, image_size: int, max_bytes: int) -> Hit | None:
    raw = read_at(fh, offset, 16)
    if len(raw) < 16 or raw[:4] != b"RIFF":
        return None
    declared = 8 + struct.unpack_from("<I", raw, 4)[0]
    form = raw[8:12]
    if form == b"WAVE":
        kind = "wav"
    elif form == b"WEBP":
        kind = "webp"
    else:
        return None
    if declared < 12 or offset + declared > image_size:
        return _partial(fh, offset, kind, image_size, max_bytes, offset + 12)
    if not _riff_walks(fh, offset, declared):
        return _partial(fh, offset, kind, image_size, max_bytes, offset + 12)
    return _complete(offset, kind, offset + declared, image_size)


def _riff_walks(fh: BinaryIO, offset: int, declared: int) -> bool:
    pos = offset + 12
    end = offset + declared
    if pos > end:
        return False
    while pos + 8 <= end:
        hdr = read_at(fh, pos, 8)
        if len(hdr) < 8:
            return False
        csize = struct.unpack_from("<I", hdr, 4)[0]
        if csize > end - (pos + 8):
            return False
        step = 8 + csize
        if (csize & 1) and pos + step < end:
            step += 1
        pos += step
    return pos == end


def carve_tiff(fh: BinaryIO, offset: int, image_size: int, max_bytes: int) -> Hit | None:
    hdr = read_at(fh, offset, 8)
    if len(hdr) < 8:
        return None
    if hdr[:2] == b"II":
        endian = "<"
    elif hdr[:2] == b"MM":
        endian = ">"
    else:
        return None
    if struct.unpack_from(endian + "H", hdr, 2)[0] != 42:
        return None
    ifd = struct.unpack_from(endian + "I", hdr, 4)[0]
    if ifd < 8:
        return None
    max_end = 8
    saw_strips = False
    seen: set[int] = set()
    while ifd and ifd not in seen and len(seen) < 64:
        if offset + ifd + 2 > image_size:
            return _partial(fh, offset, "tiff", image_size, max_bytes, offset + 8)
        seen.add(ifd)
        count_raw = read_at(fh, offset + ifd, 2)
        if len(count_raw) < 2:
            break
        count = struct.unpack(endian + "H", count_raw)[0]
        if count > 4096:
            break
        entries = read_at(fh, offset + ifd + 2, count * 12)
        if len(entries) < count * 12:
            break
        max_end = max(max_end, ifd + 2 + count * 12 + 4)
        strips_off: list[int] | None = None
        strips_len: list[int] | None = None
        for index in range(count):
            tag, typ, nvals, inline = struct.unpack_from(endian + "HHII", entries, index * 12)
            if tag == 273:
                strips_off = _tiff_values(fh, offset, endian, typ, nvals, inline, image_size)
            elif tag == 279:
                strips_len = _tiff_values(fh, offset, endian, typ, nvals, inline, image_size)
            elif tag == 324 and strips_off is None:
                strips_off = _tiff_values(fh, offset, endian, typ, nvals, inline, image_size)
            elif tag == 325 and strips_len is None:
                strips_len = _tiff_values(fh, offset, endian, typ, nvals, inline, image_size)
        if strips_off and strips_len and len(strips_off) == len(strips_len):
            saw_strips = True
            for data_off, data_len in zip(strips_off, strips_len):
                max_end = max(max_end, data_off + data_len)
        next_raw = read_at(fh, offset + ifd + 2 + count * 12, 4)
        if len(next_raw) < 4:
            break
        ifd = struct.unpack(endian + "I", next_raw)[0]
    if not saw_strips:
        return _partial(fh, offset, "tiff", image_size, max_bytes, offset + 8)
    if max_end <= image_size - offset:
        return _complete(offset, "tiff", offset + max_end, image_size)
    return _partial(fh, offset, "tiff", image_size, max_bytes, offset + 8)


def _tiff_values(
    fh: BinaryIO,
    file_off: int,
    endian: str,
    typ: int,
    count: int,
    inline: int,
    image_size: int,
) -> list[int] | None:
    size = _TIFF_TYPE_SIZE.get(typ)
    if size is None or count <= 0 or count > 1_000_000:
        return None
    total = size * count
    if total <= 4:
        raw = struct.pack(endian + "I", inline)
    else:
        if file_off + inline + total > image_size:
            return None
        raw = read_at(fh, file_off + inline, total)
        if len(raw) < total:
            return None
    fmt = {1: "B", 2: "B", 3: "H", 4: "I"}.get(typ)
    if fmt is None:
        return None
    return [struct.unpack_from(endian + fmt, raw, i * size)[0] for i in range(count)]


def _find_pdf_tokens(fh: BinaryIO, start: int, end: int) -> tuple[int | None, int | None]:
    eof_at = None
    xref_at = None
    prev = b""
    pos = start
    overlap = 8
    while pos < end and (eof_at is None or xref_at is None):
        fh.seek(pos)
        chunk = fh.read(min(1 << 20, end - pos))
        if not chunk:
            break
        data = prev + chunk
        base = pos - len(prev)
        if eof_at is None:
            found = data.find(b"%%EOF")
            if found >= 0 and base + found >= start:
                eof_at = base + found
        if xref_at is None:
            found = data.find(b"startxref")
            if found >= 0 and base + found >= start:
                xref_at = base + found
        prev = data[-overlap:] if len(data) >= overlap else data
        pos += len(chunk)
    return eof_at, xref_at


def carve_pdf(fh: BinaryIO, offset: int, image_size: int, max_bytes: int) -> Hit | None:
    head = read_at(fh, offset, 8)
    if len(head) < 6 or not head.startswith(b"%PDF-") or not (0x30 <= head[5] <= 0x39):
        return None
    limit = min(image_size, offset + max_bytes)
    eof_at, xref_at = _find_pdf_tokens(fh, offset, limit)
    nxt = find_next_strong(fh, offset + 8, limit, image_size)
    nxt_kind = looks_like(fh, nxt, image_size) if nxt is not None else None

    def finish(eof_pos: int) -> Hit | None:
        end = eof_pos + 5
        # A header embedded before %%EOF is not the next file on disk.
        after = nxt if nxt is not None and nxt >= end else None
        room = 2 if after is None else max(0, after - end)
        tail = read_at(fh, end, min(2, room))
        if tail.startswith(b"\r\n"):
            end += 2
        elif tail[:1] in (b"\r", b"\n"):
            end += 1
        return _complete(offset, "pdf", min(end, image_size), image_size)

    if eof_at is None:
        return _partial(fh, offset, "pdf", image_size, max_bytes, offset + 8)
    if nxt is None or eof_at < nxt:
        return finish(eof_at)
    if nxt_kind == "pdf":
        return _partial_at(offset, "pdf", nxt, image_size)
    # Embedded file inside a PDF whose trailer (startxref) follows that file.
    if xref_at is not None and nxt < xref_at < eof_at:
        return finish(eof_at)
    return _partial_at(offset, "pdf", nxt, image_size)


class _Local:
    __slots__ = ("name", "next_pos", "payload", "truncated")

    def __init__(self, name: str, next_pos: int, payload: bytes | None, truncated: bool) -> None:
        self.name = name
        self.next_pos = next_pos
        self.payload = payload
        self.truncated = truncated


def _decode_zip_name(name: bytes, flags: int) -> str:
    if flags & 0x800:
        return name.decode("utf-8", "replace")
    try:
        return name.decode("utf-8")
    except UnicodeDecodeError:
        return name.decode("cp437", "replace")


def _is_content_types(name: str) -> bool:
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    return base.lower() == "[content_types].xml"


def _inflate(method: int, raw: bytes) -> bytes | None:
    try:
        if method == 0:
            return raw
        if method == 8:
            return zlib.decompress(raw, -15)
    except zlib.error:
        return None
    return None


def _zip64_sizes(extra: bytes, comp: int, uncomp: int) -> tuple[int, int]:
    pos = 0
    while pos + 4 <= len(extra):
        header_id, size = struct.unpack_from("<HH", extra, pos)
        pos += 4
        if pos + size > len(extra):
            break
        data = extra[pos : pos + size]
        pos += size
        if header_id != 0x0001:
            continue
        cursor = 0
        if uncomp == 0xFFFFFFFF and cursor + 8 <= len(data):
            uncomp = struct.unpack_from("<Q", data, cursor)[0]
            cursor += 8
        if comp == 0xFFFFFFFF and cursor + 8 <= len(data):
            comp = struct.unpack_from("<Q", data, cursor)[0]
        return comp, uncomp
    return comp, uncomp


def _read_local(fh: BinaryIO, pos: int, image_size: int) -> _Local | None:
    hdr = read_at(fh, pos, 30)
    if len(hdr) < 30 or hdr[:4] != b"PK\x03\x04":
        return None
    flags, method = struct.unpack_from("<HH", hdr, 6)
    comp_size, uncomp_size, name_len, extra_len = struct.unpack_from("<IIHH", hdr, 18)
    if name_len > 65535 or extra_len > 65535:
        return None
    name_raw = read_at(fh, pos + 30, name_len)
    extra = read_at(fh, pos + 30 + name_len, extra_len)
    if len(name_raw) != name_len or len(extra) != extra_len:
        return None
    if comp_size == 0xFFFFFFFF or uncomp_size == 0xFFFFFFFF:
        comp_size, uncomp_size = _zip64_sizes(extra, comp_size, uncomp_size)
    name = _decode_zip_name(name_raw, flags)
    data_start = pos + 30 + name_len + extra_len
    payload = None

    def take_payload(raw: bytes) -> bytes | None:
        if not _is_content_types(name) or len(raw) > 2_000_000:
            return None
        return _inflate(method, raw)

    if flags & 0x08 and comp_size == 0:
        return _Local(name, data_start, None, True)
    if data_start + comp_size > image_size:
        return _Local(name, data_start, None, True)
    if _is_content_types(name):
        payload = take_payload(read_at(fh, data_start, comp_size))
    next_pos = data_start + comp_size
    if flags & 0x08:
        marker = read_at(fh, next_pos, 4)
        next_pos += 16 if marker == b"PK\x07\x08" else 12
        if next_pos > image_size:
            return _Local(name, data_start, payload, True)
    return _Local(name, next_pos, payload, False)


def _classify_ooxml(names: list[str], content: bytes | None) -> str:
    blob = (content or b"").lower()
    paths = [name.replace("\\", "/").lstrip("/").lower() for name in names]

    def has(prefix: str) -> bool:
        bare = prefix.rstrip("/")
        return any(path == bare or path.startswith(prefix) for path in paths)

    if b"wordprocessingml" in blob or has("word/"):
        return "docx"
    if b"spreadsheetml" in blob or has("xl/"):
        return "xlsx"
    if b"presentationml" in blob or has("ppt/"):
        return "pptx"
    return "zip"


def carve_zip(fh: BinaryIO, offset: int, image_size: int, max_bytes: int) -> Hit | None:
    if read_at(fh, offset, 4) != b"PK\x03\x04":
        return None
    pos = offset
    names: list[str] = []
    content: bytes | None = None
    entries = 0
    while pos + 4 <= image_size and entries < 100_000:
        sig = read_at(fh, pos, 4)
        if sig == b"PK\x03\x04":
            local = _read_local(fh, pos, image_size)
            if local is None:
                break
            names.append(local.name)
            if content is None and local.payload is not None:
                content = local.payload
            entries += 1
            if local.truncated:
                return _partial(
                    fh,
                    offset,
                    _classify_ooxml(names, content),
                    image_size,
                    max_bytes,
                    offset + 4,
                )
            pos = local.next_pos
            continue
        if sig == b"PK\x01\x02":
            while sig == b"PK\x01\x02" and pos + 46 <= image_size:
                hdr = read_at(fh, pos, 46)
                if len(hdr) < 46:
                    break
                name_len, extra_len, comment_len = struct.unpack_from("<HHH", hdr, 28)
                step = 46 + name_len + extra_len + comment_len
                if pos + step > image_size:
                    break
                pos += step
                sig = read_at(fh, pos, 4)
            if sig == b"PK\x05\x06":
                tail = read_at(fh, pos, 22)
                if len(tail) >= 22:
                    comment = struct.unpack_from("<H", tail, 20)[0]
                    end = pos + 22 + comment
                    if end <= image_size:
                        return _complete(offset, _classify_ooxml(names, content), end, image_size)
            break
        break
    if entries == 0:
        return None
    end = pos if pos > offset else min(image_size, offset + max_bytes)
    return _partial_at(offset, _classify_ooxml(names, content), min(end, image_size), image_size)


def _classify_ole(names: list[str]) -> str:
    folded = {name.lower() for name in names}
    if "worddocument" in folded:
        return "doc"
    if "workbook" in folded or "book" in folded:
        return "xls"
    if "powerpoint document" in folded:
        return "ppt"
    return "ole"


def carve_ole(fh: BinaryIO, offset: int, image_size: int, max_bytes: int) -> Hit | None:
    header = read_at(fh, offset, 512)
    if len(header) < 512 or header[:8] != OLE_SIG:
        return None
    major = struct.unpack_from("<H", header, 0x1A)[0]
    sector_shift = struct.unpack_from("<H", header, 0x1E)[0]
    if sector_shift not in (9, 12):
        return None
    sector_size = 1 << sector_shift
    num_fat = struct.unpack_from("<I", header, 0x2C)[0]
    first_dir = struct.unpack_from("<I", header, 0x30)[0]
    mini_cutoff = struct.unpack_from("<I", header, 0x38)[0]
    first_mini = struct.unpack_from("<I", header, 0x3C)[0]
    num_mini = struct.unpack_from("<I", header, 0x40)[0]
    first_difat = struct.unpack_from("<I", header, 0x44)[0]
    num_difat = struct.unpack_from("<I", header, 0x48)[0]
    max_sectors = max(1, (max(0, image_size - offset)) // sector_size)
    if num_fat > max_sectors:
        num_fat = max_sectors

    def sector_pos(sec: int) -> int:
        return offset + (sec + 1) * sector_size

    def read_sector(sec: int) -> bytes | None:
        if sec > 0xFFFFFFFA:
            return None
        pos = sector_pos(sec)
        if pos + sector_size > image_size:
            return None
        data = read_at(fh, pos, sector_size)
        return data if len(data) == sector_size else None

    difat = list(struct.unpack_from("<109I", header, 0x4C))
    sec = first_difat
    seen_difat: set[int] = set()
    for _ in range(min(num_difat, max_sectors)):
        if sec > 0xFFFFFFFA or sec in seen_difat:
            break
        seen_difat.add(sec)
        data = read_sector(sec)
        if data is None:
            break
        count = sector_size // 4
        vals = struct.unpack("<" + "I" * count, data)
        difat.extend(vals[:-1])
        sec = vals[-1]

    fat: list[int] = []
    fat_ids = [item for item in difat if item <= 0xFFFFFFFA][:num_fat]
    fat_ok = True
    for fat_sec in fat_ids:
        data = read_sector(fat_sec)
        if data is None:
            fat_ok = False
            break
        count = sector_size // 4
        fat.extend(struct.unpack("<" + "I" * count, data))

    def chain(start: int) -> list[int] | None:
        if start > 0xFFFFFFFA:
            return []
        out: list[int] = []
        seen: set[int] = set()
        current = start
        while current <= 0xFFFFFFFA and len(out) <= max_sectors:
            if current in seen or current >= len(fat):
                return None
            seen.add(current)
            out.append(current)
            current = fat[current]
        return out

    names: list[str] = []
    used: list[int] = list(fat_ids) + list(seen_difat)
    if fat_ok and fat:
        directory = chain(first_dir)
        if directory:
            used.extend(directory)
            streams: list[tuple[int, int, int]] = []
            for dir_sec in directory:
                data = read_sector(dir_sec)
                if data is None:
                    continue
                for index in range(0, len(data), 128):
                    entry = data[index : index + 128]
                    if len(entry) < 128:
                        continue
                    name_len = struct.unpack_from("<H", entry, 64)[0]
                    obj = entry[66]
                    if name_len < 2 or name_len > 64 or name_len % 2 or obj not in (1, 2, 5):
                        continue
                    name = entry[: name_len - 2].decode("utf-16le", "replace")
                    if not name:
                        continue
                    start_sec = struct.unpack_from("<I", entry, 0x74)[0]
                    if major >= 4:
                        stream_size = struct.unpack_from("<Q", entry, 0x78)[0]
                    else:
                        stream_size = struct.unpack_from("<I", entry, 0x78)[0]
                    names.append(name)
                    streams.append((obj, start_sec, stream_size))
            for obj, start_sec, stream_size in streams:
                if obj == 5 or (obj == 2 and stream_size >= mini_cutoff):
                    linked = chain(start_sec)
                    if linked:
                        used.extend(linked)
        if num_mini and first_mini <= 0xFFFFFFFA:
            mini = chain(first_mini)
            if mini:
                used.extend(mini[:num_mini])

    kind = _classify_ole(names)
    if not used:
        return _partial(fh, offset, kind, image_size, max_bytes, offset + 8)
    end = sector_pos(max(used)) + sector_size
    if names and offset < end <= image_size:
        return _complete(offset, kind, end, image_size)
    return _partial(fh, offset, kind, image_size, max_bytes, offset + 8)


def carve_7z(fh: BinaryIO, offset: int, image_size: int, max_bytes: int) -> Hit | None:
    raw = read_at(fh, offset, 32)
    if len(raw) < 32 or raw[:6] != SEVEN_SIG or raw[6] != 0:
        return None
    start = raw[12:32]
    crc = struct.unpack_from("<I", raw, 8)[0]
    if (zlib.crc32(start) & 0xFFFFFFFF) != crc:
        return None
    next_off, next_size, _next_crc = struct.unpack("<QQI", start)
    total = 32 + next_off + next_size
    if total < 32 or next_size == 0:
        return None
    if offset + total <= image_size:
        return _complete(offset, "7z", offset + total, image_size)
    return _partial(fh, offset, "7z", image_size, max_bytes, offset + 6)


def _read_vint(data: bytes, index: int) -> tuple[int, int] | None:
    value = 0
    shift = 0
    for _ in range(10):
        if index >= len(data):
            return None
        byte = data[index]
        index += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, index
        shift += 7
    return None


def carve_rar(fh: BinaryIO, offset: int, image_size: int, max_bytes: int) -> Hit | None:
    sig = read_at(fh, offset, 8)
    if sig.startswith(RAR5_SIG):
        return _carve_rar5(fh, offset, image_size, max_bytes)
    if sig.startswith(RAR4_SIG):
        return _carve_rar4(fh, offset, image_size, max_bytes)
    return None


def _carve_rar4(fh: BinaryIO, offset: int, image_size: int, max_bytes: int) -> Hit | None:
    pos = offset + 7
    saw_archive = False
    steps = 0
    while pos + 7 <= image_size and steps < 100_000:
        hdr = read_at(fh, pos, 11)
        if len(hdr) < 7:
            break
        _crc, typ, flags, head_size = struct.unpack_from("<HBHH", hdr, 0)
        if head_size < 7 or pos + head_size > image_size:
            break
        add = 0
        if flags & 0x8000:
            if head_size < 11 or len(hdr) < 11:
                break
            add = struct.unpack_from("<I", hdr, 7)[0]
        block_end = pos + head_size + add
        if block_end < pos or block_end > image_size:
            break
        if typ == 0x73:
            saw_archive = True
        pos = block_end
        steps += 1
        if typ == 0x7B and saw_archive:
            return _complete(offset, "rar", pos, image_size)
    if saw_archive or steps:
        return _partial(fh, offset, "rar", image_size, max_bytes, offset + 7)
    return None


def _carve_rar5(fh: BinaryIO, offset: int, image_size: int, max_bytes: int) -> Hit | None:
    pos = offset + 8
    steps = 0
    while pos + 6 <= image_size and steps < 100_000:
        prefix = read_at(fh, pos, 16)
        if len(prefix) < 5:
            break
        parsed = _read_vint(prefix, 4)
        if parsed is None:
            break
        header_size, vint_end = parsed
        if header_size <= 0 or header_size > 1_000_000:
            break
        header_start = pos + vint_end
        if header_start + header_size > image_size:
            break
        header = read_at(fh, header_start, header_size)
        if len(header) != header_size:
            break
        type_parsed = _read_vint(header, 0)
        if type_parsed is None:
            break
        header_type, cursor = type_parsed
        flag_parsed = _read_vint(header, cursor)
        if flag_parsed is None:
            break
        flags, cursor = flag_parsed
        data_size = 0
        if flags & 0x0001:
            extra_parsed = _read_vint(header, cursor)
            if extra_parsed is None:
                break
            _extra, cursor = extra_parsed
        if flags & 0x0002:
            data_parsed = _read_vint(header, cursor)
            if data_parsed is None:
                break
            data_size, cursor = data_parsed
        block_end = header_start + header_size + data_size
        if block_end > image_size or block_end < pos:
            break
        pos = block_end
        steps += 1
        if header_type == 5:
            return _complete(offset, "rar", pos, image_size)
    if steps:
        return _partial(fh, offset, "rar", image_size, max_bytes, offset + 8)
    return None


def carve_mp4(fh: BinaryIO, offset: int, image_size: int, max_bytes: int) -> Hit | None:
    pos = offset
    saw = False
    while pos + 8 <= image_size:
        hdr = read_at(fh, pos, 16)
        if len(hdr) < 8:
            break
        size = struct.unpack(">I", hdr[:4])[0]
        tag = hdr[4:8]
        header_len = 8
        if size == 0:
            return _partial(fh, offset, "mp4", image_size, max_bytes, offset + 8) if saw else None
        if size == 1:
            if len(hdr) < 16:
                break
            size = struct.unpack(">Q", hdr[8:16])[0]
            header_len = 16
        if size < header_len or not all(32 <= c < 127 for c in tag):
            break
        if pos == offset and tag != b"ftyp":
            return None
        if pos != offset and tag not in _MP4_BOXES:
            break
        if pos + size > image_size:
            return _partial(fh, offset, "mp4", image_size, max_bytes, offset + 8)
        pos += size
        saw = True
    if not saw:
        return None
    return _complete(offset, "mp4", pos, image_size)


def _walk_frames(fh: BinaryIO, pos: int, image_size: int) -> tuple[int, int, bool]:
    count = 0
    while count < 1_000_000 and pos + 4 <= image_size:
        header = read_at(fh, pos, 4)
        length = frame_length(header)
        if length is None:
            return pos, count, False
        if pos + length > image_size:
            return pos, count, True
        pos += length
        count += 1
    return pos, count, False


def carve_mp3(fh: BinaryIO, offset: int, image_size: int, max_bytes: int) -> Hit | None:
    head = read_at(fh, offset, 10)
    audio = offset
    if head.startswith(b"ID3"):
        if looks_like(fh, offset, image_size) != "mp3":
            return None
        tag_end = offset + 10 + synchsafe(head[6:10])
        if tag_end > image_size:
            return _partial(fh, offset, "mp3", image_size, max_bytes, offset + 3)
        audio = tag_end
    frame_end, count, truncated = _walk_frames(fh, audio, image_size)
    if count == 0:
        if audio == offset:
            return None
        return _partial(fh, offset, "mp3", image_size, max_bytes, offset + 3)
    if truncated:
        return _partial(fh, offset, "mp3", image_size, max_bytes, offset + 4)
    return _complete(offset, "mp3", frame_end, image_size)
