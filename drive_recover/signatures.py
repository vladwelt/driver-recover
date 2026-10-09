"""Header signatures and in-buffer validation.

Detection reads a window plus a short tail so a signature that straddles a
chunk boundary is still visible. The whole image is never loaded.
"""

from __future__ import annotations

import struct
import zlib
from typing import BinaryIO, Callable

from drive_recover.io import read_at

TAIL = 8192
PNG_SIG = b"\x89PNG\r\n\x1a\n"
OLE_SIG = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
RAR4_SIG = b"Rar!\x1a\x07\x00"
RAR5_SIG = b"Rar!\x1a\x07\x01\x00"
SEVEN_SIG = b"7z\xbc\xaf\x27\x1c"

Checker = Callable[[bytes, int, int, BinaryIO, int], str | None]


def _grab(buf: bytes, idx: int, buf_base: int, fh: BinaryIO, image_size: int, n: int) -> bytes:
    if n <= 0:
        return b""
    if idx >= 0 and idx + n <= len(buf):
        return buf[idx : idx + n]
    abs_off = buf_base + idx
    if abs_off < 0 or abs_off >= image_size:
        return b""
    return read_at(fh, abs_off, min(n, image_size - abs_off))


def _zip_name_ok(name: bytes) -> bool:
    if not name or b"\x00" in name or len(name) > 512:
        return False
    ok = 0
    for byte in name:
        if byte in (9, 10, 13) or 32 <= byte < 127 or byte >= 128:
            ok += 1
    return ok / len(name) >= 0.85


def check_png(buf: bytes, idx: int, base: int, fh: BinaryIO, image_size: int) -> str | None:
    raw = _grab(buf, idx, base, fh, image_size, 33)
    if len(raw) < 33 or raw[:8] != PNG_SIG:
        return None
    length = struct.unpack(">I", raw[8:12])[0]
    if length != 13 or raw[12:16] != b"IHDR":
        return None
    ihdr = raw[16:29]
    crc = struct.unpack(">I", raw[29:33])[0]
    if (zlib.crc32(b"IHDR" + ihdr) & 0xFFFFFFFF) != crc:
        return None
    width, height = struct.unpack(">II", ihdr[:8])
    if not (1 <= width <= 1_000_000 and 1 <= height <= 1_000_000):
        return None
    return "png"


def check_jpg(buf: bytes, idx: int, base: int, fh: BinaryIO, image_size: int) -> str | None:
    raw = _grab(buf, idx, base, fh, image_size, 6)
    if len(raw) < 6 or raw[:3] != b"\xff\xd8\xff":
        return None
    marker = raw[3]
    known = (
        0xC0 <= marker <= 0xC3
        or marker in (0xC4, 0xDB, 0xDD, 0xDA, 0xFE)
        or 0xE0 <= marker <= 0xEF
    )
    if not known:
        return None
    length = struct.unpack(">H", raw[4:6])[0]
    if length < 2 or length > 65535:
        return None
    return "jpg"


def check_pdf(buf: bytes, idx: int, base: int, fh: BinaryIO, image_size: int) -> str | None:
    raw = _grab(buf, idx, base, fh, image_size, 8)
    if len(raw) < 6 or not raw.startswith(b"%PDF-"):
        return None
    if not 0x30 <= raw[5] <= 0x39:
        return None
    return "pdf"


def check_gif(buf: bytes, idx: int, base: int, fh: BinaryIO, image_size: int) -> str | None:
    raw = _grab(buf, idx, base, fh, image_size, 13)
    if len(raw) < 13 or raw[:6] not in (b"GIF87a", b"GIF89a"):
        return None
    width, height, packed = struct.unpack_from("<HHB", raw, 6)
    if width == 0 or height == 0:
        return None
    gct = 3 * (2 ** ((packed & 7) + 1)) if packed & 0x80 else 0
    intro = _grab(buf, idx + 13 + gct, base, fh, image_size, 1)
    if intro not in (b"\x21", b"\x2c", b"\x3b"):
        return None
    return "gif"


def check_ole(buf: bytes, idx: int, base: int, fh: BinaryIO, image_size: int) -> str | None:
    raw = _grab(buf, idx, base, fh, image_size, 0x22)
    if len(raw) < 0x22 or raw[:8] != OLE_SIG:
        return None
    byte_order, sector_shift = struct.unpack_from("<HH", raw, 0x1C)
    major = struct.unpack_from("<H", raw, 0x1A)[0]
    if byte_order != 0xFFFE or sector_shift not in (9, 12) or major not in (3, 4):
        return None
    return "ole"


def check_zip(buf: bytes, idx: int, base: int, fh: BinaryIO, image_size: int) -> str | None:
    raw = _grab(buf, idx, base, fh, image_size, 30)
    if len(raw) < 30 or raw[:4] != b"PK\x03\x04":
        return None
    method = struct.unpack_from("<H", raw, 8)[0]
    name_len = struct.unpack_from("<H", raw, 26)[0]
    extra_len = struct.unpack_from("<H", raw, 28)[0]
    if method not in (0, 8, 9, 12, 14):
        return None
    if name_len < 1 or name_len > 512 or extra_len > 4096:
        return None
    name = _grab(buf, idx + 30, base, fh, image_size, name_len)
    if len(name) != name_len or not _zip_name_ok(name):
        return None
    return "zip"


def check_rar(buf: bytes, idx: int, base: int, fh: BinaryIO, image_size: int) -> str | None:
    raw = _grab(buf, idx, base, fh, image_size, 8)
    if raw.startswith(RAR5_SIG) or raw.startswith(RAR4_SIG):
        return "rar"
    return None


def check_7z(buf: bytes, idx: int, base: int, fh: BinaryIO, image_size: int) -> str | None:
    raw = _grab(buf, idx, base, fh, image_size, 32)
    if len(raw) < 32 or raw[:6] != SEVEN_SIG or raw[6] != 0:
        return None
    start = raw[12:32]
    crc = struct.unpack_from("<I", raw, 8)[0]
    if (zlib.crc32(start) & 0xFFFFFFFF) != crc:
        return None
    next_off, next_size, _next_crc = struct.unpack("<QQI", start)
    if next_size == 0 or next_size > (1 << 32) or next_off > (1 << 40):
        return None
    return "7z"


def check_bmp(buf: bytes, idx: int, base: int, fh: BinaryIO, image_size: int) -> str | None:
    raw = _grab(buf, idx, base, fh, image_size, 54)
    if bmp_file_size(raw) is None:
        return None
    return "bmp"


def bmp_file_size(raw: bytes) -> int | None:
    """Return the declared BMP size when the header is structurally valid."""
    if len(raw) < 30 or raw[:2] != b"BM":
        return None
    file_size, reserved, pix_off = struct.unpack_from("<III", raw, 2)
    if reserved != 0 or file_size < 54 or pix_off < 14 or pix_off >= file_size:
        return None
    if pix_off > 1_048_576:
        return None
    dib = struct.unpack_from("<I", raw, 14)[0]
    if dib == 12:
        if len(raw) < 26:
            return None
        width, height, planes, bits = struct.unpack_from("<HHHH", raw, 18)
    elif dib in (16, 40, 52, 56, 64, 108, 124):
        if len(raw) < 30:
            return None
        width, height, planes, bits = struct.unpack_from("<iiHH", raw, 18)
        width = abs(width)
        height = abs(height)
    else:
        return None
    if planes != 1 or bits not in (1, 4, 8, 16, 24, 32):
        return None
    if width == 0 or height == 0 or width > 1_000_000 or height > 1_000_000:
        return None
    return file_size


def check_tiff(buf: bytes, idx: int, base: int, fh: BinaryIO, image_size: int) -> str | None:
    raw = _grab(buf, idx, base, fh, image_size, 8)
    if len(raw) < 8:
        return None
    if raw[:4] == b"II*\x00":
        ifd = struct.unpack_from("<I", raw, 4)[0]
    elif raw[:4] == b"MM\x00*":
        ifd = struct.unpack_from(">I", raw, 4)[0]
    else:
        return None
    if ifd < 8 or ifd > 1 << 28:
        return None
    return "tiff"


def check_riff(buf: bytes, idx: int, base: int, fh: BinaryIO, image_size: int) -> str | None:
    raw = _grab(buf, idx, base, fh, image_size, 16)
    if len(raw) < 16 or raw[:4] != b"RIFF":
        return None
    size = struct.unpack_from("<I", raw, 4)[0]
    if size < 4:
        return None
    form = raw[8:12]
    chunk = raw[12:16]
    if form == b"WAVE" and chunk == b"fmt ":
        return "wav"
    if form == b"WEBP" and chunk in (b"VP8 ", b"VP8L", b"VP8X"):
        return "webp"
    return None


def check_mp4(buf: bytes, idx: int, base: int, fh: BinaryIO, image_size: int) -> str | None:
    raw = _grab(buf, idx, base, fh, image_size, 12)
    if len(raw) < 12 or raw[4:8] != b"ftyp":
        return None
    size = struct.unpack(">I", raw[:4])[0]
    # 64-bit box sizes put the brand later; ordinary files use a 32-bit size.
    if size < 16 or size > (1 << 28):
        return None
    if not all(32 <= c < 127 for c in raw[8:12]):
        return None
    return "mp4"


def check_id3(buf: bytes, idx: int, base: int, fh: BinaryIO, image_size: int) -> str | None:
    raw = _grab(buf, idx, base, fh, image_size, 10)
    if len(raw) < 10 or raw[:3] != b"ID3":
        return None
    version, _rev, flags = raw[3], raw[4], raw[5]
    if version not in (2, 3, 4):
        return None
    if version == 3 and flags & 0x1F:
        return None
    if version == 4 and flags & 0x0F:
        return None
    if any(byte & 0x80 for byte in raw[6:10]):
        return None
    size = synchsafe(raw[6:10])
    if size <= 0 or size > 256 * 1024 * 1024:
        return None
    return "mp3"


def synchsafe(raw: bytes) -> int:
    return (raw[0] << 21) | (raw[1] << 14) | (raw[2] << 7) | raw[3]


# (version id, layer id) -> bitrate table in kbps. version 3=MPEG1, 2=MPEG2, 0=MPEG2.5.
# layer 1=III, 2=II, 3=I.
_BR_V1_L1 = [0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0]
_BR_V1_L2 = [0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 0]
_BR_V1_L3 = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0]
_BR_V2_L1 = [0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256, 0]
_BR_V2_L3 = [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0]
_BITRATE = {
    (3, 3): _BR_V1_L1,
    (3, 2): _BR_V1_L2,
    (3, 1): _BR_V1_L3,
    (2, 3): _BR_V2_L1,
    (2, 2): _BR_V2_L3,
    (2, 1): _BR_V2_L3,
    (0, 3): _BR_V2_L1,
    (0, 2): _BR_V2_L3,
    (0, 1): _BR_V2_L3,
}
_SAMPLERATE = {
    3: (44100, 48000, 32000),
    2: (22050, 24000, 16000),
    0: (11025, 12000, 8000),
}


def frame_length(header: bytes) -> int | None:
    """MPEG audio frame length, or None when the 4-byte header is not a frame."""
    if len(header) < 4 or header[0] != 0xFF or (header[1] & 0xE0) != 0xE0:
        return None
    version = (header[1] >> 3) & 0x3
    layer = (header[1] >> 1) & 0x3
    bitrate_idx = (header[2] >> 4) & 0xF
    sample_idx = (header[2] >> 2) & 0x3
    padding = (header[2] >> 1) & 0x1
    if version == 1 or layer == 0 or bitrate_idx in (0, 0xF) or sample_idx == 3:
        return None
    table = _BITRATE.get((version, layer))
    rates = _SAMPLERATE.get(version)
    if table is None or rates is None:
        return None
    bitrate = table[bitrate_idx] * 1000
    sample_rate = rates[sample_idx]
    if bitrate == 0 or sample_rate == 0:
        return None
    if layer == 3:
        length = ((12 * bitrate) // sample_rate + padding) * 4
    elif layer == 1 and version != 3:
        length = (72 * bitrate) // sample_rate + padding
    else:
        length = (144 * bitrate) // sample_rate + padding
    if length < 24 or length > 4096:
        return None
    return length


def check_mp3_frame(buf: bytes, idx: int, base: int, fh: BinaryIO, image_size: int) -> str | None:
    """Two back-to-back valid frames. A single sync word is too common."""
    header = _grab(buf, idx, base, fh, image_size, 4)
    first = frame_length(header)
    if first is None:
        return None
    second_off = idx + first
    second = _grab(buf, second_off, base, fh, image_size, 4)
    if frame_length(second) is None:
        return None
    return "mp3"


# (needle, delta added to the match index to reach the file start, checker)
_NEEDLES: list[tuple[bytes, int, Checker]] = [
    (PNG_SIG, 0, check_png),
    (b"\xff\xd8\xff", 0, check_jpg),
    (b"%PDF-", 0, check_pdf),
    (b"GIF87a", 0, check_gif),
    (b"GIF89a", 0, check_gif),
    (OLE_SIG, 0, check_ole),
    (b"PK\x03\x04", 0, check_zip),
    (RAR5_SIG, 0, check_rar),
    (RAR4_SIG, 0, check_rar),
    (SEVEN_SIG, 0, check_7z),
    (b"II*\x00", 0, check_tiff),
    (b"MM\x00*", 0, check_tiff),
    (b"RIFF", 0, check_riff),
    (b"ftyp", -4, check_mp4),
    (b"ID3", 0, check_id3),
    (b"BM", 0, check_bmp),
]
_NEEDLES.extend((bytes((0xFF, n)), 0, check_mp3_frame) for n in range(0xE0, 0x100))


def _earliest(
    buf: bytes,
    buf_base: int,
    searchable: int,
    fh: BinaryIO,
    image_size: int,
) -> int | None:
    best: int | None = None
    for needle, delta, checker in _NEEDLES:
        start = 0
        while start < len(buf):
            found = buf.find(needle, start)
            if found < 0:
                break
            cand = found + delta
            if cand >= searchable:
                break
            if cand < 0:
                start = found + 1
                continue
            abs_off = buf_base + cand
            if best is not None and abs_off >= best:
                break
            if checker(buf, cand, buf_base, fh, image_size):
                best = abs_off
                break
            start = found + 1
    return best


def looks_like(fh: BinaryIO, offset: int, image_size: int) -> str | None:
    """Return the type id if a supported file starts at offset."""
    if offset < 0 or offset >= image_size:
        return None
    buf = read_at(fh, offset, min(TAIL, image_size - offset))
    for needle, delta, checker in _NEEDLES:
        index = -delta
        if index < 0 or index + len(needle) > len(buf):
            continue
        if buf[index : index + len(needle)] != needle:
            continue
        kind = checker(buf, 0, offset, fh, image_size)
        if kind:
            return kind
    return None


def find_next_strong(
    fh: BinaryIO,
    start: int,
    end: int,
    image_size: int,
    chunk_size: int = 1 << 20,
    on_pos: Callable[[int], None] | None = None,
) -> int | None:
    """Absolute offset of the next validated header in [start, end)."""
    start = max(0, start)
    end = min(end, image_size)
    chunk_size = max(1, chunk_size)
    pos = start
    while pos < end:
        if on_pos is not None:
            on_pos(pos)
        searchable = min(chunk_size, end - pos)
        to_read = min(searchable + TAIL, image_size - pos)
        fh.seek(pos)
        buf = fh.read(to_read)
        if not buf:
            break
        searchable = min(searchable, len(buf))
        found = _earliest(buf, pos, searchable, fh, image_size)
        if found is not None:
            return found
        if searchable <= 0:
            break
        pos += searchable
    return None
