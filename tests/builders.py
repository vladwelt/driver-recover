"""Synthetic files and disk images for carving tests."""

from __future__ import annotations

import io
import struct
import zipfile
import zlib

from drive_recover.signatures import OLE_SIG, PNG_SIG, frame_length

NOISE = b"\xA5NOISE!\x5A"


def noise(repeats: int = 40) -> bytes:
    return NOISE * repeats


def build_jpeg(with_eoi: bool = True) -> bytes:
    blob = b"\xff\xd8" + _segment(0xDB, bytes([0x00]) + bytes([8] * 64))
    blob += _segment(0xC0, bytes([8, 0, 1, 0, 1, 1, 1, 0x11, 0]))
    blob += _segment(0xDA, bytes([1, 1, 0x00, 0, 63, 0]))
    blob += bytes([0x12, 0x34, 0x56])
    if with_eoi:
        blob += b"\xff\xd9"
    return blob


def _segment(marker: int, data: bytes) -> bytes:
    return bytes((0xFF, marker)) + struct.pack(">H", len(data) + 2) + data


def build_png() -> bytes:
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    # Filter byte 0 plus one RGB pixel.
    compressed = zlib.compress(b"\x00\xff\x00\x00")
    return PNG_SIG + _png_chunk(b"IHDR", ihdr) + _png_chunk(b"IDAT", compressed) + _png_chunk(b"IEND", b"")


def _png_chunk(tag: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(tag + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)


def build_pdf(with_eof: bool = True) -> bytes:
    body = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\nstartxref\n9\n"
    if with_eof:
        body += b"%%EOF\n"
    return body


def build_pdf_with_embedded(payload: bytes) -> bytes:
    length = str(len(payload)).encode()
    return (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog>>endobj\n"
        b"2 0 obj<</Length " + length + b">>stream\n" + payload + b"\nendstream\nendobj\n"
        b"trailer<</Root 1 0 R>>\nstartxref\n0\n%%EOF\n"
    )


def build_zip(entries: list[tuple[str, str]], stored: bool = False) -> bytes:
    buf = io.BytesIO()
    mode = zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED
    with zipfile.ZipFile(buf, "w", compression=mode) as archive:
        for name, text in entries:
            archive.writestr(name, text)
    return buf.getvalue()


def build_ooxml(kind: str) -> bytes:
    if kind == "docx":
        content = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Override PartName="/word/document.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            "</Types>"
        )
        parts = [("[Content_Types].xml", content), ("word/document.xml", "<w:document/>")]
    elif kind == "xlsx":
        content = (
            '<?xml version="1.0"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Override PartName="/xl/workbook.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            "</Types>"
        )
        parts = [("[Content_Types].xml", content), ("xl/workbook.xml", "<workbook/>")]
    elif kind == "pptx":
        content = (
            '<?xml version="1.0"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Override PartName="/ppt/presentation.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>'
            "</Types>"
        )
        parts = [("[Content_Types].xml", content), ("ppt/presentation.xml", "<p:presentation/>")]
    else:
        raise ValueError(kind)
    return build_zip(parts)


def build_gif() -> bytes:
    return bytes.fromhex(
        "4749463839610100010000000021f90401000000002c00000000010001000002024c01003b"
    )


def build_bmp() -> bytes:
    width, height, bits = 1, 1, 24
    row = ((bits * width + 31) // 32) * 4
    pixels = b"\x00\x00\xff" + b"\x00" * (row - 3)
    dib = struct.pack("<IiiHHIIiiII", 40, width, height, 1, bits, 0, len(pixels), 0, 0, 0, 0)
    pix_off = 14 + len(dib)
    file_size = pix_off + len(pixels)
    header = b"BM" + struct.pack("<III", file_size, 0, pix_off)
    return header + dib + pixels


def build_wav() -> bytes:
    fmt = struct.pack("<HHIIHH", 1, 1, 8000, 8000, 1, 8)
    fmt_chunk = b"fmt " + struct.pack("<I", 16) + fmt
    payload = b"\x00" * 8
    data_chunk = b"data" + struct.pack("<I", len(payload)) + payload
    body = b"WAVE" + fmt_chunk + data_chunk
    return b"RIFF" + struct.pack("<I", len(body)) + body


def build_webp() -> bytes:
    payload = b"\x2f\x00\x00\x00"
    chunk = b"VP8L" + struct.pack("<I", len(payload)) + payload
    body = b"WEBP" + chunk
    return b"RIFF" + struct.pack("<I", len(body)) + body


def build_tiff() -> bytes:
    entries = [
        _tiff_entry(256, 4, 1, 1),
        _tiff_entry(257, 4, 1, 1),
        _tiff_entry(259, 3, 1, 1),
        _tiff_entry(273, 4, 1, 0),  # patched once the IFD size is known
        _tiff_entry(278, 4, 1, 1),
        _tiff_entry(279, 4, 1, 4),
    ]
    ifd = struct.pack("<H", len(entries)) + b"".join(entries) + struct.pack("<I", 0)
    data_off = 8 + len(ifd)
    entries[3] = _tiff_entry(273, 4, 1, data_off)
    ifd = struct.pack("<H", len(entries)) + b"".join(entries) + struct.pack("<I", 0)
    return b"II*\x00" + struct.pack("<I", 8) + ifd + b"\x00\x01\x02\x03"


def _tiff_entry(tag: int, typ: int, count: int, value: int) -> bytes:
    return struct.pack("<HHII", tag, typ, count, value)


def build_mp4() -> bytes:
    return _box(b"ftyp", b"isom" + struct.pack(">I", 0) + b"isom") + _box(b"mdat", b"\x00" * 16)


def _box(tag: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", 8 + len(payload)) + tag + payload


def build_mp3() -> bytes:
    header = bytes((0xFF, 0xFB, 0x90, 0x00))
    length = frame_length(header)
    if length != 417:
        raise RuntimeError(f"unexpected frame length {length}")
    frame = header + bytes(length - 4)
    return frame * 3


def build_7z() -> bytes:
    next_header = b"\x01\x02\x03\x04"
    start = struct.pack("<QQI", 0, len(next_header), zlib.crc32(next_header) & 0xFFFFFFFF)
    start_crc = zlib.crc32(start) & 0xFFFFFFFF
    return SEVEN + bytes((0, 4)) + struct.pack("<I", start_crc) + start + next_header


SEVEN = b"7z\xbc\xaf\x27\x1c"


def build_rar4() -> bytes:
    marker = b"Rar!\x1a\x07\x00"
    return marker + _rar4_block(0x73, b"\x00" * 6) + _rar4_block(0x7B, b"")


def _rar4_block(typ: int, rest: bytes) -> bytes:
    base = struct.pack("<BHH", typ, 0, 7 + len(rest)) + rest
    crc = zlib.crc32(base) & 0xFFFF
    return struct.pack("<H", crc) + base


def build_rar5() -> bytes:
    header = bytes((5, 0))
    crc = zlib.crc32(header) & 0xFFFFFFFF
    return b"Rar!\x1a\x07\x01\x00" + struct.pack("<I", crc) + bytes((len(header),)) + header


def build_ole(stream_name: str) -> bytes:
    sector = 512
    n_data = 8
    fat = bytearray(sector)
    for index in range(sector // 4):
        struct.pack_into("<I", fat, index * 4, 0xFFFFFFFF)
    struct.pack_into("<I", fat, 0, 0xFFFFFFFD)
    struct.pack_into("<I", fat, 4, 0xFFFFFFFE)
    for index in range(2, 2 + n_data - 1):
        struct.pack_into("<I", fat, index * 4, index + 1)
    struct.pack_into("<I", fat, (2 + n_data - 1) * 4, 0xFFFFFFFE)

    directory = bytearray(sector)
    directory[0:128] = _ole_entry("Root Entry", 5, 0xFFFFFFFE, 0, child=1)
    directory[128:256] = _ole_entry(stream_name, 2, 2, 4096)

    header = bytearray(512)
    header[0:8] = OLE_SIG
    struct.pack_into("<H", header, 0x18, 0x003E)
    struct.pack_into("<H", header, 0x1A, 3)
    struct.pack_into("<H", header, 0x1C, 0xFFFE)
    struct.pack_into("<H", header, 0x1E, 9)
    struct.pack_into("<H", header, 0x20, 6)
    struct.pack_into("<I", header, 0x2C, 1)
    struct.pack_into("<I", header, 0x30, 1)
    struct.pack_into("<I", header, 0x38, 4096)
    struct.pack_into("<I", header, 0x3C, 0xFFFFFFFE)
    struct.pack_into("<I", header, 0x40, 0)
    struct.pack_into("<I", header, 0x44, 0xFFFFFFFE)
    struct.pack_into("<I", header, 0x48, 0)
    for index in range(109):
        struct.pack_into("<I", header, 0x4C + index * 4, 0 if index == 0 else 0xFFFFFFFF)
    return bytes(header) + bytes(fat) + bytes(directory) + (b"\x00" * 4096)


def _ole_entry(name: str, obj: int, start: int, size: int, child: int = 0xFFFFFFFF) -> bytes:
    buf = bytearray(128)
    raw = name.encode("utf-16le")
    buf[: len(raw)] = raw
    struct.pack_into("<H", buf, 64, len(raw) + 2)
    buf[66] = obj
    buf[67] = 1
    struct.pack_into("<III", buf, 68, 0xFFFFFFFF, 0xFFFFFFFF, child)
    struct.pack_into("<I", buf, 0x74, start & 0xFFFFFFFF)
    struct.pack_into("<I", buf, 0x78, size & 0xFFFFFFFF)
    return bytes(buf)


def lay_down(parts: list[tuple[str, bytes]]) -> tuple[bytes, dict[str, tuple[int, bytes]]]:
    """Concatenate files with signature-free noise between them."""
    blob = bytearray()
    placed: dict[str, tuple[int, bytes]] = {}
    gap = noise()
    for name, data in parts:
        blob += gap
        placed[name] = (len(blob), data)
        blob += data
    blob += gap
    return bytes(blob), placed
