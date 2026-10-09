"""Recovery tests against a synthetic image of known files and noise."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from drive_recover.carve import scan_image
from drive_recover.evaluate import evaluate
from tests.builders import (
    build_7z,
    build_bmp,
    build_gif,
    build_jpeg,
    build_mp3,
    build_mp4,
    build_ole,
    build_ooxml,
    build_pdf,
    build_pdf_with_embedded,
    build_png,
    build_rar4,
    build_rar5,
    build_tiff,
    build_wav,
    build_webp,
    build_zip,
    lay_down,
)


def _write(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def _scan(data: bytes, **kwargs):
    with tempfile.TemporaryDirectory() as tmp:
        image = Path(tmp) / "disk.img"
        _write(image, data)
        return scan_image(image, **kwargs)


def _describe(hits) -> str:
    return "\n".join(f"{hit.offset} {hit.type} {hit.status} {hit.length}" for hit in hits)


class SyntheticImageTests(unittest.TestCase):
    def test_recovers_intact_and_partial_files(self) -> None:
        jpeg = build_jpeg()
        png = build_png()
        pdf = build_pdf()
        docx = build_ooxml("docx")
        jpeg_cut = build_jpeg(with_eoi=False)
        pdf_cut = build_pdf(with_eof=False)
        self.assertNotIn(b"\xff\xd9", jpeg_cut)
        self.assertNotIn(b"%%EOF", pdf_cut)

        blob, placed = lay_down(
            [
                ("jpg", jpeg),
                ("png", png),
                ("pdf", pdf),
                ("docx", docx),
                ("jpg_partial", jpeg_cut),
                ("pdf_partial", pdf_cut),
            ]
        )
        hits = _scan(blob)
        by_offset = {hit.offset: hit for hit in hits}
        self.assertEqual(
            set(by_offset),
            {placed[name][0] for name in placed},
            _describe(hits),
        )

        for name, kind in (("jpg", "jpg"), ("png", "png"), ("pdf", "pdf"), ("docx", "docx")):
            offset, data = placed[name]
            hit = by_offset[offset]
            self.assertEqual(hit.type, kind, name)
            self.assertEqual(hit.status, "complete", name)
            self.assertEqual(hit.length, len(data), name)
            self.assertEqual(blob[offset : offset + hit.length], data)

        jpg_off, jpg_data = placed["jpg_partial"]
        pdf_off, pdf_data = placed["pdf_partial"]
        partial_jpg = by_offset[jpg_off]
        self.assertEqual(partial_jpg.type, "jpg")
        self.assertEqual(partial_jpg.status, "partial")
        self.assertEqual(partial_jpg.length, pdf_off - jpg_off)
        self.assertTrue(blob[jpg_off : jpg_off + len(jpg_data)] == jpg_data)
        self.assertNotIn(b"\xff\xd9", blob[jpg_off : jpg_off + partial_jpg.length])

        partial_pdf = by_offset[pdf_off]
        self.assertEqual(partial_pdf.type, "pdf")
        self.assertEqual(partial_pdf.status, "partial")
        self.assertEqual(blob[pdf_off : pdf_off + len(pdf_data)], pdf_data)
        self.assertEqual(partial_pdf.length, len(blob) - pdf_off)
        self.assertNotIn(b"%%EOF", blob[pdf_off : pdf_off + partial_pdf.length])

    def test_chunk_boundary_is_not_missed(self) -> None:
        jpeg = build_jpeg()
        chunk = 128
        pad = b"\x11" * (chunk - 2)
        blob = pad + jpeg + b"\x11" * 40
        hits = _scan(blob, chunk_size=chunk)
        matched = [
            hit
            for hit in hits
            if hit.offset == len(pad) and hit.type == "jpg" and hit.status == "complete"
        ]
        self.assertEqual(len(matched), 1, _describe(hits))
        self.assertEqual(matched[0].length, len(jpeg))

    def test_pdf_keeps_embedded_png_through_eof(self) -> None:
        png = build_png()
        pdf = build_pdf_with_embedded(png)
        self.assertIn(png, pdf)
        self.assertIn(b"%%EOF", pdf)
        blob, placed = lay_down([("pdf", pdf)])
        hits = _scan(blob)
        self.assertEqual(len(hits), 1, _describe(hits))
        hit = hits[0]
        self.assertEqual(hit.offset, placed["pdf"][0])
        self.assertEqual(hit.type, "pdf")
        self.assertEqual(hit.status, "complete")
        self.assertEqual(hit.length, len(pdf))

    def test_other_formats_and_ooxml_split(self) -> None:
        parts = [
            ("gif", build_gif()),
            ("bmp", build_bmp()),
            ("wav", build_wav()),
            ("webp", build_webp()),
            ("tiff", build_tiff()),
            ("mp4", build_mp4()),
            ("mp3", build_mp3()),
            ("7z", build_7z()),
            ("rar", build_rar4()),
            ("rar5", build_rar5()),
            ("zip", build_zip([("readme.txt", "hello")], stored=True)),
            ("xlsx", build_ooxml("xlsx")),
            ("pptx", build_ooxml("pptx")),
            ("doc", build_ole("WordDocument")),
            ("xls", build_ole("Workbook")),
            ("ppt", build_ole("PowerPoint Document")),
            ("ole", build_ole("DataStream")),
        ]
        blob, placed = lay_down(parts)
        hits = _scan(blob)
        by_offset = {hit.offset: hit for hit in hits}
        self.assertEqual(set(by_offset), {off for off, _ in placed.values()}, _describe(hits))
        expected = {name: name for name, _ in parts}
        expected["rar5"] = "rar"
        for name, data_info in placed.items():
            offset, data = data_info
            hit = by_offset[offset]
            self.assertEqual(hit.type, expected[name], name)
            self.assertEqual(hit.status, "complete", f"{name} {_describe(hits)}")
            self.assertEqual(hit.length, len(data), name)

    def test_filesystem_hint_is_informational(self) -> None:
        boot = bytearray(4096)
        boot[3:11] = b"NTFS    "
        boot[510:512] = b"\x55\xaa"
        jpeg = build_jpeg()
        blob = bytes(boot) + noise_pad() + jpeg
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "ntfs.img"
            _write(image, blob)
            info = evaluate(image)
            self.assertEqual(info.filesystem, "NTFS boot sector")
            self.assertTrue(info.readable)
            hits = scan_image(image)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].type, "jpg")
        self.assertEqual(hits[0].status, "complete")

    def test_ext_superblock_hint(self) -> None:
        blob = bytearray(2048)
        blob[1024 + 0x38 : 1024 + 0x3A] = b"\x53\xef"
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "ext.img"
            _write(image, bytes(blob))
            info = evaluate(image)
        self.assertEqual(info.filesystem, "ext2/ext3/ext4 superblock")


def noise_pad() -> bytes:
    return b"\xA5NOISE!\x5A" * 8


class CliTests(unittest.TestCase):
    def _image(self, directory: Path) -> Path:
        jpeg = build_jpeg()
        png = build_png()
        pdf = build_pdf()
        docx = build_ooxml("docx")
        jpeg_cut = build_jpeg(with_eoi=False)
        pdf_cut = build_pdf(with_eof=False)
        blob, self.placed = lay_down(
            [
                ("jpg", jpeg),
                ("png", png),
                ("pdf", pdf),
                ("docx", docx),
                ("jpg_partial", jpeg_cut),
                ("pdf_partial", pdf_cut),
            ]
        )
        image = directory / "disk.img"
        _write(image, blob)
        self.digest = hashlib.sha256(blob).hexdigest()
        self.blob = blob
        return image

    def test_cli_recovers_and_does_not_modify_image(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image = self._image(root)
            output = root / "recovered"
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "drive_recover",
                    str(image),
                    "-o",
                    str(output),
                    "--types",
                    "jpeg,png,pdf,docx",
                    "--yes",
                ],
                cwd=Path(__file__).resolve().parents[1],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            self.assertEqual(hashlib.sha256(image.read_bytes()).hexdigest(), self.digest)
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["image"], str(image.resolve()))
            self.assertEqual(len(manifest["files"]), 6)
            for record in manifest["files"]:
                self.assertIn(record["status"], {"complete", "partial"})
                self.assertEqual(
                    set(record),
                    {"offset", "type", "size", "status", "sha256", "path"},
                )
                recovered = (output / record["path"]).read_bytes()
                self.assertEqual(len(recovered), record["size"])
                self.assertEqual(hashlib.sha256(recovered).hexdigest(), record["sha256"])
                self.assertEqual(self.blob[record["offset"] : record["offset"] + record["size"]], recovered)
            kinds = {(item["offset"], item["type"], item["status"]) for item in manifest["files"]}
            self.assertIn((self.placed["jpg"][0], "jpg", "complete"), kinds)
            self.assertIn((self.placed["png"][0], "png", "complete"), kinds)
            self.assertIn((self.placed["pdf"][0], "pdf", "complete"), kinds)
            self.assertIn((self.placed["docx"][0], "docx", "complete"), kinds)
            self.assertIn((self.placed["jpg_partial"][0], "jpg", "partial"), kinds)
            self.assertIn((self.placed["pdf_partial"][0], "pdf", "partial"), kinds)
            self.assertIn("%", proc.stderr)

    def test_scan_only_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image = self._image(root)
            proc = subprocess.run(
                [sys.executable, "-m", "drive_recover", str(image), "--scan-only", "--yes"],
                cwd=Path(__file__).resolve().parents[1],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("complete", proc.stdout)
            self.assertIn("partial", proc.stdout)
            self.assertFalse((root / "recovered").exists())
            self.assertEqual(hashlib.sha256(image.read_bytes()).hexdigest(), self.digest)

    def test_types_filter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image = self._image(root)
            output = root / "only-jpg"
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "drive_recover",
                    str(image),
                    "-o",
                    str(output),
                    "--types",
                    "jpg",
                    "--yes",
                ],
                cwd=Path(__file__).resolve().parents[1],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            files = list(output.rglob("*"))
            names = [path.name for path in files if path.is_file()]
            self.assertTrue(all(name.endswith(".jpg") or name == "manifest.json" for name in names))
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual({item["type"] for item in manifest["files"]}, {"jpg"})
            self.assertEqual(len(manifest["files"]), 2)

    def test_bad_path_exits_2(self) -> None:
        proc = subprocess.run(
            [sys.executable, "-m", "drive_recover", "/no/such/drive-recover-image", "--yes", "--scan-only"],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 2)
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run(
                [sys.executable, "-m", "drive_recover", tmp, "--yes", "--scan-only"],
                cwd=Path(__file__).resolve().parents[1],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 2)

    def test_noninteractive_without_yes_exits_1(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "disk.img"
            _write(image, build_jpeg())
            proc = subprocess.run(
                [sys.executable, "-m", "drive_recover", str(image)],
                cwd=Path(__file__).resolve().parents[1],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 1)
            self.assertIn("--yes", proc.stderr)

    def test_yes_without_output_exits_1(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "disk.img"
            _write(image, build_jpeg() + b"\xA5" * 16)
            proc = subprocess.run(
                [sys.executable, "-m", "drive_recover", str(image), "--yes"],
                cwd=Path(__file__).resolve().parents[1],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 1)
            self.assertIn("output", proc.stderr.lower())

    def test_refuses_to_write_onto_the_image(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "disk.img"
            data = build_jpeg()
            _write(image, data)
            digest = hashlib.sha256(data).hexdigest()
            proc = subprocess.run(
                [sys.executable, "-m", "drive_recover", str(image), "-o", str(image), "--yes"],
                cwd=Path(__file__).resolve().parents[1],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 1)
            self.assertEqual(hashlib.sha256(image.read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
