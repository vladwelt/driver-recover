# drive-recover

`drive-recover` reads a disk image and copies out common files it can recognize by their byte signatures. The image may be intact or damaged. This does not mount a filesystem, and it does not repair one. A boot sector or superblock is reported only when the magic is obvious, and carving does not depend on it.

The source image is opened read-only and is never modified.

## Install

```bash
pip install -e .
```

Python 3.11 or newer. The tool uses the standard library only.

## Run

Pass the image path. When the optional flags are left off and stdin is a terminal, the tool asks you to confirm the image, shows a short evaluation, scans, prints counts by type (complete versus partial), then asks which types to keep and where to write them.

```bash
drive-recover disk.img
python -m drive_recover disk.img
```

Skip the prompts with `--yes`. Non-interactive recovery requires an output directory. `--scan-only` prints the counts and writes nothing.

```bash
drive-recover disk.img --scan-only --yes
drive-recover disk.img -o recovered --types jpg,png,pdf,docx --yes
drive-recover disk.img -o recovered --yes --max-bytes 67108864
```

| Flag | Meaning |
| --- | --- |
| `-o`, `--output` | Directory for recovered files and `manifest.json` |
| `--types` | Comma-separated types to keep (`jpeg` is `jpg`, `tif` is `tiff`) |
| `--yes` | Do not prompt |
| `--scan-only` | Scan and print counts; do not write files |
| `--max-bytes` | How far to search for a JPEG EOI or PDF `%%EOF`, and the cap for a file whose end is not known (default 32 MiB) |

Progress is written to stderr.

Exit codes: `0` when the scan or recovery finishes, `2` when the image path is missing, a directory, or unreadable, `1` for any other error (including a non-interactive run that still needs an answer).

## Supported types

| Type | How the end is found |
| --- | --- |
| jpg | JPEG markers through the EOI (`FF D9`) |
| png | Chunks through a valid `IEND` |
| gif | Blocks through the trailer |
| bmp | Size in the file header |
| webp, wav | RIFF size, walked chunk by chunk |
| tiff | Strip or tile offsets in the IFD |
| pdf | First `%%EOF` (an embedded file stays inside the PDF when `startxref` follows it) |
| docx, xlsx, pptx, zip | ZIP local headers through the end of the central directory. `[Content_Types].xml` separates Office Open XML from a generic zip |
| doc, xls, ppt, ole | OLE compound file. Stream names `WordDocument`, `Workbook` / `Book`, and `PowerPoint Document` pick the Office type; anything else is `ole` |
| rar | RAR 4.x or 5.x blocks through the end marker |
| 7z | Start header (CRC checked) plus the next-header range |
| mp3 | ID3v2 tag and/or consecutive MPEG frames |
| mp4 | Top-level boxes starting at `ftyp` |

If a JPEG or PDF has no footer inside `--max-bytes`, the saved file is marked `partial` and stops at the next recognized header (or at the cap). That keeps a truncated file from swallowing everything after it. Container formats are walked by their own structure, so headers inside a ZIP, PNG, OLE file, and the other structured types are not reported again.

## Output

```text
recovered/
  jpg/1040.jpg
  pdf/8192.pdf
  docx/16384.docx
  manifest.json
```

`manifest.json` lists `offset`, `type`, `size`, `status` (`complete` or `partial`), and `sha256`, plus the relative `path`.

## Tests

```bash
python -m unittest discover -s tests -v
```

The tests build a synthetic image: noise, an intact JPEG, PNG, PDF, and DOCX, a JPEG with no EOI, and a PDF with no `%%EOF`. They check type, status, and that the source bytes do not change.
