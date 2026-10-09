"""Interactive and flagged entry points for drive-recover."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from drive_recover import __version__
from drive_recover.carve import DEFAULT_CHUNK, DEFAULT_MAX_BYTES, scan_image
from drive_recover.errors import BadPath, UsageError
from drive_recover.evaluate import ImageInfo, evaluate, human_size
from drive_recover.extract import extract
from drive_recover.models import Hit
from drive_recover.progress import Progress
from drive_recover.prompts import banner, confirm, ask
from drive_recover.typeset import parse_types


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="drive-recover",
        description="Recover common files from a disk image by carving signatures. The image is never modified.",
        epilog=(
            "examples:\n"
            "  drive-recover disk.img\n"
            "  drive-recover disk.img --scan-only --yes\n"
            "  drive-recover disk.img -o recovered --types jpg,png,pdf,docx --yes\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("image", help="Disk image to read (opened read-only)")
    parser.add_argument("-o", "--output", help="Directory for recovered files and manifest.json")
    parser.add_argument("--types", help="Comma-separated types to recover (default: all)")
    parser.add_argument("--yes", action="store_true", help="Do not prompt; require -o unless --scan-only")
    parser.add_argument("--scan-only", action="store_true", help="Scan and print counts; do not write files")
    parser.add_argument(
        "--max-bytes",
        type=_positive_int,
        default=DEFAULT_MAX_BYTES,
        help=f"Cap for files with no footer, and the JPEG/PDF footer search window (default: {DEFAULT_MAX_BYTES})",
    )
    parser.add_argument("--version", action="version", version=f"drive-recover {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(line_buffering=True)
        except (AttributeError, OSError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    try:
        return _run(args)
    except BadPath as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except UsageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 — top-level boundary for exit code 1
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _run(args: argparse.Namespace) -> int:
    image = Path(args.image)
    if not args.yes:
        banner()
    info = evaluate(image)
    _print_info(info)
    if not args.yes and not confirm(f"Scan {info.path.name}?", default=True):
        print("Cancelled.")
        return 0

    bar = Progress("scan")
    try:
        hits = scan_image(
            info.path,
            max_bytes=args.max_bytes,
            chunk_size=DEFAULT_CHUNK,
            progress=lambda current, total, found: bar.update(
                current,
                total,
                "1 file" if found == 1 else f"{found} files",
            ),
        )
    finally:
        bar.close()

    print()
    print(format_summary(hits))
    if args.scan_only:
        return 0

    selected = parse_types(args.types) if args.types else None
    if selected is None and not args.yes:
        found = _found_types(hits)
        if not hits:
            print("No matching files.")
            return 0
        default = ",".join(found)
        raw = ask("Types to recover", default=default)
        if raw.lower() != "all":
            selected = parse_types(raw)
    matching = [hit for hit in hits if selected is None or hit.type in selected]
    if not matching:
        if args.output:
            extract(info.path, [], Path(args.output))
            print(f"No matching files. Wrote {Path(args.output) / 'manifest.json'}")
        else:
            print("No matching files.")
        return 0

    if args.output:
        output = Path(args.output)
    elif args.yes:
        raise UsageError("output directory is required with --yes (pass -o)")
    else:
        output = Path(ask("Output directory", default="recovered"))

    if not args.yes and not confirm(f"Write {len(matching)} files to {output}?", default=True):
        print("Cancelled.")
        return 0

    recover = Progress("recover", byte_counts=False)
    try:
        records = extract(
            info.path,
            matching,
            output,
            progress=lambda current, total: recover.update(current, total),
        )
    finally:
        recover.close()
    print(f"Wrote {len(records)} files to {output}")
    print(f"Manifest {Path(output) / 'manifest.json'}")
    return 0


def _print_info(info: ImageInfo) -> None:
    hint = info.filesystem or "no boot sector or superblock signature"
    print(info.path.name)
    print(f"  size         {human_size(info.size)}")
    print(f"  readable     {'yes' if info.readable else 'no'}")
    print(f"  filesystem   {hint}")
    print()


def format_summary(hits: list[Hit]) -> str:
    if not hits:
        return "No files found."
    counts: dict[str, list[int]] = {}
    for hit in hits:
        bucket = counts.setdefault(hit.type, [0, 0])
        if hit.status == "complete":
            bucket[0] += 1
        else:
            bucket[1] += 1
    lines = [f"{'type':<8} {'complete':>8}  {'partial':>7}", f"{'----':<8} {'--------':>8}  {'-------':>7}"]
    for name in sorted(counts):
        complete, partial = counts[name]
        lines.append(f"{name:<8} {complete:8d}  {partial:7d}")
    complete = sum(1 for hit in hits if hit.status == "complete")
    partial = len(hits) - complete
    noun = "file" if len(hits) == 1 else "files"
    lines.append("")
    lines.append(f"{len(hits)} {noun} ({complete} complete, {partial} partial)")
    return "\n".join(lines)


def _found_types(hits: list[Hit]) -> list[str]:
    found: list[str] = []
    for hit in hits:
        if hit.type not in found:
            found.append(hit.type)
    return found


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number

