"""Small Expo-style prompts. Used only when flags are omitted."""

from __future__ import annotations

import sys

from drive_recover.errors import UsageError


def _paint(code: str, text: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def banner() -> None:
    print(_paint("1", "drive-recover"))
    print("Carve files out of a disk image. The image is never modified.")
    print()


def ensure_tty() -> None:
    if not sys.stdin.isatty():
        raise UsageError("stdin is not a terminal; pass --yes and the flags you need")


def _readline(prompt: str) -> str:
    """Read one line. The prompt is written to stdout, not via readline."""
    sys.stdout.write(prompt)
    sys.stdout.flush()
    try:
        line = sys.stdin.readline()
    except EOFError:
        line = ""
    if line == "":
        raise UsageError("input closed; pass --yes and the flags you need")
    return line.strip()


def ask(question: str, default: str | None = None) -> str:
    ensure_tty()
    hint = f" [{default}]" if default else ""
    answer = _readline(f"{_paint('36', '?')} {question}{hint} ")
    if answer == "" and default is not None:
        return default
    return answer


def confirm(question: str, default: bool = True) -> bool:
    ensure_tty()
    suffix = "Y/n" if default else "y/N"
    prompt = f"{_paint('36', '?')} {question} ({suffix}) "
    while True:
        answer = _readline(prompt).lower()
        if answer == "":
            return default
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        print("Please answer yes or no.")
