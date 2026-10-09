"""Errors the CLI maps onto exit codes."""


class BadPath(Exception):
    """The image path cannot be read. Exit code 2."""


class UsageError(Exception):
    """The invocation is incomplete or would write to the image. Exit code 1."""
