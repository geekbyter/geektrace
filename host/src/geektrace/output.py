import sys

from .constants import LOG_PREFIX


def log(message: str, *, stream=None) -> None:
    target = stream if stream is not None else sys.stderr
    print(f"{LOG_PREFIX} {message}", file=target, flush=True)
