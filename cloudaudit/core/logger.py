"""cloudaudit — Logging Configuration"""

from __future__ import annotations

import logging
import sys
from typing import Optional

_LOG_FORMAT  = "%(asctime)s [%(levelname)-8s] %(name)s — %(message)s"
_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"


def configure_logging(
    verbose: bool = False,
    debug:   bool = False,
    log_file: Optional[str] = None,
) -> None:
    level = logging.WARNING
    if verbose:
        level = logging.INFO
    if debug:
        level = logging.DEBUG

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

    logging.basicConfig(
        level=level,
        format=_LOG_FORMAT,
        datefmt=_DATE_FORMAT,
        handlers=handlers,
        force=True,
    )

    for noisy in ("aiohttp", "asyncio", "urllib3", "PIL"):
        logging.getLogger(noisy).setLevel(logging.ERROR)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"cloudaudit.{name}")
