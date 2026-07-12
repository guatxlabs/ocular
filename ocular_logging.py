from __future__ import annotations

import logging
import sys

from ocular_settings import log_level

_CONFIGURED = False


def get_logger(name: str, stream=None) -> logging.Logger:
    global _CONFIGURED
    if not _CONFIGURED:
        handler = logging.StreamHandler(stream or sys.stdout)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s"))
        root = logging.getLogger("ocular")
        root.handlers[:] = [handler]
        root.setLevel(log_level())
        _CONFIGURED = True
    return logging.getLogger("ocular." + name)
