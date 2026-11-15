from __future__ import annotations

import sys
import time
from pathlib import Path

from loguru import logger

logger.remove()

logger.add(
    sys.stderr,
    level="INFO",
    format="<level>{message}</level>",
    colorize=True,
)

_file_sink_id: int | None = None

def setup(*, validator: str = "parallel", level: str = "DEBUG") -> Path:
    global _file_sink_id
    log_dir = Path("log")
    log_dir.mkdir(exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    log_path = log_dir / f"{validator}-{ts}.log"

    if _file_sink_id is not None:
        logger.remove(_file_sink_id)

    _file_sink_id = logger.add(
        str(log_path),
        level=level,
        format="{time:HH:mm:ss} | {level:<5} | {message}",
        rotation="50 MB",
    )
    return log_path
