"""Rotating file + console logging, shared by every CLI command.

Mirrors a simple, deterministic convention: one named logger per module
under the ``scripter`` namespace, a rotating file handler so a long
competition session doesn't grow one unbounded log file, and a console
handler for interactive use. Nothing here ever logs full request/response
payloads - only the structured fields each module already extracted.
"""
from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path


def configure_logging(log_dir: Path, level: str = "INFO", max_bytes: int = 5_000_000, backup_count: int = 3) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger("scripter")
    root.setLevel(level.upper())
    root.handlers.clear()

    fmt = logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")

    file_handler = logging.handlers.RotatingFileHandler(
        log_dir / "scripter.log", maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
    )
    file_handler.setFormatter(fmt)
    root.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(fmt)
    root.addHandler(console_handler)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"scripter.{name}")
