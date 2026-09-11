"""Logging setup for local workers and Lambda."""

import logging
import sys


def configure_logging(level: str = "INFO") -> None:
    """Configure concise logs suitable for local development and CloudWatch."""

    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stdout,
        force=True,
    )
