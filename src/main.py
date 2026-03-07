"""Main entry point for Sentinel-AI."""

from __future__ import annotations

import asyncio
import logging
import sys

import uvicorn

from src.api.server import create_app
from src.core.config import SentinelConfig


def setup_logging(config: SentinelConfig) -> None:
    level = getattr(logging, config.log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def main() -> None:
    config = SentinelConfig.from_yaml()
    setup_logging(config)

    app = create_app()
    uvicorn.run(
        app,
        host=config.api.host,
        port=config.api.port,
        log_level=config.log_level.lower(),
    )


if __name__ == "__main__":
    main()
