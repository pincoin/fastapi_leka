import logging

import fastapi

from core.config import settings


async def list_params(
    q: str | None = None,
    skip: int | None = fastapi.Query(default=None, ge=0),
    take: int | None = fastapi.Query(default=None, le=100),
) -> dict:
    return {"q": q, "skip": skip, "take": take}


def get_logger():
    logger = logging.getLogger()

    if not logger.handlers:
        if settings.debug:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.WARNING)

        handler = logging.FileHandler(settings.log_file)
        handler.setFormatter(
            logging.Formatter(
                "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S %z",
            ),
        )

        logger.addHandler(handler)

    return logger
