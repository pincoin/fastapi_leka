import os
import typing
from asyncio.log import logger

from core.utils import get_logger

from .database import engine

logger = get_logger()

logger.debug(f"core dependency module imported - [{os.getpid()}]")


async def engine_connect() -> typing.Generator:
    """
    “BEGIN (implicit)” starts transaction block by DBAPI (ie. PostgreSQL)
    even though SQLAlchemy did not actually send any command to the database.
    """
    async with engine.connect() as conn:
        logger.debug(f"engine.connect() - [{os.getpid()}]")
        yield conn

    logger.debug(f"engine connection is implictly closed. - [{os.getpid()}]")
    # await engine.dispose()
