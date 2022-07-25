import os
import typing
from asyncio.log import logger

import redis

from core.utils import get_logger

from .database import engine
from .redis_pool import rd_pool

logger = get_logger()

logger.debug(f"core dependency module imported - [{os.getpid()}]")


async def engine_connect() -> typing.Generator:
    # “BEGIN (implicit)” starts transaction block by DBAPI (ie. PostgreSQL)
    # even though SQLAlchemy did not actually send any command to the database.
    #
    # The connection is retrieved from the connection pool
    # at the point at which Connection is created.
    async with engine.connect() as conn:
        logger.debug(f"engine.connect() - [{os.getpid()}]")
        yield conn

        # At the end of the with: block, the Connection
        # is released to the connection pool not actually closed.
        logger.debug(f"sa engine closed (implicit) - [{os.getpid()}]")


async def redis_connect() -> typing.Generator:
    async with redis.StrictRedis(connection_pool=rd_pool) as conn:
        yield conn

        # At the end of the with: block, the Connection
        # is released to the connection pool not actually closed.
        logger.debug(f"redis closed (implicit) - [{os.getpid()}]")
