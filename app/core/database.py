import os
from functools import lru_cache

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

from core.utils import get_logger

from .config import settings

logger = get_logger()

kwargs = {
    "echo": settings.sqlalchemy_echo,
    "pool_size": settings.sqlalchemy_pool_size,
    "max_overflow": settings.sqlalchemy_max_overflow,
    "pool_recycle": settings.sqlalchemy_pool_recycle,
    "pool_timeout": settings.sqlalchemy_pool_timeout,
}

logger.debug(f"database module imported - [{os.getpid()}]")


engine = create_async_engine(
    # dialect+driver://username:password@host:port/database
    settings.sqlalchemy_database_uri,
    **kwargs,
)

# SQLAlchemy engine instance (lazy initialization)
# Engine is a factory for connections as well as a pool of connections
# Engine is held globally for the lifetime of a single application process.
logger.debug(f"sqlalchemy.async.engine created - [{os.getpid()}]")


@lru_cache(maxsize=1)
def get_metadata() -> sa.sql.schema.MetaData:
    return sa.MetaData()


metadata: sa.sql.schema.MetaData = get_metadata()
