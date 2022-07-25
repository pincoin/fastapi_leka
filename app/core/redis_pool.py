import os

import redis

from core.utils import get_logger

from .config import settings

logger = get_logger()

rd_pool = redis.ConnectionPool(
    host=settings.redis_uri.host,
    port=settings.redis_uri.port,
    db=int(settings.redis_uri.path[1:]),
    username=settings.redis_uri.user,
    password=settings.redis_uri.password,
)


logger.debug(f"redis pool created - [{os.getpid()}]")
