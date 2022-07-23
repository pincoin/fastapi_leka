import typing
import datetime

import sqlalchemy as sa
from core import exceptions
from core.repositories import BaseRepository
from core.utils import get_logger

from . import models as auth_models
from . import schemas as auth_schemas
from . import hashers

logger = get_logger()

logger.debug("auth repositories module imported")


class TokenService(BaseRepository):
    async def find_by_user_id(self, user_id: int):
        stmt = (
            sa.select(
                auth_models.tokens,
                auth_models.users.c.username,
            )
            .join_from(
                auth_models.tokens,
                auth_models.users,
            )
            .where(
                auth_models.tokens.c.user_id == user_id,
                auth_models.users.c.is_active == True,
            )
        )

        return await self.get_one_or_none(stmt)

    async def create(
        self,
        token_dict: dict,
    ) -> None:
        stmt = auth_models.tokens.insert().values(**token_dict)

        try:
            await self.insert(stmt)
        except sa.exc.IntegrityError:
            raise exceptions.conflict_exception()


class UserService(BaseRepository):
    async def find_all(
        self,
        is_active: bool,
        is_staff: bool,
        is_superuser: bool,
        skip: int,
        take: int,
    ) -> list[typing.Any]:
        stmt = sa.select(auth_models.users)

        if is_active:
            stmt = stmt.where(auth_models.users.c.is_active == is_active)
        if is_staff:
            stmt = stmt.where(auth_models.users.c.is_staff == is_staff)
        if is_superuser:
            stmt = stmt.where(auth_models.users.c.is_superuser == is_superuser)

        stmt = stmt.offset(skip).limit(take)

        return await self.get_all(stmt)

    async def find_by_id(self, user_id: int):
        stmt = sa.select(auth_models.users).where(auth_models.users.c.id == user_id)
        return await self.get_one_or_404(stmt, auth_schemas.User.Config().title)

    async def find_by_username(self, username: str):
        stmt = sa.select(auth_models.users).where(
            auth_models.users.c.username == username,
            auth_models.users.c.is_active == True,
        )
        return await self.get_one_or_none(stmt)

    async def create(self, user):
        hashed_password = hashers.hasher.get_hashed_password(user.password)
        logger.debug("create 3")
        user_dict = user.dict() | {
            "password": hashed_password,
            "is_active": True,
            "is_staff": False,
            "is_superuser": False,
            "date_joined": datetime.datetime.now(),
            "last_login": None,
        }
        logger.debug("create 4")
        stmt = auth_models.users.insert().values(**user_dict)
        logger.debug("create 5")
        logger.debug(stmt)
        logger.debug("create 6")
        id = await self.insert(stmt)
        logger.debug("create 7")
        logger.debug(id)
        logger.debug(user_dict)

        return auth_schemas.User(id=id, **user_dict)


class GroupService(BaseRepository):
    pass


class PermissionService(BaseRepository):
    async def find_by_user_id(self, user_id: int):
        stmt = (
            sa.select(
                auth_models.permissions,
                auth_models.content_types.c.app_label,
                auth_models.content_types.c.model,
            )
            .join_from(
                auth_models.content_types,
                auth_models.permissions,
            )
            .join_from(
                auth_models.permissions,
                auth_models.user_permissions,
            )
            .join_from(
                auth_models.user_permissions,
                auth_models.user,
            )
            .where(
                auth_models.users.c.user_id == user_id,
                auth_models.users.c.is_active == True,
            )
        )

        return await self.get_all(stmt)


class ContentTypeService(BaseRepository):
    pass
