import datetime
import typing

import fastapi
import sqlalchemy as sa
from core import exceptions
from core.repositories import BaseRepository
from core.utils import get_logger

from . import hashers
from . import models as auth_models
from . import schemas as auth_schemas

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

    async def create(self, user: auth_schemas.UserCreate):
        logger.debug(user)

        hashed_password = hashers.hasher.get_hashed_password(user.password)

        user_dict = user.dict() | {
            "password": hashed_password,
            "is_active": True,
            "is_staff": False,
            "is_superuser": False,
            "date_joined": datetime.datetime.now(),
            "last_login": None,
        }

        logger.debug(f"user_dict: {user_dict}")

        stmt = auth_models.users.insert().values(**user_dict)

        return auth_schemas.User(
            **user_dict,
            id=await self.insert(stmt),
        )

    async def update_by_id(self, user: auth_schemas.UserCreate, user_id: int):
        user_dict = user.dict(exclude_unset=True)

        if not user_dict:
            raise exceptions.bad_request_exception()

        stmt = sa.update(auth_models.users).where(auth_models.users.c.id == user_id)

        user_model = await self.update_or_failure(
            stmt,
            user_dict,
            auth_schemas.User,
        )
        return fastapi.encoders.jsonable_encoder(user_model)

    async def delete_by_id(self, user_id: int):
        stmt = auth_models.users.delete().where(auth_models.users.c.id == user_id)
        await self.delete_one_or_404(stmt, "User")


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
