import sqlalchemy as sa
from core import exceptions
from core.repositories import BaseRepository
from core.utils import get_logger

from . import models as auth_models

logger = get_logger()

logger.debug("auth repositories module imported")


class TokenRepository(BaseRepository):
    async def get_by_user_id(self, user_id: int):
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

    async def create_refresh_token(
        self,
        token_dict: dict,
    ) -> None:
        stmt = auth_models.tokens.insert().values(**token_dict)

        try:
            await self.insert(stmt)
        except sa.exc.IntegrityError:
            raise exceptions.conflict_exception()


class UserRepository(BaseRepository):
    async def get_by_username(self, username: str):
        stmt = sa.select(auth_models.users).where(
            auth_models.users.c.username == username,
            auth_models.users.c.is_active == True,
        )

        return await self.get_one_or_none(stmt)


class GroupRepository(BaseRepository):
    pass


class PermissionRepository(BaseRepository):
    async def get_by_user_id(self, user_id: int):
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


class ContentTypeRepository(BaseRepository):
    pass