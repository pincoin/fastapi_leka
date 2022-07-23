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

logger.debug("auth services module imported")


class TokenService(BaseRepository):
    async def find_by_user_id(
        self,
        user_id: int,
    ):
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

    async def find_by_id(
        self,
        user_id: int,
    ):
        stmt = sa.select(auth_models.users).where(
            auth_models.users.c.id == user_id,
            auth_models.users.c.is_active == True,
        )
        return await self.get_one_or_404(stmt, auth_schemas.User.Config().title)

    async def find_by_id_active_true_superuser_true(
        self,
        user_id: int,
    ):
        stmt = sa.select(auth_models.users).where(
            auth_models.users.c.id == user_id,
            auth_models.users.c.is_active == True,
            auth_models.users.c.is_superuser == True,
        )

        return await self.get_one_or_none(stmt)

    async def find_by_username(
        self,
        username: str,
    ):
        stmt = sa.select(auth_models.users).where(
            auth_models.users.c.username == username,
            auth_models.users.c.is_active == True,
        )
        return await self.get_one_or_none(stmt)

    async def find_by_group_id(
        self,
        group_id: int,
        skip: int,
        take: int,
    ):
        stmt = (
            sa.select(auth_models.users)
            .join_from(
                auth_models.users,
                auth_models.user_groups,
            )
            .where(auth_models.groups.c.id == group_id)
        )
        stmt = stmt.offset(skip).limit(take)

        return await self.get_all(stmt)

    async def find_by_permission_id(
        self,
        permission_id: int,
        skip: int,
        take: int,
    ):
        stmt = (
            sa.select(auth_models.users)
            .join_from(
                auth_models.users,
                auth_models.user_permissions,
            )
            .where(auth_models.user_permissions.c.permission_id == permission_id)
        )
        stmt = stmt.offset(skip).limit(take)
        return await self.get_all(stmt)

    async def create(
        self,
        user: auth_schemas.UserCreate,
    ):
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

    async def update_by_id(
        self,
        user: auth_schemas.UserUpdate,
        user_id: int,
    ):
        user_dict = user.dict(exclude_unset=True)

        if not user_dict:
            raise exceptions.bad_request_exception()

        stmt = sa.update(auth_models.users).where(
            auth_models.users.c.id == user_id,
            auth_models.users.c.is_active == True,
        )

        user_model = await self.update_or_failure(
            stmt,
            user_dict,
            auth_schemas.User,
        )
        return fastapi.encoders.jsonable_encoder(user_model)

    async def delete_by_id(
        self,
        user_id: int,
    ):
        stmt = auth_models.users.delete().where(
            auth_models.users.c.id == user_id,
            auth_models.users.c.is_active == True,
        )
        await self.delete_one_or_404(stmt, "User")

    async def add_permission(
        self,
        permission_id: int,
        user_id: int,
    ):
        user_permission_dict = {
            "permission_id": permission_id,
            "user_id": user_id,
        }

        stmt = auth_models.user_permissions.insert().values(**user_permission_dict)

        return auth_schemas.UserPermission(
            **user_permission_dict,
            id=await self.insert(stmt),
        )

    async def remove_permission(
        self,
        permission_id: int,
        user_id: int,
    ):
        stmt = auth_models.user_permissions.delete().where(
            auth_models.user_permissions.c.user_id == user_id,
            auth_models.user_permissions.c.permission_id == permission_id,
        )
        await self.delete_one_or_404(stmt, "User Permission")


class GroupService(BaseRepository):
    async def find_all(
        self,
        skip: int,
        take: int,
    ) -> list[typing.Any]:
        stmt = sa.select(auth_models.groups).offset(skip).limit(take)
        return await self.get_all(stmt)

    async def find_by_id(
        self,
        group_id: int,
    ):
        stmt = sa.select(auth_models.groups).where(auth_models.groups.c.id == group_id)
        return await self.get_one_or_404(stmt, auth_schemas.Group.Config().title)

    async def find_by_user_id(
        self,
        user_id: int,
        skip: int,
        take: int,
    ):
        stmt = (
            sa.select(auth_models.groups)
            .join_from(
                auth_models.groups,
                auth_models.user_groups,
            )
            .where(
                auth_models.user_groups.c.user_id == user_id,
                auth_models.users.c.is_active == True,
            )
        )
        stmt = stmt.offset(skip).limit(take)

        return await self.get_all(stmt)

    async def find_by_permission_id(
        self,
        permission_id: int,
        skip: int,
        take: int,
    ):
        stmt = (
            sa.select(auth_models.groups)
            .join_from(
                auth_models.groups,
                auth_models.group_permissions,
            )
            .where(auth_models.permissions.c.permission_id == permission_id)
        )
        stmt = stmt.offset(skip).limit(take)

        return await self.get_all(stmt)

    async def create(
        self,
        group: auth_schemas.GroupCreate,
    ):
        group_dict = group.dict()
        stmt = auth_models.groups.insert().values(**group_dict)

        return auth_schemas.Group(
            **group_dict,
            id=await self.insert(stmt),
        )

    async def update_by_id(
        self,
        group: auth_schemas.GroupUpdate,
        group_id: int,
    ):
        group_dict = group.dict(exclude_unset=True)

        if not group_dict:
            raise exceptions.bad_request_exception()

        stmt = sa.update(auth_models.groups).where(auth_models.groups.c.id == group_id)

        group_model = await self.update_or_failure(
            stmt,
            group_dict,
            auth_schemas.Group,
        )
        return fastapi.encoders.jsonable_encoder(group_model)

    async def delete_by_id(
        self,
        group_id: int,
    ):
        stmt = auth_models.groups.delete().where(auth_models.groups.c.id == group_id)
        await self.delete_one_or_404(stmt, "Group")

    async def add_user(
        self,
        group_id: int,
        user_id: int,
    ):
        user_group_dict = {
            "user_id": user_id,
            "group_id": group_id,
        }

        stmt = auth_models.user_groups.insert().values(**user_group_dict)

        return auth_schemas.UserGroup(
            **user_group_dict,
            id=await self.insert(stmt),
        )

    async def remove_user(
        self,
        group_id: int,
        user_id: int,
    ):
        stmt = auth_models.user_groups.delete().where(
            auth_models.user_groups.c.user_id == user_id,
            auth_models.user_groups.c.group_id == group_id,
        )
        await self.delete_one_or_404(stmt, "User Group")

    async def add_permission(
        self,
        permission_id: int,
        group_id: int,
    ):
        group_permission_dict = {
            "permission_id": permission_id,
            "group_id": group_id,
        }

        stmt = auth_models.group_permissions.insert().values(**group_permission_dict)

        return auth_schemas.GroupPermission(
            **group_permission_dict,
            id=await self.insert(stmt),
        )

    async def remove_permission(
        self,
        permission_id: int,
        group_id: int,
    ):
        stmt = auth_models.group_permissions.delete().where(
            auth_models.group_permissions.c.group_id == group_id,
            auth_models.group_permissions.c.permission_id == permission_id,
        )
        await self.delete_one_or_404(stmt, "Group Permission")


class PermissionService(BaseRepository):
    async def find_all(
        self,
        skip: int,
        take: int,
    ) -> list[typing.Any]:
        stmt = sa.select(
            auth_models.permissions,
            auth_models.content_types.c.app_label,
            auth_models.content_types.c.model,
        ).join_from(
            auth_models.permissions,
            auth_models.content_types,
        )

        stmt = stmt.offset(skip).limit(take)

        return await self.get_all(stmt)

    async def find_by_id(
        self,
        permission_id: int,
    ):
        stmt = (
            sa.select(
                auth_models.permissions,
                auth_models.content_types.c.app_label,
                auth_models.content_types.c.model,
            )
            .join_from(
                auth_models.permissions,
                auth_models.content_types,
            )
            .where(auth_models.permissions.c.id == permission_id)
        )

        return await self.get_one_or_404(stmt, auth_schemas.Permission.Config().title)

    async def find_by_user_id(
        self,
        user_id: int,
        skip: int,
        take: int,
    ):
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

        stmt = stmt.offset(skip).limit(take)

        return await self.get_all(stmt)

    async def find_by_group_id(
        self,
        group_id: int,
        skip: int,
        take: int,
    ):
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
                auth_models.group_permissions,
            )
            .where(auth_models.group_permissions.c.group_id == group_id)
        )
        stmt = stmt.offset(skip).limit(take)

        return await self.get_all(stmt)

    async def find_by_content_type_id(
        self,
        content_type_id: int,
        skip: int,
        take: int,
    ):
        stmt = (
            sa.select(
                auth_models.permissions,
                auth_models.content_types.c.app_label,
                auth_models.content_types.c.model,
            )
            .join_from(
                auth_models.permissions,
                auth_models.content_types,
            )
            .where(auth_models.content_types.c.id == content_type_id)
        )
        stmt = stmt.offset(skip).limit(take)

        return await self.get_all(stmt)


class ContentTypeService(BaseRepository):
    async def find_all(
        self,
        app_label: str,
        model: str,
        skip: int,
        take: int,
    ) -> list[typing.Any]:
        stmt = sa.select(auth_models.content_types)

        if app_label:
            stmt = stmt.where(auth_models.content_types.c.app_label == app_label)
        if model:
            stmt = stmt.where(auth_models.content_types.c.app_label == model)

        stmt = stmt.offset(skip).limit(take)

        return await self.get_all(stmt)

    async def find_by_id(
        self,
        content_type_id: int,
    ):
        stmt = sa.select(auth_models.content_types).where(
            auth_models.content_types.c.id == content_type_id
        )

        return await self.get_one_or_404(stmt, auth_schemas.ContentType.Config().title)

    async def find_by_permission_id(
        self,
        permission_id: int,
        skip: int,
        take: int,
    ):
        stmt = (
            sa.select(auth_models.content_types)
            .join_from(
                auth_models.content_types,
                auth_models.permissions,
            )
            .where(auth_models.permissions.c.id == permission_id)
        )
        stmt = stmt.offset(skip).limit(take)

        return await self.get_all(stmt)

    async def create(
        self,
        content_type: auth_schemas.ContentTypeCreate,
    ):
        content_type_dict = content_type.dict()
        stmt = auth_models.content_types.insert().values(**content_type_dict)

        return auth_schemas.ContentType(
            **content_type_dict,
            id=await self.insert(stmt),
        )

    async def update_by_id(
        self,
        content_type: auth_schemas.ContentTypeUpdate,
        content_type_id: int,
    ):
        content_type_dict = content_type.dict(exclude_unset=True)

        if not content_type_dict:
            raise exceptions.bad_request_exception()

        stmt = sa.update(auth_models.content_types).where(
            auth_models.content_types.c.id == content_type_id
        )

        content_type_model = await self.update_or_failure(
            stmt,
            content_type_dict,
            auth_schemas.ContentType,
        )
        return fastapi.encoders.jsonable_encoder(content_type_model)

    async def delete_by_id(
        self,
        content_type_id: int,
    ):
        stmt = auth_models.content_types.delete().where(
            auth_models.content_types.c.id == content_type_id
        )
        await self.delete_one_or_404(stmt, "Content Type")

    async def add_permission(
        self,
        permission: auth_schemas.PermissionCreate,
        content_type_id: int,
    ):
        permission_dict = permission.dict()

        if permission_dict["content_type_id"] != content_type_id:
            raise exceptions.bad_request_exception()

        stmt = auth_models.permissions.insert().values(**permission_dict)

        return auth_schemas.Permission(**permission_dict, id=await self.insert(stmt))

    async def update_permission(
        self,
        permission: auth_schemas.PermissionUpdate,
        content_type_id: int,
        permission_id: int,
    ):
        permission_dict = permission.dict(exclude_unset=True)

        if not permission_dict:
            raise exceptions.bad_request_exception()

        if permission_dict["content_type_id"] != content_type_id:
            raise exceptions.bad_request_exception()

        stmt = sa.update(auth_models.permissions).where(
            auth_models.permissions.c.id == permission_id
        )

        permission_model = await self.update_or_failure(
            stmt,
            permission_dict,
            auth_schemas.Permission,
        )
        return fastapi.encoders.jsonable_encoder(permission_model)

    async def remove_permission(
        self,
        content_type_id: int,
        permission_id: int,
    ):
        stmt = auth_models.permissions.delete().where(
            auth_models.permissions.c.id == permission_id,
            auth_models.permissions.c.content_type_id == content_type_id,
        )

        await self.delete_one_or_404(stmt, "Permission")
