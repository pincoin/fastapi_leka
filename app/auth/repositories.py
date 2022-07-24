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
from .repository_mixins import UserClauseMixin

logger = get_logger()

logger.debug("auth services module imported")


class TokenRepository(BaseRepository):
    async def find_by_user_id(
        self,
        user_id: int,
    ):
        self.statement = (
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

        return await self.get_one_or_none()

    async def create(
        self,
        token_dict: dict,
    ) -> None:
        self.statement = auth_models.tokens.insert().values(**token_dict)

        try:
            await self.insert()
        except sa.exc.IntegrityError:
            raise exceptions.conflict_exception()


class UserRepository(BaseRepository, UserClauseMixin):
    async def find_all(
        self,
        is_active: bool | None = True,
        is_staff: bool | None = None,
        is_superuser: bool | None = None,
        skip: int | None = None,
        take: int | None = None,
    ) -> list[typing.Any]:
        self.statement = sa.select(auth_models.users)

        self.appendUserFlags(is_active, is_staff, is_superuser)
        self.append_skip_take(skip, take)

        return await self.get_all()

    async def find_by_id(
        self,
        user_id: int,
        is_superuser: bool | None = None,
        is_staff: bool | None = None,
        is_active: bool | None = True,
    ):
        self.statement = sa.select(auth_models.users).where(
            auth_models.users.c.id == user_id,
        )

        self.appendUserFlags(is_active, is_staff, is_superuser)

        return await self.get_one_or_404(auth_schemas.User.Config().title)

    async def find_by_id_active_true_superuser_true(
        self,
        user_id: int,
    ):
        self.statement = sa.select(auth_models.users).where(
            auth_models.users.c.id == user_id,
            auth_models.users.c.is_active == True,
            auth_models.users.c.is_superuser == True,
        )

        return await self.get_one_or_none()

    async def find_by_username(
        self,
        username: str,
        is_superuser: bool | None = None,
        is_staff: bool | None = None,
        is_active: bool | None = True,
    ):
        self.statement = sa.select(auth_models.users).where(
            auth_models.users.c.username == username,
        )

        self.appendUserFlags(is_active, is_staff, is_superuser)

        return await self.get_one_or_none()

    async def find_by_group_id(
        self,
        group_id: int,
        skip: int | None = None,
        take: int | None = None,
    ):
        self.statement = (
            sa.select(auth_models.users)
            .join_from(
                auth_models.users,
                auth_models.user_groups,
            )
            .where(auth_models.groups.c.id == group_id)
        )

        self.append_skip_take(skip, take)

        return await self.get_all()

    async def find_by_permission_id(
        self,
        permission_id: int,
        is_active=True,
        include_superusers=True,
        skip: int | None = None,
        take: int | None = None,
    ):
        self.statement = (
            sa.select(auth_models.users)
            .join_from(
                auth_models.users,
                auth_models.user_permissions,
            )
            .where(auth_models.user_permissions.c.permission_id == permission_id)
        )

        if is_active:
            self.statement = self.statement.where(auth_models.users.c.is_active == True)

        if not include_superusers:
            self.statement = self.statement.where(
                auth_models.users.c.is_superuser == False
            )

        self.append_skip_take(skip, take)

        return await self.get_all()

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

        self.statement = auth_models.users.insert().values(**user_dict)

        return auth_schemas.User(
            **user_dict,
            id=await self.insert(),
        )

    async def update_by_id(
        self,
        user: auth_schemas.UserUpdate,
        user_id: int,
        is_superuser: bool | None = None,
        is_staff: bool | None = None,
        is_active: bool | None = True,
    ):
        user_dict = user.dict(exclude_unset=True)

        if not user_dict:
            raise exceptions.bad_request_exception()

        self.statement = sa.update(auth_models.users).where(
            auth_models.users.c.id == user_id,
        )

        self.appendUserFlags(is_active, is_staff, is_superuser)

        user_model = await self.update_or_failure(
            user_dict,
            auth_schemas.User,
        )
        return fastapi.encoders.jsonable_encoder(user_model)

    async def delete_by_id(
        self,
        user_id: int,
        is_superuser: bool | None = None,
        is_staff: bool | None = None,
        is_active: bool | None = True,
    ):
        self.statement = auth_models.users.delete().where(
            auth_models.users.c.id == user_id,
            auth_models.users.c.is_active == True,
        )

        self.appendUserFlags(is_active, is_staff, is_superuser)

        await self.delete_one_or_404("User")

    async def add_permission(
        self,
        permission_id: int,
        user_id: int,
    ):
        user_permission_dict = {
            "permission_id": permission_id,
            "user_id": user_id,
        }

        self.statement = auth_models.user_permissions.insert().values(
            **user_permission_dict
        )

        return auth_schemas.UserPermission(
            **user_permission_dict,
            id=await self.insert(),
        )

    async def remove_permission(
        self,
        permission_id: int,
        user_id: int,
    ):
        self.statement = auth_models.user_permissions.delete().where(
            auth_models.user_permissions.c.user_id == user_id,
            auth_models.user_permissions.c.permission_id == permission_id,
        )
        await self.delete_one_or_404("User Permission")


class GroupRepository(BaseRepository, UserClauseMixin):
    async def find_all(
        self,
        skip: int | None = None,
        take: int | None = None,
    ) -> list[typing.Any]:
        self.statement = sa.select(auth_models.groups)

        self.append_skip_take(skip, take)

        return await self.get_all()

    async def find_by_id(
        self,
        group_id: int,
    ):
        self.statement = sa.select(auth_models.groups).where(
            auth_models.groups.c.id == group_id
        )
        return await self.get_one_or_404(auth_schemas.Group.Config().title)

    async def find_by_user_id(
        self,
        user_id: int,
        is_superuser: bool | None = None,
        is_staff: bool | None = None,
        is_active: bool | None = True,
        skip: int | None = None,
        take: int | None = None,
    ):
        self.statement = (
            sa.select(auth_models.groups)
            .join_from(
                auth_models.groups,
                auth_models.user_groups,
            )
            .where(
                auth_models.user_groups.c.user_id == user_id,
            )
        )

        self.appendUserFlags(is_active, is_staff, is_superuser)
        self.append_skip_take(skip, take)

        return await self.get_all()

    async def find_by_permission_id(
        self,
        permission_id: int,
        skip: int | None = None,
        take: int | None = None,
    ):
        self.statement = (
            sa.select(auth_models.groups)
            .join_from(
                auth_models.groups,
                auth_models.group_permissions,
            )
            .where(auth_models.permissions.c.permission_id == permission_id)
        )

        self.append_skip_take(skip, take)

        return await self.get_all()

    async def create(
        self,
        group: auth_schemas.GroupCreate,
    ):
        group_dict = group.dict()
        self.statement = auth_models.groups.insert().values(**group_dict)

        return auth_schemas.Group(
            **group_dict,
            id=await self.insert(),
        )

    async def update_by_id(
        self,
        group: auth_schemas.GroupUpdate,
        group_id: int,
    ):
        group_dict = group.dict(exclude_unset=True)

        if not group_dict:
            raise exceptions.bad_request_exception()

        self.statement = sa.update(auth_models.groups).where(
            auth_models.groups.c.id == group_id
        )

        group_model = await self.update_or_failure(
            group_dict,
            auth_schemas.Group,
        )
        return fastapi.encoders.jsonable_encoder(group_model)

    async def delete_by_id(
        self,
        group_id: int,
    ):
        self.statement = auth_models.groups.delete().where(
            auth_models.groups.c.id == group_id
        )
        await self.delete_one_or_404("Group")

    async def add_user(
        self,
        group_id: int,
        user_id: int,
    ):
        user_group_dict = {
            "user_id": user_id,
            "group_id": group_id,
        }

        self.statement = auth_models.user_groups.insert().values(**user_group_dict)

        return auth_schemas.UserGroup(
            **user_group_dict,
            id=await self.insert(),
        )

    async def remove_user(
        self,
        group_id: int,
        user_id: int,
    ):
        self.statement = auth_models.user_groups.delete().where(
            auth_models.user_groups.c.user_id == user_id,
            auth_models.user_groups.c.group_id == group_id,
        )
        await self.delete_one_or_404("User Group")

    async def add_permission(
        self,
        permission_id: int,
        group_id: int,
    ):
        group_permission_dict = {
            "permission_id": permission_id,
            "group_id": group_id,
        }

        self.statement = auth_models.group_permissions.insert().values(
            **group_permission_dict
        )

        return auth_schemas.GroupPermission(
            **group_permission_dict,
            id=await self.insert(),
        )

    async def remove_permission(
        self,
        permission_id: int,
        group_id: int,
    ):
        self.statement = auth_models.group_permissions.delete().where(
            auth_models.group_permissions.c.group_id == group_id,
            auth_models.group_permissions.c.permission_id == permission_id,
        )
        await self.delete_one_or_404("Group Permission")


class PermissionRepository(BaseRepository, UserClauseMixin):
    async def find_all(
        self,
        skip: int | None = None,
        take: int | None = None,
    ) -> list[typing.Any]:
        self.statement = sa.select(
            auth_models.permissions,
            auth_models.content_types.c.app_label,
            auth_models.content_types.c.model,
        ).join_from(
            auth_models.permissions,
            auth_models.content_types,
        )

        self.append_skip_take(skip, take)

        return await self.get_all()

    async def find_all_by_user_id(
        self,
        user_id: int,
        is_superuser: bool | None = None,
        is_staff: bool | None = None,
        is_active: bool | None = True,
    ):
        # 1. Caching required!
        # 2. Rules assumption required for tuning
        # - Rule 1: User-Permission many-to-many relations are disabled.
        # - Rule 2: Each user has to be a member of a group.
        # - Rule 3: User-Group relations is one-to-one.
        stmt1 = (
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
                auth_models.users,
            )
            .where(
                auth_models.users.c.user_id == user_id,
                auth_models.users.c.is_active == True,
            )
        )

        stmt1 = self.appendUserFlags(stmt1, is_active, is_staff, is_superuser)

        stmt2 = (
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
            .join_from(
                auth_models.group_permissions,
                auth_models.groups,
            )
            .join_from(
                auth_models.groups,
                auth_models.user_groups,
            )
            .join_from(
                auth_models.user_groups,
                auth_models.users,
            )
            .where(
                auth_models.users.c.user_id == user_id,
                auth_models.users.c.is_active == True,
            )
        )

        stmt2 = self.appendUserFlags(stmt2, is_active, is_staff, is_superuser)

        self.statement = sa.union(stmt1, stmt2)

        return await self.get_all()

    async def find_by_id(
        self,
        permission_id: int,
    ):
        self.statement = (
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

        return await self.get_one_or_404(auth_schemas.Permission.Config().title)

    async def find_by_user_id(
        self,
        user_id: int,
        skip: int | None = None,
        take: int | None = None,
    ):
        self.statement = (
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

        self.append_skip_take(skip, take)

        return await self.get_all()

    async def find_by_group_id(
        self,
        group_id: int,
        skip: int | None = None,
        take: int | None = None,
    ):
        self.statement = (
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

        self.append_skip_take(skip, take)

        return await self.get_all()

    async def find_by_group_id_by_user_id(
        self,
        user_id: int,
        is_superuser: bool | None = None,
        is_staff: bool | None = None,
        is_active: bool | None = True,
        skip: int | None = None,
        take: int | None = None,
    ):
        # permissions belongs to group which belongs to user
        self.statement = (
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
            .join_from(
                auth_models.group_permissions,
                auth_models.groups,
            )
            .join_from(
                auth_models.groups,
                auth_models.user_groups,
            )
            .join_from(
                auth_models.user_groups,
                auth_models.users,
            )
            .where(
                auth_models.users.c.user_id == user_id,
                auth_models.users.c.is_active == True,
            )
        )

        self.appendUserFlags(is_active, is_staff, is_superuser)
        self.append_skip_take(skip, take)

        return await self.get_all()

    async def find_by_content_type_id(
        self,
        content_type_id: int,
        skip: int | None = None,
        take: int | None = None,
    ):
        self.statement = (
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

        self.append_skip_take(skip, take)

        return await self.get_all()


class ContentTypeRepository(BaseRepository):
    async def find_all(
        self,
        app_label: str,
        model: str,
        skip: int | None = None,
        take: int | None = None,
    ) -> list[typing.Any]:
        self.statement = sa.select(auth_models.content_types)

        if app_label:
            self.statement = self.statement.where(
                auth_models.content_types.c.app_label == app_label
            )
        if model:
            self.statement = self.statement.where(
                auth_models.content_types.c.app_label == model
            )

        self.append_skip_take(skip, take)

        return await self.get_all()

    async def find_by_id(
        self,
        content_type_id: int,
    ):
        self.statement = sa.select(auth_models.content_types).where(
            auth_models.content_types.c.id == content_type_id
        )

        return await self.get_one_or_404(auth_schemas.ContentType.Config().title)

    async def find_by_permission_id(
        self,
        permission_id: int,
        skip: int | None = None,
        take: int | None = None,
    ):
        self.statement = (
            sa.select(auth_models.content_types)
            .join_from(
                auth_models.content_types,
                auth_models.permissions,
            )
            .where(auth_models.permissions.c.id == permission_id)
        )

        self.append_skip_take(skip, take)

        return await self.get_all()

    async def create(
        self,
        content_type: auth_schemas.ContentTypeCreate,
    ):
        content_type_dict = content_type.dict()
        self.statement = auth_models.content_types.insert().values(**content_type_dict)

        return auth_schemas.ContentType(
            **content_type_dict,
            id=await self.insert(),
        )

    async def update_by_id(
        self,
        content_type: auth_schemas.ContentTypeUpdate,
        content_type_id: int,
    ):
        content_type_dict = content_type.dict(exclude_unset=True)

        if not content_type_dict:
            raise exceptions.bad_request_exception()

        self.statement = sa.update(auth_models.content_types).where(
            auth_models.content_types.c.id == content_type_id
        )

        content_type_model = await self.update_or_failure(
            content_type_dict,
            auth_schemas.ContentType,
        )
        return fastapi.encoders.jsonable_encoder(content_type_model)

    async def delete_by_id(
        self,
        content_type_id: int,
    ):
        self.statement = auth_models.content_types.delete().where(
            auth_models.content_types.c.id == content_type_id
        )
        await self.delete_one_or_404("Content Type")

    async def add_permission(
        self,
        permission: auth_schemas.PermissionCreate,
        content_type_id: int,
    ):
        permission_dict = permission.dict()

        if permission_dict["content_type_id"] != content_type_id:
            raise exceptions.bad_request_exception()

        self.statement = auth_models.permissions.insert().values(**permission_dict)

        return auth_schemas.Permission(**permission_dict, id=await self.insert())

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

        self.statement = sa.update(auth_models.permissions).where(
            auth_models.permissions.c.id == permission_id
        )

        permission_model = await self.update_or_failure(
            permission_dict,
            auth_schemas.Permission,
        )
        return fastapi.encoders.jsonable_encoder(permission_model)

    async def remove_permission(
        self,
        content_type_id: int,
        permission_id: int,
    ):
        self.statement = auth_models.permissions.delete().where(
            auth_models.permissions.c.id == permission_id,
            auth_models.permissions.c.content_type_id == content_type_id,
        )

        await self.delete_one_or_404("Permission")
