import abc
import datetime
import importlib
import typing
from functools import lru_cache

import fastapi
import sqlalchemy as sa
from core import exceptions
from core.config import settings
from core.utils import get_logger
from jose import JWTError, jwt

from . import hashers, repositories

logger = get_logger()

oauth2_scheme = fastapi.security.OAuth2PasswordBearer(tokenUrl="/auth/token")


class BaseAuthenticationBackend(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    async def get_current_user(self, **kwargs) -> dict:
        pass

    @abc.abstractmethod
    async def authenticate(self, **kwargs) -> dict | None:
        pass

    @abc.abstractmethod
    def create_access_token(self, **kwargs) -> typing.Any:
        pass

    @abc.abstractmethod
    def create_refresh_token(self, **kwargs) -> typing.Any:
        pass

    @abc.abstractmethod
    async def get_user_permissions(self, **kwargs) -> typing.Any:
        pass

    @abc.abstractmethod
    async def get_group_permissions(self, **kwargs) -> typing.Any:
        pass

    @abc.abstractmethod
    async def get_all_permissions(self, **kwargs) -> typing.Any:
        pass

    @abc.abstractmethod
    async def has_perm(self, **kwargs) -> bool:
        pass


class AuthenticationBackend(BaseAuthenticationBackend):
    async def get_current_user(
        self,
        token: str = fastapi.Depends(oauth2_scheme),
    ) -> dict:
        try:
            payload = jwt.decode(
                token,
                settings.jwt_secret_key,
                algorithms=[settings.jwt_algorithm],
            )

            logger.info(
                datetime.datetime.fromtimestamp(
                    payload["exp"], tz=datetime.timezone.utc
                )
            )
            logger.info(datetime.datetime.now(tz=datetime.timezone.utc))

            if datetime.datetime.fromtimestamp(
                payload["exp"], tz=datetime.timezone.utc
            ) < datetime.datetime.now(tz=datetime.timezone.utc):
                raise exceptions.invalid_token_exception()

            username: str = payload.get("sub")
            user_id: int = payload.get("id")

            if username is None or user_id is None:
                raise exceptions.invalid_token_exception()

            return {"username": username, "id": user_id}
        except JWTError:
            raise exceptions.invalid_token_exception()

    async def authenticate(
        self,
        username: str,
        password: str,
    ) -> dict | None:
        user_row = await repositories.UserRepository().find_by_username(username)

        if not user_row:
            return False

        user_dict = user_row._mapping

        if not hashers.hasher.verify_password(password, user_dict["password"]):
            return False

        return user_dict

    def create_access_token(
        self,
        username: str,
        user_id: int,
        expires_delta: datetime.timedelta | None,
    ) -> typing.Any:
        if expires_delta:
            expire = datetime.datetime.utcnow() + expires_delta
        else:
            expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)

        payload = {
            "sub": username,
            "id": user_id,
            "exp": expire,
        }

        return jwt.encode(
            payload,
            settings.jwt_secret_key,
            algorithm=settings.jwt_algorithm,
        )

    def create_refresh_token(
        self,
        user_id: int,
        expires_delta: datetime.timedelta | None,
    ) -> typing.Any:
        if expires_delta:
            expire = datetime.datetime.utcnow() + expires_delta
        else:
            expire = datetime.datetime.utcnow() + datetime.timedelta(days=14)

        payload = {
            "id": user_id,
            "exp": expire,
        }

        return jwt.encode(
            payload,
            settings.jwt_refresh_secret_key,
            algorithm=settings.jwt_algorithm,
        )

    async def get_user_permissions(
        self,
        user_id: int,
    ) -> list[typing.Any]:
        # permissions belongs to user
        return await repositories.PermissionRepository().find_by_user_id(user_id)

    async def get_group_permissions(
        self,
        user_id: int,
    ) -> list[typing.Any]:
        # permissions belongs to group which belongs to user
        return await repositories.PermissionRepository().find_by_group_id_by_user_id(
            user_id
        )

    async def get_all_permissions(
        self,
        user_id: int,
    ) -> list[typing.Any]:
        return await repositories.PermissionRepository().find_all_by_user_id(user_id)

    async def has_perm(
        self,
        user_id: int,
        permission_id: int,
    ) -> bool:
        perms = await self.get_all_permissions(user_id)
        return any(d["id"] == permission_id for d in [perm._mapping for perm in perms])

    async def has_module_perm(
        self,
        user_id: int,
        app_label: str,
        conn: sa.ext.asyncio.engine.AsyncConnection,
    ) -> bool:
        perms = await self.get_all_permissions(user_id, conn)
        return any(
            d["app_label"] == app_label for d in [perm._mapping for perm in perms]
        )

    async def with_perm(
        self,
        permission_id: int,
        is_active=True,
        include_superusers=True,
    ) -> list[typing.Any]:
        return await repositories.UserRepository().find_by_permission_id(
            permission_id,
            is_active,
            include_superusers,
        )


@lru_cache(maxsize=1)
def get_authentication_backend() -> BaseAuthenticationBackend:
    m, c = settings.authentication_backend.rsplit(".", 1)
    AuthenticationBackendClass = getattr(importlib.import_module(m), c)
    return AuthenticationBackendClass()


authentication: BaseAuthenticationBackend = get_authentication_backend()


async def get_superuser(
    self,  # This is a method to be bound.
    current_user: dict = fastapi.Depends(authentication.get_current_user),
    user_service: repositories.UserRepository = fastapi.Depends(
        repositories.UserRepository
    ),
) -> dict:
    row = await user_service.find_by_id_active_true_superuser_true(
        current_user["id"],
    )

    return row._mapping if row else None


# Add a method into an instance dynamically
authentication.get_superuser = get_superuser.__get__(authentication)
