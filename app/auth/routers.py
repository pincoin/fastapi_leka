import asyncio
import datetime
import json
import typing
import uuid

import fastapi
import httpx
import sqlalchemy as sa
from core import exceptions
from core.config import settings
from core.utils import get_logger, list_params
from jose import JWTError, jwt
from oauthlib.oauth2 import WebApplicationClient
from sse_starlette import EventSourceResponse

from auth import repositories

from . import forms, schemas
from .backends import authentication

logger = get_logger()

router = fastapi.APIRouter(
    prefix="/auth",
    tags=[
        "auth",
    ],
)


@router.post(
    "/token",
    # response model is not specified to support both grant type `password` and `refresh_token`.
)
async def get_access_token(
    response: fastapi.Response,
    form_data: forms.OAuth2RequestForm = fastapi.Depends(),
    token_repo: repositories.TokenRepository = fastapi.Depends(
        repositories.TokenRepository
    ),
) -> dict:
    if form_data.grant_type == "password" and form_data.username and form_data.password:
        user_dict = await authentication.authenticate(
            form_data.username,
            form_data.password,
        )

        if not user_dict:
            raise exceptions.invalid_credentials_exception()

        access_token_expires = datetime.timedelta(
            minutes=settings.jwt_expiration_delta,
        )
        access_token = authentication.create_access_token(
            user_dict["username"],
            user_dict["id"],
            expires_delta=access_token_expires,
        )

        refresh_token_expires = datetime.timedelta(
            minutes=settings.jwt_refresh_expiration_delta,
        )
        refresh_token = authentication.create_refresh_token(
            user_dict["id"],
            expires_delta=refresh_token_expires,
        )

        token_dict = {
            "user_id": user_dict["id"],
            "username": user_dict["username"],
            "token": refresh_token,
        }

        logger.debug(token_dict)
        await token_repo.create(token_dict)

        response.headers["cache-control"] = "no-store"

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        }

    elif form_data.grant_type == "refresh_token" and form_data.refresh_token:
        try:
            payload = jwt.decode(
                form_data.refresh_token,
                settings.jwt_refresh_secret_key,
                algorithms=[settings.jwt_algorithm],
            )

            if datetime.datetime.fromtimestamp(
                payload["exp"], tz=datetime.timezone.utc
            ) < datetime.datetime.now(tz=datetime.timezone.utc):
                raise exceptions.invalid_token_exception()

            user_id: int = payload.get("id")

            token_dict = await token_repo.find_by_id(user_id)

            if token_dict is None:
                raise exceptions.invalid_token_exception()

            if token_dict["token"] != form_data.refresh_token:
                raise exceptions.invalid_token_exception()

            access_token_expires = datetime.timedelta(
                minutes=settings.jwt_expiration_delta,
            )
            access_token = authentication.create_access_token(
                token_dict["username"],
                user_id,
                expires_delta=access_token_expires,
            )

            response.headers["cache-control"] = "no-store"

            return {
                "access_token": access_token,
                "token_type": "bearer",
            }
        except JWTError:
            raise exceptions.invalid_token_exception()

    raise exceptions.bad_request_exception()


@router.post(
    "/refresh",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=schemas.RefreshToken,
)
async def get_refresh_token(
    response: fastapi.Response,
    user: dict = fastapi.Depends(authentication.get_current_user),
    token_repo: repositories.TokenRepository = fastapi.Depends(
        repositories.TokenRepository
    ),
) -> dict:
    if user is None:
        raise exceptions.forbidden_exception()

    refresh_token_expires = datetime.timedelta(
        minutes=settings.jwt_refresh_expiration_delta,
    )
    refresh_token = authentication.create_refresh_token(
        user["id"],
        expires_delta=refresh_token_expires,
    )

    token_dict = {
        "user_id": user["id"],
        "username": user["username"],
        "token": refresh_token,
    }

    logger.debug(token_dict)
    await token_repo.create(token_dict)

    response.headers["cache-control"] = "no-store"

    return {
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.get(
    "/users",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.User],
    response_model_exclude={"password"},
)
async def list_users(
    is_active: bool | None = True,
    is_staff: bool | None = False,
    is_superuser: bool | None = False,
    params: dict = fastapi.Depends(list_params),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    user_repo: repositories.UserRepository = fastapi.Depends(
        repositories.UserRepository
    ),
) -> list[typing.Any]:
    if superuser is None:
        raise exceptions.forbidden_exception()

    return await user_repo.find_all(
        is_active,
        is_staff,
        is_superuser,
        params["skip"],
        params["take"],
    )


@router.get(
    "/users/{user_id}",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=schemas.User,
    response_model_exclude={"password"},
)
async def get_user(
    user_id: int = fastapi.Query(gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    user_repo: repositories.UserRepository = fastapi.Depends(
        repositories.UserRepository
    ),
) -> typing.Any:
    if superuser is None:
        raise exceptions.forbidden_exception()

    return await user_repo.find_by_id(user_id)


@router.post(
    "/users/",
    status_code=fastapi.status.HTTP_201_CREATED,
    response_model=schemas.User,
    response_model_exclude={"password"},
)
async def create_user(
    user: schemas.UserCreate,
    superuser: dict = fastapi.Depends(authentication.get_current_user),
    user_repo: repositories.UserRepository = fastapi.Depends(
        repositories.UserRepository
    ),
) -> schemas.User:
    if superuser is None:
        raise exceptions.forbidden_exception()

    try:
        return await user_repo.create(user)
    except sa.exc.IntegrityError:
        raise exceptions.conflict_exception()


@router.put(
    "/users/{user_id}",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=schemas.User,
    response_model_exclude={"password"},
)
async def update_user(
    user: schemas.UserUpdate,
    user_id: int = fastapi.Query(gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    user_repo: repositories.UserRepository = fastapi.Depends(
        repositories.UserRepository
    ),
) -> typing.Any:
    if superuser is None:
        raise exceptions.forbidden_exception()

    try:
        return await user_repo.update_by_id(user, user_id)
    except sa.exc.IntegrityError:
        raise exceptions.conflict_exception()


@router.delete(
    "/users/{user_id}",
    status_code=fastapi.status.HTTP_204_NO_CONTENT,
    response_class=fastapi.Response,
)
async def delete_user(
    user_id: int = fastapi.Query(gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    user_repo: repositories.UserRepository = fastapi.Depends(
        repositories.UserRepository
    ),
) -> None:
    if superuser is None:
        raise exceptions.forbidden_exception()

    await user_repo.delete_by_id(user_id)


@router.get(
    "/users/{user_id}/groups",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.Group],
)
async def list_groups_of_user(
    user_id: int = fastapi.Query(gt=0),
    params: dict = fastapi.Depends(list_params),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    group_repo: repositories.GroupRepository = fastapi.Depends(
        repositories.GroupRepository
    ),
) -> list[typing.Any]:
    if superuser is None:
        raise exceptions.forbidden_exception()

    return await group_repo.find_by_user_id(
        user_id,
        params["skip"],
        params["take"],
    )


@router.get(
    "/users/{user_id}/permissions",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.PermissionContentType],
)
async def list_permissions_of_user(
    user_id: int = fastapi.Query(gt=0),
    params: dict = fastapi.Depends(list_params),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    permission_repo: repositories.PermissionRepository = fastapi.Depends(
        repositories.PermissionRepository
    ),
) -> list[typing.Any]:
    if superuser is None:
        raise exceptions.forbidden_exception()

    return await permission_repo.find_by_user_id(
        user_id,
        params["skip"],
        params["take"],
    )


@router.get(
    "/content-types",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.ContentType],
)
async def list_content_types(
    params: dict = fastapi.Depends(list_params),
    app_label: str | None = fastapi.Query(default=None, max_length=100),
    model: str | None = fastapi.Query(default=None, max_length=100),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    content_type_repo: repositories.ContentTypeRepository = fastapi.Depends(
        repositories.ContentTypeRepository
    ),
) -> list[typing.Any]:
    if superuser is None:
        raise exceptions.forbidden_exception()

    return await content_type_repo.find_all(
        app_label,
        model,
        params["skip"],
        params["take"],
    )


@router.get(
    "/content_types/{content_type_id}",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=schemas.ContentType,
)
async def get_content_type(
    content_type_id: int = fastapi.Query(default=0, gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    content_type_repo: repositories.ContentTypeRepository = fastapi.Depends(
        repositories.ContentTypeRepository
    ),
) -> typing.Any:
    if superuser is None:
        raise exceptions.forbidden_exception()

    return await content_type_repo.find_by_id(content_type_id)


@router.post(
    "/content-types/",
    status_code=fastapi.status.HTTP_201_CREATED,
    response_model=schemas.ContentType,
)
async def create_content_type(
    content_type: schemas.ContentTypeCreate,
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    content_type_repo: repositories.ContentTypeRepository = fastapi.Depends(
        repositories.ContentTypeRepository
    ),
) -> schemas.ContentType:
    if superuser is None:
        raise exceptions.forbidden_exception()

    try:
        return await content_type_repo.create(content_type)
    except sa.exc.IntegrityError:
        raise exceptions.conflict_exception()


@router.put(
    "/content-types/{content_type_id}",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=schemas.ContentType,
)
async def update_content_type(
    content_type: schemas.ContentTypeUpdate,
    content_type_id: int = fastapi.Query(default=0, gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    content_type_repo: repositories.ContentTypeRepository = fastapi.Depends(
        repositories.ContentTypeRepository
    ),
) -> typing.Any:
    if superuser is None:
        raise exceptions.forbidden_exception()

    try:
        return await content_type_repo.update_by_id(content_type, content_type_id)
    except sa.exc.IntegrityError:
        raise exceptions.conflict_exception()


@router.delete(
    "/content-types/{content_type_id}",
    status_code=fastapi.status.HTTP_204_NO_CONTENT,
    response_class=fastapi.Response,
)
async def delete_content_type(
    content_type_id: int = fastapi.Query(default=0, gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    content_type_repo: repositories.ContentTypeRepository = fastapi.Depends(
        repositories.ContentTypeRepository
    ),
) -> None:
    if superuser is None:
        raise exceptions.forbidden_exception()

    await content_type_repo.delete_by_id(content_type_id)


@router.get(
    "/content-types/{content_type_id}/permissions",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.PermissionContentType],
)
async def list_permissions_of_content_type(
    content_type_id: int = fastapi.Query(gt=0),
    params: dict = fastapi.Depends(list_params),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    permission_repo: repositories.PermissionRepository = fastapi.Depends(
        repositories.PermissionRepository
    ),
) -> list[typing.Any]:
    if superuser is None:
        raise exceptions.forbidden_exception()

    return await permission_repo.find_by_content_type_id(
        content_type_id,
        params["skip"],
        params["take"],
    )


@router.post(
    "/content-types/{content_type_id}/permissions",
    status_code=fastapi.status.HTTP_201_CREATED,
    response_model=schemas.Permission,
)
async def create_permission_of_content_type(
    permission: schemas.PermissionCreate,
    content_type_id: int = fastapi.Query(gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    content_type_repo: repositories.ContentTypeRepository = fastapi.Depends(
        repositories.ContentTypeRepository
    ),
) -> schemas.Permission:
    if superuser is None:
        raise exceptions.forbidden_exception()

    try:
        return await content_type_repo.add_permission(
            permission,
            content_type_id,
        )
    except sa.exc.IntegrityError:
        raise exceptions.conflict_exception()


@router.put(
    "/content-types/{content_type_id}/permissions/{permission_id}",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=schemas.Permission,
)
async def update_permission_of_content_type(
    permission: schemas.PermissionUpdate,
    content_type_id: int = fastapi.Query(gt=0),
    permission_id: int = fastapi.Query(gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    content_type_repo: repositories.ContentTypeRepository = fastapi.Depends(
        repositories.ContentTypeRepository
    ),
) -> typing.Any:
    if superuser is None:
        raise exceptions.forbidden_exception()

    try:
        return await content_type_repo.update_permission(
            permission,
            content_type_id,
            permission_id,
        )
    except sa.exc.IntegrityError:
        raise exceptions.conflict_exception()


@router.delete(
    "/content-types/{content_type_id}/permissions/{permission_id}",
    status_code=fastapi.status.HTTP_204_NO_CONTENT,
    response_class=fastapi.Response,
)
async def delete_permission_of_content_type(
    content_type_id: int = fastapi.Query(gt=0),
    permission_id: int = fastapi.Query(gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    content_type_repo: repositories.ContentTypeRepository = fastapi.Depends(
        repositories.ContentTypeRepository
    ),
) -> None:
    if superuser is None:
        raise exceptions.forbidden_exception()

    await content_type_repo.remove_permission(
        content_type_id,
        permission_id,
    )


@router.get(
    "/groups",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.Group],
)
async def list_groups(
    params: dict = fastapi.Depends(list_params),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    group_repo: repositories.GroupRepository = fastapi.Depends(
        repositories.GroupRepository
    ),
) -> list[typing.Any]:
    if superuser is None:
        raise exceptions.forbidden_exception()

    return await group_repo.find_all(
        params["skip"],
        params["take"],
    )


@router.get(
    "/groups/{group_id}",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=schemas.Group,
)
async def get_group(
    group_id: int = fastapi.Query(default=0, gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    group_repo: repositories.GroupRepository = fastapi.Depends(
        repositories.GroupRepository
    ),
) -> typing.Any:
    if superuser is None:
        raise exceptions.forbidden_exception()

    return await group_repo.find_by_id(group_id)


@router.post(
    "/groups/",
    status_code=fastapi.status.HTTP_201_CREATED,
    response_model=schemas.Group,
)
async def create_group(
    group: schemas.GroupCreate,
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    group_repo: repositories.GroupRepository = fastapi.Depends(
        repositories.GroupRepository
    ),
) -> schemas.Group:
    if superuser is None:
        raise exceptions.forbidden_exception()

    try:
        return await group_repo.create(group)
    except sa.exc.IntegrityError:
        raise exceptions.conflict_exception()


@router.put(
    "/groups/{group_id}",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=schemas.Group,
)
async def update_group(
    group: schemas.GroupUpdate,
    group_id: int = fastapi.Query(default=0, gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    group_repo: repositories.GroupRepository = fastapi.Depends(
        repositories.GroupRepository
    ),
) -> typing.Any:
    if superuser is None:
        raise exceptions.forbidden_exception()

    try:
        return await group_repo.update_by_id(group, group_id)
    except sa.exc.IntegrityError:
        raise exceptions.conflict_exception()


@router.delete(
    "/groups/{group_id}",
    status_code=fastapi.status.HTTP_204_NO_CONTENT,
    response_class=fastapi.Response,
)
async def delete_group(
    group_id: int = fastapi.Query(default=0, gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    group_repo: repositories.GroupRepository = fastapi.Depends(
        repositories.GroupRepository
    ),
) -> None:
    if superuser is None:
        raise exceptions.forbidden_exception()

    group_repo.delete_by_id(group_id)


@router.get(
    "/groups/{group_id}/users",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.User],
    response_model_exclude={"password"},
)
async def list_users_of_group(
    group_id: int = fastapi.Query(gt=0),
    params: dict = fastapi.Depends(list_params),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    group_repo: repositories.GroupRepository = fastapi.Depends(
        repositories.GroupRepository
    ),
) -> list[typing.Any]:
    if superuser is None:
        raise exceptions.forbidden_exception()

    return await group_repo.find_by_group_id(
        group_id,
        params["skip"],
        params["take"],
    )


@router.get(
    "/groups/{group_id}/permissions",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.PermissionContentType],
)
async def list_permissions_of_group(
    group_id: int = fastapi.Query(gt=0),
    params: dict = fastapi.Depends(list_params),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    permission_repo: repositories.PermissionRepository = fastapi.Depends(
        repositories.PermissionRepository
    ),
) -> list[typing.Any]:
    if superuser is None:
        raise exceptions.forbidden_exception()

    return await permission_repo.find_by_group_id(
        group_id,
        params["skip"],
        params["take"],
    )


@router.post(
    "/groups/{group_id}/users/{user_id}",
    status_code=fastapi.status.HTTP_201_CREATED,
    response_model=schemas.UserGroup,
)
async def create_user_of_group(
    group_id: int = fastapi.Query(gt=0),
    user_id: int = fastapi.Query(gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    group_repo: repositories.GroupRepository = fastapi.Depends(
        repositories.GroupRepository
    ),
) -> schemas.UserGroup:
    if superuser is None:
        raise exceptions.forbidden_exception()

    try:
        return await group_repo.add_user(group_id, user_id)
    except sa.exc.IntegrityError:
        raise exceptions.conflict_exception()


@router.delete(
    "/groups/{group_id}/users/{user_id}",
    status_code=fastapi.status.HTTP_204_NO_CONTENT,
    response_class=fastapi.Response,
)
async def delete_user_of_group(
    group_id: int = fastapi.Query(gt=0),
    user_id: int = fastapi.Query(gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    group_repo: repositories.GroupRepository = fastapi.Depends(
        repositories.GroupRepository
    ),
) -> None:
    if superuser is None:
        raise exceptions.forbidden_exception()

    group_repo.remove_user(group_id, user_id)


@router.get(
    "/permissions",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.PermissionContentType],
)
async def list_permissions(
    params: dict = fastapi.Depends(list_params),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    permission_repo: repositories.PermissionRepository = fastapi.Depends(
        repositories.PermissionRepository
    ),
) -> list[typing.Any]:
    if superuser is None:
        raise exceptions.forbidden_exception()

    return await permission_repo.find_all(
        params["skip"],
        params["take"],
    )


@router.get(
    "/permissions/{permission_id}",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=schemas.UserPermission,
)
async def get_permission(
    permission_id: int = fastapi.Query(default=0, gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    permission_repo: repositories.PermissionRepository = fastapi.Depends(
        repositories.PermissionRepository
    ),
) -> typing.Any:
    if superuser is None:
        raise exceptions.forbidden_exception()

    return await permission_repo.find_by_id(permission_id)


@router.get(
    "/permissions/{permission_id}/users",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.User],
    response_model_exclude={"password"},
)
async def list_users_of_permission(
    params: dict = fastapi.Depends(list_params),
    permission_id: int = fastapi.Query(gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    user_repo: repositories.UserRepository = fastapi.Depends(
        repositories.UserRepository
    ),
) -> list[typing.Any]:
    if superuser is None:
        raise exceptions.forbidden_exception()

    return await user_repo.find_by_permission_id(
        permission_id,
        params["skip"],
        params["take"],
    )


@router.get(
    "/permissions/{permission_id}/groups",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.Group],
)
async def list_groups_of_permission(
    permission_id: int = fastapi.Query(gt=0),
    params: dict = fastapi.Depends(list_params),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    group_repo: repositories.GroupRepository = fastapi.Depends(
        repositories.GroupRepository
    ),
) -> list[typing.Any]:
    if superuser is None:
        raise exceptions.forbidden_exception()

    return await group_repo.find_by_permission_id(
        permission_id,
        params["skip"],
        params["take"],
    )


@router.post(
    "/permissions/{permission_id}/users/{user_id}",
    status_code=fastapi.status.HTTP_201_CREATED,
    response_model=schemas.UserPermission,
)
async def create_permission_of_user(
    permission_id: int = fastapi.Query(gt=0),
    user_id: int = fastapi.Query(gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    user_repo: repositories.UserRepository = fastapi.Depends(
        repositories.UserRepository
    ),
) -> schemas.UserPermission:
    if superuser is None:
        raise exceptions.forbidden_exception()

    try:
        return await user_repo.add_permission(permission_id, user_id)
    except sa.exc.IntegrityError:
        raise exceptions.conflict_exception()


@router.delete(
    "/permissions/{permission_id}/users/{user_id}",
    status_code=fastapi.status.HTTP_204_NO_CONTENT,
    response_class=fastapi.Response,
)
async def delete_permission_of_user(
    permission_id: int = fastapi.Query(gt=0),
    user_id: int = fastapi.Query(gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    user_repo: repositories.UserRepository = fastapi.Depends(
        repositories.UserRepository
    ),
) -> None:
    if superuser is None:
        raise exceptions.forbidden_exception()

    await user_repo.remove_permission(permission_id, user_id)


@router.post(
    "/permissions/{permission_id}/group/{group_id}",
    status_code=fastapi.status.HTTP_201_CREATED,
    response_model=schemas.GroupPermission,
)
async def create_permission_of_group(
    permission_id: int = fastapi.Query(gt=0),
    group_id: int = fastapi.Query(gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    group_repo: repositories.GroupRepository = fastapi.Depends(
        repositories.GroupRepository
    ),
) -> schemas.GroupPermission:
    if superuser is None:
        raise exceptions.forbidden_exception()

    try:
        return await group_repo.add_permission(permission_id, group_id)
    except sa.exc.IntegrityError:
        raise exceptions.conflict_exception()


@router.delete(
    "/permissions/{permission_id}/groups/{group_id}",
    status_code=fastapi.status.HTTP_204_NO_CONTENT,
    response_class=fastapi.Response,
)
async def delete_permission_of_group(
    permission_id: int = fastapi.Query(gt=0),
    group_id: int = fastapi.Query(gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    group_repo: repositories.GroupRepository = fastapi.Depends(
        repositories.GroupRepository
    ),
) -> None:
    if superuser is None:
        raise exceptions.forbidden_exception()

    await group_repo.remove_permission(permission_id, group_id)


@router.get(
    "/permissions/{permission_id}/content-types",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.ContentType],
)
async def list_content_types_of_permission(
    permission_id: int = fastapi.Query(gt=0),
    params: dict = fastapi.Depends(list_params),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    content_type_repo: repositories.ContentTypeRepository = fastapi.Depends(
        repositories.ContentTypeRepository
    ),
) -> list[typing.Any]:
    if superuser is None:
        raise exceptions.forbidden_exception()

    return await content_type_repo.find_by_permission_id(
        permission_id,
        params["skip"],
        params["take"],
    )


@router.get("/google/login")
async def google_login() -> fastapi.responses.RedirectResponse:
    client = WebApplicationClient(client_id=settings.sso_google_client_id)

    # redirect to authorization consent screen
    # prompt = "consent" | None

    # For the first time, prompt="consent" is set as default,
    # so callback will be called once.

    # Once allowed, redirection without consent, the sign-in callback will be called
    # every time that the user's signed in status changes.

    # Set prompt="consent" to prevent callback called twice
    # Otherwise, prevent to redirect consent screen if already signed in.

    state = str(uuid.uuid4())

    login_uri = client.prepare_request_uri(
        "https://accounts.google.com/o/oauth2/v2/auth",
        redirect_uri=settings.sso_google_client_callback,
        scope=["openid", "email", "profile"],
        state=state,
        prompt="consent",
    )

    response = fastapi.responses.RedirectResponse(login_uri, 303)
    response.set_cookie("oauth2_state", state, expires=600)
    return response


@router.get("/google/callback")
async def google_callback(
    code: str,
    state: str,
    request: fastapi.requests.Request,
):
    if code is None:
        return None

    if state is None:
        return None

    oauth2_state = request.cookies.get("oauth2_state")

    if oauth2_state is None or oauth2_state != state:
        return None

    client = WebApplicationClient(client_id=settings.sso_google_client_id)

    authorization_response = str(request.url).replace("http://", "https://")

    token_url, headers, body = client.prepare_token_request(
        "https://oauth2.googleapis.com/token",
        authorization_response=authorization_response,
        redirect_url=settings.sso_google_client_callback,
        code=code,
    )

    if token_url is None:
        return None

    auth = httpx.BasicAuth(
        settings.sso_google_client_id,
        settings.sso_google_client_secret,
    )

    async with httpx.AsyncClient() as session:
        # fetch access token
        response = await session.post(
            token_url, headers=headers, content=body, auth=auth
        )
        content = response.json()  # dict

        client.parse_request_body_response(json.dumps(content))  # parse str

        # read user info
        uri, headers, _ = client.add_token(
            "https://openidconnect.googleapis.com/v1/userinfo"
        )

        response = await session.get(uri, headers=headers)
        content = response.json()

    return content


@router.get("/sse-stream/{state}")
async def sse(
    state: str,
    request: fastapi.requests.Request,
):
    def new_messages():
        yield "signed-in"

    async def event_generator():
        STREAM_DELAY = 1  # second
        RETRY_TIMEOUT = 15000  # milisecond

        while True:
            if await request.is_disconnected():
                break

            # Checks for new messages and return them to client if any
            if new_messages():
                yield {
                    "event": "signed-in",
                    "id": state,
                    "retry": RETRY_TIMEOUT,
                    "data": "message_content",
                }

            await asyncio.sleep(STREAM_DELAY)

    return EventSourceResponse(event_generator())
