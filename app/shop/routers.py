import typing

import fastapi
from auth import repositories as auth_services
from auth import schemas as auth_schemas
from auth.backends import authentication
from core import exceptions
from core.utils import get_logger, list_params

logger = get_logger()

router = fastapi.APIRouter(
    prefix="/shop",
    tags=[
        "shop",
    ],
)


@router.get(
    "/permissions",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[auth_schemas.PermissionContentType],
)
async def list_permissions(
    params: dict = fastapi.Depends(list_params),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    permission_service: auth_services.PermissionRepository = fastapi.Depends(
        auth_services.PermissionRepository
    ),
) -> list[typing.Any]:
    if superuser is None:
        raise exceptions.forbidden_exception()

    return await permission_service.find_all(
        params["skip"],
        params["take"],
    )
