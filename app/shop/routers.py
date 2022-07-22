import typing

import fastapi
import sqlalchemy as sa
from auth import models as auth_models
from auth import schemas as auth_schemas
from core.dependencies import engine_connect
from core.persistence import Persistence
from core.utils import get_logger, list_params

logger = get_logger()

router = fastapi.APIRouter(
    prefix="/shop",
    tags=[
        "shop",
    ],
)


@router.get(
    "/users",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[auth_schemas.User],
    response_model_exclude={"password"},
)
async def list_users(
    is_active: bool | None = True,
    is_staff: bool | None = False,
    is_superuser: bool | None = False,
    params: dict = fastapi.Depends(list_params),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> list[typing.Any]:
    stmt = sa.select(auth_models.users)

    if is_active:
        stmt = stmt.where(auth_models.users.c.is_active == is_active)
    if is_staff:
        stmt = stmt.where(auth_models.users.c.is_staff == is_staff)
    if is_superuser:
        stmt = stmt.where(auth_models.users.c.is_superuser == is_superuser)

    stmt = stmt.offset(params["skip"]).limit(params["take"])

    return await Persistence(conn).get_all(stmt)
