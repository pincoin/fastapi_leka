import typing

import sqlalchemy as sa
from pydantic import BaseModel
from sqlalchemy.engine import CursorResult

from core import exceptions
from core.utils import get_logger

from .database import engine

logger = get_logger()


class BaseRepository:
    async def get_one_or_none(
        self,
        statement,
    ) -> typing.Any:
        async with engine.connect() as conn:
            cr: CursorResult = await conn.execute(statement)

        return cr.first()

    async def get_one_or_404(
        self,
        statement,
        item: str = "Item",
    ) -> typing.Any:
        async with engine.connect() as conn:
            cr: CursorResult = await conn.execute(statement)

        if row := cr.first():
            return row

        raise exceptions.item_not_found_exception(item)

    async def get_all(
        self,
        statement,
    ) -> list[typing.Any]:
        async with engine.connect() as conn:
            cr: CursorResult = await conn.execute(statement)

        return cr.fetchall()

    async def insert(
        self,
        statement,
    ) -> int:
        async with engine.connect() as conn:
            cr: CursorResult = await conn.execute(statement)
            await conn.commit()

        return cr.inserted_primary_key[0]

    async def update_or_failure(
        self,
        statement,
        dict_in: dict,
        model_out: BaseModel,
    ) -> typing.Any:
        # 1. Fetch saved row from database
        stmt = sa.select(statement.table).where(statement.whereclause)
        row = await self.get_one_or_404(stmt, model_out.Config().title)

        # 2. Create pydantic model instance from fetched row dict
        model = model_out(**row._mapping)

        # 3. Create NEW pydantic model from model + dict_in
        model_new = model.copy(update=dict_in)

        # 4. Execute upate query
        async with engine.connect() as conn:
            await conn.execute(statement.values(**model_new.dict()))
            await conn.commit()

        return model_new

    async def delete_one_or_404(
        self,
        statement,
        item: str = "Item",
    ) -> None:
        async with engine.connect() as conn:
            cr: CursorResult = await conn.execute(statement)
            await conn.commit()

        if cr.rowcount > 0:
            return None

        raise exceptions.item_not_found_exception(item)

    def append_skip_take(
        self,
        statement,
        skip: int | None = None,
        take: int | None = None,
    ):
        if skip:
            statement = statement.offset(skip)
        if take:
            statement = statement.limit(take)

        return statement
