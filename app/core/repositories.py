import typing

import sqlalchemy as sa
from pydantic import BaseModel
from sqlalchemy.engine import CursorResult

from core import exceptions
from core.utils import get_logger

from .database import engine

logger = get_logger()


class BaseRepository:
    def __init__(self):
        self.statement = None

    async def get_one_or_none(
        self,
    ) -> typing.Any:
        async with engine.connect() as conn:
            cr: CursorResult = await conn.execute(self.statement)

        return cr.first()

    async def get_one_or_404(
        self,
        item: str = "Item",
    ) -> typing.Any:
        async with engine.connect() as conn:
            cr: CursorResult = await conn.execute(self.statement)

        if row := cr.first():
            return row

        raise exceptions.item_not_found_exception(item)

    async def get_all(
        self,
    ) -> list[typing.Any]:
        async with engine.connect() as conn:
            cr: CursorResult = await conn.execute(self.statement)

        return cr.fetchall()

    async def insert(
        self,
    ) -> int:
        async with engine.connect() as conn:
            cr: CursorResult = await conn.execute(self.statement)
            await conn.commit()

        return cr.inserted_primary_key[0]

    async def update_or_failure(
        self,
        dict_in: dict,
        model_out: BaseModel,
    ) -> typing.Any:
        # 1. Fetch saved row from database
        update_statement = self.statement

        self.statement = (
            sa.select(self.statement.table)
            .with_for_update()  # nowait = False (default)
            .where(self.statement.whereclause)
        )

        row = await self.get_one_or_404(model_out.Config().title)

        # 2. Create pydantic model instance from fetched row dict
        model = model_out(**row._mapping)

        # 3. Create NEW pydantic model from model + dict_in
        model_new = model.copy(update=dict_in)

        # 4. Execute upate query
        async with engine.connect() as conn:
            self.statement = update_statement

            await conn.execute(self.statement.values(**model_new.dict()))
            await conn.commit()

        return model_new

    async def delete_one_or_404(
        self,
        item: str = "Item",
    ) -> None:
        async with engine.connect() as conn:
            cr: CursorResult = await conn.execute(self.statement)
            await conn.commit()

        if cr.rowcount > 0:
            return None

        raise exceptions.item_not_found_exception(item)

    def append_skip_take(
        self,
        skip: int | None = None,
        take: int | None = None,
    ):
        if skip is not None:  # 0 is not passed
            self.statement = self.statement.offset(skip)
        if take is not None:
            self.statement = self.statement.limit(take)

        return self.statement
