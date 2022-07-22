import os

import uvicorn
from fastapi import FastAPI

import auth
import home
import shop
from core.config import settings
from core.database import engine
from core.utils import get_logger

logger = get_logger()


app_params = {}

if settings.disable_swagger_ui:
    app_params["docs_url"] = None

if settings.disable_openapi_json:
    app_params["openapi_url"] = None

logger.debug(app_params)

app = FastAPI(**app_params)


@app.on_event("startup")
async def startup():
    logger.info("on startup")


@app.on_event("shutdown")
async def shutdown():
    logger.info("on shutdown")

    # Engine disposal closes all connections of the connection pool
    logger.debug(f"sqlalchemy.async.engine disposed - [{os.getpid()}]")
    await engine.dispose()


app.include_router(auth.routers.router)
app.include_router(shop.routers.router)
app.include_router(home.routers.router)


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        reload=settings.uvicorn_reload,
        debug=settings.debug,
        host=settings.host,
        port=settings.port,
    )
