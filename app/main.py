import os

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import auth
import home
import shop
from core.config import settings
from core.database import engine
from core.utils import get_logger

logger = get_logger()


def get_application():
    app_params = {}

    if settings.disable_swagger_ui:
        app_params["docs_url"] = None

    if settings.disable_openapi_json:
        app_params["openapi_url"] = None

    logger.debug(app_params)

    _app = FastAPI(**app_params)

    _app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.origins],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    _app.include_router(auth.routers.router)
    _app.include_router(shop.routers.router)
    _app.include_router(home.routers.router)

    return _app


app = get_application()


@app.on_event("startup")
async def startup():
    logger.info("on startup")


@app.on_event("shutdown")
async def shutdown():
    logger.info("on shutdown")

    # Engine disposal closes all connections of the connection pool
    logger.debug(f"sqlalchemy.async.engine disposed - [{os.getpid()}]")
    await engine.dispose()


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        reload=settings.uvicorn_reload,
        debug=settings.debug,
        host=settings.host,
        port=settings.port,
    )
