import os
from functools import lru_cache

from pydantic import BaseSettings, Field, HttpUrl, PostgresDsn, RedisDsn


class Settings(BaseSettings):
    title: str = "fastapi-starter"

    uvicorn_reload: bool = False
    debug: bool = True
    host: str = "127.0.0.1"
    port: int = 8000
    origins: list = [
        "http://localhost:8080",
        "http://127.0.0.1:8000",
    ]

    disable_swagger_ui: bool = False
    disable_openapi_json: bool = False

    jwt_secret_key: str = Field(min_length=32)
    jwt_expiration_delta: int = 30
    jwt_refresh_secret_key: str = Field(min_length=32)
    jwt_refresh_expiration_delta: int = 14 * 24 * 60
    jwt_algorithm: str = "HS256"
    password_hasher = "auth.hashers.Pbkdf2Sha256Hasher"
    authentication_backend = "auth.backends.AuthenticationBackend"

    sqlalchemy_database_uri: PostgresDsn
    sqlalchemy_echo: bool = True
    sqlalchemy_pool_size: int = 5
    sqlalchemy_max_overflow: int = 10
    sqlalchemy_pool_recycle: int = 28800  # recycle connection in seconds
    sqlalchemy_pool_timeout: int = 30  # raise TimeoutError

    redis_uri: RedisDsn

    sso_google_client_id: str
    sso_google_client_secret: str
    sso_google_client_callback: HttpUrl

    log_file: str = "fastapi.log"

    class Config:
        env_file_encoding = "utf-8"
        env_nested_delimiter = "__"
        env_file = (
            f'{os.getenv("ENV_STATE")}.env' if os.getenv("ENV_STATE") else "local.env"
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings: Settings = get_settings()
