from core.config import settings
from fastapi_sso.sso.google import GoogleSSO


def get_google_sso():
    return GoogleSSO(
        settings.sso_google_client_id,
        settings.sso_google_client_secret,
        settings.sso_google_client_callback,
    )
