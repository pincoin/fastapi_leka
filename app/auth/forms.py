from fastapi.param_functions import Form


class OAuth2RequestForm:
    def __init__(
        self,
        grant_type: str = Form(default=None, regex="password|refresh_token"),
        username: str | None = Form(default=None),
        password: str | None = Form(default=None),
        refresh_token: str | None = Form(default=None),
        scope: str = Form(default=""),
        client_id: str | None = Form(default=None),
        client_secret: str | None = Form(default=None),
    ):
        self.grant_type = grant_type
        self.username = username
        self.password = password
        self.refresh_token = refresh_token
        self.scopes = scope.split()
        self.client_id = client_id
        self.client_secret = client_secret
