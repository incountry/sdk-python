import time

import requests

from .token_client import TokenClient
from ..exceptions import StorageServerException


class Token:
    def __init__(self, access_token: str, expires_at: float):
        self.access_token = access_token
        self.expires_at = expires_at


class OAuthTokenClient(TokenClient):
    DEFAULT_AUTH_ENDPOINT = "https://auth.incountry.com/oauth2/token"

    def __init__(
        self, client_id: str, client_secret: str, scope: str, endpoint: str = None, options: dict = {},
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.endpoint = endpoint or OAuthTokenClient.DEFAULT_AUTH_ENDPOINT

        self.tokens = {}

    def get_token(self, audience, refetch=False):
        token = self.tokens.get(audience, None)
        if refetch or not isinstance(token, Token) or token.expires_at <= time.time():
            self.refresh_access_token(audience)
            token = self.tokens.get(audience, None)

        if isinstance(token, Token):
            return token.access_token

        raise StorageServerException(f"Unable to find token for audience: {audience}")

    def fetch_token(self, audience):
        try:
            session = requests.Session()
            session.auth = (self.client_id, self.client_secret)

            request_data = {"grant_type": "client_credentials", "scope": self.scope, "audience": audience}

            res = session.post(url=self.endpoint, data=request_data)

            if res.status_code != 200:
                raise StorageServerException(
                    "oAuth fetch token error: {} {} - {}".format(res.status_code, res.url, res.text)
                )

            return res.json()
        except Exception as e:
            raise StorageServerException("Error fetching oAuth token") from e

    def refresh_access_token(self, audience):
        token_data = self.fetch_token(audience=audience)
        self.tokens[audience] = Token(
            access_token=token_data["access_token"], expires_at=time.time() + token_data["expires_in"],
        )

    def can_refetch(self):
        return True
