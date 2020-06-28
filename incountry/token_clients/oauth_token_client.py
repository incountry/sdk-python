import time

import requests

from .token_client import TokenClient
from ..exceptions import StorageServerException


class Token:
    def __init__(self, access_token: str, expires_at: float):
        self.access_token = access_token
        self.expires_at = expires_at


class OAuthTokenClient(TokenClient):
    DEFAULT_AUTH_ENDPOINTS = {
        "apac": "https://auth-apac.incountry.com/oauth2/token",
        "emea": "https://auth-emea.incountry.com/oauth2/token",
        "default": "https://auth-emea.incountry.com/oauth2/token",
    }

    def __init__(
        self, client_id: str, client_secret: str, scope: str, auth_endpoints: dict = None, options: dict = {},
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.auth_endpoints = auth_endpoints or OAuthTokenClient.DEFAULT_AUTH_ENDPOINTS

        self.tokens = {}

    def get_token(self, audience, region=None, refetch=False):
        token = self.tokens.get(audience, None)
        if refetch or not isinstance(token, Token) or token.expires_at <= time.time():
            self.refresh_access_token(audience=audience, region=region)
            token = self.tokens.get(audience, None)

        if isinstance(token, Token):
            return token.access_token

        raise StorageServerException(f"Unable to find token for audience: {audience}")

    def fetch_token(self, audience, region):
        try:
            session = requests.Session()
            session.auth = (self.client_id, self.client_secret)

            request_data = {"grant_type": "client_credentials", "scope": self.scope, "audience": audience}
            res = session.post(
                url=OAuthTokenClient.get_endpoint(region=region, auth_endpoints=self.auth_endpoints), data=request_data
            )

            if res.status_code != 200:
                raise StorageServerException(
                    "oAuth fetch token error: {} {} - {}".format(res.status_code, res.url, res.text)
                )

            return res.json()
        except Exception as e:
            raise StorageServerException("Error fetching oAuth token") from e

    def refresh_access_token(self, audience, region):
        token_data = self.fetch_token(audience=audience, region=region)
        self.tokens[audience] = Token(
            access_token=token_data["access_token"], expires_at=time.time() + token_data["expires_in"],
        )

    def can_refetch(self):
        return True

    @staticmethod
    def get_endpoint(region, auth_endpoints=DEFAULT_AUTH_ENDPOINTS):
        if region not in auth_endpoints:
            return auth_endpoints["default"]

        return auth_endpoints[region]
