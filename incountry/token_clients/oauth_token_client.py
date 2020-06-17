import time

import requests

from .token_client import TokenClient
from ..exceptions import StorageServerException


class Token:
    def __init__(self, access_token: str, expires_at: float):
        self.access_token = access_token
        self.expires_at = expires_at


class OAuthTokenClient(TokenClient):
    REGIONAL_AUTH_ENDPOINTS = {
        "apac": "https://auth-apac.incountry.com/oauth2/token",
        "emea": "https://auth-emea.incountry.com/oauth2/token",
        "amer": "https://auth-emea.incountry.com/oauth2/token",
    }

    REGIONAL_MAPPING = {"apac": "apac", "emea": "emea", "amer": "emea"}

    AUTH_PREFIX = "auth"
    DEFAULT_REGION = "emea"

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        scope: str,
        endpoint: str = None,
        endpoint_mask: str = None,
        options: dict = {},
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.endpoint = endpoint
        self.endpoint_mask = endpoint_mask

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
            res = session.post(url=self.get_endpoint(region=region), data=request_data)

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

    def get_endpoint(self, region=DEFAULT_REGION):
        if self.endpoint is not None:
            return self.endpoint

        if self.endpoint_mask:
            return OAuthTokenClient.get_auth_url(region, self.endpoint_mask)

        if region not in OAuthTokenClient.REGIONAL_AUTH_ENDPOINTS:
            return OAuthTokenClient.REGIONAL_AUTH_ENDPOINTS[OAuthTokenClient.DEFAULT_REGION]

        return OAuthTokenClient.REGIONAL_AUTH_ENDPOINTS[region]

    def can_refetch(self):
        return True

    @staticmethod
    def get_auth_url(region, endpoint_mask):
        region = region.lower()
        result_region = OAuthTokenClient.REGIONAL_MAPPING[OAuthTokenClient.DEFAULT_REGION]
        if region in OAuthTokenClient.REGIONAL_MAPPING:
            result_region = OAuthTokenClient.REGIONAL_MAPPING[region]
        return f"https://{OAuthTokenClient.AUTH_PREFIX}-{result_region}.{endpoint_mask}"
