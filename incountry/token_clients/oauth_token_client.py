import time

import requests

from ..exceptions import StorageServerException


class Token:
    def __init__(self, access_token: str, expires_at: float):
        self.access_token = access_token
        self.expires_at = expires_at


class OAuthTokenClient:
    def __init__(self, client_id: str, client_secret: str, endpoint: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.endpoint = endpoint

        self.tokens = {}

        self.refresh_access_token()

    def get_token(self, audience_url):
        token = self.tokens.get(audience_url, None)
        if not isinstance(token, Token) or self.token.expires_at <= time.time():
            self.refresh_access_token(audience_url)

        if isinstance(self.token, Token):
            return "Bearer " + self.token.access_token
        return ""

    def fetch_token(self):
        try:
            session = requests.Session()
            session.auth = (self.client_id, self.client_secret)

            res = res = session.post(self.endpoint, data={"grant_type": "client_credentials"})

            if res.status_code >= 400:
                raise StorageServerException("{} {} - {}".format(res.status_code, res.url, res.text))

            return res.json()
        except Exception as e:
            raise StorageServerException(e) from None

    def refresh_access_token(self, audience_url):

        token_data = self.fetch_token
        self.token = Token(access_token=token_data["access_token"], expires_at=time.time() + token_data["expires_in"])
