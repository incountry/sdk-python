from .token_client import TokenClient


class ApiKeyTokenClient(TokenClient):
    def __init__(self, api_key: str):
        self.api_key = api_key

    def get_token(self, audience=None, region=None, refetch=False):
        return self.api_key

    def can_refetch(self):
        return False
