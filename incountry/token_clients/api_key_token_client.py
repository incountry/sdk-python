class ApiKeyTokenClient:
    def __init__(self, api_key: str):
        self.api_key = api_key

    def get_token(self):
        return "Bearer " + self.api_key
