class TokenClient:
    def get_token(self, audience: str = None, refetch: bool = False) -> str:
        raise NotImplementedError

    def can_refetch(self) -> bool:
        raise NotImplementedError
