class TokenClient:
    def get_token(self, host: str = None, refetch: bool = False) -> str:
        raise NotImplementedError

    def can_refetch(self) -> bool:
        raise NotImplementedError
