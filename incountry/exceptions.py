class StorageError(Exception):
    pass


class StorageClientError(StorageError):
    def __init__(self, message, original_exception=None):
        super(StorageError, self).__init__(message)

        self.original_exception = original_exception


class StorageServerError(StorageError):
    pass


class InCryptoException(StorageError):
    pass
