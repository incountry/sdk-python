class StorageException(Exception):
    pass


class StorageClientException(StorageException):
    def __init__(self, message, original_exception=None):
        super(StorageException, self).__init__(message)

        self.original_exception = original_exception


class StorageServerException(StorageException):
    pass


class StorageCryptoException(StorageException):
    pass
