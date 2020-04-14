import wrapt

from .utils import function_args_to_kwargs
from ..exceptions import StorageClientException


@wrapt.decorator
def validate_encryption_enabled(function, instance, args, kwargs):
    function_args_to_kwargs(function, args, kwargs)

    if not instance.encrypt:
        raise StorageClientException(
            f"Validation failed during {function.__qualname__}(): This method is only allowed with encryption enabled"
        )
    return function(**kwargs)
