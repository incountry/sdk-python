import wrapt
from pydantic import ValidationError

from .utils import get_formatted_validation_error
from ..exceptions import StorageServerException


def validate_http_response_wrapper(function, model, **kwargs):
    try:
        return model.validate(kwargs).dict()
    except ValidationError as e:
        errors_report = get_formatted_validation_error(e)
        error_text = f"HTTP Response validation failed during {function.__qualname__}():{errors_report}"
        raise StorageServerException(error_text) from None


def validate_http_response(model):
    @wrapt.decorator
    def decorator(function, instance, args, kwargs):
        response = function(*args, **kwargs)
        validate_http_response_wrapper(function, model, **{"body": response})
        return response

    return decorator
