from inspect import getfullargspec
from typing import Callable

from pydantic import BaseModel, validator, StrictStr, StrictBool

CUSTOM_ENCRYPTION_METHODS_ARGS = ["input", "key", "key_version"]


class CustomEncryptionConfig(BaseModel):
    encrypt: Callable
    decrypt: Callable
    version: StrictStr
    isCurrent: StrictBool = False

    @validator("encrypt", "decrypt")
    def validate_methods_signature(cls, value):
        method_args = getfullargspec(value)[0]
        if method_args != CUSTOM_ENCRYPTION_METHODS_ARGS:
            raise ValueError(
                f"Invalid signature ({', '.join(method_args)}). Should be ({', '.join(CUSTOM_ENCRYPTION_METHODS_ARGS)})"
            )
        return value
