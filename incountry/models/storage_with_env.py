import os
from typing import Any

from pydantic import AnyHttpUrl, BaseModel, constr, StrictBool, validator


class StorageWithEnv(BaseModel):
    encrypt: StrictBool = True
    environment_id: constr(strict=True, min_length=1) = None
    api_key: constr(strict=True, min_length=1) = None
    endpoint: AnyHttpUrl = None
    secret_key_accessor: Any = None
    debug: StrictBool = False

    @validator("environment_id", pre=True, always=True)
    def environment_id_env(cls, value):
        res = value or os.environ.get("INC_ENVIRONMENT_ID")
        if res is None:
            raise ValueError(
                "Cannot be None. Please pass a valid environment_id param or set INC_ENVIRONMENT_ID env var"
            )
        return res

    @validator("api_key", pre=True, always=True)
    def api_key_env(cls, value):
        res = value or os.environ.get("INC_API_KEY")
        if res is None:
            raise ValueError("Cannot be None. Please pass a valid api_key param or set INC_API_KEY env var")
        return res

    @validator("endpoint", pre=True, always=True)
    def endpoint_env(cls, value):
        if value is not None and not isinstance(value, str) or isinstance(value, str) and len(value) == 0:
            raise ValueError("should be a valid URL")
        return value or os.environ.get("INC_ENDPOINT")

    @validator("secret_key_accessor", always=True)
    def validate_secret_key_accessor(cls, value, values):
        from ..secret_key_accessor import SecretKeyAccessor

        if "encrypt" not in values or values["encrypt"] is False:
            return value
        if not isinstance(value, SecretKeyAccessor):
            raise ValueError(
                f"Encryption is On. "
                f"Please provide a valid secret_key_accessor param of class {SecretKeyAccessor.__name__}"
            )

        return value
