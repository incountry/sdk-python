import os
from typing import Any

from pydantic import AnyHttpUrl, BaseModel, constr, StrictBool, validator, root_validator

from .http_options import HttpOptions

DEFAULT_AUTH_ENDPOINT = "https://auth.incountry.io"


class Options(BaseModel):
    http_options: HttpOptions
    auth_endpoint: AnyHttpUrl = DEFAULT_AUTH_ENDPOINT

    @validator("http_options", pre=True)
    def check_options(cls, value):
        if not isinstance(value, dict) or len(value) == 0:
            raise ValueError("value is not a valid dict")
        return value


class StorageWithEnv(BaseModel):
    encrypt: StrictBool = True
    environment_id: constr(strict=True, min_length=1) = None
    client_id: constr(strict=True, min_length=1) = None
    client_secret: constr(strict=True, min_length=1) = None
    api_key: constr(strict=True, min_length=1) = None
    endpoint: AnyHttpUrl = None
    secret_key_accessor: Any = None
    debug: StrictBool = False
    options: Options = {}

    @validator("environment_id", pre=True, always=True)
    def environment_id_env(cls, value):
        res = value or os.environ.get("INC_ENVIRONMENT_ID")
        if res is None:
            raise ValueError(
                "Cannot be None. Please pass a valid environment_id param or set INC_ENVIRONMENT_ID env var"
            )
        return res

    @validator("api_key", pre=True, always=True)
    def api_key_env(cls, value, values, config):
        return value or os.environ.get("INC_API_KEY")

    @validator("client_id", pre=True, always=True)
    def client_id_env(cls, value, values):
        return value or os.environ.get("INC_CLIENT_ID")

    @validator("client_secret", pre=True, always=True)
    def client_secret_env(cls, value, values):
        return value or os.environ.get("INC_CLIENT_SECRET")

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

    @root_validator(pre=True)
    def check_auth_methods(cls, values):
        has_api_key = "api_key" in values
        has_oauth_creds = "client_id" in values or "client_secret" in values
        if has_api_key and has_oauth_creds:
            raise ValueError(
                "Please choose either API key autorization or oAuth (client_id + client_secret) authorization, not both"
            )
        if not has_api_key and not has_oauth_creds:
            raise ValueError(
                "Please choose either API key autorization or oAuth (client_id + client_secret) authorization, not none"
            )

        return values

    @root_validator
    def check_auth_methods_for_nones(cls, values):
        has_api_key = values["api_key"] is not None
        has_oauth_creds = values["client_id"] is not None or values["client_secret"] is not None

        if has_api_key:
            if values["api_key"] is None:
                raise ValueError(
                    f"  api_key - Cannot be None. Please pass a valid api_key param or set INC_API_KEY env var"
                )

        if has_oauth_creds:
            if values["client_id"] is None:
                raise ValueError(
                    "  client_id - Cannot be None. Please pass a valid client_id param or set INC_CLIENT_ID env var"
                )
            if values["client_secret"] is None:
                raise ValueError(
                    f"  client_secret - Cannot be None. "
                    f"Please pass a valid client_secret param or set INC_CLIENT_SECRET env var"
                )

        return values
