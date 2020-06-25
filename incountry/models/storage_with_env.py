import os
from typing import Any, Dict, Optional

from pydantic import AnyHttpUrl, BaseModel, constr, StrictBool, StrictStr, validator, root_validator

from .http_options import HttpOptions


class Options(BaseModel):
    http_options: Optional[HttpOptions] = {}
    auth_endpoints: Dict[constr(min_length=1), AnyHttpUrl] = None
    normalize_keys: StrictBool = False
    endpoint_mask: StrictStr = None
    countries_endpoint: AnyHttpUrl = None

    @root_validator(pre=True)
    def check_empty_options(cls, values):
        if isinstance(values, dict) and len(values) == 0:
            raise ValueError("Options cannot be empty dict")

        return values

    @validator("http_options", pre=True)
    def check_options(cls, value):
        if not isinstance(value, dict) or len(value) == 0:
            raise ValueError("value is not a valid dict")
        return value

    @validator("auth_endpoints")
    def lowercase_auth_endpoint_keys(cls, value):
        lowercased = {}
        for key in value.keys():
            lowercased[key.lower()] = str(value[key])

        if "default" not in lowercased:
            raise ValueError("Missing default auth enpoint")

        return lowercased


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
    def validate_auth_methods(cls, values):
        values["api_key"] = values.get("api_key", os.environ.get("INC_API_KEY"))
        values["client_id"] = values.get("client_id", os.environ.get("INC_CLIENT_ID"))
        values["client_secret"] = values.get("client_secret", os.environ.get("INC_CLIENT_SECRET"))

        if values["api_key"] is not None and (values["client_id"] is not None or values["client_secret"] is not None):
            raise ValueError(
                f"Please choose either API key authorization or oAuth (client_id + client_secret) authorization, "
                f"not both"
            )

        return values

    @root_validator
    def check_auth_methods_for_nones(cls, values):
        has_api_key = values.get("api_key", None) is not None
        has_oauth_creds = values.get("client_id", None) is not None or values.get("client_secret", None) is not None

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

        if not has_api_key and not has_oauth_creds:
            raise ValueError("Please provide valid API key or oAuth (client_id + client_secret) credentials")

        return values
