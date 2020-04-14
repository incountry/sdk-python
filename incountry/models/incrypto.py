from typing import Any, List

from pydantic import BaseModel, validator, root_validator

from .custom_encryption_config import CustomEncryptionConfig
from ..exceptions import StorageClientException
from ..validation.utils import get_formatted_validation_error


class InCrypto(BaseModel):
    secret_key_accessor: Any = None
    custom_encryption_configs: List[CustomEncryptionConfig] = None

    @root_validator(pre=True)
    def init(cls, values):
        from ..secret_key_accessor import SecretKeyAccessor

        secret_key_accessor = values.get("secret_key_accessor", None)
        custom_encryption_configs = values.get("custom_encryption_configs", None)

        if not isinstance(secret_key_accessor, SecretKeyAccessor):
            if secret_key_accessor is not None:
                raise ValueError(
                    f"secret_key_accessor - "
                    f"provide a valid secret_key_accessor param of class {SecretKeyAccessor.__name__}"
                )
            if custom_encryption_configs is not None:
                raise ValueError(
                    f"secret_key_accessor - provide a valid secret_key_accessor param "
                    f"of class {SecretKeyAccessor.__name__} to use custom encryption"
                )
        elif custom_encryption_configs is not None:
            secret_key_accessor.enable_custom_encryption_keys()

        return values

    @validator("secret_key_accessor", always=True)
    def validate_secret_key_accessor(cls, value, values):
        if value is None:
            return value

        try:
            value.validate()
        except StorageClientException as e:
            if e.original_exception is not None:
                raise ValueError(
                    "incorrect secrets data" + get_formatted_validation_error(e.original_exception, prefix="  ")
                )
            else:
                raise ValueError(e)

        return value

    @validator("custom_encryption_configs", always=True, pre=True)
    def check_min_length(cls, value, values):
        if value is not None and len(value) == 0:
            raise ValueError("provide at least 1 valid custom encryption config")
        return value

    @validator("custom_encryption_configs")
    def check_versions(cls, value, values):
        if value is None:
            return value

        has_current_version = False
        versions = []
        for custom_encryption_config in value:
            if custom_encryption_config["version"] in versions:
                raise ValueError("Versions must be unique")
            versions.append(custom_encryption_config["version"])
            if custom_encryption_config.get("isCurrent", False) is True:
                if has_current_version:
                    raise ValueError("There must be at most one current version of custom encryption")
                else:
                    has_current_version = True
        return value

    @validator("custom_encryption_configs", each_item=True)
    def configs_to_dict(cls, value):
        return value.dict()

    @validator("custom_encryption_configs", each_item=True)
    def validate_methods(cls, value, values):
        if "secret_key_accessor" not in values:
            return value

        from ..validation.validate_custom_encryption_config import validate_custom_encryption_config

        validate_custom_encryption_config(value, values["secret_key_accessor"].get_secrets_raw())

        return value
