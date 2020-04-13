import traceback
from typing import Callable

from pydantic import BaseModel, validator, StrictBool, StrictInt, StrictStr

CUSTOM_ENCRYPTION_METHODS_ARGS = ["input", "key", "key_version"]


class CustomEncryptionConfigMethodValidation(BaseModel):
    key: bytes
    keyVersion: StrictInt
    version: StrictStr
    isCurrent: StrictBool = False
    encrypt: Callable
    decrypt: Callable

    @validator("key", pre=True)
    def validate_key(cls, value):
        if not isinstance(value, bytes):
            raise ValueError("value is not valid bytes")
        return value

    @validator("encrypt", pre=True)
    def validate_enc(cls, value, values):
        plaintext = "incountry"

        try:
            enc = value(input=plaintext, key=values["key"], key_version=values["keyVersion"])
        except Exception:
            raise ValueError(
                "should return str. Threw exception instead"
                + "\n\n==Validation Error Traceback Start==\n\n"
                + traceback.format_exc()
                + "\n==Validation Error Traceback End=="
            )

        if not isinstance(enc, str):
            raise ValueError(f"should return str. Got {type(enc).__name__}")
        return value

    @validator("decrypt", pre=True)
    def validate_dec(cls, value, values):
        plaintext = "incountry"
        if "encrypt" not in values:
            return value

        try:
            enc = values["encrypt"](input=plaintext, key=values["key"], key_version=values["keyVersion"])
            dec = value(input=enc, key=values["key"], key_version=values["keyVersion"])
        except Exception:
            raise ValueError(
                "should return str. Threw exception instead"
                + "\n\n==Validation Error Traceback Start==\n\n"
                + traceback.format_exc()
                + "\n==Validation Error Traceback End=="
            )

        if not isinstance(dec, str):
            raise ValueError(f"should return str. Got {type(dec).__name__}")
        if dec != plaintext:
            raise ValueError(f"decrypted data doesn't match the original input")

        return value
