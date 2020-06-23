from typing import Dict
from pydantic import BaseModel, validator


class HttpRecordDelete(BaseModel):
    body: Dict

    @validator("body", pre=True)
    def is_empty_body(cls, value):
        if len(value) > 0:
            raise ValueError("body should be empty")
        return value
