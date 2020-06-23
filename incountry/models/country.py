import re

from pydantic import BaseModel, validator, StrictStr


class Country(BaseModel):
    country: StrictStr

    @validator("country")
    def regex_check_and_normalize(cls, v):
        if re.search("^[a-zA-Z]{2}$", v) is None:
            raise ValueError("must be a two-letter code")
        return v.lower()
