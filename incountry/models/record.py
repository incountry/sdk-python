from pydantic import BaseModel, conint, constr, StrictStr, StrictInt


class Record(BaseModel):
    key: constr(strict=True, min_length=1)
    body: StrictStr = None
    key2: StrictStr = None
    key3: StrictStr = None
    profile_key: StrictStr = None
    range_key: StrictInt = None
    version: conint(ge=0, strict=True) = None
