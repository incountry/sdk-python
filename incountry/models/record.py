from typing import List
from datetime import datetime
from pydantic import BaseModel, conint, constr, StrictInt, StrictStr

from .attachment_meta import AttachmentMeta


class Record(BaseModel):
    record_key: constr(strict=True, min_length=1)
    body: StrictStr = None
    precommit_body: StrictStr = None
    profile_key: StrictStr = None
    service_key1: StrictStr = None
    service_key2: StrictStr = None
    key1: StrictStr = None
    key2: StrictStr = None
    key3: StrictStr = None
    key4: StrictStr = None
    key5: StrictStr = None
    key6: StrictStr = None
    key7: StrictStr = None
    key8: StrictStr = None
    key9: StrictStr = None
    key10: StrictStr = None
    range_key1: StrictInt = None
    range_key2: StrictInt = None
    range_key3: StrictInt = None
    range_key4: StrictInt = None
    range_key5: StrictInt = None
    range_key6: StrictInt = None
    range_key7: StrictInt = None
    range_key8: StrictInt = None
    range_key9: StrictInt = None
    range_key10: StrictInt = None
    version: conint(ge=0, strict=True) = None
    created_at: datetime = None
    updated_at: datetime = None
    attachments: List[AttachmentMeta] = None
