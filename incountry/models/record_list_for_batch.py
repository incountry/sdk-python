from pydantic import BaseModel, conlist, validator

from .record import Record

MAX_RECORDS_IN_BATCH = 100


class RecordListForBatch(BaseModel):
    records: conlist(Record, min_items=1, max_items=MAX_RECORDS_IN_BATCH)

    @validator("records", each_item=True)
    def record_to_dict(cls, value):
        return value.dict()
