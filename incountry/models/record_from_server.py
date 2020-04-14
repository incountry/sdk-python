from pydantic import conint

from .record import Record


class RecordFromServer(Record):
    version: conint(ge=0, strict=True)
