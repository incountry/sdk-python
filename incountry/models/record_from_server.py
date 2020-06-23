from pydantic import StrictInt

from .record import Record


class RecordFromServer(Record):
    version: StrictInt = None
