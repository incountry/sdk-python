from pydantic import StrictBool, StrictInt

from .record import Record


class RecordFromServer(Record):
    version: StrictInt = None
    is_encrypted: StrictBool = None
